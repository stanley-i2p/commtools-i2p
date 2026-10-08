use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant, SystemTime};
use tokio::fs;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{
    TcpStream,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
};
use tokio::sync::{Mutex, Notify, Semaphore};
use tokio::time::{sleep, timeout};

const DEFAULT_SAM_ENDPOINT: &str = "127.0.0.1:7656";
const DEFAULT_DROP_COUNT: usize = 1;
const MAX_DROP_COUNT: usize = 16;

const BLOB_TTL_SECONDS: u64 = 14 * 24 * 60 * 60; // 14 days
const GC_INTERVAL_SECONDS: u64 = 60 * 60; // 1 hour
const MAX_BLOB_SIZE: usize = 256 * 1024;
const MAX_KEY_LEN: usize = 128;
const CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(15);
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_ACTIVE_CLIENTS_PER_DROP: usize = 32;
const PUT_RATE_WINDOW_SECONDS: u64 = 60;
const MAX_PUTS_PER_WINDOW_PER_DROP: usize = 500;
const POW_PREFIX: &[u8] = b"POWv1";
const POW_ZERO_BITS: usize = 20;

const SAM_CONFIG: [(&str, u32); 4] = [
    ("inbound.length", 2),
    ("outbound.length", 2),
    ("inbound.quantity", 2),
    ("outbound.quantity", 2),
];

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct Config {
    sam_endpoint: String,
    drop_count: usize,
}

impl Config {
    fn from_args() -> Result<Option<Self>, String> {
        let mut sam_endpoint = DEFAULT_SAM_ENDPOINT.to_string();
        let mut drop_count = DEFAULT_DROP_COUNT;
        let mut sam_seen = false;
        let mut drops_seen = false;
        let mut args = std::env::args().skip(1);

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-h" | "--help" => {
                    print_help();
                    return Ok(None);
                }
                "-V" | "--version" => {
                    println!("deaddrop-server {}", env!("CARGO_PKG_VERSION"));
                    return Ok(None);
                }
                "--sam" => {
                    if sam_seen {
                        return Err("--sam may only be specified once".to_string());
                    }
                    let value = args
                        .next()
                        .ok_or_else(|| "--sam requires a HOST:PORT value".to_string())?;
                    sam_endpoint = parse_sam_endpoint(&value)?;
                    sam_seen = true;
                }
                "--drops" => {
                    if drops_seen {
                        return Err("--drops may only be specified once".to_string());
                    }
                    let value = args
                        .next()
                        .ok_or_else(|| "--drops requires a numeric value".to_string())?;
                    drop_count = parse_drop_count(&value)?;
                    drops_seen = true;
                }
                _ => {
                    if let Some(value) = arg.strip_prefix("--sam=") {
                        if sam_seen {
                            return Err("--sam may only be specified once".to_string());
                        }
                        sam_endpoint = parse_sam_endpoint(value)?;
                        sam_seen = true;
                    } else if let Some(value) = arg.strip_prefix("--drops=") {
                        if drops_seen {
                            return Err("--drops may only be specified once".to_string());
                        }
                        drop_count = parse_drop_count(value)?;
                        drops_seen = true;
                    } else {
                        return Err(format!("unknown option: {arg}"));
                    }
                }
            }
        }

        Ok(Some(Self {
            sam_endpoint,
            drop_count,
        }))
    }
}

fn parse_sam_endpoint(value: &str) -> Result<String, String> {
    let (host, port) = if let Some(bracketed) = value.strip_prefix('[') {
        let (host, suffix) = bracketed
            .split_once(']')
            .ok_or_else(|| "--sam has an invalid bracketed IPv6 address".to_string())?;
        let port = suffix
            .strip_prefix(':')
            .ok_or_else(|| "--sam must use the format [IPv6]:PORT".to_string())?;
        (host, port)
    } else {
        let (host, port) = value
            .rsplit_once(':')
            .ok_or_else(|| "--sam must use the format HOST:PORT".to_string())?;
        if host.contains(':') {
            return Err("IPv6 SAM addresses must use the format [IPv6]:PORT".to_string());
        }
        (host, port)
    };

    if host.is_empty() {
        return Err("--sam host must not be empty".to_string());
    }

    let port = port
        .parse::<u16>()
        .map_err(|_| "--sam port must be an integer from 1 to 65535".to_string())?;
    if port == 0 {
        return Err("--sam port must be an integer from 1 to 65535".to_string());
    }

    Ok(value.to_string())
}

fn parse_drop_count(value: &str) -> Result<usize, String> {
    let count = value
        .parse::<usize>()
        .map_err(|_| format!("--drops must be an integer from 1 to {MAX_DROP_COUNT}"))?;
    if !(1..=MAX_DROP_COUNT).contains(&count) {
        return Err(format!(
            "--drops must be an integer from 1 to {MAX_DROP_COUNT}"
        ));
    }
    Ok(count)
}

fn print_help() {
    println!(
        "deaddrop-server {version}\n\
         CommTools-I2P DeadDrop Server\n\n\
         Usage: deaddrop-server [OPTIONS]\n\n\
         Options:\n\
           --sam <HOST:PORT>  SAM endpoint [default: {sam}]\n\
           --drops <COUNT>    Persistent drop identities to host [default: {drops}; max: {max}]\n\
           -h, --help         Show this help\n\
           -V, --version      Show version",
        version = env!("CARGO_PKG_VERSION"),
        sam = DEFAULT_SAM_ENDPOINT,
        drops = DEFAULT_DROP_COUNT,
        max = MAX_DROP_COUNT,
    );
}

#[derive(Clone)]
struct ServerState {
    drop_semaphores: Arc<HashMap<String, Arc<Semaphore>>>,
    drop_put_times: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
}

impl ServerState {
    fn new(drop_count: usize) -> Self {
        let mut drop_semaphores = HashMap::new();
        let mut drop_put_times = HashMap::new();

        for i in 0..drop_count {
            let drop_name = format!("drop_{}", i);
            drop_semaphores.insert(
                drop_name.clone(),
                Arc::new(Semaphore::new(MAX_ACTIVE_CLIENTS_PER_DROP)),
            );
            drop_put_times.insert(drop_name, VecDeque::new());
        }

        Self {
            drop_semaphores: Arc::new(drop_semaphores),
            drop_put_times: Arc::new(Mutex::new(drop_put_times)),
        }
    }

    fn semaphore(&self, drop_name: &str) -> Option<Arc<Semaphore>> {
        self.drop_semaphores.get(drop_name).cloned()
    }

    async fn allow_put(&self, drop_name: &str) -> bool {
        let now = Instant::now();
        let cutoff = now - Duration::from_secs(PUT_RATE_WINDOW_SECONDS);
        let mut all_times = self.drop_put_times.lock().await;
        let Some(times) = all_times.get_mut(drop_name) else {
            return false;
        };

        while times.front().is_some_and(|t| *t < cutoff) {
            times.pop_front();
        }

        if times.len() >= MAX_PUTS_PER_WINDOW_PER_DROP {
            return false;
        }

        times.push_back(now);
        true
    }
}

#[derive(Clone)]
struct Shutdown {
    flag: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl Shutdown {
    fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    fn trigger(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    fn is_set(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    async fn wait(&self) {
        if self.is_set() {
            return;
        }
        self.notify.notified().await;
    }
}

fn base_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        Path::new(&home).join(".deaddrop-server")
    } else if let Ok(profile) = std::env::var("USERPROFILE") {
        Path::new(&profile).join(".deaddrop-server")
    } else {
        PathBuf::from(".deaddrop-server")
    }
}

fn identity_dir() -> PathBuf {
    base_dir().join("identities")
}

fn storage_dir() -> PathBuf {
    base_dir().join("storage")
}

fn drop_storage_dir(drop_name: &str) -> PathBuf {
    storage_dir().join(drop_name)
}

async fn ensure_dirs(drop_count: usize) -> io::Result<()> {
    fs::create_dir_all(identity_dir()).await?;
    fs::create_dir_all(storage_dir()).await?;

    for i in 0..drop_count {
        let drop_name = format!("drop_{}", i);
        fs::create_dir_all(drop_storage_dir(&drop_name)).await?;
    }

    Ok(())
}

fn blob_path(drop_name: &str, key: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let h = hex::encode(hasher.finalize());
    let sub = drop_storage_dir(drop_name).join(&h[..2]);
    sub.join(h)
}

fn is_valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_KEY_LEN
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn pow_material(key: &str, size: usize, blob: &[u8], pow_counter: u64) -> Vec<u8> {
    let mut material = Vec::with_capacity(POW_PREFIX.len() + key.len() + blob.len() + 32);
    material.extend_from_slice(POW_PREFIX);
    material.push(b'|');
    material.extend_from_slice(key.as_bytes());
    material.push(b'|');
    material.extend_from_slice(size.to_string().as_bytes());
    material.push(b'|');
    material.extend_from_slice(blob);
    material.push(b'|');
    material.extend_from_slice(pow_counter.to_string().as_bytes());
    material
}

fn pow_ok(digest: &[u8]) -> bool {
    let zero_bytes = POW_ZERO_BITS / 8;
    let rem_bits = POW_ZERO_BITS % 8;

    if digest.len() <= zero_bytes {
        return false;
    }

    if digest[..zero_bytes].iter().any(|b| *b != 0) {
        return false;
    }

    if rem_bits == 0 {
        return true;
    }

    let mask = 0xffu8 << (8 - rem_bits);
    (digest[zero_bytes] & mask) == 0
}

fn verify_put_pow(key: &str, size: usize, blob: &[u8], pow_counter: u64) -> bool {
    let material = pow_material(key, size, blob, pow_counter);
    let digest = Sha256::digest(&material);
    pow_ok(&digest)
}

async fn ensure_blob_parent_dir(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    Ok(())
}

async fn atomic_write_blob(path: &Path, data: &[u8]) -> io::Result<()> {
    ensure_blob_parent_dir(path).await?;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().and_then(|v| v.to_str()).unwrap_or("blob");
    let tmp_name = format!(
        ".{}.tmp.{}.{}",
        file_name,
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let tmp_path = parent.join(tmp_name);

    let write_result: io::Result<()> = async {
        let mut tmp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .await?;
        tmp.write_all(data).await?;
        tmp.flush().await?;
        tmp.sync_all().await?;
        drop(tmp);
        fs::rename(&tmp_path, path).await?;
        Ok(())
    }
    .await;

    if write_result.is_err() {
        let _ = fs::remove_file(&tmp_path).await;
    }

    write_result
}

async fn write_all_with_timeout(writer: &mut OwnedWriteHalf, data: &[u8]) -> io::Result<()> {
    timeout(CLIENT_WRITE_TIMEOUT, writer.write_all(data))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "client write timeout"))??;
    Ok(())
}

async fn flush_with_timeout(writer: &mut OwnedWriteHalf) -> io::Result<()> {
    timeout(CLIENT_WRITE_TIMEOUT, writer.flush())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "client write timeout"))??;
    Ok(())
}

async fn gc_loop(drop_count: usize, shutdown: Shutdown) {
    while !shutdown.is_set() {
        let mut deleted = 0usize;

        for i in 0..drop_count {
            let drop_name = format!("drop_{}", i);
            let root = drop_storage_dir(&drop_name);

            match walk_and_gc_dir(&root).await {
                Ok(count) => {
                    deleted += count;
                }
                Err(e) => {
                    eprintln!("[GC] loop error in {}: {}", drop_name, e);
                }
            }
        }

        if deleted > 0 {
            println!("[GC] removed {deleted} expired blobs");
        }

        tokio::select! {
            _ = shutdown.wait() => break,
            _ = sleep(Duration::from_secs(GC_INTERVAL_SECONDS)) => {}
        }
    }
}

async fn walk_and_gc_dir(root: &Path) -> io::Result<usize> {
    let mut deleted = 0usize;

    let mut dirs = vec![root.to_path_buf()];

    while let Some(dir) = dirs.pop() {
        let mut rd = match fs::read_dir(&dir).await {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };

        while let Some(entry) = rd.next_entry().await? {
            let path = entry.path();
            let ty = entry.file_type().await?;

            if ty.is_dir() {
                dirs.push(path);
                continue;
            }

            if !ty.is_file() {
                continue;
            }

            match entry.metadata().await {
                Ok(meta) => {
                    if let Ok(modified) = meta.modified() {
                        if is_older_than_ttl(modified) {
                            match fs::remove_file(&path).await {
                                Ok(_) => deleted += 1,
                                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                                Err(e) => {
                                    eprintln!("[GC] failed to remove {}: {}", path.display(), e)
                                }
                            }
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => eprintln!("[GC] failed to stat {}: {}", path.display(), e),
            }
        }
    }

    Ok(deleted)
}

fn is_older_than_ttl(modified: SystemTime) -> bool {
    match SystemTime::now().duration_since(modified) {
        Ok(age) => age.as_secs() > BLOB_TTL_SECONDS,
        Err(_) => false,
    }
}

async fn read_line_from_half(reader: &mut BufReader<OwnedReadHalf>) -> io::Result<Option<String>> {
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(line))
}

async fn handle_client(
    drop_name: &str,
    state: ServerState,
    mut reader: BufReader<OwnedReadHalf>,
    mut writer: OwnedWriteHalf,
) {
    let result: io::Result<()> = async {
        let line = match timeout(CLIENT_READ_TIMEOUT, read_line_from_half(&mut reader))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "client read timeout"))??
        {
            Some(v) => v,
            None => return Ok(()),
        };

        //println!("[SERVER] raw line: {}", line.trim_end()); Debug messages

        if line.len() > 512 {
            write_all_with_timeout(&mut writer, b"ERR\n").await?;
            flush_with_timeout(&mut writer).await?;
            println!("[{}] rejected oversized command line", drop_name);
            return Ok(());
        }

        let parts: Vec<String> = line
            .trim()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        //println!("[SERVER] parsed: {:?}", parts); Debug messages

        if parts.is_empty() {
            return Ok(());
        }

        let cmd = parts[0].as_str();

        if cmd == "PUT" && parts.len() >= 4 {
            let key = &parts[1];

            if !is_valid_key(key) {
                write_all_with_timeout(&mut writer, b"ERR\n").await?;
                flush_with_timeout(&mut writer).await?;
                println!("[{}] PUT invalid key", drop_name);
                return Ok(());
            }

            let size: usize = match parts[2].parse() {
                Ok(v) => v,
                Err(_) => {
                    write_all_with_timeout(&mut writer, b"ERR\n").await?;
                    flush_with_timeout(&mut writer).await?;
                    println!("[{}] PUT invalid size", drop_name);
                    return Ok(());
                }
            };

            let pow_counter: u64 = match parts[3].parse() {
                Ok(v) => v,
                Err(_) => {
                    write_all_with_timeout(&mut writer, b"ERR\n").await?;
                    flush_with_timeout(&mut writer).await?;
                    println!(
                        "[{}] PUT key={} size={} result=REJECT_POW_COUNTER",
                        drop_name, key, size
                    );
                    return Ok(());
                }
            };

            if size > MAX_BLOB_SIZE {
                write_all_with_timeout(&mut writer, b"ERR\n").await?;
                flush_with_timeout(&mut writer).await?;
                println!(
                    "[{}] PUT key={} size={} result=REJECT_SIZE",
                    drop_name, key, size
                );
                return Ok(());
            }

            if !state.allow_put(drop_name).await {
                write_all_with_timeout(&mut writer, b"ERR\n").await?;
                flush_with_timeout(&mut writer).await?;
                println!(
                    "[{}] PUT key={} size={} result=RATE_LIMIT",
                    drop_name, key, size
                );
                return Ok(());
            }

            //println!("[SERVER] PUT key={} size={}", key, size); Debug messages

            let mut data = vec![0u8; size];
            timeout(CLIENT_READ_TIMEOUT, reader.read_exact(&mut data))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "client read timeout"))??;

            if !verify_put_pow(key, size, &data, pow_counter) {
                write_all_with_timeout(&mut writer, b"ERR\n").await?;
                flush_with_timeout(&mut writer).await?;
                println!(
                    "[{}] PUT key={} size={} result=REJECT_POW",
                    drop_name, key, size
                );
                return Ok(());
            }

            let path = blob_path(drop_name, key);

            if fs::metadata(&path).await.is_ok() {
                write_all_with_timeout(&mut writer, b"EXISTS\n").await?;
                println!(
                    "[{}] PUT key={} size={} result=EXISTS",
                    drop_name, key, size
                );
            } else {
                atomic_write_blob(&path, &data).await?;
                write_all_with_timeout(&mut writer, b"OK\n").await?;
                println!("[{}] PUT key={} size={} result=OK", drop_name, key, size);
            }
        } else if cmd == "GET" && parts.len() >= 2 {
            let key = &parts[1];

            if !is_valid_key(key) {
                write_all_with_timeout(&mut writer, b"ERR\n").await?;
                flush_with_timeout(&mut writer).await?;
                println!("[{}] GET invalid key", drop_name);
                return Ok(());
            }

            let path = blob_path(drop_name, key);

            match fs::metadata(&path).await {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    write_all_with_timeout(&mut writer, b"MISS\n").await?;
                    println!("[{}] GET key={} result=MISS", drop_name, key);
                }
                Err(e) => return Err(e),
                Ok(meta) => {
                    let expired = meta.modified().map(is_older_than_ttl).unwrap_or(false);

                    if expired {
                        match fs::remove_file(&path).await {
                            Ok(_) => {}
                            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                            Err(e) => eprintln!(
                                "[{}] GET expired remove failed key={}: {}",
                                drop_name, key, e
                            ),
                        }
                        write_all_with_timeout(&mut writer, b"MISS\n").await?;
                        println!("[{}] GET key={} result=MISS_EXPIRED", drop_name, key);
                    } else {
                        let data = fs::read(&path).await?;
                        let hdr = format!("OK {}\n", data.len());
                        write_all_with_timeout(&mut writer, hdr.as_bytes()).await?;
                        write_all_with_timeout(&mut writer, &data).await?;
                        println!(
                            "[{}] GET key={} size={} result=OK",
                            drop_name,
                            key,
                            data.len()
                        );
                    }
                }
            }
        } else {
            write_all_with_timeout(&mut writer, b"ERR\n").await?;
        }

        flush_with_timeout(&mut writer).await?;
        Ok(())
    }
    .await;

    if let Err(e) = result {
        if e.kind() == io::ErrorKind::TimedOut {
            println!("[{}] client timeout", drop_name);
        } else {
            eprintln!("[ERROR] client handling: {e}");
        }
    }

    let _ = writer.shutdown().await;
}

async fn handle_client_limited(
    drop_name: String,
    state: ServerState,
    reader: BufReader<OwnedReadHalf>,
    mut writer: OwnedWriteHalf,
) {
    let Some(sem) = state.semaphore(&drop_name) else {
        eprintln!("[{}] missing semaphore", drop_name);
        let _ = writer.shutdown().await;
        return;
    };

    let Ok(_permit) = sem.try_acquire_owned() else {
        println!(
            "[{}] connection rejected: too many active clients",
            drop_name
        );
        let _ = write_all_with_timeout(&mut writer, b"ERR\n").await;
        let _ = flush_with_timeout(&mut writer).await;
        let _ = writer.shutdown().await;
        return;
    };

    handle_client(&drop_name, state, reader, writer).await;
}

async fn create_session(
    name: &str,
    keyfile: &Path,
    sam_endpoint: &str,
) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(sam_endpoint).await?;

    // HELLO
    stream.write_all(b"HELLO VERSION MIN=3.0 MAX=3.2\n").await?;
    stream.flush().await?;

    let hello_resp = {
        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "SAM did not respond to HELLO",
            ));
        }
        line
    };

    println!("[{}] HELLO: {}", name, hello_resp.trim());

    // Load or create destination
    let dest = match fs::read_to_string(keyfile).await {
        Ok(s) => s.trim().to_string(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => "TRANSIENT".to_string(),
        Err(e) => return Err(e),
    };

    // SESSION CREATE
    let options_str = SAM_CONFIG
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ");

    let cmd = format!(
        "SESSION CREATE STYLE=STREAM ID={} DESTINATION={} SIGNATURE_TYPE=7 OPTION {}\n",
        name, dest, options_str
    );

    stream.write_all(cmd.as_bytes()).await?;
    stream.flush().await?;

    let resp_str = {
        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "SAM did not respond to SESSION CREATE",
            ));
        }
        line.trim().to_string()
    };

    println!("[{}] {}", name, resp_str);

    if !resp_str.contains("RESULT=OK") {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to create session: {}", resp_str),
        ));
    }

    if let Some(dest_b64) = extract_destination(&resp_str) {
        if let Some(parent) = keyfile.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(keyfile, dest_b64).await?;
    }

    Ok(stream)
}

fn extract_destination(resp: &str) -> Option<&str> {
    for part in resp.split_whitespace() {
        if let Some(rest) = part.strip_prefix("DESTINATION=") {
            return Some(rest);
        }
    }
    None
}

async fn accept_loop(
    name: String,
    state: ServerState,
    shutdown: Shutdown,
    sam_endpoint: String,
) {
    while !shutdown.is_set() {
        let res: io::Result<()> = async {
            let stream = TcpStream::connect(sam_endpoint.as_str()).await?;
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);

            write_half
                .write_all(b"HELLO VERSION MIN=3.0 MAX=3.2\n")
                .await?;
            write_half.flush().await?;
            let _ = read_line_from_half(&mut reader).await?;

            let accept_cmd = format!("STREAM ACCEPT ID={}\n", name);
            write_half.write_all(accept_cmd.as_bytes()).await?;
            write_half.flush().await?;

            let resp = match read_line_from_half(&mut reader).await? {
                Some(v) => v,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "SAM closed during ACCEPT",
                    ));
                }
            };

            if !resp.contains("RESULT=OK") {
                println!("[{}] ACCEPT failed: {}", name, resp.trim());
                return Ok(());
            }

            //println!("[{}] waiting...", name); Debug messages

            let _dest_line = match read_line_from_half(&mut reader).await? {
                Some(v) => v,
                None => {
                    println!("[{}] incoming stream closed before peer destination", name);
                    return Ok(());
                }
            };

            //let bytes = dest_line.as_bytes();
            //let preview_len = bytes.len().min(60);
            //println!("[{}] incoming from: {:?}", name, &bytes[..preview_len]);

            tokio::spawn(handle_client_limited(
                name.clone(),
                state.clone(),
                reader,
                write_half,
            ));
            Ok(())
        }
        .await;

        if shutdown.is_set() {
            break;
        }

        if let Err(e) = res {
            eprintln!("[{}] accept error: {}", name, e);
        }

        if !shutdown.is_set() {
            sleep(Duration::from_secs(1)).await;
        }
    }
}

async fn signal_task(shutdown: Shutdown) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigint = signal(SignalKind::interrupt()).ok();
        let mut sigterm = signal(SignalKind::terminate()).ok();

        tokio::select! {
            _ = async {
                if let Some(s) = sigint.as_mut() {
                    s.recv().await;
                }
            } => {
                println!("\n[INFO] Shutdown signal received");
                shutdown.trigger();
            }
            _ = async {
                if let Some(s) = sigterm.as_mut() {
                    s.recv().await;
                }
            } => {
                println!("\n[INFO] Shutdown signal received");
                shutdown.trigger();
            }
            _ = shutdown.wait() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        println!("\n[INFO] Shutdown signal received");
        shutdown.trigger();
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = match Config::from_args() {
        Ok(Some(config)) => config,
        Ok(None) => return Ok(()),
        Err(message) => {
            eprintln!("error: {message}\n\nUse --help to list available options.");
            std::process::exit(2);
        }
    };

    ensure_dirs(config.drop_count).await?;

    let shutdown = Shutdown::new();
    let state = ServerState::new(config.drop_count);

    let signal_shutdown = shutdown.clone();
    tokio::spawn(async move {
        signal_task(signal_shutdown).await;
    });

    let mut tasks = Vec::new();
    let mut session_conns = Vec::new();

    for i in 0..config.drop_count {
        let name = format!("drop_{}", i);
        let keyfile = identity_dir().join(format!("{}.dat", name));

        let session_stream = create_session(&name, &keyfile, &config.sam_endpoint).await?;
        session_conns.push(session_stream);

        let s = shutdown.clone();
        let loop_state = state.clone();
        let sam_endpoint = config.sam_endpoint.clone();
        let task = tokio::spawn(async move {
            accept_loop(name, loop_state, s, sam_endpoint).await;
        });
        tasks.push(task);
    }

    {
        let s = shutdown.clone();
        let drop_count = config.drop_count;
        tasks.push(tokio::spawn(async move {
            gc_loop(drop_count, s).await;
        }));
    }

    println!("[INFO] SAM endpoint: {}", config.sam_endpoint);
    println!("[INFO] Started {} drop identities", config.drop_count);

    shutdown.wait().await;

    println!("[INFO] Shutting down accept loops...");

    for t in tasks {
        t.abort();
        let _ = t.await;
    }

    println!("[INFO] Closing SAM sessions...");

    for mut stream in session_conns {
        let _ = stream.shutdown().await;
    }

    println!("[INFO] Shutdown complete");
    Ok(())
}
