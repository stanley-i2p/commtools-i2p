use crate::config::SamEndpoint;
use crate::sam::{SamByteStream, SamError, SamSessionConfig, TunnelOptions};
use crate::sam_runtime::SamRuntime;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::sleep;

pub const MAX_DEADDROP_BLOB_SIZE: usize = 256 * 1024;
pub const MAX_DEADDROP_KEY_LENGTH: usize = 128;
pub const DEFAULT_POW_ZERO_BITS: u8 = 20;
pub const MAX_POW_ZERO_BITS: u8 = 32;

const RESPONSE_LINE_LIMIT: usize = 512;
const READY_PROBE_ATTEMPTS: usize = 3;
const READY_PROBE_DELAY: Duration = Duration::from_millis(650);
const DROP_TUNNEL_LENGTH: u8 = 2;
const DROP_TUNNEL_QUANTITY: u8 = 2;
const POW_DOMAIN: &[u8] = b"POWv1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeaddropConfig {
    endpoint: SamEndpoint,
    session_prefix: String,
    servers: Vec<String>,
    pow_zero_bits: u8,
}

impl DeaddropConfig {
    pub fn new(
        endpoint: SamEndpoint,
        session_prefix: impl Into<String>,
        servers: impl IntoIterator<Item = String>,
    ) -> Result<Self, DeaddropError> {
        Self::with_pow_bits(endpoint, session_prefix, servers, DEFAULT_POW_ZERO_BITS)
    }

    pub fn with_pow_bits(
        endpoint: SamEndpoint,
        session_prefix: impl Into<String>,
        servers: impl IntoIterator<Item = String>,
        pow_zero_bits: u8,
    ) -> Result<Self, DeaddropError> {
        if !(1..=MAX_POW_ZERO_BITS).contains(&pow_zero_bits) {
            return Err(DeaddropError::InvalidPowBits(pow_zero_bits));
        }

        let session_prefix = session_prefix.into();
        let tunnels = drop_tunnels()?;
        SamSessionConfig::transient(format!("{session_prefix}_put"), tunnels)?;
        SamSessionConfig::transient(format!("{session_prefix}_get"), tunnels)?;

        let mut seen = HashSet::new();
        let mut validated_servers = Vec::new();
        for server in servers {
            let server = normalize_deaddrop_server(&server)?;
            if seen.insert(server.clone()) {
                validated_servers.push(server);
            }
        }
        if validated_servers.is_empty() {
            return Err(DeaddropError::NoServers);
        }

        Ok(Self {
            endpoint,
            session_prefix,
            servers: validated_servers,
            pow_zero_bits,
        })
    }

    pub fn endpoint(&self) -> &SamEndpoint {
        &self.endpoint
    }

    pub fn session_prefix(&self) -> &str {
        &self.session_prefix
    }

    pub fn servers(&self) -> &[String] {
        &self.servers
    }

    pub fn pow_zero_bits(&self) -> u8 {
        self.pow_zero_bits
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutReplicaStatus {
    Stored,
    Exists,
    Rejected,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutStatus {
    Stored,
    Exists,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutReplicaResult {
    pub server: String,
    pub status: PutReplicaStatus,
    pub latency_ms: u64,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutResult {
    pub status: PutStatus,
    pub successful_servers: Vec<String>,
    pub replicas: Vec<PutReplicaResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetReplicaStatus {
    Hit,
    Miss,
    Rejected,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetReplicaResult {
    pub server: String,
    pub status: GetReplicaStatus,
    pub blob: Option<Vec<u8>>,
    pub latency_ms: u64,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetResult {
    pub replicas: Vec<GetReplicaResult>,
}

impl GetResult {
    pub fn hits(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.replicas.iter().filter_map(|result| {
            result
                .blob
                .as_deref()
                .map(|blob| (result.server.as_str(), blob))
        })
    }
}

#[derive(Clone)]
pub struct DeaddropClient {
    inner: Arc<DeaddropClientInner>,
}

struct DeaddropClientInner {
    config: DeaddropConfig,
    put_runtime: SamRuntime,
    get_runtime: SamRuntime,
    start_lock: Mutex<()>,
    sessions_initialized: AtomicBool,
    started: AtomicBool,
    closed: AtomicBool,
}

impl DeaddropClient {
    pub fn new(config: DeaddropConfig) -> Self {
        Self {
            inner: Arc::new(DeaddropClientInner {
                put_runtime: SamRuntime::new(config.endpoint.clone()),
                get_runtime: SamRuntime::new(config.endpoint.clone()),
                config,
                start_lock: Mutex::new(()),
                sessions_initialized: AtomicBool::new(false),
                started: AtomicBool::new(false),
                closed: AtomicBool::new(false),
            }),
        }
    }

    pub fn config(&self) -> &DeaddropConfig {
        &self.inner.config
    }

    pub fn is_started(&self) -> bool {
        self.inner.started.load(Ordering::SeqCst)
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    pub async fn start(&self) -> Result<(), DeaddropError> {
        if self.is_closed() {
            return Err(DeaddropError::Closed);
        }
        if self.is_started() {
            return Ok(());
        }

        let _guard = self.inner.start_lock.lock().await;
        if self.is_closed() {
            return Err(DeaddropError::Closed);
        }
        if self.is_started() {
            return Ok(());
        }

        if !self.inner.sessions_initialized.load(Ordering::SeqCst) {
            let tunnels = drop_tunnels()?;
            let put_config = SamSessionConfig::transient(
                format!("{}_put", self.inner.config.session_prefix),
                tunnels,
            )?;
            self.inner.put_runtime.create_session(&put_config).await?;

            let get_config = SamSessionConfig::transient(
                format!("{}_get", self.inner.config.session_prefix),
                tunnels,
            )?;
            if let Err(error) = self.inner.get_runtime.create_session(&get_config).await {
                self.inner.closed.store(true, Ordering::SeqCst);
                let _ = self.inner.put_runtime.shutdown().await;
                let _ = self.inner.get_runtime.shutdown().await;
                return Err(error.into());
            }
            self.inner
                .sessions_initialized
                .store(true, Ordering::SeqCst);
        }

        self.wait_until_any_server_ready().await?;
        self.inner.started.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub async fn put(&self, key: &str, blob: &[u8]) -> Result<PutResult, DeaddropError> {
        self.put_to_servers(key, blob, &self.inner.config.servers)
            .await
    }

    pub async fn put_to_servers(
        &self,
        key: &str,
        blob: &[u8],
        servers: &[String],
    ) -> Result<PutResult, DeaddropError> {
        validate_key(key)?;
        validate_blob(blob)?;
        let servers = self.operation_servers(servers)?;
        self.ensure_started().await?;

        let key_for_pow = key.to_string();
        let blob_for_pow = blob.to_vec();
        let bits = self.inner.config.pow_zero_bits;
        let pow_counter = tokio::task::spawn_blocking(move || {
            find_pow_counter(bits, &key_for_pow, &blob_for_pow)
        })
        .await
        .map_err(|error| DeaddropError::Worker(error.to_string()))??;
        self.put_with_counter_to_servers(key, blob, pow_counter, &servers)
            .await
    }

    pub async fn put_with_counter(
        &self,
        key: &str,
        blob: &[u8],
        pow_counter: u64,
    ) -> Result<PutResult, DeaddropError> {
        self.put_with_counter_to_servers(key, blob, pow_counter, &self.inner.config.servers)
            .await
    }

    pub async fn put_with_counter_to_servers(
        &self,
        key: &str,
        blob: &[u8],
        pow_counter: u64,
        servers: &[String],
    ) -> Result<PutResult, DeaddropError> {
        validate_key(key)?;
        validate_blob(blob)?;
        let servers = self.operation_servers(servers)?;
        self.ensure_started().await?;

        let mut tasks = JoinSet::new();
        for server in servers {
            let runtime = self.inner.put_runtime.clone();
            let key = key.to_string();
            let blob = blob.to_vec();
            tasks.spawn(async move { put_one(runtime, server, key, blob, pow_counter).await });
        }

        let mut replicas = Vec::new();
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(replica) => replicas.push(replica),
                Err(error) => replicas.push(PutReplicaResult {
                    server: "<worker>".to_string(),
                    status: PutReplicaStatus::Failed,
                    latency_ms: 0,
                    detail: error.to_string(),
                }),
            }
        }
        replicas.sort_by(|left, right| left.server.cmp(&right.server));

        let stored = replicas
            .iter()
            .filter(|replica| replica.status == PutReplicaStatus::Stored)
            .map(|replica| replica.server.clone())
            .collect::<Vec<_>>();
        let existing = replicas
            .iter()
            .filter(|replica| replica.status == PutReplicaStatus::Exists)
            .map(|replica| replica.server.clone())
            .collect::<Vec<_>>();
        if !stored.is_empty() {
            Ok(PutResult {
                status: PutStatus::Stored,
                successful_servers: stored,
                replicas,
            })
        } else if !existing.is_empty() {
            Ok(PutResult {
                status: PutStatus::Exists,
                successful_servers: existing,
                replicas,
            })
        } else {
            Ok(PutResult {
                status: PutStatus::Failed,
                successful_servers: Vec::new(),
                replicas,
            })
        }
    }

    pub async fn get(&self, key: &str) -> Result<GetResult, DeaddropError> {
        self.get_from_servers(key, &self.inner.config.servers).await
    }

    pub async fn get_from_servers(
        &self,
        key: &str,
        servers: &[String],
    ) -> Result<GetResult, DeaddropError> {
        validate_key(key)?;
        let servers = self.operation_servers(servers)?;
        self.ensure_started().await?;

        let mut tasks = JoinSet::new();
        for server in servers {
            let runtime = self.inner.get_runtime.clone();
            let key = key.to_string();
            tasks.spawn(async move { get_one(runtime, server, key).await });
        }

        let mut replicas = Vec::new();
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(replica) => replicas.push(replica),
                Err(error) => replicas.push(GetReplicaResult {
                    server: "<worker>".to_string(),
                    status: GetReplicaStatus::Failed,
                    blob: None,
                    latency_ms: 0,
                    detail: error.to_string(),
                }),
            }
        }
        replicas.sort_by(|left, right| left.server.cmp(&right.server));
        Ok(GetResult { replicas })
    }

    fn operation_servers(&self, servers: &[String]) -> Result<Vec<String>, DeaddropError> {
        if servers.is_empty() {
            return Err(DeaddropError::NoServers);
        }
        let configured = self
            .inner
            .config
            .servers
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        let mut selected = Vec::new();
        let mut seen = HashSet::new();
        for server in servers {
            let server = normalize_deaddrop_server(server)?;
            if !configured.contains(server.as_str()) {
                return Err(DeaddropError::ServerNotConfigured(server));
            }
            if seen.insert(server.clone()) {
                selected.push(server);
            }
        }
        if selected.is_empty() {
            return Err(DeaddropError::NoServers);
        }
        Ok(selected)
    }

    pub async fn shutdown(&self) -> Result<(), DeaddropError> {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        self.inner.started.store(false, Ordering::SeqCst);
        self.inner
            .sessions_initialized
            .store(false, Ordering::SeqCst);
        let (put_result, get_result) = tokio::join!(
            self.inner.put_runtime.shutdown(),
            self.inner.get_runtime.shutdown()
        );
        put_result?;
        get_result?;
        Ok(())
    }

    async fn ensure_started(&self) -> Result<(), DeaddropError> {
        if self.is_closed() {
            return Err(DeaddropError::Closed);
        }
        if !self.is_started() {
            self.start().await?;
        }
        Ok(())
    }

    async fn wait_until_any_server_ready(&self) -> Result<(), DeaddropError> {
        let mut last_error = None;
        for attempt in 0..READY_PROBE_ATTEMPTS {
            for server in &self.inner.config.servers {
                match self.inner.put_runtime.connect_byte_stream(server).await {
                    Ok(stream) => {
                        self.inner.put_runtime.close_byte_stream(&stream).await?;
                        return Ok(());
                    }
                    Err(error) => last_error = Some(error.to_string()),
                }
            }
            if attempt + 1 < READY_PROBE_ATTEMPTS {
                sleep(READY_PROBE_DELAY).await;
            }
        }
        Err(DeaddropError::NoReadyServer(last_error.unwrap_or_else(
            || "no server accepted a probe".to_string(),
        )))
    }
}

impl std::fmt::Debug for DeaddropClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeaddropClient")
            .field("config", &self.inner.config)
            .field("started", &self.is_started())
            .field("closed", &self.is_closed())
            .finish()
    }
}

pub fn find_pow_counter(zero_bits: u8, key: &str, blob: &[u8]) -> Result<u64, DeaddropError> {
    if !(1..=MAX_POW_ZERO_BITS).contains(&zero_bits) {
        return Err(DeaddropError::InvalidPowBits(zero_bits));
    }
    validate_key(key)?;
    validate_blob(blob)?;

    let mut base = Sha256::new();
    base.update(POW_DOMAIN);
    base.update(b"|");
    base.update(key.as_bytes());
    base.update(b"|");
    base.update(blob.len().to_string().as_bytes());
    base.update(b"|");
    base.update(blob);
    base.update(b"|");

    let mut counter = 0u64;
    loop {
        let mut hash = base.clone();
        hash.update(counter.to_string().as_bytes());
        if has_leading_zero_bits(&hash.finalize(), zero_bits) {
            return Ok(counter);
        }
        counter = counter.wrapping_add(1);
    }
}

pub fn verify_pow(zero_bits: u8, key: &str, blob: &[u8], counter: u64) -> bool {
    if !(1..=MAX_POW_ZERO_BITS).contains(&zero_bits)
        || validate_key(key).is_err()
        || validate_blob(blob).is_err()
    {
        return false;
    }
    let mut hash = Sha256::new();
    hash.update(POW_DOMAIN);
    hash.update(b"|");
    hash.update(key.as_bytes());
    hash.update(b"|");
    hash.update(blob.len().to_string().as_bytes());
    hash.update(b"|");
    hash.update(blob);
    hash.update(b"|");
    hash.update(counter.to_string().as_bytes());
    has_leading_zero_bits(&hash.finalize(), zero_bits)
}

async fn put_one(
    runtime: SamRuntime,
    server: String,
    key: String,
    blob: Vec<u8>,
    pow_counter: u64,
) -> PutReplicaResult {
    let started = Instant::now();
    let result = async {
        let stream = runtime.connect_byte_stream(&server).await?;
        let operation = put_on_stream(&runtime, &stream, &key, &blob, pow_counter).await;
        let close_result = runtime.close_byte_stream(&stream).await;
        operation.and(close_result.map_err(DeaddropError::from).map(|_| ()))
    }
    .await;

    let (status, detail) = match result {
        Ok(()) => (PutReplicaStatus::Stored, "OK".to_string()),
        Err(DeaddropError::AlreadyExists) => (PutReplicaStatus::Exists, "EXISTS".to_string()),
        Err(DeaddropError::ServerRejected) => (PutReplicaStatus::Rejected, "ERR".to_string()),
        Err(error) => (PutReplicaStatus::Failed, error.to_string()),
    };
    PutReplicaResult {
        server,
        status,
        latency_ms: elapsed_millis(started),
        detail,
    }
}

async fn put_on_stream(
    runtime: &SamRuntime,
    stream: &SamByteStream,
    key: &str,
    blob: &[u8],
    pow_counter: u64,
) -> Result<(), DeaddropError> {
    let header = format!("PUT {key} {} {pow_counter}\n", blob.len());
    runtime.write_bytes(stream, header.as_bytes()).await?;
    runtime.write_bytes(stream, blob).await?;
    match read_response_line(runtime, stream).await?.as_str() {
        "OK" => Ok(()),
        "EXISTS" => Err(DeaddropError::AlreadyExists),
        "ERR" => Err(DeaddropError::ServerRejected),
        response => Err(DeaddropError::UnexpectedResponse(response.to_string())),
    }
}

async fn get_one(runtime: SamRuntime, server: String, key: String) -> GetReplicaResult {
    let started = Instant::now();
    let result = async {
        let stream = runtime.connect_byte_stream(&server).await?;
        let operation = get_from_stream(&runtime, &stream, &key).await;
        let close_result = runtime.close_byte_stream(&stream).await;
        match operation {
            Ok(value) => {
                close_result?;
                Ok(value)
            }
            Err(error) => Err(error),
        }
    }
    .await;

    let (status, blob, detail) = match result {
        Ok(Some(blob)) => (GetReplicaStatus::Hit, Some(blob), "OK".to_string()),
        Ok(None) => (GetReplicaStatus::Miss, None, "MISS".to_string()),
        Err(DeaddropError::ServerRejected) => (GetReplicaStatus::Rejected, None, "ERR".to_string()),
        Err(error) => (GetReplicaStatus::Failed, None, error.to_string()),
    };
    GetReplicaResult {
        server,
        status,
        blob,
        latency_ms: elapsed_millis(started),
        detail,
    }
}

async fn get_from_stream(
    runtime: &SamRuntime,
    stream: &SamByteStream,
    key: &str,
) -> Result<Option<Vec<u8>>, DeaddropError> {
    runtime
        .write_bytes(stream, format!("GET {key}\n").as_bytes())
        .await?;
    let response = read_response_line(runtime, stream).await?;
    if response == "MISS" {
        return Ok(None);
    }
    if response == "ERR" {
        return Err(DeaddropError::ServerRejected);
    }
    let Some(size) = response.strip_prefix("OK ") else {
        return Err(DeaddropError::UnexpectedResponse(response));
    };
    let size = size
        .parse::<usize>()
        .map_err(|_| DeaddropError::InvalidSizeResponse)?;
    if size > MAX_DEADDROP_BLOB_SIZE {
        return Err(DeaddropError::BlobTooLarge(size));
    }
    Ok(Some(runtime.read_bytes_exact(stream, size).await?))
}

async fn read_response_line(
    runtime: &SamRuntime,
    stream: &SamByteStream,
) -> Result<String, DeaddropError> {
    let response = runtime.read_byte_line(stream).await?;
    if response.len() > RESPONSE_LINE_LIMIT {
        return Err(DeaddropError::ResponseTooLarge);
    }
    Ok(response.trim_end_matches('\r').to_string())
}

pub fn normalize_deaddrop_server(server: &str) -> Result<String, DeaddropError> {
    let server = server.trim().to_ascii_lowercase();
    let Some(label) = server.strip_suffix(".b32.i2p") else {
        return Err(DeaddropError::InvalidServer);
    };
    if label.len() != 52
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
    {
        return Err(DeaddropError::InvalidServer);
    }
    Ok(server)
}

fn validate_key(key: &str) -> Result<(), DeaddropError> {
    if key.is_empty()
        || key.len() > MAX_DEADDROP_KEY_LENGTH
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(DeaddropError::InvalidKey);
    }
    Ok(())
}

fn validate_blob(blob: &[u8]) -> Result<(), DeaddropError> {
    if blob.len() > MAX_DEADDROP_BLOB_SIZE {
        return Err(DeaddropError::BlobTooLarge(blob.len()));
    }
    Ok(())
}

fn has_leading_zero_bits(hash: &[u8], bits: u8) -> bool {
    let full_bytes = usize::from(bits / 8);
    let remaining = bits % 8;
    if hash.len() < full_bytes + usize::from(remaining != 0) {
        return false;
    }
    if hash[..full_bytes].iter().any(|byte| *byte != 0) {
        return false;
    }
    remaining == 0 || hash[full_bytes] & (0xff << (8 - remaining)) == 0
}

fn drop_tunnels() -> Result<TunnelOptions, SamError> {
    TunnelOptions::new(DROP_TUNNEL_LENGTH, DROP_TUNNEL_QUANTITY)
}

fn elapsed_millis(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

#[derive(Debug, Error)]
pub enum DeaddropError {
    #[error(transparent)]
    Sam(#[from] SamError),
    #[error("at least one deaddrop server is required")]
    NoServers,
    #[error("invalid deaddrop server address")]
    InvalidServer,
    #[error("deaddrop server is not configured for this client: {0}")]
    ServerNotConfigured(String),
    #[error("invalid deaddrop key")]
    InvalidKey,
    #[error("deaddrop blob exceeds {MAX_DEADDROP_BLOB_SIZE} bytes: {0}")]
    BlobTooLarge(usize),
    #[error("proof-of-work bits must be between 1 and {MAX_POW_ZERO_BITS}: {0}")]
    InvalidPowBits(u8),
    #[error("no deaddrop server became ready: {0}")]
    NoReadyServer(String),
    #[error("deaddrop client is closed")]
    Closed,
    #[error("deaddrop server rejected the operation")]
    ServerRejected,
    #[error("deaddrop blob already exists")]
    AlreadyExists,
    #[error("deaddrop response is too large")]
    ResponseTooLarge,
    #[error("invalid deaddrop size response")]
    InvalidSizeResponse,
    #[error("unexpected deaddrop response: {0}")]
    UnexpectedResponse(String),
    #[error("deaddrop worker failed: {0}")]
    Worker(String),
}
