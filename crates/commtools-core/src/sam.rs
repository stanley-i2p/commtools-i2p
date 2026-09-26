use crate::config::SamEndpoint;
use crate::protocol::Frame;
use base64::{Engine as _, engine::general_purpose};
use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;

pub const SAM_MIN_VERSION: &str = "3.0";
pub const SAM_MAX_VERSION: &str = "3.2";
pub const DEFAULT_TUNNEL_LENGTH: u8 = 2;
pub const DEFAULT_TUNNEL_QUANTITY: u8 = 3;
pub const MIN_TUNNEL_LENGTH: u8 = 1;
pub const MAX_TUNNEL_LENGTH: u8 = 4;
pub const MIN_TUNNEL_QUANTITY: u8 = 1;
pub const MAX_TUNNEL_QUANTITY: u8 = 5;

const MAX_SAM_LINE_SIZE: usize = 64 * 1024;
const MAX_DESTINATION_SIZE: usize = 16 * 1024;
const MAX_SESSION_ID_SIZE: usize = 128;
const MAX_QUEUED_FRAMES: usize = 1_024;
const READER_JOIN_TIMEOUT: Duration = Duration::from_millis(250);
const CANCELLED_CONNECT_GRACE: Duration = Duration::from_secs(4);

#[derive(Clone)]
pub(crate) struct CancellationToken {
    inner: Arc<CancellationInner>,
}

struct CancellationInner {
    cancelled: AtomicBool,
    notify: Notify,
}

impl CancellationToken {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(CancellationInner {
                cancelled: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }

    pub(crate) fn cancel(&self) {
        if !self.inner.cancelled.swap(true, Ordering::SeqCst) {
            self.inner.notify.notify_waiters();
        }
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::SeqCst)
    }

    pub(crate) async fn cancelled(&self) {
        while !self.is_cancelled() {
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_cancelled() {
                break;
            }
            notified.await;
        }
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CancellationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CancellationToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelOptions {
    length: u8,
    quantity: u8,
}

impl TunnelOptions {
    pub fn new(length: u8, quantity: u8) -> Result<Self, SamError> {
        if !(MIN_TUNNEL_LENGTH..=MAX_TUNNEL_LENGTH).contains(&length) {
            return Err(SamError::InvalidTunnelLength(length));
        }
        if !(MIN_TUNNEL_QUANTITY..=MAX_TUNNEL_QUANTITY).contains(&quantity) {
            return Err(SamError::InvalidTunnelQuantity(quantity));
        }
        Ok(Self { length, quantity })
    }

    pub fn length(self) -> u8 {
        self.length
    }

    pub fn quantity(self) -> u8 {
        self.quantity
    }
}

impl Default for TunnelOptions {
    fn default() -> Self {
        Self {
            length: DEFAULT_TUNNEL_LENGTH,
            quantity: DEFAULT_TUNNEL_QUANTITY,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum SamSessionKind {
    Transient,
    Persistent { private_destination: String },
}

impl fmt::Debug for SamSessionKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transient => formatter.write_str("Transient"),
            Self::Persistent { .. } => formatter
                .debug_struct("Persistent")
                .field("private_destination", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SamSessionConfig {
    session_id: String,
    kind: SamSessionKind,
    tunnels: TunnelOptions,
}

impl fmt::Debug for SamSessionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SamSessionConfig")
            .field("session_id", &self.session_id)
            .field("kind", &self.kind)
            .field("tunnels", &self.tunnels)
            .finish()
    }
}

impl SamSessionConfig {
    pub fn transient(
        session_id: impl Into<String>,
        tunnels: TunnelOptions,
    ) -> Result<Self, SamError> {
        Self::new(session_id.into(), SamSessionKind::Transient, tunnels)
    }

    pub fn persistent(
        session_id: impl Into<String>,
        private_destination: impl Into<String>,
        tunnels: TunnelOptions,
    ) -> Result<Self, SamError> {
        Self::new(
            session_id.into(),
            SamSessionKind::Persistent {
                private_destination: private_destination.into(),
            },
            tunnels,
        )
    }

    fn new(
        session_id: String,
        kind: SamSessionKind,
        tunnels: TunnelOptions,
    ) -> Result<Self, SamError> {
        validate_token("session id", &session_id, MAX_SESSION_ID_SIZE)?;
        if let SamSessionKind::Persistent {
            private_destination,
        } = &kind
        {
            validate_token(
                "private destination",
                private_destination,
                MAX_DESTINATION_SIZE,
            )?;
        }
        Ok(Self {
            session_id,
            kind,
            tunnels,
        })
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn kind(&self) -> &SamSessionKind {
        &self.kind
    }

    pub fn tunnels(&self) -> TunnelOptions {
        self.tunnels
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SamSessionInfo {
    pub session_id: String,
    pub private_destination: String,
    pub public_destination: String,
    pub b32: String,
}

impl fmt::Debug for SamSessionInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SamSessionInfo")
            .field("session_id", &self.session_id)
            .field("private_destination", &"<redacted>")
            .field("public_destination", &self.public_destination)
            .field("b32", &self.b32)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SamReply {
    command: Vec<String>,
    fields: BTreeMap<String, String>,
}

impl fmt::Debug for SamReply {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fields = self
            .fields
            .iter()
            .map(|(key, value)| {
                (
                    key.as_str(),
                    if key == "PRIV" {
                        "<redacted>"
                    } else {
                        value.as_str()
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        formatter
            .debug_struct("SamReply")
            .field("command", &self.command)
            .field("fields", &fields)
            .finish()
    }
}

impl SamReply {
    pub fn parse(line: &str) -> Result<Self, SamError> {
        if line.is_empty() || line.len() > MAX_SAM_LINE_SIZE {
            return Err(SamError::MalformedReply);
        }
        let mut command = Vec::new();
        let mut fields = BTreeMap::new();
        for token in tokenize_reply(line)? {
            if let Some((key, value)) = token.split_once('=') {
                if key.is_empty() || fields.insert(key.to_string(), value.to_string()).is_some() {
                    return Err(SamError::MalformedReply);
                }
            } else {
                command.push(token);
            }
        }
        if command.is_empty() {
            return Err(SamError::MalformedReply);
        }
        Ok(Self { command, fields })
    }

    pub fn command(&self) -> &[String] {
        &self.command
    }

    pub fn field(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }

    pub fn is_ok(&self) -> bool {
        self.field("RESULT") == Some("OK")
    }

    fn require_ok(&self, operation: &'static str) -> Result<(), SamError> {
        if self.is_ok() {
            return Ok(());
        }
        Err(SamError::Rejected {
            operation,
            result: self.field("RESULT").unwrap_or("UNKNOWN").to_string(),
            message: self.field("MESSAGE").map(str::to_string),
        })
    }
}

#[derive(Clone)]
pub(crate) struct SamClient {
    endpoint: SamEndpoint,
    state: Arc<Mutex<ClientState>>,
}

struct ClientState {
    session_id: Option<String>,
    control: Option<SamControl>,
}

struct SamControl {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
}

pub(crate) struct SamStreamParts {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
}

impl SamClient {
    pub(crate) fn new(endpoint: SamEndpoint) -> Self {
        Self {
            endpoint,
            state: Arc::new(Mutex::new(ClientState {
                session_id: None,
                control: None,
            })),
        }
    }

    pub(crate) fn endpoint(&self) -> &SamEndpoint {
        &self.endpoint
    }

    pub(crate) async fn session_id(&self) -> Option<String> {
        self.state.lock().await.session_id.clone()
    }

    pub(crate) async fn test_endpoint(endpoint: &SamEndpoint) -> Result<SamReply, SamError> {
        let stream = TcpStream::connect((endpoint.host(), endpoint.port())).await?;
        let (read_half, mut writer) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        send_hello(&mut writer).await?;
        let reply = read_reply(&mut reader).await?;
        reply.require_ok("HELLO")?;
        let _ = writer.shutdown().await;
        Ok(reply)
    }

    pub(crate) async fn create_session_cancelled(
        &self,
        config: &SamSessionConfig,
        cancellation: &CancellationToken,
    ) -> Result<SamSessionInfo, SamError> {
        let mut state = tokio::select! {
            state = self.state.lock() => state,
            _ = cancellation.cancelled() => return Err(SamError::Cancelled),
        };
        if state.control.is_some() {
            return Err(SamError::SessionAlreadyInitialized);
        }

        let stream = connect_cancelled(&self.endpoint, cancellation).await?;
        let (read_half, writer) = stream.into_split();
        let mut control = SamControl {
            reader: BufReader::new(read_half),
            writer,
        };
        hello_cancelled(&mut control.reader, &mut control.writer, cancellation).await?;

        let private_destination = match config.kind() {
            SamSessionKind::Transient => {
                cancellation.check()?;
                write_command(&mut control.writer, "DEST GENERATE SIGNATURE_TYPE=7").await?;
                let reply = read_reply_cancelled(&mut control.reader, cancellation).await?;
                reply
                    .field("PRIV")
                    .ok_or(SamError::MissingField("PRIV"))?
                    .to_string()
            }
            SamSessionKind::Persistent {
                private_destination,
            } => private_destination.clone(),
        };
        validate_token(
            "private destination",
            &private_destination,
            MAX_DESTINATION_SIZE,
        )?;

        let tunnels = config.tunnels();
        let command = format!(
            "SESSION CREATE STYLE=STREAM ID={} DESTINATION={} SIGNATURE_TYPE=7 OPTION inbound.length={} outbound.length={} inbound.quantity={} outbound.quantity={}",
            config.session_id(),
            private_destination,
            tunnels.length(),
            tunnels.length(),
            tunnels.quantity(),
            tunnels.quantity(),
        );
        cancellation.check()?;
        write_command(&mut control.writer, &command).await?;
        read_reply_cancelled(&mut control.reader, cancellation)
            .await?
            .require_ok("SESSION CREATE")?;

        cancellation.check()?;
        write_command(&mut control.writer, "NAMING LOOKUP NAME=ME").await?;
        let lookup = read_reply_cancelled(&mut control.reader, cancellation).await?;
        lookup.require_ok("NAMING LOOKUP")?;
        let public_destination = lookup
            .field("VALUE")
            .ok_or(SamError::MissingField("VALUE"))?
            .to_string();
        let b32 = destination_to_b32(&public_destination)?;

        state.session_id = Some(config.session_id().to_string());
        state.control = Some(control);
        Ok(SamSessionInfo {
            session_id: config.session_id().to_string(),
            private_destination,
            public_destination,
            b32,
        })
    }

    pub(crate) async fn naming_lookup(
        &self,
        name: &str,
        cancellation: &CancellationToken,
    ) -> Result<String, SamError> {
        validate_token("lookup name", name, MAX_DESTINATION_SIZE)?;
        let mut state = tokio::select! {
            state = self.state.lock() => state,
            _ = cancellation.cancelled() => return Err(SamError::Cancelled),
        };
        let control = state
            .control
            .as_mut()
            .ok_or(SamError::SessionNotInitialized)?;
        cancellation.check()?;
        write_command(&mut control.writer, &format!("NAMING LOOKUP NAME={name}")).await?;
        let reply = read_reply_cancelled(&mut control.reader, cancellation).await?;
        reply.require_ok("NAMING LOOKUP")?;
        Ok(reply
            .field("VALUE")
            .ok_or(SamError::MissingField("VALUE"))?
            .to_string())
    }

    pub(crate) async fn stream_connect(
        &self,
        destination: &str,
        cancellation: &CancellationToken,
    ) -> Result<SamStreamParts, SamError> {
        validate_token("stream destination", destination, MAX_DESTINATION_SIZE)?;
        let session_id = self
            .session_id()
            .await
            .ok_or(SamError::SessionNotInitialized)?;
        let stream = connect_cancelled(&self.endpoint, cancellation).await?;
        let (read_half, mut writer) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        hello_cancelled(&mut reader, &mut writer, cancellation).await?;
        cancellation.check()?;
        write_command(
            &mut writer,
            &format!("STREAM CONNECT ID={session_id} DESTINATION={destination}"),
        )
        .await?;

        let reply = match read_reply_cancelled(&mut reader, cancellation).await {
            Ok(reply) => reply,
            Err(SamError::Cancelled) => {
                if let Ok(Ok(reply)) =
                    timeout(CANCELLED_CONNECT_GRACE, read_reply(&mut reader)).await
                {
                    if reply.is_ok() {
                        let _ = writer.shutdown().await;
                        return Err(SamError::Cancelled);
                    }
                }
                let _ = writer.shutdown().await;
                return Err(SamError::Cancelled);
            }
            Err(error) => {
                let _ = writer.shutdown().await;
                return Err(error);
            }
        };
        if let Err(error) = reply.require_ok("STREAM CONNECT") {
            let _ = writer.shutdown().await;
            return Err(error);
        }
        if cancellation.is_cancelled() {
            let _ = writer.shutdown().await;
            return Err(SamError::Cancelled);
        }
        Ok(SamStreamParts { reader, writer })
    }

    pub(crate) async fn stream_accept_with_armed_signal(
        &self,
        cancellation: &CancellationToken,
        armed: Option<oneshot::Sender<()>>,
    ) -> Result<AcceptedIncoming, SamError> {
        let session_id = self
            .session_id()
            .await
            .ok_or(SamError::SessionNotInitialized)?;
        let stream = connect_cancelled(&self.endpoint, cancellation).await?;
        let (read_half, mut writer) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        hello_cancelled(&mut reader, &mut writer, cancellation).await?;
        cancellation.check()?;
        write_command(&mut writer, &format!("STREAM ACCEPT ID={session_id}")).await?;
        let reply = read_reply_cancelled(&mut reader, cancellation).await?;
        reply.require_ok("STREAM ACCEPT")?;
        if let Some(armed) = armed {
            let _ = armed.send(());
        }
        let peer_destination = read_line_cancelled(&mut reader, cancellation).await?;
        let peer_b32 = destination_to_b32(&peer_destination)?;
        Ok(AcceptedIncoming {
            peer_destination,
            peer_b32,
            connection: LiveConnection::new(SamStreamParts { reader, writer }),
        })
    }

    pub(crate) async fn close(&self) -> Result<(), SamError> {
        let control = {
            let mut state = self.state.lock().await;
            state.session_id = None;
            state.control.take()
        };
        if let Some(mut control) = control {
            control.writer.shutdown().await?;
        }
        Ok(())
    }
}

impl fmt::Debug for SamClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SamClient")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct AcceptedIncoming {
    pub peer_destination: String,
    pub peer_b32: String,
    pub connection: LiveConnection,
}

#[derive(Clone)]
pub struct LiveConnection {
    inner: Arc<LiveConnectionInner>,
}

struct LiveConnectionInner {
    writer: Mutex<tokio::net::tcp::OwnedWriteHalf>,
    incoming: StdMutex<VecDeque<Frame>>,
    reader_error: StdMutex<Option<String>>,
    closed: AtomicBool,
    closing: AtomicBool,
    notify: Notify,
    queue_space: Notify,
    reader_task: StdMutex<Option<JoinHandle<()>>>,
}

impl LiveConnection {
    pub(crate) fn new(parts: SamStreamParts) -> Self {
        let SamStreamParts { reader, writer } = parts;
        let inner = Arc::new(LiveConnectionInner {
            writer: Mutex::new(writer),
            incoming: StdMutex::new(VecDeque::new()),
            reader_error: StdMutex::new(None),
            closed: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            notify: Notify::new(),
            queue_space: Notify::new(),
            reader_task: StdMutex::new(None),
        });
        let reader_inner = Arc::clone(&inner);
        let task = tokio::spawn(async move {
            let mut reader = reader;
            'reader: loop {
                match Frame::read_from(&mut reader).await {
                    Ok(frame) => {
                        let mut pending = Some(frame);
                        loop {
                            let space_available = reader_inner.queue_space.notified();
                            tokio::pin!(space_available);
                            space_available.as_mut().enable();
                            let queued = match reader_inner.incoming.lock() {
                                Ok(mut queue) if queue.len() < MAX_QUEUED_FRAMES => {
                                    queue.push_back(
                                        pending.take().expect("pending frame was not queued"),
                                    );
                                    true
                                }
                                Ok(_) => false,
                                Err(_) => {
                                    if let Ok(mut error) = reader_inner.reader_error.lock() {
                                        *error =
                                            Some("incoming frame queue lock failed".to_string());
                                    }
                                    break 'reader;
                                }
                            };
                            if queued {
                                reader_inner.notify.notify_waiters();
                                break;
                            }
                            if reader_inner.closing.load(Ordering::SeqCst) {
                                break 'reader;
                            }
                            space_available.await;
                        }
                    }
                    Err(error) => {
                        if let Ok(mut stored) = reader_inner.reader_error.lock() {
                            *stored = Some(error.to_string());
                        }
                        break;
                    }
                }
            }
            reader_inner.closed.store(true, Ordering::SeqCst);
            reader_inner.notify.notify_waiters();
        });
        if let Ok(mut reader_task) = inner.reader_task.lock() {
            *reader_task = Some(task);
        }
        Self { inner }
    }

    pub(crate) async fn send_destination_prelude(&self, destination: &str) -> Result<(), SamError> {
        validate_token("destination prelude", destination, MAX_DESTINATION_SIZE)?;
        self.write_bytes(format!("{destination}\n").as_bytes())
            .await
    }

    pub(crate) async fn send_frame(&self, frame: &Frame) -> Result<(), SamError> {
        if self.is_closed() {
            return Err(self.closed_error());
        }
        let mut writer = self.inner.writer.lock().await;
        frame.write_to(&mut *writer).await?;
        writer.flush().await?;
        Ok(())
    }

    pub fn try_recv_frame(&self) -> Option<Frame> {
        let frame = self.inner.incoming.lock().ok()?.pop_front();
        if frame.is_some() {
            self.inner.queue_space.notify_one();
        }
        frame
    }

    pub async fn recv_frame(&self) -> Result<Frame, SamError> {
        loop {
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(frame) = self.try_recv_frame() {
                return Ok(frame);
            }
            if self.is_closed() {
                return Err(self.closed_error());
            }
            notified.await;
        }
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    pub fn has_pending_frames(&self) -> bool {
        self.inner
            .incoming
            .lock()
            .map(|queue| !queue.is_empty())
            .unwrap_or(false)
    }

    pub(crate) async fn close(&self) -> Result<(), SamError> {
        if self.inner.closing.swap(true, Ordering::SeqCst) {
            self.wait_closed().await;
            return Ok(());
        }
        self.inner.queue_space.notify_waiters();
        let shutdown_result = {
            let mut writer = self.inner.writer.lock().await;
            let _ = writer.flush().await;
            writer.shutdown().await.map_err(SamError::from)
        };
        let reader_task = self
            .inner
            .reader_task
            .lock()
            .ok()
            .and_then(|mut task| task.take());
        if let Some(reader_task) = reader_task {
            reader_task.abort();
            let _ = timeout(READER_JOIN_TIMEOUT, reader_task).await;
        }
        self.inner.closed.store(true, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
        shutdown_result
    }

    pub(crate) fn same_stream(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    async fn write_bytes(&self, bytes: &[u8]) -> Result<(), SamError> {
        if self.is_closed() {
            return Err(self.closed_error());
        }
        let mut writer = self.inner.writer.lock().await;
        writer.write_all(bytes).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn wait_closed(&self) {
        while !self.is_closed() {
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_closed() {
                break;
            }
            notified.await;
        }
    }

    fn closed_error(&self) -> SamError {
        let detail = self
            .inner
            .reader_error
            .lock()
            .ok()
            .and_then(|error| error.clone())
            .unwrap_or_else(|| "stream is closed".to_string());
        SamError::ConnectionClosed(detail)
    }
}

#[derive(Clone)]
pub(crate) struct SamByteStream {
    inner: Arc<SamByteStreamInner>,
}

struct SamByteStreamInner {
    reader: Mutex<BufReader<tokio::net::tcp::OwnedReadHalf>>,
    writer: Mutex<tokio::net::tcp::OwnedWriteHalf>,
    closed: AtomicBool,
    closing: AtomicBool,
    notify: Notify,
}

impl SamByteStream {
    pub(crate) fn new(parts: SamStreamParts) -> Self {
        Self {
            inner: Arc::new(SamByteStreamInner {
                reader: Mutex::new(parts.reader),
                writer: Mutex::new(parts.writer),
                closed: AtomicBool::new(false),
                closing: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    pub(crate) async fn write_all(&self, bytes: &[u8]) -> Result<(), SamError> {
        if self.is_closed() {
            return Err(SamError::ConnectionClosed("stream is closed".to_string()));
        }
        let mut writer = self.inner.writer.lock().await;
        writer.write_all(bytes).await?;
        writer.flush().await?;
        Ok(())
    }

    pub(crate) async fn read_line(&self) -> Result<String, SamError> {
        if self.is_closed() {
            return Err(SamError::ConnectionClosed("stream is closed".to_string()));
        }
        let result = read_line(&mut *self.inner.reader.lock().await).await;
        if result.is_err() {
            self.mark_closed();
        }
        result
    }

    pub(crate) async fn read_exact(&self, size: usize) -> Result<Vec<u8>, SamError> {
        if self.is_closed() {
            return Err(SamError::ConnectionClosed("stream is closed".to_string()));
        }
        let mut bytes = vec![0u8; size];
        let result = self.inner.reader.lock().await.read_exact(&mut bytes).await;
        match result {
            Ok(_) => Ok(bytes),
            Err(error) => {
                self.mark_closed();
                Err(SamError::Io(error))
            }
        }
    }

    pub(crate) async fn close(&self) -> Result<(), SamError> {
        if self.inner.closing.swap(true, Ordering::SeqCst) {
            self.wait_closed().await;
            return Ok(());
        }
        let result = self
            .inner
            .writer
            .lock()
            .await
            .shutdown()
            .await
            .map_err(SamError::from);
        self.mark_closed();
        result
    }

    pub(crate) fn same_stream(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    fn mark_closed(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }

    async fn wait_closed(&self) {
        while !self.is_closed() {
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_closed() {
                break;
            }
            notified.await;
        }
    }
}

impl fmt::Debug for SamByteStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SamByteStream")
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for LiveConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiveConnection")
            .field("closed", &self.is_closed())
            .field("pending_frames", &self.has_pending_frames())
            .finish_non_exhaustive()
    }
}

pub fn destination_to_b32(destination: &str) -> Result<String, SamError> {
    validate_token("I2P destination", destination, MAX_DESTINATION_SIZE)?;
    let mut standard = destination.replace('-', "+").replace('~', "/");
    while standard.len() % 4 != 0 {
        standard.push('=');
    }
    let raw = general_purpose::STANDARD
        .decode(standard)
        .map_err(|_| SamError::InvalidDestination)?;
    let digest = Sha256::digest(raw);
    Ok(format!(
        "{}.b32.i2p",
        BASE32_NOPAD.encode(&digest).to_ascii_lowercase()
    ))
}

async fn connect_cancelled(
    endpoint: &SamEndpoint,
    cancellation: &CancellationToken,
) -> Result<TcpStream, SamError> {
    cancellation.check()?;
    tokio::select! {
        result = TcpStream::connect((endpoint.host(), endpoint.port())) => Ok(result?),
        _ = cancellation.cancelled() => Err(SamError::Cancelled),
    }
}

async fn hello_cancelled(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    cancellation: &CancellationToken,
) -> Result<(), SamError> {
    cancellation.check()?;
    send_hello(writer).await?;
    read_reply_cancelled(reader, cancellation)
        .await?
        .require_ok("HELLO")
}

async fn send_hello(writer: &mut tokio::net::tcp::OwnedWriteHalf) -> Result<(), SamError> {
    write_command(
        writer,
        &format!("HELLO VERSION MIN={SAM_MIN_VERSION} MAX={SAM_MAX_VERSION}"),
    )
    .await
}

async fn write_command(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    command: &str,
) -> Result<(), SamError> {
    if command.contains('\r') || command.contains('\n') {
        return Err(SamError::InvalidCommand);
    }
    let mut framed = Vec::with_capacity(command.len() + 1);
    framed.extend_from_slice(command.as_bytes());
    framed.push(b'\n');
    writer.write_all(&framed).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_reply<R>(reader: &mut R) -> Result<SamReply, SamError>
where
    R: AsyncBufRead + Unpin,
{
    SamReply::parse(&read_line(reader).await?)
}

async fn read_reply_cancelled<R>(
    reader: &mut R,
    cancellation: &CancellationToken,
) -> Result<SamReply, SamError>
where
    R: AsyncBufRead + Unpin,
{
    SamReply::parse(&read_line_cancelled(reader, cancellation).await?)
}

async fn read_line<R>(reader: &mut R) -> Result<String, SamError>
where
    R: AsyncBufRead + Unpin,
{
    let mut bytes = Vec::new();
    loop {
        let buffer = reader.fill_buf().await?;
        if buffer.is_empty() {
            return Err(SamError::UnexpectedEof);
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let consumed = newline.unwrap_or(buffer.len());
        if bytes.len().saturating_add(consumed) > MAX_SAM_LINE_SIZE {
            return Err(SamError::ReplyTooLarge);
        }
        bytes.extend_from_slice(&buffer[..consumed]);
        reader.consume(consumed + if newline.is_some() { 1 } else { 0 });
        if newline.is_some() {
            break;
        }
    }
    String::from_utf8(bytes)
        .map(|line| line.trim_end_matches('\r').to_string())
        .map_err(|_| SamError::MalformedReply)
}

async fn read_line_cancelled<R>(
    reader: &mut R,
    cancellation: &CancellationToken,
) -> Result<String, SamError>
where
    R: AsyncBufRead + Unpin,
{
    let mut bytes = Vec::new();
    loop {
        cancellation.check()?;
        let buffer = tokio::select! {
            result = reader.fill_buf() => result?,
            _ = cancellation.cancelled() => return Err(SamError::Cancelled),
        };
        if buffer.is_empty() {
            return Err(SamError::UnexpectedEof);
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let consumed = newline.unwrap_or(buffer.len());
        if bytes.len().saturating_add(consumed) > MAX_SAM_LINE_SIZE {
            return Err(SamError::ReplyTooLarge);
        }
        bytes.extend_from_slice(&buffer[..consumed]);
        reader.consume(consumed + if newline.is_some() { 1 } else { 0 });
        if newline.is_some() {
            break;
        }
    }
    String::from_utf8(bytes)
        .map(|line| line.trim_end_matches('\r').to_string())
        .map_err(|_| SamError::MalformedReply)
}

fn tokenize_reply(line: &str) -> Result<Vec<String>, SamError> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for character in line.chars() {
        if escaped {
            token.push(character);
            escaped = false;
        } else if character == '\\' && quoted {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if character.is_whitespace() && !quoted {
            if !token.is_empty() {
                tokens.push(std::mem::take(&mut token));
            }
        } else {
            token.push(character);
        }
    }
    if escaped || quoted {
        return Err(SamError::MalformedReply);
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    Ok(tokens)
}

fn validate_token(label: &'static str, value: &str, max_len: usize) -> Result<(), SamError> {
    if value.is_empty()
        || value.len() > max_len
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(SamError::InvalidValue(label));
    }
    Ok(())
}

impl CancellationToken {
    fn check(&self) -> Result<(), SamError> {
        if self.is_cancelled() {
            Err(SamError::Cancelled)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Error)]
pub enum SamError {
    #[error("SAM I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("SAM operation was cancelled")]
    Cancelled,
    #[error("SAM session is not initialized")]
    SessionNotInitialized,
    #[error("SAM session is already initialized")]
    SessionAlreadyInitialized,
    #[error("SAM rejected {operation}: result={result}, message={message:?}")]
    Rejected {
        operation: &'static str,
        result: String,
        message: Option<String>,
    },
    #[error("SAM reply is malformed")]
    MalformedReply,
    #[error("SAM reply exceeds the size limit")]
    ReplyTooLarge,
    #[error("SAM closed the socket unexpectedly")]
    UnexpectedEof,
    #[error("SAM reply is missing field {0}")]
    MissingField(&'static str),
    #[error("invalid SAM command")]
    InvalidCommand,
    #[error("invalid {0}")]
    InvalidValue(&'static str),
    #[error("invalid I2P destination")]
    InvalidDestination,
    #[error("tunnel length must be between {MIN_TUNNEL_LENGTH} and {MAX_TUNNEL_LENGTH}, got {0}")]
    InvalidTunnelLength(u8),
    #[error(
        "tunnel quantity must be between {MIN_TUNNEL_QUANTITY} and {MAX_TUNNEL_QUANTITY}, got {0}"
    )]
    InvalidTunnelQuantity(u8),
    #[error("SAM stream closed: {0}")]
    ConnectionClosed(String),
    #[error("invalid CommTools frame on SAM stream: {0}")]
    Frame(#[from] crate::protocol::ProtocolError),
    #[error("SAM runtime is closing")]
    RuntimeClosing,
    #[error("SAM runtime shutdown timed out")]
    ShutdownTimeout,
}
