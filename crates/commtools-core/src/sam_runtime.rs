use crate::config::SamEndpoint;
use crate::protocol::Frame;
use crate::sam::{
    AcceptedIncoming, CancellationToken, LiveConnection, SamByteStream, SamClient, SamError,
    SamReply, SamSessionConfig, SamSessionInfo,
};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::{Notify, oneshot};
use tokio::time::timeout;

const OPERATION_SHUTDOWN_GRACE: Duration = Duration::from_millis(4_500);

/// Owns one SAM session and every stream or in-flight SAM operation belonging
/// to it. Chat policy, handshakes, E2E state, and collision decisions remain in
/// higher layers.
#[derive(Clone)]
pub struct SamRuntime {
    inner: Arc<RuntimeInner>,
}

struct RuntimeInner {
    client: SamClient,
    operations: Arc<OperationRegistry>,
    streams: StdMutex<Vec<RegisteredStream>>,
    closing: AtomicBool,
    shutdown_started: AtomicBool,
    closed: AtomicBool,
    closed_notify: Notify,
}

impl SamRuntime {
    pub fn new(endpoint: SamEndpoint) -> Self {
        Self {
            inner: Arc::new(RuntimeInner {
                client: SamClient::new(endpoint),
                operations: Arc::new(OperationRegistry::new()),
                streams: StdMutex::new(Vec::new()),
                closing: AtomicBool::new(false),
                shutdown_started: AtomicBool::new(false),
                closed: AtomicBool::new(false),
                closed_notify: Notify::new(),
            }),
        }
    }

    pub fn endpoint(&self) -> &SamEndpoint {
        self.inner.client.endpoint()
    }

    pub async fn test_endpoint(endpoint: &SamEndpoint) -> Result<SamReply, SamError> {
        SamClient::test_endpoint(endpoint).await
    }

    pub fn is_closing(&self) -> bool {
        self.inner.closing.load(Ordering::SeqCst)
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    pub fn active_operation_count(&self) -> usize {
        self.inner.operations.active_count()
    }

    pub fn registered_stream_count(&self) -> usize {
        self.inner
            .streams
            .lock()
            .map(|streams| streams.len())
            .unwrap_or(0)
    }

    pub async fn session_id(&self) -> Option<String> {
        self.inner.client.session_id().await
    }

    pub async fn create_session(
        &self,
        config: &SamSessionConfig,
    ) -> Result<SamSessionInfo, SamError> {
        let (cancellation, _operation) = self.begin_operation()?;
        let result = self
            .inner
            .client
            .create_session_cancelled(config, &cancellation)
            .await;
        if self.is_closing() {
            let _ = self.inner.client.close().await;
            return Err(SamError::RuntimeClosing);
        }
        result
    }

    pub async fn naming_lookup(&self, name: &str) -> Result<String, SamError> {
        let (cancellation, _operation) = self.begin_operation()?;
        self.inner.client.naming_lookup(name, &cancellation).await
    }

    pub async fn connect(&self, destination: &str) -> Result<LiveConnection, SamError> {
        let (cancellation, _operation) = self.begin_operation()?;
        let parts = self
            .inner
            .client
            .stream_connect(destination, &cancellation)
            .await?;
        let connection = LiveConnection::new(parts);
        if !self.register_live_if_open(&connection) {
            let _ = connection.close().await;
            return Err(SamError::RuntimeClosing);
        }
        Ok(connection)
    }

    pub(crate) async fn connect_byte_stream(
        &self,
        destination: &str,
    ) -> Result<SamByteStream, SamError> {
        let (cancellation, _operation) = self.begin_operation()?;
        let parts = self
            .inner
            .client
            .stream_connect(destination, &cancellation)
            .await?;
        let stream = SamByteStream::new(parts);
        if !self.register_byte_if_open(&stream) {
            let _ = stream.close().await;
            return Err(SamError::RuntimeClosing);
        }
        Ok(stream)
    }

    pub async fn accept(&self) -> Result<AcceptedIncoming, SamError> {
        self.accept_inner(None).await
    }

    pub async fn accept_with_armed_signal(
        &self,
        armed: oneshot::Sender<()>,
    ) -> Result<AcceptedIncoming, SamError> {
        self.accept_inner(Some(armed)).await
    }

    async fn accept_inner(
        &self,
        armed: Option<oneshot::Sender<()>>,
    ) -> Result<AcceptedIncoming, SamError> {
        let (cancellation, _operation) = self.begin_operation()?;
        let incoming = self
            .inner
            .client
            .stream_accept_with_armed_signal(&cancellation, armed)
            .await?;
        if !self.register_live_if_open(&incoming.connection) {
            let _ = incoming.connection.close().await;
            return Err(SamError::RuntimeClosing);
        }
        Ok(incoming)
    }

    pub async fn send_destination_prelude(
        &self,
        connection: &LiveConnection,
        destination: &str,
    ) -> Result<(), SamError> {
        let (cancellation, _operation) = self.begin_operation()?;
        tokio::select! {
            result = connection.send_destination_prelude(destination) => result,
            _ = cancellation.cancelled() => Err(SamError::Cancelled),
        }
    }

    pub async fn send_frame(
        &self,
        connection: &LiveConnection,
        frame: &Frame,
    ) -> Result<(), SamError> {
        let (cancellation, _operation) = self.begin_operation()?;
        tokio::select! {
            result = connection.send_frame(frame) => result,
            _ = cancellation.cancelled() => Err(SamError::Cancelled),
        }
    }

    pub(crate) async fn write_bytes(
        &self,
        stream: &SamByteStream,
        bytes: &[u8],
    ) -> Result<(), SamError> {
        let (cancellation, _operation) = self.begin_operation()?;
        tokio::select! {
            result = stream.write_all(bytes) => result,
            _ = cancellation.cancelled() => Err(SamError::Cancelled),
        }
    }

    pub(crate) async fn read_byte_line(&self, stream: &SamByteStream) -> Result<String, SamError> {
        let (cancellation, _operation) = self.begin_operation()?;
        tokio::select! {
            result = stream.read_line() => result,
            _ = cancellation.cancelled() => Err(SamError::Cancelled),
        }
    }

    pub(crate) async fn read_bytes_exact(
        &self,
        stream: &SamByteStream,
        size: usize,
    ) -> Result<Vec<u8>, SamError> {
        let (cancellation, _operation) = self.begin_operation()?;
        tokio::select! {
            result = stream.read_exact(size) => result,
            _ = cancellation.cancelled() => Err(SamError::Cancelled),
        }
    }

    pub async fn close_stream(&self, connection: &LiveConnection) -> Result<(), SamError> {
        if let Ok(mut streams) = self.inner.streams.lock() {
            streams.retain(|registered| !registered.same_live(connection));
        }
        connection.close().await
    }

    pub(crate) async fn close_byte_stream(&self, stream: &SamByteStream) -> Result<(), SamError> {
        if let Ok(mut streams) = self.inner.streams.lock() {
            streams.retain(|registered| !registered.same_byte(stream));
        }
        stream.close().await
    }

    /// Stops new work, cooperatively cancels pending SAM commands, waits for a
    /// cancelled STREAM CONNECT to drain its late SAM reply, closes all known
    /// streams, and finally closes the control socket that owns the session.
    pub async fn shutdown(&self) -> Result<(), SamError> {
        self.inner.closing.store(true, Ordering::SeqCst);
        if self
            .inner
            .shutdown_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            self.wait_closed().await;
            return Ok(());
        }

        self.inner.operations.cancel_all();
        let operations_finished = self
            .inner
            .operations
            .wait_idle(OPERATION_SHUTDOWN_GRACE)
            .await;

        let streams = self
            .inner
            .streams
            .lock()
            .map(|mut streams| std::mem::take(&mut *streams))
            .unwrap_or_default();
        let mut first_error = None;
        for stream in streams {
            if let Err(error) = stream.close().await {
                first_error.get_or_insert(error);
            }
        }
        if let Err(error) = self.inner.client.close().await {
            first_error.get_or_insert(error);
        }

        self.inner.closed.store(true, Ordering::SeqCst);
        self.inner.closed_notify.notify_waiters();

        if !operations_finished {
            return Err(SamError::ShutdownTimeout);
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }

    fn begin_operation(&self) -> Result<(CancellationToken, OperationGuard), SamError> {
        if self.is_closing() {
            return Err(SamError::RuntimeClosing);
        }
        let (cancellation, operation) = self.inner.operations.start();
        if self.is_closing() {
            cancellation.cancel();
            drop(operation);
            return Err(SamError::RuntimeClosing);
        }
        Ok((cancellation, operation))
    }

    fn register_live_if_open(&self, connection: &LiveConnection) -> bool {
        let Ok(mut streams) = self.inner.streams.lock() else {
            return false;
        };
        if self.is_closing() {
            return false;
        }
        if !streams
            .iter()
            .any(|registered| registered.same_live(connection))
        {
            streams.push(RegisteredStream::Live(connection.clone()));
        }
        true
    }

    fn register_byte_if_open(&self, stream: &SamByteStream) -> bool {
        let Ok(mut streams) = self.inner.streams.lock() else {
            return false;
        };
        if self.is_closing() {
            return false;
        }
        if !streams
            .iter()
            .any(|registered| registered.same_byte(stream))
        {
            streams.push(RegisteredStream::Byte(stream.clone()));
        }
        true
    }

    async fn wait_closed(&self) {
        while !self.is_closed() {
            let notified = self.inner.closed_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_closed() {
                break;
            }
            notified.await;
        }
    }
}

#[derive(Clone)]
enum RegisteredStream {
    Live(LiveConnection),
    Byte(SamByteStream),
}

impl RegisteredStream {
    fn same_live(&self, connection: &LiveConnection) -> bool {
        matches!(self, Self::Live(registered) if registered.same_stream(connection))
    }

    fn same_byte(&self, stream: &SamByteStream) -> bool {
        matches!(self, Self::Byte(registered) if registered.same_stream(stream))
    }

    async fn close(self) -> Result<(), SamError> {
        match self {
            Self::Live(connection) => connection.close().await,
            Self::Byte(stream) => stream.close().await,
        }
    }
}

impl std::fmt::Debug for SamRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SamRuntime")
            .field("endpoint", self.endpoint())
            .field("closing", &self.is_closing())
            .field("closed", &self.is_closed())
            .field("active_operations", &self.active_operation_count())
            .field("registered_streams", &self.registered_stream_count())
            .finish()
    }
}

struct OperationRegistry {
    next_id: AtomicU64,
    active: AtomicUsize,
    tokens: StdMutex<Vec<(u64, CancellationToken)>>,
    idle_notify: Notify,
}

impl OperationRegistry {
    fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            active: AtomicUsize::new(0),
            tokens: StdMutex::new(Vec::new()),
            idle_notify: Notify::new(),
        }
    }

    fn start(self: &Arc<Self>) -> (CancellationToken, OperationGuard) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let token = CancellationToken::new();
        self.active.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut tokens) = self.tokens.lock() {
            tokens.push((id, token.clone()));
        }
        (
            token,
            OperationGuard {
                id,
                registry: Arc::clone(self),
            },
        )
    }

    fn active_count(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    fn cancel_all(&self) {
        let tokens = self
            .tokens
            .lock()
            .map(|tokens| {
                tokens
                    .iter()
                    .map(|(_, token)| token.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for token in tokens {
            token.cancel();
        }
    }

    async fn wait_idle(&self, duration: Duration) -> bool {
        timeout(duration, async {
            while self.active_count() != 0 {
                let notified = self.idle_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.active_count() == 0 {
                    break;
                }
                notified.await;
            }
        })
        .await
        .is_ok()
    }

    fn finish(&self, id: u64) {
        if let Ok(mut tokens) = self.tokens.lock() {
            tokens.retain(|(token_id, _)| *token_id != id);
        }
        if self.active.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.idle_notify.notify_waiters();
        }
    }
}

struct OperationGuard {
    id: u64,
    registry: Arc<OperationRegistry>,
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        self.registry.finish(self.id);
    }
}
