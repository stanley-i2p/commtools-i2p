use crate::constants::MAX_FRAME_PAYLOAD_SIZE;
use crate::crypto::{CryptoError, SessionCrypto};
use crate::protocol::{Frame, MessageType};
use crate::sam::{SamError, destination_to_b32};
use std::collections::BTreeSet;
use std::fmt;
use thiserror::Error;

pub const HEARTBEAT_PING_INTERVAL_MS: u64 = 10_000;
pub const HEARTBEAT_TIMEOUT_MS: u64 = 35_000;
pub const ONE_TO_ONE_HANDSHAKE_TIMEOUT_MS: u64 = 45_000;
pub const ONE_TO_ONE_CONNECT_RETRY_MS: u64 = 5_000;
pub const ONE_TO_ONE_CONNECT_TIMEOUT_MS: u64 = 120_000;
pub const GRACEFUL_CLOSE_DELAY_MS: u64 = 120;

pub const SIGNAL_PREFIX: &str = "__SIGNAL__:";
pub const QUIT_SIGNAL: &str = "__SIGNAL__:QUIT";
pub const HEARTBEAT_PING_PREFIX: &str = "__SIGNAL__:PING:";
pub const HEARTBEAT_PONG_PREFIX: &str = "__SIGNAL__:PONG:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(u64);

impl ConnectionId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OneToOnePhase {
    Standby,
    Connecting,
    IncomingPending,
    Handshaking,
    Ready,
    Closing,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollisionWinner {
    Existing,
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
    LocalRequest,
    PeerQuit,
    HeartbeatTimeout,
    HandshakeTimeout,
    TransportClosed,
    IdentityMismatch,
    TofuMismatch,
    ProtocolViolation,
    Shutdown,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PinnedPeer {
    b32: String,
    destination: String,
}

impl PinnedPeer {
    pub fn new(destination: impl Into<String>) -> Result<Self, OneToOneError> {
        let destination = destination.into();
        let b32 = destination_to_b32(&destination)?;
        Ok(Self { b32, destination })
    }

    pub fn b32(&self) -> &str {
        &self.b32
    }

    pub fn destination(&self) -> &str {
        &self.destination
    }
}

impl fmt::Debug for PinnedPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedPeer")
            .field("b32", &self.b32)
            .field("destination", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct OneToOneConfig {
    local_b32: String,
    local_destination: String,
    pinned_peer: Option<PinnedPeer>,
    control_message_seed: u64,
}

impl fmt::Debug for OneToOneConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OneToOneConfig")
            .field("local_b32", &self.local_b32)
            .field("local_destination", &"<redacted>")
            .field("pinned_peer", &self.pinned_peer)
            .field("control_message_seed", &self.control_message_seed)
            .finish()
    }
}

impl OneToOneConfig {
    pub fn new(
        local_destination: impl Into<String>,
        pinned_peer: Option<PinnedPeer>,
    ) -> Result<Self, OneToOneError> {
        let local_destination = local_destination.into();
        let local_b32 = destination_to_b32(&local_destination)?;
        if pinned_peer
            .as_ref()
            .is_some_and(|peer| peer.b32 == local_b32)
        {
            return Err(OneToOneError::IdenticalIdentities);
        }
        Ok(Self {
            local_b32,
            local_destination,
            pinned_peer,
            control_message_seed: 1,
        })
    }

    pub fn with_control_message_seed(mut self, seed: u64) -> Self {
        self.control_message_seed = seed.max(1);
        self
    }

    pub fn local_b32(&self) -> &str {
        &self.local_b32
    }

    pub fn local_destination(&self) -> &str {
        &self.local_destination
    }

    pub fn pinned_peer(&self) -> Option<&PinnedPeer> {
        self.pinned_peer.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OneToOneAction {
    Connect {
        attempt_id: u64,
        peer_b32: String,
    },
    CancelConnect {
        attempt_id: u64,
    },
    SendHandshake {
        connection_id: ConnectionId,
        destination_prelude: Option<String>,
        frames: Vec<Frame>,
    },
    SendFrame {
        connection_id: ConnectionId,
        frame: Frame,
    },
    CloseConnection {
        connection_id: ConnectionId,
    },
    NotifyAndClose {
        connection_id: ConnectionId,
        frame: Frame,
        delay_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OneToOneEvent {
    PhaseChanged(OneToOnePhase),
    IncomingCall {
        connection_id: ConnectionId,
        peer_b32: String,
    },
    CollisionResolved {
        winner: CollisionWinner,
        kept_connection: Option<ConnectionId>,
        closed_connection: Option<ConnectionId>,
    },
    IdentityVerified {
        connection_id: ConnectionId,
        peer_b32: String,
        pinned: bool,
    },
    SecureSessionReady {
        connection_id: ConnectionId,
        peer_b32: String,
    },
    ApplicationFrame {
        connection_id: ConnectionId,
        frame: Frame,
    },
    ControlSignal {
        connection_id: ConnectionId,
        signal: String,
    },
    FrameRejected {
        connection_id: ConnectionId,
        reason: String,
    },
    ConnectionRejected {
        connection_id: ConnectionId,
        reason: DisconnectReason,
    },
    ConnectFailed {
        attempt_id: u64,
        peer_b32: String,
        reason: String,
    },
    ConnectRetryScheduled {
        attempt_id: u64,
        peer_b32: String,
        reason: String,
    },
    Disconnected {
        peer_b32: Option<String>,
        reason: DisconnectReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OneToOneOutput {
    pub actions: Vec<OneToOneAction>,
    pub events: Vec<OneToOneEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectAttempt {
    id: u64,
    peer_b32: String,
    pre_handshake_signals: Vec<String>,
    started_ms: u64,
    last_attempt_ms: u64,
    in_flight: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerConnection {
    id: ConnectionId,
    direction: ConnectionDirection,
    peer_b32: String,
    peer_destination: Option<String>,
    handshake_started_ms: u64,
    identity_received: bool,
    peer_key: Option<[u8; 32]>,
}

pub struct OneToOneSession {
    config: OneToOneConfig,
    phase: OneToOnePhase,
    active: Option<PeerConnection>,
    pending: Option<PeerConnection>,
    connect_attempt: Option<ConnectAttempt>,
    closing_connections: BTreeSet<ConnectionId>,
    crypto: SessionCrypto,
    heartbeat_last_rx_ms: u64,
    heartbeat_last_ping_ms: u64,
    next_attempt_id: u64,
    next_control_message_id: u64,
}

/// A narrowly scoped snapshot of ready-session crypto for streaming file frames.
/// It cannot create handshake, chat, image, delivery, or heartbeat frames.
#[derive(Clone)]
pub struct FileFrameSealer {
    crypto: SessionCrypto,
}

impl FileFrameSealer {
    pub fn seal(
        &self,
        message_type: MessageType,
        plaintext: &[u8],
    ) -> Result<Frame, OneToOneError> {
        self.seal_with_message_id(message_type, 0, plaintext)
    }

    pub fn seal_with_message_id(
        &self,
        message_type: MessageType,
        message_id: u64,
        plaintext: &[u8],
    ) -> Result<Frame, OneToOneError> {
        match message_type {
            MessageType::F | MessageType::C => Ok(Frame::new(
                message_type,
                message_id,
                self.crypto.seal(plaintext)?,
            )),
            MessageType::E if plaintext.is_empty() => {
                Ok(Frame::new(MessageType::E, message_id, Vec::new()))
            }
            MessageType::E => Err(OneToOneError::InvalidFileTerminator),
            _ => Err(OneToOneError::InvalidFileFrameType(message_type)),
        }
    }
}

impl OneToOneSession {
    pub fn new(config: OneToOneConfig) -> Self {
        let next_control_message_id = config.control_message_seed;
        Self {
            config,
            phase: OneToOnePhase::Standby,
            active: None,
            pending: None,
            connect_attempt: None,
            closing_connections: BTreeSet::new(),
            crypto: SessionCrypto::generate(),
            heartbeat_last_rx_ms: 0,
            heartbeat_last_ping_ms: 0,
            next_attempt_id: 1,
            next_control_message_id,
        }
    }

    pub fn config(&self) -> &OneToOneConfig {
        &self.config
    }

    pub fn phase(&self) -> OneToOnePhase {
        self.phase
    }

    pub fn active_connection_id(&self) -> Option<ConnectionId> {
        self.active.as_ref().map(|peer| peer.id)
    }

    pub fn pending_connection_id(&self) -> Option<ConnectionId> {
        self.pending.as_ref().map(|peer| peer.id)
    }

    pub fn active_peer_b32(&self) -> Option<&str> {
        self.active.as_ref().map(|peer| peer.peer_b32.as_str())
    }

    pub fn peer_b32_for_connection(&self, connection_id: ConnectionId) -> Option<&str> {
        self.active
            .as_ref()
            .filter(|peer| peer.id == connection_id)
            .or_else(|| {
                self.pending
                    .as_ref()
                    .filter(|peer| peer.id == connection_id)
            })
            .map(|peer| peer.peer_b32.as_str())
    }

    pub fn active_peer_destination(&self) -> Option<&str> {
        self.active
            .as_ref()
            .and_then(|peer| peer.peer_destination.as_deref())
    }

    pub fn active_peer_pin_candidate(&self) -> Result<PinnedPeer, OneToOneError> {
        if !self.is_ready() {
            return Err(OneToOneError::SessionNotReady);
        }
        if self.config.pinned_peer.is_some() {
            return Err(OneToOneError::PeerAlreadyPinned);
        }
        let peer = self.active.as_ref().ok_or(OneToOneError::SessionNotReady)?;
        let destination = peer
            .peer_destination
            .as_ref()
            .ok_or(OneToOneError::PeerIdentityUnavailable)?;
        let pin = PinnedPeer::new(destination.clone())?;
        if pin.b32 != peer.peer_b32 {
            return Err(OneToOneError::TofuMismatch);
        }
        Ok(pin)
    }

    pub fn pin_active_peer(&mut self, pin: PinnedPeer) -> Result<(), OneToOneError> {
        let candidate = self.active_peer_pin_candidate()?;
        if candidate != pin {
            return Err(OneToOneError::TofuMismatch);
        }
        self.config.pinned_peer = Some(pin);
        Ok(())
    }

    pub fn connection_direction(&self) -> Option<ConnectionDirection> {
        self.active
            .as_ref()
            .or(self.pending.as_ref())
            .map(|peer| peer.direction)
    }

    pub fn is_ready(&self) -> bool {
        self.phase == OneToOnePhase::Ready && self.crypto.is_ready()
    }

    pub fn begin_connect(&mut self, peer_b32: &str) -> Result<OneToOneOutput, OneToOneError> {
        self.begin_connect_at(peer_b32, 0)
    }

    pub fn begin_connect_at(
        &mut self,
        peer_b32: &str,
        now_ms: u64,
    ) -> Result<OneToOneOutput, OneToOneError> {
        self.begin_connect_with_control_signals_at(peer_b32, Vec::new(), now_ms)
    }

    pub fn begin_connect_with_control_signals(
        &mut self,
        peer_b32: &str,
        pre_handshake_signals: Vec<String>,
    ) -> Result<OneToOneOutput, OneToOneError> {
        self.begin_connect_with_control_signals_at(peer_b32, pre_handshake_signals, 0)
    }

    pub fn begin_connect_with_control_signals_at(
        &mut self,
        peer_b32: &str,
        pre_handshake_signals: Vec<String>,
        now_ms: u64,
    ) -> Result<OneToOneOutput, OneToOneError> {
        self.ensure_open()?;
        if self.phase != OneToOnePhase::Standby
            || self.active.is_some()
            || self.pending.is_some()
            || self.connect_attempt.is_some()
        {
            return Err(OneToOneError::Busy(self.phase));
        }
        let peer_b32 = normalize_b32(peer_b32)?;
        self.ensure_allowed_peer(&peer_b32, None)?;
        for signal in &pre_handshake_signals {
            validate_control_signal(signal)?;
        }

        let attempt_id = self.next_attempt_id;
        self.next_attempt_id = next_nonzero(self.next_attempt_id);
        self.connect_attempt = Some(ConnectAttempt {
            id: attempt_id,
            peer_b32: peer_b32.clone(),
            pre_handshake_signals,
            started_ms: now_ms,
            last_attempt_ms: now_ms,
            in_flight: true,
        });

        let mut output = OneToOneOutput::default();
        self.set_phase(OneToOnePhase::Connecting, &mut output);
        output.actions.push(OneToOneAction::Connect {
            attempt_id,
            peer_b32,
        });
        Ok(output)
    }

    pub fn outbound_connected(
        &mut self,
        attempt_id: u64,
        connection_id: ConnectionId,
        peer_b32: &str,
        now_ms: u64,
    ) -> OneToOneOutput {
        let mut output = OneToOneOutput::default();
        let Ok(peer_b32) = normalize_b32(peer_b32) else {
            self.reject_candidate(
                connection_id,
                DisconnectReason::IdentityMismatch,
                &mut output,
            );
            return output;
        };
        let Some(attempt) = self.connect_attempt.clone() else {
            output
                .actions
                .push(OneToOneAction::CloseConnection { connection_id });
            return output;
        };
        if self.phase == OneToOnePhase::Closed
            || attempt.id != attempt_id
            || attempt.peer_b32 != peer_b32
        {
            output
                .actions
                .push(OneToOneAction::CloseConnection { connection_id });
            return output;
        }
        self.connect_attempt = None;

        if let Some(active) = &self.active {
            output.events.push(OneToOneEvent::CollisionResolved {
                winner: CollisionWinner::Existing,
                kept_connection: Some(active.id),
                closed_connection: Some(connection_id),
            });
            output
                .actions
                .push(OneToOneAction::CloseConnection { connection_id });
            return output;
        }

        if let Some(pending) = self.pending.clone() {
            let same_peer = pending.peer_b32 == peer_b32;
            if !same_peer || !self.local_prefers_outbound(&peer_b32) {
                output.events.push(OneToOneEvent::CollisionResolved {
                    winner: CollisionWinner::Inbound,
                    kept_connection: Some(pending.id),
                    closed_connection: Some(connection_id),
                });
                output
                    .actions
                    .push(OneToOneAction::CloseConnection { connection_id });
                self.set_phase(OneToOnePhase::IncomingPending, &mut output);
                return output;
            }

            self.pending = None;
            output.events.push(OneToOneEvent::CollisionResolved {
                winner: CollisionWinner::Outbound,
                kept_connection: Some(connection_id),
                closed_connection: Some(pending.id),
            });
            output.actions.push(OneToOneAction::CloseConnection {
                connection_id: pending.id,
            });
        }

        self.install_outbound(
            connection_id,
            peer_b32,
            &attempt.pre_handshake_signals,
            now_ms,
            &mut output,
        );
        output
    }

    pub fn outbound_failed(
        &mut self,
        attempt_id: u64,
        reason: impl Into<String>,
    ) -> OneToOneOutput {
        self.outbound_failed_at(attempt_id, reason, 0)
    }

    pub fn outbound_failed_at(
        &mut self,
        attempt_id: u64,
        reason: impl Into<String>,
        now_ms: u64,
    ) -> OneToOneOutput {
        let mut output = OneToOneOutput::default();
        let Some(attempt) = self.connect_attempt.as_mut() else {
            return output;
        };
        if attempt.id != attempt_id {
            return output;
        }
        let reason = reason.into();
        if attempt.started_ms == 0 {
            attempt.started_ms = now_ms.max(1);
        }
        if now_ms != 0
            && is_retryable_connect_failure(&reason)
            && now_ms.saturating_sub(attempt.started_ms) < ONE_TO_ONE_CONNECT_TIMEOUT_MS
        {
            attempt.in_flight = false;
            attempt.last_attempt_ms = now_ms;
            output.events.push(OneToOneEvent::ConnectRetryScheduled {
                attempt_id,
                peer_b32: attempt.peer_b32.clone(),
                reason,
            });
            return output;
        }
        let peer_b32 = attempt.peer_b32.clone();
        self.connect_attempt = None;
        output.events.push(OneToOneEvent::ConnectFailed {
            attempt_id,
            peer_b32,
            reason,
        });
        self.set_phase(OneToOnePhase::Standby, &mut output);
        output
    }

    pub fn incoming_connected(
        &mut self,
        connection_id: ConnectionId,
        peer_b32: &str,
        peer_destination: &str,
        now_ms: u64,
    ) -> OneToOneOutput {
        let mut output = OneToOneOutput::default();
        if self.phase == OneToOnePhase::Closed || self.phase == OneToOnePhase::Closing {
            output
                .actions
                .push(OneToOneAction::CloseConnection { connection_id });
            return output;
        }

        let peer_b32 = match normalize_b32(peer_b32) {
            Ok(peer_b32) => peer_b32,
            Err(_) => {
                self.reject_candidate(
                    connection_id,
                    DisconnectReason::IdentityMismatch,
                    &mut output,
                );
                return output;
            }
        };
        let derived_b32 = match destination_to_b32(peer_destination) {
            Ok(derived_b32) => derived_b32,
            Err(_) => {
                self.reject_candidate(
                    connection_id,
                    DisconnectReason::IdentityMismatch,
                    &mut output,
                );
                return output;
            }
        };
        if derived_b32 != peer_b32 {
            self.reject_candidate(
                connection_id,
                DisconnectReason::IdentityMismatch,
                &mut output,
            );
            return output;
        }
        if let Err(error) = self.ensure_allowed_peer(&peer_b32, Some(peer_destination)) {
            let reason = match error {
                OneToOneError::TofuMismatch => DisconnectReason::TofuMismatch,
                _ => DisconnectReason::IdentityMismatch,
            };
            self.reject_candidate(connection_id, reason, &mut output);
            return output;
        }

        if let Some(active) = self.active.clone() {
            let replace_outbound = self.phase != OneToOnePhase::Ready
                && active.direction == ConnectionDirection::Outbound
                && active.peer_b32 == peer_b32
                && !self.local_prefers_outbound(&peer_b32);
            if replace_outbound {
                self.active = None;
                self.crypto = SessionCrypto::generate();
                self.reset_heartbeat();
                output.events.push(OneToOneEvent::CollisionResolved {
                    winner: CollisionWinner::Inbound,
                    kept_connection: Some(connection_id),
                    closed_connection: Some(active.id),
                });
                output.actions.push(OneToOneAction::CloseConnection {
                    connection_id: active.id,
                });
            } else {
                output.events.push(OneToOneEvent::CollisionResolved {
                    winner: CollisionWinner::Existing,
                    kept_connection: Some(active.id),
                    closed_connection: Some(connection_id),
                });
                output
                    .actions
                    .push(OneToOneAction::CloseConnection { connection_id });
                return output;
            }
        }
        if let Some(pending) = &self.pending {
            output.events.push(OneToOneEvent::CollisionResolved {
                winner: CollisionWinner::Existing,
                kept_connection: Some(pending.id),
                closed_connection: Some(connection_id),
            });
            output
                .actions
                .push(OneToOneAction::CloseConnection { connection_id });
            return output;
        }

        if let Some(attempt) = self.connect_attempt.clone() {
            let same_peer = attempt.peer_b32 == peer_b32;
            if !same_peer || self.local_prefers_outbound(&peer_b32) {
                output.events.push(OneToOneEvent::CollisionResolved {
                    winner: CollisionWinner::Outbound,
                    kept_connection: None,
                    closed_connection: Some(connection_id),
                });
                output
                    .actions
                    .push(OneToOneAction::CloseConnection { connection_id });
                return output;
            }

            self.connect_attempt = None;
            output.actions.push(OneToOneAction::CancelConnect {
                attempt_id: attempt.id,
            });
            output.events.push(OneToOneEvent::CollisionResolved {
                winner: CollisionWinner::Inbound,
                kept_connection: Some(connection_id),
                closed_connection: None,
            });
        }

        self.crypto = SessionCrypto::generate();
        self.pending = Some(PeerConnection {
            id: connection_id,
            direction: ConnectionDirection::Inbound,
            peer_b32: peer_b32.clone(),
            peer_destination: Some(peer_destination.to_string()),
            handshake_started_ms: now_ms,
            identity_received: false,
            peer_key: None,
        });
        self.reset_heartbeat();
        self.set_phase(OneToOnePhase::IncomingPending, &mut output);
        output.events.push(OneToOneEvent::IncomingCall {
            connection_id,
            peer_b32,
        });
        output
    }

    pub fn accept_incoming(&mut self, now_ms: u64) -> Result<OneToOneOutput, OneToOneError> {
        self.ensure_open()?;
        let mut peer = self
            .pending
            .take()
            .ok_or(OneToOneError::NoPendingIncoming)?;
        peer.handshake_started_ms = now_ms;
        let connection_id = peer.id;
        self.active = Some(peer);

        let mut output = OneToOneOutput::default();
        self.set_phase(OneToOnePhase::Handshaking, &mut output);
        output
            .actions
            .push(self.handshake_action(connection_id, false, &[]));
        self.maybe_mark_ready(now_ms, &mut output);
        Ok(output)
    }

    pub fn decline_incoming(&mut self) -> Result<OneToOneOutput, OneToOneError> {
        self.ensure_open()?;
        let peer = self
            .pending
            .take()
            .ok_or(OneToOneError::NoPendingIncoming)?;
        self.crypto = SessionCrypto::generate();
        self.closing_connections.insert(peer.id);

        let mut output = OneToOneOutput::default();
        output.actions.push(OneToOneAction::NotifyAndClose {
            connection_id: peer.id,
            frame: self.signal_frame(QUIT_SIGNAL),
            delay_ms: GRACEFUL_CLOSE_DELAY_MS,
        });
        output.events.push(OneToOneEvent::ConnectionRejected {
            connection_id: peer.id,
            reason: DisconnectReason::LocalRequest,
        });
        self.set_phase(OneToOnePhase::Closing, &mut output);
        Ok(output)
    }

    pub fn receive_frame(
        &mut self,
        connection_id: ConnectionId,
        frame: Frame,
        now_ms: u64,
    ) -> OneToOneOutput {
        let mut output = OneToOneOutput::default();
        let is_active = self
            .active
            .as_ref()
            .is_some_and(|peer| peer.id == connection_id);
        let is_pending = self
            .pending
            .as_ref()
            .is_some_and(|peer| peer.id == connection_id);
        if !is_active && !is_pending {
            output.events.push(OneToOneEvent::FrameRejected {
                connection_id,
                reason: "frame belongs to an inactive connection".to_string(),
            });
            return output;
        }
        if is_active && self.phase == OneToOnePhase::Ready {
            self.heartbeat_last_rx_ms = now_ms;
        }

        match frame.message_type {
            MessageType::S => self.handle_signal_frame(connection_id, frame, now_ms, &mut output),
            MessageType::K => self.handle_key_frame(connection_id, frame, now_ms, &mut output),
            _ if is_active && self.phase == OneToOnePhase::Ready => {
                output.events.push(OneToOneEvent::ApplicationFrame {
                    connection_id,
                    frame,
                });
            }
            _ => output.events.push(OneToOneEvent::FrameRejected {
                connection_id,
                reason: "application frame received before the secure session was ready"
                    .to_string(),
            }),
        }
        output
    }

    pub fn seal_application_frame(
        &self,
        message_type: MessageType,
        message_id: u64,
        plaintext: &[u8],
    ) -> Result<Frame, OneToOneError> {
        if !self.is_ready() {
            return Err(OneToOneError::SessionNotReady);
        }
        if matches!(message_type, MessageType::S | MessageType::K) {
            return Err(OneToOneError::ReservedControlFrame(message_type));
        }
        // Delivery acknowledgements are deliberately small, validated control payloads.
        if message_type == MessageType::D {
            validate_delivery_acknowledgement(plaintext)?;
            return Ok(Frame::new(message_type, message_id, plaintext));
        }
        if matches!(message_type, MessageType::E | MessageType::Z) {
            if !plaintext.is_empty() {
                return Err(if message_type == MessageType::E {
                    OneToOneError::InvalidFileTerminator
                } else {
                    OneToOneError::InvalidImageTerminator
                });
            }
            return Ok(Frame::new(message_type, message_id, Vec::new()));
        }
        Ok(Frame::new(
            message_type,
            message_id,
            self.crypto.seal(plaintext)?,
        ))
    }

    pub fn file_frame_sealer(&self) -> Result<FileFrameSealer, OneToOneError> {
        if !self.is_ready() {
            return Err(OneToOneError::SessionNotReady);
        }
        Ok(FileFrameSealer {
            crypto: self.crypto.clone(),
        })
    }

    pub fn open_application_frame(&self, frame: &Frame) -> Result<Frame, OneToOneError> {
        if !self.is_ready() {
            return Err(OneToOneError::SessionNotReady);
        }
        if matches!(frame.message_type, MessageType::S | MessageType::K) {
            return Err(OneToOneError::ReservedControlFrame(frame.message_type));
        }

        if frame.message_type == MessageType::D {
            validate_delivery_acknowledgement(&frame.payload)?;
            return Ok(frame.clone());
        }
        if matches!(frame.message_type, MessageType::E | MessageType::Z) {
            if !frame.payload.is_empty() {
                return Err(if frame.message_type == MessageType::E {
                    OneToOneError::InvalidFileTerminator
                } else {
                    OneToOneError::InvalidImageTerminator
                });
            }
            return Ok(frame.clone());
        }
        Ok(Frame::new(
            frame.message_type,
            frame.message_id,
            self.crypto.open(&frame.payload)?,
        ))
    }

    pub fn send_control_signal(&mut self, signal: &str) -> Result<OneToOneOutput, OneToOneError> {
        if !self.is_ready() {
            return Err(OneToOneError::SessionNotReady);
        }
        validate_control_signal(signal)?;
        let connection_id = self
            .active_connection_id()
            .ok_or(OneToOneError::SessionNotReady)?;
        let frame = self.signal_frame(signal);
        Ok(OneToOneOutput {
            actions: vec![OneToOneAction::SendFrame {
                connection_id,
                frame,
            }],
            events: Vec::new(),
        })
    }

    pub fn reject_connection(
        &mut self,
        connection_id: ConnectionId,
        reason: DisconnectReason,
    ) -> OneToOneOutput {
        let mut output = OneToOneOutput::default();
        if self
            .active
            .as_ref()
            .is_some_and(|peer| peer.id == connection_id)
        {
            self.terminate_active(reason, false, &mut output);
        } else if self
            .pending
            .as_ref()
            .is_some_and(|peer| peer.id == connection_id)
        {
            self.terminate_pending(reason, &mut output);
        }
        output
    }

    pub fn tick(&mut self, now_ms: u64) -> OneToOneOutput {
        let mut output = OneToOneOutput::default();
        if let Some(attempt) = self.connect_attempt.as_mut() {
            if attempt.started_ms == 0 {
                attempt.started_ms = now_ms.max(1);
            }
            if now_ms.saturating_sub(attempt.started_ms) >= ONE_TO_ONE_CONNECT_TIMEOUT_MS {
                let attempt = self
                    .connect_attempt
                    .take()
                    .expect("connect attempt was just inspected");
                if attempt.in_flight {
                    output.actions.push(OneToOneAction::CancelConnect {
                        attempt_id: attempt.id,
                    });
                }
                output.events.push(OneToOneEvent::ConnectFailed {
                    attempt_id: attempt.id,
                    peer_b32: attempt.peer_b32,
                    reason: "connection deadline expired while waiting for the peer LeaseSet"
                        .into(),
                });
                self.set_phase(OneToOnePhase::Standby, &mut output);
                return output;
            }
            if !attempt.in_flight
                && now_ms.saturating_sub(attempt.last_attempt_ms) >= ONE_TO_ONE_CONNECT_RETRY_MS
            {
                let attempt_id = self.next_attempt_id;
                self.next_attempt_id = next_nonzero(self.next_attempt_id);
                attempt.id = attempt_id;
                attempt.last_attempt_ms = now_ms;
                attempt.in_flight = true;
                output.actions.push(OneToOneAction::Connect {
                    attempt_id,
                    peer_b32: attempt.peer_b32.clone(),
                });
            }
        }
        let Some(active) = self.active.as_ref() else {
            return output;
        };
        let connection_id = active.id;
        let handshake_started_ms = active.handshake_started_ms;

        if self.phase == OneToOnePhase::Handshaking
            && now_ms.saturating_sub(handshake_started_ms) >= ONE_TO_ONE_HANDSHAKE_TIMEOUT_MS
        {
            self.terminate_active(DisconnectReason::HandshakeTimeout, false, &mut output);
            return output;
        }
        if self.phase != OneToOnePhase::Ready {
            return output;
        }

        if now_ms.saturating_sub(self.heartbeat_last_rx_ms) >= HEARTBEAT_TIMEOUT_MS {
            self.terminate_active(DisconnectReason::HeartbeatTimeout, false, &mut output);
        } else if now_ms.saturating_sub(self.heartbeat_last_ping_ms) >= HEARTBEAT_PING_INTERVAL_MS
            && now_ms.saturating_sub(self.heartbeat_last_rx_ms) >= HEARTBEAT_PING_INTERVAL_MS
        {
            let message_id = self.next_message_id();
            self.heartbeat_last_ping_ms = now_ms;
            output.actions.push(OneToOneAction::SendFrame {
                connection_id,
                frame: Frame::new(
                    MessageType::S,
                    message_id,
                    format!("{HEARTBEAT_PING_PREFIX}{message_id:016x}"),
                ),
            });
        }
        output
    }

    pub fn disconnect(&mut self) -> OneToOneOutput {
        let mut output = OneToOneOutput::default();
        if let Some(attempt) = self.connect_attempt.take() {
            output.actions.push(OneToOneAction::CancelConnect {
                attempt_id: attempt.id,
            });
        }
        self.queue_graceful_close(DisconnectReason::LocalRequest, &mut output);
        if self.closing_connections.is_empty() {
            self.set_phase(OneToOnePhase::Standby, &mut output);
        } else {
            self.set_phase(OneToOnePhase::Closing, &mut output);
        }
        output
    }

    pub fn begin_shutdown(&mut self) -> OneToOneOutput {
        let mut output = OneToOneOutput::default();
        if let Some(attempt) = self.connect_attempt.take() {
            output.actions.push(OneToOneAction::CancelConnect {
                attempt_id: attempt.id,
            });
        }
        self.queue_graceful_close(DisconnectReason::Shutdown, &mut output);
        self.set_phase(OneToOnePhase::Closed, &mut output);
        output
    }

    pub fn connection_closed(&mut self, connection_id: ConnectionId) -> OneToOneOutput {
        let mut output = OneToOneOutput::default();
        if self.closing_connections.remove(&connection_id) {
            if self.phase == OneToOnePhase::Closing && self.closing_connections.is_empty() {
                self.set_phase(OneToOnePhase::Standby, &mut output);
            }
            return output;
        }

        if self
            .active
            .as_ref()
            .is_some_and(|peer| peer.id == connection_id)
        {
            let peer_b32 = self.active.take().map(|peer| peer.peer_b32);
            self.crypto = SessionCrypto::generate();
            self.reset_heartbeat();
            output.events.push(OneToOneEvent::Disconnected {
                peer_b32,
                reason: DisconnectReason::TransportClosed,
            });
            self.set_phase(OneToOnePhase::Standby, &mut output);
        } else if self
            .pending
            .as_ref()
            .is_some_and(|peer| peer.id == connection_id)
        {
            self.pending = None;
            self.crypto = SessionCrypto::generate();
            self.reset_heartbeat();
            self.set_phase(OneToOnePhase::Standby, &mut output);
        }
        output
    }

    fn install_outbound(
        &mut self,
        connection_id: ConnectionId,
        peer_b32: String,
        pre_handshake_signals: &[String],
        now_ms: u64,
        output: &mut OneToOneOutput,
    ) {
        self.crypto = SessionCrypto::generate();
        self.active = Some(PeerConnection {
            id: connection_id,
            direction: ConnectionDirection::Outbound,
            peer_b32,
            peer_destination: None,
            handshake_started_ms: now_ms,
            identity_received: false,
            peer_key: None,
        });
        self.reset_heartbeat();
        self.set_phase(OneToOnePhase::Handshaking, output);
        output
            .actions
            .push(self.handshake_action(connection_id, true, pre_handshake_signals));
    }

    fn handshake_action(
        &mut self,
        connection_id: ConnectionId,
        include_destination_prelude: bool,
        pre_handshake_signals: &[String],
    ) -> OneToOneAction {
        let mut frames = pre_handshake_signals
            .iter()
            .map(|signal| Frame::new(MessageType::S, self.next_message_id(), signal.clone()))
            .collect::<Vec<_>>();
        let identity_frame = Frame::new(
            MessageType::S,
            self.next_message_id(),
            self.config.local_destination.clone(),
        );
        let key_frame = Frame::new(
            MessageType::K,
            self.next_message_id(),
            self.crypto.public_key_bytes(),
        );
        frames.push(identity_frame);
        frames.push(key_frame);
        OneToOneAction::SendHandshake {
            connection_id,
            destination_prelude: include_destination_prelude
                .then(|| self.config.local_destination.clone()),
            frames,
        }
    }

    fn handle_signal_frame(
        &mut self,
        connection_id: ConnectionId,
        frame: Frame,
        now_ms: u64,
        output: &mut OneToOneOutput,
    ) {
        let Ok(body) = String::from_utf8(frame.payload) else {
            self.reject_live_protocol(
                connection_id,
                DisconnectReason::ProtocolViolation,
                "signal payload is not valid UTF-8",
                output,
            );
            return;
        };

        if body == QUIT_SIGNAL {
            if self
                .active
                .as_ref()
                .is_some_and(|peer| peer.id == connection_id)
            {
                self.terminate_active(DisconnectReason::PeerQuit, false, output);
            } else {
                self.terminate_pending(DisconnectReason::PeerQuit, output);
            }
            return;
        }

        if let Some(nonce) = body.strip_prefix(HEARTBEAT_PING_PREFIX) {
            if self
                .active
                .as_ref()
                .is_some_and(|peer| peer.id == connection_id)
                && self.phase == OneToOnePhase::Ready
            {
                output.actions.push(OneToOneAction::SendFrame {
                    connection_id,
                    frame: Frame::new(
                        MessageType::S,
                        self.next_message_id(),
                        format!("{HEARTBEAT_PONG_PREFIX}{nonce}"),
                    ),
                });
            } else {
                output.events.push(OneToOneEvent::FrameRejected {
                    connection_id,
                    reason: "heartbeat received before the secure session was ready".to_string(),
                });
            }
            return;
        }
        if body.starts_with(HEARTBEAT_PONG_PREFIX) {
            if self.phase != OneToOnePhase::Ready {
                output.events.push(OneToOneEvent::FrameRejected {
                    connection_id,
                    reason: "heartbeat received before the secure session was ready".to_string(),
                });
            }
            return;
        }
        if body.starts_with(SIGNAL_PREFIX) {
            output.events.push(OneToOneEvent::ControlSignal {
                connection_id,
                signal: body,
            });
            return;
        }

        let peer_b32 = match destination_to_b32(&body) {
            Ok(peer_b32) => peer_b32,
            Err(_) => {
                self.reject_live_protocol(
                    connection_id,
                    DisconnectReason::IdentityMismatch,
                    "peer identity is not a valid I2P destination",
                    output,
                );
                return;
            }
        };
        let expected = self
            .active
            .as_ref()
            .filter(|peer| peer.id == connection_id)
            .or_else(|| {
                self.pending
                    .as_ref()
                    .filter(|peer| peer.id == connection_id)
            });
        let Some(expected) = expected else {
            return;
        };
        if expected.peer_b32 != peer_b32
            || expected
                .peer_destination
                .as_ref()
                .is_some_and(|destination| destination != &body)
        {
            self.reject_live_protocol(
                connection_id,
                DisconnectReason::IdentityMismatch,
                "framed identity does not match the stream peer",
                output,
            );
            return;
        }
        if let Some(pinned) = &self.config.pinned_peer {
            if pinned.b32 != peer_b32 || pinned.destination != body {
                self.reject_live_protocol(
                    connection_id,
                    DisconnectReason::TofuMismatch,
                    "peer identity does not match the pinned destination",
                    output,
                );
                return;
            }
        }

        if let Some(peer) = self.peer_mut(connection_id) {
            peer.peer_destination = Some(body);
            peer.identity_received = true;
        }
        output.events.push(OneToOneEvent::IdentityVerified {
            connection_id,
            peer_b32,
            pinned: self.config.pinned_peer.is_some(),
        });
        self.maybe_mark_ready(now_ms, output);
    }

    fn handle_key_frame(
        &mut self,
        connection_id: ConnectionId,
        frame: Frame,
        now_ms: u64,
        output: &mut OneToOneOutput,
    ) {
        let peer_key: [u8; 32] = match frame.payload.as_slice().try_into() {
            Ok(peer_key) => peer_key,
            Err(_) => {
                self.reject_live_protocol(
                    connection_id,
                    DisconnectReason::ProtocolViolation,
                    "peer key must be exactly 32 bytes",
                    output,
                );
                return;
            }
        };
        if let Some(existing) = self.peer(connection_id).and_then(|peer| peer.peer_key) {
            if existing != peer_key {
                self.reject_live_protocol(
                    connection_id,
                    DisconnectReason::ProtocolViolation,
                    "peer changed its key during the handshake",
                    output,
                );
            }
            return;
        }
        if self.crypto.receive_peer_key(&peer_key).is_err() {
            self.reject_live_protocol(
                connection_id,
                DisconnectReason::ProtocolViolation,
                "peer supplied an invalid key",
                output,
            );
            return;
        }
        if let Some(peer) = self.peer_mut(connection_id) {
            peer.peer_key = Some(peer_key);
        }
        self.maybe_mark_ready(now_ms, output);
    }

    fn maybe_mark_ready(&mut self, now_ms: u64, output: &mut OneToOneOutput) {
        let Some(active) = self.active.as_ref() else {
            return;
        };
        if self.phase == OneToOnePhase::Ready
            || !active.identity_received
            || active.peer_key.is_none()
            || !self.crypto.is_ready()
        {
            return;
        }
        let connection_id = active.id;
        let peer_b32 = active.peer_b32.clone();
        self.heartbeat_last_rx_ms = now_ms;
        self.heartbeat_last_ping_ms = now_ms;
        self.set_phase(OneToOnePhase::Ready, output);
        output.events.push(OneToOneEvent::SecureSessionReady {
            connection_id,
            peer_b32,
        });
    }

    fn reject_live_protocol(
        &mut self,
        connection_id: ConnectionId,
        reason: DisconnectReason,
        detail: &str,
        output: &mut OneToOneOutput,
    ) {
        output.events.push(OneToOneEvent::FrameRejected {
            connection_id,
            reason: detail.to_string(),
        });
        if self
            .active
            .as_ref()
            .is_some_and(|peer| peer.id == connection_id)
        {
            self.terminate_active(reason, false, output);
        } else if self
            .pending
            .as_ref()
            .is_some_and(|peer| peer.id == connection_id)
        {
            self.terminate_pending(reason, output);
        }
    }

    fn reject_candidate(
        &self,
        connection_id: ConnectionId,
        reason: DisconnectReason,
        output: &mut OneToOneOutput,
    ) {
        output
            .actions
            .push(OneToOneAction::CloseConnection { connection_id });
        output.events.push(OneToOneEvent::ConnectionRejected {
            connection_id,
            reason,
        });
    }

    fn terminate_active(
        &mut self,
        reason: DisconnectReason,
        notify_peer: bool,
        output: &mut OneToOneOutput,
    ) {
        let Some(peer) = self.active.take() else {
            return;
        };
        self.crypto = SessionCrypto::generate();
        self.reset_heartbeat();
        self.closing_connections.insert(peer.id);
        if notify_peer {
            output.actions.push(OneToOneAction::NotifyAndClose {
                connection_id: peer.id,
                frame: self.signal_frame(QUIT_SIGNAL),
                delay_ms: GRACEFUL_CLOSE_DELAY_MS,
            });
        } else {
            output.actions.push(OneToOneAction::CloseConnection {
                connection_id: peer.id,
            });
        }
        output.events.push(OneToOneEvent::Disconnected {
            peer_b32: Some(peer.peer_b32),
            reason,
        });
        self.set_phase(OneToOnePhase::Closing, output);
    }

    fn terminate_pending(&mut self, reason: DisconnectReason, output: &mut OneToOneOutput) {
        let Some(peer) = self.pending.take() else {
            return;
        };
        self.crypto = SessionCrypto::generate();
        self.reset_heartbeat();
        self.closing_connections.insert(peer.id);
        output.actions.push(OneToOneAction::CloseConnection {
            connection_id: peer.id,
        });
        output.events.push(OneToOneEvent::ConnectionRejected {
            connection_id: peer.id,
            reason,
        });
        self.set_phase(OneToOnePhase::Closing, output);
    }

    fn queue_graceful_close(&mut self, reason: DisconnectReason, output: &mut OneToOneOutput) {
        let peers = [self.active.take(), self.pending.take()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        for peer in peers {
            self.closing_connections.insert(peer.id);
            output.actions.push(OneToOneAction::NotifyAndClose {
                connection_id: peer.id,
                frame: self.signal_frame(QUIT_SIGNAL),
                delay_ms: GRACEFUL_CLOSE_DELAY_MS,
            });
            output.events.push(OneToOneEvent::Disconnected {
                peer_b32: Some(peer.peer_b32),
                reason,
            });
        }
        self.crypto = SessionCrypto::generate();
        self.reset_heartbeat();
    }

    fn peer(&self, connection_id: ConnectionId) -> Option<&PeerConnection> {
        self.active
            .as_ref()
            .filter(|peer| peer.id == connection_id)
            .or_else(|| {
                self.pending
                    .as_ref()
                    .filter(|peer| peer.id == connection_id)
            })
    }

    fn peer_mut(&mut self, connection_id: ConnectionId) -> Option<&mut PeerConnection> {
        if self
            .active
            .as_ref()
            .is_some_and(|peer| peer.id == connection_id)
        {
            self.active.as_mut()
        } else {
            self.pending
                .as_mut()
                .filter(|peer| peer.id == connection_id)
        }
    }

    fn ensure_allowed_peer(
        &self,
        peer_b32: &str,
        peer_destination: Option<&str>,
    ) -> Result<(), OneToOneError> {
        let Some(pinned) = &self.config.pinned_peer else {
            return Ok(());
        };
        if pinned.b32 != peer_b32 {
            return Err(OneToOneError::UnauthorizedPeer);
        }
        if peer_destination.is_some_and(|destination| destination != pinned.destination) {
            return Err(OneToOneError::TofuMismatch);
        }
        Ok(())
    }

    fn local_prefers_outbound(&self, peer_b32: &str) -> bool {
        self.config.local_b32.as_str() < peer_b32
    }

    fn signal_frame(&mut self, signal: &str) -> Frame {
        Frame::new(MessageType::S, self.next_message_id(), signal.as_bytes())
    }

    fn next_message_id(&mut self) -> u64 {
        let current = self.next_control_message_id.max(1);
        self.next_control_message_id = next_nonzero(current);
        current
    }

    fn reset_heartbeat(&mut self) {
        self.heartbeat_last_rx_ms = 0;
        self.heartbeat_last_ping_ms = 0;
    }

    fn set_phase(&mut self, phase: OneToOnePhase, output: &mut OneToOneOutput) {
        if self.phase != phase {
            self.phase = phase;
            output.events.push(OneToOneEvent::PhaseChanged(phase));
        }
    }

    fn ensure_open(&self) -> Result<(), OneToOneError> {
        if self.phase == OneToOnePhase::Closed {
            Err(OneToOneError::Closed)
        } else {
            Ok(())
        }
    }
}

fn normalize_b32(value: &str) -> Result<String, OneToOneError> {
    let value = value.trim().to_ascii_lowercase();
    let identity = value.strip_suffix(".b32.i2p").unwrap_or(&value);
    if identity.len() != 52
        || !identity
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
    {
        return Err(OneToOneError::InvalidB32);
    }
    Ok(format!("{identity}.b32.i2p"))
}

fn validate_control_signal(signal: &str) -> Result<(), OneToOneError> {
    if !signal.starts_with(SIGNAL_PREFIX)
        || signal.len() > MAX_FRAME_PAYLOAD_SIZE
        || signal.chars().any(|character| character.is_control())
        || signal == QUIT_SIGNAL
        || signal.starts_with(HEARTBEAT_PING_PREFIX)
        || signal.starts_with(HEARTBEAT_PONG_PREFIX)
    {
        return Err(OneToOneError::InvalidControlSignal);
    }
    Ok(())
}

fn validate_delivery_acknowledgement(payload: &[u8]) -> Result<(), OneToOneError> {
    if payload.len() != std::mem::size_of::<u64>() {
        return Err(OneToOneError::InvalidDeliveryAcknowledgementLength(
            payload.len(),
        ));
    }
    Ok(())
}

fn is_retryable_connect_failure(reason: &str) -> bool {
    let reason = reason.to_ascii_lowercase();
    reason.contains("cant_reach_peer") || reason.contains("leaseset not found")
}

fn next_nonzero(value: u64) -> u64 {
    value.wrapping_add(1).max(1)
}

#[derive(Debug, Error)]
pub enum OneToOneError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Sam(#[from] SamError),
    #[error("the 1:1 session is closed")]
    Closed,
    #[error("the 1:1 session is busy in phase {0:?}")]
    Busy(OneToOnePhase),
    #[error("invalid I2P b32 identity")]
    InvalidB32,
    #[error("local and peer identities must be different")]
    IdenticalIdentities,
    #[error("peer is not the pinned contact")]
    UnauthorizedPeer,
    #[error("peer destination does not match the TOFU pin")]
    TofuMismatch,
    #[error("the contact already has a pinned peer")]
    PeerAlreadyPinned,
    #[error("the verified peer destination is unavailable")]
    PeerIdentityUnavailable,
    #[error("there is no pending incoming call")]
    NoPendingIncoming,
    #[error("the secure session is not ready")]
    SessionNotReady,
    #[error("message type {0:?} is reserved for session control")]
    ReservedControlFrame(MessageType),
    #[error("delivery acknowledgement must contain an 8-byte message id, got {0} bytes")]
    InvalidDeliveryAcknowledgementLength(usize),
    #[error("inline-image terminator payload must be empty")]
    InvalidImageTerminator,
    #[error("file-transfer terminator payload must be empty")]
    InvalidFileTerminator,
    #[error("message type {0:?} is not a file-transfer frame")]
    InvalidFileFrameType(MessageType),
    #[error("invalid 1:1 control signal")]
    InvalidControlSignal,
}
