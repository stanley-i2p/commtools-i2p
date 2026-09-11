use crate::constants::MAX_FRAME_PAYLOAD_SIZE;
use crate::crypto::{CryptoError, SessionCrypto};
use crate::group_roster::{
    GroupControlMessage, GroupDissolution, GroupRosterError, GroupRosterSync, owner_control,
};
use crate::inline_image::{
    ImageTransferHeader, ImageTransferKind, OriginalImageControl, OriginalImageMetadata,
    image_sha256_hex, validate_image_bytes,
};
use crate::one_to_one::{
    ConnectionDirection, ConnectionId, GRACEFUL_CLOSE_DELAY_MS, HEARTBEAT_PING_INTERVAL_MS,
    HEARTBEAT_PING_PREFIX, HEARTBEAT_PONG_PREFIX, HEARTBEAT_TIMEOUT_MS, QUIT_SIGNAL,
};
use crate::protocol::{Frame, MessageType};
use crate::sam::destination_to_b32;
use crate::storage::{GroupMemberRecord, GroupRecord};
use base64::{Engine as _, engine::general_purpose};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const GROUP_CONNECT_RETRY_MS: u64 = 5_000;
pub const GROUP_HANDSHAKE_TIMEOUT_MS: u64 = 45_000;
pub const GROUP_IMAGE_TRANSFER_MAX_BYTES: usize = 2 * 1_024 * 1_024;
pub const GROUP_IMAGE_CHUNK_BYTES: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupDisconnectReason {
    LocalRequest,
    PeerQuit,
    HeartbeatTimeout,
    HandshakeTimeout,
    TransportClosed,
    IdentityMismatch,
    ProtocolViolation,
    RemovedFromRoster,
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupCollisionWinner {
    Existing,
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupSessionAction {
    Connect {
        attempt_id: u64,
        peer_b32: String,
    },
    CancelConnect {
        attempt_id: u64,
    },
    SendHandshake {
        connection_id: ConnectionId,
        destination_prelude: String,
        frames: Vec<Frame>,
    },
    SendFrame {
        connection_id: ConnectionId,
        frame: Frame,
    },
    SendFrames {
        connection_id: ConnectionId,
        frames: Vec<Frame>,
    },
    SendOriginalImage {
        connection_id: ConnectionId,
        peer_b32: String,
        media_id: u64,
        frames: Vec<Frame>,
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
pub enum GroupSessionEvent {
    ConnectFailed {
        peer_b32: String,
        reason: String,
    },
    CollisionResolved {
        peer_b32: String,
        winner: GroupCollisionWinner,
        kept_connection: Option<ConnectionId>,
        closed_connection: Option<ConnectionId>,
    },
    IdentityVerified {
        peer_b32: String,
        connection_id: ConnectionId,
    },
    SecureSessionReady {
        peer_b32: String,
        connection_id: ConnectionId,
        authorized: bool,
    },
    PeerDisconnected {
        peer_b32: String,
        reason: GroupDisconnectReason,
    },
    TextReceived {
        peer_b32: String,
        message_id: u64,
        text: String,
    },
    ImageReceived {
        peer_b32: String,
        transfer_id: u64,
        media_id: u64,
        kind: ImageTransferKind,
        original: Option<OriginalImageMetadata>,
        filename: String,
        mime: String,
        bytes: Vec<u8>,
    },
    OriginalImageControlReceived {
        peer_b32: String,
        control: OriginalImageControl,
    },
    OriginalImageProgress {
        peer_b32: String,
        transfer_id: u64,
        media_id: u64,
        received_bytes: u64,
        total_bytes: u64,
    },
    DeliveryUpdated(GroupDeliveryStatus),
    ControlReceived {
        peer_b32: String,
        control: GroupControlMessage,
    },
    RosterReceived {
        peer_b32: String,
        roster: GroupRosterSync,
    },
    DissolutionReceived {
        peer_b32: String,
        dissolution: GroupDissolution,
    },
    ApplicationFrame {
        peer_b32: String,
        frame: Frame,
    },
    FrameRejected {
        peer_b32: String,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GroupSessionOutput {
    pub actions: Vec<GroupSessionAction>,
    pub events: Vec<GroupSessionEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupDeliveryStatus {
    pub message_id: u64,
    pub expected: BTreeSet<String>,
    pub received: BTreeSet<String>,
}

impl GroupDeliveryStatus {
    pub fn is_complete(&self) -> bool {
        !self.expected.is_empty() && self.received == self.expected
    }
}

#[derive(Clone)]
pub struct GroupSessionConfig {
    local_destination: String,
    local_b32: String,
    local_name: String,
    group_name: String,
    owner_b32: String,
    members: Vec<GroupMemberRecord>,
    owner_control: Option<GroupControlMessage>,
    control_message_seed: u64,
}

impl std::fmt::Debug for GroupSessionConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GroupSessionConfig")
            .field("local_destination", &"<redacted>")
            .field("local_b32", &self.local_b32)
            .field("local_name", &self.local_name)
            .field("group_name", &self.group_name)
            .field("owner_b32", &self.owner_b32)
            .field("members", &self.members)
            .field(
                "owner_control",
                &self.owner_control.as_ref().map(|_| "<redacted>"),
            )
            .field("control_message_seed", &self.control_message_seed)
            .finish()
    }
}

impl GroupSessionConfig {
    pub fn new(
        local_destination: impl Into<String>,
        local_name: impl Into<String>,
        group_name: impl Into<String>,
        owner_b32: impl Into<String>,
        members: Vec<GroupMemberRecord>,
    ) -> Result<Self, GroupSessionError> {
        let local_destination = local_destination.into();
        let local_b32 = destination_to_b32(&local_destination)?;
        let owner_b32 = normalize_b32(&owner_b32.into())?;
        let local_name = validate_name(local_name.into())?;
        let group_name = validate_name(group_name.into())?;
        let members = normalize_members(members)?;
        if !local_b32.eq_ignore_ascii_case(&owner_b32)
            && !members
                .iter()
                .any(|member| member.b32.eq_ignore_ascii_case(&owner_b32))
        {
            return Err(GroupSessionError::OwnerMissingFromRoster);
        }
        Ok(Self {
            local_destination,
            local_b32,
            local_name,
            group_name,
            owner_b32,
            members,
            owner_control: None,
            control_message_seed: 1,
        })
    }

    pub fn from_record_with_local_destination(
        group: &GroupRecord,
        local_destination: impl Into<String>,
        now_ms: u64,
    ) -> Result<Self, GroupSessionError> {
        let identity = group
            .identity
            .as_ref()
            .ok_or(GroupSessionError::MissingIdentity)?;
        let owner = group
            .owner_b32
            .as_ref()
            .ok_or(GroupSessionError::MissingOwner)?;
        let local_destination = local_destination.into();
        let local_b32 = destination_to_b32(&local_destination)?;
        if !local_b32.eq_ignore_ascii_case(&identity.b32) {
            return Err(GroupSessionError::IdentityMismatch);
        }
        let local_name = if group.local_member_name.trim().is_empty() {
            default_member_name(&identity.b32)
        } else {
            group.local_member_name.clone()
        };
        let mut config = Self::new(
            local_destination,
            local_name,
            &group.display_name,
            owner,
            group.members.clone(),
        )?;
        config.owner_control = owner_control(group, now_ms)?;
        Ok(config)
    }

    pub fn with_owner_control(mut self, control: Option<GroupControlMessage>) -> Self {
        self.owner_control = control;
        self
    }

    pub fn with_control_message_seed(mut self, seed: u64) -> Self {
        self.control_message_seed = seed.max(1);
        self
    }

    pub fn local_b32(&self) -> &str {
        &self.local_b32
    }

    pub fn owner_b32(&self) -> &str {
        &self.owner_b32
    }

    pub fn group_name(&self) -> &str {
        &self.group_name
    }
}

#[derive(Debug, Clone)]
struct GroupConnection {
    id: ConnectionId,
    direction: ConnectionDirection,
    peer_destination: Option<String>,
    handshake_started_ms: u64,
    identity_received: bool,
    peer_key: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
struct ConnectAttempt {
    id: u64,
}

#[derive(Debug, Clone)]
struct IncomingImage {
    header: ImageTransferHeader,
    expected: usize,
    transfer_id: u64,
    bytes: Vec<u8>,
}

#[derive(Clone)]
struct GroupPeer {
    member: GroupMemberRecord,
    authorized: bool,
    connection: Option<GroupConnection>,
    connect_attempt: Option<ConnectAttempt>,
    last_connect_attempt_ms: u64,
    crypto: SessionCrypto,
    ready: bool,
    heartbeat_last_rx_ms: u64,
    heartbeat_last_ping_ms: u64,
    incoming_image: Option<IncomingImage>,
}

impl GroupPeer {
    fn new(member: GroupMemberRecord, authorized: bool) -> Self {
        Self {
            member,
            authorized,
            connection: None,
            connect_attempt: None,
            last_connect_attempt_ms: 0,
            crypto: SessionCrypto::generate(),
            ready: false,
            heartbeat_last_rx_ms: 0,
            heartbeat_last_ping_ms: 0,
            incoming_image: None,
        }
    }

    fn reset_transport(&mut self) {
        self.connection = None;
        self.connect_attempt = None;
        self.crypto = SessionCrypto::generate();
        self.ready = false;
        self.heartbeat_last_rx_ms = 0;
        self.heartbeat_last_ping_ms = 0;
        self.incoming_image = None;
    }
}

pub struct GroupSession {
    config: GroupSessionConfig,
    peers: BTreeMap<String, GroupPeer>,
    deliveries: BTreeMap<u64, GroupDeliveryStatus>,
    closing_connections: BTreeSet<ConnectionId>,
    closed: bool,
    next_attempt_id: u64,
    next_control_message_id: u64,
    pending_original_images: BTreeSet<(String, u64)>,
}

impl GroupSession {
    pub fn new(config: GroupSessionConfig) -> Self {
        let mut peers = BTreeMap::new();
        for member in &config.members {
            if !member.b32.eq_ignore_ascii_case(&config.local_b32) {
                peers.insert(member.b32.clone(), GroupPeer::new(member.clone(), true));
            }
        }
        Self {
            next_control_message_id: config.control_message_seed,
            pending_original_images: BTreeSet::new(),
            config,
            peers,
            deliveries: BTreeMap::new(),
            closing_connections: BTreeSet::new(),
            closed: false,
            next_attempt_id: 1,
        }
    }

    pub fn config(&self) -> &GroupSessionConfig {
        &self.config
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn ready_member_count(&self) -> usize {
        self.peers
            .values()
            .filter(|peer| peer.ready && peer.authorized)
            .count()
    }

    pub fn member_is_ready(&self, peer_b32: &str) -> bool {
        normalize_b32(peer_b32)
            .ok()
            .and_then(|peer| self.peers.get(&peer))
            .is_some_and(|peer| peer.ready && peer.authorized)
    }

    pub fn delivery_status(&self, message_id: u64) -> Option<&GroupDeliveryStatus> {
        self.deliveries.get(&message_id)
    }

    pub fn begin_connections(&mut self, now_ms: u64) -> GroupSessionOutput {
        self.tick(now_ms)
    }

    pub fn outbound_connected(
        &mut self,
        peer_b32: &str,
        attempt_id: u64,
        connection_id: ConnectionId,
        now_ms: u64,
    ) -> GroupSessionOutput {
        let mut output = GroupSessionOutput::default();
        let Ok(peer_b32) = normalize_b32(peer_b32) else {
            output
                .actions
                .push(GroupSessionAction::CloseConnection { connection_id });
            return output;
        };
        let Some(mut peer) = self.peers.remove(&peer_b32) else {
            output
                .actions
                .push(GroupSessionAction::CloseConnection { connection_id });
            return output;
        };
        let attempt_matches = peer
            .connect_attempt
            .as_ref()
            .is_some_and(|attempt| attempt.id == attempt_id);
        if self.closed || !attempt_matches {
            output
                .actions
                .push(GroupSessionAction::CloseConnection { connection_id });
            self.peers.insert(peer_b32, peer);
            return output;
        }
        peer.connect_attempt = None;

        if let Some(existing) = peer.connection.clone() {
            if peer.ready || existing.direction == ConnectionDirection::Outbound {
                output.events.push(GroupSessionEvent::CollisionResolved {
                    peer_b32: peer_b32.clone(),
                    winner: GroupCollisionWinner::Existing,
                    kept_connection: Some(existing.id),
                    closed_connection: Some(connection_id),
                });
                output
                    .actions
                    .push(GroupSessionAction::CloseConnection { connection_id });
                self.peers.insert(peer_b32, peer);
                return output;
            }
            if !self.local_prefers_outbound(&peer_b32) {
                output.events.push(GroupSessionEvent::CollisionResolved {
                    peer_b32: peer_b32.clone(),
                    winner: GroupCollisionWinner::Inbound,
                    kept_connection: Some(existing.id),
                    closed_connection: Some(connection_id),
                });
                output
                    .actions
                    .push(GroupSessionAction::CloseConnection { connection_id });
                self.peers.insert(peer_b32, peer);
                return output;
            }
            output.events.push(GroupSessionEvent::CollisionResolved {
                peer_b32: peer_b32.clone(),
                winner: GroupCollisionWinner::Outbound,
                kept_connection: Some(connection_id),
                closed_connection: Some(existing.id),
            });
            output.actions.push(GroupSessionAction::CloseConnection {
                connection_id: existing.id,
            });
        }

        self.install_connection(
            &mut peer,
            connection_id,
            ConnectionDirection::Outbound,
            None,
            now_ms,
            &mut output,
        );
        self.peers.insert(peer_b32, peer);
        output
    }

    pub fn outbound_failed(
        &mut self,
        peer_b32: &str,
        attempt_id: u64,
        reason: impl Into<String>,
    ) -> GroupSessionOutput {
        let mut output = GroupSessionOutput::default();
        let Ok(peer_b32) = normalize_b32(peer_b32) else {
            return output;
        };
        let Some(peer) = self.peers.get_mut(&peer_b32) else {
            return output;
        };
        if !peer
            .connect_attempt
            .as_ref()
            .is_some_and(|attempt| attempt.id == attempt_id)
        {
            return output;
        }
        peer.connect_attempt = None;
        output.events.push(GroupSessionEvent::ConnectFailed {
            peer_b32,
            reason: reason.into(),
        });
        output
    }

    pub fn incoming_connected(
        &mut self,
        connection_id: ConnectionId,
        peer_b32: &str,
        peer_destination: &str,
        now_ms: u64,
    ) -> GroupSessionOutput {
        let mut output = GroupSessionOutput::default();
        if self.closed {
            output
                .actions
                .push(GroupSessionAction::CloseConnection { connection_id });
            return output;
        }
        let Ok(peer_b32) = normalize_b32(peer_b32) else {
            output
                .actions
                .push(GroupSessionAction::CloseConnection { connection_id });
            return output;
        };
        if destination_to_b32(peer_destination).ok().as_deref() != Some(peer_b32.as_str()) {
            output.events.push(GroupSessionEvent::FrameRejected {
                peer_b32,
                reason: "incoming group stream identity mismatch".into(),
            });
            output
                .actions
                .push(GroupSessionAction::CloseConnection { connection_id });
            return output;
        }

        let mut peer = match self.peers.remove(&peer_b32) {
            Some(peer) => peer,
            None if self.is_owner() => GroupPeer::new(
                GroupMemberRecord {
                    name: default_member_name(&peer_b32),
                    b32: peer_b32.clone(),
                },
                false,
            ),
            None => {
                output.events.push(GroupSessionEvent::FrameRejected {
                    peer_b32,
                    reason: "caller is not in the signed group roster".into(),
                });
                output
                    .actions
                    .push(GroupSessionAction::CloseConnection { connection_id });
                return output;
            }
        };

        if let Some(existing) = peer.connection.clone() {
            if peer.ready {
                output.events.push(GroupSessionEvent::CollisionResolved {
                    peer_b32: peer_b32.clone(),
                    winner: GroupCollisionWinner::Existing,
                    kept_connection: Some(existing.id),
                    closed_connection: Some(connection_id),
                });
                output
                    .actions
                    .push(GroupSessionAction::CloseConnection { connection_id });
                self.peers.insert(peer_b32, peer);
                return output;
            }
            if self.local_prefers_outbound(&peer_b32) {
                output.events.push(GroupSessionEvent::CollisionResolved {
                    peer_b32: peer_b32.clone(),
                    winner: GroupCollisionWinner::Outbound,
                    kept_connection: Some(existing.id),
                    closed_connection: Some(connection_id),
                });
                output
                    .actions
                    .push(GroupSessionAction::CloseConnection { connection_id });
                self.peers.insert(peer_b32, peer);
                return output;
            }
            output.events.push(GroupSessionEvent::CollisionResolved {
                peer_b32: peer_b32.clone(),
                winner: GroupCollisionWinner::Inbound,
                kept_connection: Some(connection_id),
                closed_connection: Some(existing.id),
            });
            output.actions.push(GroupSessionAction::CloseConnection {
                connection_id: existing.id,
            });
        }
        if let Some(attempt) = peer.connect_attempt.take() {
            if self.local_prefers_outbound(&peer_b32) {
                peer.connect_attempt = Some(attempt);
                output.events.push(GroupSessionEvent::CollisionResolved {
                    peer_b32: peer_b32.clone(),
                    winner: GroupCollisionWinner::Outbound,
                    kept_connection: None,
                    closed_connection: Some(connection_id),
                });
                output
                    .actions
                    .push(GroupSessionAction::CloseConnection { connection_id });
                self.peers.insert(peer_b32, peer);
                return output;
            }
            output.actions.push(GroupSessionAction::CancelConnect {
                attempt_id: attempt.id,
            });
        }

        self.install_connection(
            &mut peer,
            connection_id,
            ConnectionDirection::Inbound,
            Some(peer_destination.to_string()),
            now_ms,
            &mut output,
        );
        self.peers.insert(peer_b32, peer);
        output
    }

    pub fn receive_frame(
        &mut self,
        connection_id: ConnectionId,
        frame: Frame,
        now_ms: u64,
    ) -> GroupSessionOutput {
        let mut output = GroupSessionOutput::default();
        let Some(peer_b32) = self.peer_key_for_connection(connection_id) else {
            output.events.push(GroupSessionEvent::FrameRejected {
                peer_b32: String::new(),
                reason: "frame belongs to an inactive group connection".into(),
            });
            return output;
        };
        let mut peer = self
            .peers
            .remove(&peer_b32)
            .expect("peer key came from map");
        if peer.ready {
            peer.heartbeat_last_rx_ms = now_ms;
        }

        match frame.message_type {
            MessageType::S => {
                self.handle_signal(&mut peer, connection_id, frame, now_ms, &mut output)
            }
            MessageType::K => self.handle_key(&mut peer, connection_id, frame, now_ms, &mut output),
            MessageType::L if peer.ready => {
                self.handle_group_control(&peer, frame, &mut output);
            }
            MessageType::U if peer.ready && peer.authorized => {
                self.handle_text(&peer, connection_id, frame, &mut output);
            }
            MessageType::D if peer.ready && peer.authorized => {
                self.handle_ack(&peer_b32, frame, &mut output);
            }
            MessageType::J if peer.ready && peer.authorized => {
                self.handle_image_header(&mut peer, frame, &mut output);
            }
            MessageType::G if peer.ready && peer.authorized => {
                self.handle_image_chunk(&mut peer, frame, &mut output);
            }
            MessageType::Z if peer.ready && peer.authorized => {
                self.handle_image_end(&mut peer, connection_id, frame, &mut output);
            }
            _ if peer.ready && peer.authorized => match peer.crypto.open(&frame.payload) {
                Ok(payload) => output.events.push(GroupSessionEvent::ApplicationFrame {
                    peer_b32: peer_b32.clone(),
                    frame: Frame::new(frame.message_type, frame.message_id, payload),
                }),
                Err(_) => output.events.push(GroupSessionEvent::FrameRejected {
                    peer_b32: peer_b32.clone(),
                    reason: "group application payload authentication failed".into(),
                }),
            },
            _ => output.events.push(GroupSessionEvent::FrameRejected {
                peer_b32: peer_b32.clone(),
                reason: "group frame received before an authorized secure session was ready".into(),
            }),
        }
        self.peers.insert(peer_b32, peer);
        output
    }

    pub fn send_text(
        &mut self,
        message_id: u64,
        text: &str,
    ) -> Result<GroupSessionOutput, GroupSessionError> {
        if text.is_empty() {
            return Err(GroupSessionError::EmptyMessage);
        }
        self.fanout_encrypted(MessageType::U, message_id, text.as_bytes(), true)
    }

    pub fn send_roster(
        &mut self,
        message_id: u64,
        roster: &GroupRosterSync,
    ) -> Result<GroupSessionOutput, GroupSessionError> {
        let payload = serde_json::to_vec(roster)?;
        self.fanout_encrypted(MessageType::L, message_id, &payload, false)
    }

    pub fn send_dissolution(
        &mut self,
        message_id: u64,
        dissolution: &GroupDissolution,
    ) -> Result<GroupSessionOutput, GroupSessionError> {
        if !self.is_owner() {
            return Err(GroupSessionError::LocalMemberIsNotOwner);
        }
        let payload = serde_json::to_vec(dissolution)?;
        self.fanout_encrypted(MessageType::L, message_id, &payload, false)
    }

    pub fn send_control_to_owner(
        &mut self,
        message_id: u64,
        control: &GroupControlMessage,
    ) -> Result<GroupSessionOutput, GroupSessionError> {
        if self.is_owner() {
            return Err(GroupSessionError::LocalMemberIsOwner);
        }
        let owner_b32 = normalize_b32(&self.config.owner_b32)?;
        let peer = self
            .peers
            .get(&owner_b32)
            .ok_or(GroupSessionError::OwnerNotReady)?;
        if !peer.ready {
            return Err(GroupSessionError::OwnerNotReady);
        }
        let connection_id = peer
            .connection
            .as_ref()
            .map(|connection| connection.id)
            .ok_or(GroupSessionError::OwnerNotReady)?;
        let payload = serde_json::to_vec(control)?;
        if payload.len() > MAX_FRAME_PAYLOAD_SIZE {
            return Err(GroupSessionError::PayloadTooLarge(payload.len()));
        }
        Ok(GroupSessionOutput {
            actions: vec![GroupSessionAction::SendFrame {
                connection_id,
                frame: Frame::new(MessageType::L, message_id, peer.crypto.seal(&payload)?),
            }],
            events: Vec::new(),
        })
    }

    pub fn send_image(
        &mut self,
        message_id: u64,
        filename: &str,
        mime: &str,
        bytes: &[u8],
    ) -> Result<GroupSessionOutput, GroupSessionError> {
        if bytes.is_empty() || bytes.len() > GROUP_IMAGE_TRANSFER_MAX_BYTES {
            return Err(GroupSessionError::InvalidImageSize(bytes.len()));
        }
        self.send_image_with_original(message_id, filename, mime, bytes, None)
    }

    pub fn send_image_with_original(
        &mut self,
        message_id: u64,
        filename: &str,
        mime: &str,
        bytes: &[u8],
        original: Option<OriginalImageMetadata>,
    ) -> Result<GroupSessionOutput, GroupSessionError> {
        if bytes.is_empty() || bytes.len() > GROUP_IMAGE_TRANSFER_MAX_BYTES {
            return Err(GroupSessionError::InvalidImageSize(bytes.len()));
        }
        validate_image_bytes(mime, bytes)?;
        let header = ImageTransferHeader {
            filename: sanitize_group_filename(filename),
            mime: mime.to_string(),
            total_bytes: bytes.len() as u64,
            kind: ImageTransferKind::Preview,
            media_id: message_id,
            original,
        };
        let encoded_header = header.encode()?;
        let mut output = GroupSessionOutput::default();
        let mut expected = BTreeSet::new();
        for (peer_b32, peer) in &self.peers {
            if !peer.ready || !peer.authorized {
                continue;
            }
            let Some(connection_id) = peer.connection.as_ref().map(|conn| conn.id) else {
                continue;
            };
            let mut frames = Vec::new();
            frames.push(Frame::new(
                MessageType::J,
                message_id,
                peer.crypto.seal(encoded_header.as_bytes())?,
            ));
            for chunk in bytes.chunks(GROUP_IMAGE_CHUNK_BYTES) {
                let encoded = general_purpose::STANDARD.encode(chunk);
                frames.push(Frame::new(
                    MessageType::G,
                    message_id,
                    peer.crypto.seal(encoded.as_bytes())?,
                ));
            }
            frames.push(Frame::new(MessageType::Z, message_id, Vec::new()));
            expected.insert(peer_b32.clone());
            output.actions.push(GroupSessionAction::SendFrames {
                connection_id,
                frames,
            });
        }
        if expected.is_empty() {
            return Err(GroupSessionError::NoReadyMembers);
        }
        self.deliveries.insert(
            message_id,
            GroupDeliveryStatus {
                message_id,
                expected,
                received: BTreeSet::new(),
            },
        );
        Ok(output)
    }

    pub fn send_image_to_peer(
        &self,
        peer_b32: &str,
        transfer_id: u64,
        header: &ImageTransferHeader,
        bytes: &[u8],
    ) -> Result<GroupSessionOutput, GroupSessionError> {
        if bytes.is_empty() || bytes.len() > crate::inline_image::INLINE_IMAGE_TRANSFER_MAX_BYTES {
            return Err(GroupSessionError::InvalidImageSize(bytes.len()));
        }
        validate_image_bytes(&header.mime, bytes)?;
        if header.total_bytes != bytes.len() as u64 {
            return Err(GroupSessionError::InvalidImageSize(bytes.len()));
        }
        let peer_b32 = normalize_b32(peer_b32)?;
        let peer = self
            .peers
            .get(&peer_b32)
            .ok_or(GroupSessionError::UnknownMember)?;
        if !peer.ready || !peer.authorized {
            return Err(GroupSessionError::NoReadyMembers);
        }
        let connection_id = peer
            .connection
            .as_ref()
            .map(|connection| connection.id)
            .ok_or(GroupSessionError::NoReadyMembers)?;
        let mut frames = Vec::with_capacity(bytes.len() / GROUP_IMAGE_CHUNK_BYTES + 2);
        frames.push(Frame::new(
            MessageType::J,
            transfer_id,
            peer.crypto.seal(header.encode()?.as_bytes())?,
        ));
        for chunk in bytes.chunks(GROUP_IMAGE_CHUNK_BYTES) {
            let encoded = general_purpose::STANDARD.encode(chunk);
            frames.push(Frame::new(
                MessageType::G,
                transfer_id,
                peer.crypto.seal(encoded.as_bytes())?,
            ));
        }
        frames.push(Frame::new(MessageType::Z, transfer_id, Vec::new()));
        Ok(GroupSessionOutput {
            actions: vec![GroupSessionAction::SendOriginalImage {
                connection_id,
                peer_b32,
                media_id: header.media_id,
                frames,
            }],
            events: Vec::new(),
        })
    }

    pub fn send_original_image_control(
        &mut self,
        peer_b32: &str,
        message_id: u64,
        control: OriginalImageControl,
    ) -> Result<GroupSessionOutput, GroupSessionError> {
        let peer_b32 = normalize_b32(peer_b32)?;
        let peer = self
            .peers
            .get(&peer_b32)
            .ok_or(GroupSessionError::UnknownMember)?;
        if !peer.ready || !peer.authorized {
            return Err(GroupSessionError::NoReadyMembers);
        }
        let connection_id = peer
            .connection
            .as_ref()
            .map(|connection| connection.id)
            .ok_or(GroupSessionError::NoReadyMembers)?;
        let payload = peer.crypto.seal(&control.encode()?)?;
        match control {
            OriginalImageControl::Request(media_id) => {
                self.pending_original_images
                    .insert((peer_b32.clone(), media_id));
            }
            OriginalImageControl::Cancel(media_id) => {
                self.pending_original_images
                    .remove(&(peer_b32.clone(), media_id));
                if let Some(peer) = self.peers.get_mut(&peer_b32) {
                    peer.incoming_image = None;
                }
            }
            OriginalImageControl::Unavailable(_) => {}
        }
        Ok(GroupSessionOutput {
            actions: vec![GroupSessionAction::SendFrame {
                connection_id,
                frame: Frame::new(MessageType::J, message_id, payload),
            }],
            events: Vec::new(),
        })
    }

    pub fn authorize_peer(&mut self, member: GroupMemberRecord) -> Result<(), GroupSessionError> {
        let member = normalize_members(vec![member])?
            .pop()
            .ok_or(GroupSessionError::UnknownMember)?;
        let peer = self
            .peers
            .get_mut(&member.b32)
            .ok_or(GroupSessionError::UnknownMember)?;
        peer.member = member;
        peer.authorized = true;
        Ok(())
    }

    pub fn replace_roster(
        &mut self,
        members: Vec<GroupMemberRecord>,
    ) -> Result<GroupSessionOutput, GroupSessionError> {
        let members = normalize_members(members)?;
        let incoming = members
            .into_iter()
            .filter(|member| member.b32 != self.config.local_b32)
            .map(|member| (member.b32.clone(), member))
            .collect::<BTreeMap<_, _>>();
        let mut output = GroupSessionOutput::default();
        let removed = self
            .peers
            .keys()
            .filter(|b32| !incoming.contains_key(*b32))
            .cloned()
            .collect::<Vec<_>>();
        for b32 in removed {
            if let Some(peer) = self.peers.remove(&b32) {
                if let Some(attempt) = peer.connect_attempt {
                    output.actions.push(GroupSessionAction::CancelConnect {
                        attempt_id: attempt.id,
                    });
                }
                if let Some(connection) = peer.connection {
                    output.actions.push(GroupSessionAction::CloseConnection {
                        connection_id: connection.id,
                    });
                }
                output.events.push(GroupSessionEvent::PeerDisconnected {
                    peer_b32: b32,
                    reason: GroupDisconnectReason::RemovedFromRoster,
                });
            }
        }
        for (b32, member) in incoming {
            if let Some(peer) = self.peers.get_mut(&b32) {
                peer.member = member;
                peer.authorized = true;
            } else {
                self.peers.insert(b32, GroupPeer::new(member, true));
            }
        }
        Ok(output)
    }

    pub fn tick(&mut self, now_ms: u64) -> GroupSessionOutput {
        let mut output = GroupSessionOutput::default();
        if self.closed {
            return output;
        }
        let peer_keys = self.peers.keys().cloned().collect::<Vec<_>>();
        for peer_b32 in peer_keys {
            let mut peer = self
                .peers
                .remove(&peer_b32)
                .expect("peer key came from map");
            if let Some(connection) = peer.connection.clone() {
                if !peer.ready
                    && now_ms.saturating_sub(connection.handshake_started_ms)
                        >= GROUP_HANDSHAKE_TIMEOUT_MS
                {
                    self.terminate_peer(
                        &peer_b32,
                        &mut peer,
                        GroupDisconnectReason::HandshakeTimeout,
                        &mut output,
                    );
                } else if peer.ready
                    && now_ms.saturating_sub(peer.heartbeat_last_rx_ms) >= HEARTBEAT_TIMEOUT_MS
                {
                    self.terminate_peer(
                        &peer_b32,
                        &mut peer,
                        GroupDisconnectReason::HeartbeatTimeout,
                        &mut output,
                    );
                } else if peer.ready
                    && now_ms.saturating_sub(peer.heartbeat_last_ping_ms)
                        >= HEARTBEAT_PING_INTERVAL_MS
                    && now_ms.saturating_sub(peer.heartbeat_last_rx_ms)
                        >= HEARTBEAT_PING_INTERVAL_MS
                {
                    let message_id = self.next_message_id();
                    peer.heartbeat_last_ping_ms = now_ms;
                    output.actions.push(GroupSessionAction::SendFrame {
                        connection_id: connection.id,
                        frame: Frame::new(
                            MessageType::S,
                            message_id,
                            format!("{HEARTBEAT_PING_PREFIX}{message_id:016x}"),
                        ),
                    });
                }
            }

            if peer.authorized
                && peer.connection.is_none()
                && peer.connect_attempt.is_none()
                && (peer.last_connect_attempt_ms == 0
                    || now_ms.saturating_sub(peer.last_connect_attempt_ms)
                        >= GROUP_CONNECT_RETRY_MS)
            {
                let attempt_id = self.next_attempt_id;
                self.next_attempt_id = next_nonzero(self.next_attempt_id);
                peer.last_connect_attempt_ms = now_ms.max(1);
                peer.connect_attempt = Some(ConnectAttempt { id: attempt_id });
                output.actions.push(GroupSessionAction::Connect {
                    attempt_id,
                    peer_b32: peer_b32.clone(),
                });
            }
            self.peers.insert(peer_b32, peer);
        }
        output
    }

    pub fn connection_closed(&mut self, connection_id: ConnectionId) -> GroupSessionOutput {
        let mut output = GroupSessionOutput::default();
        if self.closing_connections.remove(&connection_id) {
            return output;
        }
        let Some(peer_b32) = self.peer_key_for_connection(connection_id) else {
            return output;
        };
        if let Some(peer) = self.peers.get_mut(&peer_b32) {
            peer.reset_transport();
        }
        output.events.push(GroupSessionEvent::PeerDisconnected {
            peer_b32,
            reason: GroupDisconnectReason::TransportClosed,
        });
        output
    }

    pub fn begin_shutdown(&mut self) -> GroupSessionOutput {
        let mut output = GroupSessionOutput::default();
        if self.closed {
            return output;
        }
        self.closed = true;
        let peer_keys = self.peers.keys().cloned().collect::<Vec<_>>();
        for peer_b32 in peer_keys {
            let mut peer = self
                .peers
                .remove(&peer_b32)
                .expect("peer key came from map");
            if let Some(attempt) = peer.connect_attempt.take() {
                output.actions.push(GroupSessionAction::CancelConnect {
                    attempt_id: attempt.id,
                });
            }
            if let Some(connection) = peer.connection.take() {
                self.closing_connections.insert(connection.id);
                output.actions.push(GroupSessionAction::NotifyAndClose {
                    connection_id: connection.id,
                    frame: self.signal_frame(QUIT_SIGNAL),
                    delay_ms: GRACEFUL_CLOSE_DELAY_MS,
                });
                output.events.push(GroupSessionEvent::PeerDisconnected {
                    peer_b32: peer_b32.clone(),
                    reason: GroupDisconnectReason::Shutdown,
                });
            }
            peer.reset_transport();
            self.peers.insert(peer_b32, peer);
        }
        output
    }

    fn fanout_encrypted(
        &mut self,
        message_type: MessageType,
        message_id: u64,
        plaintext: &[u8],
        track_delivery: bool,
    ) -> Result<GroupSessionOutput, GroupSessionError> {
        if matches!(message_type, MessageType::S | MessageType::K) {
            return Err(GroupSessionError::ReservedControlFrame(message_type));
        }
        if plaintext.len().saturating_add(40) > MAX_FRAME_PAYLOAD_SIZE {
            return Err(GroupSessionError::PayloadTooLarge(plaintext.len()));
        }
        let mut output = GroupSessionOutput::default();
        let mut expected = BTreeSet::new();
        for (peer_b32, peer) in &self.peers {
            if !peer.ready || !peer.authorized {
                continue;
            }
            let Some(connection_id) = peer.connection.as_ref().map(|connection| connection.id)
            else {
                continue;
            };
            expected.insert(peer_b32.clone());
            output.actions.push(GroupSessionAction::SendFrame {
                connection_id,
                frame: Frame::new(message_type, message_id, peer.crypto.seal(plaintext)?),
            });
        }
        if expected.is_empty() {
            return Err(GroupSessionError::NoReadyMembers);
        }
        if track_delivery {
            self.deliveries.insert(
                message_id,
                GroupDeliveryStatus {
                    message_id,
                    expected,
                    received: BTreeSet::new(),
                },
            );
        }
        Ok(output)
    }

    fn install_connection(
        &mut self,
        peer: &mut GroupPeer,
        connection_id: ConnectionId,
        direction: ConnectionDirection,
        peer_destination: Option<String>,
        now_ms: u64,
        output: &mut GroupSessionOutput,
    ) {
        peer.crypto = SessionCrypto::generate();
        peer.ready = false;
        peer.heartbeat_last_rx_ms = 0;
        peer.heartbeat_last_ping_ms = 0;
        peer.incoming_image = None;
        peer.connection = Some(GroupConnection {
            id: connection_id,
            direction,
            peer_destination,
            handshake_started_ms: now_ms,
            identity_received: false,
            peer_key: None,
        });
        output.actions.push(GroupSessionAction::SendHandshake {
            connection_id,
            destination_prelude: self.config.local_destination.clone(),
            frames: vec![
                Frame::new(
                    MessageType::S,
                    self.next_message_id(),
                    self.config.local_destination.clone(),
                ),
                Frame::new(
                    MessageType::K,
                    self.next_message_id(),
                    peer.crypto.public_key_bytes(),
                ),
            ],
        });
    }

    fn handle_signal(
        &mut self,
        peer: &mut GroupPeer,
        connection_id: ConnectionId,
        frame: Frame,
        now_ms: u64,
        output: &mut GroupSessionOutput,
    ) {
        let Ok(body) = String::from_utf8(frame.payload) else {
            self.terminate_peer(
                &peer.member.b32.clone(),
                peer,
                GroupDisconnectReason::ProtocolViolation,
                output,
            );
            return;
        };
        if body == QUIT_SIGNAL {
            self.terminate_peer(
                &peer.member.b32.clone(),
                peer,
                GroupDisconnectReason::PeerQuit,
                output,
            );
            return;
        }
        if let Some(nonce) = body.strip_prefix(HEARTBEAT_PING_PREFIX) {
            if peer.ready {
                output.actions.push(GroupSessionAction::SendFrame {
                    connection_id,
                    frame: Frame::new(
                        MessageType::S,
                        self.next_message_id(),
                        format!("{HEARTBEAT_PONG_PREFIX}{nonce}"),
                    ),
                });
            }
            return;
        }
        if body.starts_with(HEARTBEAT_PONG_PREFIX) {
            return;
        }
        let Ok(framed_b32) = destination_to_b32(&body) else {
            self.terminate_peer(
                &peer.member.b32.clone(),
                peer,
                GroupDisconnectReason::IdentityMismatch,
                output,
            );
            return;
        };
        let identity_matches = framed_b32.eq_ignore_ascii_case(&peer.member.b32)
            && peer
                .connection
                .as_ref()
                .and_then(|connection| connection.peer_destination.as_ref())
                .is_none_or(|destination| destination == &body);
        if !identity_matches {
            self.terminate_peer(
                &peer.member.b32.clone(),
                peer,
                GroupDisconnectReason::IdentityMismatch,
                output,
            );
            return;
        }
        if let Some(connection) = peer.connection.as_mut() {
            connection.peer_destination = Some(body);
            connection.identity_received = true;
        }
        output.events.push(GroupSessionEvent::IdentityVerified {
            peer_b32: peer.member.b32.clone(),
            connection_id,
        });
        self.maybe_mark_ready(peer, now_ms, output);
    }

    fn handle_key(
        &mut self,
        peer: &mut GroupPeer,
        connection_id: ConnectionId,
        frame: Frame,
        now_ms: u64,
        output: &mut GroupSessionOutput,
    ) {
        let Ok(peer_key) = <[u8; 32]>::try_from(frame.payload.as_slice()) else {
            self.terminate_peer(
                &peer.member.b32.clone(),
                peer,
                GroupDisconnectReason::ProtocolViolation,
                output,
            );
            return;
        };
        if let Some(existing) = peer
            .connection
            .as_ref()
            .and_then(|connection| connection.peer_key)
        {
            if existing != peer_key {
                self.terminate_peer(
                    &peer.member.b32.clone(),
                    peer,
                    GroupDisconnectReason::ProtocolViolation,
                    output,
                );
            }
            return;
        }
        if peer.crypto.receive_peer_key(&peer_key).is_err() {
            self.terminate_peer(
                &peer.member.b32.clone(),
                peer,
                GroupDisconnectReason::ProtocolViolation,
                output,
            );
            return;
        }
        if let Some(connection) = peer.connection.as_mut() {
            connection.peer_key = Some(peer_key);
        }
        self.maybe_mark_ready(peer, now_ms, output);
        let _ = connection_id;
    }

    fn maybe_mark_ready(
        &mut self,
        peer: &mut GroupPeer,
        now_ms: u64,
        output: &mut GroupSessionOutput,
    ) {
        let Some(connection) = peer.connection.as_ref() else {
            return;
        };
        if peer.ready
            || !connection.identity_received
            || connection.peer_key.is_none()
            || !peer.crypto.is_ready()
        {
            return;
        }
        peer.ready = true;
        peer.heartbeat_last_rx_ms = now_ms;
        peer.heartbeat_last_ping_ms = now_ms;
        let connection_id = connection.id;
        output.events.push(GroupSessionEvent::SecureSessionReady {
            peer_b32: peer.member.b32.clone(),
            connection_id,
            authorized: peer.authorized,
        });

        if !self.is_owner()
            && peer.member.b32.eq_ignore_ascii_case(&self.config.owner_b32)
            && let Some(control) = self.config.owner_control.as_ref()
            && let Ok(payload) = serde_json::to_vec(control)
            && let Ok(payload) = peer.crypto.seal(&payload)
        {
            output.actions.push(GroupSessionAction::SendFrame {
                connection_id,
                frame: Frame::new(MessageType::L, self.next_message_id(), payload),
            });
        }
    }

    fn handle_group_control(
        &self,
        peer: &GroupPeer,
        frame: Frame,
        output: &mut GroupSessionOutput,
    ) {
        let Ok(payload) = peer.crypto.open(&frame.payload) else {
            output.events.push(GroupSessionEvent::FrameRejected {
                peer_b32: peer.member.b32.clone(),
                reason: "group control authentication failed".into(),
            });
            return;
        };
        if let Ok(control) = serde_json::from_slice::<GroupControlMessage>(&payload) {
            output.events.push(GroupSessionEvent::ControlReceived {
                peer_b32: peer.member.b32.clone(),
                control,
            });
        } else if peer.authorized {
            if let Ok(dissolution) = serde_json::from_slice::<GroupDissolution>(&payload) {
                output.events.push(GroupSessionEvent::DissolutionReceived {
                    peer_b32: peer.member.b32.clone(),
                    dissolution,
                });
            } else {
                match serde_json::from_slice::<GroupRosterSync>(&payload) {
                    Ok(roster) => output.events.push(GroupSessionEvent::RosterReceived {
                        peer_b32: peer.member.b32.clone(),
                        roster,
                    }),
                    Err(_) => output.events.push(GroupSessionEvent::FrameRejected {
                        peer_b32: peer.member.b32.clone(),
                        reason: "invalid encrypted group control payload".into(),
                    }),
                }
            }
        } else {
            output.events.push(GroupSessionEvent::FrameRejected {
                peer_b32: peer.member.b32.clone(),
                reason: "unauthorized caller sent a non-admission group control".into(),
            });
        }
    }

    fn handle_text(
        &mut self,
        peer: &GroupPeer,
        connection_id: ConnectionId,
        frame: Frame,
        output: &mut GroupSessionOutput,
    ) {
        let Ok(payload) = peer.crypto.open(&frame.payload) else {
            output.events.push(GroupSessionEvent::FrameRejected {
                peer_b32: peer.member.b32.clone(),
                reason: "group message authentication failed".into(),
            });
            return;
        };
        let Ok(text) = String::from_utf8(payload) else {
            output.events.push(GroupSessionEvent::FrameRejected {
                peer_b32: peer.member.b32.clone(),
                reason: "group message is not valid UTF-8".into(),
            });
            return;
        };
        output.events.push(GroupSessionEvent::TextReceived {
            peer_b32: peer.member.b32.clone(),
            message_id: frame.message_id,
            text,
        });
        output.actions.push(GroupSessionAction::SendFrame {
            connection_id,
            frame: Frame::new(
                MessageType::D,
                self.next_message_id(),
                frame.message_id.to_be_bytes(),
            ),
        });
    }

    fn handle_ack(&mut self, peer_b32: &str, frame: Frame, output: &mut GroupSessionOutput) {
        let Ok(bytes) = <[u8; 8]>::try_from(frame.payload.as_slice()) else {
            output.events.push(GroupSessionEvent::FrameRejected {
                peer_b32: peer_b32.to_string(),
                reason: "group delivery acknowledgement must contain an 8-byte message id".into(),
            });
            return;
        };
        let message_id = u64::from_be_bytes(bytes);
        let Some(delivery) = self.deliveries.get_mut(&message_id) else {
            return;
        };
        if delivery.expected.contains(peer_b32) {
            delivery.received.insert(peer_b32.to_string());
            output
                .events
                .push(GroupSessionEvent::DeliveryUpdated(delivery.clone()));
        }
    }

    fn handle_image_header(
        &mut self,
        peer: &mut GroupPeer,
        frame: Frame,
        output: &mut GroupSessionOutput,
    ) {
        let Ok(payload) = peer.crypto.open(&frame.payload) else {
            reject_image(peer, "group image header authentication failed", output);
            return;
        };
        match OriginalImageControl::decode(&payload) {
            Ok(Some(control)) => {
                if let OriginalImageControl::Unavailable(media_id) = control {
                    self.pending_original_images
                        .remove(&(peer.member.b32.clone(), media_id));
                }
                output
                    .events
                    .push(GroupSessionEvent::OriginalImageControlReceived {
                        peer_b32: peer.member.b32.clone(),
                        control,
                    });
                return;
            }
            Err(_) => {
                reject_image(peer, "group original-image control is invalid", output);
                return;
            }
            Ok(None) => {}
        }
        let Ok(header_text) = String::from_utf8(payload) else {
            reject_image(peer, "group image header is not valid UTF-8", output);
            return;
        };
        let Ok(header) = decode_group_image_header(&header_text, frame.message_id) else {
            reject_image(peer, "group image header is invalid", output);
            return;
        };
        let Ok(size) = usize::try_from(header.total_bytes) else {
            reject_image(peer, "group image size is invalid", output);
            return;
        };
        let maximum = match header.kind {
            ImageTransferKind::Preview => GROUP_IMAGE_TRANSFER_MAX_BYTES,
            ImageTransferKind::Original => crate::inline_image::INLINE_IMAGE_TRANSFER_MAX_BYTES,
        };
        if size == 0 || size > maximum {
            reject_image(peer, "group image header exceeds policy", output);
            return;
        }
        if header.kind == ImageTransferKind::Original
            && !self
                .pending_original_images
                .contains(&(peer.member.b32.clone(), header.media_id))
        {
            reject_image(peer, "unsolicited group original image", output);
            return;
        }
        peer.incoming_image = Some(IncomingImage {
            header,
            expected: size,
            transfer_id: frame.message_id,
            bytes: Vec::with_capacity(size),
        });
    }

    fn handle_image_chunk(
        &self,
        peer: &mut GroupPeer,
        frame: Frame,
        output: &mut GroupSessionOutput,
    ) {
        let Some(image) = peer.incoming_image.as_mut() else {
            reject_image(peer, "group image chunk arrived without a header", output);
            return;
        };
        if image.transfer_id != frame.message_id {
            reject_image(
                peer,
                "group image chunk id does not match its header",
                output,
            );
            return;
        }
        let Ok(payload) = peer.crypto.open(&frame.payload) else {
            reject_image(peer, "group image chunk authentication failed", output);
            return;
        };
        let Ok(decoded) = general_purpose::STANDARD.decode(payload) else {
            reject_image(peer, "group image chunk is not valid base64", output);
            return;
        };
        if decoded.len() > GROUP_IMAGE_CHUNK_BYTES
            || image.bytes.len().saturating_add(decoded.len()) > image.expected
        {
            reject_image(peer, "group image chunk exceeds declared size", output);
            return;
        }
        image.bytes.extend_from_slice(&decoded);
        if image.header.kind == ImageTransferKind::Original {
            output
                .events
                .push(GroupSessionEvent::OriginalImageProgress {
                    peer_b32: peer.member.b32.clone(),
                    transfer_id: image.transfer_id,
                    media_id: image.header.media_id,
                    received_bytes: image.bytes.len() as u64,
                    total_bytes: image.header.total_bytes,
                });
        }
    }

    fn handle_image_end(
        &mut self,
        peer: &mut GroupPeer,
        connection_id: ConnectionId,
        frame: Frame,
        output: &mut GroupSessionOutput,
    ) {
        let Some(image) = peer.incoming_image.take() else {
            reject_image(peer, "group image end arrived without a header", output);
            return;
        };
        if image.transfer_id != frame.message_id || image.bytes.len() != image.expected {
            reject_image(peer, "group image transfer is incomplete", output);
            return;
        }
        if validate_image_bytes(&image.header.mime, &image.bytes).is_err() {
            reject_image(
                peer,
                "group image content does not match its MIME type",
                output,
            );
            return;
        }
        if image.header.kind == ImageTransferKind::Original
            && !image.header.original.as_ref().is_some_and(|metadata| {
                image_sha256_hex(&image.bytes).eq_ignore_ascii_case(&metadata.sha256)
            })
        {
            reject_image(peer, "group original image digest does not match", output);
            return;
        }
        if image.header.kind == ImageTransferKind::Original {
            self.pending_original_images
                .remove(&(peer.member.b32.clone(), image.header.media_id));
        }
        let kind = image.header.kind;
        output.events.push(GroupSessionEvent::ImageReceived {
            peer_b32: peer.member.b32.clone(),
            transfer_id: frame.message_id,
            media_id: image.header.media_id,
            kind,
            original: image.header.original,
            filename: image.header.filename,
            mime: image.header.mime,
            bytes: image.bytes,
        });
        if kind == ImageTransferKind::Preview {
            output.actions.push(GroupSessionAction::SendFrame {
                connection_id,
                frame: Frame::new(
                    MessageType::D,
                    self.next_message_id(),
                    frame.message_id.to_be_bytes(),
                ),
            });
        }
    }

    fn terminate_peer(
        &mut self,
        peer_b32: &str,
        peer: &mut GroupPeer,
        reason: GroupDisconnectReason,
        output: &mut GroupSessionOutput,
    ) {
        self.pending_original_images
            .retain(|(pending_peer, _)| pending_peer != peer_b32);
        if let Some(attempt) = peer.connect_attempt.take() {
            output.actions.push(GroupSessionAction::CancelConnect {
                attempt_id: attempt.id,
            });
        }
        if let Some(connection) = peer.connection.take() {
            output.actions.push(GroupSessionAction::CloseConnection {
                connection_id: connection.id,
            });
        }
        peer.reset_transport();
        output.events.push(GroupSessionEvent::PeerDisconnected {
            peer_b32: peer_b32.to_string(),
            reason,
        });
    }

    fn peer_key_for_connection(&self, connection_id: ConnectionId) -> Option<String> {
        self.peers.iter().find_map(|(b32, peer)| {
            peer.connection
                .as_ref()
                .is_some_and(|connection| connection.id == connection_id)
                .then(|| b32.clone())
        })
    }

    fn local_prefers_outbound(&self, peer_b32: &str) -> bool {
        self.config.local_b32.as_str() < peer_b32
    }

    fn is_owner(&self) -> bool {
        self.config
            .local_b32
            .eq_ignore_ascii_case(&self.config.owner_b32)
    }

    fn signal_frame(&mut self, signal: &str) -> Frame {
        Frame::new(MessageType::S, self.next_message_id(), signal)
    }

    fn next_message_id(&mut self) -> u64 {
        let current = self.next_control_message_id;
        self.next_control_message_id = next_nonzero(current);
        current
    }
}

fn reject_image(peer: &mut GroupPeer, reason: &str, output: &mut GroupSessionOutput) {
    peer.incoming_image = None;
    output.events.push(GroupSessionEvent::FrameRejected {
        peer_b32: peer.member.b32.clone(),
        reason: reason.into(),
    });
}

fn normalize_members(
    members: Vec<GroupMemberRecord>,
) -> Result<Vec<GroupMemberRecord>, GroupSessionError> {
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::with_capacity(members.len());
    for member in members {
        let b32 = normalize_b32(&member.b32)?;
        let name = validate_name(member.name)?;
        if !seen.insert(b32.clone()) {
            return Err(GroupSessionError::DuplicateMember(b32));
        }
        normalized.push(GroupMemberRecord { name, b32 });
    }
    Ok(normalized)
}

fn normalize_b32(value: &str) -> Result<String, GroupSessionError> {
    let normalized = value.trim().to_ascii_lowercase();
    let label = normalized
        .strip_suffix(".b32.i2p")
        .ok_or(GroupSessionError::InvalidB32)?;
    if label.len() != 52
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
    {
        return Err(GroupSessionError::InvalidB32);
    }
    Ok(format!("{label}.b32.i2p"))
}

fn validate_name(value: String) -> Result<String, GroupSessionError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 32 || value.chars().any(char::is_control) {
        return Err(GroupSessionError::InvalidName);
    }
    Ok(value.to_string())
}

fn default_member_name(b32: &str) -> String {
    let label = b32.split('.').next().unwrap_or(b32);
    format!("member-{}", &label[..label.len().min(6)])
}

fn sanitize_group_filename(filename: &str) -> String {
    filename
        .rsplit(['/', '\\'])
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("image")
        .to_string()
}

fn decode_group_image_header(
    value: &str,
    legacy_media_id: u64,
) -> Result<ImageTransferHeader, crate::inline_image::InlineImageError> {
    if value.split('|').count() == 8 {
        return ImageTransferHeader::decode(value);
    }
    let mut parts = value.split('|');
    let (Some(filename), Some(mime), Some(total_bytes), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(crate::inline_image::InlineImageError::InvalidHeader);
    };
    let total_bytes = total_bytes
        .parse::<u64>()
        .map_err(|_| crate::inline_image::InlineImageError::InvalidHeader)?;
    let header = ImageTransferHeader {
        filename: filename.to_string(),
        mime: mime.to_string(),
        total_bytes,
        kind: ImageTransferKind::Preview,
        media_id: legacy_media_id,
        original: None,
    };
    ImageTransferHeader::decode(&header.encode()?)
}

fn next_nonzero(value: u64) -> u64 {
    value.wrapping_add(1).max(1)
}

#[derive(Debug, Error)]
pub enum GroupSessionError {
    #[error("group identity is missing")]
    MissingIdentity,
    #[error("group protocol destination does not match the stored identity")]
    IdentityMismatch,
    #[error("group owner is missing")]
    MissingOwner,
    #[error("group owner is missing from the roster")]
    OwnerMissingFromRoster,
    #[error("group b32 address is invalid")]
    InvalidB32,
    #[error("group or member name is invalid")]
    InvalidName,
    #[error("group contains duplicate member {0}")]
    DuplicateMember(String),
    #[error("group member is unknown")]
    UnknownMember,
    #[error("no authorized group members are ready")]
    NoReadyMembers,
    #[error("the local group member is the owner")]
    LocalMemberIsOwner,
    #[error("only the local group owner may perform this operation")]
    LocalMemberIsNotOwner,
    #[error("the group owner is not securely connected")]
    OwnerNotReady,
    #[error("group message is empty")]
    EmptyMessage,
    #[error("group payload is too large: {0} bytes")]
    PayloadTooLarge(usize),
    #[error("group image has invalid size: {0} bytes")]
    InvalidImageSize(usize),
    #[error("unsupported group image MIME type: {0}")]
    UnsupportedImageMime(String),
    #[error("message type {0:?} is reserved for the session handshake")]
    ReservedControlFrame(MessageType),
    #[error(transparent)]
    Sam(#[from] crate::sam::SamError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Roster(#[from] GroupRosterError),
    #[error(transparent)]
    InlineImage(#[from] crate::inline_image::InlineImageError),
}
