use crate::OfflineState;
use crate::group_roster::{GroupControlMessage, GroupDissolution, GroupRosterSync};
use crate::group_session::{
    GroupSession, GroupSessionAction, GroupSessionError, GroupSessionEvent, GroupSessionOutput,
};
use crate::ids::{ContactId, GroupId, SessionId, TransientId};
use crate::inline_image::{ImageTransferHeader, OriginalImageControl, OriginalImageMetadata};
use crate::offline_coordinator::{
    OfflineCoordinator, OfflineCoordinatorAction, OfflineCoordinatorError, OfflineCoordinatorEvent,
    OfflineCoordinatorMode, OfflineCoordinatorOutput, OfflineOperationId,
};
use crate::one_to_one::{
    ConnectionDirection, ConnectionId, DisconnectReason, OneToOneAction, OneToOneError,
    OneToOneEvent, OneToOneOutput, OneToOnePhase, OneToOneSession,
};
use crate::protocol::{Frame, MessageType};
use crate::rendezvous::{
    AUTH_SIGNAL_PREFIX, IssuedAccess, OutgoingAccess, PendingRequest, RendezvousError,
    answer_request, generate_request, make_auth_signal, open_response, verify_auth_signal,
};
use crate::storage::{GroupMemberRecord, PersistedOfflineState};
use rand_core::{OsRng, RngCore};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use thiserror::Error;

const INTERNAL_MESSAGE_ID_START: u64 = 1 << 63;
const OFFLINE_SHARED_SECRET_BYTES: usize = 32;
const OFFLINE_SECRET_REQUEST_SIGNAL: &str = "__SIGNAL__:OFFLINE_SECRET_REQUEST";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationPhase {
    Running,
    StoppingSessions,
    LockingVault,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedSessionPhase {
    Open,
    Closing,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ManagedSessionKey {
    Contact(ContactId),
    Transient(TransientId),
    Group(GroupId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSessionInfo {
    pub session_id: SessionId,
    pub key: ManagedSessionKey,
    pub phase: ManagedSessionPhase,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationAction {
    OneToOne {
        session_id: SessionId,
        action: OneToOneAction,
    },
    Group {
        session_id: SessionId,
        action: GroupSessionAction,
    },
    Offline {
        session_id: SessionId,
        action: OfflineCoordinatorAction,
    },
    PersistContactOffline {
        session_id: SessionId,
        contact_id: ContactId,
        mutation_id: u64,
        state: PersistedOfflineState,
    },
    PersistContactOfflineEnrollment {
        session_id: SessionId,
        contact_id: ContactId,
        enrollment_id: u64,
        state: PersistedOfflineState,
    },
    ShutdownSam {
        session_id: SessionId,
    },
    LockVault,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationEvent {
    SessionOpening {
        key: ManagedSessionKey,
    },
    SessionOpenFailed {
        key: ManagedSessionKey,
        reason: String,
    },
    SessionOpened {
        session_id: SessionId,
        key: ManagedSessionKey,
    },
    SessionClosing {
        session_id: SessionId,
        key: ManagedSessionKey,
    },
    SessionClosed {
        session_id: SessionId,
        key: ManagedSessionKey,
    },
    OneToOne {
        session_id: SessionId,
        event: OneToOneEvent,
    },
    Rendezvous {
        session_id: SessionId,
        event: RendezvousEvent,
    },
    FileTransfer {
        session_id: SessionId,
        event: FileTransferEvent,
    },
    Group {
        session_id: SessionId,
        event: GroupSessionEvent,
    },
    Offline {
        session_id: SessionId,
        event: OfflineCoordinatorEvent,
    },
    OfflineStatePersisted {
        session_id: SessionId,
        contact_id: ContactId,
        mutation_id: u64,
    },
    OfflineEnrollmentPersisted {
        session_id: SessionId,
        contact_id: ContactId,
    },
    OperationFailed {
        session_id: Option<SessionId>,
        operation: &'static str,
        reason: String,
    },
    OperationRecovered {
        session_id: SessionId,
        operation: &'static str,
    },
    Stopping,
    VaultLockRequested,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RendezvousEvent {
    OutgoingAuthenticated {
        connection_id: ConnectionId,
        peer_b32: String,
    },
    IncomingAuthenticated {
        connection_id: ConnectionId,
        peer_b32: String,
    },
    InvitationConsumed {
        connection_id: ConnectionId,
        peer_b32: String,
    },
    AuthenticationRejected {
        connection_id: ConnectionId,
        peer_b32: String,
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileTransferDirection {
    Sent,
    Received,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileTransferEvent {
    Offered {
        transfer_id: u64,
        direction: FileTransferDirection,
        filename: String,
        total_bytes: u64,
    },
    Started {
        transfer_id: u64,
        direction: FileTransferDirection,
        filename: String,
        total_bytes: u64,
    },
    Progress {
        transfer_id: u64,
        direction: FileTransferDirection,
        transferred_bytes: u64,
        total_bytes: u64,
    },
    Completed {
        transfer_id: u64,
        direction: FileTransferDirection,
        filename: String,
        total_bytes: u64,
        path: Option<PathBuf>,
    },
    Declined {
        transfer_id: u64,
        direction: FileTransferDirection,
        filename: String,
    },
    Cancelled {
        transfer_id: u64,
        direction: FileTransferDirection,
        filename: String,
    },
    Expired {
        transfer_id: u64,
        direction: FileTransferDirection,
        filename: String,
    },
    Failed {
        transfer_id: u64,
        direction: FileTransferDirection,
        filename: Option<String>,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApplicationOutput {
    pub actions: Vec<ApplicationAction>,
    pub events: Vec<ApplicationEvent>,
}

impl ApplicationOutput {
    fn merge(&mut self, mut other: Self) {
        self.actions.append(&mut other.actions);
        self.events.append(&mut other.events);
    }
}

struct SessionLifecycle {
    phase: ManagedSessionPhase,
    closing_connections: BTreeSet<ConnectionId>,
    sam_shutdown_requested: bool,
    sam_shutdown_complete: bool,
    deaddrop_shutdown_complete: bool,
}

impl SessionLifecycle {
    fn open(has_deaddrop: bool) -> Self {
        Self {
            phase: ManagedSessionPhase::Open,
            closing_connections: BTreeSet::new(),
            sam_shutdown_requested: false,
            sam_shutdown_complete: false,
            deaddrop_shutdown_complete: !has_deaddrop,
        }
    }

    fn ready_to_remove(&self) -> bool {
        self.phase == ManagedSessionPhase::Closing
            && self.closing_connections.is_empty()
            && self.sam_shutdown_complete
            && self.deaddrop_shutdown_complete
    }
}

struct OneToOneRuntime {
    key: ManagedSessionKey,
    session: OneToOneSession,
    offline: Option<OfflineCoordinator>,
    staged_offline: Option<PersistedOfflineState>,
    pending_offline_enrollment: BTreeMap<u64, PendingOfflineEnrollment>,
    pending_offline_persistence: BTreeMap<u64, PersistedOfflineState>,
    rendezvous: ContactRendezvousState,
    lifecycle: SessionLifecycle,
}

impl OneToOneRuntime {
    fn contact_id(&self) -> Result<&ContactId, ApplicationCoordinatorError> {
        match &self.key {
            ManagedSessionKey::Contact(contact_id) => Ok(contact_id),
            _ => Err(ApplicationCoordinatorError::OfflineUnavailable),
        }
    }
}

#[derive(Default)]
struct ContactRendezvousState {
    pending_request: Option<PendingRequest>,
    issued: Option<IssuedAccess>,
    outgoing: Option<OutgoingAccess>,
    reserved_connection: Option<(ConnectionId, [u8; 16])>,
}

#[derive(Clone)]
struct PendingOfflineEnrollment {
    state: PersistedOfflineState,
    send_after_persist: bool,
}

struct GroupRuntime {
    group_id: GroupId,
    session: GroupSession,
    lifecycle: SessionLifecycle,
}

enum ManagedSession {
    OneToOne(OneToOneRuntime),
    Group(GroupRuntime),
}

impl ManagedSession {
    fn key(&self) -> ManagedSessionKey {
        match self {
            Self::OneToOne(runtime) => runtime.key.clone(),
            Self::Group(runtime) => ManagedSessionKey::Group(runtime.group_id.clone()),
        }
    }

    fn lifecycle(&self) -> &SessionLifecycle {
        match self {
            Self::OneToOne(runtime) => &runtime.lifecycle,
            Self::Group(runtime) => &runtime.lifecycle,
        }
    }

    fn lifecycle_mut(&mut self) -> &mut SessionLifecycle {
        match self {
            Self::OneToOne(runtime) => &mut runtime.lifecycle,
            Self::Group(runtime) => &mut runtime.lifecycle,
        }
    }

    fn ready_to_remove(&self) -> bool {
        match self {
            Self::OneToOne(runtime) => {
                runtime.lifecycle.ready_to_remove()
                    && runtime.pending_offline_enrollment.is_empty()
                    && runtime.pending_offline_persistence.is_empty()
            }
            Self::Group(runtime) => runtime.lifecycle.ready_to_remove(),
        }
    }
}

pub struct ApplicationCoordinator {
    phase: ApplicationPhase,
    sessions: BTreeMap<SessionId, ManagedSession>,
    contacts: BTreeMap<ContactId, SessionId>,
    transients: BTreeMap<TransientId, SessionId>,
    groups: BTreeMap<GroupId, SessionId>,
    next_session_id: u64,
    next_internal_message_id: u64,
}

impl ApplicationCoordinator {
    pub fn new() -> Self {
        Self {
            phase: ApplicationPhase::Running,
            sessions: BTreeMap::new(),
            contacts: BTreeMap::new(),
            transients: BTreeMap::new(),
            groups: BTreeMap::new(),
            next_session_id: 1,
            next_internal_message_id: INTERNAL_MESSAGE_ID_START,
        }
    }

    pub fn phase(&self) -> ApplicationPhase {
        self.phase
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn sessions(&self) -> Vec<ManagedSessionInfo> {
        self.sessions
            .iter()
            .map(|(session_id, session)| ManagedSessionInfo {
                session_id: *session_id,
                key: session.key(),
                phase: session.lifecycle().phase,
            })
            .collect()
    }

    pub fn session_for_contact(&self, contact_id: &ContactId) -> Option<SessionId> {
        self.contacts.get(contact_id).copied()
    }

    pub fn session_for_group(&self, group_id: &GroupId) -> Option<SessionId> {
        self.groups.get(group_id).copied()
    }

    pub fn session_for_transient(&self, transient_id: &TransientId) -> Option<SessionId> {
        self.transients.get(transient_id).copied()
    }

    pub fn contact_id_for_session(&self, session_id: SessionId) -> Option<&ContactId> {
        match self.sessions.get(&session_id) {
            Some(ManagedSession::OneToOne(runtime)) => match &runtime.key {
                ManagedSessionKey::Contact(contact_id) => Some(contact_id),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn transient_id_for_session(&self, session_id: SessionId) -> Option<&TransientId> {
        match self.sessions.get(&session_id) {
            Some(ManagedSession::OneToOne(runtime)) => match &runtime.key {
                ManagedSessionKey::Transient(transient_id) => Some(transient_id),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn group_id_for_session(&self, session_id: SessionId) -> Option<&GroupId> {
        match self.sessions.get(&session_id) {
            Some(ManagedSession::Group(runtime)) => Some(&runtime.group_id),
            _ => None,
        }
    }

    pub fn one_to_one_session(&self, session_id: SessionId) -> Option<&OneToOneSession> {
        match self.sessions.get(&session_id) {
            Some(ManagedSession::OneToOne(runtime)) => Some(&runtime.session),
            _ => None,
        }
    }

    pub fn group_session(&self, session_id: SessionId) -> Option<&GroupSession> {
        match self.sessions.get(&session_id) {
            Some(ManagedSession::Group(runtime)) => Some(&runtime.session),
            _ => None,
        }
    }

    pub fn offline_coordinator(&self, session_id: SessionId) -> Option<&OfflineCoordinator> {
        match self.sessions.get(&session_id) {
            Some(ManagedSession::OneToOne(runtime)) => runtime.offline.as_ref(),
            _ => None,
        }
    }

    pub fn open_contact(
        &mut self,
        contact_id: ContactId,
        session: OneToOneSession,
        offline: Option<OfflineCoordinator>,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        self.open_contact_with_staged_offline(contact_id, session, offline, None)
    }

    pub fn open_contact_with_staged_offline(
        &mut self,
        contact_id: ContactId,
        session: OneToOneSession,
        offline: Option<OfflineCoordinator>,
        staged_offline: Option<PersistedOfflineState>,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        self.ensure_running()?;
        if self.contacts.contains_key(&contact_id) {
            return Err(ApplicationCoordinatorError::ContactAlreadyOpen(contact_id));
        }
        if offline.is_some() && staged_offline.is_some() {
            return Err(ApplicationCoordinatorError::OfflineEnrollmentAlreadyActive);
        }
        if let Some(offline) = &offline {
            validate_offline_binding(&session, offline)?;
        }
        if let Some(staged) = &staged_offline {
            validate_staged_offline_binding(&session, staged)?;
        }
        let session_id = self.allocate_session_id()?;
        let has_deaddrop = offline.is_some();
        self.contacts.insert(contact_id.clone(), session_id);
        self.sessions.insert(
            session_id,
            ManagedSession::OneToOne(OneToOneRuntime {
                key: ManagedSessionKey::Contact(contact_id.clone()),
                session,
                offline,
                staged_offline,
                pending_offline_enrollment: BTreeMap::new(),
                pending_offline_persistence: BTreeMap::new(),
                rendezvous: ContactRendezvousState::default(),
                lifecycle: SessionLifecycle::open(has_deaddrop),
            }),
        );
        Ok(ApplicationOutput {
            actions: Vec::new(),
            events: vec![ApplicationEvent::SessionOpened {
                session_id,
                key: ManagedSessionKey::Contact(contact_id),
            }],
        })
    }

    pub fn open_transient(
        &mut self,
        transient_id: TransientId,
        session: OneToOneSession,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        self.ensure_running()?;
        if self.transients.contains_key(&transient_id) {
            return Err(ApplicationCoordinatorError::TransientAlreadyOpen(
                transient_id,
            ));
        }
        if session.config().pinned_peer().is_some() {
            return Err(ApplicationCoordinatorError::TransientRequiresUnpinnedSession);
        }
        let session_id = self.allocate_session_id()?;
        self.transients.insert(transient_id.clone(), session_id);
        self.sessions.insert(
            session_id,
            ManagedSession::OneToOne(OneToOneRuntime {
                key: ManagedSessionKey::Transient(transient_id.clone()),
                session,
                offline: None,
                staged_offline: None,
                pending_offline_enrollment: BTreeMap::new(),
                pending_offline_persistence: BTreeMap::new(),
                rendezvous: ContactRendezvousState::default(),
                lifecycle: SessionLifecycle::open(false),
            }),
        );
        Ok(ApplicationOutput {
            actions: Vec::new(),
            events: vec![ApplicationEvent::SessionOpened {
                session_id,
                key: ManagedSessionKey::Transient(transient_id),
            }],
        })
    }

    pub fn open_group(
        &mut self,
        group_id: GroupId,
        session: GroupSession,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        self.ensure_running()?;
        if self.groups.contains_key(&group_id) {
            return Err(ApplicationCoordinatorError::GroupAlreadyOpen(group_id));
        }
        let session_id = self.allocate_session_id()?;
        self.groups.insert(group_id.clone(), session_id);
        self.sessions.insert(
            session_id,
            ManagedSession::Group(GroupRuntime {
                group_id: group_id.clone(),
                session,
                lifecycle: SessionLifecycle::open(false),
            }),
        );
        Ok(ApplicationOutput {
            actions: Vec::new(),
            events: vec![ApplicationEvent::SessionOpened {
                session_id,
                key: ManagedSessionKey::Group(group_id),
            }],
        })
    }

    pub fn begin_contact_connect(
        &mut self,
        session_id: SessionId,
        peer_b32: &str,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        self.begin_contact_connect_at(session_id, peer_b32, 0)
    }

    pub fn begin_contact_connect_at(
        &mut self,
        session_id: SessionId,
        peer_b32: &str,
        now_ms: u64,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let runtime = self.contact_mut(session_id)?;
        ensure_session_open(&runtime.lifecycle)?;
        let output = runtime.session.begin_connect_at(peer_b32, now_ms)?;
        self.process_contact_output(session_id, output)
    }

    pub fn generate_contact_rendezvous_request(
        &mut self,
        session_id: SessionId,
        now_ms: u64,
    ) -> Result<String, ApplicationCoordinatorError> {
        let runtime = self.contact_mut(session_id)?;
        ensure_rendezvous_available(runtime)?;
        let (pending, encoded) = generate_request(now_ms)?;
        runtime.rendezvous.pending_request = Some(pending);
        runtime.rendezvous.outgoing = None;
        Ok(encoded)
    }

    pub fn answer_contact_rendezvous_request(
        &mut self,
        session_id: SessionId,
        encoded_request: &str,
        now_ms: u64,
    ) -> Result<String, ApplicationCoordinatorError> {
        let runtime = self.contact_mut(session_id)?;
        ensure_rendezvous_available(runtime)?;
        let (issued, response) = answer_request(
            encoded_request,
            runtime.session.config().local_b32(),
            now_ms,
        )?;
        runtime.rendezvous.issued = Some(issued);
        runtime.rendezvous.reserved_connection = None;
        Ok(response)
    }

    pub fn begin_contact_rendezvous_connect(
        &mut self,
        session_id: SessionId,
        encoded_response: &str,
        now_ms: u64,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let runtime = self.contact_mut(session_id)?;
        ensure_rendezvous_available(runtime)?;
        let pending = runtime
            .rendezvous
            .pending_request
            .as_ref()
            .ok_or(ApplicationCoordinatorError::RendezvousRequestMissing)?;
        let outgoing = open_response(encoded_response, pending, now_ms)?;
        let peer_b32 = outgoing.destination_b32().to_string();
        let proof = make_auth_signal(
            &outgoing,
            runtime.session.config().local_b32(),
            &peer_b32,
            now_ms,
        )?;
        let source = runtime.session.begin_connect_with_control_signals_at(
            &peer_b32,
            vec![proof],
            now_ms,
        )?;
        runtime.rendezvous.outgoing = Some(outgoing);
        self.process_contact_output(session_id, source)
    }

    pub fn revoke_contact_rendezvous(
        &mut self,
        session_id: SessionId,
    ) -> Result<(), ApplicationCoordinatorError> {
        let runtime = self.contact_mut(session_id)?;
        ensure_rendezvous_available(runtime)?;
        if let Some(issued) = runtime.rendezvous.issued.as_mut() {
            issued.revoke();
        }
        runtime.rendezvous = ContactRendezvousState::default();
        Ok(())
    }

    pub fn contact_outbound_connected(
        &mut self,
        session_id: SessionId,
        attempt_id: u64,
        connection_id: ConnectionId,
        peer_b32: &str,
        now_ms: u64,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let output = self.contact_mut(session_id)?.session.outbound_connected(
            attempt_id,
            connection_id,
            peer_b32,
            now_ms,
        );
        self.process_contact_output(session_id, output)
    }

    pub fn contact_outbound_failed(
        &mut self,
        session_id: SessionId,
        attempt_id: u64,
        reason: impl Into<String>,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let output = self
            .contact_mut(session_id)?
            .session
            .outbound_failed(attempt_id, reason);
        self.process_contact_output(session_id, output)
    }

    pub fn contact_outbound_failed_at(
        &mut self,
        session_id: SessionId,
        attempt_id: u64,
        reason: impl Into<String>,
        now_ms: u64,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let output = self
            .contact_mut(session_id)?
            .session
            .outbound_failed_at(attempt_id, reason, now_ms);
        self.process_contact_output(session_id, output)
    }

    pub fn contact_incoming_connected(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        peer_b32: &str,
        peer_destination: &str,
        now_ms: u64,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let output = self.contact_mut(session_id)?.session.incoming_connected(
            connection_id,
            peer_b32,
            peer_destination,
            now_ms,
        );
        self.process_contact_output(session_id, output)
    }

    pub fn accept_contact_incoming(
        &mut self,
        session_id: SessionId,
        now_ms: u64,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let output = self
            .contact_mut(session_id)?
            .session
            .accept_incoming(now_ms)?;
        self.process_contact_output(session_id, output)
    }

    pub fn decline_contact_incoming(
        &mut self,
        session_id: SessionId,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let connection_id = self
            .contact(session_id)?
            .session
            .pending_connection_id()
            .ok_or(OneToOneError::NoPendingIncoming)?;
        self.release_contact_rendezvous_connection(session_id, connection_id, true)?;
        let output = self.contact_mut(session_id)?.session.decline_incoming()?;
        self.process_contact_output(session_id, output)
    }

    pub fn disconnect_contact(
        &mut self,
        session_id: SessionId,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let runtime = self.contact_mut(session_id)?;
        ensure_session_open(&runtime.lifecycle)?;
        let output = runtime.session.disconnect();
        self.process_contact_output(session_id, output)
    }

    pub fn contact_pin_candidate(
        &self,
        session_id: SessionId,
    ) -> Result<crate::one_to_one::PinnedPeer, ApplicationCoordinatorError> {
        let runtime = self.contact(session_id)?;
        ensure_session_open(&runtime.lifecycle)?;
        Ok(runtime.session.active_peer_pin_candidate()?)
    }

    pub fn pin_contact_peer(
        &mut self,
        session_id: SessionId,
        pin: crate::one_to_one::PinnedPeer,
    ) -> Result<(), ApplicationCoordinatorError> {
        let runtime = self.contact_mut(session_id)?;
        ensure_session_open(&runtime.lifecycle)?;
        runtime.session.pin_active_peer(pin)?;
        Ok(())
    }

    pub fn begin_contact_offline_enrollment(
        &mut self,
        session_id: SessionId,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let runtime = self.contact(session_id)?;
        ensure_session_open(&runtime.lifecycle)?;
        validate_ready_pinned_contact(&runtime.session)?;

        if !runtime.pending_offline_enrollment.is_empty() {
            return Ok(ApplicationOutput::default());
        }

        if !local_is_offline_secret_authority(&runtime.session)? {
            if contact_offline_secret(runtime).is_some() {
                return Ok(ApplicationOutput::default());
            }
            let request = self
                .contact_mut(session_id)?
                .session
                .send_control_signal(OFFLINE_SECRET_REQUEST_SIGNAL)?;
            return Ok(wrap_one_to_one_output(session_id, request));
        }

        if let Some(shared_secret) = contact_offline_secret(runtime) {
            return self.send_contact_offline_secret(session_id, shared_secret);
        }

        let mut shared_secret = [0u8; OFFLINE_SHARED_SECRET_BYTES];
        while shared_secret.iter().all(|byte| *byte == 0) {
            OsRng.fill_bytes(&mut shared_secret);
        }
        let state = PersistedOfflineState::new(shared_secret, &OfflineState::default())
            .map_err(|error| ApplicationCoordinatorError::OfflineEnrollment(error.to_string()))?;
        self.queue_contact_offline_enrollment(session_id, state, true)
    }

    pub fn receive_contact_frame(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        frame: Frame,
        now_ms: u64,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let mut output =
            self.contact_mut(session_id)?
                .session
                .receive_frame(connection_id, frame, now_ms);
        let rendezvous_events =
            self.process_contact_rendezvous_events(session_id, &mut output, now_ms)?;
        let mut application_output = self.process_contact_output(session_id, output)?;
        application_output.events.extend(rendezvous_events);
        Ok(application_output)
    }

    pub fn send_contact_frame(
        &mut self,
        session_id: SessionId,
        message_type: MessageType,
        message_id: u64,
        plaintext: &[u8],
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let runtime = self.contact_mut(session_id)?;
        ensure_session_open(&runtime.lifecycle)?;
        let connection_id = runtime
            .session
            .active_connection_id()
            .ok_or(ApplicationCoordinatorError::ContactNotReady)?;
        let frame = runtime
            .session
            .seal_application_frame(message_type, message_id, plaintext)?;
        Ok(ApplicationOutput {
            actions: vec![ApplicationAction::OneToOne {
                session_id,
                action: OneToOneAction::SendFrame {
                    connection_id,
                    frame,
                },
            }],
            events: Vec::new(),
        })
    }

    pub fn begin_group_connections(
        &mut self,
        session_id: SessionId,
        now_ms: u64,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let runtime = self.group_mut(session_id)?;
        ensure_session_open(&runtime.lifecycle)?;
        let output = runtime.session.begin_connections(now_ms);
        Ok(wrap_group_output(session_id, output))
    }

    pub fn group_outbound_connected(
        &mut self,
        session_id: SessionId,
        peer_b32: &str,
        attempt_id: u64,
        connection_id: ConnectionId,
        now_ms: u64,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let output = self.group_mut(session_id)?.session.outbound_connected(
            peer_b32,
            attempt_id,
            connection_id,
            now_ms,
        );
        Ok(wrap_group_output(session_id, output))
    }

    pub fn group_outbound_failed(
        &mut self,
        session_id: SessionId,
        peer_b32: &str,
        attempt_id: u64,
        reason: impl Into<String>,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let output = self
            .group_mut(session_id)?
            .session
            .outbound_failed(peer_b32, attempt_id, reason);
        Ok(wrap_group_output(session_id, output))
    }

    pub fn group_incoming_connected(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        peer_b32: &str,
        peer_destination: &str,
        now_ms: u64,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let output = self.group_mut(session_id)?.session.incoming_connected(
            connection_id,
            peer_b32,
            peer_destination,
            now_ms,
        );
        Ok(wrap_group_output(session_id, output))
    }

    pub fn receive_group_frame(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        frame: Frame,
        now_ms: u64,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let output =
            self.group_mut(session_id)?
                .session
                .receive_frame(connection_id, frame, now_ms);
        Ok(wrap_group_output(session_id, output))
    }

    pub fn send_group_text(
        &mut self,
        session_id: SessionId,
        message_id: u64,
        text: &str,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let runtime = self.group_mut(session_id)?;
        ensure_session_open(&runtime.lifecycle)?;
        let output = runtime.session.send_text(message_id, text)?;
        Ok(wrap_group_output(session_id, output))
    }

    pub fn authorize_group_peer(
        &mut self,
        session_id: SessionId,
        member: GroupMemberRecord,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let runtime = self.group_mut(session_id)?;
        ensure_session_open(&runtime.lifecycle)?;
        runtime.session.authorize_peer(member)?;
        Ok(ApplicationOutput::default())
    }

    pub fn replace_group_roster(
        &mut self,
        session_id: SessionId,
        members: Vec<GroupMemberRecord>,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let runtime = self.group_mut(session_id)?;
        ensure_session_open(&runtime.lifecycle)?;
        let output = runtime.session.replace_roster(members)?;
        Ok(wrap_group_output(session_id, output))
    }

    pub fn send_group_roster(
        &mut self,
        session_id: SessionId,
        message_id: u64,
        roster: &GroupRosterSync,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let runtime = self.group_mut(session_id)?;
        ensure_session_open(&runtime.lifecycle)?;
        let output = runtime.session.send_roster(message_id, roster)?;
        Ok(wrap_group_output(session_id, output))
    }

    pub fn send_group_dissolution(
        &mut self,
        session_id: SessionId,
        message_id: u64,
        dissolution: &GroupDissolution,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let runtime = self.group_mut(session_id)?;
        ensure_session_open(&runtime.lifecycle)?;
        let output = runtime.session.send_dissolution(message_id, dissolution)?;
        Ok(wrap_group_output(session_id, output))
    }

    pub fn send_group_control_to_owner(
        &mut self,
        session_id: SessionId,
        message_id: u64,
        control: &GroupControlMessage,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let runtime = self.group_mut(session_id)?;
        ensure_session_open(&runtime.lifecycle)?;
        let output = runtime.session.send_control_to_owner(message_id, control)?;
        Ok(wrap_group_output(session_id, output))
    }

    pub fn send_group_image(
        &mut self,
        session_id: SessionId,
        message_id: u64,
        filename: &str,
        mime: &str,
        bytes: &[u8],
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let runtime = self.group_mut(session_id)?;
        ensure_session_open(&runtime.lifecycle)?;
        let output = runtime
            .session
            .send_image(message_id, filename, mime, bytes)?;
        Ok(wrap_group_output(session_id, output))
    }

    pub fn send_group_image_with_original(
        &mut self,
        session_id: SessionId,
        message_id: u64,
        filename: &str,
        mime: &str,
        bytes: &[u8],
        original: Option<OriginalImageMetadata>,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let runtime = self.group_mut(session_id)?;
        ensure_session_open(&runtime.lifecycle)?;
        let output = runtime
            .session
            .send_image_with_original(message_id, filename, mime, bytes, original)?;
        Ok(wrap_group_output(session_id, output))
    }

    pub fn send_group_image_to_peer(
        &mut self,
        session_id: SessionId,
        peer_b32: &str,
        transfer_id: u64,
        header: &ImageTransferHeader,
        bytes: &[u8],
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let runtime = self.group_mut(session_id)?;
        ensure_session_open(&runtime.lifecycle)?;
        let output = runtime
            .session
            .send_image_to_peer(peer_b32, transfer_id, header, bytes)?;
        Ok(wrap_group_output(session_id, output))
    }

    pub fn send_group_original_image_control(
        &mut self,
        session_id: SessionId,
        peer_b32: &str,
        message_id: u64,
        control: OriginalImageControl,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let runtime = self.group_mut(session_id)?;
        ensure_session_open(&runtime.lifecycle)?;
        let output = runtime
            .session
            .send_original_image_control(peer_b32, message_id, control)?;
        Ok(wrap_group_output(session_id, output))
    }

    pub fn enter_contact_offline(
        &mut self,
        session_id: SessionId,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let output = self.contact_offline_mut(session_id)?.enter_offline()?;
        self.process_offline_output(session_id, output)
    }

    pub fn leave_contact_offline(
        &mut self,
        session_id: SessionId,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let output = self.contact_offline_mut(session_id)?.leave_offline()?;
        self.process_offline_output(session_id, output)
    }

    pub fn begin_offline_send(
        &mut self,
        session_id: SessionId,
        frame: Frame,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let output = self.contact_offline_mut(session_id)?.begin_send(frame)?;
        self.process_offline_output(session_id, output)
    }

    pub fn offline_put_completed(
        &mut self,
        session_id: SessionId,
        operation_id: OfflineOperationId,
        result: crate::deaddrop::PutResult,
        now_ms: u64,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let output =
            self.contact_offline_mut(session_id)?
                .put_completed(operation_id, result, now_ms)?;
        self.process_offline_output(session_id, output)
    }

    pub fn offline_put_failed(
        &mut self,
        session_id: SessionId,
        operation_id: OfflineOperationId,
        reason: impl Into<String>,
        now_ms: u64,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let output =
            self.contact_offline_mut(session_id)?
                .put_failed(operation_id, reason, now_ms)?;
        self.process_offline_output(session_id, output)
    }

    pub fn offline_get_completed(
        &mut self,
        session_id: SessionId,
        operation_id: OfflineOperationId,
        result: crate::deaddrop::GetResult,
        now_ms: u64,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let output =
            self.contact_offline_mut(session_id)?
                .get_completed(operation_id, result, now_ms)?;
        self.process_offline_output(session_id, output)
    }

    pub fn offline_get_failed(
        &mut self,
        session_id: SessionId,
        operation_id: OfflineOperationId,
        reason: impl Into<String>,
        now_ms: u64,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let output =
            self.contact_offline_mut(session_id)?
                .get_failed(operation_id, reason, now_ms)?;
        self.process_offline_output(session_id, output)
    }

    pub fn offline_index_sync_sent(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let output = self
            .contact_offline_mut(session_id)?
            .index_sync_sent(connection_id)?;
        self.process_offline_output(session_id, output)
    }

    pub fn offline_index_sync_send_failed(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        reason: impl Into<String>,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let output = self
            .contact_offline_mut(session_id)?
            .index_sync_send_failed(connection_id, reason)?;
        self.process_offline_output(session_id, output)
    }

    pub fn offline_enrollment_persistence_completed(
        &mut self,
        session_id: SessionId,
        enrollment_id: u64,
        result: Result<(), String>,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let contact_id = self.contact(session_id)?.contact_id()?.clone();
        if !self
            .contact(session_id)?
            .pending_offline_enrollment
            .contains_key(&enrollment_id)
        {
            return Err(ApplicationCoordinatorError::OfflineEnrollmentNotPending(
                enrollment_id,
            ));
        }

        let mut output = match result {
            Ok(()) => {
                let pending = self
                    .contact_mut(session_id)?
                    .pending_offline_enrollment
                    .remove(&enrollment_id)
                    .ok_or(ApplicationCoordinatorError::OfflineEnrollmentNotPending(
                        enrollment_id,
                    ))?;
                let shared_secret = *pending.state.shared_secret.expose_secret();
                self.contact_mut(session_id)?.staged_offline = Some(pending.state);
                let mut completed = ApplicationOutput {
                    actions: Vec::new(),
                    events: vec![ApplicationEvent::OfflineEnrollmentPersisted {
                        session_id,
                        contact_id,
                    }],
                };
                if pending.send_after_persist
                    && self.contact(session_id)?.lifecycle.phase == ManagedSessionPhase::Open
                    && self.contact(session_id)?.session.is_ready()
                {
                    completed.merge(self.send_contact_offline_secret_with_id(
                        session_id,
                        enrollment_id,
                        shared_secret,
                    )?);
                }
                completed
            }
            Err(reason) => ApplicationOutput {
                actions: Vec::new(),
                events: vec![ApplicationEvent::OperationFailed {
                    session_id: Some(session_id),
                    operation: "persist offline enrollment",
                    reason,
                }],
            },
        };
        self.finish_session_if_ready(session_id, &mut output)?;
        Ok(output)
    }

    pub fn retry_offline_enrollment_persistence(
        &self,
        session_id: SessionId,
        enrollment_id: u64,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let contact = self.contact(session_id)?;
        let pending = contact
            .pending_offline_enrollment
            .get(&enrollment_id)
            .ok_or(ApplicationCoordinatorError::OfflineEnrollmentNotPending(
                enrollment_id,
            ))?;
        Ok(ApplicationOutput {
            actions: vec![ApplicationAction::PersistContactOfflineEnrollment {
                session_id,
                contact_id: contact.contact_id()?.clone(),
                enrollment_id,
                state: pending.state.clone(),
            }],
            events: Vec::new(),
        })
    }

    pub fn offline_persistence_completed(
        &mut self,
        session_id: SessionId,
        mutation_id: u64,
        result: Result<(), String>,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let contact_id = self.contact(session_id)?.contact_id()?.clone();
        if !self
            .contact(session_id)?
            .pending_offline_persistence
            .contains_key(&mutation_id)
        {
            return Err(ApplicationCoordinatorError::OfflinePersistenceNotPending(
                mutation_id,
            ));
        }
        let mut output = match result {
            Ok(()) => {
                self.contact_mut(session_id)?
                    .pending_offline_persistence
                    .remove(&mutation_id);
                ApplicationOutput {
                    actions: Vec::new(),
                    events: vec![ApplicationEvent::OfflineStatePersisted {
                        session_id,
                        contact_id,
                        mutation_id,
                    }],
                }
            }
            Err(reason) => ApplicationOutput {
                actions: Vec::new(),
                events: vec![ApplicationEvent::OperationFailed {
                    session_id: Some(session_id),
                    operation: "persist offline state",
                    reason,
                }],
            },
        };
        self.finish_session_if_ready(session_id, &mut output)?;
        Ok(output)
    }

    pub fn retry_offline_persistence(
        &self,
        session_id: SessionId,
        mutation_id: u64,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let contact = self.contact(session_id)?;
        let state = contact
            .pending_offline_persistence
            .get(&mutation_id)
            .cloned()
            .ok_or(ApplicationCoordinatorError::OfflinePersistenceNotPending(
                mutation_id,
            ))?;
        Ok(ApplicationOutput {
            actions: vec![ApplicationAction::PersistContactOffline {
                session_id,
                contact_id: contact.contact_id()?.clone(),
                mutation_id,
                state,
            }],
            events: Vec::new(),
        })
    }

    pub fn tick(&mut self, now_ms: u64) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        if self.phase == ApplicationPhase::Stopped {
            return Ok(ApplicationOutput::default());
        }
        let session_ids = self.sessions.keys().copied().collect::<Vec<_>>();
        let mut output = ApplicationOutput::default();
        for session_id in session_ids {
            let phase = self
                .sessions
                .get(&session_id)
                .ok_or(ApplicationCoordinatorError::SessionNotFound(session_id))?
                .lifecycle()
                .phase;
            if phase != ManagedSessionPhase::Open {
                continue;
            }
            let is_contact = matches!(
                self.sessions.get(&session_id),
                Some(ManagedSession::OneToOne(_))
            );
            if is_contact {
                let (contact_output, offline_output) = {
                    let runtime = self.contact_mut(session_id)?;
                    let contact_output = runtime.session.tick(now_ms);
                    let offline_output = runtime
                        .offline
                        .as_mut()
                        .map(|offline| offline.tick(now_ms))
                        .transpose()?;
                    (contact_output, offline_output)
                };
                output.merge(self.process_contact_output(session_id, contact_output)?);
                if let Some(offline_output) = offline_output {
                    output.merge(self.process_offline_output(session_id, offline_output)?);
                }
            } else {
                let group_output = self.group_mut(session_id)?.session.tick(now_ms);
                output.merge(wrap_group_output(session_id, group_output));
            }
        }
        Ok(output)
    }

    pub fn close_session(
        &mut self,
        session_id: SessionId,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let key = self
            .sessions
            .get(&session_id)
            .ok_or(ApplicationCoordinatorError::SessionNotFound(session_id))?
            .key();
        if self
            .sessions
            .get(&session_id)
            .is_some_and(|session| session.lifecycle().phase == ManagedSessionPhase::Closing)
        {
            return Ok(ApplicationOutput::default());
        }

        let mut output = ApplicationOutput {
            actions: Vec::new(),
            events: vec![ApplicationEvent::SessionClosing { session_id, key }],
        };
        let offline_output = match self.sessions.get_mut(&session_id) {
            Some(ManagedSession::OneToOne(runtime)) => {
                runtime.lifecycle.phase = ManagedSessionPhase::Closing;
                if let Some(issued) = runtime.rendezvous.issued.as_mut() {
                    issued.revoke();
                }
                runtime.rendezvous = ContactRendezvousState::default();
                let chat_output = runtime.session.begin_shutdown();
                runtime.lifecycle.closing_connections =
                    one_to_one_close_connections(&chat_output.actions);
                output.merge(wrap_one_to_one_output(session_id, chat_output));
                runtime
                    .offline
                    .as_mut()
                    .map(OfflineCoordinator::begin_shutdown)
            }
            Some(ManagedSession::Group(runtime)) => {
                runtime.lifecycle.phase = ManagedSessionPhase::Closing;
                let group_output = runtime.session.begin_shutdown();
                runtime.lifecycle.closing_connections =
                    group_close_connections(&group_output.actions);
                output.merge(wrap_group_output(session_id, group_output));
                None
            }
            None => return Err(ApplicationCoordinatorError::SessionNotFound(session_id)),
        };
        if let Some(offline_output) = offline_output {
            output.merge(self.process_offline_output(session_id, offline_output)?);
        }
        self.request_sam_shutdown_if_ready(session_id, &mut output)?;
        Ok(output)
    }

    pub fn connection_closed(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        if matches!(
            self.sessions.get(&session_id),
            Some(ManagedSession::OneToOne(_))
        ) {
            self.release_contact_rendezvous_connection(session_id, connection_id, false)?;
        }
        let mut output = match self.sessions.get_mut(&session_id) {
            Some(ManagedSession::OneToOne(runtime)) => {
                runtime.lifecycle.closing_connections.remove(&connection_id);
                if let Some(offline) = runtime.offline.as_mut() {
                    offline.live_connection_closed(connection_id);
                }
                wrap_one_to_one_output(session_id, runtime.session.connection_closed(connection_id))
            }
            Some(ManagedSession::Group(runtime)) => {
                runtime.lifecycle.closing_connections.remove(&connection_id);
                wrap_group_output(session_id, runtime.session.connection_closed(connection_id))
            }
            None => return Err(ApplicationCoordinatorError::SessionNotFound(session_id)),
        };
        self.request_sam_shutdown_if_ready(session_id, &mut output)?;
        Ok(output)
    }

    pub fn sam_shutdown_completed(
        &mut self,
        session_id: SessionId,
        result: Result<(), String>,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let mut output = ApplicationOutput::default();
        match result {
            Ok(()) => {
                let lifecycle = self.lifecycle_mut(session_id)?;
                if !lifecycle.sam_shutdown_requested {
                    return Err(ApplicationCoordinatorError::SamShutdownNotRequested);
                }
                lifecycle.sam_shutdown_complete = true;
                self.finish_session_if_ready(session_id, &mut output)?;
            }
            Err(reason) => output.events.push(ApplicationEvent::OperationFailed {
                session_id: Some(session_id),
                operation: "shutdown SAM session",
                reason,
            }),
        }
        Ok(output)
    }

    pub fn retry_sam_shutdown(
        &mut self,
        session_id: SessionId,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let lifecycle = self.lifecycle_mut(session_id)?;
        if lifecycle.phase != ManagedSessionPhase::Closing
            || !lifecycle.sam_shutdown_requested
            || lifecycle.sam_shutdown_complete
        {
            return Err(ApplicationCoordinatorError::SamShutdownNotRequired);
        }
        Ok(ApplicationOutput {
            actions: vec![ApplicationAction::ShutdownSam { session_id }],
            events: Vec::new(),
        })
    }

    pub fn deaddrop_shutdown_completed(
        &mut self,
        session_id: SessionId,
        result: Result<(), String>,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let mut output = ApplicationOutput::default();
        match result {
            Ok(()) => {
                let offline_output = {
                    let runtime = self.contact_mut(session_id)?;
                    let offline = runtime
                        .offline
                        .as_mut()
                        .ok_or(ApplicationCoordinatorError::OfflineUnavailable)?;
                    let offline_output = offline.shutdown_completed()?;
                    runtime.lifecycle.deaddrop_shutdown_complete = true;
                    offline_output
                };
                output.merge(self.process_offline_output(session_id, offline_output)?);
                self.finish_session_if_ready(session_id, &mut output)?;
            }
            Err(reason) => output.events.push(ApplicationEvent::OperationFailed {
                session_id: Some(session_id),
                operation: "shutdown deaddrop runtime",
                reason,
            }),
        }
        Ok(output)
    }

    pub fn retry_deaddrop_shutdown(
        &self,
        session_id: SessionId,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let runtime = self.contact(session_id)?;
        if runtime.lifecycle.phase != ManagedSessionPhase::Closing
            || runtime.lifecycle.deaddrop_shutdown_complete
            || runtime.offline.is_none()
        {
            return Err(ApplicationCoordinatorError::DeaddropShutdownNotRequired);
        }
        Ok(ApplicationOutput {
            actions: vec![ApplicationAction::Offline {
                session_id,
                action: OfflineCoordinatorAction::ShutdownDeaddrop,
            }],
            events: Vec::new(),
        })
    }

    pub fn begin_shutdown(&mut self) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        match self.phase {
            ApplicationPhase::Stopped
            | ApplicationPhase::StoppingSessions
            | ApplicationPhase::LockingVault => return Ok(ApplicationOutput::default()),
            ApplicationPhase::Running => {}
        }
        self.phase = ApplicationPhase::StoppingSessions;
        let mut output = ApplicationOutput {
            actions: Vec::new(),
            events: vec![ApplicationEvent::Stopping],
        };
        let session_ids = self.sessions.keys().copied().collect::<Vec<_>>();
        for session_id in session_ids {
            output.merge(self.close_session(session_id)?);
        }
        self.request_vault_lock_if_ready(&mut output);
        Ok(output)
    }

    pub fn vault_lock_completed(
        &mut self,
        result: Result<(), String>,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        if self.phase != ApplicationPhase::LockingVault {
            return Err(ApplicationCoordinatorError::VaultLockNotRequested);
        }
        Ok(match result {
            Ok(()) => {
                self.phase = ApplicationPhase::Stopped;
                ApplicationOutput {
                    actions: Vec::new(),
                    events: vec![ApplicationEvent::Stopped],
                }
            }
            Err(reason) => ApplicationOutput {
                actions: Vec::new(),
                events: vec![ApplicationEvent::OperationFailed {
                    session_id: None,
                    operation: "lock vault",
                    reason,
                }],
            },
        })
    }

    pub fn retry_vault_lock(&self) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        if self.phase != ApplicationPhase::LockingVault {
            return Err(ApplicationCoordinatorError::VaultLockNotRequested);
        }
        Ok(ApplicationOutput {
            actions: vec![ApplicationAction::LockVault],
            events: vec![ApplicationEvent::VaultLockRequested],
        })
    }

    fn process_contact_output(
        &mut self,
        session_id: SessionId,
        mut source: OneToOneOutput,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let released_connections = source
            .events
            .iter()
            .filter_map(|event| match event {
                OneToOneEvent::ConnectionRejected { connection_id, .. } => Some(*connection_id),
                OneToOneEvent::CollisionResolved {
                    closed_connection: Some(connection_id),
                    ..
                } => Some(*connection_id),
                _ => None,
            })
            .collect::<Vec<_>>();
        for connection_id in released_connections {
            self.release_contact_rendezvous_connection(session_id, connection_id, false)?;
        }
        if source
            .events
            .iter()
            .any(|event| matches!(event, OneToOneEvent::Disconnected { .. }))
        {
            let reserved_connection = self
                .contact(session_id)?
                .rendezvous
                .reserved_connection
                .map(|(connection_id, _)| connection_id);
            if let Some(connection_id) = reserved_connection {
                self.release_contact_rendezvous_connection(session_id, connection_id, false)?;
            }
        }
        let ready_connections = source
            .events
            .iter()
            .filter_map(|event| match event {
                OneToOneEvent::SecureSessionReady {
                    connection_id,
                    peer_b32,
                } => Some((*connection_id, peer_b32.clone())),
                _ => None,
            })
            .collect::<Vec<_>>();
        let secure_ready = source
            .events
            .iter()
            .any(|event| matches!(event, OneToOneEvent::SecureSessionReady { .. }));
        let mut index_frames = Vec::new();
        let mut enrollment_frames = Vec::new();
        let mut enrollment_requested = false;
        source.events.retain(|event| match event {
            OneToOneEvent::ApplicationFrame { frame, .. }
                if frame.message_type == MessageType::I =>
            {
                index_frames.push(frame.clone());
                false
            }
            OneToOneEvent::ApplicationFrame { frame, .. }
                if frame.message_type == MessageType::X =>
            {
                enrollment_frames.push(frame.clone());
                false
            }
            OneToOneEvent::ControlSignal { signal, .. }
                if signal == OFFLINE_SECRET_REQUEST_SIGNAL =>
            {
                enrollment_requested = true;
                false
            }
            _ => true,
        });
        let mut output = wrap_one_to_one_output(session_id, source);

        for (connection_id, peer_b32) in ready_connections {
            output.events.extend(self.complete_contact_rendezvous(
                session_id,
                connection_id,
                peer_b32,
            )?);
        }

        for frame in enrollment_frames {
            match self.receive_contact_offline_secret(session_id, &frame) {
                Ok(enrollment_output) => output.merge(enrollment_output),
                Err(error) => output.events.push(ApplicationEvent::OperationFailed {
                    session_id: Some(session_id),
                    operation: "receive offline enrollment",
                    reason: error.to_string(),
                }),
            }
        }

        for frame in index_frames {
            let result = {
                let runtime = self.contact_mut(session_id)?;
                match runtime.offline.as_mut() {
                    Some(offline) => offline.receive_index_sync(&runtime.session, &frame),
                    None => {
                        output.events.push(ApplicationEvent::OperationFailed {
                            session_id: Some(session_id),
                            operation: "receive offline index sync",
                            reason: "contact has no offline coordinator".into(),
                        });
                        continue;
                    }
                }
            };
            match result {
                Ok(offline_output) => {
                    output.merge(self.process_offline_output(session_id, offline_output)?);
                }
                Err(error) => output.events.push(ApplicationEvent::OperationFailed {
                    session_id: Some(session_id),
                    operation: "receive offline index sync",
                    reason: error.to_string(),
                }),
            }
        }

        if enrollment_requested
            && self
                .contact(session_id)?
                .session
                .config()
                .pinned_peer()
                .is_some()
            && local_is_offline_secret_authority(&self.contact(session_id)?.session)?
        {
            match self.begin_contact_offline_enrollment(session_id) {
                Ok(enrollment_output) => output.merge(enrollment_output),
                Err(error) => output.events.push(ApplicationEvent::OperationFailed {
                    session_id: Some(session_id),
                    operation: "answer offline enrollment request",
                    reason: error.to_string(),
                }),
            }
        }

        if secure_ready
            && self
                .contact(session_id)?
                .session
                .config()
                .pinned_peer()
                .is_some()
        {
            match self.begin_contact_offline_enrollment(session_id) {
                Ok(enrollment_output) => output.merge(enrollment_output),
                Err(error) => output.events.push(ApplicationEvent::OperationFailed {
                    session_id: Some(session_id),
                    operation: "begin offline enrollment",
                    reason: error.to_string(),
                }),
            }
        }

        if secure_ready && self.contact(session_id)?.offline.is_some() {
            let message_id = self.allocate_internal_message_id()?;
            let prepared = {
                let runtime = self.contact_mut(session_id)?;
                runtime
                    .offline
                    .as_mut()
                    .map(|offline| offline.prepare_index_sync(&runtime.session, message_id))
            };
            if let Some(prepared) = prepared {
                match prepared {
                    Ok(offline_output) => {
                        output.merge(self.process_offline_output(session_id, offline_output)?);
                    }
                    Err(error) => output.events.push(ApplicationEvent::OperationFailed {
                        session_id: Some(session_id),
                        operation: "prepare offline index sync",
                        reason: error.to_string(),
                    }),
                }
            }
        }
        Ok(output)
    }

    fn process_contact_rendezvous_events(
        &mut self,
        session_id: SessionId,
        source: &mut OneToOneOutput,
        now_ms: u64,
    ) -> Result<Vec<ApplicationEvent>, ApplicationCoordinatorError> {
        let mut retained = Vec::with_capacity(source.events.len());
        let mut additional = OneToOneOutput::default();
        let mut application_events = Vec::new();

        for event in std::mem::take(&mut source.events) {
            match event {
                OneToOneEvent::ControlSignal {
                    connection_id,
                    signal,
                } if signal.starts_with(AUTH_SIGNAL_PREFIX) => {
                    let runtime = self.contact_mut(session_id)?;
                    let peer_b32 = runtime
                        .session
                        .peer_b32_for_connection(connection_id)
                        .unwrap_or("unknown")
                        .to_string();
                    let local_b32 = runtime.session.config().local_b32().to_string();
                    let result = (|| {
                        if runtime.session.connection_direction()
                            != Some(ConnectionDirection::Inbound)
                        {
                            return Err(RendezvousError::from(
                                "rendezvous proof is valid only on an incoming connection",
                            ));
                        }
                        let issued = runtime.rendezvous.issued.as_mut().ok_or_else(|| {
                            RendezvousError::from("no one-time rendezvous invitation is active")
                        })?;
                        verify_auth_signal(&signal, issued, &peer_b32, &local_b32, now_ms)?;
                        issued.reserve()?;
                        let request_id = issued.request_id();
                        runtime.rendezvous.reserved_connection = Some((connection_id, request_id));
                        Ok(())
                    })();

                    match result {
                        Ok(()) => application_events.push(ApplicationEvent::Rendezvous {
                            session_id,
                            event: RendezvousEvent::IncomingAuthenticated {
                                connection_id,
                                peer_b32,
                            },
                        }),
                        Err(error) => {
                            let mut rejected = runtime.session.reject_connection(
                                connection_id,
                                DisconnectReason::ProtocolViolation,
                            );
                            additional.actions.append(&mut rejected.actions);
                            additional.events.append(&mut rejected.events);
                            application_events.push(ApplicationEvent::Rendezvous {
                                session_id,
                                event: RendezvousEvent::AuthenticationRejected {
                                    connection_id,
                                    peer_b32,
                                    reason: error.to_string(),
                                },
                            });
                        }
                    }
                }
                event => retained.push(event),
            }
        }

        source.events = retained;
        source.actions.append(&mut additional.actions);
        source.events.append(&mut additional.events);
        Ok(application_events)
    }

    fn complete_contact_rendezvous(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        peer_b32: String,
    ) -> Result<Vec<ApplicationEvent>, ApplicationCoordinatorError> {
        let runtime = self.contact_mut(session_id)?;
        let mut events = Vec::new();
        let consumed = runtime
            .rendezvous
            .reserved_connection
            .is_some_and(|(reserved, _)| reserved == connection_id);
        if consumed {
            runtime
                .rendezvous
                .issued
                .as_mut()
                .ok_or_else(|| RendezvousError::from("reserved invitation state is missing"))?
                .consume()?;
            runtime.rendezvous.reserved_connection = None;
            events.push(ApplicationEvent::Rendezvous {
                session_id,
                event: RendezvousEvent::InvitationConsumed {
                    connection_id,
                    peer_b32: peer_b32.clone(),
                },
            });
        }
        if runtime.rendezvous.outgoing.is_some()
            && runtime.session.connection_direction() == Some(ConnectionDirection::Outbound)
        {
            runtime.rendezvous.pending_request = None;
            runtime.rendezvous.outgoing = None;
            events.push(ApplicationEvent::Rendezvous {
                session_id,
                event: RendezvousEvent::OutgoingAuthenticated {
                    connection_id,
                    peer_b32,
                },
            });
        }
        Ok(events)
    }

    fn release_contact_rendezvous_connection(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        revoke: bool,
    ) -> Result<(), ApplicationCoordinatorError> {
        let runtime = self.contact_mut(session_id)?;
        let Some((reserved_connection, request_id)) = runtime.rendezvous.reserved_connection else {
            return Ok(());
        };
        if reserved_connection != connection_id {
            return Ok(());
        }
        if let Some(issued) = runtime.rendezvous.issued.as_mut()
            && issued.request_id() == request_id
        {
            if revoke {
                issued.revoke();
            } else {
                issued.release();
            }
        }
        runtime.rendezvous.reserved_connection = None;
        Ok(())
    }

    fn receive_contact_offline_secret(
        &mut self,
        session_id: SessionId,
        frame: &Frame,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let shared_secret = {
            let runtime = self.contact(session_id)?;
            ensure_session_open(&runtime.lifecycle)?;
            validate_ready_pinned_contact(&runtime.session)?;
            if local_is_offline_secret_authority(&runtime.session)? {
                return Err(ApplicationCoordinatorError::OfflineEnrollmentUnexpectedSender);
            }
            let opened = runtime.session.open_application_frame(frame)?;
            let shared_secret: [u8; OFFLINE_SHARED_SECRET_BYTES] = opened
                .payload
                .as_slice()
                .try_into()
                .map_err(|_| ApplicationCoordinatorError::InvalidOfflineEnrollmentSecret)?;
            if shared_secret.iter().all(|byte| *byte == 0) {
                return Err(ApplicationCoordinatorError::InvalidOfflineEnrollmentSecret);
            }
            shared_secret
        };

        let runtime = self.contact(session_id)?;
        if let Some(existing) = contact_offline_secret(runtime) {
            return if existing == shared_secret {
                Ok(ApplicationOutput::default())
            } else {
                Err(ApplicationCoordinatorError::OfflineEnrollmentReplacement)
            };
        }
        if let Some(pending) = runtime.pending_offline_enrollment.values().next() {
            return if pending.state.shared_secret.expose_secret() == &shared_secret {
                Ok(ApplicationOutput::default())
            } else {
                Err(ApplicationCoordinatorError::OfflineEnrollmentReplacement)
            };
        }

        let state = PersistedOfflineState::new(shared_secret, &OfflineState::default())
            .map_err(|error| ApplicationCoordinatorError::OfflineEnrollment(error.to_string()))?;
        self.queue_contact_offline_enrollment(session_id, state, false)
    }

    fn queue_contact_offline_enrollment(
        &mut self,
        session_id: SessionId,
        state: PersistedOfflineState,
        send_after_persist: bool,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let enrollment_id = self.allocate_internal_message_id()?;
        let runtime = self.contact_mut(session_id)?;
        let contact_id = runtime.contact_id()?.clone();
        runtime.pending_offline_enrollment.insert(
            enrollment_id,
            PendingOfflineEnrollment {
                state: state.clone(),
                send_after_persist,
            },
        );
        Ok(ApplicationOutput {
            actions: vec![ApplicationAction::PersistContactOfflineEnrollment {
                session_id,
                contact_id,
                enrollment_id,
                state,
            }],
            events: Vec::new(),
        })
    }

    fn send_contact_offline_secret(
        &mut self,
        session_id: SessionId,
        shared_secret: [u8; OFFLINE_SHARED_SECRET_BYTES],
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let message_id = self.allocate_internal_message_id()?;
        self.send_contact_offline_secret_with_id(session_id, message_id, shared_secret)
    }

    fn send_contact_offline_secret_with_id(
        &mut self,
        session_id: SessionId,
        message_id: u64,
        shared_secret: [u8; OFFLINE_SHARED_SECRET_BYTES],
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let runtime = self.contact(session_id)?;
        ensure_session_open(&runtime.lifecycle)?;
        validate_ready_pinned_contact(&runtime.session)?;
        let connection_id = runtime
            .session
            .active_connection_id()
            .ok_or(ApplicationCoordinatorError::ContactNotReady)?;
        let frame =
            runtime
                .session
                .seal_application_frame(MessageType::X, message_id, &shared_secret)?;
        Ok(ApplicationOutput {
            actions: vec![ApplicationAction::OneToOne {
                session_id,
                action: OneToOneAction::SendFrame {
                    connection_id,
                    frame,
                },
            }],
            events: Vec::new(),
        })
    }

    fn process_offline_output(
        &mut self,
        session_id: SessionId,
        source: OfflineCoordinatorOutput,
    ) -> Result<ApplicationOutput, ApplicationCoordinatorError> {
        let runtime = self.contact_mut(session_id)?;
        let contact_id = runtime.contact_id()?.clone();
        for action in &source.actions {
            if let OfflineCoordinatorAction::PersistState { mutation_id, state } = action {
                runtime
                    .pending_offline_persistence
                    .insert(*mutation_id, state.clone());
            }
        }
        Ok(wrap_offline_output(session_id, contact_id, source))
    }

    fn request_sam_shutdown_if_ready(
        &mut self,
        session_id: SessionId,
        output: &mut ApplicationOutput,
    ) -> Result<(), ApplicationCoordinatorError> {
        let lifecycle = self.lifecycle_mut(session_id)?;
        if lifecycle.phase == ManagedSessionPhase::Closing
            && lifecycle.closing_connections.is_empty()
            && !lifecycle.sam_shutdown_requested
        {
            lifecycle.sam_shutdown_requested = true;
            output
                .actions
                .push(ApplicationAction::ShutdownSam { session_id });
        }
        Ok(())
    }

    fn finish_session_if_ready(
        &mut self,
        session_id: SessionId,
        output: &mut ApplicationOutput,
    ) -> Result<(), ApplicationCoordinatorError> {
        let ready = self
            .sessions
            .get(&session_id)
            .ok_or(ApplicationCoordinatorError::SessionNotFound(session_id))?
            .ready_to_remove();
        if !ready {
            return Ok(());
        }
        let session = self
            .sessions
            .remove(&session_id)
            .ok_or(ApplicationCoordinatorError::SessionNotFound(session_id))?;
        let key = session.key();
        match &key {
            ManagedSessionKey::Contact(contact_id) => {
                self.contacts.remove(contact_id);
            }
            ManagedSessionKey::Transient(transient_id) => {
                self.transients.remove(transient_id);
            }
            ManagedSessionKey::Group(group_id) => {
                self.groups.remove(group_id);
            }
        }
        output
            .events
            .push(ApplicationEvent::SessionClosed { session_id, key });
        self.request_vault_lock_if_ready(output);
        Ok(())
    }

    fn request_vault_lock_if_ready(&mut self, output: &mut ApplicationOutput) {
        if self.phase == ApplicationPhase::StoppingSessions && self.sessions.is_empty() {
            self.phase = ApplicationPhase::LockingVault;
            output.actions.push(ApplicationAction::LockVault);
            output.events.push(ApplicationEvent::VaultLockRequested);
        }
    }

    fn contact(
        &self,
        session_id: SessionId,
    ) -> Result<&OneToOneRuntime, ApplicationCoordinatorError> {
        match self.sessions.get(&session_id) {
            Some(ManagedSession::OneToOne(runtime)) => Ok(runtime),
            Some(ManagedSession::Group(_)) => {
                Err(ApplicationCoordinatorError::ExpectedContact(session_id))
            }
            None => Err(ApplicationCoordinatorError::SessionNotFound(session_id)),
        }
    }

    fn contact_mut(
        &mut self,
        session_id: SessionId,
    ) -> Result<&mut OneToOneRuntime, ApplicationCoordinatorError> {
        match self.sessions.get_mut(&session_id) {
            Some(ManagedSession::OneToOne(runtime)) => Ok(runtime),
            Some(ManagedSession::Group(_)) => {
                Err(ApplicationCoordinatorError::ExpectedContact(session_id))
            }
            None => Err(ApplicationCoordinatorError::SessionNotFound(session_id)),
        }
    }

    fn contact_offline_mut(
        &mut self,
        session_id: SessionId,
    ) -> Result<&mut OfflineCoordinator, ApplicationCoordinatorError> {
        let runtime = self.contact_mut(session_id)?;
        ensure_session_open(&runtime.lifecycle)?;
        runtime
            .offline
            .as_mut()
            .ok_or(ApplicationCoordinatorError::OfflineUnavailable)
    }

    fn group_mut(
        &mut self,
        session_id: SessionId,
    ) -> Result<&mut GroupRuntime, ApplicationCoordinatorError> {
        match self.sessions.get_mut(&session_id) {
            Some(ManagedSession::Group(runtime)) => Ok(runtime),
            Some(ManagedSession::OneToOne(_)) => {
                Err(ApplicationCoordinatorError::ExpectedGroup(session_id))
            }
            None => Err(ApplicationCoordinatorError::SessionNotFound(session_id)),
        }
    }

    fn lifecycle_mut(
        &mut self,
        session_id: SessionId,
    ) -> Result<&mut SessionLifecycle, ApplicationCoordinatorError> {
        self.sessions
            .get_mut(&session_id)
            .map(ManagedSession::lifecycle_mut)
            .ok_or(ApplicationCoordinatorError::SessionNotFound(session_id))
    }

    fn ensure_running(&self) -> Result<(), ApplicationCoordinatorError> {
        if self.phase != ApplicationPhase::Running {
            return Err(ApplicationCoordinatorError::ApplicationNotRunning(
                self.phase,
            ));
        }
        Ok(())
    }

    fn allocate_session_id(&mut self) -> Result<SessionId, ApplicationCoordinatorError> {
        let session_id = SessionId::new(self.next_session_id);
        self.next_session_id = self
            .next_session_id
            .checked_add(1)
            .ok_or(ApplicationCoordinatorError::SessionIdExhausted)?;
        Ok(session_id)
    }

    fn allocate_internal_message_id(&mut self) -> Result<u64, ApplicationCoordinatorError> {
        let message_id = self.next_internal_message_id;
        self.next_internal_message_id = self
            .next_internal_message_id
            .checked_add(1)
            .ok_or(ApplicationCoordinatorError::MessageIdExhausted)?;
        Ok(message_id)
    }
}

impl Default for ApplicationCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_offline_binding(
    session: &OneToOneSession,
    offline: &OfflineCoordinator,
) -> Result<(), ApplicationCoordinatorError> {
    let pinned = session
        .config()
        .pinned_peer()
        .ok_or(ApplicationCoordinatorError::OfflineRequiresPinnedContact)?;
    if !session
        .config()
        .local_b32()
        .eq_ignore_ascii_case(&offline.context().my_b32())
        || !pinned
            .b32()
            .eq_ignore_ascii_case(&offline.context().peer_b32())
    {
        return Err(ApplicationCoordinatorError::OfflineIdentityMismatch);
    }
    Ok(())
}

fn validate_staged_offline_binding(
    session: &OneToOneSession,
    staged: &PersistedOfflineState,
) -> Result<(), ApplicationCoordinatorError> {
    let pinned = session
        .config()
        .pinned_peer()
        .ok_or(ApplicationCoordinatorError::OfflineRequiresPinnedContact)?;
    let state = staged
        .restore()
        .map_err(|error| ApplicationCoordinatorError::OfflineEnrollment(error.to_string()))?;
    let offline = OfflineCoordinator::new(
        *staged.shared_secret.expose_secret(),
        session.config().local_b32(),
        pinned.b32(),
        state,
    )?;
    validate_offline_binding(session, &offline)
}

fn validate_ready_pinned_contact(
    session: &OneToOneSession,
) -> Result<(), ApplicationCoordinatorError> {
    if !session.is_ready() {
        return Err(ApplicationCoordinatorError::ContactNotReady);
    }
    let pinned = session
        .config()
        .pinned_peer()
        .ok_or(ApplicationCoordinatorError::OfflineRequiresPinnedContact)?;
    if !session
        .active_peer_b32()
        .is_some_and(|peer| peer.eq_ignore_ascii_case(pinned.b32()))
        || session.active_peer_destination() != Some(pinned.destination())
    {
        return Err(ApplicationCoordinatorError::OfflineIdentityMismatch);
    }
    Ok(())
}

fn local_is_offline_secret_authority(
    session: &OneToOneSession,
) -> Result<bool, ApplicationCoordinatorError> {
    let pinned = session
        .config()
        .pinned_peer()
        .ok_or(ApplicationCoordinatorError::OfflineRequiresPinnedContact)?;
    Ok(session.config().local_b32().to_ascii_lowercase() < pinned.b32().to_ascii_lowercase())
}

fn contact_offline_secret(runtime: &OneToOneRuntime) -> Option<[u8; OFFLINE_SHARED_SECRET_BYTES]> {
    runtime
        .offline
        .as_ref()
        .map(|offline| offline.context().shared_secret())
        .or_else(|| {
            runtime
                .staged_offline
                .as_ref()
                .map(|state| *state.shared_secret.expose_secret())
        })
}

fn ensure_session_open(lifecycle: &SessionLifecycle) -> Result<(), ApplicationCoordinatorError> {
    if lifecycle.phase != ManagedSessionPhase::Open {
        return Err(ApplicationCoordinatorError::SessionClosing);
    }
    Ok(())
}

fn ensure_rendezvous_available(
    runtime: &OneToOneRuntime,
) -> Result<(), ApplicationCoordinatorError> {
    ensure_session_open(&runtime.lifecycle)?;
    if runtime.session.phase() != OneToOnePhase::Standby
        || runtime.session.config().pinned_peer().is_some()
        || runtime
            .offline
            .as_ref()
            .is_some_and(|offline| offline.mode() == OfflineCoordinatorMode::Offline)
    {
        return Err(ApplicationCoordinatorError::RendezvousUnavailable);
    }
    Ok(())
}

fn wrap_one_to_one_output(session_id: SessionId, source: OneToOneOutput) -> ApplicationOutput {
    ApplicationOutput {
        actions: source
            .actions
            .into_iter()
            .map(|action| ApplicationAction::OneToOne { session_id, action })
            .collect(),
        events: source
            .events
            .into_iter()
            .map(|event| ApplicationEvent::OneToOne { session_id, event })
            .collect(),
    }
}

fn wrap_group_output(session_id: SessionId, source: GroupSessionOutput) -> ApplicationOutput {
    ApplicationOutput {
        actions: source
            .actions
            .into_iter()
            .map(|action| ApplicationAction::Group { session_id, action })
            .collect(),
        events: source
            .events
            .into_iter()
            .map(|event| ApplicationEvent::Group { session_id, event })
            .collect(),
    }
}

fn wrap_offline_output(
    session_id: SessionId,
    contact_id: ContactId,
    source: OfflineCoordinatorOutput,
) -> ApplicationOutput {
    let actions = source
        .actions
        .into_iter()
        .map(|action| match action {
            OfflineCoordinatorAction::PersistState { mutation_id, state } => {
                ApplicationAction::PersistContactOffline {
                    session_id,
                    contact_id: contact_id.clone(),
                    mutation_id,
                    state,
                }
            }
            action => ApplicationAction::Offline { session_id, action },
        })
        .collect();
    let events = source
        .events
        .into_iter()
        .map(|event| ApplicationEvent::Offline { session_id, event })
        .collect();
    ApplicationOutput { actions, events }
}

fn one_to_one_close_connections(actions: &[OneToOneAction]) -> BTreeSet<ConnectionId> {
    actions
        .iter()
        .filter_map(|action| match action {
            OneToOneAction::CloseConnection { connection_id }
            | OneToOneAction::NotifyAndClose { connection_id, .. } => Some(*connection_id),
            _ => None,
        })
        .collect()
}

fn group_close_connections(actions: &[GroupSessionAction]) -> BTreeSet<ConnectionId> {
    actions
        .iter()
        .filter_map(|action| match action {
            GroupSessionAction::CloseConnection { connection_id }
            | GroupSessionAction::NotifyAndClose { connection_id, .. } => Some(*connection_id),
            _ => None,
        })
        .collect()
}

#[derive(Debug, Error)]
pub enum ApplicationCoordinatorError {
    #[error(transparent)]
    OneToOne(#[from] OneToOneError),
    #[error(transparent)]
    Group(#[from] GroupSessionError),
    #[error(transparent)]
    Offline(#[from] OfflineCoordinatorError),
    #[error(transparent)]
    Rendezvous(#[from] RendezvousError),
    #[error("application is not running: {0:?}")]
    ApplicationNotRunning(ApplicationPhase),
    #[error("session not found: {0}")]
    SessionNotFound(SessionId),
    #[error("session {0} is not a contact session")]
    ExpectedContact(SessionId),
    #[error("session {0} is not a group session")]
    ExpectedGroup(SessionId),
    #[error("contact is already open: {0}")]
    ContactAlreadyOpen(ContactId),
    #[error("transient session is already open: {0}")]
    TransientAlreadyOpen(TransientId),
    #[error("transient sessions cannot have a persistent peer pin")]
    TransientRequiresUnpinnedSession,
    #[error("group is already open: {0}")]
    GroupAlreadyOpen(GroupId),
    #[error("session is closing")]
    SessionClosing,
    #[error("contact live session is not ready")]
    ContactNotReady,
    #[error("authenticated rendezvous requires an unpinned online 1:1 session in standby")]
    RendezvousUnavailable,
    #[error("generate a rendezvous request before opening its response")]
    RendezvousRequestMissing,
    #[error("offline operation is unavailable for this contact")]
    OfflineUnavailable,
    #[error("offline coordinator requires an exact pinned persistent contact")]
    OfflineRequiresPinnedContact,
    #[error("offline and live contact identities differ")]
    OfflineIdentityMismatch,
    #[error("offline persistence mutation is not pending: {0}")]
    OfflinePersistenceNotPending(u64),
    #[error("offline enrollment persistence is not pending: {0}")]
    OfflineEnrollmentNotPending(u64),
    #[error("offline enrollment failed: {0}")]
    OfflineEnrollment(String),
    #[error("offline enrollment is already attached to an active offline coordinator")]
    OfflineEnrollmentAlreadyActive,
    #[error("offline enrollment secret must be exactly 32 nonzero bytes")]
    InvalidOfflineEnrollmentSecret,
    #[error("offline enrollment secret was sent by the non-authoritative peer")]
    OfflineEnrollmentUnexpectedSender,
    #[error("an established offline secret cannot be replaced")]
    OfflineEnrollmentReplacement,
    #[error("SAM shutdown was not requested")]
    SamShutdownNotRequested,
    #[error("SAM shutdown is not required")]
    SamShutdownNotRequired,
    #[error("deaddrop shutdown is not required")]
    DeaddropShutdownNotRequired,
    #[error("vault lock was not requested")]
    VaultLockNotRequested,
    #[error("application session identifier counter is exhausted")]
    SessionIdExhausted,
    #[error("application internal message identifier counter is exhausted")]
    MessageIdExhausted,
}
