//! Stable, presentation-neutral layer between CommTools and UI shells.
//!
//! A frontend submits commands, renders snapshots, and consumes events. It
//! should not duplicate session state transitions locally(!).

use crate::{ApplicationDriver, DriverError, HistoryWriteOutcome, SamMonitorStatus, SamTestStatus};
use commtools_core::{
    ACTIVE_DEADDROP_REPLICA_COUNT, ApplicationPhase, CollisionWinner, ContactBackupInspection,
    ContactId, DisconnectReason, GlobalSettings, GroupCollisionWinner, GroupDisconnectReason,
    GroupId, HistoryRecord, ManagedSessionInfo, ManagedSessionKey, ManagedSessionPhase,
    OfflineCoordinatorMode, OneToOnePhase, OriginalImageMetadata, SamFailureAction, SessionId,
    TransientId, TunnelSettings, ranked_deaddrop_servers,
};
use std::collections::BTreeSet;
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionSummary {
    pub session_id: SessionId,
    pub key: ManagedSessionKey,
    pub phase: ManagedSessionPhase,
    pub local_b32: Option<String>,
    pub peer_b32: Option<String>,
    pub pinned_peer_b32: Option<String>,
    pub one_to_one_phase: Option<OneToOnePhase>,
    pub offline_mode: Option<OfflineCoordinatorMode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ContactSummary {
    pub id: ContactId,
    pub display_name: String,
    pub local_b32: Option<String>,
    pub peer_b32: Option<String>,
    pub peer_pinned: bool,
    pub pq_enabled: bool,
    pub history_enabled: bool,
    pub tunnels: TunnelSettings,
    pub deaddrop_servers: Vec<String>,
    pub deaddrop_profiles: Vec<DeaddropServerSummary>,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeaddropServerSummary {
    pub address: String,
    pub active: bool,
    pub put_ok: u64,
    pub put_fail: u64,
    pub get_ok: u64,
    pub get_fail: u64,
    pub latency_ema_ms: Option<u64>,
    pub last_success_ms: Option<u64>,
}

impl DeaddropServerSummary {
    pub fn new(address: impl Into<String>, active: bool) -> Self {
        Self {
            address: address.into(),
            active,
            put_ok: 0,
            put_fail: 0,
            get_ok: 0,
            get_fail: 0,
            latency_ema_ms: None,
            last_success_ms: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GroupMemberSummary {
    pub name: String,
    pub b32: String,
    pub owner: bool,
    pub local: bool,
    pub connected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GroupSummary {
    pub id: GroupId,
    pub display_name: String,
    pub local_b32: Option<String>,
    pub local_member_name: String,
    pub history_enabled: bool,
    pub owner_b32: Option<String>,
    pub owner: bool,
    pub roster_version: u64,
    pub members: Vec<GroupMemberSummary>,
    pub active: bool,
    pub owner_ready: bool,
    pub leave_pending: bool,
    pub ready_member_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextSendResult {
    pub session_id: SessionId,
    pub message_id: u64,
    pub text: String,
    pub timestamp_utc: String,
    pub offline: bool,
    pub expected_group_recipients: Vec<String>,
    pub history: HistoryWriteOutcome,
    pub history_warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextReceivedEvent {
    pub session_id: SessionId,
    pub message_id: u64,
    pub text: String,
    pub timestamp_utc: String,
    pub sender_b32: Option<String>,
    pub offline: bool,
    pub offline_index: Option<u64>,
    pub history: HistoryWriteOutcome,
    pub history_warning: Option<String>,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextDeliveryEvent {
    pub session_id: SessionId,
    pub message_id: u64,
    pub peer_b32: Option<String>,
    pub group: bool,
    pub received: usize,
    pub expected: usize,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageSendResult {
    pub session_id: SessionId,
    pub message_id: u64,
    pub filename: String,
    pub mime: String,
    pub bytes: Vec<u8>,
    pub timestamp_utc: String,
    pub expected_group_recipients: Vec<String>,
    pub original: Option<OriginalImageMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReceivedEvent {
    pub session_id: SessionId,
    pub message_id: u64,
    pub filename: String,
    pub mime: String,
    pub bytes: Vec<u8>,
    pub timestamp_utc: String,
    pub sender_b32: Option<String>,
    pub original: Option<OriginalImageMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginalImageData {
    pub mime: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginalImageReceivedEvent {
    pub session_id: SessionId,
    pub transfer_id: u64,
    pub media_id: u64,
    pub filename: String,
    pub mime: String,
    pub bytes: Vec<u8>,
    pub sender_b32: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginalImageRequestResult {
    Requested,
    Cached(OriginalImageReceivedEvent),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageDeliveryEvent {
    pub session_id: SessionId,
    pub message_id: u64,
    pub group: bool,
    pub received: usize,
    pub expected: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOfferResult {
    pub session_id: SessionId,
    pub transfer_id: u64,
    pub filename: String,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileTransferDirection {
    Sent,
    Received,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileTransferEvent {
    Offered {
        session_id: SessionId,
        transfer_id: u64,
        direction: FileTransferDirection,
        filename: String,
        total_bytes: u64,
    },
    Started {
        session_id: SessionId,
        transfer_id: u64,
        direction: FileTransferDirection,
        filename: String,
        total_bytes: u64,
    },
    Progress {
        session_id: SessionId,
        transfer_id: u64,
        direction: FileTransferDirection,
        transferred_bytes: u64,
        total_bytes: u64,
    },
    Completed {
        session_id: SessionId,
        transfer_id: u64,
        direction: FileTransferDirection,
        filename: String,
        total_bytes: u64,
        path: Option<PathBuf>,
    },
    Declined {
        session_id: SessionId,
        transfer_id: u64,
        direction: FileTransferDirection,
        filename: String,
    },
    Cancelled {
        session_id: SessionId,
        transfer_id: u64,
        direction: FileTransferDirection,
        filename: String,
    },
    Expired {
        session_id: SessionId,
        transfer_id: u64,
        direction: FileTransferDirection,
        filename: String,
    },
    Failed {
        session_id: SessionId,
        transfer_id: u64,
        direction: FileTransferDirection,
        filename: Option<String>,
        reason: String,
    },
}

/// Presentation-neutral commands supported by the runtime.

#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommToolsCommand {
    CreateContact {
        display_name: String,
    },
    RenameContact {
        contact_id: ContactId,
        display_name: String,
    },
    DeleteContact {
        contact_id: ContactId,
    },
    ResetContact {
        contact_id: ContactId,
    },
    ExportContactBackup {
        contact_id: ContactId,
        path: PathBuf,
        passphrase: Zeroizing<String>,
        include_history: bool,
    },
    InspectContactBackup {
        path: PathBuf,
        passphrase: Zeroizing<String>,
    },
    ImportContactBackup {
        path: PathBuf,
        passphrase: Zeroizing<String>,
        replace: bool,
    },
    LockContactPeer {
        session_id: SessionId,
    },
    UnlockContact {
        contact_id: ContactId,
    },
    SetContactTunnelSettings {
        contact_id: ContactId,
        tunnels: TunnelSettings,
    },
    SetContactHistoryEnabled {
        contact_id: ContactId,
        enabled: bool,
    },
    AddContactDeaddropServer {
        contact_id: ContactId,
        server: String,
    },
    RemoveContactDeaddropServer {
        contact_id: ContactId,
        server: String,
    },
    CreateGroup {
        display_name: String,
    },
    DeleteGroup {
        group_id: GroupId,
    },
    SetGroupLocalName {
        group_id: GroupId,
        local_name: String,
    },
    SetGroupHistoryEnabled {
        group_id: GroupId,
        enabled: bool,
    },
    LoadHistory {
        key: ManagedSessionKey,
    },
    ClearHistory {
        key: ManagedSessionKey,
    },
    RemoveGroupMember {
        group_id: GroupId,
        member_b32: String,
    },
    RequestGroupLeave {
        group_id: GroupId,
    },
    LeaveGroupLocally {
        group_id: GroupId,
    },
    DissolveGroup {
        group_id: GroupId,
    },
    IssuePublicGroupInvite {
        group_id: GroupId,
    },
    GeneratePrivateGroupRequest,
    IssuePrivateGroupInvite {
        group_id: GroupId,
        encoded_request: String,
    },
    ImportPublicGroupInvite {
        encoded_invite: String,
    },
    ImportPrivateGroupInvite {
        encoded_invite: String,
    },
    OpenContact {
        contact_id: ContactId,
    },
    OpenTransient,
    OpenGroup {
        group_id: GroupId,
    },
    CloseSession {
        session_id: SessionId,
    },
    ConnectContact {
        session_id: SessionId,
        peer_b32: String,
    },
    AcceptContactIncoming {
        session_id: SessionId,
    },
    DeclineContactIncoming {
        session_id: SessionId,
    },
    DisconnectContact {
        session_id: SessionId,
    },
    EnterContactOffline {
        session_id: SessionId,
    },
    LeaveContactOffline {
        session_id: SessionId,
    },
    GenerateContactRendezvousRequest {
        session_id: SessionId,
    },
    AnswerContactRendezvousRequest {
        session_id: SessionId,
        encoded_request: String,
    },
    ConnectContactRendezvous {
        session_id: SessionId,
        encoded_response: String,
    },
    RevokeContactRendezvous {
        session_id: SessionId,
    },
    SendText {
        session_id: SessionId,
        text: String,
    },
    SendImage {
        session_id: SessionId,
        filename: String,
        mime: String,
        bytes: Vec<u8>,
    },
    SendImageWithOriginal {
        session_id: SessionId,
        filename: String,
        mime: String,
        bytes: Vec<u8>,
        original: OriginalImageData,
    },
    RequestOriginalImage {
        session_id: SessionId,
        media_id: u64,
        sender_b32: Option<String>,
    },
    CancelOriginalImage {
        session_id: SessionId,
        media_id: u64,
        sender_b32: Option<String>,
    },
    OfferFile {
        session_id: SessionId,
        path: PathBuf,
    },
    AcceptFile {
        session_id: SessionId,
        transfer_id: u64,
    },
    DeclineFile {
        session_id: SessionId,
        transfer_id: u64,
    },
    CancelFile {
        session_id: SessionId,
        transfer_id: u64,
    },
    SetSamHost(String),
    SetSamPort(u16),
    SetDefaultTunnelSettings(TunnelSettings),
    SetSamLivenessEnabled(bool),
    SetSamFailureAction(SamFailureAction),
    TestSam,
    ExportBackup {
        path: PathBuf,
        passphrase: Zeroizing<String>,
        include_files: bool,
    },
    RestoreBackup {
        path: PathBuf,
        passphrase: Zeroizing<String>,
        restore_files: bool,
    },
    AuthorizeWipeAll {
        vault_passphrase: Zeroizing<String>,
    },
    BeginShutdown,
}

/// Result returned after a runtime command completes its synchronous state transition.
///
/// Network and delivery are asynchronous and are reported through [`FrontendEvent`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommToolsCommandResult {
    Applied,
    ContactCreated(ContactId),
    ContactRenamed(String),
    ContactDeleted(ContactId),
    ContactReset(ContactId),
    ContactBackupExported(PathBuf),
    ContactBackupInspected(ContactBackupInspection),
    ContactBackupImported(ContactId),
    ContactPeerLocked(String),
    ContactUnlocked {
        cleared_offline_state: bool,
    },
    ContactTunnelSettingsApplied(TunnelSettings),
    ContactHistorySettingApplied {
        enabled: bool,
    },
    ContactDeaddropServerAdded(String),
    ContactDeaddropServerRemoved(String),
    GroupCreated(GroupId),
    GroupDeleted(GroupId),
    GroupLocalNameApplied,
    GroupHistorySettingApplied {
        enabled: bool,
    },
    HistoryLoaded {
        key: ManagedSessionKey,
        records: Vec<HistoryRecord>,
    },
    HistoryCleared {
        key: ManagedSessionKey,
    },
    GroupMemberRemoval {
        removed: bool,
    },
    GroupLeaveRequested,
    GroupLocalLeaveStarted {
        deleted_immediately: bool,
    },
    GroupDissolutionStarted {
        deleted_immediately: bool,
    },
    PublicGroupInviteIssued(String),
    PrivateGroupRequestGenerated(String),
    PrivateGroupInviteIssued(String),
    PublicGroupInviteImported(GroupId),
    PrivateGroupInviteImported(GroupId),
    ContactOpening(ContactId),
    TransientOpening(TransientId),
    GroupOpening(GroupId),
    SessionCloseStarted(SessionId),
    ContactConnectionStarted(SessionId),
    ContactIncomingAccepted(SessionId),
    ContactIncomingDeclined(SessionId),
    ContactDisconnectStarted(SessionId),
    ContactOfflineEntered(SessionId),
    ContactOfflineLeft(SessionId),
    ContactRendezvousRequestGenerated(String),
    ContactRendezvousResponseGenerated(String),
    ContactRendezvousConnectionStarted(SessionId),
    ContactRendezvousRevoked(SessionId),
    TextSent(TextSendResult),
    ImageSent(ImageSendResult),
    OriginalImageRequest(OriginalImageRequestResult),
    OriginalImageCancelled {
        session_id: SessionId,
        media_id: u64,
    },
    FileOffered(FileOfferResult),
    FileAccepted {
        session_id: SessionId,
        transfer_id: u64,
    },
    FileDeclined {
        session_id: SessionId,
        transfer_id: u64,
    },
    FileCancelled {
        session_id: SessionId,
        transfer_id: u64,
    },
    DefaultTunnelSettingsApplied(TunnelSettings),
    SamTestStarted,
    BackupExported(PathBuf),
    BackupRestored(PathBuf),
    WipeAllAuthorized,
    ShutdownStarted,
}

/// Immutable state for rendering by terminal, desktop, or mobile frontends.

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CommToolsSnapshot {
    pub application_phase: ApplicationPhase,
    pub settings: GlobalSettings,
    pub sessions: Vec<SessionSummary>,
    pub contacts: Vec<ContactSummary>,
    pub groups: Vec<GroupSummary>,
    pub has_open_or_pending_sessions: bool,
    pub sam_test_status: SamTestStatus,
    pub sam_monitor_status: SamMonitorStatus,
    pub sam_monitor_requires_attention: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionLifecycleEvent {
    Opening {
        key: ManagedSessionKey,
    },
    OpenFailed {
        key: ManagedSessionKey,
        reason: String,
    },
    Opened {
        session_id: SessionId,
        key: ManagedSessionKey,
    },
    Closing {
        session_id: SessionId,
        key: ManagedSessionKey,
    },
    Closed {
        session_id: SessionId,
        key: ManagedSessionKey,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContactSessionEvent {
    PhaseChanged {
        session_id: SessionId,
        phase: OneToOnePhase,
    },
    IncomingCall {
        session_id: SessionId,
        peer_b32: String,
    },
    CollisionResolved {
        session_id: SessionId,
        winner: CollisionWinner,
    },
    IdentityVerified {
        session_id: SessionId,
        peer_b32: String,
        pinned: bool,
    },
    SecureSessionReady {
        session_id: SessionId,
        peer_b32: String,
    },
    ConnectFailed {
        session_id: SessionId,
        peer_b32: String,
        reason: String,
    },
    ConnectRetryScheduled {
        session_id: SessionId,
        peer_b32: String,
        reason: String,
    },
    FrameRejected {
        session_id: SessionId,
        reason: String,
    },
    ConnectionRejected {
        session_id: SessionId,
        reason: DisconnectReason,
    },
    Disconnected {
        session_id: SessionId,
        peer_b32: Option<String>,
        reason: DisconnectReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RendezvousSessionEvent {
    OutgoingAuthenticated {
        session_id: SessionId,
        peer_b32: String,
    },
    IncomingAuthenticated {
        session_id: SessionId,
        peer_b32: String,
    },
    InvitationConsumed {
        session_id: SessionId,
        peer_b32: String,
    },
    AuthenticationRejected {
        session_id: SessionId,
        peer_b32: String,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GroupSessionEvent {
    ConnectFailed {
        session_id: SessionId,
        peer_b32: String,
        reason: String,
    },
    CollisionResolved {
        session_id: SessionId,
        peer_b32: String,
        winner: GroupCollisionWinner,
    },
    IdentityVerified {
        session_id: SessionId,
        peer_b32: String,
    },
    SecureSessionReady {
        session_id: SessionId,
        peer_b32: String,
        authorized: bool,
    },
    PeerDisconnected {
        session_id: SessionId,
        peer_b32: String,
        reason: GroupDisconnectReason,
    },
    ControlReceived {
        session_id: SessionId,
        peer_b32: String,
    },
    RosterReceived {
        session_id: SessionId,
        peer_b32: String,
    },
    DissolutionReceived {
        session_id: SessionId,
        peer_b32: String,
    },
    FrameRejected {
        session_id: SessionId,
        peer_b32: String,
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflinePollResult {
    Hit,
    Miss,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OfflineSessionEvent {
    ModeChanged {
        session_id: SessionId,
        mode: OfflineCoordinatorMode,
    },
    SendStarted {
        session_id: SessionId,
        message_id: u64,
        index: u64,
    },
    SendConfirmed {
        session_id: SessionId,
        message_id: u64,
        index: u64,
        successful_drop_count: usize,
    },
    SendFailed {
        session_id: SessionId,
        message_id: u64,
        index: u64,
        reason: String,
    },
    UnsupportedFrameReceived {
        session_id: SessionId,
        index: u64,
        frame_type: String,
    },
    BlobRejected {
        session_id: SessionId,
        index: u64,
        reason: String,
    },
    PollTargetFailed {
        session_id: SessionId,
        index: u64,
        reason: String,
    },
    PollSweepStarted {
        session_id: SessionId,
    },
    PollSweepCompleted {
        session_id: SessionId,
        result: OfflinePollResult,
        observation_count: usize,
    },
    IndexSyncSent {
        session_id: SessionId,
    },
    IndexSyncSendFailed {
        session_id: SessionId,
        reason: String,
    },
    IndexSyncApplied {
        session_id: SessionId,
    },
    StatePersisted {
        session_id: SessionId,
    },
    EnrollmentPersisted {
        session_id: SessionId,
    },
    ShutdownComplete {
        session_id: SessionId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuntimeOperationEvent {
    Failed {
        session_id: Option<SessionId>,
        operation: String,
        reason: String,
    },
    Recovered {
        session_id: SessionId,
        operation: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApplicationLifecycleEvent {
    Stopping,
    VaultLockRequested,
    Stopped,
}

/// Presentation neutral events emitted by the runtime for any frontend.

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrontendEvent {
    Session(SessionLifecycleEvent),
    Contact(ContactSessionEvent),
    Rendezvous(RendezvousSessionEvent),
    Group(GroupSessionEvent),
    FileTransfer(FileTransferEvent),
    Offline(OfflineSessionEvent),
    Operation(RuntimeOperationEvent),
    Lifecycle(ApplicationLifecycleEvent),
    TextReceived(TextReceivedEvent),
    TextDeliveryUpdated(TextDeliveryEvent),
    ImageReceived(ImageReceivedEvent),
    ImageDeliveryUpdated(ImageDeliveryEvent),
    OriginalImageProgress {
        session_id: SessionId,
        transfer_id: u64,
        media_id: u64,
        received_bytes: u64,
        total_bytes: u64,
        sender_b32: Option<String>,
    },
    OriginalImageReceived(OriginalImageReceivedEvent),
    OriginalImageUnavailable {
        session_id: SessionId,
        media_id: u64,
        sender_b32: Option<String>,
    },
    OriginalImageCancelled {
        session_id: SessionId,
        media_id: u64,
        sender_b32: Option<String>,
    },
    ImageRejected {
        session_id: SessionId,
        reason: String,
    },
    TextRejected {
        session_id: SessionId,
        offline_index: Option<u64>,
        reason: String,
    },
}

impl ApplicationDriver {
    pub fn application_phase(&self) -> ApplicationPhase {
        self.coordinator().phase()
    }

    pub fn session_summary(&self, session_id: SessionId) -> Option<SessionSummary> {
        self.coordinator()
            .sessions()
            .into_iter()
            .find(|managed| managed.session_id == session_id)
            .map(|managed| self.summarize_session(managed))
    }

    fn summarize_session(&self, managed: ManagedSessionInfo) -> SessionSummary {
        let one_to_one = self.coordinator().one_to_one_session(managed.session_id);
        SessionSummary {
            session_id: managed.session_id,
            key: managed.key,
            phase: managed.phase,
            local_b32: one_to_one.map(|session| session.config().local_b32().to_string()),
            peer_b32: one_to_one
                .and_then(|session| session.active_peer_b32())
                .map(str::to_string),
            pinned_peer_b32: one_to_one
                .and_then(|session| session.config().pinned_peer())
                .map(|peer| peer.b32().to_string()),
            one_to_one_phase: one_to_one.map(|session| session.phase()),
            offline_mode: self
                .coordinator()
                .offline_coordinator(managed.session_id)
                .map(|offline| offline.mode()),
        }
    }

    pub fn dispatch_command(
        &mut self,
        command: CommToolsCommand,
    ) -> Result<CommToolsCommandResult, DriverError> {
        match command {
            CommToolsCommand::CreateContact { display_name } => {
                let contact_id = self.create_contact(&display_name)?;
                Ok(CommToolsCommandResult::ContactCreated(contact_id))
            }
            CommToolsCommand::RenameContact {
                contact_id,
                display_name,
            } => {
                let display_name = self.rename_contact(&contact_id, &display_name)?;
                Ok(CommToolsCommandResult::ContactRenamed(display_name))
            }
            CommToolsCommand::DeleteContact { contact_id } => {
                self.delete_contact(&contact_id)?;
                Ok(CommToolsCommandResult::ContactDeleted(contact_id))
            }
            CommToolsCommand::ResetContact { contact_id } => {
                self.reset_contact(&contact_id)?;
                Ok(CommToolsCommandResult::ContactReset(contact_id))
            }
            CommToolsCommand::ExportContactBackup {
                contact_id,
                path,
                passphrase,
                include_history,
            } => {
                self.export_contact_backup(
                    &contact_id,
                    &path,
                    passphrase.as_bytes(),
                    include_history,
                )?;
                Ok(CommToolsCommandResult::ContactBackupExported(path))
            }
            CommToolsCommand::InspectContactBackup { path, passphrase } => {
                let inspection = self.inspect_contact_backup(&path, passphrase.as_bytes())?;
                Ok(CommToolsCommandResult::ContactBackupInspected(inspection))
            }
            CommToolsCommand::ImportContactBackup {
                path,
                passphrase,
                replace,
            } => {
                let contact_id =
                    self.import_contact_backup(&path, passphrase.as_bytes(), replace)?;
                Ok(CommToolsCommandResult::ContactBackupImported(contact_id))
            }
            CommToolsCommand::LockContactPeer { session_id } => {
                let peer_b32 = self.lock_contact_peer(session_id)?;
                Ok(CommToolsCommandResult::ContactPeerLocked(peer_b32))
            }
            CommToolsCommand::UnlockContact { contact_id } => {
                let cleared_offline_state = self.unlock_contact(&contact_id)?;
                Ok(CommToolsCommandResult::ContactUnlocked {
                    cleared_offline_state,
                })
            }
            CommToolsCommand::SetContactTunnelSettings {
                contact_id,
                tunnels,
            } => {
                let applied = self.set_contact_tunnel_settings(
                    &contact_id,
                    tunnels.length,
                    tunnels.quantity,
                )?;
                Ok(CommToolsCommandResult::ContactTunnelSettingsApplied(
                    applied,
                ))
            }
            CommToolsCommand::SetContactHistoryEnabled {
                contact_id,
                enabled,
            } => {
                self.set_history_enabled(&ManagedSessionKey::Contact(contact_id), enabled)?;
                Ok(CommToolsCommandResult::ContactHistorySettingApplied { enabled })
            }
            CommToolsCommand::AddContactDeaddropServer { contact_id, server } => {
                let server = self.add_contact_deaddrop_server(&contact_id, &server)?;
                Ok(CommToolsCommandResult::ContactDeaddropServerAdded(server))
            }
            CommToolsCommand::RemoveContactDeaddropServer { contact_id, server } => {
                let server = self.remove_contact_deaddrop_server(&contact_id, &server)?;
                Ok(CommToolsCommandResult::ContactDeaddropServerRemoved(server))
            }
            CommToolsCommand::CreateGroup { display_name } => {
                let group_id = self.create_group(&display_name)?;
                Ok(CommToolsCommandResult::GroupCreated(group_id))
            }
            CommToolsCommand::DeleteGroup { group_id } => {
                self.delete_group(&group_id)?;
                Ok(CommToolsCommandResult::GroupDeleted(group_id))
            }
            CommToolsCommand::SetGroupLocalName {
                group_id,
                local_name,
            } => {
                self.set_group_local_name(&group_id, &local_name)?;
                Ok(CommToolsCommandResult::GroupLocalNameApplied)
            }
            CommToolsCommand::SetGroupHistoryEnabled { group_id, enabled } => {
                self.set_history_enabled(&ManagedSessionKey::Group(group_id), enabled)?;
                Ok(CommToolsCommandResult::GroupHistorySettingApplied { enabled })
            }
            CommToolsCommand::LoadHistory { key } => {
                let records = self.load_history(&key)?;
                Ok(CommToolsCommandResult::HistoryLoaded { key, records })
            }
            CommToolsCommand::ClearHistory { key } => {
                self.clear_history(&key)?;
                Ok(CommToolsCommandResult::HistoryCleared { key })
            }
            CommToolsCommand::RemoveGroupMember {
                group_id,
                member_b32,
            } => {
                let removed = self.remove_group_member(&group_id, &member_b32)?;
                Ok(CommToolsCommandResult::GroupMemberRemoval { removed })
            }
            CommToolsCommand::RequestGroupLeave { group_id } => {
                self.request_group_leave(&group_id)?;
                Ok(CommToolsCommandResult::GroupLeaveRequested)
            }
            CommToolsCommand::LeaveGroupLocally { group_id } => {
                let deleted_immediately = self.leave_group_locally(&group_id)?;
                Ok(CommToolsCommandResult::GroupLocalLeaveStarted {
                    deleted_immediately,
                })
            }
            CommToolsCommand::DissolveGroup { group_id } => {
                let deleted_immediately = self.dissolve_group(&group_id)?;
                Ok(CommToolsCommandResult::GroupDissolutionStarted {
                    deleted_immediately,
                })
            }
            CommToolsCommand::IssuePublicGroupInvite { group_id } => {
                let invite = self.issue_public_group_invite(&group_id)?;
                Ok(CommToolsCommandResult::PublicGroupInviteIssued(invite))
            }
            CommToolsCommand::GeneratePrivateGroupRequest => {
                let request = self.generate_private_group_request()?;
                Ok(CommToolsCommandResult::PrivateGroupRequestGenerated(
                    request,
                ))
            }
            CommToolsCommand::IssuePrivateGroupInvite {
                group_id,
                encoded_request,
            } => {
                let invite = self.issue_private_group_invite(&group_id, &encoded_request)?;
                Ok(CommToolsCommandResult::PrivateGroupInviteIssued(invite))
            }
            CommToolsCommand::ImportPublicGroupInvite { encoded_invite } => {
                let group_id = self.import_public_group_invite(&encoded_invite)?;
                Ok(CommToolsCommandResult::PublicGroupInviteImported(group_id))
            }
            CommToolsCommand::ImportPrivateGroupInvite { encoded_invite } => {
                let group_id = self.import_private_group_invite(&encoded_invite)?;
                Ok(CommToolsCommandResult::PrivateGroupInviteImported(group_id))
            }
            CommToolsCommand::OpenContact { contact_id } => {
                self.begin_open_contact(contact_id.clone())?;
                Ok(CommToolsCommandResult::ContactOpening(contact_id))
            }
            CommToolsCommand::OpenTransient => {
                let transient_id = self.begin_open_transient()?;
                Ok(CommToolsCommandResult::TransientOpening(transient_id))
            }
            CommToolsCommand::OpenGroup { group_id } => {
                self.begin_open_group(group_id.clone())?;
                Ok(CommToolsCommandResult::GroupOpening(group_id))
            }
            CommToolsCommand::CloseSession { session_id } => {
                self.close_session(session_id)?;
                Ok(CommToolsCommandResult::SessionCloseStarted(session_id))
            }
            CommToolsCommand::ConnectContact {
                session_id,
                peer_b32,
            } => {
                self.begin_contact_connect(session_id, &peer_b32)?;
                Ok(CommToolsCommandResult::ContactConnectionStarted(session_id))
            }
            CommToolsCommand::AcceptContactIncoming { session_id } => {
                self.accept_contact_incoming(session_id)?;
                Ok(CommToolsCommandResult::ContactIncomingAccepted(session_id))
            }
            CommToolsCommand::DeclineContactIncoming { session_id } => {
                self.decline_contact_incoming(session_id)?;
                Ok(CommToolsCommandResult::ContactIncomingDeclined(session_id))
            }
            CommToolsCommand::DisconnectContact { session_id } => {
                self.disconnect_contact(session_id)?;
                Ok(CommToolsCommandResult::ContactDisconnectStarted(session_id))
            }
            CommToolsCommand::EnterContactOffline { session_id } => {
                self.enter_contact_offline(session_id)?;
                Ok(CommToolsCommandResult::ContactOfflineEntered(session_id))
            }
            CommToolsCommand::LeaveContactOffline { session_id } => {
                self.leave_contact_offline(session_id)?;
                Ok(CommToolsCommandResult::ContactOfflineLeft(session_id))
            }
            CommToolsCommand::GenerateContactRendezvousRequest { session_id } => {
                let request = self.generate_contact_rendezvous_request(session_id)?;
                Ok(CommToolsCommandResult::ContactRendezvousRequestGenerated(
                    request,
                ))
            }
            CommToolsCommand::AnswerContactRendezvousRequest {
                session_id,
                encoded_request,
            } => {
                let response =
                    self.answer_contact_rendezvous_request(session_id, &encoded_request)?;
                Ok(CommToolsCommandResult::ContactRendezvousResponseGenerated(
                    response,
                ))
            }
            CommToolsCommand::ConnectContactRendezvous {
                session_id,
                encoded_response,
            } => {
                self.begin_contact_rendezvous_connect(session_id, &encoded_response)?;
                Ok(CommToolsCommandResult::ContactRendezvousConnectionStarted(
                    session_id,
                ))
            }
            CommToolsCommand::RevokeContactRendezvous { session_id } => {
                self.revoke_contact_rendezvous(session_id)?;
                Ok(CommToolsCommandResult::ContactRendezvousRevoked(session_id))
            }
            CommToolsCommand::SendText { session_id, text } => Ok(
                CommToolsCommandResult::TextSent(self.send_text(session_id, &text)?),
            ),
            CommToolsCommand::SendImage {
                session_id,
                filename,
                mime,
                bytes,
            } => Ok(CommToolsCommandResult::ImageSent(
                self.send_image(session_id, filename, mime, bytes)?,
            )),
            CommToolsCommand::SendImageWithOriginal {
                session_id,
                filename,
                mime,
                bytes,
                original,
            } => Ok(CommToolsCommandResult::ImageSent(
                self.send_image_with_original(session_id, filename, mime, bytes, Some(original))?,
            )),
            CommToolsCommand::RequestOriginalImage {
                session_id,
                media_id,
                sender_b32,
            } => Ok(CommToolsCommandResult::OriginalImageRequest(
                self.request_original_image(session_id, media_id, sender_b32)?,
            )),
            CommToolsCommand::CancelOriginalImage {
                session_id,
                media_id,
                sender_b32,
            } => {
                self.cancel_original_image(session_id, media_id, sender_b32)?;
                Ok(CommToolsCommandResult::OriginalImageCancelled {
                    session_id,
                    media_id,
                })
            }
            CommToolsCommand::OfferFile { session_id, path } => {
                let (transfer_id, filename, total_bytes) =
                    self.send_contact_file_path(session_id, &path)?;
                Ok(CommToolsCommandResult::FileOffered(FileOfferResult {
                    session_id,
                    transfer_id,
                    filename,
                    total_bytes,
                }))
            }
            CommToolsCommand::AcceptFile {
                session_id,
                transfer_id,
            } => {
                self.accept_incoming_file(session_id, transfer_id)?;
                Ok(CommToolsCommandResult::FileAccepted {
                    session_id,
                    transfer_id,
                })
            }
            CommToolsCommand::DeclineFile {
                session_id,
                transfer_id,
            } => {
                self.decline_incoming_file(session_id, transfer_id)?;
                Ok(CommToolsCommandResult::FileDeclined {
                    session_id,
                    transfer_id,
                })
            }
            CommToolsCommand::CancelFile {
                session_id,
                transfer_id,
            } => {
                self.cancel_file_transfer(session_id, transfer_id)?;
                Ok(CommToolsCommandResult::FileCancelled {
                    session_id,
                    transfer_id,
                })
            }
            CommToolsCommand::SetSamHost(host) => {
                self.set_sam_host(&host)?;
                Ok(CommToolsCommandResult::Applied)
            }
            CommToolsCommand::SetSamPort(port) => {
                self.set_sam_port(port)?;
                Ok(CommToolsCommandResult::Applied)
            }
            CommToolsCommand::SetDefaultTunnelSettings(tunnels) => {
                let applied = self.set_default_tunnel_settings(tunnels.length, tunnels.quantity)?;
                Ok(CommToolsCommandResult::DefaultTunnelSettingsApplied(
                    applied,
                ))
            }
            CommToolsCommand::SetSamLivenessEnabled(enabled) => {
                self.set_sam_liveness_enabled(enabled)?;
                Ok(CommToolsCommandResult::Applied)
            }
            CommToolsCommand::SetSamFailureAction(action) => {
                self.set_sam_failure_action(action)?;
                Ok(CommToolsCommandResult::Applied)
            }
            CommToolsCommand::TestSam => {
                self.begin_sam_test()?;
                Ok(CommToolsCommandResult::SamTestStarted)
            }
            CommToolsCommand::ExportBackup {
                path,
                passphrase,
                include_files,
            } => {
                self.export_backup(&path, passphrase.as_bytes(), include_files)?;
                Ok(CommToolsCommandResult::BackupExported(path))
            }
            CommToolsCommand::RestoreBackup {
                path,
                passphrase,
                restore_files,
            } => {
                self.restore_backup(&path, passphrase.as_bytes(), restore_files)?;
                Ok(CommToolsCommandResult::BackupRestored(path))
            }
            CommToolsCommand::AuthorizeWipeAll { vault_passphrase } => {
                self.authorize_wipe_all(vault_passphrase.as_bytes())?;
                Ok(CommToolsCommandResult::WipeAllAuthorized)
            }
            CommToolsCommand::BeginShutdown => {
                self.begin_shutdown()?;
                Ok(CommToolsCommandResult::ShutdownStarted)
            }
        }
    }

    pub fn snapshot(&self) -> Result<CommToolsSnapshot, DriverError> {
        let vault = self.vault().ok_or(DriverError::VaultUnavailable)?;
        let stored = vault.snapshot();
        let mut contacts = stored
            .contacts
            .values()
            .map(|contact| {
                let session = self
                    .coordinator()
                    .session_for_contact(&contact.id)
                    .and_then(|session_id| self.coordinator().one_to_one_session(session_id));
                let ranked =
                    ranked_deaddrop_servers(&contact.deaddrop_servers, &contact.deaddrop_stats);
                let active_deaddrops = ranked
                    .iter()
                    .take(ACTIVE_DEADDROP_REPLICA_COUNT)
                    .cloned()
                    .collect::<BTreeSet<_>>();
                let deaddrop_profiles = ranked
                    .into_iter()
                    .map(|address| {
                        let stat = contact.deaddrop_stats.get(&address);
                        DeaddropServerSummary {
                            active: active_deaddrops.contains(&address),
                            put_ok: stat.map_or(0, |stat| stat.put_ok),
                            put_fail: stat.map_or(0, |stat| stat.put_fail),
                            get_ok: stat.map_or(0, |stat| stat.get_ok),
                            get_fail: stat.map_or(0, |stat| stat.get_fail),
                            latency_ema_ms: stat.filter(|stat| stat.latency_samples > 0).map(
                                |stat| {
                                    stat.latency_ema_ms.round().clamp(0.0, u64::MAX as f64) as u64
                                },
                            ),
                            last_success_ms: stat
                                .map(|stat| stat.last_success_ms)
                                .filter(|last_success_ms| *last_success_ms > 0),
                            address,
                        }
                    })
                    .collect();
                ContactSummary {
                    id: contact.id.clone(),
                    display_name: contact.display_name.clone(),
                    local_b32: session
                        .map(|session| session.config().local_b32().to_string())
                        .or_else(|| {
                            contact
                                .identity
                                .as_ref()
                                .map(|identity| identity.b32.clone())
                        }),
                    peer_b32: session
                        .and_then(|session| session.active_peer_b32())
                        .map(str::to_string)
                        .or_else(|| {
                            session
                                .and_then(|session| session.config().pinned_peer())
                                .map(|peer| peer.b32().to_string())
                        })
                        .or_else(|| contact.tofu_peer.as_ref().map(|peer| peer.b32.clone())),
                    peer_pinned: contact.tofu_peer.is_some(),
                    pq_enabled: contact.pq_enabled,
                    history_enabled: contact.history_enabled,
                    tunnels: contact.tunnels,
                    deaddrop_servers: contact.deaddrop_servers.clone(),
                    deaddrop_profiles,
                    active: self.contact_is_active(&contact.id),
                }
            })
            .collect::<Vec<_>>();
        contacts.sort_by(|left, right| {
            left.display_name
                .to_lowercase()
                .cmp(&right.display_name.to_lowercase())
                .then_with(|| left.id.cmp(&right.id))
        });

        let mut groups = stored
            .groups
            .values()
            .map(|group| {
                let session = self
                    .coordinator()
                    .session_for_group(&group.id)
                    .and_then(|session_id| self.coordinator().group_session(session_id));
                let local_b32 = session
                    .map(|session| session.config().local_b32().to_string())
                    .or_else(|| group.identity.as_ref().map(|identity| identity.b32.clone()));
                let owner_b32 = session
                    .map(|session| session.config().owner_b32().to_string())
                    .or_else(|| group.owner_b32.clone());
                let mut members = commtools_core::group_roster::canonical_members(group)
                    .unwrap_or_else(|_| group.members.clone());
                if let Some(local) = local_b32.as_deref()
                    && !members
                        .iter()
                        .any(|member| member.b32.eq_ignore_ascii_case(local))
                {
                    let name = if group.local_member_name.trim().is_empty() {
                        format!("member-{}", &local[..local.len().min(6)])
                    } else {
                        group.local_member_name.clone()
                    };
                    members.push(commtools_core::GroupMemberRecord {
                        name,
                        b32: local.to_string(),
                    });
                }
                let mut members = members
                    .into_iter()
                    .map(|member| GroupMemberSummary {
                        owner: owner_b32
                            .as_deref()
                            .is_some_and(|owner| owner.eq_ignore_ascii_case(&member.b32)),
                        local: local_b32
                            .as_deref()
                            .is_some_and(|local| local.eq_ignore_ascii_case(&member.b32)),
                        connected: session
                            .is_some_and(|session| session.member_is_ready(&member.b32)),
                        name: member.name,
                        b32: member.b32,
                    })
                    .collect::<Vec<_>>();
                members.sort_by(|left, right| {
                    left.name
                        .to_lowercase()
                        .cmp(&right.name.to_lowercase())
                        .then_with(|| left.b32.cmp(&right.b32))
                });
                let owner = match (local_b32.as_deref(), owner_b32.as_deref()) {
                    (Some(local), Some(owner)) => local.eq_ignore_ascii_case(owner),
                    _ => false,
                };
                GroupSummary {
                    id: group.id.clone(),
                    display_name: group.display_name.clone(),
                    local_b32,
                    local_member_name: group.local_member_name.clone(),
                    history_enabled: group.history_enabled,
                    owner_b32,
                    owner,
                    roster_version: group.roster_version,
                    members,
                    active: self.group_is_active(&group.id),
                    owner_ready: self.group_owner_is_ready(&group.id),
                    leave_pending: self.group_leave_is_pending(&group.id),
                    ready_member_count: session.map_or(0, |session| session.ready_member_count()),
                }
            })
            .collect::<Vec<_>>();
        groups.sort_by(|left, right| {
            left.display_name
                .to_lowercase()
                .cmp(&right.display_name.to_lowercase())
                .then_with(|| left.id.cmp(&right.id))
        });

        let sessions = self
            .coordinator()
            .sessions()
            .into_iter()
            .map(|managed| self.summarize_session(managed))
            .collect();

        Ok(CommToolsSnapshot {
            application_phase: self.coordinator().phase(),
            settings: stored.settings.clone(),
            sessions,
            contacts,
            groups,
            has_open_or_pending_sessions: self.has_open_or_pending_sessions(),
            sam_test_status: self.sam_test_status().clone(),
            sam_monitor_status: self.sam_monitor_status().clone(),
            sam_monitor_requires_attention: self.sam_monitor_requires_attention(),
        })
    }

    pub fn try_next_frontend_event(&mut self) -> Result<Option<FrontendEvent>, DriverError> {
        loop {
            let Some(event) = self.try_next_event()? else {
                return Ok(None);
            };
            if let Some(event) = self.translate_frontend_event(event)? {
                return Ok(Some(event));
            }
        }
    }

    pub async fn next_frontend_event(&mut self) -> Result<FrontendEvent, DriverError> {
        loop {
            let event = self.next_event().await?;
            if let Some(event) = self.translate_frontend_event(event)? {
                return Ok(event);
            }
        }
    }
}
