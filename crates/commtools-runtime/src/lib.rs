#![forbid(unsafe_code)]

//! Async orchestration:) facade for CommTools frontends.
//!
//! `ApplicationDriver` owns protocol coordinators, SAM resources, workers, and the unlocked vault.
//! UI shells interact through the typed API and must allow graceful shutdown to reach `Stopped`
//! before discarding the driver or performing destructive storage operations.

pub mod api;

pub use api::{
    ApplicationLifecycleEvent, CommToolsCommand, CommToolsCommandResult, CommToolsSnapshot,
    ContactSessionEvent, ContactSummary, DeaddropServerSummary, FileOfferResult,
    FileTransferDirection, FileTransferEvent, FrontendEvent, GroupMemberSummary, GroupSessionEvent,
    GroupSummary, ImageDeliveryEvent, ImageReceivedEvent, ImageSendResult, OfflinePollResult,
    OfflineSessionEvent, OriginalImageData, OriginalImageReceivedEvent, OriginalImageRequestResult,
    RendezvousSessionEvent, RuntimeOperationEvent, SessionLifecycleEvent, SessionSummary,
    TextDeliveryEvent, TextReceivedEvent, TextSendResult,
};
pub use commtools_core::{ContactBackupInspection, GroupBackupInspection};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use commtools_core::application::{
    ApplicationAction, ApplicationCoordinator, ApplicationCoordinatorError, ApplicationEvent,
    ApplicationOutput, ApplicationPhase, FileTransferDirection as CoreFileTransferDirection,
    FileTransferEvent as CoreFileTransferEvent, ManagedSessionKey, ManagedSessionPhase,
};
use commtools_core::config::SamEndpoint;
use commtools_core::deaddrop::{DeaddropClient, DeaddropConfig, GetResult, PutResult};
use commtools_core::deaddrop_profile::{
    record_get_result, record_put_result, select_deaddrop_servers,
};
use commtools_core::file_transfer::{
    FILE_TRANSFER_CHUNK_BYTES, FILE_TRANSFER_MAX_BYTES, FileTransferControl, sanitize_file_filename,
};
use commtools_core::group_roster::{
    GroupControlMessage, GroupDissolution, GroupInvite, GroupRosterError, GroupRosterSync,
    InviteRedemption, JOIN_PROOF_CONTROL, LEAVE_REQUEST_CONTROL, RENAME_REQUEST_CONTROL,
    RosterApplyOutcome, apply_invite, apply_roster_sync, decode_public_invite, is_group_owner,
    issue_group_dissolution, issue_private_invite, issue_public_invite, leave_control,
    owner_control, redeem_join_control, remove_member, rename_local_member, rename_member,
    roster_sync, sign_owner_roster, verify_group_dissolution,
};
use commtools_core::group_session::{
    GROUP_IMAGE_TRANSFER_MAX_BYTES, GroupSession, GroupSessionAction, GroupSessionConfig,
    GroupSessionEvent as CoreGroupSessionEvent,
};
use commtools_core::history::{HistoryError, HistoryRecord, HistoryScope};
use commtools_core::ids::{ContactId, GroupId, SessionId, TransientId};
use commtools_core::inline_image::{
    INLINE_IMAGE_TRANSFER_MAX_BYTES, ImageTransferHeader, ImageTransferKind, InlineImageReceiver,
    OriginalImageControl, OriginalImageMetadata, image_sha256_hex, inline_image_frames_with_header,
    sanitize_image_filename, validate_image_bytes,
};
use commtools_core::offline_coordinator::{
    OfflineCoordinator, OfflineCoordinatorAction, OfflineCoordinatorMode, OfflineOperationId,
};
use commtools_core::one_to_one::{
    ConnectionId, HEARTBEAT_PING_PREFIX, HEARTBEAT_PONG_PREFIX, OneToOneAction,
    OneToOneConfig, OneToOneSession, PinnedPeer,
};
use commtools_core::private_group_invite::{
    PrivateGroupInviteError, PrivateJoinCredential, generate_request, open_invite,
    response_request_id,
};
use commtools_core::protocol::{Frame, MessageType, generate_message_id};
use commtools_core::sam::{
    AcceptedIncoming, LiveConnection, SamSessionConfig, SamSessionInfo, TunnelOptions,
};
use commtools_core::{
    ContactRecord, FileFrameSealer, GroupRecord, MAX_DEADDROP_SERVERS, PersistentIdentity,
    SamFailureAction, SamRuntime, StorageError, TofuPeerPin, TunnelSettings, UnlockedVault,
    VaultError, group_storage_key, normalize_deaddrop_server,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(500);
const COMPLETION_QUEUE_CAPACITY: usize = 1_024;
const SEND_QUEUE_CAPACITY: usize = 256;
const PRIORITY_SEND_QUEUE_CAPACITY: usize = 16;
const IMAGE_SEND_BURST_FRAMES: usize = 1;
const BULK_SEND_PACING_INTERVAL: Duration = Duration::from_millis(40);
const FILE_PROGRESS_STEP_BYTES: u64 = 256 * 1024;
const FILE_OFFER_TIMEOUT_MS: u64 = 60_000;
const SAM_LIVENESS_PROBE_INTERVAL_MS: u64 = 10_000;
const SAM_LIVENESS_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const SAM_LIVENESS_FAILURE_THRESHOLD: u8 = 3;
const ORIGINAL_IMAGE_CACHE_MAX_ITEMS: usize = 8;
const ORIGINAL_IMAGE_CACHE_MAX_BYTES: usize = 100 * 1024 * 1024;
const DEADDROP_STATS_FLUSH_INTERVAL_MS: u64 = 15_000;
const DEFAULT_SAM_SESSION_PREFIX: &str = "termcomm";
const MAX_SAM_SESSION_PREFIX_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationDriverConfig {
    sam_session_prefix: String,
}

impl ApplicationDriverConfig {
    pub fn new(sam_session_prefix: impl Into<String>) -> Result<Self, DriverConfigError> {
        let sam_session_prefix = sam_session_prefix.into();
        if sam_session_prefix.is_empty()
            || sam_session_prefix.len() > MAX_SAM_SESSION_PREFIX_BYTES
            || !sam_session_prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(DriverConfigError::InvalidSamSessionPrefix);
        }
        Ok(Self { sam_session_prefix })
    }

    pub fn sam_session_prefix(&self) -> &str {
        &self.sam_session_prefix
    }
}

impl Default for ApplicationDriverConfig {
    fn default() -> Self {
        Self {
            sam_session_prefix: DEFAULT_SAM_SESSION_PREFIX.into(),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DriverConfigError {
    #[error("SAM session prefix must be 1 to 32 ASCII letters, digits, or underscores")]
    InvalidSamSessionPrefix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryWriteOutcome {
    Disabled,
    Stored,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SamTestStatus {
    Idle,
    Running,
    Succeeded,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SamMonitorStatus {
    Inactive,
    Checking,
    Healthy,
    Degraded {
        consecutive_failures: u8,
        reason: String,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResourceKind {
    Contact,
    Transient,
    Group,
}

#[derive(Clone)]
enum GroupProtocolEvent {
    Ready {
        peer_b32: String,
        authorized: bool,
    },
    Control {
        peer_b32: String,
        control: GroupControlMessage,
    },
    Roster {
        peer_b32: String,
        roster: GroupRosterSync,
    },
    Dissolution {
        peer_b32: String,
        dissolution: GroupDissolution,
    },
}

struct SessionResources {
    kind: ResourceKind,
    sam: SamRuntime,
    deaddrop: Option<DeaddropClient>,
    connections: BTreeMap<ConnectionId, ManagedConnection>,
    closing_connections: BTreeSet<ConnectionId>,
    accepting: bool,
    incoming_image: InlineImageReceiver,
    deaddrop_operation_sequence: u64,
}

#[derive(Debug, Clone)]
struct CachedOriginalImage {
    filename: String,
    mime: String,
    bytes: Vec<u8>,
    sha256: String,
    added_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct OriginalImageKey {
    session_id: SessionId,
    media_id: u64,
    sender_b32: String,
}

struct ManagedConnection {
    send_tx: mpsc::Sender<SendJob>,
    priority_send_tx: mpsc::Sender<SendJob>,
}

struct IncomingFileTransfer {
    transfer_id: u64,
    connection_id: ConnectionId,
    filename: String,
    expected_bytes: u64,
    received_bytes: u64,
    last_reported_bytes: u64,
    temporary_path: PathBuf,
    final_path: PathBuf,
    file: File,
}

struct IncomingFileOffer {
    transfer_id: u64,
    connection_id: ConnectionId,
    filename: String,
    total_bytes: u64,
    offered_ms: u64,
}

struct OutgoingFileTransfer {
    transfer_id: u64,
    connection_id: ConnectionId,
    filename: String,
    total_bytes: u64,
    offered_ms: u64,
    file: Option<File>,
    sealer: Option<FileFrameSealer>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileTerminalState {
    Declined,
    Cancelled,
    Expired,
}

struct PendingContactOpen {
    runtime: SamRuntime,
    failure: Option<String>,
    shutdown_started: bool,
}

struct PendingTransientOpen {
    runtime: SamRuntime,
    failure: Option<String>,
    shutdown_started: bool,
}

struct PreparedTransient {
    info: SamSessionInfo,
    session: OneToOneSession,
}

struct ContactBootstrapPlan {
    sam_config: SamSessionConfig,
    expected_b32: Option<String>,
    pinned_peer: Option<PinnedPeer>,
    offline: Option<OfflineCoordinator>,
    staged_offline: Option<commtools_core::PersistedOfflineState>,
    deaddrop: Option<DeaddropClient>,
    persist_identity: bool,
}

struct PreparedContact {
    info: SamSessionInfo,
    session: OneToOneSession,
    offline: Option<OfflineCoordinator>,
    staged_offline: Option<commtools_core::PersistedOfflineState>,
    deaddrop: Option<DeaddropClient>,
    identity: Option<PersistentIdentity>,
}

struct PendingGroupOpen {
    runtime: SamRuntime,
    failure: Option<String>,
    shutdown_started: bool,
}

struct GroupBootstrapPlan {
    group: GroupRecord,
    sam_config: SamSessionConfig,
    expected_b32: Option<String>,
}

struct PreparedGroup {
    info: SamSessionInfo,
    session: GroupSession,
    initialized_group: Option<GroupRecord>,
}

/// A successfully initialized SAM runtime paired with the identity returned by
/// that exact `SESSION CREATE` operation.
pub struct SessionTransport {
    runtime: SamRuntime,
    info: SamSessionInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupImageData {
    pub filename: String,
    pub mime: String,
    pub bytes: Vec<u8>,
}

impl SessionTransport {
    pub async fn initialize(
        endpoint: SamEndpoint,
        config: SamSessionConfig,
    ) -> Result<Self, DriverError> {
        let runtime = SamRuntime::new(endpoint);
        let info = runtime
            .create_session(&config)
            .await
            .map_err(|error| DriverError::SamInitialization(error.to_string()))?;
        Ok(Self { runtime, info })
    }

    pub fn info(&self) -> &SamSessionInfo {
        &self.info
    }
}

/// Executes `ApplicationCoordinator` actions using concrete Tokio-backed
/// resources while keeping protocol and lifecycle policy in the coordinator.
pub struct ApplicationDriver {
    config: ApplicationDriverConfig,
    coordinator: ApplicationCoordinator,
    resources: BTreeMap<SessionId, SessionResources>,
    vault: Option<UnlockedVault>,
    events: VecDeque<ApplicationEvent>,
    completions_tx: mpsc::Sender<Completion>,
    completions_rx: mpsc::Receiver<Completion>,
    tasks: Vec<JoinHandle<()>>,
    next_connection_id: u64,
    pending_contact_opens: BTreeMap<ContactId, PendingContactOpen>,
    pending_transient_opens: BTreeMap<TransientId, PendingTransientOpen>,
    pending_group_opens: BTreeMap<GroupId, PendingGroupOpen>,
    pending_group_leave_requests: BTreeSet<GroupId>,
    groups_delete_after_close: BTreeSet<GroupId>,
    outgoing_files: BTreeMap<SessionId, OutgoingFileTransfer>,
    incoming_file_offers: BTreeMap<SessionId, IncomingFileOffer>,
    incoming_files: BTreeMap<SessionId, IncomingFileTransfer>,
    outgoing_contact_images: BTreeSet<(SessionId, u64)>,
    outgoing_group_images: BTreeSet<(SessionId, u64)>,
    shared_original_images: BTreeMap<(SessionId, u64), CachedOriginalImage>,
    available_original_images: BTreeMap<OriginalImageKey, OriginalImageMetadata>,
    pending_original_images: BTreeSet<OriginalImageKey>,
    received_original_images: BTreeMap<OriginalImageKey, CachedOriginalImage>,
    outgoing_original_cancels:
        BTreeMap<OriginalImageKey, std::sync::Arc<std::sync::atomic::AtomicBool>>,
    sam_test_status: SamTestStatus,
    sam_monitor_status: SamMonitorStatus,
    sam_monitor_probe_running: bool,
    sam_monitor_generation: u64,
    sam_monitor_next_probe_ms: u64,
    sam_monitor_consecutive_failures: u8,
    sam_liveness_shutdown_requested: bool,
    shutdown_requested: bool,
    coordinator_shutdown_started: bool,
    deaddrop_stats_dirty: bool,
    deaddrop_stats_last_flush_ms: u64,
}

impl ApplicationDriver {
    pub fn new(vault: UnlockedVault) -> Self {
        Self::with_config(vault, ApplicationDriverConfig::default())
    }

    pub fn with_config(vault: UnlockedVault, config: ApplicationDriverConfig) -> Self {
        Self::with_optional_vault_and_config(Some(vault), config)
    }

    #[cfg(test)]
    fn with_optional_vault(vault: Option<UnlockedVault>) -> Self {
        Self::with_optional_vault_and_config(vault, ApplicationDriverConfig::default())
    }

    fn with_optional_vault_and_config(
        vault: Option<UnlockedVault>,
        config: ApplicationDriverConfig,
    ) -> Self {
        let (completions_tx, completions_rx) = mpsc::channel(COMPLETION_QUEUE_CAPACITY);
        Self {
            config,
            coordinator: ApplicationCoordinator::new(),
            resources: BTreeMap::new(),
            vault,
            events: VecDeque::new(),
            completions_tx,
            completions_rx,
            tasks: Vec::new(),
            next_connection_id: 1,
            pending_contact_opens: BTreeMap::new(),
            pending_transient_opens: BTreeMap::new(),
            pending_group_opens: BTreeMap::new(),
            pending_group_leave_requests: BTreeSet::new(),
            groups_delete_after_close: BTreeSet::new(),
            outgoing_files: BTreeMap::new(),
            incoming_file_offers: BTreeMap::new(),
            incoming_files: BTreeMap::new(),
            outgoing_contact_images: BTreeSet::new(),
            outgoing_group_images: BTreeSet::new(),
            shared_original_images: BTreeMap::new(),
            available_original_images: BTreeMap::new(),
            pending_original_images: BTreeSet::new(),
            received_original_images: BTreeMap::new(),
            outgoing_original_cancels: BTreeMap::new(),
            sam_test_status: SamTestStatus::Idle,
            sam_monitor_status: SamMonitorStatus::Inactive,
            sam_monitor_probe_running: false,
            sam_monitor_generation: 0,
            sam_monitor_next_probe_ms: 0,
            sam_monitor_consecutive_failures: 0,
            sam_liveness_shutdown_requested: false,
            shutdown_requested: false,
            coordinator_shutdown_started: false,
            deaddrop_stats_dirty: false,
            deaddrop_stats_last_flush_ms: 0,
        }
    }

    pub fn coordinator(&self) -> &ApplicationCoordinator {
        &self.coordinator
    }

    pub fn vault(&self) -> Option<&UnlockedVault> {
        self.vault.as_ref()
    }

    pub fn create_contact(&mut self, display_name: &str) -> Result<ContactId, DriverError> {
        let id = self.next_contact_id()?;
        let stored_id = id.clone();
        let default_tunnels = self.global_settings()?.default_tunnels;
        let mut contact = ContactRecord::new(id.clone(), display_name)
            .map_err(|error| DriverError::RecordMutation(error.to_string()))?;
        contact.tunnels = default_tunnels;
        self.vault_mut()?.update(move |snapshot| {
            snapshot.contacts.insert(stored_id, contact);
            Ok(())
        })?;
        Ok(id)
    }

    pub fn global_settings(&self) -> Result<&commtools_core::GlobalSettings, DriverError> {
        Ok(&self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .settings)
    }

    pub fn has_open_or_pending_sessions(&self) -> bool {
        !self.resources.is_empty()
            || !self.pending_contact_opens.is_empty()
            || !self.pending_transient_opens.is_empty()
            || !self.pending_group_opens.is_empty()
    }

    pub fn set_sam_host(&mut self, host: &str) -> Result<(), DriverError> {
        if self.has_open_or_pending_sessions() {
            return Err(DriverError::SamEndpointRequiresNoSessions);
        }
        let host = host.trim().to_string();
        let port = self.global_settings()?.sam_port;
        SamEndpoint::new(&host, port)
            .map_err(|error| DriverError::RecordMutation(error.to_string()))?;
        self.vault_mut()?.update(move |snapshot| {
            snapshot.settings.sam_host = host;
            Ok(())
        })?;
        Ok(())
    }

    pub fn set_sam_port(&mut self, port: u16) -> Result<(), DriverError> {
        if self.has_open_or_pending_sessions() {
            return Err(DriverError::SamEndpointRequiresNoSessions);
        }
        let host = self.global_settings()?.sam_host.clone();
        SamEndpoint::new(&host, port)
            .map_err(|error| DriverError::RecordMutation(error.to_string()))?;
        self.vault_mut()?.update(move |snapshot| {
            snapshot.settings.sam_port = port;
            Ok(())
        })?;
        Ok(())
    }

    pub fn set_default_tunnel_settings(
        &mut self,
        length: u8,
        quantity: u8,
    ) -> Result<TunnelSettings, DriverError> {
        let tunnels = TunnelSettings { length, quantity };
        tunnels
            .validate()
            .map_err(|error| DriverError::RecordMutation(error.to_string()))?;
        self.vault_mut()?.update(move |snapshot| {
            snapshot.settings.default_tunnels = tunnels;
            Ok(())
        })?;
        Ok(tunnels)
    }

    pub fn set_sam_liveness_enabled(&mut self, enabled: bool) -> Result<(), DriverError> {
        self.vault_mut()?.update(move |snapshot| {
            snapshot.settings.sam_liveness_enabled = enabled;
            Ok(())
        })?;
        if !enabled {
            self.reset_sam_monitor();
        }
        Ok(())
    }

    pub fn set_sam_failure_action(&mut self, action: SamFailureAction) -> Result<(), DriverError> {
        self.vault_mut()?.update(move |snapshot| {
            snapshot.settings.sam_failure_action = action;
            Ok(())
        })?;
        Ok(())
    }

    pub fn sam_test_status(&self) -> &SamTestStatus {
        &self.sam_test_status
    }

    pub fn sam_monitor_status(&self) -> &SamMonitorStatus {
        &self.sam_monitor_status
    }

    pub fn sam_monitor_requires_attention(&self) -> bool {
        matches!(
            self.sam_monitor_status,
            SamMonitorStatus::Degraded { .. } | SamMonitorStatus::Unavailable { .. }
        )
    }

    pub fn take_sam_liveness_shutdown_request(&mut self) -> bool {
        std::mem::take(&mut self.sam_liveness_shutdown_requested)
    }

    pub fn begin_sam_test(&mut self) -> Result<(), DriverError> {
        if self.sam_test_status == SamTestStatus::Running {
            return Err(DriverError::SamTestPending);
        }
        let endpoint = self.global_settings()?.sam_endpoint()?;
        self.sam_test_status = SamTestStatus::Running;
        let completions = self.completions_tx.clone();
        if let Err(error) = self.spawn(async move {
            let result = SamRuntime::test_endpoint(&endpoint)
                .await
                .map(|_| ())
                .map_err(|error| error.to_string());
            let _ = completions
                .send(Completion::SamTestFinished { result })
                .await;
        }) {
            self.sam_test_status = SamTestStatus::Idle;
            return Err(error);
        }
        Ok(())
    }

    pub fn create_group(&mut self, display_name: &str) -> Result<GroupId, DriverError> {
        let id = self.next_group_id()?;
        let stored_id = id.clone();
        let group = GroupRecord::new(id.clone(), display_name)
            .map_err(|error| DriverError::RecordMutation(error.to_string()))?;
        self.vault_mut()?.update(move |snapshot| {
            snapshot.groups.insert(stored_id, group);
            Ok(())
        })?;
        Ok(id)
    }

    pub fn history_enabled(&self, key: &ManagedSessionKey) -> Result<bool, DriverError> {
        let snapshot = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot();
        match key {
            ManagedSessionKey::Contact(contact_id) => snapshot
                .contacts
                .get(contact_id)
                .map(|contact| contact.history_enabled)
                .ok_or_else(|| DriverError::ContactNotFound(contact_id.clone())),
            ManagedSessionKey::Transient(_) => Ok(false),
            ManagedSessionKey::Group(group_id) => snapshot
                .groups
                .get(group_id)
                .map(|group| group.history_enabled)
                .ok_or_else(|| DriverError::GroupNotFound(group_id.clone())),
        }
    }

    pub fn set_history_enabled(
        &mut self,
        key: &ManagedSessionKey,
        enabled: bool,
    ) -> Result<(), DriverError> {
        let key = key.clone();
        self.vault_mut()?.update(move |snapshot| {
            match key {
                ManagedSessionKey::Contact(contact_id) => {
                    let contact = snapshot.contacts.get_mut(&contact_id).ok_or_else(|| {
                        StorageError::Validation(format!("contact not found: {contact_id}"))
                    })?;
                    contact.history_enabled = enabled;
                }
                ManagedSessionKey::Transient(_) => {
                    return Err(StorageError::Validation(
                        "transient sessions cannot retain history".into(),
                    ));
                }
                ManagedSessionKey::Group(group_id) => {
                    let group = snapshot.groups.get_mut(&group_id).ok_or_else(|| {
                        StorageError::Validation(format!("group not found: {group_id}"))
                    })?;
                    group.history_enabled = enabled;
                }
            }
            Ok(())
        })?;
        Ok(())
    }

    pub fn load_history(&self, key: &ManagedSessionKey) -> Result<Vec<HistoryRecord>, DriverError> {
        let vault = self.vault().ok_or(DriverError::VaultUnavailable)?;
        let scope = history_scope(vault, key)?;
        Ok(vault.history_repository()?.load(&scope)?)
    }

    pub fn clear_history(&self, key: &ManagedSessionKey) -> Result<(), DriverError> {
        let vault = self.vault().ok_or(DriverError::VaultUnavailable)?;
        let scope = history_scope(vault, key)?;
        vault.history_repository()?.clear(&scope)?;
        Ok(())
    }

    pub fn append_history_message(
        &self,
        key: &ManagedSessionKey,
        record: &HistoryRecord,
    ) -> Result<HistoryWriteOutcome, DriverError> {
        if !self.history_enabled(key)? {
            return Ok(HistoryWriteOutcome::Disabled);
        }
        let vault = self.vault().ok_or(DriverError::VaultUnavailable)?;
        let scope = history_scope(vault, key)?;
        vault.history_repository()?.append_message(&scope, record)?;
        Ok(HistoryWriteOutcome::Stored)
    }

    pub fn append_history_delivery(
        &self,
        key: &ManagedSessionKey,
        message_id: u64,
        peer_b32: Option<&str>,
    ) -> Result<(), DriverError> {
        if !self.history_enabled(key)? {
            return Ok(());
        }
        let vault = self.vault().ok_or(DriverError::VaultUnavailable)?;
        let scope = history_scope(vault, key)?;
        vault
            .history_repository()?
            .append_delivery(&scope, message_id, peer_b32)?;
        Ok(())
    }

    pub fn issue_public_group_invite(&mut self, group_id: &GroupId) -> Result<String, DriverError> {
        let mut group = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .groups
            .get(group_id)
            .cloned()
            .ok_or_else(|| DriverError::GroupNotFound(group_id.clone()))?;
        let invite = issue_public_invite(&mut group)?;
        let stored_id = group_id.clone();
        self.vault_mut()?.update(move |snapshot| {
            let stored = snapshot.groups.get_mut(&stored_id).ok_or_else(|| {
                StorageError::Validation(format!(
                    "group disappeared while its public invite was being stored: {stored_id}"
                ))
            })?;
            *stored = group;
            Ok(())
        })?;
        Ok(invite)
    }

    pub fn set_group_local_name(
        &mut self,
        group_id: &GroupId,
        new_name: &str,
    ) -> Result<(), DriverError> {
        let mut group = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .groups
            .get(group_id)
            .cloned()
            .ok_or_else(|| DriverError::GroupNotFound(group_id.clone()))?;
        if !rename_local_member(&mut group, new_name)? {
            return Ok(());
        }
        self.persist_group_record(group_id, group.clone())?;

        let Some(session_id) = self.coordinator.session_for_group(group_id) else {
            return Ok(());
        };
        if is_group_owner(&group) {
            let output = self
                .coordinator
                .replace_group_roster(session_id, group.members.clone())?;
            self.process_output(output)?;
            if self
                .coordinator
                .group_session(session_id)
                .is_some_and(|session| session.ready_member_count() > 0)
            {
                let roster = roster_sync(&group)?;
                let output = self.coordinator.send_group_roster(
                    session_id,
                    generate_message_id(),
                    &roster,
                )?;
                self.process_output(output)?;
            }
        } else if let Some(owner) = group.owner_b32.as_deref()
            && self
                .coordinator
                .group_session(session_id)
                .is_some_and(|session| session.member_is_ready(owner))
            && let Some(control) = owner_control(&group, now_epoch_millis())?
        {
            let output = self.coordinator.send_group_control_to_owner(
                session_id,
                generate_message_id(),
                &control,
            )?;
            self.process_output(output)?;
        }
        Ok(())
    }

    pub fn remove_group_member(
        &mut self,
        group_id: &GroupId,
        member_b32: &str,
    ) -> Result<bool, DriverError> {
        let mut group = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .groups
            .get(group_id)
            .cloned()
            .ok_or_else(|| DriverError::GroupNotFound(group_id.clone()))?;
        if !remove_group_member_and_invites(&mut group, member_b32)? {
            return Ok(false);
        }
        self.persist_group_record(group_id, group.clone())?;

        let Some(session_id) = self.coordinator.session_for_group(group_id) else {
            return Ok(true);
        };
        let output = self
            .coordinator
            .replace_group_roster(session_id, group.members.clone())?;
        self.process_output(output)?;
        if self
            .coordinator
            .group_session(session_id)
            .is_some_and(|session| session.ready_member_count() > 0)
        {
            let roster = roster_sync(&group)?;
            let output =
                self.coordinator
                    .send_group_roster(session_id, generate_message_id(), &roster)?;
            self.process_output(output)?;
        }
        Ok(true)
    }

    pub fn group_owner_is_ready(&self, group_id: &GroupId) -> bool {
        let Some(group) = self
            .vault()
            .and_then(|vault| vault.snapshot().groups.get(group_id))
        else {
            return false;
        };
        if is_group_owner(group) {
            return false;
        }
        let Some(owner) = group.owner_b32.as_deref() else {
            return false;
        };
        self.coordinator
            .session_for_group(group_id)
            .and_then(|session_id| self.coordinator.group_session(session_id))
            .is_some_and(|session| session.member_is_ready(owner))
    }

    pub fn group_leave_is_pending(&self, group_id: &GroupId) -> bool {
        self.pending_group_leave_requests.contains(group_id)
            || self.groups_delete_after_close.contains(group_id)
    }

    pub fn request_group_leave(&mut self, group_id: &GroupId) -> Result<(), DriverError> {
        if self.group_leave_is_pending(group_id) {
            return Err(DriverError::GroupLeavePending(group_id.clone()));
        }
        let group = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .groups
            .get(group_id)
            .cloned()
            .ok_or_else(|| DriverError::GroupNotFound(group_id.clone()))?;
        if is_group_owner(&group) {
            return Err(GroupRosterError::OwnerCannotLeave.into());
        }
        let session_id = self
            .coordinator
            .session_for_group(group_id)
            .ok_or_else(|| DriverError::GroupLeaveRequiresOpen(group_id.clone()))?;
        if !self.group_owner_is_ready(group_id) {
            return Err(DriverError::GroupOwnerNotReady(group_id.clone()));
        }
        let control = leave_control(&group)?;
        let output = self.coordinator.send_group_control_to_owner(
            session_id,
            generate_message_id(),
            &control,
        )?;
        self.pending_group_leave_requests.insert(group_id.clone());
        if let Err(error) = self.process_output(output) {
            self.pending_group_leave_requests.remove(group_id);
            return Err(error);
        }
        Ok(())
    }

    pub fn leave_group_locally(&mut self, group_id: &GroupId) -> Result<bool, DriverError> {
        let group = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .groups
            .get(group_id)
            .cloned()
            .ok_or_else(|| DriverError::GroupNotFound(group_id.clone()))?;
        if is_group_owner(&group) {
            return Err(GroupRosterError::OwnerCannotLeave.into());
        }
        self.pending_group_leave_requests.remove(group_id);
        let Some(session_id) = self.coordinator.session_for_group(group_id) else {
            self.delete_group(group_id)?;
            return Ok(true);
        };
        self.groups_delete_after_close.insert(group_id.clone());
        if let Err(error) = self.close_session(session_id) {
            self.groups_delete_after_close.remove(group_id);
            return Err(error);
        }
        Ok(false)
    }

    pub fn dissolve_group(&mut self, group_id: &GroupId) -> Result<bool, DriverError> {
        let mut group = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .groups
            .get(group_id)
            .cloned()
            .ok_or_else(|| DriverError::GroupNotFound(group_id.clone()))?;
        if !is_group_owner(&group) {
            return Err(GroupRosterError::OwnerOnly.into());
        }
        let Some(session_id) = self.coordinator.session_for_group(group_id) else {
            self.delete_group(group_id)?;
            return Ok(true);
        };
        let dissolution = issue_group_dissolution(&mut group)?;
        self.persist_group_record(group_id, group)?;
        if self
            .coordinator
            .group_session(session_id)
            .is_some_and(|session| session.ready_member_count() > 0)
        {
            let output = self.coordinator.send_group_dissolution(
                session_id,
                generate_message_id(),
                &dissolution,
            )?;
            self.process_output(output)?;
        }
        self.groups_delete_after_close.insert(group_id.clone());
        if let Err(error) = self.close_session(session_id) {
            self.groups_delete_after_close.remove(group_id);
            return Err(error);
        }
        Ok(false)
    }

    pub fn delete_group(&mut self, group_id: &GroupId) -> Result<GroupRecord, DriverError> {
        if self.group_is_active(group_id) {
            return Err(DriverError::GroupDeleteRequiresClosed(group_id.clone()));
        }
        let group = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .groups
            .get(group_id)
            .cloned()
            .ok_or_else(|| DriverError::GroupNotFound(group_id.clone()))?;
        let history_scope = HistoryScope::Group(group_storage_key(&group.id));
        self.vault()
            .ok_or(DriverError::VaultUnavailable)?
            .history_repository()?
            .clear(&history_scope)?;
        let stored_id = group_id.clone();
        self.vault_mut()?.update(move |snapshot| {
            if snapshot.groups.remove(&stored_id).is_none() {
                return Err(StorageError::Validation(format!(
                    "group disappeared while it was being deleted: {stored_id}"
                )));
            }
            Ok(())
        })?;
        Ok(group)
    }

    pub fn import_public_group_invite(
        &mut self,
        encoded_invite: &str,
    ) -> Result<GroupId, DriverError> {
        let invite = decode_public_invite(encoded_invite)?;
        let (imported_id, previous_id, group) = self.prepare_group_import(invite, None)?;
        let stored_id = imported_id.clone();
        self.vault_mut()?.update(move |snapshot| {
            if let Some(previous_id) = previous_id
                && previous_id != stored_id
            {
                snapshot.groups.remove(&previous_id);
            }
            snapshot.groups.insert(stored_id, group);
            Ok(())
        })?;
        Ok(imported_id)
    }

    pub fn generate_private_group_request(&mut self) -> Result<String, DriverError> {
        let now_ms = now_epoch_millis();
        let (pending, encoded) = generate_request(now_ms)?;
        self.vault_mut()?.update(move |snapshot| {
            snapshot
                .pending_private_group_requests
                .retain(|request| request.expires_ms() > now_ms);
            snapshot.pending_private_group_requests.push(pending);
            Ok(())
        })?;
        Ok(encoded)
    }

    pub fn issue_private_group_invite(
        &mut self,
        group_id: &GroupId,
        encoded_request: &str,
    ) -> Result<String, DriverError> {
        let mut group = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .groups
            .get(group_id)
            .cloned()
            .ok_or_else(|| DriverError::GroupNotFound(group_id.clone()))?;
        let invite = issue_private_invite(&mut group, encoded_request, now_epoch_millis())?;
        self.persist_group_record(group_id, group)?;
        Ok(invite)
    }

    pub fn import_private_group_invite(
        &mut self,
        encoded_invite: &str,
    ) -> Result<GroupId, DriverError> {
        let request_id = response_request_id(encoded_invite)?;
        let pending = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .pending_private_group_requests
            .iter()
            .find(|request| request.request_id() == request_id.as_str())
            .cloned()
            .ok_or_else(|| DriverError::PrivateGroupRequestNotFound(request_id.clone()))?;
        let (invite_json, credential) = open_invite(encoded_invite, &pending, now_epoch_millis())?;
        let invite: GroupInvite =
            serde_json::from_slice(&invite_json).map_err(GroupRosterError::from)?;
        let (imported_id, previous_id, group) =
            self.prepare_group_import(invite, Some(credential))?;
        let stored_id = imported_id.clone();
        self.vault_mut()?.update(move |snapshot| {
            if let Some(previous_id) = previous_id
                && previous_id != stored_id
            {
                snapshot.groups.remove(&previous_id);
            }
            snapshot.groups.insert(stored_id, group);
            snapshot
                .pending_private_group_requests
                .retain(|request| request.request_id() != request_id);
            Ok(())
        })?;
        Ok(imported_id)
    }

    fn prepare_group_import(
        &self,
        invite: GroupInvite,
        private_credential: Option<PrivateJoinCredential>,
    ) -> Result<(GroupId, Option<GroupId>, GroupRecord), DriverError> {
        let owner_hint = invite
            .owner_b32
            .as_deref()
            .unwrap_or(invite.inviter_b32.as_str())
            .to_string();
        let existing = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .groups
            .iter()
            .find(|(id, group)| {
                id.as_str().eq_ignore_ascii_case(&owner_hint)
                    || group
                        .owner_b32
                        .as_deref()
                        .is_some_and(|owner| owner.eq_ignore_ascii_case(&owner_hint))
            })
            .map(|(id, group)| (id.clone(), group.clone()));

        if let Some((existing_id, group)) = &existing {
            if self.group_is_active(existing_id) {
                return Err(DriverError::GroupInviteRequiresClosed(existing_id.clone()));
            }
            if is_group_owner(group) {
                return Err(DriverError::GroupInviteTargetsOwnedGroup(
                    existing_id.clone(),
                ));
            }
        }

        let previous_id = existing.as_ref().map(|(id, _)| id.clone());
        let mut group = match existing {
            Some((_, group)) => group,
            None => GroupRecord::new(
                GroupId::new("pending-group-import")
                    .map_err(|error| DriverError::RecordMutation(error.to_string()))?,
                invite.group_name.clone(),
            )?,
        };
        apply_invite(&mut group, invite, private_credential)?;
        let imported_id = group.id.clone();

        if self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .groups
            .get(&imported_id)
            .is_some_and(|stored| {
                previous_id.as_ref() != Some(&imported_id)
                    && stored
                        .owner_b32
                        .as_deref()
                        .is_none_or(|owner| !owner.eq_ignore_ascii_case(&owner_hint))
            })
        {
            return Err(DriverError::GroupInviteIdConflict(imported_id));
        }
        Ok((imported_id, previous_id, group))
    }

    pub fn add_contact_deaddrop_server(
        &mut self,
        contact_id: &ContactId,
        server: &str,
    ) -> Result<String, DriverError> {
        if self.contact_is_active(contact_id) {
            return Err(DriverError::ContactDeaddropRequiresClosed(
                contact_id.clone(),
            ));
        }
        let server = normalize_deaddrop_server(server)
            .map_err(|error| DriverError::RecordMutation(error.to_string()))?;
        let contact = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .contacts
            .get(contact_id)
            .ok_or_else(|| DriverError::ContactNotFound(contact_id.clone()))?;
        if contact.deaddrop_servers.contains(&server) {
            return Err(DriverError::ContactDeaddropAlreadyConfigured(server));
        }
        if contact.deaddrop_servers.len() >= MAX_DEADDROP_SERVERS {
            return Err(DriverError::ContactDeaddropLimit);
        }

        let stored_id = contact_id.clone();
        let stored_server = server.clone();
        self.vault_mut()?.update(move |snapshot| {
            let contact = snapshot.contacts.get_mut(&stored_id).ok_or_else(|| {
                StorageError::Validation(format!(
                    "contact disappeared while its deaddrop server was being stored: {stored_id}"
                ))
            })?;
            if contact.deaddrop_servers.contains(&stored_server) {
                return Err(StorageError::Validation(
                    "deaddrop server is already configured".into(),
                ));
            }
            if contact.deaddrop_servers.len() >= MAX_DEADDROP_SERVERS {
                return Err(StorageError::Validation(
                    "deaddrop server limit exceeded".into(),
                ));
            }
            contact.deaddrop_servers.push(stored_server.clone());
            contact.deaddrop_stats.entry(stored_server).or_default();
            Ok(())
        })?;
        Ok(server)
    }

    pub fn remove_contact_deaddrop_server(
        &mut self,
        contact_id: &ContactId,
        server: &str,
    ) -> Result<String, DriverError> {
        if self.contact_is_active(contact_id) {
            return Err(DriverError::ContactDeaddropRequiresClosed(
                contact_id.clone(),
            ));
        }
        let server = normalize_deaddrop_server(server)
            .map_err(|error| DriverError::RecordMutation(error.to_string()))?;
        let contact = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .contacts
            .get(contact_id)
            .ok_or_else(|| DriverError::ContactNotFound(contact_id.clone()))?;
        if !contact.deaddrop_servers.contains(&server) {
            return Err(DriverError::ContactDeaddropNotConfigured(server));
        }
        if contact.deaddrop_servers.len() == 1 {
            return Err(DriverError::ContactRequiresDeaddropServer);
        }

        let stored_id = contact_id.clone();
        let stored_server = server.clone();
        self.vault_mut()?.update(move |snapshot| {
            let contact = snapshot.contacts.get_mut(&stored_id).ok_or_else(|| {
                StorageError::Validation(format!(
                    "contact disappeared while its deaddrop server was being removed: {stored_id}"
                ))
            })?;
            if contact.deaddrop_servers.len() == 1 {
                return Err(StorageError::Validation(
                    "a contact must retain at least one deaddrop server".into(),
                ));
            }
            let Some(position) = contact
                .deaddrop_servers
                .iter()
                .position(|configured| configured == &stored_server)
            else {
                return Err(StorageError::Validation(
                    "deaddrop server is not configured".into(),
                ));
            };
            contact.deaddrop_servers.remove(position);
            contact.deaddrop_stats.remove(&stored_server);
            Ok(())
        })?;
        Ok(server)
    }

    pub fn set_contact_tunnel_settings(
        &mut self,
        contact_id: &ContactId,
        length: u8,
        quantity: u8,
    ) -> Result<TunnelSettings, DriverError> {
        if self.contact_is_active(contact_id) {
            return Err(DriverError::ContactTunnelsRequireClosed(contact_id.clone()));
        }
        let tunnels = TunnelSettings { length, quantity };
        tunnels
            .validate()
            .map_err(|error| DriverError::RecordMutation(error.to_string()))?;
        if !self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .contacts
            .contains_key(contact_id)
        {
            return Err(DriverError::ContactNotFound(contact_id.clone()));
        }

        let stored_id = contact_id.clone();
        self.vault_mut()?.update(move |snapshot| {
            let contact = snapshot.contacts.get_mut(&stored_id).ok_or_else(|| {
                StorageError::Validation(format!(
                    "contact disappeared while its tunnel settings were being stored: {stored_id}"
                ))
            })?;
            contact.tunnels = tunnels;
            Ok(())
        })?;
        Ok(tunnels)
    }

    pub fn rename_contact(
        &mut self,
        contact_id: &ContactId,
        display_name: &str,
    ) -> Result<String, DriverError> {
        if self.contact_is_active(contact_id) {
            return Err(DriverError::ContactRenameRequiresClosed(contact_id.clone()));
        }
        if !self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .contacts
            .contains_key(contact_id)
        {
            return Err(DriverError::ContactNotFound(contact_id.clone()));
        }
        Ok(self.vault_mut()?.rename_contact(contact_id, display_name)?)
    }

    pub fn delete_contact(&mut self, contact_id: &ContactId) -> Result<ContactRecord, DriverError> {
        if self.contact_is_active(contact_id) {
            return Err(DriverError::ContactDeleteRequiresClosed(contact_id.clone()));
        }
        let contact = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .contacts
            .get(contact_id)
            .cloned()
            .ok_or_else(|| DriverError::ContactNotFound(contact_id.clone()))?;
        let stored_id = contact_id.clone();
        self.vault_mut()?.update(move |snapshot| {
            if snapshot.contacts.remove(&stored_id).is_none() {
                return Err(StorageError::Validation(format!(
                    "contact disappeared while it was being deleted: {stored_id}"
                )));
            }
            Ok(())
        })?;
        Ok(contact)
    }

    pub fn reset_contact(&mut self, contact_id: &ContactId) -> Result<(), DriverError> {
        if self.contact_is_active(contact_id) {
            return Err(DriverError::ContactResetRequiresClosed(contact_id.clone()));
        }
        if !self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .contacts
            .contains_key(contact_id)
        {
            return Err(DriverError::ContactNotFound(contact_id.clone()));
        }
        self.vault_mut()?.reset_contact(contact_id)?;
        Ok(())
    }

    pub fn export_contact_backup(
        &mut self,
        contact_id: &ContactId,
        path: &Path,
        passphrase: &[u8],
        include_history: bool,
    ) -> Result<(), DriverError> {
        if self.contact_is_active(contact_id) {
            return Err(DriverError::ContactBackupRequiresClosed(contact_id.clone()));
        }
        self.vault_mut()?
            .export_contact_backup(contact_id, path, passphrase, include_history)?;
        Ok(())
    }

    pub fn inspect_contact_backup(
        &self,
        path: &Path,
        passphrase: &[u8],
    ) -> Result<ContactBackupInspection, DriverError> {
        Ok(self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .inspect_contact_backup(path, passphrase)?)
    }

    pub fn import_contact_backup(
        &mut self,
        path: &Path,
        passphrase: &[u8],
        replace: bool,
    ) -> Result<ContactId, DriverError> {
        let inspection = self.inspect_contact_backup(path, passphrase)?;
        if let Some(replacement_id) = &inspection.replacement_contact_id
            && self.contact_is_active(replacement_id)
        {
            return Err(DriverError::ContactImportRequiresClosed(
                replacement_id.clone(),
            ));
        }
        Ok(self
            .vault_mut()?
            .import_contact_backup(path, passphrase, replace)?)
    }

    pub fn export_group_backup(
        &mut self,
        group_id: &GroupId,
        path: &Path,
        passphrase: &[u8],
        include_history: bool,
    ) -> Result<(), DriverError> {
        if self.group_is_active(group_id) {
            return Err(DriverError::GroupBackupRequiresClosed(group_id.clone()));
        }
        self.vault_mut()?
            .export_group_backup(group_id, path, passphrase, include_history)?;
        Ok(())
    }

    pub fn inspect_group_backup(
        &self,
        path: &Path,
        passphrase: &[u8],
    ) -> Result<GroupBackupInspection, DriverError> {
        Ok(self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .inspect_group_backup(path, passphrase)?)
    }

    pub fn import_group_backup(
        &mut self,
        path: &Path,
        passphrase: &[u8],
        replace: bool,
    ) -> Result<GroupId, DriverError> {
        let inspection = self.inspect_group_backup(path, passphrase)?;
        if let Some(replacement_id) = &inspection.replacement_group_id
            && self.group_is_active(replacement_id)
        {
            return Err(DriverError::GroupImportRequiresClosed(
                replacement_id.clone(),
            ));
        }
        Ok(self
            .vault_mut()?
            .import_group_backup(path, passphrase, replace)?)
    }

    pub fn export_backup(
        &mut self,
        path: &Path,
        passphrase: &[u8],
        include_files: bool,
    ) -> Result<(), DriverError> {
        self.require_no_sessions_for_storage_operation()?;
        self.vault_mut()?
            .export_backup(path, passphrase, include_files)?;
        Ok(())
    }

    pub fn restore_backup(
        &mut self,
        path: &Path,
        passphrase: &[u8],
        restore_files: bool,
    ) -> Result<(), DriverError> {
        self.require_no_sessions_for_storage_operation()?;
        self.vault_mut()?
            .restore_backup(path, passphrase, restore_files)?;
        self.reset_sam_monitor();
        self.sam_test_status = SamTestStatus::Idle;
        self.deaddrop_stats_dirty = false;
        Ok(())
    }

    pub fn authorize_wipe_all(&self, vault_passphrase: &[u8]) -> Result<(), DriverError> {
        self.require_no_sessions_for_storage_operation()?;
        if !self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .passphrase_matches(vault_passphrase)
        {
            return Err(DriverError::VaultPassphraseMismatch);
        }
        Ok(())
    }

    fn require_no_sessions_for_storage_operation(&self) -> Result<(), DriverError> {
        if self.has_open_or_pending_sessions() {
            return Err(DriverError::StorageOperationRequiresNoSessions);
        }
        Ok(())
    }

    pub fn contact_is_active(&self, contact_id: &ContactId) -> bool {
        self.pending_contact_opens.contains_key(contact_id)
            || self.coordinator.session_for_contact(contact_id).is_some()
    }

    pub fn group_is_active(&self, group_id: &GroupId) -> bool {
        self.pending_group_opens.contains_key(group_id)
            || self.coordinator.session_for_group(group_id).is_some()
    }

    pub fn transient_is_active(&self, transient_id: &TransientId) -> bool {
        self.pending_transient_opens.contains_key(transient_id)
            || self
                .coordinator
                .session_for_transient(transient_id)
                .is_some()
    }

    pub fn contact_lock_candidate(&self, session_id: SessionId) -> Result<String, DriverError> {
        Ok(self
            .coordinator
            .contact_pin_candidate(session_id)?
            .b32()
            .to_string())
    }

    pub fn lock_contact_peer(&mut self, session_id: SessionId) -> Result<String, DriverError> {
        let contact_id = self
            .coordinator
            .contact_id_for_session(session_id)
            .cloned()
            .ok_or(DriverError::ContactSessionNotFound(session_id))?;
        let pin = self.coordinator.contact_pin_candidate(session_id)?;
        let stored_pin = TofuPeerPin::new(pin.b32(), pin.destination())?;

        let contact = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .contacts
            .get(&contact_id)
            .ok_or_else(|| DriverError::ContactNotFound(contact_id.clone()))?;
        if contact.tofu_peer.is_some() {
            return Err(DriverError::ContactAlreadyLocked(contact_id));
        }

        let stored_id = contact_id.clone();
        let persisted_pin = stored_pin.clone();
        self.vault_mut()?.update(move |snapshot| {
            let contact = snapshot.contacts.get_mut(&stored_id).ok_or_else(|| {
                StorageError::Validation(format!(
                    "contact disappeared while its peer pin was being stored: {stored_id}"
                ))
            })?;
            if contact.tofu_peer.is_some() {
                return Err(StorageError::Validation(format!(
                    "contact was locked while its peer pin was being stored: {stored_id}"
                )));
            }
            contact.tofu_peer = Some(persisted_pin);
            Ok(())
        })?;

        if let Err(error) = self.coordinator.pin_contact_peer(session_id, pin) {
            let rollback_id = contact_id.clone();
            let rollback_pin = stored_pin.clone();
            self.vault_mut()?.update(move |snapshot| {
                let contact = snapshot.contacts.get_mut(&rollback_id).ok_or_else(|| {
                    StorageError::Validation(format!(
                        "contact disappeared while its peer pin was being rolled back: {rollback_id}"
                    ))
                })?;
                if contact.tofu_peer.as_ref() == Some(&rollback_pin) {
                    contact.tofu_peer = None;
                }
                Ok(())
            })?;
            return Err(error.into());
        }

        match self
            .coordinator
            .begin_contact_offline_enrollment(session_id)
        {
            Ok(output) => {
                if let Err(error) = self.process_output(output) {
                    self.push_failure(
                        Some(session_id),
                        "begin offline enrollment after locking contact",
                        error.to_string(),
                    );
                }
            }
            Err(error) => self.push_failure(
                Some(session_id),
                "begin offline enrollment after locking contact",
                error.to_string(),
            ),
        }

        Ok(stored_pin.b32)
    }

    pub fn unlock_contact(&mut self, contact_id: &ContactId) -> Result<bool, DriverError> {
        if self.contact_is_active(contact_id) {
            return Err(DriverError::ContactTrustRequiresClosed(contact_id.clone()));
        }
        let contact = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .contacts
            .get(contact_id)
            .ok_or_else(|| DriverError::ContactNotFound(contact_id.clone()))?;
        if contact.tofu_peer.is_none() {
            return Err(DriverError::ContactAlreadyUnlocked(contact_id.clone()));
        }
        let cleared_offline_state = contact.offline.is_some();
        let stored_id = contact_id.clone();
        self.vault_mut()?.update(move |snapshot| {
            let contact = snapshot.contacts.get_mut(&stored_id).ok_or_else(|| {
                StorageError::Validation(format!(
                    "contact disappeared while its peer pin was being removed: {stored_id}"
                ))
            })?;
            contact.tofu_peer = None;
            contact.offline = None;
            Ok(())
        })?;
        Ok(cleared_offline_state)
    }

    pub fn has_resources(&self, session_id: SessionId) -> bool {
        self.resources.contains_key(&session_id)
    }

    pub fn live_connection_count(&self, session_id: SessionId) -> usize {
        self.resources
            .get(&session_id)
            .map(|resources| resources.connections.len())
            .unwrap_or(0)
    }

    pub fn active_task_count(&mut self) -> usize {
        self.prune_tasks();
        self.tasks.len()
    }

    pub fn begin_open_contact(&mut self, contact_id: ContactId) -> Result<(), DriverError> {
        if self.shutdown_requested || self.coordinator.phase() != ApplicationPhase::Running {
            return Err(DriverError::ApplicationStopping);
        }
        if self.coordinator.session_for_contact(&contact_id).is_some() {
            return Err(DriverError::ContactAlreadyOpen(contact_id));
        }
        if self.pending_contact_opens.contains_key(&contact_id) {
            return Err(DriverError::ContactOpenPending(contact_id));
        }

        let vault = self.vault.as_ref().ok_or(DriverError::VaultUnavailable)?;
        let contact = vault
            .snapshot()
            .contacts
            .get(&contact_id)
            .cloned()
            .ok_or_else(|| DriverError::ContactNotFound(contact_id.clone()))?;
        let endpoint = vault.snapshot().settings.sam_endpoint()?;
        let plan = build_contact_bootstrap_plan_with_prefix(
            &contact,
            endpoint.clone(),
            self.config.sam_session_prefix(),
        )?;
        let runtime = SamRuntime::new(endpoint);
        self.pending_contact_opens.insert(
            contact_id.clone(),
            PendingContactOpen {
                runtime: runtime.clone(),
                failure: None,
                shutdown_started: false,
            },
        );

        let task_contact_id = contact_id.clone();
        let task_runtime = runtime.clone();
        let tx = self.completions_tx.clone();
        if let Err(error) = self.spawn(async move {
            let result = prepare_contact(task_runtime.clone(), plan).await;
            if result.is_err() {
                let _ = task_runtime.shutdown().await;
            }
            let _ = tx
                .send(Completion::ContactBootstrapFinished {
                    contact_id: task_contact_id,
                    result,
                })
                .await;
        }) {
            self.pending_contact_opens.remove(&contact_id);
            return Err(error);
        }
        self.events.push_back(ApplicationEvent::SessionOpening {
            key: ManagedSessionKey::Contact(contact_id),
        });
        Ok(())
    }

    pub fn begin_open_transient(&mut self) -> Result<TransientId, DriverError> {
        if self.shutdown_requested || self.coordinator.phase() != ApplicationPhase::Running {
            return Err(DriverError::ApplicationStopping);
        }
        let transient_id = self.next_transient_id()?;
        let settings = &self
            .vault
            .as_ref()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .settings;
        let endpoint = settings.sam_endpoint()?;
        let tunnels = settings.default_tunnels;
        let runtime = SamRuntime::new(endpoint);
        self.pending_transient_opens.insert(
            transient_id.clone(),
            PendingTransientOpen {
                runtime: runtime.clone(),
                failure: None,
                shutdown_started: false,
            },
        );

        let task_id = transient_id.clone();
        let task_runtime = runtime.clone();
        let sam_session_prefix = self.config.sam_session_prefix().to_string();
        let tx = self.completions_tx.clone();
        if let Err(error) = self.spawn(async move {
            let result =
                prepare_transient(task_runtime.clone(), &task_id, tunnels, &sam_session_prefix)
                    .await;
            if result.is_err() {
                let _ = task_runtime.shutdown().await;
            }
            let _ = tx
                .send(Completion::TransientBootstrapFinished {
                    transient_id: task_id,
                    result,
                })
                .await;
        }) {
            self.pending_transient_opens.remove(&transient_id);
            return Err(error);
        }
        self.events.push_back(ApplicationEvent::SessionOpening {
            key: ManagedSessionKey::Transient(transient_id.clone()),
        });
        Ok(transient_id)
    }

    pub fn begin_open_group(&mut self, group_id: GroupId) -> Result<(), DriverError> {
        if self.shutdown_requested || self.coordinator.phase() != ApplicationPhase::Running {
            return Err(DriverError::ApplicationStopping);
        }
        if self.coordinator.session_for_group(&group_id).is_some() {
            return Err(DriverError::GroupAlreadyOpen(group_id));
        }
        if self.pending_group_opens.contains_key(&group_id) {
            return Err(DriverError::GroupOpenPending(group_id));
        }

        let vault = self.vault.as_ref().ok_or(DriverError::VaultUnavailable)?;
        let group = vault
            .snapshot()
            .groups
            .get(&group_id)
            .cloned()
            .ok_or_else(|| DriverError::GroupNotFound(group_id.clone()))?;
        let endpoint = vault.snapshot().settings.sam_endpoint()?;
        let default_tunnels = vault.snapshot().settings.default_tunnels;
        let plan = build_group_bootstrap_plan_with_prefix(
            &group,
            default_tunnels,
            self.config.sam_session_prefix(),
        )?;
        let runtime = SamRuntime::new(endpoint);
        self.pending_group_opens.insert(
            group_id.clone(),
            PendingGroupOpen {
                runtime: runtime.clone(),
                failure: None,
                shutdown_started: false,
            },
        );

        let task_group_id = group_id.clone();
        let task_runtime = runtime.clone();
        let tx = self.completions_tx.clone();
        if let Err(error) = self.spawn(async move {
            let result = prepare_group(task_runtime.clone(), plan).await;
            if result.is_err() {
                let _ = task_runtime.shutdown().await;
            }
            let _ = tx
                .send(Completion::GroupBootstrapFinished {
                    group_id: task_group_id,
                    result,
                })
                .await;
        }) {
            self.pending_group_opens.remove(&group_id);
            return Err(error);
        }
        self.events.push_back(ApplicationEvent::SessionOpening {
            key: ManagedSessionKey::Group(group_id),
        });
        Ok(())
    }

    pub fn open_contact(
        &mut self,
        contact_id: ContactId,
        session: OneToOneSession,
        offline: Option<OfflineCoordinator>,
        transport: SessionTransport,
        deaddrop: Option<DeaddropClient>,
    ) -> Result<SessionId, DriverError> {
        self.open_contact_with_staged_offline(
            contact_id, session, offline, None, transport, deaddrop,
        )
    }

    fn open_contact_with_staged_offline(
        &mut self,
        contact_id: ContactId,
        session: OneToOneSession,
        offline: Option<OfflineCoordinator>,
        staged_offline: Option<commtools_core::PersistedOfflineState>,
        transport: SessionTransport,
        deaddrop: Option<DeaddropClient>,
    ) -> Result<SessionId, DriverError> {
        validate_transport(&transport)?;
        if !session
            .config()
            .local_b32()
            .eq_ignore_ascii_case(&transport.info.b32)
        {
            return Err(DriverError::SamIdentityMismatch);
        }
        if offline.is_some() != deaddrop.is_some() {
            return Err(DriverError::OfflineResourceMismatch);
        }
        let output = self.coordinator.open_contact_with_staged_offline(
            contact_id,
            session,
            offline,
            staged_offline,
        )?;
        let session_id = opened_session_id(&output, ResourceKind::Contact)?;
        self.resources.insert(
            session_id,
            SessionResources {
                kind: ResourceKind::Contact,
                sam: transport.runtime,
                deaddrop,
                connections: BTreeMap::new(),
                closing_connections: BTreeSet::new(),
                accepting: false,
                incoming_image: InlineImageReceiver::default(),
                deaddrop_operation_sequence: 0,
            },
        );
        self.process_output(output)?;
        Ok(session_id)
    }

    fn open_transient(
        &mut self,
        transient_id: TransientId,
        session: OneToOneSession,
        transport: SessionTransport,
    ) -> Result<SessionId, DriverError> {
        validate_transport(&transport)?;
        if !session
            .config()
            .local_b32()
            .eq_ignore_ascii_case(&transport.info.b32)
        {
            return Err(DriverError::SamIdentityMismatch);
        }
        let output = self.coordinator.open_transient(transient_id, session)?;
        let session_id = opened_session_id(&output, ResourceKind::Transient)?;
        self.resources.insert(
            session_id,
            SessionResources {
                kind: ResourceKind::Transient,
                sam: transport.runtime,
                deaddrop: None,
                connections: BTreeMap::new(),
                closing_connections: BTreeSet::new(),
                accepting: false,
                incoming_image: InlineImageReceiver::default(),
                deaddrop_operation_sequence: 0,
            },
        );
        self.process_output(output)?;
        Ok(session_id)
    }

    pub fn open_group(
        &mut self,
        group_id: GroupId,
        session: GroupSession,
        transport: SessionTransport,
    ) -> Result<SessionId, DriverError> {
        validate_transport(&transport)?;
        if !session
            .config()
            .local_b32()
            .eq_ignore_ascii_case(&transport.info.b32)
        {
            return Err(DriverError::SamIdentityMismatch);
        }
        let output = self.coordinator.open_group(group_id, session)?;
        let session_id = opened_session_id(&output, ResourceKind::Group)?;
        self.resources.insert(
            session_id,
            SessionResources {
                kind: ResourceKind::Group,
                sam: transport.runtime,
                deaddrop: None,
                connections: BTreeMap::new(),
                closing_connections: BTreeSet::new(),
                accepting: false,
                incoming_image: InlineImageReceiver::default(),
                deaddrop_operation_sequence: 0,
            },
        );
        self.process_output(output)?;
        Ok(session_id)
    }

    /// Runs one coordinator operation and schedules all resulting work.
    /// Frontends never receive raw actions and cannot mutate coordinator state
    /// without passing the resulting output back through this driver.
    pub fn execute<F>(&mut self, operation: F) -> Result<(), DriverError>
    where
        F: FnOnce(
            &mut ApplicationCoordinator,
        ) -> Result<ApplicationOutput, ApplicationCoordinatorError>,
    {
        let output = operation(&mut self.coordinator)?;
        self.process_output(output)
    }

    pub fn tick(&mut self) -> Result<(), DriverError> {
        while let Ok(completion) = self.completions_rx.try_recv() {
            self.process_completion(completion)?;
        }
        let now_ms = now_epoch_millis();
        let output = self.coordinator.tick(now_ms)?;
        self.process_output(output)?;
        if self.shutdown_requested || self.coordinator.phase() != ApplicationPhase::Running {
            self.reset_sam_monitor();
            return Ok(());
        }
        self.tick_file_offers(now_ms);
        if let Err(error) = self.flush_deaddrop_stats(false, now_ms) {
            self.push_failure(None, "save deaddrop profiles", error.to_string());
        }
        self.tick_sam_liveness(now_ms)
    }

    fn tick_file_offers(&mut self, now_ms: u64) {
        let outgoing = self
            .outgoing_files
            .iter()
            .filter(|(_, transfer)| {
                transfer.file.is_some()
                    && now_ms.saturating_sub(transfer.offered_ms) >= FILE_OFFER_TIMEOUT_MS
            })
            .map(|(session_id, transfer)| (*session_id, transfer.transfer_id))
            .collect::<Vec<_>>();
        for (session_id, transfer_id) in outgoing {
            self.expire_outgoing_file_offer(session_id, transfer_id);
        }

        let incoming = self
            .incoming_file_offers
            .iter()
            .filter(|(_, offer)| now_ms.saturating_sub(offer.offered_ms) >= FILE_OFFER_TIMEOUT_MS)
            .map(|(session_id, offer)| (*session_id, offer.transfer_id))
            .collect::<Vec<_>>();
        for (session_id, transfer_id) in incoming {
            self.expire_incoming_file_offer(session_id, transfer_id);
        }
    }

    fn tick_sam_liveness(&mut self, now_ms: u64) -> Result<(), DriverError> {
        let settings = self.global_settings()?.clone();
        if !settings.sam_liveness_enabled
            || !self.has_open_or_pending_sessions()
            || self.shutdown_requested
        {
            self.reset_sam_monitor();
            return Ok(());
        }
        if matches!(
            self.sam_monitor_status,
            SamMonitorStatus::Unavailable { .. }
        ) && settings.sam_failure_action == SamFailureAction::GracefulShutdown
        {
            self.sam_liveness_shutdown_requested = true;
            return Ok(());
        }
        if self.sam_monitor_probe_running || now_ms < self.sam_monitor_next_probe_ms {
            return Ok(());
        }

        let endpoint = settings.sam_endpoint()?;
        self.sam_monitor_generation = self.sam_monitor_generation.wrapping_add(1);
        let generation = self.sam_monitor_generation;
        self.sam_monitor_probe_running = true;
        if self.sam_monitor_consecutive_failures == 0 {
            self.sam_monitor_status = SamMonitorStatus::Checking;
        }
        let completions = self.completions_tx.clone();
        if let Err(error) = self.spawn(async move {
            let result = match tokio::time::timeout(
                SAM_LIVENESS_PROBE_TIMEOUT,
                SamRuntime::test_endpoint(&endpoint),
            )
            .await
            {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(error)) => Err(error.to_string()),
                Err(_) => Err(format!(
                    "SAM probe timed out after {} seconds",
                    SAM_LIVENESS_PROBE_TIMEOUT.as_secs()
                )),
            };
            let _ = completions
                .send(Completion::SamLivenessProbeFinished {
                    generation,
                    completed_ms: now_epoch_millis(),
                    result,
                })
                .await;
        }) {
            self.sam_monitor_probe_running = false;
            self.sam_monitor_status = SamMonitorStatus::Inactive;
            return Err(error);
        }
        Ok(())
    }

    fn apply_sam_liveness_result(
        &mut self,
        result: Result<(), String>,
        completed_ms: u64,
    ) -> Result<(), DriverError> {
        self.sam_monitor_probe_running = false;
        self.sam_monitor_next_probe_ms =
            completed_ms.saturating_add(SAM_LIVENESS_PROBE_INTERVAL_MS);
        match result {
            Ok(()) => {
                self.sam_monitor_consecutive_failures = 0;
                self.sam_monitor_status = SamMonitorStatus::Healthy;
            }
            Err(reason) => {
                self.sam_monitor_consecutive_failures = self
                    .sam_monitor_consecutive_failures
                    .saturating_add(1)
                    .min(SAM_LIVENESS_FAILURE_THRESHOLD);
                if self.sam_monitor_consecutive_failures < SAM_LIVENESS_FAILURE_THRESHOLD {
                    self.sam_monitor_status = SamMonitorStatus::Degraded {
                        consecutive_failures: self.sam_monitor_consecutive_failures,
                        reason,
                    };
                } else {
                    self.sam_monitor_status = SamMonitorStatus::Unavailable { reason };
                    if self.global_settings()?.sam_failure_action
                        == SamFailureAction::GracefulShutdown
                    {
                        self.sam_liveness_shutdown_requested = true;
                    }
                }
            }
        }
        Ok(())
    }

    fn reset_sam_monitor(&mut self) {
        if self.sam_monitor_probe_running {
            self.sam_monitor_generation = self.sam_monitor_generation.wrapping_add(1);
        }
        self.sam_monitor_probe_running = false;
        self.sam_monitor_next_probe_ms = 0;
        self.sam_monitor_consecutive_failures = 0;
        self.sam_monitor_status = SamMonitorStatus::Inactive;
        self.sam_liveness_shutdown_requested = false;
    }

    pub fn close_session(&mut self, session_id: SessionId) -> Result<(), DriverError> {
        let output = self.coordinator.close_session(session_id)?;
        self.process_output(output)
    }

    pub fn begin_contact_connect(
        &mut self,
        session_id: SessionId,
        peer_b32: &str,
    ) -> Result<(), DriverError> {
        let output =
            self.coordinator
                .begin_contact_connect_at(session_id, peer_b32, now_epoch_millis())?;
        self.process_output(output)
    }

    pub fn generate_contact_rendezvous_request(
        &mut self,
        session_id: SessionId,
    ) -> Result<String, DriverError> {
        Ok(self
            .coordinator
            .generate_contact_rendezvous_request(session_id, now_epoch_millis())?)
    }

    pub fn answer_contact_rendezvous_request(
        &mut self,
        session_id: SessionId,
        encoded_request: &str,
    ) -> Result<String, DriverError> {
        Ok(self.coordinator.answer_contact_rendezvous_request(
            session_id,
            encoded_request,
            now_epoch_millis(),
        )?)
    }

    pub fn begin_contact_rendezvous_connect(
        &mut self,
        session_id: SessionId,
        encoded_response: &str,
    ) -> Result<(), DriverError> {
        let output = self.coordinator.begin_contact_rendezvous_connect(
            session_id,
            encoded_response,
            now_epoch_millis(),
        )?;
        self.process_output(output)
    }

    pub fn revoke_contact_rendezvous(&mut self, session_id: SessionId) -> Result<(), DriverError> {
        Ok(self.coordinator.revoke_contact_rendezvous(session_id)?)
    }

    pub fn accept_contact_incoming(&mut self, session_id: SessionId) -> Result<(), DriverError> {
        let output = self
            .coordinator
            .accept_contact_incoming(session_id, now_epoch_millis())?;
        self.process_output(output)
    }

    pub fn decline_contact_incoming(&mut self, session_id: SessionId) -> Result<(), DriverError> {
        let output = self.coordinator.decline_contact_incoming(session_id)?;
        self.process_output(output)
    }

    pub fn disconnect_contact(&mut self, session_id: SessionId) -> Result<(), DriverError> {
        let output = self.coordinator.disconnect_contact(session_id)?;
        self.process_output(output)
    }

    pub fn enter_contact_offline(&mut self, session_id: SessionId) -> Result<(), DriverError> {
        let output = self.coordinator.enter_contact_offline(session_id)?;
        self.process_output(output)
    }

    pub fn leave_contact_offline(&mut self, session_id: SessionId) -> Result<(), DriverError> {
        let output = self.coordinator.leave_contact_offline(session_id)?;
        self.process_output(output)
    }

    pub fn send_contact_offline_frame(
        &mut self,
        session_id: SessionId,
        frame: Frame,
    ) -> Result<(), DriverError> {
        let output = self.coordinator.begin_offline_send(session_id, frame)?;
        self.process_output(output)
    }

    pub fn send_contact_frame(
        &mut self,
        session_id: SessionId,
        message_type: MessageType,
        message_id: u64,
        plaintext: &[u8],
    ) -> Result<(), DriverError> {
        let output =
            self.coordinator
                .send_contact_frame(session_id, message_type, message_id, plaintext)?;
        self.process_output(output)
    }

    pub fn send_group_text(
        &mut self,
        session_id: SessionId,
        message_id: u64,
        text: &str,
    ) -> Result<(), DriverError> {
        let output = self
            .coordinator
            .send_group_text(session_id, message_id, text)?;
        self.process_output(output)
    }

    pub fn send_text(
        &mut self,
        session_id: SessionId,
        text: &str,
    ) -> Result<TextSendResult, DriverError> {
        let session = self
            .session_summary(session_id)
            .ok_or(DriverError::SessionNotOpen(session_id))?;
        let offline = session.offline_mode == Some(OfflineCoordinatorMode::Offline);
        let maximum_bytes = if offline {
            commtools_core::deaddrop::MAX_DEADDROP_BLOB_SIZE
                - commtools_core::constants::FRAME_HEADER_LEN
                - commtools_core::crypto::MIN_ENCRYPTED_PAYLOAD_SIZE
        } else {
            commtools_core::constants::MAX_FRAME_PAYLOAD_SIZE
                - commtools_core::crypto::MIN_ENCRYPTED_PAYLOAD_SIZE
        };
        if text.trim().is_empty() {
            return Err(DriverError::InvalidTextMessage(
                "message must not be empty".into(),
            ));
        }
        if text.len() > maximum_bytes {
            return Err(DriverError::InvalidTextMessage(format!(
                "message exceeds the {maximum_bytes}-byte limit"
            )));
        }

        let message_id = generate_message_id();
        let expected_group_recipients = match &session.key {
            ManagedSessionKey::Contact(_) | ManagedSessionKey::Transient(_) => {
                if offline {
                    self.send_contact_offline_frame(
                        session_id,
                        Frame::new(MessageType::U, message_id, text.as_bytes()),
                    )?;
                } else {
                    self.send_contact_frame(
                        session_id,
                        MessageType::U,
                        message_id,
                        text.as_bytes(),
                    )?;
                }
                Vec::new()
            }
            ManagedSessionKey::Group(_) => {
                self.send_group_text(session_id, message_id, text)?;
                self.coordinator
                    .group_session(session_id)
                    .and_then(|group| group.delivery_status(message_id))
                    .map(|delivery| delivery.expected.iter().cloned().collect())
                    .unwrap_or_default()
            }
        };

        let timestamp_utc = current_utc_hms();
        let record = HistoryRecord {
            created_ms: now_epoch_millis(),
            timestamp_utc: timestamp_utc.clone(),
            author: if offline { "Me-Offline" } else { "Me" }.into(),
            sender_b32: None,
            text: text.to_string(),
            mine: true,
            offline,
            msg_id: Some(message_id),
            delivered: false,
            group_expected_acks: expected_group_recipients.clone(),
            group_received_acks: Vec::new(),
        };
        let (history, history_warning) = self.store_text_history(&session.key, &record);

        Ok(TextSendResult {
            session_id,
            message_id,
            text: text.to_string(),
            timestamp_utc,
            offline,
            expected_group_recipients,
            history,
            history_warning,
        })
    }

    pub fn send_image(
        &mut self,
        session_id: SessionId,
        filename: String,
        mime: String,
        bytes: Vec<u8>,
    ) -> Result<ImageSendResult, DriverError> {
        self.send_image_with_original(session_id, filename, mime, bytes, None)
    }

    pub fn send_image_with_original(
        &mut self,
        session_id: SessionId,
        filename: String,
        mime: String,
        bytes: Vec<u8>,
        original: Option<OriginalImageData>,
    ) -> Result<ImageSendResult, DriverError> {
        let session = self
            .session_summary(session_id)
            .ok_or(DriverError::SessionNotOpen(session_id))?;
        if session.offline_mode == Some(OfflineCoordinatorMode::Offline) {
            return Err(DriverError::ImageRequiresLiveSession(session_id));
        }
        let message_id = generate_message_id();
        validate_image_bytes(&mime, &bytes)
            .map_err(|error| DriverError::InvalidImageFile(error.to_string()))?;
        let original_metadata = original
            .as_ref()
            .map(|original| {
                if original.bytes.is_empty()
                    || original.bytes.len() > INLINE_IMAGE_TRANSFER_MAX_BYTES
                {
                    return Err(DriverError::InvalidImageFile(format!(
                        "original image must contain 1 to {INLINE_IMAGE_TRANSFER_MAX_BYTES} bytes"
                    )));
                }
                validate_image_bytes(&original.mime, &original.bytes)
                    .map_err(|error| DriverError::InvalidImageFile(error.to_string()))?;
                OriginalImageMetadata::new(
                    original.bytes.len() as u64,
                    original.mime.clone(),
                    image_sha256_hex(&original.bytes),
                )
                .map_err(|error| DriverError::InvalidImageFile(error.to_string()))
            })
            .transpose()?;
        let expected_group_recipients = match session.key {
            ManagedSessionKey::Contact(_) | ManagedSessionKey::Transient(_) => {
                self.send_contact_image_with_original(
                    session_id,
                    message_id,
                    &filename,
                    &mime,
                    &bytes,
                    original_metadata.clone(),
                )?;
                self.outgoing_contact_images
                    .insert((session_id, message_id));
                Vec::new()
            }
            ManagedSessionKey::Group(_) => {
                let output = self.coordinator.send_group_image_with_original(
                    session_id,
                    message_id,
                    &filename,
                    &mime,
                    &bytes,
                    original_metadata.clone(),
                )?;
                self.process_output(output)?;
                let expected = self
                    .coordinator
                    .group_session(session_id)
                    .and_then(|group| group.delivery_status(message_id))
                    .map(|delivery| delivery.expected.iter().cloned().collect())
                    .unwrap_or_default();
                self.outgoing_group_images.insert((session_id, message_id));
                expected
            }
        };
        if let (Some(original), Some(metadata)) = (original, original_metadata.as_ref()) {
            self.cache_shared_original(
                session_id,
                message_id,
                sanitize_image_filename(&filename),
                original.mime,
                original.bytes,
                metadata.sha256.clone(),
            );
        }
        Ok(ImageSendResult {
            session_id,
            message_id,
            filename: sanitize_image_filename(&filename),
            mime,
            bytes,
            timestamp_utc: current_utc_hms(),
            expected_group_recipients,
            original: original_metadata,
        })
    }

    pub fn send_group_image(
        &mut self,
        session_id: SessionId,
        message_id: u64,
        filename: &str,
        mime: &str,
        bytes: &[u8],
    ) -> Result<(), DriverError> {
        validate_image_bytes(mime, bytes)
            .map_err(|error| DriverError::InvalidImageFile(error.to_string()))?;
        let output = self
            .coordinator
            .send_group_image(session_id, message_id, filename, mime, bytes)?;
        self.process_output(output)
    }

    pub fn request_original_image(
        &mut self,
        session_id: SessionId,
        media_id: u64,
        sender_b32: Option<String>,
    ) -> Result<OriginalImageRequestResult, DriverError> {
        let key = self.original_image_key(session_id, media_id, sender_b32)?;
        if let Some(image) = self.received_original_images.get(&key) {
            return Ok(OriginalImageRequestResult::Cached(
                OriginalImageReceivedEvent {
                    session_id,
                    transfer_id: media_id,
                    media_id,
                    filename: image.filename.clone(),
                    mime: image.mime.clone(),
                    bytes: image.bytes.clone(),
                    sender_b32: (!key.sender_b32.is_empty()).then(|| key.sender_b32.clone()),
                },
            ));
        }
        if !self.available_original_images.contains_key(&key) {
            return Err(DriverError::OriginalImageNotAvailable {
                session_id,
                media_id,
            });
        }
        if self.pending_original_images.contains(&key) {
            return Ok(OriginalImageRequestResult::Requested);
        }
        let control = OriginalImageControl::Request(media_id);
        if key.sender_b32.is_empty() {
            if let Some(resources) = self.resources.get_mut(&session_id) {
                resources.incoming_image.allow_original(media_id);
            }
            self.send_contact_frame(
                session_id,
                MessageType::J,
                generate_message_id(),
                &control
                    .encode()
                    .map_err(|error| DriverError::InvalidImageFile(error.to_string()))?,
            )?;
        } else {
            let output = self.coordinator.send_group_original_image_control(
                session_id,
                &key.sender_b32,
                generate_message_id(),
                control,
            )?;
            self.process_output(output)?;
        }
        self.pending_original_images.insert(key);
        Ok(OriginalImageRequestResult::Requested)
    }

    pub fn cancel_original_image(
        &mut self,
        session_id: SessionId,
        media_id: u64,
        sender_b32: Option<String>,
    ) -> Result<(), DriverError> {
        let key = self.original_image_key(session_id, media_id, sender_b32)?;
        if !self.pending_original_images.remove(&key) {
            return Err(DriverError::OriginalImageRequestNotPending {
                session_id,
                media_id,
            });
        }
        let control = OriginalImageControl::Cancel(media_id);
        if key.sender_b32.is_empty() {
            if let Some(resources) = self.resources.get_mut(&session_id) {
                resources.incoming_image.cancel_original(media_id);
            }
            self.send_contact_frame(
                session_id,
                MessageType::J,
                generate_message_id(),
                &control
                    .encode()
                    .map_err(|error| DriverError::InvalidImageFile(error.to_string()))?,
            )?;
        } else {
            let output = self.coordinator.send_group_original_image_control(
                session_id,
                &key.sender_b32,
                generate_message_id(),
                control,
            )?;
            self.process_output(output)?;
        }
        Ok(())
    }

    fn original_image_key(
        &self,
        session_id: SessionId,
        media_id: u64,
        sender_b32: Option<String>,
    ) -> Result<OriginalImageKey, DriverError> {
        if media_id == 0 {
            return Err(DriverError::OriginalImageNotAvailable {
                session_id,
                media_id,
            });
        }
        let session = self
            .session_summary(session_id)
            .ok_or(DriverError::SessionNotOpen(session_id))?;
        let sender_b32 = match session.key {
            ManagedSessionKey::Group(_) => sender_b32
                .filter(|sender| !sender.trim().is_empty())
                .ok_or(DriverError::OriginalImageGroupSenderRequired)?
                .trim()
                .to_ascii_lowercase(),
            ManagedSessionKey::Contact(_) | ManagedSessionKey::Transient(_) => String::new(),
        };
        Ok(OriginalImageKey {
            session_id,
            media_id,
            sender_b32,
        })
    }

    fn cache_shared_original(
        &mut self,
        session_id: SessionId,
        media_id: u64,
        filename: String,
        mime: String,
        bytes: Vec<u8>,
        sha256: String,
    ) {
        self.shared_original_images.remove(&(session_id, media_id));
        evict_original_cache(
            &mut self.shared_original_images,
            bytes.len(),
            |(cached_session, _), _| *cached_session == session_id,
        );
        self.shared_original_images.insert(
            (session_id, media_id),
            CachedOriginalImage {
                filename,
                mime,
                bytes,
                sha256,
                added_ms: now_epoch_millis(),
            },
        );
    }

    fn cache_received_original(&mut self, key: OriginalImageKey, image: CachedOriginalImage) {
        let session_id = key.session_id;
        self.received_original_images.remove(&key);
        evict_original_cache(
            &mut self.received_original_images,
            image.bytes.len(),
            |candidate, _| candidate.session_id == session_id,
        );
        self.received_original_images.insert(key, image);
    }

    pub fn send_group_image_path(
        &mut self,
        session_id: SessionId,
        message_id: u64,
        path: &Path,
    ) -> Result<GroupImageData, DriverError> {
        let image = load_image_path(path, GROUP_IMAGE_TRANSFER_MAX_BYTES, "group image")?;
        self.send_group_image(
            session_id,
            message_id,
            &image.filename,
            &image.mime,
            &image.bytes,
        )?;
        Ok(image)
    }

    pub fn send_contact_image_path(
        &mut self,
        session_id: SessionId,
        message_id: u64,
        path: &Path,
    ) -> Result<GroupImageData, DriverError> {
        let image = load_image_path(path, INLINE_IMAGE_TRANSFER_MAX_BYTES, "inline image")?;
        self.send_contact_image(
            session_id,
            message_id,
            &image.filename,
            &image.mime,
            &image.bytes,
        )?;
        Ok(image)
    }

    pub fn send_contact_image(
        &mut self,
        session_id: SessionId,
        message_id: u64,
        filename: &str,
        mime: &str,
        bytes: &[u8],
    ) -> Result<(), DriverError> {
        self.send_contact_image_with_original(session_id, message_id, filename, mime, bytes, None)
    }

    fn send_contact_image_with_original(
        &mut self,
        session_id: SessionId,
        message_id: u64,
        filename: &str,
        mime: &str,
        bytes: &[u8],
        original: Option<OriginalImageMetadata>,
    ) -> Result<(), DriverError> {
        let header = ImageTransferHeader {
            filename: filename.to_string(),
            mime: mime.to_string(),
            total_bytes: bytes.len() as u64,
            kind: ImageTransferKind::Preview,
            media_id: message_id,
            original,
        };
        self.send_contact_image_header(session_id, message_id, &header, bytes)
    }

    fn send_contact_image_header(
        &mut self,
        session_id: SessionId,
        transfer_id: u64,
        header: &ImageTransferHeader,
        bytes: &[u8],
    ) -> Result<(), DriverError> {
        let plaintext_frames = inline_image_frames_with_header(transfer_id, header, bytes)
            .map_err(|error| DriverError::InvalidImageFile(error.to_string()))?;
        let (connection_id, frames) = {
            let session = self
                .coordinator
                .one_to_one_session(session_id)
                .ok_or(ApplicationCoordinatorError::SessionNotFound(session_id))?;
            let connection_id = session
                .active_connection_id()
                .ok_or(ApplicationCoordinatorError::ContactNotReady)?;
            let frames = plaintext_frames
                .into_iter()
                .map(|frame| {
                    session
                        .seal_application_frame(
                            frame.message_type,
                            frame.message_id,
                            &frame.payload,
                        )
                        .map_err(ApplicationCoordinatorError::from)
                })
                .collect::<Result<Vec<_>, _>>()?;
            (connection_id, frames)
        };
        self.schedule_image_sequence(session_id, connection_id, frames, "send 1:1 image sequence")
    }

    fn send_contact_original_image(
        &mut self,
        session_id: SessionId,
        media_id: u64,
        image: &CachedOriginalImage,
    ) -> Result<(), DriverError> {
        let transfer_id = generate_message_id();
        let header = original_image_header(media_id, image)?;
        let plaintext_frames = inline_image_frames_with_header(transfer_id, &header, &image.bytes)
            .map_err(|error| DriverError::InvalidImageFile(error.to_string()))?;
        let (connection_id, frames) = {
            let session = self
                .coordinator
                .one_to_one_session(session_id)
                .ok_or(ApplicationCoordinatorError::SessionNotFound(session_id))?;
            let connection_id = session
                .active_connection_id()
                .ok_or(ApplicationCoordinatorError::ContactNotReady)?;
            let frames = plaintext_frames
                .into_iter()
                .map(|frame| {
                    session
                        .seal_application_frame(
                            frame.message_type,
                            frame.message_id,
                            &frame.payload,
                        )
                        .map_err(ApplicationCoordinatorError::from)
                })
                .collect::<Result<Vec<_>, _>>()?;
            (connection_id, frames)
        };
        let key = OriginalImageKey {
            session_id,
            media_id,
            sender_b32: String::new(),
        };
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.outgoing_original_cancels
            .insert(key.clone(), cancel.clone());
        self.schedule_original_image_sequence(
            session_id,
            connection_id,
            frames,
            cancel,
            key,
            "send requested 1:1 original image",
        )
    }

    pub fn send_contact_file_path(
        &mut self,
        session_id: SessionId,
        path: &Path,
    ) -> Result<(u64, String, u64), DriverError> {
        if self.outgoing_files.contains_key(&session_id) {
            return Err(DriverError::FileTransferAlreadyActive(session_id));
        }
        let metadata = fs::metadata(path).map_err(|source| DriverError::FileIo {
            path: path.to_path_buf(),
            source,
        })?;
        if !metadata.is_file() {
            return Err(DriverError::InvalidFileTransfer(
                "the selected path is not a regular file".into(),
            ));
        }
        let total_bytes = metadata.len();
        if total_bytes == 0 || total_bytes > FILE_TRANSFER_MAX_BYTES {
            return Err(DriverError::InvalidFileTransfer(format!(
                "file size must be between 1 and {FILE_TRANSFER_MAX_BYTES} bytes"
            )));
        }
        let filename = sanitize_file_filename(
            path.file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("file.bin"),
        );
        let file = File::open(path).map_err(|source| DriverError::FileIo {
            path: path.to_path_buf(),
            source,
        })?;
        let (connection_id, sealer) = {
            let session = self
                .coordinator
                .one_to_one_session(session_id)
                .ok_or(ApplicationCoordinatorError::SessionNotFound(session_id))?;
            let connection_id = session
                .active_connection_id()
                .ok_or(ApplicationCoordinatorError::ContactNotReady)?;
            (
                connection_id,
                session
                    .file_frame_sealer()
                    .map_err(ApplicationCoordinatorError::from)?,
            )
        };
        let transfer_id = generate_message_id();
        let control = FileTransferControl::Offer {
            filename: filename.clone(),
            total_bytes,
        }
        .encode()
        .map_err(|error| DriverError::InvalidFileTransfer(error.to_string()))?;
        self.send_contact_frame(session_id, MessageType::F, transfer_id, &control)?;
        self.outgoing_files.insert(
            session_id,
            OutgoingFileTransfer {
                transfer_id,
                connection_id,
                filename: filename.clone(),
                total_bytes,
                offered_ms: now_epoch_millis(),
                file: Some(file),
                sealer: Some(sealer),
            },
        );
        self.events.push_back(ApplicationEvent::FileTransfer {
            session_id,
            event: CoreFileTransferEvent::Offered {
                transfer_id,
                direction: CoreFileTransferDirection::Sent,
                filename: filename.clone(),
                total_bytes,
            },
        });
        Ok((transfer_id, filename, total_bytes))
    }

    pub fn accept_incoming_file(
        &mut self,
        session_id: SessionId,
        transfer_id: u64,
    ) -> Result<(), DriverError> {
        let offer = self
            .incoming_file_offers
            .get(&session_id)
            .filter(|offer| offer.transfer_id == transfer_id)
            .ok_or(DriverError::FileTransferNotFound {
                session_id,
                transfer_id,
            })?;
        let connection_id = offer.connection_id;
        let filename = offer.filename.clone();
        let total_bytes = offer.total_bytes;
        let files_dir = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .files_dir();
        let (file, temporary_path, final_path) =
            create_incoming_file(&files_dir, transfer_id, &filename)
                .map_err(DriverError::InvalidFileTransfer)?;
        self.incoming_files.insert(
            session_id,
            IncomingFileTransfer {
                transfer_id,
                connection_id,
                filename: filename.clone(),
                expected_bytes: total_bytes,
                received_bytes: 0,
                last_reported_bytes: 0,
                temporary_path,
                final_path,
                file,
            },
        );
        if let Err(error) =
            self.send_file_control(session_id, transfer_id, FileTransferControl::Accept)
        {
            self.remove_incoming_file(session_id);
            return Err(error);
        }
        self.incoming_file_offers.remove(&session_id);
        self.events.push_back(ApplicationEvent::FileTransfer {
            session_id,
            event: CoreFileTransferEvent::Started {
                transfer_id,
                direction: CoreFileTransferDirection::Received,
                filename,
                total_bytes,
            },
        });
        Ok(())
    }

    pub fn decline_incoming_file(
        &mut self,
        session_id: SessionId,
        transfer_id: u64,
    ) -> Result<(), DriverError> {
        let filename = self
            .incoming_file_offers
            .get(&session_id)
            .filter(|offer| offer.transfer_id == transfer_id)
            .map(|offer| offer.filename.clone())
            .ok_or(DriverError::FileTransferNotFound {
                session_id,
                transfer_id,
            })?;
        let notification_error = self
            .send_file_control(session_id, transfer_id, FileTransferControl::Decline)
            .err();
        self.incoming_file_offers.remove(&session_id);
        self.push_file_terminal_event(
            session_id,
            transfer_id,
            CoreFileTransferDirection::Received,
            filename,
            FileTerminalState::Declined,
        );
        if let Some(error) = notification_error {
            self.push_failure(
                Some(session_id),
                "notify peer of declined file offer",
                error.to_string(),
            );
        }
        Ok(())
    }

    pub fn cancel_file_transfer(
        &mut self,
        session_id: SessionId,
        transfer_id: u64,
    ) -> Result<(), DriverError> {
        if let Some(transfer) = self
            .outgoing_files
            .get(&session_id)
            .filter(|transfer| transfer.transfer_id == transfer_id)
        {
            let connection_id = transfer.connection_id;
            let filename = transfer.filename.clone();
            let sending = transfer.file.is_none();
            let notification_error = self
                .send_file_control(session_id, transfer_id, FileTransferControl::Cancel)
                .err();
            self.outgoing_files.remove(&session_id);
            if sending {
                let _ = self.send_job(
                    session_id,
                    connection_id,
                    SendJob::CancelFile { transfer_id },
                );
            }
            self.push_file_terminal_event(
                session_id,
                transfer_id,
                CoreFileTransferDirection::Sent,
                filename,
                FileTerminalState::Cancelled,
            );
            if let Some(error) = notification_error {
                self.push_failure(
                    Some(session_id),
                    "notify peer of cancelled file transfer",
                    error.to_string(),
                );
            }
            return Ok(());
        }

        if let Some(offer) = self
            .incoming_file_offers
            .get(&session_id)
            .filter(|offer| offer.transfer_id == transfer_id)
        {
            let filename = offer.filename.clone();
            let notification_error = self
                .send_file_control(session_id, transfer_id, FileTransferControl::Cancel)
                .err();
            self.incoming_file_offers.remove(&session_id);
            self.push_file_terminal_event(
                session_id,
                transfer_id,
                CoreFileTransferDirection::Received,
                filename,
                FileTerminalState::Cancelled,
            );
            if let Some(error) = notification_error {
                self.push_failure(
                    Some(session_id),
                    "notify peer of cancelled file transfer",
                    error.to_string(),
                );
            }
            return Ok(());
        }

        if let Some(transfer) = self
            .incoming_files
            .get(&session_id)
            .filter(|transfer| transfer.transfer_id == transfer_id)
        {
            let filename = transfer.filename.clone();
            let notification_error = self
                .send_file_control(session_id, transfer_id, FileTransferControl::Cancel)
                .err();
            self.remove_incoming_file(session_id);
            self.push_file_terminal_event(
                session_id,
                transfer_id,
                CoreFileTransferDirection::Received,
                filename,
                FileTerminalState::Cancelled,
            );
            if let Some(error) = notification_error {
                self.push_failure(
                    Some(session_id),
                    "notify peer of cancelled file transfer",
                    error.to_string(),
                );
            }
            return Ok(());
        }

        Err(DriverError::FileTransferNotFound {
            session_id,
            transfer_id,
        })
    }

    fn send_file_control(
        &mut self,
        session_id: SessionId,
        transfer_id: u64,
        control: FileTransferControl,
    ) -> Result<(), DriverError> {
        let payload = control
            .encode()
            .map_err(|error| DriverError::InvalidFileTransfer(error.to_string()))?;
        self.send_contact_frame(session_id, MessageType::F, transfer_id, &payload)
    }

    pub fn validate_received_group_image(
        &self,
        session_id: SessionId,
        filename: &str,
        mime: &str,
        bytes: &[u8],
    ) -> Result<GroupImageData, DriverError> {
        if bytes.is_empty() || bytes.len() > GROUP_IMAGE_TRANSFER_MAX_BYTES {
            return Err(DriverError::InvalidImageFile(format!(
                "received group image must contain 1 to {GROUP_IMAGE_TRANSFER_MAX_BYTES} bytes"
            )));
        }
        validate_image_bytes(mime, bytes)
            .map_err(|error| DriverError::InvalidImageFile(error.to_string()))?;
        if self.coordinator.group_id_for_session(session_id).is_none() {
            return Err(DriverError::SessionNotOpen(session_id));
        }
        Ok(GroupImageData {
            filename: sanitize_image_filename(filename),
            mime: mime.to_string(),
            bytes: bytes.to_vec(),
        })
    }

    pub fn open_contact_frame(
        &self,
        session_id: SessionId,
        frame: &Frame,
    ) -> Result<Frame, DriverError> {
        let session = self
            .coordinator
            .one_to_one_session(session_id)
            .ok_or(ApplicationCoordinatorError::SessionNotFound(session_id))?;
        session
            .open_application_frame(frame)
            .map_err(ApplicationCoordinatorError::from)
            .map_err(DriverError::from)
    }

    fn translate_frontend_event(
        &mut self,
        event: ApplicationEvent,
    ) -> Result<Option<FrontendEvent>, DriverError> {
        match event {
            ApplicationEvent::SessionOpening { key } => Ok(Some(FrontendEvent::Session(
                SessionLifecycleEvent::Opening { key },
            ))),
            ApplicationEvent::SessionOpenFailed { key, reason } => Ok(Some(
                FrontendEvent::Session(SessionLifecycleEvent::OpenFailed { key, reason }),
            )),
            ApplicationEvent::SessionOpened { session_id, key } => Ok(Some(
                FrontendEvent::Session(SessionLifecycleEvent::Opened { session_id, key }),
            )),
            ApplicationEvent::SessionClosing { session_id, key } => Ok(Some(
                FrontendEvent::Session(SessionLifecycleEvent::Closing { session_id, key }),
            )),
            ApplicationEvent::SessionClosed { session_id, key } => Ok(Some(
                FrontendEvent::Session(SessionLifecycleEvent::Closed { session_id, key }),
            )),
            ApplicationEvent::OneToOne {
                session_id,
                event: commtools_core::OneToOneEvent::ApplicationFrame { frame, .. },
            } => {
                let opened = match self.open_contact_frame(session_id, &frame) {
                    Ok(opened) => opened,
                    Err(error) => {
                        let rejected = if matches!(
                            frame.message_type,
                            MessageType::J | MessageType::G | MessageType::Z
                        ) {
                            FrontendEvent::ImageRejected {
                                session_id,
                                reason: error.to_string(),
                            }
                        } else {
                            FrontendEvent::TextRejected {
                                session_id,
                                offline_index: None,
                                reason: error.to_string(),
                            }
                        };
                        return Ok(Some(rejected));
                    }
                };
                match opened.message_type {
                    MessageType::U => self.contact_text_received(session_id, opened).map(Some),
                    MessageType::D => self.contact_delivery_received(session_id, opened).map(Some),
                    MessageType::J | MessageType::G | MessageType::Z => {
                        self.contact_image_frame_received(session_id, opened)
                    }
                    _ => Ok(None),
                }
            }
            ApplicationEvent::OneToOne {
                session_id,
                event: commtools_core::OneToOneEvent::PhaseChanged(phase),
            } => Ok(Some(FrontendEvent::Contact(
                ContactSessionEvent::PhaseChanged { session_id, phase },
            ))),
            ApplicationEvent::OneToOne {
                session_id,
                event: commtools_core::OneToOneEvent::IncomingCall { peer_b32, .. },
            } => Ok(Some(FrontendEvent::Contact(
                ContactSessionEvent::IncomingCall {
                    session_id,
                    peer_b32,
                },
            ))),
            ApplicationEvent::OneToOne {
                session_id,
                event: commtools_core::OneToOneEvent::CollisionResolved { winner, .. },
            } => Ok(Some(FrontendEvent::Contact(
                ContactSessionEvent::CollisionResolved { session_id, winner },
            ))),
            ApplicationEvent::OneToOne {
                session_id,
                event:
                    commtools_core::OneToOneEvent::IdentityVerified {
                        peer_b32, pinned, ..
                    },
            } => Ok(Some(FrontendEvent::Contact(
                ContactSessionEvent::IdentityVerified {
                    session_id,
                    peer_b32,
                    pinned,
                },
            ))),
            ApplicationEvent::OneToOne {
                session_id,
                event: commtools_core::OneToOneEvent::SecureSessionReady { peer_b32, .. },
            } => Ok(Some(FrontendEvent::Contact(
                ContactSessionEvent::SecureSessionReady {
                    session_id,
                    peer_b32,
                },
            ))),
            ApplicationEvent::OneToOne {
                session_id,
                event:
                    commtools_core::OneToOneEvent::ConnectFailed {
                        peer_b32, reason, ..
                    },
            } => Ok(Some(FrontendEvent::Contact(
                ContactSessionEvent::ConnectFailed {
                    session_id,
                    peer_b32,
                    reason,
                },
            ))),
            ApplicationEvent::OneToOne {
                session_id,
                event:
                    commtools_core::OneToOneEvent::ConnectRetryScheduled {
                        peer_b32, reason, ..
                    },
            } => Ok(Some(FrontendEvent::Contact(
                ContactSessionEvent::ConnectRetryScheduled {
                    session_id,
                    peer_b32,
                    reason,
                },
            ))),
            ApplicationEvent::OneToOne {
                session_id,
                event: commtools_core::OneToOneEvent::FrameRejected { reason, .. },
            } => Ok(Some(FrontendEvent::Contact(
                ContactSessionEvent::FrameRejected { session_id, reason },
            ))),
            ApplicationEvent::OneToOne {
                session_id,
                event: commtools_core::OneToOneEvent::ConnectionRejected { reason, .. },
            } => Ok(Some(FrontendEvent::Contact(
                ContactSessionEvent::ConnectionRejected { session_id, reason },
            ))),
            ApplicationEvent::OneToOne {
                session_id,
                event: commtools_core::OneToOneEvent::Disconnected { peer_b32, reason },
            } => Ok(Some(FrontendEvent::Contact(
                ContactSessionEvent::Disconnected {
                    session_id,
                    peer_b32,
                    reason,
                },
            ))),
            ApplicationEvent::OneToOne {
                event: commtools_core::OneToOneEvent::ControlSignal { .. },
                ..
            } => Ok(None),
            ApplicationEvent::Rendezvous { session_id, event } => Ok(Some(
                FrontendEvent::Rendezvous(translate_rendezvous_event(session_id, event)),
            )),
            ApplicationEvent::Group {
                session_id,
                event:
                    CoreGroupSessionEvent::TextReceived {
                        peer_b32,
                        message_id,
                        text,
                    },
            } => self
                .group_text_received(session_id, peer_b32, message_id, text)
                .map(Some),
            ApplicationEvent::Group {
                session_id,
                event:
                    CoreGroupSessionEvent::ImageReceived {
                        peer_b32,
                        transfer_id,
                        media_id,
                        kind,
                        original,
                        filename,
                        mime,
                        bytes,
                    },
            } => Ok(Some(self.group_image_received(
                session_id,
                peer_b32,
                transfer_id,
                media_id,
                kind,
                original,
                filename,
                mime,
                bytes,
            ))),
            ApplicationEvent::Group {
                session_id,
                event: CoreGroupSessionEvent::OriginalImageControlReceived { peer_b32, control },
            } => self.handle_group_original_image_control(session_id, peer_b32, control),
            ApplicationEvent::Group {
                session_id,
                event:
                    CoreGroupSessionEvent::OriginalImageProgress {
                        peer_b32,
                        transfer_id,
                        media_id,
                        received_bytes,
                        total_bytes,
                    },
            } => Ok(Some(FrontendEvent::OriginalImageProgress {
                session_id,
                transfer_id,
                media_id,
                received_bytes,
                total_bytes,
                sender_b32: Some(peer_b32),
            })),
            ApplicationEvent::Group {
                session_id,
                event: CoreGroupSessionEvent::DeliveryUpdated(delivery),
            } => {
                if self
                    .outgoing_group_images
                    .contains(&(session_id, delivery.message_id))
                {
                    if delivery.is_complete() {
                        self.outgoing_group_images
                            .remove(&(session_id, delivery.message_id));
                    }
                    Ok(Some(FrontendEvent::ImageDeliveryUpdated(
                        ImageDeliveryEvent {
                            session_id,
                            message_id: delivery.message_id,
                            group: true,
                            received: delivery.received.len(),
                            expected: delivery.expected.len(),
                        },
                    )))
                } else {
                    let warning = self.persist_group_delivery(session_id, &delivery);
                    Ok(Some(FrontendEvent::TextDeliveryUpdated(
                        TextDeliveryEvent {
                            session_id,
                            message_id: delivery.message_id,
                            peer_b32: None,
                            group: true,
                            received: delivery.received.len(),
                            expected: delivery.expected.len(),
                            warning,
                        },
                    )))
                }
            }
            ApplicationEvent::Group {
                session_id,
                event: CoreGroupSessionEvent::ConnectFailed { peer_b32, reason },
            } => Ok(Some(FrontendEvent::Group(
                GroupSessionEvent::ConnectFailed {
                    session_id,
                    peer_b32,
                    reason,
                },
            ))),
            ApplicationEvent::Group {
                session_id,
                event:
                    CoreGroupSessionEvent::CollisionResolved {
                        peer_b32, winner, ..
                    },
            } => Ok(Some(FrontendEvent::Group(
                GroupSessionEvent::CollisionResolved {
                    session_id,
                    peer_b32,
                    winner,
                },
            ))),
            ApplicationEvent::Group {
                session_id,
                event: CoreGroupSessionEvent::IdentityVerified { peer_b32, .. },
            } => Ok(Some(FrontendEvent::Group(
                GroupSessionEvent::IdentityVerified {
                    session_id,
                    peer_b32,
                },
            ))),
            ApplicationEvent::Group {
                session_id,
                event:
                    CoreGroupSessionEvent::SecureSessionReady {
                        peer_b32,
                        authorized,
                        ..
                    },
            } => Ok(Some(FrontendEvent::Group(
                GroupSessionEvent::SecureSessionReady {
                    session_id,
                    peer_b32,
                    authorized,
                },
            ))),
            ApplicationEvent::Group {
                session_id,
                event: CoreGroupSessionEvent::PeerDisconnected { peer_b32, reason },
            } => Ok(Some(FrontendEvent::Group(
                GroupSessionEvent::PeerDisconnected {
                    session_id,
                    peer_b32,
                    reason,
                },
            ))),
            ApplicationEvent::Group {
                session_id,
                event: CoreGroupSessionEvent::ControlReceived { peer_b32, .. },
            } => Ok(Some(FrontendEvent::Group(
                GroupSessionEvent::ControlReceived {
                    session_id,
                    peer_b32,
                },
            ))),
            ApplicationEvent::Group {
                session_id,
                event: CoreGroupSessionEvent::RosterReceived { peer_b32, .. },
            } => Ok(Some(FrontendEvent::Group(
                GroupSessionEvent::RosterReceived {
                    session_id,
                    peer_b32,
                },
            ))),
            ApplicationEvent::Group {
                session_id,
                event: CoreGroupSessionEvent::DissolutionReceived { peer_b32, .. },
            } => Ok(Some(FrontendEvent::Group(
                GroupSessionEvent::DissolutionReceived {
                    session_id,
                    peer_b32,
                },
            ))),
            ApplicationEvent::Group {
                session_id,
                event: CoreGroupSessionEvent::FrameRejected { peer_b32, reason },
            } => Ok(Some(FrontendEvent::Group(
                GroupSessionEvent::FrameRejected {
                    session_id,
                    peer_b32,
                    reason,
                },
            ))),
            ApplicationEvent::Group {
                event: CoreGroupSessionEvent::ApplicationFrame { .. },
                ..
            } => Ok(None),
            ApplicationEvent::FileTransfer { session_id, event } => Ok(Some(
                FrontendEvent::FileTransfer(translate_file_transfer_event(session_id, event)),
            )),
            ApplicationEvent::Offline {
                session_id,
                event: commtools_core::OfflineCoordinatorEvent::FrameReceived { index, frame, .. },
            } if frame.message_type == MessageType::U => self
                .offline_text_received(session_id, index, frame)
                .map(Some),
            ApplicationEvent::Offline { session_id, event } => Ok(Some(FrontendEvent::Offline(
                translate_offline_event(session_id, event),
            ))),
            ApplicationEvent::OfflineStatePersisted { session_id, .. } => Ok(Some(
                FrontendEvent::Offline(OfflineSessionEvent::StatePersisted { session_id }),
            )),
            ApplicationEvent::OfflineEnrollmentPersisted { session_id, .. } => Ok(Some(
                FrontendEvent::Offline(OfflineSessionEvent::EnrollmentPersisted { session_id }),
            )),
            ApplicationEvent::OperationFailed {
                session_id,
                operation,
                reason,
            } => Ok(Some(FrontendEvent::Operation(
                RuntimeOperationEvent::Failed {
                    session_id,
                    operation: operation.into(),
                    reason,
                },
            ))),
            ApplicationEvent::OperationRecovered {
                session_id,
                operation,
            } => Ok(Some(FrontendEvent::Operation(
                RuntimeOperationEvent::Recovered {
                    session_id,
                    operation: operation.into(),
                },
            ))),
            ApplicationEvent::Stopping => Ok(Some(FrontendEvent::Lifecycle(
                ApplicationLifecycleEvent::Stopping,
            ))),
            ApplicationEvent::VaultLockRequested => Ok(Some(FrontendEvent::Lifecycle(
                ApplicationLifecycleEvent::VaultLockRequested,
            ))),
            ApplicationEvent::Stopped => Ok(Some(FrontendEvent::Lifecycle(
                ApplicationLifecycleEvent::Stopped,
            ))),
        }
    }

    fn contact_image_frame_received(
        &mut self,
        session_id: SessionId,
        frame: Frame,
    ) -> Result<Option<FrontendEvent>, DriverError> {
        if frame.message_type == MessageType::J {
            match OriginalImageControl::decode(&frame.payload) {
                Ok(Some(control)) => {
                    return self.handle_contact_original_image_control(session_id, control);
                }
                Err(error) => {
                    return Ok(Some(FrontendEvent::ImageRejected {
                        session_id,
                        reason: error.to_string(),
                    }));
                }
                Ok(None) => {}
            }
            if let Ok(header_text) = std::str::from_utf8(&frame.payload)
                && let Ok(header) = ImageTransferHeader::decode(header_text)
                && header.kind == ImageTransferKind::Original
            {
                let key = OriginalImageKey {
                    session_id,
                    media_id: header.media_id,
                    sender_b32: String::new(),
                };
                if !self.pending_original_images.contains(&key) {
                    return Ok(Some(FrontendEvent::ImageRejected {
                        session_id,
                        reason: "unsolicited original image".into(),
                    }));
                }
            }
        }
        let received = self
            .resources
            .get_mut(&session_id)
            .ok_or(DriverError::MissingResources(session_id))?
            .incoming_image
            .receive(&frame);
        let image = match received {
            Ok(Some(image)) => image,
            Ok(None) => {
                if frame.message_type == MessageType::G {
                    let resources = self
                        .resources
                        .get(&session_id)
                        .ok_or(DriverError::MissingResources(session_id))?;
                    if let Some((transfer_id, header, received_bytes)) =
                        resources.incoming_image.active_transfer()
                        && header.kind == ImageTransferKind::Original
                    {
                        return Ok(Some(FrontendEvent::OriginalImageProgress {
                            session_id,
                            transfer_id,
                            media_id: header.media_id,
                            received_bytes,
                            total_bytes: header.total_bytes,
                            sender_b32: None,
                        }));
                    }
                }
                return Ok(None);
            }
            Err(error) => {
                return Ok(Some(FrontendEvent::ImageRejected {
                    session_id,
                    reason: error.to_string(),
                }));
            }
        };
        if let Err(error) = validate_image_bytes(&image.mime, &image.bytes) {
            return Ok(Some(FrontendEvent::ImageRejected {
                session_id,
                reason: error.to_string(),
            }));
        }
        let message_id = image.header.media_id;
        if image.header.kind == ImageTransferKind::Original {
            let key = OriginalImageKey {
                session_id,
                media_id: image.header.media_id,
                sender_b32: String::new(),
            };
            if !self.pending_original_images.remove(&key) {
                return Ok(Some(FrontendEvent::ImageRejected {
                    session_id,
                    reason: "unsolicited original image".into(),
                }));
            }
            let event = OriginalImageReceivedEvent {
                session_id,
                transfer_id: image.transfer_id,
                media_id: image.header.media_id,
                filename: image.filename.clone(),
                mime: image.mime.clone(),
                bytes: image.bytes.clone(),
                sender_b32: None,
            };
            self.cache_received_original(
                key,
                CachedOriginalImage {
                    filename: image.filename,
                    mime: image.mime,
                    sha256: image_sha256_hex(&image.bytes),
                    bytes: image.bytes,
                    added_ms: now_epoch_millis(),
                },
            );
            return Ok(Some(FrontendEvent::OriginalImageReceived(event)));
        }
        let original = image
            .header
            .original
            .clone()
            .filter(|metadata| metadata.size <= INLINE_IMAGE_TRANSFER_MAX_BYTES as u64);
        if let Some(original) = original.clone() {
            self.available_original_images.insert(
                OriginalImageKey {
                    session_id,
                    media_id: image.header.media_id,
                    sender_b32: String::new(),
                },
                original,
            );
        }
        if let Err(error) = self.send_contact_frame(
            session_id,
            MessageType::D,
            generate_message_id(),
            &message_id.to_be_bytes(),
        ) {
            self.push_failure(
                Some(session_id),
                "send media delivery acknowledgement",
                error.to_string(),
            );
        }
        Ok(Some(FrontendEvent::ImageReceived(ImageReceivedEvent {
            session_id,
            message_id,
            filename: image.filename,
            mime: image.mime,
            bytes: image.bytes,
            timestamp_utc: current_utc_hms(),
            sender_b32: None,
            original,
        })))
    }

    fn handle_contact_original_image_control(
        &mut self,
        session_id: SessionId,
        control: OriginalImageControl,
    ) -> Result<Option<FrontendEvent>, DriverError> {
        match control {
            OriginalImageControl::Request(media_id) => {
                let key = OriginalImageKey {
                    session_id,
                    media_id,
                    sender_b32: String::new(),
                };
                if self.outgoing_original_cancels.contains_key(&key) {
                    return Ok(None);
                }
                let Some(image) = self
                    .shared_original_images
                    .get(&(session_id, media_id))
                    .cloned()
                else {
                    let unavailable = OriginalImageControl::Unavailable(media_id)
                        .encode()
                        .map_err(|error| DriverError::InvalidImageFile(error.to_string()))?;
                    self.send_contact_frame(
                        session_id,
                        MessageType::J,
                        generate_message_id(),
                        &unavailable,
                    )?;
                    return Ok(None);
                };
                self.send_contact_original_image(session_id, media_id, &image)?;
                Ok(None)
            }
            OriginalImageControl::Unavailable(media_id) => {
                let key = OriginalImageKey {
                    session_id,
                    media_id,
                    sender_b32: String::new(),
                };
                self.pending_original_images.remove(&key);
                Ok(Some(FrontendEvent::OriginalImageUnavailable {
                    session_id,
                    media_id,
                    sender_b32: None,
                }))
            }
            OriginalImageControl::Cancel(media_id) => {
                let key = OriginalImageKey {
                    session_id,
                    media_id,
                    sender_b32: String::new(),
                };
                if let Some(cancel) = self.outgoing_original_cancels.remove(&key) {
                    cancel.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                Ok(Some(FrontendEvent::OriginalImageCancelled {
                    session_id,
                    media_id,
                    sender_b32: None,
                }))
            }
        }
    }

    fn group_image_received(
        &mut self,
        session_id: SessionId,
        peer_b32: String,
        transfer_id: u64,
        media_id: u64,
        kind: ImageTransferKind,
        original: Option<OriginalImageMetadata>,
        filename: String,
        mime: String,
        bytes: Vec<u8>,
    ) -> FrontendEvent {
        let original =
            original.filter(|metadata| metadata.size <= INLINE_IMAGE_TRANSFER_MAX_BYTES as u64);
        let validated = if kind == ImageTransferKind::Original {
            if self.coordinator.group_id_for_session(session_id).is_none() {
                Err(DriverError::SessionNotOpen(session_id))
            } else if bytes.is_empty() || bytes.len() > INLINE_IMAGE_TRANSFER_MAX_BYTES {
                Err(DriverError::InvalidImageFile(format!(
                    "received original image must contain 1 to {INLINE_IMAGE_TRANSFER_MAX_BYTES} bytes"
                )))
            } else {
                validate_image_bytes(&mime, &bytes)
                    .map_err(|error| DriverError::InvalidImageFile(error.to_string()))
                    .map(|()| GroupImageData {
                        filename: sanitize_image_filename(&filename),
                        mime: mime.clone(),
                        bytes: bytes.clone(),
                    })
            }
        } else {
            self.validate_received_group_image(session_id, &filename, &mime, &bytes)
        };
        match validated {
            Ok(image) if kind == ImageTransferKind::Original => {
                let key = OriginalImageKey {
                    session_id,
                    media_id,
                    sender_b32: peer_b32.to_ascii_lowercase(),
                };
                if !self.pending_original_images.remove(&key) {
                    return FrontendEvent::ImageRejected {
                        session_id,
                        reason: "unsolicited group original image".into(),
                    };
                }
                let event = OriginalImageReceivedEvent {
                    session_id,
                    transfer_id,
                    media_id,
                    filename: image.filename.clone(),
                    mime: image.mime.clone(),
                    bytes: image.bytes.clone(),
                    sender_b32: Some(peer_b32),
                };
                self.cache_received_original(
                    key,
                    CachedOriginalImage {
                        filename: image.filename,
                        mime: image.mime,
                        sha256: image_sha256_hex(&image.bytes),
                        bytes: image.bytes,
                        added_ms: now_epoch_millis(),
                    },
                );
                FrontendEvent::OriginalImageReceived(event)
            }
            Ok(image) => {
                if let Some(metadata) = original.clone() {
                    self.available_original_images.insert(
                        OriginalImageKey {
                            session_id,
                            media_id,
                            sender_b32: peer_b32.to_ascii_lowercase(),
                        },
                        metadata,
                    );
                }
                FrontendEvent::ImageReceived(ImageReceivedEvent {
                    session_id,
                    message_id: media_id,
                    filename: image.filename,
                    mime: image.mime,
                    bytes: image.bytes,
                    timestamp_utc: current_utc_hms(),
                    sender_b32: Some(peer_b32),
                    original,
                })
            }
            Err(error) => FrontendEvent::ImageRejected {
                session_id,
                reason: error.to_string(),
            },
        }
    }

    fn handle_group_original_image_control(
        &mut self,
        session_id: SessionId,
        peer_b32: String,
        control: OriginalImageControl,
    ) -> Result<Option<FrontendEvent>, DriverError> {
        match control {
            OriginalImageControl::Request(media_id) => {
                let key = OriginalImageKey {
                    session_id,
                    media_id,
                    sender_b32: peer_b32.to_ascii_lowercase(),
                };
                if self.outgoing_original_cancels.contains_key(&key) {
                    return Ok(None);
                }
                let Some(image) = self
                    .shared_original_images
                    .get(&(session_id, media_id))
                    .cloned()
                else {
                    let output = self.coordinator.send_group_original_image_control(
                        session_id,
                        &peer_b32,
                        generate_message_id(),
                        OriginalImageControl::Unavailable(media_id),
                    )?;
                    self.process_output(output)?;
                    return Ok(None);
                };
                let header = original_image_header(media_id, &image)?;
                let output = self.coordinator.send_group_image_to_peer(
                    session_id,
                    &peer_b32,
                    generate_message_id(),
                    &header,
                    &image.bytes,
                )?;
                self.process_output(output)?;
                Ok(None)
            }
            OriginalImageControl::Unavailable(media_id) => {
                let key = OriginalImageKey {
                    session_id,
                    media_id,
                    sender_b32: peer_b32.to_ascii_lowercase(),
                };
                self.pending_original_images.remove(&key);
                Ok(Some(FrontendEvent::OriginalImageUnavailable {
                    session_id,
                    media_id,
                    sender_b32: Some(peer_b32),
                }))
            }
            OriginalImageControl::Cancel(media_id) => {
                let key = OriginalImageKey {
                    session_id,
                    media_id,
                    sender_b32: peer_b32.to_ascii_lowercase(),
                };
                if let Some(cancel) = self.outgoing_original_cancels.remove(&key) {
                    cancel.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                Ok(Some(FrontendEvent::OriginalImageCancelled {
                    session_id,
                    media_id,
                    sender_b32: Some(peer_b32),
                }))
            }
        }
    }

    fn contact_text_received(
        &mut self,
        session_id: SessionId,
        frame: Frame,
    ) -> Result<FrontendEvent, DriverError> {
        let text = match String::from_utf8(frame.payload) {
            Ok(text) => text,
            Err(_) => {
                return Ok(FrontendEvent::TextRejected {
                    session_id,
                    offline_index: None,
                    reason: "received invalid UTF-8 chat payload".into(),
                });
            }
        };
        let mut warnings = Vec::new();
        if let Err(error) = self.send_contact_frame(
            session_id,
            MessageType::D,
            generate_message_id(),
            &frame.message_id.to_be_bytes(),
        ) {
            warnings.push(format!("send delivery acknowledgement: {error}"));
        }
        let event = self.received_text_event(session_id, frame.message_id, text, None, false, None);
        Ok(FrontendEvent::TextReceived(merge_text_warning(
            event, warnings,
        )))
    }

    fn contact_delivery_received(
        &mut self,
        session_id: SessionId,
        frame: Frame,
    ) -> Result<FrontendEvent, DriverError> {
        let payload = match <[u8; 8]>::try_from(frame.payload.as_slice()) {
            Ok(payload) => payload,
            Err(_) => {
                return Ok(FrontendEvent::TextRejected {
                    session_id,
                    offline_index: None,
                    reason: "delivery acknowledgement must contain an 8-byte message ID".into(),
                });
            }
        };
        let message_id = u64::from_be_bytes(payload);
        if self
            .outgoing_contact_images
            .remove(&(session_id, message_id))
        {
            return Ok(FrontendEvent::ImageDeliveryUpdated(ImageDeliveryEvent {
                session_id,
                message_id,
                group: false,
                received: 1,
                expected: 1,
            }));
        }
        let key = self
            .session_summary(session_id)
            .ok_or(DriverError::SessionNotOpen(session_id))?
            .key;
        let warning = self
            .append_history_delivery(&key, message_id, None)
            .err()
            .map(|error| format!("update text history delivery: {error}"));
        Ok(FrontendEvent::TextDeliveryUpdated(TextDeliveryEvent {
            session_id,
            message_id,
            peer_b32: None,
            group: false,
            received: 1,
            expected: 1,
            warning,
        }))
    }

    fn group_text_received(
        &self,
        session_id: SessionId,
        peer_b32: String,
        message_id: u64,
        text: String,
    ) -> Result<FrontendEvent, DriverError> {
        Ok(FrontendEvent::TextReceived(self.received_text_event(
            session_id,
            message_id,
            text,
            Some(peer_b32),
            false,
            None,
        )))
    }

    fn offline_text_received(
        &self,
        session_id: SessionId,
        index: u64,
        frame: Frame,
    ) -> Result<FrontendEvent, DriverError> {
        let text = match String::from_utf8(frame.payload) {
            Ok(text) => text,
            Err(_) => {
                return Ok(FrontendEvent::TextRejected {
                    session_id,
                    offline_index: Some(index),
                    reason: "received offline message is not valid UTF-8".into(),
                });
            }
        };
        Ok(FrontendEvent::TextReceived(self.received_text_event(
            session_id,
            frame.message_id,
            text,
            None,
            true,
            Some(index),
        )))
    }

    fn received_text_event(
        &self,
        session_id: SessionId,
        message_id: u64,
        text: String,
        sender_b32: Option<String>,
        offline: bool,
        offline_index: Option<u64>,
    ) -> TextReceivedEvent {
        let timestamp_utc = current_utc_hms();
        let key = self.session_summary(session_id).map(|session| session.key);
        let author = self.text_author(key.as_ref(), sender_b32.as_deref(), offline);
        let record = HistoryRecord {
            created_ms: now_epoch_millis(),
            timestamp_utc: timestamp_utc.clone(),
            author,
            sender_b32: sender_b32.clone(),
            text: text.clone(),
            mine: false,
            offline,
            msg_id: Some(message_id),
            delivered: false,
            group_expected_acks: Vec::new(),
            group_received_acks: Vec::new(),
        };
        let (history, history_warning) = key.as_ref().map_or(
            (
                HistoryWriteOutcome::Disabled,
                Some(format!(
                    "save text history: session {session_id} is not open"
                )),
            ),
            |key| self.store_text_history(key, &record),
        );
        TextReceivedEvent {
            session_id,
            message_id,
            text,
            timestamp_utc,
            sender_b32,
            offline,
            offline_index,
            history,
            history_warning,
            warning: None,
        }
    }

    fn store_text_history(
        &self,
        key: &ManagedSessionKey,
        record: &HistoryRecord,
    ) -> (HistoryWriteOutcome, Option<String>) {
        match self.append_history_message(key, record) {
            Ok(outcome) => (outcome, None),
            Err(error) => (
                HistoryWriteOutcome::Disabled,
                Some(format!("save text history: {error}")),
            ),
        }
    }

    fn persist_group_delivery(
        &self,
        session_id: SessionId,
        delivery: &commtools_core::GroupDeliveryStatus,
    ) -> Option<String> {
        let key = self.session_summary(session_id)?.key;
        let mut warning = None;
        for peer_b32 in &delivery.received {
            if let Err(error) =
                self.append_history_delivery(&key, delivery.message_id, Some(peer_b32))
                && warning.is_none()
            {
                warning = Some(format!("update text history delivery: {error}"));
            }
        }
        warning
    }

    fn text_author(
        &self,
        key: Option<&ManagedSessionKey>,
        sender_b32: Option<&str>,
        offline: bool,
    ) -> String {
        if offline {
            return "Peer-Offline".into();
        }
        let (Some(ManagedSessionKey::Group(group_id)), Some(sender_b32)) = (key, sender_b32) else {
            return "Peer".into();
        };
        self.vault()
            .and_then(|vault| vault.snapshot().groups.get(group_id))
            .and_then(|group| {
                group
                    .members
                    .iter()
                    .find(|member| same_b32(&member.b32, sender_b32))
            })
            .map(|member| member.name.clone())
            .unwrap_or_else(|| "Peer".into())
    }

    pub fn begin_shutdown(&mut self) -> Result<(), DriverError> {
        if self.shutdown_requested {
            return Ok(());
        }
        self.shutdown_requested = true;
        let pending = self
            .pending_contact_opens
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for contact_id in pending {
            self.start_pending_contact_shutdown(&contact_id, None)?;
        }
        let pending = self
            .pending_transient_opens
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for transient_id in pending {
            self.start_pending_transient_shutdown(&transient_id, None)?;
        }
        let pending = self.pending_group_opens.keys().cloned().collect::<Vec<_>>();
        for group_id in pending {
            self.start_pending_group_shutdown(&group_id, None)?;
        }
        self.start_coordinator_shutdown_if_ready()
    }

    pub fn start_accepting(&mut self, session_id: SessionId) -> Result<(), DriverError> {
        if !self.session_is_open(session_id) {
            return Err(DriverError::SessionNotOpen(session_id));
        }
        let resources = self.resource_mut(session_id)?;
        if resources.accepting {
            return Ok(());
        }
        resources.accepting = true;
        let runtime = resources.sam.clone();
        let connection_id = self.allocate_connection_id()?;
        let tx = self.completions_tx.clone();
        self.spawn(async move {
            let (armed_tx, mut armed_rx) = oneshot::channel();
            let mut accept = Box::pin(runtime.accept_with_armed_signal(armed_tx));
            let accept_result = tokio::select! {
                armed = &mut armed_rx => {
                    if armed.is_ok() {
                        let _ = tx.send(Completion::AcceptArmed { session_id }).await;
                    }
                    (&mut accept).await
                }
                result = &mut accept => result,
            };
            drop(accept);
            let result = accept_result.map_err(|error| error.to_string());
            if result.is_err() && !runtime.is_closing() {
                tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
            }
            let _ = tx
                .send(Completion::Accepted {
                    session_id,
                    connection_id,
                    runtime,
                    result,
                })
                .await;
        })
    }

    pub fn try_next_event(&mut self) -> Result<Option<ApplicationEvent>, DriverError> {
        if let Some(event) = self.events.pop_front() {
            return Ok(Some(event));
        }
        while let Ok(completion) = self.completions_rx.try_recv() {
            self.process_completion(completion)?;
            if let Some(event) = self.events.pop_front() {
                return Ok(Some(event));
            }
        }
        Ok(None)
    }

    pub async fn next_event(&mut self) -> Result<ApplicationEvent, DriverError> {
        loop {
            if let Some(event) = self.events.pop_front() {
                return Ok(event);
            }
            let completion = self
                .completions_rx
                .recv()
                .await
                .ok_or(DriverError::CompletionChannelClosed)?;
            self.process_completion(completion)?;
        }
    }

    fn process_output(&mut self, output: ApplicationOutput) -> Result<(), DriverError> {
        let mut actions = VecDeque::from(output.actions);
        self.record_events(output.events);
        while let Some(action) = actions.pop_front() {
            if let Some(immediate) = self.dispatch_action(action)? {
                actions.extend(immediate.actions);
                self.record_events(immediate.events);
            }
        }
        self.prune_tasks();
        Ok(())
    }

    fn process_group_protocol_event(
        &mut self,
        session_id: SessionId,
        event: GroupProtocolEvent,
    ) -> Result<(), DriverError> {
        match event {
            GroupProtocolEvent::Ready {
                peer_b32,
                authorized,
            } => self.refresh_group_control(session_id, &peer_b32, authorized),
            GroupProtocolEvent::Control { peer_b32, control } => {
                self.apply_group_control(session_id, &peer_b32, &control)
            }
            GroupProtocolEvent::Roster { peer_b32, roster } => {
                self.apply_group_roster(session_id, &peer_b32, roster)
            }
            GroupProtocolEvent::Dissolution {
                peer_b32,
                dissolution,
            } => self.apply_group_dissolution(session_id, &peer_b32, &dissolution),
        }
    }

    fn refresh_group_control(
        &mut self,
        session_id: SessionId,
        peer_b32: &str,
        authorized: bool,
    ) -> Result<(), DriverError> {
        let group_id = self
            .coordinator
            .group_id_for_session(session_id)
            .cloned()
            .ok_or(DriverError::SessionNotOpen(session_id))?;
        let group = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .groups
            .get(&group_id)
            .cloned()
            .ok_or_else(|| DriverError::GroupNotFound(group_id.clone()))?;
        if is_group_owner(&group) {
            if authorized {
                let roster = roster_sync(&group)?;
                let output = self.coordinator.send_group_roster(
                    session_id,
                    generate_message_id(),
                    &roster,
                )?;
                self.process_output(output)?;
            }
        } else if group
            .owner_b32
            .as_deref()
            .is_some_and(|owner| same_b32(owner, peer_b32))
            && let Some(control) = owner_control(&group, now_epoch_millis())?
        {
            let output = self.coordinator.send_group_control_to_owner(
                session_id,
                generate_message_id(),
                &control,
            )?;
            self.process_output(output)?;
        }
        Ok(())
    }

    fn apply_group_control(
        &mut self,
        session_id: SessionId,
        peer_b32: &str,
        control: &GroupControlMessage,
    ) -> Result<(), DriverError> {
        if !same_b32(peer_b32, &control.b32) {
            return Err(DriverError::RecordMutation(
                "group control identity does not match its authenticated connection".into(),
            ));
        }
        let group_id = self
            .coordinator
            .group_id_for_session(session_id)
            .cloned()
            .ok_or(DriverError::SessionNotOpen(session_id))?;
        let mut group = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .groups
            .get(&group_id)
            .cloned()
            .ok_or_else(|| DriverError::GroupNotFound(group_id.clone()))?;
        if !is_group_owner(&group) {
            return Err(GroupRosterError::OwnerOnly.into());
        }

        let changed = match control.kind.as_str() {
            JOIN_PROOF_CONTROL => {
                redeem_join_control(&mut group, control, now_epoch_millis())?
                    == InviteRedemption::NewlyRedeemed
            }
            RENAME_REQUEST_CONTROL => {
                if !self
                    .coordinator
                    .group_session(session_id)
                    .is_some_and(|session| session.member_is_ready(peer_b32))
                {
                    return Err(DriverError::RecordMutation(
                        "group rename request came from an unauthorized connection".into(),
                    ));
                }
                rename_member(&mut group, peer_b32, &control.name)?
            }
            LEAVE_REQUEST_CONTROL => {
                if !self
                    .coordinator
                    .group_session(session_id)
                    .is_some_and(|session| session.member_is_ready(peer_b32))
                {
                    return Err(DriverError::RecordMutation(
                        "group leave request came from an unauthorized connection".into(),
                    ));
                }
                if !remove_group_member_and_invites(&mut group, peer_b32)? {
                    return Err(GroupRosterError::UnknownMember.into());
                }
                self.persist_group_record(&group_id, group.clone())?;
                let roster = roster_sync(&group)?;
                let output = self.coordinator.send_group_roster(
                    session_id,
                    generate_message_id(),
                    &roster,
                )?;
                self.process_output(output)?;
                let output = self
                    .coordinator
                    .replace_group_roster(session_id, group.members.clone())?;
                return self.process_output(output);
            }
            _ => {
                return Err(GroupRosterError::UnsupportedControl(control.kind.clone()).into());
            }
        };
        if changed {
            self.persist_group_record(&group_id, group.clone())?;
        }
        let roster = roster_sync(&group)?;
        let output = self
            .coordinator
            .replace_group_roster(session_id, group.members.clone())?;
        self.process_output(output)?;
        let output =
            self.coordinator
                .send_group_roster(session_id, generate_message_id(), &roster)?;
        self.process_output(output)
    }

    fn apply_group_roster(
        &mut self,
        session_id: SessionId,
        peer_b32: &str,
        roster: GroupRosterSync,
    ) -> Result<(), DriverError> {
        let group_id = self
            .coordinator
            .group_id_for_session(session_id)
            .cloned()
            .ok_or(DriverError::SessionNotOpen(session_id))?;
        let mut group = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .groups
            .get(&group_id)
            .cloned()
            .ok_or_else(|| DriverError::GroupNotFound(group_id.clone()))?;
        if is_group_owner(&group) {
            return Err(DriverError::RecordMutation(
                "group owner rejected a remote roster update".into(),
            ));
        }
        let owner = group
            .owner_b32
            .as_deref()
            .ok_or(GroupRosterError::MissingOwner)?;
        if !same_b32(owner, peer_b32) || !same_b32(owner, &roster.owner_b32) {
            return Err(GroupRosterError::OwnerMismatch.into());
        }
        let outcome = apply_roster_sync(&mut group, roster)?;
        if outcome == RosterApplyOutcome::Unchanged {
            return Ok(());
        }
        self.persist_group_record(&group_id, group.clone())?;
        let output = self
            .coordinator
            .replace_group_roster(session_id, group.members.clone())?;
        self.process_output(output)?;
        if outcome == RosterApplyOutcome::LocalMemberRemoved {
            if self.pending_group_leave_requests.remove(&group_id) {
                self.groups_delete_after_close.insert(group_id.clone());
            }
            self.close_session(session_id)?;
        }
        Ok(())
    }

    fn apply_group_dissolution(
        &mut self,
        session_id: SessionId,
        peer_b32: &str,
        dissolution: &GroupDissolution,
    ) -> Result<(), DriverError> {
        let group_id = self
            .coordinator
            .group_id_for_session(session_id)
            .cloned()
            .ok_or(DriverError::SessionNotOpen(session_id))?;
        if self.groups_delete_after_close.contains(&group_id) {
            return Ok(());
        }
        let group = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .groups
            .get(&group_id)
            .cloned()
            .ok_or_else(|| DriverError::GroupNotFound(group_id.clone()))?;
        if is_group_owner(&group) {
            return Err(DriverError::RecordMutation(
                "the group owner received an unexpected dissolution control".into(),
            ));
        }
        let owner = group
            .owner_b32
            .as_deref()
            .ok_or(GroupRosterError::MissingOwner)?;
        if !same_b32(owner, peer_b32) {
            return Err(DriverError::RecordMutation(
                "group dissolution did not arrive from the authenticated owner".into(),
            ));
        }
        verify_group_dissolution(&group, dissolution)?;
        self.pending_group_leave_requests.remove(&group_id);
        self.groups_delete_after_close.insert(group_id.clone());
        if let Err(error) = self.close_session(session_id) {
            self.groups_delete_after_close.remove(&group_id);
            return Err(error);
        }
        Ok(())
    }

    fn record_events(&mut self, events: Vec<ApplicationEvent>) {
        for event in events {
            match event {
                ApplicationEvent::OneToOne {
                    session_id,
                    event:
                        commtools_core::OneToOneEvent::ApplicationFrame {
                            connection_id,
                            frame,
                        },
                } if matches!(
                    frame.message_type,
                    MessageType::F | MessageType::C | MessageType::E
                ) =>
                {
                    self.receive_contact_file_frame(session_id, connection_id, frame)
                }
                ApplicationEvent::OneToOne {
                    session_id,
                    event: commtools_core::OneToOneEvent::PhaseChanged(phase),
                } => {
                    if phase != commtools_core::OneToOnePhase::Ready {
                        self.abort_file_transfers(session_id, "secure connection ended");
                        self.pending_original_images
                            .retain(|key| key.session_id != session_id);
                        if let Some(resources) = self.resources.get_mut(&session_id) {
                            resources.incoming_image.reset();
                        }
                    }
                    self.events.push_back(ApplicationEvent::OneToOne {
                        session_id,
                        event: commtools_core::OneToOneEvent::PhaseChanged(phase),
                    });
                }
                ApplicationEvent::Group {
                    session_id,
                    event: CoreGroupSessionEvent::PeerDisconnected { peer_b32, reason },
                } => {
                    self.pending_original_images.retain(|key| {
                        key.session_id != session_id || !same_b32(&key.sender_b32, &peer_b32)
                    });
                    self.events.push_back(ApplicationEvent::Group {
                        session_id,
                        event: CoreGroupSessionEvent::PeerDisconnected { peer_b32, reason },
                    });
                }
                ApplicationEvent::SessionClosed { session_id, key } => {
                    self.abort_file_transfers(session_id, "session closed");
                    self.outgoing_contact_images
                        .retain(|(stored_session, _)| *stored_session != session_id);
                    self.outgoing_group_images
                        .retain(|(stored_session, _)| *stored_session != session_id);
                    self.shared_original_images
                        .retain(|(stored_session, _), _| *stored_session != session_id);
                    self.available_original_images
                        .retain(|key, _| key.session_id != session_id);
                    self.pending_original_images
                        .retain(|key| key.session_id != session_id);
                    self.received_original_images
                        .retain(|key, _| key.session_id != session_id);
                    self.outgoing_original_cancels.retain(|key, cancel| {
                        if key.session_id == session_id {
                            cancel.store(true, std::sync::atomic::Ordering::SeqCst);
                            false
                        } else {
                            true
                        }
                    });
                    self.resources.remove(&session_id);
                    let group_cleanup = match &key {
                        ManagedSessionKey::Group(group_id) => {
                            self.pending_group_leave_requests.remove(group_id);
                            self.groups_delete_after_close
                                .remove(group_id)
                                .then(|| group_id.clone())
                        }
                        _ => None,
                    };
                    if let Some(group_id) = group_cleanup
                        && let Err(error) = self.delete_group(&group_id)
                    {
                        self.push_failure(
                            Some(session_id),
                            "delete group after leave",
                            error.to_string(),
                        );
                    }
                    self.events
                        .push_back(ApplicationEvent::SessionClosed { session_id, key });
                }
                event => self.events.push_back(event),
            }
        }
    }

    fn receive_contact_file_frame(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        frame: Frame,
    ) {
        let opened = match self.open_contact_frame(session_id, &frame) {
            Ok(frame) => frame,
            Err(error) => {
                self.fail_incoming_file(session_id, format!("open file frame: {error}"));
                return;
            }
        };
        match opened.message_type {
            MessageType::F => self.receive_file_control(
                session_id,
                connection_id,
                opened.message_id,
                &opened.payload,
            ),
            MessageType::C => self.write_incoming_file_chunk(
                session_id,
                connection_id,
                opened.message_id,
                &opened.payload,
            ),
            MessageType::E => {
                self.finish_incoming_file(session_id, connection_id, opened.message_id)
            }
            _ => {}
        }
    }

    fn receive_file_control(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        transfer_id: u64,
        payload: &[u8],
    ) {
        let control = match FileTransferControl::decode(payload) {
            Ok(control) => control,
            Err(error) => {
                self.push_incoming_file_failure(
                    session_id,
                    transfer_id,
                    None,
                    format!("invalid file control: {error}"),
                );
                return;
            }
        };
        match control {
            FileTransferControl::Offer {
                filename,
                total_bytes,
            } => self.begin_incoming_file_offer(
                session_id,
                connection_id,
                transfer_id,
                filename,
                total_bytes,
            ),
            FileTransferControl::Accept => {
                self.start_accepted_outgoing_file(session_id, connection_id, transfer_id)
            }
            FileTransferControl::Decline => {
                self.remote_file_declined(session_id, connection_id, transfer_id)
            }
            FileTransferControl::Cancel => {
                self.remote_file_cancelled(session_id, connection_id, transfer_id)
            }
        }
    }

    fn begin_incoming_file_offer(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        transfer_id: u64,
        filename: String,
        total_bytes: u64,
    ) {
        if transfer_id == 0
            || self.incoming_file_offers.contains_key(&session_id)
            || self.incoming_files.contains_key(&session_id)
        {
            if transfer_id != 0 {
                let _ =
                    self.send_file_control(session_id, transfer_id, FileTransferControl::Decline);
            }
            self.push_incoming_file_failure(
                session_id,
                transfer_id,
                Some(filename),
                "concurrent or invalid file offer rejected".into(),
            );
            return;
        }
        self.incoming_file_offers.insert(
            session_id,
            IncomingFileOffer {
                transfer_id,
                connection_id,
                filename: filename.clone(),
                total_bytes,
                offered_ms: now_epoch_millis(),
            },
        );
        self.events.push_back(ApplicationEvent::FileTransfer {
            session_id,
            event: CoreFileTransferEvent::Offered {
                transfer_id,
                direction: CoreFileTransferDirection::Received,
                filename,
                total_bytes,
            },
        });
    }

    fn start_accepted_outgoing_file(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        transfer_id: u64,
    ) {
        let prepared = {
            let Some(transfer) = self.outgoing_files.get_mut(&session_id).filter(|transfer| {
                transfer.transfer_id == transfer_id && transfer.connection_id == connection_id
            }) else {
                return;
            };
            let (Some(file), Some(sealer)) = (transfer.file.take(), transfer.sealer.take()) else {
                return;
            };
            (
                transfer.filename.clone(),
                transfer.total_bytes,
                file,
                sealer,
            )
        };
        let (filename, total_bytes, file, sealer) = prepared;
        let result = self.send_job(
            session_id,
            connection_id,
            SendJob::File {
                transfer_id,
                filename: filename.clone(),
                total_bytes,
                file,
                sealer,
            },
        );
        match result {
            Ok(()) => self.events.push_back(ApplicationEvent::FileTransfer {
                session_id,
                event: CoreFileTransferEvent::Started {
                    transfer_id,
                    direction: CoreFileTransferDirection::Sent,
                    filename,
                    total_bytes,
                },
            }),
            Err(error) => {
                self.outgoing_files.remove(&session_id);
                self.push_outgoing_file_failure(
                    session_id,
                    transfer_id,
                    filename,
                    error.to_string(),
                );
                if matches!(error, DriverError::SendWorkerClosed { .. }) {
                    let _ = self.finalize_connection_closed(session_id, connection_id);
                }
            }
        }
    }

    fn remote_file_declined(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        transfer_id: u64,
    ) {
        let Some(transfer) = self.outgoing_files.get(&session_id).filter(|transfer| {
            transfer.transfer_id == transfer_id && transfer.connection_id == connection_id
        }) else {
            return;
        };
        let filename = transfer.filename.clone();
        let sending = transfer.file.is_none();
        self.outgoing_files.remove(&session_id);
        if sending {
            let _ = self.send_job(
                session_id,
                connection_id,
                SendJob::CancelFile { transfer_id },
            );
        }
        self.push_file_terminal_event(
            session_id,
            transfer_id,
            CoreFileTransferDirection::Sent,
            filename,
            FileTerminalState::Declined,
        );
    }

    fn remote_file_cancelled(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        transfer_id: u64,
    ) {
        if let Some(transfer) = self.outgoing_files.get(&session_id).filter(|transfer| {
            transfer.transfer_id == transfer_id && transfer.connection_id == connection_id
        }) {
            let filename = transfer.filename.clone();
            let sending = transfer.file.is_none();
            self.outgoing_files.remove(&session_id);
            if sending {
                let _ = self.send_job(
                    session_id,
                    connection_id,
                    SendJob::CancelFile { transfer_id },
                );
            }
            self.push_file_terminal_event(
                session_id,
                transfer_id,
                CoreFileTransferDirection::Sent,
                filename,
                FileTerminalState::Cancelled,
            );
            return;
        }
        if let Some(offer) = self.incoming_file_offers.get(&session_id).filter(|offer| {
            offer.transfer_id == transfer_id && offer.connection_id == connection_id
        }) {
            let filename = offer.filename.clone();
            self.incoming_file_offers.remove(&session_id);
            self.push_file_terminal_event(
                session_id,
                transfer_id,
                CoreFileTransferDirection::Received,
                filename,
                FileTerminalState::Cancelled,
            );
            return;
        }
        if let Some(transfer) = self.incoming_files.get(&session_id).filter(|transfer| {
            transfer.transfer_id == transfer_id && transfer.connection_id == connection_id
        }) {
            let filename = transfer.filename.clone();
            self.remove_incoming_file(session_id);
            self.push_file_terminal_event(
                session_id,
                transfer_id,
                CoreFileTransferDirection::Received,
                filename,
                FileTerminalState::Cancelled,
            );
        }
    }

    fn write_incoming_file_chunk(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        transfer_id: u64,
        payload: &[u8],
    ) {
        let chunk = match BASE64.decode(payload) {
            Ok(chunk) if !chunk.is_empty() && chunk.len() <= FILE_TRANSFER_CHUNK_BYTES => chunk,
            Ok(_) => {
                self.fail_incoming_file(session_id, "invalid file chunk size".into());
                return;
            }
            Err(error) => {
                self.fail_incoming_file(session_id, format!("invalid Base64 file chunk: {error}"));
                return;
            }
        };
        let mut progress = None;
        let failure = match self.incoming_files.get_mut(&session_id) {
            Some(transfer)
                if transfer.connection_id == connection_id
                    && transfer.transfer_id == transfer_id =>
            {
                let next = transfer.received_bytes.saturating_add(chunk.len() as u64);
                if next > transfer.expected_bytes {
                    Some("file transfer exceeded its declared size".to_string())
                } else if let Err(error) = transfer.file.write_all(&chunk) {
                    Some(format!("write received file: {error}"))
                } else {
                    transfer.received_bytes = next;
                    if next == transfer.expected_bytes
                        || next.saturating_sub(transfer.last_reported_bytes)
                            >= FILE_PROGRESS_STEP_BYTES
                    {
                        transfer.last_reported_bytes = next;
                        progress = Some((transfer.transfer_id, next, transfer.expected_bytes));
                    }
                    None
                }
            }
            Some(_) => Some("file chunk arrived on the wrong connection".to_string()),
            None => Some("file chunk arrived without a file header".to_string()),
        };
        if let Some(reason) = failure {
            self.fail_incoming_file(session_id, reason);
        } else if let Some((transfer_id, transferred_bytes, total_bytes)) = progress {
            self.events.push_back(ApplicationEvent::FileTransfer {
                session_id,
                event: CoreFileTransferEvent::Progress {
                    transfer_id,
                    direction: CoreFileTransferDirection::Received,
                    transferred_bytes,
                    total_bytes,
                },
            });
        }
    }

    fn finish_incoming_file(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        transfer_id: u64,
    ) {
        let Some(mut transfer) = self.incoming_files.remove(&session_id) else {
            self.push_incoming_file_failure(
                session_id,
                0,
                None,
                "file terminator arrived without a file header".into(),
            );
            return;
        };
        let validation =
            if transfer.connection_id != connection_id || transfer.transfer_id != transfer_id {
                Err("file terminator arrived on the wrong connection".to_string())
            } else if transfer.received_bytes != transfer.expected_bytes {
                Err(format!(
                    "incomplete file: expected {} bytes, received {}",
                    transfer.expected_bytes, transfer.received_bytes
                ))
            } else {
                transfer
                    .file
                    .flush()
                    .and_then(|_| transfer.file.sync_all())
                    .map_err(|error| format!("flush received file: {error}"))
            };
        drop(transfer.file);
        let result = validation.and_then(|_| {
            fs::rename(&transfer.temporary_path, &transfer.final_path)
                .map_err(|error| format!("publish received file: {error}"))
        });
        match result {
            Ok(()) => self.events.push_back(ApplicationEvent::FileTransfer {
                session_id,
                event: CoreFileTransferEvent::Completed {
                    transfer_id: transfer.transfer_id,
                    direction: CoreFileTransferDirection::Received,
                    filename: transfer.filename,
                    total_bytes: transfer.expected_bytes,
                    path: Some(transfer.final_path),
                },
            }),
            Err(reason) => {
                let _ = fs::remove_file(&transfer.temporary_path);
                self.push_incoming_file_failure(
                    session_id,
                    transfer.transfer_id,
                    Some(transfer.filename),
                    reason,
                );
            }
        }
    }

    fn abort_incoming_file(&mut self, session_id: SessionId, reason: &str) {
        let Some(transfer) = self.incoming_files.remove(&session_id) else {
            return;
        };
        let temporary_path = transfer.temporary_path.clone();
        drop(transfer.file);
        let _ = fs::remove_file(&temporary_path);
        self.push_incoming_file_failure(
            session_id,
            transfer.transfer_id,
            Some(transfer.filename),
            reason.into(),
        );
    }

    fn remove_incoming_file(&mut self, session_id: SessionId) {
        let Some(transfer) = self.incoming_files.remove(&session_id) else {
            return;
        };
        let temporary_path = transfer.temporary_path.clone();
        drop(transfer.file);
        let _ = fs::remove_file(temporary_path);
    }

    fn abort_file_transfers(&mut self, session_id: SessionId, reason: &str) {
        if let Some(offer) = self.incoming_file_offers.remove(&session_id) {
            self.push_incoming_file_failure(
                session_id,
                offer.transfer_id,
                Some(offer.filename),
                reason.into(),
            );
        }
        self.abort_incoming_file(session_id, reason);
        if let Some(transfer) = self.outgoing_files.remove(&session_id) {
            if transfer.file.is_none() {
                let _ = self.send_job(
                    session_id,
                    transfer.connection_id,
                    SendJob::CancelFile {
                        transfer_id: transfer.transfer_id,
                    },
                );
            }
            self.push_outgoing_file_failure(
                session_id,
                transfer.transfer_id,
                transfer.filename,
                reason.into(),
            );
        }
    }

    fn expire_outgoing_file_offer(&mut self, session_id: SessionId, transfer_id: u64) {
        let matches = self
            .outgoing_files
            .get(&session_id)
            .is_some_and(|transfer| transfer.transfer_id == transfer_id && transfer.file.is_some());
        if !matches {
            return;
        }
        let transfer = self
            .outgoing_files
            .remove(&session_id)
            .expect("matching outgoing file offer was checked");
        let _ = self.send_file_control(session_id, transfer_id, FileTransferControl::Cancel);
        self.push_file_terminal_event(
            session_id,
            transfer_id,
            CoreFileTransferDirection::Sent,
            transfer.filename,
            FileTerminalState::Expired,
        );
    }

    fn expire_incoming_file_offer(&mut self, session_id: SessionId, transfer_id: u64) {
        let matches = self
            .incoming_file_offers
            .get(&session_id)
            .is_some_and(|offer| offer.transfer_id == transfer_id);
        if !matches {
            return;
        }
        let offer = self
            .incoming_file_offers
            .remove(&session_id)
            .expect("matching incoming file offer was checked");
        let _ = self.send_file_control(session_id, transfer_id, FileTransferControl::Decline);
        self.push_file_terminal_event(
            session_id,
            transfer_id,
            CoreFileTransferDirection::Received,
            offer.filename,
            FileTerminalState::Expired,
        );
    }

    fn push_outgoing_file_failure(
        &mut self,
        session_id: SessionId,
        transfer_id: u64,
        filename: String,
        reason: String,
    ) {
        self.events.push_back(ApplicationEvent::FileTransfer {
            session_id,
            event: CoreFileTransferEvent::Failed {
                transfer_id,
                direction: CoreFileTransferDirection::Sent,
                filename: Some(filename),
                reason,
            },
        });
    }

    fn push_file_terminal_event(
        &mut self,
        session_id: SessionId,
        transfer_id: u64,
        direction: CoreFileTransferDirection,
        filename: String,
        state: FileTerminalState,
    ) {
        let event = match state {
            FileTerminalState::Declined => CoreFileTransferEvent::Declined {
                transfer_id,
                direction,
                filename,
            },
            FileTerminalState::Cancelled => CoreFileTransferEvent::Cancelled {
                transfer_id,
                direction,
                filename,
            },
            FileTerminalState::Expired => CoreFileTransferEvent::Expired {
                transfer_id,
                direction,
                filename,
            },
        };
        self.events
            .push_back(ApplicationEvent::FileTransfer { session_id, event });
    }

    fn fail_incoming_file(&mut self, session_id: SessionId, reason: String) {
        if let Some(transfer) = self.incoming_files.remove(&session_id) {
            let temporary_path = transfer.temporary_path.clone();
            drop(transfer.file);
            let _ = fs::remove_file(&temporary_path);
            self.push_incoming_file_failure(
                session_id,
                transfer.transfer_id,
                Some(transfer.filename),
                reason,
            );
        } else {
            self.push_incoming_file_failure(session_id, 0, None, reason);
        }
    }

    fn push_incoming_file_failure(
        &mut self,
        session_id: SessionId,
        transfer_id: u64,
        filename: Option<String>,
        reason: String,
    ) {
        self.events.push_back(ApplicationEvent::FileTransfer {
            session_id,
            event: CoreFileTransferEvent::Failed {
                transfer_id,
                direction: CoreFileTransferDirection::Received,
                filename,
                reason,
            },
        });
    }

    fn dispatch_action(
        &mut self,
        action: ApplicationAction,
    ) -> Result<Option<ApplicationOutput>, DriverError> {
        match action {
            ApplicationAction::OneToOne { session_id, action } => {
                self.dispatch_one_to_one(session_id, action)?;
                Ok(None)
            }
            ApplicationAction::Group { session_id, action } => {
                self.dispatch_group(session_id, action)?;
                Ok(None)
            }
            ApplicationAction::Offline { session_id, action } => {
                self.dispatch_offline(session_id, action)?;
                Ok(None)
            }
            ApplicationAction::PersistContactOffline {
                session_id,
                contact_id,
                mutation_id,
                state,
            } => {
                let result = self.persist_contact_offline(&contact_id, state);
                Ok(Some(self.coordinator.offline_persistence_completed(
                    session_id,
                    mutation_id,
                    result,
                )?))
            }
            ApplicationAction::PersistContactOfflineEnrollment {
                session_id,
                contact_id,
                enrollment_id,
                state,
            } => {
                let result = self.persist_contact_offline(&contact_id, state);
                Ok(Some(
                    self.coordinator.offline_enrollment_persistence_completed(
                        session_id,
                        enrollment_id,
                        result,
                    )?,
                ))
            }
            ApplicationAction::ShutdownSam { session_id } => {
                let runtime = self.resource(session_id)?.sam.clone();
                let tx = self.completions_tx.clone();
                self.spawn(async move {
                    let result = runtime.shutdown().await.map_err(|error| error.to_string());
                    let _ = tx
                        .send(Completion::SamShutdown { session_id, result })
                        .await;
                })?;
                Ok(None)
            }
            ApplicationAction::LockVault => {
                let result = self
                    .vault
                    .as_mut()
                    .ok_or_else(|| "unlocked vault is unavailable".to_string())
                    .and_then(|vault| vault.lock().map_err(|error| error.to_string()));
                if result.is_ok() {
                    self.vault.take();
                }
                Ok(Some(self.coordinator.vault_lock_completed(result)?))
            }
        }
    }

    fn dispatch_one_to_one(
        &mut self,
        session_id: SessionId,
        action: OneToOneAction,
    ) -> Result<(), DriverError> {
        match action {
            OneToOneAction::Connect {
                attempt_id,
                peer_b32,
            } => {
                let runtime = self.resource_one_to_one(session_id)?.sam.clone();
                let connection_id = self.allocate_connection_id()?;
                let tx = self.completions_tx.clone();
                self.spawn(async move {
                    let result = runtime
                        .connect(&peer_b32)
                        .await
                        .map_err(|error| error.to_string());
                    let _ = tx
                        .send(Completion::ContactConnected {
                            session_id,
                            attempt_id,
                            connection_id,
                            peer_b32,
                            runtime,
                            result,
                        })
                        .await;
                })
            }
            OneToOneAction::CancelConnect { .. } => Ok(()),
            OneToOneAction::SendHandshake {
                connection_id,
                destination_prelude,
                frames,
            } => self.schedule_send_sequence(
                session_id,
                connection_id,
                destination_prelude,
                frames,
                "send 1:1 handshake",
            ),
            OneToOneAction::SendFrame {
                connection_id,
                frame,
            } => self.schedule_send_frame(
                session_id,
                connection_id,
                frame,
                SendCompletion::None,
                "send 1:1 frame",
            ),
            OneToOneAction::CloseConnection { connection_id } => {
                self.schedule_close(session_id, connection_id, None)
            }
            OneToOneAction::NotifyAndClose {
                connection_id,
                frame,
                delay_ms,
            } => self.schedule_notify_and_close(
                session_id,
                connection_id,
                frame,
                delay_ms,
                "notify and close 1:1 connection",
            ),
        }
    }

    fn dispatch_group(
        &mut self,
        session_id: SessionId,
        action: GroupSessionAction,
    ) -> Result<(), DriverError> {
        match action {
            GroupSessionAction::Connect {
                attempt_id,
                peer_b32,
            } => {
                let runtime = self
                    .resource_of_kind(session_id, ResourceKind::Group)?
                    .sam
                    .clone();
                let connection_id = self.allocate_connection_id()?;
                let tx = self.completions_tx.clone();
                self.spawn(async move {
                    let result = runtime
                        .connect(&peer_b32)
                        .await
                        .map_err(|error| error.to_string());
                    let _ = tx
                        .send(Completion::GroupConnected {
                            session_id,
                            attempt_id,
                            connection_id,
                            peer_b32,
                            runtime,
                            result,
                        })
                        .await;
                })
            }
            GroupSessionAction::CancelConnect { .. } => Ok(()),
            GroupSessionAction::SendHandshake {
                connection_id,
                destination_prelude,
                frames,
            } => self.schedule_send_sequence(
                session_id,
                connection_id,
                Some(destination_prelude),
                frames,
                "send group handshake",
            ),
            GroupSessionAction::SendFrame {
                connection_id,
                frame,
            } => self.schedule_send_frame(
                session_id,
                connection_id,
                frame,
                SendCompletion::None,
                "send group frame",
            ),
            GroupSessionAction::SendFrames {
                connection_id,
                frames,
            } => self.schedule_image_sequence(
                session_id,
                connection_id,
                frames,
                "send group frame sequence",
            ),
            GroupSessionAction::SendOriginalImage {
                connection_id,
                peer_b32,
                media_id,
                frames,
            } => {
                let key = OriginalImageKey {
                    session_id,
                    media_id,
                    sender_b32: peer_b32.to_ascii_lowercase(),
                };
                let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                self.outgoing_original_cancels
                    .insert(key.clone(), cancel.clone());
                self.schedule_original_image_sequence(
                    session_id,
                    connection_id,
                    frames,
                    cancel,
                    key,
                    "send requested group original image",
                )
            }
            GroupSessionAction::CloseConnection { connection_id } => {
                self.schedule_close(session_id, connection_id, None)
            }
            GroupSessionAction::NotifyAndClose {
                connection_id,
                frame,
                delay_ms,
            } => self.schedule_notify_and_close(
                session_id,
                connection_id,
                frame,
                delay_ms,
                "notify and close group connection",
            ),
        }
    }

    fn dispatch_offline(
        &mut self,
        session_id: SessionId,
        action: OfflineCoordinatorAction,
    ) -> Result<(), DriverError> {
        match action {
            OfflineCoordinatorAction::Put {
                operation_id,
                target,
            } => {
                let client = self.deaddrop(session_id)?;
                let servers = self.deaddrop_operation_servers(session_id)?;
                let tx = self.completions_tx.clone();
                self.spawn(async move {
                    let result = client
                        .put_to_servers(&target.key, &target.blob, &servers)
                        .await
                        .map_err(|error| error.to_string());
                    let _ = tx
                        .send(Completion::OfflinePut {
                            session_id,
                            operation_id,
                            result,
                        })
                        .await;
                })
            }
            OfflineCoordinatorAction::Get {
                operation_id,
                target,
            } => {
                let client = self.deaddrop(session_id)?;
                let servers = self.deaddrop_operation_servers(session_id)?;
                let tx = self.completions_tx.clone();
                self.spawn(async move {
                    let result = client
                        .get_from_servers(&target.key, &servers)
                        .await
                        .map_err(|error| error.to_string());
                    let _ = tx
                        .send(Completion::OfflineGet {
                            session_id,
                            operation_id,
                            result,
                        })
                        .await;
                })
            }
            OfflineCoordinatorAction::SendIndexSync {
                connection_id,
                frame,
            } => self.schedule_send_frame(
                session_id,
                connection_id,
                frame,
                SendCompletion::OfflineIndexSync,
                "send offline index sync",
            ),
            OfflineCoordinatorAction::PersistState { .. } => {
                Err(DriverError::UnexpectedOfflinePersistenceAction)
            }
            OfflineCoordinatorAction::ShutdownDeaddrop => {
                let client = self.deaddrop(session_id)?;
                let tx = self.completions_tx.clone();
                self.spawn(async move {
                    let result = client.shutdown().await.map_err(|error| error.to_string());
                    let _ = tx
                        .send(Completion::DeaddropShutdown { session_id, result })
                        .await;
                })
            }
        }
    }

    fn schedule_send_sequence(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        destination_prelude: Option<String>,
        frames: Vec<Frame>,
        operation: &'static str,
    ) -> Result<(), DriverError> {
        self.send_connection_job(
            session_id,
            connection_id,
            SendJob::Sequence {
                destination_prelude,
                frames,
                completion: SendCompletion::None,
                operation,
            },
            operation,
        )
    }

    fn schedule_image_sequence(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        frames: Vec<Frame>,
        operation: &'static str,
    ) -> Result<(), DriverError> {
        self.send_connection_job(
            session_id,
            connection_id,
            SendJob::ImageSequence {
                frames,
                cancel: None,
                completion: SendCompletion::None,
                operation,
            },
            operation,
        )
    }

    fn schedule_original_image_sequence(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        frames: Vec<Frame>,
        cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
        key: OriginalImageKey,
        operation: &'static str,
    ) -> Result<(), DriverError> {
        self.send_connection_job(
            session_id,
            connection_id,
            SendJob::ImageSequence {
                frames,
                cancel: Some(cancel.clone()),
                completion: SendCompletion::OriginalImage { key, cancel },
                operation,
            },
            operation,
        )
    }

    fn schedule_send_frame(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        frame: Frame,
        completion: SendCompletion,
        operation: &'static str,
    ) -> Result<(), DriverError> {
        self.send_connection_job(
            session_id,
            connection_id,
            SendJob::Sequence {
                destination_prelude: None,
                frames: vec![frame],
                completion,
                operation,
            },
            operation,
        )
    }

    fn schedule_notify_and_close(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        frame: Frame,
        delay_ms: u64,
        operation: &'static str,
    ) -> Result<(), DriverError> {
        self.ensure_connection(session_id, connection_id)?;
        if !self.mark_connection_closing(session_id, connection_id)? {
            return Ok(());
        }
        self.send_close_job(
            session_id,
            connection_id,
            SendJob::NotifyAndClose {
                frame,
                delay_ms,
                operation,
            },
        )
    }

    fn schedule_close(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        operation: Option<&'static str>,
    ) -> Result<(), DriverError> {
        self.ensure_connection(session_id, connection_id)?;
        if !self.mark_connection_closing(session_id, connection_id)? {
            return Ok(());
        }
        self.send_close_job(session_id, connection_id, SendJob::Close { operation })
    }

    fn start_receiver(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        connection: LiveConnection,
    ) -> Result<(), DriverError> {
        let tx = self.completions_tx.clone();
        self.spawn(async move {
            loop {
                match connection.recv_frame().await {
                    Ok(frame) => {
                        if tx
                            .send(Completion::FrameReceived {
                                session_id,
                                connection_id,
                                frame,
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = tx
                            .send(Completion::TransportEnded {
                                session_id,
                                connection_id,
                            })
                            .await;
                        break;
                    }
                }
            }
        })
    }

    fn process_completion(&mut self, completion: Completion) -> Result<(), DriverError> {
        match completion {
            Completion::SamTestFinished { result } => {
                self.sam_test_status = match result {
                    Ok(()) => SamTestStatus::Succeeded,
                    Err(error) => SamTestStatus::Failed(error),
                };
            }
            Completion::SamLivenessProbeFinished {
                generation,
                completed_ms,
                result,
            } => {
                if generation == self.sam_monitor_generation && self.sam_monitor_probe_running {
                    self.apply_sam_liveness_result(result, completed_ms)?;
                }
            }
            Completion::ContactBootstrapFinished { contact_id, result } => {
                self.contact_bootstrap_finished(contact_id, result)?;
            }
            Completion::PendingContactShutdown { contact_id, result } => {
                self.pending_contact_shutdown_finished(contact_id, result)?;
            }
            Completion::TransientBootstrapFinished {
                transient_id,
                result,
            } => self.transient_bootstrap_finished(transient_id, result)?,
            Completion::PendingTransientShutdown {
                transient_id,
                result,
            } => self.pending_transient_shutdown_finished(transient_id, result)?,
            Completion::GroupBootstrapFinished { group_id, result } => {
                self.group_bootstrap_finished(group_id, result)?;
            }
            Completion::PendingGroupShutdown { group_id, result } => {
                self.pending_group_shutdown_finished(group_id, result)?;
            }
            Completion::ContactConnected {
                session_id,
                attempt_id,
                connection_id,
                peer_b32,
                runtime,
                result,
            } => match result {
                Ok(connection) => self.install_outbound_connection(
                    session_id,
                    connection_id,
                    runtime,
                    connection,
                    |coordinator| {
                        coordinator.contact_outbound_connected(
                            session_id,
                            attempt_id,
                            connection_id,
                            &peer_b32,
                            now_epoch_millis(),
                        )
                    },
                )?,
                Err(reason) => {
                    if !self.resources.contains_key(&session_id) {
                        return Ok(());
                    }
                    let output = self.coordinator.contact_outbound_failed_at(
                        session_id,
                        attempt_id,
                        reason,
                        now_epoch_millis(),
                    )?;
                    self.process_output(output)?;
                }
            },
            Completion::GroupConnected {
                session_id,
                attempt_id,
                connection_id,
                peer_b32,
                runtime,
                result,
            } => match result {
                Ok(connection) => self.install_outbound_connection(
                    session_id,
                    connection_id,
                    runtime,
                    connection,
                    |coordinator| {
                        coordinator.group_outbound_connected(
                            session_id,
                            &peer_b32,
                            attempt_id,
                            connection_id,
                            now_epoch_millis(),
                        )
                    },
                )?,
                Err(reason) => {
                    if !self.resources.contains_key(&session_id) {
                        return Ok(());
                    }
                    let output = self
                        .coordinator
                        .group_outbound_failed(session_id, &peer_b32, attempt_id, reason)?;
                    self.process_output(output)?;
                }
            },
            Completion::Accepted {
                session_id,
                connection_id,
                runtime,
                result,
            } => {
                if let Some(resources) = self.resources.get_mut(&session_id) {
                    resources.accepting = false;
                }
                match result {
                    Ok(incoming) => {
                        if self.resources.contains_key(&session_id) {
                            self.events.push_back(ApplicationEvent::OperationRecovered {
                                session_id,
                                operation: "accept SAM stream",
                            });
                        }
                        self.install_incoming_connection(
                            session_id,
                            connection_id,
                            runtime,
                            incoming,
                        )?;
                    }
                    Err(reason) => {
                        if self.resources.contains_key(&session_id) {
                            self.push_failure(Some(session_id), "accept SAM stream", reason);
                        }
                    }
                }
                if self.session_is_open(session_id) && self.resources.contains_key(&session_id) {
                    self.start_accepting(session_id)?;
                }
            }
            Completion::AcceptArmed { session_id } => {
                if self.session_is_open(session_id) && self.resources.contains_key(&session_id) {
                    self.events.push_back(ApplicationEvent::OperationRecovered {
                        session_id,
                        operation: "accept SAM stream",
                    });
                }
            }
            Completion::FrameReceived {
                session_id,
                connection_id,
                frame,
            } => {
                let Some(kind) = self
                    .resources
                    .get(&session_id)
                    .map(|resource| resource.kind)
                else {
                    return Ok(());
                };
                if kind == ResourceKind::Group
                    && (!self.connection_exists(session_id, connection_id)
                        || self.connection_is_closing(session_id, connection_id))
                {
                    return Ok(());
                }
                let now_ms = now_epoch_millis();
                let output = match kind {
                    ResourceKind::Contact | ResourceKind::Transient => self
                        .coordinator
                        .receive_contact_frame(session_id, connection_id, frame, now_ms)?,
                    ResourceKind::Group => self.coordinator.receive_group_frame(
                        session_id,
                        connection_id,
                        frame,
                        now_ms,
                    )?,
                };
                let group_events = if kind == ResourceKind::Group {
                    collect_group_protocol_events(&output.events)
                } else {
                    Vec::new()
                };
                self.process_output(output)?;
                for event in group_events {
                    if let Err(error) = self.process_group_protocol_event(session_id, event) {
                        self.push_failure(
                            Some(session_id),
                            "process encrypted group control",
                            error.to_string(),
                        );
                    }
                }
            }
            Completion::SendFinished {
                session_id,
                connection_id,
                completion,
                operation,
                result,
            } => {
                if !self.resources.contains_key(&session_id) {
                    return Ok(());
                }
                let offline_index_sync = matches!(&completion, SendCompletion::OfflineIndexSync);
                if let SendCompletion::OriginalImage { key, cancel } = &completion
                    && self
                        .outgoing_original_cancels
                        .get(key)
                        .is_some_and(|active| std::sync::Arc::ptr_eq(active, cancel))
                {
                    self.outgoing_original_cancels.remove(key);
                }
                match result {
                    Ok(SendOutcome::Completed) => {
                        if offline_index_sync {
                            let output = self
                                .coordinator
                                .offline_index_sync_sent(session_id, connection_id)?;
                            self.process_output(output)?;
                        }
                    }
                    Ok(SendOutcome::Cancelled) => {}
                    Err(reason) => {
                        if offline_index_sync {
                            let output = self.coordinator.offline_index_sync_send_failed(
                                session_id,
                                connection_id,
                                reason.clone(),
                            )?;
                            self.process_output(output)?;
                        }
                        self.push_failure(Some(session_id), operation, reason);
                    }
                }
            }
            Completion::FileProgress {
                session_id,
                transfer_id,
                transferred_bytes,
                total_bytes,
            } => {
                if self
                    .outgoing_files
                    .get(&session_id)
                    .is_some_and(|transfer| transfer.transfer_id == transfer_id)
                {
                    self.events.push_back(ApplicationEvent::FileTransfer {
                        session_id,
                        event: CoreFileTransferEvent::Progress {
                            transfer_id,
                            direction: CoreFileTransferDirection::Sent,
                            transferred_bytes,
                            total_bytes,
                        },
                    });
                }
            }
            Completion::FileFinished {
                session_id,
                transfer_id,
                filename,
                total_bytes,
                result,
            } => {
                if !self
                    .outgoing_files
                    .get(&session_id)
                    .is_some_and(|transfer| transfer.transfer_id == transfer_id)
                {
                    return Ok(());
                }
                self.outgoing_files.remove(&session_id);
                let event = match result {
                    Ok(()) => CoreFileTransferEvent::Completed {
                        transfer_id,
                        direction: CoreFileTransferDirection::Sent,
                        filename,
                        total_bytes,
                        path: None,
                    },
                    Err(reason) => CoreFileTransferEvent::Failed {
                        transfer_id,
                        direction: CoreFileTransferDirection::Sent,
                        filename: Some(filename),
                        reason,
                    },
                };
                self.events
                    .push_back(ApplicationEvent::FileTransfer { session_id, event });
            }
            Completion::ConnectionClosed {
                session_id,
                connection_id,
                operation,
                result,
            } => {
                if let Err(reason) = result
                    && let Some(operation) = operation
                {
                    self.push_failure(Some(session_id), operation, reason);
                }
                self.finalize_connection_closed(session_id, connection_id)?;
            }
            Completion::TransportEnded {
                session_id,
                connection_id,
            } => {
                if self.connection_exists(session_id, connection_id)
                    && !self.connection_is_closing(session_id, connection_id)
                {
                    self.schedule_close(session_id, connection_id, None)?;
                }
            }
            Completion::OfflinePut {
                session_id,
                operation_id,
                result,
            } => {
                if !self.resources.contains_key(&session_id) {
                    return Ok(());
                }
                if self
                    .coordinator
                    .offline_coordinator(session_id)
                    .is_some_and(|offline| {
                        matches!(
                            offline.mode(),
                            OfflineCoordinatorMode::Closing | OfflineCoordinatorMode::Closed
                        )
                    })
                {
                    return Ok(());
                }
                let now_ms = now_epoch_millis();
                if let Ok(result) = &result
                    && let Err(error) = self.record_deaddrop_put(session_id, result, now_ms)
                {
                    self.push_failure(
                        Some(session_id),
                        "record deaddrop PUT profile",
                        error.to_string(),
                    );
                }
                let output = match result {
                    Ok(result) => self.coordinator.offline_put_completed(
                        session_id,
                        operation_id,
                        result,
                        now_ms,
                    )?,
                    Err(reason) => self.coordinator.offline_put_failed(
                        session_id,
                        operation_id,
                        reason,
                        now_ms,
                    )?,
                };
                self.process_output(output)?;
            }
            Completion::OfflineGet {
                session_id,
                operation_id,
                result,
            } => {
                if !self.resources.contains_key(&session_id) {
                    return Ok(());
                }
                if self
                    .coordinator
                    .offline_coordinator(session_id)
                    .is_some_and(|offline| {
                        matches!(
                            offline.mode(),
                            OfflineCoordinatorMode::Closing | OfflineCoordinatorMode::Closed
                        )
                    })
                {
                    return Ok(());
                }
                let now_ms = now_epoch_millis();
                if let Ok(result) = &result
                    && let Err(error) = self.record_deaddrop_get(session_id, result, now_ms)
                {
                    self.push_failure(
                        Some(session_id),
                        "record deaddrop GET profile",
                        error.to_string(),
                    );
                }
                let output = match result {
                    Ok(result) => self.coordinator.offline_get_completed(
                        session_id,
                        operation_id,
                        result,
                        now_ms,
                    )?,
                    Err(reason) => self.coordinator.offline_get_failed(
                        session_id,
                        operation_id,
                        reason,
                        now_ms,
                    )?,
                };
                self.process_output(output)?;
            }
            Completion::SamShutdown { session_id, result } => {
                if self.resources.contains_key(&session_id) {
                    let output = self
                        .coordinator
                        .sam_shutdown_completed(session_id, result)?;
                    self.process_output(output)?;
                }
            }
            Completion::DeaddropShutdown { session_id, result } => {
                if self.resources.contains_key(&session_id) {
                    if let Err(error) = self.flush_deaddrop_stats(true, now_epoch_millis()) {
                        self.push_failure(
                            Some(session_id),
                            "save deaddrop profiles during close",
                            error.to_string(),
                        );
                    }
                    let output = self
                        .coordinator
                        .deaddrop_shutdown_completed(session_id, result)?;
                    self.process_output(output)?;
                }
            }
        }
        self.prune_tasks();
        Ok(())
    }

    fn contact_bootstrap_finished(
        &mut self,
        contact_id: ContactId,
        result: Result<PreparedContact, String>,
    ) -> Result<(), DriverError> {
        if !self.pending_contact_opens.contains_key(&contact_id) {
            return Ok(());
        }
        if self.shutdown_requested {
            return Ok(());
        }
        let prepared = match result {
            Ok(prepared) => prepared,
            Err(reason) => {
                self.pending_contact_opens.remove(&contact_id);
                self.events.push_back(ApplicationEvent::SessionOpenFailed {
                    key: ManagedSessionKey::Contact(contact_id),
                    reason,
                });
                return Ok(());
            }
        };

        if let Some(identity) = prepared.identity.clone()
            && let Err(error) = self.persist_contact_identity(&contact_id, identity)
        {
            self.start_pending_contact_shutdown(&contact_id, Some(error.to_string()))?;
            return Ok(());
        }

        let runtime = self
            .pending_contact_opens
            .get(&contact_id)
            .ok_or_else(|| DriverError::ContactOpenPending(contact_id.clone()))?
            .runtime
            .clone();
        let transport = SessionTransport {
            runtime,
            info: prepared.info,
        };
        let session_id = match self.open_contact_with_staged_offline(
            contact_id.clone(),
            prepared.session,
            prepared.offline,
            prepared.staged_offline,
            transport,
            prepared.deaddrop,
        ) {
            Ok(session_id) => session_id,
            Err(error) => {
                self.start_pending_contact_shutdown(&contact_id, Some(error.to_string()))?;
                return Ok(());
            }
        };
        self.pending_contact_opens.remove(&contact_id);
        if let Err(error) = self.start_accepting(session_id) {
            self.push_failure(
                Some(session_id),
                "start incoming contact accept loop",
                error.to_string(),
            );
            self.close_session(session_id)?;
        }
        Ok(())
    }

    fn transient_bootstrap_finished(
        &mut self,
        transient_id: TransientId,
        result: Result<PreparedTransient, String>,
    ) -> Result<(), DriverError> {
        if !self.pending_transient_opens.contains_key(&transient_id) || self.shutdown_requested {
            return Ok(());
        }
        let prepared = match result {
            Ok(prepared) => prepared,
            Err(reason) => {
                self.pending_transient_opens.remove(&transient_id);
                self.events.push_back(ApplicationEvent::SessionOpenFailed {
                    key: ManagedSessionKey::Transient(transient_id),
                    reason,
                });
                return Ok(());
            }
        };
        let runtime = self
            .pending_transient_opens
            .get(&transient_id)
            .ok_or_else(|| DriverError::TransientOpenPending(transient_id.clone()))?
            .runtime
            .clone();
        let transport = SessionTransport {
            runtime,
            info: prepared.info,
        };
        let session_id =
            match self.open_transient(transient_id.clone(), prepared.session, transport) {
                Ok(session_id) => session_id,
                Err(error) => {
                    self.start_pending_transient_shutdown(&transient_id, Some(error.to_string()))?;
                    return Ok(());
                }
            };
        self.pending_transient_opens.remove(&transient_id);
        if let Err(error) = self.start_accepting(session_id) {
            self.push_failure(
                Some(session_id),
                "start incoming transient accept loop",
                error.to_string(),
            );
            self.close_session(session_id)?;
        }
        Ok(())
    }

    fn group_bootstrap_finished(
        &mut self,
        group_id: GroupId,
        result: Result<PreparedGroup, String>,
    ) -> Result<(), DriverError> {
        if !self.pending_group_opens.contains_key(&group_id) {
            return Ok(());
        }
        if self.shutdown_requested {
            return Ok(());
        }
        let prepared = match result {
            Ok(prepared) => prepared,
            Err(reason) => {
                self.pending_group_opens.remove(&group_id);
                self.events.push_back(ApplicationEvent::SessionOpenFailed {
                    key: ManagedSessionKey::Group(group_id),
                    reason,
                });
                return Ok(());
            }
        };

        if let Some(group) = prepared.initialized_group
            && let Err(error) = self.persist_initialized_group(&group_id, group)
        {
            self.start_pending_group_shutdown(&group_id, Some(error.to_string()))?;
            return Ok(());
        }

        let runtime = self
            .pending_group_opens
            .get(&group_id)
            .ok_or_else(|| DriverError::GroupOpenPending(group_id.clone()))?
            .runtime
            .clone();
        let transport = SessionTransport {
            runtime,
            info: prepared.info,
        };
        let session_id = match self.open_group(group_id.clone(), prepared.session, transport) {
            Ok(session_id) => session_id,
            Err(error) => {
                self.start_pending_group_shutdown(&group_id, Some(error.to_string()))?;
                return Ok(());
            }
        };
        self.pending_group_opens.remove(&group_id);
        if let Err(error) = self.start_accepting(session_id) {
            self.push_failure(
                Some(session_id),
                "start incoming group accept loop",
                error.to_string(),
            );
            self.close_session(session_id)?;
        }
        Ok(())
    }

    fn persist_initialized_group(
        &mut self,
        group_id: &GroupId,
        initialized: GroupRecord,
    ) -> Result<(), DriverError> {
        let stored_id = group_id.clone();
        self.vault_mut()?.update(move |snapshot| {
            let group = snapshot.groups.get_mut(&stored_id).ok_or_else(|| {
                StorageError::Validation(format!(
                    "group disappeared while its identity was being initialized: {stored_id}"
                ))
            })?;
            if group.id != initialized.id || group.display_name != initialized.display_name {
                return Err(StorageError::Validation(format!(
                    "group changed while its session was being initialized: {stored_id}"
                )));
            }
            if let (Some(existing), Some(prepared)) = (&group.identity, &initialized.identity)
                && existing != prepared
            {
                return Err(StorageError::Validation(format!(
                    "group identity changed while its session was being initialized: {stored_id}"
                )));
            }
            *group = initialized;
            Ok(())
        })?;
        Ok(())
    }

    fn persist_group_record(
        &mut self,
        group_id: &GroupId,
        updated: GroupRecord,
    ) -> Result<(), DriverError> {
        let stored_id = group_id.clone();
        self.vault_mut()?.update(move |snapshot| {
            let stored = snapshot.groups.get_mut(&stored_id).ok_or_else(|| {
                StorageError::Validation(format!(
                    "group disappeared while its roster was being stored: {stored_id}"
                ))
            })?;
            if stored.id != updated.id
                || stored.owner_b32.as_deref() != updated.owner_b32.as_deref()
            {
                return Err(StorageError::Validation(format!(
                    "group identity changed while its roster was being stored: {stored_id}"
                )));
            }
            *stored = updated;
            Ok(())
        })?;
        Ok(())
    }

    fn persist_contact_identity(
        &mut self,
        contact_id: &ContactId,
        identity: PersistentIdentity,
    ) -> Result<(), DriverError> {
        let stored_id = contact_id.clone();
        self.vault_mut()?.update(move |snapshot| {
            let contact = snapshot.contacts.get_mut(&stored_id).ok_or_else(|| {
                StorageError::Validation(format!(
                    "contact disappeared while its identity was being initialized: {stored_id}"
                ))
            })?;
            match &contact.identity {
                None => contact.identity = Some(identity),
                Some(existing) if existing == &identity => {}
                Some(_) => {
                    return Err(StorageError::Validation(format!(
                        "contact identity changed while its session was being initialized: {stored_id}"
                    )));
                }
            }
            Ok(())
        })?;
        Ok(())
    }

    fn start_pending_contact_shutdown(
        &mut self,
        contact_id: &ContactId,
        failure: Option<String>,
    ) -> Result<(), DriverError> {
        let runtime = {
            let pending = self
                .pending_contact_opens
                .get_mut(contact_id)
                .ok_or_else(|| DriverError::ContactNotFound(contact_id.clone()))?;
            if failure.is_some() {
                pending.failure = failure;
            }
            if pending.shutdown_started {
                return Ok(());
            }
            pending.shutdown_started = true;
            pending.runtime.clone()
        };
        let task_contact_id = contact_id.clone();
        let tx = self.completions_tx.clone();
        if let Err(error) = self.spawn(async move {
            let result = runtime.shutdown().await.map_err(|error| error.to_string());
            let _ = tx
                .send(Completion::PendingContactShutdown {
                    contact_id: task_contact_id,
                    result,
                })
                .await;
        }) {
            if let Some(pending) = self.pending_contact_opens.get_mut(contact_id) {
                pending.shutdown_started = false;
            }
            return Err(error);
        }
        Ok(())
    }

    fn pending_contact_shutdown_finished(
        &mut self,
        contact_id: ContactId,
        result: Result<(), String>,
    ) -> Result<(), DriverError> {
        let Some(pending) = self.pending_contact_opens.remove(&contact_id) else {
            return Ok(());
        };
        if !self.shutdown_requested {
            let mut reason = pending
                .failure
                .unwrap_or_else(|| "contact opening was cancelled".to_string());
            if let Err(shutdown_error) = result {
                reason.push_str("; SAM cleanup failed: ");
                reason.push_str(&shutdown_error);
            }
            self.events.push_back(ApplicationEvent::SessionOpenFailed {
                key: ManagedSessionKey::Contact(contact_id),
                reason,
            });
        }
        self.start_coordinator_shutdown_if_ready()
    }

    fn start_pending_transient_shutdown(
        &mut self,
        transient_id: &TransientId,
        failure: Option<String>,
    ) -> Result<(), DriverError> {
        let runtime = {
            let pending = self
                .pending_transient_opens
                .get_mut(transient_id)
                .ok_or_else(|| DriverError::TransientOpenPending(transient_id.clone()))?;
            if failure.is_some() {
                pending.failure = failure;
            }
            if pending.shutdown_started {
                return Ok(());
            }
            pending.shutdown_started = true;
            pending.runtime.clone()
        };
        let task_id = transient_id.clone();
        let tx = self.completions_tx.clone();
        if let Err(error) = self.spawn(async move {
            let result = runtime.shutdown().await.map_err(|error| error.to_string());
            let _ = tx
                .send(Completion::PendingTransientShutdown {
                    transient_id: task_id,
                    result,
                })
                .await;
        }) {
            if let Some(pending) = self.pending_transient_opens.get_mut(transient_id) {
                pending.shutdown_started = false;
            }
            return Err(error);
        }
        Ok(())
    }

    fn pending_transient_shutdown_finished(
        &mut self,
        transient_id: TransientId,
        result: Result<(), String>,
    ) -> Result<(), DriverError> {
        let Some(pending) = self.pending_transient_opens.remove(&transient_id) else {
            return Ok(());
        };
        if !self.shutdown_requested {
            let mut reason = pending
                .failure
                .unwrap_or_else(|| "transient opening was cancelled".to_string());
            if let Err(shutdown_error) = result {
                reason.push_str("; SAM cleanup failed: ");
                reason.push_str(&shutdown_error);
            }
            self.events.push_back(ApplicationEvent::SessionOpenFailed {
                key: ManagedSessionKey::Transient(transient_id),
                reason,
            });
        }
        self.start_coordinator_shutdown_if_ready()
    }

    fn start_pending_group_shutdown(
        &mut self,
        group_id: &GroupId,
        failure: Option<String>,
    ) -> Result<(), DriverError> {
        let runtime = {
            let pending = self
                .pending_group_opens
                .get_mut(group_id)
                .ok_or_else(|| DriverError::GroupNotFound(group_id.clone()))?;
            if failure.is_some() {
                pending.failure = failure;
            }
            if pending.shutdown_started {
                return Ok(());
            }
            pending.shutdown_started = true;
            pending.runtime.clone()
        };
        let task_group_id = group_id.clone();
        let tx = self.completions_tx.clone();
        if let Err(error) = self.spawn(async move {
            let result = runtime.shutdown().await.map_err(|error| error.to_string());
            let _ = tx
                .send(Completion::PendingGroupShutdown {
                    group_id: task_group_id,
                    result,
                })
                .await;
        }) {
            if let Some(pending) = self.pending_group_opens.get_mut(group_id) {
                pending.shutdown_started = false;
            }
            return Err(error);
        }
        Ok(())
    }

    fn pending_group_shutdown_finished(
        &mut self,
        group_id: GroupId,
        result: Result<(), String>,
    ) -> Result<(), DriverError> {
        let Some(pending) = self.pending_group_opens.remove(&group_id) else {
            return Ok(());
        };
        if !self.shutdown_requested {
            let mut reason = pending
                .failure
                .unwrap_or_else(|| "group opening was cancelled".to_string());
            if let Err(shutdown_error) = result {
                reason.push_str("; SAM cleanup failed: ");
                reason.push_str(&shutdown_error);
            }
            self.events.push_back(ApplicationEvent::SessionOpenFailed {
                key: ManagedSessionKey::Group(group_id),
                reason,
            });
        }
        self.start_coordinator_shutdown_if_ready()
    }

    fn start_coordinator_shutdown_if_ready(&mut self) -> Result<(), DriverError> {
        if !self.shutdown_requested
            || self.coordinator_shutdown_started
            || !self.pending_contact_opens.is_empty()
            || !self.pending_transient_opens.is_empty()
            || !self.pending_group_opens.is_empty()
        {
            return Ok(());
        }
        self.coordinator_shutdown_started = true;
        let output = self.coordinator.begin_shutdown()?;
        self.process_output(output)
    }

    fn install_outbound_connection<F>(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        runtime: SamRuntime,
        connection: LiveConnection,
        operation: F,
    ) -> Result<(), DriverError>
    where
        F: FnOnce(
            &mut ApplicationCoordinator,
        ) -> Result<ApplicationOutput, ApplicationCoordinatorError>,
    {
        if !self.resources.contains_key(&session_id) {
            return self.close_orphan(runtime, connection);
        }
        let managed =
            self.create_managed_connection(session_id, connection_id, runtime, connection.clone())?;
        self.resources
            .get_mut(&session_id)
            .ok_or(DriverError::MissingResources(session_id))?
            .connections
            .insert(connection_id, managed);
        self.start_receiver(session_id, connection_id, connection)?;
        let output = operation(&mut self.coordinator)?;
        self.process_output(output)
    }

    fn install_incoming_connection(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        runtime: SamRuntime,
        incoming: AcceptedIncoming,
    ) -> Result<(), DriverError> {
        if !self.resources.contains_key(&session_id) {
            return self.close_orphan(runtime, incoming.connection);
        }
        let kind = self.resource(session_id)?.kind;
        let managed = self.create_managed_connection(
            session_id,
            connection_id,
            runtime,
            incoming.connection.clone(),
        )?;
        self.resources
            .get_mut(&session_id)
            .ok_or(DriverError::MissingResources(session_id))?
            .connections
            .insert(connection_id, managed);
        self.start_receiver(session_id, connection_id, incoming.connection)?;
        let now_ms = now_epoch_millis();
        let output = match kind {
            ResourceKind::Contact | ResourceKind::Transient => {
                self.coordinator.contact_incoming_connected(
                    session_id,
                    connection_id,
                    &incoming.peer_b32,
                    &incoming.peer_destination,
                    now_ms,
                )?
            }
            ResourceKind::Group => self.coordinator.group_incoming_connected(
                session_id,
                connection_id,
                &incoming.peer_b32,
                &incoming.peer_destination,
                now_ms,
            )?,
        };
        self.process_output(output)
    }

    fn create_managed_connection(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        runtime: SamRuntime,
        live: LiveConnection,
    ) -> Result<ManagedConnection, DriverError> {
        let (send_tx, send_rx) = mpsc::channel(SEND_QUEUE_CAPACITY);
        let (priority_send_tx, priority_send_rx) =
            mpsc::channel(PRIORITY_SEND_QUEUE_CAPACITY);
        let completions = self.completions_tx.clone();
        self.spawn(run_send_worker(
            session_id,
            connection_id,
            runtime,
            live.clone(),
            priority_send_rx,
            send_rx,
            completions,
        ))?;
        Ok(ManagedConnection {
            send_tx,
            priority_send_tx,
        })
    }

    fn close_orphan(
        &mut self,
        runtime: SamRuntime,
        connection: LiveConnection,
    ) -> Result<(), DriverError> {
        self.spawn(async move {
            let _ = runtime.close_stream(&connection).await;
        })
    }

    fn persist_contact_offline(
        &mut self,
        contact_id: &ContactId,
        state: commtools_core::PersistedOfflineState,
    ) -> Result<(), String> {
        let vault = self
            .vault
            .as_mut()
            .ok_or_else(|| "unlocked vault is unavailable".to_string())?;
        let contact = vault
            .snapshot_mut()
            .contacts
            .get_mut(contact_id)
            .ok_or_else(|| format!("contact is missing from the vault: {contact_id}"))?;
        contact.offline = Some(state);
        vault.commit().map_err(|error| error.to_string())
    }

    fn vault_mut(&mut self) -> Result<&mut UnlockedVault, DriverError> {
        self.vault.as_mut().ok_or(DriverError::VaultUnavailable)
    }

    fn next_contact_id(&self) -> Result<ContactId, DriverError> {
        let snapshot = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot();
        let timestamp = now_epoch_millis();
        for suffix in 0..=u32::MAX {
            let candidate = ContactId::new(format!("contact-local-{timestamp}-{suffix}"))
                .map_err(|error| DriverError::RecordMutation(error.to_string()))?;
            if !snapshot.contacts.contains_key(&candidate) {
                return Ok(candidate);
            }
        }
        Err(DriverError::RecordIdExhausted)
    }

    fn next_transient_id(&self) -> Result<TransientId, DriverError> {
        let timestamp = now_epoch_millis();
        for suffix in 0..=u32::MAX {
            let candidate = TransientId::new(format!("transient-{timestamp}-{suffix}"))
                .map_err(|error| DriverError::RecordMutation(error.to_string()))?;
            if !self.transient_is_active(&candidate) {
                return Ok(candidate);
            }
        }
        Err(DriverError::RecordIdExhausted)
    }

    fn next_group_id(&self) -> Result<GroupId, DriverError> {
        let snapshot = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot();
        let timestamp = now_epoch_millis();
        for suffix in 0..=u32::MAX {
            let candidate = GroupId::new(format!("group-local-{timestamp}-{suffix}"))
                .map_err(|error| DriverError::RecordMutation(error.to_string()))?;
            if !snapshot.groups.contains_key(&candidate) {
                return Ok(candidate);
            }
        }
        Err(DriverError::RecordIdExhausted)
    }

    fn resource(&self, session_id: SessionId) -> Result<&SessionResources, DriverError> {
        self.resources
            .get(&session_id)
            .ok_or(DriverError::MissingResources(session_id))
    }

    fn resource_mut(
        &mut self,
        session_id: SessionId,
    ) -> Result<&mut SessionResources, DriverError> {
        self.resources
            .get_mut(&session_id)
            .ok_or(DriverError::MissingResources(session_id))
    }

    fn resource_of_kind(
        &self,
        session_id: SessionId,
        kind: ResourceKind,
    ) -> Result<&SessionResources, DriverError> {
        let resources = self.resource(session_id)?;
        if resources.kind != kind {
            return Err(DriverError::WrongResourceKind(session_id));
        }
        Ok(resources)
    }

    fn resource_one_to_one(&self, session_id: SessionId) -> Result<&SessionResources, DriverError> {
        let resources = self.resource(session_id)?;
        if !matches!(
            resources.kind,
            ResourceKind::Contact | ResourceKind::Transient
        ) {
            return Err(DriverError::WrongResourceKind(session_id));
        }
        Ok(resources)
    }

    fn deaddrop(&self, session_id: SessionId) -> Result<DeaddropClient, DriverError> {
        self.resource_of_kind(session_id, ResourceKind::Contact)?
            .deaddrop
            .clone()
            .ok_or(DriverError::MissingDeaddrop(session_id))
    }

    fn deaddrop_operation_servers(
        &mut self,
        session_id: SessionId,
    ) -> Result<Vec<String>, DriverError> {
        let contact_id = self
            .coordinator
            .contact_id_for_session(session_id)
            .cloned()
            .ok_or(DriverError::ContactSessionNotFound(session_id))?;
        let contact = self
            .vault()
            .ok_or(DriverError::VaultUnavailable)?
            .snapshot()
            .contacts
            .get(&contact_id)
            .ok_or_else(|| DriverError::ContactNotFound(contact_id.clone()))?;
        let servers = contact.deaddrop_servers.clone();
        let stats = contact.deaddrop_stats.clone();
        let sequence = {
            let resources = self.resource_mut(session_id)?;
            let sequence = resources.deaddrop_operation_sequence;
            resources.deaddrop_operation_sequence = sequence.wrapping_add(1);
            sequence
        };
        Ok(select_deaddrop_servers(&servers, &stats, sequence).operation)
    }

    fn record_deaddrop_put(
        &mut self,
        session_id: SessionId,
        result: &PutResult,
        now_ms: u64,
    ) -> Result<(), DriverError> {
        self.record_deaddrop_result(session_id, now_ms, |stats| {
            record_put_result(stats, result, now_ms);
        })
    }

    fn record_deaddrop_get(
        &mut self,
        session_id: SessionId,
        result: &GetResult,
        now_ms: u64,
    ) -> Result<(), DriverError> {
        self.record_deaddrop_result(session_id, now_ms, |stats| {
            record_get_result(stats, result, now_ms);
        })
    }

    fn record_deaddrop_result(
        &mut self,
        session_id: SessionId,
        now_ms: u64,
        update: impl FnOnce(&mut BTreeMap<String, commtools_core::DeaddropServerStat>),
    ) -> Result<(), DriverError> {
        let contact_id = self
            .coordinator
            .contact_id_for_session(session_id)
            .cloned()
            .ok_or(DriverError::ContactSessionNotFound(session_id))?;
        {
            let contact = self
                .vault_mut()?
                .snapshot_mut()
                .contacts
                .get_mut(&contact_id)
                .ok_or_else(|| DriverError::ContactNotFound(contact_id.clone()))?;
            let configured = contact
                .deaddrop_servers
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            contact
                .deaddrop_stats
                .retain(|server, _| configured.contains(server));
            for server in configured {
                contact.deaddrop_stats.entry(server).or_default();
            }
            update(&mut contact.deaddrop_stats);
        }
        self.deaddrop_stats_dirty = true;
        self.flush_deaddrop_stats(false, now_ms)
    }

    fn flush_deaddrop_stats(&mut self, force: bool, now_ms: u64) -> Result<(), DriverError> {
        if !self.deaddrop_stats_dirty
            || (!force
                && self.deaddrop_stats_last_flush_ms != 0
                && now_ms.saturating_sub(self.deaddrop_stats_last_flush_ms)
                    < DEADDROP_STATS_FLUSH_INTERVAL_MS)
        {
            return Ok(());
        }
        self.vault_mut()?.commit()?;
        self.deaddrop_stats_dirty = false;
        self.deaddrop_stats_last_flush_ms = now_ms;
        Ok(())
    }

    fn ensure_connection(
        &self,
        session_id: SessionId,
        connection_id: ConnectionId,
    ) -> Result<(), DriverError> {
        let resources = self.resource(session_id)?;
        if !resources.connections.contains_key(&connection_id) {
            return Err(DriverError::MissingConnection {
                session_id,
                connection_id,
            });
        }
        Ok(())
    }

    fn send_job(
        &self,
        session_id: SessionId,
        connection_id: ConnectionId,
        job: SendJob,
    ) -> Result<(), DriverError> {
        let connection = self
            .resource(session_id)?
            .connections
            .get(&connection_id)
            .ok_or(DriverError::MissingConnection {
                session_id,
                connection_id,
            })?;
        // Liveness traffic bypasses the paced bulk queue so a large image or file cannot create a
        // false heartbeat timeout(!!!). Both queues still serialize onto the same authenticated stream.
        // Definite rewrite to multiple streams model in CommTools v2
        let send_tx = if job.is_heartbeat() {
            &connection.priority_send_tx
        } else {
            &connection.send_tx
        };
        send_tx
            .try_send(job)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => DriverError::SendQueueFull {
                    session_id,
                    connection_id,
                },
                mpsc::error::TrySendError::Closed(_) => DriverError::SendWorkerClosed {
                    session_id,
                    connection_id,
                },
            })
    }

    fn send_close_job(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        job: SendJob,
    ) -> Result<(), DriverError> {
        match self.send_job(session_id, connection_id, job) {
            Ok(()) => Ok(()),
            Err(DriverError::SendWorkerClosed { .. }) => {
                self.finalize_connection_closed(session_id, connection_id)
            }
            Err(error) => Err(error),
        }
    }

    fn send_connection_job(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
        job: SendJob,
        operation: &'static str,
    ) -> Result<(), DriverError> {
        match self.send_job(session_id, connection_id, job) {
            Ok(()) => Ok(()),
            Err(error @ DriverError::SendWorkerClosed { .. }) => {
                self.push_failure(Some(session_id), operation, error.to_string());
                self.finalize_connection_closed(session_id, connection_id)
            }
            Err(error) => Err(error),
        }
    }

    fn finalize_connection_closed(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
    ) -> Result<(), DriverError> {
        let removed = self.resources.get_mut(&session_id).and_then(|resources| {
            resources.closing_connections.remove(&connection_id);
            resources.connections.remove(&connection_id)
        });
        if removed.is_none() {
            return Ok(());
        }
        let output = self
            .coordinator
            .connection_closed(session_id, connection_id)?;
        self.process_output(output)
    }

    fn connection_exists(&self, session_id: SessionId, connection_id: ConnectionId) -> bool {
        self.resources
            .get(&session_id)
            .is_some_and(|resources| resources.connections.contains_key(&connection_id))
    }

    fn connection_is_closing(&self, session_id: SessionId, connection_id: ConnectionId) -> bool {
        self.resources
            .get(&session_id)
            .is_some_and(|resources| resources.closing_connections.contains(&connection_id))
    }

    fn mark_connection_closing(
        &mut self,
        session_id: SessionId,
        connection_id: ConnectionId,
    ) -> Result<bool, DriverError> {
        let resources = self.resource_mut(session_id)?;
        if !resources.connections.contains_key(&connection_id) {
            return Err(DriverError::MissingConnection {
                session_id,
                connection_id,
            });
        }
        Ok(resources.closing_connections.insert(connection_id))
    }

    fn session_is_open(&self, session_id: SessionId) -> bool {
        self.coordinator
            .sessions()
            .into_iter()
            .find(|session| session.session_id == session_id)
            .is_some_and(|session| session.phase == ManagedSessionPhase::Open)
    }

    fn allocate_connection_id(&mut self) -> Result<ConnectionId, DriverError> {
        let value = self.next_connection_id;
        self.next_connection_id = self
            .next_connection_id
            .checked_add(1)
            .ok_or(DriverError::ConnectionIdExhausted)?;
        Ok(ConnectionId::new(value))
    }

    fn spawn<F>(&mut self, future: F) -> Result<(), DriverError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| DriverError::NoTokioRuntime)?;
        self.tasks.push(runtime.spawn(future));
        Ok(())
    }

    fn prune_tasks(&mut self) {
        self.tasks.retain(|task| !task.is_finished());
    }

    fn push_failure(
        &mut self,
        session_id: Option<SessionId>,
        operation: &'static str,
        reason: String,
    ) {
        self.events.push_back(ApplicationEvent::OperationFailed {
            session_id,
            operation,
            reason,
        });
    }
}

impl Drop for ApplicationDriver {
    fn drop(&mut self) {
        for (_, transfer) in std::mem::take(&mut self.incoming_files) {
            let temporary_path = transfer.temporary_path.clone();
            drop(transfer.file);
            let _ = fs::remove_file(temporary_path);
        }
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn original_image_header(
    media_id: u64,
    image: &CachedOriginalImage,
) -> Result<ImageTransferHeader, DriverError> {
    Ok(ImageTransferHeader {
        filename: image.filename.clone(),
        mime: image.mime.clone(),
        total_bytes: image.bytes.len() as u64,
        kind: ImageTransferKind::Original,
        media_id,
        original: Some(
            OriginalImageMetadata::new(
                image.bytes.len() as u64,
                image.mime.clone(),
                image.sha256.clone(),
            )
            .map_err(|error| DriverError::InvalidImageFile(error.to_string()))?,
        ),
    })
}

fn evict_original_cache<K, F>(
    cache: &mut BTreeMap<K, CachedOriginalImage>,
    incoming_bytes: usize,
    belongs_to_session: F,
) where
    K: Ord + Clone,
    F: Fn(&K, &CachedOriginalImage) -> bool,
{
    loop {
        let item_count = cache
            .iter()
            .filter(|(key, image)| belongs_to_session(key, image))
            .count();
        let byte_count = cache
            .iter()
            .filter(|(key, image)| belongs_to_session(key, image))
            .map(|(_, image)| image.bytes.len())
            .sum::<usize>();
        if item_count < ORIGINAL_IMAGE_CACHE_MAX_ITEMS
            && byte_count.saturating_add(incoming_bytes) <= ORIGINAL_IMAGE_CACHE_MAX_BYTES
        {
            break;
        }
        let Some(oldest) = cache
            .iter()
            .filter(|(key, image)| belongs_to_session(key, image))
            .min_by_key(|(_, image)| image.added_ms)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        cache.remove(&oldest);
    }
}

fn create_incoming_file(
    directory: &Path,
    transfer_id: u64,
    filename: &str,
) -> Result<(File, PathBuf, PathBuf), String> {
    if !directory.is_dir() {
        return Err("the unlocked vault files directory is unavailable".into());
    }
    for suffix in 0_u16..=u16::MAX {
        let stem = if suffix == 0 {
            format!("recv_{transfer_id}_{filename}")
        } else {
            format!("recv_{transfer_id}_{suffix}_{filename}")
        };
        let final_path = directory.join(&stem);
        let temporary_path = directory.join(format!(".{stem}.part"));
        if final_path.exists() {
            continue;
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&temporary_path) {
            Ok(file) => return Ok((file, temporary_path, final_path)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("create received file: {error}")),
        }
    }
    Err("could not allocate a unique received-file path".into())
}

#[derive(Debug, Clone)]
enum SendCompletion {
    None,
    OfflineIndexSync,
    OriginalImage {
        key: OriginalImageKey,
        cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendOutcome {
    Completed,
    Cancelled,
}

enum SendJob {
    Sequence {
        destination_prelude: Option<String>,
        frames: Vec<Frame>,
        completion: SendCompletion,
        operation: &'static str,
    },
    ImageSequence {
        frames: Vec<Frame>,
        cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
        completion: SendCompletion,
        operation: &'static str,
    },
    File {
        transfer_id: u64,
        filename: String,
        total_bytes: u64,
        file: File,
        sealer: FileFrameSealer,
    },
    CancelFile {
        transfer_id: u64,
    },
    NotifyAndClose {
        frame: Frame,
        delay_ms: u64,
        operation: &'static str,
    },
    Close {
        operation: Option<&'static str>,
    },
}

impl SendJob {
    fn is_heartbeat(&self) -> bool {
        let Self::Sequence {
            destination_prelude: None,
            frames,
            ..
        } = self
        else {
            return false;
        };
        frames.len() == 1 && is_heartbeat_frame(&frames[0])
    }
}

fn is_heartbeat_frame(frame: &Frame) -> bool {
    frame.message_type == MessageType::S
        && (frame.payload.starts_with(HEARTBEAT_PING_PREFIX.as_bytes())
            || frame.payload.starts_with(HEARTBEAT_PONG_PREFIX.as_bytes()))
}

struct OutgoingFileSend {
    transfer_id: u64,
    filename: String,
    total_bytes: u64,
    file: File,
    sealer: FileFrameSealer,
    sent_bytes: u64,
    last_reported_bytes: u64,
}

struct OutgoingImageSend {
    frames: VecDeque<Frame>,
    cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    completion: SendCompletion,
    operation: &'static str,
}

impl OutgoingImageSend {
    fn new(
        frames: Vec<Frame>,
        cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
        completion: SendCompletion,
        operation: &'static str,
    ) -> Self {
        Self {
            frames: frames.into(),
            cancel,
            completion,
            operation,
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .is_some_and(|cancel| cancel.load(std::sync::atomic::Ordering::SeqCst))
    }

    fn next_frame(&mut self) -> ImageSendStep {
        if self.is_cancelled() {
            ImageSendStep::Cancelled
        } else {
            self.frames
                .pop_front()
                .map_or(ImageSendStep::Completed, ImageSendStep::Frame)
        }
    }
}

enum ImageSendStep {
    Frame(Frame),
    Completed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImageBurstOutcome {
    Continue,
    Completed,
    Cancelled,
}

enum SendWorkerWake {
    Job(SendJob),
    BulkReady,
    QueueClosed,
}

struct FileSendStep {
    frame: Frame,
    progress: Option<u64>,
    finished: bool,
}

impl OutgoingFileSend {
    fn new(
        transfer_id: u64,
        filename: String,
        total_bytes: u64,
        file: File,
        sealer: FileFrameSealer,
    ) -> Self {
        Self {
            transfer_id,
            filename,
            total_bytes,
            file,
            sealer,
            sent_bytes: 0,
            last_reported_bytes: 0,
        }
    }

    fn next_step(&mut self) -> Result<FileSendStep, String> {
        let mut buffer = [0_u8; FILE_TRANSFER_CHUNK_BYTES];
        let read = self
            .file
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            if self.sent_bytes != self.total_bytes {
                return Err(format!(
                    "file size changed during transfer: expected {}, read {}",
                    self.total_bytes, self.sent_bytes
                ));
            }
            let frame = self
                .sealer
                .seal_with_message_id(MessageType::E, self.transfer_id, &[])
                .map_err(|error| error.to_string())?;
            return Ok(FileSendStep {
                frame,
                progress: None,
                finished: true,
            });
        }

        self.sent_bytes = self
            .sent_bytes
            .checked_add(read as u64)
            .ok_or_else(|| "file transfer byte counter overflow".to_string())?;
        if self.sent_bytes > self.total_bytes {
            return Err("file grew while it was being transferred".into());
        }
        let encoded = BASE64.encode(&buffer[..read]);
        let frame = self
            .sealer
            .seal_with_message_id(MessageType::C, self.transfer_id, encoded.as_bytes())
            .map_err(|error| error.to_string())?;
        let progress = if self.sent_bytes == self.total_bytes
            || self.sent_bytes.saturating_sub(self.last_reported_bytes) >= FILE_PROGRESS_STEP_BYTES
        {
            self.last_reported_bytes = self.sent_bytes;
            Some(self.sent_bytes)
        } else {
            None
        };
        Ok(FileSendStep {
            frame,
            progress,
            finished: false,
        })
    }
}

async fn run_send_worker(
    session_id: SessionId,
    connection_id: ConnectionId,
    runtime: SamRuntime,
    connection: LiveConnection,
    mut priority_jobs: mpsc::Receiver<SendJob>,
    mut jobs: mpsc::Receiver<SendJob>,
    completions: mpsc::Sender<Completion>,
) {
    let mut active_file = None;
    let mut active_image = None;
    let mut queued_images = VecDeque::new();
    let mut next_bulk_send_at = tokio::time::Instant::now();
    loop {
        if active_image.is_none() {
            active_image = queued_images.pop_front();
        }
        let wake = wait_for_send_work(
            &mut priority_jobs,
            &mut jobs,
            active_file.is_some() || active_image.is_some(),
            next_bulk_send_at,
        )
        .await;
        let job = match wake {
            SendWorkerWake::Job(job) => Some(job),
            SendWorkerWake::BulkReady => None,
            SendWorkerWake::QueueClosed => {
                if active_file.is_none() && active_image.is_none() && queued_images.is_empty() {
                    break;
                }
                finish_active_file(
                    &mut active_file,
                    &completions,
                    session_id,
                    Err("file transfer interrupted because the send queue closed".into()),
                )
                .await;
                finish_all_images(
                    &mut active_image,
                    &mut queued_images,
                    &completions,
                    session_id,
                    connection_id,
                    Ok(SendOutcome::Cancelled),
                )
                .await;
                let _ = runtime.close_stream(&connection).await;
                break;
            }
        };

        let Some(job) = job else {
            if active_image.is_some() {
                match send_active_image_burst(&runtime, &connection, &mut active_image).await {
                    Ok(ImageBurstOutcome::Continue) => {
                        next_bulk_send_at = tokio::time::Instant::now() + BULK_SEND_PACING_INTERVAL;
                    }
                    Ok(ImageBurstOutcome::Completed) => {
                        next_bulk_send_at = tokio::time::Instant::now() + BULK_SEND_PACING_INTERVAL;
                        finish_active_image(
                            &mut active_image,
                            &completions,
                            session_id,
                            connection_id,
                            Ok(SendOutcome::Completed),
                        )
                        .await;
                    }
                    Ok(ImageBurstOutcome::Cancelled) => {
                        finish_active_image(
                            &mut active_image,
                            &completions,
                            session_id,
                            connection_id,
                            Ok(SendOutcome::Cancelled),
                        )
                        .await;
                    }
                    Err(reason) => {
                        finish_active_image(
                            &mut active_image,
                            &completions,
                            session_id,
                            connection_id,
                            Err(reason),
                        )
                        .await;
                        finish_all_images(
                            &mut active_image,
                            &mut queued_images,
                            &completions,
                            session_id,
                            connection_id,
                            Err("image transfer interrupted by a failed connection send".into()),
                        )
                        .await;
                        finish_active_file(
                            &mut active_file,
                            &completions,
                            session_id,
                            Err("file transfer interrupted by a failed connection send".into()),
                        )
                        .await;
                        close_after_send_failure(
                            &runtime,
                            &connection,
                            &completions,
                            session_id,
                            connection_id,
                            "close stream after failed image send",
                        )
                        .await;
                        break;
                    }
                }
                continue;
            }
            let step = match active_file
                .as_mut()
                .expect("active file was checked")
                .next_step()
            {
                Ok(step) => step,
                Err(reason) => {
                    finish_active_file(&mut active_file, &completions, session_id, Err(reason))
                        .await;
                    close_after_send_failure(
                        &runtime,
                        &connection,
                        &completions,
                        session_id,
                        connection_id,
                        "close stream after failed file transfer",
                    )
                    .await;
                    break;
                }
            };
            if let Err(error) = runtime.send_frame(&connection, &step.frame).await {
                finish_active_file(
                    &mut active_file,
                    &completions,
                    session_id,
                    Err(error.to_string()),
                )
                .await;
                close_after_send_failure(
                    &runtime,
                    &connection,
                    &completions,
                    session_id,
                    connection_id,
                    "close stream after failed file transfer",
                )
                .await;
                break;
            }
            next_bulk_send_at = tokio::time::Instant::now() + BULK_SEND_PACING_INTERVAL;
            if let Some(transferred_bytes) = step.progress {
                let transfer = active_file.as_ref().expect("active file was checked");
                if completions
                    .send(Completion::FileProgress {
                        session_id,
                        transfer_id: transfer.transfer_id,
                        transferred_bytes,
                        total_bytes: transfer.total_bytes,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
            if step.finished {
                finish_active_file(&mut active_file, &completions, session_id, Ok(())).await;
            }
            continue;
        };

        match job {
            SendJob::Sequence {
                destination_prelude,
                frames,
                completion,
                operation,
            } => {
                let result = send_sequence(&runtime, &connection, destination_prelude, frames)
                    .await
                    .map(|()| SendOutcome::Completed);
                let failed = result.is_err();
                let _ = completions
                    .send(Completion::SendFinished {
                        session_id,
                        connection_id,
                        completion,
                        operation,
                        result,
                    })
                    .await;
                if failed {
                    finish_all_images(
                        &mut active_image,
                        &mut queued_images,
                        &completions,
                        session_id,
                        connection_id,
                        Err("image transfer interrupted by a failed connection send".into()),
                    )
                    .await;
                    finish_active_file(
                        &mut active_file,
                        &completions,
                        session_id,
                        Err("file transfer interrupted by a failed connection send".into()),
                    )
                    .await;
                    close_after_send_failure(
                        &runtime,
                        &connection,
                        &completions,
                        session_id,
                        connection_id,
                        "close stream after failed send",
                    )
                    .await;
                    break;
                }
            }
            SendJob::ImageSequence {
                frames,
                cancel,
                completion,
                operation,
            } => {
                let image = OutgoingImageSend::new(frames, cancel, completion, operation);
                if active_image.is_none() {
                    active_image = Some(image);
                } else {
                    queued_images.push_back(image);
                }
            }
            SendJob::File {
                transfer_id,
                filename,
                total_bytes,
                file,
                sealer,
            } => {
                if active_file.is_some() {
                    let _ = completions
                        .send(Completion::FileFinished {
                            session_id,
                            transfer_id,
                            filename,
                            total_bytes,
                            result: Err("another file transfer is already active".into()),
                        })
                        .await;
                } else {
                    active_file = Some(OutgoingFileSend::new(
                        transfer_id,
                        filename,
                        total_bytes,
                        file,
                        sealer,
                    ));
                }
            }
            SendJob::CancelFile { transfer_id } => {
                if active_file
                    .as_ref()
                    .is_some_and(|transfer| transfer.transfer_id == transfer_id)
                {
                    finish_active_file(
                        &mut active_file,
                        &completions,
                        session_id,
                        Err("file transfer cancelled".into()),
                    )
                    .await;
                }
            }
            SendJob::NotifyAndClose {
                frame,
                delay_ms,
                operation,
            } => {
                finish_active_file(
                    &mut active_file,
                    &completions,
                    session_id,
                    Err("file transfer interrupted by connection shutdown".into()),
                )
                .await;
                finish_all_images(
                    &mut active_image,
                    &mut queued_images,
                    &completions,
                    session_id,
                    connection_id,
                    Ok(SendOutcome::Cancelled),
                )
                .await;
                let send_result = runtime
                    .send_frame(&connection, &frame)
                    .await
                    .map_err(|error| error.to_string());
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                let close_result = runtime
                    .close_stream(&connection)
                    .await
                    .map_err(|error| error.to_string());
                let _ = completions
                    .send(Completion::ConnectionClosed {
                        session_id,
                        connection_id,
                        operation: Some(operation),
                        result: send_result.and(close_result),
                    })
                    .await;
                break;
            }
            SendJob::Close { operation } => {
                finish_active_file(
                    &mut active_file,
                    &completions,
                    session_id,
                    Err("file transfer interrupted by connection shutdown".into()),
                )
                .await;
                finish_all_images(
                    &mut active_image,
                    &mut queued_images,
                    &completions,
                    session_id,
                    connection_id,
                    Ok(SendOutcome::Cancelled),
                )
                .await;
                let result = runtime
                    .close_stream(&connection)
                    .await
                    .map_err(|error| error.to_string());
                let _ = completions
                    .send(Completion::ConnectionClosed {
                        session_id,
                        connection_id,
                        operation,
                        result,
                    })
                    .await;
                break;
            }
        }
    }
}

async fn wait_for_send_work(
    priority_jobs: &mut mpsc::Receiver<SendJob>,
    jobs: &mut mpsc::Receiver<SendJob>,
    bulk_active: bool,
    next_bulk_send_at: tokio::time::Instant,
) -> SendWorkerWake {
    let mut priority_open = true;
    let mut normal_open = true;
    loop {
        match priority_jobs.try_recv() {
            Ok(job) => return SendWorkerWake::Job(job),
            Err(mpsc::error::TryRecvError::Disconnected) => priority_open = false,
            Err(mpsc::error::TryRecvError::Empty) => {}
        }
        match jobs.try_recv() {
            Ok(job) => return SendWorkerWake::Job(job),
            Err(mpsc::error::TryRecvError::Disconnected) => normal_open = false,
            Err(mpsc::error::TryRecvError::Empty) => {}
        }
        if !priority_open && !normal_open {
            return SendWorkerWake::QueueClosed;
        }
        if bulk_active && tokio::time::Instant::now() >= next_bulk_send_at {
            return SendWorkerWake::BulkReady;
        }
        tokio::select! {
            biased;
            job = priority_jobs.recv(), if priority_open => {
                match job {
                    Some(job) => return SendWorkerWake::Job(job),
                    None => priority_open = false,
                }
            }
            job = jobs.recv(), if normal_open => {
                match job {
                    Some(job) => return SendWorkerWake::Job(job),
                    None => normal_open = false,
                }
            }
            _ = tokio::time::sleep_until(next_bulk_send_at), if bulk_active => {
                return SendWorkerWake::BulkReady;
            }
        }
    }
}

async fn send_active_image_burst(
    runtime: &SamRuntime,
    connection: &LiveConnection,
    active_image: &mut Option<OutgoingImageSend>,
) -> Result<ImageBurstOutcome, String> {
    let image = active_image.as_mut().expect("active image was checked");
    for _ in 0..IMAGE_SEND_BURST_FRAMES {
        let frame = match image.next_frame() {
            ImageSendStep::Frame(frame) => frame,
            ImageSendStep::Completed => return Ok(ImageBurstOutcome::Completed),
            ImageSendStep::Cancelled => return Ok(ImageBurstOutcome::Cancelled),
        };
        runtime
            .send_frame(connection, &frame)
            .await
            .map_err(|error| error.to_string())?;
        if image.frames.is_empty() {
            return Ok(ImageBurstOutcome::Completed);
        }
    }
    Ok(ImageBurstOutcome::Continue)
}

async fn finish_active_image(
    active_image: &mut Option<OutgoingImageSend>,
    completions: &mpsc::Sender<Completion>,
    session_id: SessionId,
    connection_id: ConnectionId,
    result: Result<SendOutcome, String>,
) {
    let Some(image) = active_image.take() else {
        return;
    };
    let _ = completions
        .send(Completion::SendFinished {
            session_id,
            connection_id,
            completion: image.completion,
            operation: image.operation,
            result,
        })
        .await;
}

async fn finish_all_images(
    active_image: &mut Option<OutgoingImageSend>,
    queued_images: &mut VecDeque<OutgoingImageSend>,
    completions: &mpsc::Sender<Completion>,
    session_id: SessionId,
    connection_id: ConnectionId,
    result: Result<SendOutcome, String>,
) {
    let mut images = VecDeque::new();
    if let Some(image) = active_image.take() {
        images.push_back(image);
    }
    images.append(queued_images);
    while let Some(image) = images.pop_front() {
        let image_result = match &result {
            Ok(outcome) => Ok(*outcome),
            Err(reason) => Err(reason.clone()),
        };
        let _ = completions
            .send(Completion::SendFinished {
                session_id,
                connection_id,
                completion: image.completion,
                operation: image.operation,
                result: image_result,
            })
            .await;
    }
}

async fn finish_active_file(
    active_file: &mut Option<OutgoingFileSend>,
    completions: &mpsc::Sender<Completion>,
    session_id: SessionId,
    result: Result<(), String>,
) {
    let Some(transfer) = active_file.take() else {
        return;
    };
    let _ = completions
        .send(Completion::FileFinished {
            session_id,
            transfer_id: transfer.transfer_id,
            filename: transfer.filename,
            total_bytes: transfer.total_bytes,
            result,
        })
        .await;
}

async fn close_after_send_failure(
    runtime: &SamRuntime,
    connection: &LiveConnection,
    completions: &mpsc::Sender<Completion>,
    session_id: SessionId,
    connection_id: ConnectionId,
    operation: &'static str,
) {
    let result = runtime
        .close_stream(connection)
        .await
        .map_err(|error| error.to_string());
    let _ = completions
        .send(Completion::ConnectionClosed {
            session_id,
            connection_id,
            operation: Some(operation),
            result,
        })
        .await;
}

async fn send_sequence(
    runtime: &SamRuntime,
    connection: &LiveConnection,
    destination_prelude: Option<String>,
    frames: Vec<Frame>,
) -> Result<(), String> {
    if let Some(destination) = destination_prelude {
        runtime
            .send_destination_prelude(connection, &destination)
            .await
            .map_err(|error| error.to_string())?;
    }
    for frame in frames {
        runtime
            .send_frame(connection, &frame)
            .await
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

enum Completion {
    SamTestFinished {
        result: Result<(), String>,
    },
    SamLivenessProbeFinished {
        generation: u64,
        completed_ms: u64,
        result: Result<(), String>,
    },
    ContactBootstrapFinished {
        contact_id: ContactId,
        result: Result<PreparedContact, String>,
    },
    PendingContactShutdown {
        contact_id: ContactId,
        result: Result<(), String>,
    },
    TransientBootstrapFinished {
        transient_id: TransientId,
        result: Result<PreparedTransient, String>,
    },
    PendingTransientShutdown {
        transient_id: TransientId,
        result: Result<(), String>,
    },
    GroupBootstrapFinished {
        group_id: GroupId,
        result: Result<PreparedGroup, String>,
    },
    PendingGroupShutdown {
        group_id: GroupId,
        result: Result<(), String>,
    },
    ContactConnected {
        session_id: SessionId,
        attempt_id: u64,
        connection_id: ConnectionId,
        peer_b32: String,
        runtime: SamRuntime,
        result: Result<LiveConnection, String>,
    },
    GroupConnected {
        session_id: SessionId,
        attempt_id: u64,
        connection_id: ConnectionId,
        peer_b32: String,
        runtime: SamRuntime,
        result: Result<LiveConnection, String>,
    },
    Accepted {
        session_id: SessionId,
        connection_id: ConnectionId,
        runtime: SamRuntime,
        result: Result<AcceptedIncoming, String>,
    },
    AcceptArmed {
        session_id: SessionId,
    },
    FrameReceived {
        session_id: SessionId,
        connection_id: ConnectionId,
        frame: Frame,
    },
    SendFinished {
        session_id: SessionId,
        connection_id: ConnectionId,
        completion: SendCompletion,
        operation: &'static str,
        result: Result<SendOutcome, String>,
    },
    FileProgress {
        session_id: SessionId,
        transfer_id: u64,
        transferred_bytes: u64,
        total_bytes: u64,
    },
    FileFinished {
        session_id: SessionId,
        transfer_id: u64,
        filename: String,
        total_bytes: u64,
        result: Result<(), String>,
    },
    ConnectionClosed {
        session_id: SessionId,
        connection_id: ConnectionId,
        operation: Option<&'static str>,
        result: Result<(), String>,
    },
    TransportEnded {
        session_id: SessionId,
        connection_id: ConnectionId,
    },
    OfflinePut {
        session_id: SessionId,
        operation_id: OfflineOperationId,
        result: Result<PutResult, String>,
    },
    OfflineGet {
        session_id: SessionId,
        operation_id: OfflineOperationId,
        result: Result<GetResult, String>,
    },
    SamShutdown {
        session_id: SessionId,
        result: Result<(), String>,
    },
    DeaddropShutdown {
        session_id: SessionId,
        result: Result<(), String>,
    },
}

#[cfg(test)]
fn build_group_bootstrap_plan(
    group: &GroupRecord,
    default_tunnels: TunnelSettings,
) -> Result<GroupBootstrapPlan, DriverError> {
    build_group_bootstrap_plan_with_prefix(group, default_tunnels, DEFAULT_SAM_SESSION_PREFIX)
}

fn build_group_bootstrap_plan_with_prefix(
    group: &GroupRecord,
    default_tunnels: TunnelSettings,
    sam_session_prefix: &str,
) -> Result<GroupBootstrapPlan, DriverError> {
    let suffix = group_sam_session_suffix(group, now_epoch_millis());
    let session_id = format!("{sam_session_prefix}_group_{suffix}");
    let tunnels = TunnelOptions::new(default_tunnels.length, default_tunnels.quantity)
        .map_err(|error| DriverError::GroupBootstrap(error.to_string()))?;
    let (sam_config, expected_b32) = match &group.identity {
        Some(identity) => (
            SamSessionConfig::persistent(
                session_id,
                identity.destination_b64.expose_secret(),
                tunnels,
            )
            .map_err(|error| DriverError::GroupBootstrap(error.to_string()))?,
            Some(identity.b32.clone()),
        ),
        None => (
            SamSessionConfig::transient(session_id, tunnels)
                .map_err(|error| DriverError::GroupBootstrap(error.to_string()))?,
            None,
        ),
    };
    Ok(GroupBootstrapPlan {
        group: group.clone(),
        sam_config,
        expected_b32,
    })
}

async fn prepare_group(
    runtime: SamRuntime,
    plan: GroupBootstrapPlan,
) -> Result<PreparedGroup, String> {
    let info = runtime
        .create_session(&plan.sam_config)
        .await
        .map_err(|error| error.to_string())?;
    if plan
        .expected_b32
        .as_ref()
        .is_some_and(|expected| !expected.eq_ignore_ascii_case(&info.b32))
    {
        return Err("SAM initialized a different identity than the stored group identity".into());
    }

    let (group, initialized) = initialize_group_record(plan.group, &info)?;

    let now_ms = now_epoch_millis();
    let config = GroupSessionConfig::from_record_with_local_destination(
        &group,
        &info.public_destination,
        now_ms,
    )
    .map_err(|error| error.to_string())?
    .with_control_message_seed(now_ms);
    Ok(PreparedGroup {
        info,
        session: GroupSession::new(config),
        initialized_group: initialized.then_some(group),
    })
}

fn initialize_group_record(
    mut group: GroupRecord,
    info: &SamSessionInfo,
) -> Result<(GroupRecord, bool), String> {
    let mut initialized = false;
    if group.identity.is_none() {
        group.identity = Some(
            PersistentIdentity::new(info.private_destination.clone(), info.b32.clone())
                .map_err(|error| error.to_string())?,
        );
        initialized = true;
    }
    if group.owner_b32.is_none() {
        let has_imported_group_state = group.join_token.is_some()
            || group.private_join_credential.is_some()
            || group.roster_signing_public_key.is_some()
            || group.roster_signature.is_some()
            || !group.members.is_empty();
        if has_imported_group_state {
            return Err("stored group membership is missing its owner identity".into());
        }
        group.owner_b32 = Some(info.b32.clone());
        initialized = true;
    }
    if is_group_owner(&group)
        && (group.roster_signing_secret.is_none()
            || group.roster_signing_public_key.is_none()
            || group.roster_signature.is_none())
    {
        sign_owner_roster(&mut group).map_err(|error| error.to_string())?;
        initialized = true;
    }
    Ok((group, initialized))
}

#[cfg(test)]
fn build_contact_bootstrap_plan(
    contact: &ContactRecord,
    endpoint: SamEndpoint,
) -> Result<ContactBootstrapPlan, DriverError> {
    build_contact_bootstrap_plan_with_prefix(contact, endpoint, DEFAULT_SAM_SESSION_PREFIX)
}

fn build_contact_bootstrap_plan_with_prefix(
    contact: &ContactRecord,
    endpoint: SamEndpoint,
    sam_session_prefix: &str,
) -> Result<ContactBootstrapPlan, DriverError> {
    let tunnels = TunnelOptions::new(contact.tunnels.length, contact.tunnels.quantity)
        .map_err(|error| DriverError::ContactBootstrap(error.to_string()))?;
    let suffix = contact_sam_session_suffix(&contact.display_name, now_epoch_millis());
    let session_id = format!("{sam_session_prefix}_chat_{suffix}");
    let (sam_config, expected_b32, persist_identity) = match &contact.identity {
        Some(identity) => (
            SamSessionConfig::persistent(
                session_id,
                identity.destination_b64.expose_secret(),
                tunnels,
            )
            .map_err(|error| DriverError::ContactBootstrap(error.to_string()))?,
            Some(identity.b32.clone()),
            false,
        ),
        None => (
            SamSessionConfig::transient(session_id, tunnels)
                .map_err(|error| DriverError::ContactBootstrap(error.to_string()))?,
            None,
            true,
        ),
    };

    let pinned_peer = contact
        .tofu_peer
        .as_ref()
        .map(|pin| {
            let peer = PinnedPeer::new(pin.destination_b64.clone())
                .map_err(|error| DriverError::ContactBootstrap(error.to_string()))?;
            if !peer.b32().eq_ignore_ascii_case(&pin.b32) {
                return Err(DriverError::ContactBootstrap(
                    "stored TOFU destination does not match its b32 address".into(),
                ));
            }
            Ok(peer)
        })
        .transpose()?;

    let (offline, staged_offline, deaddrop) = match &contact.offline {
        Some(persisted) => {
            let identity = contact.identity.as_ref().ok_or_else(|| {
                DriverError::ContactBootstrap(
                    "offline state requires a persistent local identity".into(),
                )
            })?;
            let peer = pinned_peer.as_ref().ok_or_else(|| {
                DriverError::ContactBootstrap("offline state requires a TOFU-pinned peer".into())
            })?;
            let state = persisted
                .restore()
                .map_err(|error| DriverError::ContactBootstrap(error.to_string()))?;
            let coordinator = OfflineCoordinator::new(
                *persisted.shared_secret.expose_secret(),
                &identity.b32,
                peer.b32(),
                state,
            )
            .map_err(|error| DriverError::ContactBootstrap(error.to_string()))?;
            if contact.deaddrop_servers.is_empty() {
                (None, Some(persisted.clone()), None)
            } else {
                let config = DeaddropConfig::new(
                    endpoint,
                    format!("{sam_session_prefix}_drop_{suffix}"),
                    contact.deaddrop_servers.clone(),
                )
                .map_err(|error| DriverError::ContactBootstrap(error.to_string()))?;
                (Some(coordinator), None, Some(DeaddropClient::new(config)))
            }
        }
        None => (None, None, None),
    };

    Ok(ContactBootstrapPlan {
        sam_config,
        expected_b32,
        pinned_peer,
        offline,
        staged_offline,
        deaddrop,
        persist_identity,
    })
}

async fn prepare_contact(
    runtime: SamRuntime,
    plan: ContactBootstrapPlan,
) -> Result<PreparedContact, String> {
    let info = runtime
        .create_session(&plan.sam_config)
        .await
        .map_err(|error| error.to_string())?;
    if plan
        .expected_b32
        .as_ref()
        .is_some_and(|expected| !expected.eq_ignore_ascii_case(&info.b32))
    {
        return Err("SAM initialized a different identity than the stored contact identity".into());
    }
    let session = build_contact_protocol_session(&info, plan.pinned_peer)?;
    let identity = if plan.persist_identity {
        Some(
            PersistentIdentity::new(info.private_destination.clone(), info.b32.clone())
                .map_err(|error| error.to_string())?,
        )
    } else {
        None
    };
    Ok(PreparedContact {
        info,
        session,
        offline: plan.offline,
        staged_offline: plan.staged_offline,
        deaddrop: plan.deaddrop,
        identity,
    })
}

async fn prepare_transient(
    runtime: SamRuntime,
    transient_id: &TransientId,
    default_tunnels: TunnelSettings,
    sam_session_prefix: &str,
) -> Result<PreparedTransient, String> {
    let session_name = transient_id
        .as_str()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .take(64)
        .collect::<String>();
    let config = SamSessionConfig::transient(
        format!(
            "{sam_session_prefix}_transient_{session_name}_{}",
            now_epoch_millis()
        ),
        TunnelOptions::new(default_tunnels.length, default_tunnels.quantity)
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let info = runtime
        .create_session(&config)
        .await
        .map_err(|error| error.to_string())?;
    let session = build_contact_protocol_session(&info, None)?;
    Ok(PreparedTransient { info, session })
}

fn build_contact_protocol_session(
    info: &SamSessionInfo,
    pinned_peer: Option<PinnedPeer>,
) -> Result<OneToOneSession, String> {
    let config = OneToOneConfig::new(info.public_destination.clone(), pinned_peer)
        .map_err(|error| error.to_string())?
        .with_control_message_seed(now_epoch_millis());
    Ok(OneToOneSession::new(config))
}

fn opened_session_id(
    output: &ApplicationOutput,
    expected: ResourceKind,
) -> Result<SessionId, DriverError> {
    output
        .events
        .iter()
        .find_map(|event| match (event, expected) {
            (
                ApplicationEvent::SessionOpened {
                    session_id,
                    key: ManagedSessionKey::Contact(_),
                },
                ResourceKind::Contact,
            )
            | (
                ApplicationEvent::SessionOpened {
                    session_id,
                    key: ManagedSessionKey::Transient(_),
                },
                ResourceKind::Transient,
            )
            | (
                ApplicationEvent::SessionOpened {
                    session_id,
                    key: ManagedSessionKey::Group(_),
                },
                ResourceKind::Group,
            ) => Some(*session_id),
            _ => None,
        })
        .ok_or(DriverError::MissingSessionOpenedEvent)
}

fn validate_transport(transport: &SessionTransport) -> Result<(), DriverError> {
    if transport.runtime.is_closing() || transport.runtime.is_closed() {
        return Err(DriverError::RuntimeUnavailable);
    }
    Ok(())
}

fn now_epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn current_utc_hms() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        % 86_400;
    format!(
        "{:02}:{:02}:{:02} UTC",
        seconds / 3_600,
        (seconds % 3_600) / 60,
        seconds % 60
    )
}

fn merge_text_warning(mut event: TextReceivedEvent, warnings: Vec<String>) -> TextReceivedEvent {
    if !warnings.is_empty() {
        let warning = warnings.join("; ");
        event.warning = Some(match event.warning.take() {
            Some(existing) => format!("{existing}; {warning}"),
            None => warning,
        });
    }
    event
}

fn translate_file_transfer_event(
    session_id: SessionId,
    event: CoreFileTransferEvent,
) -> FileTransferEvent {
    let direction = |direction| match direction {
        CoreFileTransferDirection::Sent => FileTransferDirection::Sent,
        CoreFileTransferDirection::Received => FileTransferDirection::Received,
    };
    match event {
        CoreFileTransferEvent::Offered {
            transfer_id,
            direction: value,
            filename,
            total_bytes,
        } => FileTransferEvent::Offered {
            session_id,
            transfer_id,
            direction: direction(value),
            filename,
            total_bytes,
        },
        CoreFileTransferEvent::Started {
            transfer_id,
            direction: value,
            filename,
            total_bytes,
        } => FileTransferEvent::Started {
            session_id,
            transfer_id,
            direction: direction(value),
            filename,
            total_bytes,
        },
        CoreFileTransferEvent::Progress {
            transfer_id,
            direction: value,
            transferred_bytes,
            total_bytes,
        } => FileTransferEvent::Progress {
            session_id,
            transfer_id,
            direction: direction(value),
            transferred_bytes,
            total_bytes,
        },
        CoreFileTransferEvent::Completed {
            transfer_id,
            direction: value,
            filename,
            total_bytes,
            path,
        } => FileTransferEvent::Completed {
            session_id,
            transfer_id,
            direction: direction(value),
            filename,
            total_bytes,
            path,
        },
        CoreFileTransferEvent::Declined {
            transfer_id,
            direction: value,
            filename,
        } => FileTransferEvent::Declined {
            session_id,
            transfer_id,
            direction: direction(value),
            filename,
        },
        CoreFileTransferEvent::Cancelled {
            transfer_id,
            direction: value,
            filename,
        } => FileTransferEvent::Cancelled {
            session_id,
            transfer_id,
            direction: direction(value),
            filename,
        },
        CoreFileTransferEvent::Expired {
            transfer_id,
            direction: value,
            filename,
        } => FileTransferEvent::Expired {
            session_id,
            transfer_id,
            direction: direction(value),
            filename,
        },
        CoreFileTransferEvent::Failed {
            transfer_id,
            direction: value,
            filename,
            reason,
        } => FileTransferEvent::Failed {
            session_id,
            transfer_id,
            direction: direction(value),
            filename,
            reason,
        },
    }
}

fn translate_rendezvous_event(
    session_id: SessionId,
    event: commtools_core::RendezvousEvent,
) -> RendezvousSessionEvent {
    match event {
        commtools_core::RendezvousEvent::OutgoingAuthenticated { peer_b32, .. } => {
            RendezvousSessionEvent::OutgoingAuthenticated {
                session_id,
                peer_b32,
            }
        }
        commtools_core::RendezvousEvent::IncomingAuthenticated { peer_b32, .. } => {
            RendezvousSessionEvent::IncomingAuthenticated {
                session_id,
                peer_b32,
            }
        }
        commtools_core::RendezvousEvent::InvitationConsumed { peer_b32, .. } => {
            RendezvousSessionEvent::InvitationConsumed {
                session_id,
                peer_b32,
            }
        }
        commtools_core::RendezvousEvent::AuthenticationRejected {
            peer_b32, reason, ..
        } => RendezvousSessionEvent::AuthenticationRejected {
            session_id,
            peer_b32,
            reason,
        },
    }
}

fn translate_offline_event(
    session_id: SessionId,
    event: commtools_core::OfflineCoordinatorEvent,
) -> OfflineSessionEvent {
    use commtools_core::OfflineCoordinatorEvent as CoreEvent;

    match event {
        CoreEvent::ModeChanged(mode) => OfflineSessionEvent::ModeChanged { session_id, mode },
        CoreEvent::SendStarted {
            message_id, index, ..
        } => OfflineSessionEvent::SendStarted {
            session_id,
            message_id,
            index,
        },
        CoreEvent::SendConfirmed {
            message_id,
            index,
            successful_servers,
            ..
        } => OfflineSessionEvent::SendConfirmed {
            session_id,
            message_id,
            index,
            successful_drop_count: successful_servers.len(),
        },
        CoreEvent::SendFailed {
            message_id,
            index,
            reason,
        } => OfflineSessionEvent::SendFailed {
            session_id,
            message_id,
            index,
            reason,
        },
        CoreEvent::FrameReceived { index, frame, .. } => {
            OfflineSessionEvent::UnsupportedFrameReceived {
                session_id,
                index,
                frame_type: format!("{:?}", frame.message_type),
            }
        }
        CoreEvent::BlobRejected { index, reason, .. } => OfflineSessionEvent::BlobRejected {
            session_id,
            index,
            reason,
        },
        CoreEvent::PollTargetFailed { index, reason } => OfflineSessionEvent::PollTargetFailed {
            session_id,
            index,
            reason,
        },
        CoreEvent::PollSweepStarted { .. } => OfflineSessionEvent::PollSweepStarted { session_id },
        CoreEvent::PollSweepCompleted { observations, .. } => {
            let result = if observations.iter().any(|observation| {
                observation.outcome == commtools_core::offline::OfflinePollOutcome::Authenticated
            }) {
                OfflinePollResult::Hit
            } else if !observations.is_empty()
                && observations.iter().all(|observation| {
                    observation.outcome
                        == commtools_core::offline::OfflinePollOutcome::ConfirmedMiss
                })
            {
                OfflinePollResult::Miss
            } else {
                OfflinePollResult::Failed
            };
            OfflineSessionEvent::PollSweepCompleted {
                session_id,
                result,
                observation_count: observations.len(),
            }
        }
        CoreEvent::IndexSyncSent { .. } => OfflineSessionEvent::IndexSyncSent { session_id },
        CoreEvent::IndexSyncSendFailed { reason, .. } => {
            OfflineSessionEvent::IndexSyncSendFailed { session_id, reason }
        }
        CoreEvent::IndexSyncApplied { .. } => OfflineSessionEvent::IndexSyncApplied { session_id },
        CoreEvent::ShutdownComplete => OfflineSessionEvent::ShutdownComplete { session_id },
    }
}

fn contact_sam_session_suffix(display_name: &str, unix_millis: u64) -> String {
    const MAX_CONTACT_LABEL_LEN: usize = 80;

    let label = display_name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .take(MAX_CONTACT_LABEL_LEN)
        .collect::<String>();
    format!("{label}_{unix_millis}")
}

fn group_sam_session_suffix(group: &GroupRecord, unix_millis: u64) -> String {
    let source = group
        .identity
        .as_ref()
        .map(|identity| identity.b32.as_str())
        .unwrap_or_else(|| group.id.as_str())
        .trim_end_matches(".b32.i2p");
    let label = source
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>();
    let compact = if label.len() > 12 {
        format!("{}_{}", &label[..6], &label[label.len() - 6..])
    } else if label.is_empty() {
        "group".to_string()
    } else {
        label
    };
    format!("{compact}_{unix_millis}")
}

fn collect_group_protocol_events(events: &[ApplicationEvent]) -> Vec<GroupProtocolEvent> {
    events
        .iter()
        .filter_map(|event| match event {
            ApplicationEvent::Group {
                event:
                    CoreGroupSessionEvent::SecureSessionReady {
                        peer_b32,
                        authorized,
                        ..
                    },
                ..
            } => Some(GroupProtocolEvent::Ready {
                peer_b32: peer_b32.clone(),
                authorized: *authorized,
            }),
            ApplicationEvent::Group {
                event: CoreGroupSessionEvent::ControlReceived { peer_b32, control },
                ..
            } => Some(GroupProtocolEvent::Control {
                peer_b32: peer_b32.clone(),
                control: control.clone(),
            }),
            ApplicationEvent::Group {
                event: CoreGroupSessionEvent::RosterReceived { peer_b32, roster },
                ..
            } => Some(GroupProtocolEvent::Roster {
                peer_b32: peer_b32.clone(),
                roster: roster.clone(),
            }),
            ApplicationEvent::Group {
                event:
                    CoreGroupSessionEvent::DissolutionReceived {
                        peer_b32,
                        dissolution,
                    },
                ..
            } => Some(GroupProtocolEvent::Dissolution {
                peer_b32: peer_b32.clone(),
                dissolution: dissolution.clone(),
            }),
            _ => None,
        })
        .collect()
}

fn same_b32(left: &str, right: &str) -> bool {
    let normalize = |value: &str| {
        value
            .trim()
            .to_ascii_lowercase()
            .trim_end_matches(".b32.i2p")
            .to_string()
    };
    normalize(left) == normalize(right)
}

fn remove_group_member_and_invites(
    group: &mut GroupRecord,
    member_b32: &str,
) -> Result<bool, GroupRosterError> {
    if !remove_member(group, member_b32)? {
        return Ok(false);
    }
    group.issued_invites.retain(|invite| {
        invite
            .redeemed_b32
            .as_deref()
            .is_none_or(|redeemed| !same_b32(redeemed, member_b32))
    });
    Ok(true)
}

fn image_mime_for_path(path: &Path) -> Result<&'static str, DriverError> {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| DriverError::InvalidImageFile("image filename has no extension".into()))?;
    match extension.as_str() {
        "png" => Ok("image/png"),
        "jpg" | "jpeg" => Ok("image/jpeg"),
        "gif" => Ok("image/gif"),
        "bmp" => Ok("image/bmp"),
        "webp" => Ok("image/webp"),
        _ => Err(DriverError::InvalidImageFile(format!(
            "unsupported image extension: {extension}"
        ))),
    }
}

fn load_image_path(
    path: &Path,
    max_bytes: usize,
    description: &str,
) -> Result<GroupImageData, DriverError> {
    let metadata = fs::metadata(path).map_err(|source| DriverError::ImageIo {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(DriverError::InvalidImageFile(
            "image path does not identify a regular file".into(),
        ));
    }
    if metadata.len() == 0 || metadata.len() > max_bytes as u64 {
        return Err(DriverError::InvalidImageFile(format!(
            "{description} must contain 1 to {max_bytes} bytes"
        )));
    }
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| DriverError::InvalidImageFile("image filename is invalid".into()))?;
    let mime = image_mime_for_path(path)?;
    let mut file = File::open(path).map_err(|source| DriverError::ImageIo {
        path: path.to_path_buf(),
        source,
    })?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| DriverError::ImageIo {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(DriverError::InvalidImageFile(format!(
            "{description} must contain 1 to {max_bytes} bytes"
        )));
    }
    validate_image_bytes(mime, &bytes)
        .map_err(|error| DriverError::InvalidImageFile(error.to_string()))?;
    Ok(GroupImageData {
        filename: sanitize_image_filename(filename),
        mime: mime.into(),
        bytes,
    })
}

fn history_scope(
    vault: &UnlockedVault,
    key: &ManagedSessionKey,
) -> Result<HistoryScope, DriverError> {
    match key {
        ManagedSessionKey::Contact(contact_id) => vault
            .snapshot()
            .contacts
            .get(contact_id)
            .map(|contact| HistoryScope::Contact(contact.display_name.clone()))
            .ok_or_else(|| DriverError::ContactNotFound(contact_id.clone())),
        ManagedSessionKey::Transient(_) => Err(DriverError::TransientHistoryUnavailable),
        ManagedSessionKey::Group(group_id) => vault
            .snapshot()
            .groups
            .get(group_id)
            .map(|group| HistoryScope::Group(group_storage_key(&group.id)))
            .ok_or_else(|| DriverError::GroupNotFound(group_id.clone())),
    }
}

#[derive(Debug, Error)]
pub enum DriverError {
    #[error(transparent)]
    Coordinator(#[from] ApplicationCoordinatorError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    History(#[from] HistoryError),
    #[error("application shutdown has already started")]
    ApplicationStopping,
    #[error("close all chat sessions before changing the SAM endpoint")]
    SamEndpointRequiresNoSessions,
    #[error("a manual SAM test is already running")]
    SamTestPending,
    #[error("contact is already open: {0}")]
    ContactAlreadyOpen(ContactId),
    #[error("contact is already being opened: {0}")]
    ContactOpenPending(ContactId),
    #[error("contact is missing from the unlocked vault: {0}")]
    ContactNotFound(ContactId),
    #[error("contact session is missing: {0}")]
    ContactSessionNotFound(SessionId),
    #[error("contact is already locked: {0}")]
    ContactAlreadyLocked(ContactId),
    #[error("contact is already unlocked: {0}")]
    ContactAlreadyUnlocked(ContactId),
    #[error("close the contact session before changing its stored peer: {0}")]
    ContactTrustRequiresClosed(ContactId),
    #[error("close the contact session before changing its deaddrop servers: {0}")]
    ContactDeaddropRequiresClosed(ContactId),
    #[error("close the contact session before changing its tunnel settings: {0}")]
    ContactTunnelsRequireClosed(ContactId),
    #[error("close the contact session before renaming it: {0}")]
    ContactRenameRequiresClosed(ContactId),
    #[error("close the contact session before deleting it: {0}")]
    ContactDeleteRequiresClosed(ContactId),
    #[error("close the contact session before resetting it: {0}")]
    ContactResetRequiresClosed(ContactId),
    #[error("close the contact session before exporting it: {0}")]
    ContactBackupRequiresClosed(ContactId),
    #[error("close the conflicting contact session before replacing it: {0}")]
    ContactImportRequiresClosed(ContactId),
    #[error("deaddrop server is already configured: {0}")]
    ContactDeaddropAlreadyConfigured(String),
    #[error("deaddrop server is not configured: {0}")]
    ContactDeaddropNotConfigured(String),
    #[error("a contact must retain at least one deaddrop server")]
    ContactRequiresDeaddropServer,
    #[error("deaddrop server limit reached: {MAX_DEADDROP_SERVERS}")]
    ContactDeaddropLimit,
    #[error("contact session initialization failed: {0}")]
    ContactBootstrap(String),
    #[error("transient session is already being opened: {0}")]
    TransientOpenPending(TransientId),
    #[error("transient sessions cannot retain history")]
    TransientHistoryUnavailable,
    #[error("group is already open: {0}")]
    GroupAlreadyOpen(GroupId),
    #[error("group is already being opened: {0}")]
    GroupOpenPending(GroupId),
    #[error("group is missing from the unlocked vault: {0}")]
    GroupNotFound(GroupId),
    #[error("close the group before deleting it: {0}")]
    GroupDeleteRequiresClosed(GroupId),
    #[error("close the group before exporting it: {0}")]
    GroupBackupRequiresClosed(GroupId),
    #[error("close the conflicting group session before replacing it: {0}")]
    GroupImportRequiresClosed(GroupId),
    #[error("open the group before requesting an authoritative leave: {0}")]
    GroupLeaveRequiresOpen(GroupId),
    #[error("the group owner is not connected; only a local leave is currently possible: {0}")]
    GroupOwnerNotReady(GroupId),
    #[error("a group leave operation is already pending: {0}")]
    GroupLeavePending(GroupId),
    #[error("close the group before changing its invitations: {0}")]
    GroupInviteRequiresClosed(GroupId),
    #[error("a public invite cannot be imported over a locally owned group: {0}")]
    GroupInviteTargetsOwnedGroup(GroupId),
    #[error("public invite group identifier conflicts with an existing group: {0}")]
    GroupInviteIdConflict(GroupId),
    #[error("group session initialization failed: {0}")]
    GroupBootstrap(String),
    #[error(transparent)]
    GroupRoster(#[from] GroupRosterError),
    #[error(transparent)]
    PrivateGroupInvite(#[from] PrivateGroupInviteError),
    #[error("no pending private group request matches response {0}")]
    PrivateGroupRequestNotFound(String),
    #[error("session resources are missing: {0}")]
    MissingResources(SessionId),
    #[error("session resources have the wrong kind: {0}")]
    WrongResourceKind(SessionId),
    #[error("deaddrop resources are missing: {0}")]
    MissingDeaddrop(SessionId),
    #[error("offline coordinator and deaddrop resources must be attached together")]
    OfflineResourceMismatch,
    #[error("SAM runtime is already closing or closed")]
    RuntimeUnavailable,
    #[error("SAM session initialization failed: {0}")]
    SamInitialization(String),
    #[error("protocol identity does not match the initialized SAM identity")]
    SamIdentityMismatch,
    #[error("session is not open: {0}")]
    SessionNotOpen(SessionId),
    #[error("live connection {connection_id} is missing for session {session_id}")]
    MissingConnection {
        session_id: SessionId,
        connection_id: ConnectionId,
    },
    #[error("coordinator did not emit the expected session-opened event")]
    MissingSessionOpenedEvent,
    #[error("offline persistence action bypassed the application coordinator")]
    UnexpectedOfflinePersistenceAction,
    #[error("connection identifier counter is exhausted")]
    ConnectionIdExhausted,
    #[error("unlocked vault is unavailable")]
    VaultUnavailable,
    #[error("close all chat sessions before backup, restore, or wipe")]
    StorageOperationRequiresNoSessions,
    #[error("vault passphrase does not match")]
    VaultPassphraseMismatch,
    #[error("local record identifier counter is exhausted")]
    RecordIdExhausted,
    #[error("record mutation failed: {0}")]
    RecordMutation(String),
    #[error("invalid image file: {0}")]
    InvalidImageFile(String),
    #[error("inline images require a live secure session: {0}")]
    ImageRequiresLiveSession(SessionId),
    #[error("original image {media_id} is not available in session {session_id}")]
    OriginalImageNotAvailable {
        session_id: SessionId,
        media_id: u64,
    },
    #[error("group original-image requests require the sender b32 address")]
    OriginalImageGroupSenderRequired,
    #[error("original image {media_id} is not pending in session {session_id}")]
    OriginalImageRequestNotPending {
        session_id: SessionId,
        media_id: u64,
    },
    #[error("invalid text message: {0}")]
    InvalidTextMessage(String),
    #[error("invalid file transfer: {0}")]
    InvalidFileTransfer(String),
    #[error("a file transfer is already active for session {0}")]
    FileTransferAlreadyActive(SessionId),
    #[error("file transfer {transfer_id} is not pending for session {session_id}")]
    FileTransferNotFound {
        session_id: SessionId,
        transfer_id: u64,
    },
    #[error("file I/O error at {path}: {source}")]
    FileIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("image I/O error at {path}: {source}")]
    ImageIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error("send worker is closed for connection {connection_id} in session {session_id}")]
    SendWorkerClosed {
        session_id: SessionId,
        connection_id: ConnectionId,
    },
    #[error("send queue is full for connection {connection_id} in session {session_id}")]
    SendQueueFull {
        session_id: SessionId,
        connection_id: ConnectionId,
    },
    #[error("a Tokio runtime is required to execute asynchronous work")]
    NoTokioRuntime,
    #[error("runtime completion channel is closed")]
    CompletionChannelClosed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use commtools_core::one_to_one::OneToOneConfig;
    use commtools_core::sam::destination_to_b32;
    use commtools_core::vault::{
        MIN_ARGON2_ITERATIONS, MIN_ARGON2_MEMORY_KIB, VaultKdfParams, VaultRepository,
    };
    use commtools_core::{GroupMemberRecord, SamSessionKind, TofuPeerPin};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    const ALICE_DESTINATION: &str = "YWJj";
    const BOB_DESTINATION: &str = "ZGVm";
    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn driver_config_validates_frontend_sam_session_prefixes() {
        let config = ApplicationDriverConfig::new("deskcomm").expect("valid prefix");
        assert_eq!(config.sam_session_prefix(), "deskcomm");
        assert!(ApplicationDriverConfig::new("deskcomm client").is_err());
        assert!(ApplicationDriverConfig::new("").is_err());
    }

    #[test]
    fn contact_bootstrap_uses_the_configured_frontend_prefix() {
        let contact = ContactRecord::new(
            ContactId::new("deskcomm-test").expect("contact id"),
            "DeskComm Test",
        )
        .expect("contact");
        let plan =
            build_contact_bootstrap_plan_with_prefix(&contact, SamEndpoint::default(), "deskcomm")
                .expect("bootstrap plan");

        assert!(plan.sam_config.session_id().starts_with("deskcomm_chat_"));
    }

    #[test]
    fn post_lock_tick_skips_maintenance_that_requires_the_unlocked_vault() {
        let temp = TestDirectory::new("post-lock-maintenance");
        let repository = test_vault_repository(temp.path());
        let vault = repository.create(b"test passphrase").expect("create vault");
        let mut driver = ApplicationDriver::new(vault);

        driver.begin_shutdown().expect("lock idle driver");
        assert_eq!(driver.application_phase(), ApplicationPhase::Stopped);
        assert!(driver.vault().is_none());

        driver
            .tick()
            .expect("post-lock tick must not access the removed vault");
    }

    #[test]
    fn cooperative_image_sender_stops_before_the_next_frame_when_cancelled() {
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let key = OriginalImageKey {
            session_id: SessionId::new(71),
            media_id: 7001,
            sender_b32: String::new(),
        };
        let mut image = OutgoingImageSend::new(
            vec![
                Frame::new(MessageType::J, 81, b"header".to_vec()),
                Frame::new(MessageType::G, 81, b"chunk".to_vec()),
                Frame::new(MessageType::Z, 81, Vec::new()),
            ],
            Some(cancel.clone()),
            SendCompletion::OriginalImage {
                key,
                cancel: cancel.clone(),
            },
            "test original image",
        );

        assert!(matches!(
            image.next_frame(),
            ImageSendStep::Frame(Frame {
                message_type: MessageType::J,
                ..
            })
        ));
        cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(image.next_frame(), ImageSendStep::Cancelled));
        assert_eq!(image.frames.len(), 2);
    }

    #[test]
    fn image_sequences_keep_fifo_queue_order() {
        let first = OutgoingImageSend::new(
            vec![Frame::new(MessageType::J, 1, Vec::new())],
            None,
            SendCompletion::None,
            "first image",
        );
        let second = OutgoingImageSend::new(
            vec![Frame::new(MessageType::J, 2, Vec::new())],
            None,
            SendCompletion::None,
            "second image",
        );
        let mut active = Some(first);
        let mut queued = VecDeque::from([second]);

        assert_eq!(
            active
                .as_ref()
                .and_then(|image| image.frames.front())
                .map(|frame| frame.message_id),
            Some(1)
        );
        active = queued.pop_front();
        assert_eq!(
            active
                .as_ref()
                .and_then(|image| image.frames.front())
                .map(|frame| frame.message_id),
            Some(2)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn queued_control_work_preempts_a_future_bulk_send_slot() {
        let (_priority_tx, mut priority_rx) = mpsc::channel(1);
        let (tx, mut rx) = mpsc::channel(1);
        tx.send(SendJob::Sequence {
            destination_prelude: None,
            frames: vec![Frame::new(MessageType::D, 91, Vec::new())],
            completion: SendCompletion::None,
            operation: "test priority control",
        })
        .await
        .expect("queue control frame");

        let wake = wait_for_send_work(
            &mut priority_rx,
            &mut rx,
            true,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await;
        assert!(matches!(
            wake,
            SendWorkerWake::Job(SendJob::Sequence {
                operation: "test priority control",
                ..
            })
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn queued_heartbeat_preempts_ordinary_work() {
        let (priority_tx, mut priority_rx) = mpsc::channel(1);
        let (normal_tx, mut normal_rx) = mpsc::channel(1);
        normal_tx
            .send(SendJob::Sequence {
                destination_prelude: None,
                frames: vec![Frame::new(MessageType::U, 91, b"message".to_vec())],
                completion: SendCompletion::None,
                operation: "test ordinary frame",
            })
            .await
            .expect("queue ordinary frame");
        priority_tx
            .send(SendJob::Sequence {
                destination_prelude: None,
                frames: vec![Frame::new(
                    MessageType::S,
                    92,
                    format!("{HEARTBEAT_PING_PREFIX}000000000000005c"),
                )],
                completion: SendCompletion::None,
                operation: "test heartbeat frame",
            })
            .await
            .expect("queue heartbeat frame");

        let wake = wait_for_send_work(
            &mut priority_rx,
            &mut normal_rx,
            false,
            tokio::time::Instant::now(),
        )
        .await;
        assert!(matches!(
            wake,
            SendWorkerWake::Job(SendJob::Sequence {
                operation: "test heartbeat frame",
                ..
            })
        ));
    }

    #[test]
    fn only_heartbeat_ping_and_pong_jobs_use_the_priority_queue() {
        for prefix in [HEARTBEAT_PING_PREFIX, HEARTBEAT_PONG_PREFIX] {
            let job = SendJob::Sequence {
                destination_prelude: None,
                frames: vec![Frame::new(
                    MessageType::S,
                    1,
                    format!("{prefix}0000000000000001"),
                )],
                completion: SendCompletion::None,
                operation: "test heartbeat classification",
            };
            assert!(job.is_heartbeat());
        }

        let quit = SendJob::Sequence {
            destination_prelude: None,
            frames: vec![Frame::new(MessageType::S, 2, "__SIGNAL__:QUIT")],
            completion: SendCompletion::None,
            operation: "test signal classification",
        };
        let message = SendJob::Sequence {
            destination_prelude: None,
            frames: vec![Frame::new(MessageType::U, 3, b"message".to_vec())],
            completion: SendCompletion::None,
            operation: "test message classification",
        };
        assert!(!quit.is_heartbeat());
        assert!(!message.is_heartbeat());
    }

    #[test]
    fn accepted_file_sender_uses_the_negotiated_transfer_id() {
        let temp = TestDirectory::new("incremental-file-sender");
        let path = temp.path().join("payload.bin");
        let bytes = (0..FILE_TRANSFER_CHUNK_BYTES + 17)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        fs::write(&path, &bytes).expect("write source file");
        let (sender, receiver) = ready_one_to_one_pair();
        let mut transfer = OutgoingFileSend::new(
            7,
            "payload.bin".into(),
            bytes.len() as u64,
            File::open(path).expect("open source file"),
            sender.file_frame_sealer().expect("file sealer"),
        );

        let mut reconstructed = Vec::new();
        let mut frame_types = Vec::new();
        loop {
            let step = transfer.next_step().expect("file step");
            frame_types.push(step.frame.message_type);
            assert_eq!(step.frame.message_id, 7);
            let opened = receiver
                .open_application_frame(&step.frame)
                .expect("open file frame");
            if step.frame.message_type == MessageType::C {
                reconstructed.extend(
                    BASE64
                        .decode(opened.payload.as_slice())
                        .expect("decode chunk"),
                );
            }
            if step.finished {
                assert_eq!(step.frame.message_type, MessageType::E);
                assert!(opened.payload.is_empty());
                break;
            }
        }

        assert_eq!(reconstructed, bytes);
        assert_eq!(
            frame_types,
            [MessageType::C, MessageType::C, MessageType::E]
        );
    }

    #[test]
    fn incoming_file_offer_waits_for_explicit_acceptance_without_creating_a_file() {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let session_id = SessionId::new(81);

        driver.begin_incoming_file_offer(
            session_id,
            ConnectionId::new(4),
            7004,
            "notes.txt".into(),
            42,
        );

        assert!(driver.incoming_files.is_empty());
        assert!(matches!(
            driver.incoming_file_offers.get(&session_id),
            Some(IncomingFileOffer {
                transfer_id: 7004,
                filename,
                total_bytes: 42,
                ..
            }) if filename == "notes.txt"
        ));
        assert!(matches!(
            driver.events.pop_front(),
            Some(ApplicationEvent::FileTransfer {
                session_id: offered_session,
                event: CoreFileTransferEvent::Offered {
                    transfer_id: 7004,
                    direction: CoreFileTransferDirection::Received,
                    filename,
                    total_bytes: 42,
                },
            }) if offered_session == session_id && filename == "notes.txt"
        ));
    }

    #[test]
    fn stale_incoming_file_offer_expires_without_creating_a_file() {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let session_id = SessionId::new(82);
        driver.incoming_file_offers.insert(
            session_id,
            IncomingFileOffer {
                transfer_id: 7005,
                connection_id: ConnectionId::new(5),
                filename: "archive.bin".into(),
                total_bytes: 99,
                offered_ms: 1,
            },
        );

        driver.tick_file_offers(FILE_OFFER_TIMEOUT_MS + 1);

        assert!(!driver.incoming_file_offers.contains_key(&session_id));
        assert!(driver.incoming_files.is_empty());
        assert!(matches!(
            driver.events.pop_front(),
            Some(ApplicationEvent::FileTransfer {
                session_id: expired_session,
                event: CoreFileTransferEvent::Expired {
                    transfer_id: 7005,
                    direction: CoreFileTransferDirection::Received,
                    filename,
                },
            }) if expired_session == session_id && filename == "archive.bin"
        ));
    }

    #[test]
    fn stale_outgoing_file_offer_expires_before_streaming_starts() {
        let temp = TestDirectory::new("outgoing-file-offer-timeout");
        let path = temp.path().join("payload.bin");
        fs::write(&path, b"payload").expect("write source file");
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let session_id = SessionId::new(83);
        driver.outgoing_files.insert(
            session_id,
            OutgoingFileTransfer {
                transfer_id: 7006,
                connection_id: ConnectionId::new(6),
                filename: "payload.bin".into(),
                total_bytes: 7,
                offered_ms: 1,
                file: Some(File::open(path).expect("open source file")),
                sealer: None,
            },
        );

        driver.tick_file_offers(FILE_OFFER_TIMEOUT_MS + 1);

        assert!(!driver.outgoing_files.contains_key(&session_id));
        assert!(matches!(
            driver.events.pop_front(),
            Some(ApplicationEvent::FileTransfer {
                session_id: expired_session,
                event: CoreFileTransferEvent::Expired {
                    transfer_id: 7006,
                    direction: CoreFileTransferDirection::Sent,
                    filename,
                },
            }) if expired_session == session_id && filename == "payload.bin"
        ));
    }

    #[test]
    fn fresh_group_bootstrap_requests_a_transient_identity() {
        let group = GroupRecord::new(
            GroupId::new("fresh-group").expect("group id"),
            "Fresh group",
        )
        .expect("group");
        let plan =
            build_group_bootstrap_plan(&group, TunnelSettings::default()).expect("bootstrap plan");

        assert!(plan.expected_b32.is_none());
        assert!(matches!(plan.sam_config.kind(), SamSessionKind::Transient));
    }

    #[test]
    fn global_settings_are_persisted_and_apply_to_new_contacts() {
        let temp = TestDirectory::new("global-settings");
        let repository = test_vault_repository(&temp.path().join("vault"));
        let vault = repository.create(b"test passphrase").expect("create vault");
        let mut driver = ApplicationDriver::new(vault);

        driver.set_sam_host("localhost").expect("set SAM host");
        driver.set_sam_port(17656).expect("set SAM port");
        driver
            .set_default_tunnel_settings(4, 5)
            .expect("set tunnel defaults");
        driver
            .set_sam_liveness_enabled(true)
            .expect("enable monitoring");
        driver
            .set_sam_failure_action(SamFailureAction::GracefulShutdown)
            .expect("set failure action");
        let contact_id = driver.create_contact("Settings contact").expect("contact");

        let snapshot = driver.vault().expect("vault").snapshot();
        assert_eq!(snapshot.settings.sam_host, "localhost");
        assert_eq!(snapshot.settings.sam_port, 17656);
        assert_eq!(
            snapshot.settings.default_tunnels,
            TunnelSettings {
                length: 4,
                quantity: 5
            }
        );
        assert!(snapshot.settings.sam_liveness_enabled);
        assert_eq!(
            snapshot.settings.sam_failure_action,
            SamFailureAction::GracefulShutdown
        );
        assert_eq!(
            snapshot
                .contacts
                .get(&contact_id)
                .expect("stored contact")
                .tunnels,
            TunnelSettings {
                length: 4,
                quantity: 5
            }
        );
    }

    #[test]
    fn deaddrop_results_update_only_the_owning_contact_profile() {
        let temp = TestDirectory::new("deaddrop-profile-accounting");
        let repository = test_vault_repository(&temp.path().join("vault"));
        let mut vault = repository.create(b"test passphrase").expect("create vault");
        let contact_id = ContactId::new("profiled-contact").expect("contact id");
        let other_id = ContactId::new("other-contact").expect("contact id");
        let servers = (b'a'..=b'd')
            .map(|byte| format!("{}.b32.i2p", char::from(byte).to_string().repeat(52)))
            .collect::<Vec<_>>();
        let mut contact =
            ContactRecord::new(contact_id.clone(), "Profiled").expect("contact record");
        contact.deaddrop_servers = servers.clone();
        let mut other = ContactRecord::new(other_id.clone(), "Other").expect("contact record");
        other.deaddrop_servers = servers.clone();
        vault
            .update(|snapshot| {
                snapshot.contacts.insert(contact_id.clone(), contact);
                snapshot.contacts.insert(other_id.clone(), other);
                Ok(())
            })
            .expect("store contacts");
        let mut driver = ApplicationDriver::new(vault);
        let session = OneToOneSession::new(
            OneToOneConfig::new(ALICE_DESTINATION, None).expect("session config"),
        );
        let session_id = driver
            .open_contact(
                contact_id.clone(),
                session,
                None,
                test_transport(ALICE_DESTINATION),
                None,
            )
            .expect("open contact");
        let result = PutResult {
            status: commtools_core::PutStatus::Stored,
            successful_servers: vec![servers[0].clone()],
            replicas: vec![commtools_core::PutReplicaResult {
                server: servers[0].clone(),
                status: commtools_core::PutReplicaStatus::Stored,
                latency_ms: 125,
                detail: "OK".into(),
            }],
        };

        driver
            .record_deaddrop_put(session_id, &result, 5_000)
            .expect("record profile");

        let snapshot = driver.vault().expect("vault").snapshot();
        let stat = &snapshot.contacts[&contact_id].deaddrop_stats[&servers[0]];
        assert_eq!(stat.put_ok, 1);
        assert_eq!(stat.put_fail, 0);
        assert_eq!(stat.latency_ema_ms, 125.0);
        assert_eq!(stat.last_success_ms, 5_000);
        assert!(snapshot.contacts[&other_id].deaddrop_stats.is_empty());

        let summary = driver
            .snapshot()
            .expect("frontend snapshot")
            .contacts
            .into_iter()
            .find(|contact| contact.id == contact_id)
            .expect("contact summary");
        assert_eq!(summary.deaddrop_profiles.len(), 4);
        assert_eq!(
            summary
                .deaddrop_profiles
                .iter()
                .filter(|server| server.active)
                .count(),
            3
        );
        assert_eq!(summary.deaddrop_profiles[0].address, servers[0]);
        assert_eq!(summary.deaddrop_profiles[0].put_ok, 1);

        let mut vault = driver.vault.take().expect("take vault");
        vault.lock().expect("lock vault");
        let reopened = repository.unlock(b"test passphrase").expect("reopen vault");
        assert_eq!(
            reopened.snapshot().contacts[&contact_id].deaddrop_stats[&servers[0]].put_ok,
            1
        );
    }

    #[test]
    fn deaddrop_operation_selection_keeps_three_active_and_bounds_exploration() {
        let temp = TestDirectory::new("deaddrop-profile-selection");
        let repository = test_vault_repository(&temp.path().join("vault"));
        let mut vault = repository.create(b"test passphrase").expect("create vault");
        let contact_id = ContactId::new("selection-contact").expect("contact id");
        let servers = (b'a'..=b'e')
            .map(|byte| format!("{}.b32.i2p", char::from(byte).to_string().repeat(52)))
            .collect::<Vec<_>>();
        let mut contact =
            ContactRecord::new(contact_id.clone(), "Selection").expect("contact record");
        contact.deaddrop_servers = servers.clone();
        vault
            .update(|snapshot| {
                snapshot.contacts.insert(contact_id.clone(), contact);
                Ok(())
            })
            .expect("store contact");
        let mut driver = ApplicationDriver::new(vault);
        let session = OneToOneSession::new(
            OneToOneConfig::new(ALICE_DESTINATION, None).expect("session config"),
        );
        let session_id = driver
            .open_contact(
                contact_id,
                session,
                None,
                test_transport(ALICE_DESTINATION),
                None,
            )
            .expect("open contact");

        let exploratory = driver
            .deaddrop_operation_servers(session_id)
            .expect("exploratory selection");
        let ordinary = driver
            .deaddrop_operation_servers(session_id)
            .expect("ordinary selection");

        assert_eq!(exploratory[..3], servers[..3]);
        assert_eq!(exploratory.len(), 4);
        assert_eq!(ordinary, servers[..3]);
    }

    #[test]
    fn storage_operations_require_closed_sessions_and_wipe_requires_vault_passphrase() {
        let temp = TestDirectory::new("storage-operation-guards");
        let repository = test_vault_repository(&temp.path().join("vault"));
        let vault = repository.create(b"test passphrase").expect("create vault");
        let mut driver = ApplicationDriver::new(vault);

        assert!(matches!(
            driver.authorize_wipe_all(b"wrong passphrase"),
            Err(DriverError::VaultPassphraseMismatch)
        ));
        driver
            .authorize_wipe_all(b"test passphrase")
            .expect("authorize wipe");

        let contact_id = driver.create_contact("Guarded contact").expect("contact");
        let session = OneToOneSession::new(
            OneToOneConfig::new(ALICE_DESTINATION, None).expect("session config"),
        );
        driver
            .open_contact(
                contact_id,
                session,
                None,
                test_transport(ALICE_DESTINATION),
                None,
            )
            .expect("open contact");
        assert!(matches!(
            driver.authorize_wipe_all(b"test passphrase"),
            Err(DriverError::StorageOperationRequiresNoSessions)
        ));
    }

    #[test]
    fn sam_endpoint_changes_are_rejected_while_a_session_is_pending() {
        let temp = TestDirectory::new("SAM-endpoint-guard");
        let repository = test_vault_repository(&temp.path().join("vault"));
        let vault = repository.create(b"test passphrase").expect("create vault");
        let mut driver = ApplicationDriver::new(vault);
        let contact_id = ContactId::new("pending-contact").expect("contact id");
        driver.pending_contact_opens.insert(
            contact_id,
            PendingContactOpen {
                runtime: SamRuntime::new(SamEndpoint::default()),
                failure: None,
                shutdown_started: false,
            },
        );

        assert!(matches!(
            driver.set_sam_port(17656),
            Err(DriverError::SamEndpointRequiresNoSessions)
        ));
        assert!(matches!(
            driver.set_sam_host("localhost"),
            Err(DriverError::SamEndpointRequiresNoSessions)
        ));
    }

    #[test]
    fn sam_liveness_requires_three_failures_and_recovers_on_success() {
        let temp = TestDirectory::new("SAM-liveness-state");
        let repository = test_vault_repository(&temp.path().join("vault"));
        let vault = repository.create(b"test passphrase").expect("create vault");
        let mut driver = ApplicationDriver::new(vault);

        driver
            .apply_sam_liveness_result(Err("first".into()), 10)
            .expect("first failure");
        assert!(matches!(
            driver.sam_monitor_status(),
            SamMonitorStatus::Degraded {
                consecutive_failures: 1,
                ..
            }
        ));
        driver
            .apply_sam_liveness_result(Err("second".into()), 20)
            .expect("second failure");
        driver
            .apply_sam_liveness_result(Err("third".into()), 30)
            .expect("third failure");
        assert!(matches!(
            driver.sam_monitor_status(),
            SamMonitorStatus::Unavailable { reason } if reason == "third"
        ));
        assert!(!driver.take_sam_liveness_shutdown_request());

        driver
            .apply_sam_liveness_result(Ok(()), 40)
            .expect("successful recovery");
        assert_eq!(driver.sam_monitor_status(), &SamMonitorStatus::Healthy);
        assert_eq!(driver.sam_monitor_consecutive_failures, 0);
    }

    #[test]
    fn unavailable_sam_requests_only_the_configured_graceful_shutdown() {
        let temp = TestDirectory::new("SAM-liveness-shutdown");
        let repository = test_vault_repository(&temp.path().join("vault"));
        let vault = repository.create(b"test passphrase").expect("create vault");
        let mut driver = ApplicationDriver::new(vault);
        driver
            .set_sam_failure_action(SamFailureAction::GracefulShutdown)
            .expect("set failure action");

        for completed_ms in [10, 20, 30] {
            driver
                .apply_sam_liveness_result(Err("router unavailable".into()), completed_ms)
                .expect("probe failure");
        }

        assert!(matches!(
            driver.sam_monitor_status(),
            SamMonitorStatus::Unavailable { .. }
        ));
        assert!(driver.take_sam_liveness_shutdown_request());
        assert!(!driver.take_sam_liveness_shutdown_request());
    }

    #[test]
    fn group_bootstrap_restores_the_persistent_identity() {
        let b32 = destination_to_b32(ALICE_DESTINATION).expect("group b32");
        let mut group = GroupRecord::new(
            GroupId::new("stored-group").expect("group id"),
            "Stored group",
        )
        .expect("group");
        group.identity =
            Some(PersistentIdentity::new(ALICE_DESTINATION, b32.clone()).expect("group identity"));
        let plan =
            build_group_bootstrap_plan(&group, TunnelSettings::default()).expect("bootstrap plan");

        assert_eq!(plan.expected_b32.as_deref(), Some(b32.as_str()));
        assert!(matches!(
            plan.sam_config.kind(),
            SamSessionKind::Persistent { .. }
        ));
    }

    #[test]
    fn fresh_group_initialization_establishes_and_signs_the_owner() {
        let group = GroupRecord::new(GroupId::new("new-owner").expect("group id"), "Owner group")
            .expect("group");
        let info = SamSessionInfo {
            session_id: "group-test".into(),
            private_destination: ALICE_DESTINATION.into(),
            b32: destination_to_b32(ALICE_DESTINATION).expect("group b32"),
            public_destination: ALICE_DESTINATION.into(),
        };
        let (initialized, changed) =
            initialize_group_record(group, &info).expect("initialize group");

        assert!(changed);
        assert_eq!(initialized.owner_b32.as_deref(), Some(info.b32.as_str()));
        assert_eq!(
            initialized
                .identity
                .as_ref()
                .map(|identity| identity.b32.as_str()),
            Some(info.b32.as_str())
        );
        assert!(initialized.roster_signing_secret.is_some());
        assert!(initialized.roster_signing_public_key.is_some());
        assert!(initialized.roster_signature.is_some());
        let config = GroupSessionConfig::from_record_with_local_destination(
            &initialized,
            &info.public_destination,
            1,
        )
        .expect("group config");
        assert_eq!(config.local_b32(), info.b32);
    }

    #[test]
    fn group_sam_session_suffix_compacts_a_persistent_b32() {
        let b32 = destination_to_b32(ALICE_DESTINATION).expect("group b32");
        let mut group =
            GroupRecord::new(GroupId::new("group").expect("group id"), "Group").expect("group");
        group.identity =
            Some(PersistentIdentity::new(ALICE_DESTINATION, b32).expect("group identity"));
        let label = group_sam_session_suffix(&group, 1_785_699_023_123);

        assert!(label.ends_with("_1785699023123"));
        assert_eq!(label.split('_').count(), 3);
    }

    #[test]
    fn fresh_contact_bootstrap_requests_a_transient_identity_once() {
        let contact = ContactRecord::new(
            ContactId::new("fresh").expect("contact id"),
            "Fresh contact",
        )
        .expect("contact");
        let plan =
            build_contact_bootstrap_plan(&contact, SamEndpoint::default()).expect("bootstrap plan");

        assert!(plan.persist_identity);
        assert!(plan.expected_b32.is_none());
        assert!(matches!(plan.sam_config.kind(), SamSessionKind::Transient));
        assert!(plan.offline.is_none());
        assert!(plan.staged_offline.is_none());
        assert!(plan.deaddrop.is_none());
    }

    #[test]
    fn contact_sam_session_suffix_identifies_the_sanitized_contact() {
        assert_eq!(
            contact_sam_session_suffix("Alice Smith", 1_785_699_023_123),
            "Alice_Smith_1785699023123"
        );
    }

    #[test]
    fn contact_protocol_identity_uses_the_public_sam_destination() {
        let public_destination = ALICE_DESTINATION.to_string();
        let info = SamSessionInfo {
            session_id: "contact-test".into(),
            private_destination: "YWJjZGVm".into(),
            b32: destination_to_b32(&public_destination).expect("public b32"),
            public_destination: public_destination.clone(),
        };
        let session = build_contact_protocol_session(&info, None).expect("contact session");

        assert_eq!(session.config().local_destination(), public_destination);
        assert_eq!(session.config().local_b32(), info.b32);
    }

    #[test]
    fn contact_bootstrap_rejects_a_tofu_destination_b32_mismatch() {
        let mut contact = ContactRecord::new(
            ContactId::new("mismatch").expect("contact id"),
            "Mismatched contact",
        )
        .expect("contact");
        let declared_b32 = destination_to_b32("ZGVm").expect("declared b32");
        contact.tofu_peer =
            Some(TofuPeerPin::new(declared_b32, "Z2hp").expect("independently valid stored pin"));

        assert!(matches!(
            build_contact_bootstrap_plan(&contact, SamEndpoint::default()),
            Err(DriverError::ContactBootstrap(reason))
                if reason.contains("does not match")
        ));
    }

    #[test]
    fn contact_bootstrap_restores_the_exact_persisted_tofu_pin() {
        let alice_b32 = destination_to_b32(ALICE_DESTINATION).expect("alice b32");
        let bob_destination = "ZGVm";
        let bob_b32 = destination_to_b32(bob_destination).expect("bob b32");
        let mut contact = ContactRecord::new(
            ContactId::new("locked").expect("contact id"),
            "Locked contact",
        )
        .expect("contact");
        contact.identity = Some(
            PersistentIdentity::new(ALICE_DESTINATION, alice_b32).expect("persistent identity"),
        );
        contact.tofu_peer =
            Some(TofuPeerPin::new(bob_b32.clone(), bob_destination).expect("stored peer pin"));

        let plan =
            build_contact_bootstrap_plan(&contact, SamEndpoint::default()).expect("bootstrap plan");
        let restored = plan.pinned_peer.expect("restored peer pin");
        assert_eq!(restored.b32(), bob_b32);
        assert_eq!(restored.destination(), bob_destination);
        assert!(!plan.persist_identity);
    }

    #[test]
    fn contact_bootstrap_stages_persisted_offline_enrollment_without_servers() {
        let alice_b32 = destination_to_b32(ALICE_DESTINATION).expect("alice b32");
        let bob_destination = "ZGVm";
        let bob_b32 = destination_to_b32(bob_destination).expect("bob b32");
        let mut contact = ContactRecord::new(
            ContactId::new("offline-enrolled").expect("contact id"),
            "Offline enrolled",
        )
        .expect("contact");
        contact.identity = Some(
            PersistentIdentity::new(ALICE_DESTINATION, alice_b32.clone())
                .expect("persistent identity"),
        );
        contact.tofu_peer =
            Some(TofuPeerPin::new(bob_b32.clone(), bob_destination).expect("stored peer pin"));
        contact.offline = Some(
            commtools_core::PersistedOfflineState::new(
                [7; 32],
                &commtools_core::OfflineState::default(),
            )
            .expect("persisted offline state"),
        );
        contact.deaddrop_servers.clear();

        let plan =
            build_contact_bootstrap_plan(&contact, SamEndpoint::default()).expect("bootstrap plan");
        assert!(plan.offline.is_none());
        let staged = plan.staged_offline.expect("staged offline enrollment");
        assert_eq!(staged.restore().expect("restore state").send_index(), 0);
        assert_eq!(staged.restore().expect("restore state").receive_base(), 0);
        assert!(plan.deaddrop.is_none());
    }

    #[test]
    fn contact_bootstrap_attaches_predefined_servers_to_offline_enrollment() {
        let alice_b32 = destination_to_b32(ALICE_DESTINATION).expect("alice b32");
        let bob_destination = "ZGVm";
        let bob_b32 = destination_to_b32(bob_destination).expect("bob b32");
        let mut contact = ContactRecord::new(
            ContactId::new("offline-with-defaults").expect("contact id"),
            "Offline with defaults",
        )
        .expect("contact");
        contact.identity = Some(
            PersistentIdentity::new(ALICE_DESTINATION, alice_b32).expect("persistent identity"),
        );
        contact.tofu_peer =
            Some(TofuPeerPin::new(bob_b32, bob_destination).expect("stored peer pin"));
        contact.offline = Some(
            commtools_core::PersistedOfflineState::new(
                [7; 32],
                &commtools_core::OfflineState::default(),
            )
            .expect("persisted offline state"),
        );

        let plan =
            build_contact_bootstrap_plan(&contact, SamEndpoint::default()).expect("bootstrap plan");
        assert!(plan.offline.is_some());
        assert!(plan.staged_offline.is_none());
        assert_eq!(
            plan.deaddrop.expect("deaddrop client").config().servers(),
            contact.deaddrop_servers.as_slice()
        );
    }

    #[test]
    fn contact_resources_are_registered_under_the_emitted_session() {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let contact_id = ContactId::new("alice").expect("contact id");
        let session = OneToOneSession::new(
            OneToOneConfig::new(ALICE_DESTINATION, None).expect("session config"),
        );
        let transport = test_transport(ALICE_DESTINATION);
        let session_id = driver
            .open_contact(contact_id.clone(), session, None, transport, None)
            .expect("open contact");

        assert!(driver.has_resources(session_id));
        assert_eq!(
            driver.coordinator().session_for_contact(&contact_id),
            Some(session_id)
        );
        assert!(matches!(
            driver.try_next_event().expect("event"),
            Some(ApplicationEvent::SessionOpened {
                session_id: opened,
                key: ManagedSessionKey::Contact(id),
            }) if opened == session_id && id == contact_id
        ));
    }

    #[test]
    fn contact_and_group_history_writes_report_disabled_or_stored() {
        let temp = TestDirectory::new("history-write-outcome");
        let repository = test_vault_repository(&temp.path().join("history"));
        let mut vault = repository.create(b"test passphrase").expect("create vault");
        let contact_id = ContactId::new("history-contact").expect("contact id");
        let group_id = GroupId::new("history-group").expect("group id");
        vault
            .update(|snapshot| {
                snapshot.contacts.insert(
                    contact_id.clone(),
                    ContactRecord::new(contact_id.clone(), "History contact")?,
                );
                snapshot.groups.insert(
                    group_id.clone(),
                    GroupRecord::new(group_id.clone(), "History group")?,
                );
                Ok(())
            })
            .expect("store history records");
        let mut driver = ApplicationDriver::new(vault);
        let record = HistoryRecord {
            created_ms: 1,
            timestamp_utc: "12:00:00 UTC".into(),
            author: "Me".into(),
            sender_b32: None,
            text: "stored text".into(),
            mine: true,
            offline: false,
            msg_id: Some(1),
            delivered: false,
            group_expected_acks: Vec::new(),
            group_received_acks: Vec::new(),
        };

        for key in [
            ManagedSessionKey::Contact(contact_id.clone()),
            ManagedSessionKey::Group(group_id.clone()),
        ] {
            assert_eq!(
                driver
                    .append_history_message(&key, &record)
                    .expect("disabled history outcome"),
                HistoryWriteOutcome::Disabled
            );
            driver
                .set_history_enabled(&key, true)
                .expect("enable history");
            assert_eq!(
                driver
                    .append_history_message(&key, &record)
                    .expect("stored history outcome"),
                HistoryWriteOutcome::Stored
            );
            assert_eq!(driver.load_history(&key).expect("load history").len(), 1);
            driver.clear_history(&key).expect("clear history");
            assert!(
                driver
                    .load_history(&key)
                    .expect("load cleared history")
                    .is_empty()
            );
            assert!(driver.history_enabled(&key).expect("history setting"));
        }
    }

    #[test]
    fn contact_tunnel_settings_are_validated_persisted_and_require_a_closed_contact() {
        let temp = TestDirectory::new("contact-tunnel-settings");
        let repository = test_vault_repository(&temp.path().join("vault"));
        let mut vault = repository.create(b"test passphrase").expect("create vault");
        let contact_id = ContactId::new("tunnel-contact").expect("contact id");
        vault
            .update(|snapshot| {
                snapshot.contacts.insert(
                    contact_id.clone(),
                    ContactRecord::new(contact_id.clone(), "Tunnel contact")?,
                );
                Ok(())
            })
            .expect("store contact");
        let mut driver = ApplicationDriver::new(vault);

        assert_eq!(
            driver
                .set_contact_tunnel_settings(&contact_id, 4, 5)
                .expect("save tunnels"),
            TunnelSettings {
                length: 4,
                quantity: 5,
            }
        );
        assert_eq!(
            driver
                .vault()
                .expect("vault")
                .snapshot()
                .contacts
                .get(&contact_id)
                .expect("contact")
                .tunnels,
            TunnelSettings {
                length: 4,
                quantity: 5,
            }
        );
        assert!(matches!(
            driver.set_contact_tunnel_settings(&contact_id, 0, 5),
            Err(DriverError::RecordMutation(_))
        ));
        let stored_contact = driver
            .vault()
            .expect("vault")
            .snapshot()
            .contacts
            .get(&contact_id)
            .expect("contact")
            .clone();
        let plan = build_contact_bootstrap_plan(&stored_contact, SamEndpoint::default())
            .expect("contact bootstrap plan");
        assert_eq!(
            plan.sam_config.tunnels(),
            TunnelOptions::new(4, 5).expect("tunnel options")
        );

        let session = OneToOneSession::new(
            OneToOneConfig::new(ALICE_DESTINATION, None).expect("session config"),
        );
        let transport = test_transport(ALICE_DESTINATION);
        driver
            .open_contact(contact_id.clone(), session, None, transport, None)
            .expect("open contact");
        assert!(matches!(
            driver.set_contact_tunnel_settings(&contact_id, 2, 3),
            Err(DriverError::ContactTunnelsRequireClosed(id)) if id == contact_id
        ));
    }

    #[test]
    fn contact_rename_preserves_the_record_and_requires_a_closed_contact() {
        let temp = TestDirectory::new("contact-rename");
        let repository = test_vault_repository(&temp.path().join("vault"));
        let mut vault = repository.create(b"test passphrase").expect("create vault");
        let contact_id = ContactId::new("rename-contact").expect("contact id");
        let mut original =
            ContactRecord::new(contact_id.clone(), "Original name").expect("contact record");
        original.history_enabled = true;
        original.tunnels = TunnelSettings {
            length: 4,
            quantity: 5,
        };
        let other_id = ContactId::new("other-contact").expect("contact id");
        vault
            .update(|snapshot| {
                snapshot
                    .contacts
                    .insert(contact_id.clone(), original.clone());
                snapshot.contacts.insert(
                    other_id.clone(),
                    ContactRecord::new(other_id, "Taken name")?,
                );
                Ok(())
            })
            .expect("store contact");
        let mut driver = ApplicationDriver::new(vault);
        let history_record = HistoryRecord {
            created_ms: 1,
            timestamp_utc: "12:00:00 UTC".into(),
            author: "Me".into(),
            sender_b32: None,
            text: "retained across rename".into(),
            mine: true,
            offline: false,
            msg_id: Some(1),
            delivered: false,
            group_expected_acks: Vec::new(),
            group_received_acks: Vec::new(),
        };
        assert_eq!(
            driver
                .append_history_message(
                    &ManagedSessionKey::Contact(contact_id.clone()),
                    &history_record,
                )
                .expect("store contact history"),
            HistoryWriteOutcome::Stored
        );

        assert_eq!(
            driver
                .rename_contact(&contact_id, "Renamed contact")
                .expect("rename contact"),
            "Renamed contact"
        );
        let mut expected = original;
        expected
            .set_display_name("Renamed contact")
            .expect("expected name");
        assert_eq!(
            driver
                .vault()
                .expect("vault")
                .snapshot()
                .contacts
                .get(&contact_id),
            Some(&expected)
        );
        assert_eq!(
            driver
                .load_history(&ManagedSessionKey::Contact(contact_id.clone()))
                .expect("load renamed contact history"),
            vec![history_record.clone()]
        );
        assert_eq!(
            driver
                .rename_contact(&contact_id, "RENAMED CONTACT")
                .expect("rename contact capitalization"),
            "RENAMED CONTACT"
        );
        expected
            .set_display_name("RENAMED CONTACT")
            .expect("expected capitalization");
        assert_eq!(
            driver
                .load_history(&ManagedSessionKey::Contact(contact_id.clone()))
                .expect("load history after capitalization rename"),
            vec![history_record]
        );
        assert!(driver.rename_contact(&contact_id, ".hidden").is_err());
        assert!(driver.rename_contact(&contact_id, "taken NAME").is_err());
        assert_eq!(
            driver
                .vault()
                .expect("vault")
                .snapshot()
                .contacts
                .get(&contact_id),
            Some(&expected)
        );

        let session = OneToOneSession::new(
            OneToOneConfig::new(ALICE_DESTINATION, None).expect("session config"),
        );
        let transport = test_transport(ALICE_DESTINATION);
        driver
            .open_contact(contact_id.clone(), session, None, transport, None)
            .expect("open contact");
        assert!(matches!(
            driver.rename_contact(&contact_id, "Blocked rename"),
            Err(DriverError::ContactRenameRequiresClosed(id)) if id == contact_id
        ));
    }

    #[test]
    fn closed_contact_deletion_removes_its_profile_but_retains_shared_files() {
        let temp = TestDirectory::new("delete-closed-contact");
        let root = temp.path().join("vault");
        let repository = test_vault_repository(&root);
        let mut vault = repository.create(b"test passphrase").expect("create vault");
        let deleted_id = ContactId::new("delete-contact").expect("contact id");
        let retained_id = ContactId::new("retain-contact").expect("contact id");
        let mut deleted =
            ContactRecord::new(deleted_id.clone(), "Delete contact").expect("contact record");
        deleted.history_enabled = true;
        vault
            .update(|snapshot| {
                snapshot.contacts.insert(deleted_id.clone(), deleted);
                snapshot.contacts.insert(
                    retained_id.clone(),
                    ContactRecord::new(retained_id.clone(), "Retain contact")?,
                );
                Ok(())
            })
            .expect("store contacts");
        let shared_file = vault.files_dir().join("retained.bin");
        fs::write(&shared_file, b"retained file").expect("write shared file");
        let mut driver = ApplicationDriver::new(vault);
        let history = HistoryRecord {
            created_ms: 1,
            timestamp_utc: "12:00:00 UTC".into(),
            author: "Me".into(),
            sender_b32: None,
            text: "deleted history".into(),
            mine: true,
            offline: false,
            msg_id: Some(1),
            delivered: false,
            group_expected_acks: Vec::new(),
            group_received_acks: Vec::new(),
        };
        assert_eq!(
            driver
                .append_history_message(&ManagedSessionKey::Contact(deleted_id.clone()), &history,)
                .expect("store contact history"),
            HistoryWriteOutcome::Stored
        );

        let removed = driver.delete_contact(&deleted_id).expect("delete contact");
        let contacts = &driver.vault().expect("vault").snapshot().contacts;

        assert_eq!(removed.id, deleted_id);
        assert!(!contacts.contains_key(&deleted_id));
        assert!(contacts.contains_key(&retained_id));
        assert!(!root.join("profiles").join("Delete contact").exists());
        assert!(root.join("profiles").join("Retain contact").is_dir());
        assert_eq!(
            fs::read(shared_file).expect("read shared file"),
            b"retained file"
        );
    }

    #[test]
    fn active_contact_cannot_be_deleted() {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let contact_id = ContactId::new("active-contact-delete").expect("contact id");
        let session = OneToOneSession::new(
            OneToOneConfig::new(ALICE_DESTINATION, None).expect("session config"),
        );
        driver
            .open_contact(
                contact_id.clone(),
                session,
                None,
                test_transport(ALICE_DESTINATION),
                None,
            )
            .expect("open contact");

        assert!(matches!(
            driver.delete_contact(&contact_id),
            Err(DriverError::ContactDeleteRequiresClosed(id)) if id == contact_id
        ));
    }

    #[test]
    fn transport_end_finalizes_an_already_closed_send_worker() {
        let (mut driver, session_id, connection_id) = driver_with_closed_send_worker();

        driver
            .process_completion(Completion::TransportEnded {
                session_id,
                connection_id,
            })
            .expect("closed worker is already closed");

        assert!(!driver.connection_exists(session_id, connection_id));
        assert!(!driver.connection_is_closing(session_id, connection_id));
        driver
            .process_completion(Completion::ConnectionClosed {
                session_id,
                connection_id,
                operation: None,
                result: Ok(()),
            })
            .expect("duplicate close completion is harmless");
    }

    #[test]
    fn disconnect_notification_finalizes_an_already_closed_send_worker() {
        let (mut driver, session_id, connection_id) = driver_with_closed_send_worker();

        driver
            .schedule_notify_and_close(
                session_id,
                connection_id,
                Frame::new(MessageType::S, 1, "QUIT"),
                100,
                "notify 1:1 disconnect",
            )
            .expect("disconnect from a closed worker is idempotent");

        assert!(!driver.connection_exists(session_id, connection_id));
        assert!(!driver.connection_is_closing(session_id, connection_id));
    }

    #[test]
    fn closed_send_worker_during_protocol_send_is_connection_local() {
        let (mut driver, session_id, connection_id) = driver_with_closed_send_worker();

        driver
            .schedule_send_frame(
                session_id,
                connection_id,
                Frame::new(MessageType::D, 1, "delivered"),
                SendCompletion::None,
                "send test frame",
            )
            .expect("closed worker does not escape as a driver-fatal error");

        assert!(!driver.connection_exists(session_id, connection_id));
        assert!(driver.events.iter().any(|event| matches!(
            event,
            ApplicationEvent::OperationFailed {
                session_id: Some(failed_session),
                operation: "send test frame",
                reason,
            } if *failed_session == session_id && reason.contains("send worker is closed")
        )));
    }

    #[test]
    fn offline_and_deaddrop_resources_cannot_be_split() {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let session = OneToOneSession::new(
            OneToOneConfig::new(ALICE_DESTINATION, None).expect("session config"),
        );
        let transport = test_transport(ALICE_DESTINATION);
        let peer = destination_to_b32("ZGVm").expect("peer b32");
        let local = destination_to_b32(ALICE_DESTINATION).expect("local b32");
        let offline = OfflineCoordinator::new(
            [7; 32],
            &local,
            &peer,
            commtools_core::OfflineState::default(),
        )
        .expect("offline coordinator");

        assert!(matches!(
            driver.open_contact(
                ContactId::new("split").expect("contact id"),
                session,
                Some(offline),
                transport,
                None,
            ),
            Err(DriverError::OfflineResourceMismatch)
        ));
        assert_eq!(driver.coordinator().session_count(), 0);
    }

    #[test]
    fn wrong_session_kind_is_rejected_before_io_is_scheduled() {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let group_id = GroupId::new("group").expect("group id");
        let local = destination_to_b32(ALICE_DESTINATION).expect("local b32");
        let group = GroupSession::new(
            commtools_core::GroupSessionConfig::new(
                ALICE_DESTINATION,
                "Alice",
                "Group",
                local,
                Vec::new(),
            )
            .expect("group config"),
        );
        let transport = test_transport(ALICE_DESTINATION);
        let session_id = driver
            .open_group(group_id, group, transport)
            .expect("open group");

        assert!(matches!(
            driver.enter_contact_offline(session_id),
            Err(DriverError::Coordinator(
                ApplicationCoordinatorError::ExpectedContact(id)
            )) if id == session_id
        ));
        assert_eq!(driver.active_task_count(), 0);
    }

    #[test]
    fn active_owner_group_can_issue_public_and_private_invites() {
        let temp = TestDirectory::new("active-owner-invite-issue");
        let repository = test_vault_repository(&temp.path().join("owner"));
        let mut vault = repository.create(b"test passphrase").expect("create vault");
        let group = initialized_owner_group("invite-group");
        let group_id = group.id.clone();
        let session = GroupSession::new(
            GroupSessionConfig::from_record_with_local_destination(&group, ALICE_DESTINATION, 1)
                .expect("group config"),
        );
        vault
            .update(|snapshot| {
                snapshot.groups.insert(group_id.clone(), group);
                Ok(())
            })
            .expect("store owner group");
        let mut driver = ApplicationDriver::new(vault);
        driver
            .open_group(
                group_id.clone(),
                session,
                test_transport(ALICE_DESTINATION),
            )
            .expect("open group");

        let public_invite = driver
            .issue_public_group_invite(&group_id)
            .expect("issue public invite while active");
        let (_, private_request) =
            generate_request(now_epoch_millis()).expect("generate private request");
        let private_invite = driver
            .issue_private_group_invite(&group_id, &private_request)
            .expect("issue private invite while active");
        let stored = driver
            .vault()
            .expect("vault")
            .snapshot()
            .groups
            .get(&group_id)
            .expect("stored owner group");

        assert!(driver.group_is_active(&group_id));
        assert!(decode_public_invite(&public_invite).is_ok());
        assert!(response_request_id(&private_invite).is_ok());
        assert_eq!(stored.issued_invites.len(), 2);
    }

    #[test]
    fn participant_cannot_issue_public_or_private_invites() {
        let mut owner = initialized_owner_group("participant-invite-rejection");
        let invite = issue_public_invite(&mut owner).expect("issue owner invite");
        let temp = TestDirectory::new("participant-invite-rejection");
        let repository = test_vault_repository(&temp.path().join("participant"));
        let vault = repository
            .create(b"participant passphrase")
            .expect("create participant vault");
        let mut participant = ApplicationDriver::new(vault);
        let group_id = participant
            .import_public_group_invite(&invite)
            .expect("import participant group");
        let (_, private_request) =
            generate_request(now_epoch_millis()).expect("generate private request");

        assert!(matches!(
            participant.issue_public_group_invite(&group_id),
            Err(DriverError::GroupRoster(GroupRosterError::OwnerOnly))
        ));
        assert!(matches!(
            participant.issue_private_group_invite(&group_id, &private_request),
            Err(DriverError::GroupRoster(GroupRosterError::OwnerOnly))
        ));
    }

    #[test]
    fn public_invite_issue_commits_the_owner_token() {
        let temp = TestDirectory::new("public-invite-issue");
        let repository = test_vault_repository(&temp.path().join("owner"));
        let mut vault = repository.create(b"test passphrase").expect("create vault");
        let group = initialized_owner_group("owner-local-id");
        let group_id = group.id.clone();
        vault
            .update(|snapshot| {
                snapshot.groups.insert(group_id.clone(), group);
                Ok(())
            })
            .expect("store owner group");
        let revision_before_issue = vault.snapshot().revision();
        let mut driver = ApplicationDriver::new(vault);

        let encoded = driver
            .issue_public_group_invite(&group_id)
            .expect("issue public invite");
        let decoded = decode_public_invite(&encoded).expect("decode public invite");
        let token = decoded.invite_token.expect("invite token");
        let stored = driver
            .vault()
            .expect("vault")
            .snapshot()
            .groups
            .get(&group_id)
            .expect("stored owner group");

        assert_eq!(stored.issued_invites.len(), 1);
        assert_eq!(stored.issued_invites[0].token.expose_secret(), token);
        assert_eq!(
            driver.vault().expect("vault").snapshot().revision(),
            revision_before_issue + 1
        );
    }

    #[test]
    fn public_invite_import_commits_a_joinable_participant_group() {
        let mut owner = initialized_owner_group("owner-local-id");
        let owner_b32 = owner.owner_b32.clone().expect("owner b32");
        let owner_signing_key = owner
            .roster_signing_public_key
            .clone()
            .expect("owner signing key");
        let encoded = issue_public_invite(&mut owner).expect("issue public invite");
        let expected_token = decode_public_invite(&encoded)
            .expect("decode public invite")
            .invite_token
            .expect("invite token");

        let temp = TestDirectory::new("public-invite-import");
        let repository = test_vault_repository(&temp.path().join("participant"));
        let vault = repository.create(b"test passphrase").expect("create vault");
        let revision_before_import = vault.snapshot().revision();
        let mut driver = ApplicationDriver::new(vault);

        let imported_id = driver
            .import_public_group_invite(&encoded)
            .expect("import public invite");
        let stored = driver
            .vault()
            .expect("vault")
            .snapshot()
            .groups
            .get(&imported_id)
            .expect("stored participant group");

        assert_eq!(imported_id.as_str(), owner_b32);
        assert_eq!(stored.owner_b32.as_deref(), Some(owner_b32.as_str()));
        assert_eq!(
            stored.roster_signing_public_key.as_deref(),
            Some(owner_signing_key.as_str())
        );
        assert_eq!(
            stored
                .join_token
                .as_ref()
                .map(|token| token.expose_secret()),
            Some(expected_token.as_str())
        );
        assert!(stored.identity.is_none());
        assert!(stored.members.iter().any(|member| member.b32 == owner_b32));
        assert_eq!(
            driver.vault().expect("vault").snapshot().revision(),
            revision_before_import + 1
        );
    }

    #[test]
    fn private_invite_round_trip_consumes_only_the_matching_pending_request() {
        let temp = TestDirectory::new("private-invite-round-trip");
        let recipient_repository = test_vault_repository(&temp.path().join("recipient"));
        let recipient_vault = recipient_repository
            .create(b"recipient passphrase")
            .expect("create recipient vault");
        let mut recipient = ApplicationDriver::new(recipient_vault);
        let request = recipient
            .generate_private_group_request()
            .expect("generate private request");
        assert_eq!(
            recipient
                .vault()
                .expect("recipient vault")
                .snapshot()
                .pending_private_group_requests
                .len(),
            1
        );

        let owner_repository = test_vault_repository(&temp.path().join("owner"));
        let mut owner_vault = owner_repository
            .create(b"owner passphrase")
            .expect("create owner vault");
        let group = initialized_owner_group("owner-local-id");
        let group_id = group.id.clone();
        owner_vault
            .update(|snapshot| {
                snapshot.groups.insert(group_id.clone(), group);
                Ok(())
            })
            .expect("store owner group");
        let mut owner = ApplicationDriver::new(owner_vault);
        let response = owner
            .issue_private_group_invite(&group_id, &request)
            .expect("answer private request");

        let imported_id = recipient
            .import_private_group_invite(&response)
            .expect("open private invite");
        let snapshot = recipient.vault().expect("recipient vault").snapshot();
        let imported = snapshot
            .groups
            .get(&imported_id)
            .expect("stored private group");
        assert!(imported.join_token.is_some());
        assert!(imported.private_join_credential.is_some());
        assert!(snapshot.pending_private_group_requests.is_empty());
        assert!(matches!(
            recipient.import_private_group_invite(&response),
            Err(DriverError::PrivateGroupRequestNotFound(_))
        ));
    }

    #[test]
    fn closed_group_deletion_removes_only_the_selected_record_and_history() {
        let temp = TestDirectory::new("delete-closed-group");
        let repository = test_vault_repository(&temp.path().join("owner"));
        let mut vault = repository.create(b"test passphrase").expect("create vault");
        let deleted = initialized_owner_group("delete-me");
        let retained = initialized_owner_group("retain-me");
        let deleted_id = deleted.id.clone();
        let retained_id = retained.id.clone();
        vault
            .update(|snapshot| {
                snapshot.groups.insert(deleted_id.clone(), deleted);
                snapshot.groups.insert(retained_id.clone(), retained);
                Ok(())
            })
            .expect("store groups");
        let mut driver = ApplicationDriver::new(vault);
        let history = HistoryRecord {
            created_ms: 1,
            timestamp_utc: "12:00:00 UTC".into(),
            author: "Alice".into(),
            sender_b32: None,
            text: "retained group text".into(),
            mine: true,
            offline: false,
            msg_id: Some(1),
            delivered: false,
            group_expected_acks: Vec::new(),
            group_received_acks: Vec::new(),
        };
        let deleted_scope = HistoryScope::Group(group_storage_key(&deleted_id));
        let retained_scope = HistoryScope::Group(group_storage_key(&retained_id));
        driver
            .vault()
            .expect("vault")
            .history_repository()
            .expect("history")
            .replace(&deleted_scope, std::slice::from_ref(&history))
            .expect("store deleted group history");
        driver
            .vault()
            .expect("vault")
            .history_repository()
            .expect("history")
            .replace(&retained_scope, std::slice::from_ref(&history))
            .expect("store retained group history");

        let removed = driver.delete_group(&deleted_id).expect("delete group");
        let groups = &driver.vault().expect("vault").snapshot().groups;

        assert_eq!(removed.id, deleted_id);
        assert!(!groups.contains_key(&deleted_id));
        assert!(groups.contains_key(&retained_id));
        assert!(
            driver
                .vault()
                .expect("vault")
                .history_repository()
                .expect("history")
                .load(&deleted_scope)
                .expect("load deleted history")
                .is_empty()
        );
        assert_eq!(
            driver
                .vault()
                .expect("vault")
                .history_repository()
                .expect("history")
                .load(&retained_scope)
                .expect("load retained history"),
            vec![history]
        );
    }

    #[test]
    fn active_group_cannot_be_deleted() {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let group_id = GroupId::new("active-delete").expect("group id");
        let local = destination_to_b32(ALICE_DESTINATION).expect("local b32");
        let group = GroupSession::new(
            GroupSessionConfig::new(
                ALICE_DESTINATION,
                "Alice",
                "Active group",
                local,
                Vec::new(),
            )
            .expect("group config"),
        );
        driver
            .open_group(group_id.clone(), group, test_transport(ALICE_DESTINATION))
            .expect("open group");

        assert!(matches!(
            driver.delete_group(&group_id),
            Err(DriverError::GroupDeleteRequiresClosed(id)) if id == group_id
        ));
    }

    #[test]
    fn owner_member_removal_persists_a_new_signed_roster() {
        let temp = TestDirectory::new("remove-group-member");
        let repository = test_vault_repository(&temp.path().join("owner"));
        let mut vault = repository.create(b"test passphrase").expect("create vault");
        let mut group = initialized_owner_group("remove-member");
        let member_b32 = destination_to_b32("ZGVm").expect("member b32");
        group.members.push(GroupMemberRecord {
            name: "Bob".into(),
            b32: member_b32.clone(),
        });
        sign_owner_roster(&mut group).expect("sign roster with member");
        let group_id = group.id.clone();
        let previous_version = group.roster_version;
        let previous_signature = group.roster_signature.clone();
        vault
            .update(|snapshot| {
                snapshot.groups.insert(group_id.clone(), group);
                Ok(())
            })
            .expect("store group");
        let mut driver = ApplicationDriver::new(vault);

        assert!(
            driver
                .remove_group_member(&group_id, &member_b32)
                .expect("remove member")
        );
        let stored = driver
            .vault()
            .expect("vault")
            .snapshot()
            .groups
            .get(&group_id)
            .expect("stored group");

        assert!(!stored.members.iter().any(|member| member.b32 == member_b32));
        assert_eq!(stored.roster_version, previous_version + 1);
        assert_ne!(stored.roster_signature, previous_signature);
    }

    #[test]
    fn owner_member_removal_updates_an_open_group_without_ready_peers() {
        let temp = TestDirectory::new("remove-open-group-member");
        let repository = test_vault_repository(&temp.path().join("owner"));
        let mut vault = repository.create(b"test passphrase").expect("create vault");
        let mut group = initialized_owner_group("remove-open-member");
        let member_b32 = destination_to_b32("ZGVm").expect("member b32");
        group.members.push(GroupMemberRecord {
            name: "Bob".into(),
            b32: member_b32.clone(),
        });
        sign_owner_roster(&mut group).expect("sign roster with member");
        let group_id = group.id.clone();
        let session = GroupSession::new(
            GroupSessionConfig::from_record_with_local_destination(&group, ALICE_DESTINATION, 1)
                .expect("group config"),
        );
        vault
            .update(|snapshot| {
                snapshot.groups.insert(group_id.clone(), group);
                Ok(())
            })
            .expect("store group");
        let mut driver = ApplicationDriver::new(vault);
        driver
            .open_group(group_id.clone(), session, test_transport(ALICE_DESTINATION))
            .expect("open group");

        assert!(
            driver
                .remove_group_member(&group_id, &member_b32)
                .expect("remove member from open group")
        );
        assert!(driver.group_is_active(&group_id));
        assert!(
            !driver
                .vault()
                .expect("vault")
                .snapshot()
                .groups
                .get(&group_id)
                .expect("stored group")
                .members
                .iter()
                .any(|member| member.b32 == member_b32)
        );
    }

    #[test]
    fn non_owner_cannot_remove_a_group_member() {
        let mut owner = initialized_owner_group("participant-group");
        let owner_b32 = owner.owner_b32.clone().expect("owner b32");
        let invite = issue_public_invite(&mut owner).expect("issue public invite");
        let temp = TestDirectory::new("reject-member-removal");
        let repository = test_vault_repository(&temp.path().join("participant"));
        let vault = repository.create(b"test passphrase").expect("create vault");
        let mut driver = ApplicationDriver::new(vault);
        let group_id = driver
            .import_public_group_invite(&invite)
            .expect("import public invite");

        assert!(matches!(
            driver.remove_group_member(&group_id, &owner_b32),
            Err(DriverError::GroupRoster(GroupRosterError::OwnerOnly))
        ));
    }

    #[test]
    fn closed_participant_can_delete_its_local_group_by_leaving() {
        let mut owner = initialized_owner_group("participant-leave");
        let invite = issue_public_invite(&mut owner).expect("issue public invite");
        let temp = TestDirectory::new("leave-closed-group");
        let repository = test_vault_repository(&temp.path().join("participant"));
        let vault = repository.create(b"test passphrase").expect("create vault");
        let mut driver = ApplicationDriver::new(vault);
        let group_id = driver
            .import_public_group_invite(&invite)
            .expect("import public invite");

        assert!(
            driver
                .leave_group_locally(&group_id)
                .expect("leave closed group")
        );
        assert!(
            !driver
                .vault()
                .expect("vault")
                .snapshot()
                .groups
                .contains_key(&group_id)
        );
    }

    #[test]
    fn group_owner_cannot_use_participant_leave() {
        let temp = TestDirectory::new("reject-owner-leave");
        let repository = test_vault_repository(&temp.path().join("owner"));
        let mut vault = repository.create(b"test passphrase").expect("create vault");
        let group = initialized_owner_group("owner-leave");
        let group_id = group.id.clone();
        vault
            .update(|snapshot| {
                snapshot.groups.insert(group_id.clone(), group);
                Ok(())
            })
            .expect("store owner group");
        let mut driver = ApplicationDriver::new(vault);

        assert!(matches!(
            driver.leave_group_locally(&group_id),
            Err(DriverError::GroupRoster(GroupRosterError::OwnerCannotLeave))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn active_local_leave_deletes_group_only_after_session_shutdown() {
        let mut owner = initialized_owner_group("active-participant-leave");
        let encoded_invite = issue_public_invite(&mut owner).expect("issue public invite");
        let invite = decode_public_invite(&encoded_invite).expect("decode public invite");
        let participant_b32 = destination_to_b32(BOB_DESTINATION).expect("participant b32");
        let mut group = GroupRecord::new(
            GroupId::new("pending-participant-leave").expect("temporary group id"),
            "Pending participant leave",
        )
        .expect("participant group");
        group.identity = Some(
            PersistentIdentity::new(BOB_DESTINATION, &participant_b32)
                .expect("participant identity"),
        );
        group.local_member_name = "Bob".into();
        apply_invite(&mut group, invite, None).expect("apply public invite");
        let group_id = group.id.clone();
        let temp = TestDirectory::new("leave-active-group");
        let repository = test_vault_repository(&temp.path().join("participant"));
        let mut vault = repository.create(b"test passphrase").expect("create vault");
        vault
            .update(|snapshot| {
                snapshot.groups.insert(group_id.clone(), group.clone());
                Ok(())
            })
            .expect("store participant group");
        let mut driver = ApplicationDriver::new(vault);
        let session = GroupSession::new(
            GroupSessionConfig::from_record_with_local_destination(&group, BOB_DESTINATION, 1)
                .expect("group config"),
        );
        let session_id = driver
            .open_group(group_id.clone(), session, test_transport(BOB_DESTINATION))
            .expect("open group");
        assert!(matches!(
            driver.try_next_event().expect("opened event"),
            Some(ApplicationEvent::SessionOpened { .. })
        ));

        assert!(
            !driver
                .leave_group_locally(&group_id)
                .expect("start local leave")
        );
        assert!(
            driver
                .vault()
                .expect("vault")
                .snapshot()
                .groups
                .contains_key(&group_id)
        );
        loop {
            let event = driver.next_event().await.expect("shutdown event");
            if matches!(
                event,
                ApplicationEvent::SessionClosed { session_id: closed, .. }
                    if closed == session_id
            ) {
                break;
            }
        }
        assert!(
            !driver
                .vault()
                .expect("vault")
                .snapshot()
                .groups
                .contains_key(&group_id)
        );
    }

    #[test]
    fn closed_owner_can_dissolve_its_local_group() {
        let temp = TestDirectory::new("dissolve-closed-group");
        let repository = test_vault_repository(&temp.path().join("owner"));
        let mut vault = repository.create(b"test passphrase").expect("create vault");
        let group = initialized_owner_group("dissolve-closed");
        let group_id = group.id.clone();
        vault
            .update(|snapshot| {
                snapshot.groups.insert(group_id.clone(), group);
                Ok(())
            })
            .expect("store owner group");
        let mut driver = ApplicationDriver::new(vault);

        assert!(driver.dissolve_group(&group_id).expect("dissolve group"));
        assert!(
            !driver
                .vault()
                .expect("vault")
                .snapshot()
                .groups
                .contains_key(&group_id)
        );
    }

    #[test]
    fn participant_cannot_dissolve_group() {
        let mut owner = initialized_owner_group("reject-participant-dissolution");
        let invite = issue_public_invite(&mut owner).expect("issue public invite");
        let temp = TestDirectory::new("reject-participant-dissolution");
        let repository = test_vault_repository(&temp.path().join("participant"));
        let vault = repository.create(b"test passphrase").expect("create vault");
        let mut driver = ApplicationDriver::new(vault);
        let group_id = driver
            .import_public_group_invite(&invite)
            .expect("import public invite");

        assert!(matches!(
            driver.dissolve_group(&group_id),
            Err(DriverError::GroupRoster(GroupRosterError::OwnerOnly))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn active_owner_dissolution_deletes_group_only_after_session_shutdown() {
        let temp = TestDirectory::new("dissolve-active-group");
        let repository = test_vault_repository(&temp.path().join("owner"));
        let mut vault = repository.create(b"test passphrase").expect("create vault");
        let group = initialized_owner_group("dissolve-active");
        let group_id = group.id.clone();
        let session = GroupSession::new(
            GroupSessionConfig::from_record_with_local_destination(&group, ALICE_DESTINATION, 1)
                .expect("group config"),
        );
        vault
            .update(|snapshot| {
                snapshot.groups.insert(group_id.clone(), group);
                Ok(())
            })
            .expect("store owner group");
        let mut driver = ApplicationDriver::new(vault);
        let session_id = driver
            .open_group(group_id.clone(), session, test_transport(ALICE_DESTINATION))
            .expect("open group");
        assert!(matches!(
            driver.try_next_event().expect("opened event"),
            Some(ApplicationEvent::SessionOpened { .. })
        ));

        assert!(!driver.dissolve_group(&group_id).expect("start dissolution"));
        assert!(
            driver
                .vault()
                .expect("vault")
                .snapshot()
                .groups
                .contains_key(&group_id)
        );
        loop {
            let event = driver.next_event().await.expect("shutdown event");
            if matches!(
                event,
                ApplicationEvent::SessionClosed { session_id: closed, .. }
                    if closed == session_id
            ) {
                break;
            }
        }
        assert!(
            !driver
                .vault()
                .expect("vault")
                .snapshot()
                .groups
                .contains_key(&group_id)
        );
    }

    #[test]
    fn image_paths_use_the_supported_mime_policy_and_safe_components() {
        assert_eq!(
            image_mime_for_path(Path::new("preview.JPEG")).expect("jpeg mime"),
            "image/jpeg"
        );
        assert!(matches!(
            image_mime_for_path(Path::new("archive.zip")),
            Err(DriverError::InvalidImageFile(_))
        ));
        assert_eq!(
            sanitize_image_filename("../bad|name.png"),
            ".._bad_name.png"
        );
        assert_eq!(sanitize_image_filename(".."), "image");
        assert!(validate_image_bytes("image/png", b"not a png").is_err());
        assert!(validate_image_bytes("image/png", b"\x89PNG\r\n\x1a\n").is_ok());
    }

    #[test]
    fn received_group_images_are_validated_without_creating_storage() {
        let temp = TestDirectory::new("received-group-image");
        let repository = test_vault_repository(&temp.path().join("owner"));
        let mut vault = repository.create(b"test passphrase").expect("create vault");
        let group = initialized_owner_group("image-group");
        let group_id = group.id.clone();
        let session = GroupSession::new(
            GroupSessionConfig::from_record_with_local_destination(&group, ALICE_DESTINATION, 1)
                .expect("group config"),
        );
        vault
            .update(|snapshot| {
                snapshot.groups.insert(group_id.clone(), group);
                Ok(())
            })
            .expect("store group");
        let mut driver = ApplicationDriver::new(vault);
        let session_id = driver
            .open_group(group_id, session, test_transport(ALICE_DESTINATION))
            .expect("open group");
        let image_bytes = b"\x89PNG\r\n\x1a\nreceived image";
        let image = driver
            .validate_received_group_image(
                session_id,
                "../preview|one.png",
                "image/png",
                image_bytes,
            )
            .expect("validate image");
        let image_directory = driver
            .vault()
            .expect("vault")
            .files_dir()
            .join("group-images");

        assert_eq!(image.filename, ".._preview_one.png");
        assert_eq!(image.mime, "image/png");
        assert_eq!(image.bytes, image_bytes);
        assert!(!image_directory.exists());
    }

    #[test]
    fn group_text_rejects_a_contact_session_before_io_is_scheduled() {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let contact_id = ContactId::new("contact").expect("contact id");
        let session = OneToOneSession::new(
            OneToOneConfig::new(ALICE_DESTINATION, None).expect("session config"),
        );
        let session_id = driver
            .open_contact(
                contact_id,
                session,
                None,
                test_transport(ALICE_DESTINATION),
                None,
            )
            .expect("open contact");

        assert!(matches!(
            driver.send_group_text(session_id, 1, "hello"),
            Err(DriverError::Coordinator(
                ApplicationCoordinatorError::ExpectedGroup(id)
            )) if id == session_id
        ));
        assert_eq!(driver.active_task_count(), 0);
    }

    #[test]
    fn mismatched_sam_identity_is_rejected_before_registration() {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let session = OneToOneSession::new(
            OneToOneConfig::new(ALICE_DESTINATION, None).expect("session config"),
        );
        let transport = test_transport("ZGVm");

        assert!(matches!(
            driver.open_contact(
                ContactId::new("mismatch").expect("contact id"),
                session,
                None,
                transport,
                None,
            ),
            Err(DriverError::SamIdentityMismatch)
        ));
        assert_eq!(driver.coordinator().session_count(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn manual_close_removes_resources_only_after_sam_shutdown() {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let contact_id = ContactId::new("close-me").expect("contact id");
        let session = OneToOneSession::new(
            OneToOneConfig::new(ALICE_DESTINATION, None).expect("session config"),
        );
        let session_id = driver
            .open_contact(
                contact_id,
                session,
                None,
                test_transport(ALICE_DESTINATION),
                None,
            )
            .expect("open contact");
        assert!(matches!(
            driver.try_next_event().expect("opened event"),
            Some(ApplicationEvent::SessionOpened { .. })
        ));

        driver.close_session(session_id).expect("close session");
        assert!(driver.has_resources(session_id));
        assert!(matches!(
            driver.next_event().await.expect("closing event"),
            ApplicationEvent::SessionClosing { session_id: closing, .. }
                if closing == session_id
        ));
        loop {
            let event = driver.next_event().await.expect("shutdown event");
            if matches!(
                event,
                ApplicationEvent::SessionClosed { session_id: closed, .. }
                    if closed == session_id
            ) {
                break;
            }
            assert!(driver.has_resources(session_id));
        }
        assert!(!driver.has_resources(session_id));
    }

    fn test_transport(destination: &str) -> SessionTransport {
        let endpoint = SamEndpoint::new("127.0.0.1", 7656).expect("endpoint");
        let b32 = destination_to_b32(destination).expect("b32");
        SessionTransport {
            runtime: SamRuntime::new(endpoint),
            info: SamSessionInfo {
                session_id: "test-session".into(),
                private_destination: destination.into(),
                public_destination: destination.into(),
                b32,
            },
        }
    }

    fn ready_one_to_one_pair() -> (OneToOneSession, OneToOneSession) {
        let mut sender = OneToOneSession::new(
            OneToOneConfig::new(ALICE_DESTINATION, None).expect("sender config"),
        );
        let mut receiver = OneToOneSession::new(
            OneToOneConfig::new(BOB_DESTINATION, None).expect("receiver config"),
        );
        let sender_b32 = sender.config().local_b32().to_string();
        let receiver_b32 = receiver.config().local_b32().to_string();
        let sender_connection = ConnectionId::new(1);
        let receiver_connection = ConnectionId::new(2);
        let connect = sender
            .begin_connect(&receiver_b32)
            .expect("begin connection");
        let attempt_id = connect
            .actions
            .into_iter()
            .find_map(|action| match action {
                OneToOneAction::Connect { attempt_id, .. } => Some(attempt_id),
                _ => None,
            })
            .expect("connect attempt");
        let sender_connected =
            sender.outbound_connected(attempt_id, sender_connection, &receiver_b32, 1_000);
        let sender_frames = sender_connected
            .actions
            .into_iter()
            .find_map(|action| match action {
                OneToOneAction::SendHandshake { frames, .. } => Some(frames),
                _ => None,
            })
            .expect("sender handshake");

        receiver.incoming_connected(receiver_connection, &sender_b32, ALICE_DESTINATION, 1_000);
        for frame in sender_frames {
            receiver.receive_frame(receiver_connection, frame, 1_001);
        }
        let accepted = receiver.accept_incoming(1_002).expect("accept connection");
        let receiver_frames = accepted
            .actions
            .into_iter()
            .find_map(|action| match action {
                OneToOneAction::SendHandshake { frames, .. } => Some(frames),
                _ => None,
            })
            .expect("receiver handshake");
        for frame in receiver_frames {
            sender.receive_frame(sender_connection, frame, 1_002);
        }
        assert!(sender.is_ready());
        assert!(receiver.is_ready());
        (sender, receiver)
    }

    fn driver_with_closed_send_worker() -> (ApplicationDriver, SessionId, ConnectionId) {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let session = OneToOneSession::new(
            OneToOneConfig::new(ALICE_DESTINATION, None).expect("session config"),
        );
        let session_id = driver
            .open_contact(
                ContactId::new("closed-worker").expect("contact id"),
                session,
                None,
                test_transport(ALICE_DESTINATION),
                None,
            )
            .expect("open contact");
        let connection_id = ConnectionId::new(3);
        let (send_tx, send_rx) = mpsc::channel(1);
        let (priority_send_tx, priority_send_rx) = mpsc::channel(1);
        drop(send_rx);
        drop(priority_send_rx);
        driver
            .resources
            .get_mut(&session_id)
            .expect("contact resources")
            .connections
            .insert(
                connection_id,
                ManagedConnection {
                    send_tx,
                    priority_send_tx,
                },
            );
        (driver, session_id, connection_id)
    }

    fn initialized_owner_group(id: &str) -> GroupRecord {
        let owner_b32 = destination_to_b32(ALICE_DESTINATION).expect("owner b32");
        let mut group =
            GroupRecord::new(GroupId::new(id).expect("group id"), "Invite group").expect("group");
        group.identity =
            Some(PersistentIdentity::new(ALICE_DESTINATION, &owner_b32).expect("owner identity"));
        group.local_member_name = "Alice".into();
        group.owner_b32 = Some(owner_b32);
        sign_owner_roster(&mut group).expect("sign owner roster");
        group
    }

    #[test]
    fn frontend_api_applies_settings_and_returns_sanitized_catalogs() {
        let temp = TestDirectory::new("frontend-api-settings");
        let repository = test_vault_repository(temp.path());
        let mut vault = repository.create(b"test passphrase").expect("create vault");
        let contact_id = ContactId::new("api-contact").expect("contact id");
        let contact = ContactRecord::new(contact_id.clone(), "API Contact").expect("contact");
        let group = initialized_owner_group("api-group");
        let group_id = group.id.clone();
        vault
            .update(|snapshot| {
                snapshot.contacts.insert(contact_id.clone(), contact);
                snapshot.groups.insert(group_id.clone(), group);
                Ok(())
            })
            .expect("store API records");
        let mut driver = ApplicationDriver::new(vault);

        assert_eq!(
            driver
                .dispatch_command(CommToolsCommand::SetSamHost(" 192.0.2.1 ".into()))
                .expect("set SAM host"),
            CommToolsCommandResult::Applied
        );
        assert_eq!(
            driver
                .dispatch_command(CommToolsCommand::SetSamPort(17656))
                .expect("set SAM port"),
            CommToolsCommandResult::Applied
        );
        let tunnels = TunnelSettings {
            length: 3,
            quantity: 4,
        };
        assert_eq!(
            driver
                .dispatch_command(CommToolsCommand::SetDefaultTunnelSettings(tunnels))
                .expect("set tunnel defaults"),
            CommToolsCommandResult::DefaultTunnelSettingsApplied(tunnels)
        );

        let snapshot = driver.snapshot().expect("frontend snapshot");
        assert_eq!(snapshot.application_phase, ApplicationPhase::Running);
        assert_eq!(snapshot.settings.sam_host, "192.0.2.1");
        assert_eq!(snapshot.settings.sam_port, 17656);
        assert_eq!(snapshot.settings.default_tunnels, tunnels);
        assert_eq!(snapshot.contacts.len(), 1);
        assert_eq!(snapshot.contacts[0].id, contact_id);
        assert_eq!(snapshot.contacts[0].display_name, "API Contact");
        assert!(!snapshot.contacts[0].peer_pinned);
        assert!(!snapshot.contacts[0].active);
        assert_eq!(snapshot.groups.len(), 1);
        assert_eq!(snapshot.groups[0].id, group_id);
        assert!(snapshot.groups[0].owner);
        assert_eq!(snapshot.groups[0].members.len(), 1);
        assert!(snapshot.groups[0].members[0].local);
        assert!(snapshot.groups[0].members[0].owner);
        assert!(!snapshot.groups[0].members[0].connected);
        assert!(snapshot.sessions.is_empty());
        assert!(!snapshot.has_open_or_pending_sessions);
        assert_eq!(snapshot.sam_test_status, SamTestStatus::Idle);
        assert_eq!(snapshot.sam_monitor_status, SamMonitorStatus::Inactive);
        assert!(!snapshot.sam_monitor_requires_attention);
    }

    #[test]
    fn frontend_api_contact_commands_preserve_driver_validation_and_state() {
        let temp = TestDirectory::new("frontend-api-contact-commands");
        let repository = test_vault_repository(temp.path());
        let vault = repository.create(b"test passphrase").expect("create vault");
        let mut driver = ApplicationDriver::new(vault);

        let contact_id = match driver
            .dispatch_command(CommToolsCommand::CreateContact {
                display_name: "Command Contact".into(),
            })
            .expect("create contact")
        {
            CommToolsCommandResult::ContactCreated(contact_id) => contact_id,
            result => panic!("unexpected create result: {result:?}"),
        };
        assert_eq!(
            driver
                .dispatch_command(CommToolsCommand::RenameContact {
                    contact_id: contact_id.clone(),
                    display_name: "Renamed Contact".into(),
                })
                .expect("rename contact"),
            CommToolsCommandResult::ContactRenamed("Renamed Contact".into())
        );
        let tunnels = TunnelSettings {
            length: 4,
            quantity: 5,
        };
        assert_eq!(
            driver
                .dispatch_command(CommToolsCommand::SetContactTunnelSettings {
                    contact_id: contact_id.clone(),
                    tunnels,
                })
                .expect("set contact tunnels"),
            CommToolsCommandResult::ContactTunnelSettingsApplied(tunnels)
        );
        assert_eq!(
            driver
                .dispatch_command(CommToolsCommand::SetContactHistoryEnabled {
                    contact_id: contact_id.clone(),
                    enabled: true,
                })
                .expect("enable contact history"),
            CommToolsCommandResult::ContactHistorySettingApplied { enabled: true }
        );
        let history_key = ManagedSessionKey::Contact(contact_id.clone());
        let history_record = HistoryRecord {
            created_ms: 1,
            timestamp_utc: "12:00:00 UTC".into(),
            author: "Me".into(),
            sender_b32: None,
            text: "clear through frontend API".into(),
            mine: true,
            offline: false,
            msg_id: Some(1),
            delivered: false,
            group_expected_acks: Vec::new(),
            group_received_acks: Vec::new(),
        };
        assert_eq!(
            driver
                .append_history_message(&history_key, &history_record)
                .expect("append contact history"),
            HistoryWriteOutcome::Stored
        );
        assert_eq!(
            driver
                .dispatch_command(CommToolsCommand::LoadHistory {
                    key: history_key.clone(),
                })
                .expect("load contact history"),
            CommToolsCommandResult::HistoryLoaded {
                key: history_key.clone(),
                records: vec![history_record],
            }
        );
        assert_eq!(
            driver
                .dispatch_command(CommToolsCommand::ClearHistory {
                    key: history_key.clone(),
                })
                .expect("clear contact history"),
            CommToolsCommandResult::HistoryCleared {
                key: history_key.clone(),
            }
        );
        assert!(
            driver
                .load_history(&history_key)
                .expect("load cleared history")
                .is_empty()
        );
        assert!(
            driver
                .history_enabled(&history_key)
                .expect("history setting")
        );
        let server = destination_to_b32(ALICE_DESTINATION).expect("deaddrop b32");
        assert_eq!(
            driver
                .dispatch_command(CommToolsCommand::AddContactDeaddropServer {
                    contact_id: contact_id.clone(),
                    server: server.clone(),
                })
                .expect("add deaddrop"),
            CommToolsCommandResult::ContactDeaddropServerAdded(server.clone())
        );
        assert_eq!(
            driver
                .dispatch_command(CommToolsCommand::RemoveContactDeaddropServer {
                    contact_id: contact_id.clone(),
                    server,
                })
                .expect("remove deaddrop"),
            CommToolsCommandResult::ContactDeaddropServerRemoved(
                destination_to_b32(ALICE_DESTINATION).expect("deaddrop b32")
            )
        );

        let snapshot = driver.snapshot().expect("contact snapshot");
        let contact = snapshot.contacts.first().expect("contact summary");
        assert_eq!(contact.display_name, "Renamed Contact");
        assert_eq!(contact.tunnels, tunnels);
        assert!(contact.history_enabled);

        let deleted_id = match driver
            .dispatch_command(CommToolsCommand::CreateContact {
                display_name: "Delete Contact".into(),
            })
            .expect("create deletable contact")
        {
            CommToolsCommandResult::ContactCreated(contact_id) => contact_id,
            result => panic!("unexpected create result: {result:?}"),
        };
        assert_eq!(
            driver
                .dispatch_command(CommToolsCommand::DeleteContact {
                    contact_id: deleted_id.clone(),
                })
                .expect("delete contact"),
            CommToolsCommandResult::ContactDeleted(deleted_id.clone())
        );
        assert!(
            driver
                .snapshot()
                .expect("snapshot after delete")
                .contacts
                .iter()
                .all(|contact| contact.id != deleted_id)
        );

        let session = OneToOneSession::new(
            OneToOneConfig::new(ALICE_DESTINATION, None).expect("session config"),
        );
        driver
            .open_contact(
                contact_id.clone(),
                session,
                None,
                test_transport(ALICE_DESTINATION),
                None,
            )
            .expect("open contact");
        assert!(matches!(
            driver.dispatch_command(CommToolsCommand::RenameContact {
                contact_id: contact_id.clone(),
                display_name: "Rejected Rename".into(),
            }),
            Err(DriverError::ContactRenameRequiresClosed(id)) if id == contact_id
        ));
    }

    #[test]
    fn frontend_api_group_commands_preserve_driver_validation_and_state() {
        let owner_temp = TestDirectory::new("frontend-api-group-owner");
        let owner_repository = test_vault_repository(owner_temp.path());
        let mut owner_vault = owner_repository
            .create(b"owner passphrase")
            .expect("create owner vault");
        let mut owner_group = initialized_owner_group("api-owner-group");
        let owner_group_id = owner_group.id.clone();
        let member_b32 = destination_to_b32(BOB_DESTINATION).expect("member b32");
        owner_group.members.push(GroupMemberRecord {
            name: "Bob".into(),
            b32: member_b32.clone(),
        });
        sign_owner_roster(&mut owner_group).expect("sign expanded owner roster");
        owner_vault
            .update(|snapshot| {
                snapshot.groups.insert(owner_group_id.clone(), owner_group);
                Ok(())
            })
            .expect("store owner group");
        let mut owner = ApplicationDriver::new(owner_vault);

        let created_id = match owner
            .dispatch_command(CommToolsCommand::CreateGroup {
                display_name: "Command Group".into(),
            })
            .expect("create group")
        {
            CommToolsCommandResult::GroupCreated(group_id) => group_id,
            result => panic!("unexpected group-create result: {result:?}"),
        };
        assert_eq!(
            owner
                .dispatch_command(CommToolsCommand::SetGroupLocalName {
                    group_id: created_id.clone(),
                    local_name: "Local Name".into(),
                })
                .expect("set local group name"),
            CommToolsCommandResult::GroupLocalNameApplied
        );
        assert_eq!(
            owner
                .dispatch_command(CommToolsCommand::SetGroupHistoryEnabled {
                    group_id: created_id.clone(),
                    enabled: true,
                })
                .expect("enable group history"),
            CommToolsCommandResult::GroupHistorySettingApplied { enabled: true }
        );
        let created = owner
            .snapshot()
            .expect("snapshot created group")
            .groups
            .into_iter()
            .find(|group| group.id == created_id)
            .expect("created group summary");
        assert_eq!(created.local_member_name, "Local Name");
        assert!(created.history_enabled);
        assert_eq!(
            owner
                .dispatch_command(CommToolsCommand::DeleteGroup {
                    group_id: created_id.clone(),
                })
                .expect("delete group"),
            CommToolsCommandResult::GroupDeleted(created_id)
        );

        assert_eq!(
            owner
                .dispatch_command(CommToolsCommand::RemoveGroupMember {
                    group_id: owner_group_id.clone(),
                    member_b32: member_b32.clone(),
                })
                .expect("remove group member"),
            CommToolsCommandResult::GroupMemberRemoval { removed: true }
        );
        assert_eq!(
            owner
                .dispatch_command(CommToolsCommand::RemoveGroupMember {
                    group_id: owner_group_id.clone(),
                    member_b32,
                })
                .expect("repeat group-member removal"),
            CommToolsCommandResult::GroupMemberRemoval { removed: false }
        );

        let public_invite = match owner
            .dispatch_command(CommToolsCommand::IssuePublicGroupInvite {
                group_id: owner_group_id.clone(),
            })
            .expect("issue public group invite")
        {
            CommToolsCommandResult::PublicGroupInviteIssued(invite) => invite,
            result => panic!("unexpected public invite result: {result:?}"),
        };
        let participant_temp = TestDirectory::new("frontend-api-group-participant");
        let participant_repository = test_vault_repository(participant_temp.path());
        let participant_vault = participant_repository
            .create(b"participant passphrase")
            .expect("create participant vault");
        let mut participant = ApplicationDriver::new(participant_vault);
        let imported_group_id = match participant
            .dispatch_command(CommToolsCommand::ImportPublicGroupInvite {
                encoded_invite: public_invite,
            })
            .expect("import public group invite")
        {
            CommToolsCommandResult::PublicGroupInviteImported(group_id) => group_id,
            result => panic!("unexpected public invite import result: {result:?}"),
        };
        assert_eq!(
            participant
                .dispatch_command(CommToolsCommand::LeaveGroupLocally {
                    group_id: imported_group_id.clone(),
                })
                .expect("leave imported group locally"),
            CommToolsCommandResult::GroupLocalLeaveStarted {
                deleted_immediately: true,
            }
        );
        assert!(
            participant
                .snapshot()
                .expect("participant snapshot after leave")
                .groups
                .iter()
                .all(|group| group.id != imported_group_id)
        );

        let private_request = match participant
            .dispatch_command(CommToolsCommand::GeneratePrivateGroupRequest)
            .expect("generate private group request")
        {
            CommToolsCommandResult::PrivateGroupRequestGenerated(request) => request,
            result => panic!("unexpected private request result: {result:?}"),
        };
        let private_invite = match owner
            .dispatch_command(CommToolsCommand::IssuePrivateGroupInvite {
                group_id: owner_group_id.clone(),
                encoded_request: private_request,
            })
            .expect("issue private group invite")
        {
            CommToolsCommandResult::PrivateGroupInviteIssued(invite) => invite,
            result => panic!("unexpected private invite result: {result:?}"),
        };
        let private_group_id = match participant
            .dispatch_command(CommToolsCommand::ImportPrivateGroupInvite {
                encoded_invite: private_invite,
            })
            .expect("import private group invite")
        {
            CommToolsCommandResult::PrivateGroupInviteImported(group_id) => group_id,
            result => panic!("unexpected private invite import result: {result:?}"),
        };
        assert!(matches!(
            participant.dispatch_command(CommToolsCommand::RequestGroupLeave {
                group_id: private_group_id.clone(),
            }),
            Err(DriverError::GroupLeaveRequiresOpen(group_id)) if group_id == private_group_id
        ));

        assert_eq!(
            owner
                .dispatch_command(CommToolsCommand::DissolveGroup {
                    group_id: owner_group_id.clone(),
                })
                .expect("dissolve owner group"),
            CommToolsCommandResult::GroupDissolutionStarted {
                deleted_immediately: true,
            }
        );
        assert!(
            owner
                .snapshot()
                .expect("owner snapshot after dissolution")
                .groups
                .iter()
                .all(|group| group.id != owner_group_id)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn frontend_api_starts_session_bootstraps_without_exposing_transport_details() {
        let temp = TestDirectory::new("frontend-api-session-bootstrap");
        let repository = test_vault_repository(temp.path());
        let mut vault = repository.create(b"test passphrase").expect("create vault");
        let contact_id = ContactId::new("bootstrap-contact").expect("contact id");
        let contact =
            ContactRecord::new(contact_id.clone(), "Bootstrap Contact").expect("contact record");
        let group_id = GroupId::new("bootstrap-group").expect("group id");
        let group = GroupRecord::new(group_id.clone(), "Bootstrap Group").expect("group record");
        vault
            .update(|snapshot| {
                snapshot.contacts.insert(contact_id.clone(), contact);
                snapshot.groups.insert(group_id.clone(), group);
                Ok(())
            })
            .expect("store bootstrap records");
        let mut driver = ApplicationDriver::new(vault);

        assert_eq!(
            driver
                .dispatch_command(CommToolsCommand::OpenContact {
                    contact_id: contact_id.clone(),
                })
                .expect("start contact open"),
            CommToolsCommandResult::ContactOpening(contact_id.clone())
        );
        assert_eq!(
            driver
                .dispatch_command(CommToolsCommand::OpenGroup {
                    group_id: group_id.clone(),
                })
                .expect("start group open"),
            CommToolsCommandResult::GroupOpening(group_id.clone())
        );
        let transient_id = match driver
            .dispatch_command(CommToolsCommand::OpenTransient)
            .expect("start transient open")
        {
            CommToolsCommandResult::TransientOpening(transient_id) => transient_id,
            result => panic!("unexpected transient-open result: {result:?}"),
        };

        let snapshot = driver.snapshot().expect("pending-open snapshot");
        assert!(snapshot.has_open_or_pending_sessions);
        assert!(snapshot.sessions.is_empty());
        assert!(matches!(
            driver.try_next_frontend_event().expect("contact opening event"),
            Some(FrontendEvent::Session(SessionLifecycleEvent::Opening {
                key: ManagedSessionKey::Contact(id),
            })) if id == contact_id
        ));
        assert!(matches!(
            driver.try_next_frontend_event().expect("group opening event"),
            Some(FrontendEvent::Session(SessionLifecycleEvent::Opening {
                key: ManagedSessionKey::Group(id),
            })) if id == group_id
        ));
        assert!(matches!(
            driver
                .try_next_frontend_event()
                .expect("transient opening event"),
            Some(FrontendEvent::Session(SessionLifecycleEvent::Opening {
                key: ManagedSessionKey::Transient(id),
            })) if id == transient_id
        ));
    }

    #[test]
    fn frontend_api_translates_contact_state_without_transport_identifiers() {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let session_id = SessionId::new(77);
        let peer_b32 = destination_to_b32(BOB_DESTINATION).expect("peer b32");

        let phase = driver
            .translate_frontend_event(ApplicationEvent::OneToOne {
                session_id,
                event: commtools_core::OneToOneEvent::PhaseChanged(
                    commtools_core::OneToOnePhase::Ready,
                ),
            })
            .expect("translate phase");
        assert_eq!(
            phase,
            Some(FrontendEvent::Contact(ContactSessionEvent::PhaseChanged {
                session_id,
                phase: commtools_core::OneToOnePhase::Ready,
            }))
        );

        let incoming = driver
            .translate_frontend_event(ApplicationEvent::OneToOne {
                session_id,
                event: commtools_core::OneToOneEvent::IncomingCall {
                    connection_id: ConnectionId::new(9),
                    peer_b32: peer_b32.clone(),
                },
            })
            .expect("translate incoming call");
        assert_eq!(
            incoming,
            Some(FrontendEvent::Contact(ContactSessionEvent::IncomingCall {
                session_id,
                peer_b32,
            }))
        );
    }

    #[test]
    fn frontend_api_translates_group_state_without_transport_identifiers() {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let session_id = SessionId::new(78);
        let peer_b32 = destination_to_b32(BOB_DESTINATION).expect("peer b32");

        let collision = driver
            .translate_frontend_event(ApplicationEvent::Group {
                session_id,
                event: CoreGroupSessionEvent::CollisionResolved {
                    peer_b32: peer_b32.clone(),
                    winner: commtools_core::GroupCollisionWinner::Outbound,
                    kept_connection: Some(ConnectionId::new(10)),
                    closed_connection: Some(ConnectionId::new(11)),
                },
            })
            .expect("translate group collision");
        assert_eq!(
            collision,
            Some(FrontendEvent::Group(GroupSessionEvent::CollisionResolved {
                session_id,
                peer_b32: peer_b32.clone(),
                winner: commtools_core::GroupCollisionWinner::Outbound,
            }))
        );

        let ready = driver
            .translate_frontend_event(ApplicationEvent::Group {
                session_id,
                event: CoreGroupSessionEvent::SecureSessionReady {
                    peer_b32: peer_b32.clone(),
                    connection_id: ConnectionId::new(12),
                    authorized: true,
                },
            })
            .expect("translate group readiness");
        assert_eq!(
            ready,
            Some(FrontendEvent::Group(
                GroupSessionEvent::SecureSessionReady {
                    session_id,
                    peer_b32,
                    authorized: true,
                }
            ))
        );
    }

    #[test]
    fn frontend_api_translates_file_transfer_state() {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let session_id = SessionId::new(79);
        let path = PathBuf::from("files/report.txt");

        let translated = driver
            .translate_frontend_event(ApplicationEvent::FileTransfer {
                session_id,
                event: CoreFileTransferEvent::Completed {
                    transfer_id: 41,
                    direction: CoreFileTransferDirection::Received,
                    filename: "report.txt".into(),
                    total_bytes: 512,
                    path: Some(path.clone()),
                },
            })
            .expect("translate file completion");

        assert_eq!(
            translated,
            Some(FrontendEvent::FileTransfer(FileTransferEvent::Completed {
                session_id,
                transfer_id: 41,
                direction: FileTransferDirection::Received,
                filename: "report.txt".into(),
                total_bytes: 512,
                path: Some(path),
            }))
        );
    }

    #[test]
    fn frontend_api_summarizes_offline_poll_state() {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let session_id = SessionId::new(80);

        let translated = driver
            .translate_frontend_event(ApplicationEvent::Offline {
                session_id,
                event: commtools_core::OfflineCoordinatorEvent::PollSweepCompleted {
                    started_ms: 1_000,
                    completed_ms: 1_010,
                    observations: vec![commtools_core::offline::OfflinePollObservation {
                        index: 7,
                        kind: commtools_core::offline::OfflinePollKind::Window,
                        outcome: commtools_core::offline::OfflinePollOutcome::ConfirmedMiss,
                    }],
                },
            })
            .expect("translate offline poll");

        assert_eq!(
            translated,
            Some(FrontendEvent::Offline(
                OfflineSessionEvent::PollSweepCompleted {
                    session_id,
                    result: OfflinePollResult::Miss,
                    observation_count: 1,
                }
            ))
        );
    }

    #[test]
    fn frontend_api_translates_runtime_health_and_lifecycle_events() {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let session_id = SessionId::new(81);

        let failed = driver
            .translate_frontend_event(ApplicationEvent::OperationFailed {
                session_id: Some(session_id),
                operation: "accept SAM stream",
                reason: "broken pipe".into(),
            })
            .expect("translate operation failure");
        assert_eq!(
            failed,
            Some(FrontendEvent::Operation(RuntimeOperationEvent::Failed {
                session_id: Some(session_id),
                operation: "accept SAM stream".into(),
                reason: "broken pipe".into(),
            }))
        );

        let recovered = driver
            .translate_frontend_event(ApplicationEvent::OperationRecovered {
                session_id,
                operation: "accept SAM stream",
            })
            .expect("translate operation recovery");
        assert_eq!(
            recovered,
            Some(FrontendEvent::Operation(RuntimeOperationEvent::Recovered {
                session_id,
                operation: "accept SAM stream".into(),
            }))
        );

        for (source, expected) in [
            (
                ApplicationEvent::Stopping,
                ApplicationLifecycleEvent::Stopping,
            ),
            (
                ApplicationEvent::VaultLockRequested,
                ApplicationLifecycleEvent::VaultLockRequested,
            ),
            (
                ApplicationEvent::Stopped,
                ApplicationLifecycleEvent::Stopped,
            ),
        ] {
            assert_eq!(
                driver
                    .translate_frontend_event(source)
                    .expect("translate lifecycle event"),
                Some(FrontendEvent::Lifecycle(expected))
            );
        }
    }

    #[test]
    fn frontend_api_translates_rendezvous_without_connection_ids() {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let session_id = SessionId::new(82);
        let peer_b32 = destination_to_b32(BOB_DESTINATION).expect("peer b32");

        let translated = driver
            .translate_frontend_event(ApplicationEvent::Rendezvous {
                session_id,
                event: commtools_core::RendezvousEvent::AuthenticationRejected {
                    connection_id: ConnectionId::new(17),
                    peer_b32: peer_b32.clone(),
                    reason: "invalid proof".into(),
                },
            })
            .expect("translate rendezvous rejection");

        assert_eq!(
            translated,
            Some(FrontendEvent::Rendezvous(
                RendezvousSessionEvent::AuthenticationRejected {
                    session_id,
                    peer_b32,
                    reason: "invalid proof".into(),
                }
            ))
        );
    }

    #[test]
    fn frontend_api_filters_protocol_internal_events() {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let session_id = SessionId::new(83);

        assert_eq!(
            driver
                .translate_frontend_event(ApplicationEvent::OneToOne {
                    session_id,
                    event: commtools_core::OneToOneEvent::ControlSignal {
                        connection_id: ConnectionId::new(18),
                        signal: "PING".into(),
                    },
                })
                .expect("filter internal contact control"),
            None
        );
        assert_eq!(
            driver
                .translate_frontend_event(ApplicationEvent::Group {
                    session_id,
                    event: CoreGroupSessionEvent::ApplicationFrame {
                        peer_b32: "peer.b32.i2p".into(),
                        frame: Frame::new(MessageType::P, 19, b"internal"),
                    },
                })
                .expect("filter internal group frame"),
            None
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn frontend_api_summarizes_and_controls_an_open_session() {
        let temp = TestDirectory::new("frontend-api-session-control");
        let repository = test_vault_repository(temp.path());
        let mut vault = repository.create(b"test passphrase").expect("create vault");
        let contact_id = ContactId::new("session-contact").expect("contact id");
        let contact =
            ContactRecord::new(contact_id.clone(), "Session Contact").expect("contact record");
        let responder_id = ContactId::new("session-responder").expect("responder id");
        let responder = ContactRecord::new(responder_id.clone(), "Session Responder")
            .expect("responder record");
        vault
            .update(|snapshot| {
                snapshot.contacts.insert(contact_id.clone(), contact);
                snapshot.contacts.insert(responder_id.clone(), responder);
                Ok(())
            })
            .expect("store contact");
        let mut driver = ApplicationDriver::new(vault);
        let session = OneToOneSession::new(
            OneToOneConfig::new(ALICE_DESTINATION, None).expect("session config"),
        );
        let local_b32 = session.config().local_b32().to_string();
        let session_id = driver
            .open_contact(
                contact_id.clone(),
                session,
                None,
                test_transport(ALICE_DESTINATION),
                None,
            )
            .expect("open contact");
        let responder_session = OneToOneSession::new(
            OneToOneConfig::new(BOB_DESTINATION, None).expect("responder session config"),
        );
        let responder_session_id = driver
            .open_contact(
                responder_id,
                responder_session,
                None,
                test_transport(BOB_DESTINATION),
                None,
            )
            .expect("open responder contact");

        let summary = driver.session_summary(session_id).expect("session summary");
        assert_eq!(summary.key, ManagedSessionKey::Contact(contact_id));
        assert_eq!(summary.phase, ManagedSessionPhase::Open);
        assert_eq!(summary.local_b32.as_deref(), Some(local_b32.as_str()));
        assert_eq!(
            summary.one_to_one_phase,
            Some(commtools_core::OneToOnePhase::Standby)
        );
        assert_eq!(summary.peer_b32, None);
        assert_eq!(summary.pinned_peer_b32, None);
        assert_eq!(summary.offline_mode, None);

        let request = match driver
            .dispatch_command(CommToolsCommand::GenerateContactRendezvousRequest { session_id })
            .expect("generate rendezvous request")
        {
            CommToolsCommandResult::ContactRendezvousRequestGenerated(request) => request,
            result => panic!("unexpected rendezvous-request result: {result:?}"),
        };
        assert!(!request.is_empty());
        let response = match driver
            .dispatch_command(CommToolsCommand::AnswerContactRendezvousRequest {
                session_id: responder_session_id,
                encoded_request: request,
            })
            .expect("answer rendezvous request")
        {
            CommToolsCommandResult::ContactRendezvousResponseGenerated(response) => response,
            result => panic!("unexpected rendezvous-response result: {result:?}"),
        };
        assert_eq!(
            driver
                .dispatch_command(CommToolsCommand::ConnectContactRendezvous {
                    session_id,
                    encoded_response: response,
                })
                .expect("start rendezvous connection"),
            CommToolsCommandResult::ContactRendezvousConnectionStarted(session_id)
        );
        assert_eq!(
            driver
                .dispatch_command(CommToolsCommand::DisconnectContact { session_id })
                .expect("disconnect rendezvous connection"),
            CommToolsCommandResult::ContactDisconnectStarted(session_id)
        );
        assert!(matches!(
            driver
                .dispatch_command(CommToolsCommand::GenerateContactRendezvousRequest { session_id })
                .expect("generate replacement rendezvous request"),
            CommToolsCommandResult::ContactRendezvousRequestGenerated(_)
        ));
        assert_eq!(
            driver
                .dispatch_command(CommToolsCommand::RevokeContactRendezvous { session_id })
                .expect("revoke rendezvous"),
            CommToolsCommandResult::ContactRendezvousRevoked(session_id)
        );
        assert_eq!(
            driver
                .dispatch_command(CommToolsCommand::CloseSession { session_id })
                .expect("start session close"),
            CommToolsCommandResult::SessionCloseStarted(session_id)
        );
        assert_eq!(
            driver
                .session_summary(session_id)
                .expect("closing session summary")
                .phase,
            ManagedSessionPhase::Closing
        );
        assert_eq!(
            driver
                .dispatch_command(CommToolsCommand::CloseSession {
                    session_id: responder_session_id,
                })
                .expect("start responder session close"),
            CommToolsCommandResult::SessionCloseStarted(responder_session_id)
        );
    }

    #[test]
    fn disconnected_peers_release_only_their_pending_original_requests() {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let contact_session = SessionId::new(89);
        let group_session = SessionId::new(90);
        driver.pending_original_images.insert(OriginalImageKey {
            session_id: contact_session,
            media_id: 1,
            sender_b32: String::new(),
        });
        for (media_id, sender_b32) in [(2, "alice.b32.i2p"), (3, "bob.b32.i2p")] {
            driver.pending_original_images.insert(OriginalImageKey {
                session_id: group_session,
                media_id,
                sender_b32: sender_b32.into(),
            });
        }

        driver.record_events(vec![ApplicationEvent::OneToOne {
            session_id: contact_session,
            event: commtools_core::OneToOneEvent::PhaseChanged(
                commtools_core::OneToOnePhase::Standby,
            ),
        }]);
        assert!(
            driver
                .pending_original_images
                .iter()
                .all(|key| key.session_id != contact_session)
        );

        driver.record_events(vec![ApplicationEvent::Group {
            session_id: group_session,
            event: CoreGroupSessionEvent::PeerDisconnected {
                peer_b32: "alice.b32.i2p".into(),
                reason: commtools_core::GroupDisconnectReason::TransportClosed,
            },
        }]);
        assert!(
            driver
                .pending_original_images
                .iter()
                .any(|key| { key.session_id == group_session && key.sender_b32 == "bob.b32.i2p" })
        );
        assert!(
            !driver.pending_original_images.iter().any(|key| {
                key.session_id == group_session && key.sender_b32 == "alice.b32.i2p"
            })
        );
    }

    #[test]
    fn frontend_text_command_validates_input_and_emits_semantic_events() {
        let temp = TestDirectory::new("frontend-text-command");
        let repository = test_vault_repository(temp.path());
        let vault = repository.create(b"test passphrase").expect("create vault");
        let mut driver = ApplicationDriver::new(vault);
        let group_id = driver.create_group("Text group").expect("create group");
        let local_b32 = destination_to_b32(ALICE_DESTINATION).expect("local b32");
        let group = GroupSession::new(
            GroupSessionConfig::new(
                ALICE_DESTINATION,
                "Alice",
                "Text group",
                local_b32,
                Vec::new(),
            )
            .expect("group config"),
        );
        let session_id = driver
            .open_group(group_id, group, test_transport(ALICE_DESTINATION))
            .expect("open group");
        assert!(matches!(
            driver.try_next_event().expect("opened event"),
            Some(ApplicationEvent::SessionOpened { .. })
        ));

        assert!(matches!(
            driver.dispatch_command(CommToolsCommand::SendText {
                session_id,
                text: "   ".into(),
            }),
            Err(DriverError::InvalidTextMessage(_))
        ));

        driver.events.push_back(ApplicationEvent::Group {
            session_id,
            event: CoreGroupSessionEvent::TextReceived {
                peer_b32: "peer.b32.i2p".into(),
                message_id: 77,
                text: "reply".into(),
            },
        });
        assert!(matches!(
            driver.try_next_frontend_event().expect("frontend event"),
            Some(FrontendEvent::TextReceived(TextReceivedEvent {
                session_id: received_session,
                message_id: 77,
                text,
                sender_b32: Some(peer_b32),
                offline: false,
                history: HistoryWriteOutcome::Disabled,
                ..
            })) if received_session == session_id
                && text == "reply"
                && peer_b32 == "peer.b32.i2p"
        ));
    }

    #[test]
    fn contact_image_delivery_is_classified_without_touching_text_history() {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let session_id = SessionId::new(91);
        let message_id = 7001;
        driver
            .outgoing_contact_images
            .insert((session_id, message_id));

        let event = driver
            .contact_delivery_received(
                session_id,
                Frame::new(
                    MessageType::D,
                    generate_message_id(),
                    message_id.to_be_bytes(),
                ),
            )
            .expect("classify contact image delivery");

        assert_eq!(
            event,
            FrontendEvent::ImageDeliveryUpdated(ImageDeliveryEvent {
                session_id,
                message_id,
                group: false,
                received: 1,
                expected: 1,
            })
        );
        assert!(
            !driver
                .outgoing_contact_images
                .contains(&(session_id, message_id))
        );
    }

    #[test]
    fn contact_image_reassembly_is_owned_by_the_runtime() {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let session_id = SessionId::new(93);
        driver.resources.insert(
            session_id,
            SessionResources {
                kind: ResourceKind::Contact,
                sam: SamRuntime::new(SamEndpoint::default()),
                deaddrop: None,
                connections: BTreeMap::new(),
                closing_connections: BTreeSet::new(),
                accepting: false,
                incoming_image: InlineImageReceiver::default(),
                deaddrop_operation_sequence: 0,
            },
        );
        let bytes = b"\x89PNG\r\n\x1a\nruntime-owned-image";
        let frames = commtools_core::inline_image_frames(7003, "preview.png", "image/png", bytes)
            .expect("build inline image frames");

        for frame in frames.iter().take(frames.len() - 1) {
            assert_eq!(
                driver
                    .contact_image_frame_received(session_id, frame.clone())
                    .expect("consume partial image frame"),
                None
            );
        }
        assert!(matches!(
            driver
                .contact_image_frame_received(
                    session_id,
                    frames.last().expect("image terminator").clone(),
                )
                .expect("complete inline image"),
            Some(FrontendEvent::ImageReceived(ImageReceivedEvent {
                session_id: received_session,
                message_id: 7003,
                filename,
                mime,
                bytes: received,
                sender_b32: None,
                ..
            })) if received_session == session_id
                && filename == "preview.png"
                && mime == "image/png"
                && received.as_slice() == bytes
        ));
    }

    #[test]
    fn group_image_delivery_tracking_survives_partial_acknowledgements() {
        let mut driver = ApplicationDriver::with_optional_vault(None);
        let session_id = SessionId::new(92);
        let message_id = 7002;
        driver
            .outgoing_group_images
            .insert((session_id, message_id));

        let partial = commtools_core::GroupDeliveryStatus {
            message_id,
            expected: BTreeSet::from(["alice.b32.i2p".into(), "bob.b32.i2p".into()]),
            received: BTreeSet::from(["alice.b32.i2p".into()]),
        };
        let event = driver
            .translate_frontend_event(ApplicationEvent::Group {
                session_id,
                event: CoreGroupSessionEvent::DeliveryUpdated(partial),
            })
            .expect("classify partial group image delivery");
        assert_eq!(
            event,
            Some(FrontendEvent::ImageDeliveryUpdated(ImageDeliveryEvent {
                session_id,
                message_id,
                group: true,
                received: 1,
                expected: 2,
            }))
        );
        assert!(
            driver
                .outgoing_group_images
                .contains(&(session_id, message_id))
        );

        let complete = commtools_core::GroupDeliveryStatus {
            message_id,
            expected: BTreeSet::from(["alice.b32.i2p".into(), "bob.b32.i2p".into()]),
            received: BTreeSet::from(["alice.b32.i2p".into(), "bob.b32.i2p".into()]),
        };
        let event = driver
            .translate_frontend_event(ApplicationEvent::Group {
                session_id,
                event: CoreGroupSessionEvent::DeliveryUpdated(complete),
            })
            .expect("classify complete group image delivery");
        assert_eq!(
            event,
            Some(FrontendEvent::ImageDeliveryUpdated(ImageDeliveryEvent {
                session_id,
                message_id,
                group: true,
                received: 2,
                expected: 2,
            }))
        );
        assert!(
            !driver
                .outgoing_group_images
                .contains(&(session_id, message_id))
        );
    }

    fn test_vault_repository(root: &Path) -> VaultRepository {
        let params = VaultKdfParams::new(MIN_ARGON2_MEMORY_KIB, MIN_ARGON2_ITERATIONS, 1)
            .expect("test KDF parameters");
        VaultRepository::with_kdf(root, params).expect("vault repository")
    }

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "commtools-runtime-{label}-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("create test directory");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
