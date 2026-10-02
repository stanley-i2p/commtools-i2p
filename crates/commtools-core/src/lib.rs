#![forbid(unsafe_code)]

//! Presentation-independent CommTools protocol, identity, session, storage, and vault engines.
//!
//! Frontends/UI should normally use `commtools-runtime` rather than coordinating these modules
//! directly. Keeping UI policy outside this crate preserves the same security framework(!!!) across
//! terminal, desktop, and other clients.

pub mod application;
pub mod config;
pub mod constants;
pub mod crypto;
pub mod deaddrop;
pub mod deaddrop_profile;
pub mod error;
pub mod file_transfer;
pub mod group_roster;
pub mod group_session;
pub mod history;
pub mod ids;
pub mod inline_image;
pub mod offline;
pub mod offline_coordinator;
pub mod one_to_one;
pub mod private_group_invite;
pub mod protocol;
pub mod rendezvous;
pub mod runtime;
pub mod sam;
pub mod sam_runtime;
pub mod storage;
pub mod vault;

pub use application::{
    ApplicationAction, ApplicationCoordinator, ApplicationCoordinatorError, ApplicationEvent,
    ApplicationOutput, ApplicationPhase, FileTransferDirection, FileTransferEvent,
    ManagedSessionInfo, ManagedSessionKey, ManagedSessionPhase, RendezvousEvent,
};
pub use config::{CoreConfig, SamConfig, SamEndpoint, StorageConfig};
pub use crypto::{CryptoError, SessionCrypto};
pub use deaddrop::{
    DeaddropClient, DeaddropConfig, DeaddropError, GetReplicaResult, GetReplicaStatus, GetResult,
    PutReplicaResult, PutReplicaStatus, PutResult, PutStatus, normalize_deaddrop_server,
};
pub use deaddrop_profile::{
    ACTIVE_DEADDROP_REPLICA_COUNT, DEADDROP_EXPLORATION_INTERVAL_OPERATIONS,
    DEADDROP_LATENCY_EMA_ALPHA, DeaddropSelection, ranked_deaddrop_servers, record_get_result,
    record_put_result, select_deaddrop_servers,
};
pub use error::CoreError;
pub use file_transfer::{
    FILE_TRANSFER_CHUNK_BYTES, FILE_TRANSFER_MAX_BYTES, FILE_TRANSFER_MAX_FILENAME_BYTES,
    FileTransferControl, FileTransferError, sanitize_file_filename,
};
pub use group_roster::{
    GroupControlMessage, GroupDissolution, GroupInvite, GroupRosterError, GroupRosterSync,
    InviteApplyOutcome, InviteRedemption, RosterApplyOutcome,
};
pub use group_session::{
    GroupCollisionWinner, GroupDeliveryStatus, GroupDisconnectReason, GroupSession,
    GroupSessionAction, GroupSessionConfig, GroupSessionError, GroupSessionEvent,
    GroupSessionOutput,
};
pub use history::{HistoryError, HistoryRecord, HistoryRepository, HistoryScope};
pub use ids::{ContactId, GroupId, SessionId, TransientId};
pub use inline_image::{
    INLINE_IMAGE_CHUNK_BYTES, INLINE_IMAGE_TRANSFER_MAX_BYTES, ImageTransferHeader,
    ImageTransferKind, InlineImage, InlineImageError, InlineImageReceiver,
    ORIGINAL_IMAGE_CONTROL_PREFIX, OriginalImageControl, OriginalImageMetadata, image_sha256_hex,
    inline_image_frames, inline_image_frames_with_header, sanitize_image_filename,
    validate_image_bytes, validate_image_mime,
};
pub use offline::{
    OfflineContext, OfflineError, OfflineIndexSync, OfflineMissingIndexSnapshot,
    OfflineSkippedIndexSnapshot, OfflineState, OfflineStateSnapshot,
};
pub use offline_coordinator::{
    OfflineCoordinator, OfflineCoordinatorAction, OfflineCoordinatorError, OfflineCoordinatorEvent,
    OfflineCoordinatorMode, OfflineCoordinatorOutput, OfflineOperationId,
};
pub use one_to_one::{
    CollisionWinner, ConnectionDirection, ConnectionId, DisconnectReason, FileFrameSealer,
    OneToOneAction, OneToOneConfig, OneToOneError, OneToOneEvent, OneToOneOutput, OneToOnePhase,
    OneToOneSession, PinnedPeer,
};
pub use protocol::{Frame, MessageType, ProtocolError, generate_message_id};
pub use runtime::{CoreCommand, CoreEvent};
pub use sam::{
    AcceptedIncoming, LiveConnection, SamError, SamReply, SamSessionConfig, SamSessionInfo,
    SamSessionKind, TunnelOptions,
};
pub use sam_runtime::SamRuntime;
pub use storage::{
    ContactRecord, DEFAULT_DEADDROP_SERVERS, DeaddropServerStat, GlobalSettings,
    GroupIssuedInviteRecord, GroupMemberRecord, GroupRecord, MAX_DEADDROP_SERVERS,
    PersistedOfflineState, PersistentIdentity, SamFailureAction, SecretBytes32, SecretText,
    StorageError, StorageRepository, StorageSnapshot, TofuPeerPin, TunnelSettings,
    group_storage_key,
};
pub use vault::{
    ContactBackupInspection, GroupBackupInspection, UnlockedVault, VaultError, VaultKdfParams,
    VaultLease, VaultRepository, suggested_backup_export_path, suggested_backup_import_path,
    suggested_contact_backup_export_path, suggested_contact_backup_import_path,
    suggested_group_backup_export_path, suggested_group_backup_import_path,
};
