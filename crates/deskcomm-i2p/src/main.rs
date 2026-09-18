#![deny(unsafe_code)]

mod backend;
mod cli;
mod image_media;

use arboard::Clipboard;
use backend::{BackendCommand, BackendEvent, BackendHandle, BackendSender};
use cli::{ParseOutcome, StartupOptions};
use commtools_core::group_roster::{MAX_PUBLIC_INVITE_BYTES, PUBLIC_INVITE_PREFIX};
use commtools_core::group_session::GROUP_IMAGE_TRANSFER_MAX_BYTES;
use commtools_core::private_group_invite::{InputKind, MAX_ENCODED_LEN, input_kind};
use commtools_core::rendezvous::{
    InputKind as RendezvousInputKind, MAX_ENCODED_LEN as MAX_RENDEZVOUS_INPUT_BYTES,
    input_kind as rendezvous_input_kind,
};
use commtools_core::{
    ContactBackupInspection, ContactId, DisconnectReason, GroupId, HistoryRecord,
    ManagedSessionKey, ManagedSessionPhase, OfflineCoordinatorMode, OneToOnePhase,
    SamFailureAction, SessionId, TransientId, TunnelSettings, VaultRepository,
};
use commtools_runtime::{
    CommToolsCommand, CommToolsCommandResult, CommToolsSnapshot, ContactSessionEvent,
    FileTransferDirection, FileTransferEvent, FrontendEvent, GroupSessionEvent,
    HistoryWriteOutcome, ImageDeliveryEvent, ImageReceivedEvent, ImageSendResult,
    OfflinePollResult, OfflineSessionEvent, OriginalImageData, OriginalImageReceivedEvent,
    OriginalImageRequestResult, RendezvousSessionEvent, RuntimeOperationEvent,
    SamMonitorStatus, SamTestStatus, SessionLifecycleEvent, TextDeliveryEvent, TextReceivedEvent,
    TextSendResult,
};
use image_media::{PreparedImage, prepare_image_path, slint_image_from_bytes};
use slint::{
    CloseRequestResponse, ComponentHandle, Model, ModelRc, SharedString, Timer, TimerMode, VecModel,
};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::Zeroizing;

slint::include_modules!();

const UI_EVENT_INTERVAL: Duration = Duration::from_millis(50);
const MAX_PRESENTED_TEXT_MESSAGES: usize = 5_000;
const TEXT_BUBBLE_MAX_WIDTH: f32 = 460.0;
const TEXT_BUBBLE_MIN_BODY_WIDTH: f32 = 92.0;
const IMAGE_BUBBLE_MAX_WIDTH: f32 = 420.0;
const IMAGE_BUBBLE_MAX_HEIGHT: f32 = 360.0;
const IMAGE_BUBBLE_MIN_WIDTH: f32 = 220.0;
const BUBBLE_HORIZONTAL_PADDING: f32 = 20.0;
const OFFLINE_STATUS_VISIBLE_FOR: Duration = Duration::from_secs(8);
const MAX_SESSION_LOG_LINES: usize = 1_000;
const SESSION_LOG_TRIM_BATCH: usize = 100;
const MAX_TRANSIENT_LABEL_CHARS: usize = 64;
const MAX_CHAT_TEXT_BYTES: usize = commtools_core::constants::MAX_FRAME_PAYLOAD_SIZE
    - commtools_core::crypto::MIN_ENCRYPTED_PAYLOAD_SIZE;
const MAX_OFFLINE_CHAT_TEXT_BYTES: usize = commtools_core::deaddrop::MAX_DEADDROP_BLOB_SIZE
    - commtools_core::constants::FRAME_HEADER_LEN
    - commtools_core::crypto::MIN_ENCRYPTED_PAYLOAD_SIZE;
const REPLY_BEGIN_MARKER: &str = "[COMMTOOLS-I2P-REPLY-v1]";
const REPLY_QUOTE_MARKER: &str = "[COMMTOOLS-I2P-QUOTE]";
const REPLY_END_MARKER: &str = "[/COMMTOOLS-I2P-REPLY]";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionLogLevel {
    Info,
    Warning,
    Error,
}

impl SessionLogLevel {
    fn tone(self) -> i32 {
        match self {
            Self::Info => 0,
            Self::Warning => 1,
            Self::Error => 2,
        }
    }
}

#[derive(Debug, Clone)]
struct SessionLogEntry {
    timestamp_utc: String,
    category: String,
    message: String,
    level: SessionLogLevel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplyDraft {
    author: String,
    text: String,
}

#[derive(Debug, Clone)]
struct PresentedMessage {
    message_id: Option<u64>,
    text: String,
    image: Option<slint::Image>,
    image_detail: String,
    image_width: f32,
    image_height: f32,
    bubble_width: f32,
    author: String,
    timestamp_utc: String,
    mine: bool,
    offline: bool,
    stored: bool,
    delivered: bool,
    relayed: bool,
    delivery_received: usize,
    delivery_expected: usize,
    original_size: u64,
    original_sender_b32: Option<String>,
    original_state: OriginalImagePresentationState,
    original_received: u64,
    file: Option<PresentedFileTransfer>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PresentedFileTransferState {
    IncomingOffer,
    AwaitingAcceptance,
    Active,
    Completed,
    Declined,
    Cancelled,
    Expired,
    Failed,
}

#[derive(Debug, Clone)]
struct PresentedFileTransfer {
    transfer_id: u64,
    filename: String,
    total_bytes: u64,
    transferred_bytes: u64,
    state: PresentedFileTransferState,
    saved_path: Option<String>,
    failure: Option<String>,
}

struct FileTransferPresentation {
    bytes: String,
    progress: f32,
    status: String,
    path: String,
    can_accept: bool,
    can_decline: bool,
    can_cancel: bool,
}

#[derive(Debug, Clone, Copy)]
struct FileTransferTarget {
    session_id: SessionId,
    transfer_id: u64,
    state: PresentedFileTransferState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OriginalImagePresentationState {
    None,
    Available,
    Requesting,
    Receiving,
    Cached,
    Unavailable,
    Failed,
}

#[derive(Debug, Clone)]
struct PresentedOriginalImage {
    source_session_id: SessionId,
    filename: String,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct OriginalImageTarget {
    session_id: SessionId,
    media_id: u64,
    sender_b32: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingOriginalImageCommandKind {
    Request,
    Cancel,
}

#[derive(Debug, Clone)]
struct PendingOriginalImageCommand {
    kind: PendingOriginalImageCommandKind,
    target: OriginalImageTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingRendezvousCommandKind {
    GenerateRequest,
    AnswerRequest,
    ConnectResponse,
    Revoke,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingRendezvousCommand {
    session_id: SessionId,
    kind: PendingRendezvousCommandKind,
}

#[derive(Debug, Clone)]
struct RendezvousOutputPresentation {
    label: String,
    value: Zeroizing<String>,
}

#[derive(Debug, Clone)]
struct PendingContactImport {
    path: PathBuf,
    passphrase: Zeroizing<String>,
}

#[derive(Debug, Clone)]
struct ContactImportConfirmation {
    path: PathBuf,
    passphrase: Zeroizing<String>,
    inspection: ContactBackupInspection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OfflineActivityState {
    Poll,
    Put,
    Hit,
    Miss,
    Fail,
}

impl OfflineActivityState {
    fn label(self) -> &'static str {
        match self {
            Self::Poll => "DD POLL",
            Self::Put => "DD PUT",
            Self::Hit => "DD HIT",
            Self::Miss => "DD MISS",
            Self::Fail => "DD FAIL",
        }
    }

    fn tone(self) -> i32 {
        match self {
            Self::Poll => 3,
            Self::Put => 2,
            Self::Hit => 1,
            Self::Miss => 0,
            Self::Fail => 4,
        }
    }
}

#[derive(Debug, Clone)]
struct OfflineActivityPresentation {
    state: OfflineActivityState,
    expires_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ContactCatalogEntry {
    Persistent(ContactId),
    Transient(TransientId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TofuPresentationState {
    Verified,
    Mismatch,
}

#[derive(Default)]
struct UiMappings {
    contacts: RefCell<Vec<ContactId>>,
    contact_catalog: RefCell<Vec<ContactCatalogEntry>>,
    pending_contact_selection: RefCell<Option<ContactCatalogEntry>>,
    contact_deaddrops: RefCell<Vec<String>>,
    details_contact: RefCell<Option<ContactId>>,
    groups: RefCell<Vec<GroupId>>,
    group_members: RefCell<Vec<String>>,
    details_group: RefCell<Option<GroupId>>,
    pending_group_selection: RefCell<Option<GroupId>>,
    sessions: RefCell<Vec<Option<SessionId>>>,
    visible_session_keys: RefCell<Vec<ManagedSessionKey>>,
    opening_sessions: RefCell<Vec<ManagedSessionKey>>,
    transient_labels: RefCell<BTreeMap<TransientId, String>>,
    pending_transient_label: RefCell<Option<String>>,
    session_keys: RefCell<BTreeMap<SessionId, ManagedSessionKey>>,
    contact_tofu_states: RefCell<BTreeMap<SessionId, TofuPresentationState>>,
    offline_activities: RefCell<BTreeMap<SessionId, OfflineActivityPresentation>>,
    conversations: RefCell<BTreeMap<SessionId, Vec<PresentedMessage>>>,
    reply_drafts: RefCell<BTreeMap<SessionId, ReplyDraft>>,
    session_logs: RefCell<BTreeMap<SessionId, VecDeque<SessionLogEntry>>>,
    open_log_panels: RefCell<BTreeSet<SessionId>>,
    original_viewer: RefCell<Option<PresentedOriginalImage>>,
    pending_original_command: RefCell<Option<PendingOriginalImageCommand>>,
    rendezvous_panel_session: RefCell<Option<SessionId>>,
    rendezvous_outputs: RefCell<BTreeMap<SessionId, RendezvousOutputPresentation>>,
    rendezvous_authenticated: RefCell<BTreeSet<SessionId>>,
    pending_rendezvous_command: RefCell<Option<PendingRendezvousCommand>>,
    pending_contact_import: RefCell<Option<PendingContactImport>>,
    contact_import_confirmation: RefCell<Option<ContactImportConfirmation>>,
    history_requested: RefCell<BTreeSet<ManagedSessionKey>>,
    latest_snapshot: RefCell<Option<CommToolsSnapshot>>,
}

#[derive(Debug, Error)]
enum AppError {
    #[error("{0}")]
    Arguments(String),
    #[error(transparent)]
    Vault(#[from] commtools_core::VaultError),
    #[error(transparent)]
    Ui(#[from] slint::PlatformError),
    #[error("could not start the DeskComm backend: {0}")]
    BackendStart(#[from] std::io::Error),
    #[error("DeskComm backend terminated unexpectedly")]
    BackendPanicked,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("DeskComm-I2P: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), AppError> {
    let options = match cli::parse_process_args().map_err(AppError::Arguments)? {
        ParseOutcome::Run(options) => options,
        ParseOutcome::Print(output) => {
            println!("{output}");
            return Ok(());
        }
    };
    run_desktop(options)
}

fn run_desktop(options: StartupOptions) -> Result<(), AppError> {
    let repository = VaultRepository::new(&options.data_dir)?;
    let vault_root = options.data_dir.clone();
    let vault_exists = repository.exists()?;
    let lease = repository.try_acquire_lease()?;
    let (backend, events) = BackendHandle::spawn(repository, lease)?;
    let ui = AppWindow::new()?;
    let mappings = Rc::new(UiMappings::default());
    let clipboard = Rc::new(RefCell::new(None));

    ui.set_screen(if vault_exists { 0 } else { 1 });
    ui.set_vault_path(options.data_dir.display().to_string().into());

    let copy_address_ui = ui.as_weak();
    let copy_address_clipboard = clipboard.clone();
    ui.on_copy_address(move |address, local| {
        let Some(ui) = copy_address_ui.upgrade() else {
            return;
        };
        let address = address.trim();
        if address.is_empty() {
            return;
        }
        match set_clipboard_text(&copy_address_clipboard, address) {
            Ok(()) => ui.set_operation_status(
                if local {
                    "My B32 copied to the system clipboard"
                } else {
                    "Peer B32 copied to the system clipboard"
                }
                .into(),
            ),
            Err(error) => ui.set_operation_status(format!("Clipboard copy failed: {error}").into()),
        }
    });

    let toggle_logs_ui = ui.as_weak();
    let toggle_logs_mappings = mappings.clone();
    ui.on_toggle_session_logs(move |index| {
        let Some(ui) = toggle_logs_ui.upgrade() else {
            return;
        };
        let Some(session_id) = row_value(&toggle_logs_mappings.sessions, index).flatten() else {
            ui.set_operation_status("Session logs are unavailable while the session opens".into());
            return;
        };
        let visible = {
            let mut open = toggle_logs_mappings.open_log_panels.borrow_mut();
            if open.remove(&session_id) {
                false
            } else {
                open.insert(session_id);
                true
            }
        };
        refresh_session_logs(&ui, &toggle_logs_mappings);
        ui.set_operation_status(
            if visible {
                "Session logs opened"
            } else {
                "Session logs closed"
            }
            .into(),
        );
    });

    let clear_logs_ui = ui.as_weak();
    let clear_logs_mappings = mappings.clone();
    ui.on_clear_session_logs(move |index| {
        let Some(ui) = clear_logs_ui.upgrade() else {
            return;
        };
        let Some(session_id) = row_value(&clear_logs_mappings.sessions, index).flatten() else {
            return;
        };
        clear_logs_mappings
            .session_logs
            .borrow_mut()
            .remove(&session_id);
        refresh_session_logs(&ui, &clear_logs_mappings);
        ui.set_operation_status("Session logs cleared".into());
    });

    let copy_logs_ui = ui.as_weak();
    let copy_logs_mappings = mappings.clone();
    let copy_logs_clipboard = clipboard.clone();
    ui.on_copy_session_logs(move |index| {
        let Some(ui) = copy_logs_ui.upgrade() else {
            return;
        };
        let Some(session_id) = row_value(&copy_logs_mappings.sessions, index).flatten() else {
            return;
        };
        let text = joined_session_log(&copy_logs_mappings, session_id);
        if text.is_empty() {
            ui.set_operation_status("Session logs are empty".into());
            return;
        }
        match set_clipboard_text(&copy_logs_clipboard, &text) {
            Ok(()) => ui.set_operation_status("Session logs copied to the system clipboard".into()),
            Err(error) => ui.set_operation_status(format!("Clipboard copy failed: {error}").into()),
        }
    });

    let command_sender = backend.sender();
    let gate_ui = ui.as_weak();
    ui.on_submit_gate(move |password, confirmation| {
        let Some(ui) = gate_ui.upgrade() else {
            return;
        };
        let create = ui.get_screen() == 1;
        if password.is_empty() {
            ui.set_gate_error("Passphrase must not be empty".into());
            return;
        }
        if create && password != confirmation {
            ui.set_gate_error("Passphrases do not match".into());
            return;
        }

        ui.set_busy(true);
        ui.set_gate_error("".into());
        ui.set_password("".into());
        ui.set_confirm_password("".into());
        if let Err(error) = command_sender.send(BackendCommand::OpenVault {
            passphrase: Zeroizing::new(password.to_string()),
            create,
        }) {
            ui.set_busy(false);
            ui.set_gate_error(error.into());
        }
    });

    let sam_host_sender = backend.sender();
    let sam_host_ui = ui.as_weak();
    ui.on_set_sam_host(move |host| {
        let Some(ui) = sam_host_ui.upgrade() else {
            return;
        };
        let host = host.trim();
        if host.is_empty() {
            ui.set_operation_status("SAM host must not be empty".into());
            return;
        }
        ui.set_settings_sam_host(host.into());
        ui.set_operation_busy(true);
        ui.set_operation_status("Saving SAM host...".into());
        if let Err(error) = sam_host_sender.send(BackendCommand::Runtime(
            CommToolsCommand::SetSamHost(host.to_string()),
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let sam_port_sender = backend.sender();
    let sam_port_ui = ui.as_weak();
    ui.on_set_sam_port(move |port| {
        let Some(ui) = sam_port_ui.upgrade() else {
            return;
        };
        let Ok(port) = port.trim().parse::<u16>() else {
            ui.set_operation_status("SAM port must be an integer from 1 to 65535".into());
            return;
        };
        if port == 0 {
            ui.set_operation_status("SAM port must be an integer from 1 to 65535".into());
            return;
        }
        ui.set_settings_sam_port(port.to_string().into());
        ui.set_operation_busy(true);
        ui.set_operation_status("Saving SAM port...".into());
        if let Err(error) = sam_port_sender.send(BackendCommand::Runtime(
            CommToolsCommand::SetSamPort(port),
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let default_tunnels_sender = backend.sender();
    let default_tunnels_ui = ui.as_weak();
    ui.on_set_default_tunnels(move |length, quantity| {
        let Some(ui) = default_tunnels_ui.upgrade() else {
            return;
        };
        let (Ok(length), Ok(quantity)) = (u8::try_from(length), u8::try_from(quantity)) else {
            ui.set_operation_status("Invalid default tunnel settings".into());
            return;
        };
        let tunnels = TunnelSettings { length, quantity };
        if let Err(error) = tunnels.validate() {
            ui.set_operation_status(error.to_string().into());
            return;
        }
        ui.set_operation_busy(true);
        ui.set_operation_status("Saving default tunnel settings...".into());
        if let Err(error) = default_tunnels_sender.send(BackendCommand::Runtime(
            CommToolsCommand::SetDefaultTunnelSettings(tunnels),
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let sam_liveness_sender = backend.sender();
    let sam_liveness_ui = ui.as_weak();
    ui.on_set_sam_liveness(move |enabled| {
        let Some(ui) = sam_liveness_ui.upgrade() else {
            return;
        };
        ui.set_settings_sam_liveness_enabled(!enabled);
        ui.set_operation_busy(true);
        ui.set_operation_status("Saving SAM monitoring setting...".into());
        if let Err(error) = sam_liveness_sender.send(BackendCommand::Runtime(
            CommToolsCommand::SetSamLivenessEnabled(enabled),
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let sam_failure_sender = backend.sender();
    let sam_failure_ui = ui.as_weak();
    ui.on_set_sam_failure_action(move |shutdown| {
        let Some(ui) = sam_failure_ui.upgrade() else {
            return;
        };
        ui.set_settings_sam_shutdown_on_failure(!shutdown);
        let action = if shutdown {
            SamFailureAction::GracefulShutdown
        } else {
            SamFailureAction::WarningOnly
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Saving SAM failure action...".into());
        if let Err(error) = sam_failure_sender.send(BackendCommand::Runtime(
            CommToolsCommand::SetSamFailureAction(action),
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let sam_test_sender = backend.sender();
    let sam_test_ui = ui.as_weak();
    ui.on_test_sam(move || {
        let Some(ui) = sam_test_ui.upgrade() else {
            return;
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Testing the configured SAM endpoint...".into());
        if let Err(error) =
            sam_test_sender.send(BackendCommand::Runtime(CommToolsCommand::TestSam))
        {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let begin_data_ui = ui.as_weak();
    let begin_data_root = vault_root.clone();
    let begin_data_mappings = mappings.clone();
    ui.on_begin_settings_data_action(move |action| {
        let Some(ui) = begin_data_ui.upgrade() else {
            return;
        };
        if !(1..=4).contains(&action) {
            return;
        }
        begin_data_mappings.pending_contact_import.borrow_mut().take();
        begin_data_mappings
            .contact_import_confirmation
            .borrow_mut()
            .take();
        clear_settings_data_form(&ui);
        ui.set_settings_data_action(action);
        ui.set_settings_data_option(true);
        let default_path = match action {
            1 | 2 => sibling_export_path(&begin_data_root, "-backup.ctbak"),
            3 => sibling_export_path(&begin_data_root, "-contact.ctcontact"),
            _ => PathBuf::new(),
        };
        ui.set_settings_data_path(default_path.display().to_string().into());
    });

    let choose_data_ui = ui.as_weak();
    let choose_data_root = vault_root.clone();
    ui.on_choose_settings_data_path(move |action| {
        let Some(ui) = choose_data_ui.upgrade() else {
            return;
        };
        let current = PathBuf::from(ui.get_settings_data_path().as_str());
        let default_path = match action {
            1 | 2 => sibling_export_path(&choose_data_root, "-backup.ctbak"),
            3 => sibling_export_path(&choose_data_root, "-contact.ctcontact"),
            _ => return,
        };
        if let Some(path) = choose_data_path(action, &current, &default_path) {
            ui.set_settings_data_path(path.display().to_string().into());
        }
    });

    let submit_data_sender = backend.sender();
    let submit_data_ui = ui.as_weak();
    let submit_data_mappings = mappings.clone();
    ui.on_submit_settings_data_action(
        move |action, path, passphrase, confirmation, option| {
            let Some(ui) = submit_data_ui.upgrade() else {
                return;
            };
            if !ui.get_settings_transport_editable() {
                ui.set_operation_status("Close all chats before managing stored data".into());
                return;
            }
            let path = path.trim();
            if action != 4 && path.is_empty() {
                ui.set_operation_status("A data file path is required".into());
                return;
            }
            if passphrase.is_empty() {
                ui.set_operation_status(
                    if action == 4 {
                        "The current vault passphrase is required"
                    } else {
                        "An encryption passphrase is required"
                    }
                    .into(),
                );
                return;
            }
            if action == 1 && passphrase != confirmation {
                ui.set_operation_status("Backup passphrases do not match".into());
                return;
            }

            match action {
                1 => {
                    let command = CommToolsCommand::ExportBackup {
                        path: PathBuf::from(path),
                        passphrase: Zeroizing::new(passphrase.to_string()),
                        include_files: option,
                    };
                    clear_settings_data_secrets(&ui);
                    ui.set_operation_busy(true);
                    ui.set_operation_status("Creating encrypted backup...".into());
                    if let Err(error) =
                        submit_data_sender.send(BackendCommand::Runtime(command))
                    {
                        ui.set_operation_busy(false);
                        ui.set_operation_status(error.into());
                    }
                }
                2 => {
                    ui.set_settings_data_confirmation_text(
                        "Replace all contacts, groups, settings, and retained history from this backup?"
                            .into(),
                    );
                    ui.set_settings_data_confirmation_visible(true);
                }
                3 => {
                    *submit_data_mappings.pending_contact_import.borrow_mut() =
                        Some(PendingContactImport {
                            path: PathBuf::from(path),
                            passphrase: Zeroizing::new(passphrase.to_string()),
                        });
                    clear_settings_data_secrets(&ui);
                    ui.set_operation_busy(true);
                    ui.set_operation_status("Inspecting encrypted contact backup...".into());
                    let pending = submit_data_mappings.pending_contact_import.borrow();
                    let pending = pending.as_ref().expect("pending import was just stored");
                    if let Err(error) = submit_data_sender.send(BackendCommand::Runtime(
                        CommToolsCommand::InspectContactBackup {
                            path: pending.path.clone(),
                            passphrase: pending.passphrase.clone(),
                        },
                    )) {
                        drop(pending);
                        submit_data_mappings.pending_contact_import.borrow_mut().take();
                        ui.set_operation_busy(false);
                        ui.set_operation_status(error.into());
                    }
                }
                4 => {
                    ui.set_settings_data_confirmation_text(
                        "Permanently wipe the complete local vault and all received files? DeskComm will shut down."
                            .into(),
                    );
                    ui.set_settings_data_confirmation_visible(true);
                }
                _ => {}
            }
        },
    );

    let confirm_data_sender = backend.sender();
    let confirm_data_ui = ui.as_weak();
    let confirm_data_mappings = mappings.clone();
    ui.on_confirm_settings_data_action(move |action, confirmed| {
        let Some(ui) = confirm_data_ui.upgrade() else {
            return;
        };
        if !confirmed {
            confirm_data_mappings.pending_contact_import.borrow_mut().take();
            confirm_data_mappings
                .contact_import_confirmation
                .borrow_mut()
                .take();
            clear_settings_data_form(&ui);
            ui.set_operation_status("Data operation cancelled".into());
            return;
        }

        let command = match action {
            2 => {
                let path = PathBuf::from(ui.get_settings_data_path().as_str());
                let passphrase = ui.get_settings_data_passphrase();
                if path.as_os_str().is_empty() || passphrase.is_empty() {
                    ui.set_operation_status("Backup path and passphrase are required".into());
                    return;
                }
                CommToolsCommand::RestoreBackup {
                    path,
                    passphrase: Zeroizing::new(passphrase.to_string()),
                    restore_files: ui.get_settings_data_option(),
                }
            }
            3 => {
                let Some(confirmation) = confirm_data_mappings
                    .contact_import_confirmation
                    .borrow_mut()
                    .take()
                else {
                    ui.set_operation_status("Contact import confirmation expired".into());
                    clear_settings_data_form(&ui);
                    return;
                };
                CommToolsCommand::ImportContactBackup {
                    path: confirmation.path,
                    passphrase: confirmation.passphrase,
                    replace: confirmation.inspection.replacement_contact_id.is_some(),
                }
            }
            4 => {
                let passphrase = ui.get_settings_data_passphrase();
                if passphrase.is_empty() {
                    ui.set_operation_status("The current vault passphrase is required".into());
                    return;
                }
                CommToolsCommand::AuthorizeWipeAll {
                    vault_passphrase: Zeroizing::new(passphrase.to_string()),
                }
            }
            _ => return,
        };
        clear_settings_data_secrets(&ui);
        ui.set_settings_data_confirmation_visible(false);
        ui.set_operation_busy(true);
        ui.set_operation_status(
            match action {
                2 => "Restoring encrypted backup...",
                3 => "Importing encrypted contact backup...",
                4 => "Authorizing complete local wipe...",
                _ => "Applying data operation...",
            }
            .into(),
        );
        if let Err(error) = confirm_data_sender.send(BackendCommand::Runtime(command)) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let cancel_data_ui = ui.as_weak();
    let cancel_data_mappings = mappings.clone();
    ui.on_cancel_settings_data_action(move || {
        let Some(ui) = cancel_data_ui.upgrade() else {
            return;
        };
        cancel_data_mappings.pending_contact_import.borrow_mut().take();
        cancel_data_mappings
            .contact_import_confirmation
            .borrow_mut()
            .take();
        clear_settings_data_form(&ui);
        ui.set_operation_status("Data operation cancelled".into());
    });

    let create_sender = backend.sender();
    let create_ui = ui.as_weak();
    ui.on_create_contact(move |display_name| {
        let Some(ui) = create_ui.upgrade() else {
            return;
        };
        let display_name = display_name.trim();
        if display_name.is_empty() {
            ui.set_operation_status("Contact name must not be empty".into());
            return;
        }
        ui.set_operation_busy(true);
        ui.set_operation_status("Creating contact...".into());
        if let Err(error) =
            create_sender.send(BackendCommand::Runtime(CommToolsCommand::CreateContact {
                display_name: display_name.to_string(),
            }))
        {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let transient_sender = backend.sender();
    let transient_ui = ui.as_weak();
    let transient_mappings = mappings.clone();
    ui.on_open_transient(move |display_label| {
        let Some(ui) = transient_ui.upgrade() else {
            return;
        };
        let display_label = normalize_transient_label(&display_label);
        *transient_mappings.pending_transient_label.borrow_mut() = Some(display_label);
        ui.set_operation_busy(true);
        ui.set_operation_status("Opening transient session...".into());
        if let Err(error) =
            transient_sender.send(BackendCommand::Runtime(CommToolsCommand::OpenTransient))
        {
            transient_mappings
                .pending_transient_label
                .borrow_mut()
                .take();
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let open_sender = backend.sender();
    let open_ui = ui.as_weak();
    let open_mappings = mappings.clone();
    ui.on_open_contact(move |index| {
        let Some(ui) = open_ui.upgrade() else {
            return;
        };
        let Some(entry) = row_value(&open_mappings.contact_catalog, index) else {
            ui.set_operation_status("Select a valid contact".into());
            return;
        };
        if focus_catalog_session(&ui, &open_mappings, &entry) {
            ui.set_operation_status("Focused existing conversation".into());
            return;
        }
        let ContactCatalogEntry::Persistent(contact_id) = entry else {
            ui.set_operation_status("Transient session is still opening".into());
            return;
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Opening contact session...".into());
        if let Err(error) =
            open_sender.send(BackendCommand::Runtime(CommToolsCommand::OpenContact {
                contact_id,
            }))
        {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let select_contact_ui = ui.as_weak();
    let select_contact_mappings = mappings.clone();
    ui.on_select_contact(move |index| {
        let Some(ui) = select_contact_ui.upgrade() else {
            return;
        };
        let selected = persistent_contact_id(&select_contact_mappings, index);
        *select_contact_mappings.details_contact.borrow_mut() = None;
        refresh_contact_details(&ui, &select_contact_mappings, selected.as_ref());
    });

    let rename_contact_sender = backend.sender();
    let rename_contact_ui = ui.as_weak();
    let rename_contact_mappings = mappings.clone();
    ui.on_rename_contact(move |index, display_name| {
        let Some(ui) = rename_contact_ui.upgrade() else {
            return;
        };
        let Some(contact_id) = persistent_contact_id(&rename_contact_mappings, index) else {
            ui.set_operation_status("Select a valid persistent contact".into());
            return;
        };
        if contact_is_active(&rename_contact_mappings, &contact_id) {
            ui.set_operation_status("Close the contact session before renaming it".into());
            return;
        }
        let display_name = display_name.trim();
        if display_name.is_empty() {
            ui.set_operation_status("Contact name must not be empty".into());
            return;
        }
        ui.set_operation_busy(true);
        ui.set_operation_status("Renaming contact...".into());
        if let Err(error) = rename_contact_sender.send(BackendCommand::Runtime(
            CommToolsCommand::RenameContact {
                contact_id,
                display_name: display_name.to_string(),
            },
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let reset_contact_sender = backend.sender();
    let reset_contact_ui = ui.as_weak();
    let reset_contact_mappings = mappings.clone();
    ui.on_reset_contact(move |index| {
        let Some(ui) = reset_contact_ui.upgrade() else {
            return;
        };
        let Some(contact_id) = persistent_contact_id(&reset_contact_mappings, index) else {
            ui.set_operation_status("Select a valid persistent contact".into());
            return;
        };
        if contact_is_active(&reset_contact_mappings, &contact_id) {
            ui.set_operation_status("Close the contact session before resetting it".into());
            return;
        }
        ui.set_operation_busy(true);
        ui.set_operation_status("Resetting contact...".into());
        if let Err(error) = reset_contact_sender.send(BackendCommand::Runtime(
            CommToolsCommand::ResetContact { contact_id },
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let delete_contact_sender = backend.sender();
    let delete_contact_ui = ui.as_weak();
    let delete_contact_mappings = mappings.clone();
    ui.on_delete_contact(move |index| {
        let Some(ui) = delete_contact_ui.upgrade() else {
            return;
        };
        let Some(contact_id) = persistent_contact_id(&delete_contact_mappings, index) else {
            ui.set_operation_status("Select a valid persistent contact".into());
            return;
        };
        if contact_is_active(&delete_contact_mappings, &contact_id) {
            ui.set_operation_status("Close the contact session before deleting it".into());
            return;
        }
        ui.set_operation_busy(true);
        ui.set_operation_status("Deleting contact...".into());
        if let Err(error) = delete_contact_sender.send(BackendCommand::Runtime(
            CommToolsCommand::DeleteContact { contact_id },
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let begin_contact_export_ui = ui.as_weak();
    let begin_contact_export_mappings = mappings.clone();
    let begin_contact_export_root = vault_root.clone();
    ui.on_begin_contact_export(move |index| {
        let Some(ui) = begin_contact_export_ui.upgrade() else {
            return;
        };
        let Some(contact_id) = persistent_contact_id(&begin_contact_export_mappings, index) else {
            ui.set_operation_status("Select a valid persistent contact".into());
            return;
        };
        if contact_is_active(&begin_contact_export_mappings, &contact_id) {
            ui.set_operation_status("Close the contact session before exporting it".into());
            return;
        }
        clear_contact_export_form(&ui);
        ui.set_contact_export_path(
            sibling_export_path(
                &begin_contact_export_root,
                &format!("-contact-{contact_id}.ctcontact"),
            )
            .display()
            .to_string()
            .into(),
        );
        ui.set_contact_export_history(true);
        ui.set_contact_export_visible(true);
    });

    let choose_contact_export_ui = ui.as_weak();
    let choose_contact_export_root = vault_root.clone();
    ui.on_choose_contact_export_path(move || {
        let Some(ui) = choose_contact_export_ui.upgrade() else {
            return;
        };
        let current = PathBuf::from(ui.get_contact_export_path().as_str());
        let default_path = sibling_export_path(&choose_contact_export_root, "-contact.ctcontact");
        if let Some(path) = choose_save_path(
            "Export encrypted contact",
            "CommTools contact",
            "ctcontact",
            &current,
            &default_path,
        ) {
            ui.set_contact_export_path(path.display().to_string().into());
        }
    });

    let submit_contact_export_sender = backend.sender();
    let submit_contact_export_ui = ui.as_weak();
    let submit_contact_export_mappings = mappings.clone();
    ui.on_submit_contact_export(
        move |index, path, passphrase, confirmation, include_history| {
            let Some(ui) = submit_contact_export_ui.upgrade() else {
                return;
            };
            let Some(contact_id) =
                persistent_contact_id(&submit_contact_export_mappings, index)
            else {
                ui.set_operation_status("Select a valid persistent contact".into());
                return;
            };
            if contact_is_active(&submit_contact_export_mappings, &contact_id) {
                ui.set_operation_status("Close the contact session before exporting it".into());
                return;
            }
            let path = path.trim();
            if path.is_empty() || passphrase.is_empty() {
                ui.set_operation_status(
                    "Contact export path and encryption passphrase are required".into(),
                );
                return;
            }
            if passphrase != confirmation {
                ui.set_operation_status("Contact export passphrases do not match".into());
                return;
            }
            let command = CommToolsCommand::ExportContactBackup {
                contact_id,
                path: PathBuf::from(path),
                passphrase: Zeroizing::new(passphrase.to_string()),
                include_history,
            };
            clear_contact_export_secrets(&ui);
            ui.set_operation_busy(true);
            ui.set_operation_status("Exporting encrypted contact...".into());
            if let Err(error) =
                submit_contact_export_sender.send(BackendCommand::Runtime(command))
            {
                ui.set_operation_busy(false);
                ui.set_operation_status(error.into());
            }
        },
    );

    let cancel_contact_export_ui = ui.as_weak();
    ui.on_cancel_contact_export(move || {
        let Some(ui) = cancel_contact_export_ui.upgrade() else {
            return;
        };
        clear_contact_export_form(&ui);
        ui.set_operation_status("Contact export cancelled".into());
    });

    let contact_history_sender = backend.sender();
    let contact_history_ui = ui.as_weak();
    let contact_history_mappings = mappings.clone();
    ui.on_set_contact_history(move |index, enabled| {
        let Some(ui) = contact_history_ui.upgrade() else {
            return;
        };
        let Some(contact_id) = persistent_contact_id(&contact_history_mappings, index) else {
            ui.set_operation_status("Select a valid contact".into());
            return;
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Saving contact history setting...".into());
        if let Err(error) = contact_history_sender.send(BackendCommand::Runtime(
            CommToolsCommand::SetContactHistoryEnabled {
                contact_id,
                enabled,
            },
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let clear_history_sender = backend.sender();
    let clear_history_ui = ui.as_weak();
    let clear_history_mappings = mappings.clone();
    ui.on_clear_contact_history(move |index| {
        let Some(ui) = clear_history_ui.upgrade() else {
            return;
        };
        let Some(contact_id) = persistent_contact_id(&clear_history_mappings, index) else {
            ui.set_operation_status("Select a valid contact".into());
            return;
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Clearing contact text history...".into());
        if let Err(error) =
            clear_history_sender.send(BackendCommand::Runtime(CommToolsCommand::ClearHistory {
                key: ManagedSessionKey::Contact(contact_id),
            }))
        {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let contact_tunnels_sender = backend.sender();
    let contact_tunnels_ui = ui.as_weak();
    let contact_tunnels_mappings = mappings.clone();
    ui.on_set_contact_tunnels(move |index, length, quantity| {
        let Some(ui) = contact_tunnels_ui.upgrade() else {
            return;
        };
        let Some(contact_id) = persistent_contact_id(&contact_tunnels_mappings, index) else {
            ui.set_operation_status("Select a valid contact".into());
            return;
        };
        let (Ok(length), Ok(quantity)) = (u8::try_from(length), u8::try_from(quantity)) else {
            ui.set_operation_status("Invalid contact tunnel settings".into());
            return;
        };
        let tunnels = TunnelSettings { length, quantity };
        if let Err(error) = tunnels.validate() {
            ui.set_operation_status(error.to_string().into());
            return;
        }
        ui.set_operation_busy(true);
        ui.set_operation_status("Saving contact tunnel settings...".into());
        if let Err(error) = contact_tunnels_sender.send(BackendCommand::Runtime(
            CommToolsCommand::SetContactTunnelSettings {
                contact_id,
                tunnels,
            },
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let reset_tunnels_sender = backend.sender();
    let reset_tunnels_ui = ui.as_weak();
    let reset_tunnels_mappings = mappings.clone();
    ui.on_reset_contact_tunnels(move |index| {
        let Some(ui) = reset_tunnels_ui.upgrade() else {
            return;
        };
        let Some(contact_id) = persistent_contact_id(&reset_tunnels_mappings, index) else {
            ui.set_operation_status("Select a valid contact".into());
            return;
        };
        let Some(tunnels) = reset_tunnels_mappings
            .latest_snapshot
            .borrow()
            .as_ref()
            .map(|snapshot| snapshot.settings.default_tunnels)
        else {
            ui.set_operation_status("Runtime settings are unavailable".into());
            return;
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Restoring default contact tunnels...".into());
        if let Err(error) = reset_tunnels_sender.send(BackendCommand::Runtime(
            CommToolsCommand::SetContactTunnelSettings {
                contact_id,
                tunnels,
            },
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let add_deaddrop_sender = backend.sender();
    let add_deaddrop_ui = ui.as_weak();
    let add_deaddrop_mappings = mappings.clone();
    ui.on_add_contact_deaddrop(move |index, server| {
        let Some(ui) = add_deaddrop_ui.upgrade() else {
            return;
        };
        let Some(contact_id) = persistent_contact_id(&add_deaddrop_mappings, index) else {
            ui.set_operation_status("Select a valid contact".into());
            return;
        };
        let server = server.trim();
        if server.is_empty() {
            ui.set_operation_status("Deaddrop server address must not be empty".into());
            return;
        }
        ui.set_operation_busy(true);
        ui.set_operation_status("Adding contact deaddrop server...".into());
        if let Err(error) = add_deaddrop_sender.send(BackendCommand::Runtime(
            CommToolsCommand::AddContactDeaddropServer {
                contact_id,
                server: server.to_string(),
            },
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let remove_deaddrop_sender = backend.sender();
    let remove_deaddrop_ui = ui.as_weak();
    let remove_deaddrop_mappings = mappings.clone();
    ui.on_remove_contact_deaddrop(move |contact_index, server_index| {
        let Some(ui) = remove_deaddrop_ui.upgrade() else {
            return;
        };
        let Some(contact_id) = persistent_contact_id(&remove_deaddrop_mappings, contact_index)
        else {
            ui.set_operation_status("Select a valid contact".into());
            return;
        };
        let Some(server) = row_value(&remove_deaddrop_mappings.contact_deaddrops, server_index)
        else {
            ui.set_operation_status("Select a valid deaddrop server".into());
            return;
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Removing contact deaddrop server...".into());
        if let Err(error) = remove_deaddrop_sender.send(BackendCommand::Runtime(
            CommToolsCommand::RemoveContactDeaddropServer { contact_id, server },
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let create_group_sender = backend.sender();
    let create_group_ui = ui.as_weak();
    ui.on_create_group(move |display_name| {
        let Some(ui) = create_group_ui.upgrade() else {
            return;
        };
        let display_name = display_name.trim();
        if display_name.is_empty() {
            ui.set_operation_status("Group name must not be empty".into());
            return;
        }
        ui.set_operation_busy(true);
        ui.set_operation_status("Creating group...".into());
        if let Err(error) =
            create_group_sender.send(BackendCommand::Runtime(CommToolsCommand::CreateGroup {
                display_name: display_name.to_string(),
            }))
        {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let open_group_sender = backend.sender();
    let open_group_ui = ui.as_weak();
    let open_group_mappings = mappings.clone();
    ui.on_open_group(move |index| {
        let Some(ui) = open_group_ui.upgrade() else {
            return;
        };
        let Some(group_id) = row_value(&open_group_mappings.groups, index) else {
            ui.set_operation_status("Select a valid group".into());
            return;
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Opening group session...".into());
        if let Err(error) =
            open_group_sender.send(BackendCommand::Runtime(CommToolsCommand::OpenGroup {
                group_id,
            }))
        {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let select_group_ui = ui.as_weak();
    let select_group_mappings = mappings.clone();
    ui.on_select_group(move |index| {
        let Some(ui) = select_group_ui.upgrade() else {
            return;
        };
        let selected = row_value(&select_group_mappings.groups, index);
        *select_group_mappings.details_group.borrow_mut() = None;
        refresh_group_details(&ui, &select_group_mappings, selected.as_ref());
    });

    let group_history_sender = backend.sender();
    let group_history_ui = ui.as_weak();
    let group_history_mappings = mappings.clone();
    ui.on_set_group_history(move |index, enabled| {
        let Some(ui) = group_history_ui.upgrade() else {
            return;
        };
        let Some(group_id) = row_value(&group_history_mappings.groups, index) else {
            ui.set_operation_status("Select a valid group".into());
            return;
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Saving group history setting...".into());
        if let Err(error) = group_history_sender.send(BackendCommand::Runtime(
            CommToolsCommand::SetGroupHistoryEnabled { group_id, enabled },
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let clear_group_history_sender = backend.sender();
    let clear_group_history_ui = ui.as_weak();
    let clear_group_history_mappings = mappings.clone();
    ui.on_clear_group_history(move |index| {
        let Some(ui) = clear_group_history_ui.upgrade() else {
            return;
        };
        let Some(group_id) = row_value(&clear_group_history_mappings.groups, index) else {
            ui.set_operation_status("Select a valid group".into());
            return;
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Clearing group text history...".into());
        if let Err(error) = clear_group_history_sender.send(BackendCommand::Runtime(
            CommToolsCommand::ClearHistory {
                key: ManagedSessionKey::Group(group_id),
            },
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let group_name_sender = backend.sender();
    let group_name_ui = ui.as_weak();
    let group_name_mappings = mappings.clone();
    ui.on_set_group_local_name(move |index, local_name| {
        let Some(ui) = group_name_ui.upgrade() else {
            return;
        };
        let Some(group_id) = row_value(&group_name_mappings.groups, index) else {
            ui.set_operation_status("Select a valid group".into());
            return;
        };
        let local_name = local_name.trim();
        if local_name.is_empty() {
            ui.set_operation_status("Local member name must not be empty".into());
            return;
        }
        ui.set_group_local_name_input(local_name.to_string().into());
        ui.set_operation_busy(true);
        ui.set_operation_status("Saving local group name...".into());
        if let Err(error) = group_name_sender.send(BackendCommand::Runtime(
            CommToolsCommand::SetGroupLocalName {
                group_id,
                local_name: local_name.to_string(),
            },
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let remove_member_sender = backend.sender();
    let remove_member_ui = ui.as_weak();
    let remove_member_mappings = mappings.clone();
    ui.on_remove_group_member(move |group_index, member_index| {
        let Some(ui) = remove_member_ui.upgrade() else {
            return;
        };
        let Some(group_id) = row_value(&remove_member_mappings.groups, group_index) else {
            ui.set_operation_status("Select a valid group".into());
            return;
        };
        let Some(member_b32) = row_value(&remove_member_mappings.group_members, member_index)
        else {
            ui.set_operation_status("Select a removable group member".into());
            return;
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Removing group member...".into());
        if let Err(error) = remove_member_sender.send(BackendCommand::Runtime(
            CommToolsCommand::RemoveGroupMember {
                group_id,
                member_b32,
            },
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let leave_group_sender = backend.sender();
    let leave_group_ui = ui.as_weak();
    let leave_group_mappings = mappings.clone();
    ui.on_leave_group(move |index, local_only| {
        let Some(ui) = leave_group_ui.upgrade() else {
            return;
        };
        let Some(group_id) = row_value(&leave_group_mappings.groups, index) else {
            ui.set_operation_status("Select a valid group".into());
            return;
        };
        let command = if local_only {
            CommToolsCommand::LeaveGroupLocally { group_id }
        } else {
            CommToolsCommand::RequestGroupLeave { group_id }
        };
        ui.set_operation_busy(true);
        ui.set_operation_status(
            if local_only {
                "Leaving group locally..."
            } else {
                "Requesting authoritative group leave..."
            }
            .into(),
        );
        if let Err(error) = leave_group_sender.send(BackendCommand::Runtime(command)) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let dissolve_group_sender = backend.sender();
    let dissolve_group_ui = ui.as_weak();
    let dissolve_group_mappings = mappings.clone();
    ui.on_dissolve_group(move |index| {
        let Some(ui) = dissolve_group_ui.upgrade() else {
            return;
        };
        let Some(group_id) = row_value(&dissolve_group_mappings.groups, index) else {
            ui.set_operation_status("Select a valid group".into());
            return;
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Dissolving group...".into());
        if let Err(error) =
            dissolve_group_sender.send(BackendCommand::Runtime(CommToolsCommand::DissolveGroup {
                group_id,
            }))
        {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let delete_group_sender = backend.sender();
    let delete_group_ui = ui.as_weak();
    let delete_group_mappings = mappings.clone();
    ui.on_delete_group(move |index| {
        let Some(ui) = delete_group_ui.upgrade() else {
            return;
        };
        let Some(group_id) = row_value(&delete_group_mappings.groups, index) else {
            ui.set_operation_status("Select a valid group".into());
            return;
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Deleting local group data...".into());
        if let Err(error) =
            delete_group_sender.send(BackendCommand::Runtime(CommToolsCommand::DeleteGroup {
                group_id,
            }))
        {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let public_invite_sender = backend.sender();
    let public_invite_ui = ui.as_weak();
    let public_invite_mappings = mappings.clone();
    ui.on_generate_public_invite(move |index| {
        let Some(ui) = public_invite_ui.upgrade() else {
            return;
        };
        let Some(group_id) = row_value(&public_invite_mappings.groups, index) else {
            ui.set_operation_status("Select a valid group".into());
            return;
        };
        ui.set_generated_group_material_label("".into());
        ui.set_generated_group_material("".into());
        ui.set_operation_busy(true);
        ui.set_operation_status("Generating public group invite...".into());
        if let Err(error) = public_invite_sender.send(BackendCommand::Runtime(
            CommToolsCommand::IssuePublicGroupInvite { group_id },
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let private_request_sender = backend.sender();
    let private_request_ui = ui.as_weak();
    ui.on_generate_private_request(move || {
        let Some(ui) = private_request_ui.upgrade() else {
            return;
        };
        ui.set_generated_group_material_label("".into());
        ui.set_generated_group_material("".into());
        ui.set_operation_busy(true);
        ui.set_operation_status("Generating private group request...".into());
        if let Err(error) = private_request_sender.send(BackendCommand::Runtime(
            CommToolsCommand::GeneratePrivateGroupRequest,
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let private_invite_sender = backend.sender();
    let private_invite_ui = ui.as_weak();
    let private_invite_mappings = mappings.clone();
    ui.on_answer_private_request(move |index, encoded_request| {
        let Some(ui) = private_invite_ui.upgrade() else {
            return;
        };
        let Some(group_id) = row_value(&private_invite_mappings.groups, index) else {
            ui.set_operation_status("Select a valid group".into());
            return;
        };
        let encoded_request = encoded_request.trim();
        if encoded_request.is_empty() {
            ui.set_operation_status("Private request must not be empty".into());
            return;
        }
        if encoded_request.len() > MAX_ENCODED_LEN {
            ui.set_operation_status(
                format!("Private request exceeds the {MAX_ENCODED_LEN}-byte limit").into(),
            );
            return;
        }
        ui.set_generated_group_material_label("".into());
        ui.set_generated_group_material("".into());
        ui.set_operation_busy(true);
        ui.set_operation_status("Generating private group invite...".into());
        if let Err(error) = private_invite_sender.send(BackendCommand::Runtime(
            CommToolsCommand::IssuePrivateGroupInvite {
                group_id,
                encoded_request: encoded_request.to_string(),
            },
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let import_invite_sender = backend.sender();
    let import_invite_ui = ui.as_weak();
    ui.on_import_group_invite(move |encoded_invite| {
        let Some(ui) = import_invite_ui.upgrade() else {
            return;
        };
        let encoded_invite = encoded_invite.trim();
        if encoded_invite.is_empty() {
            ui.set_operation_status("Group invite must not be empty".into());
            return;
        }
        let command = match input_kind(encoded_invite, PUBLIC_INVITE_PREFIX) {
            InputKind::Public => {
                if encoded_invite.len() > MAX_PUBLIC_INVITE_BYTES {
                    ui.set_operation_status(
                        format!("Public invite exceeds the {MAX_PUBLIC_INVITE_BYTES}-byte limit")
                            .into(),
                    );
                    return;
                }
                CommToolsCommand::ImportPublicGroupInvite {
                    encoded_invite: encoded_invite.to_string(),
                }
            }
            InputKind::Private => {
                if encoded_invite.len() > MAX_ENCODED_LEN {
                    ui.set_operation_status(
                        format!("Private invite exceeds the {MAX_ENCODED_LEN}-byte limit").into(),
                    );
                    return;
                }
                CommToolsCommand::ImportPrivateGroupInvite {
                    encoded_invite: encoded_invite.to_string(),
                }
            }
            InputKind::Unknown => {
                ui.set_operation_status("Unsupported group invite format".into());
                return;
            }
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Importing group invite...".into());
        if let Err(error) = import_invite_sender.send(BackendCommand::Runtime(command)) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let copy_material_ui = ui.as_weak();
    let copy_material_clipboard = clipboard.clone();
    ui.on_copy_group_material(move |material| {
        let Some(ui) = copy_material_ui.upgrade() else {
            return;
        };
        if material.is_empty() {
            ui.set_operation_status("No generated group material to copy".into());
            return;
        }
        match set_clipboard_text(&copy_material_clipboard, material.as_str()) {
            Ok(()) => ui.set_operation_status(
                "Generated group material copied to the system clipboard".into(),
            ),
            Err(error) => ui.set_operation_status(format!("Clipboard copy failed: {error}").into()),
        }
    });

    let toggle_rendezvous_ui = ui.as_weak();
    let toggle_rendezvous_mappings = mappings.clone();
    ui.on_toggle_rendezvous(move |index| {
        let Some(ui) = toggle_rendezvous_ui.upgrade() else {
            return;
        };
        let Some(session_id) = rendezvous_session_at(&toggle_rendezvous_mappings, index) else {
            ui.set_operation_status(
                "Rendezvous requires an unlocked 1:1 session in online standby".into(),
            );
            return;
        };
        if toggle_rendezvous_mappings
            .rendezvous_panel_session
            .borrow()
            .as_ref()
            == Some(&session_id)
            && ui.get_rendezvous_visible()
        {
            close_rendezvous_panel(&ui, &toggle_rendezvous_mappings);
            return;
        }
        show_rendezvous_panel(&ui, &toggle_rendezvous_mappings, session_id);
    });

    let generate_rendezvous_sender = backend.sender();
    let generate_rendezvous_ui = ui.as_weak();
    let generate_rendezvous_mappings = mappings.clone();
    ui.on_generate_rendezvous_request(move |index| {
        let Some(ui) = generate_rendezvous_ui.upgrade() else {
            return;
        };
        let Some(session_id) = rendezvous_session_at(&generate_rendezvous_mappings, index) else {
            ui.set_operation_status("Rendezvous is not available for this session".into());
            return;
        };
        begin_rendezvous_command(
            &ui,
            &generate_rendezvous_mappings,
            session_id,
            PendingRendezvousCommandKind::GenerateRequest,
            "Generating rendezvous request...",
        );
        if let Err(error) = generate_rendezvous_sender.send(BackendCommand::Runtime(
            CommToolsCommand::GenerateContactRendezvousRequest { session_id },
        )) {
            fail_rendezvous_command(&ui, &generate_rendezvous_mappings, error);
        }
    });

    let submit_rendezvous_sender = backend.sender();
    let submit_rendezvous_ui = ui.as_weak();
    let submit_rendezvous_mappings = mappings.clone();
    ui.on_submit_rendezvous_input(move |index, encoded| {
        let Some(ui) = submit_rendezvous_ui.upgrade() else {
            return;
        };
        let Some(session_id) = rendezvous_session_at(&submit_rendezvous_mappings, index) else {
            ui.set_operation_status("Rendezvous is not available for this session".into());
            return;
        };
        let Some(encoded) = validated_rendezvous_input(&encoded) else {
            ui.set_operation_status("Paste valid bounded rendezvous material".into());
            return;
        };
        let (kind, status, command) = match rendezvous_input_kind(&encoded) {
            RendezvousInputKind::Request => (
                PendingRendezvousCommandKind::AnswerRequest,
                "Answering rendezvous request...",
                CommToolsCommand::AnswerContactRendezvousRequest {
                    session_id,
                    encoded_request: encoded,
                },
            ),
            RendezvousInputKind::Response => (
                PendingRendezvousCommandKind::ConnectResponse,
                "Connecting through rendezvous...",
                CommToolsCommand::ConnectContactRendezvous {
                    session_id,
                    encoded_response: encoded,
                },
            ),
            RendezvousInputKind::Unknown => {
                ui.set_operation_status("Unrecognized rendezvous material".into());
                return;
            }
        };
        begin_rendezvous_command(&ui, &submit_rendezvous_mappings, session_id, kind, status);
        if let Err(error) = submit_rendezvous_sender.send(BackendCommand::Runtime(command)) {
            fail_rendezvous_command(&ui, &submit_rendezvous_mappings, error);
        }
    });

    let revoke_rendezvous_sender = backend.sender();
    let revoke_rendezvous_ui = ui.as_weak();
    let revoke_rendezvous_mappings = mappings.clone();
    ui.on_revoke_rendezvous(move |index| {
        let Some(ui) = revoke_rendezvous_ui.upgrade() else {
            return;
        };
        let Some(session_id) = rendezvous_session_at(&revoke_rendezvous_mappings, index) else {
            ui.set_operation_status("Rendezvous is not available for this session".into());
            return;
        };
        begin_rendezvous_command(
            &ui,
            &revoke_rendezvous_mappings,
            session_id,
            PendingRendezvousCommandKind::Revoke,
            "Revoking rendezvous material...",
        );
        if let Err(error) = revoke_rendezvous_sender.send(BackendCommand::Runtime(
            CommToolsCommand::RevokeContactRendezvous { session_id },
        )) {
            fail_rendezvous_command(&ui, &revoke_rendezvous_mappings, error);
        }
    });

    let copy_rendezvous_ui = ui.as_weak();
    let copy_rendezvous_clipboard = clipboard.clone();
    ui.on_copy_rendezvous_output(move |material| {
        let Some(ui) = copy_rendezvous_ui.upgrade() else {
            return;
        };
        if material.is_empty() {
            ui.set_operation_status("No rendezvous material is available".into());
            return;
        }
        match set_clipboard_text(&copy_rendezvous_clipboard, material.as_str()) {
            Ok(()) => {
                ui.set_operation_status("Rendezvous material copied to the system clipboard".into())
            }
            Err(error) => ui.set_operation_status(format!("Clipboard copy failed: {error}").into()),
        }
    });

    let close_session_sender = backend.sender();
    let close_session_ui = ui.as_weak();
    let close_session_mappings = mappings.clone();
    ui.on_close_session(move |index| {
        let Some(ui) = close_session_ui.upgrade() else {
            return;
        };
        let Some(session_id) = row_value(&close_session_mappings.sessions, index).flatten() else {
            ui.set_operation_status("Select a valid active chat".into());
            return;
        };
        if close_session_mappings
            .rendezvous_panel_session
            .borrow()
            .as_ref()
            == Some(&session_id)
        {
            close_rendezvous_panel(&ui, &close_session_mappings);
        }
        ui.set_operation_busy(true);
        ui.set_operation_status("Closing chat session...".into());
        if let Err(error) =
            close_session_sender.send(BackendCommand::Runtime(CommToolsCommand::CloseSession {
                session_id,
            }))
        {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let connect_sender = backend.sender();
    let connect_ui = ui.as_weak();
    let connect_mappings = mappings.clone();
    ui.on_connect_session(move |index, peer_b32| {
        let Some(ui) = connect_ui.upgrade() else {
            return;
        };
        let Some(session_id) = row_value(&connect_mappings.sessions, index).flatten() else {
            ui.set_operation_status("Select a valid contact session".into());
            return;
        };
        let peer_b32 = peer_b32.trim();
        if peer_b32.is_empty() {
            ui.set_operation_status("Peer b32 address must not be empty".into());
            return;
        }
        ui.set_operation_busy(true);
        ui.set_operation_status("Connecting to peer...".into());
        if let Err(error) =
            connect_sender.send(BackendCommand::Runtime(CommToolsCommand::ConnectContact {
                session_id,
                peer_b32: peer_b32.to_string(),
            }))
        {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let accept_sender = backend.sender();
    let accept_ui = ui.as_weak();
    let accept_mappings = mappings.clone();
    ui.on_accept_session(move |index| {
        let Some(ui) = accept_ui.upgrade() else {
            return;
        };
        let Some(session_id) = row_value(&accept_mappings.sessions, index).flatten() else {
            ui.set_operation_status("Select a valid incoming call".into());
            return;
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Accepting incoming call...".into());
        if let Err(error) = accept_sender.send(BackendCommand::Runtime(
            CommToolsCommand::AcceptContactIncoming { session_id },
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let decline_sender = backend.sender();
    let decline_ui = ui.as_weak();
    let decline_mappings = mappings.clone();
    ui.on_decline_session(move |index| {
        let Some(ui) = decline_ui.upgrade() else {
            return;
        };
        let Some(session_id) = row_value(&decline_mappings.sessions, index).flatten() else {
            ui.set_operation_status("Select a valid incoming call".into());
            return;
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Declining incoming call...".into());
        if let Err(error) = decline_sender.send(BackendCommand::Runtime(
            CommToolsCommand::DeclineContactIncoming { session_id },
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let disconnect_sender = backend.sender();
    let disconnect_ui = ui.as_weak();
    let disconnect_mappings = mappings.clone();
    ui.on_disconnect_session(move |index| {
        let Some(ui) = disconnect_ui.upgrade() else {
            return;
        };
        let Some(session_id) = row_value(&disconnect_mappings.sessions, index).flatten() else {
            ui.set_operation_status("Select a valid contact session".into());
            return;
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Disconnecting from peer...".into());
        if let Err(error) = disconnect_sender.send(BackendCommand::Runtime(
            CommToolsCommand::DisconnectContact { session_id },
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let enter_offline_sender = backend.sender();
    let enter_offline_ui = ui.as_weak();
    let enter_offline_mappings = mappings.clone();
    ui.on_enter_offline(move |index| {
        let Some(ui) = enter_offline_ui.upgrade() else {
            return;
        };
        let Some(session_id) = row_value(&enter_offline_mappings.sessions, index).flatten() else {
            ui.set_operation_status("Select an eligible contact session".into());
            return;
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Entering offline mode...".into());
        if let Err(error) = enter_offline_sender.send(BackendCommand::Runtime(
            CommToolsCommand::EnterContactOffline { session_id },
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let leave_offline_sender = backend.sender();
    let leave_offline_ui = ui.as_weak();
    let leave_offline_mappings = mappings.clone();
    ui.on_leave_offline(move |index| {
        let Some(ui) = leave_offline_ui.upgrade() else {
            return;
        };
        let Some(session_id) = row_value(&leave_offline_mappings.sessions, index).flatten() else {
            ui.set_operation_status("Select an offline contact session".into());
            return;
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Returning to online standby...".into());
        if let Err(error) = leave_offline_sender.send(BackendCommand::Runtime(
            CommToolsCommand::LeaveContactOffline { session_id },
        )) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let lock_sender = backend.sender();
    let lock_ui = ui.as_weak();
    let lock_mappings = mappings.clone();
    ui.on_lock_session(move |index| {
        let Some(ui) = lock_ui.upgrade() else {
            return;
        };
        let Some(session_id) = row_value(&lock_mappings.sessions, index).flatten() else {
            ui.set_operation_status("Select a verified contact session".into());
            return;
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Locking verified peer identity...".into());
        if let Err(error) =
            lock_sender.send(BackendCommand::Runtime(CommToolsCommand::LockContactPeer {
                session_id,
            }))
        {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let unlock_sender = backend.sender();
    let unlock_ui = ui.as_weak();
    let unlock_mappings = mappings.clone();
    ui.on_unlock_contact(move |index| {
        let Some(ui) = unlock_ui.upgrade() else {
            return;
        };
        let Some(contact_id) = persistent_contact_id(&unlock_mappings, index) else {
            ui.set_operation_status("Select a locked, closed contact".into());
            return;
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Unlocking contact...".into());
        if let Err(error) =
            unlock_sender.send(BackendCommand::Runtime(CommToolsCommand::UnlockContact {
                contact_id,
            }))
        {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let select_session_ui = ui.as_weak();
    let select_session_mappings = mappings.clone();
    ui.on_select_session(move |index| {
        let Some(ui) = select_session_ui.upgrade() else {
            return;
        };
        if row_value(&select_session_mappings.visible_session_keys, index).is_none() {
            return;
        }
        close_rendezvous_panel(&ui, &select_session_mappings);
        ui.set_selected_session(index);
        ui.set_message_follow_bottom(true);
        ui.set_message_input("".into());
        refresh_messages(&ui, &select_session_mappings);
    });

    let show_details_ui = ui.as_weak();
    let show_details_mappings = mappings.clone();
    ui.on_show_session_details(move |index| {
        let Some(ui) = show_details_ui.upgrade() else {
            return;
        };
        close_rendezvous_panel(&ui, &show_details_mappings);
        match show_session_details(&ui, &show_details_mappings, index) {
            Ok(()) => ui.set_operation_status("Session details opened".into()),
            Err(error) => ui.set_operation_status(error.into()),
        }
    });

    let copy_text_ui = ui.as_weak();
    let copy_text_mappings = mappings.clone();
    let copy_text_clipboard = clipboard.clone();
    ui.on_copy_text_message(move |session_index, message_index| {
        let Some(ui) = copy_text_ui.upgrade() else {
            return;
        };
        match text_message_target(&copy_text_mappings, session_index, message_index) {
            Ok((_, _, text)) => {
                let text = display_reply_text(&text);
                match set_clipboard_text(&copy_text_clipboard, &text) {
                    Ok(()) => ui.set_operation_status("Message copied to the system clipboard".into()),
                    Err(error) => ui.set_operation_status(format!("Clipboard error: {error}").into()),
                }
            }
            Err(error) => ui.set_operation_status(error.into()),
        }
    });

    let reply_text_ui = ui.as_weak();
    let reply_text_mappings = mappings.clone();
    ui.on_reply_text_message(move |session_index, message_index| {
        let Some(ui) = reply_text_ui.upgrade() else {
            return;
        };
        match text_message_target(&reply_text_mappings, session_index, message_index) {
            Ok((session_id, author, text)) => {
                let text = reply_source_text(&text).trim().to_string();
                if text.is_empty() {
                    ui.set_operation_status("The selected message has no replyable text".into());
                    return;
                }
                reply_text_mappings
                    .reply_drafts
                    .borrow_mut()
                    .insert(session_id, ReplyDraft { author, text });
                ui.set_message_follow_bottom(true);
                refresh_reply_draft(&ui, &reply_text_mappings);
                ui.set_operation_status("Reply prepared".into());
            }
            Err(error) => ui.set_operation_status(error.into()),
        }
    });

    let cancel_reply_ui = ui.as_weak();
    let cancel_reply_mappings = mappings.clone();
    ui.on_cancel_reply(move |session_index| {
        let Some(ui) = cancel_reply_ui.upgrade() else {
            return;
        };
        let Some(session_id) = row_value(&cancel_reply_mappings.sessions, session_index).flatten()
        else {
            return;
        };
        cancel_reply_mappings
            .reply_drafts
            .borrow_mut()
            .remove(&session_id);
        refresh_reply_draft(&ui, &cancel_reply_mappings);
        ui.set_operation_status("Reply cancelled".into());
    });

    let send_text_sender = backend.sender();
    let send_text_ui = ui.as_weak();
    let send_text_mappings = mappings.clone();
    ui.on_send_text(move |index, text| {
        let Some(ui) = send_text_ui.upgrade() else {
            return;
        };
        let Some(session_id) = row_value(&send_text_mappings.sessions, index).flatten() else {
            ui.set_operation_status("Select a valid contact session".into());
            return;
        };
        if text.trim().is_empty() {
            ui.set_operation_status("Message must not be empty".into());
            return;
        }
        let wire_text = compose_reply_text(
            send_text_mappings.reply_drafts.borrow().get(&session_id),
            text.as_str(),
        );
        let offline = send_text_mappings
            .latest_snapshot
            .borrow()
            .as_ref()
            .and_then(|snapshot| {
                snapshot
                    .sessions
                    .iter()
                    .find(|session| session.session_id == session_id)
                    .and_then(|session| session.offline_mode)
            }) == Some(OfflineCoordinatorMode::Offline);
        let maximum_bytes = if offline {
            MAX_OFFLINE_CHAT_TEXT_BYTES
        } else {
            MAX_CHAT_TEXT_BYTES
        };
        if wire_text.len() > maximum_bytes {
            ui.set_operation_status("Message and reply quote exceed the allowed message size".into());
            return;
        }
        ui.set_operation_busy(true);
        ui.set_operation_status("Sending message...".into());
        if let Err(error) =
            send_text_sender.send(BackendCommand::Runtime(CommToolsCommand::SendText {
                session_id,
                text: wire_text,
            }))
        {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let send_image_sender = backend.sender();
    let send_image_ui = ui.as_weak();
    let send_image_mappings = mappings.clone();
    ui.on_send_image(move |index| {
        let Some(ui) = send_image_ui.upgrade() else {
            return;
        };
        let Some(session_id) = row_value(&send_image_mappings.sessions, index).flatten() else {
            ui.set_operation_status("Select a valid live chat session".into());
            return;
        };
        let Some(session_key) = send_image_mappings
            .session_keys
            .borrow()
            .get(&session_id)
            .cloned()
        else {
            ui.set_operation_status("The selected chat session is not ready".into());
            return;
        };
        let Some(path) = rfd::FileDialog::new()
            .set_title("Select image")
            .add_filter("Images", &["png", "jpg", "jpeg", "gif", "bmp", "webp"])
            .pick_file()
        else {
            return;
        };
        let max_preview_bytes = if matches!(session_key, ManagedSessionKey::Group(_)) {
            GROUP_IMAGE_TRANSFER_MAX_BYTES
        } else {
            commtools_core::INLINE_IMAGE_TRANSFER_MAX_BYTES
        };
        let image = match prepare_image_path(&path, max_preview_bytes) {
            Ok(image) => image,
            Err(error) => {
                ui.set_operation_status(format!("Image preparation failed: {error}").into());
                return;
            }
        };
        let command = image_send_command(session_id, image);
        ui.set_operation_busy(true);
        ui.set_operation_status("Sending image preview...".into());
        if let Err(error) = send_image_sender.send(BackendCommand::Runtime(command)) {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let send_file_sender = backend.sender();
    let send_file_ui = ui.as_weak();
    let send_file_mappings = mappings.clone();
    ui.on_send_file(move |index| {
        let Some(ui) = send_file_ui.upgrade() else {
            return;
        };
        let Some(session_id) = row_value(&send_file_mappings.sessions, index).flatten() else {
            ui.set_operation_status("Select a valid live 1:1 session".into());
            return;
        };
        if send_file_mappings
            .session_keys
            .borrow()
            .get(&session_id)
            .is_none_or(|key| matches!(key, ManagedSessionKey::Group(_)))
        {
            ui.set_operation_status("File transfer is available only in 1:1 sessions".into());
            return;
        }
        let Some(path) = rfd::FileDialog::new().set_title("Select file").pick_file() else {
            return;
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Offering file to peer...".into());
        if let Err(error) =
            send_file_sender.send(BackendCommand::Runtime(CommToolsCommand::OfferFile {
                session_id,
                path,
            }))
        {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let accept_file_sender = backend.sender();
    let accept_file_ui = ui.as_weak();
    let accept_file_mappings = mappings.clone();
    ui.on_accept_file(move |session_index, message_index| {
        let Some(ui) = accept_file_ui.upgrade() else {
            return;
        };
        let target = match file_transfer_target(&accept_file_mappings, session_index, message_index)
        {
            Ok(target) if target.state == PresentedFileTransferState::IncomingOffer => target,
            Ok(_) => {
                ui.set_operation_status("The file offer is no longer awaiting acceptance".into());
                return;
            }
            Err(error) => {
                ui.set_operation_status(error.into());
                return;
            }
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Accepting file offer...".into());
        if let Err(error) =
            accept_file_sender.send(BackendCommand::Runtime(CommToolsCommand::AcceptFile {
                session_id: target.session_id,
                transfer_id: target.transfer_id,
            }))
        {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let decline_file_sender = backend.sender();
    let decline_file_ui = ui.as_weak();
    let decline_file_mappings = mappings.clone();
    ui.on_decline_file(move |session_index, message_index| {
        let Some(ui) = decline_file_ui.upgrade() else {
            return;
        };
        let target =
            match file_transfer_target(&decline_file_mappings, session_index, message_index) {
                Ok(target) if target.state == PresentedFileTransferState::IncomingOffer => target,
                Ok(_) => {
                    ui.set_operation_status(
                        "The file offer is no longer awaiting a decision".into(),
                    );
                    return;
                }
                Err(error) => {
                    ui.set_operation_status(error.into());
                    return;
                }
            };
        ui.set_operation_busy(true);
        ui.set_operation_status("Declining file offer...".into());
        if let Err(error) =
            decline_file_sender.send(BackendCommand::Runtime(CommToolsCommand::DeclineFile {
                session_id: target.session_id,
                transfer_id: target.transfer_id,
            }))
        {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let cancel_file_sender = backend.sender();
    let cancel_file_ui = ui.as_weak();
    let cancel_file_mappings = mappings.clone();
    ui.on_cancel_file(move |session_index, message_index| {
        let Some(ui) = cancel_file_ui.upgrade() else {
            return;
        };
        let target = match file_transfer_target(&cancel_file_mappings, session_index, message_index)
        {
            Ok(target)
                if matches!(
                    target.state,
                    PresentedFileTransferState::AwaitingAcceptance
                        | PresentedFileTransferState::Active
                ) =>
            {
                target
            }
            Ok(_) => {
                ui.set_operation_status("The file transfer cannot be cancelled now".into());
                return;
            }
            Err(error) => {
                ui.set_operation_status(error.into());
                return;
            }
        };
        ui.set_operation_busy(true);
        ui.set_operation_status("Cancelling file transfer...".into());
        if let Err(error) =
            cancel_file_sender.send(BackendCommand::Runtime(CommToolsCommand::CancelFile {
                session_id: target.session_id,
                transfer_id: target.transfer_id,
            }))
        {
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let request_original_sender = backend.sender();
    let request_original_ui = ui.as_weak();
    let request_original_mappings = mappings.clone();
    ui.on_request_original_image(move |session_index, message_index| {
        let Some(ui) = request_original_ui.upgrade() else {
            return;
        };
        let target =
            match original_image_target(&request_original_mappings, session_index, message_index) {
                Ok(target) => target,
                Err(error) => {
                    ui.set_operation_status(error.into());
                    return;
                }
            };
        if !matches!(
            original_image_state(&request_original_mappings, &target),
            Some(
                OriginalImagePresentationState::Available
                    | OriginalImagePresentationState::Cached
                    | OriginalImagePresentationState::Failed
            )
        ) {
            ui.set_operation_status("The original image cannot be requested now".into());
            return;
        }
        if request_original_mappings
            .pending_original_command
            .borrow()
            .is_some()
        {
            ui.set_operation_status("Another original-image action is still pending".into());
            return;
        }
        set_original_image_state(
            &request_original_mappings,
            &target,
            OriginalImagePresentationState::Requesting,
            0,
        );
        refresh_messages(&ui, &request_original_mappings);
        *request_original_mappings
            .pending_original_command
            .borrow_mut() = Some(PendingOriginalImageCommand {
            kind: PendingOriginalImageCommandKind::Request,
            target: target.clone(),
        });
        ui.set_operation_busy(true);
        ui.set_operation_status("Requesting original image...".into());
        if let Err(error) = request_original_sender.send(BackendCommand::Runtime(
            CommToolsCommand::RequestOriginalImage {
                session_id: target.session_id,
                media_id: target.media_id,
                sender_b32: target.sender_b32.clone(),
            },
        )) {
            request_original_mappings
                .pending_original_command
                .borrow_mut()
                .take();
            set_original_image_state(
                &request_original_mappings,
                &target,
                OriginalImagePresentationState::Failed,
                0,
            );
            refresh_messages(&ui, &request_original_mappings);
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let cancel_original_sender = backend.sender();
    let cancel_original_ui = ui.as_weak();
    let cancel_original_mappings = mappings.clone();
    ui.on_cancel_original_image(move |session_index, message_index| {
        let Some(ui) = cancel_original_ui.upgrade() else {
            return;
        };
        let target =
            match original_image_target(&cancel_original_mappings, session_index, message_index) {
                Ok(target) => target,
                Err(error) => {
                    ui.set_operation_status(error.into());
                    return;
                }
            };
        if !matches!(
            original_image_state(&cancel_original_mappings, &target),
            Some(
                OriginalImagePresentationState::Requesting
                    | OriginalImagePresentationState::Receiving
            )
        ) {
            ui.set_operation_status("The original image is not downloading".into());
            return;
        }
        if cancel_original_mappings
            .pending_original_command
            .borrow()
            .is_some()
        {
            ui.set_operation_status("Another original-image action is still pending".into());
            return;
        }
        *cancel_original_mappings
            .pending_original_command
            .borrow_mut() = Some(PendingOriginalImageCommand {
            kind: PendingOriginalImageCommandKind::Cancel,
            target: target.clone(),
        });
        ui.set_operation_busy(true);
        ui.set_operation_status("Cancelling original-image download...".into());
        if let Err(error) = cancel_original_sender.send(BackendCommand::Runtime(
            CommToolsCommand::CancelOriginalImage {
                session_id: target.session_id,
                media_id: target.media_id,
                sender_b32: target.sender_b32.clone(),
            },
        )) {
            cancel_original_mappings
                .pending_original_command
                .borrow_mut()
                .take();
            ui.set_operation_busy(false);
            ui.set_operation_status(error.into());
        }
    });

    let close_original_ui = ui.as_weak();
    let close_original_mappings = mappings.clone();
    ui.on_close_original_viewer(move || {
        let Some(ui) = close_original_ui.upgrade() else {
            return;
        };
        clear_original_image_viewer(&ui, &close_original_mappings);
    });

    let save_original_ui = ui.as_weak();
    let save_original_mappings = mappings.clone();
    ui.on_save_original_image(move || {
        let Some(ui) = save_original_ui.upgrade() else {
            return;
        };
        let Some(original) = save_original_mappings.original_viewer.borrow().clone() else {
            ui.set_original_viewer_status("No original image is open".into());
            return;
        };
        let Some(path) = rfd::FileDialog::new()
            .set_title("Save original image")
            .set_file_name(&original.filename)
            .save_file()
        else {
            return;
        };
        ui.set_original_viewer_status("Saving...".into());
        match save_original_image(&path, &original.bytes) {
            Ok(()) => ui.set_original_viewer_status(format!("Saved to {}", path.display()).into()),
            Err(error) => ui.set_original_viewer_status(error.into()),
        }
    });

    let close_allowed = Rc::new(Cell::new(false));
    let close_requested = Rc::new(Cell::new(false));
    let close_sender = backend.sender();
    let close_ui = ui.as_weak();
    let close_allowed_for_callback = close_allowed.clone();
    let close_requested_for_callback = close_requested.clone();
    ui.window().on_close_requested(move || {
        if close_allowed_for_callback.get() {
            return CloseRequestResponse::HideWindow;
        }
        if !close_requested_for_callback.replace(true) {
            if let Some(ui) = close_ui.upgrade() {
                ui.set_screen(3);
                ui.set_busy(true);
                ui.set_gate_error("Closing sessions and encrypting the vault...".into());
            }
            let _ = close_sender.send(BackendCommand::Shutdown);
        }
        CloseRequestResponse::KeepWindowShown
    });

    let event_ui = ui.as_weak();
    let event_mappings = mappings.clone();
    let event_sender = backend.sender();
    let close_allowed_for_events = close_allowed.clone();
    let event_timer = Timer::default();
    event_timer.start(TimerMode::Repeated, UI_EVENT_INTERVAL, move || {
        let Some(ui) = event_ui.upgrade() else {
            return;
        };
        while let Ok(event) = events.try_recv() {
            match event {
                BackendEvent::GateFailed(error) => {
                    ui.set_busy(false);
                    ui.set_gate_error(error.into());
                }
                BackendEvent::Ready(snapshot) => {
                    apply_snapshot(
                        &ui,
                        &event_mappings,
                        &event_sender,
                        snapshot,
                        ConversationRefresh::Refresh,
                    );
                }
                BackendEvent::Snapshot(snapshot) => {
                    apply_snapshot(
                        &ui,
                        &event_mappings,
                        &event_sender,
                        snapshot,
                        ConversationRefresh::Preserve,
                    );
                }
                BackendEvent::Frontend(event) => {
                    apply_frontend_event(&ui, &event_mappings, &event_sender, event)
                }
                BackendEvent::CommandCompleted(result) => {
                    apply_command_result(&ui, &event_mappings, result);
                }
                BackendEvent::CommandFailed(error) => {
                    fail_pending_original_command(&event_mappings);
                    event_mappings
                        .pending_rendezvous_command
                        .borrow_mut()
                        .take();
                    event_mappings.pending_transient_label.borrow_mut().take();
                    event_mappings.pending_contact_import.borrow_mut().take();
                    event_mappings
                        .contact_import_confirmation
                        .borrow_mut()
                        .take();
                    clear_settings_data_secrets(&ui);
                    ui.set_settings_data_confirmation_visible(false);
                    ui.set_settings_data_confirmation_text("".into());
                    clear_contact_export_secrets(&ui);
                    refresh_messages(&ui, &event_mappings);
                    ui.set_operation_busy(false);
                    ui.set_operation_status(format!("Operation failed: {error}").into());
                }
                BackendEvent::SamLivenessShutdown => {
                    ui.set_screen(3);
                    ui.set_busy(true);
                    ui.set_gate_error(
                        "SAM is unavailable. Closing sessions and encrypting the vault...".into(),
                    );
                }
                BackendEvent::Fatal(error) => {
                    ui.set_runtime_status(format!("Runtime error: {error}").into());
                    ui.set_gate_error(error.into());
                }
                BackendEvent::Stopped => {
                    close_allowed_for_events.set(true);
                    let _ = ui.window().hide();
                }
            }
        }
        if expire_offline_activities(&event_mappings) {
            let snapshot = event_mappings.latest_snapshot.borrow().clone();
            if let Some(snapshot) = snapshot {
                apply_snapshot(
                    &ui,
                    &event_mappings,
                    &event_sender,
                    snapshot,
                    ConversationRefresh::Preserve,
                );
            }
        }
    });

    let run_result = ui.run();
    let _ = backend.sender().send(BackendCommand::Shutdown);
    backend.join().map_err(|_| AppError::BackendPanicked)?;
    run_result?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConversationRefresh {
    Preserve,
    Refresh,
}

fn apply_snapshot(
    ui: &AppWindow,
    mappings: &UiMappings,
    sender: &BackendSender,
    snapshot: CommToolsSnapshot,
    conversation_refresh: ConversationRefresh,
) {
    let previous_selected_contact = row_value(&mappings.contact_catalog, ui.get_selected_contact());
    let selected_group = mappings
        .pending_group_selection
        .borrow_mut()
        .take()
        .or_else(|| row_value(&mappings.groups, ui.get_selected_group()));
    let selected_session_key = row_value(&mappings.visible_session_keys, ui.get_selected_session());
    let selected_session_was_pending = row_value(&mappings.sessions, ui.get_selected_session())
        .is_some_and(|session_id| session_id.is_none());
    *mappings.latest_snapshot.borrow_mut() = Some(snapshot.clone());
    let open_rendezvous_session = *mappings.rendezvous_panel_session.borrow();
    if open_rendezvous_session.is_some_and(|session_id| {
        !snapshot
            .sessions
            .iter()
            .any(|session| session.session_id == session_id && rendezvous_available(session))
    }) {
        close_rendezvous_panel(ui, mappings);
    }
    let active_session_keys = snapshot
        .sessions
        .iter()
        .map(|session| (session.session_id, session.key.clone()))
        .collect::<BTreeMap<_, _>>();
    let active_session_ids = active_session_keys.keys().copied().collect::<BTreeSet<_>>();
    let active_keys = active_session_keys
        .values()
        .cloned()
        .collect::<BTreeSet<_>>();
    mappings
        .conversations
        .borrow_mut()
        .retain(|session_id, _| active_session_ids.contains(session_id));
    mappings
        .contact_tofu_states
        .borrow_mut()
        .retain(|session_id, _| active_session_ids.contains(session_id));
    mappings
        .offline_activities
        .borrow_mut()
        .retain(|session_id, _| active_session_ids.contains(session_id));
    mappings
        .rendezvous_outputs
        .borrow_mut()
        .retain(|session_id, _| active_session_ids.contains(session_id));
    mappings
        .rendezvous_authenticated
        .borrow_mut()
        .retain(|session_id| active_session_ids.contains(session_id));
    if mappings
        .rendezvous_panel_session
        .borrow()
        .is_some_and(|session_id| !active_session_ids.contains(&session_id))
    {
        close_rendezvous_panel(ui, mappings);
    }
    mappings
        .history_requested
        .borrow_mut()
        .retain(|key| active_keys.contains(key));
    *mappings.session_keys.borrow_mut() = active_session_keys;

    let history_to_load = snapshot
        .sessions
        .iter()
        .filter_map(|session| match &session.key {
            ManagedSessionKey::Contact(_) | ManagedSessionKey::Group(_) => {
                Some(session.key.clone())
            }
            _ => None,
        })
        .filter(|key| mappings.history_requested.borrow_mut().insert(key.clone()))
        .collect::<Vec<_>>();
    for key in history_to_load {
        if let Err(error) = sender.send(BackendCommand::Runtime(CommToolsCommand::LoadHistory {
            key: key.clone(),
        })) {
            mappings.history_requested.borrow_mut().remove(&key);
            ui.set_operation_status(error.into());
        }
    }
    let contact_names = snapshot
        .contacts
        .iter()
        .map(|contact| (contact.id.clone(), contact.display_name.clone()))
        .collect::<BTreeMap<_, _>>();
    let contact_history_enabled = snapshot
        .contacts
        .iter()
        .map(|contact| (contact.id.clone(), contact.history_enabled))
        .collect::<BTreeMap<_, _>>();
    let group_names = snapshot
        .groups
        .iter()
        .map(|group| (group.id.clone(), group.display_name.clone()))
        .collect::<BTreeMap<_, _>>();
    let group_history_enabled = snapshot
        .groups
        .iter()
        .map(|group| (group.id.clone(), group.history_enabled))
        .collect::<BTreeMap<_, _>>();
    let transient_labels = mappings.transient_labels.borrow().clone();

    let contact_count = snapshot.contacts.len();
    let contact_ids = snapshot
        .contacts
        .iter()
        .map(|contact| contact.id.clone())
        .collect::<Vec<_>>();
    let mut contact_catalog = contact_ids
        .iter()
        .cloned()
        .map(ContactCatalogEntry::Persistent)
        .collect::<Vec<_>>();
    let mut contacts = snapshot
        .contacts
        .iter()
        .map(|contact| CatalogItem {
            title: contact.display_name.clone().into(),
            detail: "".into(),
            state: if contact.active { "Open" } else { "Closed" }.into(),
            active: contact.active,
            transient: false,
            peer_pinned: contact.peer_pinned,
            owner: false,
        })
        .collect::<Vec<_>>();

    let live_transient_ids = snapshot
        .sessions
        .iter()
        .filter_map(|session| match &session.key {
            ManagedSessionKey::Transient(transient_id) => Some(transient_id.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    for session in &snapshot.sessions {
        let ManagedSessionKey::Transient(transient_id) = &session.key else {
            continue;
        };
        contact_catalog.push(ContactCatalogEntry::Transient(transient_id.clone()));
        contacts.push(CatalogItem {
            title: format!(
                "T  {}",
                transient_title(
                    transient_id,
                    transient_labels.get(transient_id).map(String::as_str),
                )
            )
            .into(),
            detail: "".into(),
            state: if session.phase == ManagedSessionPhase::Closing {
                "Closing"
            } else {
                "Open"
            }
            .into(),
            active: session.phase == ManagedSessionPhase::Open,
            transient: true,
            peer_pinned: false,
            owner: false,
        });
    }
    for key in mappings.opening_sessions.borrow().iter() {
        let ManagedSessionKey::Transient(transient_id) = key else {
            continue;
        };
        if live_transient_ids.contains(transient_id) {
            continue;
        }
        contact_catalog.push(ContactCatalogEntry::Transient(transient_id.clone()));
        contacts.push(CatalogItem {
            title: format!(
                "T  {}",
                transient_title(
                    transient_id,
                    transient_labels.get(transient_id).map(String::as_str),
                )
            )
            .into(),
            detail: "".into(),
            state: "Opening".into(),
            active: true,
            transient: true,
            peer_pinned: false,
            owner: false,
        });
    }
    let pending_contact_selection = mappings.pending_contact_selection.borrow().clone();
    let selected_contact_entry = pending_contact_selection
        .filter(|pending| contact_catalog.contains(pending))
        .or_else(|| {
            previous_selected_contact.filter(|selected| contact_catalog.contains(selected))
        });
    let pending_selection_applied = mappings
        .pending_contact_selection
        .borrow()
        .as_ref()
        .is_some_and(|pending| selected_contact_entry.as_ref() == Some(pending));
    if pending_selection_applied {
        mappings.pending_contact_selection.borrow_mut().take();
    }
    let selected_contact = selected_contact_entry
        .as_ref()
        .and_then(|selected| match selected {
            ContactCatalogEntry::Persistent(contact_id) => Some(contact_id.clone()),
            ContactCatalogEntry::Transient(_) => None,
        });
    let selected_contact_opening = selected_contact.as_ref().is_some_and(|contact_id| {
        mappings
            .opening_sessions
            .borrow()
            .contains(&ManagedSessionKey::Contact(contact_id.clone()))
    });
    let selected_contact_state =
        selected_contact_entry
            .as_ref()
            .and_then(|selected| match selected {
                ContactCatalogEntry::Persistent(contact_id) => snapshot
                    .contacts
                    .iter()
                    .find(|contact| &contact.id == contact_id)
                    .map(|contact| {
                        (
                            contact.active || selected_contact_opening,
                            contact.peer_pinned,
                        )
                    }),
                ContactCatalogEntry::Transient(_) => Some((true, false)),
            });

    let group_count = snapshot.groups.len();
    let selected_group_state = selected_group.as_ref().and_then(|selected| {
        snapshot
            .groups
            .iter()
            .find(|group| &group.id == selected)
            .map(|group| (group.active, group.owner))
    });
    let group_ids = snapshot
        .groups
        .iter()
        .map(|group| group.id.clone())
        .collect::<Vec<_>>();
    let groups = snapshot
        .groups
        .into_iter()
        .map(|group| CatalogItem {
            title: group.display_name.into(),
            detail: format!(
                "{} member(s), roster {}",
                group.members.len(),
                group.roster_version
            )
            .into(),
            state: if group.active { "Open" } else { "Closed" }.into(),
            active: group.active,
            transient: false,
            peer_pinned: false,
            owner: group.owner,
        })
        .collect::<Vec<_>>();

    let live_keys = snapshot
        .sessions
        .iter()
        .map(|session| session.key.clone())
        .collect::<BTreeSet<_>>();
    mappings
        .opening_sessions
        .borrow_mut()
        .retain(|key| !live_keys.contains(key));
    let contact_tofu_states = mappings.contact_tofu_states.borrow().clone();
    let offline_activities = mappings.offline_activities.borrow().clone();
    let rendezvous_authenticated = mappings.rendezvous_authenticated.borrow().clone();

    let mut session_ids = snapshot
        .sessions
        .iter()
        .map(|session| Some(session.session_id))
        .collect::<Vec<_>>();
    let mut visible_session_keys = snapshot
        .sessions
        .iter()
        .map(|session| session.key.clone())
        .collect::<Vec<_>>();
    let mut sessions = snapshot
        .sessions
        .iter()
        .map(|session| {
            let title = match &session.key {
                ManagedSessionKey::Contact(contact_id) => contact_names
                    .get(contact_id)
                    .cloned()
                    .unwrap_or_else(|| format!("Contact {contact_id}")),
                ManagedSessionKey::Transient(transient_id) => transient_title(
                    transient_id,
                    transient_labels.get(transient_id).map(String::as_str),
                ),
                ManagedSessionKey::Group(group_id) => group_names
                    .get(group_id)
                    .cloned()
                    .unwrap_or_else(|| format!("Group {group_id}")),
            };
            let offline = session.offline_mode == Some(OfflineCoordinatorMode::Offline);
            let (offline_activity, offline_activity_tone) = visible_offline_activity(
                offline,
                offline_activities.get(&session.session_id),
                Instant::now(),
            );
            let detail = if session.phase == ManagedSessionPhase::Closing {
                "Closing session resources".into()
            } else if offline {
                "Deaddrop offline mode".into()
            } else {
                session
                    .one_to_one_phase
                    .map(one_to_one_detail)
                    .unwrap_or_else(|| "Group session".into())
            };
            let state = match (session.phase, session.offline_mode) {
                (ManagedSessionPhase::Open, Some(OfflineCoordinatorMode::Offline)) => "Offline",
                (ManagedSessionPhase::Open, _) => session
                    .one_to_one_phase
                    .map(one_to_one_state)
                    .unwrap_or("Active"),
                (ManagedSessionPhase::Closing, _) => "Closing",
            };
            let is_contact = matches!(&session.key, ManagedSessionKey::Contact(_));
            let is_one_to_one = is_one_to_one_key(&session.key);
            let is_group = matches!(&session.key, ManagedSessionKey::Group(_));
            let history_enabled = match &session.key {
                ManagedSessionKey::Contact(contact_id) => contact_history_enabled
                    .get(contact_id)
                    .copied()
                    .unwrap_or(false),
                ManagedSessionKey::Group(group_id) => group_history_enabled
                    .get(group_id)
                    .copied()
                    .unwrap_or(false),
                ManagedSessionKey::Transient(_) => false,
            };
            let peer_pinned = session.pinned_peer_b32.is_some();
            let peer_b32 = session
                .peer_b32
                .clone()
                .or_else(|| session.pinned_peer_b32.clone())
                .unwrap_or_default();
            let local_b32 = session.local_b32.clone().unwrap_or_default();
            let local_b32_display = compact_b32_address(&local_b32);
            let peer_b32_display = compact_b32_address(&peer_b32);
            let connect_address = session
                .pinned_peer_b32
                .clone()
                .or_else(|| session.peer_b32.clone())
                .unwrap_or_default();
            let phase = session.one_to_one_phase;
            let tofu_state = if offline {
                0
            } else {
                match contact_tofu_states.get(&session.session_id) {
                    Some(TofuPresentationState::Verified)
                        if matches!(
                            phase,
                            Some(OneToOnePhase::Handshaking | OneToOnePhase::Ready)
                        ) =>
                    {
                        1
                    }
                    Some(TofuPresentationState::Mismatch) => 2,
                    Some(TofuPresentationState::Verified) => 0,
                    None if peer_pinned && phase == Some(OneToOnePhase::Ready) => 1,
                    None => 0,
                }
            };
            SessionItem {
                title: title.into(),
                session_kind: session_kind(&session.key).into(),
                detail: detail.into(),
                state: state.into(),
                local_b32: local_b32.into(),
                local_b32_display: local_b32_display.into(),
                peer_b32: peer_b32.into(),
                peer_b32_display: peer_b32_display.into(),
                connect_address: connect_address.into(),
                trust: if peer_pinned { "Locked" } else { "Unlocked" }.into(),
                tofu_state,
                is_contact,
                is_one_to_one,
                peer_pinned,
                can_connect: is_one_to_one && !offline && phase == Some(OneToOnePhase::Standby),
                can_accept: is_one_to_one && phase == Some(OneToOnePhase::IncomingPending),
                can_decline: is_one_to_one && phase == Some(OneToOnePhase::IncomingPending),
                can_disconnect: is_one_to_one
                    && matches!(
                        phase,
                        Some(
                            OneToOnePhase::Connecting
                                | OneToOnePhase::Handshaking
                                | OneToOnePhase::Ready
                        )
                    ),
                can_send: (is_one_to_one && phase == Some(OneToOnePhase::Ready))
                    || (is_contact && offline)
                    || (is_group && session.phase == ManagedSessionPhase::Open),
                can_send_image: !offline
                    && ((is_one_to_one && phase == Some(OneToOnePhase::Ready))
                        || (is_group && session.phase == ManagedSessionPhase::Open)),
                can_send_file: !offline && is_one_to_one && phase == Some(OneToOnePhase::Ready),
                can_enter_offline: is_contact
                    && session.phase == ManagedSessionPhase::Open
                    && session.offline_mode == Some(OfflineCoordinatorMode::Standby)
                    && phase == Some(OneToOnePhase::Standby),
                can_leave_offline: is_contact && offline,
                offline,
                offline_activity: offline_activity.into(),
                offline_activity_tone,
                can_close: session.phase == ManagedSessionPhase::Open,
                can_lock: is_contact
                    && session.phase == ManagedSessionPhase::Open
                    && !peer_pinned
                    && phase == Some(OneToOnePhase::Ready)
                    && session.peer_b32.is_some(),
                can_rendezvous: is_one_to_one
                    && session.phase == ManagedSessionPhase::Open
                    && !offline
                    && !peer_pinned
                    && phase == Some(OneToOnePhase::Standby),
                rendezvous_authenticated: rendezvous_authenticated.contains(&session.session_id),
                history_enabled,
                has_details: session_has_details(&session.key),
                opening: false,
            }
        })
        .collect::<Vec<_>>();

    for key in mappings.opening_sessions.borrow().iter() {
        if live_keys.contains(key) {
            continue;
        }
        let title = session_title(key, &contact_names, &group_names, &transient_labels);
        let is_contact = matches!(key, ManagedSessionKey::Contact(_));
        let is_one_to_one = is_one_to_one_key(key);
        let history_enabled = match key {
            ManagedSessionKey::Contact(contact_id) => contact_history_enabled
                .get(contact_id)
                .copied()
                .unwrap_or(false),
            ManagedSessionKey::Group(group_id) => group_history_enabled
                .get(group_id)
                .copied()
                .unwrap_or(false),
            ManagedSessionKey::Transient(_) => false,
        };
        let has_details = session_has_details(key);
        visible_session_keys.push(key.clone());
        session_ids.push(None);
        sessions.push(SessionItem {
            title: title.into(),
            session_kind: session_kind(key).into(),
            detail: "Initializing SAM session and I2P tunnels".into(),
            state: "Opening".into(),
            local_b32: "".into(),
            local_b32_display: "----".into(),
            peer_b32: "".into(),
            peer_b32_display: "----".into(),
            connect_address: "".into(),
            trust: if is_contact { "Pending" } else { "" }.into(),
            tofu_state: 0,
            is_contact,
            is_one_to_one,
            peer_pinned: false,
            can_connect: false,
            can_accept: false,
            can_decline: false,
            can_disconnect: false,
            can_send: false,
            can_send_image: false,
            can_send_file: false,
            can_enter_offline: false,
            can_leave_offline: false,
            offline: false,
            offline_activity: "".into(),
            offline_activity_tone: 0,
            can_close: false,
            can_lock: false,
            can_rendezvous: false,
            rendezvous_authenticated: false,
            history_enabled,
            has_details,
            opening: true,
        });
    }

    let selected_contact_index = selected_contact_entry
        .as_ref()
        .and_then(|selected| contact_catalog.iter().position(|entry| entry == selected))
        .and_then(|index| i32::try_from(index).ok())
        .unwrap_or(-1);
    let selected_group_index = selected_group
        .as_ref()
        .and_then(|selected| group_ids.iter().position(|id| id == selected))
        .and_then(|index| i32::try_from(index).ok())
        .unwrap_or(-1);
    let selected_session_index = selected_session_key
        .and_then(|selected| visible_session_keys.iter().position(|key| key == &selected))
        .and_then(|index| i32::try_from(index).ok());
    let transient_count = contact_catalog.len().saturating_sub(contact_count);

    *mappings.contacts.borrow_mut() = contact_ids;
    *mappings.contact_catalog.borrow_mut() = contact_catalog;
    *mappings.groups.borrow_mut() = group_ids;
    *mappings.sessions.borrow_mut() = session_ids;
    *mappings.visible_session_keys.borrow_mut() = visible_session_keys;

    ui.set_contacts(model(contacts));
    ui.set_groups(model(groups));
    let effective_selected_session_index = if sessions.is_empty() {
        None
    } else {
        Some(selected_session_index.unwrap_or(0))
    };
    let selected_connect_address = effective_selected_session_index
        .and_then(|index| sessions.get(index as usize))
        .map(|session| session.connect_address.clone());
    let selected_can_lock = effective_selected_session_index
        .and_then(|index| sessions.get(index as usize))
        .is_some_and(|session| session.can_lock);
    let selected_can_connect = effective_selected_session_index
        .and_then(|index| sessions.get(index as usize))
        .is_some_and(|session| session.can_connect);
    let has_sessions = !sessions.is_empty();
    ui.set_sessions(session_model(sessions));
    ui.set_contacts_summary(contact_catalog_summary(contact_count, transient_count).into());
    ui.set_groups_summary(count_label(group_count, "group", "groups"));
    ui.set_selected_contact(selected_contact_index);
    ui.set_selected_contact_active(selected_contact_state.is_some_and(|(active, _)| active));
    ui.set_selected_contact_pinned(
        selected_contact_state.is_some_and(|(_, peer_pinned)| peer_pinned),
    );
    ui.set_selected_contact_transient(matches!(
        selected_contact_entry,
        Some(ContactCatalogEntry::Transient(_))
    ));
    refresh_contact_details(ui, mappings, selected_contact.as_ref());
    ui.set_selected_group(selected_group_index);
    ui.set_selected_group_active(selected_group_state.is_some_and(|(active, _)| active));
    ui.set_selected_group_owner(selected_group_state.is_some_and(|(_, owner)| owner));
    refresh_group_details(ui, mappings, selected_group.as_ref());
    if !selected_contact_state.is_some_and(|(active, peer_pinned)| !active && peer_pinned) {
        ui.set_unlock_confirmation_visible(false);
    }
    if !selected_can_lock {
        ui.set_lock_confirmation_visible(false);
    }
    if !selected_can_connect {
        ui.set_connect_input_visible(false);
    }
    if !has_sessions {
        ui.set_selected_session(-1);
        ui.set_message_follow_bottom(true);
        ui.set_messages(message_model(Vec::new()));
        ui.set_message_input("".into());
        ui.set_reply_visible(false);
        ui.set_reply_author("".into());
        ui.set_reply_preview("".into());
        ui.set_connect_input_visible(false);
    } else {
        let selected_index = effective_selected_session_index.expect("sessions are not empty");
        ui.set_selected_session(selected_index);
        let conversation_selection_changed =
            selected_session_index.is_none() || selected_session_was_pending;
        if conversation_selection_changed {
            ui.set_message_follow_bottom(true);
            ui.set_message_input("".into());
            if let Some(address) = selected_connect_address {
                ui.set_peer_address_input(address);
            }
        }
        if conversation_refresh == ConversationRefresh::Refresh || conversation_selection_changed {
            refresh_messages(ui, mappings);
        }
    }
    refresh_session_logs(ui, mappings);
    ui.set_sam_endpoint(
        format!(
            "{}:{}",
            snapshot.settings.sam_host, snapshot.settings.sam_port
        )
        .into(),
    );
    ui.set_tunnel_defaults(
        format!(
            "length {}, quantity {}",
            snapshot.settings.default_tunnels.length, snapshot.settings.default_tunnels.quantity
        )
        .into(),
    );
    if !ui.get_settings_visible() {
        ui.set_settings_sam_host(snapshot.settings.sam_host.clone().into());
        ui.set_settings_sam_port(snapshot.settings.sam_port.to_string().into());
        ui.set_settings_tunnel_length(i32::from(snapshot.settings.default_tunnels.length));
        ui.set_settings_tunnel_quantity(i32::from(snapshot.settings.default_tunnels.quantity));
    }
    ui.set_settings_transport_editable(!snapshot.has_open_or_pending_sessions);
    ui.set_settings_sam_liveness_enabled(snapshot.settings.sam_liveness_enabled);
    ui.set_settings_sam_shutdown_on_failure(matches!(
        snapshot.settings.sam_failure_action,
        SamFailureAction::GracefulShutdown
    ));
    ui.set_settings_sam_monitor_status(sam_monitor_status_text(&snapshot.sam_monitor_status).into());
    ui.set_settings_sam_monitor_tone(sam_monitor_status_tone(&snapshot.sam_monitor_status));
    ui.set_settings_sam_test_status(sam_test_status_text(&snapshot.sam_test_status).into());
    ui.set_settings_sam_test_tone(sam_test_status_tone(&snapshot.sam_test_status));
    ui.set_settings_sam_test_running(snapshot.sam_test_status == SamTestStatus::Running);
    ui.set_runtime_status(format!("Ready | SAM {:?}", snapshot.sam_monitor_status).into());
    ui.set_busy(false);
    ui.set_gate_error("".into());
    ui.set_screen(2);
}

fn apply_frontend_event(
    ui: &AppWindow,
    mappings: &UiMappings,
    sender: &BackendSender,
    event: FrontendEvent,
) {
    record_frontend_event_log(mappings, &event);
    refresh_session_logs(ui, mappings);
    match event {
        FrontendEvent::Lifecycle(lifecycle) => {
            ui.set_runtime_status(format!("Runtime {lifecycle:?}").into());
        }
        FrontendEvent::Session(session) => {
            let select_key = match &session {
                SessionLifecycleEvent::Opening { key } => {
                    let mut opening = mappings.opening_sessions.borrow_mut();
                    if !opening.contains(key) {
                        opening.push(key.clone());
                    }
                    Some(key.clone())
                }
                SessionLifecycleEvent::OpenFailed { key, .. } => {
                    mappings
                        .opening_sessions
                        .borrow_mut()
                        .retain(|pending| pending != key);
                    if let ManagedSessionKey::Transient(transient_id) = key {
                        mappings.transient_labels.borrow_mut().remove(transient_id);
                        clear_pending_transient_selection(mappings, transient_id);
                    }
                    None
                }
                SessionLifecycleEvent::Opened { session_id, .. } => {
                    mappings.contact_tofu_states.borrow_mut().remove(session_id);
                    None
                }
                SessionLifecycleEvent::Closing { session_id, .. } => {
                    mappings.contact_tofu_states.borrow_mut().remove(session_id);
                    None
                }
                SessionLifecycleEvent::Closed {
                    session_id, key, ..
                } => {
                    mappings.contact_tofu_states.borrow_mut().remove(session_id);
                    mappings.offline_activities.borrow_mut().remove(session_id);
                    mappings.conversations.borrow_mut().remove(session_id);
                    mappings.reply_drafts.borrow_mut().remove(session_id);
                    mappings.session_logs.borrow_mut().remove(session_id);
                    mappings.open_log_panels.borrow_mut().remove(session_id);
                    mappings.rendezvous_outputs.borrow_mut().remove(session_id);
                    mappings
                        .rendezvous_authenticated
                        .borrow_mut()
                        .remove(session_id);
                    if mappings
                        .pending_rendezvous_command
                        .borrow()
                        .is_some_and(|pending| pending.session_id == *session_id)
                    {
                        mappings.pending_rendezvous_command.borrow_mut().take();
                        ui.set_operation_busy(false);
                    }
                    if mappings.rendezvous_panel_session.borrow().as_ref() == Some(session_id) {
                        close_rendezvous_panel(ui, mappings);
                    }
                    mappings.session_keys.borrow_mut().remove(session_id);
                    if mappings
                        .pending_original_command
                        .borrow()
                        .as_ref()
                        .is_some_and(|pending| pending.target.session_id == *session_id)
                    {
                        mappings.pending_original_command.borrow_mut().take();
                        ui.set_operation_busy(false);
                    }
                    if mappings
                        .original_viewer
                        .borrow()
                        .as_ref()
                        .is_some_and(|viewer| viewer.source_session_id == *session_id)
                    {
                        clear_original_image_viewer(ui, mappings);
                    }
                    mappings
                        .opening_sessions
                        .borrow_mut()
                        .retain(|pending| pending != key);
                    if let ManagedSessionKey::Transient(transient_id) = key {
                        mappings.transient_labels.borrow_mut().remove(transient_id);
                        clear_pending_transient_selection(mappings, transient_id);
                    }
                    None
                }
                _ => None,
            };
            let latest_snapshot = mappings.latest_snapshot.borrow().clone();
            if let Some(snapshot) = latest_snapshot {
                apply_snapshot(ui, mappings, sender, snapshot, ConversationRefresh::Refresh);
            }
            if let Some(key) = select_key
                && let Some(index) = mappings
                    .visible_session_keys
                    .borrow()
                    .iter()
                    .position(|candidate| candidate == &key)
                && let Ok(index) = i32::try_from(index)
            {
                ui.set_selected_session(index);
                ui.set_message_follow_bottom(true);
                ui.set_message_input("".into());
                ui.set_peer_address_input("".into());
                ui.set_connect_input_visible(false);
                ui.set_lock_confirmation_visible(false);
                refresh_messages(ui, mappings);
            }
            ui.set_operation_status(format!("Session {session:?}").into());
        }
        FrontendEvent::Contact(contact) => {
            let clear_rendezvous_auth = match &contact {
                ContactSessionEvent::IncomingCall { session_id, .. }
                | ContactSessionEvent::Disconnected { session_id, .. } => Some(*session_id),
                ContactSessionEvent::PhaseChanged { session_id, phase }
                    if matches!(phase, OneToOnePhase::Standby | OneToOnePhase::Closed) =>
                {
                    Some(*session_id)
                }
                _ => None,
            };
            if let Some(session_id) = clear_rendezvous_auth {
                mappings
                    .rendezvous_authenticated
                    .borrow_mut()
                    .remove(&session_id);
            }
            update_contact_tofu_state(mappings, &contact);
            let status = contact_event_status(contact);
            let latest_snapshot = mappings.latest_snapshot.borrow().clone();
            if let Some(snapshot) = latest_snapshot {
                apply_snapshot(ui, mappings, sender, snapshot, ConversationRefresh::Refresh);
            }
            ui.set_operation_status(status.into());
        }
        FrontendEvent::Rendezvous(rendezvous) => {
            update_rendezvous_authentication(mappings, &rendezvous);
            let status = rendezvous_event_status(&rendezvous);
            let latest_snapshot = mappings.latest_snapshot.borrow().clone();
            if let Some(snapshot) = latest_snapshot {
                apply_snapshot(
                    ui,
                    mappings,
                    sender,
                    snapshot,
                    ConversationRefresh::Preserve,
                );
            }
            ui.set_operation_status(status.into());
        }
        FrontendEvent::Group(group) => {
            ui.set_operation_status(group_event_status(group).into());
        }
        FrontendEvent::FileTransfer(event) => {
            let progress = match &event {
                FileTransferEvent::Progress {
                    session_id,
                    transfer_id,
                    direction,
                    ..
                } => Some((*session_id, *transfer_id, *direction)),
                _ => None,
            };
            let status = apply_file_transfer_event(mappings, event);
            if !progress.is_some_and(|(session_id, transfer_id, direction)| {
                refresh_visible_file_progress_row(ui, mappings, session_id, transfer_id, direction)
            }) {
                refresh_messages(ui, mappings);
            }
            ui.set_operation_status(status.into());
        }
        FrontendEvent::Offline(event) => {
            apply_offline_event(ui, mappings, sender, event);
        }
        FrontendEvent::TextReceived(event) => {
            receive_text(mappings, &event);
            refresh_messages(ui, mappings);
            let status = event
                .warning
                .or(event.history_warning)
                .unwrap_or_else(|| "Message received".into());
            ui.set_operation_status(status.into());
        }
        FrontendEvent::TextDeliveryUpdated(event) => {
            receive_delivery(mappings, &event);
            refresh_messages(ui, mappings);
            ui.set_operation_status(
                event
                    .warning
                    .unwrap_or_else(|| "Message delivered".into())
                    .into(),
            );
        }
        FrontendEvent::ImageReceived(event) => {
            let filename = event.filename.clone();
            match receive_image(mappings, event) {
                Ok(()) => {
                    refresh_messages(ui, mappings);
                    ui.set_operation_status(format!("Image received: {filename}").into());
                }
                Err(error) => {
                    ui.set_operation_status(format!("Image preview rejected: {error}").into());
                }
            }
        }
        FrontendEvent::ImageDeliveryUpdated(event) => {
            receive_image_delivery(mappings, &event);
            refresh_messages(ui, mappings);
            ui.set_operation_status("Image delivered".into());
        }
        FrontendEvent::OriginalImageProgress {
            session_id,
            media_id,
            received_bytes,
            sender_b32,
            ..
        } => {
            let target = OriginalImageTarget {
                session_id,
                media_id,
                sender_b32,
            };
            if original_image_download_active(mappings, &target) {
                set_original_image_state(
                    mappings,
                    &target,
                    OriginalImagePresentationState::Receiving,
                    received_bytes,
                );
                refresh_messages(ui, mappings);
            }
        }
        FrontendEvent::OriginalImageReceived(event) => {
            let target = OriginalImageTarget {
                session_id: event.session_id,
                media_id: event.media_id,
                sender_b32: event.sender_b32.clone(),
            };
            if !original_image_download_active(mappings, &target) {
                return;
            }
            let filename = event.filename.clone();
            match present_original_image(ui, mappings, event) {
                Ok(()) => {
                    refresh_messages(ui, mappings);
                    ui.set_operation_status(format!("Original image received: {filename}").into());
                }
                Err(error) => {
                    refresh_messages(ui, mappings);
                    ui.set_operation_status(format!("Original image rejected: {error}").into());
                }
            }
        }
        FrontendEvent::OriginalImageUnavailable {
            session_id,
            media_id,
            sender_b32,
        } => {
            let target = OriginalImageTarget {
                session_id,
                media_id,
                sender_b32,
            };
            if original_image_download_active(mappings, &target) {
                set_original_image_state(
                    mappings,
                    &target,
                    OriginalImagePresentationState::Unavailable,
                    0,
                );
                refresh_messages(ui, mappings);
                ui.set_operation_status("The original image is no longer available".into());
            }
        }
        FrontendEvent::OriginalImageCancelled {
            session_id,
            media_id,
            sender_b32,
        } => {
            set_original_image_state(
                mappings,
                &OriginalImageTarget {
                    session_id,
                    media_id,
                    sender_b32,
                },
                OriginalImagePresentationState::Available,
                0,
            );
            refresh_messages(ui, mappings);
            ui.set_operation_status("Original-image transfer cancelled".into());
        }
        FrontendEvent::ImageRejected { reason, .. } => {
            ui.set_operation_status(format!("Image rejected: {reason}").into());
        }
        _ => {}
    }
}

fn sam_monitor_status_text(status: &SamMonitorStatus) -> String {
    match status {
        SamMonitorStatus::Inactive => "Inactive".into(),
        SamMonitorStatus::Checking => "Checking".into(),
        SamMonitorStatus::Healthy => "Healthy".into(),
        SamMonitorStatus::Degraded {
            consecutive_failures,
            reason,
        } => format!("Degraded ({consecutive_failures}/3): {reason}"),
        SamMonitorStatus::Unavailable { reason } => format!("Unavailable: {reason}"),
    }
}

fn sam_monitor_status_tone(status: &SamMonitorStatus) -> i32 {
    match status {
        SamMonitorStatus::Healthy => 1,
        SamMonitorStatus::Degraded { .. } => 2,
        SamMonitorStatus::Unavailable { .. } => 3,
        SamMonitorStatus::Inactive | SamMonitorStatus::Checking => 0,
    }
}

fn sam_test_status_text(status: &SamTestStatus) -> String {
    match status {
        SamTestStatus::Idle => "Not run".into(),
        SamTestStatus::Running => "Running".into(),
        SamTestStatus::Succeeded => "Succeeded".into(),
        SamTestStatus::Failed(reason) => format!("Failed: {reason}"),
    }
}

fn sam_test_status_tone(status: &SamTestStatus) -> i32 {
    match status {
        SamTestStatus::Succeeded => 1,
        SamTestStatus::Failed(_) => 3,
        SamTestStatus::Idle | SamTestStatus::Running => 0,
    }
}

fn record_frontend_event_log(mappings: &UiMappings, event: &FrontendEvent) {
    match event {
        FrontendEvent::Session(SessionLifecycleEvent::Opened { session_id, .. }) => {
            append_session_log(
                mappings,
                *session_id,
                "SESSION",
                SessionLogLevel::Info,
                "Session opened.",
            );
        }
        FrontendEvent::Session(SessionLifecycleEvent::Closing { session_id, .. }) => {
            append_session_log(
                mappings,
                *session_id,
                "SESSION",
                SessionLogLevel::Warning,
                "Session is closing.",
            );
        }
        FrontendEvent::Contact(contact) => {
            if let Some(session_id) = contact_event_session_id(contact) {
                append_session_log(
                    mappings,
                    session_id,
                    "1:1",
                    contact_event_log_level(contact),
                    contact_event_status(contact.clone()),
                );
            }
        }
        FrontendEvent::Rendezvous(rendezvous) => {
            let (session_id, message, level) = match rendezvous {
                commtools_runtime::RendezvousSessionEvent::OutgoingAuthenticated {
                    session_id,
                    peer_b32,
                } => (
                    *session_id,
                    format!("Outgoing rendezvous authenticated with {peer_b32}."),
                    SessionLogLevel::Info,
                ),
                commtools_runtime::RendezvousSessionEvent::IncomingAuthenticated {
                    session_id,
                    peer_b32,
                } => (
                    *session_id,
                    format!("Incoming rendezvous authenticated with {peer_b32}."),
                    SessionLogLevel::Info,
                ),
                commtools_runtime::RendezvousSessionEvent::InvitationConsumed {
                    session_id,
                    peer_b32,
                } => (
                    *session_id,
                    format!("Rendezvous invitation consumed by {peer_b32}."),
                    SessionLogLevel::Info,
                ),
                commtools_runtime::RendezvousSessionEvent::AuthenticationRejected {
                    session_id,
                    peer_b32,
                    reason,
                } => (
                    *session_id,
                    format!("Rendezvous authentication from {peer_b32} rejected: {reason}"),
                    SessionLogLevel::Error,
                ),
                _ => return,
            };
            append_session_log(mappings, session_id, "RENDEZVOUS", level, message);
        }
        FrontendEvent::Group(group) => {
            if let Some(session_id) = group_event_session_id(group) {
                append_session_log(
                    mappings,
                    session_id,
                    "GROUP",
                    group_event_log_level(group),
                    group_event_status(group.clone()),
                );
            }
        }
        FrontendEvent::FileTransfer(file) => {
            if let Some((session_id, message, level)) = file_transfer_log_entry(file) {
                append_session_log(mappings, session_id, "FILE", level, message);
            }
        }
        FrontendEvent::Offline(offline) => {
            if let Some(session_id) = offline_event_session_id(offline) {
                append_session_log(
                    mappings,
                    session_id,
                    "OFFLINE",
                    offline_event_log_level(offline),
                    offline_event_status(offline),
                );
            }
        }
        FrontendEvent::Operation(RuntimeOperationEvent::Failed {
            session_id: Some(session_id),
            operation,
            reason,
        }) => append_session_log(
            mappings,
            *session_id,
            "RUNTIME",
            SessionLogLevel::Error,
            format!("{operation} failed: {reason}"),
        ),
        FrontendEvent::Operation(RuntimeOperationEvent::Recovered {
            session_id,
            operation,
        }) => append_session_log(
            mappings,
            *session_id,
            "RUNTIME",
            SessionLogLevel::Info,
            format!("{operation} recovered."),
        ),
        FrontendEvent::TextReceived(text) => append_session_log(
            mappings,
            text.session_id,
            "MESSAGE",
            if text.warning.is_some() || text.history_warning.is_some() {
                SessionLogLevel::Warning
            } else {
                SessionLogLevel::Info
            },
            if text.offline {
                "Offline text message received."
            } else {
                "Text message received."
            },
        ),
        FrontendEvent::TextDeliveryUpdated(delivery) => append_session_log(
            mappings,
            delivery.session_id,
            "MESSAGE",
            if delivery.warning.is_some() {
                SessionLogLevel::Warning
            } else {
                SessionLogLevel::Info
            },
            format!(
                "Text delivery updated: {}/{} acknowledgement(s).",
                delivery.received, delivery.expected
            ),
        ),
        FrontendEvent::ImageReceived(image) => append_session_log(
            mappings,
            image.session_id,
            "IMAGE",
            SessionLogLevel::Info,
            format!("Image preview received ({} bytes).", image.bytes.len()),
        ),
        FrontendEvent::ImageDeliveryUpdated(delivery) => append_session_log(
            mappings,
            delivery.session_id,
            "IMAGE",
            SessionLogLevel::Info,
            format!(
                "Image delivery updated: {}/{} acknowledgement(s).",
                delivery.received, delivery.expected
            ),
        ),
        FrontendEvent::OriginalImageReceived(original) => append_session_log(
            mappings,
            original.session_id,
            "IMAGE",
            SessionLogLevel::Info,
            format!("Original image received ({} bytes).", original.bytes.len()),
        ),
        FrontendEvent::OriginalImageUnavailable { session_id, .. } => append_session_log(
            mappings,
            *session_id,
            "IMAGE",
            SessionLogLevel::Warning,
            "Requested original image is unavailable.",
        ),
        FrontendEvent::OriginalImageCancelled { session_id, .. } => append_session_log(
            mappings,
            *session_id,
            "IMAGE",
            SessionLogLevel::Warning,
            "Original-image transfer cancelled.",
        ),
        FrontendEvent::ImageRejected { session_id, reason } => append_session_log(
            mappings,
            *session_id,
            "IMAGE",
            SessionLogLevel::Error,
            format!("Image rejected: {reason}"),
        ),
        FrontendEvent::TextRejected {
            session_id, reason, ..
        } => append_session_log(
            mappings,
            *session_id,
            "MESSAGE",
            SessionLogLevel::Error,
            format!("Text frame rejected: {reason}"),
        ),
        FrontendEvent::OriginalImageProgress { .. }
        | FrontendEvent::Session(_)
        | FrontendEvent::Operation(_)
        | FrontendEvent::Lifecycle(_) => {}
        _ => {}
    }
}

fn contact_event_session_id(event: &ContactSessionEvent) -> Option<SessionId> {
    match event {
        ContactSessionEvent::PhaseChanged { session_id, .. }
        | ContactSessionEvent::IncomingCall { session_id, .. }
        | ContactSessionEvent::CollisionResolved { session_id, .. }
        | ContactSessionEvent::IdentityVerified { session_id, .. }
        | ContactSessionEvent::SecureSessionReady { session_id, .. }
        | ContactSessionEvent::ConnectFailed { session_id, .. }
        | ContactSessionEvent::ConnectRetryScheduled { session_id, .. }
        | ContactSessionEvent::FrameRejected { session_id, .. }
        | ContactSessionEvent::ConnectionRejected { session_id, .. }
        | ContactSessionEvent::Disconnected { session_id, .. } => Some(*session_id),
        _ => None,
    }
}

fn contact_event_log_level(event: &ContactSessionEvent) -> SessionLogLevel {
    match event {
        ContactSessionEvent::ConnectFailed { .. }
        | ContactSessionEvent::FrameRejected { .. }
        | ContactSessionEvent::ConnectionRejected { .. } => SessionLogLevel::Error,
        ContactSessionEvent::ConnectRetryScheduled { .. }
        | ContactSessionEvent::Disconnected { .. } => SessionLogLevel::Warning,
        _ => SessionLogLevel::Info,
    }
}

fn group_event_session_id(event: &GroupSessionEvent) -> Option<SessionId> {
    match event {
        GroupSessionEvent::ConnectFailed { session_id, .. }
        | GroupSessionEvent::CollisionResolved { session_id, .. }
        | GroupSessionEvent::IdentityVerified { session_id, .. }
        | GroupSessionEvent::SecureSessionReady { session_id, .. }
        | GroupSessionEvent::PeerDisconnected { session_id, .. }
        | GroupSessionEvent::ControlReceived { session_id, .. }
        | GroupSessionEvent::RosterReceived { session_id, .. }
        | GroupSessionEvent::DissolutionReceived { session_id, .. }
        | GroupSessionEvent::FrameRejected { session_id, .. } => Some(*session_id),
        _ => None,
    }
}

fn group_event_log_level(event: &GroupSessionEvent) -> SessionLogLevel {
    match event {
        GroupSessionEvent::ConnectFailed { .. } | GroupSessionEvent::FrameRejected { .. } => {
            SessionLogLevel::Error
        }
        GroupSessionEvent::PeerDisconnected { .. }
        | GroupSessionEvent::DissolutionReceived { .. } => SessionLogLevel::Warning,
        GroupSessionEvent::SecureSessionReady {
            authorized: false, ..
        } => SessionLogLevel::Warning,
        _ => SessionLogLevel::Info,
    }
}

fn file_transfer_log_entry(
    event: &FileTransferEvent,
) -> Option<(SessionId, String, SessionLogLevel)> {
    let direction = |direction| match direction {
        FileTransferDirection::Sent => "outgoing",
        FileTransferDirection::Received => "incoming",
    };
    match event {
        FileTransferEvent::Offered {
            session_id,
            direction: transfer_direction,
            total_bytes,
            ..
        } => Some((
            *session_id,
            format!(
                "{} file offered ({total_bytes} bytes).",
                direction(*transfer_direction)
            ),
            SessionLogLevel::Info,
        )),
        FileTransferEvent::Started {
            session_id,
            direction: transfer_direction,
            total_bytes,
            ..
        } => Some((
            *session_id,
            format!(
                "{} file transfer started ({total_bytes} bytes).",
                direction(*transfer_direction)
            ),
            SessionLogLevel::Info,
        )),
        FileTransferEvent::Completed {
            session_id,
            direction: transfer_direction,
            total_bytes,
            ..
        } => Some((
            *session_id,
            format!(
                "{} file transfer completed ({total_bytes} bytes).",
                direction(*transfer_direction)
            ),
            SessionLogLevel::Info,
        )),
        FileTransferEvent::Declined {
            session_id,
            direction: transfer_direction,
            ..
        } => Some((
            *session_id,
            format!("{} file transfer declined.", direction(*transfer_direction)),
            SessionLogLevel::Warning,
        )),
        FileTransferEvent::Cancelled {
            session_id,
            direction: transfer_direction,
            ..
        } => Some((
            *session_id,
            format!(
                "{} file transfer cancelled.",
                direction(*transfer_direction)
            ),
            SessionLogLevel::Warning,
        )),
        FileTransferEvent::Expired {
            session_id,
            direction: transfer_direction,
            ..
        } => Some((
            *session_id,
            format!("{} file transfer expired.", direction(*transfer_direction)),
            SessionLogLevel::Warning,
        )),
        FileTransferEvent::Failed {
            session_id,
            direction: transfer_direction,
            ..
        } => Some((
            *session_id,
            format!("{} file transfer failed.", direction(*transfer_direction)),
            SessionLogLevel::Error,
        )),
        FileTransferEvent::Progress { .. } => None,
        _ => None,
    }
}

fn offline_event_log_level(event: &OfflineSessionEvent) -> SessionLogLevel {
    match event {
        OfflineSessionEvent::SendFailed { .. }
        | OfflineSessionEvent::BlobRejected { .. }
        | OfflineSessionEvent::PollTargetFailed { .. }
        | OfflineSessionEvent::IndexSyncSendFailed { .. } => SessionLogLevel::Error,
        OfflineSessionEvent::UnsupportedFrameReceived { .. } => SessionLogLevel::Warning,
        _ => SessionLogLevel::Info,
    }
}

fn apply_offline_event(
    ui: &AppWindow,
    mappings: &UiMappings,
    sender: &BackendSender,
    event: OfflineSessionEvent,
) {
    let conversation_refresh = if offline_event_requires_conversation_refresh(&event) {
        ConversationRefresh::Refresh
    } else {
        ConversationRefresh::Preserve
    };
    let Some(session_id) = offline_event_session_id(&event) else {
        return;
    };
    match offline_event_activity(&event) {
        Some(activity) => {
            mappings.offline_activities.borrow_mut().insert(
                session_id,
                OfflineActivityPresentation {
                    state: activity,
                    expires_at: Instant::now() + OFFLINE_STATUS_VISIBLE_FOR,
                },
            );
        }
        None if matches!(&event, OfflineSessionEvent::ModeChanged { .. }) => {
            mappings.offline_activities.borrow_mut().remove(&session_id);
        }
        None => {}
    }
    if let OfflineSessionEvent::SendConfirmed { message_id, .. } = &event {
        mark_offline_message_relayed(mappings, session_id, *message_id);
    }
    if let OfflineSessionEvent::ModeChanged { mode, .. } = &event
        && *mode != OfflineCoordinatorMode::Offline
        && row_value(&mappings.sessions, ui.get_selected_session()).flatten() == Some(session_id)
    {
        ui.set_message_input("".into());
    }
    let snapshot = mappings.latest_snapshot.borrow().clone();
    if let Some(snapshot) = snapshot {
        apply_snapshot(ui, mappings, sender, snapshot, conversation_refresh);
    } else if conversation_refresh == ConversationRefresh::Refresh {
        refresh_messages(ui, mappings);
    }
    ui.set_operation_status(offline_event_status(&event).into());
}

fn offline_event_requires_conversation_refresh(event: &OfflineSessionEvent) -> bool {
    matches!(event, OfflineSessionEvent::SendConfirmed { .. })
}

fn offline_event_session_id(event: &OfflineSessionEvent) -> Option<SessionId> {
    match event {
        OfflineSessionEvent::ModeChanged { session_id, .. }
        | OfflineSessionEvent::SendStarted { session_id, .. }
        | OfflineSessionEvent::SendConfirmed { session_id, .. }
        | OfflineSessionEvent::SendFailed { session_id, .. }
        | OfflineSessionEvent::UnsupportedFrameReceived { session_id, .. }
        | OfflineSessionEvent::BlobRejected { session_id, .. }
        | OfflineSessionEvent::PollTargetFailed { session_id, .. }
        | OfflineSessionEvent::PollSweepStarted { session_id }
        | OfflineSessionEvent::PollSweepCompleted { session_id, .. }
        | OfflineSessionEvent::IndexSyncSent { session_id }
        | OfflineSessionEvent::IndexSyncSendFailed { session_id, .. }
        | OfflineSessionEvent::IndexSyncApplied { session_id }
        | OfflineSessionEvent::StatePersisted { session_id }
        | OfflineSessionEvent::EnrollmentPersisted { session_id }
        | OfflineSessionEvent::ShutdownComplete { session_id } => Some(*session_id),
        _ => None,
    }
}

fn offline_event_activity(event: &OfflineSessionEvent) -> Option<OfflineActivityState> {
    match event {
        OfflineSessionEvent::SendStarted { .. } | OfflineSessionEvent::SendConfirmed { .. } => {
            Some(OfflineActivityState::Put)
        }
        OfflineSessionEvent::UnsupportedFrameReceived { .. } => Some(OfflineActivityState::Hit),
        OfflineSessionEvent::SendFailed { .. }
        | OfflineSessionEvent::BlobRejected { .. }
        | OfflineSessionEvent::PollTargetFailed { .. } => Some(OfflineActivityState::Fail),
        OfflineSessionEvent::PollSweepStarted { .. } => Some(OfflineActivityState::Poll),
        OfflineSessionEvent::PollSweepCompleted { result, .. } => Some(match result {
            OfflinePollResult::Hit => OfflineActivityState::Hit,
            OfflinePollResult::Miss => OfflineActivityState::Miss,
            OfflinePollResult::Failed => OfflineActivityState::Fail,
        }),
        _ => None,
    }
}

fn offline_event_status(event: &OfflineSessionEvent) -> String {
    match event {
        OfflineSessionEvent::ModeChanged { mode, .. } => match mode {
            OfflineCoordinatorMode::Offline => "Entered offline mode".into(),
            OfflineCoordinatorMode::Standby => "Returned to online standby".into(),
            OfflineCoordinatorMode::Closing => "Offline resources are closing".into(),
            OfflineCoordinatorMode::Closed => "Offline resources closed".into(),
        },
        OfflineSessionEvent::SendStarted { index, .. } => {
            format!("Offline PUT started at index {index}")
        }
        OfflineSessionEvent::SendConfirmed {
            index,
            successful_drop_count,
            ..
        } => format!("Offline PUT confirmed at index {index} on {successful_drop_count} drop(s)"),
        OfflineSessionEvent::SendFailed { index, reason, .. } => {
            format!("Offline PUT failed at index {index}: {reason}")
        }
        OfflineSessionEvent::UnsupportedFrameReceived {
            index, frame_type, ..
        } => format!("Unsupported offline frame {frame_type} at index {index}"),
        OfflineSessionEvent::BlobRejected { index, reason, .. } => {
            format!("Offline blob rejected at index {index}: {reason}")
        }
        OfflineSessionEvent::PollTargetFailed { index, reason, .. } => {
            format!("Offline poll failed at index {index}: {reason}")
        }
        OfflineSessionEvent::PollSweepStarted { .. } => "Offline poll sweep started".into(),
        OfflineSessionEvent::PollSweepCompleted {
            result,
            observation_count,
            ..
        } => {
            format!("Offline poll sweep completed: {result:?}, {observation_count} observation(s)")
        }
        OfflineSessionEvent::IndexSyncSent { .. } => "Offline index synchronization sent".into(),
        OfflineSessionEvent::IndexSyncSendFailed { reason, .. } => {
            format!("Offline index synchronization failed: {reason}")
        }
        OfflineSessionEvent::IndexSyncApplied { .. } => {
            "Offline index synchronization applied".into()
        }
        OfflineSessionEvent::StatePersisted { .. } => "Offline state persisted".into(),
        OfflineSessionEvent::EnrollmentPersisted { .. } => "Offline enrollment persisted".into(),
        OfflineSessionEvent::ShutdownComplete { .. } => "Offline coordinator stopped".into(),
        _ => "Offline session updated".into(),
    }
}

fn expire_offline_activities(mappings: &UiMappings) -> bool {
    let now = Instant::now();
    let mut activities = mappings.offline_activities.borrow_mut();
    let previous_len = activities.len();
    activities.retain(|_, activity| activity.expires_at > now);
    activities.len() != previous_len
}

fn visible_offline_activity(
    offline: bool,
    activity: Option<&OfflineActivityPresentation>,
    now: Instant,
) -> (&'static str, i32) {
    if !offline {
        return ("", 0);
    }
    activity
        .filter(|activity| activity.expires_at > now)
        .map(|activity| (activity.state.label(), activity.state.tone()))
        .unwrap_or(("DD IDLE", 0))
}

fn update_contact_tofu_state(mappings: &UiMappings, event: &ContactSessionEvent) {
    let (session_id, state) = match event {
        ContactSessionEvent::IncomingCall { session_id, .. } => (*session_id, None),
        ContactSessionEvent::IdentityVerified {
            session_id, pinned, ..
        } => (
            *session_id,
            (*pinned).then_some(TofuPresentationState::Verified),
        ),
        ContactSessionEvent::ConnectionRejected { session_id, reason } => {
            if *reason != DisconnectReason::TofuMismatch {
                return;
            }
            (*session_id, Some(TofuPresentationState::Mismatch))
        }
        ContactSessionEvent::Disconnected {
            session_id, reason, ..
        } => (
            *session_id,
            (*reason == DisconnectReason::TofuMismatch).then_some(TofuPresentationState::Mismatch),
        ),
        _ => return,
    };

    let mut states = mappings.contact_tofu_states.borrow_mut();
    if let Some(state) = state {
        states.insert(session_id, state);
    } else {
        states.remove(&session_id);
    }
}

fn contact_event_status(event: ContactSessionEvent) -> String {
    match event {
        ContactSessionEvent::PhaseChanged { phase, .. } => {
            format!("Contact state: {}", one_to_one_state(phase))
        }
        ContactSessionEvent::IncomingCall { peer_b32, .. } => {
            format!("Incoming call from {peer_b32}")
        }
        ContactSessionEvent::CollisionResolved { winner, .. } => {
            format!("Connection collision resolved: {winner:?}")
        }
        ContactSessionEvent::IdentityVerified {
            peer_b32, pinned, ..
        } => {
            let trust = if pinned { "locked" } else { "unlocked" };
            format!("Peer identity verified ({trust}): {peer_b32}")
        }
        ContactSessionEvent::SecureSessionReady { peer_b32, .. } => {
            format!("Secure session established with {peer_b32}")
        }
        ContactSessionEvent::ConnectFailed {
            peer_b32, reason, ..
        } => format!("Connection to {peer_b32} failed: {reason}"),
        ContactSessionEvent::ConnectRetryScheduled {
            peer_b32, reason, ..
        } => format!("Retrying connection to {peer_b32}: {reason}"),
        ContactSessionEvent::FrameRejected { reason, .. } => {
            format!("Rejected contact frame: {reason}")
        }
        ContactSessionEvent::ConnectionRejected { reason, .. } => {
            format!("Rejected contact connection: {reason:?}")
        }
        ContactSessionEvent::Disconnected {
            peer_b32, reason, ..
        } => match peer_b32 {
            Some(peer_b32) => format!("Disconnected from {peer_b32}: {reason:?}"),
            None => format!("Contact disconnected: {reason:?}"),
        },
        _ => "Contact session updated".into(),
    }
}

fn group_event_status(event: GroupSessionEvent) -> String {
    match event {
        GroupSessionEvent::ConnectFailed {
            peer_b32, reason, ..
        } => format!("Group connection to {peer_b32} failed: {reason}"),
        GroupSessionEvent::CollisionResolved {
            peer_b32, winner, ..
        } => format!("Group connection collision with {peer_b32} resolved: {winner:?}"),
        GroupSessionEvent::IdentityVerified { peer_b32, .. } => {
            format!("Group peer identity verified: {peer_b32}")
        }
        GroupSessionEvent::SecureSessionReady {
            peer_b32,
            authorized,
            ..
        } => {
            let state = if authorized {
                "authorized"
            } else {
                "not authorized"
            };
            format!("Secure group session ready with {peer_b32} ({state})")
        }
        GroupSessionEvent::PeerDisconnected {
            peer_b32, reason, ..
        } => format!("Group peer {peer_b32} disconnected: {reason:?}"),
        GroupSessionEvent::ControlReceived { peer_b32, .. } => {
            format!("Group control received from {peer_b32}")
        }
        GroupSessionEvent::RosterReceived { peer_b32, .. } => {
            format!("Group roster received from {peer_b32}")
        }
        GroupSessionEvent::DissolutionReceived { peer_b32, .. } => {
            format!("Group dissolution received from {peer_b32}")
        }
        GroupSessionEvent::FrameRejected {
            peer_b32, reason, ..
        } => format!("Rejected group frame from {peer_b32}: {reason}"),
        _ => "Group session updated".into(),
    }
}

fn apply_command_result(ui: &AppWindow, mappings: &UiMappings, result: CommToolsCommandResult) {
    let result = match result {
        CommToolsCommandResult::HistoryLoaded { key, records } => {
            merge_history(mappings, &key, records);
            refresh_messages(ui, mappings);
            return;
        }
        result => result,
    };

    let status: String = match result {
        CommToolsCommandResult::Applied => "Setting saved".into(),
        CommToolsCommandResult::ContactCreated(contact_id) => {
            *mappings.pending_contact_selection.borrow_mut() =
                Some(ContactCatalogEntry::Persistent(contact_id));
            ui.set_new_contact_name("".into());
            ui.set_new_one_to_one_visible(false);
            "Contact created".into()
        }
        CommToolsCommandResult::ContactRenamed(display_name) => {
            ui.set_contact_detail_name(display_name.clone().into());
            ui.set_contact_rename_input(display_name.into());
            "Contact renamed".into()
        }
        CommToolsCommandResult::ContactReset(contact_id) => {
            mappings
                .history_requested
                .borrow_mut()
                .remove(&ManagedSessionKey::Contact(contact_id));
            ui.set_contact_confirmation(0);
            ui.set_selected_contact_deaddrop(-1);
            ui.set_selected_contact_deaddrop_removable(false);
            "Contact trust, offline state, history, and deaddrop statistics reset".into()
        }
        CommToolsCommandResult::ContactDeleted(contact_id) => {
            mappings
                .history_requested
                .borrow_mut()
                .remove(&ManagedSessionKey::Contact(contact_id.clone()));
            if mappings.details_contact.borrow().as_ref() == Some(&contact_id) {
                mappings.details_contact.borrow_mut().take();
            }
            mappings.contact_deaddrops.borrow_mut().clear();
            clear_contact_export_form(ui);
            ui.set_contact_details_visible(false);
            ui.set_contact_confirmation(0);
            ui.set_contact_rename_input("".into());
            ui.set_contact_deaddrops(deaddrop_server_model(Vec::new()));
            ui.set_selected_contact_deaddrop(-1);
            ui.set_selected_contact_deaddrop_removable(false);
            ui.set_selected_contact(-1);
            "Contact deleted".into()
        }
        CommToolsCommandResult::ContactBackupExported(path) => {
            clear_contact_export_form(ui);
            format!("Encrypted contact exported to {}", path.display())
        }
        CommToolsCommandResult::ContactBackupInspected(inspection) => {
            let Some(pending) = mappings.pending_contact_import.borrow_mut().take() else {
                ui.set_operation_busy(false);
                ui.set_operation_status("Unexpected contact-backup inspection result".into());
                return;
            };
            let replacement = if inspection.replacement_contact_id.is_some() {
                "replace the existing matching contact"
            } else {
                "create a new contact"
            };
            let history = if inspection.includes_history {
                "including retained history"
            } else {
                "without retained history"
            };
            ui.set_settings_data_confirmation_text(
                format!(
                    "Import '{}' ({history}) and {replacement}?",
                    inspection.display_name
                )
                .into(),
            );
            ui.set_settings_data_confirmation_visible(true);
            *mappings.contact_import_confirmation.borrow_mut() =
                Some(ContactImportConfirmation {
                    path: pending.path,
                    passphrase: pending.passphrase,
                    inspection,
                });
            "Encrypted contact backup inspected".into()
        }
        CommToolsCommandResult::ContactBackupImported(contact_id) => {
            *mappings.pending_contact_selection.borrow_mut() =
                Some(ContactCatalogEntry::Persistent(contact_id));
            mappings.contact_import_confirmation.borrow_mut().take();
            clear_settings_data_form(ui);
            "Encrypted contact backup imported".into()
        }
        CommToolsCommandResult::TransientOpening(transient_id) => {
            let label = mappings
                .pending_transient_label
                .borrow_mut()
                .take()
                .unwrap_or_default();
            if !label.is_empty() {
                mappings
                    .transient_labels
                    .borrow_mut()
                    .insert(transient_id.clone(), label);
            }
            *mappings.pending_contact_selection.borrow_mut() =
                Some(ContactCatalogEntry::Transient(transient_id));
            ui.set_new_transient_label("".into());
            ui.set_new_one_to_one_visible(false);
            "Transient session is opening".into()
        }
        CommToolsCommandResult::ContactRendezvousRequestGenerated(material) => {
            let Some(session_id) = take_pending_rendezvous_command(
                mappings,
                PendingRendezvousCommandKind::GenerateRequest,
            ) else {
                ui.set_operation_busy(false);
                ui.set_operation_status("Unexpected rendezvous request result".into());
                return;
            };
            store_rendezvous_output(
                ui,
                mappings,
                session_id,
                "Request",
                Zeroizing::new(material),
            );
            ui.set_rendezvous_input("".into());
            "Rendezvous request generated".into()
        }
        CommToolsCommandResult::ContactRendezvousResponseGenerated(material) => {
            let Some(session_id) = take_pending_rendezvous_command(
                mappings,
                PendingRendezvousCommandKind::AnswerRequest,
            ) else {
                ui.set_operation_busy(false);
                ui.set_operation_status("Unexpected rendezvous response result".into());
                return;
            };
            store_rendezvous_output(
                ui,
                mappings,
                session_id,
                "Response",
                Zeroizing::new(material),
            );
            ui.set_rendezvous_input("".into());
            "Rendezvous response generated".into()
        }
        CommToolsCommandResult::ContactRendezvousConnectionStarted(session_id) => {
            if take_pending_rendezvous_command(
                mappings,
                PendingRendezvousCommandKind::ConnectResponse,
            ) != Some(session_id)
            {
                ui.set_operation_busy(false);
                ui.set_operation_status("Unexpected rendezvous connection result".into());
                return;
            }
            mappings.rendezvous_outputs.borrow_mut().remove(&session_id);
            close_rendezvous_panel(ui, mappings);
            "Rendezvous connection started".into()
        }
        CommToolsCommandResult::ContactRendezvousRevoked(session_id) => {
            if take_pending_rendezvous_command(mappings, PendingRendezvousCommandKind::Revoke)
                != Some(session_id)
            {
                ui.set_operation_busy(false);
                ui.set_operation_status("Unexpected rendezvous revoke result".into());
                return;
            }
            mappings.rendezvous_outputs.borrow_mut().remove(&session_id);
            mappings
                .rendezvous_authenticated
                .borrow_mut()
                .remove(&session_id);
            if mappings.rendezvous_panel_session.borrow().as_ref() == Some(&session_id) {
                ui.set_rendezvous_input("".into());
                ui.set_rendezvous_output_label("".into());
                ui.set_rendezvous_output("".into());
            }
            "Rendezvous material revoked".into()
        }
        CommToolsCommandResult::ContactOpening(_) => {
            ui.set_settings_visible(false);
            "Contact session is opening".into()
        }
        CommToolsCommandResult::GroupCreated(_) => {
            ui.set_new_group_name("".into());
            "Group created".into()
        }
        CommToolsCommandResult::GroupLocalNameApplied => "Local group member name saved".into(),
        CommToolsCommandResult::GroupMemberRemoval { removed } => {
            ui.set_group_confirmation(0);
            ui.set_selected_group_member(-1);
            ui.set_selected_group_member_removable(false);
            if removed {
                "Group member removed".into()
            } else {
                "The selected member is no longer in the group".into()
            }
        }
        CommToolsCommandResult::GroupLeaveRequested => {
            ui.set_group_confirmation(0);
            clear_group_invitation_fields(ui);
            "Leave request sent; waiting for the owner's signed roster".into()
        }
        CommToolsCommandResult::GroupLocalLeaveStarted {
            deleted_immediately,
        } => {
            ui.set_group_confirmation(0);
            clear_group_invitation_fields(ui);
            if deleted_immediately {
                "Left group and deleted its local data".into()
            } else {
                "Group is closing; local data will be deleted after shutdown".into()
            }
        }
        CommToolsCommandResult::GroupDissolutionStarted {
            deleted_immediately,
        } => {
            ui.set_group_confirmation(0);
            clear_group_invitation_fields(ui);
            if deleted_immediately {
                "Group dissolved and local data deleted".into()
            } else {
                "Group dissolution sent; local data will be deleted after shutdown".into()
            }
        }
        CommToolsCommandResult::GroupDeleted(_) => {
            ui.set_group_confirmation(0);
            clear_group_invitation_fields(ui);
            "Local group data deleted".into()
        }
        CommToolsCommandResult::GroupOpening(_) => {
            ui.set_settings_visible(false);
            ui.set_group_invites_visible(false);
            ui.set_group_details_visible(false);
            ui.set_group_confirmation(0);
            clear_group_invitation_fields(ui);
            "Group session is opening".into()
        }
        CommToolsCommandResult::PublicGroupInviteIssued(invite) => {
            ui.set_generated_group_material_label("Public invite".into());
            ui.set_generated_group_material(invite.into());
            "Public group invite generated".into()
        }
        CommToolsCommandResult::PrivateGroupRequestGenerated(request) => {
            ui.set_generated_group_material_label("Private request".into());
            ui.set_generated_group_material(request.into());
            "Private group request generated".into()
        }
        CommToolsCommandResult::PrivateGroupInviteIssued(invite) => {
            ui.set_private_request_input("".into());
            ui.set_generated_group_material_label("Private invite".into());
            ui.set_generated_group_material(invite.into());
            "Private group invite generated".into()
        }
        CommToolsCommandResult::PublicGroupInviteImported(group_id)
        | CommToolsCommandResult::PrivateGroupInviteImported(group_id) => {
            *mappings.pending_group_selection.borrow_mut() = Some(group_id);
            clear_group_invitation_fields(ui);
            "Group invite imported; select Open to join".into()
        }
        CommToolsCommandResult::SessionCloseStarted(_) => "Chat session is closing".into(),
        CommToolsCommandResult::ContactConnectionStarted(_) => "Connecting to peer".into(),
        CommToolsCommandResult::ContactIncomingAccepted(_) => "Incoming call accepted".into(),
        CommToolsCommandResult::ContactIncomingDeclined(_) => "Incoming call declined".into(),
        CommToolsCommandResult::ContactDisconnectStarted(_) => "Disconnecting from peer".into(),
        CommToolsCommandResult::ContactOfflineEntered(_) => "Entered offline mode".into(),
        CommToolsCommandResult::ContactOfflineLeft(_) => "Returned to online standby".into(),
        CommToolsCommandResult::ContactPeerLocked(peer_b32) => {
            format!("Contact locked to verified peer {peer_b32}")
        }
        CommToolsCommandResult::ContactUnlocked {
            cleared_offline_state,
        } => {
            if cleared_offline_state {
                "Contact unlocked; peer-bound offline state was cleared".into()
            } else {
                "Contact unlocked".into()
            }
        }
        CommToolsCommandResult::ContactTunnelSettingsApplied(tunnels) => format!(
            "Contact tunnels saved: length {}, quantity {}",
            tunnels.length, tunnels.quantity
        ),
        CommToolsCommandResult::DefaultTunnelSettingsApplied(tunnels) => format!(
            "Default tunnels saved: length {}, quantity {}",
            tunnels.length, tunnels.quantity
        ),
        CommToolsCommandResult::SamTestStarted => "SAM test started".into(),
        CommToolsCommandResult::BackupExported(path) => {
            clear_settings_data_form(ui);
            format!("Encrypted backup created at {}", path.display())
        }
        CommToolsCommandResult::BackupRestored(path) => {
            clear_settings_data_form(ui);
            format!("Encrypted backup restored from {}", path.display())
        }
        CommToolsCommandResult::WipeAllAuthorized => {
            clear_settings_data_form(ui);
            ui.set_screen(3);
            ui.set_busy(true);
            ui.set_gate_error(
                "Wiping local data after closing sessions and encrypting shutdown state...".into(),
            );
            ui.set_operation_status("Complete local wipe authorized".into());
            return;
        }
        CommToolsCommandResult::ContactHistorySettingApplied { enabled } => {
            if enabled {
                "Contact text history enabled".into()
            } else {
                "Contact text history disabled; existing history retained".into()
            }
        }
        CommToolsCommandResult::GroupHistorySettingApplied { enabled } => {
            if enabled {
                "Group text history enabled".into()
            } else {
                "Group text history disabled; existing history retained".into()
            }
        }
        CommToolsCommandResult::HistoryCleared { key } => {
            clear_presented_history(mappings, &key);
            mappings.history_requested.borrow_mut().remove(&key);
            ui.set_contact_confirmation(0);
            ui.set_group_confirmation(0);
            refresh_messages(ui, mappings);
            "Text history cleared".into()
        }
        CommToolsCommandResult::ContactDeaddropServerAdded(server) => {
            ui.set_contact_deaddrop_input("".into());
            ui.set_selected_contact_deaddrop(-1);
            ui.set_selected_contact_deaddrop_removable(false);
            format!("Contact deaddrop server added: {server}")
        }
        CommToolsCommandResult::ContactDeaddropServerRemoved(server) => {
            ui.set_contact_confirmation(0);
            ui.set_selected_contact_deaddrop(-1);
            ui.set_selected_contact_deaddrop_removable(false);
            format!("Contact deaddrop server removed: {server}")
        }
        CommToolsCommandResult::TextSent(sent) => {
            let status = sent
                .history_warning
                .clone()
                .unwrap_or_else(|| "Message sent".into());
            let selected_session =
                row_value(&mappings.sessions, ui.get_selected_session()).flatten();
            let sent_session = sent.session_id;
            mappings.reply_drafts.borrow_mut().remove(&sent_session);
            append_session_log(
                mappings,
                sent_session,
                "MESSAGE",
                if sent.history_warning.is_some() {
                    SessionLogLevel::Warning
                } else {
                    SessionLogLevel::Info
                },
                if sent.offline {
                    "Offline text message queued."
                } else {
                    "Text message sent."
                },
            );
            record_sent_text(mappings, sent);
            if selected_session == Some(sent_session) {
                ui.set_message_input("".into());
            }
            refresh_messages(ui, mappings);
            status
        }
        CommToolsCommandResult::ImageSent(sent) => {
            let filename = sent.filename.clone();
            append_session_log(
                mappings,
                sent.session_id,
                "IMAGE",
                SessionLogLevel::Info,
                format!("Image preview sent ({} bytes).", sent.bytes.len()),
            );
            match record_sent_image(mappings, sent) {
                Ok(session_id) => {
                    let selected_session =
                        row_value(&mappings.sessions, ui.get_selected_session()).flatten();
                    if selected_session == Some(session_id) {
                        refresh_messages(ui, mappings);
                    }
                    format!("Image sent: {filename}")
                }
                Err(error) => {
                    format!("Image sent, but its preview could not be displayed: {error}")
                }
            }
        }
        CommToolsCommandResult::FileOffered(offered) => {
            let filename = offered.filename.clone();
            upsert_presented_file(
                mappings,
                offered.session_id,
                FileTransferDirection::Sent,
                PresentedFileTransfer {
                    transfer_id: offered.transfer_id,
                    filename: offered.filename,
                    total_bytes: offered.total_bytes,
                    transferred_bytes: 0,
                    state: PresentedFileTransferState::AwaitingAcceptance,
                    saved_path: None,
                    failure: None,
                },
            );
            refresh_messages(ui, mappings);
            format!("File offered: {filename}")
        }
        CommToolsCommandResult::FileAccepted { .. } => "File offer accepted".into(),
        CommToolsCommandResult::FileDeclined { .. } => "File offer declined".into(),
        CommToolsCommandResult::FileCancelled { .. } => "File transfer cancelled".into(),
        CommToolsCommandResult::OriginalImageRequest(result) => {
            let pending = mappings.pending_original_command.borrow_mut().take();
            match result {
                OriginalImageRequestResult::Requested => {
                    if let Some(pending) = pending
                        && pending.kind == PendingOriginalImageCommandKind::Request
                    {
                        set_original_image_state(
                            mappings,
                            &pending.target,
                            OriginalImagePresentationState::Requesting,
                            0,
                        );
                    }
                    refresh_messages(ui, mappings);
                    "Original image requested".into()
                }
                OriginalImageRequestResult::Cached(event) => {
                    let presented = present_original_image(ui, mappings, event);
                    refresh_messages(ui, mappings);
                    match presented {
                        Ok(()) => "Original image opened from memory cache".into(),
                        Err(error) => format!("Cached original image rejected: {error}"),
                    }
                }
            }
        }
        CommToolsCommandResult::OriginalImageCancelled { .. } => {
            if let Some(pending) = mappings.pending_original_command.borrow_mut().take()
                && pending.kind == PendingOriginalImageCommandKind::Cancel
            {
                set_original_image_state(
                    mappings,
                    &pending.target,
                    OriginalImagePresentationState::Available,
                    0,
                );
            }
            refresh_messages(ui, mappings);
            "Original-image download cancelled".into()
        }
        _ => "Operation completed".into(),
    };
    ui.set_operation_busy(false);
    ui.set_operation_status(status.into());
}

fn sibling_export_path(vault_root: &Path, suffix: &str) -> PathBuf {
    let mut filename = vault_root
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new(".termcomm-i2p"))
        .to_os_string();
    filename.push(suffix);
    vault_root
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(filename)
}

fn choose_data_path(action: i32, current: &Path, default_path: &Path) -> Option<PathBuf> {
    match action {
        1 => choose_save_path(
            "Create encrypted backup",
            "CommTools backup",
            "ctbak",
            current,
            default_path,
        ),
        2 => choose_open_path(
            "Restore encrypted backup",
            "CommTools backup",
            "ctbak",
            current,
            default_path,
        ),
        3 => choose_open_path(
            "Import encrypted contact",
            "CommTools contact",
            "ctcontact",
            current,
            default_path,
        ),
        _ => None,
    }
}

fn choose_save_path(
    title: &str,
    filter_name: &str,
    extension: &str,
    current: &Path,
    default_path: &Path,
) -> Option<PathBuf> {
    let selected = if current.as_os_str().is_empty() {
        default_path
    } else {
        current
    };
    let mut dialog = rfd::FileDialog::new()
        .set_title(title)
        .add_filter(filter_name, &[extension]);
    if let Some(parent) = selected.parent() {
        dialog = dialog.set_directory(parent);
    }
    if let Some(filename) = selected.file_name().and_then(|value| value.to_str()) {
        dialog = dialog.set_file_name(filename);
    }
    dialog.save_file()
}

fn choose_open_path(
    title: &str,
    filter_name: &str,
    extension: &str,
    current: &Path,
    default_path: &Path,
) -> Option<PathBuf> {
    let selected = if current.as_os_str().is_empty() {
        default_path
    } else {
        current
    };
    let mut dialog = rfd::FileDialog::new()
        .set_title(title)
        .add_filter(filter_name, &[extension]);
    if let Some(parent) = selected.parent() {
        dialog = dialog.set_directory(parent);
    }
    dialog.pick_file()
}

fn clear_settings_data_secrets(ui: &AppWindow) {
    ui.set_settings_data_passphrase("".into());
    ui.set_settings_data_passphrase_confirm("".into());
}

fn clear_settings_data_form(ui: &AppWindow) {
    clear_settings_data_secrets(ui);
    ui.set_settings_data_action(0);
    ui.set_settings_data_path("".into());
    ui.set_settings_data_option(true);
    ui.set_settings_data_confirmation_visible(false);
    ui.set_settings_data_confirmation_text("".into());
}

fn clear_contact_export_secrets(ui: &AppWindow) {
    ui.set_contact_export_passphrase("".into());
    ui.set_contact_export_passphrase_confirm("".into());
}

fn clear_contact_export_form(ui: &AppWindow) {
    clear_contact_export_secrets(ui);
    ui.set_contact_export_visible(false);
    ui.set_contact_export_path("".into());
    ui.set_contact_export_history(true);
}

fn clear_group_invitation_fields(ui: &AppWindow) {
    ui.set_group_invite_input("".into());
    ui.set_private_request_input("".into());
    ui.set_generated_group_material_label("".into());
    ui.set_generated_group_material("".into());
}

fn clear_presented_history(mappings: &UiMappings, key: &ManagedSessionKey) {
    let session_ids = mappings
        .session_keys
        .borrow()
        .iter()
        .filter_map(|(session_id, candidate)| (candidate == key).then_some(*session_id))
        .collect::<Vec<_>>();
    let mut conversations = mappings.conversations.borrow_mut();
    for session_id in session_ids {
        if let Some(messages) = conversations.get_mut(&session_id) {
            messages.retain(|message| !message.stored);
        }
    }
}

fn row_value<T: Clone>(values: &RefCell<Vec<T>>, index: i32) -> Option<T> {
    usize::try_from(index)
        .ok()
        .and_then(|index| values.borrow().get(index).cloned())
}

fn row_index<T: PartialEq>(values: &RefCell<Vec<T>>, value: &T) -> Option<i32> {
    values
        .borrow()
        .iter()
        .position(|candidate| candidate == value)
        .and_then(|index| i32::try_from(index).ok())
}

fn persistent_contact_id(mappings: &UiMappings, index: i32) -> Option<ContactId> {
    match row_value(&mappings.contact_catalog, index)? {
        ContactCatalogEntry::Persistent(contact_id) => Some(contact_id),
        ContactCatalogEntry::Transient(_) => None,
    }
}

fn contact_is_active(mappings: &UiMappings, contact_id: &ContactId) -> bool {
    if mappings
        .opening_sessions
        .borrow()
        .contains(&ManagedSessionKey::Contact(contact_id.clone()))
    {
        return true;
    }
    mappings
        .latest_snapshot
        .borrow()
        .as_ref()
        .and_then(|snapshot| {
            snapshot
                .contacts
                .iter()
                .find(|contact| &contact.id == contact_id)
        })
        .is_none_or(|contact| contact.active)
}

fn rendezvous_session_at(mappings: &UiMappings, index: i32) -> Option<SessionId> {
    let session_id = row_value(&mappings.sessions, index).flatten()?;
    mappings
        .latest_snapshot
        .borrow()
        .as_ref()?
        .sessions
        .iter()
        .find(|session| session.session_id == session_id)
        .filter(|session| rendezvous_available(session))
        .map(|session| session.session_id)
}

fn rendezvous_available(session: &commtools_runtime::SessionSummary) -> bool {
    rendezvous_available_for(
        &session.key,
        session.phase,
        session.one_to_one_phase,
        session.offline_mode,
        session.pinned_peer_b32.is_some(),
    )
}

fn rendezvous_available_for(
    key: &ManagedSessionKey,
    phase: ManagedSessionPhase,
    one_to_one_phase: Option<OneToOnePhase>,
    offline_mode: Option<OfflineCoordinatorMode>,
    peer_pinned: bool,
) -> bool {
    is_one_to_one_key(key)
        && phase == ManagedSessionPhase::Open
        && one_to_one_phase == Some(OneToOnePhase::Standby)
        && offline_mode != Some(OfflineCoordinatorMode::Offline)
        && !peer_pinned
}

fn is_one_to_one_key(key: &ManagedSessionKey) -> bool {
    matches!(
        key,
        ManagedSessionKey::Contact(_) | ManagedSessionKey::Transient(_)
    )
}

fn show_rendezvous_panel(ui: &AppWindow, mappings: &UiMappings, session_id: SessionId) {
    let output = mappings
        .rendezvous_outputs
        .borrow()
        .get(&session_id)
        .map(|output| (output.label.clone(), output.value.to_string()));
    *mappings.rendezvous_panel_session.borrow_mut() = Some(session_id);
    ui.set_connect_input_visible(false);
    ui.set_lock_confirmation_visible(false);
    ui.set_rendezvous_input("".into());
    if let Some((label, value)) = output {
        ui.set_rendezvous_output_label(label.into());
        ui.set_rendezvous_output(value.into());
    } else {
        ui.set_rendezvous_output_label("".into());
        ui.set_rendezvous_output("".into());
    }
    ui.set_rendezvous_visible(true);
}

fn close_rendezvous_panel(ui: &AppWindow, mappings: &UiMappings) {
    mappings.rendezvous_panel_session.borrow_mut().take();
    ui.set_rendezvous_visible(false);
    ui.set_rendezvous_input("".into());
    ui.set_rendezvous_output_label("".into());
    ui.set_rendezvous_output("".into());
}

fn begin_rendezvous_command(
    ui: &AppWindow,
    mappings: &UiMappings,
    session_id: SessionId,
    kind: PendingRendezvousCommandKind,
    status: &str,
) {
    *mappings.pending_rendezvous_command.borrow_mut() =
        Some(PendingRendezvousCommand { session_id, kind });
    ui.set_operation_busy(true);
    ui.set_operation_status(status.into());
}

fn fail_rendezvous_command(ui: &AppWindow, mappings: &UiMappings, error: impl ToString) {
    mappings.pending_rendezvous_command.borrow_mut().take();
    ui.set_operation_busy(false);
    ui.set_operation_status(error.to_string().into());
}

fn validated_rendezvous_input(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= MAX_RENDEZVOUS_INPUT_BYTES).then(|| value.to_owned())
}

fn take_pending_rendezvous_command(
    mappings: &UiMappings,
    expected: PendingRendezvousCommandKind,
) -> Option<SessionId> {
    let pending = mappings.pending_rendezvous_command.borrow_mut().take()?;
    (pending.kind == expected).then_some(pending.session_id)
}

fn store_rendezvous_output(
    ui: &AppWindow,
    mappings: &UiMappings,
    session_id: SessionId,
    label: &str,
    value: Zeroizing<String>,
) {
    let visible = mappings.rendezvous_panel_session.borrow().as_ref() == Some(&session_id);
    if visible {
        ui.set_rendezvous_output_label(label.into());
        ui.set_rendezvous_output(value.as_str().into());
    }
    mappings.rendezvous_outputs.borrow_mut().insert(
        session_id,
        RendezvousOutputPresentation {
            label: label.into(),
            value,
        },
    );
}

fn update_rendezvous_authentication(mappings: &UiMappings, event: &RendezvousSessionEvent) {
    let (session_id, authenticated) = match event {
        RendezvousSessionEvent::OutgoingAuthenticated { session_id, .. }
        | RendezvousSessionEvent::IncomingAuthenticated { session_id, .. }
        | RendezvousSessionEvent::InvitationConsumed { session_id, .. } => (*session_id, true),
        RendezvousSessionEvent::AuthenticationRejected { session_id, .. } => (*session_id, false),
        _ => return,
    };
    let mut states = mappings.rendezvous_authenticated.borrow_mut();
    if authenticated {
        states.insert(session_id);
    } else {
        states.remove(&session_id);
    }
    drop(states);
    if matches!(
        event,
        RendezvousSessionEvent::OutgoingAuthenticated { .. }
            | RendezvousSessionEvent::InvitationConsumed { .. }
    ) {
        remove_rendezvous_output(mappings, session_id);
    }
}

fn remove_rendezvous_output(mappings: &UiMappings, session_id: SessionId) {
    mappings.rendezvous_outputs.borrow_mut().remove(&session_id);
}

fn rendezvous_event_status(event: &RendezvousSessionEvent) -> String {
    match event {
        RendezvousSessionEvent::OutgoingAuthenticated { peer_b32, .. } => {
            format!("Outgoing rendezvous authenticated with {peer_b32}")
        }
        RendezvousSessionEvent::IncomingAuthenticated { peer_b32, .. } => {
            format!("Incoming rendezvous authenticated with {peer_b32}")
        }
        RendezvousSessionEvent::InvitationConsumed { peer_b32, .. } => {
            format!("Rendezvous invitation consumed by {peer_b32}")
        }
        RendezvousSessionEvent::AuthenticationRejected {
            peer_b32, reason, ..
        } => format!("Rendezvous authentication from {peer_b32} rejected: {reason}"),
        _ => "Rendezvous session updated".into(),
    }
}

fn clear_pending_transient_selection(mappings: &UiMappings, transient_id: &TransientId) {
    let should_clear = mappings
        .pending_contact_selection
        .borrow()
        .as_ref()
        .is_some_and(|pending| {
            matches!(pending, ContactCatalogEntry::Transient(pending_id) if pending_id == transient_id)
        });
    if should_clear {
        mappings.pending_contact_selection.borrow_mut().take();
    }
}

fn focus_catalog_session(
    ui: &AppWindow,
    mappings: &UiMappings,
    entry: &ContactCatalogEntry,
) -> bool {
    let key = match entry {
        ContactCatalogEntry::Persistent(contact_id) => {
            ManagedSessionKey::Contact(contact_id.clone())
        }
        ContactCatalogEntry::Transient(transient_id) => {
            ManagedSessionKey::Transient(transient_id.clone())
        }
    };
    let Some(index) = row_index(&mappings.visible_session_keys, &key) else {
        return false;
    };
    ui.set_selected_session(index);
    ui.set_message_follow_bottom(true);
    ui.set_message_input("".into());
    ui.set_connect_input_visible(false);
    ui.set_lock_confirmation_visible(false);
    refresh_messages(ui, mappings);
    true
}

fn contact_catalog_summary(persistent_count: usize, transient_count: usize) -> String {
    let persistent = count_label(persistent_count, "contact", "contacts");
    if transient_count == 0 {
        persistent.to_string()
    } else {
        format!(
            "{persistent}, {}",
            count_label(transient_count, "transient", "transients")
        )
    }
}

fn show_session_details(
    ui: &AppWindow,
    mappings: &UiMappings,
    session_index: i32,
) -> Result<(), String> {
    let key = row_value(&mappings.visible_session_keys, session_index)
        .ok_or_else(|| "Select a valid persistent session".to_string())?;
    match key {
        ManagedSessionKey::Contact(contact_id) => {
            let contact_index = row_index(&mappings.contacts, &contact_id)
                .ok_or_else(|| "The contact record is no longer available".to_string())?;
            let (active, peer_pinned) = mappings
                .latest_snapshot
                .borrow()
                .as_ref()
                .and_then(|snapshot| {
                    snapshot
                        .contacts
                        .iter()
                        .find(|contact| contact.id == contact_id)
                })
                .map(|contact| (contact.active, contact.peer_pinned))
                .ok_or_else(|| "The contact record is no longer available".to_string())?;

            ui.set_settings_visible(false);
            ui.set_new_one_to_one_visible(false);
            ui.set_contact_details_visible(false);
            ui.set_group_details_visible(false);
            ui.set_group_invites_visible(false);
            ui.set_selected_section(0);
            ui.set_selected_contact(contact_index);
            ui.set_selected_contact_active(active);
            ui.set_selected_contact_pinned(peer_pinned);
            ui.set_contact_confirmation(0);
            ui.set_contact_deaddrop_input("".into());
            ui.set_selected_contact_deaddrop(-1);
            ui.set_unlock_confirmation_visible(false);
            ui.set_group_confirmation(0);
            clear_group_invitation_fields(ui);
            ui.set_connect_input_visible(false);
            ui.set_lock_confirmation_visible(false);
            *mappings.details_contact.borrow_mut() = None;
            refresh_contact_details(ui, mappings, Some(&contact_id));
            if mappings.details_contact.borrow().as_ref() != Some(&contact_id) {
                return Err("The contact details are no longer available".into());
            }
            ui.set_contact_details_visible(true);
            Ok(())
        }
        ManagedSessionKey::Group(group_id) => {
            let group_index = row_index(&mappings.groups, &group_id)
                .ok_or_else(|| "The group record is no longer available".to_string())?;
            let (active, owner) = mappings
                .latest_snapshot
                .borrow()
                .as_ref()
                .and_then(|snapshot| snapshot.groups.iter().find(|group| group.id == group_id))
                .map(|group| (group.active, group.owner))
                .ok_or_else(|| "The group record is no longer available".to_string())?;

            ui.set_settings_visible(false);
            ui.set_new_one_to_one_visible(false);
            ui.set_contact_details_visible(false);
            ui.set_group_details_visible(false);
            ui.set_group_invites_visible(false);
            ui.set_selected_section(1);
            ui.set_selected_group(group_index);
            ui.set_selected_group_active(active);
            ui.set_selected_group_owner(owner);
            ui.set_group_confirmation(0);
            ui.set_selected_group_member(-1);
            ui.set_selected_group_member_removable(false);
            ui.set_contact_confirmation(0);
            ui.set_contact_deaddrop_input("".into());
            ui.set_selected_contact_deaddrop(-1);
            ui.set_unlock_confirmation_visible(false);
            clear_group_invitation_fields(ui);
            ui.set_connect_input_visible(false);
            ui.set_lock_confirmation_visible(false);
            *mappings.details_group.borrow_mut() = None;
            refresh_group_details(ui, mappings, Some(&group_id));
            if mappings.details_group.borrow().as_ref() != Some(&group_id) {
                return Err("The group details are no longer available".into());
            }
            ui.set_group_details_visible(true);
            Ok(())
        }
        ManagedSessionKey::Transient(_) => {
            Err("Transient sessions do not have persistent details".into())
        }
    }
}

fn session_title(
    key: &ManagedSessionKey,
    contact_names: &BTreeMap<ContactId, String>,
    group_names: &BTreeMap<commtools_core::GroupId, String>,
    transient_labels: &BTreeMap<TransientId, String>,
) -> String {
    match key {
        ManagedSessionKey::Contact(contact_id) => contact_names
            .get(contact_id)
            .cloned()
            .unwrap_or_else(|| format!("Contact {contact_id}")),
        ManagedSessionKey::Transient(transient_id) => transient_title(
            transient_id,
            transient_labels.get(transient_id).map(String::as_str),
        ),
        ManagedSessionKey::Group(group_id) => group_names
            .get(group_id)
            .cloned()
            .unwrap_or_else(|| format!("Group {group_id}")),
    }
}

fn transient_title(transient_id: &TransientId, display_label: Option<&str>) -> String {
    display_label
        .filter(|label| !label.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("Transient {transient_id}"))
}

fn normalize_transient_label(value: &str) -> String {
    value
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_TRANSIENT_LABEL_CHARS)
        .collect()
}

fn session_kind(key: &ManagedSessionKey) -> &'static str {
    match key {
        ManagedSessionKey::Contact(_) => "P",
        ManagedSessionKey::Transient(_) => "T",
        ManagedSessionKey::Group(_) => "G",
    }
}

fn session_has_details(key: &ManagedSessionKey) -> bool {
    matches!(
        key,
        ManagedSessionKey::Contact(_) | ManagedSessionKey::Group(_)
    )
}

fn model(items: Vec<CatalogItem>) -> ModelRc<CatalogItem> {
    Rc::new(VecModel::from(items)).into()
}

fn session_model(items: Vec<SessionItem>) -> ModelRc<SessionItem> {
    Rc::new(VecModel::from(items)).into()
}

fn set_clipboard_text(clipboard: &RefCell<Option<Clipboard>>, text: &str) -> Result<(), String> {
    let mut clipboard = clipboard.borrow_mut();
    if clipboard.is_none() {
        *clipboard = Some(Clipboard::new().map_err(|error| error.to_string())?);
    }
    let result = clipboard
        .as_mut()
        .expect("clipboard initialized above")
        .set_text(text.to_owned())
        .map_err(|error| error.to_string());
    if result.is_err() {
        *clipboard = None;
    }
    result
}

fn message_model(items: Vec<MessageItem>) -> ModelRc<MessageItem> {
    Rc::new(VecModel::from(items)).into()
}

fn session_log_model(items: Vec<LogItem>) -> ModelRc<LogItem> {
    Rc::new(VecModel::from(items)).into()
}

fn append_session_log(
    mappings: &UiMappings,
    session_id: SessionId,
    category: &str,
    level: SessionLogLevel,
    message: impl AsRef<str>,
) {
    let mut logs = mappings.session_logs.borrow_mut();
    let entries = logs.entry(session_id).or_default();
    if entries.len() >= MAX_SESSION_LOG_LINES {
        let trim = SESSION_LOG_TRIM_BATCH.min(entries.len());
        entries.drain(..trim);
    }
    entries.push_back(SessionLogEntry {
        timestamp_utc: current_utc_hms(),
        category: category.to_string(),
        message: sanitize_log_message(message.as_ref()),
        level,
    });
}

fn refresh_session_logs(ui: &AppWindow, mappings: &UiMappings) {
    let session_id = row_value(&mappings.sessions, ui.get_selected_session()).flatten();
    let visible = session_id
        .is_some_and(|session_id| mappings.open_log_panels.borrow().contains(&session_id));
    let entries = session_id
        .and_then(|session_id| mappings.session_logs.borrow().get(&session_id).cloned())
        .unwrap_or_default();
    let count = entries.len();
    let items = entries
        .into_iter()
        .map(|entry| LogItem {
            timestamp: entry.timestamp_utc.into(),
            category: entry.category.into(),
            message: entry.message.into(),
            tone: entry.level.tone(),
        })
        .collect();
    ui.set_session_logs(session_log_model(items));
    ui.set_session_log_summary(format!("Session Logs ({count})").into());
    ui.set_session_logs_empty(count == 0);
    ui.set_session_logs_visible(visible);
}

fn joined_session_log(mappings: &UiMappings, session_id: SessionId) -> String {
    mappings
        .session_logs
        .borrow()
        .get(&session_id)
        .map(|entries| {
            entries
                .iter()
                .map(|entry| {
                    format!(
                        "[{}] [{}] {}",
                        entry.timestamp_utc, entry.category, entry.message
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

fn sanitize_log_message(message: &str) -> String {
    const B32_BODY_CHARS: usize = 52;
    const B32_SUFFIX: &[char] = &['.', 'b', '3', '2', '.', 'i', '2', 'p'];
    const MAX_LOG_MESSAGE_CHARS: usize = 2_048;

    let characters = message
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(MAX_LOG_MESSAGE_CHARS)
        .collect::<Vec<_>>();
    let mut sanitized = String::new();
    let mut index = 0;
    while index < characters.len() {
        let suffix_start = index.saturating_add(B32_BODY_CHARS);
        let suffix_end = suffix_start.saturating_add(B32_SUFFIX.len());
        let is_b32 = suffix_end <= characters.len()
            && characters[index..suffix_start]
                .iter()
                .all(|character| matches!(character, 'a'..='z' | 'A'..='Z' | '2'..='7'))
            && characters[suffix_start..suffix_end]
                .iter()
                .zip(B32_SUFFIX)
                .all(|(actual, expected)| actual.eq_ignore_ascii_case(expected));
        if is_b32 {
            let address = characters[index..suffix_end].iter().collect::<String>();
            sanitized.push_str(&compact_b32_address(&address));
            index = suffix_end;
        } else {
            sanitized.push(characters[index]);
            index += 1;
        }
    }
    sanitized.trim().to_string()
}

fn group_member_model(items: Vec<GroupMemberItem>) -> ModelRc<GroupMemberItem> {
    Rc::new(VecModel::from(items)).into()
}

fn deaddrop_server_model(items: Vec<DeaddropServerItem>) -> ModelRc<DeaddropServerItem> {
    Rc::new(VecModel::from(items)).into()
}

fn refresh_contact_details(ui: &AppWindow, mappings: &UiMappings, selected: Option<&ContactId>) {
    let contact = selected.and_then(|contact_id| {
        mappings
            .latest_snapshot
            .borrow()
            .as_ref()
            .and_then(|snapshot| {
                snapshot
                    .contacts
                    .iter()
                    .find(|contact| &contact.id == contact_id)
            })
            .cloned()
    });
    let Some(contact) = contact else {
        *mappings.details_contact.borrow_mut() = None;
        mappings.contact_deaddrops.borrow_mut().clear();
        ui.set_contact_details_visible(false);
        ui.set_contact_deaddrops(deaddrop_server_model(Vec::new()));
        ui.set_selected_contact_deaddrop(-1);
        ui.set_selected_contact_deaddrop_removable(false);
        ui.set_contact_detail_name("".into());
        ui.set_contact_rename_input("".into());
        ui.set_contact_detail_local_b32("".into());
        ui.set_contact_detail_peer_b32("".into());
        ui.set_contact_history_enabled(false);
        ui.set_contact_deaddrop_summary("No deaddrop servers".into());
        ui.set_contact_deaddrop_input("".into());
        ui.set_contact_confirmation(0);
        return;
    };

    let context_changed = mappings.details_contact.borrow().as_ref() != Some(&contact.id);
    let selected_server = if context_changed {
        None
    } else {
        row_value(
            &mappings.contact_deaddrops,
            ui.get_selected_contact_deaddrop(),
        )
    };
    let server_addresses = contact
        .deaddrop_profiles
        .iter()
        .map(|server| server.address.clone())
        .collect::<Vec<_>>();
    let servers = contact
        .deaddrop_profiles
        .iter()
        .map(|server| DeaddropServerItem {
            address: server.address.clone().into(),
            statistics: format!(
                "PUT {}/{}  GET {}/{}",
                server.put_ok, server.put_fail, server.get_ok, server.get_fail
            )
            .into(),
            timing: deaddrop_timing(server.latency_ema_ms, server.last_success_ms).into(),
            active: server.active,
            removable: contact.deaddrop_profiles.len() > 1,
        })
        .collect::<Vec<_>>();
    let selected_server_index = selected_server
        .as_ref()
        .and_then(|selected| {
            server_addresses
                .iter()
                .position(|server| server.eq_ignore_ascii_case(selected))
        })
        .and_then(|index| i32::try_from(index).ok())
        .unwrap_or(-1);

    if context_changed {
        ui.set_contact_deaddrop_input("".into());
        ui.set_contact_rename_input(contact.display_name.clone().into());
        ui.set_contact_confirmation(0);
    }
    *mappings.details_contact.borrow_mut() = Some(contact.id);
    *mappings.contact_deaddrops.borrow_mut() = server_addresses;
    ui.set_contact_deaddrops(deaddrop_server_model(servers));
    ui.set_selected_contact_deaddrop(selected_server_index);
    ui.set_selected_contact_deaddrop_removable(
        selected_server_index >= 0 && contact.deaddrop_profiles.len() > 1,
    );
    ui.set_contact_detail_name(contact.display_name.into());
    ui.set_contact_detail_local_b32(contact.local_b32.unwrap_or_default().into());
    ui.set_contact_detail_peer_b32(contact.peer_b32.unwrap_or_default().into());
    ui.set_contact_history_enabled(contact.history_enabled);
    ui.set_contact_tunnel_length(i32::from(contact.tunnels.length));
    ui.set_contact_tunnel_quantity(i32::from(contact.tunnels.quantity));
    ui.set_contact_deaddrop_summary(
        format!(
            "{} configured, {} active",
            contact.deaddrop_profiles.len(),
            contact
                .deaddrop_profiles
                .iter()
                .filter(|server| server.active)
                .count()
        )
        .into(),
    );
}

fn deaddrop_timing(latency_ms: Option<u64>, last_success_ms: Option<u64>) -> String {
    let latency = latency_ms
        .map(|latency| format!("{latency}ms"))
        .unwrap_or_else(|| "latency -".into());
    let last = last_success_ms
        .map(format_epoch_millis_utc)
        .unwrap_or_else(|| "never".into());
    format!("{latency}  last {last}")
}

fn format_epoch_millis_utc(epoch_millis: u64) -> String {
    let seconds = (epoch_millis / 1_000) % 86_400;
    let hours = seconds / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let seconds = seconds % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02} UTC")
}

fn refresh_group_details(ui: &AppWindow, mappings: &UiMappings, selected: Option<&GroupId>) {
    let group = selected.and_then(|group_id| {
        mappings
            .latest_snapshot
            .borrow()
            .as_ref()
            .and_then(|snapshot| snapshot.groups.iter().find(|group| &group.id == group_id))
            .cloned()
    });
    let Some(group) = group else {
        *mappings.details_group.borrow_mut() = None;
        mappings.group_members.borrow_mut().clear();
        ui.set_group_details_visible(false);
        ui.set_group_members(group_member_model(Vec::new()));
        ui.set_selected_group_member(-1);
        ui.set_selected_group_member_removable(false);
        ui.set_group_detail_name("".into());
        ui.set_group_detail_role("".into());
        ui.set_group_detail_local_b32("".into());
        ui.set_group_detail_roster("".into());
        ui.set_group_history_enabled(false);
        ui.set_group_owner_ready(false);
        ui.set_group_leave_pending(false);
        ui.set_group_confirmation(0);
        return;
    };

    let context_changed = mappings.details_group.borrow().as_ref() != Some(&group.id);
    let selected_member = if context_changed {
        None
    } else {
        row_value(&mappings.group_members, ui.get_selected_group_member())
    };
    let member_b32s = group
        .members
        .iter()
        .map(|member| member.b32.clone())
        .collect::<Vec<_>>();
    let members = group
        .members
        .iter()
        .map(|member| GroupMemberItem {
            name: member.name.clone().into(),
            b32: member.b32.clone().into(),
            role: if member.owner {
                "Owner"
            } else if member.local {
                "Me"
            } else {
                "Member"
            }
            .into(),
            state: if member.connected {
                "Online"
            } else {
                "Offline"
            }
            .into(),
            removable: group.owner && !member.owner && !member.local,
        })
        .collect::<Vec<_>>();
    let selected_member_index = selected_member
        .as_ref()
        .and_then(|selected| {
            member_b32s
                .iter()
                .position(|member| member.eq_ignore_ascii_case(selected))
        })
        .and_then(|index| i32::try_from(index).ok())
        .unwrap_or(-1);
    let selected_member_removable = usize::try_from(selected_member_index)
        .ok()
        .and_then(|index| members.get(index))
        .is_some_and(|member| member.removable);

    if context_changed {
        ui.set_group_local_name_input(group.local_member_name.clone().into());
        ui.set_group_confirmation(0);
    }
    *mappings.details_group.borrow_mut() = Some(group.id.clone());
    *mappings.group_members.borrow_mut() = member_b32s;
    ui.set_group_members(group_member_model(members));
    ui.set_selected_group_member(selected_member_index);
    ui.set_selected_group_member_removable(selected_member_removable);
    ui.set_group_detail_name(group.display_name.into());
    ui.set_group_detail_role(if group.owner { "Owner" } else { "Participant" }.into());
    ui.set_group_detail_local_b32(group.local_b32.unwrap_or_default().into());
    ui.set_group_detail_roster(format!("Roster {}", group.roster_version).into());
    ui.set_group_history_enabled(group.history_enabled);
    ui.set_group_owner_ready(group.owner_ready);
    ui.set_group_leave_pending(group.leave_pending);
}

fn refresh_messages(ui: &AppWindow, mappings: &UiMappings) {
    let messages = row_value(&mappings.sessions, ui.get_selected_session())
        .flatten()
        .and_then(|session_id| mappings.conversations.borrow().get(&session_id).cloned())
        .unwrap_or_default()
        .iter()
        .map(message_item)
        .collect();
    ui.set_messages(message_model(messages));
    refresh_reply_draft(ui, mappings);
    refresh_session_logs(ui, mappings);
}

fn message_item(message: &PresentedMessage) -> MessageItem {
    let delivery = message_delivery_label(message);
    let (is_reply, reply_author, reply_quote, reply_body) =
        if let Some(reply) = parse_reply_text(&message.text) {
            (
                true,
                reply.author.to_string(),
                reply.quote.to_string(),
                reply.body.to_string(),
            )
        } else {
            (false, String::new(), String::new(), String::new())
        };
    let (original_action, original_status, original_progress, original_busy) =
        original_image_presentation(message);
    let file_presentation = message
        .file
        .as_ref()
        .map(|file| file_transfer_presentation(file, message.mine));
    MessageItem {
        text: display_reply_text(&message.text).into(),
        is_reply,
        reply_author: reply_author.into(),
        reply_quote: reply_quote.into(),
        reply_body: reply_body.into(),
        image: message.image.clone().unwrap_or_default(),
        image_detail: message.image_detail.clone().into(),
        image_width: message.image_width,
        image_height: message.image_height,
        bubble_width: message.bubble_width,
        is_image: message.image.is_some(),
        author: message.author.clone().into(),
        timestamp: message.timestamp_utc.clone().into(),
        delivery: delivery.into(),
        mine: message.mine,
        offline: message.offline,
        stored: message.stored,
        original_action: original_action.into(),
        original_status: original_status.into(),
        original_progress,
        original_busy,
        is_file: message.file.is_some(),
        file_total: file_presentation
            .as_ref()
            .map_or_else(String::new, |file| file.bytes.clone())
            .into(),
        file_progress: file_presentation.as_ref().map_or(0.0, |file| file.progress),
        file_status: file_presentation
            .as_ref()
            .map_or_else(String::new, |file| file.status.clone())
            .into(),
        file_path: file_presentation
            .as_ref()
            .map_or_else(String::new, |file| file.path.clone())
            .into(),
        file_can_accept: file_presentation
            .as_ref()
            .is_some_and(|file| file.can_accept),
        file_can_decline: file_presentation
            .as_ref()
            .is_some_and(|file| file.can_decline),
        file_can_cancel: file_presentation
            .as_ref()
            .is_some_and(|file| file.can_cancel),
    }
}

fn refresh_visible_file_progress_row(
    ui: &AppWindow,
    mappings: &UiMappings,
    session_id: SessionId,
    transfer_id: u64,
    direction: FileTransferDirection,
) -> bool {
    let selected_session = row_value(&mappings.sessions, ui.get_selected_session()).flatten();
    if selected_session != Some(session_id) {
        return true;
    }
    let message = {
        let conversations = mappings.conversations.borrow();
        let Some(messages) = conversations.get(&session_id) else {
            return false;
        };
        let Some(index) = file_transfer_message_index(messages, transfer_id, direction) else {
            return false;
        };
        (index, messages[index].clone())
    };
    let model = ui.get_messages();
    if message.0 >= model.row_count() {
        return false;
    }
    model.set_row_data(message.0, message_item(&message.1));
    true
}

fn file_transfer_message_index(
    messages: &[PresentedMessage],
    transfer_id: u64,
    direction: FileTransferDirection,
) -> Option<usize> {
    let mine = direction == FileTransferDirection::Sent;
    messages.iter().position(|message| {
        message.mine == mine
            && message
                .file
                .as_ref()
                .is_some_and(|file| file.transfer_id == transfer_id)
    })
}

fn refresh_reply_draft(ui: &AppWindow, mappings: &UiMappings) {
    let draft = row_value(&mappings.sessions, ui.get_selected_session())
        .flatten()
        .and_then(|session_id| mappings.reply_drafts.borrow().get(&session_id).cloned());
    if let Some(draft) = draft {
        ui.set_reply_author(draft.author.into());
        ui.set_reply_preview(compact_reply_preview(&draft.text, 96).into());
        ui.set_reply_visible(true);
    } else {
        ui.set_reply_visible(false);
        ui.set_reply_author("".into());
        ui.set_reply_preview("".into());
    }
}

fn message_delivery_label(message: &PresentedMessage) -> String {
    if message.file.is_some() || !message.mine {
        return String::new();
    }
    if message.delivery_expected > 0 {
        format!(
            "{}/{} delivered",
            message.delivery_received, message.delivery_expected
        )
    } else if message.delivered {
        "Delivered".into()
    } else if message.offline && message.relayed {
        "Relayed".into()
    } else {
        "Pending".into()
    }
}

fn record_sent_text(mappings: &UiMappings, sent: TextSendResult) {
    let delivery_expected = sent.expected_group_recipients.len();
    let stored = sent.history == HistoryWriteOutcome::Stored && sent.history_warning.is_none();
    let display_text = display_reply_text(&sent.text);
    let bubble_width = text_bubble_width(
        &display_text,
        "Me",
        &sent.timestamp_utc,
        sent.offline,
        stored,
        delivery_expected,
    );
    insert_presented_message(
        mappings,
        sent.session_id,
        PresentedMessage {
            message_id: Some(sent.message_id),
            text: sent.text,
            image: None,
            image_detail: String::new(),
            image_width: 0.0,
            image_height: 0.0,
            bubble_width,
            author: "Me".into(),
            timestamp_utc: sent.timestamp_utc,
            mine: true,
            offline: sent.offline,
            stored,
            delivered: false,
            relayed: false,
            delivery_received: 0,
            delivery_expected,
            original_size: 0,
            original_sender_b32: None,
            original_state: OriginalImagePresentationState::None,
            original_received: 0,
            file: None,
        },
    );
}

fn receive_text(mappings: &UiMappings, event: &TextReceivedEvent) {
    let author = received_text_author(mappings, event);
    let display_text = display_reply_text(&event.text);
    insert_presented_message(
        mappings,
        event.session_id,
        PresentedMessage {
            message_id: Some(event.message_id),
            text: event.text.clone(),
            image: None,
            image_detail: String::new(),
            image_width: 0.0,
            image_height: 0.0,
            bubble_width: text_bubble_width(
                &display_text,
                &author,
                &event.timestamp_utc,
                event.offline,
                event.history == HistoryWriteOutcome::Stored && event.history_warning.is_none(),
                0,
            ),
            author,
            timestamp_utc: event.timestamp_utc.clone(),
            mine: false,
            offline: event.offline,
            stored: event.history == HistoryWriteOutcome::Stored && event.history_warning.is_none(),
            delivered: false,
            relayed: false,
            delivery_received: 0,
            delivery_expected: 0,
            original_size: 0,
            original_sender_b32: None,
            original_state: OriginalImagePresentationState::None,
            original_received: 0,
            file: None,
        },
    );
}

fn image_send_command(session_id: SessionId, image: PreparedImage) -> CommToolsCommand {
    match (image.original_mime, image.original_bytes) {
        (Some(mime), Some(bytes)) => CommToolsCommand::SendImageWithOriginal {
            session_id,
            filename: image.filename,
            mime: image.mime,
            bytes: image.bytes,
            original: OriginalImageData { mime, bytes },
        },
        _ => CommToolsCommand::SendImage {
            session_id,
            filename: image.filename,
            mime: image.mime,
            bytes: image.bytes,
        },
    }
}

fn record_sent_image(mappings: &UiMappings, sent: ImageSendResult) -> Result<SessionId, String> {
    let session_id = sent.session_id;
    let preview = slint_image_from_bytes(&sent.bytes).map_err(|error| error.to_string())?;
    let (image_width, image_height) = image_display_size(preview.width, preview.height);
    let delivery_expected = sent.expected_group_recipients.len();
    let detail = image_detail(
        &sent.mime,
        sent.bytes.len(),
        sent.original.as_ref().map(|value| value.size),
    );
    let bubble_width = image_bubble_width(
        image_width,
        &sent.filename,
        &detail,
        &sent.timestamp_utc,
        true,
        delivery_expected,
    );
    insert_presented_message(
        mappings,
        session_id,
        PresentedMessage {
            message_id: Some(sent.message_id),
            text: sent.filename,
            image: Some(preview.image),
            image_detail: detail,
            image_width,
            image_height,
            bubble_width,
            author: "Me".into(),
            timestamp_utc: sent.timestamp_utc,
            mine: true,
            offline: false,
            stored: false,
            delivered: false,
            relayed: false,
            delivery_received: 0,
            delivery_expected,
            original_size: 0,
            original_sender_b32: None,
            original_state: OriginalImagePresentationState::None,
            original_received: 0,
            file: None,
        },
    );
    Ok(session_id)
}

fn receive_image(mappings: &UiMappings, event: ImageReceivedEvent) -> Result<(), String> {
    let preview = slint_image_from_bytes(&event.bytes).map_err(|error| error.to_string())?;
    let (image_width, image_height) = image_display_size(preview.width, preview.height);
    let author = received_author(mappings, event.session_id, event.sender_b32.as_deref());
    let detail = image_detail(
        &event.mime,
        event.bytes.len(),
        event.original.as_ref().map(|value| value.size),
    );
    let original_size = event.original.as_ref().map_or(0, |value| value.size);
    let original_state = if event.original.is_some() {
        OriginalImagePresentationState::Available
    } else {
        OriginalImagePresentationState::None
    };
    let bubble_width = image_bubble_width(
        image_width,
        &event.filename,
        &detail,
        &event.timestamp_utc,
        false,
        0,
    );
    insert_presented_message(
        mappings,
        event.session_id,
        PresentedMessage {
            message_id: Some(event.message_id),
            text: event.filename,
            image: Some(preview.image),
            image_detail: detail,
            image_width,
            image_height,
            bubble_width,
            author,
            timestamp_utc: event.timestamp_utc,
            mine: false,
            offline: false,
            stored: false,
            delivered: false,
            relayed: false,
            delivery_received: 0,
            delivery_expected: 0,
            original_size,
            original_sender_b32: event.sender_b32,
            original_state,
            original_received: 0,
            file: None,
        },
    );
    Ok(())
}

fn receive_image_delivery(mappings: &UiMappings, event: &ImageDeliveryEvent) {
    let mut conversations = mappings.conversations.borrow_mut();
    let Some(messages) = conversations.get_mut(&event.session_id) else {
        return;
    };
    if let Some(message) = messages
        .iter_mut()
        .find(|message| message.mine && message.message_id == Some(event.message_id))
    {
        message.delivered = event.expected > 0 && event.received >= event.expected;
        if event.group {
            message.delivery_received = event.received;
            message.delivery_expected = event.expected;
        }
    }
}

fn text_message_target(
    mappings: &UiMappings,
    session_index: i32,
    message_index: i32,
) -> Result<(SessionId, String, String), String> {
    let session_id = row_value(&mappings.sessions, session_index)
        .flatten()
        .ok_or_else(|| "Select a valid conversation".to_string())?;
    let message_index =
        usize::try_from(message_index).map_err(|_| "Select a valid text message".to_string())?;
    let conversations = mappings.conversations.borrow();
    let message = conversations
        .get(&session_id)
        .and_then(|messages| messages.get(message_index))
        .filter(|message| message.image.is_none() && message.file.is_none())
        .ok_or_else(|| "The selected text message is no longer available".to_string())?;
    Ok((session_id, message.author.clone(), message.text.clone()))
}

fn file_transfer_target(
    mappings: &UiMappings,
    session_index: i32,
    message_index: i32,
) -> Result<FileTransferTarget, String> {
    let session_id = row_value(&mappings.sessions, session_index)
        .flatten()
        .ok_or_else(|| "Select a valid live 1:1 session".to_string())?;
    let message_index =
        usize::try_from(message_index).map_err(|_| "Select a valid file transfer".to_string())?;
    let conversations = mappings.conversations.borrow();
    let file = conversations
        .get(&session_id)
        .and_then(|messages| messages.get(message_index))
        .and_then(|message| message.file.as_ref())
        .ok_or_else(|| "The selected file transfer is no longer available".to_string())?;
    Ok(FileTransferTarget {
        session_id,
        transfer_id: file.transfer_id,
        state: file.state,
    })
}

fn upsert_presented_file(
    mappings: &UiMappings,
    session_id: SessionId,
    direction: FileTransferDirection,
    file: PresentedFileTransfer,
) {
    let mine = direction == FileTransferDirection::Sent;
    let mut conversations = mappings.conversations.borrow_mut();
    let messages = conversations.entry(session_id).or_default();
    if let Some(message) = messages.iter_mut().find(|message| {
        message.mine == mine
            && message
                .file
                .as_ref()
                .is_some_and(|existing| existing.transfer_id == file.transfer_id)
    }) {
        message.text = file.filename.clone();
        message.file = Some(file);
        return;
    }
    messages.push(PresentedMessage {
        message_id: None,
        text: file.filename.clone(),
        image: None,
        image_detail: String::new(),
        image_width: 0.0,
        image_height: 0.0,
        bubble_width: 380.0,
        author: if mine {
            "Me".into()
        } else {
            received_author(mappings, session_id, None)
        },
        timestamp_utc: current_utc_hms(),
        mine,
        offline: false,
        stored: false,
        delivered: false,
        relayed: false,
        delivery_received: 0,
        delivery_expected: 0,
        original_size: 0,
        original_sender_b32: None,
        original_state: OriginalImagePresentationState::None,
        original_received: 0,
        file: Some(file),
    });
    trim_presented_messages(messages);
}

fn update_presented_file_event_state(
    mappings: &UiMappings,
    session_id: SessionId,
    transfer_id: u64,
    direction: FileTransferDirection,
    state: PresentedFileTransferState,
    failure: Option<String>,
) -> bool {
    let mine = direction == FileTransferDirection::Sent;
    let mut conversations = mappings.conversations.borrow_mut();
    let Some(file) = conversations.get_mut(&session_id).and_then(|messages| {
        messages.iter_mut().find_map(|message| {
            (message.mine == mine)
                .then_some(message.file.as_mut())
                .flatten()
                .filter(|file| file.transfer_id == transfer_id)
        })
    }) else {
        return false;
    };
    file.state = state;
    file.failure = failure;
    true
}

fn finish_presented_file(
    mappings: &UiMappings,
    session_id: SessionId,
    transfer_id: u64,
    direction: FileTransferDirection,
    filename: String,
    state: PresentedFileTransferState,
    failure: Option<String>,
) {
    if update_presented_file_event_state(
        mappings,
        session_id,
        transfer_id,
        direction,
        state,
        failure.clone(),
    ) {
        return;
    }
    upsert_presented_file(
        mappings,
        session_id,
        direction,
        PresentedFileTransfer {
            transfer_id,
            filename,
            total_bytes: 0,
            transferred_bytes: 0,
            state,
            saved_path: None,
            failure,
        },
    );
}

fn apply_file_transfer_event(mappings: &UiMappings, event: FileTransferEvent) -> String {
    match event {
        FileTransferEvent::Offered {
            session_id,
            transfer_id,
            direction,
            filename,
            total_bytes,
        } => {
            let incoming = direction == FileTransferDirection::Received;
            upsert_presented_file(
                mappings,
                session_id,
                direction,
                PresentedFileTransfer {
                    transfer_id,
                    filename: filename.clone(),
                    total_bytes,
                    transferred_bytes: 0,
                    state: if incoming {
                        PresentedFileTransferState::IncomingOffer
                    } else {
                        PresentedFileTransferState::AwaitingAcceptance
                    },
                    saved_path: None,
                    failure: None,
                },
            );
            if incoming {
                format!("Incoming file offer: {filename}")
            } else {
                format!("File offered: {filename}")
            }
        }
        FileTransferEvent::Started {
            session_id,
            transfer_id,
            direction,
            filename,
            total_bytes,
        } => {
            upsert_presented_file(
                mappings,
                session_id,
                direction,
                PresentedFileTransfer {
                    transfer_id,
                    filename: filename.clone(),
                    total_bytes,
                    transferred_bytes: 0,
                    state: PresentedFileTransferState::Active,
                    saved_path: None,
                    failure: None,
                },
            );
            format!("File transfer started: {filename}")
        }
        FileTransferEvent::Progress {
            session_id,
            transfer_id,
            direction,
            transferred_bytes,
            total_bytes,
        } => {
            let mine = direction == FileTransferDirection::Sent;
            let mut conversations = mappings.conversations.borrow_mut();
            if let Some(file) = conversations.get_mut(&session_id).and_then(|messages| {
                messages.iter_mut().find_map(|message| {
                    (message.mine == mine)
                        .then_some(message.file.as_mut())
                        .flatten()
                        .filter(|file| file.transfer_id == transfer_id)
                })
            }) {
                file.total_bytes = total_bytes;
                file.transferred_bytes = transferred_bytes.min(total_bytes);
                file.state = PresentedFileTransferState::Active;
            }
            "File transfer in progress".into()
        }
        FileTransferEvent::Completed {
            session_id,
            transfer_id,
            direction,
            filename,
            total_bytes,
            path,
        } => {
            upsert_presented_file(
                mappings,
                session_id,
                direction,
                PresentedFileTransfer {
                    transfer_id,
                    filename: filename.clone(),
                    total_bytes,
                    transferred_bytes: total_bytes,
                    state: PresentedFileTransferState::Completed,
                    saved_path: path.map(|path| path.display().to_string()),
                    failure: None,
                },
            );
            format!("File transfer completed: {filename}")
        }
        FileTransferEvent::Declined {
            session_id,
            transfer_id,
            direction,
            filename,
        } => {
            finish_presented_file(
                mappings,
                session_id,
                transfer_id,
                direction,
                filename.clone(),
                PresentedFileTransferState::Declined,
                None,
            );
            format!("File transfer declined: {filename}")
        }
        FileTransferEvent::Cancelled {
            session_id,
            transfer_id,
            direction,
            filename,
        } => {
            finish_presented_file(
                mappings,
                session_id,
                transfer_id,
                direction,
                filename.clone(),
                PresentedFileTransferState::Cancelled,
                None,
            );
            format!("File transfer cancelled: {filename}")
        }
        FileTransferEvent::Expired {
            session_id,
            transfer_id,
            direction,
            filename,
        } => {
            finish_presented_file(
                mappings,
                session_id,
                transfer_id,
                direction,
                filename.clone(),
                PresentedFileTransferState::Expired,
                None,
            );
            format!("File transfer expired: {filename}")
        }
        FileTransferEvent::Failed {
            session_id,
            transfer_id,
            direction,
            filename,
            reason,
        } => {
            let filename = filename.unwrap_or_else(|| "file.bin".into());
            finish_presented_file(
                mappings,
                session_id,
                transfer_id,
                direction,
                filename.clone(),
                PresentedFileTransferState::Failed,
                Some(reason.clone()),
            );
            format!("File transfer failed for {filename}: {reason}")
        }
        _ => "File transfer updated".into(),
    }
}

fn current_utc_hms() -> String {
    let epoch_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;
    format_epoch_millis_utc(epoch_millis)
}

#[derive(Debug, Clone, Copy)]
struct ParsedReply<'a> {
    author: &'a str,
    quote: &'a str,
    body: &'a str,
}

fn parse_reply_text(value: &str) -> Option<ParsedReply<'_>> {
    let rest = value.strip_prefix(REPLY_BEGIN_MARKER)?.strip_prefix('\n')?;
    let (author, rest) = rest.split_once('\n')?;
    let rest = rest.strip_prefix(REPLY_QUOTE_MARKER)?.strip_prefix('\n')?;
    let end_marker = format!("\n{REPLY_END_MARKER}\n");
    let (quote, body) = rest.split_once(end_marker.as_str())?;
    Some(ParsedReply {
        author,
        quote,
        body,
    })
}

fn compose_reply_text(reply: Option<&ReplyDraft>, text: &str) -> String {
    let Some(reply) = reply else {
        return text.to_string();
    };
    format!(
        "{REPLY_BEGIN_MARKER}\n{}\n{REPLY_QUOTE_MARKER}\n{}\n{REPLY_END_MARKER}\n{text}",
        reply.author, reply.text
    )
}

fn display_reply_text(value: &str) -> String {
    parse_reply_text(value).map_or_else(
        || value.to_string(),
        |reply| {
            format!(
                "Reply to {}:\n{}\n\n{}",
                reply.author, reply.quote, reply.body
            )
        },
    )
}

fn reply_source_text(value: &str) -> &str {
    parse_reply_text(value).map_or(value, |reply| reply.body)
}

fn compact_reply_preview(value: &str, maximum_chars: usize) -> String {
    let flattened = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if flattened.chars().count() <= maximum_chars {
        return flattened;
    }
    let mut preview = flattened.chars().take(maximum_chars).collect::<String>();
    preview.push_str("...");
    preview
}

fn original_image_target(
    mappings: &UiMappings,
    session_index: i32,
    message_index: i32,
) -> Result<OriginalImageTarget, String> {
    let session_id = row_value(&mappings.sessions, session_index)
        .flatten()
        .ok_or_else(|| "Select a valid live chat session".to_string())?;
    let message_index =
        usize::try_from(message_index).map_err(|_| "Select a valid image message".to_string())?;
    let conversations = mappings.conversations.borrow();
    let message = conversations
        .get(&session_id)
        .and_then(|messages| messages.get(message_index))
        .ok_or_else(|| "The selected image message is no longer available".to_string())?;
    if message.mine
        || message.image.is_none()
        || message.original_size == 0
        || message.original_state == OriginalImagePresentationState::None
    {
        return Err("The selected message has no downloadable original image".into());
    }
    let media_id = message
        .message_id
        .ok_or_else(|| "The selected image has no media identifier".to_string())?;
    Ok(OriginalImageTarget {
        session_id,
        media_id,
        sender_b32: message.original_sender_b32.clone(),
    })
}

fn original_image_state(
    mappings: &UiMappings,
    target: &OriginalImageTarget,
) -> Option<OriginalImagePresentationState> {
    mappings
        .conversations
        .borrow()
        .get(&target.session_id)?
        .iter()
        .find(|message| original_image_matches(message, target))
        .map(|message| message.original_state)
}

fn original_image_download_active(mappings: &UiMappings, target: &OriginalImageTarget) -> bool {
    matches!(
        original_image_state(mappings, target),
        Some(
            OriginalImagePresentationState::Requesting | OriginalImagePresentationState::Receiving
        )
    )
}

fn original_image_matches(message: &PresentedMessage, target: &OriginalImageTarget) -> bool {
    !message.mine
        && message.message_id == Some(target.media_id)
        && optional_b32_matches(
            message.original_sender_b32.as_deref(),
            target.sender_b32.as_deref(),
        )
}

fn optional_b32_matches(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        (None, None) => true,
        _ => false,
    }
}

fn set_original_image_state(
    mappings: &UiMappings,
    target: &OriginalImageTarget,
    state: OriginalImagePresentationState,
    received: u64,
) -> bool {
    let mut conversations = mappings.conversations.borrow_mut();
    let Some(message) = conversations
        .get_mut(&target.session_id)
        .and_then(|messages| {
            messages
                .iter_mut()
                .find(|message| original_image_matches(message, target))
        })
    else {
        return false;
    };
    message.original_state = state;
    message.original_received = received.min(message.original_size);
    true
}

fn present_original_image(
    ui: &AppWindow,
    mappings: &UiMappings,
    event: OriginalImageReceivedEvent,
) -> Result<(), String> {
    let target = OriginalImageTarget {
        session_id: event.session_id,
        media_id: event.media_id,
        sender_b32: event.sender_b32.clone(),
    };
    let decoded = match slint_image_from_bytes(&event.bytes) {
        Ok(decoded) => decoded,
        Err(error) => {
            set_original_image_state(mappings, &target, OriginalImagePresentationState::Failed, 0);
            return Err(error.to_string());
        }
    };
    if !set_original_image_state(
        mappings,
        &target,
        OriginalImagePresentationState::Cached,
        event.bytes.len() as u64,
    ) {
        return Err("the matching image preview is no longer available".into());
    }
    let detail = format!(
        "{} | {} | {}x{}",
        event.mime,
        format_bytes(event.bytes.len() as u64),
        decoded.width,
        decoded.height
    );
    *mappings.original_viewer.borrow_mut() = Some(PresentedOriginalImage {
        source_session_id: event.session_id,
        filename: event.filename.clone(),
        bytes: event.bytes,
    });
    ui.set_original_viewer_image(decoded.image);
    ui.set_original_viewer_filename(event.filename.into());
    ui.set_original_viewer_detail(detail.into());
    ui.set_original_viewer_status("Loaded in memory".into());
    ui.set_original_viewer_visible(true);
    Ok(())
}

fn clear_original_image_viewer(ui: &AppWindow, mappings: &UiMappings) {
    mappings.original_viewer.borrow_mut().take();
    ui.set_original_viewer_visible(false);
    ui.set_original_viewer_image(slint::Image::default());
    ui.set_original_viewer_filename("".into());
    ui.set_original_viewer_detail("".into());
    ui.set_original_viewer_status("".into());
}

fn fail_pending_original_command(mappings: &UiMappings) {
    let Some(pending) = mappings.pending_original_command.borrow_mut().take() else {
        return;
    };
    let state = match pending.kind {
        PendingOriginalImageCommandKind::Request => OriginalImagePresentationState::Failed,
        PendingOriginalImageCommandKind::Cancel => OriginalImagePresentationState::Available,
    };
    set_original_image_state(mappings, &pending.target, state, 0);
}

fn save_original_image(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("Image save failed for {}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.flush())
        .map_err(|error| format!("Image save failed for {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("Could not secure {}: {error}", path.display()))?;
    }
    Ok(())
}

fn mark_offline_message_relayed(mappings: &UiMappings, session_id: SessionId, message_id: u64) {
    let mut conversations = mappings.conversations.borrow_mut();
    let Some(messages) = conversations.get_mut(&session_id) else {
        return;
    };
    if let Some(message) = messages
        .iter_mut()
        .find(|message| message.mine && message.offline && message.message_id == Some(message_id))
    {
        message.relayed = true;
    }
}

fn image_detail(mime: &str, preview_bytes: usize, original_bytes: Option<u64>) -> String {
    match original_bytes {
        Some(original_bytes) => format!(
            "{mime} | preview {} | original {}",
            format_bytes(preview_bytes as u64),
            format_bytes(original_bytes)
        ),
        None => format!("{mime} | preview {}", format_bytes(preview_bytes as u64)),
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MiB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1_024 {
        format!("{:.1} KiB", bytes as f64 / 1_024.0)
    } else {
        format!("{bytes} B")
    }
}

fn original_image_presentation(message: &PresentedMessage) -> (String, String, f32, bool) {
    match message.original_state {
        OriginalImagePresentationState::None => (String::new(), String::new(), 0.0, false),
        OriginalImagePresentationState::Available => {
            ("Request Original".into(), String::new(), 0.0, false)
        }
        OriginalImagePresentationState::Requesting => {
            (String::new(), "Requesting original".into(), 0.0, true)
        }
        OriginalImagePresentationState::Receiving => {
            let received = message.original_received.min(message.original_size);
            let progress = if message.original_size == 0 {
                0.0
            } else {
                received as f32 / message.original_size as f32
            };
            (
                String::new(),
                format!(
                    "{} / {}",
                    format_bytes(received),
                    format_bytes(message.original_size)
                ),
                progress,
                true,
            )
        }
        OriginalImagePresentationState::Cached => (
            "Open Original".into(),
            "Cached in memory".into(),
            1.0,
            false,
        ),
        OriginalImagePresentationState::Unavailable => {
            (String::new(), "Original unavailable".into(), 0.0, false)
        }
        OriginalImagePresentationState::Failed => (
            "Retry Original".into(),
            "Download failed".into(),
            0.0,
            false,
        ),
    }
}

fn file_transfer_presentation(
    file: &PresentedFileTransfer,
    mine: bool,
) -> FileTransferPresentation {
    let transferred = file.transferred_bytes.min(file.total_bytes);
    let progress = if file.total_bytes == 0 {
        0.0
    } else {
        transferred as f32 / file.total_bytes as f32
    };
    let status = match file.state {
        PresentedFileTransferState::IncomingOffer => "Awaiting your decision".into(),
        PresentedFileTransferState::AwaitingAcceptance => "Waiting for peer".into(),
        PresentedFileTransferState::Active => "Transferring".into(),
        PresentedFileTransferState::Completed => if mine { "Sent" } else { "Received" }.into(),
        PresentedFileTransferState::Declined => "Declined".into(),
        PresentedFileTransferState::Cancelled => "Cancelled".into(),
        PresentedFileTransferState::Expired => "Expired".into(),
        PresentedFileTransferState::Failed => file
            .failure
            .as_deref()
            .map_or_else(|| "Failed".into(), |reason| format!("Failed: {reason}")),
    };
    FileTransferPresentation {
        bytes: format!(
            "{} / {}",
            format_bytes(transferred),
            format_bytes(file.total_bytes)
        ),
        progress,
        status,
        path: file.saved_path.clone().unwrap_or_default(),
        can_accept: file.state == PresentedFileTransferState::IncomingOffer,
        can_decline: file.state == PresentedFileTransferState::IncomingOffer,
        can_cancel: matches!(
            file.state,
            PresentedFileTransferState::AwaitingAcceptance | PresentedFileTransferState::Active
        ),
    }
}

fn image_display_size(width: u32, height: u32) -> (f32, f32) {
    let source_width = width.max(1) as f32;
    let source_height = height.max(1) as f32;
    let scale = (IMAGE_BUBBLE_MAX_WIDTH / source_width)
        .min(IMAGE_BUBBLE_MAX_HEIGHT / source_height)
        .min(1.0);
    (source_width * scale, source_height * scale)
}

fn image_bubble_width(
    image_width: f32,
    filename: &str,
    detail: &str,
    timestamp: &str,
    mine: bool,
    expected_deliveries: usize,
) -> f32 {
    let filename_width = filename.chars().count() as f32 * 7.0 + 4.0;
    let detail_width = detail.chars().count() as f32 * 6.0 + 4.0;
    let delivery = if mine {
        if expected_deliveries > 0 {
            format!("  0/{expected_deliveries} delivered")
        } else {
            "  Pending".into()
        }
    } else {
        String::new()
    };
    let footer_width = (timestamp.chars().count() + delivery.chars().count()) as f32 * 6.0 + 4.0;
    (image_width
        .max(filename_width)
        .max(detail_width)
        .max(footer_width)
        + BUBBLE_HORIZONTAL_PADDING)
        .clamp(
            IMAGE_BUBBLE_MIN_WIDTH,
            IMAGE_BUBBLE_MAX_WIDTH + BUBBLE_HORIZONTAL_PADDING,
        )
}

fn text_bubble_width(
    text: &str,
    author: &str,
    timestamp: &str,
    offline: bool,
    stored: bool,
    expected_deliveries: usize,
) -> f32 {
    let longest_text_width = text
        .lines()
        .map(|line| line.chars().count() as f32 * 8.0 + 4.0)
        .fold(0.0_f32, f32::max);
    let author_width = author.chars().count() as f32 * 7.0 + 4.0;
    let footer = format!(
        "{timestamp}{}{}",
        if offline { "  OFFLINE" } else { "" },
        if expected_deliveries > 0 {
            format!("  0/{expected_deliveries} delivered")
        } else {
            "  Pending".into()
        }
    );
    let history_indicator_width = if stored { 22.0 } else { 0.0 };
    let footer_width =
        56.0 + history_indicator_width + footer.chars().count() as f32 * 6.0 + 4.0;
    let body_width = longest_text_width
        .max(author_width)
        .max(footer_width)
        .clamp(
            TEXT_BUBBLE_MIN_BODY_WIDTH,
            TEXT_BUBBLE_MAX_WIDTH - BUBBLE_HORIZONTAL_PADDING,
        );
    body_width + BUBBLE_HORIZONTAL_PADDING
}

fn receive_delivery(mappings: &UiMappings, event: &TextDeliveryEvent) {
    let mut conversations = mappings.conversations.borrow_mut();
    let Some(messages) = conversations.get_mut(&event.session_id) else {
        return;
    };
    if let Some(message) = messages
        .iter_mut()
        .find(|message| message.mine && message.message_id == Some(event.message_id))
    {
        message.delivered = event.expected > 0 && event.received >= event.expected;
        if event.group {
            message.delivery_received = event.received;
            message.delivery_expected = event.expected;
        }
    }
}

fn received_text_author(mappings: &UiMappings, event: &TextReceivedEvent) -> String {
    received_author(mappings, event.session_id, event.sender_b32.as_deref())
}

fn received_author(
    mappings: &UiMappings,
    session_id: SessionId,
    sender_b32: Option<&str>,
) -> String {
    let Some(sender_b32) = sender_b32 else {
        return "Peer".into();
    };
    let group_id = mappings
        .session_keys
        .borrow()
        .get(&session_id)
        .and_then(|key| match key {
            ManagedSessionKey::Group(group_id) => Some(group_id.clone()),
            _ => None,
        });
    let member_name = group_id.and_then(|group_id| {
        mappings
            .latest_snapshot
            .borrow()
            .as_ref()
            .and_then(|snapshot| snapshot.groups.iter().find(|group| group.id == group_id))
            .and_then(|group| {
                group
                    .members
                    .iter()
                    .find(|member| member.b32.eq_ignore_ascii_case(sender_b32))
            })
            .map(|member| member.name.clone())
    });
    member_name.unwrap_or_else(|| format!("Peer {}", abbreviated_b32(sender_b32)))
}

fn abbreviated_b32(address: &str) -> String {
    const PREFIX_CHARS: usize = 10;
    if address.chars().count() <= PREFIX_CHARS {
        address.to_string()
    } else {
        format!(
            "{}...",
            address.chars().take(PREFIX_CHARS).collect::<String>()
        )
    }
}

fn compact_b32_address(address: &str) -> String {
    const EDGE_CHARS: usize = 6;
    let address = address.trim_end_matches(".b32.i2p");
    if address.is_empty() {
        return "----".into();
    }
    let characters = address.chars().collect::<Vec<_>>();
    if characters.len() <= EDGE_CHARS * 2 {
        return address.to_string();
    }
    let prefix = characters
        .iter()
        .take(EDGE_CHARS)
        .copied()
        .collect::<String>();
    let suffix = characters
        .iter()
        .skip(characters.len() - EDGE_CHARS)
        .copied()
        .collect::<String>();
    format!("{prefix}...{suffix}")
}

fn merge_history(mappings: &UiMappings, key: &ManagedSessionKey, records: Vec<HistoryRecord>) {
    let session_ids = mappings
        .session_keys
        .borrow()
        .iter()
        .filter_map(|(session_id, session_key)| (session_key == key).then_some(*session_id))
        .collect::<Vec<_>>();

    for session_id in session_ids {
        let mut merged = records
            .iter()
            .cloned()
            .map(PresentedMessage::from)
            .collect::<Vec<_>>();
        if let Some(current) = mappings.conversations.borrow_mut().remove(&session_id) {
            for message in current {
                upsert_presented_message(&mut merged, message);
            }
        }
        trim_presented_messages(&mut merged);
        mappings
            .conversations
            .borrow_mut()
            .insert(session_id, merged);
    }
}

fn insert_presented_message(
    mappings: &UiMappings,
    session_id: SessionId,
    message: PresentedMessage,
) {
    let mut conversations = mappings.conversations.borrow_mut();
    let messages = conversations.entry(session_id).or_default();
    upsert_presented_message(messages, message);
    trim_presented_messages(messages);
}

fn upsert_presented_message(messages: &mut Vec<PresentedMessage>, mut message: PresentedMessage) {
    let existing_index = if let Some(message_id) = message.message_id {
        messages.iter().position(|candidate| {
            candidate.mine == message.mine
                && candidate.message_id == Some(message_id)
                && candidate.image.is_some() == message.image.is_some()
                && (message.original_sender_b32.is_none()
                    || optional_b32_matches(
                        candidate.original_sender_b32.as_deref(),
                        message.original_sender_b32.as_deref(),
                    ))
        })
    } else {
        messages.iter().position(|candidate| {
            candidate.message_id.is_none()
                && candidate.mine == message.mine
                && candidate.timestamp_utc == message.timestamp_utc
                && candidate.text == message.text
        })
    };
    if let Some(existing_index) = existing_index {
        let existing = &mut messages[existing_index];
        message.delivered |= existing.delivered;
        message.relayed |= existing.relayed;
        message.stored |= existing.stored;
        message.delivery_received = message.delivery_received.max(existing.delivery_received);
        message.delivery_expected = message.delivery_expected.max(existing.delivery_expected);
        if existing.original_state != OriginalImagePresentationState::None
            && message.original_state != OriginalImagePresentationState::None
        {
            message.original_state = existing.original_state;
            message.original_received = existing.original_received;
        }
        *existing = message;
    } else {
        messages.push(message);
    }
}

fn trim_presented_messages(messages: &mut Vec<PresentedMessage>) {
    let excess = messages.len().saturating_sub(MAX_PRESENTED_TEXT_MESSAGES);
    if excess > 0 {
        messages.drain(..excess);
    }
}

impl From<HistoryRecord> for PresentedMessage {
    fn from(record: HistoryRecord) -> Self {
        let display_text = display_reply_text(&record.text);
        let bubble_width = text_bubble_width(
            &display_text,
            if record.mine { "Me" } else { &record.author },
            &record.timestamp_utc,
            record.offline,
            true,
            record.group_expected_acks.len(),
        );
        Self {
            message_id: record.msg_id,
            text: record.text,
            image: None,
            image_detail: String::new(),
            image_width: 0.0,
            image_height: 0.0,
            bubble_width,
            author: if record.mine {
                "Me".into()
            } else {
                record.author
            },
            timestamp_utc: record.timestamp_utc,
            mine: record.mine,
            offline: record.offline,
            stored: true,
            delivered: record.delivered,
            relayed: false,
            delivery_received: record.group_received_acks.len(),
            delivery_expected: record.group_expected_acks.len(),
            original_size: 0,
            original_sender_b32: None,
            original_state: OriginalImagePresentationState::None,
            original_received: 0,
            file: None,
        }
    }
}

fn one_to_one_state(phase: OneToOnePhase) -> &'static str {
    match phase {
        OneToOnePhase::Standby => "Standby",
        OneToOnePhase::Connecting => "Connecting",
        OneToOnePhase::IncomingPending => "Incoming",
        OneToOnePhase::Handshaking => "Securing",
        OneToOnePhase::Ready => "Connected",
        OneToOnePhase::Closing => "Disconnecting",
        OneToOnePhase::Closed => "Closed",
    }
}

fn one_to_one_detail(phase: OneToOnePhase) -> String {
    match phase {
        OneToOnePhase::Standby => "Online standby",
        OneToOnePhase::Connecting => "Waiting for peer reachability",
        OneToOnePhase::IncomingPending => "Incoming call awaiting a decision",
        OneToOnePhase::Handshaking => "Establishing the secure session",
        OneToOnePhase::Ready => "Secure session ready",
        OneToOnePhase::Closing => "Closing peer connection",
        OneToOnePhase::Closed => "Session closed",
    }
    .into()
}

fn count_label(count: usize, singular: &str, plural: &str) -> SharedString {
    match count {
        0 => format!("No {plural}"),
        1 => format!("1 {singular}"),
        count => format!("{count} {plural}"),
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn presented_message(message_id: u64, mine: bool) -> PresentedMessage {
        PresentedMessage {
            message_id: Some(message_id),
            text: "test".into(),
            image: None,
            image_detail: String::new(),
            image_width: 0.0,
            image_height: 0.0,
            bubble_width: 180.0,
            author: if mine { "Me" } else { "Peer" }.into(),
            timestamp_utc: "01:02:03 UTC".into(),
            mine,
            offline: false,
            stored: false,
            delivered: false,
            relayed: false,
            delivery_received: 0,
            delivery_expected: 0,
            original_size: 0,
            original_sender_b32: None,
            original_state: OriginalImagePresentationState::None,
            original_received: 0,
            file: None,
        }
    }

    fn presented_file_message(transfer_id: u64, mine: bool) -> PresentedMessage {
        let mut message = presented_message(transfer_id, mine);
        message.file = Some(PresentedFileTransfer {
            transfer_id,
            filename: "payload.bin".into(),
            total_bytes: 4_096,
            transferred_bytes: 2_048,
            state: PresentedFileTransferState::Active,
            saved_path: None,
            failure: None,
        });
        message
    }

    #[test]
    fn reply_text_uses_the_established_wire_markers_and_readable_display() {
        let draft = ReplyDraft {
            author: "Peer".into(),
            text: "original text".into(),
        };
        let encoded = compose_reply_text(Some(&draft), "response text");

        assert_eq!(
            encoded,
            "[COMMTOOLS-I2P-REPLY-v1]\nPeer\n[COMMTOOLS-I2P-QUOTE]\noriginal text\n[/COMMTOOLS-I2P-REPLY]\nresponse text"
        );
        assert_eq!(
            display_reply_text(&encoded),
            "Reply to Peer:\noriginal text\n\nresponse text"
        );
        assert_eq!(reply_source_text(&encoded), "response text");
    }

    #[test]
    fn malformed_reply_markers_remain_plain_text() {
        let text = "[COMMTOOLS-I2P-REPLY-v1]\nincomplete";

        assert_eq!(display_reply_text(text), text);
        assert_eq!(reply_source_text(text), text);
    }

    #[test]
    fn cancelled_original_rejects_stale_progress_and_completion_events() {
        let mappings = UiMappings::default();
        let session_id = SessionId::new(31);
        let mut message = presented_message(77, false);
        message.original_size = 4_096;
        message.original_state = OriginalImagePresentationState::Requesting;
        mappings
            .conversations
            .borrow_mut()
            .insert(session_id, vec![message]);
        let target = OriginalImageTarget {
            session_id,
            media_id: 77,
            sender_b32: None,
        };

        assert!(original_image_download_active(&mappings, &target));
        set_original_image_state(
            &mappings,
            &target,
            OriginalImagePresentationState::Available,
            0,
        );
        assert!(!original_image_download_active(&mappings, &target));
    }

    #[test]
    fn reply_preview_is_flattened_and_bounded() {
        assert_eq!(compact_reply_preview("one\ntwo  three", 32), "one two three");
        assert_eq!(compact_reply_preview("abcdefgh", 5), "abcde...");
    }

    #[test]
    fn row_index_finds_only_existing_catalog_entries() {
        let values = RefCell::new(vec!["first", "second", "third"]);

        assert_eq!(row_index(&values, &"second"), Some(1));
        assert_eq!(row_index(&values, &"missing"), None);
    }

    #[test]
    fn file_progress_row_is_scoped_by_transfer_direction_and_identifier() {
        let messages = vec![
            presented_file_message(17, true),
            presented_message(18, false),
            presented_file_message(17, false),
        ];

        assert_eq!(
            file_transfer_message_index(&messages, 17, FileTransferDirection::Sent),
            Some(0)
        );
        assert_eq!(
            file_transfer_message_index(&messages, 17, FileTransferDirection::Received),
            Some(2)
        );
        assert_eq!(
            file_transfer_message_index(&messages, 99, FileTransferDirection::Sent),
            None
        );
    }

    #[test]
    fn persistent_contact_commands_reject_transient_catalog_rows() {
        let mappings = UiMappings::default();
        let contact_id = ContactId::new("persistent-row").expect("contact identifier");
        let transient_id = TransientId::new("transient-row").expect("transient identifier");
        *mappings.contact_catalog.borrow_mut() = vec![
            ContactCatalogEntry::Persistent(contact_id.clone()),
            ContactCatalogEntry::Transient(transient_id),
        ];

        assert_eq!(persistent_contact_id(&mappings, 0), Some(contact_id));
        assert_eq!(persistent_contact_id(&mappings, 1), None);
        assert_eq!(persistent_contact_id(&mappings, 2), None);
    }

    #[test]
    fn contact_summary_distinguishes_ephemeral_entries() {
        assert_eq!(contact_catalog_summary(2, 0), "2 contacts");
        assert_eq!(contact_catalog_summary(1, 1), "1 contact, 1 transient");
        assert_eq!(contact_catalog_summary(0, 2), "No contacts, 2 transients");
    }

    #[test]
    fn failed_transient_open_clears_only_its_pending_selection() {
        let mappings = UiMappings::default();
        let first = TransientId::new("first-transient").expect("transient identifier");
        let second = TransientId::new("second-transient").expect("transient identifier");
        *mappings.pending_contact_selection.borrow_mut() =
            Some(ContactCatalogEntry::Transient(first.clone()));

        clear_pending_transient_selection(&mappings, &second);
        assert_eq!(
            mappings.pending_contact_selection.borrow().as_ref(),
            Some(&ContactCatalogEntry::Transient(first.clone()))
        );
        clear_pending_transient_selection(&mappings, &first);
        assert!(mappings.pending_contact_selection.borrow().is_none());
    }

    #[test]
    fn session_logs_are_bounded_and_scoped() {
        let mappings = UiMappings::default();
        let first = SessionId::new(11);
        let second = SessionId::new(12);
        for index in 0..=MAX_SESSION_LOG_LINES {
            append_session_log(
                &mappings,
                first,
                "TEST",
                SessionLogLevel::Info,
                format!("event {index}"),
            );
        }
        append_session_log(
            &mappings,
            second,
            "TEST",
            SessionLogLevel::Warning,
            "second session",
        );

        let logs = mappings.session_logs.borrow();
        assert_eq!(
            logs[&first].len(),
            MAX_SESSION_LOG_LINES - SESSION_LOG_TRIM_BATCH + 1
        );
        assert_eq!(logs[&first].front().unwrap().message.as_str(), "event 100");
        assert_eq!(logs[&second].len(), 1);
        drop(logs);
        assert!(!joined_session_log(&mappings, first).contains("second session"));
    }

    #[test]
    fn session_logs_sanitize_addresses_and_never_record_text_payloads() {
        let full_b32 = format!("{}.b32.i2p", "a".repeat(52));
        let sanitized = sanitize_log_message(&format!("peer {full_b32}\nconnected"));
        assert!(!sanitized.contains(&full_b32));
        assert!(sanitized.contains("aaaaaa...aaaaaa"));
        assert!(!sanitized.contains('\n'));

        let mappings = UiMappings::default();
        let session_id = SessionId::new(13);
        record_frontend_event_log(
            &mappings,
            &FrontendEvent::TextReceived(TextReceivedEvent {
                session_id,
                message_id: 1,
                text: "SECRET MESSAGE CONTENT".into(),
                timestamp_utc: "01:02:03 UTC".into(),
                sender_b32: Some(full_b32),
                offline: false,
                offline_index: None,
                history: HistoryWriteOutcome::Disabled,
                history_warning: None,
                warning: None,
            }),
        );
        let copied = joined_session_log(&mappings, session_id);
        assert!(copied.contains("Text message received."));
        assert!(!copied.contains("SECRET MESSAGE CONTENT"));
    }

    #[test]
    fn details_are_available_only_for_persistent_sessions() {
        let contact = ManagedSessionKey::Contact(
            ContactId::new("contact-details").expect("contact identifier"),
        );
        let group =
            ManagedSessionKey::Group(GroupId::new("group-details").expect("group identifier"));
        let transient = ManagedSessionKey::Transient(
            TransientId::new("transient-details").expect("transient identifier"),
        );

        assert!(session_has_details(&contact));
        assert!(session_has_details(&group));
        assert!(!session_has_details(&transient));
    }

    #[test]
    fn transient_sessions_receive_only_live_one_to_one_capabilities() {
        let transient = ManagedSessionKey::Transient(
            TransientId::new("transient-capabilities").expect("transient identifier"),
        );
        let contact = ManagedSessionKey::Contact(
            ContactId::new("contact-capabilities").expect("contact identifier"),
        );
        let group =
            ManagedSessionKey::Group(GroupId::new("group-capabilities").expect("group identifier"));

        assert!(is_one_to_one_key(&transient));
        assert!(is_one_to_one_key(&contact));
        assert!(!is_one_to_one_key(&group));
        assert!(rendezvous_available_for(
            &transient,
            ManagedSessionPhase::Open,
            Some(OneToOnePhase::Standby),
            None,
            false,
        ));
        assert!(!rendezvous_available_for(
            &transient,
            ManagedSessionPhase::Open,
            Some(OneToOnePhase::Ready),
            None,
            false,
        ));
        assert!(!rendezvous_available_for(
            &transient,
            ManagedSessionPhase::Open,
            Some(OneToOnePhase::Standby),
            Some(OfflineCoordinatorMode::Offline),
            false,
        ));
        assert!(!rendezvous_available_for(
            &contact,
            ManagedSessionPhase::Open,
            Some(OneToOnePhase::Standby),
            None,
            true,
        ));
    }

    #[test]
    fn rendezvous_inputs_are_trimmed_and_bounded() {
        assert_eq!(
            validated_rendezvous_input("  request  "),
            Some("request".into())
        );
        assert_eq!(validated_rendezvous_input("   "), None);
        assert_eq!(
            validated_rendezvous_input(&"x".repeat(MAX_RENDEZVOUS_INPUT_BYTES + 1)),
            None
        );
    }

    #[test]
    fn rendezvous_results_are_bound_to_the_pending_session_and_operation() {
        let mappings = UiMappings::default();
        let session_id = SessionId::new(91);
        *mappings.pending_rendezvous_command.borrow_mut() = Some(PendingRendezvousCommand {
            session_id,
            kind: PendingRendezvousCommandKind::AnswerRequest,
        });

        assert_eq!(
            take_pending_rendezvous_command(
                &mappings,
                PendingRendezvousCommandKind::GenerateRequest
            ),
            None
        );
        assert!(mappings.pending_rendezvous_command.borrow().is_none());
    }

    #[test]
    fn consumed_rendezvous_state_is_cleared_only_for_its_session() {
        let mappings = UiMappings::default();
        let first = SessionId::new(92);
        let second = SessionId::new(93);
        for session_id in [first, second] {
            mappings.rendezvous_outputs.borrow_mut().insert(
                session_id,
                RendezvousOutputPresentation {
                    label: "Request".into(),
                    value: Zeroizing::new("material".into()),
                },
            );
        }

        update_rendezvous_authentication(
            &mappings,
            &RendezvousSessionEvent::OutgoingAuthenticated {
                session_id: first,
                peer_b32: "peer.b32.i2p".into(),
            },
        );

        assert!(mappings.rendezvous_authenticated.borrow().contains(&first));
        assert!(!mappings.rendezvous_outputs.borrow().contains_key(&first));
        assert!(mappings.rendezvous_outputs.borrow().contains_key(&second));
    }

    #[test]
    fn transient_labels_are_local_bounded_tab_titles() {
        let transient_id = TransientId::new("transient-label").expect("transient identifier");
        let label = normalize_transient_label(&format!("  Desk session\n{}  ", "x".repeat(80)));
        let mut labels = BTreeMap::new();
        labels.insert(transient_id.clone(), label.clone());

        assert!(!label.contains('\n'));
        assert_eq!(label.chars().count(), MAX_TRANSIENT_LABEL_CHARS);
        assert_eq!(
            session_title(
                &ManagedSessionKey::Transient(transient_id.clone()),
                &BTreeMap::new(),
                &BTreeMap::new(),
                &labels,
            ),
            label
        );
        assert_eq!(
            transient_title(&transient_id, None),
            format!("Transient {transient_id}")
        );
    }

    #[test]
    fn original_image_progress_is_scoped_by_session_media_and_sender() {
        let mappings = UiMappings::default();
        let session_id = SessionId::new(41);
        let mut first = presented_message(7, false);
        first.original_size = 200;
        first.original_sender_b32 = Some("FIRST.b32.i2p".into());
        first.original_state = OriginalImagePresentationState::Available;
        let mut second = presented_message(7, false);
        second.original_size = 200;
        second.original_sender_b32 = Some("second.b32.i2p".into());
        second.original_state = OriginalImagePresentationState::Available;
        mappings
            .conversations
            .borrow_mut()
            .insert(session_id, vec![first, second]);

        let target = OriginalImageTarget {
            session_id,
            media_id: 7,
            sender_b32: Some("first.b32.i2p".into()),
        };
        assert!(set_original_image_state(
            &mappings,
            &target,
            OriginalImagePresentationState::Receiving,
            50,
        ));

        let conversations = mappings.conversations.borrow();
        let messages = &conversations[&session_id];
        assert_eq!(messages[0].original_received, 50);
        assert_eq!(
            messages[0].original_state,
            OriginalImagePresentationState::Receiving
        );
        assert_eq!(messages[1].original_received, 0);
        assert_eq!(
            messages[1].original_state,
            OriginalImagePresentationState::Available
        );
    }

    #[test]
    fn group_image_previews_with_equal_media_ids_remain_sender_scoped() {
        let mut messages = Vec::new();
        let mut first = presented_message(12, false);
        first.image = Some(slint::Image::default());
        first.original_size = 100;
        first.original_sender_b32 = Some("first.b32.i2p".into());
        first.original_state = OriginalImagePresentationState::Available;
        let mut second = first.clone();
        second.original_sender_b32 = Some("second.b32.i2p".into());

        upsert_presented_message(&mut messages, first);
        upsert_presented_message(&mut messages, second);

        assert_eq!(messages.len(), 2);
    }

    #[test]
    fn original_image_presentation_distinguishes_progress_and_cache() {
        let mut message = presented_message(9, false);
        message.original_size = 200;
        message.original_received = 50;
        message.original_state = OriginalImagePresentationState::Receiving;

        let (action, status, progress, busy) = original_image_presentation(&message);
        assert!(action.is_empty());
        assert_eq!(status, "50 B / 200 B");
        assert_eq!(progress, 0.25);
        assert!(busy);

        message.original_state = OriginalImagePresentationState::Cached;
        let (action, status, progress, busy) = original_image_presentation(&message);
        assert_eq!(action, "Open Original");
        assert_eq!(status, "Cached in memory");
        assert_eq!(progress, 1.0);
        assert!(!busy);
    }

    #[test]
    fn file_transfer_presentation_exposes_only_valid_actions() {
        let mut file = PresentedFileTransfer {
            transfer_id: 3,
            filename: "document.bin".into(),
            total_bytes: 200,
            transferred_bytes: 50,
            state: PresentedFileTransferState::IncomingOffer,
            saved_path: None,
            failure: None,
        };

        let presentation = file_transfer_presentation(&file, false);
        assert_eq!(presentation.bytes, "50 B / 200 B");
        assert_eq!(presentation.progress, 0.25);
        assert!(presentation.can_accept);
        assert!(presentation.can_decline);
        assert!(!presentation.can_cancel);

        file.state = PresentedFileTransferState::Active;
        let presentation = file_transfer_presentation(&file, false);
        assert!(!presentation.can_accept);
        assert!(!presentation.can_decline);
        assert!(presentation.can_cancel);

        file.state = PresentedFileTransferState::Completed;
        file.transferred_bytes = file.total_bytes;
        let presentation = file_transfer_presentation(&file, true);
        assert_eq!(presentation.progress, 1.0);
        assert_eq!(presentation.status, "Sent");
        assert!(!presentation.can_accept);
        assert!(!presentation.can_decline);
        assert!(!presentation.can_cancel);

        let presentation = file_transfer_presentation(&file, false);
        assert_eq!(presentation.status, "Received");

        let mut outgoing = presented_message(3, true);
        assert_eq!(message_delivery_label(&outgoing), "Pending");
        outgoing.file = Some(file);
        assert!(message_delivery_label(&outgoing).is_empty());
    }

    #[test]
    fn file_terminal_events_are_direction_scoped_and_preserve_progress() {
        let mappings = UiMappings::default();
        let session_id = SessionId::new(52);
        for (direction, total_bytes, transferred_bytes) in [
            (FileTransferDirection::Sent, 100, 40),
            (FileTransferDirection::Received, 200, 75),
        ] {
            upsert_presented_file(
                &mappings,
                session_id,
                direction,
                PresentedFileTransfer {
                    transfer_id: 7,
                    filename: "same-id.bin".into(),
                    total_bytes,
                    transferred_bytes,
                    state: PresentedFileTransferState::Active,
                    saved_path: None,
                    failure: None,
                },
            );
        }

        apply_file_transfer_event(
            &mappings,
            FileTransferEvent::Cancelled {
                session_id,
                transfer_id: 7,
                direction: FileTransferDirection::Received,
                filename: "same-id.bin".into(),
            },
        );

        let conversations = mappings.conversations.borrow();
        let messages = &conversations[&session_id];
        assert_eq!(messages.len(), 2);
        let sent = messages.iter().find(|message| message.mine).unwrap();
        let received = messages.iter().find(|message| !message.mine).unwrap();
        let sent = sent.file.as_ref().unwrap();
        let received = received.file.as_ref().unwrap();
        assert_eq!(sent.state, PresentedFileTransferState::Active);
        assert_eq!(sent.total_bytes, 100);
        assert_eq!(sent.transferred_bytes, 40);
        assert_eq!(received.state, PresentedFileTransferState::Cancelled);
        assert_eq!(received.total_bytes, 200);
        assert_eq!(received.transferred_bytes, 75);
    }

    #[test]
    fn presentation_deduplicates_by_direction_and_preserves_confirmed_state() {
        let mut messages = Vec::new();
        let mut confirmed = presented_message(7, true);
        confirmed.stored = true;
        confirmed.delivered = true;
        confirmed.relayed = true;
        confirmed.delivery_received = 2;
        confirmed.delivery_expected = 3;
        upsert_presented_message(&mut messages, confirmed);
        upsert_presented_message(&mut messages, presented_message(7, true));
        upsert_presented_message(&mut messages, presented_message(7, false));

        assert_eq!(messages.len(), 2);
        assert!(messages[0].stored);
        assert!(messages[0].delivered);
        assert!(messages[0].relayed);
        assert_eq!(messages[0].delivery_received, 2);
        assert_eq!(messages[0].delivery_expected, 3);
        assert!(messages[0].mine);
        assert!(!messages[1].mine);
    }

    #[test]
    fn image_display_size_preserves_aspect_ratio_without_upscaling() {
        assert_eq!(image_display_size(100, 80), (100.0, 80.0));
        assert_eq!(image_display_size(840, 720), (420.0, 360.0));
        assert_eq!(image_display_size(300, 600), (180.0, 360.0));
    }

    #[test]
    fn bubble_widths_remain_within_their_presentation_bounds() {
        let short_text = text_bubble_width("x", "Me", "01:02:03 UTC", false, false, 0);
        let stored_text = text_bubble_width("x", "Me", "01:02:03 UTC", false, true, 0);
        let long_text =
            text_bubble_width(&"x".repeat(1_000), "Peer", "01:02:03 UTC", false, false, 0);
        assert!(short_text >= TEXT_BUBBLE_MIN_BODY_WIDTH + BUBBLE_HORIZONTAL_PADDING);
        assert!(stored_text > short_text);
        assert_eq!(long_text, TEXT_BUBBLE_MAX_WIDTH);

        let small_image = image_bubble_width(
            32.0,
            "a.png",
            "image/png | preview 1.0 KiB",
            "01:02:03 UTC",
            false,
            0,
        );
        let large_image = image_bubble_width(
            IMAGE_BUBBLE_MAX_WIDTH,
            "a.png",
            "image/png | preview 1.0 MiB",
            "01:02:03 UTC",
            true,
            4,
        );
        assert!(small_image >= IMAGE_BUBBLE_MIN_WIDTH);
        assert_eq!(
            large_image,
            IMAGE_BUBBLE_MAX_WIDTH + BUBBLE_HORIZONTAL_PADDING
        );
    }

    #[test]
    fn compact_b32_labels_preserve_both_identity_edges() {
        assert_eq!(compact_b32_address(""), "----");
        assert_eq!(compact_b32_address("short.b32.i2p"), "short");
        assert_eq!(
            compact_b32_address("abcdef0123456789uvwxyz.b32.i2p"),
            "abcdef...uvwxyz"
        );
    }

    #[test]
    fn tofu_presentation_tracks_live_verification_and_mismatch_separately() {
        let mappings = UiMappings::default();
        let session_id = SessionId::new(7);

        update_contact_tofu_state(
            &mappings,
            &ContactSessionEvent::IdentityVerified {
                session_id,
                peer_b32: "peer.b32.i2p".into(),
                pinned: true,
            },
        );
        assert_eq!(
            mappings
                .contact_tofu_states
                .borrow()
                .get(&session_id)
                .copied(),
            Some(TofuPresentationState::Verified)
        );

        update_contact_tofu_state(
            &mappings,
            &ContactSessionEvent::Disconnected {
                session_id,
                peer_b32: Some("peer.b32.i2p".into()),
                reason: DisconnectReason::LocalRequest,
            },
        );
        assert!(
            !mappings
                .contact_tofu_states
                .borrow()
                .contains_key(&session_id)
        );

        update_contact_tofu_state(
            &mappings,
            &ContactSessionEvent::ConnectionRejected {
                session_id,
                reason: DisconnectReason::TofuMismatch,
            },
        );
        assert_eq!(
            mappings
                .contact_tofu_states
                .borrow()
                .get(&session_id)
                .copied(),
            Some(TofuPresentationState::Mismatch)
        );
    }

    #[test]
    fn deaddrop_timing_formats_latency_and_utc_time() {
        assert_eq!(
            deaddrop_timing(Some(125), Some(3_723_000)),
            "125ms  last 01:02:03 UTC"
        );
        assert_eq!(deaddrop_timing(None, None), "latency -  last never");
    }

    #[test]
    fn sam_status_presentation_preserves_failure_context_and_severity() {
        let monitor = SamMonitorStatus::Degraded {
            consecutive_failures: 2,
            reason: "connection refused".into(),
        };
        let test = SamTestStatus::Failed("unexpected EOF".into());

        assert_eq!(
            sam_monitor_status_text(&monitor),
            "Degraded (2/3): connection refused"
        );
        assert_eq!(sam_monitor_status_tone(&monitor), 2);
        assert_eq!(sam_test_status_text(&test), "Failed: unexpected EOF");
        assert_eq!(sam_test_status_tone(&test), 3);
    }

    #[test]
    fn offline_events_map_to_the_expected_activity_markers() {
        let session_id = SessionId::new(17);

        assert_eq!(
            offline_event_activity(&OfflineSessionEvent::PollSweepStarted { session_id }),
            Some(OfflineActivityState::Poll)
        );
        assert_eq!(
            offline_event_activity(&OfflineSessionEvent::PollSweepCompleted {
                session_id,
                result: OfflinePollResult::Miss,
                observation_count: 1,
            }),
            Some(OfflineActivityState::Miss)
        );
        assert_eq!(
            offline_event_activity(&OfflineSessionEvent::SendConfirmed {
                session_id,
                message_id: 9,
                index: 3,
                successful_drop_count: 2,
            }),
            Some(OfflineActivityState::Put)
        );
        assert_eq!(
            offline_event_activity(&OfflineSessionEvent::SendFailed {
                session_id,
                message_id: 9,
                index: 3,
                reason: "unavailable".into(),
            }),
            Some(OfflineActivityState::Fail)
        );
    }

    #[test]
    fn only_offline_events_that_change_bubbles_refresh_the_conversation() {
        let session_id = SessionId::new(22);

        assert!(offline_event_requires_conversation_refresh(
            &OfflineSessionEvent::SendConfirmed {
                session_id,
                message_id: 9,
                index: 3,
                successful_drop_count: 2,
            }
        ));
        assert!(!offline_event_requires_conversation_refresh(
            &OfflineSessionEvent::PollSweepStarted { session_id }
        ));
        assert!(!offline_event_requires_conversation_refresh(
            &OfflineSessionEvent::PollSweepCompleted {
                session_id,
                result: OfflinePollResult::Miss,
                observation_count: 1,
            }
        ));
        assert!(!offline_event_requires_conversation_refresh(
            &OfflineSessionEvent::IndexSyncApplied { session_id }
        ));
    }

    #[test]
    fn expired_offline_activity_is_removed_without_touching_live_activity() {
        let mappings = UiMappings::default();
        let expired_session = SessionId::new(18);
        let live_session = SessionId::new(19);
        let now = Instant::now();
        mappings.offline_activities.borrow_mut().insert(
            expired_session,
            OfflineActivityPresentation {
                state: OfflineActivityState::Miss,
                expires_at: now - Duration::from_millis(1),
            },
        );
        mappings.offline_activities.borrow_mut().insert(
            live_session,
            OfflineActivityPresentation {
                state: OfflineActivityState::Poll,
                expires_at: now + Duration::from_secs(1),
            },
        );

        assert!(expire_offline_activities(&mappings));
        let activities = mappings.offline_activities.borrow();
        assert!(!activities.contains_key(&expired_session));
        assert!(activities.contains_key(&live_session));
    }

    #[test]
    fn offline_activity_slot_stays_idle_when_no_recent_activity_is_visible() {
        let now = Instant::now();
        let expired = OfflineActivityPresentation {
            state: OfflineActivityState::Hit,
            expires_at: now - Duration::from_millis(1),
        };

        assert_eq!(visible_offline_activity(false, None, now), ("", 0));
        assert_eq!(visible_offline_activity(true, None, now), ("DD IDLE", 0));
        assert_eq!(
            visible_offline_activity(true, Some(&expired), now),
            ("DD IDLE", 0)
        );
    }

    #[test]
    fn offline_put_confirmation_marks_only_the_matching_message_as_relayed() {
        let mappings = UiMappings::default();
        let session_id = SessionId::new(20);
        let other_session = SessionId::new(21);
        let mut target = presented_message(11, true);
        target.offline = true;
        let mut other = presented_message(11, true);
        other.offline = true;
        mappings
            .conversations
            .borrow_mut()
            .insert(session_id, vec![target]);
        mappings
            .conversations
            .borrow_mut()
            .insert(other_session, vec![other]);

        mark_offline_message_relayed(&mappings, session_id, 11);

        assert!(mappings.conversations.borrow()[&session_id][0].relayed);
        assert!(!mappings.conversations.borrow()[&other_session][0].relayed);
    }

    #[test]
    fn clearing_presented_history_only_removes_stored_messages_for_target() {
        let mappings = UiMappings::default();
        let target_session = SessionId::new(7);
        let other_session = SessionId::new(8);
        let target =
            ManagedSessionKey::Contact(ContactId::new("target").expect("target contact id"));
        let other = ManagedSessionKey::Contact(ContactId::new("other").expect("other contact id"));
        mappings
            .session_keys
            .borrow_mut()
            .insert(target_session, target.clone());
        mappings
            .session_keys
            .borrow_mut()
            .insert(other_session, other);

        let mut stored = presented_message(1, true);
        stored.stored = true;
        mappings
            .conversations
            .borrow_mut()
            .insert(target_session, vec![stored, presented_message(2, true)]);
        mappings
            .conversations
            .borrow_mut()
            .insert(other_session, vec![presented_message(3, true)]);

        clear_presented_history(&mappings, &target);

        assert_eq!(mappings.conversations.borrow()[&target_session].len(), 1);
        assert_eq!(mappings.conversations.borrow()[&other_session].len(), 1);
    }
}
