use crate::cli::StartupOptions;
use crate::terminal::ClipboardCopyMethod;
use crate::workspace::{
    CloseDisposition, ConversationKey, ConversationTabState, OfflineToggleDisposition,
    OpenDisposition, RendezvousSubmitDisposition, TransientBrowserEntry, Workspace,
};
use commtools_core::{
    ContactBackupInspection, ContactId, GroupId, HistoryRecord, ManagedSessionKey,
    SamFailureAction, TransientId, TunnelSettings,
};
use commtools_runtime::{
    ApplicationDriver, CommToolsCommand, CommToolsCommandResult, ContactSessionEvent,
    ContactSummary, DeaddropServerSummary, FrontendEvent, GroupMemberSummary, GroupSummary,
    SamMonitorStatus, SamTestStatus,
};
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use std::io;
use std::path::{Path, PathBuf};
use tui_file_explorer::{ExplorerOutcome, FileExplorer, Theme};
use tui_tabs::TabNav;
use zeroize::Zeroizing;

const MAX_NAME_BYTES: usize = 256;
const MAX_PUBLIC_INVITE_BYTES: usize = commtools_core::group_roster::MAX_PUBLIC_INVITE_BYTES;
const MAX_PRIVATE_INVITE_BYTES: usize = commtools_core::private_group_invite::MAX_ENCODED_LEN;
const MAX_GROUP_NAME_CHARS: usize = commtools_core::group_roster::MAX_GROUP_DISPLAY_NAME_CHARS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellAction {
    Continue,
    Quit,
    WipeAll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Contacts,
    Groups,
    Settings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootNavigationTarget {
    ActiveChats,
    Contacts,
    Groups,
    Settings,
}

impl RootNavigationTarget {
    fn label(self) -> &'static str {
        match self {
            Self::ActiveChats => "Active Chats",
            Self::Contacts => "Contacts",
            Self::Groups => "Groups",
            Self::Settings => "Settings",
        }
    }

    fn section(self) -> Option<Section> {
        match self {
            Self::ActiveChats => None,
            Self::Contacts => Some(Section::Contacts),
            Self::Groups => Some(Section::Groups),
            Self::Settings => Some(Section::Settings),
        }
    }
}

impl From<Section> for RootNavigationTarget {
    fn from(section: Section) -> Self {
        match section {
            Section::Contacts => Self::Contacts,
            Section::Groups => Self::Groups,
            Section::Settings => Self::Settings,
        }
    }
}

fn root_navigation_targets(has_active_chats: bool) -> Vec<RootNavigationTarget> {
    if has_active_chats {
        vec![
            RootNavigationTarget::ActiveChats,
            RootNavigationTarget::Contacts,
            RootNavigationTarget::Groups,
            RootNavigationTarget::Settings,
        ]
    } else {
        vec![
            RootNavigationTarget::Contacts,
            RootNavigationTarget::Groups,
            RootNavigationTarget::Settings,
        ]
    }
}

fn root_navigation_label(
    target: RootNavigationTarget,
    active_chats_marker: Option<char>,
    missed_calls: usize,
    has_unread: bool,
    has_warning: bool,
    sam_warning: bool,
) -> String {
    let mut label = target.label().to_string();
    if target == RootNavigationTarget::ActiveChats {
        if let Some(marker) = active_chats_marker {
            label.push(' ');
            label.push(marker);
        }
        if missed_calls > 0 {
            label.push(' ');
            label.push_str(&missed_calls.to_string());
        }
        if has_unread {
            label.push_str(" +");
        }
        if has_warning {
            label.push_str(" !");
        }
    }
    if target == RootNavigationTarget::Settings && sam_warning {
        label.push_str(" !");
    }
    label
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ContactBrowserItem {
    Contact(ContactId),
    Transient(TransientId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContactBrowserPane {
    Contacts,
    Actions,
}

impl ContactBrowserPane {
    fn next(self) -> Self {
        match self {
            Self::Contacts => Self::Actions,
            Self::Actions => Self::Contacts,
        }
    }

    fn previous(self) -> Self {
        self.next()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContactBrowserAction {
    NewContact,
    NewTransient,
    OpenOrFocus,
    RenameContact,
    ToggleHistory,
    ClearHistory,
    ExportContact,
    ImportContact,
    TunnelSettings,
    AddDeaddrop,
    RemoveDeaddrop,
    UnlockContact,
    ResetContact,
    DeleteContact,
}

impl ContactBrowserAction {
    const ALL: [Self; 14] = [
        Self::NewContact,
        Self::NewTransient,
        Self::OpenOrFocus,
        Self::RenameContact,
        Self::ToggleHistory,
        Self::ClearHistory,
        Self::ExportContact,
        Self::ImportContact,
        Self::TunnelSettings,
        Self::AddDeaddrop,
        Self::RemoveDeaddrop,
        Self::UnlockContact,
        Self::ResetContact,
        Self::DeleteContact,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::NewContact => "New contact",
            Self::NewTransient => "New transient",
            Self::OpenOrFocus => "Open / focus",
            Self::RenameContact => "Rename contact",
            Self::ToggleHistory => "Toggle history",
            Self::ClearHistory => "Clear history",
            Self::ExportContact => "Export encrypted contact",
            Self::ImportContact => "Import encrypted contact",
            Self::TunnelSettings => "Edit tunnel settings",
            Self::AddDeaddrop => "Add deaddrop server",
            Self::RemoveDeaddrop => "Remove deaddrop server",
            Self::UnlockContact => "Unlock contact",
            Self::ResetContact => "Reset contact",
            Self::DeleteContact => "Delete contact",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupBrowserPane {
    Groups,
    Members,
    Actions,
}

impl GroupBrowserPane {
    fn next(self) -> Self {
        match self {
            Self::Groups => Self::Members,
            Self::Members => Self::Actions,
            Self::Actions => Self::Groups,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Groups => Self::Actions,
            Self::Members => Self::Groups,
            Self::Actions => Self::Members,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupBrowserAction {
    NewGroup,
    OpenGroup,
    LocalName,
    ToggleHistory,
    ClearHistory,
    GeneratePublicInvite,
    CopyPublicInvite,
    GeneratePrivateRequest,
    CopyPrivateRequest,
    AnswerPrivateRequest,
    CopyPrivateInvite,
    ImportInvite,
    RemoveSelectedMember,
    LeaveGroup,
    DissolveGroup,
    DeleteLocalGroup,
}

impl GroupBrowserAction {
    const ALL: [Self; 16] = [
        Self::NewGroup,
        Self::OpenGroup,
        Self::LocalName,
        Self::ToggleHistory,
        Self::ClearHistory,
        Self::GeneratePublicInvite,
        Self::CopyPublicInvite,
        Self::GeneratePrivateRequest,
        Self::CopyPrivateRequest,
        Self::AnswerPrivateRequest,
        Self::CopyPrivateInvite,
        Self::ImportInvite,
        Self::RemoveSelectedMember,
        Self::LeaveGroup,
        Self::DissolveGroup,
        Self::DeleteLocalGroup,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::NewGroup => "New group",
            Self::OpenGroup => "Open group",
            Self::LocalName => "Set local member name",
            Self::ToggleHistory => "Toggle history",
            Self::ClearHistory => "Clear history",
            Self::GeneratePublicInvite => "Generate public invite",
            Self::CopyPublicInvite => "Copy public invite",
            Self::GeneratePrivateRequest => "Generate private request",
            Self::CopyPrivateRequest => "Copy private request",
            Self::AnswerPrivateRequest => "Answer private request",
            Self::CopyPrivateInvite => "Copy private invite",
            Self::ImportInvite => "Import group invite",
            Self::RemoveSelectedMember => "Remove selected member",
            Self::LeaveGroup => "Leave group",
            Self::DissolveGroup => "Dissolve group",
            Self::DeleteLocalGroup => "Delete local group",
        }
    }

    fn requires_group(self) -> bool {
        !matches!(
            self,
            Self::NewGroup
                | Self::GeneratePrivateRequest
                | Self::CopyPrivateRequest
                | Self::ImportInvite
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CreateKind {
    Contact,
    Group,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DeaddropInput {
    Add {
        contact_id: ContactId,
        display_name: String,
    },
    Remove {
        contact_id: ContactId,
        display_name: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunnelSettingField {
    Length,
    Quantity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TunnelSettingsInput {
    contact_id: ContactId,
    display_name: String,
    length: u8,
    quantity: u8,
    field: TunnelSettingField,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettingsAction {
    EditSamHost,
    EditSamPort,
    TestSam,
    DefaultTunnels,
    ToggleLiveness,
    ToggleFailureAction,
    ExportBackup,
    RestoreBackup,
    WipeAll,
}

impl SettingsAction {
    const ALL: [Self; 9] = [
        Self::EditSamHost,
        Self::EditSamPort,
        Self::TestSam,
        Self::DefaultTunnels,
        Self::ToggleLiveness,
        Self::ToggleFailureAction,
        Self::ExportBackup,
        Self::RestoreBackup,
        Self::WipeAll,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::EditSamHost => "Edit SAM host",
            Self::EditSamPort => "Edit SAM port",
            Self::TestSam => "Test SAM",
            Self::DefaultTunnels => "Default tunnels",
            Self::ToggleLiveness => "Toggle liveness monitoring",
            Self::ToggleFailureAction => "Toggle failure action",
            Self::ExportBackup => "Export encrypted backup",
            Self::RestoreBackup => "Restore encrypted backup",
            Self::WipeAll => "Wipe all local data",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackupInputField {
    Path,
    Passphrase,
}

#[derive(Clone, PartialEq, Eq)]
enum ContactBackupOperation {
    Export {
        contact_id: ContactId,
        display_name: String,
    },
    Import,
}

#[derive(Clone, PartialEq, Eq)]
struct ContactBackupInput {
    operation: ContactBackupOperation,
    path: String,
    passphrase: Zeroizing<String>,
    include_history: bool,
    field: BackupInputField,
}

#[derive(Clone, PartialEq, Eq)]
struct ContactBackupConfirmation {
    path: PathBuf,
    passphrase: Zeroizing<String>,
    inspection: ContactBackupInspection,
}

#[derive(Clone, PartialEq, Eq)]
enum SettingsInput {
    SamHost(String),
    SamPort(String),
    DefaultTunnels {
        length: u8,
        quantity: u8,
        field: TunnelSettingField,
    },
    ExportBackup {
        path: String,
        passphrase: Zeroizing<String>,
        include_files: bool,
        field: BackupInputField,
    },
    RestoreBackup {
        path: String,
        passphrase: Zeroizing<String>,
        restore_files: bool,
        field: BackupInputField,
    },
    WipeAll {
        passphrase: Zeroizing<String>,
    },
}

#[derive(Clone, PartialEq, Eq)]
enum StorageConfirmation {
    RestoreBackup {
        path: PathBuf,
        passphrase: Zeroizing<String>,
        restore_files: bool,
    },
    WipeAll {
        passphrase: Zeroizing<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum View {
    Browser,
    Conversation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrowserFocus {
    Root,
    Content,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileChooserKind {
    Image,
    File,
}

struct FileChooserState {
    kind: FileChooserKind,
    explorer: FileExplorer,
}

impl FileChooserState {
    fn new(kind: FileChooserKind) -> Self {
        let start_dir = std::env::current_dir().unwrap_or_else(|_| ".".into());
        let mut builder = FileExplorer::builder(start_dir);
        if kind == FileChooserKind::Image {
            for extension in ["png", "jpg", "jpeg", "gif", "bmp", "webp"] {
                builder = builder.allow_extension(extension);
            }
        }
        Self {
            kind,
            explorer: builder.build(),
        }
    }

    fn title(&self) -> &'static str {
        match self.kind {
            FileChooserKind::Image => "Select Image",
            FileChooserKind::File => "Select File",
        }
    }
}

fn termcomm_file_chooser_theme() -> Theme {
    Theme::default()
        .brand(Color::Cyan)
        .accent(Color::Cyan)
        .success(Color::Green)
        .dim(Color::DarkGray)
        .fg(Color::White)
        .sel_bg(Color::DarkGray)
        .dir(Color::Cyan)
        .match_file(Color::Green)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TrustConfirmation {
    Lock {
        session_id: commtools_core::SessionId,
        peer_b32: String,
    },
    Unlock {
        contact_id: ContactId,
        display_name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeaddropRemovalConfirmation {
    contact_id: ContactId,
    display_name: String,
    server: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContactDeletionConfirmation {
    contact_id: ContactId,
    display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HistoryClearConfirmation {
    key: ManagedSessionKey,
    display_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupLeaveMode {
    Authoritative,
    LocalOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GroupConfirmation {
    DeleteLocalGroup {
        group_id: GroupId,
        group_name: String,
    },
    RemoveMember {
        group_id: GroupId,
        group_name: String,
        member_b32: String,
        member_name: String,
    },
    LeaveGroup {
        group_id: GroupId,
        group_name: String,
        mode: GroupLeaveMode,
    },
    DissolveGroup {
        group_id: GroupId,
        group_name: String,
    },
}

pub struct ShellState {
    vault_root: PathBuf,
    section: Section,
    root_navigation: RootNavigationTarget,
    selected_contact_item: Option<ContactBrowserItem>,
    contact_browser_pane: ContactBrowserPane,
    selected_contact_action: usize,
    selected_group: Option<GroupId>,
    group_browser_pane: GroupBrowserPane,
    selected_group_member: usize,
    selected_group_action: usize,
    selected_settings_action: usize,
    create_kind: Option<CreateKind>,
    contact_name_input: Option<ContactId>,
    deaddrop_input: Option<DeaddropInput>,
    tunnel_settings_input: Option<TunnelSettingsInput>,
    settings_input: Option<SettingsInput>,
    input: String,
    status: String,
    view: View,
    browser_focus: BrowserFocus,
    workspace: Workspace,
    trust_confirmation: Option<TrustConfirmation>,
    contact_deletion_confirmation: Option<ContactDeletionConfirmation>,
    history_clear_confirmation: Option<HistoryClearConfirmation>,
    deaddrop_removal_confirmation: Option<DeaddropRemovalConfirmation>,
    group_confirmation: Option<GroupConfirmation>,
    contact_reset_confirmation: Option<ContactDeletionConfirmation>,
    contact_backup_input: Option<ContactBackupInput>,
    contact_backup_confirmation: Option<ContactBackupConfirmation>,
    storage_confirmation: Option<StorageConfirmation>,
    public_invite_input: Option<Zeroizing<String>>,
    private_request_input: Option<(GroupId, Zeroizing<String>)>,
    group_name_input: Option<GroupId>,
    generated_public_invite: Option<(GroupId, Zeroizing<String>)>,
    generated_private_request: Option<Zeroizing<String>>,
    generated_private_invite: Option<(GroupId, Zeroizing<String>)>,
    pending_clipboard: Option<Zeroizing<String>>,
    pending_log_copy_lines: Option<usize>,
    file_chooser: Option<FileChooserState>,
}

impl ShellState {
    pub fn new(driver: &ApplicationDriver, vault_root: &Path) -> Self {
        let mut state = Self {
            vault_root: vault_root.to_path_buf(),
            section: Section::Contacts,
            root_navigation: RootNavigationTarget::Contacts,
            selected_contact_item: None,
            contact_browser_pane: ContactBrowserPane::Contacts,
            selected_contact_action: 0,
            selected_group: None,
            group_browser_pane: GroupBrowserPane::Groups,
            selected_group_member: 0,
            selected_group_action: 0,
            selected_settings_action: 0,
            create_kind: None,
            contact_name_input: None,
            deaddrop_input: None,
            tunnel_settings_input: None,
            settings_input: None,
            input: String::new(),
            status: "Vault unlocked.".into(),
            view: View::Browser,
            browser_focus: BrowserFocus::Content,
            workspace: Workspace::default(),
            trust_confirmation: None,
            contact_deletion_confirmation: None,
            history_clear_confirmation: None,
            deaddrop_removal_confirmation: None,
            group_confirmation: None,
            contact_reset_confirmation: None,
            contact_backup_input: None,
            contact_backup_confirmation: None,
            storage_confirmation: None,
            public_invite_input: None,
            private_request_input: None,
            group_name_input: None,
            generated_public_invite: None,
            generated_private_request: None,
            generated_private_invite: None,
            pending_clipboard: None,
            pending_log_copy_lines: None,
            file_chooser: None,
        };
        state.normalize_selection(driver);
        state
    }

    pub fn handle_event(&mut self, event: Event, driver: &mut ApplicationDriver) -> ShellAction {
        match event {
            Event::Key(key) if is_key_action(&key) => self.handle_key(key, driver),
            Event::Paste(_) if self.file_chooser.is_some() => ShellAction::Continue,
            Event::Paste(_) if self.tunnel_settings_input.is_some() => ShellAction::Continue,
            Event::Paste(value) if self.contact_backup_input.is_some() => {
                if let Some(input) = self.contact_backup_input.as_mut() {
                    match input.field {
                        BackupInputField::Path => {
                            let remaining = 4_096usize.saturating_sub(input.path.len());
                            input.path.extend(
                                value
                                    .chars()
                                    .filter(|character| !character.is_control())
                                    .take(remaining),
                            );
                        }
                        BackupInputField::Passphrase => {
                            let remaining = 1_024usize.saturating_sub(input.passphrase.len());
                            input.passphrase.extend(value.chars().take(remaining));
                        }
                    }
                }
                ShellAction::Continue
            }
            Event::Paste(value) if self.settings_input.is_some() => {
                match self.settings_input.as_mut() {
                    Some(SettingsInput::SamHost(input)) => {
                        let remaining = 255usize.saturating_sub(input.len());
                        input.extend(
                            value
                                .chars()
                                .filter(|character| !character.is_control())
                                .take(remaining),
                        );
                    }
                    Some(SettingsInput::SamPort(input)) => {
                        let remaining = 5usize.saturating_sub(input.len());
                        input.extend(value.chars().filter(char::is_ascii_digit).take(remaining));
                    }
                    Some(
                        SettingsInput::ExportBackup {
                            path,
                            passphrase,
                            field,
                            ..
                        }
                        | SettingsInput::RestoreBackup {
                            path,
                            passphrase,
                            field,
                            ..
                        },
                    ) => match field {
                        BackupInputField::Path => {
                            path.extend(
                                value
                                    .chars()
                                    .filter(|character| !character.is_control())
                                    .take(4_096usize.saturating_sub(path.len())),
                            );
                        }
                        BackupInputField::Passphrase => {
                            let remaining = 1_024usize.saturating_sub(passphrase.len());
                            passphrase.extend(value.chars().take(remaining));
                        }
                    },
                    Some(SettingsInput::WipeAll { passphrase }) => {
                        let remaining = 1_024usize.saturating_sub(passphrase.len());
                        passphrase.extend(value.chars().take(remaining));
                    }
                    _ => {}
                }
                ShellAction::Continue
            }
            Event::Paste(value) if self.public_invite_input.is_some() => {
                self.set_public_invite_input(value);
                ShellAction::Continue
            }
            Event::Paste(value) if self.private_request_input.is_some() => {
                self.set_private_request_input(value);
                ShellAction::Continue
            }
            Event::Paste(value) if self.contact_name_input.is_some() => {
                self.input.clear();
                for character in value.chars().filter(|character| !character.is_control()) {
                    self.push_input(character);
                }
                ShellAction::Continue
            }
            Event::Paste(value) if self.group_name_input.is_some() => {
                self.input = value
                    .chars()
                    .filter(|character| !character.is_control())
                    .take(MAX_GROUP_NAME_CHARS)
                    .collect();
                self.status.clear();
                ShellAction::Continue
            }
            Event::Paste(value) if self.create_kind.is_some() || self.deaddrop_input.is_some() => {
                for character in value.chars().filter(|character| !character.is_control()) {
                    self.push_input(character);
                }
                ShellAction::Continue
            }
            Event::Paste(value) if self.workspace.connect_input_active() => {
                for character in value.chars() {
                    self.workspace.push_connect_input(character);
                }
                self.status.clear();
                ShellAction::Continue
            }
            Event::Paste(value) if self.workspace.rendezvous_input_active() => {
                self.workspace.set_rendezvous_input(value);
                self.status.clear();
                ShellAction::Continue
            }
            Event::Paste(value) if self.workspace.image_path_input_active() => {
                self.workspace.set_image_input(value);
                self.status.clear();
                ShellAction::Continue
            }
            Event::Paste(value) if self.workspace.file_path_input_active() => {
                self.workspace.set_file_input(value);
                self.status.clear();
                ShellAction::Continue
            }
            Event::Paste(value) if self.workspace.message_input_active() => {
                self.workspace.insert_message_input(&value);
                self.status.clear();
                ShellAction::Continue
            }
            _ => ShellAction::Continue,
        }
    }

    pub fn advance_animation(&mut self) -> bool {
        self.workspace.advance_tab_spinner()
    }

    pub fn take_pending_clipboard(&mut self) -> Option<Zeroizing<String>> {
        self.pending_clipboard.take()
    }

    pub fn record_clipboard_result(&mut self, result: io::Result<ClipboardCopyMethod>) {
        let log_line_count = self.pending_log_copy_lines.take();
        self.status = match result {
            Ok(_) if log_line_count.is_some() => {
                format!("Copied {} log lines.", log_line_count.unwrap_or(0))
            }
            Ok(ClipboardCopyMethod::System) => "Content copied to the system clipboard.".into(),
            Ok(ClipboardCopyMethod::TerminalOsc52) => {
                "Content sent through terminal OSC52 clipboard fallback.".into()
            }
            Err(error) => format!("Terminal clipboard copy failed: {error}"),
        };
    }

    pub fn handle_frontend_event(&mut self, event: &FrontendEvent, driver: &mut ApplicationDriver) {
        match event {
            FrontendEvent::Session(event) => self.workspace.handle_session_lifecycle_event(event),
            FrontendEvent::Contact(event) => self.handle_contact_session_event(event, driver),
            FrontendEvent::Rendezvous(event) => {
                self.workspace.handle_rendezvous_session_event(event)
            }
            FrontendEvent::Group(event) => self.workspace.handle_group_session_event(event),
            FrontendEvent::FileTransfer(event) => self.workspace.handle_file_transfer_event(event),
            FrontendEvent::Offline(event) => self.workspace.handle_offline_session_event(event),
            FrontendEvent::Operation(event) => self.workspace.handle_runtime_operation_event(event),
            FrontendEvent::Lifecycle(_) => {}
            FrontendEvent::TextReceived(event) => self.workspace.receive_text(event),
            FrontendEvent::TextDeliveryUpdated(event) => {
                self.workspace.receive_text_delivery(event)
            }
            FrontendEvent::ImageReceived(event) => self.workspace.receive_image(event),
            FrontendEvent::ImageDeliveryUpdated(event) => {
                self.workspace.receive_image_delivery(event)
            }
            FrontendEvent::OriginalImageProgress {
                session_id,
                media_id,
                received_bytes,
                total_bytes,
                sender_b32,
                ..
            } => self.workspace.receive_original_image_progress(
                *session_id,
                *media_id,
                *received_bytes,
                *total_bytes,
                sender_b32.as_deref(),
            ),
            FrontendEvent::OriginalImageReceived(event) => {
                self.workspace.receive_original_image(event)
            }
            FrontendEvent::OriginalImageUnavailable {
                session_id,
                media_id,
                sender_b32,
            } => self.workspace.original_image_unavailable(
                *session_id,
                *media_id,
                sender_b32.as_deref(),
            ),
            FrontendEvent::OriginalImageCancelled {
                session_id,
                media_id,
                sender_b32,
            } => self.workspace.original_image_cancelled(
                *session_id,
                *media_id,
                sender_b32.as_deref(),
            ),
            FrontendEvent::ImageRejected { session_id, reason } => self
                .workspace
                .record_contact_warning(*session_id, format!("Receive inline image: {reason}")),
            FrontendEvent::TextRejected {
                session_id,
                offline_index,
                reason,
            } => self
                .workspace
                .record_text_rejection(*session_id, *offline_index, reason.clone()),
            _ => {}
        }
        self.workspace.sync_contact_offline_modes(driver);
        self.workspace.sync_group_metadata(driver);
        if self.workspace.is_empty() {
            self.view = View::Browser;
        }
    }

    fn handle_contact_session_event(
        &mut self,
        event: &ContactSessionEvent,
        driver: &mut ApplicationDriver,
    ) {
        let ready_offline_session = match event {
            ContactSessionEvent::PhaseChanged {
                session_id,
                phase: commtools_core::OneToOnePhase::Ready,
            } if driver.session_summary(*session_id).is_some_and(|session| {
                session.offline_mode == Some(commtools_core::OfflineCoordinatorMode::Offline)
            }) =>
            {
                Some(*session_id)
            }
            _ => None,
        };
        let online_transition_error = ready_offline_session.and_then(|session_id| {
            driver
                .dispatch_command(CommToolsCommand::LeaveContactOffline { session_id })
                .err()
                .map(|error| (session_id, error.to_string()))
        });
        self.workspace.handle_contact_session_event(event);
        if let Some((session_id, reason)) = online_transition_error {
            self.workspace.record_contact_warning(
                session_id,
                format!("Return to online mode after secure connection: {reason}"),
            );
        }
    }

    pub fn render(
        &mut self,
        frame: &mut Frame<'_>,
        driver: &ApplicationDriver,
        options: &StartupOptions,
    ) {
        self.normalize_selection(driver);
        if self.view == View::Conversation {
            self.workspace.mark_active_viewed();
        }
        let sections = Layout::vertical([
            Constraint::Length(3),
            Constraint::Fill(1),
            Constraint::Length(
                if self.view == View::Browser
                    && (self.create_kind.is_some()
                        || self.contact_name_input.is_some()
                        || self.deaddrop_input.is_some()
                        || self.tunnel_settings_input.is_some()
                        || self.contact_backup_input.is_some()
                        || self.settings_input.is_some()
                        || self.public_invite_input.is_some()
                        || self.private_request_input.is_some()
                        || self.group_name_input.is_some())
                {
                    3
                } else {
                    0
                },
            ),
            Constraint::Length(3),
        ])
        .split(frame.area());

        match self.view {
            View::Browser => {
                let root_targets = root_navigation_targets(!self.workspace.is_empty());
                let selected = root_targets
                    .iter()
                    .position(|target| *target == self.root_navigation)
                    .unwrap_or_else(|| {
                        root_targets
                            .iter()
                            .position(|target| target.section() == Some(self.section))
                            .unwrap_or(0)
                    });
                let snapshot = driver.snapshot().ok();
                let sam_requires_attention = snapshot
                    .as_ref()
                    .is_some_and(|snapshot| snapshot.sam_monitor_requires_attention);
                let active_chats_marker = self.workspace.active_chats_marker(|group_id| {
                    snapshot.as_ref().is_some_and(|snapshot| {
                        snapshot
                            .groups
                            .iter()
                            .any(|group| &group.id == group_id && group.ready_member_count > 0)
                    })
                });
                let missed_calls = self.workspace.total_missed_calls();
                let labels = root_targets
                    .iter()
                    .map(|target| {
                        root_navigation_label(
                            *target,
                            active_chats_marker,
                            missed_calls,
                            self.workspace.has_unread_attention(),
                            self.workspace.has_warning_attention(),
                            sam_requires_attention,
                        )
                    })
                    .collect::<Vec<_>>();
                let label_refs = labels.iter().map(String::as_str).collect::<Vec<_>>();
                let border_color = if self.browser_focus == BrowserFocus::Root {
                    Color::Cyan
                } else {
                    Color::DarkGray
                };
                let selected_style = if self.browser_focus == BrowserFocus::Root {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };
                frame.render_widget(
                    TabNav::new(&label_refs, selected)
                        .style(Style::default().fg(Color::DarkGray))
                        .highlight_style(selected_style)
                        .border_style(Style::default().fg(border_color))
                        .indicator(None),
                    sections[0],
                );
                match self.section {
                    Section::Contacts => self.render_contacts(frame, sections[1], driver),
                    Section::Groups => self.render_groups(frame, sections[1], driver),
                    Section::Settings => self.render_settings(frame, sections[1], driver),
                }
            }
            View::Conversation => {
                self.workspace.render_tabs(frame, sections[0], driver);
                if let Some(chooser) = self.file_chooser.as_mut() {
                    let chooser_sections =
                        Layout::vertical([Constraint::Length(1), Constraint::Fill(1)])
                            .split(sections[1]);
                    frame.render_widget(
                        Paragraph::new(chooser.title())
                            .alignment(Alignment::Center)
                            .style(
                                Style::default()
                                    .fg(Color::Cyan)
                                    .add_modifier(Modifier::BOLD),
                            ),
                        chooser_sections[0],
                    );
                    tui_file_explorer::render_themed(
                        &mut chooser.explorer,
                        frame,
                        chooser_sections[1],
                        &termcomm_file_chooser_theme(),
                    );
                } else {
                    self.workspace.render_active(frame, sections[1], driver);
                }
            }
        }

        if self.view == View::Browser
            && (self.create_kind.is_some()
                || self.contact_name_input.is_some()
                || self.deaddrop_input.is_some()
                || self.tunnel_settings_input.is_some()
                || self.contact_backup_input.is_some()
                || self.settings_input.is_some()
                || self.public_invite_input.is_some()
                || self.private_request_input.is_some()
                || self.group_name_input.is_some())
        {
            let title = if let Some(input) = self.contact_backup_input.as_ref() {
                match &input.operation {
                    ContactBackupOperation::Export { .. } => " Export encrypted contact ",
                    ContactBackupOperation::Import => " Import encrypted contact ",
                }
            } else if self.settings_input.is_some() {
                match self.settings_input.as_ref() {
                    Some(SettingsInput::ExportBackup { .. }) => " Export encrypted backup ",
                    Some(SettingsInput::RestoreBackup { .. }) => " Restore encrypted backup ",
                    Some(SettingsInput::WipeAll { .. }) => " Confirm vault passphrase ",
                    _ => " Application settings ",
                }
            } else if self.tunnel_settings_input.is_some() {
                " Tunnel settings "
            } else if self.contact_name_input.is_some() {
                " Rename contact "
            } else {
                match (
                    &self.create_kind,
                    &self.deaddrop_input,
                    &self.public_invite_input,
                    &self.private_request_input,
                    &self.group_name_input,
                ) {
                    (Some(CreateKind::Contact), _, _, _, _) => " New contact ",
                    (Some(CreateKind::Group), _, _, _, _) => " New group ",
                    (_, Some(DeaddropInput::Add { .. }), _, _, _) => " Add deaddrop server ",
                    (_, Some(DeaddropInput::Remove { .. }), _, _, _) => {
                        " Remove deaddrop server number "
                    }
                    (_, _, Some(_), _, _) => " Import group invite ",
                    (_, _, _, Some(_), _) => " Answer private group request ",
                    (_, _, _, _, Some(_)) => " Local group name ",
                    _ => " Input ",
                }
            };
            let displayed_input = if let Some(input) = self.contact_backup_input.as_ref() {
                backup_input_display(
                    &input.path,
                    &input.passphrase,
                    input.include_history,
                    input.field,
                    match &input.operation {
                        ContactBackupOperation::Export { .. } => "Include history",
                        ContactBackupOperation::Import => "Backup history",
                    },
                )
            } else if let Some(setting) = self.settings_input.as_ref() {
                match setting {
                    SettingsInput::SamHost(host) => format!("SAM host: {host}"),
                    SettingsInput::SamPort(port) => format!("SAM port: {port}"),
                    SettingsInput::DefaultTunnels {
                        length,
                        quantity,
                        field,
                    } => match field {
                        TunnelSettingField::Length => {
                            format!("[Length: {length}]  Quantity: {quantity}")
                        }
                        TunnelSettingField::Quantity => {
                            format!("Length: {length}  [Quantity: {quantity}]")
                        }
                    },
                    SettingsInput::ExportBackup {
                        path,
                        passphrase,
                        include_files,
                        field,
                    } => backup_input_display(
                        path,
                        passphrase,
                        *include_files,
                        *field,
                        "Include files",
                    ),
                    SettingsInput::RestoreBackup {
                        path,
                        passphrase,
                        restore_files,
                        field,
                    } => backup_input_display(
                        path,
                        passphrase,
                        *restore_files,
                        *field,
                        "Restore files",
                    ),
                    SettingsInput::WipeAll { passphrase } => {
                        format!(
                            "Vault passphrase: {}",
                            "*".repeat(passphrase.chars().count())
                        )
                    }
                }
            } else if let Some(tunnels) = self.tunnel_settings_input.as_ref() {
                match tunnels.field {
                    TunnelSettingField::Length => format!(
                        "[Length: {}]  Quantity: {}",
                        tunnels.length, tunnels.quantity
                    ),
                    TunnelSettingField::Quantity => format!(
                        "Length: {}  [Quantity: {}]",
                        tunnels.length, tunnels.quantity
                    ),
                }
            } else if let Some(invite) = self.public_invite_input.as_ref() {
                if invite.is_empty() {
                    "Paste the public or private invite here".to_string()
                } else {
                    format!(
                        "Group invite ready: {} bytes; press Enter to import",
                        invite.len()
                    )
                }
            } else if let Some((_, request)) = self.private_request_input.as_ref() {
                if request.is_empty() {
                    "Paste the recipient's private request here".to_string()
                } else {
                    format!(
                        "Private request ready: {} bytes; press Enter to answer",
                        request.len()
                    )
                }
            } else {
                self.input.clone()
            };
            frame.render_widget(
                Paragraph::new(displayed_input)
                    .style(Style::default().fg(Color::White))
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(Color::Cyan))
                            .title(title),
                    ),
                sections[2],
            );
        }

        let footer = Line::from(vec![
            Span::styled(self.status.as_str(), Style::default().fg(Color::Gray)),
            Span::raw("  "),
            Span::styled(
                options.data_dir.display().to_string(),
                Style::default().fg(Color::DarkGray),
            ),
        ]);
        frame.render_widget(
            Paragraph::new(footer)
                .alignment(Alignment::Center)
                .block(Block::default().borders(Borders::ALL)),
            sections[3],
        );
    }

    fn handle_key(&mut self, key: KeyEvent, driver: &mut ApplicationDriver) -> ShellAction {
        if self.view == View::Conversation {
            self.workspace.clear_active_missed_calls();
        }
        if self.file_chooser.is_some() {
            return self.handle_file_chooser_key(key, driver);
        }
        if self.group_confirmation.is_some() {
            return self.handle_group_confirmation_key(key, driver);
        }
        if self.storage_confirmation.is_some() {
            return self.handle_storage_confirmation_key(key, driver);
        }
        if self.contact_backup_confirmation.is_some() {
            return self.handle_contact_backup_confirmation_key(key, driver);
        }
        if self.history_clear_confirmation.is_some() {
            return self.handle_history_clear_confirmation_key(key, driver);
        }
        if self.contact_deletion_confirmation.is_some() {
            return self.handle_contact_deletion_confirmation_key(key, driver);
        }
        if self.contact_reset_confirmation.is_some() {
            return self.handle_contact_reset_confirmation_key(key, driver);
        }
        if self.deaddrop_removal_confirmation.is_some() {
            return self.handle_deaddrop_removal_confirmation_key(key, driver);
        }
        if self.trust_confirmation.is_some() {
            return self.handle_trust_confirmation_key(key, driver);
        }
        if self.deaddrop_input.is_some() {
            return self.handle_deaddrop_input_key(key, driver);
        }
        if self.tunnel_settings_input.is_some() {
            return self.handle_tunnel_settings_key(key, driver);
        }
        if self.contact_backup_input.is_some() {
            return self.handle_contact_backup_input_key(key, driver);
        }
        if self.settings_input.is_some() {
            return self.handle_settings_input_key(key, driver);
        }
        if self.contact_name_input.is_some() {
            return self.handle_contact_name_input_key(key, driver);
        }
        if self.public_invite_input.is_some() {
            return self.handle_public_invite_input_key(key, driver);
        }
        if self.private_request_input.is_some() {
            return self.handle_private_request_input_key(key, driver);
        }
        if self.group_name_input.is_some() {
            return self.handle_group_name_input_key(key, driver);
        }
        if self.create_kind.is_some() {
            return self.handle_create_key(key, driver);
        }
        if self.workspace.connect_input_active() {
            return self.handle_connect_input_key(key, driver);
        }
        if self.workspace.rendezvous_input_active() {
            return self.handle_rendezvous_input_key(key, driver);
        }
        if self.workspace.image_path_input_active() {
            return self.handle_image_input_key(key, driver);
        }
        if self.workspace.file_path_input_active() {
            return self.handle_file_input_key(key, driver);
        }
        if self.workspace.message_input_active() {
            return self.handle_message_input_key(key, driver);
        }
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        if key.code == KeyCode::Char('q') {
            return ShellAction::Quit;
        }
        match self.view {
            View::Browser => self.handle_browser_key(key, driver),
            View::Conversation => self.handle_conversation_key(key, driver),
        }
        self.normalize_selection(driver);
        ShellAction::Continue
    }

    fn handle_browser_key(&mut self, key: KeyEvent, driver: &mut ApplicationDriver) {
        if self.browser_focus == BrowserFocus::Root {
            self.handle_browser_root_key(key);
            return;
        }
        match self.section {
            Section::Contacts => self.handle_contact_browser_key(key, driver),
            Section::Groups => self.handle_group_browser_key(key, driver),
            Section::Settings => self.handle_settings_browser_key(key, driver),
        }
    }

    fn handle_browser_root_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Left | KeyCode::BackTab => self.move_root_navigation(-1),
            KeyCode::Right | KeyCode::Tab => self.move_root_navigation(1),
            KeyCode::Enter | KeyCode::Down => {
                if self.root_navigation == RootNavigationTarget::ActiveChats {
                    self.return_to_open_conversations();
                } else {
                    self.browser_focus = BrowserFocus::Content;
                    match self.section {
                        Section::Contacts => {
                            self.contact_browser_pane = ContactBrowserPane::Contacts
                        }
                        Section::Groups => self.group_browser_pane = GroupBrowserPane::Groups,
                        Section::Settings => {}
                    }
                }
            }
            KeyCode::Esc => {}
            _ => {}
        }
    }

    fn move_root_navigation(&mut self, delta: isize) {
        let targets = root_navigation_targets(!self.workspace.is_empty());
        let current = targets
            .iter()
            .position(|target| *target == self.root_navigation)
            .or_else(|| {
                targets
                    .iter()
                    .position(|target| target.section() == Some(self.section))
            })
            .unwrap_or(0);
        let next = current
            .saturating_add_signed(delta)
            .min(targets.len().saturating_sub(1));
        self.root_navigation = targets[next];
        if let Some(section) = self.root_navigation.section() {
            self.section = section;
        }
    }

    fn return_to_open_conversations(&mut self) {
        if !self.workspace.is_empty() {
            self.view = View::Conversation;
            self.workspace.clear_active_missed_calls();
            self.status = "Returned to open conversations.".into();
        }
    }

    fn handle_contact_browser_key(&mut self, key: KeyEvent, driver: &mut ApplicationDriver) {
        match key.code {
            KeyCode::Tab => self.contact_browser_pane = self.contact_browser_pane.next(),
            KeyCode::BackTab => self.contact_browser_pane = self.contact_browser_pane.previous(),
            KeyCode::Left => {
                if self.contact_browser_pane == ContactBrowserPane::Actions {
                    self.contact_browser_pane = ContactBrowserPane::Contacts;
                }
            }
            KeyCode::Right => match self.contact_browser_pane {
                ContactBrowserPane::Contacts => {
                    self.contact_browser_pane = ContactBrowserPane::Actions
                }
                ContactBrowserPane::Actions => {
                    self.section = Section::Groups;
                    self.root_navigation = RootNavigationTarget::Groups;
                    self.group_browser_pane = GroupBrowserPane::Groups;
                }
            },
            KeyCode::Esc => {
                self.browser_focus = BrowserFocus::Root;
                self.root_navigation = RootNavigationTarget::Contacts;
            }
            KeyCode::Up | KeyCode::Char('k') => self.move_contact_browser_selection(driver, -1),
            KeyCode::Down | KeyCode::Char('j') => self.move_contact_browser_selection(driver, 1),
            KeyCode::Home => self.select_contact_browser_edge(driver, false),
            KeyCode::End => self.select_contact_browser_edge(driver, true),
            KeyCode::Char('n') => self.begin_new_contact(),
            KeyCode::Char('t') => self.open_new_transient(driver),
            KeyCode::Char('w') if !self.workspace.is_empty() => {
                self.return_to_open_conversations();
            }
            KeyCode::Char('u') => self.begin_unlock_confirmation(driver),
            KeyCode::Char('a') => self.begin_add_deaddrop(driver),
            KeyCode::Char('r') => self.begin_remove_deaddrop(driver),
            KeyCode::Char('s') => self.begin_tunnel_settings(driver),
            KeyCode::Char('h') => self.toggle_selected_history(driver),
            KeyCode::Enter => match self.contact_browser_pane {
                ContactBrowserPane::Contacts => self.open_selected(driver),
                ContactBrowserPane::Actions => self.execute_contact_browser_action(driver),
            },
            _ => {}
        }
    }

    fn handle_group_browser_key(&mut self, key: KeyEvent, driver: &mut ApplicationDriver) {
        match key.code {
            KeyCode::Tab => self.group_browser_pane = self.group_browser_pane.next(),
            KeyCode::BackTab => self.group_browser_pane = self.group_browser_pane.previous(),
            KeyCode::Left => match self.group_browser_pane {
                GroupBrowserPane::Groups => {
                    self.section = Section::Contacts;
                    self.root_navigation = RootNavigationTarget::Contacts;
                    self.contact_browser_pane = ContactBrowserPane::Contacts;
                }
                GroupBrowserPane::Members => self.group_browser_pane = GroupBrowserPane::Groups,
                GroupBrowserPane::Actions => self.group_browser_pane = GroupBrowserPane::Members,
            },
            KeyCode::Right => match self.group_browser_pane {
                GroupBrowserPane::Groups => self.group_browser_pane = GroupBrowserPane::Members,
                GroupBrowserPane::Members => self.group_browser_pane = GroupBrowserPane::Actions,
                GroupBrowserPane::Actions => {}
            },
            KeyCode::Esc => {
                self.browser_focus = BrowserFocus::Root;
                self.root_navigation = RootNavigationTarget::Groups;
            }
            KeyCode::Up | KeyCode::Char('k') => self.move_group_browser_selection(driver, -1),
            KeyCode::Down | KeyCode::Char('j') => self.move_group_browser_selection(driver, 1),
            KeyCode::Home => self.select_group_browser_edge(driver, false),
            KeyCode::End => self.select_group_browser_edge(driver, true),
            KeyCode::Char('n') => self.begin_new_group(),
            KeyCode::Char('g') => self.generate_public_group_invite(driver),
            KeyCode::Char('v') => self.copy_generated_public_invite(),
            KeyCode::Char('i') => self.begin_public_invite_import(),
            KeyCode::Char('p') => self.generate_private_group_request(driver),
            KeyCode::Char('c') => self.copy_private_group_request(),
            KeyCode::Char('b') => self.begin_private_request_answer(driver),
            KeyCode::Char('y') => self.copy_private_group_invite(),
            KeyCode::Char('m') => self.begin_group_name_input(driver),
            KeyCode::Char('h') => self.toggle_selected_history(driver),
            KeyCode::Enter => match self.group_browser_pane {
                GroupBrowserPane::Groups => self.open_selected(driver),
                GroupBrowserPane::Members => self.begin_group_member_removal(driver),
                GroupBrowserPane::Actions => self.execute_group_browser_action(driver),
            },
            _ => {}
        }
    }

    fn handle_settings_browser_key(&mut self, key: KeyEvent, driver: &mut ApplicationDriver) {
        match key.code {
            KeyCode::Esc => {
                self.browser_focus = BrowserFocus::Root;
                self.root_navigation = RootNavigationTarget::Settings;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected_settings_action =
                    moved_index(SettingsAction::ALL.len(), self.selected_settings_action, -1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected_settings_action =
                    moved_index(SettingsAction::ALL.len(), self.selected_settings_action, 1);
            }
            KeyCode::Home => self.selected_settings_action = 0,
            KeyCode::End => {
                self.selected_settings_action = SettingsAction::ALL.len().saturating_sub(1)
            }
            KeyCode::Enter => self.execute_settings_action(driver),
            _ => {}
        }
    }

    fn execute_settings_action(&mut self, driver: &mut ApplicationDriver) {
        let action = SettingsAction::ALL
            .get(self.selected_settings_action)
            .copied()
            .unwrap_or(SettingsAction::EditSamHost);
        let snapshot = match driver.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.status = error.to_string();
                return;
            }
        };
        if matches!(
            action,
            SettingsAction::EditSamHost
                | SettingsAction::EditSamPort
                | SettingsAction::ExportBackup
                | SettingsAction::RestoreBackup
                | SettingsAction::WipeAll
        ) && (!self.workspace.is_empty() || snapshot.has_open_or_pending_sessions)
        {
            self.status = "Close all chat sessions before this settings operation.".into();
            return;
        }
        let settings = snapshot.settings;
        match action {
            SettingsAction::EditSamHost => {
                self.settings_input = Some(SettingsInput::SamHost(settings.sam_host));
                self.status = "Enter the SAM host; Enter saves; Esc cancels.".into();
            }
            SettingsAction::EditSamPort => {
                self.settings_input = Some(SettingsInput::SamPort(settings.sam_port.to_string()));
                self.status = "Enter the SAM port; Enter saves; Esc cancels.".into();
            }
            SettingsAction::TestSam => match driver.dispatch_command(CommToolsCommand::TestSam) {
                Ok(_) => self.status = "Testing the configured SAM endpoint...".into(),
                Err(error) => self.status = format!("Test SAM: {error}"),
            },
            SettingsAction::DefaultTunnels => {
                self.settings_input = Some(SettingsInput::DefaultTunnels {
                    length: settings.default_tunnels.length,
                    quantity: settings.default_tunnels.quantity,
                    field: TunnelSettingField::Length,
                });
                self.status =
                    "Left/Right selects a field; Up/Down changes it; Enter saves; Esc cancels."
                        .into();
            }
            SettingsAction::ToggleLiveness => {
                let enabled = !settings.sam_liveness_enabled;
                match driver.dispatch_command(CommToolsCommand::SetSamLivenessEnabled(enabled)) {
                    Ok(_) => {
                        self.status = if enabled {
                            "Automatic SAM liveness monitoring enabled."
                        } else {
                            "Automatic SAM liveness monitoring disabled."
                        }
                        .into();
                    }
                    Err(error) => self.status = format!("Save SAM monitoring setting: {error}"),
                }
            }
            SettingsAction::ToggleFailureAction => {
                let action = match settings.sam_failure_action {
                    SamFailureAction::GracefulShutdown => SamFailureAction::WarningOnly,
                    SamFailureAction::WarningOnly => SamFailureAction::GracefulShutdown,
                };
                match driver.dispatch_command(CommToolsCommand::SetSamFailureAction(action)) {
                    Ok(_) => self.status = "SAM failure action saved.".into(),
                    Err(error) => self.status = format!("Save SAM failure action: {error}"),
                }
            }
            SettingsAction::ExportBackup => {
                self.settings_input = Some(SettingsInput::ExportBackup {
                    path: sibling_export_path(&self.vault_root, "-backup.ctbak")
                        .display()
                        .to_string(),
                    passphrase: Zeroizing::new(String::new()),
                    include_files: true,
                    field: BackupInputField::Path,
                });
                self.status =
                    "Enter path; Tab selects passphrase; Space toggles files; Enter exports."
                        .into();
            }
            SettingsAction::RestoreBackup => {
                self.settings_input = Some(SettingsInput::RestoreBackup {
                    path: sibling_export_path(&self.vault_root, "-backup.ctbak")
                        .display()
                        .to_string(),
                    passphrase: Zeroizing::new(String::new()),
                    restore_files: true,
                    field: BackupInputField::Path,
                });
                self.status =
                    "Enter path; Tab selects passphrase; Space toggles files; Enter continues."
                        .into();
            }
            SettingsAction::WipeAll => {
                self.settings_input = Some(SettingsInput::WipeAll {
                    passphrase: Zeroizing::new(String::new()),
                });
                self.status = "Enter the current vault passphrase, then press Enter.".into();
            }
        }
    }

    fn handle_settings_input_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Esc => {
                self.settings_input = None;
                self.status = "Settings unchanged.".into();
            }
            KeyCode::Enter => return self.save_settings_input(driver),
            KeyCode::Backspace => match self.settings_input.as_mut() {
                Some(SettingsInput::SamHost(value) | SettingsInput::SamPort(value)) => {
                    value.pop();
                }
                Some(
                    SettingsInput::ExportBackup {
                        path,
                        passphrase,
                        field,
                        ..
                    }
                    | SettingsInput::RestoreBackup {
                        path,
                        passphrase,
                        field,
                        ..
                    },
                ) => match field {
                    BackupInputField::Path => {
                        path.pop();
                    }
                    BackupInputField::Passphrase => {
                        passphrase.pop();
                    }
                },
                Some(SettingsInput::WipeAll { passphrase }) => {
                    passphrase.pop();
                }
                _ => {}
            },
            KeyCode::Char(' ') => match self.settings_input.as_mut() {
                Some(SettingsInput::ExportBackup {
                    include_files,
                    field: BackupInputField::Path,
                    ..
                }) => {
                    *include_files = !*include_files;
                }
                Some(SettingsInput::RestoreBackup {
                    restore_files,
                    field: BackupInputField::Path,
                    ..
                }) => {
                    *restore_files = !*restore_files;
                }
                Some(
                    SettingsInput::ExportBackup {
                        passphrase,
                        field: BackupInputField::Passphrase,
                        ..
                    }
                    | SettingsInput::RestoreBackup {
                        passphrase,
                        field: BackupInputField::Passphrase,
                        ..
                    },
                ) if passphrase.len() < 1_024 => passphrase.push(' '),
                Some(SettingsInput::WipeAll { passphrase }) if passphrase.len() < 1_024 => {
                    passphrase.push(' ');
                }
                _ => {}
            },
            KeyCode::Char(character) => match self.settings_input.as_mut() {
                Some(SettingsInput::SamHost(value)) if !character.is_control() => {
                    if value.len() < 255 {
                        value.push(character);
                    }
                }
                Some(SettingsInput::SamPort(value)) if character.is_ascii_digit() => {
                    if value.len() < 5 {
                        value.push(character);
                    }
                }
                Some(
                    SettingsInput::ExportBackup {
                        path,
                        passphrase,
                        field,
                        ..
                    }
                    | SettingsInput::RestoreBackup {
                        path,
                        passphrase,
                        field,
                        ..
                    },
                ) => match field {
                    BackupInputField::Path if !character.is_control() && path.len() < 4_096 => {
                        path.push(character);
                    }
                    BackupInputField::Passphrase
                        if !character.is_control() && passphrase.len() < 1_024 =>
                    {
                        passphrase.push(character);
                    }
                    _ => {}
                },
                Some(SettingsInput::WipeAll { passphrase })
                    if !character.is_control() && passphrase.len() < 1_024 =>
                {
                    passphrase.push(character);
                }
                Some(SettingsInput::DefaultTunnels { .. }) => match character {
                    '+' | '=' => self.adjust_default_tunnel_setting(1),
                    '-' => self.adjust_default_tunnel_setting(-1),
                    _ => {}
                },
                _ => {}
            },
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Left | KeyCode::Right => {
                match self.settings_input.as_mut() {
                    Some(SettingsInput::DefaultTunnels { field, .. }) => {
                        *field = match field {
                            TunnelSettingField::Length => TunnelSettingField::Quantity,
                            TunnelSettingField::Quantity => TunnelSettingField::Length,
                        };
                    }
                    Some(
                        SettingsInput::ExportBackup { field, .. }
                        | SettingsInput::RestoreBackup { field, .. },
                    ) => {
                        *field = match field {
                            BackupInputField::Path => BackupInputField::Passphrase,
                            BackupInputField::Passphrase => BackupInputField::Path,
                        };
                    }
                    _ => {}
                }
            }
            KeyCode::Up => self.adjust_default_tunnel_setting(1),
            KeyCode::Down => self.adjust_default_tunnel_setting(-1),
            _ => {}
        }
        ShellAction::Continue
    }

    fn adjust_default_tunnel_setting(&mut self, delta: i8) {
        let Some(SettingsInput::DefaultTunnels {
            length,
            quantity,
            field,
        }) = self.settings_input.as_mut()
        else {
            return;
        };
        match field {
            TunnelSettingField::Length => *length = length.saturating_add_signed(delta).clamp(1, 4),
            TunnelSettingField::Quantity => {
                *quantity = quantity.saturating_add_signed(delta).clamp(1, 5)
            }
        }
    }

    fn save_settings_input(&mut self, driver: &mut ApplicationDriver) -> ShellAction {
        let Some(input) = self.settings_input.clone() else {
            return ShellAction::Continue;
        };
        match input {
            SettingsInput::ExportBackup {
                path,
                passphrase,
                include_files,
                ..
            } => {
                if path.trim().is_empty() || passphrase.is_empty() {
                    self.status = "Backup path and passphrase are required.".into();
                    return ShellAction::Continue;
                }
                match driver.dispatch_command(CommToolsCommand::ExportBackup {
                    path: PathBuf::from(path.trim()),
                    passphrase,
                    include_files,
                }) {
                    Ok(CommToolsCommandResult::BackupExported(path)) => {
                        self.settings_input = None;
                        self.status = format!("Encrypted backup exported to {}", path.display());
                    }
                    Ok(_) => self.status = "Unexpected backup-export result.".into(),
                    Err(error) => self.status = format!("Export backup: {error}"),
                }
                return ShellAction::Continue;
            }
            SettingsInput::RestoreBackup {
                path,
                passphrase,
                restore_files,
                ..
            } => {
                if path.trim().is_empty() || passphrase.is_empty() {
                    self.status = "Backup path and passphrase are required.".into();
                    return ShellAction::Continue;
                }
                self.storage_confirmation = Some(StorageConfirmation::RestoreBackup {
                    path: PathBuf::from(path.trim()),
                    passphrase,
                    restore_files,
                });
                self.settings_input = None;
                self.status =
                    "Replace all contacts, groups, settings, and history from backup? y/n".into();
                return ShellAction::Continue;
            }
            SettingsInput::WipeAll { passphrase } => {
                if passphrase.is_empty() {
                    self.status = "Current vault passphrase is required.".into();
                    return ShellAction::Continue;
                }
                self.storage_confirmation = Some(StorageConfirmation::WipeAll { passphrase });
                self.settings_input = None;
                self.status =
                    "Permanently wipe the complete local vault and all received files? y/n".into();
                return ShellAction::Continue;
            }
            _ => {}
        }
        let result = match input {
            SettingsInput::SamHost(host) => driver
                .dispatch_command(CommToolsCommand::SetSamHost(host))
                .map(|_| ()),
            SettingsInput::SamPort(port) => match port.parse::<u16>() {
                Ok(port) => driver
                    .dispatch_command(CommToolsCommand::SetSamPort(port))
                    .map(|_| ()),
                Err(_) => {
                    self.status = "SAM port must be an integer from 1 to 65535.".into();
                    return ShellAction::Continue;
                }
            },
            SettingsInput::DefaultTunnels {
                length, quantity, ..
            } => driver
                .dispatch_command(CommToolsCommand::SetDefaultTunnelSettings(TunnelSettings {
                    length,
                    quantity,
                }))
                .map(|_| ()),
            SettingsInput::ExportBackup { .. }
            | SettingsInput::RestoreBackup { .. }
            | SettingsInput::WipeAll { .. } => unreachable!(),
        };
        match result {
            Ok(()) => {
                self.settings_input = None;
                self.status = "Settings saved.".into();
            }
            Err(error) => self.status = format!("Save settings: {error}"),
        }
        ShellAction::Continue
    }

    fn handle_storage_confirmation_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Char('y') => {
                let Some(confirmation) = self.storage_confirmation.take() else {
                    return ShellAction::Continue;
                };
                match confirmation {
                    StorageConfirmation::RestoreBackup {
                        path,
                        passphrase,
                        restore_files,
                    } => match driver.dispatch_command(CommToolsCommand::RestoreBackup {
                        path: path.clone(),
                        passphrase,
                        restore_files,
                    }) {
                        Ok(CommToolsCommandResult::BackupRestored(_)) => {
                            self.workspace = Workspace::default();
                            self.selected_contact_item = None;
                            self.selected_group = None;
                            self.normalize_selection(driver);
                            self.status =
                                format!("Encrypted backup restored from {}", path.display());
                        }
                        Ok(_) => self.status = "Unexpected backup-restore result.".into(),
                        Err(error) => self.status = format!("Restore backup: {error}"),
                    },
                    StorageConfirmation::WipeAll { passphrase } => {
                        match driver.dispatch_command(CommToolsCommand::AuthorizeWipeAll {
                            vault_passphrase: passphrase,
                        }) {
                            Ok(CommToolsCommandResult::WipeAllAuthorized) => {
                                self.status = "Wiping all local data...".into();
                                return ShellAction::WipeAll;
                            }
                            Ok(_) => self.status = "Unexpected wipe authorization result.".into(),
                            Err(error) => self.status = format!("Authorize wipe: {error}"),
                        }
                    }
                }
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                self.storage_confirmation = None;
                self.status = "Storage operation cancelled.".into();
            }
            _ => {}
        }
        ShellAction::Continue
    }

    fn begin_contact_backup_export(&mut self, driver: &ApplicationDriver) {
        let Some(contact) = selected_contact(driver, self.selected_persistent_contact_id()) else {
            self.status = "Export applies only to persistent contacts.".into();
            return;
        };
        if self.workspace.contains_contact(&contact.id) || contact.active {
            self.status = "Close the contact tab before exporting it.".into();
            return;
        }
        self.contact_backup_input = Some(ContactBackupInput {
            operation: ContactBackupOperation::Export {
                contact_id: contact.id.clone(),
                display_name: contact.display_name.clone(),
            },
            path: sibling_export_path(
                &self.vault_root,
                &format!("-contact-{}.ctcontact", contact.id),
            )
            .display()
            .to_string(),
            passphrase: Zeroizing::new(String::new()),
            include_history: true,
            field: BackupInputField::Path,
        });
        self.status =
            "Enter path; Tab selects passphrase; Space toggles history; Enter exports.".into();
    }

    fn begin_contact_backup_import(&mut self) {
        self.contact_backup_input = Some(ContactBackupInput {
            operation: ContactBackupOperation::Import,
            path: sibling_export_path(&self.vault_root, "-contact.ctcontact")
                .display()
                .to_string(),
            passphrase: Zeroizing::new(String::new()),
            include_history: false,
            field: BackupInputField::Path,
        });
        self.status =
            "Enter path; Tab selects passphrase; Enter inspects the contact backup.".into();
    }

    fn handle_contact_backup_input_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Esc => {
                self.contact_backup_input = None;
                self.status = "Contact backup operation cancelled.".into();
            }
            KeyCode::Enter => self.submit_contact_backup_input(driver),
            KeyCode::Backspace => {
                if let Some(input) = self.contact_backup_input.as_mut() {
                    match input.field {
                        BackupInputField::Path => {
                            input.path.pop();
                        }
                        BackupInputField::Passphrase => {
                            input.passphrase.pop();
                        }
                    }
                }
            }
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Left | KeyCode::Right => {
                if let Some(input) = self.contact_backup_input.as_mut() {
                    input.field = match input.field {
                        BackupInputField::Path => BackupInputField::Passphrase,
                        BackupInputField::Passphrase => BackupInputField::Path,
                    };
                }
            }
            KeyCode::Char(' ')
                if self.contact_backup_input.as_ref().is_some_and(|input| {
                    matches!(&input.operation, ContactBackupOperation::Export { .. })
                        && input.field == BackupInputField::Path
                }) =>
            {
                if let Some(input) = self.contact_backup_input.as_mut() {
                    input.include_history = !input.include_history;
                }
            }
            KeyCode::Char(character) => {
                let Some(input) = self.contact_backup_input.as_mut() else {
                    return ShellAction::Continue;
                };
                match input.field {
                    BackupInputField::Path
                        if !character.is_control() && input.path.len() < 4_096 =>
                    {
                        input.path.push(character);
                    }
                    BackupInputField::Passphrase
                        if !character.is_control() && input.passphrase.len() < 1_024 =>
                    {
                        input.passphrase.push(character);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        ShellAction::Continue
    }

    fn submit_contact_backup_input(&mut self, driver: &mut ApplicationDriver) {
        let Some(input) = self.contact_backup_input.clone() else {
            return;
        };
        if input.path.trim().is_empty() || input.passphrase.is_empty() {
            self.status = "Contact backup path and passphrase are required.".into();
            return;
        }
        let path = PathBuf::from(input.path.trim());
        match input.operation {
            ContactBackupOperation::Export {
                contact_id,
                display_name,
            } => match driver.dispatch_command(CommToolsCommand::ExportContactBackup {
                contact_id,
                path: path.clone(),
                passphrase: input.passphrase,
                include_history: input.include_history,
            }) {
                Ok(CommToolsCommandResult::ContactBackupExported(_)) => {
                    self.contact_backup_input = None;
                    self.status = format!(
                        "Encrypted contact backup for {display_name} exported to {}",
                        path.display()
                    );
                }
                Ok(_) => self.status = "Unexpected contact-export result.".into(),
                Err(error) => self.status = format!("Export contact: {error}"),
            },
            ContactBackupOperation::Import => {
                match driver.dispatch_command(CommToolsCommand::InspectContactBackup {
                    path: path.clone(),
                    passphrase: input.passphrase.clone(),
                }) {
                    Ok(CommToolsCommandResult::ContactBackupInspected(inspection)) => {
                        let replacement = inspection
                            .replacement_contact_id
                            .as_ref()
                            .map_or("new contact", |_| "replace existing contact");
                        let history = if inspection.includes_history {
                            "with history"
                        } else {
                            "without history"
                        };
                        self.status = format!(
                            "Import {} ({}, {replacement})? y/n",
                            inspection.display_name, history
                        );
                        self.contact_backup_confirmation = Some(ContactBackupConfirmation {
                            path,
                            passphrase: input.passphrase,
                            inspection,
                        });
                        self.contact_backup_input = None;
                    }
                    Ok(_) => self.status = "Unexpected contact-inspection result.".into(),
                    Err(error) => self.status = format!("Inspect contact backup: {error}"),
                }
            }
        }
    }

    fn handle_contact_backup_confirmation_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Char('y') => {
                let Some(confirmation) = self.contact_backup_confirmation.take() else {
                    return ShellAction::Continue;
                };
                let replace = confirmation.inspection.replacement_contact_id.is_some();
                match driver.dispatch_command(CommToolsCommand::ImportContactBackup {
                    path: confirmation.path,
                    passphrase: confirmation.passphrase,
                    replace,
                }) {
                    Ok(CommToolsCommandResult::ContactBackupImported(contact_id)) => {
                        self.selected_contact_item =
                            Some(ContactBrowserItem::Contact(contact_id.clone()));
                        self.status = format!(
                            "Imported encrypted contact backup: {}",
                            confirmation.inspection.display_name
                        );
                    }
                    Ok(_) => self.status = "Unexpected contact-import result.".into(),
                    Err(error) => self.status = format!("Import contact: {error}"),
                }
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                self.contact_backup_confirmation = None;
                self.status = "Contact import cancelled.".into();
            }
            _ => {}
        }
        ShellAction::Continue
    }

    fn begin_new_contact(&mut self) {
        self.create_kind = Some(CreateKind::Contact);
        self.input.clear();
        self.status.clear();
    }

    fn move_contact_browser_selection(&mut self, driver: &ApplicationDriver, delta: isize) {
        match self.contact_browser_pane {
            ContactBrowserPane::Contacts => {
                let items = contact_browser_items(driver, &self.workspace);
                self.selected_contact_item =
                    moved_id(&items, self.selected_contact_item.as_ref(), delta);
            }
            ContactBrowserPane::Actions => {
                self.selected_contact_action = moved_index(
                    ContactBrowserAction::ALL.len(),
                    self.selected_contact_action,
                    delta,
                );
            }
        }
    }

    fn select_contact_browser_edge(&mut self, driver: &ApplicationDriver, end: bool) {
        match self.contact_browser_pane {
            ContactBrowserPane::Contacts => {
                self.selected_contact_item =
                    edge_id(&contact_browser_items(driver, &self.workspace), end);
            }
            ContactBrowserPane::Actions => {
                self.selected_contact_action = edge_index(ContactBrowserAction::ALL.len(), end);
            }
        }
    }

    fn execute_contact_browser_action(&mut self, driver: &mut ApplicationDriver) {
        let action = ContactBrowserAction::ALL
            .get(self.selected_contact_action)
            .copied()
            .unwrap_or(ContactBrowserAction::NewContact);
        if !self.contact_action_available(action, driver) {
            self.status = "Selected contact action is unavailable in the current state.".into();
            return;
        }
        match action {
            ContactBrowserAction::NewContact => self.begin_new_contact(),
            ContactBrowserAction::NewTransient => self.open_new_transient(driver),
            ContactBrowserAction::OpenOrFocus => self.open_selected(driver),
            ContactBrowserAction::RenameContact => self.begin_contact_name_input(driver),
            ContactBrowserAction::ToggleHistory => self.toggle_selected_history(driver),
            ContactBrowserAction::ClearHistory => self.begin_contact_history_clear(driver),
            ContactBrowserAction::ExportContact => self.begin_contact_backup_export(driver),
            ContactBrowserAction::ImportContact => self.begin_contact_backup_import(),
            ContactBrowserAction::TunnelSettings => self.begin_tunnel_settings(driver),
            ContactBrowserAction::AddDeaddrop => self.begin_add_deaddrop(driver),
            ContactBrowserAction::RemoveDeaddrop => self.begin_remove_deaddrop(driver),
            ContactBrowserAction::UnlockContact => self.begin_unlock_confirmation(driver),
            ContactBrowserAction::ResetContact => self.begin_contact_reset(driver),
            ContactBrowserAction::DeleteContact => self.begin_contact_deletion(driver),
        }
    }

    fn contact_action_available(
        &self,
        action: ContactBrowserAction,
        driver: &ApplicationDriver,
    ) -> bool {
        let contact = selected_contact(driver, self.selected_persistent_contact_id());
        self.contact_action_available_for(action, contact.as_ref())
    }

    fn contact_action_available_for(
        &self,
        action: ContactBrowserAction,
        contact: Option<&ContactSummary>,
    ) -> bool {
        if matches!(
            action,
            ContactBrowserAction::NewContact
                | ContactBrowserAction::NewTransient
                | ContactBrowserAction::ImportContact
        ) {
            return true;
        }
        if action == ContactBrowserAction::OpenOrFocus {
            return self.selected_contact_item.is_some();
        }
        let Some(contact) = contact else {
            return false;
        };
        let closed = !self.workspace.contains_contact(&contact.id) && !contact.active;
        match action {
            ContactBrowserAction::ToggleHistory | ContactBrowserAction::ClearHistory => true,
            ContactBrowserAction::ExportContact => closed,
            ContactBrowserAction::RenameContact
            | ContactBrowserAction::TunnelSettings
            | ContactBrowserAction::AddDeaddrop => closed,
            ContactBrowserAction::RemoveDeaddrop => closed && contact.deaddrop_servers.len() > 1,
            ContactBrowserAction::UnlockContact => closed && contact.peer_pinned,
            ContactBrowserAction::ResetContact | ContactBrowserAction::DeleteContact => closed,
            ContactBrowserAction::NewContact
            | ContactBrowserAction::NewTransient
            | ContactBrowserAction::ImportContact
            | ContactBrowserAction::OpenOrFocus => true,
        }
    }

    fn begin_new_group(&mut self) {
        self.create_kind = Some(CreateKind::Group);
        self.input.clear();
        self.status.clear();
    }

    fn move_group_browser_selection(&mut self, driver: &ApplicationDriver, delta: isize) {
        match self.group_browser_pane {
            GroupBrowserPane::Groups => {
                let ids = group_ids(driver);
                self.selected_group = moved_id(&ids, self.selected_group.as_ref(), delta);
                self.selected_group_member = 0;
            }
            GroupBrowserPane::Members => {
                let count = selected_group(driver, self.selected_group.as_ref())
                    .as_ref()
                    .map(group_member_records)
                    .map_or(0, |members| members.len());
                self.selected_group_member = moved_index(count, self.selected_group_member, delta);
            }
            GroupBrowserPane::Actions => {
                self.selected_group_action = moved_index(
                    GroupBrowserAction::ALL.len(),
                    self.selected_group_action,
                    delta,
                );
            }
        }
    }

    fn select_group_browser_edge(&mut self, driver: &ApplicationDriver, end: bool) {
        match self.group_browser_pane {
            GroupBrowserPane::Groups => {
                self.selected_group = edge_id(&group_ids(driver), end);
                self.selected_group_member = 0;
            }
            GroupBrowserPane::Members => {
                let count = selected_group(driver, self.selected_group.as_ref())
                    .as_ref()
                    .map(group_member_records)
                    .map_or(0, |members| members.len());
                self.selected_group_member = edge_index(count, end);
            }
            GroupBrowserPane::Actions => {
                self.selected_group_action = edge_index(GroupBrowserAction::ALL.len(), end);
            }
        }
    }

    fn execute_group_browser_action(&mut self, driver: &mut ApplicationDriver) {
        let action = GroupBrowserAction::ALL
            .get(self.selected_group_action)
            .copied()
            .unwrap_or(GroupBrowserAction::NewGroup);
        if !self.group_action_available(action, driver) {
            self.status = "Selected group action is unavailable in the current state.".into();
            return;
        }
        match action {
            GroupBrowserAction::NewGroup => self.begin_new_group(),
            GroupBrowserAction::OpenGroup => self.open_selected(driver),
            GroupBrowserAction::LocalName => self.begin_group_name_input(driver),
            GroupBrowserAction::ToggleHistory => self.toggle_selected_history(driver),
            GroupBrowserAction::ClearHistory => self.begin_group_history_clear(driver),
            GroupBrowserAction::GeneratePublicInvite => self.generate_public_group_invite(driver),
            GroupBrowserAction::CopyPublicInvite => self.copy_generated_public_invite(),
            GroupBrowserAction::GeneratePrivateRequest => {
                self.generate_private_group_request(driver)
            }
            GroupBrowserAction::CopyPrivateRequest => self.copy_private_group_request(),
            GroupBrowserAction::AnswerPrivateRequest => self.begin_private_request_answer(driver),
            GroupBrowserAction::CopyPrivateInvite => self.copy_private_group_invite(),
            GroupBrowserAction::ImportInvite => self.begin_public_invite_import(),
            GroupBrowserAction::RemoveSelectedMember => self.begin_group_member_removal(driver),
            GroupBrowserAction::LeaveGroup => self.begin_group_leave(driver),
            GroupBrowserAction::DissolveGroup => self.begin_group_dissolution(driver),
            GroupBrowserAction::DeleteLocalGroup => self.begin_local_group_deletion(driver),
        }
    }

    fn group_action_available(
        &self,
        action: GroupBrowserAction,
        driver: &ApplicationDriver,
    ) -> bool {
        let group = selected_group(driver, self.selected_group.as_ref());
        self.group_action_available_for(action, group.as_ref())
    }

    fn group_action_available_for(
        &self,
        action: GroupBrowserAction,
        group: Option<&GroupSummary>,
    ) -> bool {
        if action.requires_group() && group.is_none() {
            return false;
        }
        match action {
            GroupBrowserAction::GeneratePublicInvite | GroupBrowserAction::AnswerPrivateRequest => {
                group.is_some_and(|group| !group.active)
            }
            GroupBrowserAction::CopyPublicInvite => group.is_some_and(|group| {
                self.generated_public_invite
                    .as_ref()
                    .is_some_and(|(group_id, _)| group_id == &group.id)
            }),
            GroupBrowserAction::CopyPrivateRequest => self.generated_private_request.is_some(),
            GroupBrowserAction::CopyPrivateInvite => group.is_some_and(|group| {
                self.generated_private_invite
                    .as_ref()
                    .is_some_and(|(group_id, _)| group_id == &group.id)
            }),
            GroupBrowserAction::RemoveSelectedMember => {
                self.group_member_removal_available_for(group)
            }
            GroupBrowserAction::LeaveGroup => group
                .is_some_and(|group| !group.owner && (!group.leave_pending || !group.owner_ready)),
            GroupBrowserAction::DissolveGroup => {
                group.is_some_and(|group| group.owner && !group.leave_pending)
            }
            GroupBrowserAction::DeleteLocalGroup => group.is_some_and(|group| !group.active),
            _ => true,
        }
    }

    fn begin_group_member_removal(&mut self, driver: &ApplicationDriver) {
        let Some(group) = selected_group(driver, self.selected_group.as_ref()) else {
            self.status = "No group is selected.".into();
            return;
        };
        if !group_is_owner(&group) {
            self.status = "Only the group owner can remove members.".into();
            return;
        }
        let members = group_member_records(&group);
        let Some(member) = members.get(self.selected_group_member) else {
            self.status = "No group member is selected.".into();
            return;
        };
        if group
            .owner_b32
            .as_deref()
            .is_some_and(|owner| owner.eq_ignore_ascii_case(&member.b32))
        {
            self.status = "The group owner cannot be removed.".into();
            return;
        }
        self.status = format!("Remove {} from {}? y/n", member.name, group.display_name);
        self.group_confirmation = Some(GroupConfirmation::RemoveMember {
            group_id: group.id.clone(),
            group_name: group.display_name.clone(),
            member_b32: member.b32.clone(),
            member_name: member.name.clone(),
        });
    }

    fn group_member_removal_available(&self, driver: &ApplicationDriver) -> bool {
        let group = selected_group(driver, self.selected_group.as_ref());
        self.group_member_removal_available_for(group.as_ref())
    }

    fn group_member_removal_available_for(&self, group: Option<&GroupSummary>) -> bool {
        let Some(group) = group else {
            return false;
        };
        if !group_is_owner(group) {
            return false;
        }
        let members = group_member_records(group);
        let Some(member) = members.get(self.selected_group_member) else {
            return false;
        };
        group
            .owner_b32
            .as_deref()
            .is_none_or(|owner| !owner.eq_ignore_ascii_case(&member.b32))
    }

    fn begin_local_group_deletion(&mut self, driver: &ApplicationDriver) {
        let Some(group) = selected_group(driver, self.selected_group.as_ref()) else {
            self.status = "No group is selected.".into();
            return;
        };
        if group.active {
            self.status = "Close the group conversation before deleting its local data.".into();
            return;
        }
        self.status = format!(
            "Delete local group {}? Other participants and their group records are unaffected. y/n",
            group.display_name
        );
        self.group_confirmation = Some(GroupConfirmation::DeleteLocalGroup {
            group_id: group.id.clone(),
            group_name: group.display_name.clone(),
        });
    }

    fn begin_group_leave(&mut self, driver: &ApplicationDriver) {
        let Some(group) = selected_group(driver, self.selected_group.as_ref()) else {
            self.status = "No group is selected.".into();
            return;
        };
        if group_is_owner(&group) {
            self.status = "The group owner cannot leave; use local deletion if appropriate.".into();
            return;
        }
        let owner_is_ready = group.owner_ready;
        if group.leave_pending && owner_is_ready {
            self.status = "A leave operation is already pending for this group.".into();
            return;
        }
        let mode = if owner_is_ready {
            self.status = format!(
                "Leave {}? The owner will remove this identity from the signed roster. y/n",
                group.display_name
            );
            GroupLeaveMode::Authoritative
        } else {
            self.status = format!(
                "Owner unavailable. Leave {} locally? Other peers may retain its stale address. y/n",
                group.display_name
            );
            GroupLeaveMode::LocalOnly
        };
        self.group_confirmation = Some(GroupConfirmation::LeaveGroup {
            group_id: group.id.clone(),
            group_name: group.display_name.clone(),
            mode,
        });
    }

    fn begin_group_dissolution(&mut self, driver: &ApplicationDriver) {
        let Some(group) = selected_group(driver, self.selected_group.as_ref()) else {
            self.status = "No group is selected.".into();
            return;
        };
        if !group_is_owner(&group) {
            self.status = "Only the group owner can dissolve the group.".into();
            return;
        }
        if group.leave_pending {
            self.status = "This group is already closing.".into();
            return;
        }
        self.status = format!(
            "Dissolve {}? Connected participants will delete it; offline participants remain stale. y/n",
            group.display_name
        );
        self.group_confirmation = Some(GroupConfirmation::DissolveGroup {
            group_id: group.id.clone(),
            group_name: group.display_name.clone(),
        });
    }

    fn handle_group_confirmation_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Char('y') => {
                let Some(confirmation) = self.group_confirmation.take() else {
                    return ShellAction::Continue;
                };
                match confirmation {
                    GroupConfirmation::DeleteLocalGroup {
                        group_id,
                        group_name,
                    } => match driver.dispatch_command(CommToolsCommand::DeleteGroup {
                        group_id: group_id.clone(),
                    }) {
                        Ok(CommToolsCommandResult::GroupDeleted(_)) => {
                            self.clear_generated_group_material(&group_id);
                            self.selected_group = None;
                            self.selected_group_member = 0;
                            self.status = format!("Deleted local group: {group_name}");
                        }
                        Ok(_) => self.status = "Unexpected group-delete result.".into(),
                        Err(error) => self.status = error.to_string(),
                    },
                    GroupConfirmation::RemoveMember {
                        group_id,
                        group_name,
                        member_b32,
                        member_name,
                    } => match driver.dispatch_command(CommToolsCommand::RemoveGroupMember {
                        group_id,
                        member_b32,
                    }) {
                        Ok(CommToolsCommandResult::GroupMemberRemoval { removed: true }) => {
                            self.status = format!("Removed {member_name} from {group_name}.");
                        }
                        Ok(CommToolsCommandResult::GroupMemberRemoval { removed: false }) => {
                            self.status = format!("{member_name} is no longer in {group_name}.");
                        }
                        Ok(_) => self.status = "Unexpected group-member removal result.".into(),
                        Err(error) => self.status = error.to_string(),
                    },
                    GroupConfirmation::LeaveGroup {
                        group_id,
                        group_name,
                        mode,
                    } => match mode {
                        GroupLeaveMode::Authoritative => {
                            match driver.dispatch_command(CommToolsCommand::RequestGroupLeave {
                                group_id: group_id.clone(),
                            }) {
                                Ok(CommToolsCommandResult::GroupLeaveRequested) => {
                                    self.clear_generated_group_material(&group_id);
                                    self.status = format!(
                                        "Leave request sent for {group_name}; waiting for the owner's signed roster."
                                    );
                                }
                                Ok(_) => {
                                    self.status = "Unexpected group-leave result.".into();
                                }
                                Err(error) => self.status = error.to_string(),
                            }
                        }
                        GroupLeaveMode::LocalOnly => {
                            match driver.dispatch_command(CommToolsCommand::LeaveGroupLocally {
                                group_id: group_id.clone(),
                            }) {
                                Ok(CommToolsCommandResult::GroupLocalLeaveStarted {
                                    deleted_immediately: true,
                                }) => {
                                    self.clear_generated_group_material(&group_id);
                                    self.selected_group = None;
                                    self.selected_group_member = 0;
                                    self.status = format!("Left local group: {group_name}");
                                }
                                Ok(CommToolsCommandResult::GroupLocalLeaveStarted {
                                    deleted_immediately: false,
                                }) => {
                                    self.clear_generated_group_material(&group_id);
                                    self.status = format!(
                                        "Closing {group_name}; local group data will be deleted after shutdown."
                                    );
                                }
                                Ok(_) => {
                                    self.status = "Unexpected local group-leave result.".into()
                                }
                                Err(error) => self.status = error.to_string(),
                            }
                        }
                    },
                    GroupConfirmation::DissolveGroup {
                        group_id,
                        group_name,
                    } => match driver.dispatch_command(CommToolsCommand::DissolveGroup {
                        group_id: group_id.clone(),
                    }) {
                        Ok(CommToolsCommandResult::GroupDissolutionStarted {
                            deleted_immediately: true,
                        }) => {
                            self.clear_generated_group_material(&group_id);
                            self.selected_group = None;
                            self.selected_group_member = 0;
                            self.status = format!("Dissolved local group: {group_name}");
                        }
                        Ok(CommToolsCommandResult::GroupDissolutionStarted {
                            deleted_immediately: false,
                        }) => {
                            self.clear_generated_group_material(&group_id);
                            self.status = format!(
                                "Dissolving {group_name}; local data will be deleted after shutdown."
                            );
                        }
                        Ok(_) => self.status = "Unexpected group-dissolution result.".into(),
                        Err(error) => self.status = error.to_string(),
                    },
                }
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                self.group_confirmation = None;
                self.status = "Group operation cancelled.".into();
            }
            _ => {}
        }
        self.normalize_selection(driver);
        ShellAction::Continue
    }

    fn clear_generated_group_material(&mut self, group_id: &GroupId) {
        if self
            .generated_public_invite
            .as_ref()
            .is_some_and(|(generated_for, _)| generated_for == group_id)
        {
            self.generated_public_invite = None;
        }
        if self
            .generated_private_invite
            .as_ref()
            .is_some_and(|(generated_for, _)| generated_for == group_id)
        {
            self.generated_private_invite = None;
        }
    }

    fn handle_conversation_key(&mut self, key: KeyEvent, driver: &mut ApplicationDriver) {
        if self.workspace.rendezvous_panel_open() {
            self.handle_rendezvous_panel_key(key, driver);
            return;
        }
        if self.workspace.active_logs_open() {
            self.handle_log_panel_key(key);
            return;
        }
        match key.code {
            KeyCode::Esc => {
                if self.workspace.clear_active_message_selection() {
                    self.status.clear();
                } else {
                    self.view = View::Browser;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                match self.workspace.move_active_message_selection(-1) {
                    Ok(()) => {
                        self.status = self
                            .workspace
                            .active_original_image_selection_hint()
                            .or_else(|| self.workspace.active_file_selection_hint())
                            .unwrap_or("Text message selected; c copies and r replies.")
                            .into()
                    }
                    Err(error) => self.status = error,
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                match self.workspace.move_active_message_selection(1) {
                    Ok(()) => {
                        self.status = self
                            .workspace
                            .active_original_image_selection_hint()
                            .or_else(|| self.workspace.active_file_selection_hint())
                            .unwrap_or("Text message selected; c copies and r replies.")
                            .into()
                    }
                    Err(error) => self.status = error,
                }
            }
            KeyCode::PageUp => self.workspace.scroll_active_page_up(),
            KeyCode::PageDown => self.workspace.scroll_active_page_down(),
            KeyCode::Home => self.workspace.scroll_active_to_oldest(),
            KeyCode::End => self.workspace.scroll_active_to_latest(),
            KeyCode::Char('i') => self.workspace.toggle_active_details(),
            KeyCode::Char('L') => match self.workspace.toggle_active_logs() {
                Ok(true) => self.status = "Conversation logs opened.".into(),
                Ok(false) => self.status = "Conversation logs closed.".into(),
                Err(error) => self.status = error,
            },
            KeyCode::Char('1') => self.copy_active_address(driver, true),
            KeyCode::Char('2') => self.copy_active_address(driver, false),
            KeyCode::Tab | KeyCode::Right | KeyCode::Char(']') => {
                self.workspace.select_next();
                self.status.clear();
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('[') => {
                self.workspace.select_previous();
                self.status.clear();
            }
            KeyCode::Char('x') => match self.workspace.close_active(driver) {
                Ok(CloseDisposition::Removed) => {
                    self.status = "Closed conversation.".into();
                    if self.workspace.is_empty() {
                        self.view = View::Browser;
                    }
                }
                Ok(CloseDisposition::Closing) => {
                    self.status = "Closing conversation.".into();
                }
                Ok(CloseDisposition::Opening) => {
                    self.status = "Contact is still opening.".into();
                }
                Ok(CloseDisposition::None) => {}
                Err(error) => self.status = error.to_string(),
            },
            KeyCode::Char('c') => {
                if self.workspace.active_selected_message_is_text()
                    || (!self.workspace.active_message_selected()
                        && self.workspace.active_is_group())
                {
                    self.copy_selected_message();
                } else if self.workspace.active_message_selected() {
                    self.status = self
                        .workspace
                        .active_file_selection_hint()
                        .unwrap_or("The selected entry cannot be copied.")
                        .into();
                } else {
                    match self.workspace.begin_connect_input(driver) {
                        Ok(()) => self.status = "Enter the peer B32 address.".into(),
                        Err(error) => self.status = error,
                    }
                }
            }
            KeyCode::Char('z') => match self.workspace.toggle_rendezvous_panel(driver) {
                Ok(true) => self.status = "Authenticated rendezvous opened.".into(),
                Ok(false) => self.status = "Authenticated rendezvous closed.".into(),
                Err(error) => self.status = error,
            },
            KeyCode::Char('r') => match self.workspace.begin_reply_to_selected() {
                Ok(author) => self.status = format!("Replying to {author}."),
                Err(error) => self.status = error,
            },
            KeyCode::Char('g') => match self.workspace.request_selected_original_image(driver) {
                Ok(status) => self.status = status,
                Err(error) => self.status = error,
            },
            KeyCode::Char('y') => {
                if self.workspace.active_file_selection_hint().is_some() {
                    match self.workspace.accept_selected_file_offer(driver) {
                        Ok(filename) => self.status = format!("Accepted file: {filename}"),
                        Err(error) => self.status = error,
                    }
                } else {
                    match self.workspace.accept_incoming(driver) {
                        Ok(()) => self.status = "Incoming call accepted.".into(),
                        Err(error) => self.status = error,
                    }
                }
            }
            KeyCode::Char('n') => {
                if self.workspace.active_file_selection_hint().is_some() {
                    match self.workspace.decline_selected_file_offer(driver) {
                        Ok(filename) => self.status = format!("Declined file: {filename}"),
                        Err(error) => self.status = error,
                    }
                } else {
                    match self.workspace.decline_incoming(driver) {
                        Ok(()) => self.status = "Incoming call declined.".into(),
                        Err(error) => self.status = error,
                    }
                }
            }
            KeyCode::Char('X') => {
                if self
                    .workspace
                    .active_original_image_selection_hint()
                    .is_some()
                {
                    match self.workspace.cancel_selected_original_image(driver) {
                        Ok(status) => self.status = status,
                        Err(error) => self.status = error,
                    }
                } else {
                    match self.workspace.cancel_selected_file_transfer(driver) {
                        Ok(filename) => {
                            self.status = format!("Cancelled file transfer: {filename}")
                        }
                        Err(error) => self.status = error,
                    }
                }
            }
            KeyCode::Char('d') => match self.workspace.disconnect_contact(driver) {
                Ok(()) => self.status = "Disconnecting from peer.".into(),
                Err(error) => self.status = error,
            },
            KeyCode::Char('o') => match self.workspace.toggle_contact_offline(driver) {
                Ok(OfflineToggleDisposition::Entered) => {
                    self.status = "Entered offline mode.".into();
                }
                Ok(OfflineToggleDisposition::Left) => {
                    self.status = "Returned to online standby.".into();
                }
                Err(error) => self.status = error,
            },
            KeyCode::Char('l') => match self.workspace.active_contact_lock_candidate(driver) {
                Ok((session_id, peer_b32)) => {
                    self.status = format!("Lock this contact to {peer_b32}? y/n");
                    self.trust_confirmation = Some(TrustConfirmation::Lock {
                        session_id,
                        peer_b32,
                    });
                }
                Err(error) => self.status = error,
            },
            KeyCode::Char('m') => match self.workspace.begin_message_input() {
                Ok(()) => self.status = "Enter a message.".into(),
                Err(error) => self.status = error,
            },
            KeyCode::Char('a') => match self.workspace.begin_image_input() {
                Ok(()) => {
                    self.file_chooser = Some(FileChooserState::new(FileChooserKind::Image));
                    self.status = "Select an image; Enter selects and Esc cancels.".into();
                }
                Err(error) => self.status = error,
            },
            KeyCode::Char('f') => match self.workspace.begin_file_input() {
                Ok(()) => {
                    self.file_chooser = Some(FileChooserState::new(FileChooserKind::File));
                    self.status = "Select a file; Enter selects and Esc cancels.".into();
                }
                Err(error) => self.status = error,
            },
            _ => {}
        }
    }

    fn handle_log_panel_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('L') => match self.workspace.toggle_active_logs() {
                Ok(_) => self.status = "Conversation logs closed.".into(),
                Err(error) => self.status = error,
            },
            KeyCode::PageUp => self.workspace.scroll_active_logs_page_up(),
            KeyCode::PageDown => self.workspace.scroll_active_logs_page_down(),
            KeyCode::Home => self.workspace.scroll_active_logs_to_oldest(),
            KeyCode::End => self.workspace.scroll_active_logs_to_latest(),
            KeyCode::Tab | KeyCode::Right | KeyCode::Char(']') => {
                self.workspace.select_next();
                self.status.clear();
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('[') => {
                self.workspace.select_previous();
                self.status.clear();
            }
            KeyCode::Char('c') => match self.workspace.active_logs_copy_text() {
                Ok((line_count, logs)) => {
                    self.pending_clipboard = Some(Zeroizing::new(logs));
                    self.pending_log_copy_lines = Some(line_count);
                    self.status = format!("Copying {line_count} log lines.");
                }
                Err(error) => self.status = error,
            },
            _ => {}
        }
    }

    fn copy_active_address(&mut self, driver: &ApplicationDriver, local: bool) {
        match self.workspace.active_copy_address(driver, local) {
            Ok((label, address)) => {
                self.pending_clipboard = Some(Zeroizing::new(address));
                self.status = format!("Copying {label}.");
            }
            Err(error) => self.status = error,
        }
    }

    fn copy_selected_message(&mut self) {
        match self.workspace.active_selected_message_copy_text() {
            Ok(text) => {
                self.pending_clipboard = Some(Zeroizing::new(text));
                self.status = "Copying selected message.".into();
            }
            Err(error) => self.status = error,
        }
    }

    fn handle_file_chooser_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }

        let mutation_key = self
            .file_chooser
            .as_ref()
            .is_some_and(|chooser| !chooser.explorer.is_searching())
            && matches!(key.code, KeyCode::Char('n' | 'N' | 'r') | KeyCode::Delete);
        if mutation_key {
            self.status = "The file chooser is read-only.".into();
            return ShellAction::Continue;
        }

        let Some(chooser) = self.file_chooser.as_mut() else {
            return ShellAction::Continue;
        };
        let kind = chooser.kind;
        match chooser.explorer.handle_key(key) {
            ExplorerOutcome::Selected(path) => {
                self.file_chooser = None;
                let result = match kind {
                    FileChooserKind::Image => {
                        self.workspace
                            .set_image_input(path.to_string_lossy().into_owned());
                        self.workspace
                            .submit_image(driver)
                            .map(|filename| format!("Image queued: {filename}"))
                    }
                    FileChooserKind::File => {
                        self.workspace
                            .set_file_input(path.to_string_lossy().into_owned());
                        self.workspace
                            .submit_file(driver)
                            .map(|filename| format!("File offered: {filename}"))
                    }
                };
                self.status = match result {
                    Ok(status) => status,
                    Err(error) => {
                        match kind {
                            FileChooserKind::Image => self.workspace.cancel_image_input(),
                            FileChooserKind::File => self.workspace.cancel_file_input(),
                        }
                        error
                    }
                };
            }
            ExplorerOutcome::Dismissed => {
                self.file_chooser = None;
                match kind {
                    FileChooserKind::Image => self.workspace.cancel_image_input(),
                    FileChooserKind::File => self.workspace.cancel_file_input(),
                }
                self.status = "File selection cancelled.".into();
            }
            _ => {}
        }
        ShellAction::Continue
    }

    fn handle_trust_confirmation_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Char('y') => {
                let Some(confirmation) = self.trust_confirmation.take() else {
                    return ShellAction::Continue;
                };
                match confirmation {
                    TrustConfirmation::Lock {
                        session_id,
                        peer_b32,
                    } => match driver
                        .dispatch_command(CommToolsCommand::LockContactPeer { session_id })
                    {
                        Ok(CommToolsCommandResult::ContactPeerLocked(locked_peer)) => {
                            self.workspace.mark_contact_tofu_verified(session_id);
                            self.status = format!("Locked contact to {locked_peer}.");
                        }
                        Ok(_) => self.status = "Unexpected contact-lock result.".into(),
                        Err(error) => {
                            self.status = format!("Lock {peer_b32} failed: {error}");
                        }
                    },
                    TrustConfirmation::Unlock {
                        contact_id,
                        display_name,
                    } => match driver
                        .dispatch_command(CommToolsCommand::UnlockContact { contact_id })
                    {
                        Ok(CommToolsCommandResult::ContactUnlocked {
                            cleared_offline_state: true,
                        }) => {
                            self.status = format!(
                                "Unlocked {display_name}; peer-bound offline state was cleared."
                            );
                        }
                        Ok(CommToolsCommandResult::ContactUnlocked {
                            cleared_offline_state: false,
                        }) => self.status = format!("Unlocked {display_name}."),
                        Ok(_) => self.status = "Unexpected contact-unlock result.".into(),
                        Err(error) => self.status = error.to_string(),
                    },
                }
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                self.trust_confirmation = None;
                self.status = "Trust change cancelled.".into();
            }
            _ => {}
        }
        ShellAction::Continue
    }

    fn begin_unlock_confirmation(&mut self, driver: &ApplicationDriver) {
        let Some(contact) = selected_contact(driver, self.selected_persistent_contact_id()) else {
            self.status = "Unlock applies only to persistent contacts.".into();
            return;
        };
        if !contact.peer_pinned {
            self.status = "Selected contact is already unlocked.".into();
            return;
        }
        if contact.active {
            self.status = "Close the contact tab before unlocking its stored peer.".into();
            return;
        }
        let contact_id = contact.id.clone();
        let display_name = contact.display_name.clone();
        self.status = format!("Unlock {display_name} from its stored peer? y/n");
        self.trust_confirmation = Some(TrustConfirmation::Unlock {
            contact_id,
            display_name,
        });
    }

    fn begin_contact_name_input(&mut self, driver: &ApplicationDriver) {
        let Some(contact) = selected_contact(driver, self.selected_persistent_contact_id()) else {
            self.status = "Rename applies only to persistent contacts.".into();
            return;
        };
        if self.workspace.contains_contact(&contact.id) || contact.active {
            self.status = "Close the contact tab before renaming it.".into();
            return;
        }
        self.contact_name_input = Some(contact.id.clone());
        self.input = contact.display_name.clone();
        self.status = "Enter the new contact name, then press Enter.".into();
    }

    fn begin_contact_deletion(&mut self, driver: &ApplicationDriver) {
        let Some(contact) = selected_contact(driver, self.selected_persistent_contact_id()) else {
            self.status = "Delete applies only to persistent contacts.".into();
            return;
        };
        if self.workspace.contains_contact(&contact.id) || contact.active {
            self.status = "Close the contact tab before deleting it.".into();
            return;
        }
        self.status = format!("Delete contact {}? y/n", contact.display_name);
        self.contact_deletion_confirmation = Some(ContactDeletionConfirmation {
            contact_id: contact.id.clone(),
            display_name: contact.display_name.clone(),
        });
    }

    fn begin_contact_reset(&mut self, driver: &ApplicationDriver) {
        let Some(contact) = selected_contact(driver, self.selected_persistent_contact_id()) else {
            self.status = "Reset applies only to persistent contacts.".into();
            return;
        };
        if self.workspace.contains_contact(&contact.id) || contact.active {
            self.status = "Close the contact tab before resetting it.".into();
            return;
        }
        self.status = format!(
            "Reset {} trust, offline state, history, and deaddrop statistics? y/n",
            contact.display_name
        );
        self.contact_reset_confirmation = Some(ContactDeletionConfirmation {
            contact_id: contact.id.clone(),
            display_name: contact.display_name.clone(),
        });
    }

    fn handle_contact_reset_confirmation_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Char('y') => {
                let Some(confirmation) = self.contact_reset_confirmation.take() else {
                    return ShellAction::Continue;
                };
                match driver.dispatch_command(CommToolsCommand::ResetContact {
                    contact_id: confirmation.contact_id,
                }) {
                    Ok(CommToolsCommandResult::ContactReset(_)) => {
                        self.status = format!("Reset contact: {}", confirmation.display_name);
                    }
                    Ok(_) => self.status = "Unexpected contact-reset result.".into(),
                    Err(error) => self.status = format!("Reset contact: {error}"),
                }
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                self.contact_reset_confirmation = None;
                self.status = "Contact reset cancelled.".into();
            }
            _ => {}
        }
        ShellAction::Continue
    }

    fn handle_contact_deletion_confirmation_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Char('y') => {
                let Some(confirmation) = self.contact_deletion_confirmation.take() else {
                    return ShellAction::Continue;
                };
                match driver.dispatch_command(CommToolsCommand::DeleteContact {
                    contact_id: confirmation.contact_id.clone(),
                }) {
                    Ok(CommToolsCommandResult::ContactDeleted(_)) => {
                        self.selected_contact_item = None;
                        self.status = format!("Deleted contact: {}", confirmation.display_name);
                    }
                    Ok(_) => self.status = "Unexpected contact-delete result.".into(),
                    Err(error) => self.status = error.to_string(),
                }
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                self.contact_deletion_confirmation = None;
                self.status = "Contact deletion cancelled.".into();
            }
            _ => {}
        }
        self.normalize_selection(driver);
        ShellAction::Continue
    }

    fn handle_contact_name_input_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Esc => {
                self.contact_name_input = None;
                self.input.clear();
                self.status = "Contact rename cancelled.".into();
            }
            KeyCode::Backspace => {
                self.input.pop();
                self.status.clear();
            }
            KeyCode::Enter => self.submit_contact_name(driver),
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                    && !character.is_control() =>
            {
                self.push_input(character);
            }
            _ => {}
        }
        ShellAction::Continue
    }

    fn submit_contact_name(&mut self, driver: &mut ApplicationDriver) {
        let Some(contact_id) = self.contact_name_input.clone() else {
            return;
        };
        let name = self.input.trim().to_string();
        if name.is_empty() {
            self.status = "Contact name must not be empty.".into();
            return;
        }
        match driver.dispatch_command(CommToolsCommand::RenameContact {
            contact_id,
            display_name: name,
        }) {
            Ok(CommToolsCommandResult::ContactRenamed(name)) => {
                self.contact_name_input = None;
                self.input.clear();
                self.status = format!("Renamed contact: {name}");
            }
            Ok(_) => self.status = "Unexpected contact-rename result.".into(),
            Err(error) => self.status = error.to_string(),
        }
    }

    fn begin_add_deaddrop(&mut self, driver: &ApplicationDriver) {
        let Some(contact) = selected_contact(driver, self.selected_persistent_contact_id()) else {
            self.status = "Deaddrop settings apply only to persistent contacts.".into();
            return;
        };
        if self.workspace.contains_contact(&contact.id) || contact.active {
            self.status = "Close the contact tab before changing its deaddrop servers.".into();
            return;
        }
        self.deaddrop_input = Some(DeaddropInput::Add {
            contact_id: contact.id.clone(),
            display_name: contact.display_name.clone(),
        });
        self.input.clear();
        self.status = "Enter a deaddrop server B32 address.".into();
    }

    fn begin_remove_deaddrop(&mut self, driver: &ApplicationDriver) {
        let Some(contact) = selected_contact(driver, self.selected_persistent_contact_id()) else {
            self.status = "Deaddrop settings apply only to persistent contacts.".into();
            return;
        };
        if self.workspace.contains_contact(&contact.id) || contact.active {
            self.status = "Close the contact tab before changing its deaddrop servers.".into();
            return;
        }
        if contact.deaddrop_servers.len() <= 1 {
            self.status = "A contact must retain at least one deaddrop server.".into();
            return;
        }
        self.deaddrop_input = Some(DeaddropInput::Remove {
            contact_id: contact.id.clone(),
            display_name: contact.display_name.clone(),
        });
        self.input.clear();
        self.status = "Enter the number of the deaddrop server to remove.".into();
    }

    fn begin_tunnel_settings(&mut self, driver: &ApplicationDriver) {
        let Some(contact) = selected_contact(driver, self.selected_persistent_contact_id()) else {
            self.status = "Tunnel settings apply only to persistent contacts.".into();
            return;
        };
        if self.workspace.contains_contact(&contact.id) || contact.active {
            self.status = "Close the contact tab before changing its tunnel settings.".into();
            return;
        }
        self.tunnel_settings_input = Some(TunnelSettingsInput {
            contact_id: contact.id.clone(),
            display_name: contact.display_name.clone(),
            length: contact.tunnels.length,
            quantity: contact.tunnels.quantity,
            field: TunnelSettingField::Length,
        });
        self.status =
            "Left/Right selects a field; Up/Down changes it; Enter saves; Esc cancels.".into();
    }

    fn handle_tunnel_settings_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Esc => {
                self.tunnel_settings_input = None;
                self.status = "Tunnel settings unchanged.".into();
            }
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Left | KeyCode::Right => {
                let Some(input) = self.tunnel_settings_input.as_mut() else {
                    return ShellAction::Continue;
                };
                input.field = match input.field {
                    TunnelSettingField::Length => TunnelSettingField::Quantity,
                    TunnelSettingField::Quantity => TunnelSettingField::Length,
                };
            }
            KeyCode::Up | KeyCode::Char('+') | KeyCode::Char('=') => {
                self.adjust_tunnel_setting(1);
            }
            KeyCode::Down | KeyCode::Char('-') => self.adjust_tunnel_setting(-1),
            KeyCode::Home => self.set_tunnel_setting_to_bound(false),
            KeyCode::End => self.set_tunnel_setting_to_bound(true),
            KeyCode::Enter => {
                let Some(input) = self.tunnel_settings_input.clone() else {
                    return ShellAction::Continue;
                };
                match driver.dispatch_command(CommToolsCommand::SetContactTunnelSettings {
                    contact_id: input.contact_id.clone(),
                    tunnels: TunnelSettings {
                        length: input.length,
                        quantity: input.quantity,
                    },
                }) {
                    Ok(CommToolsCommandResult::ContactTunnelSettingsApplied(_)) => {
                        self.tunnel_settings_input = None;
                        self.status = format!(
                            "Saved {} tunnel settings: length {}, quantity {}.",
                            input.display_name, input.length, input.quantity
                        );
                    }
                    Ok(_) => self.status = "Unexpected contact-tunnel result.".into(),
                    Err(error) => self.status = format!("Save tunnel settings: {error}"),
                }
            }
            _ => {}
        }
        ShellAction::Continue
    }

    fn adjust_tunnel_setting(&mut self, delta: i8) {
        let Some(input) = self.tunnel_settings_input.as_mut() else {
            return;
        };
        let (value, minimum, maximum) = match input.field {
            TunnelSettingField::Length => (
                &mut input.length,
                commtools_core::sam::MIN_TUNNEL_LENGTH,
                commtools_core::sam::MAX_TUNNEL_LENGTH,
            ),
            TunnelSettingField::Quantity => (
                &mut input.quantity,
                commtools_core::sam::MIN_TUNNEL_QUANTITY,
                commtools_core::sam::MAX_TUNNEL_QUANTITY,
            ),
        };
        *value = adjusted_tunnel_value(*value, delta, minimum, maximum);
    }

    fn set_tunnel_setting_to_bound(&mut self, maximum: bool) {
        let Some(input) = self.tunnel_settings_input.as_mut() else {
            return;
        };
        match input.field {
            TunnelSettingField::Length => {
                input.length = if maximum {
                    commtools_core::sam::MAX_TUNNEL_LENGTH
                } else {
                    commtools_core::sam::MIN_TUNNEL_LENGTH
                };
            }
            TunnelSettingField::Quantity => {
                input.quantity = if maximum {
                    commtools_core::sam::MAX_TUNNEL_QUANTITY
                } else {
                    commtools_core::sam::MIN_TUNNEL_QUANTITY
                };
            }
        }
    }

    fn handle_deaddrop_input_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Esc => {
                self.deaddrop_input = None;
                self.input.clear();
                self.status = "Deaddrop server change cancelled.".into();
            }
            KeyCode::Backspace => {
                self.input.pop();
                self.status.clear();
            }
            KeyCode::Enter => self.submit_deaddrop_input(driver),
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.push_input(character);
            }
            _ => {}
        }
        ShellAction::Continue
    }

    fn submit_deaddrop_input(&mut self, driver: &mut ApplicationDriver) {
        let Some(operation) = self.deaddrop_input.clone() else {
            return;
        };
        match operation {
            DeaddropInput::Add {
                contact_id,
                display_name,
            } => match driver.dispatch_command(CommToolsCommand::AddContactDeaddropServer {
                contact_id,
                server: self.input.trim().to_string(),
            }) {
                Ok(CommToolsCommandResult::ContactDeaddropServerAdded(server)) => {
                    self.deaddrop_input = None;
                    self.input.clear();
                    self.status = format!("Added deaddrop server to {display_name}: {server}");
                }
                Ok(_) => self.status = "Unexpected deaddrop-add result.".into(),
                Err(error) => self.status = error.to_string(),
            },
            DeaddropInput::Remove {
                contact_id,
                display_name,
            } => {
                let Ok(number) = self.input.trim().parse::<usize>() else {
                    self.status = "Enter a valid deaddrop server number.".into();
                    return;
                };
                let server = selected_contact(driver, Some(&contact_id)).and_then(|contact| {
                    number
                        .checked_sub(1)
                        .and_then(|index| contact.deaddrop_servers.get(index))
                        .cloned()
                });
                let Some(server) = server else {
                    self.status = "Deaddrop server number is out of range.".into();
                    return;
                };
                self.deaddrop_input = None;
                self.input.clear();
                self.status = format!("Remove deaddrop server {number} from {display_name}? y/n");
                self.deaddrop_removal_confirmation = Some(DeaddropRemovalConfirmation {
                    contact_id,
                    display_name,
                    server,
                });
            }
        }
    }

    fn handle_deaddrop_removal_confirmation_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Char('y') => {
                let Some(confirmation) = self.deaddrop_removal_confirmation.take() else {
                    return ShellAction::Continue;
                };
                match driver.dispatch_command(CommToolsCommand::RemoveContactDeaddropServer {
                    contact_id: confirmation.contact_id,
                    server: confirmation.server,
                }) {
                    Ok(CommToolsCommandResult::ContactDeaddropServerRemoved(server)) => {
                        self.status = format!(
                            "Removed deaddrop server from {}: {server}",
                            confirmation.display_name
                        );
                    }
                    Ok(_) => self.status = "Unexpected deaddrop-remove result.".into(),
                    Err(error) => self.status = error.to_string(),
                }
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                self.deaddrop_removal_confirmation = None;
                self.status = "Deaddrop server removal cancelled.".into();
            }
            _ => {}
        }
        ShellAction::Continue
    }

    fn generate_public_group_invite(&mut self, driver: &mut ApplicationDriver) {
        let Some(group) = selected_group(driver, self.selected_group.as_ref()) else {
            self.status = "No group is selected.".into();
            return;
        };
        let group_id = group.id.clone();
        match driver.dispatch_command(CommToolsCommand::IssuePublicGroupInvite {
            group_id: group_id.clone(),
        }) {
            Ok(CommToolsCommandResult::PublicGroupInviteIssued(invite)) => {
                let invite = Zeroizing::new(invite);
                self.pending_clipboard = Some(Zeroizing::new(invite.to_string()));
                self.generated_public_invite = Some((group_id, invite));
                self.status = "Generated a new single-use public invite.".into();
            }
            Ok(_) => self.status = "Unexpected public group-invite result.".into(),
            Err(error) => self.status = error.to_string(),
        }
    }

    fn copy_generated_public_invite(&mut self) {
        let Some(selected) = self.selected_group.as_ref() else {
            self.status = "No group is selected.".into();
            return;
        };
        let Some((group_id, invite)) = self.generated_public_invite.as_ref() else {
            self.status = "Generate a public invite first.".into();
            return;
        };
        if group_id != selected {
            self.status = "No generated public invite is retained for this group.".into();
            return;
        }
        self.pending_clipboard = Some(Zeroizing::new(invite.to_string()));
        self.status = "Copying the retained public invite.".into();
    }

    fn begin_public_invite_import(&mut self) {
        self.public_invite_input = Some(Zeroizing::new(String::new()));
        self.status = "Paste a public or private group invite, then press Enter.".into();
    }

    fn generate_private_group_request(&mut self, driver: &mut ApplicationDriver) {
        match driver.dispatch_command(CommToolsCommand::GeneratePrivateGroupRequest) {
            Ok(CommToolsCommandResult::PrivateGroupRequestGenerated(request)) => {
                self.generated_private_request = Some(Zeroizing::new(request));
                self.status = "Generated and retained a private group request.".into();
            }
            Ok(_) => self.status = "Unexpected private group-request result.".into(),
            Err(error) => self.status = error.to_string(),
        }
    }

    fn copy_private_group_request(&mut self) {
        let Some(request) = self.generated_private_request.as_ref() else {
            self.status = "Generate a private group request first.".into();
            return;
        };
        self.pending_clipboard = Some(Zeroizing::new(request.to_string()));
        self.status = "Copying the retained private group request.".into();
    }

    fn begin_private_request_answer(&mut self, driver: &ApplicationDriver) {
        let Some(group) = selected_group(driver, self.selected_group.as_ref()) else {
            self.status = "No group is selected.".into();
            return;
        };
        self.private_request_input = Some((group.id.clone(), Zeroizing::new(String::new())));
        self.status = "Paste the recipient's private request, then press Enter.".into();
    }

    fn set_private_request_input(&mut self, value: String) {
        let value = value.trim();
        if value.len() > MAX_PRIVATE_INVITE_BYTES {
            self.status =
                format!("Private request exceeds the {MAX_PRIVATE_INVITE_BYTES}-byte input limit.");
            return;
        }
        let Some((_, request)) = self.private_request_input.as_mut() else {
            return;
        };
        request.clear();
        request.push_str(value);
        self.status = format!("Private request pasted: {} bytes.", value.len());
    }

    fn handle_private_request_input_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Esc => {
                self.private_request_input = None;
                self.status = "Private request cancelled.".into();
            }
            KeyCode::Backspace => {
                if let Some((_, request)) = self.private_request_input.as_mut() {
                    request.pop();
                }
                self.status.clear();
            }
            KeyCode::Enter => self.submit_private_request(driver),
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                let Some((_, request)) = self.private_request_input.as_mut() else {
                    return ShellAction::Continue;
                };
                if !character.is_control()
                    && request.len() + character.len_utf8() <= MAX_PRIVATE_INVITE_BYTES
                {
                    request.push(character);
                    self.status.clear();
                }
            }
            _ => {}
        }
        ShellAction::Continue
    }

    fn submit_private_request(&mut self, driver: &mut ApplicationDriver) {
        let Some((group_id, request)) = self.private_request_input.as_ref() else {
            return;
        };
        if request.trim().is_empty() {
            self.status = "Private request must not be empty.".into();
            return;
        }
        match driver.dispatch_command(CommToolsCommand::IssuePrivateGroupInvite {
            group_id: group_id.clone(),
            encoded_request: request.to_string(),
        }) {
            Ok(CommToolsCommandResult::PrivateGroupInviteIssued(invite)) => {
                let group_id = group_id.clone();
                self.generated_private_invite = Some((group_id, Zeroizing::new(invite)));
                self.private_request_input = None;
                self.status = "Generated and retained a recipient-bound private invite.".into();
            }
            Ok(_) => self.status = "Unexpected private group-invite result.".into(),
            Err(error) => self.status = error.to_string(),
        }
    }

    fn copy_private_group_invite(&mut self) {
        let Some(selected) = self.selected_group.as_ref() else {
            self.status = "No group is selected.".into();
            return;
        };
        let Some((group_id, invite)) = self.generated_private_invite.as_ref() else {
            self.status = "Answer a private group request first.".into();
            return;
        };
        if group_id != selected {
            self.status = "No private invite is retained for this group.".into();
            return;
        }
        self.pending_clipboard = Some(Zeroizing::new(invite.to_string()));
        self.status = "Copying the retained private group invite.".into();
    }

    fn begin_group_name_input(&mut self, driver: &ApplicationDriver) {
        let Some(group) = selected_group(driver, self.selected_group.as_ref()) else {
            self.status = "No group is selected.".into();
            return;
        };
        self.group_name_input = Some(group.id.clone());
        self.input = group.local_member_name.clone();
        self.status = "Enter your local group name, then press Enter.".into();
    }

    fn handle_group_name_input_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Esc => {
                self.group_name_input = None;
                self.input.clear();
                self.status = "Group name change cancelled.".into();
            }
            KeyCode::Backspace => {
                self.input.pop();
                self.status.clear();
            }
            KeyCode::Enter => self.submit_group_name(driver),
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                    && !character.is_control()
                    && self.input.chars().count() < MAX_GROUP_NAME_CHARS =>
            {
                self.input.push(character);
                self.status.clear();
            }
            _ => {}
        }
        ShellAction::Continue
    }

    fn submit_group_name(&mut self, driver: &mut ApplicationDriver) {
        let Some(group_id) = self.group_name_input.clone() else {
            return;
        };
        let name = self.input.trim().to_string();
        if name.is_empty() {
            self.status = "Group name must not be empty.".into();
            return;
        }
        match driver.dispatch_command(CommToolsCommand::SetGroupLocalName {
            group_id,
            local_name: name.clone(),
        }) {
            Ok(CommToolsCommandResult::GroupLocalNameApplied) => {
                self.group_name_input = None;
                self.input.clear();
                self.status = format!("Saved local group name: {name}");
            }
            Ok(_) => self.status = "Unexpected group-name result.".into(),
            Err(error) => self.status = error.to_string(),
        }
    }

    fn set_public_invite_input(&mut self, value: String) {
        let value = value.trim();
        if value.len() > MAX_PUBLIC_INVITE_BYTES {
            self.status =
                format!("Public invite exceeds the {MAX_PUBLIC_INVITE_BYTES}-byte input limit.");
            return;
        }
        self.public_invite_input = Some(Zeroizing::new(value.to_string()));
        self.status = format!("Public invite pasted: {} bytes.", value.len());
    }

    fn handle_public_invite_input_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Esc => {
                self.public_invite_input = None;
                self.status = "Public invite import cancelled.".into();
            }
            KeyCode::Backspace => {
                if let Some(invite) = self.public_invite_input.as_mut() {
                    invite.pop();
                }
                self.status.clear();
            }
            KeyCode::Enter => self.submit_public_invite(driver),
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                let Some(invite) = self.public_invite_input.as_mut() else {
                    return ShellAction::Continue;
                };
                if !character.is_control()
                    && invite.len() + character.len_utf8() <= MAX_PUBLIC_INVITE_BYTES
                {
                    invite.push(character);
                    self.status.clear();
                }
            }
            _ => {}
        }
        ShellAction::Continue
    }

    fn submit_public_invite(&mut self, driver: &mut ApplicationDriver) {
        let Some(invite) = self.public_invite_input.as_ref() else {
            return;
        };
        if invite.trim().is_empty() {
            self.status = "Group invite must not be empty.".into();
            return;
        }
        let result = match commtools_core::private_group_invite::input_kind(
            invite.as_str(),
            commtools_core::group_roster::PUBLIC_INVITE_PREFIX,
        ) {
            commtools_core::private_group_invite::InputKind::Public => {
                match driver.dispatch_command(CommToolsCommand::ImportPublicGroupInvite {
                    encoded_invite: invite.to_string(),
                }) {
                    Ok(CommToolsCommandResult::PublicGroupInviteImported(group_id)) => Ok(group_id),
                    Ok(_) => Err("Unexpected public group-invite import result.".into()),
                    Err(error) => Err(error.to_string()),
                }
            }
            commtools_core::private_group_invite::InputKind::Private => {
                match driver.dispatch_command(CommToolsCommand::ImportPrivateGroupInvite {
                    encoded_invite: invite.to_string(),
                }) {
                    Ok(CommToolsCommandResult::PrivateGroupInviteImported(group_id)) => {
                        Ok(group_id)
                    }
                    Ok(_) => Err("Unexpected private group-invite import result.".into()),
                    Err(error) => Err(error.to_string()),
                }
            }
            commtools_core::private_group_invite::InputKind::Unknown => {
                self.status = "Unsupported group invite format.".into();
                return;
            }
        };
        match result {
            Ok(group_id) => {
                self.selected_group = Some(group_id);
                self.public_invite_input = None;
                self.status = "Imported group invite. Open the group to join.".into();
            }
            Err(error) => self.status = error.to_string(),
        }
    }

    fn handle_connect_input_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Esc => {
                self.workspace.cancel_connect_input();
                self.status = "Connection entry cancelled.".into();
            }
            KeyCode::Backspace => {
                self.workspace.pop_connect_input();
                self.status.clear();
            }
            KeyCode::Enter => match self.workspace.submit_connect(driver) {
                Ok(()) => self.status = "Connecting to peer.".into(),
                Err(error) => self.status = error,
            },
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.workspace.push_connect_input(character);
                self.status.clear();
            }
            _ => {}
        }
        ShellAction::Continue
    }

    fn handle_rendezvous_panel_key(&mut self, key: KeyEvent, driver: &mut ApplicationDriver) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('z') => {
                match self.workspace.toggle_rendezvous_panel(driver) {
                    Ok(_) => self.status = "Authenticated rendezvous closed.".into(),
                    Err(error) => self.status = error,
                }
            }
            KeyCode::Char('g') => match self.workspace.generate_rendezvous_request(driver) {
                Ok(()) => {
                    self.status = "One-time request generated; press v to copy it.".into();
                }
                Err(error) => self.status = error,
            },
            KeyCode::Char('a') => match self.workspace.begin_rendezvous_answer_input(driver) {
                Ok(()) => self.status = "Paste the received rendezvous request.".into(),
                Err(error) => self.status = error,
            },
            KeyCode::Char('c') => match self.workspace.begin_rendezvous_connect_input(driver) {
                Ok(()) => self.status = "Paste the response to your rendezvous request.".into(),
                Err(error) => self.status = error,
            },
            KeyCode::Char('v') => match self.workspace.rendezvous_output() {
                Ok(output) => {
                    self.pending_clipboard = Some(Zeroizing::new(output));
                    self.status = "Copying rendezvous value.".into();
                }
                Err(error) => self.status = error,
            },
            KeyCode::Char('r') => match self.workspace.revoke_rendezvous(driver) {
                Ok(()) => self.status = "One-time rendezvous state revoked.".into(),
                Err(error) => self.status = error,
            },
            _ => {}
        }
    }

    fn handle_rendezvous_input_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Esc => {
                self.workspace.cancel_rendezvous_input();
                self.status = "Rendezvous entry cancelled.".into();
            }
            KeyCode::Backspace => {
                self.workspace.pop_rendezvous_input();
                self.status.clear();
            }
            KeyCode::Enter => match self.workspace.submit_rendezvous_input(driver) {
                Ok(RendezvousSubmitDisposition::ResponseGenerated) => {
                    self.status = "Sealed response generated; press v to copy it.".into();
                }
                Ok(RendezvousSubmitDisposition::Connecting) => {
                    self.status = "Connecting with one-time rendezvous authentication.".into();
                }
                Err(error) => self.status = error,
            },
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.workspace.push_rendezvous_input(character);
                self.status.clear();
            }
            _ => {}
        }
        ShellAction::Continue
    }

    fn handle_message_input_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Esc => {
                self.workspace.cancel_message_input();
                self.status = "Message entry cancelled.".into();
            }
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::CONTROL) => {
                match self.workspace.submit_message(driver) {
                    Ok(()) => self.status = "Message queued.".into(),
                    Err(error) => self.status = error,
                }
            }
            KeyCode::F(2) => match self.workspace.submit_message(driver) {
                Ok(()) => self.status = "Message queued.".into(),
                Err(error) => self.status = error,
            },
            _ => {
                self.workspace.edit_message_input(key.into());
                self.status.clear();
            }
        }
        ShellAction::Continue
    }

    fn handle_image_input_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Esc => {
                self.workspace.cancel_image_input();
                self.status = "Image selection cancelled.".into();
            }
            KeyCode::Backspace => {
                self.workspace.pop_image_input();
                self.status.clear();
            }
            KeyCode::Enter => match self.workspace.submit_image(driver) {
                Ok(filename) => self.status = format!("Image queued: {filename}"),
                Err(error) => self.status = error,
            },
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.workspace.push_image_input(character);
                self.status.clear();
            }
            _ => {}
        }
        ShellAction::Continue
    }

    fn handle_file_input_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Esc => {
                self.workspace.cancel_file_input();
                self.status = "File selection cancelled.".into();
            }
            KeyCode::Backspace => {
                self.workspace.pop_file_input();
                self.status.clear();
            }
            KeyCode::Enter => match self.workspace.submit_file(driver) {
                Ok(filename) => self.status = format!("File offered: {filename}"),
                Err(error) => self.status = error,
            },
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.workspace.push_file_input(character);
                self.status.clear();
            }
            _ => {}
        }
        ShellAction::Continue
    }

    fn handle_create_key(&mut self, key: KeyEvent, driver: &mut ApplicationDriver) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Esc => self.cancel_create(),
            KeyCode::Backspace => {
                self.input.pop();
                self.status.clear();
            }
            KeyCode::Enter => self.submit_create(driver),
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.push_input(character);
            }
            _ => {}
        }
        ShellAction::Continue
    }

    fn push_input(&mut self, character: char) {
        if self.input.len() + character.len_utf8() <= MAX_NAME_BYTES {
            self.input.push(character);
            self.status.clear();
        }
    }

    fn submit_create(&mut self, driver: &mut ApplicationDriver) {
        let name = self.input.trim().to_string();
        if name.is_empty() {
            self.status = "Name must not be empty.".into();
            return;
        }
        match self.create_kind {
            Some(CreateKind::Contact) => {
                match driver.dispatch_command(CommToolsCommand::CreateContact {
                    display_name: name.clone(),
                }) {
                    Ok(CommToolsCommandResult::ContactCreated(id)) => {
                        self.selected_contact_item = Some(ContactBrowserItem::Contact(id));
                        self.status = format!("Created contact: {name}");
                    }
                    Ok(_) => {
                        self.status = "Unexpected contact-create result.".into();
                        return;
                    }
                    Err(error) => {
                        self.status = error.to_string();
                        return;
                    }
                }
            }
            Some(CreateKind::Group) => {
                match driver.dispatch_command(CommToolsCommand::CreateGroup {
                    display_name: name.clone(),
                }) {
                    Ok(CommToolsCommandResult::GroupCreated(id)) => {
                        self.selected_group = Some(id);
                        self.status = format!("Created group: {name}");
                    }
                    Ok(_) => {
                        self.status = "Unexpected group-create result.".into();
                        return;
                    }
                    Err(error) => {
                        self.status = error.to_string();
                        return;
                    }
                }
            }
            None => return,
        }
        self.input.clear();
        self.create_kind = None;
    }

    fn cancel_create(&mut self) {
        self.input.clear();
        self.create_kind = None;
        self.status = "Creation cancelled.".into();
    }

    fn normalize_selection(&mut self, driver: &ApplicationDriver) {
        if self.workspace.is_empty() && self.root_navigation == RootNavigationTarget::ActiveChats {
            self.root_navigation = self.section.into();
        }
        let contacts = contact_browser_items(driver, &self.workspace);
        if self
            .selected_contact_item
            .as_ref()
            .is_none_or(|selected| !contacts.contains(selected))
        {
            self.selected_contact_item = contacts.first().cloned();
        }
        self.selected_contact_action = self
            .selected_contact_action
            .min(ContactBrowserAction::ALL.len().saturating_sub(1));
        let previous_group = self.selected_group.clone();
        let groups = group_ids(driver);
        if self
            .selected_group
            .as_ref()
            .is_none_or(|selected| !groups.contains(selected))
        {
            self.selected_group = groups.first().cloned();
        }
        if self.selected_group != previous_group {
            self.selected_group_member = 0;
        }
        let member_count = selected_group(driver, self.selected_group.as_ref())
            .as_ref()
            .map(group_member_records)
            .map_or(0, |members| members.len());
        self.selected_group_member = self
            .selected_group_member
            .min(member_count.saturating_sub(1));
        self.selected_group_action = self
            .selected_group_action
            .min(GroupBrowserAction::ALL.len().saturating_sub(1));
    }

    fn open_selected(&mut self, driver: &mut ApplicationDriver) {
        let selected = match self.section {
            Section::Contacts => match self.selected_contact_item.as_ref() {
                Some(ContactBrowserItem::Contact(contact_id)) => {
                    selected_contact(driver, Some(contact_id)).map(|contact| {
                        (
                            ConversationKey::Contact(contact.id.clone()),
                            contact.display_name.clone(),
                        )
                    })
                }
                Some(ContactBrowserItem::Transient(transient_id)) => self
                    .workspace
                    .transient_browser_entries()
                    .into_iter()
                    .find(|entry| &entry.id == transient_id)
                    .map(|entry| (ConversationKey::Transient(entry.id), entry.label)),
                None => None,
            },
            Section::Groups => selected_group(driver, self.selected_group.as_ref()).map(|group| {
                (
                    ConversationKey::Group(group.id.clone()),
                    group.display_name.clone(),
                )
            }),
            Section::Settings => None,
        };
        let Some((key, label)) = selected else {
            self.status = "No record is selected.".into();
            return;
        };
        self.status = match self.workspace.open(key.clone(), label.clone()) {
            OpenDisposition::Opened => {
                let managed_key = match &key {
                    ConversationKey::Contact(contact_id) => {
                        ManagedSessionKey::Contact(contact_id.clone())
                    }
                    ConversationKey::Transient(transient_id) => {
                        ManagedSessionKey::Transient(transient_id.clone())
                    }
                    ConversationKey::Group(group_id) => ManagedSessionKey::Group(group_id.clone()),
                };
                let history_error =
                    if history_enabled_from_snapshot(driver, &managed_key).unwrap_or(false) {
                        match load_history(driver, managed_key.clone()) {
                            Ok(records) => {
                                self.workspace.load_history(&key, records);
                                None
                            }
                            Err(error) => Some(error.to_string()),
                        }
                    } else {
                        None
                    };
                let opening_status = match &key {
                    ConversationKey::Contact(contact_id) => {
                        match driver.dispatch_command(CommToolsCommand::OpenContact {
                            contact_id: contact_id.clone(),
                        }) {
                            Ok(CommToolsCommandResult::ContactOpening(_)) => {
                                self.workspace.mark_opening(&key);
                                format!("Opening contact: {label}")
                            }
                            Ok(_) => {
                                let error = "Unexpected contact-open result.".to_string();
                                self.workspace.mark_failed(&key, error.clone());
                                error
                            }
                            Err(error) => {
                                self.workspace.mark_failed(&key, error.to_string());
                                error.to_string()
                            }
                        }
                    }
                    ConversationKey::Transient(_) => {
                        "Transient session is already opening.".to_string()
                    }
                    ConversationKey::Group(group_id) => {
                        match driver.dispatch_command(CommToolsCommand::OpenGroup {
                            group_id: group_id.clone(),
                        }) {
                            Ok(CommToolsCommandResult::GroupOpening(_)) => {
                                self.workspace.mark_opening(&key);
                                format!("Opening group: {label}")
                            }
                            Ok(_) => {
                                let error = "Unexpected group-open result.".to_string();
                                self.workspace.mark_failed(&key, error.clone());
                                error
                            }
                            Err(error) => {
                                self.workspace.mark_failed(&key, error.to_string());
                                error.to_string()
                            }
                        }
                    }
                };
                history_error.map_or(opening_status.clone(), |error| {
                    format!("{opening_status}; load text history failed: {error}")
                })
            }
            OpenDisposition::Focused => format!("Focused conversation: {label}"),
            OpenDisposition::Closing => format!("Conversation is still closing: {label}"),
        };
        self.view = View::Conversation;
        self.workspace.clear_active_missed_calls();
    }

    fn open_new_transient(&mut self, driver: &mut ApplicationDriver) {
        let transient_id = match driver.dispatch_command(CommToolsCommand::OpenTransient) {
            Ok(CommToolsCommandResult::TransientOpening(transient_id)) => transient_id,
            Ok(_) => {
                self.status = "Unexpected transient-open result.".into();
                return;
            }
            Err(error) => {
                self.status = format!("Open transient session: {error}");
                return;
            }
        };
        let mut short = transient_id
            .as_str()
            .chars()
            .rev()
            .take(8)
            .collect::<String>();
        short = short.chars().rev().collect();
        let label = format!("Transient {short}");
        let key = ConversationKey::Transient(transient_id);
        self.workspace.open(key.clone(), label.clone());
        self.workspace.mark_opening(&key);
        self.view = View::Conversation;
        self.status = format!("Opening {label}");
    }

    fn toggle_selected_history(&mut self, driver: &mut ApplicationDriver) {
        let key = history_target_key(
            self.view,
            self.section,
            self.selected_persistent_contact_id(),
            self.selected_group.as_ref(),
            self.workspace.active_managed_key(),
        );
        let Some(key) = key else {
            self.status = "No record is selected.".into();
            return;
        };
        let enabled = match history_enabled_from_snapshot(driver, &key) {
            Ok(enabled) => !enabled,
            Err(error) => {
                self.status = error.to_string();
                return;
            }
        };
        let save_result =
            match &key {
                ManagedSessionKey::Contact(contact_id) => {
                    match driver.dispatch_command(CommToolsCommand::SetContactHistoryEnabled {
                        contact_id: contact_id.clone(),
                        enabled,
                    }) {
                        Ok(CommToolsCommandResult::ContactHistorySettingApplied {
                            enabled: applied,
                        }) if applied == enabled => Ok(()),
                        Ok(_) => {
                            self.status = "Unexpected contact-history result.".into();
                            return;
                        }
                        Err(error) => Err(error),
                    }
                }
                ManagedSessionKey::Group(group_id) => {
                    match driver.dispatch_command(CommToolsCommand::SetGroupHistoryEnabled {
                        group_id: group_id.clone(),
                        enabled,
                    }) {
                        Ok(CommToolsCommandResult::GroupHistorySettingApplied {
                            enabled: applied,
                        }) if applied == enabled => Ok(()),
                        Ok(_) => {
                            self.status = "Unexpected group-history result.".into();
                            return;
                        }
                        Err(error) => Err(error),
                    }
                }
                ManagedSessionKey::Transient(_) => {
                    self.status = "Transient sessions cannot retain history.".into();
                    return;
                }
            };
        if let Err(error) = save_result {
            self.status = format!("Save history setting: {error}");
            return;
        }
        let load_error = if enabled {
            let conversation_key = match &key {
                ManagedSessionKey::Contact(contact_id) => {
                    ConversationKey::Contact(contact_id.clone())
                }
                ManagedSessionKey::Transient(transient_id) => {
                    ConversationKey::Transient(transient_id.clone())
                }
                ManagedSessionKey::Group(group_id) => ConversationKey::Group(group_id.clone()),
            };
            match load_history(driver, key.clone()) {
                Ok(records) => {
                    self.workspace.load_history(&conversation_key, records);
                    None
                }
                Err(error) => Some(error.to_string()),
            }
        } else {
            None
        };
        self.status = if let Some(error) = load_error {
            format!("Text history enabled, but existing history could not be loaded: {error}")
        } else if enabled {
            "Text history enabled.".into()
        } else {
            "Text history disabled; existing history was retained.".into()
        };
    }

    fn begin_contact_history_clear(&mut self, driver: &ApplicationDriver) {
        let Some(contact) = selected_contact(driver, self.selected_persistent_contact_id()) else {
            self.status = "Clear history applies only to persistent contacts.".into();
            return;
        };
        self.begin_history_clear(ManagedSessionKey::Contact(contact.id), contact.display_name);
    }

    fn begin_group_history_clear(&mut self, driver: &ApplicationDriver) {
        let Some(group) = selected_group(driver, self.selected_group.as_ref()) else {
            self.status = "No group is selected.".into();
            return;
        };
        self.begin_history_clear(ManagedSessionKey::Group(group.id), group.display_name);
    }

    fn begin_history_clear(&mut self, key: ManagedSessionKey, display_name: String) {
        self.status = format!("Permanently clear text history for {display_name}? y/n");
        self.history_clear_confirmation = Some(HistoryClearConfirmation { key, display_name });
    }

    fn handle_history_clear_confirmation_key(
        &mut self,
        key: KeyEvent,
        driver: &mut ApplicationDriver,
    ) -> ShellAction {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return ShellAction::Quit;
        }
        match key.code {
            KeyCode::Char('y') => {
                let Some(confirmation) = self.history_clear_confirmation.take() else {
                    return ShellAction::Continue;
                };
                match driver.dispatch_command(CommToolsCommand::ClearHistory {
                    key: confirmation.key.clone(),
                }) {
                    Ok(CommToolsCommandResult::HistoryCleared { key })
                        if key == confirmation.key =>
                    {
                        self.workspace.clear_loaded_history(&key);
                        self.status =
                            format!("Cleared text history for {}.", confirmation.display_name);
                    }
                    Ok(_) => self.status = "Unexpected history-clear result.".into(),
                    Err(error) => self.status = format!("Clear text history: {error}"),
                }
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                self.history_clear_confirmation = None;
                self.status = "History clear cancelled.".into();
            }
            _ => {}
        }
        ShellAction::Continue
    }

    fn selected_persistent_contact_id(&self) -> Option<&ContactId> {
        match self.selected_contact_item.as_ref()? {
            ContactBrowserItem::Contact(contact_id) => Some(contact_id),
            ContactBrowserItem::Transient(_) => None,
        }
    }

    fn render_contacts(
        &mut self,
        frame: &mut Frame<'_>,
        area: ratatui::layout::Rect,
        driver: &ApplicationDriver,
    ) {
        let columns = Layout::horizontal([
            Constraint::Percentage(28),
            Constraint::Percentage(44),
            Constraint::Percentage(28),
        ])
        .split(area);
        let contacts_focused = self.browser_focus == BrowserFocus::Content
            && self.contact_browser_pane == ContactBrowserPane::Contacts;
        let actions_focused = self.browser_focus == BrowserFocus::Content
            && self.contact_browser_pane == ContactBrowserPane::Actions;
        let contact_target_visible = contacts_focused || actions_focused;
        let records = contacts(driver);
        let transients = self.workspace.transient_browser_entries();
        let browser_items = contact_browser_items_from(&records, &transients);
        let selected_contact = self
            .selected_persistent_contact_id()
            .and_then(|contact_id| records.iter().find(|contact| &contact.id == contact_id));
        let mut items = records
            .iter()
            .map(|contact| {
                let mut spans = vec![
                    Span::styled(
                        "P ",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(contact.display_name.clone()),
                ];
                append_tab_state(&mut spans, self.workspace.contact_tab_state(&contact.id));
                ListItem::new(Line::from(spans))
            })
            .collect::<Vec<_>>();
        items.extend(transients.iter().map(|transient| {
            let mut spans = vec![
                Span::styled(
                    "T ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(transient.label.clone()),
            ];
            append_tab_state(&mut spans, Some(transient.state));
            ListItem::new(Line::from(spans))
        }));
        let selected = self
            .selected_contact_item
            .as_ref()
            .and_then(|selected| browser_items.iter().position(|item| item == selected));
        let mut list_state = ListState::default().with_selected(selected);
        frame.render_stateful_widget(
            List::new(items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(browser_pane_border(contacts_focused))
                        .title(" Contacts "),
                )
                .highlight_symbol(browser_target_symbol(contact_target_visible))
                .highlight_style(browser_target_style(
                    contact_target_visible,
                    contacts_focused,
                )),
            columns[0],
            &mut list_state,
        );

        let lines = match self.selected_contact_item.as_ref() {
            Some(ContactBrowserItem::Contact(_)) => selected_contact.map(contact_details),
            Some(ContactBrowserItem::Transient(transient_id)) => transients
                .iter()
                .find(|entry| &entry.id == transient_id)
                .map(transient_details),
            None => None,
        }
        .unwrap_or_else(|| vec![Line::from("No contacts")]);
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(Block::default().borders(Borders::ALL).title(" Details ")),
            columns[1],
        );

        let action_items = ContactBrowserAction::ALL
            .iter()
            .map(|action| {
                let style = if self.contact_action_available_for(*action, selected_contact) {
                    Style::default().fg(Color::White)
                } else {
                    Style::default().fg(Color::DarkGray)
                };
                ListItem::new(Line::from(Span::styled(action.label(), style)))
            })
            .collect::<Vec<_>>();
        self.selected_contact_action = self
            .selected_contact_action
            .min(ContactBrowserAction::ALL.len().saturating_sub(1));
        let mut action_state =
            ListState::default().with_selected(Some(self.selected_contact_action));
        let action_title = match (
            self.contact_deletion_confirmation.as_ref(),
            self.history_clear_confirmation.as_ref(),
        ) {
            (Some(confirmation), _) => format!(" Delete {}? y/n ", confirmation.display_name),
            (
                None,
                Some(HistoryClearConfirmation {
                    key: ManagedSessionKey::Contact(_),
                    display_name,
                }),
            ) => format!(" Clear {display_name} history? y/n "),
            _ => " Actions ".into(),
        };
        frame.render_stateful_widget(
            List::new(action_items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(browser_pane_border(actions_focused))
                        .title(action_title),
                )
                .highlight_symbol(browser_selection_symbol(actions_focused))
                .highlight_style(browser_selection_style(actions_focused)),
            columns[2],
            &mut action_state,
        );
    }

    fn render_settings(
        &mut self,
        frame: &mut Frame<'_>,
        area: ratatui::layout::Rect,
        driver: &ApplicationDriver,
    ) {
        let columns = Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)])
            .split(area);
        let actions_focused = self.browser_focus == BrowserFocus::Content;
        let snapshot = driver.snapshot();
        let lines = match snapshot.as_ref() {
            Ok(snapshot) => {
                let settings = &snapshot.settings;
                vec![
                    Line::from(vec![
                        Span::styled("SAM host: ", Style::default().fg(Color::Gray)),
                        Span::raw(settings.sam_host.clone()),
                    ]),
                    Line::from(vec![
                        Span::styled("SAM port: ", Style::default().fg(Color::Gray)),
                        Span::raw(settings.sam_port.to_string()),
                    ]),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("Default tunnel length: ", Style::default().fg(Color::Gray)),
                        Span::raw(settings.default_tunnels.length.to_string()),
                    ]),
                    Line::from(vec![
                        Span::styled(
                            "Default tunnel quantity: ",
                            Style::default().fg(Color::Gray),
                        ),
                        Span::raw(settings.default_tunnels.quantity.to_string()),
                    ]),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled(
                            "Automatic liveness monitoring: ",
                            Style::default().fg(Color::Gray),
                        ),
                        Span::raw(if settings.sam_liveness_enabled {
                            "Enabled"
                        } else {
                            "Disabled"
                        }),
                    ]),
                    Line::from(vec![
                        Span::styled("Monitor state: ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            match &snapshot.sam_monitor_status {
                                SamMonitorStatus::Inactive => "Inactive".to_string(),
                                SamMonitorStatus::Checking => "Checking".to_string(),
                                SamMonitorStatus::Healthy => "Healthy".to_string(),
                                SamMonitorStatus::Degraded {
                                    consecutive_failures,
                                    reason,
                                } => format!("Degraded ({consecutive_failures}/3): {reason}"),
                                SamMonitorStatus::Unavailable { reason } => {
                                    format!("Unavailable: {reason}")
                                }
                            },
                            match &snapshot.sam_monitor_status {
                                SamMonitorStatus::Healthy => Style::default().fg(Color::Green),
                                SamMonitorStatus::Degraded { .. } => {
                                    Style::default().fg(Color::Yellow)
                                }
                                SamMonitorStatus::Unavailable { .. } => {
                                    Style::default().fg(Color::Red)
                                }
                                _ => Style::default().fg(Color::White),
                            },
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled("SAM failure action: ", Style::default().fg(Color::Gray)),
                        Span::raw(match settings.sam_failure_action {
                            SamFailureAction::GracefulShutdown => "Graceful shutdown",
                            SamFailureAction::WarningOnly => "Warning only",
                        }),
                    ]),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("Manual SAM test: ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            match &snapshot.sam_test_status {
                                SamTestStatus::Idle => "Not run".to_string(),
                                SamTestStatus::Running => "Running".to_string(),
                                SamTestStatus::Succeeded => "Succeeded".to_string(),
                                SamTestStatus::Failed(error) => format!("Failed: {error}"),
                            },
                            match &snapshot.sam_test_status {
                                SamTestStatus::Succeeded => Style::default().fg(Color::Green),
                                SamTestStatus::Failed(_) => Style::default().fg(Color::Red),
                                _ => Style::default().fg(Color::White),
                            },
                        ),
                    ]),
                ]
            }
            Err(error) => vec![Line::from(format!("Settings unavailable: {error}"))],
        };
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(Block::default().borders(Borders::ALL).title(" Settings ")),
            columns[0],
        );

        let endpoint_editable = self.workspace.is_empty()
            && snapshot
                .as_ref()
                .is_ok_and(|snapshot| !snapshot.has_open_or_pending_sessions);
        let storage_operation_available = endpoint_editable;
        let actions = SettingsAction::ALL
            .iter()
            .map(|action| {
                let available = match action {
                    SettingsAction::EditSamHost | SettingsAction::EditSamPort => endpoint_editable,
                    SettingsAction::ExportBackup
                    | SettingsAction::RestoreBackup
                    | SettingsAction::WipeAll => storage_operation_available,
                    SettingsAction::TestSam => snapshot
                        .as_ref()
                        .is_ok_and(|snapshot| snapshot.sam_test_status != SamTestStatus::Running),
                    _ => true,
                };
                ListItem::new(Line::from(Span::styled(
                    action.label(),
                    Style::default().fg(if available {
                        Color::White
                    } else {
                        Color::DarkGray
                    }),
                )))
            })
            .collect::<Vec<_>>();
        self.selected_settings_action = self
            .selected_settings_action
            .min(SettingsAction::ALL.len().saturating_sub(1));
        let mut state = ListState::default().with_selected(Some(self.selected_settings_action));
        frame.render_stateful_widget(
            List::new(actions)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(browser_pane_border(actions_focused))
                        .title(" Actions "),
                )
                .highlight_symbol(browser_selection_symbol(actions_focused))
                .highlight_style(browser_selection_style(actions_focused)),
            columns[1],
            &mut state,
        );
    }

    fn render_groups(
        &mut self,
        frame: &mut Frame<'_>,
        area: ratatui::layout::Rect,
        driver: &ApplicationDriver,
    ) {
        let columns = Layout::horizontal([
            Constraint::Percentage(28),
            Constraint::Percentage(44),
            Constraint::Percentage(28),
        ])
        .split(area);
        let details =
            Layout::vertical([Constraint::Length(11), Constraint::Fill(1)]).split(columns[1]);
        let groups_focused = self.browser_focus == BrowserFocus::Content
            && self.group_browser_pane == GroupBrowserPane::Groups;
        let members_focused = self.browser_focus == BrowserFocus::Content
            && self.group_browser_pane == GroupBrowserPane::Members;
        let actions_focused = self.browser_focus == BrowserFocus::Content
            && self.group_browser_pane == GroupBrowserPane::Actions;
        let group_target_visible = self.browser_focus == BrowserFocus::Content;
        let records = groups(driver);
        let items = records
            .iter()
            .map(|group| {
                let mut spans = vec![
                    Span::styled(
                        "G ",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(group.display_name.clone()),
                ];
                append_tab_state(&mut spans, self.workspace.group_tab_state(&group.id));
                ListItem::new(Line::from(spans))
            })
            .collect::<Vec<_>>();
        let selected = self
            .selected_group
            .as_ref()
            .and_then(|id| records.iter().position(|group| &group.id == id));
        let mut list_state = ListState::default().with_selected(selected);
        frame.render_stateful_widget(
            List::new(items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(browser_pane_border(groups_focused))
                        .title(" Groups "),
                )
                .highlight_symbol(browser_target_symbol(group_target_visible))
                .highlight_style(browser_target_style(group_target_visible, groups_focused)),
            columns[0],
            &mut list_state,
        );

        let selected = self
            .selected_group
            .as_ref()
            .and_then(|group_id| records.iter().find(|group| &group.id == group_id));
        let summary = selected
            .map(group_summary)
            .unwrap_or_else(|| vec![Line::from("No group selected")]);
        frame.render_widget(
            Paragraph::new(summary)
                .wrap(Wrap { trim: false })
                .block(Block::default().borders(Borders::ALL).title(" Group ")),
            details[0],
        );

        let members = selected.map(group_member_records).unwrap_or_default();
        if self.selected_group_member >= members.len() {
            self.selected_group_member = members.len().saturating_sub(1);
        }
        let mut member_items = members
            .iter()
            .map(|member| group_member_line(selected, member))
            .map(ListItem::new)
            .collect::<Vec<_>>();
        if member_items.is_empty() {
            member_items.push(ListItem::new(Line::from(Span::styled(
                "No roster members",
                Style::default().fg(Color::DarkGray),
            ))));
        }
        let member_selected = (!members.is_empty()).then_some(self.selected_group_member);
        let mut member_state = ListState::default().with_selected(member_selected);
        let member_title = match self.group_confirmation.as_ref() {
            Some(GroupConfirmation::RemoveMember { member_name, .. }) => {
                format!(" Remove {member_name}? y/n ")
            }
            _ => " Members ".into(),
        };
        frame.render_stateful_widget(
            List::new(member_items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(browser_pane_border(members_focused))
                        .title(member_title),
                )
                .highlight_symbol(browser_selection_symbol(members_focused))
                .highlight_style(browser_selection_style(members_focused)),
            details[1],
            &mut member_state,
        );

        let action_items = GroupBrowserAction::ALL
            .iter()
            .map(|action| {
                let style = if self.group_action_available_for(*action, selected) {
                    Style::default().fg(Color::White)
                } else {
                    Style::default().fg(Color::DarkGray)
                };
                ListItem::new(Line::from(Span::styled(action.label(), style)))
            })
            .collect::<Vec<_>>();
        self.selected_group_action = self
            .selected_group_action
            .min(GroupBrowserAction::ALL.len().saturating_sub(1));
        let mut action_state = ListState::default().with_selected(Some(self.selected_group_action));
        let action_title = match self.group_confirmation.as_ref() {
            Some(GroupConfirmation::DeleteLocalGroup { group_name, .. }) => {
                format!(" Delete {group_name} locally? y/n ")
            }
            Some(GroupConfirmation::LeaveGroup {
                group_name, mode, ..
            }) => match mode {
                GroupLeaveMode::Authoritative => format!(" Leave {group_name}? y/n "),
                GroupLeaveMode::LocalOnly => format!(" Leave {group_name} locally? y/n "),
            },
            Some(GroupConfirmation::DissolveGroup { group_name, .. }) => {
                format!(" Dissolve {group_name}? y/n ")
            }
            _ => match self.history_clear_confirmation.as_ref() {
                Some(HistoryClearConfirmation {
                    key: ManagedSessionKey::Group(_),
                    display_name,
                }) => format!(" Clear {display_name} history? y/n "),
                _ => " Actions ".into(),
            },
        };
        frame.render_stateful_widget(
            List::new(action_items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(browser_pane_border(actions_focused))
                        .title(action_title),
                )
                .highlight_symbol(browser_selection_symbol(actions_focused))
                .highlight_style(browser_selection_style(actions_focused)),
            columns[2],
            &mut action_state,
        );
    }
}

fn history_target_key(
    view: View,
    section: Section,
    selected_contact: Option<&ContactId>,
    selected_group: Option<&GroupId>,
    active_conversation: Option<ManagedSessionKey>,
) -> Option<ManagedSessionKey> {
    if view == View::Conversation {
        return active_conversation;
    }
    match section {
        Section::Contacts => selected_contact.cloned().map(ManagedSessionKey::Contact),
        Section::Groups => selected_group.cloned().map(ManagedSessionKey::Group),
        Section::Settings => None,
    }
}

fn history_enabled_from_snapshot(
    driver: &ApplicationDriver,
    key: &ManagedSessionKey,
) -> Result<bool, String> {
    let snapshot = driver.snapshot().map_err(|error| error.to_string())?;
    match key {
        ManagedSessionKey::Contact(contact_id) => snapshot
            .contacts
            .iter()
            .find(|contact| &contact.id == contact_id)
            .map(|contact| contact.history_enabled)
            .ok_or_else(|| format!("Contact not found: {contact_id}")),
        ManagedSessionKey::Transient(_) => Ok(false),
        ManagedSessionKey::Group(group_id) => snapshot
            .groups
            .iter()
            .find(|group| &group.id == group_id)
            .map(|group| group.history_enabled)
            .ok_or_else(|| format!("Group not found: {group_id}")),
    }
}

fn load_history(
    driver: &mut ApplicationDriver,
    key: ManagedSessionKey,
) -> Result<Vec<HistoryRecord>, String> {
    match driver
        .dispatch_command(CommToolsCommand::LoadHistory { key: key.clone() })
        .map_err(|error| error.to_string())?
    {
        CommToolsCommandResult::HistoryLoaded {
            key: loaded_key,
            records,
        } if loaded_key == key => Ok(records),
        CommToolsCommandResult::HistoryLoaded { .. } => {
            Err("History result belongs to a different conversation.".into())
        }
        _ => Err("Unexpected history-load result.".into()),
    }
}

fn is_key_action(key: &KeyEvent) -> bool {
    matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat)
}

fn contacts(driver: &ApplicationDriver) -> Vec<ContactSummary> {
    driver
        .snapshot()
        .map(|snapshot| snapshot.contacts)
        .unwrap_or_default()
}

fn groups(driver: &ApplicationDriver) -> Vec<GroupSummary> {
    driver
        .snapshot()
        .map(|snapshot| snapshot.groups)
        .unwrap_or_default()
}

fn contact_browser_items(
    driver: &ApplicationDriver,
    workspace: &Workspace,
) -> Vec<ContactBrowserItem> {
    let contacts = contacts(driver);
    let transients = workspace.transient_browser_entries();
    contact_browser_items_from(&contacts, &transients)
}

fn contact_browser_items_from(
    contacts: &[ContactSummary],
    transients: &[TransientBrowserEntry],
) -> Vec<ContactBrowserItem> {
    contacts
        .iter()
        .map(|contact| ContactBrowserItem::Contact(contact.id.clone()))
        .chain(
            transients
                .iter()
                .map(|transient| ContactBrowserItem::Transient(transient.id.clone())),
        )
        .collect()
}

fn group_ids(driver: &ApplicationDriver) -> Vec<GroupId> {
    groups(driver)
        .into_iter()
        .map(|group| group.id.clone())
        .collect()
}

fn selected_contact(
    driver: &ApplicationDriver,
    selected: Option<&ContactId>,
) -> Option<ContactSummary> {
    let selected = selected?;
    driver
        .snapshot()
        .ok()?
        .contacts
        .into_iter()
        .find(|contact| &contact.id == selected)
}

fn selected_group(driver: &ApplicationDriver, selected: Option<&GroupId>) -> Option<GroupSummary> {
    let selected = selected?;
    driver
        .snapshot()
        .ok()?
        .groups
        .into_iter()
        .find(|group| &group.id == selected)
}

fn moved_id<T: Clone + PartialEq>(ids: &[T], selected: Option<&T>, delta: isize) -> Option<T> {
    if ids.is_empty() {
        return None;
    }
    let current = selected
        .and_then(|selected| ids.iter().position(|id| id == selected))
        .unwrap_or(0);
    let next = current.saturating_add_signed(delta).min(ids.len() - 1);
    Some(ids[next].clone())
}

fn edge_id<T: Clone>(ids: &[T], end: bool) -> Option<T> {
    if end {
        ids.last().cloned()
    } else {
        ids.first().cloned()
    }
}

fn adjusted_tunnel_value(value: u8, delta: i8, minimum: u8, maximum: u8) -> u8 {
    value.saturating_add_signed(delta).clamp(minimum, maximum)
}

fn moved_index(count: usize, current: usize, delta: isize) -> usize {
    if count == 0 {
        0
    } else {
        current
            .min(count - 1)
            .saturating_add_signed(delta)
            .min(count - 1)
    }
}

fn edge_index(count: usize, end: bool) -> usize {
    if end { count.saturating_sub(1) } else { 0 }
}

fn browser_pane_border(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

fn browser_selection_symbol(focused: bool) -> &'static str {
    if focused { "> " } else { "  " }
}

fn browser_selection_style(focused: bool) -> Style {
    if focused {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    }
}

fn browser_target_symbol(visible: bool) -> &'static str {
    if visible { "> " } else { "  " }
}

fn browser_target_style(visible: bool, focused: bool) -> Style {
    if focused {
        browser_selection_style(true)
    } else if visible {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default()
    }
}

fn append_tab_state(spans: &mut Vec<Span<'static>>, state: Option<ConversationTabState>) {
    let Some((label, color)) = state.map(|state| match state {
        ConversationTabState::Open => ("OPEN", Color::Cyan),
        ConversationTabState::Closing => ("CLOSING", Color::Yellow),
    }) else {
        return;
    };
    spans.push(Span::raw("  "));
    spans.push(Span::styled(
        label,
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    ));
}

fn contact_details(contact: &ContactSummary) -> Vec<Line<'static>> {
    let mut lines = vec![
        detail_line("Name", &contact.display_name),
        detail_line(
            "Peer pin",
            if contact.peer_pinned {
                "Locked"
            } else {
                "Unlocked"
            },
        ),
        detail_line(
            "Identity",
            contact.local_b32.as_deref().unwrap_or("Not initialized"),
        ),
        detail_line("Peer", contact.peer_b32.as_deref().unwrap_or("Not locked")),
        detail_line(
            "History",
            if contact.history_enabled { "On" } else { "Off" },
        ),
        detail_line("Tunnel length", &contact.tunnels.length.to_string()),
        detail_line("Tunnel quantity", &contact.tunnels.quantity.to_string()),
        detail_line(
            "Deaddrop servers",
            &contact.deaddrop_servers.len().to_string(),
        ),
    ];
    lines.extend(
        contact
            .deaddrop_profiles
            .iter()
            .enumerate()
            .map(|(index, server)| deaddrop_profile_line(index, server)),
    );
    lines
}

fn deaddrop_profile_line(index: usize, server: &DeaddropServerSummary) -> Line<'static> {
    let marker = if server.active { "A" } else { "S" };
    let marker_color = if server.active {
        Color::Green
    } else {
        Color::DarkGray
    };
    let mut spans = vec![
        Span::styled(
            format!(" {marker} "),
            Style::default()
                .fg(marker_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{}. {}", index + 1, short_group_b32(&server.address)),
            Style::default().fg(Color::White),
        ),
    ];
    let samples = server
        .put_ok
        .saturating_add(server.put_fail)
        .saturating_add(server.get_ok)
        .saturating_add(server.get_fail);
    if samples == 0 {
        spans.push(Span::styled(
            "  untested",
            Style::default().fg(Color::DarkGray),
        ));
        return Line::from(spans);
    }
    spans.push(Span::styled(
        format!(
            "  PUT {}/{}  GET {}/{}",
            server.put_ok, server.put_fail, server.get_ok, server.get_fail
        ),
        Style::default().fg(Color::DarkGray),
    ));
    if let Some(latency_ms) = server.latency_ema_ms {
        spans.push(Span::styled(
            format!("  {latency_ms}ms"),
            Style::default().fg(Color::DarkGray),
        ));
    }
    if let Some(last_success_ms) = server.last_success_ms {
        spans.push(Span::styled(
            format!("  last {}", utc_hms_from_epoch_ms(last_success_ms)),
            Style::default().fg(Color::DarkGray),
        ));
    }
    Line::from(spans)
}

fn utc_hms_from_epoch_ms(epoch_ms: u64) -> String {
    let seconds = (epoch_ms / 1_000) % 86_400;
    format!(
        "{:02}:{:02}:{:02} UTC",
        seconds / 3_600,
        (seconds % 3_600) / 60,
        seconds % 60
    )
}

fn transient_details(transient: &TransientBrowserEntry) -> Vec<Line<'static>> {
    vec![
        detail_line("Name", &transient.label),
        detail_line("Type", "Transient"),
        detail_line(
            "State",
            match transient.state {
                ConversationTabState::Open => "Open",
                ConversationTabState::Closing => "Closing",
            },
        ),
        detail_line("Tunnel settings", "Application defaults"),
        detail_line("Retention", "Ephemeral"),
    ]
}

fn group_summary(group: &GroupSummary) -> Vec<Line<'static>> {
    let role = if group_is_owner(group) {
        "Owner"
    } else if group.owner_b32.is_some() {
        "Member"
    } else {
        "Not initialized"
    };
    let identity = group
        .local_b32
        .as_deref()
        .map(short_group_b32)
        .unwrap_or_else(|| "Not initialized".into());
    vec![
        detail_line("Name", &group.display_name),
        detail_line("Identity", &identity),
        detail_line(
            "Local name",
            if group.local_member_name.is_empty() {
                "Not set"
            } else {
                &group.local_member_name
            },
        ),
        detail_line("Role", role),
        detail_line("State", if group.active { "Open" } else { "Closed" }),
        detail_line("Members", &group.members.len().to_string()),
        detail_line("Connected peers", &group.ready_member_count.to_string()),
        detail_line("History", if group.history_enabled { "On" } else { "Off" }),
        detail_line("Roster version", &group.roster_version.to_string()),
    ]
}

fn group_is_owner(group: &GroupSummary) -> bool {
    group.owner
}

fn group_member_records(group: &GroupSummary) -> Vec<GroupMemberSummary> {
    group.members.clone()
}

fn group_member_line(group: Option<&GroupSummary>, member: &GroupMemberSummary) -> Line<'static> {
    let Some(group) = group else {
        return Line::from(member.name.clone());
    };
    let (state, state_style) = if member.local {
        ("Local", Style::default().fg(Color::Green))
    } else if member.connected {
        ("Connected", Style::default().fg(Color::Cyan))
    } else if group.active {
        ("Offline", Style::default().fg(Color::DarkGray))
    } else {
        ("Closed", Style::default().fg(Color::DarkGray))
    };
    let role = if member.owner { "Owner" } else { "Member" };
    Line::from(vec![
        Span::styled(member.name.clone(), Style::default().fg(Color::White)),
        Span::styled(
            format!("  {}  {role}  ", short_group_b32(&member.b32)),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(state, state_style),
    ])
}

fn short_group_b32(value: &str) -> String {
    let label = value.trim_end_matches(".b32.i2p");
    if label.len() > 14 {
        format!("{}...{}", &label[..6], &label[label.len() - 6..])
    } else {
        label.to_string()
    }
}

fn detail_line(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label}: "), Style::default().fg(Color::DarkGray)),
        Span::raw(value.to_string()),
    ])
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

fn backup_input_display(
    path: &str,
    passphrase: &str,
    files: bool,
    field: BackupInputField,
    files_label: &str,
) -> String {
    let path = if field == BackupInputField::Path {
        format!("[{path}]")
    } else {
        path.to_string()
    };
    let masked = "*".repeat(passphrase.chars().count());
    let passphrase = if field == BackupInputField::Passphrase {
        format!("[{masked}]")
    } else {
        masked
    };
    format!(
        "Path: {path}  Passphrase: {passphrase}  {files_label}: {}",
        if files { "Yes" } else { "No" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_chats_root_command_is_visible_only_with_open_conversations() {
        assert_eq!(
            root_navigation_targets(false),
            vec![
                RootNavigationTarget::Contacts,
                RootNavigationTarget::Groups,
                RootNavigationTarget::Settings,
            ]
        );
        assert_eq!(
            root_navigation_targets(true),
            vec![
                RootNavigationTarget::ActiveChats,
                RootNavigationTarget::Contacts,
                RootNavigationTarget::Groups,
                RootNavigationTarget::Settings,
            ]
        );
    }

    #[test]
    fn active_chats_root_command_reports_conversation_attention() {
        assert_eq!(
            root_navigation_label(
                RootNavigationTarget::ActiveChats,
                None,
                0,
                false,
                false,
                false,
            ),
            "Active Chats"
        );
        assert_eq!(
            root_navigation_label(
                RootNavigationTarget::ActiveChats,
                Some('◆'),
                2,
                true,
                false,
                false,
            ),
            "Active Chats ◆ 2 +"
        );
        assert_eq!(
            root_navigation_label(
                RootNavigationTarget::ActiveChats,
                Some('◇'),
                3,
                true,
                true,
                false,
            ),
            "Active Chats ◇ 3 + !"
        );
        assert_eq!(
            root_navigation_label(
                RootNavigationTarget::Contacts,
                Some('◆'),
                4,
                true,
                true,
                true,
            ),
            "Contacts"
        );
        assert_eq!(
            root_navigation_label(RootNavigationTarget::Settings, None, 0, false, false, true,),
            "Settings !"
        );
    }

    #[test]
    fn root_navigation_commands_map_only_browser_targets_to_sections() {
        assert_eq!(RootNavigationTarget::ActiveChats.section(), None);
        assert_eq!(
            RootNavigationTarget::Contacts.section(),
            Some(Section::Contacts)
        );
        assert_eq!(
            RootNavigationTarget::Groups.section(),
            Some(Section::Groups)
        );
        assert_eq!(
            RootNavigationTarget::Settings.section(),
            Some(Section::Settings)
        );
    }

    #[test]
    fn contact_browser_focus_cycles_between_records_and_actions() {
        assert_eq!(
            ContactBrowserPane::Contacts.next(),
            ContactBrowserPane::Actions
        );
        assert_eq!(
            ContactBrowserPane::Actions.next(),
            ContactBrowserPane::Contacts
        );
        assert_eq!(
            ContactBrowserPane::Contacts.previous(),
            ContactBrowserPane::Actions
        );
    }

    #[test]
    fn browser_target_marker_remains_visible_when_its_pane_loses_focus() {
        assert_eq!(browser_target_symbol(true), "> ");
        assert_eq!(browser_target_style(true, false).fg, Some(Color::DarkGray));
        assert_eq!(browser_target_style(true, true).fg, Some(Color::Cyan));
        assert_eq!(browser_target_symbol(false), "  ");
        assert_eq!(browser_target_style(false, false), Style::default());
    }

    #[test]
    fn deaddrop_profile_lines_distinguish_active_and_untested_servers() {
        let mut active_server =
            DeaddropServerSummary::new(format!("{}.b32.i2p", "a".repeat(52)), true);
        active_server.put_ok = 2;
        active_server.put_fail = 1;
        active_server.get_ok = 4;
        active_server.latency_ema_ms = Some(125);
        active_server.last_success_ms = Some(3_723_000);
        let active = deaddrop_profile_line(0, &active_server);
        let active_text = active
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<Vec<&str>>()
            .concat();
        assert!(active_text.contains("A 1."));
        assert!(active_text.contains("PUT 2/1  GET 4/0"));
        assert!(active_text.contains("125ms"));
        assert!(active_text.contains("last 01:02:03 UTC"));

        let standby_server =
            DeaddropServerSummary::new(format!("{}.b32.i2p", "b".repeat(52)), false);
        let standby = deaddrop_profile_line(1, &standby_server);
        let standby_text = standby
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<Vec<&str>>()
            .concat();
        assert!(standby_text.contains("S 2."));
        assert!(standby_text.contains("untested"));
    }

    #[test]
    fn contact_action_catalog_exposes_existing_operations_once() {
        assert_eq!(ContactBrowserAction::ALL.len(), 14);
        assert_eq!(ContactBrowserAction::ALL[0].label(), "New contact");
        assert!(ContactBrowserAction::ALL.contains(&ContactBrowserAction::RenameContact));
        assert!(ContactBrowserAction::ALL.contains(&ContactBrowserAction::ClearHistory));
        assert!(ContactBrowserAction::ALL.contains(&ContactBrowserAction::ExportContact));
        assert!(ContactBrowserAction::ALL.contains(&ContactBrowserAction::ImportContact));
        assert!(ContactBrowserAction::ALL.contains(&ContactBrowserAction::ResetContact));
        assert_eq!(
            ContactBrowserAction::ALL[ContactBrowserAction::ALL.len() - 1].label(),
            "Delete contact"
        );
    }

    #[test]
    fn storage_actions_are_present_and_backup_passphrases_are_masked() {
        assert!(SettingsAction::ALL.contains(&SettingsAction::ExportBackup));
        assert!(SettingsAction::ALL.contains(&SettingsAction::RestoreBackup));
        assert!(SettingsAction::ALL.contains(&SettingsAction::WipeAll));
        let displayed = backup_input_display(
            "/tmp/backup.ctbak",
            "do not display me",
            true,
            BackupInputField::Passphrase,
            "Include files",
        );
        assert!(displayed.contains("/tmp/backup.ctbak"));
        assert!(displayed.contains("Include files: Yes"));
        assert!(!displayed.contains("do not display me"));
    }

    #[test]
    fn export_defaults_are_siblings_of_the_vault_root() {
        let vault_root = Path::new("secure-device").join(".termcomm-i2p");
        assert_eq!(
            sibling_export_path(&vault_root, "-backup.ctbak"),
            Path::new("secure-device").join(".termcomm-i2p-backup.ctbak")
        );
        assert_eq!(
            sibling_export_path(&vault_root, "-contact-alice.ctcontact"),
            Path::new("secure-device").join(".termcomm-i2p-contact-alice.ctcontact")
        );
    }

    #[test]
    fn group_action_catalog_exposes_history_controls() {
        assert_eq!(GroupBrowserAction::ALL.len(), 16);
        assert!(GroupBrowserAction::ALL.contains(&GroupBrowserAction::ToggleHistory));
        assert!(GroupBrowserAction::ALL.contains(&GroupBrowserAction::ClearHistory));
    }

    #[test]
    fn tunnel_editor_adjustments_stay_within_validated_bounds() {
        assert_eq!(
            adjusted_tunnel_value(
                commtools_core::sam::MAX_TUNNEL_LENGTH,
                1,
                commtools_core::sam::MIN_TUNNEL_LENGTH,
                commtools_core::sam::MAX_TUNNEL_LENGTH,
            ),
            commtools_core::sam::MAX_TUNNEL_LENGTH
        );
        assert_eq!(
            adjusted_tunnel_value(
                commtools_core::sam::MIN_TUNNEL_QUANTITY,
                -1,
                commtools_core::sam::MIN_TUNNEL_QUANTITY,
                commtools_core::sam::MAX_TUNNEL_QUANTITY,
            ),
            commtools_core::sam::MIN_TUNNEL_QUANTITY
        );
    }

    #[test]
    fn transient_browser_items_follow_persistent_contacts() {
        let transient = TransientId::new("transient-browser-item").expect("transient id");
        let entries = vec![TransientBrowserEntry {
            id: transient.clone(),
            label: "Transient browser".into(),
            state: ConversationTabState::Open,
        }];

        assert_eq!(
            contact_browser_items_from(&[], &entries),
            vec![ContactBrowserItem::Transient(transient)]
        );
    }

    #[test]
    fn browser_history_target_uses_the_selected_section_record() {
        let contact = ContactId::new("selected-contact").expect("contact id");
        let group = GroupId::new("selected-group").expect("group id");

        assert_eq!(
            history_target_key(
                View::Browser,
                Section::Contacts,
                Some(&contact),
                Some(&group),
                None,
            ),
            Some(ManagedSessionKey::Contact(contact))
        );
        assert_eq!(
            history_target_key(View::Browser, Section::Groups, None, Some(&group), None,),
            Some(ManagedSessionKey::Group(group))
        );
    }

    #[test]
    fn conversation_history_target_ignores_the_browser_selection() {
        let selected_contact = ContactId::new("selected-contact").expect("contact id");
        let selected_group = GroupId::new("selected-group").expect("group id");
        let active_group = GroupId::new("active-group").expect("group id");

        assert_eq!(
            history_target_key(
                View::Conversation,
                Section::Contacts,
                Some(&selected_contact),
                Some(&selected_group),
                Some(ManagedSessionKey::Group(active_group.clone())),
            ),
            Some(ManagedSessionKey::Group(active_group))
        );
    }
}
