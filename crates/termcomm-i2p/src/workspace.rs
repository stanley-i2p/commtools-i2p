//! Per-conversation terminal presentation state.
//!


use crate::image_media::{
    IMAGE_RENDER_WIDTH, MAX_IMAGE_LINES, RenderedImage, RenderedImageCell, prepare_image_path,
    render_image_bytes,
};
use commtools_core::{
    CollisionWinner, ContactId, DisconnectReason, GroupId, HistoryRecord, ManagedSessionKey,
    OfflineCoordinatorMode, OneToOnePhase, OriginalImageMetadata, SessionId, TransientId,
    generate_message_id,
};
use commtools_runtime::{
    ApplicationDriver, CommToolsCommand, CommToolsCommandResult, ContactSessionEvent,
    FileTransferDirection as RuntimeFileTransferDirection,
    FileTransferEvent as RuntimeFileTransferEvent, GroupSessionEvent as RuntimeGroupSessionEvent,
    HistoryWriteOutcome, ImageDeliveryEvent, ImageReceivedEvent, OfflinePollResult,
    OfflineSessionEvent, OriginalImageReceivedEvent, OriginalImageRequestResult,
    RendezvousSessionEvent, RuntimeOperationEvent, SessionLifecycleEvent, TextDeliveryEvent,
    TextReceivedEvent,
};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap,
};
use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tui_tabs::TabNav;
use tui_textarea::{Input as TextAreaInput, TextArea, WrapMode as TextAreaWrapMode};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};
use zeroize::Zeroizing;

const TAB_OPENING_SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

const MAX_PEER_B32_INPUT_BYTES: usize = 256;
const MAX_RENDEZVOUS_INPUT_BYTES: usize = commtools_core::rendezvous::MAX_ENCODED_LEN;
const MAX_CHAT_TEXT_BYTES: usize = commtools_core::constants::MAX_FRAME_PAYLOAD_SIZE
    - commtools_core::crypto::MIN_ENCRYPTED_PAYLOAD_SIZE;
const MAX_OFFLINE_CHAT_TEXT_BYTES: usize = commtools_core::deaddrop::MAX_DEADDROP_BLOB_SIZE
    - commtools_core::constants::FRAME_HEADER_LEN
    - commtools_core::crypto::MIN_ENCRYPTED_PAYLOAD_SIZE;
const MAX_TRANSCRIPT_MESSAGES: usize = 500;
const TRANSCRIPT_METADATA_ALLOWANCE: usize = 4_096;
const TRANSCRIPT_RENDER_ALLOWANCE: usize =
    IMAGE_RENDER_WIDTH as usize * MAX_IMAGE_LINES * std::mem::size_of::<RenderedImageCell>();
const MAX_IMAGE_PATH_BYTES: usize = 4_096;
const MAX_FILE_PATH_BYTES: usize = 4_096;
const MESSAGE_COMPOSER_MIN_ROWS: u16 = 3;
const MESSAGE_COMPOSER_MAX_ROWS: u16 = 8;
const MESSAGE_BUBBLE_WIDTH_PERCENT: usize = 75;
const OFFLINE_STATUS_VISIBLE_FOR: Duration = Duration::from_secs(8);
const MAX_LOG_LINES: usize = 500;
const LOG_TRIM_BATCH: usize = 50;
const REPLY_BEGIN_MARKER: &str = "[COMMTOOLS-I2P-REPLY-v1]";
const REPLY_QUOTE_MARKER: &str = "[COMMTOOLS-I2P-QUOTE]";
const REPLY_END_MARKER: &str = "[/COMMTOOLS-I2P-REPLY]";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationKey {
    Contact(ContactId),
    Transient(TransientId),
    Group(GroupId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConversationPhase {
    Idle,
    Opening,
    Standby,
    Closing,
    Failed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChatDirection {
    Sent,
    Received,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChatMessageKind {
    Text,
    Image,
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileTransferUiState {
    IncomingOffer,
    AwaitingAcceptance,
    Active,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OriginalImageUiState {
    Available,
    Requesting {
        received_bytes: u64,
        total_bytes: u64,
    },
    Cached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TofuPresentationState {
    Inactive,
    Verified,
    Mismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OfflineActivityState {
    Idle,
    Poll,
    Put,
    Hit,
    Miss,
    Fail,
}

#[derive(Debug, Clone)]
struct OfflineActivityPresentation {
    state: OfflineActivityState,
    changed_at: Option<Instant>,
}

impl Default for OfflineActivityPresentation {
    fn default() -> Self {
        Self {
            state: OfflineActivityState::Idle,
            changed_at: None,
        }
    }
}

impl OfflineActivityPresentation {
    fn set(&mut self, state: OfflineActivityState) {
        self.state = state;
        self.changed_at = (state != OfflineActivityState::Idle).then(Instant::now);
    }

    fn visible_state(&self) -> OfflineActivityState {
        if self.changed_at.is_some_and(|changed_at| {
            Instant::now().saturating_duration_since(changed_at) <= OFFLINE_STATUS_VISIBLE_FOR
        }) {
            self.state
        } else {
            OfflineActivityState::Idle
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationTabState {
    Open,
    Closing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransientBrowserEntry {
    pub id: TransientId,
    pub label: String,
    pub state: ConversationTabState,
}

#[derive(Debug, Clone)]
struct ChatMessage {
    direction: ChatDirection,
    kind: ChatMessageKind,
    offline: bool,
    message_id: u64,
    timestamp_utc: String,
    text: String,
    image_bytes: Option<Vec<u8>>,
    image_render: Option<RenderedImage>,
    original: Option<OriginalImageMetadata>,
    original_sender_b32: Option<String>,
    original_state: Option<OriginalImageUiState>,
    author: Option<String>,
    group_delivery: Option<(usize, usize)>,
    relayed: bool,
    delivered: bool,
    failed: bool,
    history: MessageHistoryState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageHistoryState {
    NotStored,
    Stored,
    StoreFailed,
}

#[derive(Debug, Clone)]
struct ReplyDraft {
    author: String,
    text: String,
}

#[derive(Debug, Clone, Default)]
struct ConversationLog {
    lines: VecDeque<String>,
}

impl ConversationLog {
    fn push(&mut self, message: impl Into<String>) {
        self.push_at(&current_utc_hms(), message);
    }

    fn push_at(&mut self, timestamp_utc: &str, message: impl Into<String>) {
        if self.lines.len() >= MAX_LOG_LINES {
            let trim_count = LOG_TRIM_BATCH.min(self.lines.len());
            self.lines.drain(..trim_count);
        }
        let message = message
            .into()
            .chars()
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .collect::<String>();
        self.lines
            .push_back(format!("[{timestamp_utc}] {}", message.trim()));
    }

    fn joined(&self) -> String {
        self.lines.iter().cloned().collect::<Vec<_>>().join("\n")
    }
}

#[derive(Debug, Clone)]
struct ConversationPresentationState {
    transcript_scroll: usize,
    transcript_max_scroll: usize,
    transcript_page_lines: usize,
    follow_latest: bool,
    details_expanded: bool,
    selected_message: Option<usize>,
    logs_open: bool,
    log_scroll: usize,
    log_max_scroll: usize,
    log_page_lines: usize,
    log_follow_latest: bool,
    unread_text: bool,
    unseen_warning: bool,
    missed_calls: usize,
}

impl Default for ConversationPresentationState {
    fn default() -> Self {
        Self {
            transcript_scroll: 0,
            transcript_max_scroll: 0,
            transcript_page_lines: 1,
            follow_latest: true,
            details_expanded: false,
            selected_message: None,
            logs_open: false,
            log_scroll: 0,
            log_max_scroll: 0,
            log_page_lines: 1,
            log_follow_latest: true,
            unread_text: false,
            unseen_warning: false,
            missed_calls: 0,
        }
    }
}

#[derive(Debug, Clone)]
struct ConversationTab {
    key: ConversationKey,
    label: String,
    phase: ConversationPhase,
    contact_phase: Option<OneToOnePhase>,
    offline_mode: Option<OfflineCoordinatorMode>,
    session_id: Option<SessionId>,
    peer_b32: Option<String>,
    incoming_peer_b32: Option<String>,
    connect_input: Option<String>,
    rendezvous_panel_open: bool,
    rendezvous_input: Option<RendezvousInputDraft>,
    rendezvous_output: Option<Zeroizing<String>>,
    rendezvous_authenticated: bool,
    message_input: Option<TextArea<'static>>,
    image_path_input: Option<String>,
    file_path_input: Option<String>,
    reply_to: Option<ReplyDraft>,
    messages: VecDeque<ChatMessage>,
    history_loaded: bool,
    loaded_history_count: usize,
    group_member_names: BTreeMap<String, String>,
    file_names: BTreeMap<u64, String>,
    file_transfer_states: BTreeMap<u64, FileTransferUiState>,
    transcript_bytes: usize,
    last_warning: Option<String>,
    log: ConversationLog,
    tofu_state: TofuPresentationState,
    offline_activity: OfflineActivityPresentation,
    presentation: ConversationPresentationState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RendezvousInputKind {
    AnswerRequest,
    ConnectResponse,
}

#[derive(Debug, Clone)]
struct RendezvousInputDraft {
    kind: RendezvousInputKind,
    value: Zeroizing<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RendezvousSubmitDisposition {
    ResponseGenerated,
    Connecting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenDisposition {
    Opened,
    Focused,
    Closing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseDisposition {
    None,
    Removed,
    Opening,
    Closing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineToggleDisposition {
    Entered,
    Left,
}

#[derive(Debug, Default)]
pub struct Workspace {

    tabs: Vec<ConversationTab>,
    active: Option<usize>,
    tab_spinner_frame: usize,
}

impl Workspace {
    pub fn is_empty(&self) -> bool {
        self.tabs.is_empty()
    }

    pub fn has_unread_attention(&self) -> bool {
        self.tabs.iter().any(|tab| tab.presentation.unread_text)
    }

    pub fn has_warning_attention(&self) -> bool {
        self.tabs.iter().any(|tab| tab.presentation.unseen_warning)
    }

    pub fn total_missed_calls(&self) -> usize {
        self.tabs.iter().fold(0, |total, tab| {
            total.saturating_add(tab.presentation.missed_calls)
        })
    }

    pub fn active_chats_marker(
        &self,
        mut group_connected: impl FnMut(&GroupId) -> bool,
    ) -> Option<char> {
        if self.tabs.iter().any(ConversationTab::has_incoming_call) {
            return Some(tab_activity_pulse(self.tab_spinner_frame));
        }

        self.tabs
            .iter()
            .any(|tab| {
                let group_connected = match &tab.key {
                    ConversationKey::Group(group_id) => group_connected(group_id),
                    _ => false,
                };
                tab.has_live_connection(group_connected)
            })
            .then_some('◆')
    }

    pub fn mark_active_viewed(&mut self) {
        let Some(tab) = self.active.and_then(|index| self.tabs.get_mut(index)) else {
            return;
        };
        tab.presentation.unread_text = false;
        tab.presentation.unseen_warning = false;
    }

    pub fn clear_active_missed_calls(&mut self) {
        if let Some(tab) = self.active.and_then(|index| self.tabs.get_mut(index)) {
            tab.presentation.missed_calls = 0;
        }
    }

    pub fn advance_tab_spinner(&mut self) -> bool {
        if !self.tabs.iter().any(|tab| {
            tab.phase == ConversationPhase::Opening
                || (tab.phase == ConversationPhase::Standby
                    && tab.contact_phase == Some(OneToOnePhase::IncomingPending))
        }) {
            return false;
        }
        self.tab_spinner_frame = (self.tab_spinner_frame + 1) % TAB_OPENING_SPINNER.len();
        true
    }

    pub fn contains_contact(&self, contact_id: &ContactId) -> bool {
        self.tabs.iter().any(
            |tab| matches!(&tab.key, ConversationKey::Contact(open_id) if open_id == contact_id),
        )
    }

    pub fn contact_tab_state(&self, contact_id: &ContactId) -> Option<ConversationTabState> {
        self.tabs
            .iter()
            .find(|tab| {
                matches!(&tab.key, ConversationKey::Contact(open_id) if open_id == contact_id)
            })
            .map(ConversationTab::list_state)
    }

    pub fn transient_browser_entries(&self) -> Vec<TransientBrowserEntry> {
        self.tabs
            .iter()
            .filter_map(|tab| {
                let ConversationKey::Transient(id) = &tab.key else {
                    return None;
                };
                Some(TransientBrowserEntry {
                    id: id.clone(),
                    label: tab.label.clone(),
                    state: tab.list_state(),
                })
            })
            .collect()
    }

    pub fn group_tab_state(&self, group_id: &GroupId) -> Option<ConversationTabState> {
        self.tabs
            .iter()
            .find(|tab| matches!(&tab.key, ConversationKey::Group(open_id) if open_id == group_id))
            .map(ConversationTab::list_state)
    }

    pub fn sync_contact_offline_modes(&mut self, driver: &ApplicationDriver) {
        for tab in &mut self.tabs {
            if !matches!(&tab.key, ConversationKey::Contact(_)) {
                continue;
            }
            tab.offline_mode = tab
                .session_id
                .and_then(|session_id| driver.session_summary(session_id))
                .and_then(|session| session.offline_mode);
        }
    }

    pub fn sync_group_metadata(&mut self, driver: &ApplicationDriver) {
        let Ok(snapshot) = driver.snapshot() else {
            return;
        };
        for tab in &mut self.tabs {
            let ConversationKey::Group(group_id) = &tab.key else {
                continue;
            };
            tab.group_member_names.clear();
            let Some(group) = snapshot.groups.iter().find(|group| &group.id == group_id) else {
                continue;
            };
            tab.group_member_names = group
                .members
                .iter()
                .map(|member| (member.b32.clone(), member.name.clone()))
                .collect();
        }
    }

    pub fn open(&mut self, key: ConversationKey, label: impl Into<String>) -> OpenDisposition {
        if let Some(index) = self.tabs.iter().position(|tab| tab.key == key) {
            self.active = Some(index);
            return if self.tabs[index].phase == ConversationPhase::Closing {
                OpenDisposition::Closing
            } else {
                OpenDisposition::Focused
            };
        }
        let contact_phase = matches!(
            &key,
            ConversationKey::Contact(_) | ConversationKey::Transient(_)
        )
        .then_some(OneToOnePhase::Standby);
        self.tabs.push(ConversationTab {
            key,
            label: label.into(),
            phase: ConversationPhase::Idle,
            contact_phase,
            offline_mode: None,
            session_id: None,
            peer_b32: None,
            incoming_peer_b32: None,
            connect_input: None,
            rendezvous_panel_open: false,
            rendezvous_input: None,
            rendezvous_output: None,
            rendezvous_authenticated: false,
            message_input: None,
            image_path_input: None,
            file_path_input: None,
            reply_to: None,
            messages: VecDeque::new(),
            history_loaded: false,
            loaded_history_count: 0,
            group_member_names: BTreeMap::new(),
            file_names: BTreeMap::new(),
            file_transfer_states: BTreeMap::new(),
            transcript_bytes: 0,
            last_warning: None,
            log: ConversationLog::default(),
            tofu_state: TofuPresentationState::Inactive,
            offline_activity: OfflineActivityPresentation::default(),
            presentation: ConversationPresentationState::default(),
        });
        self.active = Some(self.tabs.len() - 1);
        OpenDisposition::Opened
    }

    pub fn mark_opening(&mut self, key: &ConversationKey) {
        if let Some(index) = self.index_for_key(key) {
            self.tabs[index].phase = ConversationPhase::Opening;
        }
    }

    pub fn load_history(&mut self, key: &ConversationKey, records: Vec<HistoryRecord>) {
        let Some(index) = self.index_for_key(key) else {
            return;
        };
        if self.tabs[index].history_loaded {
            return;
        }
        let current = std::mem::take(&mut self.tabs[index].messages);
        self.tabs[index].transcript_bytes = 0;
        self.tabs[index].presentation.selected_message = None;
        for record in records {
            self.tabs[index].push_transcript_message(ChatMessage::from_history(record));
        }
        self.tabs[index].loaded_history_count = self.tabs[index].messages.len();
        for message in current {
            self.tabs[index].push_transcript_message(message);
        }
        self.tabs[index].history_loaded = true;
    }

    pub fn clear_loaded_history(&mut self, key: &ManagedSessionKey) {
        let Some(index) = self.index_for_managed_key(key) else {
            return;
        };
        let tab = &mut self.tabs[index];
        let clear_count = tab.loaded_history_count.min(tab.messages.len());
        for message in tab.messages.drain(..clear_count) {
            tab.transcript_bytes = tab
                .transcript_bytes
                .saturating_sub(retained_message_bytes(&message));
        }
        tab.presentation.selected_message = tab
            .presentation
            .selected_message
            .and_then(|selected| selected.checked_sub(clear_count));
        for message in &mut tab.messages {
            if message.history == MessageHistoryState::Stored {
                message.history = MessageHistoryState::NotStored;
            }
        }
        tab.loaded_history_count = 0;
    }

    pub fn mark_failed(&mut self, key: &ConversationKey, reason: impl Into<String>) {
        if let Some(index) = self.index_for_key(key) {
            let reason = reason.into();
            self.tabs[index]
                .log
                .push(format!("Conversation failed: {reason}"));
            self.tabs[index].phase = ConversationPhase::Failed(reason);
            self.tabs[index].presentation.unseen_warning = true;
        }
    }

    pub fn select_next(&mut self) {
        if self.tabs.is_empty() {
            self.active = None;
            return;
        }
        self.active = Some(self.active.map_or(0, |index| (index + 1) % self.tabs.len()));
        self.clear_active_missed_calls();
    }

    pub fn select_previous(&mut self) {
        if self.tabs.is_empty() {
            self.active = None;
            return;
        }
        self.active = Some(self.active.map_or(0, |index| {
            index.checked_sub(1).unwrap_or(self.tabs.len() - 1)
        }));
        self.clear_active_missed_calls();
    }

    pub fn scroll_active_page_up(&mut self) {
        let Some(tab) = self.active.and_then(|index| self.tabs.get_mut(index)) else {
            return;
        };
        let presentation = &mut tab.presentation;
        if presentation.transcript_max_scroll == 0 {
            presentation.transcript_scroll = 0;
            presentation.follow_latest = true;
            return;
        }
        if presentation.follow_latest {
            presentation.transcript_scroll = presentation.transcript_max_scroll;
            presentation.follow_latest = false;
        }
        presentation.transcript_scroll = presentation
            .transcript_scroll
            .saturating_sub(presentation.transcript_page_lines);
    }

    pub fn scroll_active_page_down(&mut self) {
        let Some(tab) = self.active.and_then(|index| self.tabs.get_mut(index)) else {
            return;
        };
        let presentation = &mut tab.presentation;
        presentation.transcript_scroll = presentation
            .transcript_scroll
            .saturating_add(presentation.transcript_page_lines)
            .min(presentation.transcript_max_scroll);
        presentation.follow_latest =
            presentation.transcript_scroll >= presentation.transcript_max_scroll;
    }

    pub fn scroll_active_to_oldest(&mut self) {
        let Some(tab) = self.active.and_then(|index| self.tabs.get_mut(index)) else {
            return;
        };
        if tab.presentation.transcript_max_scroll == 0 {
            tab.presentation.transcript_scroll = 0;
            tab.presentation.follow_latest = true;
            return;
        }
        tab.presentation.transcript_scroll = 0;
        tab.presentation.follow_latest = false;
    }

    pub fn scroll_active_to_latest(&mut self) {
        let Some(tab) = self.active.and_then(|index| self.tabs.get_mut(index)) else {
            return;
        };
        tab.presentation.transcript_scroll = tab.presentation.transcript_max_scroll;
        tab.presentation.follow_latest = true;
    }

    pub fn active_logs_open(&self) -> bool {
        self.active
            .and_then(|index| self.tabs.get(index))
            .is_some_and(|tab| tab.presentation.logs_open)
    }

    pub fn toggle_active_logs(&mut self) -> Result<bool, String> {
        let index = self.active_index()?;
        let presentation = &mut self.tabs[index].presentation;
        presentation.logs_open = !presentation.logs_open;
        if presentation.logs_open {
            presentation.log_follow_latest = true;
        }
        Ok(presentation.logs_open)
    }

    pub fn scroll_active_logs_page_up(&mut self) {
        let Some(tab) = self.active.and_then(|index| self.tabs.get_mut(index)) else {
            return;
        };
        let presentation = &mut tab.presentation;
        if presentation.log_max_scroll == 0 {
            presentation.log_scroll = 0;
            presentation.log_follow_latest = true;
            return;
        }
        if presentation.log_follow_latest {
            presentation.log_scroll = presentation.log_max_scroll;
            presentation.log_follow_latest = false;
        }
        presentation.log_scroll = presentation
            .log_scroll
            .saturating_sub(presentation.log_page_lines);
    }

    pub fn scroll_active_logs_page_down(&mut self) {
        let Some(tab) = self.active.and_then(|index| self.tabs.get_mut(index)) else {
            return;
        };
        let presentation = &mut tab.presentation;
        presentation.log_scroll = presentation
            .log_scroll
            .saturating_add(presentation.log_page_lines)
            .min(presentation.log_max_scroll);
        presentation.log_follow_latest = presentation.log_scroll >= presentation.log_max_scroll;
    }

    pub fn scroll_active_logs_to_oldest(&mut self) {
        let Some(tab) = self.active.and_then(|index| self.tabs.get_mut(index)) else {
            return;
        };
        if tab.presentation.log_max_scroll == 0 {
            tab.presentation.log_scroll = 0;
            tab.presentation.log_follow_latest = true;
            return;
        }
        tab.presentation.log_scroll = 0;
        tab.presentation.log_follow_latest = false;
    }

    pub fn scroll_active_logs_to_latest(&mut self) {
        let Some(tab) = self.active.and_then(|index| self.tabs.get_mut(index)) else {
            return;
        };
        tab.presentation.log_scroll = tab.presentation.log_max_scroll;
        tab.presentation.log_follow_latest = true;
    }

    pub fn active_logs_copy_text(&self) -> Result<(usize, String), String> {
        let tab = self
            .active
            .and_then(|index| self.tabs.get(index))
            .ok_or_else(|| "No conversation is active.".to_string())?;
        if tab.log.lines.is_empty() {
            return Err("The active conversation log is empty.".into());
        }
        Ok((tab.log.lines.len(), tab.log.joined()))
    }

    pub fn move_active_message_selection(&mut self, direction: i32) -> Result<(), String> {
        let index = self.active_index()?;
        let tab = &mut self.tabs[index];
        let selectable = tab
            .messages
            .iter()
            .enumerate()
            .filter_map(|(index, message)| {
                (message.kind == ChatMessageKind::Text
                    || (message.kind == ChatMessageKind::File
                        && tab.file_transfer_states.contains_key(&message.message_id))
                    || (message.kind == ChatMessageKind::Image && message.original_state.is_some()))
                .then_some(index)
            })
            .collect::<Vec<_>>();
        if selectable.is_empty() {
            tab.presentation.selected_message = None;
            return Err(
                "There are no text messages, requestable images, or active file transfers to select."
                    .into(),
            );
        }

        let selected_position = tab
            .presentation
            .selected_message
            .and_then(|selected| selectable.iter().position(|index| *index == selected));
        let next_position = match (selected_position, direction.is_negative()) {
            (Some(position), true) => position.saturating_sub(1),
            (Some(position), false) => (position + 1).min(selectable.len() - 1),
            (None, _) => selectable.len() - 1,
        };
        tab.presentation.selected_message = Some(selectable[next_position]);
        tab.presentation.follow_latest = false;
        Ok(())
    }

    pub fn clear_active_message_selection(&mut self) -> bool {
        let Some(tab) = self.active.and_then(|index| self.tabs.get_mut(index)) else {
            return false;
        };
        tab.presentation.selected_message.take().is_some()
    }

    pub fn active_message_selected(&self) -> bool {
        self.active
            .and_then(|index| self.tabs.get(index))
            .is_some_and(|tab| tab.presentation.selected_message.is_some())
    }

    pub fn active_selected_message_is_text(&self) -> bool {
        self.active
            .and_then(|index| self.tabs.get(index))
            .and_then(|tab| {
                tab.presentation
                    .selected_message
                    .and_then(|selected| tab.messages.get(selected))
            })
            .is_some_and(|message| message.kind == ChatMessageKind::Text)
    }

    pub fn active_file_selection_hint(&self) -> Option<&'static str> {
        match self.selected_file_transfer().ok()?.3 {
            FileTransferUiState::IncomingOffer => {
                Some("File offer selected; y accepts and n declines.")
            }
            FileTransferUiState::AwaitingAcceptance | FileTransferUiState::Active => {
                Some("File transfer selected; X cancels it.")
            }
        }
    }

    pub fn active_original_image_selection_hint(&self) -> Option<&'static str> {
        match self.selected_original_image().ok()?.3 {
            OriginalImageUiState::Available => {
                Some("Image selected; g requests the original image.")
            }
            OriginalImageUiState::Requesting { .. } => {
                Some("Original image download selected; X cancels it.")
            }
            OriginalImageUiState::Cached => {
                Some("Original image selected; g reloads it from memory.")
            }
        }
    }

    pub fn request_selected_original_image(
        &mut self,
        driver: &mut ApplicationDriver,
    ) -> Result<String, String> {
        let (session_id, media_id, sender_b32, state) = self.selected_original_image()?;
        if matches!(state, OriginalImageUiState::Requesting { .. }) {
            return Err("The selected original image is already downloading.".into());
        }
        let result = driver
            .dispatch_command(CommToolsCommand::RequestOriginalImage {
                session_id,
                media_id,
                sender_b32: sender_b32.clone(),
            })
            .map_err(|error| error.to_string())?;
        match result {
            CommToolsCommandResult::OriginalImageRequest(OriginalImageRequestResult::Requested) => {
                if let Some(message) =
                    self.original_image_message_mut(session_id, media_id, sender_b32.as_deref())
                {
                    let total_bytes = message
                        .original
                        .as_ref()
                        .map_or(0, |original| original.size);
                    message.original_state = Some(OriginalImageUiState::Requesting {
                        received_bytes: 0,
                        total_bytes,
                    });
                }
                Ok("Original image requested.".into())
            }
            CommToolsCommandResult::OriginalImageRequest(OriginalImageRequestResult::Cached(
                event,
            )) => {
                let filename = event.filename.clone();
                self.receive_original_image(&event);
                Ok(format!("Original image loaded from memory: {filename}"))
            }
            _ => Err("Unexpected original-image request result.".into()),
        }
    }

    pub fn cancel_selected_original_image(
        &mut self,
        driver: &mut ApplicationDriver,
    ) -> Result<String, String> {
        let (session_id, media_id, sender_b32, state) = self.selected_original_image()?;
        if !matches!(state, OriginalImageUiState::Requesting { .. }) {
            return Err("The selected original image is not downloading.".into());
        }
        match driver
            .dispatch_command(CommToolsCommand::CancelOriginalImage {
                session_id,
                media_id,
                sender_b32: sender_b32.clone(),
            })
            .map_err(|error| error.to_string())?
        {
            CommToolsCommandResult::OriginalImageCancelled { .. } => {
                if let Some(message) =
                    self.original_image_message_mut(session_id, media_id, sender_b32.as_deref())
                {
                    message.original_state = Some(OriginalImageUiState::Available);
                }
                Ok("Original image download cancelled.".into())
            }
            _ => Err("Unexpected original-image cancellation result.".into()),
        }
    }

    fn selected_original_image(
        &self,
    ) -> Result<(SessionId, u64, Option<String>, OriginalImageUiState), String> {
        let tab = self
            .active
            .and_then(|index| self.tabs.get(index))
            .ok_or_else(|| "No conversation is active.".to_string())?;
        let selected = tab
            .presentation
            .selected_message
            .ok_or_else(|| "Select a requestable image with Up or Down first.".to_string())?;
        let message = tab
            .messages
            .get(selected)
            .filter(|message| {
                message.kind == ChatMessageKind::Image
                    && message.direction == ChatDirection::Received
            })
            .ok_or_else(|| "The selected transcript entry is not a received image.".to_string())?;
        let state = message.original_state.clone().ok_or_else(|| {
            "The sender did not advertise an original for this image.".to_string()
        })?;
        let session_id = tab
            .session_id
            .ok_or_else(|| "Conversation session is not open.".to_string())?;
        Ok((
            session_id,
            message.message_id,
            message.original_sender_b32.clone(),
            state,
        ))
    }

    pub fn accept_selected_file_offer(
        &mut self,
        driver: &mut ApplicationDriver,
    ) -> Result<String, String> {
        let (session_id, transfer_id, filename, state) = self.selected_file_transfer()?;
        if state != FileTransferUiState::IncomingOffer {
            return Err("The selected file transfer is not awaiting acceptance.".into());
        }
        match driver
            .dispatch_command(CommToolsCommand::AcceptFile {
                session_id,
                transfer_id,
            })
            .map_err(|error| error.to_string())?
        {
            CommToolsCommandResult::FileAccepted { .. } => {
                if let Some(tab) = self.tab_for_session_mut(session_id) {
                    tab.file_transfer_states
                        .insert(transfer_id, FileTransferUiState::Active);
                }
                Ok(filename)
            }
            _ => Err("Unexpected file-accept result.".into()),
        }
    }

    pub fn decline_selected_file_offer(
        &mut self,
        driver: &mut ApplicationDriver,
    ) -> Result<String, String> {
        let (session_id, transfer_id, filename, state) = self.selected_file_transfer()?;
        if state != FileTransferUiState::IncomingOffer {
            return Err("The selected file transfer is not awaiting a decision.".into());
        }
        match driver
            .dispatch_command(CommToolsCommand::DeclineFile {
                session_id,
                transfer_id,
            })
            .map_err(|error| error.to_string())?
        {
            CommToolsCommandResult::FileDeclined { .. } => {
                if let Some(tab) = self.tab_for_session_mut(session_id) {
                    tab.file_transfer_states.remove(&transfer_id);
                    tab.clear_selection_for_message(transfer_id);
                }
                Ok(filename)
            }
            _ => Err("Unexpected file-decline result.".into()),
        }
    }

    pub fn cancel_selected_file_transfer(
        &mut self,
        driver: &mut ApplicationDriver,
    ) -> Result<String, String> {
        let (session_id, transfer_id, filename, state) = self.selected_file_transfer()?;
        if state == FileTransferUiState::IncomingOffer {
            return Err("Use n to decline the selected incoming file offer.".into());
        }
        match driver
            .dispatch_command(CommToolsCommand::CancelFile {
                session_id,
                transfer_id,
            })
            .map_err(|error| error.to_string())?
        {
            CommToolsCommandResult::FileCancelled { .. } => {
                if let Some(tab) = self.tab_for_session_mut(session_id) {
                    tab.file_transfer_states.remove(&transfer_id);
                    tab.clear_selection_for_message(transfer_id);
                }
                Ok(filename)
            }
            _ => Err("Unexpected file-cancel result.".into()),
        }
    }

    fn selected_file_transfer(
        &self,
    ) -> Result<(SessionId, u64, String, FileTransferUiState), String> {
        let tab = self
            .active
            .and_then(|index| self.tabs.get(index))
            .ok_or_else(|| "No conversation is active.".to_string())?;
        let selected = tab
            .presentation
            .selected_message
            .ok_or_else(|| "Select an active file transfer with Up or Down first.".to_string())?;
        let message = tab
            .messages
            .get(selected)
            .filter(|message| message.kind == ChatMessageKind::File)
            .ok_or_else(|| "The selected transcript entry is not a file transfer.".to_string())?;
        let state = tab
            .file_transfer_states
            .get(&message.message_id)
            .copied()
            .ok_or_else(|| "The selected file transfer is no longer active.".to_string())?;
        let session_id = tab
            .session_id
            .ok_or_else(|| "Conversation session is not open.".to_string())?;
        let filename = tab
            .file_names
            .get(&message.message_id)
            .cloned()
            .unwrap_or_else(|| "file.bin".into());
        Ok((session_id, message.message_id, filename, state))
    }

    pub fn active_is_group(&self) -> bool {
        self.active
            .and_then(|index| self.tabs.get(index))
            .is_some_and(|tab| matches!(&tab.key, ConversationKey::Group(_)))
    }

    pub fn active_managed_key(&self) -> Option<ManagedSessionKey> {
        self.active
            .and_then(|index| self.tabs.get(index))
            .map(|tab| managed_key(&tab.key))
    }

    pub fn active_selected_message_copy_text(&self) -> Result<String, String> {
        let tab = self
            .active
            .and_then(|index| self.tabs.get(index))
            .ok_or_else(|| "No conversation is active.".to_string())?;
        let message = selected_text_message(tab)?;
        Ok(display_reply_text(&message.text))
    }

    pub fn begin_reply_to_selected(&mut self) -> Result<String, String> {
        let index = self.active_index()?;
        let (author, text) = {
            let tab = &self.tabs[index];
            let message = selected_text_message(tab)?;
            (
                message_display_author(message),
                reply_source_text(&message.text).to_string(),
            )
        };
        if text.trim().is_empty() {
            return Err("The selected message has no replyable text.".into());
        }
        self.begin_message_input()?;
        self.tabs[index].presentation.follow_latest = true;
        self.tabs[index].reply_to = Some(ReplyDraft {
            author: author.clone(),
            text,
        });
        Ok(author)
    }

    pub fn toggle_active_details(&mut self) {
        let Some(tab) = self.active.and_then(|index| self.tabs.get_mut(index)) else {
            return;
        };
        tab.presentation.details_expanded = !tab.presentation.details_expanded;
    }

    pub fn active_copy_address(
        &self,
        driver: &ApplicationDriver,
        local: bool,
    ) -> Result<(&'static str, String), String> {
        let tab = self
            .active
            .and_then(|index| self.tabs.get(index))
            .ok_or_else(|| "No conversation is active.".to_string())?;
        if !tab.presentation.details_expanded {
            return Err("Expand conversation details with i before copying an address.".into());
        }

        match &tab.key {
            ConversationKey::Contact(contact_id) => {
                let record = driver
                    .snapshot()
                    .ok()
                    .and_then(|snapshot| {
                        snapshot
                            .contacts
                            .into_iter()
                            .find(|contact| &contact.id == contact_id)
                    })
                    .ok_or_else(|| "The contact is not available.".to_string())?;
                if local {
                    let address = record
                        .local_b32
                        .as_deref()
                        .ok_or_else(|| "The local contact B32 is not initialized.".to_string())?;
                    Ok(("local contact B32", address.to_string()))
                } else {
                    let address = tab
                        .peer_b32
                        .as_deref()
                        .or(record.peer_b32.as_deref())
                        .ok_or_else(|| "The peer B32 is not available.".to_string())?;
                    Ok(("peer B32", address.to_string()))
                }
            }
            ConversationKey::Transient(_) => {
                let session = tab
                    .session_id
                    .and_then(|session_id| driver.session_summary(session_id))
                    .ok_or_else(|| "The transient session is not initialized.".to_string())?;
                if local {
                    let address = session
                        .local_b32
                        .ok_or_else(|| "The local transient B32 is not initialized.".to_string())?;
                    Ok(("local transient B32", address))
                } else {
                    let address = tab
                        .peer_b32
                        .as_deref()
                        .or(session.peer_b32.as_deref())
                        .ok_or_else(|| "The transient peer B32 is not available.".to_string())?;
                    Ok(("transient peer B32", address.to_string()))
                }
            }
            ConversationKey::Group(group_id) => {
                let record = driver
                    .snapshot()
                    .ok()
                    .and_then(|snapshot| {
                        snapshot
                            .groups
                            .into_iter()
                            .find(|group| &group.id == group_id)
                    })
                    .ok_or_else(|| "The group is not available.".to_string())?;
                if local {
                    let address = record
                        .local_b32
                        .as_deref()
                        .ok_or_else(|| "The local group B32 is not initialized.".to_string())?;
                    Ok(("local group B32", address.to_string()))
                } else {
                    let address = record
                        .owner_b32
                        .as_deref()
                        .ok_or_else(|| "The group owner B32 is not available.".to_string())?;
                    Ok(("group owner B32", address.to_string()))
                }
            }
        }
    }

    pub fn mark_contact_tofu_verified(&mut self, session_id: SessionId) {
        if let Some(tab) = self
            .tabs
            .iter_mut()
            .find(|tab| tab.session_id == Some(session_id))
        {
            tab.tofu_state = TofuPresentationState::Verified;
        }
    }

    pub fn connect_input_active(&self) -> bool {
        self.active
            .and_then(|index| self.tabs.get(index))
            .is_some_and(|tab| tab.connect_input.is_some())
    }

    pub fn rendezvous_input_active(&self) -> bool {
        self.active
            .and_then(|index| self.tabs.get(index))
            .is_some_and(|tab| tab.rendezvous_input.is_some())
    }

    pub fn rendezvous_panel_open(&self) -> bool {
        self.active
            .and_then(|index| self.tabs.get(index))
            .is_some_and(|tab| tab.rendezvous_panel_open)
    }

    pub fn toggle_rendezvous_panel(&mut self, driver: &ApplicationDriver) -> Result<bool, String> {
        let index = self.active_index()?;
        if self.tabs[index].rendezvous_panel_open {
            self.tabs[index].rendezvous_panel_open = false;
            self.tabs[index].rendezvous_input = None;
            return Ok(false);
        }
        self.ensure_rendezvous_available(index, driver)?;
        if self.tabs[index].connect_input.is_some() {
            return Err("Cancel direct B32 entry before opening rendezvous.".into());
        }
        self.tabs[index].rendezvous_panel_open = true;
        Ok(true)
    }

    pub fn generate_rendezvous_request(
        &mut self,
        driver: &mut ApplicationDriver,
    ) -> Result<(), String> {
        let index = self.active_index()?;
        self.ensure_rendezvous_available(index, driver)?;
        let session_id = self.tabs[index]
            .session_id
            .ok_or_else(|| "Contact session is not open.".to_string())?;
        let output = match driver
            .dispatch_command(CommToolsCommand::GenerateContactRendezvousRequest { session_id })
        {
            Ok(CommToolsCommandResult::ContactRendezvousRequestGenerated(output)) => output,
            Ok(_) => return Err("Unexpected rendezvous-request result.".into()),
            Err(error) => return Err(error.to_string()),
        };
        self.tabs[index].rendezvous_output = Some(Zeroizing::new(output));
        self.tabs[index].rendezvous_input = None;
        Ok(())
    }

    pub fn begin_rendezvous_answer_input(
        &mut self,
        driver: &ApplicationDriver,
    ) -> Result<(), String> {
        self.begin_rendezvous_input(driver, RendezvousInputKind::AnswerRequest)
    }

    pub fn begin_rendezvous_connect_input(
        &mut self,
        driver: &ApplicationDriver,
    ) -> Result<(), String> {
        self.begin_rendezvous_input(driver, RendezvousInputKind::ConnectResponse)
    }

    pub fn set_rendezvous_input(&mut self, value: String) {
        let Some(input) = self
            .active
            .and_then(|index| self.tabs.get_mut(index))
            .and_then(|tab| tab.rendezvous_input.as_mut())
        else {
            return;
        };
        let mut value = value;
        if value.len() > MAX_RENDEZVOUS_INPUT_BYTES {
            let mut end = MAX_RENDEZVOUS_INPUT_BYTES;
            while !value.is_char_boundary(end) {
                end = end.saturating_sub(1);
            }
            value.truncate(end);
        }
        input.value = Zeroizing::new(value);
    }

    pub fn push_rendezvous_input(&mut self, character: char) {
        let Some(input) = self
            .active
            .and_then(|index| self.tabs.get_mut(index))
            .and_then(|tab| tab.rendezvous_input.as_mut())
        else {
            return;
        };
        if !character.is_control()
            && input.value.len() + character.len_utf8() <= MAX_RENDEZVOUS_INPUT_BYTES
        {
            input.value.push(character);
        }
    }

    pub fn pop_rendezvous_input(&mut self) {
        if let Some(input) = self
            .active
            .and_then(|index| self.tabs.get_mut(index))
            .and_then(|tab| tab.rendezvous_input.as_mut())
        {
            input.value.pop();
        }
    }

    pub fn cancel_rendezvous_input(&mut self) {
        if let Some(tab) = self.active.and_then(|index| self.tabs.get_mut(index)) {
            tab.rendezvous_input = None;
        }
    }

    pub fn submit_rendezvous_input(
        &mut self,
        driver: &mut ApplicationDriver,
    ) -> Result<RendezvousSubmitDisposition, String> {
        let index = self.active_index()?;
        self.ensure_rendezvous_available(index, driver)?;
        let session_id = self.tabs[index]
            .session_id
            .ok_or_else(|| "Contact session is not open.".to_string())?;
        let input = self.tabs[index]
            .rendezvous_input
            .take()
            .ok_or_else(|| "Rendezvous input is not active.".to_string())?;
        if input.value.trim().is_empty() {
            self.tabs[index].rendezvous_input = Some(input);
            return Err("Paste a rendezvous value before submitting.".into());
        }
        match input.kind {
            RendezvousInputKind::AnswerRequest => {
                let output = match driver.dispatch_command(
                    CommToolsCommand::AnswerContactRendezvousRequest {
                        session_id,
                        encoded_request: input.value.trim().to_string(),
                    },
                ) {
                    Ok(CommToolsCommandResult::ContactRendezvousResponseGenerated(output)) => {
                        output
                    }
                    Ok(_) => {
                        self.tabs[index].rendezvous_input = Some(input);
                        return Err("Unexpected rendezvous-response result.".into());
                    }
                    Err(error) => {
                        self.tabs[index].rendezvous_input = Some(input);
                        return Err(error.to_string());
                    }
                };
                self.tabs[index].rendezvous_output = Some(Zeroizing::new(output));
                Ok(RendezvousSubmitDisposition::ResponseGenerated)
            }
            RendezvousInputKind::ConnectResponse => {
                match driver.dispatch_command(CommToolsCommand::ConnectContactRendezvous {
                    session_id,
                    encoded_response: input.value.trim().to_string(),
                }) {
                    Ok(CommToolsCommandResult::ContactRendezvousConnectionStarted(_)) => {}
                    Ok(_) => {
                        self.tabs[index].rendezvous_input = Some(input);
                        return Err("Unexpected rendezvous-connect result.".into());
                    }
                    Err(error) => {
                        self.tabs[index].rendezvous_input = Some(input);
                        return Err(error.to_string());
                    }
                }
                self.tabs[index].rendezvous_panel_open = false;
                self.tabs[index].rendezvous_output = None;
                Ok(RendezvousSubmitDisposition::Connecting)
            }
        }
    }

    pub fn rendezvous_output(&self) -> Result<String, String> {
        self.active
            .and_then(|index| self.tabs.get(index))
            .and_then(|tab| tab.rendezvous_output.as_deref())
            .map(ToOwned::to_owned)
            .ok_or_else(|| "No generated rendezvous value is available.".to_string())
    }

    pub fn revoke_rendezvous(&mut self, driver: &mut ApplicationDriver) -> Result<(), String> {
        let index = self.active_index()?;
        let session_id = self.tabs[index]
            .session_id
            .ok_or_else(|| "Contact session is not open.".to_string())?;
        match driver.dispatch_command(CommToolsCommand::RevokeContactRendezvous { session_id }) {
            Ok(CommToolsCommandResult::ContactRendezvousRevoked(_)) => {}
            Ok(_) => return Err("Unexpected rendezvous-revoke result.".into()),
            Err(error) => return Err(error.to_string()),
        }
        self.tabs[index].rendezvous_input = None;
        self.tabs[index].rendezvous_output = None;
        self.tabs[index].rendezvous_authenticated = false;
        Ok(())
    }

    pub fn begin_connect_input(&mut self, driver: &ApplicationDriver) -> Result<(), String> {
        let index = self.active_index()?;
        let tab = &self.tabs[index];
        if !is_one_to_one_key(&tab.key) {
            return Err("Only 1:1 sessions support direct connections.".into());
        }
        if tab.phase != ConversationPhase::Standby
            || tab.contact_phase != Some(OneToOnePhase::Standby)
        {
            return Err("Contact is not in online standby.".into());
        }
        if tab.rendezvous_panel_open {
            return Err("Close rendezvous before entering a direct B32 address.".into());
        }
        let session_id = tab
            .session_id
            .ok_or_else(|| "Contact session is not open.".to_string())?;
        let session = driver
            .session_summary(session_id)
            .ok_or_else(|| "Contact session is not initialized.".to_string())?;
        if session.offline_mode == Some(OfflineCoordinatorMode::Offline) {
            return Err("Return to online standby before connecting to the peer.".into());
        }
        let initial = session.pinned_peer_b32.unwrap_or_default();
        self.tabs[index].connect_input = Some(initial);
        Ok(())
    }

    fn begin_rendezvous_input(
        &mut self,
        driver: &ApplicationDriver,
        kind: RendezvousInputKind,
    ) -> Result<(), String> {
        let index = self.active_index()?;
        self.ensure_rendezvous_available(index, driver)?;
        if !self.tabs[index].rendezvous_panel_open {
            return Err("Open rendezvous before entering a value.".into());
        }
        self.tabs[index].rendezvous_input = Some(RendezvousInputDraft {
            kind,
            value: Zeroizing::new(String::new()),
        });
        Ok(())
    }

    fn ensure_rendezvous_available(
        &self,
        index: usize,
        driver: &ApplicationDriver,
    ) -> Result<(), String> {
        let tab = self
            .tabs
            .get(index)
            .ok_or_else(|| "No conversation is active.".to_string())?;
        if !is_one_to_one_key(&tab.key) {
            return Err("Authenticated rendezvous is available only for 1:1 sessions.".into());
        }
        if tab.phase != ConversationPhase::Standby
            || tab.contact_phase != Some(OneToOnePhase::Standby)
            || tab.offline_mode == Some(OfflineCoordinatorMode::Offline)
        {
            return Err("Rendezvous requires an unlocked contact in online standby.".into());
        }
        let session_id = tab
            .session_id
            .ok_or_else(|| "Contact session is not open.".to_string())?;
        if driver
            .session_summary(session_id)
            .is_some_and(|session| session.pinned_peer_b32.is_some())
        {
            return Err("Rendezvous is not available after this contact is locked.".into());
        }
        Ok(())
    }

    pub fn push_connect_input(&mut self, character: char) {
        let Some(input) = self
            .active
            .and_then(|index| self.tabs.get_mut(index))
            .and_then(|tab| tab.connect_input.as_mut())
        else {
            return;
        };
        if !character.is_control() && input.len() + character.len_utf8() <= MAX_PEER_B32_INPUT_BYTES
        {
            input.push(character);
        }
    }

    pub fn pop_connect_input(&mut self) {
        if let Some(input) = self
            .active
            .and_then(|index| self.tabs.get_mut(index))
            .and_then(|tab| tab.connect_input.as_mut())
        {
            input.pop();
        }
    }

    pub fn cancel_connect_input(&mut self) {
        if let Some(tab) = self.active.and_then(|index| self.tabs.get_mut(index)) {
            tab.connect_input = None;
        }
    }

    pub fn submit_connect(&mut self, driver: &mut ApplicationDriver) -> Result<(), String> {
        let index = self.active_index()?;
        let tab = &self.tabs[index];
        let session_id = tab
            .session_id
            .ok_or_else(|| "Contact session is not open.".to_string())?;
        let peer_b32 = tab
            .connect_input
            .as_deref()
            .ok_or_else(|| "Peer address entry is not active.".to_string())?
            .trim()
            .to_string();
        if peer_b32.is_empty() {
            return Err("Peer B32 address must not be empty.".into());
        }
        match driver.dispatch_command(CommToolsCommand::ConnectContact {
            session_id,
            peer_b32: peer_b32.clone(),
        }) {
            Ok(CommToolsCommandResult::ContactConnectionStarted(_)) => {}
            Ok(_) => return Err("Unexpected contact-connect result.".into()),
            Err(error) => return Err(error.to_string()),
        }
        self.tabs[index].peer_b32 = Some(peer_b32);
        self.tabs[index].connect_input = None;
        self.tabs[index].tofu_state = TofuPresentationState::Inactive;
        Ok(())
    }

    pub fn accept_incoming(&mut self, driver: &mut ApplicationDriver) -> Result<(), String> {
        let index = self.active_index()?;
        let tab = &self.tabs[index];
        if tab.contact_phase != Some(OneToOnePhase::IncomingPending) {
            return Err("There is no incoming call to accept.".into());
        }
        let session_id = tab
            .session_id
            .ok_or_else(|| "Contact session is not open.".to_string())?;
        match driver.dispatch_command(CommToolsCommand::AcceptContactIncoming { session_id }) {
            Ok(CommToolsCommandResult::ContactIncomingAccepted(_)) => {
                self.tabs[index].incoming_peer_b32 = None;
                Ok(())
            }
            Ok(_) => Err("Unexpected incoming-call acceptance result.".into()),
            Err(error) => Err(error.to_string()),
        }
    }

    pub fn decline_incoming(&mut self, driver: &mut ApplicationDriver) -> Result<(), String> {
        let index = self.active_index()?;
        let tab = &self.tabs[index];
        if tab.contact_phase != Some(OneToOnePhase::IncomingPending) {
            return Err("There is no incoming call to decline.".into());
        }
        let session_id = tab
            .session_id
            .ok_or_else(|| "Contact session is not open.".to_string())?;
        match driver.dispatch_command(CommToolsCommand::DeclineContactIncoming { session_id }) {
            Ok(CommToolsCommandResult::ContactIncomingDeclined(_)) => {
                self.tabs[index].incoming_peer_b32 = None;
                Ok(())
            }
            Ok(_) => Err("Unexpected incoming-call decline result.".into()),
            Err(error) => Err(error.to_string()),
        }
    }

    pub fn disconnect_contact(&mut self, driver: &mut ApplicationDriver) -> Result<(), String> {
        let index = self.active_index()?;
        let tab = &self.tabs[index];
        if !is_one_to_one_key(&tab.key) {
            return Err("Only 1:1 sessions support direct disconnect.".into());
        }
        if tab.phase != ConversationPhase::Standby
            || !matches!(
                tab.contact_phase,
                Some(OneToOnePhase::Connecting | OneToOnePhase::Handshaking | OneToOnePhase::Ready)
            )
        {
            return Err("Contact has no active connection to disconnect.".into());
        }
        let session_id = tab
            .session_id
            .ok_or_else(|| "Contact session is not open.".to_string())?;
        match driver.dispatch_command(CommToolsCommand::DisconnectContact { session_id }) {
            Ok(CommToolsCommandResult::ContactDisconnectStarted(_)) => Ok(()),
            Ok(_) => Err("Unexpected contact-disconnect result.".into()),
            Err(error) => Err(error.to_string()),
        }
    }

    pub fn toggle_contact_offline(
        &mut self,
        driver: &mut ApplicationDriver,
    ) -> Result<OfflineToggleDisposition, String> {
        let index = self.active_index()?;
        let tab = &self.tabs[index];
        if !matches!(&tab.key, ConversationKey::Contact(_)) {
            return Err("Only 1:1 contacts support offline mode.".into());
        }
        if tab.phase != ConversationPhase::Standby {
            return Err("Contact session is not open.".into());
        }
        let session_id = tab
            .session_id
            .ok_or_else(|| "Contact session is not open.".to_string())?;
        let mode = driver
            .session_summary(session_id)
            .and_then(|session| session.offline_mode)
            .ok_or_else(|| {
                "Offline mode requires a locked contact with completed offline enrollment."
                    .to_string()
            })?;
        match mode {
            OfflineCoordinatorMode::Standby => {
                if tab.contact_phase != Some(OneToOnePhase::Standby) {
                    return Err(
                        "Disconnect the live peer connection before entering offline mode.".into(),
                    );
                }
                match driver.dispatch_command(CommToolsCommand::EnterContactOffline { session_id })
                {
                    Ok(CommToolsCommandResult::ContactOfflineEntered(_)) => {}
                    Ok(_) => return Err("Unexpected enter-offline result.".into()),
                    Err(error) => return Err(error.to_string()),
                }
                self.tabs[index].offline_mode = Some(OfflineCoordinatorMode::Offline);
                Ok(OfflineToggleDisposition::Entered)
            }
            OfflineCoordinatorMode::Offline => {
                match driver.dispatch_command(CommToolsCommand::LeaveContactOffline { session_id })
                {
                    Ok(CommToolsCommandResult::ContactOfflineLeft(_)) => {}
                    Ok(_) => return Err("Unexpected leave-offline result.".into()),
                    Err(error) => return Err(error.to_string()),
                }
                self.tabs[index].offline_mode = Some(OfflineCoordinatorMode::Standby);
                self.tabs[index].message_input = None;
                self.tabs[index].reply_to = None;
                Ok(OfflineToggleDisposition::Left)
            }
            OfflineCoordinatorMode::Closing | OfflineCoordinatorMode::Closed => {
                Err("Offline resources are closing.".into())
            }
        }
    }

    pub fn active_contact_lock_candidate(
        &self,
        driver: &ApplicationDriver,
    ) -> Result<(SessionId, String), String> {
        let index = self.active_index()?;
        let tab = &self.tabs[index];
        if !matches!(&tab.key, ConversationKey::Contact(_)) {
            return Err("Only 1:1 contacts support peer locking.".into());
        }
        if tab.phase != ConversationPhase::Standby
            || tab.contact_phase != Some(OneToOnePhase::Ready)
        {
            return Err("A verified secure 1:1 session must be ready before locking.".into());
        }
        let session_id = tab
            .session_id
            .ok_or_else(|| "Contact session is not open.".to_string())?;
        let peer_b32 = driver
            .contact_lock_candidate(session_id)
            .map_err(|error| error.to_string())?;
        Ok((session_id, peer_b32))
    }

    pub fn message_input_active(&self) -> bool {
        self.active
            .and_then(|index| self.tabs.get(index))
            .is_some_and(|tab| tab.message_input.is_some())
    }

    pub fn image_path_input_active(&self) -> bool {
        self.active
            .and_then(|index| self.tabs.get(index))
            .is_some_and(|tab| tab.image_path_input.is_some())
    }

    pub fn file_path_input_active(&self) -> bool {
        self.active
            .and_then(|index| self.tabs.get(index))
            .is_some_and(|tab| tab.file_path_input.is_some())
    }

    pub fn begin_file_input(&mut self) -> Result<(), String> {
        let index = self.active_index()?;
        let tab = &self.tabs[index];
        if !is_one_to_one_key(&tab.key) {
            return Err("File transfer is available only in live 1:1 chats.".into());
        }
        if tab.phase != ConversationPhase::Standby
            || tab.contact_phase != Some(OneToOnePhase::Ready)
            || tab.offline_mode == Some(OfflineCoordinatorMode::Offline)
        {
            return Err("A live secure 1:1 session is required to send a file.".into());
        }
        self.tabs[index].file_path_input = Some(String::new());
        Ok(())
    }

    pub fn set_file_input(&mut self, value: String) {
        let Some(input) = self
            .active
            .and_then(|index| self.tabs.get_mut(index))
            .and_then(|tab| tab.file_path_input.as_mut())
        else {
            return;
        };
        input.clear();
        for character in value.trim().chars() {
            if input.len() + character.len_utf8() > MAX_FILE_PATH_BYTES {
                break;
            }
            if !character.is_control() {
                input.push(character);
            }
        }
    }

    pub fn push_file_input(&mut self, character: char) {
        let Some(input) = self
            .active
            .and_then(|index| self.tabs.get_mut(index))
            .and_then(|tab| tab.file_path_input.as_mut())
        else {
            return;
        };
        if !character.is_control() && input.len() + character.len_utf8() <= MAX_FILE_PATH_BYTES {
            input.push(character);
        }
    }

    pub fn pop_file_input(&mut self) {
        if let Some(input) = self
            .active
            .and_then(|index| self.tabs.get_mut(index))
            .and_then(|tab| tab.file_path_input.as_mut())
        {
            input.pop();
        }
    }

    pub fn cancel_file_input(&mut self) {
        if let Some(tab) = self.active.and_then(|index| self.tabs.get_mut(index)) {
            tab.file_path_input = None;
        }
    }

    pub fn submit_file(&mut self, driver: &mut ApplicationDriver) -> Result<String, String> {
        let index = self.active_index()?;
        let tab = &self.tabs[index];
        if !is_one_to_one_key(&tab.key)
            || tab.phase != ConversationPhase::Standby
            || tab.contact_phase != Some(OneToOnePhase::Ready)
            || tab.offline_mode == Some(OfflineCoordinatorMode::Offline)
        {
            return Err("A live secure 1:1 session is required to send a file.".into());
        }
        let session_id = tab
            .session_id
            .ok_or_else(|| "Contact session is not open.".to_string())?;
        let path = tab
            .file_path_input
            .as_deref()
            .ok_or_else(|| "File path entry is not active.".to_string())?
            .trim();
        if path.is_empty() {
            return Err("File path must not be empty.".into());
        }
        let offered = match driver
            .dispatch_command(CommToolsCommand::OfferFile {
                session_id,
                path: Path::new(path).to_path_buf(),
            })
            .map_err(|error| error.to_string())?
        {
            CommToolsCommandResult::FileOffered(offered) => offered,
            _ => return Err("Unexpected file-offer result.".into()),
        };
        let tab = &mut self.tabs[index];
        tab.file_path_input = None;
        tab.file_names
            .insert(offered.transfer_id, offered.filename.clone());
        tab.push_file_message(
            ChatDirection::Sent,
            offered.transfer_id,
            file_status_text(
                &offered.filename,
                0,
                offered.total_bytes,
                "Waiting for peer",
                None,
            ),
        );
        Ok(offered.filename)
    }

    pub fn begin_image_input(&mut self) -> Result<(), String> {
        let index = self.active_index()?;
        let tab = &self.tabs[index];
        match &tab.key {
            ConversationKey::Contact(_) | ConversationKey::Transient(_) => {
                if tab.phase != ConversationPhase::Standby
                    || tab.contact_phase != Some(OneToOnePhase::Ready)
                    || tab.offline_mode == Some(OfflineCoordinatorMode::Offline)
                {
                    return Err("A live secure 1:1 session is required to send an image.".into());
                }
            }
            ConversationKey::Group(_) => {
                if tab.phase != ConversationPhase::Standby || tab.session_id.is_none() {
                    return Err("The group session must be online before sending an image.".into());
                }
            }
        }
        self.tabs[index].image_path_input = Some(String::new());
        Ok(())
    }

    pub fn set_image_input(&mut self, value: String) {
        let Some(input) = self
            .active
            .and_then(|index| self.tabs.get_mut(index))
            .and_then(|tab| tab.image_path_input.as_mut())
        else {
            return;
        };
        input.clear();
        for character in value.trim().chars() {
            if input.len() + character.len_utf8() > MAX_IMAGE_PATH_BYTES {
                break;
            }
            if !character.is_control() {
                input.push(character);
            }
        }
    }

    pub fn push_image_input(&mut self, character: char) {
        let Some(input) = self
            .active
            .and_then(|index| self.tabs.get_mut(index))
            .and_then(|tab| tab.image_path_input.as_mut())
        else {
            return;
        };
        if !character.is_control() && input.len() + character.len_utf8() <= MAX_IMAGE_PATH_BYTES {
            input.push(character);
        }
    }

    pub fn pop_image_input(&mut self) {
        if let Some(input) = self
            .active
            .and_then(|index| self.tabs.get_mut(index))
            .and_then(|tab| tab.image_path_input.as_mut())
        {
            input.pop();
        }
    }

    pub fn cancel_image_input(&mut self) {
        if let Some(tab) = self.active.and_then(|index| self.tabs.get_mut(index)) {
            tab.image_path_input = None;
        }
    }

    pub fn submit_image(&mut self, driver: &mut ApplicationDriver) -> Result<String, String> {
        let index = self.active_index()?;
        let tab = &self.tabs[index];
        let key = tab.key.clone();
        let session_id = tab
            .session_id
            .ok_or_else(|| "Conversation session is not open.".to_string())?;
        let path = tab
            .image_path_input
            .as_deref()
            .ok_or_else(|| "Image path entry is not active.".to_string())?
            .trim();
        if path.is_empty() {
            return Err("Image path must not be empty.".into());
        }
        match &key {
            ConversationKey::Contact(_) | ConversationKey::Transient(_) => {
                if tab.phase != ConversationPhase::Standby
                    || tab.contact_phase != Some(OneToOnePhase::Ready)
                    || tab.offline_mode == Some(OfflineCoordinatorMode::Offline)
                {
                    return Err("A live secure 1:1 session is required to send an image.".into());
                }
            }
            ConversationKey::Group(_) => {
                if tab.phase != ConversationPhase::Standby {
                    return Err("The group session must be online before sending an image.".into());
                }
            }
        }
        let maximum = match &key {
            ConversationKey::Contact(_) | ConversationKey::Transient(_) => {
                commtools_core::INLINE_IMAGE_TRANSFER_MAX_BYTES
            }
            ConversationKey::Group(_) => {
                commtools_core::group_session::GROUP_IMAGE_TRANSFER_MAX_BYTES
            }
        };
        let image =
            prepare_image_path(Path::new(path), maximum).map_err(|error| error.to_string())?;
        let rendered = image.rendered;
        let command = match (image.original_mime, image.original_bytes) {
            (Some(original_mime), Some(original_bytes)) => {
                CommToolsCommand::SendImageWithOriginal {
                    session_id,
                    filename: image.filename,
                    mime: image.mime,
                    bytes: image.bytes,
                    original: commtools_runtime::OriginalImageData {
                        mime: original_mime,
                        bytes: original_bytes,
                    },
                }
            }
            _ => CommToolsCommand::SendImage {
                session_id,
                filename: image.filename,
                mime: image.mime,
                bytes: image.bytes,
            },
        };
        let sent = match driver
            .dispatch_command(command)
            .map_err(|error| error.to_string())?
        {
            CommToolsCommandResult::ImageSent(sent) => sent,
            _ => return Err("Unexpected image-send result.".into()),
        };
        let description = format!(
            "[image: {}, {}, {} bytes]",
            sent.filename,
            sent.mime,
            sent.bytes.len()
        );
        let filename = sent.filename.clone();
        let tab = &mut self.tabs[index];
        tab.image_path_input = None;
        tab.log.push(format!(
            "Inline image sent: {} ({} bytes).",
            sent.filename,
            sent.bytes.len()
        ));
        tab.push_image(
            ChatDirection::Sent,
            sent.message_id,
            description,
            None,
            (!sent.expected_group_recipients.is_empty())
                .then_some((0, sent.expected_group_recipients.len())),
            sent.bytes,
            Some(rendered),
            sent.original,
            None,
        );
        if let Some(message) = tab.messages.back_mut() {
            message.timestamp_utc = sent.timestamp_utc;
        }
        Ok(filename)
    }

    pub fn receive_image(&mut self, event: &ImageReceivedEvent) {
        let Some(tab) = self
            .tabs
            .iter_mut()
            .find(|tab| tab.session_id == Some(event.session_id))
        else {
            return;
        };
        let rendered = match render_image_bytes(&event.bytes) {
            Ok(rendered) => rendered,
            Err(error) => {
                tab.set_warning(format!("Render inline image: {error}"));
                return;
            }
        };
        let author = event.sender_b32.as_deref().map(|peer_b32| {
            tab.group_member_names
                .get(peer_b32)
                .cloned()
                .unwrap_or_else(|| short_b32(peer_b32))
        });
        let description = format!(
            "[image: {}, {}, {} bytes]",
            event.filename,
            event.mime,
            event.bytes.len()
        );
        tab.log.push(format!(
            "Inline image received: {} ({} bytes).",
            event.filename,
            event.bytes.len()
        ));
        tab.push_image(
            ChatDirection::Received,
            event.message_id,
            description,
            author,
            None,
            event.bytes.clone(),
            Some(rendered),
            event.original.clone(),
            event.sender_b32.clone(),
        );
        if let Some(message) = tab.messages.back_mut() {
            message.timestamp_utc = event.timestamp_utc.clone();
        }
        tab.presentation.unread_text = true;
    }

    pub fn receive_image_delivery(&mut self, event: &ImageDeliveryEvent) {
        let Some(tab) = self
            .tabs
            .iter_mut()
            .find(|tab| tab.session_id == Some(event.session_id))
        else {
            return;
        };
        if let Some(message) = tab.messages.iter_mut().find(|message| {
            message.kind == ChatMessageKind::Image
                && message.direction == ChatDirection::Sent
                && message.message_id == event.message_id
        }) {
            if event.group {
                message.group_delivery = Some((event.received, event.expected));
            } else {
                message.delivered = event.received == event.expected;
            }
        }
    }

    pub fn receive_original_image_progress(
        &mut self,
        session_id: SessionId,
        media_id: u64,
        received_bytes: u64,
        total_bytes: u64,
        sender_b32: Option<&str>,
    ) {
        if let Some(message) = self.original_image_message_mut(session_id, media_id, sender_b32) {
            message.original_state = Some(OriginalImageUiState::Requesting {
                received_bytes,
                total_bytes,
            });
        }
    }

    pub fn receive_original_image(&mut self, event: &OriginalImageReceivedEvent) {
        let rendered = render_image_bytes(&event.bytes);
        let Some(tab) = self.tab_for_session_mut(event.session_id) else {
            return;
        };
        let Some(message_index) =
            find_original_image_message_index(tab, event.media_id, event.sender_b32.as_deref())
        else {
            return;
        };
        let previous_bytes = retained_message_bytes(&tab.messages[message_index]);
        tab.messages[message_index].original_state = Some(OriginalImageUiState::Cached);
        match rendered {
            Ok(rendered) => {
                tab.messages[message_index].image_render = Some(rendered);
                tab.log.push(format!(
                    "Original image received: {} ({} bytes).",
                    event.filename,
                    event.bytes.len()
                ));
            }
            Err(error) => {
                tab.set_warning(format!(
                    "Original image received but cannot be rendered in the terminal: {error}"
                ));
            }
        }
        let current_bytes = retained_message_bytes(&tab.messages[message_index]);
        tab.transcript_bytes = tab
            .transcript_bytes
            .saturating_sub(previous_bytes)
            .saturating_add(current_bytes);
    }

    pub fn original_image_unavailable(
        &mut self,
        session_id: SessionId,
        media_id: u64,
        sender_b32: Option<&str>,
    ) {
        let Some(tab) = self.tab_for_session_mut(session_id) else {
            return;
        };
        if let Some(message) = find_original_image_message_mut(tab, media_id, sender_b32) {
            message.original_state = Some(OriginalImageUiState::Available);
            tab.set_warning("The sender no longer has the requested original image.");
        }
    }

    pub fn original_image_cancelled(
        &mut self,
        session_id: SessionId,
        media_id: u64,
        sender_b32: Option<&str>,
    ) {
        let Some(tab) = self.tab_for_session_mut(session_id) else {
            return;
        };
        if let Some(message) = find_original_image_message_mut(tab, media_id, sender_b32) {
            message.original_state = Some(OriginalImageUiState::Available);
            tab.log.push("Original image transfer cancelled.");
        }
    }

    fn original_image_message_mut(
        &mut self,
        session_id: SessionId,
        media_id: u64,
        sender_b32: Option<&str>,
    ) -> Option<&mut ChatMessage> {
        let tab = self.tab_for_session_mut(session_id)?;
        find_original_image_message_mut(tab, media_id, sender_b32)
    }

    pub fn begin_message_input(&mut self) -> Result<(), String> {
        let index = self.active_index()?;
        let tab = &self.tabs[index];
        match &tab.key {
            ConversationKey::Contact(_) | ConversationKey::Transient(_) => {
                let offline = tab.offline_mode == Some(OfflineCoordinatorMode::Offline);
                if tab.phase != ConversationPhase::Standby
                    || (!offline && tab.contact_phase != Some(OneToOnePhase::Ready))
                {
                    return Err("A secure 1:1 session must be ready before sending text.".into());
                }
            }
            ConversationKey::Group(_) => {
                if tab.phase != ConversationPhase::Standby || tab.session_id.is_none() {
                    return Err("The group session must be online before sending text.".into());
                }
            }
        }
        self.tabs[index].reply_to = None;
        self.tabs[index].presentation.selected_message = None;
        self.tabs[index].message_input = Some(new_message_editor());
        Ok(())
    }

    #[cfg(test)]
    pub fn push_message_input(&mut self, character: char) {
        let mut encoded = [0; 4];
        self.insert_message_input(character.encode_utf8(&mut encoded));
    }

    pub fn insert_message_input(&mut self, value: &str) {
        let Some(index) = self.active.filter(|index| *index < self.tabs.len()) else {
            return;
        };
        let limit = message_input_limit(&self.tabs[index]);
        let Some(editor) = self.tabs[index].message_input.as_mut() else {
            return;
        };
        let remaining = limit.saturating_sub(message_editor_bytes(editor));
        let text = sanitized_message_insert(value, remaining);
        if !text.is_empty() {
            editor.insert_str(text);
        }
    }

    pub fn edit_message_input(&mut self, input: TextAreaInput) {
        let Some(index) = self.active.filter(|index| *index < self.tabs.len()) else {
            return;
        };
        let limit = message_input_limit(&self.tabs[index]);
        let Some(editor) = self.tabs[index].message_input.as_mut() else {
            return;
        };
        let previous = editor.clone();
        editor.input(input);
        if message_editor_bytes(editor) > limit {
            *editor = previous;
        }
    }

    pub fn cancel_message_input(&mut self) {
        if let Some(tab) = self.active.and_then(|index| self.tabs.get_mut(index)) {
            tab.message_input = None;
            tab.reply_to = None;
        }
    }

    pub fn submit_message(&mut self, driver: &mut ApplicationDriver) -> Result<(), String> {
        let index = self.active_index()?;
        let tab = &self.tabs[index];
        let key = tab.key.clone();
        let offline = tab.offline_mode == Some(OfflineCoordinatorMode::Offline);
        let session_id = tab
            .session_id
            .ok_or_else(|| "Conversation session is not open.".to_string())?;
        let editor = tab
            .message_input
            .as_ref()
            .ok_or_else(|| "Message entry is not active.".to_string())?;
        let draft_text = message_editor_text(editor);
        if draft_text.trim().is_empty() {
            return Err("Message must not be empty.".into());
        }
        let text = compose_reply_text(tab.reply_to.as_ref(), &draft_text);
        let maximum_bytes = if offline {
            MAX_OFFLINE_CHAT_TEXT_BYTES
        } else {
            MAX_CHAT_TEXT_BYTES
        };
        if text.len() > maximum_bytes {
            return Err("Message and reply quote exceed the allowed message size.".into());
        }
        match key {
            ConversationKey::Contact(_) | ConversationKey::Transient(_)
                if !offline && tab.contact_phase != Some(OneToOnePhase::Ready) =>
            {
                return Err("A secure 1:1 session must be ready before sending text.".into());
            }
            ConversationKey::Group(_) if tab.phase != ConversationPhase::Standby => {
                return Err("The group session must be online before sending text.".into());
            }
            _ => {}
        }
        let sent = match driver
            .dispatch_command(CommToolsCommand::SendText { session_id, text })
            .map_err(|error| error.to_string())?
        {
            CommToolsCommandResult::TextSent(sent) => sent,
            _ => return Err("Unexpected text-send result.".into()),
        };

        let tab = &mut self.tabs[index];
        tab.message_input = None;
        tab.reply_to = None;
        if sent.offline {
            tab.push_offline_message(ChatDirection::Sent, sent.message_id, sent.text);
        } else {
            tab.push_message(ChatDirection::Sent, sent.message_id, sent.text);
        }
        if let Some(message) = tab.messages.back_mut() {
            message.timestamp_utc = sent.timestamp_utc;
            if !sent.expected_group_recipients.is_empty() {
                message.group_delivery = Some((0, sent.expected_group_recipients.len()));
            }
            message.history = match sent.history {
                HistoryWriteOutcome::Stored => MessageHistoryState::Stored,
                HistoryWriteOutcome::Disabled => MessageHistoryState::NotStored,
            };
        }
        if let Some(warning) = sent.history_warning {
            if let Some(message) = tab.messages.back_mut() {
                message.history = MessageHistoryState::StoreFailed;
            }
            tab.set_warning(warning);
        }
        Ok(())
    }

    pub fn receive_text(&mut self, event: &TextReceivedEvent) {
        let Some(tab) = self
            .tabs
            .iter_mut()
            .find(|tab| tab.session_id == Some(event.session_id))
        else {
            return;
        };
        if event.offline {
            tab.offline_activity.set(OfflineActivityState::Hit);
            if let Some(index) = event.offline_index {
                tab.log.push(format!(
                    "Authenticated offline frame received at index {index}."
                ));
            }
            tab.push_offline_message(
                ChatDirection::Received,
                event.message_id,
                event.text.clone(),
            );
        } else if let Some(peer_b32) = event.sender_b32.as_deref() {
            let author = tab
                .group_member_names
                .get(peer_b32)
                .cloned()
                .unwrap_or_else(|| short_b32(peer_b32));
            tab.push_group_message(
                ChatDirection::Received,
                event.message_id,
                event.text.clone(),
                Some(author),
                None,
            );
        } else {
            tab.push_message(
                ChatDirection::Received,
                event.message_id,
                event.text.clone(),
            );
        }
        if let Some(message) = tab.messages.back_mut() {
            message.timestamp_utc = event.timestamp_utc.clone();
            message.history = match event.history {
                HistoryWriteOutcome::Stored => MessageHistoryState::Stored,
                HistoryWriteOutcome::Disabled => MessageHistoryState::NotStored,
            };
        }
        tab.presentation.unread_text = true;
        if let Some(warning) = &event.history_warning {
            if let Some(message) = tab.messages.back_mut() {
                message.history = MessageHistoryState::StoreFailed;
            }
            tab.set_warning(warning.clone());
        }
        if let Some(warning) = &event.warning {
            tab.set_warning(warning.clone());
        }
    }

    pub fn receive_text_delivery(&mut self, event: &TextDeliveryEvent) {
        let Some(tab) = self
            .tabs
            .iter_mut()
            .find(|tab| tab.session_id == Some(event.session_id))
        else {
            return;
        };
        if let Some(message) = tab.messages.iter_mut().find(|message| {
            message.direction == ChatDirection::Sent && message.message_id == event.message_id
        }) {
            if !event.group {
                message.delivered = event.received == 1;
            } else {
                message.group_delivery = Some((event.received, event.expected));
            }
        }
        if let Some(warning) = &event.warning {
            tab.set_warning(warning.clone());
        }
    }

    pub fn record_text_rejection(
        &mut self,
        session_id: SessionId,
        offline_index: Option<u64>,
        reason: impl Into<String>,
    ) {
        if let Some(tab) = self
            .tabs
            .iter_mut()
            .find(|tab| tab.session_id == Some(session_id))
        {
            if offline_index.is_some() {
                tab.offline_activity.set(OfflineActivityState::Hit);
            }
            tab.set_warning(reason);
        }
    }

    pub fn record_contact_warning(&mut self, session_id: SessionId, warning: impl Into<String>) {
        if let Some(tab) = self
            .tabs
            .iter_mut()
            .find(|tab| tab.session_id == Some(session_id))
        {
            tab.set_warning(warning);
        }
    }

    pub fn close_active(
        &mut self,
        driver: &mut ApplicationDriver,
    ) -> Result<CloseDisposition, String> {
        let Some(index) = self.active.filter(|index| *index < self.tabs.len()) else {
            return Ok(CloseDisposition::None);
        };
        if self.tabs[index].phase == ConversationPhase::Opening {
            return Ok(CloseDisposition::Opening);
        }
        let Some(session_id) = self.tabs[index].session_id else {
            self.remove(index);
            return Ok(CloseDisposition::Removed);
        };
        if self.tabs[index].phase == ConversationPhase::Closing {
            return Ok(CloseDisposition::Closing);
        }
        let previous = self.tabs[index].phase.clone();
        self.tabs[index].phase = ConversationPhase::Closing;
        match driver.dispatch_command(CommToolsCommand::CloseSession { session_id }) {
            Ok(CommToolsCommandResult::SessionCloseStarted(_)) => {}
            Ok(_) => {
                self.tabs[index].phase = previous;
                return Err("Unexpected session-close result.".into());
            }
            Err(error) => {
                self.tabs[index].phase = previous;
                return Err(error.to_string());
            }
        }
        Ok(CloseDisposition::Closing)
    }

    pub fn handle_session_lifecycle_event(&mut self, event: &SessionLifecycleEvent) {
        let (key, log_message) = match event {
            SessionLifecycleEvent::Opening { key } => (key, "Opening SAM session."),
            SessionLifecycleEvent::OpenFailed { key, .. } => (key, "SAM session open failed."),
            SessionLifecycleEvent::Opened { key, .. } => (key, "SAM session initialized."),
            SessionLifecycleEvent::Closing { key, .. } => (key, "Closing conversation session."),
            SessionLifecycleEvent::Closed { key, .. } => (key, ""),
            _ => return,
        };
        if !log_message.is_empty()
            && let Some(tab) = self.tab_for_managed_key_mut(key)
        {
            let message = match event {
                SessionLifecycleEvent::OpenFailed { reason, .. } => {
                    format!("SAM session open failed: {reason}")
                }
                _ => log_message.to_string(),
            };
            tab.log.push(message);
        }
        self.apply_session_lifecycle_event(event);
    }

    fn apply_session_lifecycle_event(&mut self, event: &SessionLifecycleEvent) {
        match event {
            SessionLifecycleEvent::Opening { key } => {
                if let Some(tab) = self.tab_for_managed_key_mut(key) {
                    tab.phase = ConversationPhase::Opening;
                    tab.tofu_state = TofuPresentationState::Inactive;
                }
            }
            SessionLifecycleEvent::OpenFailed { key, reason } => {
                if let Some(tab) = self.tab_for_managed_key_mut(key) {
                    tab.phase = ConversationPhase::Failed(reason.clone());
                    tab.presentation.unseen_warning = true;
                    tab.connect_input = None;
                    tab.rendezvous_panel_open = false;
                    tab.rendezvous_input = None;
                    tab.rendezvous_output = None;
                    tab.rendezvous_authenticated = false;
                    tab.message_input = None;
                    tab.reply_to = None;
                    tab.image_path_input = None;
                    tab.file_path_input = None;
                    tab.tofu_state = TofuPresentationState::Inactive;
                }
            }
            SessionLifecycleEvent::Opened { session_id, key } => {
                if let Some(tab) = self.tab_for_managed_key_mut(key) {
                    tab.session_id = Some(*session_id);
                    tab.phase = ConversationPhase::Standby;
                    tab.last_warning = None;
                    tab.tofu_state = TofuPresentationState::Inactive;
                }
            }
            SessionLifecycleEvent::Closing { session_id, key } => {
                if let Some(tab) = self.tab_for_managed_key_mut(key) {
                    tab.session_id = Some(*session_id);
                    tab.phase = ConversationPhase::Closing;
                    tab.connect_input = None;
                    tab.rendezvous_panel_open = false;
                    tab.rendezvous_input = None;
                    tab.rendezvous_output = None;
                    tab.rendezvous_authenticated = false;
                    tab.message_input = None;
                    tab.reply_to = None;
                    tab.image_path_input = None;
                    tab.file_path_input = None;
                    tab.tofu_state = TofuPresentationState::Inactive;
                }
            }
            SessionLifecycleEvent::Closed { key, .. } => {
                if let Some(index) = self.index_for_managed_key(key) {
                    self.remove(index);
                }
            }
            _ => {}
        }
    }

    pub fn handle_contact_session_event(&mut self, event: &ContactSessionEvent) {
        let Some(session_id) = contact_session_id(event) else {
            return;
        };
        if let Some(message) = contact_session_log_message(event)
            && let Some(tab) = self.tab_for_session_mut(session_id)
        {
            tab.log.push(message);
        }
        self.apply_contact_session_event(session_id, event);
    }

    fn apply_contact_session_event(&mut self, session_id: SessionId, event: &ContactSessionEvent) {
        let Some(tab) = self.tab_for_session_mut(session_id) else {
            return;
        };
        match event {
            ContactSessionEvent::PhaseChanged { phase, .. } => {
                let missed_call = tab.contact_phase == Some(OneToOnePhase::IncomingPending)
                    && tab.incoming_peer_b32.is_some()
                    && *phase != OneToOnePhase::IncomingPending
                    && tab.phase != ConversationPhase::Closing
                    && matches!(phase, OneToOnePhase::Standby | OneToOnePhase::Closing);
                if missed_call {
                    tab.presentation.missed_calls = tab.presentation.missed_calls.saturating_add(1);
                }
                tab.contact_phase = Some(*phase);
                if matches!(phase, OneToOnePhase::Handshaking | OneToOnePhase::Ready)
                    && tab
                        .last_warning
                        .as_deref()
                        .is_some_and(|warning| warning.starts_with("Waiting for peer LeaseSet;"))
                {
                    tab.last_warning = None;
                }
                if *phase != OneToOnePhase::IncomingPending {
                    tab.incoming_peer_b32 = None;
                }
                if *phase != OneToOnePhase::Standby {
                    tab.connect_input = None;
                    tab.rendezvous_panel_open = false;
                    tab.rendezvous_input = None;
                }
                if matches!(phase, OneToOnePhase::Standby | OneToOnePhase::Closed) {
                    tab.rendezvous_authenticated = false;
                }
                if *phase != OneToOnePhase::Ready {
                    tab.message_input = None;
                    tab.reply_to = None;
                    tab.image_path_input = None;
                    tab.file_path_input = None;
                    reset_pending_original_images(tab, None);
                }
            }
            ContactSessionEvent::IncomingCall { peer_b32, .. } => {
                tab.peer_b32 = Some(peer_b32.clone());
                tab.incoming_peer_b32 = Some(peer_b32.clone());
                tab.tofu_state = TofuPresentationState::Inactive;
                tab.rendezvous_authenticated = false;
            }
            ContactSessionEvent::IdentityVerified {
                peer_b32, pinned, ..
            } => {
                tab.peer_b32 = Some(peer_b32.clone());
                tab.tofu_state = if *pinned {
                    TofuPresentationState::Verified
                } else {
                    TofuPresentationState::Inactive
                };
            }
            ContactSessionEvent::SecureSessionReady { peer_b32, .. } => {
                tab.peer_b32 = Some(peer_b32.clone());
            }
            ContactSessionEvent::ConnectFailed {
                peer_b32, reason, ..
            } => {
                tab.peer_b32 = Some(peer_b32.clone());
                tab.set_runtime_warning(format!("Connect failed: {reason}"));
            }
            ContactSessionEvent::ConnectRetryScheduled {
                peer_b32, reason, ..
            } => {
                tab.peer_b32 = Some(peer_b32.clone());
                tab.set_runtime_warning(format!(
                    "Waiting for peer LeaseSet; retrying connection: {reason}"
                ));
            }
            ContactSessionEvent::FrameRejected { reason, .. } => {
                tab.set_runtime_warning(format!("Frame rejected: {reason}"));
            }
            ContactSessionEvent::ConnectionRejected { reason, .. } => {
                tab.set_runtime_warning(format!("Connection rejected: {reason:?}"));
                if *reason == DisconnectReason::TofuMismatch {
                    tab.tofu_state = TofuPresentationState::Mismatch;
                }
            }
            ContactSessionEvent::Disconnected { reason, .. } => {
                tab.tofu_state = if *reason == DisconnectReason::TofuMismatch {
                    TofuPresentationState::Mismatch
                } else {
                    TofuPresentationState::Inactive
                };
            }
            ContactSessionEvent::CollisionResolved { winner, .. } => {
                if *winner == CollisionWinner::Outbound
                    && tab.contact_phase == Some(OneToOnePhase::IncomingPending)
                {
                    tab.incoming_peer_b32 = None;
                }
            }
            _ => {}
        }
    }

    pub fn handle_group_session_event(&mut self, event: &RuntimeGroupSessionEvent) {
        let Some(session_id) = runtime_group_session_id(event) else {
            return;
        };
        if let Some(message) = runtime_group_session_log_message(event)
            && let Some(tab) = self.tab_for_session_mut(session_id)
        {
            tab.log.push(message);
        }
        let Some(tab) = self.tab_for_session_mut(session_id) else {
            return;
        };
        match event {
            RuntimeGroupSessionEvent::ConnectFailed {
                peer_b32, reason, ..
            } => {
                tab.set_runtime_warning(format!(
                    "Connect to group peer {peer_b32} failed: {reason}"
                ));
            }
            RuntimeGroupSessionEvent::SecureSessionReady {
                peer_b32,
                authorized: false,
                ..
            } => {
                tab.set_runtime_warning(format!("Group peer {peer_b32} was not authorized."));
            }
            RuntimeGroupSessionEvent::PeerDisconnected {
                peer_b32, reason, ..
            } => {
                reset_pending_original_images(tab, Some(peer_b32));
                tab.set_runtime_warning(format!("Group peer {peer_b32} disconnected: {reason:?}"));
            }
            RuntimeGroupSessionEvent::FrameRejected {
                peer_b32, reason, ..
            } => {
                tab.set_runtime_warning(format!(
                    "Rejected frame from group peer {peer_b32}: {reason}"
                ));
            }
            _ => {}
        }
    }

    pub fn handle_file_transfer_event(&mut self, event: &RuntimeFileTransferEvent) {
        let Some(session_id) = runtime_file_transfer_session_id(event) else {
            return;
        };
        if let Some(message) = runtime_file_transfer_log_message(event)
            && let Some(tab) = self.tab_for_session_mut(session_id)
        {
            tab.log.push(message);
        }
        let Some(tab) = self.tab_for_session_mut(session_id) else {
            return;
        };
        match event {
            RuntimeFileTransferEvent::Offered {
                transfer_id,
                direction,
                filename,
                total_bytes,
                ..
            } => {
                tab.file_names.insert(*transfer_id, filename.clone());
                tab.file_transfer_states.insert(
                    *transfer_id,
                    match direction {
                        RuntimeFileTransferDirection::Sent => {
                            FileTransferUiState::AwaitingAcceptance
                        }
                        RuntimeFileTransferDirection::Received => {
                            FileTransferUiState::IncomingOffer
                        }
                    },
                );
                if *direction == RuntimeFileTransferDirection::Received {
                    tab.presentation.unread_text = true;
                }
                let direction = runtime_chat_direction(*direction);
                let status = match direction {
                    ChatDirection::Sent => "Waiting for peer",
                    ChatDirection::Received => "Awaiting decision",
                };
                if let Some(message) = tab
                    .messages
                    .iter_mut()
                    .find(|message| message.message_id == *transfer_id)
                {
                    message.text = file_status_text(filename, 0, *total_bytes, status, None);
                } else {
                    tab.push_file_message(
                        direction,
                        *transfer_id,
                        file_status_text(filename, 0, *total_bytes, status, None),
                    );
                }
            }
            RuntimeFileTransferEvent::Started {
                transfer_id,
                direction,
                filename,
                total_bytes,
                ..
            } => {
                tab.file_names.insert(*transfer_id, filename.clone());
                tab.file_transfer_states
                    .insert(*transfer_id, FileTransferUiState::Active);
                let direction = runtime_chat_direction(*direction);
                if let Some(message) = tab
                    .messages
                    .iter_mut()
                    .find(|message| message.message_id == *transfer_id)
                {
                    message.text = file_status_text(filename, 0, *total_bytes, "Starting", None);
                } else {
                    tab.push_file_message(
                        direction,
                        *transfer_id,
                        file_status_text(filename, 0, *total_bytes, "Receiving", None),
                    );
                }
            }
            RuntimeFileTransferEvent::Progress {
                transfer_id,
                transferred_bytes,
                total_bytes,
                ..
            } => {
                let filename = tab
                    .file_names
                    .get(transfer_id)
                    .cloned()
                    .unwrap_or_else(|| "file.bin".into());
                if let Some(message) = tab
                    .messages
                    .iter_mut()
                    .find(|message| message.message_id == *transfer_id)
                {
                    message.text = file_status_text(
                        &filename,
                        *transferred_bytes,
                        *total_bytes,
                        "Transferring",
                        None,
                    );
                }
            }
            RuntimeFileTransferEvent::Completed {
                transfer_id,
                direction,
                filename,
                total_bytes,
                path,
                ..
            } => {
                if let Some(message) = tab
                    .messages
                    .iter_mut()
                    .find(|message| message.message_id == *transfer_id)
                {
                    message.text = file_status_text(
                        filename,
                        *total_bytes,
                        *total_bytes,
                        match direction {
                            RuntimeFileTransferDirection::Sent => "Sent",
                            RuntimeFileTransferDirection::Received => "Received",
                        },
                        path.as_deref(),
                    );
                }
                tab.file_names.remove(transfer_id);
                tab.file_transfer_states.remove(transfer_id);
                tab.clear_selection_for_message(*transfer_id);
            }
            RuntimeFileTransferEvent::Failed {
                transfer_id,
                filename,
                reason,
                ..
            } => {
                let name = filename
                    .clone()
                    .or_else(|| tab.file_names.get(transfer_id).cloned())
                    .unwrap_or_else(|| "file.bin".into());
                if let Some(message) = tab
                    .messages
                    .iter_mut()
                    .find(|message| message.message_id == *transfer_id)
                {
                    message.text = format!("[file: {name}, failed: {reason}]");
                    message.failed = true;
                } else {
                    tab.set_runtime_warning(format!("File transfer failed: {reason}"));
                }
                tab.file_names.remove(transfer_id);
                tab.file_transfer_states.remove(transfer_id);
                tab.clear_selection_for_message(*transfer_id);
            }
            RuntimeFileTransferEvent::Declined {
                transfer_id,
                filename,
                ..
            }
            | RuntimeFileTransferEvent::Cancelled {
                transfer_id,
                filename,
                ..
            }
            | RuntimeFileTransferEvent::Expired {
                transfer_id,
                filename,
                ..
            } => {
                let status = match event {
                    RuntimeFileTransferEvent::Declined { .. } => "Declined",
                    RuntimeFileTransferEvent::Cancelled { .. } => "Cancelled",
                    RuntimeFileTransferEvent::Expired { .. } => "Expired",
                    _ => unreachable!(),
                };
                if let Some(message) = tab
                    .messages
                    .iter_mut()
                    .find(|message| message.message_id == *transfer_id)
                {
                    message.text = format!("[file: {filename}, {status}]");
                }
                tab.file_names.remove(transfer_id);
                tab.file_transfer_states.remove(transfer_id);
                tab.clear_selection_for_message(*transfer_id);
            }
            _ => {}
        }
    }

    pub fn handle_offline_session_event(&mut self, event: &OfflineSessionEvent) {
        let session_id = match event {
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
            | OfflineSessionEvent::ShutdownComplete { session_id } => *session_id,
            _ => return,
        };
        let Some(tab) = self.tab_for_session_mut(session_id) else {
            return;
        };
        if let Some(message) = offline_session_log_message(event) {
            tab.log.push(message);
        }
        match event {
            OfflineSessionEvent::ModeChanged { mode, .. } => {
                tab.offline_mode = Some(*mode);
                tab.offline_activity.set(OfflineActivityState::Idle);
                if *mode != OfflineCoordinatorMode::Offline
                    && tab.contact_phase != Some(OneToOnePhase::Ready)
                {
                    tab.message_input = None;
                    tab.reply_to = None;
                }
            }
            OfflineSessionEvent::SendStarted { .. } => {
                tab.offline_activity.set(OfflineActivityState::Put);
            }
            OfflineSessionEvent::SendConfirmed { message_id, .. } => {
                tab.offline_activity.set(OfflineActivityState::Put);
                if let Some(message) = tab.messages.iter_mut().find(|message| {
                    message.direction == ChatDirection::Sent && message.message_id == *message_id
                }) {
                    message.relayed = true;
                    message.failed = false;
                }
            }
            OfflineSessionEvent::SendFailed {
                message_id,
                index,
                reason,
                ..
            } => {
                tab.offline_activity.set(OfflineActivityState::Fail);
                if let Some(message) = tab.messages.iter_mut().find(|message| {
                    message.direction == ChatDirection::Sent && message.message_id == *message_id
                }) {
                    message.failed = true;
                }
                tab.set_runtime_warning(format!("Offline send failed at index {index}: {reason}"));
            }
            OfflineSessionEvent::UnsupportedFrameReceived {
                index, frame_type, ..
            } => {
                tab.offline_activity.set(OfflineActivityState::Hit);
                tab.set_runtime_warning(format!(
                    "Unsupported offline frame at index {index}: {frame_type}"
                ));
            }
            OfflineSessionEvent::BlobRejected { index, reason, .. } => {
                tab.offline_activity.set(OfflineActivityState::Fail);
                tab.set_runtime_warning(format!(
                    "Rejected offline blob at index {index}: {reason}"
                ));
            }
            OfflineSessionEvent::PollTargetFailed { index, reason, .. } => {
                tab.offline_activity.set(OfflineActivityState::Fail);
                tab.set_runtime_warning(format!("Offline poll failed at index {index}: {reason}"));
            }
            OfflineSessionEvent::PollSweepStarted { .. } => {
                tab.offline_activity.set(OfflineActivityState::Poll);
            }
            OfflineSessionEvent::PollSweepCompleted { result, .. } => {
                tab.offline_activity.set(match result {
                    OfflinePollResult::Hit => OfflineActivityState::Hit,
                    OfflinePollResult::Miss => OfflineActivityState::Miss,
                    OfflinePollResult::Failed => OfflineActivityState::Fail,
                });
            }
            OfflineSessionEvent::EnrollmentPersisted { .. } => {
                if tab
                    .last_warning
                    .as_deref()
                    .is_some_and(|warning| warning.contains("offline enrollment"))
                {
                    tab.last_warning = None;
                }
            }
            _ => {}
        }
    }

    pub fn handle_runtime_operation_event(&mut self, event: &RuntimeOperationEvent) {
        match event {
            RuntimeOperationEvent::Failed {
                session_id: Some(session_id),
                operation,
                reason,
            } => {
                if let Some(tab) = self.tab_for_session_mut(*session_id) {
                    tab.log.push(format!("{operation} failed: {reason}"));
                    tab.set_runtime_warning(format!("{operation}: {reason}"));
                }
            }
            RuntimeOperationEvent::Recovered {
                session_id,
                operation,
            } => {
                if let Some(tab) = self.tab_for_session_mut(*session_id) {
                    tab.log.push(format!("{operation} recovered."));
                    let warning_prefix = format!("{operation}:");
                    if tab
                        .last_warning
                        .as_deref()
                        .is_some_and(|warning| warning.starts_with(&warning_prefix))
                    {
                        tab.last_warning = None;
                    }
                }
            }
            _ => {}
        }
    }

    pub fn handle_rendezvous_session_event(&mut self, event: &RendezvousSessionEvent) {
        let (session_id, log_message) = match event {
            RendezvousSessionEvent::OutgoingAuthenticated {
                session_id,
                peer_b32,
            } => (
                *session_id,
                format!(
                    "Outgoing rendezvous authenticated with {}.",
                    short_b32(peer_b32)
                ),
            ),
            RendezvousSessionEvent::IncomingAuthenticated {
                session_id,
                peer_b32,
            } => (
                *session_id,
                format!(
                    "Incoming rendezvous authenticated with {}.",
                    short_b32(peer_b32)
                ),
            ),
            RendezvousSessionEvent::InvitationConsumed {
                session_id,
                peer_b32,
            } => (
                *session_id,
                format!("Rendezvous invitation consumed by {}.", short_b32(peer_b32)),
            ),
            RendezvousSessionEvent::AuthenticationRejected {
                session_id,
                peer_b32,
                reason,
            } => (
                *session_id,
                format!(
                    "Rendezvous authentication from {} rejected: {reason}",
                    short_b32(peer_b32)
                ),
            ),
            _ => return,
        };
        let Some(tab) = self.tab_for_session_mut(session_id) else {
            return;
        };
        tab.log.push(log_message);
        match event {
            RendezvousSessionEvent::OutgoingAuthenticated { peer_b32, .. } => {
                tab.peer_b32 = Some(peer_b32.clone());
                tab.rendezvous_authenticated = true;
                tab.rendezvous_output = None;
            }
            RendezvousSessionEvent::IncomingAuthenticated { peer_b32, .. } => {
                tab.peer_b32 = Some(peer_b32.clone());
                tab.rendezvous_authenticated = true;
                tab.last_warning = None;
            }
            RendezvousSessionEvent::InvitationConsumed { .. } => {
                tab.rendezvous_authenticated = true;
                tab.rendezvous_output = None;
            }
            RendezvousSessionEvent::AuthenticationRejected { reason, .. } => {
                tab.rendezvous_authenticated = false;
                tab.set_runtime_warning(format!("Rendezvous authentication rejected: {reason}"));
            }
            _ => {}
        }
    }

    pub fn render_tabs(&self, frame: &mut Frame<'_>, area: Rect, driver: &ApplicationDriver) {
        let snapshot = driver.snapshot().ok();
        let labels = self
            .tabs
            .iter()
            .map(|tab| {
                let group_connected = match &tab.key {
                    ConversationKey::Group(group_id) => snapshot.as_ref().is_some_and(|snapshot| {
                        snapshot
                            .groups
                            .iter()
                            .any(|group| &group.id == group_id && group.ready_member_count > 0)
                    }),
                    _ => false,
                };
                tab.rendered_label(self.tab_spinner_frame, group_connected)
            })
            .collect::<Vec<_>>();
        if labels.is_empty() {
            frame.render_widget(Block::default().borders(Borders::BOTTOM), area);
            return;
        }
        let selected = self
            .active
            .unwrap_or(0)
            .min(self.tabs.len().saturating_sub(1));
        let visible = visible_tab_range(&labels, selected, area.width);
        let selected_visible = selected.saturating_sub(visible.start);
        let visible_labels = labels[visible]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        frame.render_widget(
            TabNav::new(&visible_labels, selected_visible)
                .style(Style::default().fg(Color::DarkGray))
                .highlight_style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .border_style(Style::default().fg(Color::DarkGray))
                .indicator(None),
            area,
        );
    }

    pub fn render_active(&mut self, frame: &mut Frame<'_>, area: Rect, driver: &ApplicationDriver) {
        let Some(tab) = self.active.and_then(|index| self.tabs.get_mut(index)) else {
            frame.render_widget(
                Paragraph::new("No conversation is open.")
                    .block(Block::default().borders(Borders::ALL)),
                area,
            );
            return;
        };
        let is_group = matches!(&tab.key, ConversationKey::Group(_));
        let phase = match (&tab.phase, tab.contact_phase, tab.offline_mode) {
            (ConversationPhase::Opening, _, _) if is_group => "Opening group session",
            (ConversationPhase::Standby, _, _) if is_group => "Group session active",
            (ConversationPhase::Closing, _, _) if is_group => "Closing group session",
            (ConversationPhase::Failed(_), _, _) if is_group => "Group session failed",
            (ConversationPhase::Standby, _, Some(OfflineCoordinatorMode::Offline)) => "Offline",
            (ConversationPhase::Standby, Some(contact_phase), _) => {
                contact_phase_label(contact_phase)
            }
            (ConversationPhase::Idle, _, _) => "Not started",
            (ConversationPhase::Opening, _, _) => "Opening SAM session",
            (ConversationPhase::Standby, _, _) => "Online standby",
            (ConversationPhase::Closing, _, _) => "Closing",
            (ConversationPhase::Failed(_), _, _) => "Failed",
        };
        let mut summary_spans = Vec::new();
        if matches!(&tab.key, ConversationKey::Transient(_)) {
            push_status_badge(&mut summary_spans, "T", Color::Yellow);
        } else {
            push_status_badge(&mut summary_spans, "P", Color::Green);
        }
        if matches!(&tab.key, ConversationKey::Group(_)) {
            push_status_badge(&mut summary_spans, "G", Color::Green);
        }
        let mut detail_lines = Vec::new();
        let mut alert_lines = Vec::new();
        let mut transcript_lines = Vec::new();
        let mut selected_line_range = None;
        let app_snapshot = driver.snapshot().ok();
        if let ConversationKey::Contact(contact_id) = &tab.key {
            let record = app_snapshot.as_ref().and_then(|snapshot| {
                snapshot
                    .contacts
                    .iter()
                    .find(|contact| &contact.id == contact_id)
            });
            let local_b32 = record
                .and_then(|contact| contact.local_b32.as_deref())
                .unwrap_or("Not initialized");
            let peer_b32 = tab
                .peer_b32
                .as_deref()
                .or_else(|| record.and_then(|contact| contact.peer_b32.as_deref()))
                .unwrap_or("Not connected");
            let trust = if record.is_some_and(|contact| contact.peer_pinned) {
                "Locked"
            } else {
                "Unlocked"
            };
            let offline = match tab.offline_mode {
                Some(OfflineCoordinatorMode::Offline) => "Active",
                Some(OfflineCoordinatorMode::Standby) => "Available",
                Some(OfflineCoordinatorMode::Closing) => "Closing",
                Some(OfflineCoordinatorMode::Closed) => "Closed",
                None => "Unavailable",
            };
            push_status_badge(
                &mut summary_spans,
                if trust == "Locked" { "LOCK" } else { "UNLOCK" },
                if trust == "Locked" {
                    Color::Green
                } else {
                    Color::Red
                },
            );
            if tab.offline_mode != Some(OfflineCoordinatorMode::Offline) {
                match tab.tofu_state {
                    TofuPresentationState::Verified => {
                        push_status_badge(&mut summary_spans, "TOFU", Color::Green);
                    }
                    TofuPresentationState::Mismatch => {
                        push_status_badge(&mut summary_spans, "TOFU", Color::Red);
                    }
                    TofuPresentationState::Inactive => {}
                }
            }
            if tab.offline_mode == Some(OfflineCoordinatorMode::Offline) {
                push_status_badge(&mut summary_spans, "OFF", Color::Yellow);
                let (label, color) = offline_activity_badge(tab.offline_activity.visible_state());
                push_status_badge(&mut summary_spans, label, color);
            }
            if tab.rendezvous_authenticated {
                push_status_badge(&mut summary_spans, "AUTH", Color::Green);
            }
            push_history_and_state(
                &mut summary_spans,
                record.is_some_and(|contact| contact.history_enabled),
                phase,
            );
            detail_lines.push(detail_line("[1] My B32", local_b32));
            detail_lines.push(detail_line("[2] Peer B32", peer_b32));
            detail_lines.push(detail_line("Copy", "1 local, 2 peer"));
            detail_lines.push(detail_line("Offline messaging", offline));
            if let Some(peer_b32) = &tab.incoming_peer_b32 {
                detail_lines.push(detail_line("Incoming call", peer_b32));
            }
            for (message_index, message) in tab.messages.iter().enumerate() {
                let author = message_display_author(message);
                let message_start = transcript_lines.len();
                append_message_bubble(
                    &mut transcript_lines,
                    message,
                    &author,
                    contact_delivery_label(message).as_deref(),
                    tab.presentation.selected_message == Some(message_index),
                    area.width.saturating_sub(2),
                );
                if tab.presentation.selected_message == Some(message_index) {
                    selected_line_range = Some((message_start, transcript_lines.len()));
                }
            }
        } else if matches!(&tab.key, ConversationKey::Transient(_)) {
            let session = tab
                .session_id
                .and_then(|session_id| driver.session_summary(session_id));
            let local_b32 = session
                .as_ref()
                .and_then(|session| session.local_b32.as_deref())
                .unwrap_or("Not initialized");
            let peer_b32 = tab
                .peer_b32
                .as_deref()
                .or_else(|| {
                    session
                        .as_ref()
                        .and_then(|session| session.peer_b32.as_deref())
                })
                .unwrap_or("Not connected");
            if tab.rendezvous_authenticated {
                push_status_badge(&mut summary_spans, "AUTH", Color::Green);
            }
            push_history_and_state(&mut summary_spans, false, phase);
            detail_lines.push(detail_line("[1] My transient B32", local_b32));
            detail_lines.push(detail_line("[2] Peer B32", peer_b32));
            detail_lines.push(detail_line(
                "Retention",
                "Ephemeral; history and offline disabled",
            ));
            if let Some(peer_b32) = &tab.incoming_peer_b32 {
                detail_lines.push(detail_line("Incoming call", peer_b32));
            }
            for (message_index, message) in tab.messages.iter().enumerate() {
                let author = message_display_author(message);
                let message_start = transcript_lines.len();
                append_message_bubble(
                    &mut transcript_lines,
                    message,
                    &author,
                    contact_delivery_label(message).as_deref(),
                    tab.presentation.selected_message == Some(message_index),
                    area.width.saturating_sub(2),
                );
                if tab.presentation.selected_message == Some(message_index) {
                    selected_line_range = Some((message_start, transcript_lines.len()));
                }
            }
        } else if let ConversationKey::Group(group_id) = &tab.key {
            let record = app_snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.groups.iter().find(|group| &group.id == group_id));
            let local_b32 = record
                .and_then(|group| group.local_b32.as_deref())
                .unwrap_or("Not initialized");
            let owner_b32 = record
                .and_then(|group| group.owner_b32.as_deref())
                .unwrap_or("Not initialized");
            let role = if local_b32 == "Not initialized" || owner_b32 == "Not initialized" {
                "Unknown"
            } else if local_b32.eq_ignore_ascii_case(owner_b32) {
                "Owner"
            } else {
                "Member"
            };
            if let Some(local_name) = record
                .map(|group| group.local_member_name.trim())
                .filter(|name| !name.is_empty())
            {
                push_inline_detail(&mut summary_spans, "Name", local_name);
            }
            push_inline_detail(&mut summary_spans, "Role", role);
            detail_lines.push(detail_line("[1] My group B32", local_b32));
            detail_lines.push(detail_line("[2] Owner B32", owner_b32));
            detail_lines.push(detail_line("Copy", "1 local, 2 owner"));
            if let Some(group) = record.filter(|group| group.active) {
                let total_members = group.members.len().max(1);
                let active_members = group.ready_member_count.saturating_add(1);
                push_inline_detail(
                    &mut summary_spans,
                    "Active",
                    &format!("{active_members}/{total_members}"),
                );
            }
            push_history_and_state(
                &mut summary_spans,
                record.is_some_and(|group| group.history_enabled),
                phase,
            );
            for (message_index, message) in tab.messages.iter().enumerate() {
                let author = message_display_author(message);
                let message_start = transcript_lines.len();
                append_message_bubble(
                    &mut transcript_lines,
                    message,
                    &author,
                    group_delivery_label(message).as_deref(),
                    tab.presentation.selected_message == Some(message_index),
                    area.width.saturating_sub(2),
                );
                if tab.presentation.selected_message == Some(message_index) {
                    selected_line_range = Some((message_start, transcript_lines.len()));
                }
            }
        }
        if let ConversationPhase::Failed(reason) = &tab.phase {
            alert_lines.push(Line::from(Span::styled(
                reason.as_str(),
                Style::default().fg(Color::Red),
            )));
        }
        if let Some(warning) = &tab.last_warning {
            detail_lines.push(detail_line("Last runtime warning", warning));
        }

        let mut header_lines = vec![Line::from(summary_spans)];
        if tab.presentation.details_expanded {
            header_lines.extend(detail_lines);
        }
        header_lines.extend(alert_lines);

        if transcript_lines.is_empty() {
            transcript_lines.push(Line::from(Span::styled(
                "No messages yet.",
                Style::default().fg(Color::DarkGray),
            )));
        }

        let composer_line = if tab.presentation.logs_open {
            Some(Line::from(Span::styled(
                "Logs: PgUp/PgDn scroll  Home/End oldest/latest  c copy all  L/Esc close",
                Style::default().fg(Color::DarkGray),
            )))
        } else if tab.message_input.is_some() {
            None
        } else if let Some(input) = &tab.rendezvous_input {
            Some(detail_line(
                match input.kind {
                    RendezvousInputKind::AnswerRequest => "Rendezvous request",
                    RendezvousInputKind::ConnectResponse => "Rendezvous response",
                },
                &format!(
                    "{} bytes pasted; Enter submits, Esc cancels",
                    input.value.len()
                ),
            ))
        } else if let Some(input) = &tab.connect_input {
            Some(detail_line("Connect to B32", input))
        } else if let Some(input) = &tab.image_path_input {
            Some(detail_line("Image path", input))
        } else if let Some(input) = &tab.file_path_input {
            Some(detail_line("File path", input))
        } else if let Some(state) = selected_original_image_ui_state(tab) {
            Some(Line::from(Span::styled(
                match state {
                    OriginalImageUiState::Available => {
                        "Selected image: g request original  Esc clear selection"
                    }
                    OriginalImageUiState::Requesting { .. } => {
                        "Selected original download: X cancel  Esc clear selection"
                    }
                    OriginalImageUiState::Cached => {
                        "Selected image: original cached in memory  g reload  Esc clear selection"
                    }
                },
                Style::default().fg(Color::DarkGray),
            )))
        } else if let Some(state) = selected_file_ui_state(tab) {
            Some(Line::from(Span::styled(
                match state {
                    FileTransferUiState::IncomingOffer => {
                        "Selected file offer: y accept  n decline  Esc clear selection"
                    }
                    FileTransferUiState::AwaitingAcceptance | FileTransferUiState::Active => {
                        "Selected file transfer: X cancel  Esc clear selection"
                    }
                },
                Style::default().fg(Color::DarkGray),
            )))
        } else {
            let mut actions = match &tab.key {
                ConversationKey::Contact(_) => {
                    if tab.rendezvous_panel_open {
                        "Rendezvous: g request  a answer request  c connect response  v copy output  r revoke  z close".to_string()
                    } else {
                        "m message  a image  f file  c connect/copy  z rendezvous  r reply  o offline  i details  L logs  x close  Up/Down select  PgUp/PgDn scroll".to_string()
                    }
                }
                ConversationKey::Transient(_) => {
                    if tab.rendezvous_panel_open {
                        "Rendezvous: g request  a answer request  c connect response  v copy output  r revoke  z close".to_string()
                    } else {
                        "m message  a image  f file  c connect/copy  z rendezvous  r reply  i details  L logs  x close  Up/Down select  PgUp/PgDn scroll".to_string()
                    }
                }
                ConversationKey::Group(_) => {
                    "m message  a image  c copy  r reply  i details  L logs  x close  Up/Down select  PgUp/PgDn scroll".to_string()
                }
            };
            if tab.presentation.details_expanded {
                actions.push_str("  1/2 copy B32");
            }
            Some(Line::from(Span::styled(
                actions,
                Style::default().fg(Color::DarkGray),
            )))
        };

        let header_width = area.width.saturating_sub(2);
        let desired_header_height = wrapped_line_count(&header_lines, header_width)
            .saturating_add(2)
            .min(usize::from(u16::MAX)) as u16;
        let header_height = desired_header_height.min(area.height.saturating_sub(6).max(1));
        let composer_height = tab.message_input.as_mut().map_or(3, |editor| {
            editor.measure(area.width).preferred_rows.min(
                area.height
                    .saturating_sub(header_height.saturating_add(3))
                    .max(3),
            )
        });
        let sections = Layout::vertical([
            Constraint::Length(header_height),
            Constraint::Fill(1),
            Constraint::Length(composer_height),
        ])
        .split(area);

        frame.render_widget(
            Paragraph::new(header_lines)
                .wrap(Wrap { trim: false })
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!(" {} ", tab.label)),
                ),
            sections[0],
        );

        let (transcript_area, log_area) = if tab.presentation.logs_open {
            let content_sections =
                Layout::vertical([Constraint::Fill(2), Constraint::Fill(1)]).split(sections[1]);
            (content_sections[0], Some(content_sections[1]))
        } else {
            (sections[1], None)
        };
        let transcript_width = transcript_area.width.saturating_sub(2);
        let transcript_height = usize::from(transcript_area.height.saturating_sub(2));
        let transcript_line_count = wrapped_line_count(&transcript_lines, transcript_width);
        let maximum_scroll = transcript_line_count.saturating_sub(transcript_height);
        tab.presentation.transcript_max_scroll = maximum_scroll;
        tab.presentation.transcript_page_lines = transcript_height.saturating_sub(1).max(1);
        if tab.presentation.follow_latest {
            tab.presentation.transcript_scroll = maximum_scroll;
        } else {
            tab.presentation.transcript_scroll =
                tab.presentation.transcript_scroll.min(maximum_scroll);
        }
        if let Some((selected_start, selected_end)) = selected_line_range {
            tab.presentation.follow_latest = false;
            if selected_start < tab.presentation.transcript_scroll {
                tab.presentation.transcript_scroll = selected_start;
            } else if selected_end
                > tab
                    .presentation
                    .transcript_scroll
                    .saturating_add(transcript_height)
            {
                tab.presentation.transcript_scroll = selected_end
                    .saturating_sub(transcript_height)
                    .min(maximum_scroll);
            }
        }
        let scroll = tab
            .presentation
            .transcript_scroll
            .min(usize::from(u16::MAX)) as u16;
        let transcript_title = if tab.presentation.selected_message.is_some() {
            " Messages (entry selected) ".to_string()
        } else if tab.presentation.follow_latest {
            " Messages ".to_string()
        } else {
            " Messages (scrolling) ".to_string()
        };
        frame.render_widget(
            Paragraph::new(transcript_lines)
                .wrap(Wrap { trim: false })
                .scroll((scroll, 0))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(transcript_title),
                ),
            transcript_area,
        );
        if maximum_scroll > 0 && transcript_area.height > 2 {
            let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .track_style(Style::default().fg(Color::DarkGray))
                .thumb_style(Style::default().fg(Color::Cyan));
            let mut scrollbar_state = ScrollbarState::new(transcript_line_count)
                .position(tab.presentation.transcript_scroll)
                .viewport_content_length(transcript_height);
            frame.render_stateful_widget(
                scrollbar,
                transcript_area.inner(Margin {
                    vertical: 1,
                    horizontal: 0,
                }),
                &mut scrollbar_state,
            );
        }

        if let Some(log_area) = log_area {
            render_log_panel(frame, tab, log_area);
        }

        if let Some(editor) = tab.message_input.as_mut() {
            if let Some(reply) = &tab.reply_to {
                editor.set_block(Block::default().borders(Borders::ALL).title(format!(
                    " Replying to {}: {} ",
                    reply.author,
                    compact_reply_preview(&reply.text, 48)
                )));
            }
            frame.render_widget(&*editor, sections[2]);
        } else if let Some(composer_line) = composer_line {
            frame.render_widget(
                Paragraph::new(composer_line)
                    .wrap(Wrap { trim: false })
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" Input / Actions "),
                    ),
                sections[2],
            );
        }
    }

    fn index_for_managed_key(&self, key: &ManagedSessionKey) -> Option<usize> {
        self.tabs.iter().position(|tab| match (&tab.key, key) {
            (ConversationKey::Contact(left), ManagedSessionKey::Contact(right)) => left == right,
            (ConversationKey::Transient(left), ManagedSessionKey::Transient(right)) => {
                left == right
            }
            (ConversationKey::Group(left), ManagedSessionKey::Group(right)) => left == right,
            _ => false,
        })
    }

    fn index_for_key(&self, key: &ConversationKey) -> Option<usize> {
        self.tabs.iter().position(|tab| &tab.key == key)
    }

    fn active_index(&self) -> Result<usize, String> {
        self.active
            .filter(|index| *index < self.tabs.len())
            .ok_or_else(|| "No conversation is active.".to_string())
    }

    fn tab_for_managed_key_mut(&mut self, key: &ManagedSessionKey) -> Option<&mut ConversationTab> {
        let index = self.index_for_managed_key(key)?;
        self.tabs.get_mut(index)
    }

    fn tab_for_session_mut(&mut self, session_id: SessionId) -> Option<&mut ConversationTab> {
        self.tabs
            .iter_mut()
            .find(|tab| tab.session_id == Some(session_id))
    }

    fn remove(&mut self, index: usize) {
        self.tabs.remove(index);
        self.active = if self.tabs.is_empty() {
            None
        } else {
            Some(index.min(self.tabs.len() - 1))
        };
    }
}

impl ConversationTab {
    fn clear_selection_for_message(&mut self, message_id: u64) {
        if self
            .presentation
            .selected_message
            .and_then(|selected| self.messages.get(selected))
            .is_some_and(|message| message.message_id == message_id)
        {
            self.presentation.selected_message = None;
        }
    }

    fn set_warning(&mut self, warning: impl Into<String>) {
        let warning = warning.into();
        self.log.push(warning.clone());
        self.set_runtime_warning(warning);
    }

    fn set_runtime_warning(&mut self, warning: impl Into<String>) {
        self.last_warning = Some(warning.into());
        self.presentation.unseen_warning = true;
    }

    fn list_state(&self) -> ConversationTabState {
        if self.phase == ConversationPhase::Closing {
            ConversationTabState::Closing
        } else {
            ConversationTabState::Open
        }
    }

    fn push_message(&mut self, direction: ChatDirection, message_id: u64, text: String) {
        self.push_text_message(direction, message_id, text, None, None, false);
    }

    fn push_offline_message(&mut self, direction: ChatDirection, message_id: u64, text: String) {
        self.push_text_message(direction, message_id, text, None, None, true);
    }

    fn push_file_message(&mut self, direction: ChatDirection, message_id: u64, text: String) {
        self.push_transcript_message(ChatMessage {
            direction,
            kind: ChatMessageKind::File,
            offline: false,
            message_id,
            timestamp_utc: current_utc_hms(),
            text,
            image_bytes: None,
            image_render: None,
            original: None,
            original_sender_b32: None,
            original_state: None,
            author: None,
            group_delivery: None,
            relayed: false,
            delivered: false,
            failed: false,
            history: MessageHistoryState::NotStored,
        });
    }

    fn push_group_message(
        &mut self,
        direction: ChatDirection,
        message_id: u64,
        text: String,
        author: Option<String>,
        group_delivery: Option<(usize, usize)>,
    ) {
        self.push_text_message(direction, message_id, text, author, group_delivery, false);
    }

    fn push_text_message(
        &mut self,
        direction: ChatDirection,
        message_id: u64,
        text: String,
        author: Option<String>,
        group_delivery: Option<(usize, usize)>,
        offline: bool,
    ) {
        self.push_transcript_message(ChatMessage {
            direction,
            kind: ChatMessageKind::Text,
            offline,
            message_id,
            timestamp_utc: current_utc_hms(),
            text,
            image_bytes: None,
            image_render: None,
            original: None,
            original_sender_b32: None,
            original_state: None,
            author,
            group_delivery,
            relayed: false,
            delivered: false,
            failed: false,
            history: MessageHistoryState::NotStored,
        });
    }

    fn push_image(
        &mut self,
        direction: ChatDirection,
        message_id: u64,
        text: String,
        author: Option<String>,
        group_delivery: Option<(usize, usize)>,
        image_bytes: Vec<u8>,
        image_render: Option<RenderedImage>,
        original: Option<OriginalImageMetadata>,
        original_sender_b32: Option<String>,
    ) {
        let original_state = (direction == ChatDirection::Received && original.is_some())
            .then_some(OriginalImageUiState::Available);
        self.push_transcript_message(ChatMessage {
            direction,
            kind: ChatMessageKind::Image,
            offline: false,
            message_id,
            timestamp_utc: current_utc_hms(),
            text,
            image_bytes: Some(image_bytes),
            image_render,
            original,
            original_sender_b32,
            original_state,
            author,
            group_delivery,
            relayed: false,
            delivered: false,
            failed: false,
            history: MessageHistoryState::NotStored,
        });
    }

    fn push_transcript_message(&mut self, message: ChatMessage) {
        let message_bytes = retained_message_bytes(&message);
        let transcript_limit = match &self.key {
            ConversationKey::Contact(_) | ConversationKey::Transient(_) => {
                commtools_core::INLINE_IMAGE_TRANSFER_MAX_BYTES
                    + TRANSCRIPT_RENDER_ALLOWANCE
                    + TRANSCRIPT_METADATA_ALLOWANCE
            }
            ConversationKey::Group(_) => {
                commtools_core::group_session::GROUP_IMAGE_TRANSFER_MAX_BYTES
                    + TRANSCRIPT_RENDER_ALLOWANCE
                    + TRANSCRIPT_METADATA_ALLOWANCE
            }
        };
        while !self.messages.is_empty()
            && (self.messages.len() >= MAX_TRANSCRIPT_MESSAGES
                || self.transcript_bytes.saturating_add(message_bytes) > transcript_limit)
        {
            if let Some(removed) = self.messages.pop_front() {
                let removed_bytes = retained_message_bytes(&removed);
                self.transcript_bytes = self.transcript_bytes.saturating_sub(removed_bytes);
                self.loaded_history_count = self.loaded_history_count.saturating_sub(1);
                self.presentation.selected_message = self
                    .presentation
                    .selected_message
                    .and_then(|selected| selected.checked_sub(1));
            }
        }
        self.transcript_bytes = self.transcript_bytes.saturating_add(message_bytes);
        self.messages.push_back(message);
    }

    fn rendered_label(&self, spinner_frame: usize, group_connected: bool) -> String {
        let display_label = if matches!(&self.key, ConversationKey::Group(_)) {
            format!("#{}", self.label)
        } else {
            self.label.clone()
        };
        let mut label = match &self.phase {
            ConversationPhase::Failed(_) => format!("{display_label} !"),
            ConversationPhase::Opening => format!(
                "{} {}",
                display_label,
                TAB_OPENING_SPINNER[spinner_frame % TAB_OPENING_SPINNER.len()]
            ),
            ConversationPhase::Closing => format!("{display_label} ..."),
            _ => display_label,
        };
        if let Some(marker) = self.activity_marker(spinner_frame, group_connected) {
            label.push(' ');
            label.push(marker);
        }
        if self.presentation.missed_calls > 0 {
            label.push(' ');
            label.push_str(&self.presentation.missed_calls.to_string());
        }
        if self.presentation.unread_text {
            label.push_str(" +");
        }
        if self.presentation.unseen_warning && !matches!(self.phase, ConversationPhase::Failed(_)) {
            label.push_str(" !");
        }
        label
    }

    fn activity_marker(&self, spinner_frame: usize, group_connected: bool) -> Option<char> {
        if self.has_incoming_call() {
            return Some(tab_activity_pulse(spinner_frame));
        }
        self.has_live_connection(group_connected).then_some('◆')
    }

    fn has_incoming_call(&self) -> bool {
        self.phase == ConversationPhase::Standby
            && self.contact_phase == Some(OneToOnePhase::IncomingPending)
    }

    fn has_live_connection(&self, group_connected: bool) -> bool {
        if self.phase != ConversationPhase::Standby {
            return false;
        }
        match &self.key {
            ConversationKey::Group(_) => group_connected,
            ConversationKey::Contact(_) | ConversationKey::Transient(_) => {
                self.contact_phase == Some(OneToOnePhase::Ready)
                    && self.offline_mode != Some(OfflineCoordinatorMode::Offline)
            }
        }
    }
}

fn tab_activity_pulse(spinner_frame: usize) -> char {
    if spinner_frame < TAB_OPENING_SPINNER.len() / 2 {
        '◆'
    } else {
        '◇'
    }
}

impl ChatMessage {
    fn from_history(record: HistoryRecord) -> Self {
        let group_delivery = (!record.group_expected_acks.is_empty()).then_some((
            record.group_received_acks.len(),
            record.group_expected_acks.len(),
        ));
        Self {
            direction: if record.mine {
                ChatDirection::Sent
            } else {
                ChatDirection::Received
            },
            kind: ChatMessageKind::Text,
            offline: record.offline,
            message_id: record.msg_id.unwrap_or_else(generate_message_id),
            timestamp_utc: record.timestamp_utc,
            text: record.text,
            image_bytes: None,
            image_render: None,
            original: None,
            original_sender_b32: None,
            original_state: None,
            author: (!record.mine).then_some(record.author),
            group_delivery,
            relayed: record.offline && record.mine,
            delivered: record.delivered,
            failed: false,
            history: MessageHistoryState::Stored,
        }
    }
}

fn managed_key(key: &ConversationKey) -> ManagedSessionKey {
    match key {
        ConversationKey::Contact(contact_id) => ManagedSessionKey::Contact(contact_id.clone()),
        ConversationKey::Transient(transient_id) => {
            ManagedSessionKey::Transient(transient_id.clone())
        }
        ConversationKey::Group(group_id) => ManagedSessionKey::Group(group_id.clone()),
    }
}

fn is_one_to_one_key(key: &ConversationKey) -> bool {
    matches!(
        key,
        ConversationKey::Contact(_) | ConversationKey::Transient(_)
    )
}

fn retained_message_bytes(message: &ChatMessage) -> usize {
    let image_bytes = message.image_bytes.as_ref().map_or(0, Vec::len);
    let rendered_bytes = message.image_render.as_ref().map_or(0, |image| {
        image
            .lines
            .iter()
            .map(|line| {
                line.len()
                    .saturating_mul(std::mem::size_of::<RenderedImageCell>())
            })
            .sum::<usize>()
    });
    message
        .text
        .len()
        .saturating_add(message.timestamp_utc.len())
        .saturating_add(image_bytes)
        .saturating_add(rendered_bytes)
}

fn selected_text_message(tab: &ConversationTab) -> Result<&ChatMessage, String> {
    let selected = tab
        .presentation
        .selected_message
        .ok_or_else(|| "Select a text message with Up or Down first.".to_string())?;
    tab.messages
        .get(selected)
        .filter(|message| message.kind == ChatMessageKind::Text)
        .ok_or_else(|| "The selected transcript entry is not a text message.".to_string())
}

fn selected_file_ui_state(tab: &ConversationTab) -> Option<FileTransferUiState> {
    let message = tab
        .presentation
        .selected_message
        .and_then(|selected| tab.messages.get(selected))?;
    (message.kind == ChatMessageKind::File)
        .then(|| tab.file_transfer_states.get(&message.message_id).copied())
        .flatten()
}

fn selected_original_image_ui_state(tab: &ConversationTab) -> Option<&OriginalImageUiState> {
    tab.presentation
        .selected_message
        .and_then(|selected| tab.messages.get(selected))
        .and_then(|message| message.original_state.as_ref())
}

fn find_original_image_message_mut<'a>(
    tab: &'a mut ConversationTab,
    media_id: u64,
    sender_b32: Option<&str>,
) -> Option<&'a mut ChatMessage> {
    let index = find_original_image_message_index(tab, media_id, sender_b32)?;
    tab.messages.get_mut(index)
}

fn find_original_image_message_index(
    tab: &ConversationTab,
    media_id: u64,
    sender_b32: Option<&str>,
) -> Option<usize> {
    tab.messages.iter().position(|message| {
        message.kind == ChatMessageKind::Image
            && message.direction == ChatDirection::Received
            && message.message_id == media_id
            && optional_b32_eq(message.original_sender_b32.as_deref(), sender_b32)
    })
}

fn reset_pending_original_images(tab: &mut ConversationTab, sender_b32: Option<&str>) {
    for message in &mut tab.messages {
        let sender_matches = sender_b32.is_none()
            || optional_b32_eq(message.original_sender_b32.as_deref(), sender_b32);
        if sender_matches
            && matches!(
                message.original_state,
                Some(OriginalImageUiState::Requesting { .. })
            )
        {
            message.original_state = Some(OriginalImageUiState::Available);
        }
    }
}

fn optional_b32_eq(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        (None, None) => true,
        _ => false,
    }
}

fn original_image_status(message: &ChatMessage) -> Option<String> {
    let metadata = message.original.as_ref()?;
    match message.original_state.as_ref()? {
        OriginalImageUiState::Available => {
            Some(format!("Original: {} bytes available", metadata.size))
        }
        OriginalImageUiState::Requesting {
            received_bytes,
            total_bytes,
        } => {
            let total_bytes = (*total_bytes).max(metadata.size);
            Some(format!("Original: {received_bytes}/{total_bytes} bytes"))
        }
        OriginalImageUiState::Cached => Some(format!("Original: {} bytes cached", metadata.size)),
    }
}

fn message_display_author(message: &ChatMessage) -> String {
    match (message.direction, message.offline) {
        (ChatDirection::Sent, false) => "Me".into(),
        (ChatDirection::Sent, true) => "Me-Offline".into(),
        (ChatDirection::Received, false) => message.author.clone().unwrap_or_else(|| "Peer".into()),
        (ChatDirection::Received, true) => "Peer-Offline".into(),
    }
}

fn file_status_text(
    filename: &str,
    transferred_bytes: u64,
    total_bytes: u64,
    status: &str,
    path: Option<&Path>,
) -> String {
    let location = path
        .map(|path| format!(", {}", path.display()))
        .unwrap_or_default();
    format!("[file: {filename}, {status}, {transferred_bytes}/{total_bytes} bytes{location}]")
}

fn contact_phase_label(phase: OneToOnePhase) -> &'static str {
    match phase {
        OneToOnePhase::Standby => "Online standby",
        OneToOnePhase::Connecting => "Connecting",
        OneToOnePhase::IncomingPending => "Incoming call",
        OneToOnePhase::Handshaking => "Secure handshake",
        OneToOnePhase::Ready => "Secure session ready",
        OneToOnePhase::Closing => "Disconnecting",
        OneToOnePhase::Closed => "Closed",
    }
}

fn new_message_editor() -> TextArea<'static> {
    let mut editor = TextArea::default();
    editor.set_block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Message - Enter newline, Ctrl+Enter/F2 send, Esc cancel "),
    );
    editor.set_placeholder_text("Type message...");
    editor.set_placeholder_style(Style::default().fg(Color::DarkGray));
    editor.set_wrap_mode(TextAreaWrapMode::WordOrGlyph);
    editor.set_min_rows(MESSAGE_COMPOSER_MIN_ROWS);
    editor.set_max_rows(MESSAGE_COMPOSER_MAX_ROWS);
    editor
}

fn message_input_limit(tab: &ConversationTab) -> usize {
    if tab.offline_mode == Some(OfflineCoordinatorMode::Offline) {
        MAX_OFFLINE_CHAT_TEXT_BYTES
    } else {
        MAX_CHAT_TEXT_BYTES
    }
}

fn message_editor_bytes(editor: &TextArea<'_>) -> usize {
    editor.lines().iter().map(String::len).sum::<usize>() + editor.lines().len().saturating_sub(1)
}

fn message_editor_text(editor: &TextArea<'_>) -> String {
    editor.lines().join("\n")
}

fn sanitized_message_insert(value: &str, max_bytes: usize) -> String {
    let mut sanitized = String::new();
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        let normalized = match character {
            '\r' if characters.peek() == Some(&'\n') => continue,
            '\r' => continue,
            '\n' | '\t' => character,
            character if !character.is_control() => character,
            _ => continue,
        };
        if sanitized.len() + normalized.len_utf8() > max_bytes {
            break;
        }
        sanitized.push(normalized);
    }
    sanitized
}

#[derive(Debug, Clone)]
struct BubbleSegment {
    text: String,
    style: Style,
}

type BubbleRow = Vec<BubbleSegment>;

fn append_message_bubble(
    lines: &mut Vec<Line<'static>>,
    message: &ChatMessage,
    author: &str,
    delivery: Option<&str>,
    selected: bool,
    transcript_width: u16,
) {
    let available_width = usize::from(transcript_width);
    if available_width < 8 {
        lines.push(Line::from(message.text.clone()));
        return;
    }

    let selection_gutter = if selected { 2 } else { 0 };
    let maximum_outer_width = available_width
        .saturating_mul(MESSAGE_BUBBLE_WIDTH_PERCENT)
        .checked_div(100)
        .unwrap_or(available_width)
        .clamp(6, available_width);
    let maximum_content_width = maximum_outer_width.saturating_sub(4).max(1);
    let (border_color, author_color) = match (message.direction, message.offline) {
        (ChatDirection::Sent, false) => (Color::Green, Color::Green),
        (ChatDirection::Received, false) => (Color::Cyan, Color::Cyan),
        (ChatDirection::Sent, true) => (Color::Yellow, Color::Yellow),
        (ChatDirection::Received, true) => (Color::Magenta, Color::Magenta),
    };

    let header_capacity = maximum_content_width.saturating_add(1);
    let full_timestamp = format!("[{}]", message.timestamp_utc);
    let timestamp_width = UnicodeWidthStr::width(full_timestamp.as_str());
    let history_marker = message_history_marker(message);
    let history_width =
        history_marker.map_or(0, |marker| UnicodeWidthStr::width(marker).saturating_add(1));
    let (timestamp, author, history_marker, delivery) = if header_capacity
        >= timestamp_width
            .saturating_add(history_width)
            .saturating_add(3)
    {
        let delivery_capacity = header_capacity
            .saturating_sub(timestamp_width.saturating_add(4))
            .saturating_sub(history_width);
        let delivery = delivery
            .filter(|_| delivery_capacity > 0)
            .map(|value| truncate_visual(value, delivery_capacity));
        let delivery_width = delivery.as_ref().map_or(0, |value| {
            UnicodeWidthStr::width(value.as_str()).saturating_add(1)
        });
        let author_width = header_capacity
            .saturating_sub(timestamp_width.saturating_add(2))
            .saturating_sub(history_width)
            .saturating_sub(delivery_width)
            .max(1);
        (
            Some(full_timestamp),
            truncate_visual(author, author_width),
            history_marker,
            delivery,
        )
    } else {
        let history_marker = history_marker
            .filter(|marker| header_capacity >= UnicodeWidthStr::width(*marker).saturating_add(2));
        let history_width =
            history_marker.map_or(0, |marker| UnicodeWidthStr::width(marker).saturating_add(1));
        (
            None,
            truncate_visual(
                author,
                header_capacity
                    .saturating_sub(history_width)
                    .saturating_sub(1)
                    .max(1),
            ),
            history_marker,
            None,
        )
    };
    let header_width = timestamp
        .as_ref()
        .map_or(0, |value| {
            UnicodeWidthStr::width(value.as_str()).saturating_add(1)
        })
        .saturating_add(UnicodeWidthStr::width(author.as_str()))
        .saturating_add(
            history_marker.map_or(0, |marker| UnicodeWidthStr::width(marker).saturating_add(1)),
        )
        .saturating_add(delivery.as_ref().map_or(0, |value| {
            UnicodeWidthStr::width(value.as_str()).saturating_add(1)
        }))
        .saturating_add(1);

    let mut rows = Vec::new();
    let message_color = if message.text.starts_with("[file:") {
        Color::LightCyan
    } else {
        Color::White
    };
    if let Some(reply) = parse_reply_text(&message.text) {
        rows.push(vec![BubbleSegment {
            text: truncate_visual(&format!("Reply to {}", reply.author), maximum_content_width),
            style: Style::default().fg(Color::DarkGray),
        }]);
        rows.extend(
            wrap_visual_text(reply.quote, maximum_content_width)
                .into_iter()
                .map(|text| {
                    vec![BubbleSegment {
                        text,
                        style: Style::default().fg(Color::DarkGray),
                    }]
                }),
        );
        rows.push(Vec::new());
        rows.extend(
            wrap_visual_text(reply.body, maximum_content_width)
                .into_iter()
                .map(|text| {
                    vec![BubbleSegment {
                        text,
                        style: Style::default().fg(message_color),
                    }]
                }),
        );
    } else {
        rows.extend(
            wrap_visual_text(&message.text, maximum_content_width)
                .into_iter()
                .map(|text| {
                    vec![BubbleSegment {
                        text,
                        style: Style::default().fg(message_color),
                    }]
                }),
        );
    }
    if let Some(image) = &message.image_render {
        rows.extend(
            image
                .lines
                .iter()
                .map(|line| bubble_image_row(line, maximum_content_width)),
        );
    }
    if let Some(status) = original_image_status(message) {
        rows.push(vec![BubbleSegment {
            text: truncate_visual(&status, maximum_content_width),
            style: Style::default().fg(Color::DarkGray),
        }]);
    }
    let content_width = rows
        .iter()
        .map(|row| bubble_row_width(row))
        .max()
        .unwrap_or(1)
        .max(header_width.saturating_sub(1))
        .max(1)
        .min(maximum_content_width);
    let outer_width = content_width.saturating_add(4);
    let indent = match message.direction {
        ChatDirection::Sent => 0,
        ChatDirection::Received => available_width
            .saturating_sub(outer_width)
            .saturating_sub(selection_gutter),
    };
    let border_style = if selected {
        Style::default()
            .fg(border_color)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(border_color)
    };

    let mut header = vec![Span::raw(" ".repeat(indent))];
    if selected {
        header.push(Span::styled(
            "▶ ",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ));
    }
    header.push(Span::styled("╭─", border_style));
    if let Some(timestamp) = timestamp {
        header.push(Span::styled(
            timestamp,
            Style::default().fg(Color::DarkGray),
        ));
        header.push(Span::raw(" "));
    }
    header.push(Span::styled(
        author,
        Style::default()
            .fg(author_color)
            .add_modifier(Modifier::BOLD),
    ));
    if let Some(history_marker) = history_marker {
        header.push(Span::raw(" "));
        header.push(Span::styled(
            history_marker,
            Style::default().fg(if message.history == MessageHistoryState::StoreFailed {
                Color::Red
            } else {
                Color::DarkGray
            }),
        ));
    }
    if let Some(delivery) = delivery {
        header.push(Span::raw(" "));
        header.push(Span::styled(
            delivery,
            Style::default().fg(if message.failed {
                Color::Red
            } else {
                Color::Green
            }),
        ));
    }
    header.push(Span::raw(" "));
    header.push(Span::styled(
        format!(
            "{}╮",
            "─".repeat(content_width.saturating_add(1).saturating_sub(header_width))
        ),
        border_style,
    ));
    lines.push(Line::from(header));
    for row in rows {
        let row_width = bubble_row_width(&row).min(content_width);
        let mut spans = vec![
            Span::raw(" ".repeat(indent.saturating_add(selection_gutter))),
            Span::styled("│ ", border_style),
        ];
        spans.extend(
            row.into_iter()
                .map(|segment| Span::styled(segment.text, segment.style)),
        );
        spans.push(Span::raw(
            " ".repeat(content_width.saturating_sub(row_width)),
        ));
        spans.push(Span::styled(" │", border_style));
        lines.push(Line::from(spans));
    }
    lines.push(Line::from(vec![
        Span::raw(" ".repeat(indent.saturating_add(selection_gutter))),
        Span::styled(
            format!("╰{}╯", "─".repeat(content_width.saturating_add(2))),
            border_style,
        ),
    ]));
    lines.push(Line::default());
}

fn message_history_marker(message: &ChatMessage) -> Option<&'static str> {
    if message.kind != ChatMessageKind::Text {
        return None;
    }
    match message.history {
        MessageHistoryState::NotStored => None,
        MessageHistoryState::Stored => Some("[H]"),
        MessageHistoryState::StoreFailed => Some("[H!]"),
    }
}

fn bubble_row_width(row: &BubbleRow) -> usize {
    row.iter()
        .map(|segment| UnicodeWidthStr::width(segment.text.as_str()))
        .sum()
}

fn bubble_image_row(line: &[RenderedImageCell], maximum_width: usize) -> BubbleRow {
    let mut row = Vec::new();
    let mut current_color = None;
    let mut symbols = String::new();
    let mut width: usize = 0;
    for cell in line {
        let symbol_width = UnicodeWidthChar::width(cell.symbol).unwrap_or(0);
        if width.saturating_add(symbol_width) > maximum_width {
            break;
        }
        if cell.color != current_color && !symbols.is_empty() {
            row.push(BubbleSegment {
                text: std::mem::take(&mut symbols),
                style: image_style(current_color),
            });
        }
        current_color = cell.color;
        symbols.push(cell.symbol);
        width = width.saturating_add(symbol_width);
    }
    if !symbols.is_empty() {
        row.push(BubbleSegment {
            text: symbols,
            style: image_style(current_color),
        });
    }
    row
}

fn image_style(color: Option<(u8, u8, u8)>) -> Style {
    match color {
        Some((red, green, blue)) => Style::default().fg(Color::Rgb(red, green, blue)),
        None => Style::default().fg(Color::White),
    }
}

fn wrap_visual_text(text: &str, maximum_width: usize) -> Vec<String> {
    let mut wrapped = Vec::new();
    for logical_line in text.split('\n') {
        wrap_visual_line(logical_line, maximum_width, &mut wrapped);
    }
    if wrapped.is_empty() {
        wrapped.push(String::new());
    }
    wrapped
}

fn wrap_visual_line(line: &str, maximum_width: usize, wrapped: &mut Vec<String>) {
    if line.is_empty() {
        wrapped.push(String::new());
        return;
    }
    let maximum_width = maximum_width.max(1);
    let mut remaining = line;
    while UnicodeWidthStr::width(remaining) > maximum_width {
        let mut width: usize = 0;
        let mut hard_end = 0;
        let mut whitespace_break = None;
        for (index, character) in remaining.char_indices() {
            let character_width = UnicodeWidthChar::width(character).unwrap_or(0);
            if width.saturating_add(character_width) > maximum_width {
                break;
            }
            width = width.saturating_add(character_width);
            hard_end = index + character.len_utf8();
            if character.is_whitespace() {
                whitespace_break = Some((index, hard_end));
            }
        }
        if hard_end == 0 {
            hard_end = remaining
                .char_indices()
                .next()
                .map_or(remaining.len(), |(index, character)| {
                    index + character.len_utf8()
                });
        }
        let (line_end, mut next_start) = whitespace_break
            .filter(|(index, _)| *index > 0)
            .unwrap_or((hard_end, hard_end));
        while let Some(character) = remaining[next_start..].chars().next() {
            if !character.is_whitespace() {
                break;
            }
            next_start += character.len_utf8();
        }
        wrapped.push(remaining[..line_end].trim_end().to_string());
        remaining = &remaining[next_start..];
    }
    wrapped.push(remaining.to_string());
}

fn truncate_visual(text: &str, maximum_width: usize) -> String {
    if UnicodeWidthStr::width(text) <= maximum_width {
        return text.to_string();
    }
    if maximum_width == 0 {
        return String::new();
    }
    let content_width = maximum_width.saturating_sub(1);
    let mut output = String::new();
    let mut width: usize = 0;
    for character in text.chars() {
        let character_width = UnicodeWidthChar::width(character).unwrap_or(0);
        if width.saturating_add(character_width) > content_width {
            break;
        }
        output.push(character);
        width = width.saturating_add(character_width);
    }
    output.push('…');
    output
}

fn contact_delivery_label(message: &ChatMessage) -> Option<String> {
    if message.direction != ChatDirection::Sent {
        return None;
    }
    if message.failed {
        Some("!".into())
    } else if message.delivered {
        Some("✓✓".into())
    } else if message.relayed {
        Some("✓".into())
    } else {
        None
    }
}

fn group_delivery_label(message: &ChatMessage) -> Option<String> {
    if message.direction != ChatDirection::Sent {
        return None;
    }
    if message.failed {
        return Some("!".into());
    }
    message.group_delivery.map(|(received, expected)| {
        let mark = if expected > 0 && received >= expected {
            "✓✓"
        } else {
            "✓"
        };
        format!("{mark} {received}/{expected}")
    })
}

fn contact_session_id(event: &ContactSessionEvent) -> Option<SessionId> {
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

fn contact_session_log_message(event: &ContactSessionEvent) -> Option<String> {
    match event {
        ContactSessionEvent::PhaseChanged { phase, .. } => {
            Some(format!("1:1 state changed to {phase:?}."))
        }
        ContactSessionEvent::IncomingCall { peer_b32, .. } => {
            Some(format!("Incoming call from {}.", short_b32(peer_b32)))
        }
        ContactSessionEvent::CollisionResolved { winner, .. } => {
            Some(format!("Connection collision resolved: {winner:?}."))
        }
        ContactSessionEvent::IdentityVerified {
            peer_b32, pinned, ..
        } => Some(format!(
            "Peer identity verified: {} (pinned: {pinned}).",
            short_b32(peer_b32)
        )),
        ContactSessionEvent::SecureSessionReady { peer_b32, .. } => Some(format!(
            "Secure session established with {}.",
            short_b32(peer_b32)
        )),
        ContactSessionEvent::FrameRejected { reason, .. } => {
            Some(format!("Received frame rejected: {reason}"))
        }
        ContactSessionEvent::ConnectionRejected { reason, .. } => {
            Some(format!("Connection rejected: {reason:?}."))
        }
        ContactSessionEvent::ConnectFailed {
            peer_b32, reason, ..
        } => Some(format!(
            "Connect to {} failed: {reason}",
            short_b32(peer_b32)
        )),
        ContactSessionEvent::ConnectRetryScheduled {
            peer_b32, reason, ..
        } => Some(format!(
            "Peer {} is not reachable yet; connection retry scheduled: {reason}",
            short_b32(peer_b32)
        )),
        ContactSessionEvent::Disconnected {
            peer_b32, reason, ..
        } => Some(match peer_b32 {
            Some(peer_b32) => {
                format!("Peer {} disconnected: {reason:?}.", short_b32(peer_b32))
            }
            None => format!("Peer disconnected: {reason:?}."),
        }),
        _ => None,
    }
}

fn runtime_group_session_id(event: &RuntimeGroupSessionEvent) -> Option<SessionId> {
    match event {
        RuntimeGroupSessionEvent::ConnectFailed { session_id, .. }
        | RuntimeGroupSessionEvent::CollisionResolved { session_id, .. }
        | RuntimeGroupSessionEvent::IdentityVerified { session_id, .. }
        | RuntimeGroupSessionEvent::SecureSessionReady { session_id, .. }
        | RuntimeGroupSessionEvent::PeerDisconnected { session_id, .. }
        | RuntimeGroupSessionEvent::ControlReceived { session_id, .. }
        | RuntimeGroupSessionEvent::RosterReceived { session_id, .. }
        | RuntimeGroupSessionEvent::DissolutionReceived { session_id, .. }
        | RuntimeGroupSessionEvent::FrameRejected { session_id, .. } => Some(*session_id),
        _ => None,
    }
}

fn runtime_group_session_log_message(event: &RuntimeGroupSessionEvent) -> Option<String> {
    match event {
        RuntimeGroupSessionEvent::ConnectFailed {
            peer_b32, reason, ..
        } => Some(format!(
            "Connect to group peer {} failed: {reason}",
            short_b32(peer_b32)
        )),
        RuntimeGroupSessionEvent::CollisionResolved {
            peer_b32, winner, ..
        } => Some(format!(
            "Connection collision with {} resolved: {winner:?}.",
            short_b32(peer_b32)
        )),
        RuntimeGroupSessionEvent::IdentityVerified { peer_b32, .. } => Some(format!(
            "Group peer identity verified: {}.",
            short_b32(peer_b32)
        )),
        RuntimeGroupSessionEvent::SecureSessionReady {
            peer_b32,
            authorized,
            ..
        } => Some(format!(
            "Secure group session with {} ready (authorized: {authorized}).",
            short_b32(peer_b32)
        )),
        RuntimeGroupSessionEvent::PeerDisconnected {
            peer_b32, reason, ..
        } => Some(format!(
            "Group peer {} disconnected: {reason:?}.",
            short_b32(peer_b32)
        )),
        RuntimeGroupSessionEvent::ControlReceived { peer_b32, .. } => Some(format!(
            "Group control update received from {}.",
            short_b32(peer_b32)
        )),
        RuntimeGroupSessionEvent::RosterReceived { peer_b32, .. } => Some(format!(
            "Group roster received from {}.",
            short_b32(peer_b32)
        )),
        RuntimeGroupSessionEvent::DissolutionReceived { peer_b32, .. } => Some(format!(
            "Group dissolution received from {}.",
            short_b32(peer_b32)
        )),
        RuntimeGroupSessionEvent::FrameRejected {
            peer_b32, reason, ..
        } => Some(format!(
            "Frame from group peer {} rejected: {reason}",
            short_b32(peer_b32)
        )),
        _ => None,
    }
}

fn runtime_file_transfer_session_id(event: &RuntimeFileTransferEvent) -> Option<SessionId> {
    match event {
        RuntimeFileTransferEvent::Offered { session_id, .. }
        | RuntimeFileTransferEvent::Started { session_id, .. }
        | RuntimeFileTransferEvent::Progress { session_id, .. }
        | RuntimeFileTransferEvent::Completed { session_id, .. }
        | RuntimeFileTransferEvent::Declined { session_id, .. }
        | RuntimeFileTransferEvent::Cancelled { session_id, .. }
        | RuntimeFileTransferEvent::Expired { session_id, .. }
        | RuntimeFileTransferEvent::Failed { session_id, .. } => Some(*session_id),
        _ => None,
    }
}

fn runtime_chat_direction(direction: RuntimeFileTransferDirection) -> ChatDirection {
    match direction {
        RuntimeFileTransferDirection::Sent => ChatDirection::Sent,
        RuntimeFileTransferDirection::Received => ChatDirection::Received,
    }
}

fn runtime_transfer_direction_label(direction: RuntimeFileTransferDirection) -> &'static str {
    match direction {
        RuntimeFileTransferDirection::Sent => "sending",
        RuntimeFileTransferDirection::Received => "receiving",
    }
}

fn runtime_file_transfer_log_message(event: &RuntimeFileTransferEvent) -> Option<String> {
    match event {
        RuntimeFileTransferEvent::Offered {
            direction,
            filename,
            total_bytes,
            ..
        } => Some(format!(
            "File {} offered: {filename} ({total_bytes} bytes).",
            runtime_transfer_direction_label(*direction)
        )),
        RuntimeFileTransferEvent::Started {
            direction,
            filename,
            total_bytes,
            ..
        } => Some(format!(
            "File transfer {}: {filename} ({total_bytes} bytes).",
            runtime_transfer_direction_label(*direction)
        )),
        RuntimeFileTransferEvent::Completed {
            direction,
            filename,
            total_bytes,
            ..
        } => Some(format!(
            "File transfer {}: {filename} ({total_bytes} bytes).",
            match direction {
                RuntimeFileTransferDirection::Sent => "completed",
                RuntimeFileTransferDirection::Received => "received",
            }
        )),
        RuntimeFileTransferEvent::Failed {
            direction,
            filename,
            reason,
            ..
        } => Some(format!(
            "File transfer {}{} failed: {reason}",
            runtime_transfer_direction_label(*direction),
            filename
                .as_ref()
                .map(|filename| format!(" for {filename}"))
                .unwrap_or_default()
        )),
        RuntimeFileTransferEvent::Declined {
            direction,
            filename,
            ..
        } => Some(format!(
            "File transfer {} for {filename} was declined.",
            runtime_transfer_direction_label(*direction)
        )),
        RuntimeFileTransferEvent::Cancelled {
            direction,
            filename,
            ..
        } => Some(format!(
            "File transfer {} for {filename} was cancelled.",
            runtime_transfer_direction_label(*direction)
        )),
        RuntimeFileTransferEvent::Expired {
            direction,
            filename,
            ..
        } => Some(format!(
            "File transfer {} for {filename} expired.",
            runtime_transfer_direction_label(*direction)
        )),
        RuntimeFileTransferEvent::Progress { .. } => None,
        _ => None,
    }
}

fn offline_session_log_message(event: &OfflineSessionEvent) -> Option<String> {
    match event {
        OfflineSessionEvent::ModeChanged { mode, .. } => {
            Some(format!("Offline coordinator mode changed to {mode:?}."))
        }
        OfflineSessionEvent::SendStarted { index, .. } => {
            Some(format!("Offline PUT started at index {index}."))
        }
        OfflineSessionEvent::SendConfirmed {
            index,
            successful_drop_count,
            ..
        } => Some(format!(
            "Offline PUT confirmed at index {index} on {successful_drop_count} drop(s)."
        )),
        OfflineSessionEvent::SendFailed { index, reason, .. } => {
            Some(format!("Offline PUT failed at index {index}: {reason}"))
        }
        OfflineSessionEvent::UnsupportedFrameReceived { index, .. } => Some(format!(
            "Authenticated offline frame received at index {index}."
        )),
        OfflineSessionEvent::BlobRejected { index, reason, .. } => {
            Some(format!("Offline blob at index {index} rejected: {reason}"))
        }
        OfflineSessionEvent::PollTargetFailed { index, reason, .. } => {
            Some(format!("Offline poll at index {index} failed: {reason}"))
        }
        OfflineSessionEvent::PollSweepStarted { .. } => Some("Offline poll sweep started.".into()),
        OfflineSessionEvent::PollSweepCompleted {
            observation_count, ..
        } => Some(format!(
            "Offline poll sweep completed with {observation_count} observation(s)."
        )),
        OfflineSessionEvent::IndexSyncSent { .. } => {
            Some("Offline index synchronization sent.".into())
        }
        OfflineSessionEvent::IndexSyncSendFailed { reason, .. } => {
            Some(format!("Offline index synchronization failed: {reason}"))
        }
        OfflineSessionEvent::IndexSyncApplied { .. } => {
            Some("Offline index synchronization applied.".into())
        }
        OfflineSessionEvent::StatePersisted { .. } => Some("Offline state persisted.".into()),
        OfflineSessionEvent::EnrollmentPersisted { .. } => {
            Some("Offline enrollment persisted.".into())
        }
        OfflineSessionEvent::ShutdownComplete { .. } => Some("Offline coordinator stopped.".into()),
        _ => None,
    }
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
    let mut preview = flattened
        .chars()
        .take(maximum_chars.saturating_sub(1))
        .collect::<String>();
    preview.push('…');
    preview
}

fn detail_line(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label}: "), Style::default().fg(Color::DarkGray)),
        Span::raw(value.to_string()),
    ])
}

fn render_log_panel(frame: &mut Frame<'_>, tab: &mut ConversationTab, area: Rect) {
    let log_lines = if tab.log.lines.is_empty() {
        vec![Line::from(Span::styled(
            "No log entries yet.",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        tab.log
            .lines
            .iter()
            .map(|line| Line::from(Span::styled(line.clone(), Style::default().fg(Color::Gray))))
            .collect::<Vec<_>>()
    };
    let content_width = area.width.saturating_sub(2);
    let viewport_height = usize::from(area.height.saturating_sub(2));
    let line_count = wrapped_line_count(&log_lines, content_width);
    let maximum_scroll = line_count.saturating_sub(viewport_height);
    tab.presentation.log_max_scroll = maximum_scroll;
    tab.presentation.log_page_lines = viewport_height.saturating_sub(1).max(1);
    if tab.presentation.log_follow_latest {
        tab.presentation.log_scroll = maximum_scroll;
    } else {
        tab.presentation.log_scroll = tab.presentation.log_scroll.min(maximum_scroll);
    }
    let scroll = tab.presentation.log_scroll.min(usize::from(u16::MAX)) as u16;
    let title = if tab.presentation.log_follow_latest {
        format!(" Logs ({}) ", tab.log.lines.len())
    } else {
        format!(" Logs ({}, scrolling) ", tab.log.lines.len())
    };
    frame.render_widget(
        Paragraph::new(log_lines)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0))
            .block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
    if maximum_scroll > 0 && area.height > 2 {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .track_style(Style::default().fg(Color::DarkGray))
            .thumb_style(Style::default().fg(Color::Cyan));
        let mut scrollbar_state = ScrollbarState::new(line_count)
            .position(tab.presentation.log_scroll)
            .viewport_content_length(viewport_height);
        frame.render_stateful_widget(
            scrollbar,
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut scrollbar_state,
        );
    }
}

fn push_inline_detail(spans: &mut Vec<Span<'static>>, label: &str, value: &str) {
    if !spans.is_empty() {
        spans.push(Span::styled(" | ", Style::default().fg(Color::DarkGray)));
    }
    spans.push(Span::styled(
        format!("{label}: "),
        Style::default().fg(Color::DarkGray),
    ));
    spans.push(Span::raw(value.to_string()));
}

fn push_status_badge(spans: &mut Vec<Span<'static>>, label: &str, color: Color) {
    if !spans.is_empty() {
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled(
        format!(" {label} "),
        Style::default()
            .fg(Color::Black)
            .bg(color)
            .add_modifier(Modifier::BOLD),
    ));
}

fn push_history_and_state(spans: &mut Vec<Span<'static>>, history_enabled: bool, state: &str) {
    if history_enabled {
        push_status_badge(spans, "H", Color::Green);
    }
    push_inline_detail(spans, "State", state);
}

fn offline_activity_badge(state: OfflineActivityState) -> (&'static str, Color) {
    match state {
        OfflineActivityState::Idle => ("DD IDLE", Color::Gray),
        OfflineActivityState::Poll => ("DD POLL", Color::Yellow),
        OfflineActivityState::Put => ("DD PUT", Color::Green),
        OfflineActivityState::Hit => ("DD HIT", Color::Magenta),
        OfflineActivityState::Miss => ("DD MISS", Color::Gray),
        OfflineActivityState::Fail => ("DD FAIL", Color::Red),
    }
}

fn short_b32(value: &str) -> String {
    let clean = value.trim_end_matches(".b32.i2p");
    if clean.len() > 12 {
        format!("{}...{}", &clean[..6], &clean[clean.len() - 6..])
    } else {
        clean.to_string()
    }
}

fn wrapped_line_count(lines: &[Line<'_>], width: u16) -> usize {
    let width = usize::from(width);
    if width == 0 {
        return 0;
    }
    lines
        .iter()
        .map(|line| line.width().max(1).saturating_add(width - 1) / width)
        .sum()
}

fn visible_tab_range(
    labels: &[String],
    selected: usize,
    area_width: u16,
) -> std::ops::Range<usize> {
    if labels.is_empty() {
        return 0..0;
    }
    let selected = selected.min(labels.len() - 1);
    let available = usize::from(area_width.saturating_sub(2));
    let tab_width = |index: usize| Line::from(labels[index].as_str()).width() + 2;
    let divider_width = 3;
    let mut start = selected;
    let mut end = selected + 1;
    let mut used = tab_width(selected);

    loop {
        let mut changed = false;
        if start > 0 {
            let added = divider_width + tab_width(start - 1);
            if used + added <= available {
                start -= 1;
                used += added;
                changed = true;
            }
        }
        if end < labels.len() {
            let added = divider_width + tab_width(end);
            if used + added <= available {
                used += added;
                end += 1;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    start..end
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{DynamicImage, ImageBuffer, ImageFormat, Rgba};
    use std::io::Cursor;

    fn test_png() -> Vec<u8> {
        let image = DynamicImage::ImageRgba8(ImageBuffer::from_fn(8, 8, |x, y| {
            Rgba([(x * 24) as u8, (y * 24) as u8, 160, 255])
        }));
        let mut cursor = Cursor::new(Vec::new());
        image
            .write_to(&mut cursor, ImageFormat::Png)
            .expect("encode test image");
        cursor.into_inner()
    }

    fn received_text(session_id: SessionId, message_id: u64, text: &str) -> TextReceivedEvent {
        TextReceivedEvent {
            session_id,
            message_id,
            text: text.into(),
            timestamp_utc: "12:00:00 UTC".into(),
            sender_b32: None,
            offline: false,
            offline_index: None,
            history: HistoryWriteOutcome::Disabled,
            history_warning: None,
            warning: None,
        }
    }

    #[test]
    fn conversation_log_timestamps_and_trims_in_bounded_batches() {
        let mut log = ConversationLog::default();
        for index in 0..MAX_LOG_LINES {
            log.push_at("12:00:00 UTC", format!("entry {index}"));
        }
        log.push_at("12:00:01 UTC", "newest");

        assert_eq!(log.lines.len(), MAX_LOG_LINES - LOG_TRIM_BATCH + 1);
        assert_eq!(
            log.lines.front().map(String::as_str),
            Some("[12:00:00 UTC] entry 50")
        );
        assert_eq!(
            log.lines.back().map(String::as_str),
            Some("[12:00:01 UTC] newest")
        );
    }

    #[test]
    fn conversation_log_clock_uses_hms_utc_format() {
        let timestamp = current_utc_hms();
        let bytes = timestamp.as_bytes();

        assert_eq!(bytes.len(), 12);
        assert_eq!(bytes[2], b':');
        assert_eq!(bytes[5], b':');
        assert_eq!(&timestamp[8..], " UTC");
        assert!(
            bytes[..8]
                .iter()
                .enumerate()
                .all(|(index, byte)| matches!(index, 2 | 5) || byte.is_ascii_digit())
        );
    }

    #[test]
    fn conversation_log_keeps_untrusted_values_on_one_visual_record() {
        let mut log = ConversationLog::default();
        log.push_at("12:00:00 UTC", "failure\n[00:00:00 UTC] forged\tline");

        assert_eq!(log.lines.len(), 1);
        assert_eq!(
            log.lines.front().map(String::as_str),
            Some("[12:00:00 UTC] failure [00:00:00 UTC] forged line")
        );
    }

    #[test]
    fn runtime_logs_are_routed_only_to_the_matching_conversation() {
        let mut workspace = Workspace::default();
        let alice = ContactId::new("log-alice").expect("contact id");
        let bob = ContactId::new("log-bob").expect("contact id");
        let alice_key = ManagedSessionKey::Contact(alice.clone());
        let bob_key = ManagedSessionKey::Contact(bob.clone());
        let alice_session = SessionId::new(901);
        let bob_session = SessionId::new(902);
        workspace.open(ConversationKey::Contact(alice), "Alice");
        workspace.open(ConversationKey::Contact(bob), "Bob");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: alice_session,
            key: alice_key,
        });
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: bob_session,
            key: bob_key,
        });
        let alice_before = workspace.tabs[0].log.lines.len();
        let bob_before = workspace.tabs[1].log.lines.len();

        workspace.handle_contact_session_event(&ContactSessionEvent::PhaseChanged {
            session_id: alice_session,
            phase: OneToOnePhase::Ready,
        });

        assert_eq!(workspace.tabs[0].log.lines.len(), alice_before + 1);
        assert_eq!(workspace.tabs[1].log.lines.len(), bob_before);
        assert!(
            workspace.tabs[0]
                .log
                .lines
                .back()
                .is_some_and(|line| line.contains("1:1 state changed to Ready"))
        );
    }

    #[test]
    fn log_panel_state_and_copy_content_are_independent_per_tab() {
        let mut workspace = Workspace::default();
        workspace.open(
            ConversationKey::Contact(ContactId::new("log-first").expect("contact id")),
            "First",
        );
        workspace.open(
            ConversationKey::Group(GroupId::new("log-second").expect("group id")),
            "Second",
        );
        workspace.select_previous();
        workspace.tabs[0].log.push_at("09:10:11 UTC", "first entry");

        assert_eq!(workspace.toggle_active_logs(), Ok(true));
        assert!(workspace.active_logs_open());
        assert_eq!(
            workspace.active_logs_copy_text(),
            Ok((1, "[09:10:11 UTC] first entry".into()))
        );

        workspace.select_next();
        assert!(!workspace.active_logs_open());
        assert!(workspace.active_logs_copy_text().is_err());
        workspace.select_previous();
        assert!(workspace.active_logs_open());
    }

    #[test]
    fn opening_an_existing_key_focuses_without_duplicating_it() {
        let mut workspace = Workspace::default();
        let alice_id = ContactId::new("alice").expect("contact id");
        let alice = ConversationKey::Contact(alice_id.clone());

        assert!(!workspace.contains_contact(&alice_id));

        assert_eq!(
            workspace.open(alice.clone(), "Alice"),
            OpenDisposition::Opened
        );
        assert!(workspace.contains_contact(&alice_id));
        assert_eq!(
            workspace.open(alice, "Renamed Alice"),
            OpenDisposition::Focused
        );
        assert_eq!(workspace.tabs.len(), 1);
        assert_eq!(workspace.active, Some(0));
        assert_eq!(workspace.tabs[0].label, "Alice");
        assert!(workspace.tabs[0].presentation.follow_latest);
        assert_eq!(workspace.tabs[0].presentation.transcript_scroll, 0);
        assert!(!workspace.tabs[0].presentation.details_expanded);
    }

    #[test]
    fn tab_selection_wraps_in_both_directions() {
        let mut workspace = Workspace::default();
        workspace.open(
            ConversationKey::Contact(ContactId::new("alice").expect("contact id")),
            "Alice",
        );
        workspace.open(
            ConversationKey::Group(GroupId::new("group").expect("group id")),
            "Group",
        );

        workspace.select_next();
        assert_eq!(workspace.active, Some(0));
        workspace.select_previous();
        assert_eq!(workspace.active, Some(1));
    }

    #[test]
    fn opening_tabs_animate_while_closing_tabs_keep_the_ellipsis() {
        let mut workspace = Workspace::default();
        let key = ConversationKey::Contact(ContactId::new("opening").expect("contact id"));
        workspace.open(key.clone(), "Opening");
        workspace.mark_opening(&key);
        assert_eq!(workspace.tabs[0].rendered_label(0, false), "Opening ⠋");
        assert_eq!(workspace.tabs[0].rendered_label(1, false), "Opening ⠙");

        workspace.tabs[0].phase = ConversationPhase::Closing;
        assert_eq!(workspace.tabs[0].rendered_label(0, false), "Opening ...");
        assert_eq!(workspace.tabs[0].rendered_label(1, false), "Opening ...");
    }

    #[test]
    fn one_to_one_tabs_mark_live_and_incoming_sessions_only() {
        let mut workspace = Workspace::default();
        workspace.open(
            ConversationKey::Contact(ContactId::new("alice").expect("contact id")),
            "Alice",
        );
        workspace.tabs[0].phase = ConversationPhase::Standby;
        workspace.tabs[0].contact_phase = Some(OneToOnePhase::Ready);

        assert_eq!(workspace.tabs[0].rendered_label(0, false), "Alice ◆");
        workspace.tabs[0].presentation.missed_calls = 2;
        workspace.tabs[0].presentation.unread_text = true;
        assert_eq!(workspace.tabs[0].rendered_label(0, false), "Alice ◆ 2 +");
        workspace.tabs[0].presentation.missed_calls = 0;
        workspace.tabs[0].presentation.unread_text = false;

        workspace.tabs[0].contact_phase = Some(OneToOnePhase::IncomingPending);
        assert_eq!(workspace.tabs[0].rendered_label(0, false), "Alice ◆");
        assert_eq!(workspace.tabs[0].rendered_label(5, false), "Alice ◇");
        assert!(workspace.advance_tab_spinner());

        workspace.tabs[0].contact_phase = Some(OneToOnePhase::Ready);
        workspace.tabs[0].offline_mode = Some(OfflineCoordinatorMode::Offline);
        assert_eq!(workspace.tabs[0].rendered_label(0, false), "Alice");

        workspace.open(
            ConversationKey::Group(GroupId::new("group").expect("group id")),
            "Group",
        );
        workspace.tabs[1].phase = ConversationPhase::Standby;
        assert_eq!(workspace.tabs[1].rendered_label(0, false), "#Group");
        assert_eq!(workspace.tabs[1].rendered_label(0, true), "#Group ◆");

        workspace.tabs[1].presentation.unread_text = true;
        assert_eq!(workspace.tabs[1].rendered_label(0, true), "#Group ◆ +");
    }

    #[test]
    fn active_chats_marker_aggregates_group_connections_and_incoming_calls() {
        let mut workspace = Workspace::default();
        let group_id = GroupId::new("group").expect("group id");
        workspace.open(ConversationKey::Group(group_id.clone()), "Group");
        workspace.tabs[0].phase = ConversationPhase::Standby;

        assert_eq!(workspace.active_chats_marker(|_| false), None);
        assert_eq!(
            workspace.active_chats_marker(|open_group_id| open_group_id == &group_id),
            Some('◆')
        );

        workspace.open(
            ConversationKey::Contact(ContactId::new("alice").expect("contact id")),
            "Alice",
        );
        workspace.tabs[1].phase = ConversationPhase::Standby;
        workspace.tabs[1].contact_phase = Some(OneToOnePhase::IncomingPending);
        workspace.tab_spinner_frame = 5;
        assert_eq!(workspace.active_chats_marker(|_| true), Some('◇'));
    }

    #[test]
    fn incoming_text_marks_only_its_conversation_until_it_is_viewed() {
        let mut workspace = Workspace::default();
        let alice_id = ContactId::new("attention-alice").expect("contact id");
        let bob_id = ContactId::new("attention-bob").expect("contact id");
        let alice_session = SessionId::new(901);
        workspace.open(ConversationKey::Contact(alice_id.clone()), "Alice");
        workspace.open(ConversationKey::Contact(bob_id), "Bob");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: alice_session,
            key: ManagedSessionKey::Contact(alice_id),
        });

        workspace.receive_text(&received_text(alice_session, 1, "hello"));

        assert_eq!(workspace.tabs[0].rendered_label(0, false), "Alice +");
        assert_eq!(workspace.tabs[1].rendered_label(0, false), "Bob");
        assert!(workspace.has_unread_attention());

        workspace.mark_active_viewed();
        assert!(workspace.has_unread_attention());
        workspace.select_previous();
        workspace.mark_active_viewed();
        assert!(!workspace.has_unread_attention());
        assert_eq!(workspace.tabs[0].rendered_label(0, false), "Alice");
    }

    #[test]
    fn runtime_warning_marks_only_its_conversation_until_it_is_viewed() {
        let mut workspace = Workspace::default();
        let alpha_id = GroupId::new("attention-alpha").expect("group id");
        let beta_id = GroupId::new("attention-beta").expect("group id");
        let alpha_session = SessionId::new(902);
        workspace.open(ConversationKey::Group(alpha_id.clone()), "Alpha");
        workspace.open(ConversationKey::Group(beta_id), "Beta");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: alpha_session,
            key: ManagedSessionKey::Group(alpha_id),
        });

        workspace.handle_group_session_event(&RuntimeGroupSessionEvent::ConnectFailed {
            session_id: alpha_session,
            peer_b32: "peer.b32.i2p".into(),
            reason: "unreachable".into(),
        });

        assert_eq!(workspace.tabs[0].rendered_label(0, false), "#Alpha !");
        assert_eq!(workspace.tabs[1].rendered_label(0, false), "#Beta");
        assert!(workspace.has_warning_attention());

        workspace.select_previous();
        workspace.mark_active_viewed();
        assert!(!workspace.has_warning_attention());
        assert_eq!(workspace.tabs[0].rendered_label(0, false), "#Alpha");
    }

    #[test]
    fn frontend_session_and_contact_events_drive_existing_tab_state() {
        let mut workspace = Workspace::default();
        let contact_id = ContactId::new("typed-contact").expect("contact id");
        let managed_key = ManagedSessionKey::Contact(contact_id.clone());
        let session_id = SessionId::new(903);
        workspace.open(ConversationKey::Contact(contact_id), "Typed Contact");

        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id,
            key: managed_key,
        });
        workspace.handle_contact_session_event(&ContactSessionEvent::IncomingCall {
            session_id,
            peer_b32: "peer.b32.i2p".into(),
        });
        workspace.handle_contact_session_event(&ContactSessionEvent::PhaseChanged {
            session_id,
            phase: OneToOnePhase::IncomingPending,
        });

        assert_eq!(workspace.tabs[0].session_id, Some(session_id));
        assert_eq!(
            workspace.tabs[0].contact_phase,
            Some(OneToOnePhase::IncomingPending)
        );
        assert_eq!(
            workspace.tabs[0].incoming_peer_b32.as_deref(),
            Some("peer.b32.i2p")
        );
        assert!(
            workspace.tabs[0]
                .log
                .lines
                .iter()
                .any(|line| line.contains("Incoming call"))
        );
    }

    #[test]
    fn frontend_group_events_drive_existing_tab_warnings_and_logs() {
        let mut workspace = Workspace::default();
        let group_id = GroupId::new("typed-group").expect("group id");
        let managed_key = ManagedSessionKey::Group(group_id.clone());
        let session_id = SessionId::new(904);
        workspace.open(ConversationKey::Group(group_id), "Typed Group");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id,
            key: managed_key,
        });

        workspace.handle_group_session_event(&RuntimeGroupSessionEvent::ConnectFailed {
            session_id,
            peer_b32: "peer.b32.i2p".into(),
            reason: "unreachable".into(),
        });

        assert!(
            workspace.tabs[0]
                .last_warning
                .as_deref()
                .is_some_and(|warning| warning.contains("unreachable"))
        );
        assert!(
            workspace.tabs[0]
                .log
                .lines
                .back()
                .is_some_and(|line| line.contains("Connect to group peer"))
        );
    }

    #[test]
    fn active_managed_key_tracks_the_selected_conversation_tab() {
        let mut workspace = Workspace::default();
        let contact_id = ContactId::new("active-contact").expect("contact id");
        let group_id = GroupId::new("active-group").expect("group id");
        workspace.open(ConversationKey::Contact(contact_id.clone()), "Contact");
        workspace.open(ConversationKey::Group(group_id.clone()), "Group");

        assert_eq!(
            workspace.active_managed_key(),
            Some(ManagedSessionKey::Group(group_id))
        );
        workspace.select_next();
        assert_eq!(
            workspace.active_managed_key(),
            Some(ManagedSessionKey::Contact(contact_id))
        );
    }

    #[test]
    fn history_badge_is_enabled_only_and_precedes_state() {
        let mut enabled = Vec::new();
        push_history_and_state(&mut enabled, true, "Online");
        assert_eq!(enabled.len(), 4);
        assert_eq!(enabled[0].content, " H ");
        assert_eq!(enabled[0].style.bg, Some(Color::Green));
        assert_eq!(enabled[2].content, "State: ");
        assert_eq!(enabled[3].content, "Online");

        let mut disabled = Vec::new();
        push_history_and_state(&mut disabled, false, "Offline");
        assert_eq!(disabled.len(), 2);
        assert!(disabled.iter().all(|span| span.content != " H "));
        assert_eq!(disabled[0].content, "State: ");
        assert_eq!(disabled[1].content, "Offline");
    }

    #[test]
    fn transcript_page_navigation_resumes_following_at_the_latest_message() {
        let mut workspace = Workspace::default();
        workspace.open(
            ConversationKey::Contact(ContactId::new("alice").expect("contact id")),
            "Alice",
        );
        workspace.tabs[0].presentation.transcript_max_scroll = 100;
        workspace.tabs[0].presentation.transcript_page_lines = 20;

        workspace.scroll_active_page_up();
        assert_eq!(workspace.tabs[0].presentation.transcript_scroll, 80);
        assert!(!workspace.tabs[0].presentation.follow_latest);

        workspace.scroll_active_page_down();
        assert_eq!(workspace.tabs[0].presentation.transcript_scroll, 100);
        assert!(workspace.tabs[0].presentation.follow_latest);
    }

    #[test]
    fn transcript_navigation_keeps_following_when_content_does_not_overflow() {
        let mut workspace = Workspace::default();
        workspace.open(
            ConversationKey::Contact(ContactId::new("alice").expect("contact id")),
            "Alice",
        );

        workspace.scroll_active_page_up();
        workspace.scroll_active_to_oldest();

        assert_eq!(workspace.tabs[0].presentation.transcript_scroll, 0);
        assert!(workspace.tabs[0].presentation.follow_latest);
    }

    #[test]
    fn transcript_scroll_state_is_independent_for_each_tab() {
        let mut workspace = Workspace::default();
        workspace.open(
            ConversationKey::Contact(ContactId::new("alice").expect("contact id")),
            "Alice",
        );
        workspace.tabs[0].presentation.transcript_max_scroll = 40;
        workspace.scroll_active_to_oldest();

        workspace.open(
            ConversationKey::Group(GroupId::new("group").expect("group id")),
            "Group",
        );
        workspace.tabs[1].presentation.transcript_max_scroll = 60;
        workspace.scroll_active_to_latest();

        workspace.select_previous();
        assert_eq!(workspace.tabs[0].presentation.transcript_scroll, 0);
        assert!(!workspace.tabs[0].presentation.follow_latest);
        assert_eq!(workspace.tabs[1].presentation.transcript_scroll, 60);
        assert!(workspace.tabs[1].presentation.follow_latest);
    }

    #[test]
    fn details_expansion_is_independent_for_each_tab() {
        let mut workspace = Workspace::default();
        workspace.open(
            ConversationKey::Contact(ContactId::new("alice").expect("contact id")),
            "Alice",
        );
        workspace.toggle_active_details();

        workspace.open(
            ConversationKey::Group(GroupId::new("group").expect("group id")),
            "Group",
        );
        assert!(!workspace.tabs[1].presentation.details_expanded);

        workspace.select_previous();
        assert!(workspace.tabs[0].presentation.details_expanded);
        assert!(!workspace.tabs[1].presentation.details_expanded);
    }

    #[test]
    fn browser_tab_state_distinguishes_open_and_closing_conversations() {
        let mut workspace = Workspace::default();
        let contact_id = ContactId::new("alice").expect("contact id");
        let group_id = GroupId::new("group").expect("group id");
        workspace.open(ConversationKey::Contact(contact_id.clone()), "Alice");
        workspace.open(ConversationKey::Group(group_id.clone()), "Group");

        assert_eq!(
            workspace.contact_tab_state(&contact_id),
            Some(ConversationTabState::Open)
        );
        assert_eq!(
            workspace.group_tab_state(&group_id),
            Some(ConversationTabState::Open)
        );

        workspace.tabs[0].phase = ConversationPhase::Closing;
        assert_eq!(
            workspace.contact_tab_state(&contact_id),
            Some(ConversationTabState::Closing)
        );
    }

    #[test]
    fn pinned_identity_events_drive_live_tofu_presentation_state() {
        let mut workspace = Workspace::default();
        let contact_id = ContactId::new("alice").expect("contact id");
        let session_id = SessionId::new(21);
        workspace.open(ConversationKey::Contact(contact_id.clone()), "Alice");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id,
            key: ManagedSessionKey::Contact(contact_id),
        });

        workspace.handle_contact_session_event(&ContactSessionEvent::IdentityVerified {
            session_id,
            peer_b32: "peer.b32.i2p".into(),
            pinned: true,
        });
        assert_eq!(
            workspace.tabs[0].tofu_state,
            TofuPresentationState::Verified
        );

        workspace.handle_contact_session_event(&ContactSessionEvent::ConnectionRejected {
            session_id,
            reason: DisconnectReason::TofuMismatch,
        });
        assert_eq!(
            workspace.tabs[0].tofu_state,
            TofuPresentationState::Mismatch
        );
    }

    #[test]
    fn rendezvous_authentication_marks_only_the_matching_contact_tab() {
        let mut workspace = Workspace::default();
        let alice_id = ContactId::new("alice-auth").expect("contact id");
        let bob_id = ContactId::new("bob-auth").expect("contact id");
        let alice_session = SessionId::new(41);
        workspace.open(ConversationKey::Contact(alice_id.clone()), "Alice");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: alice_session,
            key: ManagedSessionKey::Contact(alice_id),
        });
        workspace.open(ConversationKey::Contact(bob_id.clone()), "Bob");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: SessionId::new(42),
            key: ManagedSessionKey::Contact(bob_id),
        });

        workspace.handle_rendezvous_session_event(&RendezvousSessionEvent::IncomingAuthenticated {
            session_id: alice_session,
            peer_b32: "alice-peer.b32.i2p".into(),
        });

        assert!(workspace.tabs[0].rendezvous_authenticated);
        assert!(!workspace.tabs[1].rendezvous_authenticated);
    }

    #[test]
    fn runtime_close_event_removes_only_the_matching_tab() {
        let mut workspace = Workspace::default();
        let alice_id = ContactId::new("alice").expect("contact id");
        workspace.open(ConversationKey::Contact(alice_id.clone()), "Alice");
        workspace.open(
            ConversationKey::Group(GroupId::new("group").expect("group id")),
            "Group",
        );
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Closed {
            session_id: SessionId::new(7),
            key: ManagedSessionKey::Contact(alice_id),
        });

        assert_eq!(workspace.tabs.len(), 1);
        assert!(matches!(&workspace.tabs[0].key, ConversationKey::Group(_)));
    }

    #[test]
    fn keyed_bootstrap_events_update_only_the_matching_contact() {
        let mut workspace = Workspace::default();
        let alice_id = ContactId::new("alice").expect("contact id");
        let bob_id = ContactId::new("bob").expect("contact id");
        workspace.open(ConversationKey::Contact(alice_id.clone()), "Alice");
        workspace.open(ConversationKey::Contact(bob_id.clone()), "Bob");

        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opening {
            key: ManagedSessionKey::Contact(alice_id),
        });
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::OpenFailed {
            key: ManagedSessionKey::Contact(bob_id),
            reason: "SAM unavailable".into(),
        });

        assert_eq!(workspace.tabs[0].phase, ConversationPhase::Opening);
        assert!(matches!(
            &workspace.tabs[1].phase,
            ConversationPhase::Failed(reason) if reason == "SAM unavailable"
        ));
    }

    #[test]
    fn group_bootstrap_and_runtime_warning_update_only_the_matching_group() {
        let mut workspace = Workspace::default();
        let alpha_id = GroupId::new("alpha").expect("group id");
        let beta_id = GroupId::new("beta").expect("group id");
        let alpha_session = SessionId::new(31);
        workspace.open(ConversationKey::Group(alpha_id.clone()), "Alpha");
        workspace.open(ConversationKey::Group(beta_id), "Beta");

        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: alpha_session,
            key: ManagedSessionKey::Group(alpha_id),
        });
        workspace.handle_group_session_event(&RuntimeGroupSessionEvent::ConnectFailed {
            session_id: alpha_session,
            peer_b32: "peer.b32.i2p".into(),
            reason: "unreachable".into(),
        });

        assert_eq!(workspace.tabs[0].phase, ConversationPhase::Standby);
        assert_eq!(workspace.tabs[0].session_id, Some(alpha_session));
        assert!(
            workspace.tabs[0]
                .last_warning
                .as_deref()
                .is_some_and(|warning| warning.contains("unreachable"))
        );
        assert_eq!(workspace.tabs[1].phase, ConversationPhase::Idle);
        assert!(workspace.tabs[1].last_warning.is_none());
    }

    #[test]
    fn group_text_and_delivery_update_only_the_matching_transcript() {
        let mut workspace = Workspace::default();
        let alpha_id = GroupId::new("alpha-text").expect("group id");
        let beta_id = GroupId::new("beta-text").expect("group id");
        let alpha_session = SessionId::new(32);
        let beta_session = SessionId::new(33);
        workspace.open(ConversationKey::Group(alpha_id.clone()), "Alpha");
        workspace.open(ConversationKey::Group(beta_id.clone()), "Beta");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: alpha_session,
            key: ManagedSessionKey::Group(alpha_id),
        });
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: beta_session,
            key: ManagedSessionKey::Group(beta_id),
        });
        workspace.tabs[0]
            .group_member_names
            .insert("alice.b32.i2p".into(), "Alice".into());
        workspace.tabs[0].push_group_message(
            ChatDirection::Sent,
            81,
            "outgoing".into(),
            None,
            Some((0, 2)),
        );

        let mut incoming = received_text(alpha_session, 82, "incoming");
        incoming.sender_b32 = Some("alice.b32.i2p".into());
        workspace.receive_text(&incoming);
        workspace.receive_text_delivery(&TextDeliveryEvent {
            session_id: alpha_session,
            message_id: 81,
            peer_b32: None,
            group: true,
            received: 1,
            expected: 2,
            warning: None,
        });

        assert_eq!(workspace.tabs[0].messages[0].group_delivery, Some((1, 2)));
        assert_eq!(
            workspace.tabs[0].messages[1].author.as_deref(),
            Some("Alice")
        );
        assert_eq!(workspace.tabs[0].messages[1].text, "incoming");
        assert!(workspace.tabs[1].messages.is_empty());
    }

    #[test]
    fn online_group_allows_message_composition() {
        let mut workspace = Workspace::default();
        let group_id = GroupId::new("compose-group").expect("group id");
        workspace.open(ConversationKey::Group(group_id.clone()), "Group");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: SessionId::new(34),
            key: ManagedSessionKey::Group(group_id),
        });

        workspace
            .begin_message_input()
            .expect("group message input");
        workspace.push_message_input('h');
        workspace.push_message_input('i');
        assert_eq!(
            workspace.tabs[0]
                .message_input
                .as_ref()
                .map(message_editor_text),
            Some("hi".into())
        );
    }

    #[test]
    fn online_group_allows_separate_image_path_composition() {
        let mut workspace = Workspace::default();
        let group_id = GroupId::new("image-compose-group").expect("group id");
        workspace.open(ConversationKey::Group(group_id.clone()), "Group");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: SessionId::new(35),
            key: ManagedSessionKey::Group(group_id),
        });

        workspace.begin_image_input().expect("group image input");
        workspace.set_image_input(" /tmp/preview.png\n".into());

        assert_eq!(
            workspace.tabs[0].image_path_input.as_deref(),
            Some("/tmp/preview.png")
        );
        assert!(workspace.tabs[0].message_input.is_none());
    }

    #[test]
    fn received_group_image_is_kept_only_in_the_matching_transcript_memory() {
        let mut workspace = Workspace::default();
        let alpha_id = GroupId::new("alpha-image").expect("group id");
        let beta_id = GroupId::new("beta-image").expect("group id");
        let alpha_session = SessionId::new(36);
        workspace.open(ConversationKey::Group(alpha_id.clone()), "Alpha");
        workspace.open(ConversationKey::Group(beta_id), "Beta");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: alpha_session,
            key: ManagedSessionKey::Group(alpha_id),
        });
        workspace.tabs[0]
            .group_member_names
            .insert("alice.b32.i2p".into(), "Alice".into());

        let image_bytes = test_png();
        workspace.receive_image(&ImageReceivedEvent {
            session_id: alpha_session,
            message_id: 91,
            filename: "preview.png".into(),
            mime: "image/png".into(),
            bytes: image_bytes.clone(),
            timestamp_utc: "12:00:00 UTC".into(),
            sender_b32: Some("alice.b32.i2p".into()),
            original: None,
        });

        assert_eq!(workspace.tabs[0].messages.len(), 1);
        assert_eq!(
            workspace.tabs[0].messages[0].author.as_deref(),
            Some("Alice")
        );
        assert!(workspace.tabs[0].messages[0].text.contains("preview.png"));
        assert_eq!(
            workspace.tabs[0].messages[0]
                .image_bytes
                .as_deref()
                .map(<[u8]>::len),
            Some(image_bytes.len())
        );
        assert!(workspace.tabs[0].messages[0].image_render.is_some());
        assert!(workspace.tabs[0].presentation.unread_text);
        assert!(workspace.tabs[1].messages.is_empty());
        assert!(!workspace.tabs[1].presentation.unread_text);
    }

    #[test]
    fn group_original_image_state_is_scoped_to_media_and_sender() {
        let mut workspace = Workspace::default();
        let group_id = GroupId::new("original-image-group").expect("group id");
        let session_id = SessionId::new(39);
        workspace.open(ConversationKey::Group(group_id.clone()), "Originals");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id,
            key: ManagedSessionKey::Group(group_id),
        });
        let original =
            OriginalImageMetadata::new(test_png().len() as u64, "image/png", "00".repeat(32))
                .expect("original metadata");
        for sender_b32 in ["alice.b32.i2p", "bob.b32.i2p"] {
            workspace.receive_image(&ImageReceivedEvent {
                session_id,
                message_id: 92,
                filename: "preview.png".into(),
                mime: "image/png".into(),
                bytes: test_png(),
                timestamp_utc: "12:00:00 UTC".into(),
                sender_b32: Some(sender_b32.into()),
                original: Some(original.clone()),
            });
        }
        workspace
            .move_active_message_selection(-1)
            .expect("select latest requestable image");
        assert_eq!(workspace.tabs[0].presentation.selected_message, Some(1));
        assert_eq!(
            workspace.active_original_image_selection_hint(),
            Some("Image selected; g requests the original image.")
        );

        workspace.receive_original_image_progress(
            session_id,
            92,
            20,
            original.size,
            Some("bob.b32.i2p"),
        );
        assert_eq!(
            workspace.tabs[0].messages[0].original_state,
            Some(OriginalImageUiState::Available)
        );
        assert_eq!(
            workspace.tabs[0].messages[1].original_state,
            Some(OriginalImageUiState::Requesting {
                received_bytes: 20,
                total_bytes: original.size,
            })
        );
        assert_eq!(
            workspace.active_original_image_selection_hint(),
            Some("Original image download selected; X cancels it.")
        );

        workspace.receive_original_image(&OriginalImageReceivedEvent {
            session_id,
            transfer_id: 93,
            media_id: 92,
            filename: "original.png".into(),
            mime: "image/png".into(),
            bytes: test_png(),
            sender_b32: Some("bob.b32.i2p".into()),
        });
        assert_eq!(
            workspace.tabs[0].messages[0].original_state,
            Some(OriginalImageUiState::Available)
        );
        assert_eq!(
            workspace.tabs[0].messages[1].original_state,
            Some(OriginalImageUiState::Cached)
        );
        assert_eq!(
            workspace.active_original_image_selection_hint(),
            Some("Original image selected; g reloads it from memory.")
        );
    }

    #[test]
    fn recoverable_session_operation_error_does_not_fail_the_tab() {
        let mut workspace = Workspace::default();
        let contact_id = ContactId::new("alice").expect("contact id");
        let session_id = SessionId::new(9);
        workspace.open(ConversationKey::Contact(contact_id.clone()), "Alice");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id,
            key: ManagedSessionKey::Contact(contact_id),
        });
        workspace.handle_runtime_operation_event(&RuntimeOperationEvent::Failed {
            session_id: Some(session_id),
            operation: "accept SAM stream".into(),
            reason: "broken pipe".into(),
        });

        assert_eq!(workspace.tabs[0].phase, ConversationPhase::Standby);
        assert_eq!(
            workspace.tabs[0].last_warning.as_deref(),
            Some("accept SAM stream: broken pipe")
        );
    }

    #[test]
    fn recovered_accept_operation_clears_only_its_matching_warning() {
        let mut workspace = Workspace::default();
        let contact_id = ContactId::new("alice").expect("contact id");
        let session_id = SessionId::new(9);
        workspace.open(ConversationKey::Contact(contact_id.clone()), "Alice");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id,
            key: ManagedSessionKey::Contact(contact_id),
        });
        workspace.handle_runtime_operation_event(&RuntimeOperationEvent::Failed {
            session_id: Some(session_id),
            operation: "accept SAM stream".into(),
            reason: "broken pipe".into(),
        });
        workspace.handle_runtime_operation_event(&RuntimeOperationEvent::Recovered {
            session_id,
            operation: "accept SAM stream".into(),
        });

        assert_eq!(workspace.tabs[0].phase, ConversationPhase::Standby);
        assert!(workspace.tabs[0].last_warning.is_none());

        workspace.handle_runtime_operation_event(&RuntimeOperationEvent::Failed {
            session_id: Some(session_id),
            operation: "send chat frame".into(),
            reason: "connection closed".into(),
        });
        workspace.handle_runtime_operation_event(&RuntimeOperationEvent::Recovered {
            session_id,
            operation: "accept SAM stream".into(),
        });

        assert_eq!(
            workspace.tabs[0].last_warning.as_deref(),
            Some("send chat frame: connection closed")
        );
    }

    #[test]
    fn incoming_call_state_updates_only_the_matching_contact() {
        let mut workspace = Workspace::default();
        let alice_id = ContactId::new("alice").expect("contact id");
        let bob_id = ContactId::new("bob").expect("contact id");
        let alice_session = SessionId::new(11);
        let bob_session = SessionId::new(12);
        workspace.open(ConversationKey::Contact(alice_id.clone()), "Alice");
        workspace.open(ConversationKey::Contact(bob_id.clone()), "Bob");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: alice_session,
            key: ManagedSessionKey::Contact(alice_id),
        });
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: bob_session,
            key: ManagedSessionKey::Contact(bob_id),
        });

        workspace.handle_contact_session_event(&ContactSessionEvent::PhaseChanged {
            session_id: alice_session,
            phase: OneToOnePhase::IncomingPending,
        });
        workspace.handle_contact_session_event(&ContactSessionEvent::IncomingCall {
            session_id: alice_session,
            peer_b32: "alice-peer.b32.i2p".into(),
        });

        assert_eq!(
            workspace.tabs[0].contact_phase,
            Some(OneToOnePhase::IncomingPending)
        );
        assert_eq!(
            workspace.tabs[0].incoming_peer_b32.as_deref(),
            Some("alice-peer.b32.i2p")
        );
        assert_eq!(
            workspace.tabs[1].contact_phase,
            Some(OneToOnePhase::Standby)
        );
        assert!(workspace.tabs[1].incoming_peer_b32.is_none());
    }

    #[test]
    fn unresolved_incoming_calls_are_counted_until_the_tab_is_viewed() {
        let mut workspace = Workspace::default();
        let contact_id = ContactId::new("alice").expect("contact id");
        let session_id = SessionId::new(14);
        workspace.open(ConversationKey::Contact(contact_id.clone()), "Alice");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id,
            key: ManagedSessionKey::Contact(contact_id),
        });
        workspace.handle_contact_session_event(&ContactSessionEvent::PhaseChanged {
            session_id,
            phase: OneToOnePhase::IncomingPending,
        });
        workspace.handle_contact_session_event(&ContactSessionEvent::IncomingCall {
            session_id,
            peer_b32: "peer.b32.i2p".into(),
        });

        workspace.handle_contact_session_event(&ContactSessionEvent::PhaseChanged {
            session_id,
            phase: OneToOnePhase::Standby,
        });

        assert_eq!(workspace.tabs[0].presentation.missed_calls, 1);
        assert_eq!(workspace.total_missed_calls(), 1);
        assert_eq!(workspace.tabs[0].rendered_label(0, false), "Alice 1");

        workspace.clear_active_missed_calls();
        assert_eq!(workspace.tabs[0].presentation.missed_calls, 0);
        assert_eq!(workspace.total_missed_calls(), 0);

        workspace.handle_contact_session_event(&ContactSessionEvent::PhaseChanged {
            session_id,
            phase: OneToOnePhase::IncomingPending,
        });
        workspace.handle_contact_session_event(&ContactSessionEvent::IncomingCall {
            session_id,
            peer_b32: "peer.b32.i2p".into(),
        });
        workspace.handle_contact_session_event(&ContactSessionEvent::CollisionResolved {
            session_id,
            winner: CollisionWinner::Outbound,
        });
        workspace.handle_contact_session_event(&ContactSessionEvent::PhaseChanged {
            session_id,
            phase: OneToOnePhase::Handshaking,
        });
        assert_eq!(workspace.total_missed_calls(), 0);
    }

    #[test]
    fn leaving_incoming_phase_clears_pending_call_display() {
        let mut workspace = Workspace::default();
        let contact_id = ContactId::new("alice").expect("contact id");
        let session_id = SessionId::new(13);
        workspace.open(ConversationKey::Contact(contact_id.clone()), "Alice");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id,
            key: ManagedSessionKey::Contact(contact_id),
        });
        workspace.handle_contact_session_event(&ContactSessionEvent::IncomingCall {
            session_id,
            peer_b32: "peer.b32.i2p".into(),
        });

        workspace.handle_contact_session_event(&ContactSessionEvent::PhaseChanged {
            session_id,
            phase: OneToOnePhase::Handshaking,
        });

        assert_eq!(
            workspace.tabs[0].contact_phase,
            Some(OneToOnePhase::Handshaking)
        );
        assert!(workspace.tabs[0].incoming_peer_b32.is_none());
    }

    #[test]
    fn closing_a_session_discards_contact_address_entry() {
        let mut workspace = Workspace::default();
        let contact_id = ContactId::new("alice").expect("contact id");
        let session_id = SessionId::new(14);
        workspace.open(ConversationKey::Contact(contact_id.clone()), "Alice");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id,
            key: ManagedSessionKey::Contact(contact_id.clone()),
        });
        workspace.tabs[0].connect_input = Some("peer.b32.i2p".into());

        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Closing {
            session_id,
            key: ManagedSessionKey::Contact(contact_id),
        });

        assert_eq!(workspace.tabs[0].phase, ConversationPhase::Closing);
        assert!(workspace.tabs[0].connect_input.is_none());
    }

    #[test]
    fn message_entry_is_available_only_while_contact_is_ready() {
        let mut workspace = Workspace::default();
        let contact_id = ContactId::new("alice").expect("contact id");
        let session_id = SessionId::new(15);
        workspace.open(ConversationKey::Contact(contact_id.clone()), "Alice");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id,
            key: ManagedSessionKey::Contact(contact_id),
        });

        assert!(workspace.begin_message_input().is_err());
        workspace.handle_contact_session_event(&ContactSessionEvent::PhaseChanged {
            session_id,
            phase: OneToOnePhase::Ready,
        });
        workspace.begin_message_input().expect("message input");
        workspace.push_message_input('h');
        workspace.push_message_input('i');
        assert_eq!(
            workspace.tabs[0]
                .message_input
                .as_ref()
                .map(message_editor_text),
            Some("hi".into())
        );

        workspace.handle_contact_session_event(&ContactSessionEvent::PhaseChanged {
            session_id,
            phase: OneToOnePhase::Standby,
        });
        assert!(workspace.tabs[0].message_input.is_none());
    }

    #[test]
    fn offline_mode_allows_message_entry_from_online_standby() {
        let mut workspace = Workspace::default();
        let contact_id = ContactId::new("alice").expect("contact id");
        let session_id = SessionId::new(21);
        workspace.open(ConversationKey::Contact(contact_id.clone()), "Alice");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id,
            key: ManagedSessionKey::Contact(contact_id),
        });

        workspace.handle_offline_session_event(&OfflineSessionEvent::ModeChanged {
            session_id,
            mode: OfflineCoordinatorMode::Offline,
        });
        workspace
            .begin_message_input()
            .expect("offline message input");
        workspace.push_message_input('h');
        workspace.push_message_input('i');
        assert_eq!(
            workspace.tabs[0]
                .message_input
                .as_ref()
                .map(message_editor_text),
            Some("hi".into())
        );

        workspace.handle_offline_session_event(&OfflineSessionEvent::ModeChanged {
            session_id,
            mode: OfflineCoordinatorMode::Standby,
        });
        assert!(workspace.tabs[0].message_input.is_none());
    }

    #[test]
    fn message_editor_preserves_multiline_paste_and_filters_other_control_characters() {
        let mut editor = new_message_editor();
        let text = sanitized_message_insert("first\r\nsecond\nthird\0", 128);
        editor.insert_str(text);

        assert_eq!(message_editor_text(&editor), "first\nsecond\nthird");
        assert_eq!(message_editor_bytes(&editor), 18);
    }

    #[test]
    fn message_insert_limit_never_splits_a_utf8_character() {
        assert_eq!(sanitized_message_insert("abéz", 4), "abé");
        assert_eq!(sanitized_message_insert("é", 1), "");
    }

    #[test]
    fn offline_receive_and_put_confirmation_update_only_the_matching_transcript() {
        let mut workspace = Workspace::default();
        let alice_id = ContactId::new("alice").expect("contact id");
        let bob_id = ContactId::new("bob").expect("contact id");
        let alice_session = SessionId::new(22);
        let bob_session = SessionId::new(23);
        workspace.open(ConversationKey::Contact(alice_id.clone()), "Alice");
        workspace.open(ConversationKey::Contact(bob_id.clone()), "Bob");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: alice_session,
            key: ManagedSessionKey::Contact(alice_id),
        });
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: bob_session,
            key: ManagedSessionKey::Contact(bob_id),
        });
        workspace.tabs[0].push_message(ChatDirection::Sent, 71, "outgoing".into());

        workspace.handle_offline_session_event(&OfflineSessionEvent::SendConfirmed {
            session_id: alice_session,
            message_id: 71,
            index: 4,
            successful_drop_count: 1,
        });
        let mut incoming = received_text(alice_session, 72, "incoming");
        incoming.offline = true;
        workspace.receive_text(&incoming);

        assert!(workspace.tabs[0].messages[0].relayed);
        assert!(!workspace.tabs[0].messages[0].delivered);
        assert_eq!(workspace.tabs[0].messages[1].text, "incoming");
        assert_eq!(
            workspace.tabs[0].messages[1].direction,
            ChatDirection::Received
        );
        assert!(workspace.tabs[1].messages.is_empty());
    }

    #[test]
    fn offline_activity_events_update_only_the_matching_tab_and_expire_to_idle() {
        let mut workspace = Workspace::default();
        let alice_id = ContactId::new("alice").expect("contact id");
        let bob_id = ContactId::new("bob").expect("contact id");
        let alice_session = SessionId::new(24);
        let bob_session = SessionId::new(25);
        workspace.open(ConversationKey::Contact(alice_id.clone()), "Alice");
        workspace.open(ConversationKey::Contact(bob_id.clone()), "Bob");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: alice_session,
            key: ManagedSessionKey::Contact(alice_id),
        });
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: bob_session,
            key: ManagedSessionKey::Contact(bob_id),
        });

        workspace.handle_offline_session_event(&OfflineSessionEvent::PollSweepStarted {
            session_id: alice_session,
        });
        assert_eq!(
            workspace.tabs[0].offline_activity.visible_state(),
            OfflineActivityState::Poll
        );
        assert_eq!(
            workspace.tabs[1].offline_activity.visible_state(),
            OfflineActivityState::Idle
        );

        workspace.handle_offline_session_event(&OfflineSessionEvent::PollSweepCompleted {
            session_id: alice_session,
            result: OfflinePollResult::Miss,
            observation_count: 1,
        });
        assert_eq!(
            workspace.tabs[0].offline_activity.visible_state(),
            OfflineActivityState::Miss
        );

        workspace.tabs[0].offline_activity.changed_at =
            Instant::now().checked_sub(OFFLINE_STATUS_VISIBLE_FOR + Duration::from_millis(1));
        assert_eq!(
            workspace.tabs[0].offline_activity.visible_state(),
            OfflineActivityState::Idle
        );
    }

    #[test]
    fn semantic_text_event_is_recorded_only_in_its_contact_transcript() {
        let mut workspace = Workspace::default();
        let alice_id = ContactId::new("alice").expect("contact id");
        let bob_id = ContactId::new("bob").expect("contact id");
        let alice_session = SessionId::new(16);
        let bob_session = SessionId::new(17);
        workspace.open(ConversationKey::Contact(alice_id.clone()), "Alice");
        workspace.open(ConversationKey::Contact(bob_id.clone()), "Bob");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: alice_session,
            key: ManagedSessionKey::Contact(alice_id),
        });
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: bob_session,
            key: ManagedSessionKey::Contact(bob_id),
        });

        workspace.receive_text(&received_text(alice_session, 7, "hello"));

        assert_eq!(workspace.tabs[0].messages.len(), 1);
        assert_eq!(
            workspace.tabs[0].messages[0].direction,
            ChatDirection::Received
        );
        assert_eq!(workspace.tabs[0].messages[0].text, "hello");
        assert!(workspace.tabs[1].messages.is_empty());
    }

    #[test]
    fn semantic_image_event_is_kept_in_contact_memory() {
        let mut workspace = Workspace::default();
        let contact_id = ContactId::new("image-peer").expect("contact id");
        let session_id = SessionId::new(37);
        workspace.open(ConversationKey::Contact(contact_id.clone()), "Image peer");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id,
            key: ManagedSessionKey::Contact(contact_id),
        });
        let bytes = test_png();
        workspace.receive_image(&ImageReceivedEvent {
            session_id,
            message_id: 81,
            filename: "preview.png".into(),
            mime: "image/png".into(),
            bytes: bytes.clone(),
            timestamp_utc: "12:00:00 UTC".into(),
            sender_b32: None,
            original: None,
        });
        assert_eq!(workspace.tabs[0].messages.len(), 1);
        assert!(workspace.tabs[0].messages[0].text.contains("preview.png"));
        assert_eq!(
            workspace.tabs[0].messages[0].image_bytes.as_deref(),
            Some(bytes.as_slice())
        );
        assert!(workspace.tabs[0].messages[0].image_render.is_some());
    }

    #[test]
    fn undecodable_semantic_image_is_not_displayed() {
        let mut workspace = Workspace::default();
        let contact_id = ContactId::new("invalid-image-peer").expect("contact id");
        let session_id = SessionId::new(38);
        workspace.open(
            ConversationKey::Contact(contact_id.clone()),
            "Invalid image peer",
        );
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id,
            key: ManagedSessionKey::Contact(contact_id),
        });
        let bytes = b"\x89PNG\r\n\x1a\nnot a complete png";
        workspace.receive_image(&ImageReceivedEvent {
            session_id,
            message_id: 82,
            filename: "broken.png".into(),
            mime: "image/png".into(),
            bytes: bytes.to_vec(),
            timestamp_utc: "12:00:00 UTC".into(),
            sender_b32: None,
            original: None,
        });
        assert!(workspace.tabs[0].messages.is_empty());
        assert!(
            workspace.tabs[0]
                .last_warning
                .as_deref()
                .is_some_and(|warning| warning.starts_with("Render inline image:"))
        );
    }

    #[test]
    fn delivery_acknowledgement_marks_only_the_matching_sent_message() {
        let mut workspace = Workspace::default();
        let alice_id = ContactId::new("alice").expect("contact id");
        let bob_id = ContactId::new("bob").expect("contact id");
        let alice_session = SessionId::new(18);
        let bob_session = SessionId::new(19);
        workspace.open(ConversationKey::Contact(alice_id.clone()), "Alice");
        workspace.open(ConversationKey::Contact(bob_id.clone()), "Bob");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: alice_session,
            key: ManagedSessionKey::Contact(alice_id),
        });
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id: bob_session,
            key: ManagedSessionKey::Contact(bob_id),
        });
        workspace.tabs[0].push_message(ChatDirection::Sent, 41, "first".into());
        workspace.tabs[0].push_message(ChatDirection::Sent, 42, "second".into());
        workspace.tabs[1].push_message(ChatDirection::Sent, 42, "other tab".into());

        workspace.receive_text_delivery(&TextDeliveryEvent {
            session_id: alice_session,
            message_id: 42,
            peer_b32: None,
            group: false,
            received: 1,
            expected: 1,
            warning: None,
        });

        assert!(!workspace.tabs[0].messages[0].delivered);
        assert!(workspace.tabs[0].messages[1].delivered);
        assert!(!workspace.tabs[1].messages[0].delivered);
    }

    #[test]
    fn transcript_retention_is_bounded() {
        let mut workspace = Workspace::default();
        let contact_id = ContactId::new("alice").expect("contact id");
        let session_id = SessionId::new(20);
        workspace.open(ConversationKey::Contact(contact_id.clone()), "Alice");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id,
            key: ManagedSessionKey::Contact(contact_id),
        });

        for index in 0..=MAX_TRANSCRIPT_MESSAGES {
            workspace.receive_text(&received_text(session_id, index as u64, &index.to_string()));
        }

        assert_eq!(workspace.tabs[0].messages.len(), MAX_TRANSCRIPT_MESSAGES);
        assert_eq!(workspace.tabs[0].messages[0].text, "1");
    }

    #[test]
    fn message_bubbles_keep_outgoing_left_and_incoming_right_within_width() {
        let outgoing = ChatMessage {
            direction: ChatDirection::Sent,
            kind: ChatMessageKind::Text,
            offline: false,
            message_id: 1,
            timestamp_utc: "12:34:56 UTC".into(),
            text: "first line\nsecond line wraps across the bubble width".into(),
            image_bytes: None,
            image_render: None,
            original: None,
            original_sender_b32: None,
            original_state: None,
            author: None,
            group_delivery: None,
            relayed: false,
            delivered: true,
            failed: false,
            history: MessageHistoryState::Stored,
        };
        let incoming = ChatMessage {
            direction: ChatDirection::Received,
            kind: ChatMessageKind::Text,
            offline: false,
            message_id: 2,
            timestamp_utc: "12:35:01 UTC".into(),
            text: "reply".into(),
            image_bytes: None,
            image_render: None,
            original: None,
            original_sender_b32: None,
            original_state: None,
            author: Some("Alice".into()),
            group_delivery: None,
            relayed: false,
            delivered: false,
            failed: false,
            history: MessageHistoryState::NotStored,
        };
        let mut outgoing_lines = Vec::new();
        let mut incoming_lines = Vec::new();
        append_message_bubble(
            &mut outgoing_lines,
            &outgoing,
            "Me",
            contact_delivery_label(&outgoing).as_deref(),
            false,
            40,
        );
        append_message_bubble(&mut incoming_lines, &incoming, "Alice", None, false, 40);

        let outgoing_top = rendered_line_text(&outgoing_lines[0]);
        let incoming_top = rendered_line_text(&incoming_lines[0]);
        assert!(outgoing_top.starts_with('╭'));
        assert!(incoming_top.starts_with(' '));
        assert!(incoming_top.trim_start().starts_with('╭'));
        assert!(
            outgoing_lines
                .iter()
                .chain(&incoming_lines)
                .all(|line| UnicodeWidthStr::width(rendered_line_text(line).as_str()) <= 40)
        );
        let outgoing_text = outgoing_lines
            .iter()
            .map(rendered_line_text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(outgoing_text.contains("first line"));
        assert!(outgoing_text.contains("second line"));
        assert!(outgoing_text.contains("[12:34:56 UTC]"));
        assert!(outgoing_text.contains("✓✓"));
        assert!(
            outgoing_lines[0]
                .spans
                .iter()
                .any(|span| span.content == "Me" && span.style.fg == Some(Color::Green))
        );
        assert!(
            outgoing_lines[0]
                .spans
                .iter()
                .any(|span| { span.content == "[H]" && span.style.fg == Some(Color::DarkGray) })
        );
        assert!(
            !incoming_lines[0]
                .spans
                .iter()
                .any(|span| span.content == "[H]")
        );
        assert!(
            incoming_lines[0]
                .spans
                .iter()
                .any(|span| span.content == "Alice" && span.style.fg == Some(Color::Cyan))
        );
    }

    #[test]
    fn image_preview_is_rendered_inside_its_message_bubble() {
        let rendered = render_image_bytes(&test_png()).expect("render image");
        let message = ChatMessage {
            direction: ChatDirection::Received,
            kind: ChatMessageKind::Image,
            offline: false,
            message_id: 3,
            timestamp_utc: "12:35:01 UTC".into(),
            text: "[image: preview.png, image/png]".into(),
            image_bytes: Some(test_png()),
            image_render: Some(rendered),
            original: None,
            original_sender_b32: None,
            original_state: None,
            author: Some("Alice".into()),
            group_delivery: None,
            relayed: false,
            delivered: false,
            failed: false,
            history: MessageHistoryState::Stored,
        };
        let mut lines = Vec::new();
        append_message_bubble(&mut lines, &message, "Alice", None, false, 80);

        assert!(lines.iter().map(rendered_line_text).any(|line| {
            line.chars()
                .any(|character| ('\u{2800}'..='\u{28ff}').contains(&character))
        }));
        assert!(
            lines
                .iter()
                .all(|line| { UnicodeWidthStr::width(rendered_line_text(line).as_str()) <= 80 })
        );
        assert!(
            !lines
                .iter()
                .flat_map(|line| line.spans.iter())
                .any(|span| span.content == "[H]")
        );
    }

    #[test]
    fn failed_history_write_has_a_distinct_red_marker() {
        let mut message = ChatMessage {
            direction: ChatDirection::Sent,
            kind: ChatMessageKind::Text,
            offline: false,
            message_id: 6,
            timestamp_utc: "12:38:00 UTC".into(),
            text: "not persisted".into(),
            image_bytes: None,
            image_render: None,
            original: None,
            original_sender_b32: None,
            original_state: None,
            author: None,
            group_delivery: None,
            relayed: false,
            delivered: false,
            failed: false,
            history: MessageHistoryState::StoreFailed,
        };
        assert_eq!(message_history_marker(&message), Some("[H!]"));

        let mut lines = Vec::new();
        append_message_bubble(&mut lines, &message, "Me", None, false, 60);
        assert!(
            lines[0]
                .spans
                .iter()
                .any(|span| { span.content == "[H!]" && span.style.fg == Some(Color::Red) })
        );

        message.history = MessageHistoryState::NotStored;
        assert_eq!(message_history_marker(&message), None);
    }

    #[test]
    fn delivery_labels_distinguish_relayed_partial_and_complete_states() {
        let mut message = ChatMessage {
            direction: ChatDirection::Sent,
            kind: ChatMessageKind::Text,
            offline: false,
            message_id: 4,
            timestamp_utc: "12:36:00 UTC".into(),
            text: "status".into(),
            image_bytes: None,
            image_render: None,
            original: None,
            original_sender_b32: None,
            original_state: None,
            author: None,
            group_delivery: None,
            relayed: true,
            delivered: false,
            failed: false,
            history: MessageHistoryState::NotStored,
        };

        assert_eq!(contact_delivery_label(&message).as_deref(), Some("✓"));
        message.group_delivery = Some((1, 3));
        assert_eq!(group_delivery_label(&message).as_deref(), Some("✓ 1/3"));
        message.group_delivery = Some((3, 3));
        assert_eq!(group_delivery_label(&message).as_deref(), Some("✓✓ 3/3"));
    }

    #[test]
    fn offline_bubbles_use_reference_colors_without_background_fill() {
        let message = ChatMessage {
            direction: ChatDirection::Received,
            kind: ChatMessageKind::Text,
            offline: true,
            message_id: 5,
            timestamp_utc: "12:37:00 UTC".into(),
            text: "offline".into(),
            image_bytes: None,
            image_render: None,
            original: None,
            original_sender_b32: None,
            original_state: None,
            author: None,
            group_delivery: None,
            relayed: false,
            delivered: false,
            failed: false,
            history: MessageHistoryState::Stored,
        };
        let mut lines = Vec::new();
        append_message_bubble(&mut lines, &message, "Peer-Offline", None, true, 60);

        assert!(
            lines[0]
                .spans
                .iter()
                .any(|span| span.content == "╭─" && span.style.fg == Some(Color::Magenta))
        );
        assert!(
            lines
                .iter()
                .flat_map(|line| line.spans.iter())
                .all(|span| span.style.bg.is_none())
        );
        assert!(rendered_line_text(&lines[0]).contains("▶"));
    }

    #[test]
    fn message_selection_skips_media_and_copies_only_text() {
        let mut workspace = Workspace::default();
        workspace.open(
            ConversationKey::Contact(ContactId::new("alice").expect("contact id")),
            "Alice",
        );
        workspace.tabs[0].push_file_message(ChatDirection::Sent, 1, "[file: one.bin]".into());
        workspace.tabs[0].push_image(
            ChatDirection::Received,
            2,
            "[image: one.png]".into(),
            None,
            None,
            test_png(),
            None,
            None,
            None,
        );
        workspace.tabs[0].push_message(ChatDirection::Received, 3, "copy me".into());

        workspace
            .move_active_message_selection(-1)
            .expect("select text");
        assert_eq!(workspace.tabs[0].presentation.selected_message, Some(2));
        assert_eq!(
            workspace
                .active_selected_message_copy_text()
                .expect("copy text"),
            "copy me"
        );

        assert!(workspace.clear_active_message_selection());
        workspace
            .move_active_message_selection(1)
            .expect("select newest text when entering with down");
        assert_eq!(workspace.tabs[0].presentation.selected_message, Some(2));
    }

    #[test]
    fn beginning_a_reply_restores_follow_latest() {
        let mut workspace = Workspace::default();
        workspace.open(
            ConversationKey::Contact(ContactId::new("alice").expect("contact id")),
            "Alice",
        );
        workspace.tabs[0].phase = ConversationPhase::Standby;
        workspace.tabs[0].contact_phase = Some(OneToOnePhase::Ready);
        workspace.tabs[0].push_message(ChatDirection::Received, 1, "reply target".into());
        workspace.tabs[0].push_message(ChatDirection::Received, 2, "latest message".into());

        workspace
            .move_active_message_selection(-1)
            .expect("select latest message");
        workspace
            .move_active_message_selection(-1)
            .expect("select older reply target");
        assert!(!workspace.tabs[0].presentation.follow_latest);

        workspace
            .begin_reply_to_selected()
            .expect("begin reply composition");

        assert!(workspace.tabs[0].presentation.follow_latest);
        assert!(workspace.tabs[0].presentation.selected_message.is_none());
        assert!(workspace.tabs[0].reply_to.is_some());
    }

    #[test]
    fn actionable_file_offer_can_be_selected_and_terminal_event_clears_selection() {
        let mut workspace = Workspace::default();
        let contact_id = ContactId::new("alice").expect("contact id");
        let session_id = SessionId::new(31);
        workspace.open(ConversationKey::Contact(contact_id.clone()), "Alice");
        workspace.handle_session_lifecycle_event(&SessionLifecycleEvent::Opened {
            session_id,
            key: ManagedSessionKey::Contact(contact_id),
        });
        workspace.handle_file_transfer_event(&RuntimeFileTransferEvent::Offered {
            session_id,
            transfer_id: 7010,
            direction: RuntimeFileTransferDirection::Received,
            filename: "notes.txt".into(),
            total_bytes: 42,
        });

        workspace
            .move_active_message_selection(-1)
            .expect("select incoming file offer");
        assert_eq!(workspace.tabs[0].presentation.selected_message, Some(0));
        assert_eq!(
            workspace.active_file_selection_hint(),
            Some("File offer selected; y accepts and n declines.")
        );
        assert!(
            workspace.tabs[0]
                .log
                .lines
                .back()
                .is_some_and(|line| line.contains("File receiving offered: notes.txt (42 bytes)."))
        );

        workspace.handle_file_transfer_event(&RuntimeFileTransferEvent::Declined {
            session_id,
            transfer_id: 7010,
            direction: RuntimeFileTransferDirection::Received,
            filename: "notes.txt".into(),
        });

        assert!(workspace.tabs[0].file_transfer_states.is_empty());
        assert_eq!(workspace.tabs[0].presentation.selected_message, None);
        assert!(workspace.tabs[0].log.lines.back().is_some_and(|line| {
            line.contains("File transfer receiving for notes.txt was declined.")
        }));
    }

    #[test]
    fn reply_payload_matches_shared_format_and_does_not_recurse() {
        let first = compose_reply_text(
            Some(&ReplyDraft {
                author: "Alice".into(),
                text: "original".into(),
            }),
            "first reply",
        );
        let parsed = parse_reply_text(&first).expect("parse reply");
        assert_eq!(parsed.author, "Alice");
        assert_eq!(parsed.quote, "original");
        assert_eq!(parsed.body, "first reply");
        assert_eq!(reply_source_text(&first), "first reply");
        assert_eq!(
            display_reply_text(&first),
            "Reply to Alice:\noriginal\n\nfirst reply"
        );
    }

    #[test]
    fn loaded_history_precedes_messages_from_the_current_tab_lifetime() {
        let contact = ConversationKey::Contact(ContactId::new("alice").expect("contact id"));
        let mut workspace = Workspace::default();
        workspace.open(contact.clone(), "Alice");
        workspace.tabs[0].push_message(ChatDirection::Received, 22, "current".into());

        workspace.load_history(
            &contact,
            vec![HistoryRecord {
                created_ms: 1,
                timestamp_utc: "12:00:00 UTC".into(),
                author: "Alice".into(),
                sender_b32: None,
                text: "historic".into(),
                mine: false,
                offline: false,
                msg_id: Some(11),
                delivered: false,
                group_expected_acks: Vec::new(),
                group_received_acks: Vec::new(),
            }],
        );

        assert_eq!(workspace.tabs[0].messages.len(), 2);
        assert_eq!(workspace.tabs[0].messages[0].text, "historic");
        assert_eq!(workspace.tabs[0].messages[1].text, "current");
        assert_eq!(
            workspace.tabs[0].messages[0].history,
            MessageHistoryState::Stored
        );
        assert_eq!(
            workspace.tabs[0].messages[1].history,
            MessageHistoryState::NotStored
        );
        assert!(workspace.tabs[0].history_loaded);
    }

    #[test]
    fn clearing_loaded_history_preserves_current_tab_messages() {
        let contact_id = ContactId::new("alice").expect("contact id");
        let contact = ConversationKey::Contact(contact_id.clone());
        let managed = ManagedSessionKey::Contact(contact_id);
        let mut workspace = Workspace::default();
        workspace.open(contact.clone(), "Alice");
        workspace.tabs[0].push_message(ChatDirection::Received, 22, "current".into());
        workspace.load_history(
            &contact,
            vec![HistoryRecord {
                created_ms: 1,
                timestamp_utc: "12:00:00 UTC".into(),
                author: "Alice".into(),
                sender_b32: None,
                text: "historic".into(),
                mine: false,
                offline: false,
                msg_id: Some(11),
                delivered: false,
                group_expected_acks: Vec::new(),
                group_received_acks: Vec::new(),
            }],
        );
        workspace.tabs[0].messages[1].history = MessageHistoryState::Stored;

        workspace.clear_loaded_history(&managed);

        assert_eq!(workspace.tabs[0].messages.len(), 1);
        assert_eq!(workspace.tabs[0].messages[0].text, "current");
        assert_eq!(
            workspace.tabs[0].messages[0].history,
            MessageHistoryState::NotStored
        );
        assert_eq!(workspace.tabs[0].loaded_history_count, 0);
        assert!(workspace.tabs[0].history_loaded);
    }

    #[test]
    fn overflow_window_always_contains_the_selected_tab() {
        let labels = ["One", "Two", "Three", "Four", "Five"].map(str::to_string);
        let visible = visible_tab_range(&labels, 4, 18);

        assert!(visible.contains(&4));
        assert!(visible.len() < labels.len());
    }

    #[test]
    fn multiple_transient_tabs_are_distinct_one_to_one_conversations() {
        let first = TransientId::new("transient-one").expect("transient id");
        let second = TransientId::new("transient-two").expect("transient id");
        let mut workspace = Workspace::default();

        assert_eq!(
            workspace.open(ConversationKey::Transient(first.clone()), "Transient 1"),
            OpenDisposition::Opened
        );
        assert_eq!(
            workspace.open(ConversationKey::Transient(second.clone()), "Transient 2"),
            OpenDisposition::Opened
        );
        assert_eq!(workspace.tabs.len(), 2);
        assert_eq!(
            managed_key(&workspace.tabs[0].key),
            ManagedSessionKey::Transient(first.clone())
        );
        assert_eq!(
            managed_key(&workspace.tabs[1].key),
            ManagedSessionKey::Transient(second.clone())
        );
        assert!(workspace.tabs.iter().all(|tab| {
            tab.contact_phase == Some(OneToOnePhase::Standby) && tab.offline_mode.is_none()
        }));
        assert_eq!(
            workspace.transient_browser_entries(),
            vec![
                TransientBrowserEntry {
                    id: first,
                    label: "Transient 1".into(),
                    state: ConversationTabState::Open,
                },
                TransientBrowserEntry {
                    id: second,
                    label: "Transient 2".into(),
                    state: ConversationTabState::Open,
                },
            ]
        );
    }

    fn rendered_line_text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }
}
