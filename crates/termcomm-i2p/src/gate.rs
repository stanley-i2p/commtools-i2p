use commtools_core::{UnlockedVault, VaultError, VaultRepository};
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use futures_util::StreamExt;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use std::io;
use thiserror::Error;
use zeroize::Zeroize;

use crate::terminal::TerminalSession;

const MAX_PASSPHRASE_BYTES: usize = 1_024;
const MAX_VISIBLE_MASK: usize = 64;

#[derive(Debug, Error)]
pub enum GateError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error("terminal event stream ended")]
    EventStreamEnded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateStage {
    Unlock,
    SetPassphrase,
    ConfirmPassphrase,
    RecoveryChoice,
    RecoveryDiscardConfirmation,
    RecoveryPassphrase,
    RecoverySetPassphrase,
    RecoveryConfirmPassphrase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoverySelection {
    Recover,
    Discard,
}

pub async fn run(
    terminal: &mut TerminalSession,
    events: &mut crossterm::event::EventStream,
    repository: &VaultRepository,
) -> Result<Option<UnlockedVault>, GateError> {
    let stage = if repository.exists()? {
        GateStage::Unlock
    } else {
        GateStage::SetPassphrase
    };
    let mut gate = GateState::new(stage);
    draw(terminal, &gate)?;

    loop {
        let event = events.next().await.ok_or(GateError::EventStreamEnded)??;
        match event {
            Event::Key(key) if is_key_action(&key) => match gate.handle_key(key, repository)? {
                GateAction::Continue => draw(terminal, &gate)?,
                GateAction::Quit => return Ok(None),
                GateAction::Unlocked(vault) => return Ok(Some(vault)),
            },
            Event::Paste(value) => {
                gate.paste(&value);
                draw(terminal, &gate)?;
            }
            Event::Resize(_, _) => draw(terminal, &gate)?,
            _ => {}
        }
    }
}

struct GateState {
    stage: GateStage,
    first: String,
    current: String,
    error: Option<String>,
    recovery_encrypted_vault: bool,
    recovery_selection: RecoverySelection,
}

impl GateState {
    fn new(stage: GateStage) -> Self {
        Self {
            stage,
            first: String::new(),
            current: String::new(),
            error: None,
            recovery_encrypted_vault: false,
            recovery_selection: RecoverySelection::Recover,
        }
    }

    fn handle_key(
        &mut self,
        key: KeyEvent,
        repository: &VaultRepository,
    ) -> Result<GateAction, VaultError> {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            return Ok(GateAction::Quit);
        }
        if self.stage == GateStage::RecoveryChoice {
            return self.handle_recovery_choice(key);
        }
        if self.stage == GateStage::RecoveryDiscardConfirmation {
            return self.handle_recovery_discard_confirmation(key);
        }
        match key.code {
            KeyCode::Char(character) if self.accepts_passphrase() => self.push(character),
            KeyCode::Backspace => {
                self.current.pop();
                self.error = None;
            }
            KeyCode::Enter => return self.submit(repository),
            KeyCode::Esc
                if matches!(
                    self.stage,
                    GateStage::ConfirmPassphrase | GateStage::RecoveryConfirmPassphrase
                ) =>
            {
                self.clear_secrets();
                self.stage = if self.stage == GateStage::ConfirmPassphrase {
                    GateStage::SetPassphrase
                } else {
                    GateStage::RecoverySetPassphrase
                };
                self.error = None;
            }
            KeyCode::Esc
                if matches!(
                    self.stage,
                    GateStage::RecoveryPassphrase | GateStage::RecoverySetPassphrase
                ) =>
            {
                self.clear_secrets();
                self.stage = GateStage::RecoveryChoice;
                self.recovery_selection = RecoverySelection::Recover;
                self.error = None;
            }
            KeyCode::Esc => return Ok(GateAction::Quit),
            _ => {}
        }
        Ok(GateAction::Continue)
    }

    fn paste(&mut self, value: &str) {
        if !self.accepts_passphrase() {
            return;
        }
        for character in value.chars().filter(|character| !character.is_control()) {
            self.push(character);
        }
    }

    fn accepts_passphrase(&self) -> bool {
        !matches!(
            self.stage,
            GateStage::RecoveryChoice | GateStage::RecoveryDiscardConfirmation
        )
    }

    fn handle_recovery_choice(&mut self, key: KeyEvent) -> Result<GateAction, VaultError> {
        match key.code {
            KeyCode::Up | KeyCode::Down | KeyCode::Tab | KeyCode::BackTab => {
                self.recovery_selection = match self.recovery_selection {
                    RecoverySelection::Recover => RecoverySelection::Discard,
                    RecoverySelection::Discard => RecoverySelection::Recover,
                };
                self.error = None;
            }
            KeyCode::Enter => match self.recovery_selection {
                RecoverySelection::Recover => self.begin_recovery_credentials(),
                RecoverySelection::Discard => {
                    self.stage = GateStage::RecoveryDiscardConfirmation;
                    self.error = None;
                }
            },
            KeyCode::Esc => return Ok(GateAction::Quit),
            _ => {}
        }
        Ok(GateAction::Continue)
    }

    fn handle_recovery_discard_confirmation(
        &mut self,
        key: KeyEvent,
    ) -> Result<GateAction, VaultError> {
        match key.code {
            KeyCode::Char('y') => self.begin_recovery_credentials(),
            KeyCode::Char('n') | KeyCode::Esc => {
                self.stage = GateStage::RecoveryChoice;
                self.recovery_selection = RecoverySelection::Recover;
                self.error = None;
            }
            _ => {}
        }
        Ok(GateAction::Continue)
    }

    fn begin_recovery_credentials(&mut self) {
        self.clear_secrets();
        self.stage = if self.recovery_encrypted_vault {
            GateStage::RecoveryPassphrase
        } else {
            GateStage::RecoverySetPassphrase
        };
        self.error = None;
    }

    fn push(&mut self, character: char) {
        if self.current.len() + character.len_utf8() <= MAX_PASSPHRASE_BYTES {
            self.current.push(character);
            self.error = None;
        }
    }

    fn submit(&mut self, repository: &VaultRepository) -> Result<GateAction, VaultError> {
        if self.current.is_empty() {
            self.error = Some("Passphrase must not be empty.".into());
            return Ok(GateAction::Continue);
        }
        match self.stage {
            GateStage::Unlock => match repository.unlock(self.current.as_bytes()) {
                Ok(vault) => Ok(GateAction::Unlocked(vault)),
                Err(VaultError::AuthenticationFailed) => {
                    self.current.zeroize();
                    self.current.clear();
                    self.error = Some("Passphrase is invalid or the vault is damaged.".into());
                    Ok(GateAction::Continue)
                }
                Err(VaultError::PlaintextPresent) => self.begin_recovery(repository),
                Err(error) => Err(error),
            },
            GateStage::SetPassphrase => {
                self.first.zeroize();
                std::mem::swap(&mut self.first, &mut self.current);
                self.current.clear();
                self.stage = GateStage::ConfirmPassphrase;
                self.error = None;
                Ok(GateAction::Continue)
            }
            GateStage::ConfirmPassphrase => {
                if self.first.as_bytes() != self.current.as_bytes() {
                    self.clear_secrets();
                    self.stage = GateStage::SetPassphrase;
                    self.error = Some("Passphrases do not match.".into());
                    return Ok(GateAction::Continue);
                }
                match repository.create(self.current.as_bytes()) {
                    Ok(vault) => Ok(GateAction::Unlocked(vault)),
                    Err(VaultError::PlaintextPresent) => self.begin_recovery(repository),
                    Err(error) => Err(error),
                }
            }
            GateStage::RecoveryPassphrase => self.submit_existing_recovery(repository),
            GateStage::RecoverySetPassphrase => {
                self.first.zeroize();
                std::mem::swap(&mut self.first, &mut self.current);
                self.current.clear();
                self.stage = GateStage::RecoveryConfirmPassphrase;
                self.error = None;
                Ok(GateAction::Continue)
            }
            GateStage::RecoveryConfirmPassphrase => {
                if self.first.as_bytes() != self.current.as_bytes() {
                    self.clear_secrets();
                    self.stage = GateStage::RecoverySetPassphrase;
                    self.error = Some("Passphrases do not match.".into());
                    return Ok(GateAction::Continue);
                }
                self.submit_initial_recovery(repository)
            }
            GateStage::RecoveryChoice | GateStage::RecoveryDiscardConfirmation => {
                Ok(GateAction::Continue)
            }
        }
    }

    fn begin_recovery(&mut self, repository: &VaultRepository) -> Result<GateAction, VaultError> {
        self.clear_secrets();
        self.recovery_encrypted_vault = repository.exists()?;
        self.recovery_selection = RecoverySelection::Recover;
        self.stage = GateStage::RecoveryChoice;
        self.error = Some(if self.recovery_encrypted_vault {
            "Plaintext recovery data exists beside the encrypted vault.".into()
        } else {
            "Plaintext recovery data exists from an interrupted initial vault.".into()
        });
        Ok(GateAction::Continue)
    }

    fn submit_existing_recovery(
        &mut self,
        repository: &VaultRepository,
    ) -> Result<GateAction, VaultError> {
        let result = match self.recovery_selection {
            RecoverySelection::Recover => {
                repository.recover_existing_plaintext(self.current.as_bytes())
            }
            RecoverySelection::Discard => {
                repository.discard_plaintext_and_unlock(self.current.as_bytes())
            }
        };
        self.finish_recovery_attempt(result)
    }

    fn submit_initial_recovery(
        &mut self,
        repository: &VaultRepository,
    ) -> Result<GateAction, VaultError> {
        let result = match self.recovery_selection {
            RecoverySelection::Recover => {
                repository.adopt_initial_plaintext(self.current.as_bytes())
            }
            RecoverySelection::Discard => {
                repository.discard_plaintext_and_create(self.current.as_bytes())
            }
        };
        self.finish_recovery_attempt(result)
    }

    fn finish_recovery_attempt(
        &mut self,
        result: Result<UnlockedVault, VaultError>,
    ) -> Result<GateAction, VaultError> {
        match result {
            Ok(vault) => Ok(GateAction::Unlocked(vault)),
            Err(error) => {
                self.clear_secrets();
                self.stage = if self.recovery_encrypted_vault {
                    GateStage::RecoveryPassphrase
                } else {
                    GateStage::RecoverySetPassphrase
                };
                self.error = Some(error.to_string());
                Ok(GateAction::Continue)
            }
        }
    }

    fn clear_secrets(&mut self) {
        self.first.zeroize();
        self.first.clear();
        self.current.zeroize();
        self.current.clear();
    }
}

impl Drop for GateState {
    fn drop(&mut self) {
        self.clear_secrets();
    }
}

enum GateAction {
    Continue,
    Quit,
    Unlocked(UnlockedVault),
}

fn is_key_action(key: &KeyEvent) -> bool {
    matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat)
}

fn draw(terminal: &mut TerminalSession, gate: &GateState) -> io::Result<()> {
    terminal.terminal_mut().draw(|frame| render(frame, gate))?;
    Ok(())
}

fn render(frame: &mut Frame<'_>, gate: &GateState) {
    let area = frame.area();
    let recovery_choice = gate.stage == GateStage::RecoveryChoice;
    let recovery_confirmation = gate.stage == GateStage::RecoveryDiscardConfirmation;
    let panel_height = if recovery_choice || recovery_confirmation {
        17
    } else {
        11
    };
    let panel = centered_rect(72, panel_height, area);
    frame.render_widget(
        Block::default().style(Style::default().bg(Color::Black)),
        area,
    );

    let prompt = match gate.stage {
        GateStage::Unlock => "Unlock vault",
        GateStage::SetPassphrase => "Set vault passphrase",
        GateStage::ConfirmPassphrase => "Confirm vault passphrase",
        GateStage::RecoveryChoice => "Vault recovery required",
        GateStage::RecoveryDiscardConfirmation => "Confirm destructive recovery",
        GateStage::RecoveryPassphrase => "Enter the existing vault passphrase",
        GateStage::RecoverySetPassphrase => "Set a new vault passphrase",
        GateStage::RecoveryConfirmPassphrase => "Confirm the new vault passphrase",
    };
    let mask_len = gate.current.chars().count().min(MAX_VISIBLE_MASK);
    let prefix = if gate.current.chars().count() > MAX_VISIBLE_MASK {
        "..."
    } else {
        ""
    };
    let masked = format!("{prefix}{}", "*".repeat(mask_len));
    let error = gate.error.as_deref().unwrap_or("");
    let mut body = vec![
        Line::from(Span::styled(
            "TermComm-I2P",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(prompt),
    ];
    if recovery_choice {
        let recover_style = if gate.recovery_selection == RecoverySelection::Recover {
            Style::default().fg(Color::Black).bg(Color::Cyan)
        } else {
            Style::default().fg(Color::White)
        };
        let discard_style = if gate.recovery_selection == RecoverySelection::Discard {
            Style::default().fg(Color::Black).bg(Color::Red)
        } else {
            Style::default().fg(Color::White)
        };
        let (recover_label, recover_description, discard_label, discard_description) =
            if gate.recovery_encrypted_vault {
                (
                    " Recover newest session data (Recommended) ",
                    "Keeps changes from the interrupted session.",
                    " Roll back to last encrypted vault ",
                    "Discards changes from the interrupted session.",
                )
            } else {
                (
                    " Recover existing data (Recommended) ",
                    "Keeps the data created before the interruption.",
                    " Discard data and create an empty vault ",
                    "Permanently deletes the interrupted vault data.",
                )
            };
        body.extend([
            Line::from(""),
            Line::from("The previous session ended before working data could be encrypted."),
            Line::from(""),
            Line::from(Span::styled(recover_label, recover_style)),
            Line::from(Span::styled(
                recover_description,
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(discard_label, discard_style)),
            Line::from(Span::styled(
                discard_description,
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
            Line::from("Up/Down selects  Enter continues  Esc quits"),
        ]);
    } else if recovery_confirmation {
        body.extend([
            Line::from(""),
            Line::from(if gate.recovery_encrypted_vault {
                "Roll back to the last encrypted vault?"
            } else {
                "Discard the interrupted vault data and start over?"
            }),
            Line::from(if gate.recovery_encrypted_vault {
                "All changes from the interrupted session will be permanently lost."
            } else {
                "All existing local data will be permanently lost."
            }),
            Line::from(""),
            Line::from(Span::styled(
                "y confirms  n/Esc cancels",
                Style::default().fg(Color::Red),
            )),
        ]);
    } else {
        body.extend([
            Line::from(""),
            Line::from(Span::styled(masked, Style::default().fg(Color::Green))),
        ]);
    }
    body.extend([
        Line::from(""),
        Line::from(Span::styled(error, Style::default().fg(Color::Red))),
    ]);
    let widget = Paragraph::new(body)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: false })
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(widget, panel);
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width.saturating_sub(2)).max(1);
    let height = height.min(area.height.saturating_sub(2)).max(1);
    let vertical = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(height),
        Constraint::Fill(1),
    ])
    .split(area);
    Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(width),
        Constraint::Fill(1),
    ])
    .split(vertical[1])[1]
}
