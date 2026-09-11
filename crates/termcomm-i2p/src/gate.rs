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
}

impl GateState {
    fn new(stage: GateStage) -> Self {
        Self {
            stage,
            first: String::new(),
            current: String::new(),
            error: None,
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
        match key.code {
            KeyCode::Char(character) => self.push(character),
            KeyCode::Backspace => {
                self.current.pop();
                self.error = None;
            }
            KeyCode::Enter => return self.submit(repository),
            KeyCode::Esc if self.stage == GateStage::ConfirmPassphrase => {
                self.clear_secrets();
                self.stage = GateStage::SetPassphrase;
                self.error = None;
            }
            KeyCode::Esc => return Ok(GateAction::Quit),
            _ => {}
        }
        Ok(GateAction::Continue)
    }

    fn paste(&mut self, value: &str) {
        for character in value.chars().filter(|character| !character.is_control()) {
            self.push(character);
        }
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
                repository
                    .create(self.current.as_bytes())
                    .map(GateAction::Unlocked)
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
    let panel = centered_rect(62, 11, area);
    frame.render_widget(
        Block::default().style(Style::default().bg(Color::Black)),
        area,
    );

    let prompt = match gate.stage {
        GateStage::Unlock => "Unlock vault",
        GateStage::SetPassphrase => "Set vault passphrase",
        GateStage::ConfirmPassphrase => "Confirm vault passphrase",
    };
    let mask_len = gate.current.chars().count().min(MAX_VISIBLE_MASK);
    let prefix = if gate.current.chars().count() > MAX_VISIBLE_MASK {
        "..."
    } else {
        ""
    };
    let masked = format!("{prefix}{}", "*".repeat(mask_len));
    let error = gate.error.as_deref().unwrap_or("");
    let body = vec![
        Line::from(Span::styled(
            "TermComm-I2P",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(prompt),
        Line::from(""),
        Line::from(Span::styled(masked, Style::default().fg(Color::Green))),
        Line::from(""),
        Line::from(Span::styled(error, Style::default().fg(Color::Red))),
    ];
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
