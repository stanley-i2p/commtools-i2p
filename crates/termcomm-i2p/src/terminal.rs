use crossterm::clipboard::CopyToClipboard;
use crossterm::cursor::{Hide, Show};
use crossterm::event::{DisableBracketedPaste, EnableBracketedPaste};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use std::io::{self, Stdout};

pub type AppTerminal = Terminal<CrosstermBackend<Stdout>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardCopyMethod {
    System,
    TerminalOsc52,
}

pub struct TerminalSession {
    terminal: AppTerminal,
    system_clipboard: Option<arboard::Clipboard>,
    restored: bool,
}

impl TerminalSession {
    pub fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen, EnableBracketedPaste, Hide) {
            let _ = disable_raw_mode();
            return Err(error);
        }
        let terminal = match Terminal::new(CrosstermBackend::new(stdout)) {
            Ok(terminal) => terminal,
            Err(error) => {
                let mut stdout = io::stdout();
                let _ = execute!(stdout, Show, DisableBracketedPaste, LeaveAlternateScreen);
                let _ = disable_raw_mode();
                return Err(error);
            }
        };
        Ok(Self {
            terminal,
            system_clipboard: None,
            restored: false,
        })
    }

    pub fn terminal_mut(&mut self) -> &mut AppTerminal {
        &mut self.terminal
    }

    pub fn copy_to_clipboard(&mut self, content: &str) -> io::Result<ClipboardCopyMethod> {
        if self.system_clipboard.is_none() {
            self.system_clipboard = arboard::Clipboard::new().ok();
        }
        if let Some(clipboard) = self.system_clipboard.as_mut() {
            if set_system_clipboard_text(clipboard, content).is_ok() {
                return Ok(ClipboardCopyMethod::System);
            }
            self.system_clipboard = None;
        }

        execute!(
            self.terminal.backend_mut(),
            CopyToClipboard::to_clipboard_from(content)
        )?;
        Ok(ClipboardCopyMethod::TerminalOsc52)
    }

    pub fn restore(&mut self) -> io::Result<()> {
        if self.restored {
            return Ok(());
        }
        self.restored = true;
        let screen_result = execute!(
            self.terminal.backend_mut(),
            Show,
            DisableBracketedPaste,
            LeaveAlternateScreen
        );
        let raw_result = disable_raw_mode();
        screen_result.and(raw_result)
    }
}

#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
))]
fn set_system_clipboard_text(
    clipboard: &mut arboard::Clipboard,
    content: &str,
) -> Result<(), arboard::Error> {
    use arboard::SetExtLinux;

    clipboard
        .set()
        .exclude_from_history()
        .text(content.to_owned())
}

#[cfg(not(all(
    unix,
    not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
)))]
fn set_system_clipboard_text(
    clipboard: &mut arboard::Clipboard,
    content: &str,
) -> Result<(), arboard::Error> {
    clipboard.set_text(content.to_owned())
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}
