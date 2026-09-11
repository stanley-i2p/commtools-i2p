use crate::ids::SessionId;

/// Frontend-to-core lifecycle commands available before session engines exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreCommand {
    Shutdown,
}

/// Core lifecycle events. Session-specific events will be added with their
/// corresponding state machines instead of being represented prematurely.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreEvent {
    Started,
    Stopping,
    Stopped,
    LogLine {
        session_id: Option<SessionId>,
        line: String,
    },
}
