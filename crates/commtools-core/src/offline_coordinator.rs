use crate::deaddrop::{GetResult, PutResult, PutStatus};
use crate::offline::{
    OfflineContext, OfflineError, OfflinePollObservation, OfflinePollResult, OfflinePollTarget,
    OfflineSendTarget, OfflineState,
};
use crate::one_to_one::{ConnectionId, OneToOneError, OneToOneSession};
use crate::protocol::{Frame, MessageType};
use crate::storage::{PersistedOfflineState, StorageError};
use std::collections::VecDeque;
use std::fmt;
use thiserror::Error;

pub const OFFLINE_POLL_INTERVAL_MS: u64 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineCoordinatorMode {
    Standby,
    Offline,
    Closing,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OfflineOperationId(u64);

impl OfflineOperationId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for OfflineOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum OfflineCoordinatorAction {
    Put {
        operation_id: OfflineOperationId,
        target: OfflineSendTarget,
    },
    Get {
        operation_id: OfflineOperationId,
        target: OfflinePollTarget,
    },
    SendIndexSync {
        connection_id: ConnectionId,
        frame: Frame,
    },
    PersistState {
        mutation_id: u64,
        state: PersistedOfflineState,
    },
    ShutdownDeaddrop,
}

impl fmt::Debug for OfflineCoordinatorAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Put {
                operation_id,
                target,
            } => formatter
                .debug_struct("Put")
                .field("operation_id", operation_id)
                .field("index", &target.index)
                .field("key", &"<redacted>")
                .field("blob", &"<redacted>")
                .field("blob_len", &target.blob.len())
                .finish(),
            Self::Get {
                operation_id,
                target,
            } => formatter
                .debug_struct("Get")
                .field("operation_id", operation_id)
                .field("index", &target.index)
                .field("kind", &target.kind)
                .field("key", &"<redacted>")
                .finish(),
            Self::SendIndexSync {
                connection_id,
                frame,
            } => formatter
                .debug_struct("SendIndexSync")
                .field("connection_id", connection_id)
                .field("message_id", &frame.message_id)
                .field("payload", &"<redacted>")
                .field("payload_len", &frame.payload.len())
                .finish(),
            Self::PersistState { mutation_id, state } => formatter
                .debug_struct("PersistState")
                .field("mutation_id", mutation_id)
                .field("state", state)
                .finish(),
            Self::ShutdownDeaddrop => formatter.write_str("ShutdownDeaddrop"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfflineCoordinatorEvent {
    ModeChanged(OfflineCoordinatorMode),
    SendStarted {
        operation_id: OfflineOperationId,
        message_id: u64,
        index: u64,
    },
    SendConfirmed {
        message_id: u64,
        index: u64,
        status: PutStatus,
        successful_servers: Vec<String>,
    },
    SendFailed {
        message_id: u64,
        index: u64,
        reason: String,
    },
    FrameReceived {
        index: u64,
        server: String,
        blob_hash: String,
        frame: Frame,
    },
    BlobRejected {
        index: u64,
        server: String,
        reason: String,
    },
    PollTargetFailed {
        index: u64,
        reason: String,
    },
    PollSweepStarted {
        started_ms: u64,
    },
    PollSweepCompleted {
        started_ms: u64,
        completed_ms: u64,
        observations: Vec<OfflinePollObservation>,
    },
    IndexSyncSent {
        connection_id: ConnectionId,
    },
    IndexSyncSendFailed {
        connection_id: ConnectionId,
        reason: String,
    },
    IndexSyncApplied {
        remote_next_send: u64,
        remote_receive_base: u64,
        local_next_send: u64,
        known_remote_next_send: u64,
    },
    ShutdownComplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OfflineCoordinatorOutput {
    pub actions: Vec<OfflineCoordinatorAction>,
    pub events: Vec<OfflineCoordinatorEvent>,
}

#[derive(Clone)]
struct PendingPut {
    operation_id: OfflineOperationId,
    target: OfflineSendTarget,
    message_id: u64,
}

#[derive(Clone)]
struct PendingPoll {
    started_ms: u64,
    queued: VecDeque<OfflinePollTarget>,
    current: Option<(OfflineOperationId, OfflinePollTarget)>,
    observations: Vec<OfflinePollObservation>,
}

pub struct OfflineCoordinator {
    context: OfflineContext,
    state: OfflineState,
    mode: OfflineCoordinatorMode,
    pending_put: Option<PendingPut>,
    pending_poll: Option<PendingPoll>,
    last_poll_completed_ms: Option<u64>,
    pending_index_sync: Option<ConnectionId>,
    synced_connection: Option<ConnectionId>,
    next_operation_id: u64,
    next_mutation_id: u64,
}

impl OfflineCoordinator {
    pub fn new(
        shared_secret: [u8; 32],
        my_b32: &str,
        peer_b32: &str,
        state: OfflineState,
    ) -> Result<Self, OfflineCoordinatorError> {
        Ok(Self {
            context: OfflineContext::new(shared_secret, my_b32, peer_b32)?,
            state,
            mode: OfflineCoordinatorMode::Standby,
            pending_put: None,
            pending_poll: None,
            last_poll_completed_ms: None,
            pending_index_sync: None,
            synced_connection: None,
            next_operation_id: 1,
            next_mutation_id: 1,
        })
    }

    pub fn from_persisted(
        my_b32: &str,
        peer_b32: &str,
        persisted: &PersistedOfflineState,
    ) -> Result<Self, OfflineCoordinatorError> {
        Self::new(
            *persisted.shared_secret.expose_secret(),
            my_b32,
            peer_b32,
            persisted.restore()?,
        )
    }

    pub fn mode(&self) -> OfflineCoordinatorMode {
        self.mode
    }

    pub fn context(&self) -> &OfflineContext {
        &self.context
    }

    pub fn state(&self) -> &OfflineState {
        &self.state
    }

    pub fn has_put_in_flight(&self) -> bool {
        self.pending_put.is_some()
    }

    pub fn has_poll_in_flight(&self) -> bool {
        self.pending_poll.is_some()
    }

    pub fn persisted_state(&self) -> Result<PersistedOfflineState, OfflineCoordinatorError> {
        Ok(PersistedOfflineState::new(
            self.context.shared_secret(),
            &self.state,
        )?)
    }

    pub fn enter_offline(&mut self) -> Result<OfflineCoordinatorOutput, OfflineCoordinatorError> {
        self.ensure_not_closed()?;
        if self.mode == OfflineCoordinatorMode::Offline {
            return Ok(OfflineCoordinatorOutput::default());
        }
        if self.mode == OfflineCoordinatorMode::Closing {
            return Err(OfflineCoordinatorError::Closing);
        }
        self.mode = OfflineCoordinatorMode::Offline;
        self.last_poll_completed_ms = None;
        Ok(OfflineCoordinatorOutput {
            actions: Vec::new(),
            events: vec![OfflineCoordinatorEvent::ModeChanged(self.mode)],
        })
    }

    pub fn leave_offline(&mut self) -> Result<OfflineCoordinatorOutput, OfflineCoordinatorError> {
        self.ensure_not_closed()?;
        if self.mode != OfflineCoordinatorMode::Offline {
            return Ok(OfflineCoordinatorOutput::default());
        }
        self.mode = OfflineCoordinatorMode::Standby;
        let poll_operation_in_flight = self
            .pending_poll
            .as_ref()
            .is_some_and(|poll| poll.current.is_some());
        if let Some(poll) = self.pending_poll.as_mut() {
            poll.queued.clear();
        }
        let discarded_idle_poll = self.pending_poll.is_some() && !poll_operation_in_flight;
        if discarded_idle_poll {
            self.pending_poll = None;
        }
        let mut output = OfflineCoordinatorOutput {
            actions: Vec::new(),
            events: vec![OfflineCoordinatorEvent::ModeChanged(self.mode)],
        };
        if discarded_idle_poll {
            self.push_persist_action(&mut output)?;
        }
        Ok(output)
    }

    pub fn begin_send(
        &mut self,
        frame: Frame,
    ) -> Result<OfflineCoordinatorOutput, OfflineCoordinatorError> {
        self.ensure_offline()?;
        if self.pending_put.is_some() {
            return Err(OfflineCoordinatorError::PutInProgress);
        }
        if frame.message_type != MessageType::U {
            return Err(OfflineCoordinatorError::UnsupportedOfflineFrame(
                frame.message_type,
            ));
        }

        let operation_id = self.allocate_operation_id()?;
        let message_id = frame.message_id;
        let target = self.state.prepare_send(&self.context, &frame)?;
        let index = target.index;
        self.pending_put = Some(PendingPut {
            operation_id,
            target: target.clone(),
            message_id,
        });
        Ok(OfflineCoordinatorOutput {
            actions: vec![OfflineCoordinatorAction::Put {
                operation_id,
                target,
            }],
            events: vec![OfflineCoordinatorEvent::SendStarted {
                operation_id,
                message_id,
                index,
            }],
        })
    }

    pub fn put_completed(
        &mut self,
        operation_id: OfflineOperationId,
        result: PutResult,
        now_ms: u64,
    ) -> Result<OfflineCoordinatorOutput, OfflineCoordinatorError> {
        let pending = self.take_pending_put(operation_id)?;
        let mut output = OfflineCoordinatorOutput::default();
        match result.status {
            PutStatus::Stored | PutStatus::Exists => {
                self.state.confirm_send(pending.target.index)?;
                output.events.push(OfflineCoordinatorEvent::SendConfirmed {
                    message_id: pending.message_id,
                    index: pending.target.index,
                    status: result.status,
                    successful_servers: result.successful_servers,
                });
                self.push_persist_action(&mut output)?;
            }
            PutStatus::Failed => output.events.push(OfflineCoordinatorEvent::SendFailed {
                message_id: pending.message_id,
                index: pending.target.index,
                reason: "all deaddrop replicas failed".to_string(),
            }),
        }
        self.resume_poll(now_ms, &mut output)?;
        Ok(output)
    }

    pub fn put_failed(
        &mut self,
        operation_id: OfflineOperationId,
        reason: impl Into<String>,
        now_ms: u64,
    ) -> Result<OfflineCoordinatorOutput, OfflineCoordinatorError> {
        let pending = self.take_pending_put(operation_id)?;
        let mut output = OfflineCoordinatorOutput {
            actions: Vec::new(),
            events: vec![OfflineCoordinatorEvent::SendFailed {
                message_id: pending.message_id,
                index: pending.target.index,
                reason: reason.into(),
            }],
        };
        self.resume_poll(now_ms, &mut output)?;
        Ok(output)
    }

    pub fn tick(
        &mut self,
        now_ms: u64,
    ) -> Result<OfflineCoordinatorOutput, OfflineCoordinatorError> {
        if self.mode != OfflineCoordinatorMode::Offline {
            return Ok(OfflineCoordinatorOutput::default());
        }
        if self.pending_poll.is_some() {
            let mut output = OfflineCoordinatorOutput::default();
            self.resume_poll(now_ms, &mut output)?;
            return Ok(output);
        }
        if self.pending_put.is_some()
            || self
                .last_poll_completed_ms
                .is_some_and(|last| now_ms.saturating_sub(last) < OFFLINE_POLL_INTERVAL_MS)
        {
            return Ok(OfflineCoordinatorOutput::default());
        }

        let targets = self.state.poll_targets(&self.context, now_ms);
        if targets.is_empty() {
            self.last_poll_completed_ms = Some(now_ms);
            return Ok(OfflineCoordinatorOutput::default());
        }
        self.pending_poll = Some(PendingPoll {
            started_ms: now_ms,
            queued: targets.into(),
            current: None,
            observations: Vec::new(),
        });
        let mut output = OfflineCoordinatorOutput {
            actions: Vec::new(),
            events: vec![OfflineCoordinatorEvent::PollSweepStarted { started_ms: now_ms }],
        };
        self.resume_poll(now_ms, &mut output)?;
        Ok(output)
    }

    pub fn get_completed(
        &mut self,
        operation_id: OfflineOperationId,
        result: GetResult,
        now_ms: u64,
    ) -> Result<OfflineCoordinatorOutput, OfflineCoordinatorError> {
        let target = self.take_current_poll_target(operation_id)?;
        let classified = self
            .state
            .classify_get_result(&self.context, &target, &result);
        let mut output = OfflineCoordinatorOutput::default();
        if classified.observation.outcome == crate::offline::OfflinePollOutcome::Authenticated {
            self.state.record_authenticated(target.index);
            self.push_persist_action(&mut output)?;
        }
        self.append_poll_result(&target, classified, &mut output)?;
        self.resume_or_finish_poll(now_ms, &mut output)?;
        Ok(output)
    }

    pub fn get_failed(
        &mut self,
        operation_id: OfflineOperationId,
        reason: impl Into<String>,
        now_ms: u64,
    ) -> Result<OfflineCoordinatorOutput, OfflineCoordinatorError> {
        let target = self.take_current_poll_target(operation_id)?;
        let reason = reason.into();
        let observation = OfflinePollObservation {
            index: target.index,
            kind: target.kind,
            outcome: crate::offline::OfflinePollOutcome::Indeterminate,
        };
        self.pending_poll_mut()?.observations.push(observation);
        let mut output = OfflineCoordinatorOutput {
            actions: Vec::new(),
            events: vec![OfflineCoordinatorEvent::PollTargetFailed {
                index: target.index,
                reason,
            }],
        };
        self.resume_or_finish_poll(now_ms, &mut output)?;
        Ok(output)
    }

    pub fn prepare_index_sync(
        &mut self,
        session: &OneToOneSession,
        message_id: u64,
    ) -> Result<OfflineCoordinatorOutput, OfflineCoordinatorError> {
        let connection_id = self.verify_live_session(session)?;
        if self.pending_index_sync == Some(connection_id)
            || self.synced_connection == Some(connection_id)
        {
            return Ok(OfflineCoordinatorOutput::default());
        }
        let frame = session.seal_application_frame(
            MessageType::I,
            message_id,
            &self.state.index_sync().encode(),
        )?;
        self.pending_index_sync = Some(connection_id);
        Ok(OfflineCoordinatorOutput {
            actions: vec![OfflineCoordinatorAction::SendIndexSync {
                connection_id,
                frame,
            }],
            events: Vec::new(),
        })
    }

    pub fn index_sync_sent(
        &mut self,
        connection_id: ConnectionId,
    ) -> Result<OfflineCoordinatorOutput, OfflineCoordinatorError> {
        self.take_pending_index_sync(connection_id)?;
        self.synced_connection = Some(connection_id);
        Ok(OfflineCoordinatorOutput {
            actions: Vec::new(),
            events: vec![OfflineCoordinatorEvent::IndexSyncSent { connection_id }],
        })
    }

    pub fn index_sync_send_failed(
        &mut self,
        connection_id: ConnectionId,
        reason: impl Into<String>,
    ) -> Result<OfflineCoordinatorOutput, OfflineCoordinatorError> {
        self.take_pending_index_sync(connection_id)?;
        Ok(OfflineCoordinatorOutput {
            actions: Vec::new(),
            events: vec![OfflineCoordinatorEvent::IndexSyncSendFailed {
                connection_id,
                reason: reason.into(),
            }],
        })
    }

    pub fn receive_index_sync(
        &mut self,
        session: &OneToOneSession,
        frame: &Frame,
    ) -> Result<OfflineCoordinatorOutput, OfflineCoordinatorError> {
        self.verify_live_session(session)?;
        if frame.message_type != MessageType::I {
            return Err(OfflineCoordinatorError::ExpectedIndexSyncFrame(
                frame.message_type,
            ));
        }
        let opened = session.open_application_frame(frame)?;
        let remote = crate::offline::OfflineIndexSync::decode(&opened.payload)?;
        let previous = self.state.snapshot();
        self.state.apply_remote_index_sync(remote);
        let mut output = OfflineCoordinatorOutput {
            actions: Vec::new(),
            events: vec![OfflineCoordinatorEvent::IndexSyncApplied {
                remote_next_send: remote.next_send,
                remote_receive_base: remote.receive_base,
                local_next_send: self.state.send_index(),
                known_remote_next_send: self.state.known_remote_next_send(),
            }],
        };
        if self.state.snapshot() != previous {
            self.push_persist_action(&mut output)?;
        }
        Ok(output)
    }

    pub fn live_connection_closed(&mut self, connection_id: ConnectionId) {
        if self.pending_index_sync == Some(connection_id) {
            self.pending_index_sync = None;
        }
        if self.synced_connection == Some(connection_id) {
            self.synced_connection = None;
        }
    }

    pub fn begin_shutdown(&mut self) -> OfflineCoordinatorOutput {
        if matches!(
            self.mode,
            OfflineCoordinatorMode::Closing | OfflineCoordinatorMode::Closed
        ) {
            return OfflineCoordinatorOutput::default();
        }
        self.mode = OfflineCoordinatorMode::Closing;
        self.pending_put = None;
        self.pending_poll = None;
        self.pending_index_sync = None;
        self.synced_connection = None;
        OfflineCoordinatorOutput {
            actions: vec![OfflineCoordinatorAction::ShutdownDeaddrop],
            events: vec![OfflineCoordinatorEvent::ModeChanged(self.mode)],
        }
    }

    pub fn shutdown_completed(
        &mut self,
    ) -> Result<OfflineCoordinatorOutput, OfflineCoordinatorError> {
        if self.mode != OfflineCoordinatorMode::Closing {
            return Err(OfflineCoordinatorError::NotClosing);
        }
        self.mode = OfflineCoordinatorMode::Closed;
        Ok(OfflineCoordinatorOutput {
            actions: Vec::new(),
            events: vec![
                OfflineCoordinatorEvent::ModeChanged(self.mode),
                OfflineCoordinatorEvent::ShutdownComplete,
            ],
        })
    }

    fn append_poll_result(
        &mut self,
        target: &OfflinePollTarget,
        result: OfflinePollResult,
        output: &mut OfflineCoordinatorOutput,
    ) -> Result<(), OfflineCoordinatorError> {
        self.pending_poll_mut()?
            .observations
            .push(result.observation);
        output
            .events
            .extend(result.frames.into_iter().map(|received| {
                OfflineCoordinatorEvent::FrameReceived {
                    index: target.index,
                    server: received.server,
                    blob_hash: received.blob_hash,
                    frame: received.frame,
                }
            }));
        output
            .events
            .extend(result.rejected_blobs.into_iter().map(|rejected| {
                OfflineCoordinatorEvent::BlobRejected {
                    index: target.index,
                    server: rejected.server,
                    reason: rejected.reason,
                }
            }));
        Ok(())
    }

    fn resume_or_finish_poll(
        &mut self,
        now_ms: u64,
        output: &mut OfflineCoordinatorOutput,
    ) -> Result<(), OfflineCoordinatorError> {
        if self
            .pending_poll
            .as_ref()
            .is_some_and(|poll| poll.queued.is_empty())
        {
            self.finish_poll(now_ms, output)
        } else {
            self.resume_poll(now_ms, output)
        }
    }

    fn resume_poll(
        &mut self,
        _now_ms: u64,
        output: &mut OfflineCoordinatorOutput,
    ) -> Result<(), OfflineCoordinatorError> {
        if self.mode != OfflineCoordinatorMode::Offline || self.pending_put.is_some() {
            return Ok(());
        }
        let should_schedule = self
            .pending_poll
            .as_ref()
            .is_some_and(|poll| poll.current.is_none() && !poll.queued.is_empty());
        if !should_schedule {
            return Ok(());
        }
        let operation_id = self.allocate_operation_id()?;
        let target = self
            .pending_poll_mut()?
            .queued
            .pop_front()
            .ok_or(OfflineCoordinatorError::InvalidPollState)?;
        self.pending_poll_mut()?.current = Some((operation_id, target.clone()));
        output.actions.push(OfflineCoordinatorAction::Get {
            operation_id,
            target,
        });
        Ok(())
    }

    fn finish_poll(
        &mut self,
        now_ms: u64,
        output: &mut OfflineCoordinatorOutput,
    ) -> Result<(), OfflineCoordinatorError> {
        let pending = self
            .pending_poll
            .take()
            .ok_or(OfflineCoordinatorError::NoPollInProgress)?;
        if pending.current.is_some() || !pending.queued.is_empty() {
            self.pending_poll = Some(pending);
            return Err(OfflineCoordinatorError::InvalidPollState);
        }
        self.state
            .finalize_poll_sweep(now_ms, &pending.observations);
        self.last_poll_completed_ms = Some(now_ms);
        output
            .events
            .push(OfflineCoordinatorEvent::PollSweepCompleted {
                started_ms: pending.started_ms,
                completed_ms: now_ms,
                observations: pending.observations,
            });
        self.push_persist_action(output)
    }

    fn take_pending_put(
        &mut self,
        operation_id: OfflineOperationId,
    ) -> Result<PendingPut, OfflineCoordinatorError> {
        let pending = self
            .pending_put
            .take()
            .ok_or(OfflineCoordinatorError::NoPutInProgress)?;
        if pending.operation_id != operation_id {
            let expected = pending.operation_id;
            self.pending_put = Some(pending);
            return Err(OfflineCoordinatorError::UnexpectedOperation {
                expected,
                actual: operation_id,
            });
        }
        Ok(pending)
    }

    fn take_current_poll_target(
        &mut self,
        operation_id: OfflineOperationId,
    ) -> Result<OfflinePollTarget, OfflineCoordinatorError> {
        let poll = self.pending_poll_mut()?;
        let (expected, target) = poll
            .current
            .take()
            .ok_or(OfflineCoordinatorError::NoPollOperationInProgress)?;
        if expected != operation_id {
            poll.current = Some((expected, target));
            return Err(OfflineCoordinatorError::UnexpectedOperation {
                expected,
                actual: operation_id,
            });
        }
        Ok(target)
    }

    fn take_pending_index_sync(
        &mut self,
        connection_id: ConnectionId,
    ) -> Result<(), OfflineCoordinatorError> {
        let expected = self
            .pending_index_sync
            .take()
            .ok_or(OfflineCoordinatorError::NoIndexSyncInProgress)?;
        if expected != connection_id {
            self.pending_index_sync = Some(expected);
            return Err(OfflineCoordinatorError::UnexpectedIndexSyncConnection {
                expected,
                actual: connection_id,
            });
        }
        Ok(())
    }

    fn verify_live_session(
        &self,
        session: &OneToOneSession,
    ) -> Result<ConnectionId, OfflineCoordinatorError> {
        if !session.is_ready() {
            return Err(OfflineCoordinatorError::LiveSessionNotReady);
        }
        let expected_local = self.context.my_b32();
        let expected_peer = self.context.peer_b32();
        let pinned = session
            .config()
            .pinned_peer()
            .ok_or(OfflineCoordinatorError::PersistentPeerRequired)?;
        if !session
            .config()
            .local_b32()
            .eq_ignore_ascii_case(&expected_local)
            || !pinned.b32().eq_ignore_ascii_case(&expected_peer)
            || !session
                .active_peer_b32()
                .is_some_and(|peer| peer.eq_ignore_ascii_case(&expected_peer))
        {
            return Err(OfflineCoordinatorError::LiveSessionIdentityMismatch);
        }
        session
            .active_connection_id()
            .ok_or(OfflineCoordinatorError::LiveSessionNotReady)
    }

    fn pending_poll_mut(&mut self) -> Result<&mut PendingPoll, OfflineCoordinatorError> {
        self.pending_poll
            .as_mut()
            .ok_or(OfflineCoordinatorError::NoPollInProgress)
    }

    fn push_persist_action(
        &mut self,
        output: &mut OfflineCoordinatorOutput,
    ) -> Result<(), OfflineCoordinatorError> {
        let mutation_id = self.next_mutation_id;
        self.next_mutation_id = self
            .next_mutation_id
            .checked_add(1)
            .ok_or(OfflineCoordinatorError::MutationIdExhausted)?;
        output.actions.push(OfflineCoordinatorAction::PersistState {
            mutation_id,
            state: self.persisted_state()?,
        });
        Ok(())
    }

    fn allocate_operation_id(&mut self) -> Result<OfflineOperationId, OfflineCoordinatorError> {
        let operation_id = OfflineOperationId::new(self.next_operation_id);
        self.next_operation_id = self
            .next_operation_id
            .checked_add(1)
            .ok_or(OfflineCoordinatorError::OperationIdExhausted)?;
        Ok(operation_id)
    }

    fn ensure_offline(&self) -> Result<(), OfflineCoordinatorError> {
        self.ensure_not_closed()?;
        if self.mode != OfflineCoordinatorMode::Offline {
            return Err(OfflineCoordinatorError::OfflineModeRequired);
        }
        Ok(())
    }

    fn ensure_not_closed(&self) -> Result<(), OfflineCoordinatorError> {
        match self.mode {
            OfflineCoordinatorMode::Closing => Err(OfflineCoordinatorError::Closing),
            OfflineCoordinatorMode::Closed => Err(OfflineCoordinatorError::Closed),
            OfflineCoordinatorMode::Standby | OfflineCoordinatorMode::Offline => Ok(()),
        }
    }
}

impl fmt::Debug for OfflineCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfflineCoordinator")
            .field("context", &self.context)
            .field("state", &self.state)
            .field("mode", &self.mode)
            .field("put_in_flight", &self.pending_put.is_some())
            .field("poll_in_flight", &self.pending_poll.is_some())
            .field("pending_index_sync", &self.pending_index_sync)
            .field("synced_connection", &self.synced_connection)
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum OfflineCoordinatorError {
    #[error(transparent)]
    Offline(#[from] OfflineError),
    #[error(transparent)]
    Session(#[from] OneToOneError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("offline coordinator is closing")]
    Closing,
    #[error("offline coordinator is closed")]
    Closed,
    #[error("offline mode is required")]
    OfflineModeRequired,
    #[error("an offline PUT is already in progress")]
    PutInProgress,
    #[error("no offline PUT is in progress")]
    NoPutInProgress,
    #[error("no offline poll sweep is in progress")]
    NoPollInProgress,
    #[error("no offline poll operation is in progress")]
    NoPollOperationInProgress,
    #[error("offline poll scheduler entered an invalid state")]
    InvalidPollState,
    #[error("unexpected offline operation: expected {expected}, got {actual}")]
    UnexpectedOperation {
        expected: OfflineOperationId,
        actual: OfflineOperationId,
    },
    #[error("offline frame type {0:?} is not supported")]
    UnsupportedOfflineFrame(MessageType),
    #[error("a verified persistent live session is required")]
    PersistentPeerRequired,
    #[error("live 1:1 session is not ready")]
    LiveSessionNotReady,
    #[error("live 1:1 session identities do not match the offline contact")]
    LiveSessionIdentityMismatch,
    #[error("expected an encrypted I frame, got {0:?}")]
    ExpectedIndexSyncFrame(MessageType),
    #[error("no offline index synchronization is in progress")]
    NoIndexSyncInProgress,
    #[error("unexpected index-sync connection: expected {expected}, got {actual}")]
    UnexpectedIndexSyncConnection {
        expected: ConnectionId,
        actual: ConnectionId,
    },
    #[error("offline operation identifier counter is exhausted")]
    OperationIdExhausted,
    #[error("offline mutation identifier counter is exhausted")]
    MutationIdExhausted,
    #[error("offline coordinator is not closing")]
    NotClosing,
}
