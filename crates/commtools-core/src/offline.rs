use crate::crypto::{CryptoError, derive_offline_blob_key, open_offline_blob, seal_offline_blob};
use crate::deaddrop::{GetReplicaStatus, GetResult, MAX_DEADDROP_BLOB_SIZE};
use crate::protocol::{Frame, ProtocolError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use thiserror::Error;

pub const DEFAULT_OFFLINE_WINDOW: u32 = 8;
pub const MAX_OFFLINE_WINDOW: u32 = 256;
pub const OFFLINE_INDEX_SYNC_VERSION: u8 = 1;
pub const OFFLINE_INDEX_SYNC_PAYLOAD_SIZE: usize = 17;
pub const OFFLINE_GAP_MISS_ROUNDS: u32 = 3;
pub const OFFLINE_FORWARD_PROBE_STALL_ROUNDS: u32 = 3;
pub const OFFLINE_RECOVERY_STATE_LIMIT: usize = 512;
pub const OFFLINE_SKIPPED_RETENTION_MS: u64 = 14 * 24 * 60 * 60 * 1_000;
pub const OFFLINE_RECOVERY_PROBE_INTERVAL_MS: u64 = 60_000;
pub const OFFLINE_SEEN_BLOB_LIMIT: usize = 2_048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineDirection {
    Send,
    Receive,
}

#[derive(Clone, PartialEq, Eq)]
pub struct OfflineContext {
    shared_secret: [u8; 32],
    my_identity: String,
    peer_identity: String,
}

impl OfflineContext {
    pub fn new(
        shared_secret: [u8; 32],
        my_b32: &str,
        peer_b32: &str,
    ) -> Result<Self, OfflineError> {
        if shared_secret.iter().all(|byte| *byte == 0) {
            return Err(OfflineError::InvalidSharedSecret);
        }
        let my_identity = normalize_b32(my_b32)?;
        let peer_identity = normalize_b32(peer_b32)?;
        if my_identity == peer_identity {
            return Err(OfflineError::IdenticalIdentities);
        }
        Ok(Self {
            shared_secret,
            my_identity,
            peer_identity,
        })
    }

    pub fn my_b32(&self) -> String {
        format!("{}.b32.i2p", self.my_identity)
    }

    pub fn peer_b32(&self) -> String {
        format!("{}.b32.i2p", self.peer_identity)
    }

    pub(crate) fn shared_secret(&self) -> [u8; 32] {
        self.shared_secret
    }

    pub fn directional_key(&self, direction: OfflineDirection, index: u64) -> String {
        let (low, high) = if self.my_identity <= self.peer_identity {
            (self.my_identity.as_str(), self.peer_identity.as_str())
        } else {
            (self.peer_identity.as_str(), self.my_identity.as_str())
        };
        let label = match (self.my_identity.as_str() == low, direction) {
            (true, OfflineDirection::Send) | (false, OfflineDirection::Receive) => "LOW_TO_HIGH",
            (true, OfflineDirection::Receive) | (false, OfflineDirection::Send) => "HIGH_TO_LOW",
        };

        let mut material = Vec::with_capacity(
            self.shared_secret.len() + low.len() + high.len() + label.len() + 32,
        );
        material.extend_from_slice(&self.shared_secret);
        material.push(b'|');
        material.extend_from_slice(low.as_bytes());
        material.push(b'|');
        material.extend_from_slice(high.as_bytes());
        material.push(b'|');
        material.extend_from_slice(label.as_bytes());
        material.push(b'|');
        material.extend_from_slice(index.to_string().as_bytes());
        hex_lower(&Sha256::digest(material))
    }

    pub fn seal_frame(&self, frame: &Frame) -> Result<Vec<u8>, OfflineError> {
        let encoded = frame.encode()?;
        let key = self.blob_key();
        let blob = seal_offline_blob(&encoded, &key)?;
        if blob.len() > MAX_DEADDROP_BLOB_SIZE {
            return Err(OfflineError::BlobTooLarge(blob.len()));
        }
        Ok(blob)
    }

    pub fn open_frame(&self, blob: &[u8]) -> Result<Frame, OfflineError> {
        if blob.len() > MAX_DEADDROP_BLOB_SIZE {
            return Err(OfflineError::BlobTooLarge(blob.len()));
        }
        let key = self.blob_key();
        let encoded = open_offline_blob(blob, &key)?;
        Ok(Frame::decode(&encoded)?)
    }

    fn blob_key(&self) -> [u8; 32] {
        derive_offline_blob_key(&self.shared_secret, &self.my_identity, &self.peer_identity)
    }
}

impl fmt::Debug for OfflineContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfflineContext")
            .field("shared_secret", &"<redacted>")
            .field("my_b32", &self.my_b32())
            .field("peer_b32", &self.peer_b32())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfflineIndexSync {
    pub next_send: u64,
    pub receive_base: u64,
}

impl OfflineIndexSync {
    pub fn encode(self) -> [u8; OFFLINE_INDEX_SYNC_PAYLOAD_SIZE] {
        let mut payload = [0u8; OFFLINE_INDEX_SYNC_PAYLOAD_SIZE];
        payload[0] = OFFLINE_INDEX_SYNC_VERSION;
        payload[1..9].copy_from_slice(&self.next_send.to_be_bytes());
        payload[9..17].copy_from_slice(&self.receive_base.to_be_bytes());
        payload
    }

    pub fn decode(payload: &[u8]) -> Result<Self, OfflineError> {
        if payload.len() != OFFLINE_INDEX_SYNC_PAYLOAD_SIZE
            || payload[0] != OFFLINE_INDEX_SYNC_VERSION
        {
            return Err(OfflineError::InvalidIndexSync);
        }
        let next_send = u64::from_be_bytes(
            payload[1..9]
                .try_into()
                .map_err(|_| OfflineError::InvalidIndexSync)?,
        );
        let receive_base = u64::from_be_bytes(
            payload[9..17]
                .try_into()
                .map_err(|_| OfflineError::InvalidIndexSync)?,
        );
        Ok(Self {
            next_send,
            receive_base,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflinePollKind {
    Window,
    ForwardProbe,
    RecoveryProbe,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflinePollTarget {
    pub index: u64,
    pub key: String,
    pub kind: OfflinePollKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflinePollOutcome {
    Authenticated,
    ConfirmedMiss,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflinePollObservation {
    pub index: u64,
    pub kind: OfflinePollKind,
    pub outcome: OfflinePollOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineReceivedFrame {
    pub server: String,
    pub blob_hash: String,
    pub frame: Frame,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineRejectedBlob {
    pub server: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflinePollResult {
    pub observation: OfflinePollObservation,
    pub frames: Vec<OfflineReceivedFrame>,
    pub rejected_blobs: Vec<OfflineRejectedBlob>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineSendTarget {
    pub index: u64,
    pub key: String,
    pub blob: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineMissingIndex {
    pub index: u64,
    pub confirmed_miss_rounds: u32,
    pub first_miss_ms: u64,
    pub last_miss_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineSkippedIndex {
    pub index: u64,
    pub skipped_at_ms: u64,
    pub last_recovery_probe_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OfflineStateSnapshot {
    pub send_index: u64,
    pub send_exhausted: bool,
    pub receive_base: u64,
    pub receive_exhausted: bool,
    pub window: u32,
    pub consumed: Vec<u64>,
    pub known_remote_next_send: u64,
    pub highest_authenticated_receive: Option<u64>,
    pub missing: Vec<OfflineMissingIndexSnapshot>,
    pub skipped: Vec<OfflineSkippedIndexSnapshot>,
    pub forward_probe_index: u64,
    pub stalled_sweeps: u32,
    pub last_recovery_probe_ms: u64,
    pub seen_blob_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OfflineMissingIndexSnapshot {
    pub index: u64,
    pub confirmed_miss_rounds: u32,
    pub first_miss_ms: u64,
    pub last_miss_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OfflineSkippedIndexSnapshot {
    pub index: u64,
    pub skipped_at_ms: u64,
    pub last_recovery_probe_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineState {
    send_index: u64,
    send_exhausted: bool,
    receive_base: u64,
    receive_exhausted: bool,
    window: u32,
    consumed: BTreeSet<u64>,
    known_remote_next_send: u64,
    highest_authenticated_receive: Option<u64>,
    missing: BTreeMap<u64, OfflineMissingIndex>,
    skipped: BTreeMap<u64, OfflineSkippedIndex>,
    forward_probe_index: u64,
    stalled_sweeps: u32,
    last_recovery_probe_ms: u64,
    seen_blob_hashes: BTreeSet<String>,
    seen_blob_order: VecDeque<String>,
}

impl OfflineState {
    pub fn new(window: u32) -> Result<Self, OfflineError> {
        if !(1..=MAX_OFFLINE_WINDOW).contains(&window) {
            return Err(OfflineError::InvalidWindow(window));
        }
        Ok(Self {
            send_index: 0,
            send_exhausted: false,
            receive_base: 0,
            receive_exhausted: false,
            window,
            consumed: BTreeSet::new(),
            known_remote_next_send: 0,
            highest_authenticated_receive: None,
            missing: BTreeMap::new(),
            skipped: BTreeMap::new(),
            forward_probe_index: u64::from(window),
            stalled_sweeps: 0,
            last_recovery_probe_ms: 0,
            seen_blob_hashes: BTreeSet::new(),
            seen_blob_order: VecDeque::new(),
        })
    }

    pub fn send_index(&self) -> u64 {
        self.send_index
    }

    pub fn send_exhausted(&self) -> bool {
        self.send_exhausted
    }

    pub fn receive_base(&self) -> u64 {
        self.receive_base
    }

    pub fn receive_exhausted(&self) -> bool {
        self.receive_exhausted
    }

    pub fn window(&self) -> u32 {
        self.window
    }

    pub fn known_remote_next_send(&self) -> u64 {
        self.known_remote_next_send
    }

    pub fn highest_authenticated_receive(&self) -> Option<u64> {
        self.highest_authenticated_receive
    }

    pub fn missing(&self) -> impl Iterator<Item = &OfflineMissingIndex> {
        self.missing.values()
    }

    pub fn skipped(&self) -> impl Iterator<Item = &OfflineSkippedIndex> {
        self.skipped.values()
    }

    pub fn stalled_sweeps(&self) -> u32 {
        self.stalled_sweeps
    }

    pub fn index_sync(&self) -> OfflineIndexSync {
        OfflineIndexSync {
            next_send: self.send_index,
            receive_base: self.receive_base,
        }
    }

    pub fn snapshot(&self) -> OfflineStateSnapshot {
        OfflineStateSnapshot {
            send_index: self.send_index,
            send_exhausted: self.send_exhausted,
            receive_base: self.receive_base,
            receive_exhausted: self.receive_exhausted,
            window: self.window,
            consumed: self.consumed.iter().copied().collect(),
            known_remote_next_send: self.known_remote_next_send,
            highest_authenticated_receive: self.highest_authenticated_receive,
            missing: self
                .missing
                .values()
                .map(|entry| OfflineMissingIndexSnapshot {
                    index: entry.index,
                    confirmed_miss_rounds: entry.confirmed_miss_rounds,
                    first_miss_ms: entry.first_miss_ms,
                    last_miss_ms: entry.last_miss_ms,
                })
                .collect(),
            skipped: self
                .skipped
                .values()
                .map(|entry| OfflineSkippedIndexSnapshot {
                    index: entry.index,
                    skipped_at_ms: entry.skipped_at_ms,
                    last_recovery_probe_ms: entry.last_recovery_probe_ms,
                })
                .collect(),
            forward_probe_index: self.forward_probe_index,
            stalled_sweeps: self.stalled_sweeps,
            last_recovery_probe_ms: self.last_recovery_probe_ms,
            seen_blob_hashes: self.seen_blob_order.iter().cloned().collect(),
        }
    }

    pub fn from_snapshot(snapshot: OfflineStateSnapshot) -> Result<Self, OfflineError> {
        if !(1..=MAX_OFFLINE_WINDOW).contains(&snapshot.window) {
            return Err(OfflineError::InvalidWindow(snapshot.window));
        }
        if snapshot.consumed.len() > OFFLINE_RECOVERY_STATE_LIMIT
            || snapshot.missing.len() > OFFLINE_RECOVERY_STATE_LIMIT
            || snapshot.skipped.len() > OFFLINE_RECOVERY_STATE_LIMIT
            || snapshot.seen_blob_hashes.len() > OFFLINE_SEEN_BLOB_LIMIT
        {
            return Err(OfflineError::InvalidState("collection limit exceeded"));
        }
        if (snapshot.send_exhausted && snapshot.send_index != u64::MAX)
            || (snapshot.receive_exhausted && snapshot.receive_base != u64::MAX)
        {
            return Err(OfflineError::InvalidState("invalid exhausted-index state"));
        }

        let consumed_len = snapshot.consumed.len();
        let consumed = snapshot.consumed.into_iter().collect::<BTreeSet<_>>();
        if consumed.len() != consumed_len
            || consumed.len() > OFFLINE_RECOVERY_STATE_LIMIT
            || (!snapshot.receive_exhausted
                && consumed.iter().any(|index| *index < snapshot.receive_base))
        {
            return Err(OfflineError::InvalidState("invalid consumed indexes"));
        }

        let mut missing = BTreeMap::new();
        for entry in snapshot.missing {
            if entry.confirmed_miss_rounds == 0
                || entry.first_miss_ms > entry.last_miss_ms
                || missing
                    .insert(
                        entry.index,
                        OfflineMissingIndex {
                            index: entry.index,
                            confirmed_miss_rounds: entry.confirmed_miss_rounds,
                            first_miss_ms: entry.first_miss_ms,
                            last_miss_ms: entry.last_miss_ms,
                        },
                    )
                    .is_some()
            {
                return Err(OfflineError::InvalidState("invalid missing indexes"));
            }
        }

        let mut skipped = BTreeMap::new();
        for entry in snapshot.skipped {
            if missing.contains_key(&entry.index)
                || skipped
                    .insert(
                        entry.index,
                        OfflineSkippedIndex {
                            index: entry.index,
                            skipped_at_ms: entry.skipped_at_ms,
                            last_recovery_probe_ms: entry.last_recovery_probe_ms,
                        },
                    )
                    .is_some()
            {
                return Err(OfflineError::InvalidState("invalid skipped indexes"));
            }
        }
        if consumed
            .iter()
            .any(|index| missing.contains_key(index) || skipped.contains_key(index))
        {
            return Err(OfflineError::InvalidState(
                "offline index appears in conflicting states",
            ));
        }
        if snapshot
            .highest_authenticated_receive
            .is_some_and(|index| snapshot.known_remote_next_send < index.saturating_add(1))
        {
            return Err(OfflineError::InvalidState(
                "authenticated receive evidence is inconsistent",
            ));
        }

        let mut seen_blob_hashes = BTreeSet::new();
        let mut seen_blob_order = VecDeque::new();
        for hash in snapshot.seen_blob_hashes {
            if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(OfflineError::InvalidState("invalid seen-blob hashes"));
            }
            let hash = hash.to_ascii_lowercase();
            if !seen_blob_hashes.insert(hash.clone()) {
                return Err(OfflineError::InvalidState("invalid seen-blob hashes"));
            }
            seen_blob_order.push_back(hash);
        }

        Ok(Self {
            send_index: snapshot.send_index,
            send_exhausted: snapshot.send_exhausted,
            receive_base: snapshot.receive_base,
            receive_exhausted: snapshot.receive_exhausted,
            window: snapshot.window,
            consumed,
            known_remote_next_send: snapshot.known_remote_next_send,
            highest_authenticated_receive: snapshot.highest_authenticated_receive,
            missing,
            skipped,
            forward_probe_index: snapshot.forward_probe_index,
            stalled_sweeps: snapshot.stalled_sweeps,
            last_recovery_probe_ms: snapshot.last_recovery_probe_ms,
            seen_blob_hashes,
            seen_blob_order,
        })
    }

    pub fn apply_remote_index_sync(&mut self, remote: OfflineIndexSync) {
        if !self.send_exhausted {
            self.send_index = self.send_index.max(remote.receive_base);
        }
        self.known_remote_next_send = self.known_remote_next_send.max(remote.next_send);
    }

    pub fn prepare_send(
        &self,
        context: &OfflineContext,
        frame: &Frame,
    ) -> Result<OfflineSendTarget, OfflineError> {
        if self.send_exhausted {
            return Err(OfflineError::SendIndexExhausted);
        }
        Ok(OfflineSendTarget {
            index: self.send_index,
            key: context.directional_key(OfflineDirection::Send, self.send_index),
            blob: context.seal_frame(frame)?,
        })
    }

    pub fn confirm_send(&mut self, index: u64) -> Result<(), OfflineError> {
        if self.send_exhausted {
            return Err(OfflineError::SendIndexExhausted);
        }
        if index != self.send_index {
            return Err(OfflineError::UnexpectedSendIndex {
                expected: self.send_index,
                actual: index,
            });
        }
        if self.send_index == u64::MAX {
            self.send_exhausted = true;
        } else {
            self.send_index += 1;
        }
        Ok(())
    }

    pub fn poll_targets(
        &mut self,
        context: &OfflineContext,
        now_ms: u64,
    ) -> Vec<OfflinePollTarget> {
        let mut targets = Vec::new();
        let mut target_indexes = BTreeSet::new();

        if !self.receive_exhausted {
            for offset in 0..u64::from(self.window) {
                let Some(index) = self.receive_base.checked_add(offset) else {
                    break;
                };
                if self.consumed.contains(&index) {
                    continue;
                }
                target_indexes.insert(index);
                targets.push(OfflinePollTarget {
                    index,
                    key: context.directional_key(OfflineDirection::Receive, index),
                    kind: OfflinePollKind::Window,
                });
            }
        }

        if !self.receive_exhausted && self.stalled_sweeps >= OFFLINE_FORWARD_PROBE_STALL_ROUNDS {
            let window_end = self.receive_base.saturating_add(u64::from(self.window));
            let index = self.forward_probe_index.max(window_end);
            self.forward_probe_index = index.saturating_add(1);
            if target_indexes.insert(index) {
                targets.push(OfflinePollTarget {
                    index,
                    key: context.directional_key(OfflineDirection::Receive, index),
                    kind: OfflinePollKind::ForwardProbe,
                });
            }
        }

        if now_ms.saturating_sub(self.last_recovery_probe_ms) >= OFFLINE_RECOVERY_PROBE_INTERVAL_MS
        {
            if let Some(skipped) = self.skipped.values_mut().find(|entry| {
                now_ms.saturating_sub(entry.last_recovery_probe_ms)
                    >= OFFLINE_RECOVERY_PROBE_INTERVAL_MS
            }) {
                skipped.last_recovery_probe_ms = now_ms;
                self.last_recovery_probe_ms = now_ms;
                let index = skipped.index;
                if target_indexes.insert(index) {
                    targets.push(OfflinePollTarget {
                        index,
                        key: context.directional_key(OfflineDirection::Receive, index),
                        kind: OfflinePollKind::RecoveryProbe,
                    });
                }
            }
        }

        targets
    }

    pub fn classify_get_result(
        &mut self,
        context: &OfflineContext,
        target: &OfflinePollTarget,
        result: &GetResult,
    ) -> OfflinePollResult {
        let mut frames = Vec::new();
        let mut rejected_blobs = Vec::new();
        let mut authenticated = false;
        let mut had_hit = false;
        let mut confirmed_miss = false;
        let mut round_hashes = BTreeSet::new();

        for replica in &result.replicas {
            match replica.status {
                GetReplicaStatus::Hit => {
                    had_hit = true;
                    let Some(blob) = replica.blob.as_deref() else {
                        rejected_blobs.push(OfflineRejectedBlob {
                            server: replica.server.clone(),
                            reason: "hit response is missing its blob".to_string(),
                        });
                        continue;
                    };
                    let blob_hash = hex_lower(&Sha256::digest(blob));
                    if !round_hashes.insert(blob_hash.clone()) {
                        continue;
                    }
                    if self.seen_blob_hashes.contains(&blob_hash) {
                        continue;
                    }
                    match context.open_frame(blob) {
                        Ok(frame) => {
                            authenticated = true;
                            self.remember_blob(blob_hash.clone());
                            frames.push(OfflineReceivedFrame {
                                server: replica.server.clone(),
                                blob_hash,
                                frame,
                            });
                        }
                        Err(error) => rejected_blobs.push(OfflineRejectedBlob {
                            server: replica.server.clone(),
                            reason: error.to_string(),
                        }),
                    }
                }
                GetReplicaStatus::Miss => confirmed_miss = true,
                GetReplicaStatus::Rejected | GetReplicaStatus::Failed => {}
            }
        }

        let outcome = if authenticated {
            OfflinePollOutcome::Authenticated
        } else if !had_hit && confirmed_miss {
            OfflinePollOutcome::ConfirmedMiss
        } else {
            OfflinePollOutcome::Indeterminate
        };
        OfflinePollResult {
            observation: OfflinePollObservation {
                index: target.index,
                kind: target.kind,
                outcome,
            },
            frames,
            rejected_blobs,
        }
    }

    pub fn finalize_poll_sweep(&mut self, now_ms: u64, observations: &[OfflinePollObservation]) {
        let authenticated = observations
            .iter()
            .filter(|observation| observation.outcome == OfflinePollOutcome::Authenticated)
            .map(|observation| observation.index)
            .collect::<BTreeSet<_>>();

        for index in &authenticated {
            self.record_authenticated(*index);
        }

        for observation in observations {
            if observation.outcome != OfflinePollOutcome::ConfirmedMiss
                || observation.kind == OfflinePollKind::RecoveryProbe
                || authenticated.contains(&observation.index)
            {
                continue;
            }
            self.missing
                .entry(observation.index)
                .and_modify(|entry| {
                    entry.confirmed_miss_rounds = entry.confirmed_miss_rounds.saturating_add(1);
                    entry.last_miss_ms = now_ms;
                })
                .or_insert(OfflineMissingIndex {
                    index: observation.index,
                    confirmed_miss_rounds: 1,
                    first_miss_ms: now_ms,
                    last_miss_ms: now_ms,
                });
        }

        let skip_indexes = self
            .missing
            .values()
            .filter(|entry| {
                entry.confirmed_miss_rounds >= OFFLINE_GAP_MISS_ROUNDS
                    && entry.index >= self.receive_base
                    && entry.index < self.known_remote_next_send
            })
            .map(|entry| entry.index)
            .collect::<Vec<_>>();
        for index in skip_indexes {
            self.skipped.entry(index).or_insert(OfflineSkippedIndex {
                index,
                skipped_at_ms: now_ms,
                last_recovery_probe_ms: 0,
            });
        }
        let skipped_indexes = self.skipped.keys().copied().collect::<Vec<_>>();
        for index in skipped_indexes {
            self.missing.remove(&index);
        }
        self.skipped.retain(|_, entry| {
            now_ms.saturating_sub(entry.skipped_at_ms) <= OFFLINE_SKIPPED_RETENTION_MS
        });
        truncate_map(&mut self.missing, OFFLINE_RECOVERY_STATE_LIMIT);
        truncate_map(&mut self.skipped, OFFLINE_RECOVERY_STATE_LIMIT);

        let previous_base = self.receive_base;
        self.advance_receive_base();
        if previous_base != self.receive_base || !authenticated.is_empty() {
            self.stalled_sweeps = 0;
            self.forward_probe_index = self.receive_base.saturating_add(u64::from(self.window));
        } else {
            self.stalled_sweeps = self.stalled_sweeps.saturating_add(1);
        }
    }

    pub fn record_authenticated(&mut self, index: u64) {
        self.known_remote_next_send = self.known_remote_next_send.max(index.saturating_add(1));
        self.highest_authenticated_receive = Some(
            self.highest_authenticated_receive
                .map(|current| current.max(index))
                .unwrap_or(index),
        );
        self.missing.remove(&index);
        self.skipped.remove(&index);
        if !self.receive_exhausted && index >= self.receive_base {
            self.consumed.insert(index);
        }
        self.advance_receive_base();
    }

    fn advance_receive_base(&mut self) {
        while !self.receive_exhausted
            && (self.consumed.contains(&self.receive_base)
                || self.skipped.contains_key(&self.receive_base))
        {
            self.consumed.remove(&self.receive_base);
            if self.receive_base == u64::MAX {
                self.skipped.remove(&self.receive_base);
                self.receive_exhausted = true;
            } else {
                self.receive_base += 1;
            }
        }
        self.consumed.retain(|index| *index >= self.receive_base);
    }

    fn remember_blob(&mut self, blob_hash: String) {
        if !self.seen_blob_hashes.insert(blob_hash.clone()) {
            return;
        }
        self.seen_blob_order.push_back(blob_hash);
        while self.seen_blob_order.len() > OFFLINE_SEEN_BLOB_LIMIT {
            if let Some(expired) = self.seen_blob_order.pop_front() {
                self.seen_blob_hashes.remove(&expired);
            }
        }
    }
}

impl Default for OfflineState {
    fn default() -> Self {
        Self::new(DEFAULT_OFFLINE_WINDOW).expect("default offline window is valid")
    }
}

fn normalize_b32(value: &str) -> Result<String, OfflineError> {
    let value = value.trim().to_ascii_lowercase();
    let identity = value.strip_suffix(".b32.i2p").unwrap_or(&value);
    if identity.len() != 52
        || !identity
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
    {
        return Err(OfflineError::InvalidB32);
    }
    Ok(identity.to_string())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn truncate_map<T>(map: &mut BTreeMap<u64, T>, limit: usize) {
    while map.len() > limit {
        map.pop_last();
    }
}

#[derive(Debug, Error)]
pub enum OfflineError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("offline shared secret must not be all zero")]
    InvalidSharedSecret,
    #[error("invalid I2P b32 identity")]
    InvalidB32,
    #[error("offline peers must have different identities")]
    IdenticalIdentities,
    #[error("offline window must be between 1 and {MAX_OFFLINE_WINDOW}: {0}")]
    InvalidWindow(u32),
    #[error("offline blob exceeds {MAX_DEADDROP_BLOB_SIZE} bytes: {0}")]
    BlobTooLarge(usize),
    #[error("invalid offline index-sync payload")]
    InvalidIndexSync,
    #[error("offline send index is exhausted")]
    SendIndexExhausted,
    #[error("unexpected offline send index: expected {expected}, got {actual}")]
    UnexpectedSendIndex { expected: u64, actual: u64 },
    #[error("invalid persisted offline state: {0}")]
    InvalidState(&'static str),
}
