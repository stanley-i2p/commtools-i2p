use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

use crate::storage::{create_secure_directory, set_file_mode, write_atomic};

pub const HISTORY_FILENAME: &str = "history.jsonl";
pub const MAX_HISTORY_RECORDS: usize = 5_000;
pub const MAX_HISTORY_FILE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_HISTORY_TEXT_BYTES: usize = 256 * 1024;

const HISTORY_FORMAT_VERSION: u8 = 1;
const MAX_HISTORY_LINE_BYTES: usize = MAX_HISTORY_TEXT_BYTES + 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryScope {
    Contact(String),
    Group(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HistoryRecord {
    pub created_ms: u64,
    pub timestamp_utc: String,
    pub author: String,
    #[serde(default)]
    pub sender_b32: Option<String>,
    pub text: String,
    pub mine: bool,
    pub offline: bool,
    #[serde(default)]
    pub msg_id: Option<u64>,
    #[serde(default)]
    pub delivered: bool,
    #[serde(default)]
    pub group_expected_acks: Vec<String>,
    #[serde(default)]
    pub group_received_acks: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
enum HistoryEvent {
    Message {
        version: u8,
        record: HistoryRecord,
    },
    Delivery {
        version: u8,
        msg_id: u64,
        #[serde(default)]
        peer_b32: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct HistoryRepository {
    root: PathBuf,
}

impl HistoryRepository {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, HistoryError> {
        let root = root.into();
        if root.as_os_str().is_empty() {
            return Err(HistoryError::InvalidRoot);
        }
        Ok(Self { root })
    }

    pub fn load(&self, scope: &HistoryScope) -> Result<Vec<HistoryRecord>, HistoryError> {
        let path = self.history_path(scope)?;
        if !path.exists() {
            return Ok(Vec::new());
        }
        let metadata = fs::metadata(&path).map_err(|source| io_error(&path, source))?;
        if metadata.len() > MAX_HISTORY_FILE_BYTES + MAX_HISTORY_LINE_BYTES as u64 {
            return Err(HistoryError::FileTooLarge);
        }

        let file = File::open(&path).map_err(|source| io_error(&path, source))?;
        let mut records = VecDeque::new();
        let mut record_keys = HashSet::new();
        for line in BufReader::new(file).split(b'\n') {
            let Ok(line) = line else {
                continue;
            };
            if line.is_empty() || line.len() > MAX_HISTORY_LINE_BYTES {
                continue;
            }
            let Ok(event) = serde_json::from_slice::<HistoryEvent>(&line) else {
                continue;
            };
            match event {
                HistoryEvent::Message { version, record }
                    if version == HISTORY_FORMAT_VERSION && valid_record(&record) =>
                {
                    if let Some(key) = record_key(&record)
                        && !record_keys.insert(key)
                    {
                        continue;
                    }
                    records.push_back(record);
                    while records.len() > MAX_HISTORY_RECORDS {
                        if let Some(removed) = records.pop_front()
                            && let Some(key) = record_key(&removed)
                        {
                            record_keys.remove(&key);
                        }
                    }
                }
                HistoryEvent::Delivery {
                    version,
                    msg_id,
                    peer_b32,
                } if version == HISTORY_FORMAT_VERSION => {
                    apply_delivery(&mut records, msg_id, peer_b32.as_deref());
                }
                _ => {}
            }
        }
        Ok(records.into_iter().collect())
    }

    pub fn append_message(
        &self,
        scope: &HistoryScope,
        record: &HistoryRecord,
    ) -> Result<(), HistoryError> {
        if !valid_record(record) {
            return Err(HistoryError::InvalidRecord);
        }
        self.append_event(
            scope,
            &HistoryEvent::Message {
                version: HISTORY_FORMAT_VERSION,
                record: record.clone(),
            },
        )
    }

    pub fn append_delivery(
        &self,
        scope: &HistoryScope,
        msg_id: u64,
        peer_b32: Option<&str>,
    ) -> Result<(), HistoryError> {
        self.append_event(
            scope,
            &HistoryEvent::Delivery {
                version: HISTORY_FORMAT_VERSION,
                msg_id,
                peer_b32: peer_b32.map(str::to_ascii_lowercase),
            },
        )
    }

    pub fn clear(&self, scope: &HistoryScope) -> Result<(), HistoryError> {
        let path = self.history_path(scope)?;
        if path.exists() {
            fs::remove_file(&path).map_err(|source| io_error(&path, source))?;
        }
        Ok(())
    }

    pub fn validate_records(records: &[HistoryRecord]) -> Result<(), HistoryError> {
        if records.len() > MAX_HISTORY_RECORDS || records.iter().any(|record| !valid_record(record))
        {
            return Err(HistoryError::InvalidRecord);
        }
        Ok(())
    }

    pub fn replace(
        &self,
        scope: &HistoryScope,
        records: &[HistoryRecord],
    ) -> Result<(), HistoryError> {
        Self::validate_records(records)?;
        if records.is_empty() {
            return self.clear(scope);
        }
        let mut encoded = Vec::new();
        for record in records {
            let mut line = serde_json::to_vec(&HistoryEvent::Message {
                version: HISTORY_FORMAT_VERSION,
                record: record.clone(),
            })?;
            if line.len() > MAX_HISTORY_LINE_BYTES {
                return Err(HistoryError::InvalidRecord);
            }
            line.push(b'\n');
            if encoded.len().saturating_add(line.len()) > MAX_HISTORY_FILE_BYTES as usize {
                return Err(HistoryError::FileTooLarge);
            }
            encoded.extend_from_slice(&line);
        }
        let path = self.history_path(scope)?;
        let parent = path.parent().ok_or(HistoryError::InvalidRoot)?;
        create_secure_directory(parent)
            .map_err(|error| HistoryError::Storage(error.to_string()))?;
        write_atomic(&path, &encoded).map_err(|error| HistoryError::Storage(error.to_string()))
    }

    fn append_event(&self, scope: &HistoryScope, event: &HistoryEvent) -> Result<(), HistoryError> {
        let path = self.history_path(scope)?;
        let parent = path.parent().ok_or(HistoryError::InvalidRoot)?;
        create_secure_directory(parent)
            .map_err(|error| HistoryError::Storage(error.to_string()))?;
        let mut line = serde_json::to_vec(event)?;
        if line.len() > MAX_HISTORY_LINE_BYTES {
            return Err(HistoryError::InvalidRecord);
        }
        line.push(b'\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|source| io_error(&path, source))?;
        set_file_mode(&file, &path).map_err(|error| HistoryError::Storage(error.to_string()))?;
        file.write_all(&line)
            .and_then(|_| file.flush())
            .and_then(|_| file.sync_data())
            .map_err(|source| io_error(&path, source))?;
        let compact = file
            .metadata()
            .map_err(|source| io_error(&path, source))?
            .len()
            > MAX_HISTORY_FILE_BYTES;
        drop(file);
        if compact {
            self.compact(scope)?;
        }
        Ok(())
    }

    fn compact(&self, scope: &HistoryScope) -> Result<(), HistoryError> {
        let records = self.load(scope)?;
        let mut lines = VecDeque::new();
        let mut retained_bytes = 0usize;
        for record in records {
            let mut line = serde_json::to_vec(&HistoryEvent::Message {
                version: HISTORY_FORMAT_VERSION,
                record,
            })?;
            line.push(b'\n');
            retained_bytes = retained_bytes.saturating_add(line.len());
            lines.push_back(line);
            while retained_bytes > MAX_HISTORY_FILE_BYTES as usize {
                let Some(removed) = lines.pop_front() else {
                    break;
                };
                retained_bytes = retained_bytes.saturating_sub(removed.len());
            }
        }
        let mut compacted = Vec::with_capacity(retained_bytes);
        compacted.extend(lines.into_iter().flatten());
        let path = self.history_path(scope)?;
        write_atomic(&path, &compacted).map_err(|error| HistoryError::Storage(error.to_string()))
    }

    fn history_path(&self, scope: &HistoryScope) -> Result<PathBuf, HistoryError> {
        let (parent, component) = match scope {
            HistoryScope::Contact(component) => ("profiles", component),
            HistoryScope::Group(component) => ("groups", component),
        };
        validate_component(component)?;
        Ok(self
            .root
            .join(parent)
            .join(component)
            .join(HISTORY_FILENAME))
    }
}

fn validate_component(value: &str) -> Result<(), HistoryError> {
    let mut components = Path::new(value).components();
    if value.is_empty()
        || !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(HistoryError::InvalidScope);
    }
    Ok(())
}

fn valid_record(record: &HistoryRecord) -> bool {
    record.text.len() <= MAX_HISTORY_TEXT_BYTES
        && record.timestamp_utc.len() <= 32
        && record.author.len() <= 256
        && record.group_expected_acks.len() <= 256
        && record.group_received_acks.len() <= 256
        && record
            .sender_b32
            .as_ref()
            .is_none_or(|sender| sender.len() <= 256)
        && record
            .group_expected_acks
            .iter()
            .chain(&record.group_received_acks)
            .all(|peer| peer.len() <= 256)
}

fn apply_delivery(records: &mut VecDeque<HistoryRecord>, msg_id: u64, peer_b32: Option<&str>) {
    let Some(record) = records
        .iter_mut()
        .rev()
        .find(|record| record.mine && record.msg_id == Some(msg_id))
    else {
        return;
    };
    if let Some(peer_b32) = peer_b32 {
        if record
            .group_expected_acks
            .iter()
            .any(|expected| expected.eq_ignore_ascii_case(peer_b32))
            && !record
                .group_received_acks
                .iter()
                .any(|received| received.eq_ignore_ascii_case(peer_b32))
        {
            record
                .group_received_acks
                .push(peer_b32.to_ascii_lowercase());
        }
        record.delivered = !record.group_expected_acks.is_empty()
            && record.group_received_acks.len() >= record.group_expected_acks.len();
    } else {
        record.delivered = true;
    }
}

fn record_key(record: &HistoryRecord) -> Option<String> {
    let message_id = record.msg_id?;
    Some(format!(
        "{}:{message_id}:{}",
        if record.mine { "out" } else { "in" },
        record
            .sender_b32
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase()
    ))
}

fn io_error(path: &Path, source: std::io::Error) -> HistoryError {
    HistoryError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Debug, Error)]
pub enum HistoryError {
    #[error("history repository root is invalid")]
    InvalidRoot,
    #[error("history scope is invalid")]
    InvalidScope,
    #[error("history record is invalid or exceeds its limit")]
    InvalidRecord,
    #[error("history file exceeds its storage limit")]
    FileTooLarge,
    #[error("history storage error: {0}")]
    Storage(String),
    #[error("history JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("history I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(message_id: u64, mine: bool) -> HistoryRecord {
        HistoryRecord {
            created_ms: message_id,
            timestamp_utc: "12:34:56 UTC".into(),
            author: if mine { "Me" } else { "Alice" }.into(),
            sender_b32: (!mine).then(|| "alice.b32.i2p".into()),
            text: format!("message {message_id}"),
            mine,
            offline: false,
            msg_id: Some(message_id),
            delivered: false,
            group_expected_acks: Vec::new(),
            group_received_acks: Vec::new(),
        }
    }

    #[test]
    fn message_and_delivery_round_trip() {
        let root = std::env::temp_dir().join(format!(
            "commtools-history-{}-{}",
            std::process::id(),
            crate::protocol::generate_message_id()
        ));
        let repository = HistoryRepository::new(&root).expect("repository");
        let scope = HistoryScope::Contact("Alice".into());
        repository
            .append_message(&scope, &record(7, true))
            .expect("append message");
        repository
            .append_delivery(&scope, 7, None)
            .expect("append delivery");
        let loaded = repository.load(&scope).expect("load history");
        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].delivered);
        repository.clear(&scope).expect("clear history");
        assert!(repository.load(&scope).expect("load cleared").is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn scope_cannot_escape_the_storage_root() {
        let repository = HistoryRepository::new("vault").expect("repository");
        assert!(
            repository
                .load(&HistoryScope::Contact("../Alice".into()))
                .is_err()
        );
    }
}
