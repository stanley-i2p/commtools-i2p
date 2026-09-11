use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

pub const FILE_TRANSFER_MAX_BYTES: u64 = 50 * 1024 * 1024;
pub const FILE_TRANSFER_CHUNK_BYTES: usize = 4_096;
pub const FILE_TRANSFER_MAX_FILENAME_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum FileTransferControl {
    Offer { filename: String, total_bytes: u64 },
    Accept,
    Decline,
    Cancel,
}

impl FileTransferControl {
    pub fn encode(&self) -> Result<Vec<u8>, FileTransferError> {
        serde_json::to_vec(&self.normalized()?)
            .map_err(|error| FileTransferError::InvalidControl(error.to_string()))
    }

    pub fn decode(payload: &[u8]) -> Result<Self, FileTransferError> {
        let control = serde_json::from_slice::<Self>(payload)
            .map_err(|error| FileTransferError::InvalidControl(error.to_string()))?;
        control.normalized()
    }

    fn normalized(&self) -> Result<Self, FileTransferError> {
        match self {
            Self::Offer {
                filename,
                total_bytes,
            } => {
                validate_file_size(*total_bytes)?;
                Ok(Self::Offer {
                    filename: sanitize_file_filename(filename),
                    total_bytes: *total_bytes,
                })
            }
            Self::Accept => Ok(Self::Accept),
            Self::Decline => Ok(Self::Decline),
            Self::Cancel => Ok(Self::Cancel),
        }
    }
}

pub fn sanitize_file_filename(filename: &str) -> String {
    let basename = Path::new(filename)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("file.bin");
    let mut sanitized = String::new();
    for character in basename.chars() {
        if character == '|' || character.is_control() {
            continue;
        }
        if sanitized.len() + character.len_utf8() > FILE_TRANSFER_MAX_FILENAME_BYTES {
            break;
        }
        sanitized.push(character);
    }
    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        "file.bin".into()
    } else {
        sanitized
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FileTransferError {
    #[error("file transfer size must be between 1 and {FILE_TRANSFER_MAX_BYTES} bytes, got {0}")]
    InvalidSize(u64),
    #[error("invalid file-transfer control: {0}")]
    InvalidControl(String),
}

fn validate_file_size(size: u64) -> Result<(), FileTransferError> {
    if size == 0 || size > FILE_TRANSFER_MAX_BYTES {
        Err(FileTransferError::InvalidSize(size))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iced_file_offer_uses_the_canonical_json_shape() {
        let control = FileTransferControl::Offer {
            filename: "notes.txt".into(),
            total_bytes: 42,
        };
        let encoded = control.encode().expect("encode offer");

        assert_eq!(
            encoded.as_slice(),
            br#"{"action":"offer","filename":"notes.txt","total_bytes":42}"#
        );
        assert_eq!(
            FileTransferControl::decode(&encoded).expect("decode offer"),
            control
        );
    }

    #[test]
    fn iced_file_decisions_round_trip_with_their_exact_action_names() {
        for (control, encoded) in [
            (
                FileTransferControl::Accept,
                br#"{"action":"accept"}"#.as_slice(),
            ),
            (
                FileTransferControl::Decline,
                br#"{"action":"decline"}"#.as_slice(),
            ),
            (
                FileTransferControl::Cancel,
                br#"{"action":"cancel"}"#.as_slice(),
            ),
        ] {
            assert_eq!(
                control.encode().expect("encode decision").as_slice(),
                encoded
            );
            assert_eq!(
                FileTransferControl::decode(encoded).expect("decode decision"),
                control
            );
        }
    }

    #[test]
    fn file_offer_codec_validates_size_and_sanitizes_filename() {
        assert_eq!(
            FileTransferControl::decode(
                br#"{"action":"offer","filename":"../notes.txt","total_bytes":42}"#,
            )
            .expect("decode sanitized offer"),
            FileTransferControl::Offer {
                filename: "notes.txt".into(),
                total_bytes: 42,
            }
        );
        assert!(matches!(
            FileTransferControl::decode(
                br#"{"action":"offer","filename":"empty.bin","total_bytes":0}"#,
            ),
            Err(FileTransferError::InvalidSize(0))
        ));
        assert!(matches!(
            FileTransferControl::decode(br#"{"action":"unknown"}"#),
            Err(FileTransferError::InvalidControl(_))
        ));
    }
}
