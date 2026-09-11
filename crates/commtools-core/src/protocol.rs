use crate::constants::{FRAME_HEADER_LEN, FRAME_MAGIC, MAX_FRAME_PAYLOAD_SIZE, PROTOCOL_VERSION};
use rand_core::{OsRng, RngCore};
use std::io;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub fn generate_message_id() -> u64 {
    OsRng.next_u64()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    U,
    D,
    I,
    S,
    F,
    C,
    E,
    K,
    P,
    O,
    X,
    L,
    Q,
    Y,
    J,
    G,
    Z,
}

impl MessageType {
    pub const ALL: [Self; 17] = [
        Self::U,
        Self::D,
        Self::I,
        Self::S,
        Self::F,
        Self::C,
        Self::E,
        Self::K,
        Self::P,
        Self::O,
        Self::X,
        Self::L,
        Self::Q,
        Self::Y,
        Self::J,
        Self::G,
        Self::Z,
    ];

    pub const fn as_u8(self) -> u8 {
        match self {
            Self::U => b'U',
            Self::D => b'D',
            Self::I => b'I',
            Self::S => b'S',
            Self::F => b'F',
            Self::C => b'C',
            Self::E => b'E',
            Self::K => b'K',
            Self::P => b'P',
            Self::O => b'O',
            Self::X => b'X',
            Self::L => b'L',
            Self::Q => b'Q',
            Self::Y => b'Y',
            Self::J => b'J',
            Self::G => b'G',
            Self::Z => b'Z',
        }
    }

    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            b'U' => Some(Self::U),
            b'D' => Some(Self::D),
            b'I' => Some(Self::I),
            b'S' => Some(Self::S),
            b'F' => Some(Self::F),
            b'C' => Some(Self::C),
            b'E' => Some(Self::E),
            b'K' => Some(Self::K),
            b'P' => Some(Self::P),
            b'O' => Some(Self::O),
            b'X' => Some(Self::X),
            b'L' => Some(Self::L),
            b'Q' => Some(Self::Q),
            b'Y' => Some(Self::Y),
            b'J' => Some(Self::J),
            b'G' => Some(Self::G),
            b'Z' => Some(Self::Z),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub message_type: MessageType,
    pub message_id: u64,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(message_type: MessageType, message_id: u64, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            message_type,
            message_id,
            payload: payload.into(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        validate_payload_size(self.payload.len())?;

        let mut encoded = Vec::with_capacity(FRAME_HEADER_LEN + self.payload.len());
        encoded.extend_from_slice(&FRAME_MAGIC);
        encoded.push(PROTOCOL_VERSION);
        encoded.push(self.message_type.as_u8());
        encoded.extend_from_slice(&self.message_id.to_be_bytes());
        encoded.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.payload);
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, ProtocolError> {
        if encoded.len() < FRAME_HEADER_LEN {
            return Err(ProtocolError::TooShort);
        }
        if encoded[..FRAME_MAGIC.len()] != FRAME_MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }

        let version = encoded[4];
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::InvalidVersion(version));
        }

        let message_type = MessageType::from_u8(encoded[5])
            .ok_or(ProtocolError::UnknownMessageType(encoded[5]))?;

        let mut message_id = [0u8; 8];
        message_id.copy_from_slice(&encoded[6..14]);

        let mut payload_len = [0u8; 4];
        payload_len.copy_from_slice(&encoded[14..18]);
        let payload_len = u32::from_be_bytes(payload_len) as usize;
        validate_payload_size(payload_len)?;

        if encoded.len() != FRAME_HEADER_LEN + payload_len {
            return Err(ProtocolError::LengthMismatch);
        }

        Ok(Self {
            message_type,
            message_id: u64::from_be_bytes(message_id),
            payload: encoded[FRAME_HEADER_LEN..].to_vec(),
        })
    }

    pub async fn read_from<R>(reader: &mut R) -> Result<Self, ProtocolError>
    where
        R: AsyncRead + Unpin,
    {
        let mut magic_buffer = Vec::with_capacity(FRAME_MAGIC.len());

        loop {
            let mut byte = [0u8; 1];
            reader.read_exact(&mut byte).await?;
            magic_buffer.push(byte[0]);

            if magic_buffer.ends_with(&FRAME_MAGIC) {
                break;
            }

            if magic_buffer.len() > FRAME_MAGIC.len() {
                magic_buffer.remove(0);
            }
        }

        let mut remainder = [0u8; FRAME_HEADER_LEN - 4];
        reader.read_exact(&mut remainder).await?;

        let version = remainder[0];
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::InvalidVersion(version));
        }

        let message_type = MessageType::from_u8(remainder[1])
            .ok_or(ProtocolError::UnknownMessageType(remainder[1]))?;

        let mut message_id = [0u8; 8];
        message_id.copy_from_slice(&remainder[2..10]);

        let mut payload_len = [0u8; 4];
        payload_len.copy_from_slice(&remainder[10..14]);
        let payload_len = u32::from_be_bytes(payload_len) as usize;
        validate_payload_size(payload_len)?;

        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload).await?;

        Ok(Self {
            message_type,
            message_id: u64::from_be_bytes(message_id),
            payload,
        })
    }

    pub async fn write_to<W>(&self, writer: &mut W) -> Result<(), ProtocolError>
    where
        W: AsyncWrite + Unpin,
    {
        writer.write_all(&self.encode()?).await?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("frame is shorter than the 18-byte header")]
    TooShort,
    #[error("invalid frame magic")]
    InvalidMagic,
    #[error("unsupported protocol version: {0}")]
    InvalidVersion(u8),
    #[error("unknown frame message type: {0}")]
    UnknownMessageType(u8),
    #[error("invalid frame payload size: {0}")]
    InvalidPayloadSize(usize),
    #[error("frame length does not match its payload length")]
    LengthMismatch,
}

fn validate_payload_size(payload_len: usize) -> Result<(), ProtocolError> {
    if payload_len > MAX_FRAME_PAYLOAD_SIZE {
        return Err(ProtocolError::InvalidPayloadSize(payload_len));
    }
    Ok(())
}
