//! Product-neutral limits and identifiers defined by the wire protocol.

pub const FRAME_MAGIC: [u8; 4] = [0x89, b'I', b'2', b'P'];
pub const PROTOCOL_VERSION: u8 = 3;
pub const FRAME_HEADER_LEN: usize = 18;
pub const MAX_FRAME_PAYLOAD_SIZE: usize = 256 * 1024;

pub const DEFAULT_SAM_HOST: &str = "127.0.0.1";
pub const DEFAULT_SAM_PORT: u16 = 7656;
