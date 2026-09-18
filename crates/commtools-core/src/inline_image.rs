use crate::protocol::{Frame, MessageType};
use base64::{Engine as _, engine::general_purpose};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

pub const INLINE_IMAGE_TRANSFER_MAX_BYTES: usize = 50 * 1_024 * 1_024;
pub const INLINE_IMAGE_CHUNK_BYTES: usize = 4_096;
pub const ORIGINAL_IMAGE_CONTROL_PREFIX: &str = "__COMMTOOLS_IMAGE_V1__:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageTransferKind {
    Preview,
    Original,
}

impl ImageTransferKind {
    fn as_wire_name(self) -> &'static str {
        match self {
            Self::Preview => "preview",
            Self::Original => "original",
        }
    }

    fn from_wire_name(value: &str) -> Result<Self, InlineImageError> {
        match value {
            "preview" => Ok(Self::Preview),
            "original" => Ok(Self::Original),
            _ => Err(InlineImageError::InvalidHeader),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginalImageMetadata {
    pub size: u64,
    pub mime: String,
    pub sha256: String,
}

impl OriginalImageMetadata {
    pub fn new(
        size: u64,
        mime: impl Into<String>,
        sha256: impl Into<String>,
    ) -> Result<Self, InlineImageError> {
        let mime = mime.into();
        let sha256 = sha256.into();
        if size == 0 {
            return Err(InlineImageError::InvalidOriginalMetadata);
        }
        validate_image_mime(&mime)?;
        if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(InlineImageError::InvalidOriginalMetadata);
        }
        Ok(Self {
            size,
            mime,
            sha256: sha256.to_ascii_lowercase(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageTransferHeader {
    pub filename: String,
    pub mime: String,
    pub total_bytes: u64,
    pub kind: ImageTransferKind,
    /// Stable preview ID. Original transfers use a separate frame ID but retain this media ID.
    pub media_id: u64,
    /// Description of the requestable original, if the sender retained one in memory.
    pub original: Option<OriginalImageMetadata>,
}

impl ImageTransferHeader {
    pub fn encode(&self) -> Result<String, InlineImageError> {
        let header = self.normalized()?;
        let (original_size, original_mime, sha256) = header
            .original
            .as_ref()
            .map(|original| {
                (
                    original.size,
                    original.mime.as_str(),
                    original.sha256.as_str(),
                )
            })
            .unwrap_or((0, "", ""));
        Ok(format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            header.filename,
            header.mime,
            header.total_bytes,
            header.kind.as_wire_name(),
            header.media_id,
            original_size,
            original_mime,
            sha256
        ))
    }

    pub fn decode(value: &str) -> Result<Self, InlineImageError> {
        let mut parts = value.split('|');
        let (Some(filename), Some(mime), Some(total_bytes), Some(kind), Some(media_id)) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(InlineImageError::InvalidHeader);
        };
        let (Some(original_size), Some(original_mime), Some(sha256), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(InlineImageError::InvalidHeader);
        };
        let total_bytes = total_bytes
            .parse::<u64>()
            .map_err(|_| InlineImageError::InvalidHeader)?;
        let media_id = media_id
            .parse::<u64>()
            .map_err(|_| InlineImageError::InvalidHeader)?;
        let original_size = original_size
            .parse::<u64>()
            .map_err(|_| InlineImageError::InvalidHeader)?;
        let original = if original_size == 0 {
            if !original_mime.is_empty() || !sha256.is_empty() {
                return Err(InlineImageError::InvalidOriginalMetadata);
            }
            None
        } else {
            Some(OriginalImageMetadata::new(
                original_size,
                original_mime,
                sha256,
            )?)
        };
        Self {
            filename: filename.into(),
            mime: mime.into(),
            total_bytes,
            kind: ImageTransferKind::from_wire_name(kind)?,
            media_id,
            original,
        }
        .normalized()
    }

    fn normalized(&self) -> Result<Self, InlineImageError> {
        if self.total_bytes == 0 || self.media_id == 0 {
            return Err(InlineImageError::InvalidHeader);
        }
        validate_image_mime(&self.mime)?;
        let original = self
            .original
            .as_ref()
            .map(|original| {
                OriginalImageMetadata::new(
                    original.size,
                    original.mime.clone(),
                    original.sha256.clone(),
                )
            })
            .transpose()?;
        if self.kind == ImageTransferKind::Original
            && !original.as_ref().is_some_and(|metadata| {
                metadata.size == self.total_bytes && metadata.mime == self.mime
            })
        {
            return Err(InlineImageError::InvalidOriginalMetadata);
        }
        Ok(Self {
            filename: sanitize_image_filename(&self.filename),
            mime: self.mime.clone(),
            total_bytes: self.total_bytes,
            kind: self.kind,
            media_id: self.media_id,
            original,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginalImageControl {
    Request(u64),
    Unavailable(u64),
    Cancel(u64),
}

impl OriginalImageControl {
    pub fn encode(self) -> Result<Vec<u8>, InlineImageError> {
        let (action, media_id) = match self {
            Self::Request(media_id) => ("REQUEST", media_id),
            Self::Unavailable(media_id) => ("UNAVAILABLE", media_id),
            Self::Cancel(media_id) => ("CANCEL", media_id),
        };
        if media_id == 0 {
            return Err(InlineImageError::InvalidImageControl);
        }
        Ok(format!("{ORIGINAL_IMAGE_CONTROL_PREFIX}{action}|{media_id}").into_bytes())
    }

    pub fn decode(payload: &[u8]) -> Result<Option<Self>, InlineImageError> {
        let Ok(body) = std::str::from_utf8(payload) else {
            return Ok(None);
        };
        let Some(control) = body.strip_prefix(ORIGINAL_IMAGE_CONTROL_PREFIX) else {
            return Ok(None);
        };
        let Some((action, media_id)) = control.split_once('|') else {
            return Err(InlineImageError::InvalidImageControl);
        };
        if media_id.contains('|') {
            return Err(InlineImageError::InvalidImageControl);
        }
        let media_id = media_id
            .parse::<u64>()
            .map_err(|_| InlineImageError::InvalidImageControl)?;
        if media_id == 0 {
            return Err(InlineImageError::InvalidImageControl);
        }
        match action {
            "REQUEST" => Ok(Some(Self::Request(media_id))),
            "UNAVAILABLE" => Ok(Some(Self::Unavailable(media_id))),
            "CANCEL" => Ok(Some(Self::Cancel(media_id))),
            _ => Err(InlineImageError::InvalidImageControl),
        }
    }
}

pub fn image_sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineImage {
    pub transfer_id: u64,
    pub header: ImageTransferHeader,
    pub filename: String,
    pub mime: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct InlineImageReceiver {
    incoming: Option<IncomingImage>,
    discarding_transfer: Option<u64>,
    cancelled_originals: BTreeSet<u64>,
}

#[derive(Debug, Clone)]
struct IncomingImage {
    header: ImageTransferHeader,
    expected: usize,
    transfer_id: u64,
    bytes: Vec<u8>,
}

impl InlineImageReceiver {
    pub fn reset(&mut self) {
        self.incoming = None;
        self.discarding_transfer = None;
        self.cancelled_originals.clear();
    }

    pub fn cancel_original(&mut self, media_id: u64) -> bool {
        self.cancelled_originals.insert(media_id);
        let cancelled_transfer = self.incoming.as_ref().and_then(|image| {
            (image.header.kind == ImageTransferKind::Original && image.header.media_id == media_id)
                .then_some(image.transfer_id)
        });
        if let Some(transfer_id) = cancelled_transfer {
            self.discarding_transfer = Some(transfer_id);
            self.incoming = None;
            self.cancelled_originals.remove(&media_id);
            true
        } else {
            false
        }
    }

    pub fn allow_original(&mut self, media_id: u64) {
        self.cancelled_originals.remove(&media_id);
    }

    pub fn active_transfer(&self) -> Option<(u64, &ImageTransferHeader, u64)> {
        self.incoming
            .as_ref()
            .map(|image| (image.transfer_id, &image.header, image.bytes.len() as u64))
    }

    pub fn receive(&mut self, frame: &Frame) -> Result<Option<InlineImage>, InlineImageError> {
        if let Some(transfer_id) = self.discarding_transfer {
            if frame.message_id == transfer_id {
                match frame.message_type {
                    MessageType::G => return Ok(None),
                    MessageType::Z => {
                        self.discarding_transfer = None;
                        return Ok(None);
                    }
                    _ => {}
                }
            }
            if frame.message_type == MessageType::J {
                self.discarding_transfer = None;
            }
        }
        match frame.message_type {
            MessageType::J => self.receive_header(frame),
            MessageType::G => self.receive_chunk(frame),
            MessageType::Z => self.receive_end(frame),
            other => Err(InlineImageError::UnexpectedFrame(other)),
        }
    }

    fn receive_header(&mut self, frame: &Frame) -> Result<Option<InlineImage>, InlineImageError> {
        self.incoming = None;
        self.discarding_transfer = None;
        let header =
            std::str::from_utf8(&frame.payload).map_err(|_| InlineImageError::InvalidHeader)?;
        let header = decode_compatible_header(header, frame.message_id)?;
        if header.kind == ImageTransferKind::Original
            && self.cancelled_originals.remove(&header.media_id)
        {
            self.incoming = None;
            self.discarding_transfer = Some(frame.message_id);
            return Ok(None);
        }
        let expected = usize::try_from(header.total_bytes)
            .map_err(|_| InlineImageError::InvalidSize(usize::MAX))?;
        if expected == 0 || expected > INLINE_IMAGE_TRANSFER_MAX_BYTES {
            return Err(InlineImageError::InvalidSize(expected));
        }
        self.incoming = Some(IncomingImage {
            header,
            expected,
            transfer_id: frame.message_id,
            bytes: Vec::with_capacity(expected),
        });
        Ok(None)
    }

    fn receive_chunk(&mut self, frame: &Frame) -> Result<Option<InlineImage>, InlineImageError> {
        let Some(mut image) = self.incoming.take() else {
            return Err(InlineImageError::MissingHeader);
        };
        if image.transfer_id != frame.message_id {
            return Err(InlineImageError::MessageIdMismatch);
        }
        let max_encoded_chunk = INLINE_IMAGE_CHUNK_BYTES.div_ceil(3) * 4;
        if frame.payload.len() > max_encoded_chunk {
            return Err(InlineImageError::TransferOverflow);
        }
        let chunk = match general_purpose::STANDARD.decode(&frame.payload) {
            Ok(chunk) => chunk,
            Err(_) => return Err(InlineImageError::InvalidChunk),
        };
        if chunk.len() > INLINE_IMAGE_CHUNK_BYTES
            || image.bytes.len().saturating_add(chunk.len()) > image.expected
        {
            return Err(InlineImageError::TransferOverflow);
        }
        image.bytes.extend_from_slice(&chunk);
        self.incoming = Some(image);
        Ok(None)
    }

    fn receive_end(&mut self, frame: &Frame) -> Result<Option<InlineImage>, InlineImageError> {
        let Some(image) = self.incoming.take() else {
            return Err(InlineImageError::MissingHeader);
        };
        if image.transfer_id != frame.message_id {
            return Err(InlineImageError::MessageIdMismatch);
        }
        if image.bytes.len() != image.expected {
            return Err(InlineImageError::Incomplete {
                received: image.bytes.len(),
                expected: image.expected,
            });
        }
        validate_image_bytes(&image.header.mime, &image.bytes)?;
        if image.header.kind == ImageTransferKind::Original {
            let expected_digest = image
                .header
                .original
                .as_ref()
                .ok_or(InlineImageError::InvalidOriginalMetadata)?
                .sha256
                .as_str();
            if !image_sha256_hex(&image.bytes).eq_ignore_ascii_case(expected_digest) {
                return Err(InlineImageError::OriginalDigestMismatch);
            }
        }
        Ok(Some(InlineImage {
            transfer_id: image.transfer_id,
            filename: image.header.filename.clone(),
            mime: image.header.mime.clone(),
            header: image.header,
            bytes: image.bytes,
        }))
    }
}

pub fn inline_image_frames(
    message_id: u64,
    filename: &str,
    mime: &str,
    bytes: &[u8],
) -> Result<Vec<Frame>, InlineImageError> {
    if bytes.is_empty() || bytes.len() > INLINE_IMAGE_TRANSFER_MAX_BYTES {
        return Err(InlineImageError::InvalidSize(bytes.len()));
    }
    validate_image_bytes(mime, bytes)?;
    let header = ImageTransferHeader {
        filename: filename.to_string(),
        mime: mime.to_string(),
        total_bytes: bytes.len() as u64,
        kind: ImageTransferKind::Preview,
        media_id: message_id,
        original: None,
    };
    inline_image_frames_with_header(message_id, &header, bytes)
}

pub fn inline_image_frames_with_header(
    transfer_id: u64,
    header: &ImageTransferHeader,
    bytes: &[u8],
) -> Result<Vec<Frame>, InlineImageError> {
    if bytes.is_empty() || bytes.len() > INLINE_IMAGE_TRANSFER_MAX_BYTES {
        return Err(InlineImageError::InvalidSize(bytes.len()));
    }
    let header = header.normalized()?;
    if header.total_bytes != bytes.len() as u64 {
        return Err(InlineImageError::InvalidSize(bytes.len()));
    }
    validate_image_bytes(&header.mime, bytes)?;
    let mut frames = Vec::with_capacity(bytes.len() / INLINE_IMAGE_CHUNK_BYTES + 2);
    frames.push(Frame::new(MessageType::J, transfer_id, header.encode()?));
    frames.extend(bytes.chunks(INLINE_IMAGE_CHUNK_BYTES).map(|chunk| {
        Frame::new(
            MessageType::G,
            transfer_id,
            general_purpose::STANDARD.encode(chunk),
        )
    }));
    frames.push(Frame::new(MessageType::Z, transfer_id, Vec::new()));
    Ok(frames)
}

fn decode_compatible_header(
    value: &str,
    legacy_media_id: u64,
) -> Result<ImageTransferHeader, InlineImageError> {
    if value.split('|').count() == 8 {
        return ImageTransferHeader::decode(value);
    }
    let mut parts = value.split('|');
    let (Some(filename), Some(mime), Some(total_bytes), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(InlineImageError::InvalidHeader);
    };
    let total_bytes = total_bytes
        .parse::<u64>()
        .map_err(|_| InlineImageError::InvalidHeader)?;
    ImageTransferHeader {
        filename: filename.to_string(),
        mime: mime.to_string(),
        total_bytes,
        kind: ImageTransferKind::Preview,
        media_id: legacy_media_id,
        original: None,
    }
    .normalized()
}

pub fn validate_image_bytes(mime: &str, bytes: &[u8]) -> Result<(), InlineImageError> {
    validate_image_mime(mime)?;
    let valid = match mime {
        "image/png" => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        "image/jpeg" => bytes.starts_with(&[0xff, 0xd8, 0xff]),
        "image/gif" => bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"),
        "image/bmp" => bytes.starts_with(b"BM"),
        "image/webp" => bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP",
        _ => false,
    };
    valid
        .then_some(())
        .ok_or_else(|| InlineImageError::ContentMismatch(mime.to_string()))
}

pub fn validate_image_mime(mime: &str) -> Result<(), InlineImageError> {
    matches!(
        mime,
        "image/png" | "image/jpeg" | "image/gif" | "image/bmp" | "image/webp"
    )
    .then_some(())
    .ok_or_else(|| InlineImageError::UnsupportedMime(mime.to_string()))
}

pub fn sanitize_image_filename(filename: &str) -> String {
    let mut sanitized = filename
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .take(128)
        .collect::<String>();
    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        sanitized = "image".into();
    }
    sanitized
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum InlineImageError {
    #[error("unexpected inline-image frame type: {0:?}")]
    UnexpectedFrame(MessageType),
    #[error("inline-image header is invalid")]
    InvalidHeader,
    #[error("inline-image size is invalid: {0} bytes")]
    InvalidSize(usize),
    #[error("unsupported inline-image MIME type: {0}")]
    UnsupportedMime(String),
    #[error("inline-image content does not match {0}")]
    ContentMismatch(String),
    #[error("inline-image chunk arrived without a header")]
    MissingHeader,
    #[error("inline-image transfer message id does not match")]
    MessageIdMismatch,
    #[error("inline-image chunk is not valid base64")]
    InvalidChunk,
    #[error("inline-image transfer exceeds its declared size")]
    TransferOverflow,
    #[error("inline-image transfer is incomplete: {received}/{expected} bytes")]
    Incomplete { received: usize, expected: usize },
    #[error("inline-image original metadata is invalid")]
    InvalidOriginalMetadata,
    #[error("inline-image original digest does not match its advertised digest")]
    OriginalDigestMismatch,
    #[error("inline-image control is invalid")]
    InvalidImageControl,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_sequence_round_trips_only_in_memory() {
        let bytes = b"\x89PNG\r\n\x1a\ninline image";
        let frames = inline_image_frames(41, "../preview|one.png", "image/png", bytes)
            .expect("image frames");
        let mut receiver = InlineImageReceiver::default();
        let mut image = None;
        for frame in &frames {
            image = receiver.receive(frame).expect("receive image").or(image);
        }
        let image = image.expect("completed image");
        assert_eq!(image.filename, ".._preview_one.png");
        assert_eq!(image.mime, "image/png");
        assert_eq!(image.bytes.as_slice(), bytes);
    }

    #[test]
    fn overflow_resets_the_active_transfer() {
        let mut receiver = InlineImageReceiver::default();
        receiver
            .receive(&Frame::new(MessageType::J, 7, "small.png|image/png|8"))
            .expect("header");
        let oversized = general_purpose::STANDARD.encode([0_u8; 9]);
        assert_eq!(
            receiver.receive(&Frame::new(MessageType::G, 7, oversized)),
            Err(InlineImageError::TransferOverflow)
        );
        assert_eq!(
            receiver.receive(&Frame::new(MessageType::Z, 7, Vec::new())),
            Err(InlineImageError::MissingHeader)
        );
    }

    #[test]
    fn iced_extended_preview_header_round_trips_exactly() {
        let digest = image_sha256_hex(b"original image");
        let header = ImageTransferHeader {
            filename: "preview.png".into(),
            mime: "image/png".into(),
            total_bytes: 1234,
            kind: ImageTransferKind::Preview,
            media_id: 77,
            original: Some(
                OriginalImageMetadata::new(4321, "image/jpeg", digest.clone())
                    .expect("original metadata"),
            ),
        };
        let encoded = header.encode().expect("encode header");

        assert_eq!(
            encoded,
            format!("preview.png|image/png|1234|preview|77|4321|image/jpeg|{digest}")
        );
        assert_eq!(
            ImageTransferHeader::decode(&encoded).expect("decode header"),
            header
        );
    }

    #[test]
    fn iced_extended_original_header_requires_matching_metadata() {
        let digest = image_sha256_hex(b"original image");
        let encoded = format!("photo.jpg|image/jpeg|4321|original|77|4321|image/jpeg|{digest}");
        assert_eq!(
            ImageTransferHeader::decode(&encoded).expect("decode original header"),
            ImageTransferHeader {
                filename: "photo.jpg".into(),
                mime: "image/jpeg".into(),
                total_bytes: 4321,
                kind: ImageTransferKind::Original,
                media_id: 77,
                original: Some(
                    OriginalImageMetadata::new(4321, "image/jpeg", digest)
                        .expect("original metadata"),
                ),
            }
        );
        assert_eq!(
            ImageTransferHeader::decode(
                "photo.jpg|image/jpeg|4321|original|77|123|image/jpeg|0000000000000000000000000000000000000000000000000000000000000000",
            ),
            Err(InlineImageError::InvalidOriginalMetadata)
        );
    }

    #[test]
    fn extended_header_without_an_original_preserves_empty_wire_fields() {
        let header = ImageTransferHeader {
            filename: "preview.png".into(),
            mime: "image/png".into(),
            total_bytes: 1234,
            kind: ImageTransferKind::Preview,
            media_id: 77,
            original: None,
        };

        assert_eq!(
            header.encode().expect("encode header"),
            "preview.png|image/png|1234|preview|77|0||"
        );
    }

    #[test]
    fn iced_original_image_controls_round_trip_exactly() {
        for (control, encoded) in [
            (
                OriginalImageControl::Request(77),
                b"__COMMTOOLS_IMAGE_V1__:REQUEST|77".as_slice(),
            ),
            (
                OriginalImageControl::Unavailable(77),
                b"__COMMTOOLS_IMAGE_V1__:UNAVAILABLE|77".as_slice(),
            ),
            (
                OriginalImageControl::Cancel(77),
                b"__COMMTOOLS_IMAGE_V1__:CANCEL|77".as_slice(),
            ),
        ] {
            assert_eq!(
                control.encode().expect("encode control").as_slice(),
                encoded
            );
            assert_eq!(
                OriginalImageControl::decode(encoded).expect("decode control"),
                Some(control)
            );
        }
        assert_eq!(
            OriginalImageControl::decode(b"preview.png|image/png|42"),
            Ok(None)
        );
        assert_eq!(
            OriginalImageControl::decode(b"__COMMTOOLS_IMAGE_V1__:REQUEST|0"),
            Err(InlineImageError::InvalidImageControl)
        );
    }

    #[test]
    fn extended_original_sequence_validates_and_preserves_media_identity() {
        let bytes = b"\x89PNG\r\n\x1a\nfull original";
        let metadata =
            OriginalImageMetadata::new(bytes.len() as u64, "image/png", image_sha256_hex(bytes))
                .expect("metadata");
        let header = ImageTransferHeader {
            filename: "original.png".into(),
            mime: "image/png".into(),
            total_bytes: bytes.len() as u64,
            kind: ImageTransferKind::Original,
            media_id: 77,
            original: Some(metadata),
        };
        let frames = inline_image_frames_with_header(88, &header, bytes).expect("frames");
        let mut receiver = InlineImageReceiver::default();
        let mut received = None;
        for frame in &frames {
            received = receiver.receive(frame).expect("receive").or(received);
        }
        let received = received.expect("complete original");
        assert_eq!(received.transfer_id, 88);
        assert_eq!(received.header.media_id, 77);
        assert_eq!(received.header.kind, ImageTransferKind::Original);
        assert_eq!(received.bytes, bytes);
    }

    #[test]
    fn cancelled_original_drains_buffered_frames_and_allows_the_next_image() {
        let mut original = b"\x89PNG\r\n\x1a\n".to_vec();
        original.extend(std::iter::repeat_n(0x5a, INLINE_IMAGE_CHUNK_BYTES * 2));
        let metadata = OriginalImageMetadata::new(
            original.len() as u64,
            "image/png",
            image_sha256_hex(&original),
        )
        .expect("metadata");
        let header = ImageTransferHeader {
            filename: "original.png".into(),
            mime: "image/png".into(),
            total_bytes: original.len() as u64,
            kind: ImageTransferKind::Original,
            media_id: 77,
            original: Some(metadata),
        };
        let frames = inline_image_frames_with_header(88, &header, &original).expect("frames");
        let mut receiver = InlineImageReceiver::default();
        receiver.receive(&frames[0]).expect("original header");
        receiver.receive(&frames[1]).expect("first original chunk");

        assert!(receiver.cancel_original(77));
        for frame in frames[2..]
            .iter()
            .filter(|frame| frame.message_type == MessageType::G)
        {
            assert_eq!(
                receiver.receive(frame).expect("drain cancelled frame"),
                None
            );
        }

        let preview = b"\x89PNG\r\n\x1a\nnext preview";
        let preview_frames =
            inline_image_frames(99, "preview.png", "image/png", preview).expect("preview frames");
        let mut received = None;
        for frame in &preview_frames {
            received = receiver
                .receive(frame)
                .expect("receive preview")
                .or(received);
        }
        assert_eq!(received.expect("completed preview").bytes, preview);
    }

    #[test]
    fn original_cancelled_before_its_header_is_drained_on_arrival() {
        let bytes = b"\x89PNG\r\n\x1a\nlate original";
        let metadata =
            OriginalImageMetadata::new(bytes.len() as u64, "image/png", image_sha256_hex(bytes))
                .expect("metadata");
        let header = ImageTransferHeader {
            filename: "late.png".into(),
            mime: "image/png".into(),
            total_bytes: bytes.len() as u64,
            kind: ImageTransferKind::Original,
            media_id: 177,
            original: Some(metadata),
        };
        let frames = inline_image_frames_with_header(188, &header, bytes).expect("frames");
        let mut receiver = InlineImageReceiver::default();

        assert!(!receiver.cancel_original(177));
        for frame in &frames {
            assert_eq!(receiver.receive(frame).expect("drain late frame"), None);
        }
        assert!(receiver.active_transfer().is_none());
    }
}
