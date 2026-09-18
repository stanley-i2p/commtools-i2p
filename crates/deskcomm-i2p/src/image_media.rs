use commtools_core::{INLINE_IMAGE_TRANSFER_MAX_BYTES, sanitize_image_filename};
use image::codecs::jpeg::JpegEncoder;
use image::imageops::FilterType;
use image::{DynamicImage, ExtendedColorType, ImageFormat};
use slint::{Image, Rgba8Pixel, SharedPixelBuffer};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use thiserror::Error;

const IMAGE_PREVIEW_MAX_WIDTH: u32 = 840;
const IMAGE_PREVIEW_MAX_HEIGHT: u32 = 720;
const IMAGE_TRANSFER_JPEG_QUALITY: u8 = 82;
const IMAGE_MAX_PIXELS: u64 = 20_000_000;

pub struct PreparedImage {
    pub filename: String,
    pub mime: String,
    pub bytes: Vec<u8>,
    pub original_mime: Option<String>,
    pub original_bytes: Option<Vec<u8>>,
}

pub struct DecodedImage {
    pub image: Image,
    pub width: u32,
    pub height: u32,
}

pub fn prepare_image_path(
    path: &Path,
    max_preview_bytes: usize,
) -> Result<PreparedImage, ImageMediaError> {
    let metadata = fs::metadata(path).map_err(|source| ImageMediaError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(ImageMediaError::NotAFile(path.to_path_buf()));
    }
    if metadata.len() == 0 || metadata.len() > INLINE_IMAGE_TRANSFER_MAX_BYTES as u64 {
        return Err(ImageMediaError::InvalidSourceSize(metadata.len()));
    }

    let (width, height) = image::image_dimensions(path).map_err(ImageMediaError::Decode)?;
    validate_dimensions(width, height)?;
    let original_bytes = fs::read(path).map_err(|source| ImageMediaError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let original_mime = image::guess_format(&original_bytes)
        .ok()
        .and_then(supported_original_mime)
        .map(str::to_string);
    let decoded = image::open(path).map_err(ImageMediaError::Decode)?;
    let (bytes, mime) = encode_preview(decoded)?;
    if bytes.is_empty() || bytes.len() > max_preview_bytes {
        return Err(ImageMediaError::EncodedPreviewTooLarge {
            actual: bytes.len(),
            maximum: max_preview_bytes,
        });
    }
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(sanitize_image_filename)
        .ok_or_else(|| ImageMediaError::InvalidFilename(path.to_path_buf()))?;

    Ok(PreparedImage {
        filename,
        mime: mime.into(),
        bytes,
        original_bytes: original_mime.as_ref().map(|_| original_bytes),
        original_mime,
    })
}

pub fn slint_image_from_bytes(bytes: &[u8]) -> Result<DecodedImage, ImageMediaError> {
    if bytes.is_empty() || bytes.len() > INLINE_IMAGE_TRANSFER_MAX_BYTES {
        return Err(ImageMediaError::InvalidSourceSize(bytes.len() as u64));
    }
    let decoded = image::load_from_memory(bytes).map_err(ImageMediaError::Decode)?;
    validate_dimensions(decoded.width(), decoded.height())?;
    let width = decoded.width();
    let height = decoded.height();
    let rgba = decoded.into_rgba8();
    let buffer = SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(
        rgba.as_raw(),
        rgba.width(),
        rgba.height(),
    );
    Ok(DecodedImage {
        image: Image::from_rgba8(buffer),
        width,
        height,
    })
}

fn supported_original_mime(format: ImageFormat) -> Option<&'static str> {
    match format {
        ImageFormat::Png => Some("image/png"),
        ImageFormat::Jpeg => Some("image/jpeg"),
        ImageFormat::Gif => Some("image/gif"),
        ImageFormat::Bmp => Some("image/bmp"),
        ImageFormat::WebP => Some("image/webp"),
        _ => None,
    }
}

fn validate_dimensions(width: u32, height: u32) -> Result<(), ImageMediaError> {
    let pixels = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or(ImageMediaError::InvalidDimensions { width, height })?;
    if width == 0 || height == 0 || pixels > IMAGE_MAX_PIXELS {
        return Err(ImageMediaError::InvalidDimensions { width, height });
    }
    Ok(())
}

fn encode_preview(decoded: DynamicImage) -> Result<(Vec<u8>, &'static str), ImageMediaError> {
    let keep_alpha = decoded.color().has_alpha();
    let preview = if decoded.width() > IMAGE_PREVIEW_MAX_WIDTH
        || decoded.height() > IMAGE_PREVIEW_MAX_HEIGHT
    {
        decoded.resize(
            IMAGE_PREVIEW_MAX_WIDTH,
            IMAGE_PREVIEW_MAX_HEIGHT,
            FilterType::Lanczos3,
        )
    } else {
        decoded
    };

    if keep_alpha {
        let mut cursor = Cursor::new(Vec::new());
        preview
            .write_to(&mut cursor, ImageFormat::Png)
            .map_err(ImageMediaError::Encode)?;
        Ok((cursor.into_inner(), "image/png"))
    } else {
        let rgb = preview.to_rgb8();
        let mut bytes = Vec::new();
        JpegEncoder::new_with_quality(&mut bytes, IMAGE_TRANSFER_JPEG_QUALITY)
            .encode(&rgb, rgb.width(), rgb.height(), ExtendedColorType::Rgb8)
            .map_err(ImageMediaError::Encode)?;
        Ok((bytes, "image/jpeg"))
    }
}

#[derive(Debug, Error)]
pub enum ImageMediaError {
    #[error("image path is not a regular file: {0}")]
    NotAFile(PathBuf),
    #[error("image filename is invalid: {0}")]
    InvalidFilename(PathBuf),
    #[error("image source must contain 1 to {INLINE_IMAGE_TRANSFER_MAX_BYTES} bytes; got {0}")]
    InvalidSourceSize(u64),
    #[error("image dimensions are invalid or exceed {IMAGE_MAX_PIXELS} pixels: {width}x{height}")]
    InvalidDimensions { width: u32, height: u32 },
    #[error("encoded image preview is {actual} bytes; maximum is {maximum}")]
    EncodedPreviewTooLarge { actual: usize, maximum: usize },
    #[error("image I/O failed for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("image decode failed: {0}")]
    Decode(#[source] image::ImageError),
    #[error("image encode failed: {0}")]
    Encode(#[source] image::ImageError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded_preview_dimensions(width: u32, height: u32) -> (u32, u32) {
        let source = DynamicImage::new_rgb8(width, height);
        let (bytes, _) = encode_preview(source).expect("encode preview");
        let preview = image::load_from_memory(&bytes).expect("decode preview");
        (preview.width(), preview.height())
    }

    #[test]
    fn landscape_preview_fits_high_dpi_bubble_bounds() {
        assert_eq!(encoded_preview_dimensions(1_000, 750), (840, 630));
    }

    #[test]
    fn portrait_preview_fits_high_dpi_bubble_bounds() {
        assert_eq!(encoded_preview_dimensions(750, 1_000), (540, 720));
    }

    #[test]
    fn preview_does_not_enlarge_an_image_within_bounds() {
        assert_eq!(encoded_preview_dimensions(640, 480), (640, 480));
    }
}
