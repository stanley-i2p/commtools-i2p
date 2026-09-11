use commtools_core::{INLINE_IMAGE_TRANSFER_MAX_BYTES, sanitize_image_filename};
use image::codecs::jpeg::JpegEncoder;
use image::imageops::FilterType;
use image::{DynamicImage, ExtendedColorType, ImageFormat, RgbImage};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const IMAGE_TRANSFER_MAX_DIMENSION: u32 = 1_280;
pub const IMAGE_TRANSFER_JPEG_QUALITY: u8 = 82;
pub const IMAGE_MAX_PIXELS: u64 = 20_000_000;
pub const IMAGE_RENDER_WIDTH: u32 = 60;
pub const MAX_IMAGE_LINES: usize = 2_000;

#[derive(Debug, Clone)]
pub struct PreparedImage {
    pub filename: String,
    pub mime: String,
    pub bytes: Vec<u8>,
    pub original_mime: Option<String>,
    pub original_bytes: Option<Vec<u8>>,
    pub rendered: RenderedImage,
}

#[derive(Debug, Clone, Default)]
pub struct RenderedImage {
    pub lines: Vec<RenderedImageLine>,
}

pub type RenderedImageLine = Vec<RenderedImageCell>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderedImageCell {
    pub symbol: char,
    pub color: Option<(u8, u8, u8)>,
}

pub fn prepare_image_path(
    path: &Path,
    max_encoded_bytes: usize,
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
    if bytes.is_empty() || bytes.len() > max_encoded_bytes {
        return Err(ImageMediaError::EncodedPreviewTooLarge {
            actual: bytes.len(),
            maximum: max_encoded_bytes,
        });
    }
    let rendered = render_image_bytes(&bytes)?;
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
        rendered,
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

pub fn render_image_bytes(bytes: &[u8]) -> Result<RenderedImage, ImageMediaError> {
    if bytes.is_empty() || bytes.len() > INLINE_IMAGE_TRANSFER_MAX_BYTES {
        return Err(ImageMediaError::InvalidSourceSize(bytes.len() as u64));
    }
    let reader = image::ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(ImageMediaError::IoWithoutPath)?;
    let (width, height) = reader.into_dimensions().map_err(ImageMediaError::Decode)?;
    validate_dimensions(width, height)?;
    let decoded = image::load_from_memory(bytes).map_err(ImageMediaError::Decode)?;
    render_decoded_image(&decoded)
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
    let preview = if decoded.width() > IMAGE_TRANSFER_MAX_DIMENSION
        || decoded.height() > IMAGE_TRANSFER_MAX_DIMENSION
    {
        decoded.resize(
            IMAGE_TRANSFER_MAX_DIMENSION,
            IMAGE_TRANSFER_MAX_DIMENSION,
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

fn render_decoded_image(decoded: &DynamicImage) -> Result<RenderedImage, ImageMediaError> {
    validate_dimensions(decoded.width(), decoded.height())?;
    let width = IMAGE_RENDER_WIDTH;
    let ratio = f64::from(decoded.height()) / f64::from(decoded.width());
    let line_count = (f64::from(width) * ratio * 0.5).ceil().max(1.0) as usize;
    if line_count > MAX_IMAGE_LINES {
        return Err(ImageMediaError::RenderedImageTooTall {
            actual: line_count,
            maximum: MAX_IMAGE_LINES,
        });
    }
    let sample_width = width.saturating_mul(2);
    let sample_height = u32::try_from(line_count)
        .unwrap_or(u32::MAX)
        .saturating_mul(4);
    let color = decoded.to_rgb8();
    let color = image::imageops::resize(&color, sample_width, sample_height, FilterType::Lanczos3);
    let gray = decoded.to_luma8();
    let gray = image::imageops::resize(&gray, sample_width, sample_height, FilterType::Lanczos3);
    let mask = dither_mask(gray.as_raw(), sample_width as usize, sample_height as usize);
    Ok(RenderedImage {
        lines: braille_lines(&color, &mask, width as usize, line_count),
    })
}

fn dither_mask(gray: &[u8], width: usize, height: usize) -> Vec<bool> {
    let (minimum, maximum) = gray
        .iter()
        .fold((u8::MAX, u8::MIN), |(minimum, maximum), value| {
            (minimum.min(*value), maximum.max(*value))
        });
    let range = f32::from(maximum.saturating_sub(minimum));
    let mut values = gray
        .iter()
        .map(|value| {
            if range == 0.0 {
                f32::from(*value)
            } else {
                f32::from(value.saturating_sub(minimum)) * 255.0 / range
            }
        })
        .collect::<Vec<_>>();
    let mut mask = vec![false; values.len()];
    for y in 0..height {
        for x in 0..width {
            let index = y * width + x;
            let old = values[index].clamp(0.0, 255.0);
            let new = if old >= 128.0 { 255.0 } else { 0.0 };
            mask[index] = new > 0.0;
            let error = old - new;
            diffuse(&mut values, width, height, x + 1, y, error * 7.0 / 16.0);
            if x > 0 {
                diffuse(&mut values, width, height, x - 1, y + 1, error * 3.0 / 16.0);
            }
            diffuse(&mut values, width, height, x, y + 1, error * 5.0 / 16.0);
            diffuse(&mut values, width, height, x + 1, y + 1, error / 16.0);
        }
    }
    mask
}

fn diffuse(values: &mut [f32], width: usize, height: usize, x: usize, y: usize, error: f32) {
    if x < width && y < height {
        values[y * width + x] += error;
    }
}

fn braille_lines(
    color: &RgbImage,
    mask: &[bool],
    character_width: usize,
    line_count: usize,
) -> Vec<RenderedImageLine> {
    const DOT_BITS: [[u8; 2]; 4] = [[0, 3], [1, 4], [2, 5], [6, 7]];
    let sample_width = character_width * 2;
    let mut lines = Vec::with_capacity(line_count);
    for line_index in 0..line_count {
        let mut line = Vec::with_capacity(character_width);
        for character_x in 0..character_width {
            let mut dots = 0_u8;
            let mut red = 0_u32;
            let mut green = 0_u32;
            let mut blue = 0_u32;
            let mut samples = 0_u32;
            for (dy, bits) in DOT_BITS.iter().enumerate() {
                for (dx, bit) in bits.iter().enumerate() {
                    let x = character_x * 2 + dx;
                    let y = line_index * 4 + dy;
                    if mask[y * sample_width + x] {
                        dots |= 1_u8 << *bit;
                        let pixel = color.get_pixel(x as u32, y as u32).0;
                        red += u32::from(pixel[0]);
                        green += u32::from(pixel[1]);
                        blue += u32::from(pixel[2]);
                        samples += 1;
                    }
                }
            }
            let color = (samples > 0).then(|| {
                (
                    (red / samples) as u8,
                    (green / samples) as u8,
                    (blue / samples) as u8,
                )
            });
            line.push(RenderedImageCell {
                symbol: char::from_u32(0x2800 + u32::from(dots)).unwrap_or(' '),
                color,
            });
        }
        lines.push(line);
    }
    lines
}

#[derive(Debug, Error)]
pub enum ImageMediaError {
    #[error("image path is not a regular file: {0}")]
    NotAFile(PathBuf),
    #[error("image filename is invalid: {0}")]
    InvalidFilename(PathBuf),
    #[error("image source must contain 1 to 52428800 bytes, got {0}")]
    InvalidSourceSize(u64),
    #[error("image dimensions are unsafe: {width}x{height}")]
    InvalidDimensions { width: u32, height: u32 },
    #[error("encoded image preview is too large: {actual} bytes; maximum is {maximum}")]
    EncodedPreviewTooLarge { actual: usize, maximum: usize },
    #[error("terminal image would require {actual} lines; maximum is {maximum}")]
    RenderedImageTooTall { actual: usize, maximum: usize },
    #[error("image I/O failed for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("image I/O failed: {0}")]
    IoWithoutPath(#[source] std::io::Error),
    #[error("image decode failed: {0}")]
    Decode(#[source] image::ImageError),
    #[error("image preview encode failed: {0}")]
    Encode(#[source] image::ImageError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgba};

    fn test_png() -> Vec<u8> {
        let image = DynamicImage::ImageRgba8(ImageBuffer::from_fn(8, 8, |x, y| {
            Rgba([(x * 24) as u8, (y * 24) as u8, 160, 255])
        }));
        let mut cursor = Cursor::new(Vec::new());
        image
            .write_to(&mut cursor, ImageFormat::Png)
            .expect("encode test image");
        cursor.into_inner()
    }

    #[test]
    fn received_image_renders_without_filesystem_storage() {
        let rendered = render_image_bytes(&test_png()).expect("render image");

        assert!(!rendered.lines.is_empty());
        assert!(rendered.lines.len() <= MAX_IMAGE_LINES);
        assert!(
            rendered
                .lines
                .iter()
                .all(|line| line.len() == IMAGE_RENDER_WIDTH as usize)
        );
    }

    #[test]
    fn excessive_dimensions_are_rejected() {
        assert!(matches!(
            validate_dimensions(5_000, 5_000),
            Err(ImageMediaError::InvalidDimensions { .. })
        ));
    }

    #[test]
    fn opaque_large_images_become_bounded_jpeg_previews() {
        let source = DynamicImage::ImageRgb8(ImageBuffer::from_fn(2_000, 1_000, |x, y| {
            image::Rgb([(x % 255) as u8, (y % 255) as u8, 120])
        }));
        let (bytes, mime) = encode_preview(source).expect("encode preview");
        let preview = image::load_from_memory(&bytes).expect("decode preview");

        assert_eq!(mime, "image/jpeg");
        assert!(preview.width() <= IMAGE_TRANSFER_MAX_DIMENSION);
        assert!(preview.height() <= IMAGE_TRANSFER_MAX_DIMENSION);
    }

    #[test]
    fn alpha_images_remain_png_previews() {
        let source =
            DynamicImage::ImageRgba8(ImageBuffer::from_pixel(8, 8, Rgba([10, 20, 30, 80])));
        let (_, mime) = encode_preview(source).expect("encode preview");

        assert_eq!(mime, "image/png");
    }
}
