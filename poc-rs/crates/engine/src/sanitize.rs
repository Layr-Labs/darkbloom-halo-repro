//! Consumer-supplied input images (Go `engine.SanitizeImage`).
//!
//! The image is decoded with memory-safe pure-Rust decoders (`png`, and
//! `jpeg-decoder` built with `platform_independent`, which makes it
//! `#![forbid(unsafe_code)]`), its dimensions are checked from the header
//! before any pixel data is decoded (decompression bombs), and it is
//! re-encoded as a plain 8-bit PNG. Only the re-encoded bytes ever reach the
//! engine's Python decoders, so a malformed file aimed at Pillow or
//! torchvision cannot be used against the engine, which also holds other
//! consumers' jobs over its lifetime.

use crate::EngineError;
use std::io::Cursor;
use zeroize::Zeroizing;

/// Largest accepted input image side.
pub const MAX_INPUT_SIDE: u32 = 4096;
/// Most accepted input image pixels.
pub const MAX_INPUT_PIXELS: u64 = 4096 * 4096;

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";
const JPEG_MAGIC: &[u8] = b"\xff\xd8";

fn undecodable() -> EngineError {
    EngineError("input image does not decode".to_owned())
}

fn check_dimensions(width: u32, height: u32) -> Result<(), EngineError> {
    if width == 0
        || height == 0
        || width > MAX_INPUT_SIDE
        || height > MAX_INPUT_SIDE
        || u64::from(width) * u64::from(height) > MAX_INPUT_PIXELS
    {
        return Err(EngineError("input image dimensions out of range".to_owned()));
    }
    Ok(())
}

/// Decoded 8-bit pixels.
struct Pixels {
    width: u32,
    height: u32,
    color: png::ColorType,
    data: Zeroizing<Vec<u8>>,
}

fn decode_png(input: &[u8]) -> Result<Pixels, EngineError> {
    // IHDR is the first chunk: length 13, then width and height at 16..24.
    let ihdr = input.get(8..24).ok_or_else(undecodable)?;
    if ihdr.get(0..8) != Some(b"\x00\x00\x00\x0dIHDR".as_slice()) {
        return Err(undecodable());
    }
    let be32 = |b: Option<&[u8]>| b.and_then(|b| <[u8; 4]>::try_from(b).ok()).map(u32::from_be_bytes).ok_or_else(undecodable);
    let (width, height) = (be32(ihdr.get(8..12))?, be32(ihdr.get(12..16))?);
    if width == 0 || height == 0 {
        return Err(undecodable()); // invalid PNG, as Go's decoder reports
    }
    check_dimensions(width, height)?;
    let limits = png::Limits { bytes: (MAX_INPUT_PIXELS as usize) * 8 + (4 << 20) };
    let mut decoder = png::Decoder::new_with_limits(Cursor::new(input), limits);
    decoder.set_transformations(png::Transformations::normalize_to_color8());
    let mut reader = decoder.read_info().map_err(|_| undecodable())?;
    let size = reader.output_buffer_size().ok_or_else(undecodable)?;
    let mut data = Zeroizing::new(vec![0u8; size]);
    let info = reader.next_frame(&mut data).map_err(|_| undecodable())?;
    check_dimensions(info.width, info.height)?;
    if info.bit_depth != png::BitDepth::Eight {
        return Err(undecodable());
    }
    data.truncate(info.buffer_size());
    Ok(Pixels { width: info.width, height: info.height, color: info.color_type, data })
}

/// Go's `color.CMYK` to RGB conversion, to 8 bits.
fn cmyk_to_rgb(c: u8, m: u8, y: u8, k: u8) -> [u8; 3] {
    let w = 0xffff - u32::from(k) * 0x101;
    let ch = |v: u8| (((0xffff - u32::from(v) * 0x101) * w / 0xffff) >> 8) as u8;
    [ch(c), ch(m), ch(y)]
}

fn decode_jpeg(input: &[u8]) -> Result<Pixels, EngineError> {
    let mut decoder = jpeg_decoder::Decoder::new(Cursor::new(input));
    decoder.read_info().map_err(|_| undecodable())?;
    let info = decoder.info().ok_or_else(undecodable)?;
    let (width, height) = (u32::from(info.width), u32::from(info.height));
    check_dimensions(width, height)?;
    decoder.set_max_decoding_buffer_size((MAX_INPUT_PIXELS as usize) * 4);
    let raw = Zeroizing::new(decoder.decode().map_err(|_| undecodable())?);
    let pixels = usize::try_from(u64::from(width) * u64::from(height)).map_err(|_| undecodable())?;
    let (color, data) = match info.pixel_format {
        jpeg_decoder::PixelFormat::L8 => (png::ColorType::Grayscale, Zeroizing::new(raw.get(..pixels).ok_or_else(undecodable)?.to_vec())),
        jpeg_decoder::PixelFormat::RGB24 => (png::ColorType::Rgb, Zeroizing::new(raw.get(..pixels * 3).ok_or_else(undecodable)?.to_vec())),
        jpeg_decoder::PixelFormat::CMYK32 => {
            let src = raw.get(..pixels * 4).ok_or_else(undecodable)?;
            let mut rgb = Zeroizing::new(Vec::with_capacity(pixels * 3));
            for &[c, m, y, k] in src.as_chunks::<4>().0 {
                rgb.extend_from_slice(&cmyk_to_rgb(c, m, y, k));
            }
            (png::ColorType::Rgb, rgb)
        }
        // Like Go's image/jpeg, which supports neither 12-bit nor lossless.
        jpeg_decoder::PixelFormat::L16 => return Err(undecodable()),
    };
    Ok(Pixels { width, height, color, data })
}

fn encode_png(p: &Pixels) -> Result<Vec<u8>, EngineError> {
    let enc_err = |e: png::EncodingError| EngineError(format!("re-encode input image: {e}"));
    // Room for the whole encoding up front: a reallocation would leave a
    // partial copy of the image behind.
    let mut out = Vec::with_capacity(p.data.len() + p.data.len() / 64 + p.height as usize + 4096);
    {
        let mut enc = png::Encoder::new(&mut out, p.width, p.height);
        enc.set_color(p.color);
        enc.set_depth(png::BitDepth::Eight);
        enc.set_compression(png::Compression::Fast);
        let mut writer = enc.write_header().map_err(enc_err)?;
        writer.write_image_data(&p.data).map_err(enc_err)?;
        writer.finish().map_err(enc_err)?;
    }
    Ok(out)
}

/// Decodes a consumer-supplied PNG or JPEG with memory-safe decoders,
/// enforces the size limits before decoding pixel data, and re-encodes it
/// as an 8-bit PNG (fast compression). Anything else is refused. Error texts
/// match Go's (`does not decode`, `dimensions out of range`).
pub fn sanitize_image(input: &[u8]) -> Result<Vec<u8>, EngineError> {
    let decode: fn(&[u8]) -> Result<Pixels, EngineError> = if input.starts_with(PNG_MAGIC) {
        decode_png
    } else if input.starts_with(JPEG_MAGIC) {
        decode_jpeg
    } else {
        // Go's image.DecodeConfig knows no other format: "does not decode".
        return Err(undecodable());
    };
    // Defence in depth: a decoder bug must fail this job, not the agent.
    let pixels = std::panic::catch_unwind(|| decode(input)).map_err(|_| undecodable())??;
    encode_png(&pixels)
}
