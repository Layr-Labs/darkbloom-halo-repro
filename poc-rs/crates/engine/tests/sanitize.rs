//! Input-image sanitizing (port of Go's sanitize_test.go, plus format,
//! limit and robustness cases).

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use db_engine::{Engine as _, Fake, sanitize_image};
use tokio_util::sync::CancellationToken;

/// A 24x16 baseline 4:2:0 JPEG written by Go's image/jpeg (quality 90).
const JPEG_HEX: &str = include_str!("data/gradient.jpg.hex");

fn png_bytes(w: u32, h: u32, color: png::ColorType, depth: png::BitDepth, data: &[u8], palette: Option<(&[u8], &[u8])>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut enc = png::Encoder::new(&mut out, w, h);
    enc.set_color(color);
    enc.set_depth(depth);
    if let Some((plte, trns)) = palette {
        enc.set_palette(plte.to_vec());
        enc.set_trns(trns.to_vec());
    }
    let mut writer = enc.write_header().unwrap();
    writer.write_image_data(data).unwrap();
    writer.finish().unwrap();
    out
}

fn rgba_64x32() -> Vec<u8> {
    let mut px = vec![0u8; 64 * 32 * 4];
    for (i, p) in px.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        *p = [(i % 64) as u8 * 4, (i / 64) as u8 * 8, 7, 255 - (i % 64) as u8];
    }
    px[(3 * 64 + 3) * 4..][..4].copy_from_slice(&[255, 0, 0, 255]);
    png_bytes(64, 32, png::ColorType::Rgba, png::BitDepth::Eight, &px, None)
}

fn decode(b: &[u8]) -> (u32, u32, png::ColorType, png::BitDepth, Vec<u8>) {
    let mut r = png::Decoder::new(std::io::Cursor::new(b)).read_info().unwrap();
    let mut buf = vec![0u8; r.output_buffer_size().unwrap()];
    let info = r.next_frame(&mut buf).unwrap();
    buf.truncate(info.buffer_size());
    (info.width, info.height, info.color_type, info.bit_depth, buf)
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 == 1 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
        }
    }
    !c
}

/// Rewrites the IHDR size (with a valid CRC, so only the limits reject it).
fn with_ihdr(p: &[u8], w: u32, h: u32) -> Vec<u8> {
    let mut out = p.to_vec();
    out[16..20].copy_from_slice(&w.to_be_bytes());
    out[20..24].copy_from_slice(&h.to_be_bytes());
    let crc = crc32(&out[12..29]);
    out[29..33].copy_from_slice(&crc.to_be_bytes());
    out
}

#[test]
fn png_round_trip() {
    let input = rgba_64x32();
    let out = sanitize_image(&input).unwrap();
    let (w, h, color, depth, px) = decode(&out);
    assert_eq!((w, h, color, depth), (64, 32, png::ColorType::Rgba, png::BitDepth::Eight));
    assert_eq!(&px[(3 * 64 + 3) * 4..][..4], &[255, 0, 0, 255]);
    assert_eq!(px, decode(&input).4, "pixels survive unchanged");
}

#[test]
fn rejects_other_formats_truncation_and_bombs() {
    let good = rgba_64x32();
    let msg = |b: &[u8]| sanitize_image(b).unwrap_err().to_string();
    assert_eq!(msg(b"GIF89a...."), "engine: input image does not decode");
    assert_eq!(msg(b""), "engine: input image does not decode");
    assert_eq!(msg(b"\xff"), "engine: input image does not decode");
    assert_eq!(msg(&good[..40]), "engine: input image does not decode");
    assert_eq!(msg(&with_ihdr(&good, 32768, 32768)), "engine: input image dimensions out of range");
    assert_eq!(msg(&with_ihdr(&good, 4097, 1)), "engine: input image dimensions out of range");
    assert_eq!(msg(&with_ihdr(&good, 1, 4097)), "engine: input image dimensions out of range");
    assert_eq!(msg(&with_ihdr(&good, 0, 32)), "engine: input image does not decode");
    // Go's test overwrites the size without fixing the CRC: still refused.
    let mut huge = good.clone();
    huge[16..24].copy_from_slice(&[0, 0, 0x80, 0, 0, 0, 0x80, 0]);
    assert!(sanitize_image(&huge).is_err());
    // A header claiming the maximum with too little data fails to decode.
    assert_eq!(msg(&with_ihdr(&good, 4096, 4096)), "engine: input image does not decode");
    let jpeg = hex::decode(JPEG_HEX.trim()).unwrap();
    assert_eq!(msg(&jpeg[..jpeg.len() / 2]), "engine: input image does not decode");
}

#[test]
fn largest_side_is_accepted() {
    let out = sanitize_image(&png_bytes(4096, 1, png::ColorType::Grayscale, png::BitDepth::Eight, &[9u8; 4096], None)).unwrap();
    assert_eq!(decode(&out).0, 4096);
}

#[test]
fn jpeg_is_reencoded_as_png() {
    let jpeg = hex::decode(JPEG_HEX.trim()).unwrap();
    let out = sanitize_image(&jpeg).unwrap();
    assert!(out.starts_with(b"\x89PNG\r\n\x1a\n"));
    let (w, h, color, _, px) = decode(&out);
    assert_eq!((w, h, color), (24, 16, png::ColorType::Rgb));
    // The source was (10x, 15y, 128): lossy, but close.
    let p = &px[(8 * 24 + 12) * 3..][..3];
    assert!(p[0].abs_diff(120) < 12 && p[1].abs_diff(120) < 12 && p[2].abs_diff(128) < 12, "{p:?}");
}

#[test]
fn palette_and_16_bit_images_become_8_bit() {
    let pal = png_bytes(
        4,
        2,
        png::ColorType::Indexed,
        png::BitDepth::Eight,
        &[0, 1, 2, 0, 1, 2, 0, 1],
        Some((&[0, 0, 0, 255, 0, 0, 0, 0, 255], &[0, 255, 128])),
    );
    let (_, _, color, depth, px) = decode(&sanitize_image(&pal).unwrap());
    assert_eq!((color, depth), (png::ColorType::Rgba, png::BitDepth::Eight));
    assert_eq!(&px[..12], &[0, 0, 0, 0, 255, 0, 0, 255, 0, 0, 255, 128]);
    let g16: Vec<u8> = (0..16u16).flat_map(|v| (v * 4000).to_be_bytes()).collect();
    let (_, _, color, depth, px) =
        decode(&sanitize_image(&png_bytes(4, 4, png::ColorType::Grayscale, png::BitDepth::Sixteen, &g16, None)).unwrap());
    assert_eq!((color, depth), (png::ColorType::Grayscale, png::BitDepth::Eight));
    assert_eq!(px, (0..16u16).map(|v| ((v * 4000) >> 8) as u8).collect::<Vec<_>>());
}

#[test]
fn never_panics_on_mutated_inputs() {
    let samples = [rgba_64x32(), hex::decode(JPEG_HEX.trim()).unwrap()];
    let mut s = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let mut accepted = 0;
    for i in 0..6000 {
        let mut b = samples[i % 2].clone();
        match next() % 4 {
            0 => b.truncate(next() as usize % b.len()),
            1 => {
                for _ in 0..1 + next() % 8 {
                    let j = next() as usize % b.len();
                    b[j] = next() as u8;
                }
            }
            2 => {
                let j = 8 + next() as usize % (b.len() - 8);
                let junk: Vec<u8> = (0..next() % 64).map(|_| next() as u8).collect();
                b.splice(j..j, junk);
            }
            _ => {
                let n = next() as usize % 512;
                b.truncate(2 + (i % 7));
                b.extend((0..n).map(|_| next() as u8));
            }
        }
        if let Ok(out) = sanitize_image(&b) {
            accepted += 1;
            assert!(out.starts_with(b"\x89PNG\r\n\x1a\n"));
            decode(&out);
        }
    }
    assert!(accepted > 0, "some mutations (e.g. in pixel data) still decode");
}

#[tokio::test]
async fn engines_refuse_input_images_for_text_workflows() {
    let mut req = db_wire::JobRequest::default();
    req.model = "fake-image".to_owned();
    req.workflow = "fake-t2i".to_owned();
    req.prompt = "x".to_owned();
    req.width = 256;
    req.height = 256;
    req.steps = 1;
    req.input_image = rgba_64x32();
    let err = Fake::default().generate(&req, &|_, _| {}, CancellationToken::new()).await.unwrap_err();
    assert_eq!(err.to_string(), "engine: workflow takes no input image");
}
