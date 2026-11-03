//! A deterministic CPU engine for tests and protocol demos (Go `engine.Fake`).

use crate::{BoxFuture, Engine, EngineError, Output, Progress};
use db_release::Artifact;
use db_tpmattest::ModelReport;
use db_wire::{JobRequest, ModelCap, Units};
use sha2::{Digest as _, Sha256};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const MODEL: &str = "fake-image";
const WORKFLOW: &str = "fake-t2i";

/// Largest rendered side in pixels (a quarter of the requested side). Valid
/// requests are far below it; it only stops absurd sizes from allocating.
const MAX_RENDER_SIDE: i64 = 4096;

/// A deterministic CPU engine for tests and protocol demos: it renders a
/// small gradient whose colours derive from the prompt and seed. It is
/// reported as `fake-engine` and never matches a production release.
#[derive(Debug, Clone, Copy, Default)]
pub struct Fake {
    /// Sleep per step (cancellable).
    pub delay: Duration,
}

fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// FNV-1a, 64-bit (Go's `hash/fnv.New64a`).
pub(crate) fn fnv1a64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn png_err(e: png::EncodingError) -> EngineError {
    EngineError(format!("png: {e}"))
}

/// Renders the `w`x`h` gradient for `seed` as an 8-bit PNG. Every pixel is
/// `(seed>>8 + x, seed>>16 + y, seed>>24)` (wrapping bytes, opaque), as in
/// the Go engine; Go's encoder writes opaque RGBA images as RGB, as here.
fn render_png(seed: u64, w: i64, h: i64) -> Result<Zeroizing<Vec<u8>>, EngineError> {
    if !(1..=MAX_RENDER_SIDE).contains(&w) || !(1..=MAX_RENDER_SIDE).contains(&h) {
        return Err(EngineError(format!("png: invalid image size: {w}x{h}")));
    }
    let bad = |_| EngineError("png: invalid image size".to_owned());
    let (wu, hu) = (usize::try_from(w).map_err(bad)?, usize::try_from(h).map_err(bad)?);
    let (w32, h32) = (u32::try_from(w).map_err(bad)?, u32::try_from(h).map_err(bad)?);
    let (r0, g0, b) = ((seed >> 8) as u8, (seed >> 16) as u8, (seed >> 24) as u8);
    let mut pixels = Zeroizing::new(Vec::with_capacity(wu * hu * 3));
    for y in 0..hu {
        for x in 0..wu {
            pixels.extend_from_slice(&[r0.wrapping_add(x as u8), g0.wrapping_add(y as u8), b]);
        }
    }
    // Room for the whole encoding up front, so no partial copy of the image
    // is left behind by a reallocation.
    let mut out = Zeroizing::new(Vec::with_capacity(pixels.len() + hu + 4096));
    {
        let mut enc = png::Encoder::new(&mut *out, w32, h32);
        enc.set_color(png::ColorType::Rgb);
        enc.set_depth(png::BitDepth::Eight);
        let mut writer = enc.write_header().map_err(png_err)?;
        writer.write_image_data(&pixels).map_err(png_err)?;
        writer.finish().map_err(png_err)?;
    }
    Ok(out)
}

impl Fake {
    async fn run(&self, req: &JobRequest, progress: Progress<'_>, cancel: CancellationToken) -> Result<Output, EngineError> {
        let start = Instant::now();
        if req.model != MODEL || req.workflow != WORKFLOW {
            return Err(EngineError(format!("fake engine does not serve {}/{}", req.model, req.workflow)));
        }
        if !req.input_image.is_empty() {
            return Err(EngineError("workflow takes no input image".to_owned()));
        }
        for i in 1..=req.steps {
            if self.delay.is_zero() {
                if cancel.is_cancelled() {
                    return Err(EngineError::cancelled());
                }
                tokio::task::yield_now().await;
            } else {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => return Err(EngineError::cancelled()),
                    () = tokio::time::sleep(self.delay) => {}
                }
            }
            progress(i, req.steps);
        }
        let seed = fnv1a64(req.prompt.as_bytes()) ^ (req.seed as u64);
        let data = render_png(seed, req.width / 4, req.height / 4)?;
        let units = Units {
            images: 1,
            megapixels: req.width.wrapping_mul(req.height) as f64 / 1e6,
            steps: req.steps,
            video_seconds: 0.0,
            gpu_millis: i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX),
            ..Units::default()
        };
        Ok(Output { data, mime: "image/png".to_owned(), units })
    }
}

impl Engine for Fake {
    fn name(&self) -> String {
        "fake-engine".to_owned()
    }

    fn workflows(&self) -> Vec<Artifact> {
        vec![Artifact { name: WORKFLOW.to_owned(), sha256: sha256_hex("fake-t2i"), bytes: 0 }]
    }

    fn models(&self) -> Vec<ModelReport> {
        vec![ModelReport {
            id: MODEL.to_owned(),
            files: vec![Artifact { name: "fake.safetensors".to_owned(), sha256: sha256_hex("fake-model"), bytes: 0 }],
        }]
    }

    fn caps(&self) -> Vec<ModelCap> {
        vec![ModelCap {
            id: MODEL.to_owned(),
            kind: "image".to_owned(),
            workflows: vec![WORKFLOW.to_owned()],
            max_width: 1024,
            max_height: 1024,
            max_steps: 8,
            max_frames: 0,
            max_tokens: 0,
        }]
    }

    fn generate<'a>(
        &'a self,
        req: &'a JobRequest,
        progress: Progress<'a>,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<Output, EngineError>> {
        Box::pin(self.run(req, progress, cancel))
    }
}

#[cfg(test)]
mod tests {
    use super::fnv1a64;

    #[test]
    fn fnv_matches_go() {
        // hash/fnv New64a test vectors.
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"ab"), 0x089c_4407_b545_986a);
        assert_eq!(fnv1a64(b"abc"), 0xe71f_a219_0541_574b);
    }
}
