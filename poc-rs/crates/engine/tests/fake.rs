//! The fake engine: Go-compatible identity, deterministic pixels, progress
//! and cancellation.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use db_engine::{Engine, EngineError, Fake, Output};
use db_wire::JobRequest;
use sha2::{Digest as _, Sha256};
use std::sync::Mutex;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn request(prompt: &str, seed: i64, width: i64, height: i64, steps: i64) -> JobRequest {
    let mut r = JobRequest::default();
    r.v = 1;
    r.job_id = "job-1".to_owned();
    r.model = "fake-image".to_owned();
    r.workflow = "fake-t2i".to_owned();
    r.prompt = prompt.to_owned();
    r.seed = seed;
    r.width = width;
    r.height = height;
    r.steps = steps;
    r
}

async fn run(f: &Fake, req: &JobRequest, cancel: CancellationToken) -> (Result<Output, EngineError>, Vec<(i64, i64)>) {
    let calls = Mutex::new(Vec::new());
    let progress = |s: i64, t: i64| calls.lock().unwrap().push((s, t));
    let out = f.generate(req, &progress, cancel).await;
    (out, calls.into_inner().unwrap())
}

fn fnv1a64(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3))
}

/// Decodes a PNG into (width, height, color type, pixel bytes).
fn decode(png_bytes: &[u8]) -> (u32, u32, png::ColorType, Vec<u8>) {
    let reader = png::Decoder::new(std::io::Cursor::new(png_bytes));
    let mut reader = reader.read_info().unwrap();
    let mut buf = vec![0u8; reader.output_buffer_size().unwrap()];
    let info = reader.next_frame(&mut buf).unwrap();
    buf.truncate(info.buffer_size());
    (info.width, info.height, info.color_type, buf)
}

#[test]
fn identity_matches_go() {
    let f = Fake::default();
    assert_eq!(f.name(), "fake-engine");
    let wf = f.workflows();
    assert_eq!(wf.len(), 1);
    assert_eq!(wf[0].name, "fake-t2i");
    assert_eq!(wf[0].sha256, hex::encode(Sha256::digest(b"fake-t2i")));
    let m = f.models();
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].id, "fake-image");
    assert_eq!(m[0].files[0].name, "fake.safetensors");
    assert_eq!(m[0].files[0].sha256, hex::encode(Sha256::digest(b"fake-model")));
    let caps = db_gojson::to_vec(&f.caps()).unwrap();
    assert_eq!(
        String::from_utf8(caps).unwrap(),
        r#"[{"id":"fake-image","kind":"image","workflows":["fake-t2i"],"max_width":1024,"max_height":1024,"max_steps":8}]"#
    );
}

#[tokio::test]
async fn deterministic_gradient_png() {
    let f = Fake::default();
    let req = request("a lighthouse at dusk, <oil> & \"ink\"", -42, 1024, 512, 4);
    let (out, calls) = run(&f, &req, CancellationToken::new()).await;
    let out = out.unwrap();
    assert_eq!(calls, vec![(1, 4), (2, 4), (3, 4), (4, 4)]);
    assert_eq!(out.mime, "image/png");
    assert_eq!(out.units.images, 1);
    assert_eq!(out.units.steps, 4);
    assert_eq!(out.units.megapixels, 1024.0 * 512.0 / 1e6);
    assert_eq!(out.units.video_seconds, 0.0);
    assert!(out.units.gpu_millis >= 0);
    let (w, h, color, px) = decode(&out.data);
    assert_eq!((w, h, color), (256, 128, png::ColorType::Rgb));
    let seed = fnv1a64(req.prompt.as_bytes()) ^ (req.seed as u64);
    for y in 0..h as usize {
        for x in 0..w as usize {
            let p = &px[(y * w as usize + x) * 3..][..3];
            let want = [((seed >> 8) as u8).wrapping_add(x as u8), ((seed >> 16) as u8).wrapping_add(y as u8), (seed >> 24) as u8];
            assert_eq!(p, want, "pixel ({x},{y})");
        }
    }
    // Same request, same image; another prompt or seed, another image.
    let (again, _) = run(&f, &req, CancellationToken::new()).await;
    assert_eq!(decode(&again.unwrap().data).3, px);
    let (other, _) = run(&f, &request("a lighthouse at dawn", -42, 1024, 512, 4), CancellationToken::new()).await;
    assert_ne!(decode(&other.unwrap().data).3, px);
    let (reseeded, _) = run(&f, &request(&req.prompt, 7, 1024, 512, 4), CancellationToken::new()).await;
    assert_ne!(decode(&reseeded.unwrap().data).3, px);
}

#[tokio::test]
async fn refuses_other_models_and_bad_sizes() {
    let f = Fake::default();
    let mut req = request("x", 1, 512, 512, 2);
    req.model = "z-image-turbo".to_owned();
    let (out, calls) = run(&f, &req, CancellationToken::new()).await;
    assert!(out.unwrap_err().0.contains("does not serve z-image-turbo/fake-t2i"));
    assert!(calls.is_empty());
    let mut req = request("x", 1, 512, 512, 2);
    req.workflow = "other".to_owned();
    assert!(run(&f, &req, CancellationToken::new()).await.0.is_err());
    // Go's PNG encoder refuses an empty image; so do we.
    assert!(run(&f, &request("x", 1, 3, 512, 1), CancellationToken::new()).await.0.is_err());
    assert!(run(&f, &request("x", 1, i64::MAX, 512, 1), CancellationToken::new()).await.0.is_err());
}

#[tokio::test]
async fn cancellation_stops_the_job() {
    let f = Fake { delay: Duration::from_millis(40) };
    let req = request("x", 1, 256, 256, 8);
    let cancel = CancellationToken::new();
    let c2 = cancel.clone();
    let calls = Mutex::new(Vec::new());
    let progress = |s: i64, t: i64| {
        calls.lock().unwrap().push((s, t));
        if s == 2 {
            c2.cancel();
        }
    };
    let err = f.generate(&req, &progress, cancel).await.unwrap_err();
    assert!(err.is_cancelled(), "{err}");
    assert_eq!(calls.into_inner().unwrap(), vec![(1, 8), (2, 8)]);
    // Already cancelled with no delay: stops before the first step.
    let cancel = CancellationToken::new();
    cancel.cancel();
    let (out, calls) = run(&Fake::default(), &req, cancel).await;
    assert!(out.unwrap_err().is_cancelled());
    assert!(calls.is_empty());
    assert!(!EngineError("other".to_owned()).is_cancelled());
}

#[tokio::test]
async fn delay_is_applied_per_step() {
    let f = Fake { delay: Duration::from_millis(20) };
    let start = std::time::Instant::now();
    let (out, calls) = run(&f, &request("x", 1, 256, 256, 3), CancellationToken::new()).await;
    out.unwrap();
    assert_eq!(calls.len(), 3);
    assert!(start.elapsed() >= Duration::from_millis(60));
}
