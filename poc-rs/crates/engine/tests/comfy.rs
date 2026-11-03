//! The ComfyUI adapter's job flow against a mock ComfyUI: results, errors,
//! cancellation, purging and prompt isolation.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

mod mock;
mod support;

use mock::Mode;
use serde_json::{Value, json};
use std::time::Duration;
use support::{WAN_FILES, Z_FILES, env, generate, image_request, pos, video_request};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn image_job_happy_path() {
    let e = env(Mode::Complete, &Z_FILES).await;
    let c = e.comfy().await;
    let req = image_request("a red fox in the snow");
    let (out, calls) = generate(&c, &req, CancellationToken::new()).await;
    let out = out.unwrap();
    assert_eq!(out.data.as_slice(), e.server.with(|m| m.content.clone()).as_slice());
    assert_eq!(out.mime, "image/png");
    assert_eq!((out.units.images, out.units.megapixels, out.units.steps), (1, 1.048576, 8));
    assert_eq!(out.units.video_seconds, 0.0);
    assert_eq!(calls, vec![(0, 8), (8, 8)]);

    let body = e.server.with(|m| m.prompts[0].clone());
    let graph = &body["prompt"];
    let prefix = graph["9"]["inputs"]["filename_prefix"].as_str().unwrap().to_owned();
    let tag = prefix.strip_prefix("dbjob-").unwrap();
    assert!(tag.len() == 16 && tag.bytes().all(|b| b.is_ascii_hexdigit()), "{prefix}");
    assert_eq!(body["client_id"], json!(format!("{tag}-agent")));
    assert_eq!(graph["27"]["inputs"]["text"], json!("a red fox in the snow"));
    assert_eq!(graph["3"]["inputs"]["seed"], json!(42));
    assert_eq!(graph["3"]["inputs"]["steps"], json!(8));
    assert_eq!(graph["13"]["inputs"], json!({"width": 1024, "height": 1024, "batch_size": 1}));
    assert_eq!(e.server.with(|m| m.view_queries.clone()), vec![format!("filename={prefix}_00001_.png&subfolder=&type=output")]);

    // Purged: no interrupt (it finished), history deleted, files gone.
    let ev = e.server.events();
    assert!(!ev.iter().any(|x| x.starts_with("interrupt")), "{ev:?}");
    assert!(pos(&ev, &format!("view {prefix}_00001_.png")) < pos(&ev, "history-delete prompt-1"));
    assert_eq!(e.server.with(|m| m.history_posts.clone()), vec![json!({"delete": ["prompt-1"]})]);
    assert_eq!(e.server.retained(), 0);
    assert!(e.job_files().is_empty());
}

#[tokio::test]
async fn video_job_happy_path() {
    let e = env(Mode::Complete, &WAN_FILES).await;
    let c = e.comfy().await;
    let (out, calls) = generate(&c, &video_request("waves at night"), CancellationToken::new()).await;
    let out = out.unwrap();
    assert_eq!(out.mime, "video/mp4");
    assert_eq!(calls, vec![(0, 20), (20, 20)]);
    let mut units = out.units.clone();
    units.gpu_millis = 0;
    assert_eq!(
        String::from_utf8(db_gojson::to_vec(&units).unwrap()).unwrap(),
        r#"{"megapixels":0.39936,"steps":20,"video_seconds":2.0625,"gpu_ms":0}"#
    );
    let graph = e.server.with(|m| m.prompts[0]["prompt"].clone());
    assert_eq!(graph["6"]["inputs"]["text"], json!("waves at night"));
    assert!(graph["7"]["inputs"]["text"].as_str().unwrap().starts_with("色调艳丽，过曝"), "default Wan negative prompt");
    assert_eq!(graph["40"]["inputs"], json!({"width": 832, "height": 480, "length": 33, "batch_size": 1}));
    assert_eq!(graph["49"]["inputs"], json!({"images": ["8", 0], "fps": 16}));
    assert_eq!(graph["50"]["inputs"]["format"], json!("mp4"));
    assert!(e.job_files().is_empty());

    let mut req = video_request("waves");
    req.negative_prompt = "blurry".to_owned();
    generate(&c, &req, CancellationToken::new()).await.0.unwrap();
    assert_eq!(e.server.with(|m| m.prompts[1]["prompt"]["7"]["inputs"]["text"].clone()), json!("blurry"));
}

#[tokio::test]
async fn execution_error_and_missing_output_are_purged() {
    for (mode, want) in [(Mode::ExecError, "execution error"), (Mode::NoOutput, "produced no output")] {
        let e = env(mode, &Z_FILES).await;
        let c = e.comfy().await;
        let err = generate(&c, &image_request("x"), CancellationToken::new()).await.0.unwrap_err();
        assert!(err.0.contains(want), "{err}");
        assert!(!err.is_cancelled());
        let ev = e.server.events();
        assert!(ev.contains(&"history-delete prompt-1".to_owned()), "{ev:?}");
        assert!(!ev.iter().any(|x| x.starts_with("interrupt")), "{ev:?}");
        assert_eq!(e.server.retained(), 0);
        assert!(e.job_files().is_empty());
    }
}

#[tokio::test]
async fn cancellation_interrupts_and_purges() {
    let e = env(Mode::Hang, &Z_FILES).await;
    let c = e.comfy().await;
    let cancel = CancellationToken::new();
    let canceller = async {
        e.eventually("the job to run", |e| e.server.events().contains(&"history-get prompt-1".to_owned())).await;
        cancel.cancel();
    };
    let req = image_request("x");
    let ((res, calls), ()) = tokio::join!(generate(&c, &req, cancel.clone()), canceller);
    assert!(res.unwrap_err().is_cancelled());
    assert_eq!(calls, vec![(0, 8)]);
    let ev = e.server.events();
    let (i, q, h) = (pos(&ev, "interrupt prompt-1"), pos(&ev, "queue-delete prompt-1"), pos(&ev, "history-delete prompt-1"));
    assert!(i < q && q < h, "{ev:?}");
    // It waited for ComfyUI to drop the prompt before deleting its history.
    assert!(ev[q..h].iter().filter(|x| *x == "queue-get").count() >= 2, "{ev:?}");
    assert_eq!(e.server.with(|m| m.interrupts.clone()), vec![json!({"prompt_id": "prompt-1"})]);
    assert_eq!(e.server.with(|m| m.queue_posts.clone()), vec![json!({"delete": ["prompt-1"]})]);
    assert_eq!(e.server.retained(), 0, "the interrupted prompt must not stay in history");
    assert!(e.job_files().is_empty());
}

#[tokio::test]
async fn dropped_future_still_purges_and_releases_the_gpu() {
    let e = env(Mode::Hang, &Z_FILES).await;
    let c = e.comfy().await;
    let req = image_request("x");
    let timed = tokio::time::timeout(Duration::from_millis(700), generate(&c, &req, CancellationToken::new())).await;
    assert!(timed.is_err(), "job should still be running");
    e.eventually("the background purge", |e| {
        e.server.events().contains(&"history-delete prompt-1".to_owned()) && e.server.retained() == 0 && e.job_files().is_empty()
    })
    .await;
    let ev = e.server.events();
    assert!(pos(&ev, "interrupt prompt-1") < pos(&ev, "history-delete prompt-1"));
    // The next job runs once the purge released the GPU.
    e.server.with(|m| m.mode = Mode::Complete);
    generate(&c, &image_request("y"), CancellationToken::new()).await.0.unwrap();
    let ev = e.server.events();
    assert!(pos(&ev, "history-delete prompt-1") < pos(&ev, "prompt prompt-2"));
}

#[tokio::test]
async fn one_job_at_a_time() {
    let e = env(Mode::Complete, &Z_FILES).await;
    e.server.with(|m| m.polls = 2);
    let c = e.comfy().await;
    let (first, second) = (image_request("first"), image_request("second"));
    let (a, b) = tokio::join!(generate(&c, &first, CancellationToken::new()), generate(&c, &second, CancellationToken::new()));
    a.0.unwrap();
    b.0.unwrap();
    let ev = e.server.events();
    assert!(pos(&ev, "history-delete prompt-1") < pos(&ev, "prompt prompt-2"), "{ev:?}");
}

#[tokio::test]
async fn prompt_cannot_alter_the_graph() {
    let e = env(Mode::Complete, &Z_FILES).await;
    let c = e.comfy().await;
    let normalize = |mut g: Value| {
        g["27"]["inputs"]["text"] = json!("");
        g["9"]["inputs"]["filename_prefix"] = json!("");
        g
    };
    generate(&c, &image_request("benign"), CancellationToken::new()).await.0.unwrap();
    let reference = normalize(e.server.with(|m| m.prompts[0]["prompt"].clone()));
    let hostile = [
        "\"}",
        "\"}}, \"99\": {\"class_type\": \"SaveImage\", \"inputs\": {\"images\": [\"8\", 0]}}, \"x\": {\"y\": \"",
        "{}[]\\\"\\\\ <script>&amp; \u{2028}\u{2029}",
        "\u{0}\u{1}\u{1f}\u{7f} ünïcödé 中文 🙂",
        "\n\t\r\\u0022 }",
    ];
    for (i, p) in hostile.iter().enumerate() {
        generate(&c, &image_request(p), CancellationToken::new()).await.0.unwrap();
        let graph = e.server.with(|m| m.prompts[i + 1]["prompt"].clone());
        assert_eq!(graph["27"]["inputs"]["text"], json!(p), "prompt must arrive verbatim as one string");
        assert_eq!(normalize(graph), reference, "prompt {p:?} changed the graph");
    }
}

#[tokio::test]
async fn limits_are_enforced_before_contacting_comfyui() {
    let e = env(Mode::Complete, &[&Z_FILES[..], &WAN_FILES[..]].concat()).await;
    let c = e.comfy().await;
    let mut bad = Vec::new();
    let mut r = image_request("x");
    r.width = 2064;
    bad.push(r);
    let mut r = image_request("x");
    r.steps = 17;
    bad.push(r);
    let mut r = image_request("x");
    r.frames = 5;
    bad.push(r);
    let mut r = image_request("x");
    r.workflow = "wan2.1-t2v".to_owned();
    bad.push(r);
    for frames in [0, 32, 85] {
        let mut r = video_request("x");
        r.frames = frames;
        bad.push(r);
    }
    let mut r = video_request("x");
    r.fps = 0;
    bad.push(r);
    let mut r = video_request("x");
    r.height = 832;
    bad.push(r);
    // No compiled-in workflow takes an input image: consumer bytes never
    // reach ComfyUI's decoders.
    let mut r = image_request("x");
    r.input_image = b"\x89PNG\r\n\x1a\n...".to_vec();
    bad.push(r);
    for r in &bad {
        assert!(generate(&c, r, CancellationToken::new()).await.0.is_err(), "{r:?}");
    }
    assert!(e.server.with(|m| m.prompts.is_empty()));
}

#[tokio::test]
async fn rejected_prompt_error_does_not_echo_the_prompt() {
    let e = env(Mode::Reject, &Z_FILES).await;
    let c = e.comfy().await;
    let secret = "a very secret prompt with \"quotes\", ünïcode and 中文";
    let err = generate(&c, &image_request(secret), CancellationToken::new()).await.0.unwrap_err();
    let text = err.to_string();
    assert!(text.contains("400") && text.contains("Prompt outputs failed validation"), "{text}");
    assert!(text.contains("CLIPTextEncode") && text.contains("Value not in list"), "{text}");
    assert!(!text.contains("very secret") && !text.contains("u00fcn"), "{text}");
    assert!(e.job_files().is_empty());
}
