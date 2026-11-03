//! The llama.cpp adapter against a bounded loopback mock and the real
//! supervisor marker protocol. No GPU or GGUF weights are needed.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use db_engine::{Engine, Llama, LlamaConfig, llama_release};
use db_wire::JobRequest;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const MODEL: &str = "test-text-model";
const WORKFLOW: &str = r#"{"v":1,"id":"llama-text-greedy-v1","endpoint":"/v1/completions","temperature":0,"cache_prompt":false}"#;

#[derive(Clone, Copy)]
enum Mode {
    Complete,
    Reject,
    Oversize,
    WrongModel,
    BadUsage,
    Hang,
}

struct MockState {
    generation: AtomicU64,
    data: Mutex<MockData>,
}

struct MockData {
    mode: Mode,
    requests: Vec<(u64, Value)>,
}

async fn health() -> Json<Value> {
    Json(json!({"status":"ok"}))
}

async fn complete(State(state): State<Arc<MockState>>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let mode = {
        let mut data = state.data.lock().unwrap();
        data.requests.push((state.generation.load(Ordering::SeqCst), body.clone()));
        data.mode
    };
    match mode {
        Mode::Complete => (
            StatusCode::OK,
            Json(json!({"model": MODEL, "choices": [{"text": "hello"}], "usage": {
                "prompt_tokens": 3,
                "completion_tokens": body["max_tokens"].as_i64().unwrap_or_default().min(2)
            }})),
        ),
        Mode::Reject => (StatusCode::BAD_REQUEST, Json(json!({"error":"PRIVATE-CANARY escaped by server"}))),
        Mode::Oversize => (
            StatusCode::OK,
            Json(
                json!({"model": MODEL, "choices": [{"text": "X".repeat((1 << 20) + 100)}], "usage": {"prompt_tokens": 3, "completion_tokens": 2}}),
            ),
        ),
        Mode::WrongModel => (
            StatusCode::OK,
            Json(
                json!({"model": "different-model", "choices": [{"text": "secret"}], "usage": {"prompt_tokens": 3, "completion_tokens": 2}}),
            ),
        ),
        Mode::BadUsage => (
            StatusCode::OK,
            Json(json!({"model": MODEL, "choices": [{"text": "secret"}], "usage": {"prompt_tokens": 3, "completion_tokens": 9999}})),
        ),
        Mode::Hang => {
            tokio::time::sleep(Duration::from_secs(60)).await;
            (
                StatusCode::OK,
                Json(json!({"model": MODEL, "choices": [{"text": "late"}], "usage": {"prompt_tokens": 3, "completion_tokens": 2}})),
            )
        }
    }
}

struct Env {
    _tmp: tempfile::TempDir,
    cfg: LlamaConfig,
    state: Arc<MockState>,
    server: JoinHandle<()>,
    supervisor: JoinHandle<()>,
}

impl Drop for Env {
    fn drop(&mut self) {
        self.server.abort();
        self.supervisor.abort();
    }
}

async fn env() -> Env {
    db_tls::install_default_provider();
    let tmp = tempfile::tempdir().unwrap();
    let model_path = tmp.path().join("model.gguf");
    let workflow_path = tmp.path().join("workflow.json");
    std::fs::write(&model_path, b"GGUF toy model bytes for engine tests").unwrap();
    std::fs::write(&workflow_path, WORKFLOW).unwrap();
    let model_sha256 = hex::encode(Sha256::digest(std::fs::read(&model_path).unwrap()));
    let recycle = tmp.path().join("control");
    std::fs::create_dir(&recycle).unwrap();
    std::fs::write(recycle.join("engine.gen"), "1 101\n").unwrap();
    let state =
        Arc::new(MockState { generation: AtomicU64::new(1), data: Mutex::new(MockData { mode: Mode::Complete, requests: Vec::new() }) });
    let router = Router::new().route("/health", get(health)).route("/v1/completions", post(complete)).with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let state_for_supervisor = state.clone();
    let control = recycle.clone();
    let supervisor = tokio::spawn(async move {
        loop {
            if control.join("restart").exists() {
                std::fs::remove_file(control.join("restart")).unwrap();
                let next = state_for_supervisor.generation.fetch_add(1, Ordering::SeqCst) + 1;
                std::fs::write(control.join("engine.gen"), format!("{next} {}\n", next + 100)).unwrap();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    let cfg = LlamaConfig {
        url: url.clone(),
        model_id: MODEL.to_owned(),
        model_path,
        model_sha256,
        workflow_path,
        max_tokens: 64,
        recycle: Some(recycle),
        warmup: false,
    };
    Env { _tmp: tmp, cfg, state, server, supervisor }
}

fn request(prompt: &str, max_tokens: i64) -> JobRequest {
    let mut req = JobRequest::default();
    req.v = 1;
    req.job_id = "job-1".to_owned();
    req.model = MODEL.to_owned();
    req.workflow = "llama-text-greedy-v1".to_owned();
    req.prompt = prompt.to_owned();
    req.max_tokens = max_tokens;
    req
}

async fn generate(engine: &Llama, req: &JobRequest, cancel: CancellationToken) -> Result<db_engine::Output, db_engine::EngineError> {
    engine.generate(req, &|_, _| {}, cancel).await
}

fn count(state: &MockState) -> usize {
    state.data.lock().unwrap().requests.len()
}

async fn eventually(mut predicate: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn release_and_successful_completion_are_pinned_and_bounded() {
    let e = env().await;
    let (workflows, models) = llama_release(MODEL, &e.cfg.model_path, &e.cfg.workflow_path).unwrap();
    assert_eq!(workflows[0].name, "llama-text-greedy-v1");
    assert_eq!(workflows[0].sha256, hex::encode(Sha256::digest(WORKFLOW)));
    assert_eq!(workflows[0].bytes, WORKFLOW.len() as i64);
    assert_eq!(models[0].kind, "text");
    assert_eq!(models[0].files.as_ref().unwrap()[0].name, "model.gguf");
    assert_eq!(models[0].files.as_ref().unwrap()[0].sha256, e.cfg.model_sha256);
    let source_named = e._tmp.path().join("Qwen-source-name.gguf");
    std::fs::copy(&e.cfg.model_path, &source_named).unwrap();
    let (_, from_source_name) = llama_release(MODEL, &source_named, &e.cfg.workflow_path).unwrap();
    assert_eq!(from_source_name[0].files.as_ref().unwrap()[0].name, "model.gguf");
    let engine = Llama::connect(e.cfg.clone()).await.unwrap();
    assert_eq!(engine.name(), "llama.cpp");
    assert_eq!(engine.models()[0].files, models[0].files.clone().unwrap());
    assert_eq!(engine.workflows(), workflows);
    let caps = engine.caps();
    assert_eq!((caps[0].kind.as_str(), caps[0].max_tokens, caps[0].max_width, caps[0].max_height), ("text", 64, 0, 0));
    let req = request("PRIVATE-CANARY", 8);
    let out = generate(&engine, &req, CancellationToken::new()).await.unwrap();
    assert_eq!(&*out.data, b"hello");
    assert_eq!(out.mime, "text/plain; charset=utf-8");
    assert_eq!((out.units.prompt_tokens, out.units.completion_tokens), (3, 2));
    let data = e.state.data.lock().unwrap();
    assert_eq!(data.requests.len(), 1);
    assert_eq!(
        data.requests[0].1,
        json!({
            "model": MODEL, "prompt": "PRIVATE-CANARY", "max_tokens": 8,
            "temperature": 0, "seed": 0, "cache_prompt": false, "stream": false
        })
    );
}

#[tokio::test]
async fn invalid_configuration_and_workflow_fail_before_serving() {
    let e = env().await;
    let mut cfg = e.cfg.clone();
    cfg.url = "http://example.com:8080".to_owned();
    assert!(Llama::connect(cfg).await.unwrap_err().to_string().contains("loopback"));
    let mut cfg = e.cfg.clone();
    cfg.model_sha256 = "0".repeat(64);
    assert!(Llama::connect(cfg).await.unwrap_err().to_string().contains("SHA-256 mismatch"));
    let mut cfg = e.cfg.clone();
    cfg.recycle = None;
    assert!(Llama::connect(cfg).await.unwrap_err().to_string().contains("recycling is required"));
    std::fs::write(&e.cfg.workflow_path, WORKFLOW.replace("false", "true")).unwrap();
    assert!(llama_release(MODEL, &e.cfg.model_path, &e.cfg.workflow_path).is_err());
    std::fs::write(&e.cfg.workflow_path, WORKFLOW).unwrap();
    std::fs::write(&e.cfg.model_path, b"not a GGUF model").unwrap();
    assert!(llama_release(MODEL, &e.cfg.model_path, &e.cfg.workflow_path).is_err());
}

#[tokio::test]
async fn fixed_warmup_runs_after_each_restart() {
    let e = env().await;
    let mut cfg = e.cfg.clone();
    cfg.warmup = true;
    let engine = Llama::connect(cfg).await.unwrap();
    generate(&engine, &request("consumer text", 8), CancellationToken::new()).await.unwrap();
    let data = e.state.data.lock().unwrap();
    assert_eq!(data.requests.len(), 3);
    assert_eq!(data.requests[0].1["prompt"], "warmup");
    assert_eq!(data.requests[0].1["max_tokens"], 1);
    assert_eq!(data.requests[0].1["cache_prompt"], false);
    assert_eq!(data.requests[1].1["prompt"], "consumer text");
    assert_eq!(data.requests[2].1["prompt"], "warmup");
    assert!(data.requests[2].0 > data.requests[1].0);
}

#[tokio::test]
async fn request_and_response_limits_never_echo_canary() {
    let e = env().await;
    let engine = Llama::connect(e.cfg.clone()).await.unwrap();
    let req = request("PRIVATE-CANARY", 65);
    let err = generate(&engine, &req, CancellationToken::new()).await.unwrap_err();
    assert!(!err.to_string().contains("PRIVATE-CANARY"));
    assert_eq!(count(&e.state), 0);
    let req = request("PRIVATE-CANARY", 8);
    for mode in [Mode::Reject, Mode::Oversize, Mode::WrongModel, Mode::BadUsage] {
        e.state.data.lock().unwrap().mode = mode;
        let err = generate(&engine, &req, CancellationToken::new()).await.unwrap_err();
        assert!(!err.to_string().contains("PRIVATE-CANARY"), "{err}");
        assert!(!format!("{err:?}").contains("PRIVATE-CANARY"));
    }
    assert!(!format!("{req:?}").contains("PRIVATE-CANARY"));
    assert!(!format!("{engine:?}").contains("PRIVATE-CANARY"));
}

#[tokio::test]
async fn cancellation_and_abandonment_restart_before_next_request() {
    let e = env().await;
    let engine = Llama::connect(e.cfg.clone()).await.unwrap();
    e.state.data.lock().unwrap().mode = Mode::Hang;
    let req = request("PRIVATE-CANARY cancel", 8);
    let cancel = CancellationToken::new();
    let previous = count(&e.state);
    let canceller = async {
        eventually(|| count(&e.state) > previous).await;
        cancel.cancel();
    };
    let (result, ()) = tokio::join!(generate(&engine, &req, cancel.clone()), canceller);
    assert!(result.unwrap_err().is_cancelled());
    let first_generation = e.state.data.lock().unwrap().requests[0].0;
    e.state.data.lock().unwrap().mode = Mode::Complete;
    generate(&engine, &request("second", 8), CancellationToken::new()).await.unwrap();
    let second_generation = e.state.data.lock().unwrap().requests[1].0;
    assert!(second_generation > first_generation);

    e.state.data.lock().unwrap().mode = Mode::Hang;
    let previous = count(&e.state);
    let req = request("PRIVATE-CANARY abandoned", 8);
    let dropped = tokio::time::timeout(Duration::from_millis(200), generate(&engine, &req, CancellationToken::new())).await;
    assert!(dropped.is_err());
    assert!(count(&e.state) > previous);
    e.state.data.lock().unwrap().mode = Mode::Complete;
    generate(&engine, &request("fourth", 8), CancellationToken::new()).await.unwrap();
    let data = e.state.data.lock().unwrap();
    let abandoned_generation = data.requests[2].0;
    let fourth_generation = data.requests[3].0;
    assert!(fourth_generation > abandoned_generation);
}
