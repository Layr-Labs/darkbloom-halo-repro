//! A mock ComfyUI HTTP API (the endpoints the adapter uses) that records
//! what the adapter does.

#![allow(dead_code)]

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// How the mock runs a prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Mode {
    /// Completes after `polls` history polls with an output file.
    #[default]
    Complete,
    /// Reports an execution error.
    ExecError,
    /// Runs until interrupted, then leaves the queue after a few polls and
    /// is recorded in history as interrupted (as ComfyUI does).
    Hang,
    /// Rejects the prompt (HTTP 400) with errors that quote the prompt.
    Reject,
    /// Completes without producing the job's file.
    NoOutput,
}

struct Running {
    graph: Value,
    prefix: String,
    ext: &'static str,
    polls_left: usize,
    interrupted: Option<usize>,
}

/// Mock state and observations.
#[derive(Default)]
pub struct Mock {
    pub mode: Mode,
    pub polls: usize,
    pub output_dir: PathBuf,
    pub content: Vec<u8>,
    /// Ordered log: "prompt <id>", "interrupt <id>", "queue-delete <id>", "history-delete <id>", ...
    pub events: Vec<String>,
    pub prompts: Vec<Value>,
    pub interrupts: Vec<Value>,
    pub queue_posts: Vec<Value>,
    pub history_posts: Vec<Value>,
    pub view_queries: Vec<String>,
    pub history: BTreeMap<String, Value>,
    /// Queued prompts by ID, in order: (prompt ID, graph).
    pub accepted: Vec<(String, Value)>,
    /// The process is down (restarting): every endpoint answers 503.
    pub down: bool,
    running: BTreeMap<String, Running>,
    next: usize,
}

impl Mock {
    /// A fresh ComfyUI process: nothing queued, running or in history
    /// (prompt IDs stay unique, as ComfyUI's UUIDs are).
    pub fn restart(&mut self) {
        self.running.clear();
        self.history.clear();
    }
}

pub type Shared = Arc<Mutex<Mock>>;

/// A running mock server.
pub struct Server {
    pub url: String,
    pub state: Shared,
}

impl Server {
    pub fn with<T>(&self, f: impl FnOnce(&mut Mock) -> T) -> T {
        f(&mut self.state.lock().unwrap())
    }

    pub fn events(&self) -> Vec<String> {
        self.with(|m| m.events.clone())
    }

    /// Prompts ComfyUI still runs or has in history.
    pub fn retained(&self) -> usize {
        self.with(|m| m.running.len() + m.history.len())
    }
}

pub async fn start(mode: Mode, output_dir: PathBuf) -> Server {
    let state: Shared =
        Arc::new(Mutex::new(Mock { mode, polls: 1, output_dir, content: b"\x89PNG\r\n\x1a\nmock output".to_vec(), ..Mock::default() }));
    let app = Router::new()
        .route("/system_stats", get(system_stats))
        .route("/prompt", post(prompt))
        .route("/history/{id}", get(history_get))
        .route("/history", post(history_post))
        .route("/view", get(view))
        .route("/interrupt", post(interrupt))
        .route("/queue", get(queue_get).post(queue_post))
        .layer(axum::middleware::from_fn_with_state(state.clone(), unless_down))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Server { url: format!("http://{addr}"), state }
}

/// A restarting ComfyUI answers nothing.
async fn unless_down(State(s): State<Shared>, req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    if s.lock().unwrap().down {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    next.run(req).await
}

async fn system_stats() -> Json<Value> {
    Json(json!({"system": {"os": "posix", "comfyui_version": "0.3.75"}, "devices": []}))
}

/// The text of the graph's (first) CLIPTextEncode node: the prompt.
pub fn find_text(graph: &Value) -> String {
    let nodes = graph.as_object().cloned().unwrap_or_default();
    nodes
        .values()
        .find(|n| n["class_type"] == "CLIPTextEncode")
        .and_then(|n| n["inputs"]["text"].as_str().map(str::to_owned))
        .unwrap_or_default()
}

async fn prompt(State(s): State<Shared>, body: Bytes) -> Response {
    let Ok(v) = serde_json::from_slice::<Value>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad json").into_response();
    };
    let mut m = s.lock().unwrap();
    m.prompts.push(v.clone());
    let graph = v["prompt"].clone();
    if m.mode == Mode::Reject {
        let text = find_text(&graph);
        let err = json!({
            "error": {"type": "prompt_outputs_failed_validation", "message": "Prompt outputs failed validation", "details": "", "extra_info": {}},
            "node_errors": {"27": {"errors": [{"type": "value_not_in_list", "message": "Value not in list",
                "details": format!("text: '{text}' not in []"), "extra_info": {"input_name": "text", "received_value": text}}],
                "dependent_outputs": ["9"], "class_type": "CLIPTextEncode"}},
        });
        return (StatusCode::BAD_REQUEST, Json(err)).into_response();
    }
    m.next += 1;
    let id = format!("prompt-{}", m.next);
    let mut found = (String::new(), "png");
    for n in graph.as_object().cloned().unwrap_or_default().values() {
        match n["class_type"].as_str() {
            Some("SaveImage") => found = (n["inputs"]["filename_prefix"].as_str().unwrap_or_default().to_owned(), "png"),
            Some("SaveVideo") => found = (n["inputs"]["filename_prefix"].as_str().unwrap_or_default().to_owned(), "mp4"),
            _ => {}
        }
    }
    let (prefix, ext) = found;
    // Output appears on tmpfs as soon as the job runs (partial for Hang).
    let file = m.output_dir.join(format!("{prefix}_00001_.{ext}"));
    std::fs::write(&file, &m.content).unwrap();
    let polls = m.polls;
    m.accepted.push((id.clone(), graph.clone()));
    m.running.insert(id.clone(), Running { graph, prefix, ext, polls_left: polls, interrupted: None });
    m.events.push(format!("prompt {id}"));
    Json(json!({"prompt_id": id, "number": m.next, "node_errors": {}})).into_response()
}

fn finish(m: &mut Mock, id: &str) {
    let Some(r) = m.running.remove(id) else { return };
    let prompt = json!([1, id, r.graph, {"client_id": "x"}, ["9"]]);
    let entry = if r.interrupted.is_some() {
        json!({"prompt": prompt, "outputs": {}, "status": {"status_str": "error", "completed": false,
            "messages": [["execution_interrupted", {"prompt_id": id}]]}})
    } else {
        match m.mode {
            Mode::ExecError => json!({"prompt": prompt, "outputs": {}, "status": {"status_str": "error", "completed": false,
                "messages": [["execution_error", {"prompt_id": id, "exception_message": "out of memory"}]]}}),
            Mode::NoOutput => {
                json!({"prompt": prompt, "outputs": {}, "status": {"status_str": "success", "completed": true, "messages": []}})
            }
            _ => json!({"prompt": prompt, "status": {"status_str": "success", "completed": true, "messages": []}, "outputs": {
                // Sorted before "9": a foreign file and a temp preview must be skipped.
                "10": {"images": [{"filename": "someone-else_00001_.png", "subfolder": "", "type": "output"},
                                  {"filename": format!("{}_temp_00001_.png", r.prefix), "subfolder": "", "type": "temp"}]},
                "9": {"images": [{"filename": format!("{}_00001_.{}", r.prefix, r.ext), "subfolder": "", "type": "output"}]},
            }}),
        }
    };
    m.history.insert(id.to_owned(), entry);
}

async fn history_get(State(s): State<Shared>, Path(id): Path<String>) -> Json<Value> {
    let mut m = s.lock().unwrap();
    m.events.push(format!("history-get {id}"));
    let hang = m.mode == Mode::Hang;
    let mut done = false;
    if let Some(r) = m.running.get_mut(&id)
        && !hang
        && r.interrupted.is_none()
    {
        if r.polls_left == 0 {
            done = true;
        } else {
            r.polls_left -= 1;
        }
    }
    if done {
        finish(&mut m, &id);
    }
    match m.history.get(&id) {
        Some(e) => Json(json!({ id: e })),
        None => Json(json!({})),
    }
}

async fn history_post(State(s): State<Shared>, body: Bytes) -> StatusCode {
    let v: Value = serde_json::from_slice(&body).unwrap_or_default();
    let mut m = s.lock().unwrap();
    m.history_posts.push(v.clone());
    for id in v["delete"].as_array().cloned().unwrap_or_default() {
        let id = id.as_str().unwrap_or_default().to_owned();
        m.history.remove(&id);
        m.events.push(format!("history-delete {id}"));
    }
    StatusCode::OK
}

async fn interrupt(State(s): State<Shared>, body: Bytes) -> StatusCode {
    let v: Value = serde_json::from_slice(&body).unwrap_or_default();
    let mut m = s.lock().unwrap();
    m.interrupts.push(v.clone());
    let target = v["prompt_id"].as_str().map(str::to_owned);
    m.events.push(format!("interrupt {}", target.clone().unwrap_or_default()));
    for (id, r) in m.running.iter_mut() {
        if target.as_deref().is_none_or(|t| t == id) && r.interrupted.is_none() {
            r.interrupted = Some(2);
        }
    }
    StatusCode::OK
}

async fn queue_post(State(s): State<Shared>, body: Bytes) -> StatusCode {
    let v: Value = serde_json::from_slice(&body).unwrap_or_default();
    let mut m = s.lock().unwrap();
    m.queue_posts.push(v.clone());
    for id in v["delete"].as_array().cloned().unwrap_or_default() {
        m.events.push(format!("queue-delete {}", id.as_str().unwrap_or_default()));
    }
    StatusCode::OK
}

async fn queue_get(State(s): State<Shared>) -> Json<Value> {
    let mut m = s.lock().unwrap();
    m.events.push("queue-get".to_owned());
    let mut gone = Vec::new();
    for (id, r) in m.running.iter_mut() {
        if let Some(n) = r.interrupted.as_mut() {
            if *n == 0 {
                gone.push(id.clone());
            } else {
                *n -= 1;
            }
        }
    }
    for id in gone {
        finish(&mut m, &id);
    }
    let running: Vec<Value> = m.running.keys().enumerate().map(|(i, id)| json!([i, id, {}, {}, ["9"]])).collect();
    Json(json!({"queue_running": running, "queue_pending": []}))
}

/// Decodes `application/x-www-form-urlencoded` pairs.
pub fn parse_query(q: &str) -> BTreeMap<String, String> {
    let dec = |s: &str| {
        let b = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'+' => out.push(b' '),
                b'%' if i + 2 < b.len() => {
                    out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
                    i += 2;
                }
                c => out.push(c),
            }
            i += 1;
        }
        String::from_utf8(out).unwrap()
    };
    q.split('&').filter_map(|kv| kv.split_once('=')).map(|(k, v)| (dec(k), dec(v))).collect()
}

async fn view(State(s): State<Shared>, RawQuery(q): RawQuery) -> Response {
    let q = q.unwrap_or_default();
    let mut m = s.lock().unwrap();
    m.view_queries.push(q.clone());
    let p = parse_query(&q);
    m.events.push(format!("view {}", p.get("filename").cloned().unwrap_or_default()));
    if p.get("type").map(String::as_str) != Some("output") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = m.output_dir.join(p.get("subfolder").cloned().unwrap_or_default()).join(p.get("filename").cloned().unwrap_or_default());
    match std::fs::read(path) {
        Ok(b) => b.into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}
