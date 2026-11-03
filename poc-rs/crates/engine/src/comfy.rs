//! The ComfyUI engine adapter (Go `engine.Comfy`): drives a local ComfyUI
//! over its HTTP API with the workflows compiled into [`graphs`].

mod graphs;
mod hashcache;
mod http;
mod purge;
pub(crate) mod recycle;

use crate::{BoxFuture, Engine, EngineError, Output, Progress};
use db_log::{Logger, logf};
use db_release::{Artifact, Model};
use db_tpmattest::ModelReport;
use db_wire::{JobRequest, ModelCap, Units};
use graphs::{ComfyModel, Sorted, wipe};
use hashcache::{HashCache, scan};
use http::{Http, PostError, path_escape, redact, truncate, view_path};
use purge::{Job, POLL, PurgeGuard};
use recycle::{DEFAULT_RESTART_TIMEOUT, GEN_FILE, Recycler, Slot, read_generation};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

/// Configures the ComfyUI engine adapter.
#[derive(Debug, Clone, Default)]
pub struct ComfyConfig {
    /// ComfyUI's base URL; loopback only, e.g. `http://127.0.0.1:8190`.
    pub url: String,
    /// ComfyUI's `--output-directory` (tmpfs), for deleting results.
    pub output_dir: Option<PathBuf>,
    /// Roots holding `diffusion_models/`, `text_encoders/` and `vae/`,
    /// searched in order.
    pub models_dirs: Vec<PathBuf>,
    /// ComfyUI build identity (reported as `comfyui@<commit>`).
    pub commit: String,
    /// Optional model-hash cache (development OS only).
    pub hash_cache: Option<PathBuf>,
    /// Engine recycling: the engine supervisor's control directory
    /// (`run-engine.sh` with `ENGINE_CONTROL_DIR`). Every job then runs in a
    /// freshly started ComfyUI process.
    pub recycle_dir: Option<PathBuf>,
    /// With recycling: after each restart, run one fixed warm-up generation
    /// (no consumer data) so the weights are loaded before the next job.
    pub warmup: bool,
    /// With recycling: how long a restart may take before jobs fail with
    /// `engine_unavailable` (zero means 180 s).
    pub restart_timeout: Duration,
    /// Logs restarts and warm-ups (never prompts); `None` discards.
    pub logger: Option<Logger>,
}

/// Drives a local ComfyUI over its HTTP API, one job at a time.
pub struct Comfy {
    cfg: ComfyConfig,
    http: Http,
    models: Vec<ModelReport>,
    available: Vec<&'static ComfyModel>,
    workflows: Vec<Artifact>,
    /// The GPU slot: one job (or restart, or warm-up) on the engine at a time.
    gpu: Arc<tokio::sync::Mutex<Slot>>,
    recycle: Option<Recycler>,
}

impl std::fmt::Debug for Comfy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ids: Vec<&str> = self.available.iter().map(|m| m.id).collect();
        f.debug_struct("Comfy").field("url", &self.cfg.url).field("models", &ids).finish_non_exhaustive()
    }
}

#[derive(Default, Deserialize)]
struct Queued {
    #[serde(default, deserialize_with = "db_gojson::null_default")]
    prompt_id: String,
}

#[derive(Default, Deserialize)]
struct HistoryEntry {
    #[serde(default, deserialize_with = "db_gojson::null_default")]
    status: HistoryStatus,
    #[serde(default, deserialize_with = "db_gojson::null_default")]
    outputs: BTreeMap<String, NodeOutput>,
}

#[derive(Default, Deserialize)]
struct HistoryStatus {
    #[serde(default, deserialize_with = "db_gojson::null_default")]
    status_str: String,
    #[serde(default, deserialize_with = "db_gojson::null_default")]
    completed: bool,
}

#[derive(Default, Deserialize)]
struct NodeOutput {
    #[serde(default, deserialize_with = "db_gojson::null_default")]
    images: Vec<OutputFile>,
}

#[derive(Default, Deserialize)]
struct OutputFile {
    #[serde(default, deserialize_with = "db_gojson::null_default")]
    filename: String,
    #[serde(default, deserialize_with = "db_gojson::null_default")]
    subfolder: String,
    #[serde(default, rename = "type", deserialize_with = "db_gojson::null_default")]
    kind: String,
}

fn workflow_artifact(m: &ComfyModel) -> Artifact {
    Artifact { name: m.workflow.to_owned(), sha256: m.workflow_hash(), bytes: 0 }
}

fn elapsed_ms(start: Instant) -> i64 {
    i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX)
}

/// Runs `f` unless `cancel` fires first.
async fn or_cancel<T>(cancel: &CancellationToken, f: impl Future<Output = Result<T, EngineError>>) -> Result<T, EngineError> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(EngineError::cancelled()),
        r = f => r,
    }
}

/// Summarizes a ComfyUI error body without echoing request content: the
/// error and per-node error types and messages (their `details` can quote
/// inputs), with the prompts redacted; unparseable bodies are truncated.
fn describe(body: &[u8], secrets: &[&str]) -> String {
    let text = String::from_utf8_lossy(body);
    let Ok(v) = serde_json::from_slice::<Value>(body) else { return truncate(&redact(&text, secrets), 300) };
    let field = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or_default().to_owned();
    let mut parts = Vec::new();
    if let Some(e) = v.get("error") {
        parts.push(match e.as_str() {
            Some(s) => s.to_owned(),
            None => format!("{}: {}", field(e, "type"), field(e, "message")),
        });
    }
    if let Some(nodes) = v.get("node_errors").and_then(Value::as_object) {
        for (id, n) in nodes {
            let errs = n.get("errors").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
            let msgs: Vec<String> = errs.iter().map(|e| format!("{}: {}", field(e, "type"), field(e, "message"))).collect();
            parts.push(format!("node {id} ({}): {}", field(n, "class_type"), msgs.join("; ")));
        }
    }
    if parts.is_empty() {
        return truncate(&redact(&text, secrets), 300);
    }
    truncate(&redact(&parts.join("; "), secrets), 600)
}

/// Encodes the `/prompt` request into a buffer sized for the worst case,
/// so no partial copy of the prompt is left by a reallocation.
fn encode_request(body: &Value, req: &JobRequest) -> Result<Zeroizing<Vec<u8>>, EngineError> {
    use serde::Serialize as _;
    let cap = 6 * (req.prompt.len() + req.negative_prompt.len()) + 8192;
    let mut buf = Zeroizing::new(Vec::with_capacity(cap));
    let fmt = db_gojson::GoFormatter::new(serde_json::ser::CompactFormatter);
    let mut ser = serde_json::Serializer::with_formatter(&mut *buf, fmt);
    Sorted(body).serialize(&mut ser).map_err(|e| EngineError(format!("encode workflow: {e}")))?;
    Ok(buf)
}

impl Comfy {
    /// Checks that ComfyUI answers on loopback and hashes the approved
    /// model files (on a blocking thread). Only fully present models are
    /// served; at least one must be.
    pub async fn new(cfg: ComfyConfig) -> Result<Self, EngineError> {
        let http = Http::new(&cfg.url)?;
        http.get("/system_stats").await.map_err(|e| EngineError(format!("ComfyUI not reachable at {}: {}", cfg.url, e.0)))?;
        let (dirs, cache_path) = (cfg.models_dirs.clone(), cfg.hash_cache.clone());
        let present = tokio::task::spawn_blocking(move || {
            let mut cache = HashCache::load(cache_path.as_deref());
            let present = scan(&dirs, &mut cache)?;
            if present.is_empty() {
                return Err(EngineError("no approved model is fully present".to_owned()));
            }
            cache.save(cache_path.as_deref());
            Ok(present)
        })
        .await
        .map_err(|e| EngineError(format!("hashing models: {e}")))??;
        let available: Vec<&'static ComfyModel> = present.iter().map(|p| p.model).collect();
        let workflows = available.iter().map(|m| workflow_artifact(m)).collect();
        let models = present.into_iter().map(|p| ModelReport { id: p.model.id.to_owned(), files: p.files }).collect();
        let recycle = match &cfg.recycle_dir {
            None => None,
            Some(dir) => {
                let log = cfg.logger.clone().unwrap_or_else(Logger::discard);
                let Some(generation) = read_generation(dir) else {
                    return Err(EngineError(format!(
                        "engine recycling: no valid {GEN_FILE} in {} (run run-engine.sh with ENGINE_CONTROL_DIR={})",
                        dir.display(),
                        dir.display()
                    )));
                };
                // The first image workflow (the cheapest to run) loads its
                // weights; there is no warm-up without one.
                let warmup = available.iter().copied().find(|m| !m.video).filter(|_| cfg.warmup);
                let timeout = if cfg.restart_timeout.is_zero() { DEFAULT_RESTART_TIMEOUT } else { cfg.restart_timeout };
                logf!(
                    log,
                    "engine recycling via {} (engine generation {generation}); warm-up: {}",
                    dir.display(),
                    warmup.map_or("off", |m| m.workflow)
                );
                Some(Recycler::new(http.clone(), dir.clone(), cfg.output_dir.clone(), warmup, timeout, log))
            }
        };
        let gpu = Arc::new(tokio::sync::Mutex::new(Slot::default()));
        if let Some(r) = &recycle {
            // The running engine may already hold a job (e.g. one an earlier
            // agent process ran before it went away): begin with a fresh one.
            let mut slot = gpu.clone().lock_owned().await;
            r.request(&mut slot);
            let r = r.clone();
            tokio::spawn(async move { r.settle(&mut slot).await });
        }
        Ok(Self { cfg, http, models, available, workflows, gpu, recycle })
    }

    async fn run(&self, req: &JobRequest, progress: Progress<'_>, cancel: CancellationToken) -> Result<Output, EngineError> {
        let model = self
            .available
            .iter()
            .copied()
            .find(|m| m.id == req.model && m.workflow == req.workflow)
            .ok_or_else(|| EngineError(format!("model {:?} with workflow {:?} is not served", req.model, req.workflow)))?;
        if req.width > model.max_width || req.height > model.max_height || req.steps > model.max_steps {
            return Err(EngineError("request exceeds the model's limits".to_owned()));
        }
        if !req.input_image.is_empty() && !model.takes_image {
            // Never hand consumer-supplied bytes to the engine's decoders
            // unless the workflow needs them (and then only after the agent
            // re-encodes them with `sanitize_image`).
            return Err(EngineError("workflow takes no input image".to_owned()));
        }
        if model.video {
            if req.frames < 1 || req.frames > model.max_frames || (req.frames - 1) % 4 != 0 || req.fps < 1 {
                return Err(EngineError("video length must be 4n+1 frames within the model's limit".to_owned()));
            }
        } else if req.frames != 0 {
            return Err(EngineError("image models take no frames".to_owned()));
        }
        let arrived = Instant::now();
        let mut slot = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(EngineError::cancelled()),
            g = self.gpu.clone().lock_owned() => g,
        };
        if let Some(r) = &self.recycle
            && slot.restart_pending()
        {
            // The restart after an earlier job was not confirmed in time:
            // never run in a process that may still hold that job. Waits at
            // most the restart timeout from this job's arrival.
            let deadline = arrived.checked_add(r.timeout()).unwrap_or(arrived);
            if !or_cancel(&cancel, async { Ok(r.wait(&mut slot, deadline).await) }).await? {
                return Err(EngineError::unavailable());
            }
        }
        let start = Instant::now();
        let mut rnd = [0u8; 8];
        getrandom::fill(&mut rnd).map_err(|e| EngineError(format!("random: {e}")))?;
        let tag = hex::encode(rnd);
        let prefix = format!("dbjob-{tag}");
        let mut body = Value::Object(Map::from_iter([
            ("client_id".to_owned(), Value::String(format!("{tag}-agent"))),
            ("prompt".to_owned(), (model.graph)(req, &prefix)),
        ]));
        let encoded = encode_request(&body, req);
        wipe(&mut body);
        let encoded = encoded?;
        // From here on the prompt may reach ComfyUI: the guard purges it
        // (and restarts a recycling engine) whatever happens.
        let mut guard = PurgeGuard::new(Job {
            http: self.http.clone(),
            prompt_id: None,
            prefix: prefix.clone(),
            output_dir: self.cfg.output_dir.clone(),
            slot,
            recycle: self.recycle.clone(),
        });
        let result = async {
            let secrets = [req.prompt.as_str(), req.negative_prompt.as_str()];
            // Not raced with cancellation: once ComfyUI has the prompt we
            // must learn its ID to purge it.
            let rsp = match self.http.post("/prompt", encoded).await {
                Ok(b) => b,
                Err(PostError::Net(e)) => return Err(EngineError(format!("POST /prompt: {e}"))),
                Err(PostError::Status(status, b)) => {
                    return Err(EngineError(format!("POST /prompt: {status}: {}", describe(&b, &secrets))));
                }
            };
            let queued: Queued = serde_json::from_slice(&rsp).unwrap_or_default();
            if queued.prompt_id.is_empty() {
                return Err(EngineError(format!("ComfyUI did not queue the job: {}", describe(&rsp, &secrets))));
            }
            guard.set_prompt(queued.prompt_id.clone());
            progress(0, req.steps);
            self.wait_and_fetch(req, model, &prefix, &queued.prompt_id, &mut guard, progress, &cancel, start).await
        }
        .await;
        guard.purge().await;
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn wait_and_fetch(
        &self,
        req: &JobRequest,
        model: &ComfyModel,
        prefix: &str,
        prompt_id: &str,
        guard: &mut PurgeGuard,
        progress: Progress<'_>,
        cancel: &CancellationToken,
        start: Instant,
    ) -> Result<Output, EngineError> {
        let history = format!("/history/{}", path_escape(prompt_id));
        let entry = loop {
            or_cancel(cancel, async {
                tokio::time::sleep(POLL).await;
                Ok(())
            })
            .await?;
            let b = or_cancel(cancel, self.http.get(&history)).await?;
            let mut h: BTreeMap<String, HistoryEntry> =
                serde_json::from_slice(&b).map_err(|e| EngineError(format!("GET /history: {e}")))?;
            if let Some(e) = h.remove(prompt_id) {
                if e.status.status_str == "error" {
                    guard.mark_finished();
                    return Err(EngineError("ComfyUI reported an execution error".to_owned()));
                }
                if e.status.completed {
                    guard.mark_finished();
                    break e;
                }
            }
        };
        for out in entry.outputs.values() {
            for img in &out.images {
                if !img.filename.starts_with(prefix) || img.kind != "output" {
                    continue;
                }
                let data = or_cancel(cancel, self.http.get(&view_path(&img.filename, &img.subfolder, &img.kind))).await?;
                progress(req.steps, req.steps);
                let mut units = Units {
                    images: 0,
                    megapixels: req.width.wrapping_mul(req.height) as f64 / 1e6,
                    steps: req.steps,
                    video_seconds: 0.0,
                    gpu_millis: elapsed_ms(start),
                    ..Units::default()
                };
                let mime = if model.video {
                    units.video_seconds = req.frames as f64 / req.fps as f64;
                    "video/mp4"
                } else {
                    units.images = 1;
                    "image/png"
                };
                return Ok(Output { data, mime: mime.to_owned(), units });
            }
        }
        Err(EngineError("ComfyUI produced no output".to_owned()))
    }
}

impl Engine for Comfy {
    fn name(&self) -> String {
        format!("comfyui@{}", self.cfg.commit)
    }

    fn workflows(&self) -> Vec<Artifact> {
        self.workflows.clone()
    }

    fn models(&self) -> Vec<ModelReport> {
        self.models.clone()
    }

    fn caps(&self) -> Vec<ModelCap> {
        self.available.iter().map(|m| m.cap()).collect()
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

/// The workflows and models (with file hashes) a release manifest should
/// pin for this adapter (Go `engine.ComfyRelease`). Models whose files are
/// not all present are left out, so both lists may be empty (the Go code
/// then pins `null`).
pub fn comfy_release<P: AsRef<Path>>(models_dirs: &[P], hash_cache: Option<&Path>) -> Result<(Vec<Artifact>, Vec<Model>), EngineError> {
    let dirs: Vec<PathBuf> = models_dirs.iter().map(|d| d.as_ref().to_path_buf()).collect();
    let mut cache = HashCache::load(hash_cache);
    let present = scan(&dirs, &mut cache)?;
    let workflows = present.iter().map(|p| workflow_artifact(p.model)).collect();
    let models =
        present.into_iter().map(|p| Model { id: p.model.id.to_owned(), kind: p.model.kind.to_owned(), files: Some(p.files) }).collect();
    cache.save(hash_cache);
    Ok((workflows, models))
}
