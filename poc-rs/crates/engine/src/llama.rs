//! A bounded llama.cpp text adapter. Consumer text reaches only the local
//! `llama-server`; the agent encrypts the resulting bytes for the consumer.

mod recycle;

use crate::comfy::recycle::{GEN_FILE, read_generation};
use crate::{BoxFuture, Engine, EngineError, Output, Progress};
use db_release::{Artifact, Model};
use db_tpmattest::ModelReport;
use db_wire::{JobRequest, ModelCap, Units};
use recycle::{Active, LlamaRecycler, Slot};
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const WORKFLOW_ID: &str = "llama-text-greedy-v1";
const ENDPOINT: &str = "/v1/completions";
const RESPONSE_LIMIT: usize = 1 << 20;
const WORKFLOW_LIMIT: u64 = 4096;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// A llama.cpp instance serving one pinned GGUF text model.
#[derive(Debug, Clone)]
pub struct LlamaConfig {
    /// Plain HTTP loopback URL, e.g. `http://127.0.0.1:8080`.
    pub url: String,
    /// Alias advertised by the supervised llama-server.
    pub model_id: String,
    /// GGUF file that the supervisor loads.
    pub model_path: PathBuf,
    /// Lowercase SHA-256 pinned in the release manifest.
    pub model_sha256: String,
    /// Approved workflow JSON; its exact bytes are attested.
    pub workflow_path: PathBuf,
    /// Maximum generated tokens, at most 1024.
    pub max_tokens: i64,
    /// Supervisor control directory with `engine.gen` and `restart`.
    pub recycle: Option<PathBuf>,
    /// Run a fixed, non-consumer warm-up after each process restart.
    pub warmup: bool,
}

/// A single-model text engine. Every request that can reach llama-server is
/// followed by a supervised process restart before the GPU slot is reused.
pub struct Llama {
    cfg: LlamaConfig,
    http: LlamaHttp,
    model: ModelReport,
    workflow: Artifact,
    gpu: Arc<tokio::sync::Mutex<Slot>>,
    recycler: LlamaRecycler,
}

impl std::fmt::Debug for Llama {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Llama").field("model_id", &self.cfg.model_id).field("url", &self.cfg.url).finish_non_exhaustive()
    }
}

/// The workflow is data from the signed release, not an arbitrary API
/// template. Reject unknown fields and any setting that could retain a
/// consumer prompt or change the approved endpoint/sampler.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Workflow {
    v: u32,
    id: String,
    endpoint: String,
    temperature: f64,
    cache_prompt: bool,
}

fn workflow_artifact(path: &Path) -> Result<Artifact, EngineError> {
    let file = std::fs::File::open(path).map_err(|_| EngineError("llama workflow file is unavailable".to_owned()))?;
    let mut raw = Vec::new();
    file.take(WORKFLOW_LIMIT + 1).read_to_end(&mut raw).map_err(|_| EngineError("llama workflow file could not be read".to_owned()))?;
    if raw.len() as u64 > WORKFLOW_LIMIT {
        return Err(EngineError("llama workflow file is too large".to_owned()));
    }
    let workflow: Workflow = serde_json::from_slice(&raw).map_err(|_| EngineError("llama workflow JSON is invalid".to_owned()))?;
    if workflow.v != 1
        || workflow.id != WORKFLOW_ID
        || workflow.endpoint != ENDPOINT
        || workflow.temperature != 0.0
        || workflow.cache_prompt
    {
        return Err(EngineError("llama workflow settings are not approved".to_owned()));
    }
    Ok(Artifact { name: WORKFLOW_ID.to_owned(), sha256: hex::encode(Sha256::digest(&raw)), bytes: raw.len() as i64 })
}

fn model_artifact(path: &Path) -> Result<Artifact, EngineError> {
    let mut file = std::fs::File::open(path).map_err(|_| EngineError("llama model file is unavailable".to_owned()))?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).map_err(|_| EngineError("llama model header is invalid".to_owned()))?;
    if &magic != b"GGUF" {
        return Err(EngineError("llama model is not a GGUF file".to_owned()));
    }
    // Always read and hash the full GGUF. An mtime/size hash cache is not a
    // production integrity check, even when the model is many gigabytes.
    let (digest, bytes) = db_release::file_sha256(path).map_err(|_| EngineError("llama model file cannot be hashed".to_owned()))?;
    let sha256 = hex::encode(digest);
    // Logical deployed artifact name, independent of the source filename.
    Ok(Artifact { name: "model.gguf".to_owned(), sha256, bytes: i64::try_from(bytes).unwrap_or(i64::MAX) })
}

fn valid_model_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128
}

/// Workflow and model artifacts to pin in a signed release manifest. This
/// uses the same validation and streaming hash as [`Llama::connect`] without
/// requiring a running server or a supervisor control directory.
pub fn llama_release(model_id: &str, model_path: &Path, workflow_path: &Path) -> Result<(Vec<Artifact>, Vec<Model>), EngineError> {
    if !valid_model_id(model_id) {
        return Err(EngineError("llama model ID is invalid".to_owned()));
    }
    let workflow = workflow_artifact(workflow_path)?;
    let model = model_artifact(model_path)?;
    Ok((vec![workflow], vec![Model { id: model_id.to_owned(), kind: "text".to_owned(), files: Some(vec![model]) }]))
}

impl Llama {
    /// Verifies the workflow and every GGUF byte, then requests and waits
    /// for a fresh supervised llama-server before serving consumer jobs.
    pub async fn connect(cfg: LlamaConfig) -> Result<Self, EngineError> {
        if !valid_model_id(&cfg.model_id) || !(1..=db_wire::MAX_TEXT_TOKENS).contains(&cfg.max_tokens) {
            return Err(EngineError("llama model ID or token limit is invalid".to_owned()));
        }
        if cfg.model_sha256.len() != 64 || !cfg.model_sha256.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f')) {
            return Err(EngineError("llama model SHA-256 must be 64 lowercase hex characters".to_owned()));
        }
        let Some(dir) = cfg.recycle.clone() else {
            return Err(EngineError("llama process recycling is required for private text".to_owned()));
        };
        let http = LlamaHttp::new(&cfg.url)?;
        let hash_cfg = cfg.clone();
        let (workflow, model_file) = tokio::task::spawn_blocking(move || {
            Ok::<_, EngineError>((workflow_artifact(&hash_cfg.workflow_path)?, model_artifact(&hash_cfg.model_path)?))
        })
        .await
        .map_err(|_| EngineError("llama integrity check failed".to_owned()))??;
        if model_file.sha256 != cfg.model_sha256 {
            return Err(EngineError("llama model SHA-256 mismatch".to_owned()));
        }
        if read_generation(&dir).is_none() {
            return Err(EngineError(format!("llama process recycling needs a valid {GEN_FILE}")));
        }
        let model = ModelReport { id: cfg.model_id.clone(), files: vec![model_file] };
        let recycler = LlamaRecycler::new(dir, http.clone(), cfg.model_id.clone(), cfg.warmup);
        let gpu = Arc::new(tokio::sync::Mutex::new(Slot::default()));
        let result = Self { cfg, http, model, workflow, gpu, recycler };
        {
            let mut slot = result.gpu.lock().await;
            result.recycler.request(&mut slot);
            result.recycler.settle(&mut slot).await?;
        }
        Ok(result)
    }

    fn validate_request(&self, req: &JobRequest) -> Result<(), EngineError> {
        if req.v != 1
            || req.job_id.is_empty()
            || req.model != self.cfg.model_id
            || req.workflow != WORKFLOW_ID
            || req.prompt.is_empty()
            || req.prompt.len() > db_wire::MAX_PROMPT_BYTES
            || !req.negative_prompt.is_empty()
            || !req.input_image.is_empty()
            || req.width != 0
            || req.height != 0
            || req.steps != 0
            || req.frames != 0
            || req.fps != 0
            || !(1..=self.cfg.max_tokens).contains(&req.max_tokens)
        {
            return Err(EngineError("llama text request is outside the approved workflow".to_owned()));
        }
        Ok(())
    }

    async fn run(&self, req: &JobRequest, progress: Progress<'_>, cancel: CancellationToken) -> Result<Output, EngineError> {
        self.validate_request(req)?;
        let arrived = Instant::now();
        let slot = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(EngineError::cancelled()),
            slot = self.gpu.clone().lock_owned() => slot,
        };
        let mut active = Active::new(self.recycler.clone(), slot);
        if active.pending() {
            let deadline = arrived.checked_add(self.recycler.timeout()).unwrap_or(arrived);
            // A pending restart may include a fixed warm-up. Keep the slot
            // until that finishes, even if this caller cancels meanwhile.
            // An outer future drop is covered by Active's restart guard.
            active.mark_reached();
            if !active.wait(deadline).await {
                return Err(EngineError::unavailable());
            }
            if cancel.is_cancelled() {
                return Err(EngineError::cancelled());
            }
        }
        progress(0, req.max_tokens);
        active.mark_reached();
        let start = Instant::now();
        let outcome = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(EngineError::cancelled()),
            result = self.http.complete(&self.cfg.model_id, req) => result,
        };
        let inference_ms = i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX);
        // The HTTP future has been dropped before this point on cancellation.
        // A restart is required even when the server rejected the request:
        // it may already have parsed and retained the prompt.
        let cleanup = active.settle().await;
        if cleanup.is_err() {
            return Err(EngineError::unavailable());
        }
        let mut output = outcome?;
        output.units.gpu_millis = inference_ms;
        progress(output.units.completion_tokens, req.max_tokens);
        Ok(output)
    }
}

impl Engine for Llama {
    fn name(&self) -> String {
        "llama.cpp".to_owned()
    }

    fn workflows(&self) -> Vec<Artifact> {
        vec![self.workflow.clone()]
    }

    fn models(&self) -> Vec<ModelReport> {
        vec![self.model.clone()]
    }

    fn caps(&self) -> Vec<ModelCap> {
        vec![ModelCap {
            id: self.cfg.model_id.clone(),
            kind: "text".to_owned(),
            workflows: vec![WORKFLOW_ID.to_owned()],
            max_tokens: self.cfg.max_tokens,
            ..ModelCap::default()
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

#[derive(Clone)]
struct LlamaHttp {
    base: String,
    client: reqwest::Client,
}

#[derive(Serialize)]
struct CompletionRequest<'a> {
    model: &'a str,
    prompt: &'a str,
    max_tokens: i64,
    temperature: i32,
    seed: i64,
    cache_prompt: bool,
    stream: bool,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct CompletionResponse {
    #[serde(default)]
    model: String,
    choices: Vec<Choice>,
    usage: Usage,
}

#[derive(Deserialize, Zeroize)]
struct Choice {
    text: String,
}

#[derive(Deserialize, Zeroize)]
struct Usage {
    prompt_tokens: i64,
    completion_tokens: i64,
}

impl LlamaHttp {
    fn new(url: &str) -> Result<Self, EngineError> {
        let parsed = Url::parse(url).map_err(|_| EngineError("llama URL is invalid".to_owned()))?;
        if parsed.scheme() != "http"
            || !matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(EngineError("llama URL must be a plain HTTP loopback origin".to_owned()));
        }
        let no_tls = db_tls::client_config(&db_tls::Trust::Pinned(Vec::new()))
            .map_err(|_| EngineError("llama HTTP client configuration failed".to_owned()))?;
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .tls_backend_preconfigured(no_tls)
            .build()
            .map_err(|_| EngineError("llama HTTP client configuration failed".to_owned()))?;
        Ok(Self { base: parsed.as_str().trim_end_matches('/').to_owned(), client })
    }

    async fn health(&self) -> bool {
        self.client
            .get(format!("{}/health", self.base))
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .is_ok_and(|rsp| rsp.status() == StatusCode::OK)
    }

    async fn complete(&self, model: &str, req: &JobRequest) -> Result<Output, EngineError> {
        let payload = CompletionRequest {
            model,
            prompt: &req.prompt,
            max_tokens: req.max_tokens,
            temperature: 0,
            seed: req.seed,
            cache_prompt: false,
            stream: false,
        };
        let body = Zeroizing::new(serde_json::to_vec(&payload).map_err(|_| EngineError("llama request encoding failed".to_owned()))?);
        let rsp = self
            .client
            .post(format!("{}{ENDPOINT}", self.base))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(bytes::Bytes::from_owner(body))
            .send()
            .await
            .map_err(|_| EngineError("llama request failed".to_owned()))?;
        if rsp.status() != StatusCode::OK {
            return Err(EngineError(format!("llama rejected the request with HTTP {}", rsp.status().as_u16())));
        }
        let body = read_limited(rsp).await?;
        let mut parsed: CompletionResponse =
            serde_json::from_slice(&body).map_err(|_| EngineError("llama response JSON is invalid".to_owned()))?;
        if !parsed.model.is_empty() && parsed.model != model {
            return Err(EngineError("llama answered for another model".to_owned()));
        }
        if parsed.choices.len() != 1 || parsed.usage.prompt_tokens < 0 || !(0..=req.max_tokens).contains(&parsed.usage.completion_tokens) {
            return Err(EngineError("llama response usage or choice count is invalid".to_owned()));
        }
        let Some(mut choice) = parsed.choices.pop() else {
            return Err(EngineError("llama response has no choice".to_owned()));
        };
        let data = Zeroizing::new(std::mem::take(&mut choice.text).into_bytes());
        let units =
            Units { prompt_tokens: parsed.usage.prompt_tokens, completion_tokens: parsed.usage.completion_tokens, ..Units::default() };
        Ok(Output { data, mime: "text/plain; charset=utf-8".to_owned(), units })
    }
}

async fn read_limited(mut rsp: reqwest::Response) -> Result<Zeroizing<Vec<u8>>, EngineError> {
    if rsp.content_length().is_some_and(|n| n > RESPONSE_LIMIT as u64) {
        return Err(EngineError("llama response exceeds the size limit".to_owned()));
    }
    let mut out = Zeroizing::new(Vec::new());
    while let Some(chunk) = rsp.chunk().await.map_err(|_| EngineError("llama response read failed".to_owned()))? {
        if out.len().saturating_add(chunk.len()) > RESPONSE_LIMIT {
            return Err(EngineError("llama response exceeds the size limit".to_owned()));
        }
        out.extend_from_slice(&chunk);
        if let Ok(mut bytes) = chunk.try_into_mut() {
            bytes.as_mut().zeroize();
        }
    }
    Ok(out)
}
