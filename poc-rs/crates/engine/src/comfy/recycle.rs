//! Engine recycling: every job runs in a freshly started ComfyUI process, so
//! no earlier job's prompt, latents or images survive in engine memory
//! (defense in depth against a later engine compromise, e.g. through a
//! decoder bug, and against leftovers across consumers).
//!
//! The agent cannot signal the engine (they run as different users), so it
//! talks to the engine's supervisor (`run-engine.sh` with
//! `ENGINE_CONTROL_DIR`) through two files in a shared, group-writable
//! directory:
//!
//! - `engine.gen`: `<generation> <pid>` of the running ComfyUI, replaced
//!   atomically (write + rename) by the supervisor each time it starts one;
//! - `restart`: created by the agent to ask for a fresh process. The
//!   supervisor removes it, kills ComfyUI, clears the per-job tmpfs
//!   directories and starts a new ComfyUI.
//!
//! After every job that reached ComfyUI (finished, failed or cancelled) the
//! adapter purges it, creates `restart` and returns the job's result, so a
//! consumer pays for the restart only when jobs are back to back. The GPU
//! slot stays held until the supervisor has taken the request, published a
//! new generation and ComfyUI answers `GET /system_stats`, and optionally
//! until a fixed warm-up generation has loaded the weights; the next job
//! runs only then. A restart not confirmed within the timeout makes jobs fail
//! with `engine_unavailable` rather than run in a process that may still hold
//! the previous job.

use super::graphs::{ComfyModel, Sorted};
use super::http::{Http, PostError, path_escape};
use super::purge::{POLL, purge_prompt};
use super::{HistoryEntry, Queued, describe};
use db_log::{Logger, logf};
use db_wire::JobRequest;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// The supervisor's generation file.
pub(crate) const GEN_FILE: &str = "engine.gen";
/// The agent's restart request.
pub(crate) const RESTART_FILE: &str = "restart";
/// How long a restart may take before jobs fail with `engine_unavailable`.
pub(crate) const DEFAULT_RESTART_TIMEOUT: Duration = Duration::from_secs(180);
/// How often a pending restart is checked (the supervisor polls as often).
const READY_POLL: Duration = Duration::from_millis(200);
/// Timeout of one `GET /system_stats` probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Bound on the warm-up generation, model loading included.
const WARMUP_TIMEOUT: Duration = Duration::from_secs(300);
/// The warm-up prompt: a constant, never consumer data.
pub(crate) const WARMUP_PROMPT: &str = "warmup";

/// `<generation> <pid>` as published in `engine.gen`. Both identify the
/// process: a supervisor that itself restarted counts from 1 again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Generation {
    generation: u64,
    pid: u64,
}

impl std::fmt::Display for Generation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}, pid {}", self.generation, self.pid)
    }
}

/// Reads `engine.gen`; `None` if it is missing or malformed.
pub(crate) fn read_generation(dir: &Path) -> Option<Generation> {
    let text = std::fs::read_to_string(dir.join(GEN_FILE)).ok()?;
    let mut fields = text.split_ascii_whitespace();
    let generation = fields.next()?.parse().ok()?;
    let pid = fields.next()?.parse().ok()?;
    fields.next().is_none().then_some(Generation { generation, pid })
}

/// What the holder of the GPU slot knows about the engine process.
#[derive(Debug, Default)]
pub(crate) struct Slot {
    /// A restart was requested and is not confirmed yet.
    pending: Option<Pending>,
}

impl Slot {
    /// Whether the engine may still be the process an earlier job ran in.
    pub(crate) fn restart_pending(&self) -> bool {
        self.pending.is_some()
    }
}

#[derive(Debug)]
struct Pending {
    /// The generation before the request.
    before: Option<Generation>,
    requested: Instant,
}

pub(crate) fn create_restart_file(dir: &Path) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // Group-accessible: the supervisor runs as another user.
        opts.mode(0o660);
    }
    opts.open(dir.join(RESTART_FILE)).map(drop)
}

fn elapsed(since: Instant) -> String {
    db_gojson::duration_ms_string(since.elapsed())
}

/// Restarts the engine between jobs and warms it up.
#[derive(Clone)]
pub(crate) struct Recycler {
    http: Http,
    dir: PathBuf,
    output_dir: Option<PathBuf>,
    warmup: Option<&'static ComfyModel>,
    timeout: Duration,
    log: Logger,
}

impl Recycler {
    pub(crate) fn new(
        http: Http,
        dir: PathBuf,
        output_dir: Option<PathBuf>,
        warmup: Option<&'static ComfyModel>,
        timeout: Duration,
        log: Logger,
    ) -> Self {
        Self { http, dir, output_dir, warmup, timeout, log }
    }

    /// How long a restart may take.
    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Asks the supervisor for a fresh engine process (after the job was
    /// purged). If the request cannot be made, the restart stays pending and
    /// jobs fail closed until the engine restarts for another reason.
    pub(crate) fn request(&self, slot: &mut Slot) {
        let before = read_generation(&self.dir);
        if let Err(e) = create_restart_file(&self.dir) {
            logf!(self.log, "engine recycle: cannot request a restart in {}: {e}", self.dir.display());
        }
        slot.pending = Some(Pending { before, requested: Instant::now() });
    }

    /// The new generation once the requested restart is done: the supervisor
    /// took the request, published another generation, and ComfyUI answers.
    async fn restarted(&self, p: &Pending) -> Option<Generation> {
        if !matches!(self.dir.join(RESTART_FILE).try_exists(), Ok(false)) {
            return None;
        }
        let now = read_generation(&self.dir).filter(|g| Some(*g) != p.before)?;
        self.http.probe("/system_stats", PROBE_TIMEOUT).await.then_some(now)
    }

    /// Waits until the pending restart (if any) is done, or `deadline`.
    pub(crate) async fn wait(&self, slot: &mut Slot, deadline: Instant) -> bool {
        loop {
            let Some(p) = &slot.pending else { return true };
            if let Some(g) = self.restarted(p).await {
                logf!(self.log, "engine restarted (generation {g}) in {}", elapsed(p.requested));
                slot.pending = None;
                return true;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            tokio::time::sleep(left.min(READY_POLL)).await;
        }
    }

    /// After a job: waits (bounded by the restart timeout) for the fresh
    /// engine, then warms it up. The caller holds the GPU slot throughout.
    pub(crate) async fn settle(&self, slot: &mut Slot) {
        let Some(requested) = slot.pending.as_ref().map(|p| p.requested) else { return };
        if !self.wait(slot, requested.checked_add(self.timeout).unwrap_or(requested)).await {
            logf!(
                self.log,
                "engine restart not confirmed within {}; jobs fail with engine_unavailable until it is",
                db_gojson::duration_ms_string(self.timeout)
            );
            return;
        }
        if let Some(model) = self.warmup {
            self.warm_up(model).await;
        }
    }

    /// One fixed generation (constant prompt, smallest size, one step) so
    /// the weights are loaded before the next consumer job, purged like a
    /// job. It never sees consumer data, so it needs no restart afterwards.
    async fn warm_up(&self, model: &'static ComfyModel) {
        let start = Instant::now();
        let mut rnd = [0u8; 8];
        if getrandom::fill(&mut rnd).is_err() {
            logf!(self.log, "engine warm-up skipped: no randomness");
            return;
        }
        let tag = hex::encode(rnd);
        let prefix = format!("dbjob-{tag}");
        let mut req = JobRequest::default();
        req.v = 1;
        req.job_id = "warmup".to_owned();
        req.model = model.id.to_owned();
        req.workflow = model.workflow.to_owned();
        req.prompt = WARMUP_PROMPT.to_owned();
        req.width = db_wire::MIN_SIDE;
        req.height = db_wire::MIN_SIDE;
        req.steps = 1;
        req.seed = 1;
        let body = Value::Object(Map::from_iter([
            ("client_id".to_owned(), Value::String(format!("{tag}-warmup"))),
            ("prompt".to_owned(), (model.graph)(&req, &prefix)),
        ]));
        let Ok(encoded) = db_gojson::to_vec(&Sorted(&body)) else { return };
        let mut prompt_id: Option<String> = None;
        let mut finished = false;
        let outcome = tokio::time::timeout(WARMUP_TIMEOUT, async {
            let rsp = self.http.post("/prompt", Zeroizing::new(encoded)).await.map_err(|e| match e {
                PostError::Net(e) => e,
                PostError::Status(status, b) => format!("{status}: {}", describe(&b, &[])),
            })?;
            let queued: Queued = serde_json::from_slice(&rsp).unwrap_or_default();
            if queued.prompt_id.is_empty() {
                return Err(format!("not queued: {}", describe(&rsp, &[])));
            }
            prompt_id = Some(queued.prompt_id.clone());
            let history = format!("/history/{}", path_escape(&queued.prompt_id));
            loop {
                tokio::time::sleep(POLL).await;
                let b = self.http.get(&history).await.map_err(|e| e.0)?;
                let mut h: BTreeMap<String, HistoryEntry> = serde_json::from_slice(&b).map_err(|e| e.to_string())?;
                if let Some(e) = h.remove(&queued.prompt_id) {
                    if e.status.status_str == "error" {
                        finished = true;
                        return Err("ComfyUI reported an execution error".to_owned());
                    }
                    if e.status.completed {
                        finished = true;
                        return Ok(());
                    }
                }
            }
        })
        .await;
        purge_prompt(&self.http, prompt_id.as_deref(), &prefix, self.output_dir.as_deref(), !finished).await;
        match outcome {
            Ok(Ok(())) => logf!(self.log, "engine warm-up ({}, {}x{}, 1 step) done in {}", model.id, req.width, req.height, elapsed(start)),
            Ok(Err(e)) => logf!(self.log, "engine warm-up failed after {}: {e}", elapsed(start)),
            Err(_) => logf!(self.log, "engine warm-up timed out after {}", elapsed(start)),
        }
    }
}
