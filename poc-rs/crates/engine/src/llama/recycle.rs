//! The same `engine.gen`/`restart` supervisor handshake used by ComfyUI,
//! with llama-server readiness and an optional fixed text warm-up.

use super::{LlamaHttp, WORKFLOW_ID};
use crate::EngineError;
use crate::comfy::recycle::{DEFAULT_RESTART_TIMEOUT, Generation, RESTART_FILE, create_restart_file, read_generation};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::OwnedMutexGuard;

const READY_POLL: Duration = Duration::from_millis(200);

#[derive(Default)]
pub(super) struct Slot {
    pending: Option<Pending>,
}

struct Pending {
    before: Option<Generation>,
    requested: Instant,
}

#[derive(Clone)]
pub(super) struct LlamaRecycler {
    dir: PathBuf,
    http: LlamaHttp,
    model_id: String,
    warmup: bool,
    timeout: Duration,
}

impl LlamaRecycler {
    pub(super) fn new(dir: PathBuf, http: LlamaHttp, model_id: String, warmup: bool) -> Self {
        Self { dir, http, model_id, warmup, timeout: DEFAULT_RESTART_TIMEOUT }
    }

    pub(super) fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Even if the marker cannot be written, keep the slot pending; a later
    /// job must never run in the process that saw the prior prompt.
    pub(super) fn request(&self, slot: &mut Slot) {
        let before = read_generation(&self.dir);
        let _ = create_restart_file(&self.dir);
        slot.pending = Some(Pending { before, requested: Instant::now() });
    }

    async fn restarted(&self, pending: &Pending) -> bool {
        if !matches!(self.dir.join(RESTART_FILE).try_exists(), Ok(false)) {
            return false;
        }
        let Some(now) = read_generation(&self.dir) else { return false };
        Some(now) != pending.before && self.http.health().await
    }

    async fn wait(&self, slot: &mut Slot, deadline: Instant) -> bool {
        loop {
            let Some(pending) = slot.pending.as_ref() else { return true };
            if self.restarted(pending).await {
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

    pub(super) async fn settle(&self, slot: &mut Slot) -> Result<(), EngineError> {
        let Some(requested) = slot.pending.as_ref().map(|p| p.requested) else { return Ok(()) };
        let deadline = requested.checked_add(self.timeout).unwrap_or(requested);
        self.ensure_ready(slot, deadline).await
    }

    async fn ensure_ready(&self, slot: &mut Slot, deadline: Instant) -> Result<(), EngineError> {
        if !self.wait(slot, deadline).await {
            return Err(EngineError::unavailable());
        }
        if self.warmup {
            let mut request = db_wire::JobRequest::default();
            request.v = 1;
            request.job_id = "warmup".to_owned();
            request.model = self.model_id.clone();
            request.workflow = WORKFLOW_ID.to_owned();
            request.prompt = "warmup".to_owned();
            request.max_tokens = 1;
            // The warm-up contains no consumer data. A failure makes this
            // generation unavailable; another restart is required.
            if self.http.complete(&self.model_id, &request).await.is_err() {
                self.request(slot);
                return Err(EngineError::unavailable());
            }
        }
        Ok(())
    }

    pub(super) async fn wait_for_next(&self, slot: &mut Slot, deadline: Instant) -> bool {
        self.ensure_ready(slot, deadline).await.is_ok()
    }
}

/// Owns the GPU slot while a request can have reached llama-server. Dropping
/// the generation future (including a caller timeout) still asks the
/// supervisor to kill that process and keeps the slot held during cleanup.
pub(super) struct Active {
    recycler: LlamaRecycler,
    slot: Option<OwnedMutexGuard<Slot>>,
    reached: bool,
}

impl Active {
    pub(super) fn new(recycler: LlamaRecycler, slot: OwnedMutexGuard<Slot>) -> Self {
        Self { recycler, slot: Some(slot), reached: false }
    }

    pub(super) fn pending(&self) -> bool {
        self.slot.as_ref().is_some_and(|slot| slot.pending.is_some())
    }

    pub(super) async fn wait(&mut self, deadline: Instant) -> bool {
        let Some(slot) = self.slot.as_mut() else { return false };
        self.recycler.wait_for_next(slot, deadline).await
    }

    pub(super) fn mark_reached(&mut self) {
        self.reached = true;
    }

    pub(super) async fn settle(&mut self) -> Result<(), EngineError> {
        let Some(slot) = self.slot.as_mut() else { return Err(EngineError::unavailable()) };
        if slot.pending.is_none() {
            self.recycler.request(slot);
        }
        let result = self.recycler.settle(slot).await;
        self.reached = false;
        result
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        if !self.reached {
            return;
        }
        let Some(mut slot) = self.slot.take() else { return };
        if slot.pending.is_none() {
            self.recycler.request(&mut slot);
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let recycler = self.recycler.clone();
            runtime.spawn(async move {
                let _ = recycler.settle(&mut slot).await;
            });
        }
    }
}
