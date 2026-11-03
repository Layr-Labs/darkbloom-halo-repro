//! Purging a job from ComfyUI's memory and from tmpfs on every path,
//! including when the generate future is dropped, and with engine recycling
//! restarting the engine afterwards.
//!
//! A job is owned by a [`PurgeGuard`] from just before its prompt is sent.
//! Whatever happens, the guard (1) stops the prompt if ComfyUI has not
//! reported it finished (POST /interrupt and /queue delete, then waits,
//! bounded, until ComfyUI no longer holds it, so the history delete cannot
//! race its completion), (2) deletes it from ComfyUI's history (which holds
//! the whole graph, prompt included), (3) overwrites with zeros and unlinks
//! the output files carrying the job's random prefix and (4) with recycling,
//! asks the supervisor for a fresh engine process. This runs as a spawned
//! task that owns the GPU slot, so it completes even if the caller goes away.
//! [`PurgeGuard::purge`] returns once (1)-(4) are done; with recycling the
//! task keeps the slot until the fresh engine is up (and warmed up), so the
//! next job starts only then.

use super::http::Http;
use super::recycle::{Recycler, Slot};
use serde_json::{Value, json};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedMutexGuard, oneshot};

/// How often ComfyUI is polled.
pub(crate) const POLL: Duration = Duration::from_millis(300);

/// How long a purge waits for an interrupted prompt to leave ComfyUI.
const STOP_WAIT: Duration = Duration::from_secs(30);

/// A job on the engine and everything needed to purge it.
pub(crate) struct Job {
    pub(crate) http: Http,
    /// Set once ComfyUI queued the prompt.
    pub(crate) prompt_id: Option<String>,
    pub(crate) prefix: String,
    pub(crate) output_dir: Option<PathBuf>,
    /// Held until the purge (with recycling: the restart) completes: one
    /// job on the GPU at a time.
    pub(crate) slot: OwnedMutexGuard<Slot>,
    /// Restarts the engine after the purge.
    pub(crate) recycle: Option<Recycler>,
}

/// Purges its job when consumed with [`PurgeGuard::purge`] or dropped.
pub(crate) struct PurgeGuard {
    job: Option<Job>,
    finished: bool,
}

impl PurgeGuard {
    pub(crate) fn new(job: Job) -> Self {
        Self { job: Some(job), finished: false }
    }

    /// ComfyUI queued the prompt under this ID.
    pub(crate) fn set_prompt(&mut self, prompt_id: String) {
        if let Some(job) = &mut self.job {
            job.prompt_id = Some(prompt_id);
        }
    }

    /// ComfyUI reported the prompt finished (completed or failed), so there
    /// is nothing left to stop.
    pub(crate) fn mark_finished(&mut self) {
        self.finished = true;
    }

    /// Purges, requests the restart (with recycling) and returns. The work
    /// is a spawned task, so dropping this future part-way does not
    /// interrupt it; the task waits for the fresh engine on its own.
    pub(crate) async fn purge(mut self) {
        let Some(job) = self.job.take() else { return };
        let stop = !self.finished;
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                let (tx, rx) = oneshot::channel();
                rt.spawn(job.run(stop, Some(tx)));
                let _ = rx.await;
            }
            Err(_) => job.run(stop, None).await,
        }
    }
}

impl Drop for PurgeGuard {
    fn drop(&mut self) {
        let Some(mut job) = self.job.take() else { return };
        let stop = !self.finished;
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                rt.spawn(job.run(stop, None));
            }
            // No runtime to talk to ComfyUI from: at least remove the files
            // and ask for a fresh engine.
            Err(_) => {
                if let Some(dir) = &job.output_dir {
                    wipe_files(dir, &job.prefix);
                }
                if let Some(r) = job.recycle.take() {
                    r.request(&mut job.slot);
                }
            }
        }
    }
}

impl Job {
    /// Purges the job, then (with recycling) requests a fresh engine,
    /// reports `purged`, and keeps the GPU slot until that engine is ready.
    async fn run(mut self, stop: bool, purged: Option<oneshot::Sender<()>>) {
        purge_prompt(&self.http, self.prompt_id.as_deref(), &self.prefix, self.output_dir.as_deref(), stop).await;
        if let Some(r) = &self.recycle {
            r.request(&mut self.slot);
        }
        if let Some(tx) = purged {
            let _ = tx.send(());
        }
        if let Some(r) = &self.recycle {
            r.settle(&mut self.slot).await;
        }
    }
}

/// Stops (when `stop`) and forgets a queued prompt, then wipes the output
/// files carrying `prefix`.
pub(crate) async fn purge_prompt(http: &Http, prompt_id: Option<&str>, prefix: &str, output_dir: Option<&Path>, stop: bool) {
    if let Some(id) = prompt_id {
        if stop {
            http.post_quiet("/interrupt", &json!({"prompt_id": id})).await;
            http.post_quiet("/queue", &json!({"delete": [id]})).await;
            wait_until_released(http, id).await;
        }
        http.post_quiet("/history", &json!({"delete": [id]})).await;
    }
    if let Some(dir) = output_dir {
        let (dir, prefix) = (dir.to_path_buf(), prefix.to_owned());
        let _ = tokio::task::spawn_blocking(move || wipe_files(&dir, &prefix)).await;
    }
}

/// Whether ComfyUI's `/queue` lists the prompt as running or pending
/// (items are `[number, prompt_id, prompt, extra_data, outputs]`).
fn queued(queue: &Value, prompt_id: &str) -> bool {
    ["queue_running", "queue_pending"].iter().any(|k| {
        queue
            .get(k)
            .and_then(Value::as_array)
            .is_some_and(|items| items.iter().any(|it| it.get(1).and_then(Value::as_str) == Some(prompt_id)))
    })
}

/// Waits (bounded) until ComfyUI neither runs nor queues the prompt.
async fn wait_until_released(http: &Http, prompt_id: &str) {
    let deadline = Instant::now() + STOP_WAIT;
    loop {
        let Ok(b) = http.get("/queue").await else { return };
        let Ok(q) = serde_json::from_slice::<Value>(&b) else { return };
        if !queued(&q, prompt_id) || Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Overwrites with zeros, then unlinks, every regular file in `dir` whose
/// name starts with `prefix` (symlinks are unlinked, never followed).
pub(crate) fn wipe_files(dir: &Path, prefix: &str) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        if !e.file_name().to_string_lossy().starts_with(prefix) {
            continue;
        }
        let path = e.path();
        if e.file_type().is_ok_and(|t| t.is_file())
            && let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&path)
            && let Ok(md) = f.metadata()
        {
            let zeros = vec![0u8; 1 << 20];
            let mut left = md.len();
            while left > 0 {
                let n = usize::try_from(left.min(zeros.len() as u64)).unwrap_or(zeros.len());
                if f.write_all(zeros.get(..n).unwrap_or_default()).is_err() {
                    break;
                }
                left -= n as u64;
            }
            let _ = f.sync_data();
        }
        let _ = std::fs::remove_file(&path);
    }
}
