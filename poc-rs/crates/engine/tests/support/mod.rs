//! Shared fixtures for the ComfyUI adapter tests.

#![allow(dead_code)]

use crate::mock::{self, Mode, Server};
use db_engine::{Comfy, ComfyConfig, Engine, EngineError, Output};
use db_wire::JobRequest;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub const Z_FILES: [&str; 3] =
    ["diffusion_models/z_image_turbo_bf16.safetensors", "text_encoders/qwen_3_4b.safetensors", "vae/ae.safetensors"];

pub const WAN_FILES: [&str; 3] = [
    "diffusion_models/wan2.1_t2v_1.3B_fp16.safetensors",
    "text_encoders/umt5_xxl_fp8_e4m3fn_scaled.safetensors",
    "vae/wan_2.1_vae.safetensors",
];

/// Pinned workflow hashes for the local adapter fixtures.
pub const Z_WORKFLOW_SHA256: &str = "313ab0dfe71d36e7c439df0cea9c8c5de9f0130213a0837f0e13fa2444da3424";
pub const WAN_WORKFLOW_SHA256: &str = "8d5dd15a34c6977587318d45bc3ca2c0659345cf3a443290cfc6dc72a8463da2";

/// Dummy weights content for a model file.
pub fn weights(rel: &str) -> String {
    format!("weights of {rel}")
}

/// Temp models root and output dir, plus a mock ComfyUI.
pub struct Env {
    pub tmp: tempfile::TempDir,
    pub models: PathBuf,
    pub out: PathBuf,
    pub server: Server,
}

pub async fn env(mode: Mode, files: &[&str]) -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let models = tmp.path().join("models");
    let out = tmp.path().join("output");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(&models).unwrap();
    for f in files {
        let p = models.join(f);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, weights(f)).unwrap();
    }
    let server = mock::start(mode, out.clone()).await;
    Env { tmp, models, out, server }
}

impl Env {
    pub fn config(&self) -> ComfyConfig {
        ComfyConfig {
            url: self.server.url.clone(),
            output_dir: Some(self.out.clone()),
            models_dirs: vec![self.models.clone()],
            commit: "abc123".to_owned(),
            hash_cache: None,
            ..ComfyConfig::default()
        }
    }

    pub async fn comfy(&self) -> Comfy {
        Comfy::new(self.config()).await.unwrap()
    }

    /// Files left in the output dir by jobs.
    pub fn job_files(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(&self.out)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("dbjob-"))
            .collect();
        v.sort();
        v
    }

    /// Waits until `f` holds (polling for up to 10 s).
    pub async fn eventually(&self, what: &str, f: impl Fn(&Env) -> bool) {
        for _ in 0..200 {
            if f(self) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("timed out waiting for {what}; events: {:?}", self.server.events());
    }
}

fn base_request(model: &str, workflow: &str, prompt: &str) -> JobRequest {
    let mut r = JobRequest::default();
    r.v = 1;
    r.job_id = "job-1".to_owned();
    r.model = model.to_owned();
    r.workflow = workflow.to_owned();
    r.prompt = prompt.to_owned();
    r.seed = 42;
    r
}

pub fn image_request(prompt: &str) -> JobRequest {
    let mut r = base_request("z-image-turbo", "z-image-turbo-t2i", prompt);
    r.width = 1024;
    r.height = 1024;
    r.steps = 8;
    r
}

pub fn video_request(prompt: &str) -> JobRequest {
    let mut r = base_request("wan2.1-t2v-1.3b", "wan2.1-t2v", prompt);
    r.width = 832;
    r.height = 480;
    r.steps = 20;
    r.frames = 33;
    r.fps = 16;
    r
}

/// Runs a job, collecting progress calls.
pub async fn generate(c: &Comfy, req: &JobRequest, cancel: CancellationToken) -> (Result<Output, EngineError>, Vec<(i64, i64)>) {
    let calls = Mutex::new(Vec::new());
    let progress = |s: i64, t: i64| calls.lock().unwrap().push((s, t));
    let out = c.generate(req, &progress, cancel).await;
    (out, calls.into_inner().unwrap())
}

/// Index of the first event equal to `e`.
pub fn pos(events: &[String], e: &str) -> usize {
    events.iter().position(|x| x == e).unwrap_or_else(|| panic!("no event {e:?} in {events:?}"))
}

/// What the fake engine supervisor does and has done.
#[derive(Debug, Default)]
pub struct SupervisorState {
    /// The published generation.
    pub generation: u64,
    /// Restart requests served.
    pub restarts: usize,
    /// Time from publishing a generation until ComfyUI answers.
    pub boot: Duration,
    /// Takes no requests (a dead supervisor).
    pub stuck: bool,
}

/// A stand-in for `run-engine.sh` with `ENGINE_CONTROL_DIR`: on `restart`
/// it removes the file, "kills" the mock ComfyUI (state lost, 503s),
/// publishes the next `<generation> <pid>` atomically, and brings the mock
/// back after `boot`. Events: "engine-killed", "engine-gen N", "engine-up N".
pub struct Supervisor {
    pub dir: PathBuf,
    pub state: std::sync::Arc<Mutex<SupervisorState>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Supervisor {
    pub fn with<T>(&self, f: impl FnOnce(&mut SupervisorState) -> T) -> T {
        f(&mut self.state.lock().unwrap())
    }

    pub fn restarts(&self) -> usize {
        self.with(|s| s.restarts)
    }
}

fn publish(dir: &std::path::Path, generation: u64) {
    let tmp = dir.join("engine.gen.tmp");
    std::fs::write(&tmp, format!("{generation} {}\n", 40_000 + generation)).unwrap();
    std::fs::rename(&tmp, dir.join("engine.gen")).unwrap();
}

impl Env {
    /// Starts the fake supervisor on a control directory in the temp dir
    /// (generation 1 published, ComfyUI up).
    pub fn supervisor(&self, boot: Duration) -> Supervisor {
        let dir = self.tmp.path().join("control");
        std::fs::create_dir_all(&dir).unwrap();
        publish(&dir, 1);
        let state = std::sync::Arc::new(Mutex::new(SupervisorState { generation: 1, boot, ..SupervisorState::default() }));
        let (d, st, mock) = (dir.clone(), state.clone(), self.server.state.clone());
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
                let restart = d.join("restart");
                if st.lock().unwrap().stuck || !restart.exists() {
                    continue;
                }
                std::fs::remove_file(&restart).unwrap();
                {
                    let mut m = mock.lock().unwrap();
                    m.down = true;
                    m.restart();
                    m.events.push("engine-killed".to_owned());
                }
                let (generation, boot) = {
                    let mut s = st.lock().unwrap();
                    s.generation += 1;
                    s.restarts += 1;
                    (s.generation, s.boot)
                };
                publish(&d, generation);
                mock.lock().unwrap().events.push(format!("engine-gen {generation}"));
                tokio::time::sleep(boot).await;
                let mut m = mock.lock().unwrap();
                m.down = false;
                m.events.push(format!("engine-up {generation}"));
            }
        });
        Supervisor { dir, state, task }
    }

    /// A recycling adapter on `sup`'s control directory.
    pub fn recycling_config(&self, sup: &Supervisor, warmup: bool, restart_timeout: Duration) -> ComfyConfig {
        ComfyConfig { recycle_dir: Some(sup.dir.clone()), warmup, restart_timeout, ..self.config() }
    }

    /// Accepted prompts (ID, CLIPTextEncode text).
    pub fn accepted(&self) -> Vec<(String, String)> {
        self.server.with(|m| m.accepted.iter().map(|(id, g)| (id.clone(), crate::mock::find_text(g))).collect())
    }
}
