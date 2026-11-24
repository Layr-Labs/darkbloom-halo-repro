//! Image, video and text generation engines. The provider agent is the engine's
//! only client; the engine listens on loopback (in the Node OS: inside a
//! network namespace with no route out) and keeps inputs and outputs on
//! tmpfs.

#![forbid(unsafe_code)]

use db_release::Artifact;
use db_tpmattest::ModelReport;
use db_wire::{JobRequest, ModelCap, Units};
use std::future::Future;
use std::pin::Pin;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

mod comfy;
mod fake;
mod llama;
mod sanitize;

pub use comfy::{Comfy, ComfyConfig, comfy_release};
pub use fake::Fake;
pub use llama::{Llama, LlamaConfig, llama_release};
pub use sanitize::{MAX_INPUT_PIXELS, MAX_INPUT_SIDE, sanitize_image};

/// A finished generation. The content is zeroized on drop.
pub struct Output {
    /// Result bytes (PNG or MP4).
    pub data: Zeroizing<Vec<u8>>,
    /// MIME type.
    pub mime: String,
    /// Billable units as measured by the engine.
    pub units: Units,
}

impl std::fmt::Debug for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Output").field("bytes", &self.data.len()).field("mime", &self.mime).finish_non_exhaustive()
    }
}

/// An engine failure. Its text may echo request content (e.g. a ComfyUI
/// validation error quoting the prompt), so it is only ever logged locally
/// on the provider and never sent to the coordinator.
#[derive(Debug, thiserror::Error)]
#[error("engine: {0}")]
pub struct EngineError(pub String);

const CANCELLED: &str = "job cancelled";
const UNAVAILABLE: &str = "engine unavailable: the restart after the previous job was not confirmed in time";

impl EngineError {
    /// The error an engine returns when the job's cancellation token fired
    /// (after the job was stopped and purged).
    pub fn cancelled() -> Self {
        Self(CANCELLED.to_owned())
    }

    /// Whether this is [`EngineError::cancelled`].
    pub fn is_cancelled(&self) -> bool {
        self.0 == CANCELLED
    }

    /// The error a recycling engine returns when the fresh engine process
    /// requested after the previous job did not come up in time; the job
    /// never reached the engine.
    pub fn unavailable() -> Self {
        Self(UNAVAILABLE.to_owned())
    }

    /// Whether this is [`EngineError::unavailable`].
    pub fn is_unavailable(&self) -> bool {
        self.0 == UNAVAILABLE
    }
}

/// Progress callback: (step, total).
pub type Progress<'a> = &'a (dyn Fn(i64, i64) + Send + Sync);

/// A boxed, sendable future.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Generates images or videos.
pub trait Engine: Send + Sync {
    /// Identifies the engine build, e.g. `comfyui@<commit>`.
    fn name(&self) -> String;
    /// The approved workflow templates and their hashes.
    fn workflows(&self) -> Vec<Artifact>;
    /// Loaded models with verified file hashes.
    fn models(&self) -> Vec<ModelReport>;
    /// What the engine serves.
    fn caps(&self) -> Vec<ModelCap>;
    /// Runs one job. `progress` may be called with (step, total). When
    /// `cancel` fires the engine stops the job, purges it and returns an
    /// error. Implementations must purge prompts and outputs on every path.
    fn generate<'a>(
        &'a self,
        req: &'a JobRequest,
        progress: Progress<'a>,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<Output, EngineError>>;
}
