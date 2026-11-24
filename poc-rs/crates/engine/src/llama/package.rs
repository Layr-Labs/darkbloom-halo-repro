//! Checks the exact signed package manifest selected by the trusted loader.
//! The loader owns signature verification, monotonic package selection and
//! mounting the image read-only through dm-verity. Rust independently binds
//! the manifest's identity to the loaded GGUF and fixed workflow.

use crate::EngineError;
use db_release::Artifact;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::io::Read as _;
use std::path::Path;

const MAX_MANIFEST_BYTES: u64 = 4096;

// Lexical field order matches the package verifier's canonical JSON.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Package {
    domain: String,
    engine_version: String,
    image_sha256: String,
    image_size: i64,
    model_id: String,
    model_sha256: String,
    model_size: i64,
    security_version: u32,
    tree_sha256: String,
    tree_size: i64,
    v: u32,
    verity_root: String,
    workflow_sha256: String,
}

fn valid_id(value: &str, plus: bool) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') || (plus && matches!(b, b'+' | b':')))
}

fn lowercase_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

pub(super) fn manifest_artifact(path: &Path, model_id: &str, gguf: &Artifact, workflow: &Artifact) -> Result<Artifact, EngineError> {
    let fail = || EngineError("llama model-package manifest is invalid or does not match the selected model and workflow".to_owned());
    let file = std::fs::File::open(path).map_err(|_| fail())?;
    let mut raw = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1).read_to_end(&mut raw).map_err(|_| fail())?;
    if raw.is_empty() || raw.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(fail());
    }
    let package: Package = serde_json::from_slice(&raw).map_err(|_| fail())?;
    if package.v != 1
        || package.domain != "darkbloom/model-package/v1"
        || !valid_id(&package.model_id, false)
        || !valid_id(&package.engine_version, true)
        || package.security_version == 0
        || package.model_size <= 0
        || package.image_size <= 0
        || package.tree_size <= 0
        || ![&package.model_sha256, &package.verity_root, &package.workflow_sha256, &package.image_sha256, &package.tree_sha256]
            .into_iter()
            .all(|value| lowercase_digest(value))
        || package.model_id != model_id
        || package.model_sha256 != gguf.sha256
        || package.model_size != gguf.bytes
        || package.workflow_sha256 != workflow.sha256
    {
        return Err(fail());
    }
    // All string fields are ASCII and all fields are integers or strings.
    // This is byte-identical to Python sort_keys/compact/ensure_ascii + LF.
    let mut canonical = serde_json::to_vec(&package).map_err(|_| fail())?;
    canonical.push(b'\n');
    if canonical != raw {
        return Err(fail());
    }
    Ok(Artifact { name: "manifest.json".to_owned(), sha256: hex::encode(Sha256::digest(&raw)), bytes: raw.len() as i64 })
}
