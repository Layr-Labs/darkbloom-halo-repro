//! Model file discovery and hashing, with the Go adapter's hash cache.
//!
//! The cache avoids re-hashing multi-GB weights on every start of the PoC
//! on a development OS. It is untrusted convenience: in the Node OS the
//! model store is dm-verity protected and listed in the release manifest.
//! The file format is the Go reference's (`json.MarshalIndent` of
//! `{"entries": {real path: {"size", "mtime" (Unix ns), "sha256"}}}`), so a
//! cache written by either implementation is reused by the other.

use super::graphs::{ComfyModel, MODELS};
use crate::EngineError;
use db_release::Artifact;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// The cache file contents.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct HashCache {
    #[serde(default, deserialize_with = "db_gojson::null_default")]
    entries: BTreeMap<String, HashEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct HashEntry {
    #[serde(deserialize_with = "db_gojson::null_default")]
    size: i64,
    #[serde(deserialize_with = "db_gojson::null_default")]
    mtime: i64,
    #[serde(deserialize_with = "db_gojson::null_default")]
    sha256: String,
}

/// A file's modification time in Unix nanoseconds (Go's `ModTime().UnixNano()`).
fn mtime_nanos(md: &std::fs::Metadata) -> i64 {
    let Ok(t) = md.modified() else { return 0 };
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_nanos()).unwrap_or(i64::MAX),
        Err(e) => i64::try_from(e.duration().as_nanos()).map(|n| -n).unwrap_or(i64::MIN),
    }
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(data)
}

impl HashCache {
    /// Reads a cache; a missing or unreadable cache is empty.
    pub(crate) fn load(path: Option<&Path>) -> Self {
        let Some(path) = path else { return Self::default() };
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Writes the cache (best effort, mode 0600).
    pub(crate) fn save(&self, path: Option<&Path>) {
        let Some(path) = path else { return };
        if let Ok(b) = db_gojson::to_vec_indent(self) {
            let _ = write_private(path, &b);
        }
    }

    /// The SHA-256 (hex) and size of a file, from the cache when its size
    /// and modification time are unchanged.
    pub(crate) fn hash(&mut self, path: &Path) -> Result<(String, i64), String> {
        let real = std::fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let md = std::fs::metadata(&real).map_err(|e| format!("{}: {e}", real.display()))?;
        let key = real.to_string_lossy().into_owned();
        let size = i64::try_from(md.len()).unwrap_or(i64::MAX);
        let mtime = mtime_nanos(&md);
        if let Some(e) = self.entries.get(&key)
            && e.size == size
            && e.mtime == mtime
        {
            return Ok((e.sha256.clone(), e.size));
        }
        let (sum, n) = db_release::file_sha256(&real).map_err(|e| e.to_string())?;
        let sha256 = hex::encode(sum);
        let n = i64::try_from(n).unwrap_or(i64::MAX);
        self.entries.insert(key, HashEntry { size: n, mtime, sha256: sha256.clone() });
        Ok((sha256, n))
    }
}

/// Searches the model roots, in order, for a relative path.
fn find_model_file(dirs: &[PathBuf], rel: &str) -> Option<PathBuf> {
    dirs.iter().map(|d| d.join(rel)).find(|p| std::fs::metadata(p).is_ok())
}

fn base_name(rel: &str) -> String {
    Path::new(rel).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| rel.to_owned())
}

/// An approved model whose files are all present, with their hashes.
pub(crate) struct Present {
    pub(crate) model: &'static ComfyModel,
    pub(crate) files: Vec<Artifact>,
}

/// Finds and hashes the approved models' files. Models with a missing file
/// are left out; a file that cannot be hashed is an error.
pub(crate) fn scan(dirs: &[PathBuf], cache: &mut HashCache) -> Result<Vec<Present>, EngineError> {
    let mut out = Vec::new();
    'models: for model in &MODELS {
        let mut files = Vec::with_capacity(model.files.len());
        for rel in model.files {
            let Some(path) = find_model_file(dirs, rel) else { continue 'models };
            let (sha256, bytes) = cache.hash(&path).map_err(|e| EngineError(format!("model {}: {e}", model.id)))?;
            files.push(Artifact { name: base_name(rel), sha256, bytes });
        }
        out.push(Present { model, files });
    }
    Ok(out)
}
