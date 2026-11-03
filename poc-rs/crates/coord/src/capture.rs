//! Optional operator-local TPM evidence capture for calibrating a first UKI
//! release. Capturing evidence never changes a verifier verdict or lease.

use crate::PROVIDER_READ_LIMIT;
use db_gojson::GoTime;
use db_tpmattest::{Check, Evidence, Expect, RootKind, Verdict};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

const MIN_CAPTURE_INTERVAL: Duration = Duration::from_secs(30);
const MAX_CAPTURE_JSON: usize = PROVIDER_READ_LIMIT * 2;

/// One private directory, retaining at most the latest capture per provider.
pub(crate) struct CaptureStore {
    dir: PathBuf,
    last: Mutex<HashMap<String, Instant>>,
    min_interval: Duration,
}

#[derive(Serialize)]
struct CaptureRecord<'a> {
    schema: &'static str,
    captured_at: GoTime,
    provider_id: &'a str,
    session_id: &'a str,
    expected_account_id: &'a str,
    expected_nonce_hex: String,
    expected_pcrs: &'a [u32],
    ak_activated: bool,
    /// The EK chain, AK binding, quote, event-log replay, statement and
    /// firmware checks passed. This does not authenticate a NodeOS release.
    pre_release_verified: bool,
    /// False for calibration records lacking an admitted signed release.
    release_admitted: bool,
    matched_release: &'a str,
    root_kind: &'a str,
    device_id: &'a str,
    verifier_checks: &'a [Check],
    evidence: &'a Evidence,
}

/// An evidence record is useful only after the TPM proof, event-log replay,
/// statement binding and Secure Boot policy have passed. A release mismatch
/// is allowed because obtaining its measurements is this feature's purpose.
fn pre_release_verified(v: &Verdict) -> bool {
    matches!(v.root_kind, Some(RootKind::AmdPluton | RootKind::AmdFtpm))
        && ["ek-chain", "ak-bound-to-ek", "quote", "event-log", "statement", "secure-boot"]
            .iter()
            .all(|name| v.checks.iter().any(|c| c.name == *name && c.ok))
}

impl CaptureStore {
    pub(crate) fn new(dir: PathBuf) -> Result<Self, String> {
        if dir.as_os_str().is_empty() {
            return Err("capture directory is empty".to_owned());
        }
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.create(&dir).map_err(|e| format!("capture directory {}: {e}", dir.display()))?;
        let meta = fs::symlink_metadata(&dir).map_err(|e| format!("capture directory {}: {e}", dir.display()))?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(format!("capture directory {} must be a real directory", dir.display()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(format!("capture directory {} must not be accessible to group or others (mode 0700)", dir.display()));
            }
        }
        Ok(Self { dir, last: Mutex::new(HashMap::new()), min_interval: MIN_CAPTURE_INTERVAL })
    }

    /// Save an authenticated, fresh TPM proof. This is a calibration record,
    /// never a serving decision. Returns `Ok(false)` for skipped captures.
    pub(crate) fn capture(&self, provider_id: &str, ev: &Evidence, ex: &Expect, v: &Verdict) -> Result<bool, String> {
        if !ex.ak_activated || ev.nonce.len() != 32 || !pre_release_verified(v) {
            return Ok(false);
        }
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        if last.get(provider_id).is_some_and(|at| at.elapsed() < self.min_interval) {
            return Ok(false);
        }
        let record = CaptureRecord {
            schema: "darkbloom-amd/attestation-capture/v1",
            captured_at: GoTime::now_utc(),
            provider_id,
            session_id: &ex.session_id,
            expected_account_id: &ex.account_id,
            expected_nonce_hex: hex::encode(&ev.nonce),
            expected_pcrs: &ex.pcrs,
            ak_activated: ex.ak_activated,
            pre_release_verified: true,
            release_admitted: v.ok,
            matched_release: &v.release,
            root_kind: v.root_kind.as_ref().map(RootKind::as_str).unwrap_or(""),
            device_id: &v.device_id,
            verifier_checks: &v.checks,
            evidence: ev,
        };
        let body = serde_json::to_vec(&record).map_err(|e| format!("serialize attestation capture: {e}"))?;
        if body.len() > MAX_CAPTURE_JSON {
            return Err(format!("attestation capture is {} bytes, above {MAX_CAPTURE_JSON}", body.len()));
        }
        let provider_key = hex::encode(Sha256::digest(provider_id.as_bytes()));
        let nonce_key = hex::encode(&ev.nonce);
        let final_name = format!("{provider_key}-{nonce_key}.json");
        let final_path = self.dir.join(&final_name);
        let mut suffix = [0u8; 8];
        getrandom::fill(&mut suffix).map_err(|e| format!("capture temporary name: {e}"))?;
        let tmp_path = self.dir.join(format!(".{final_name}.{}.tmp", hex::encode(suffix)));
        let write_result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut file = options.open(&tmp_path).map_err(|e| format!("create capture file: {e}"))?;
            file.write_all(&body).map_err(|e| format!("write capture file: {e}"))?;
            file.sync_all().map_err(|e| format!("sync capture file: {e}"))?;
            fs::rename(&tmp_path, &final_path).map_err(|e| format!("publish capture file: {e}"))?;
            Ok::<(), String>(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }
        write_result?;
        self.remove_older(&provider_key, &final_path)?;
        last.insert(provider_id.to_owned(), Instant::now());
        Ok(true)
    }

    fn remove_older(&self, provider_key: &str, keep: &Path) -> Result<(), String> {
        let prefix = format!("{provider_key}-");
        for entry in fs::read_dir(&self.dir).map_err(|e| format!("list capture directory: {e}"))? {
            let entry = entry.map_err(|e| format!("list capture directory: {e}"))?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path != keep && name.starts_with(&prefix) && name.ends_with(".json") {
                fs::remove_file(&path).map_err(|e| format!("remove superseded capture: {e}"))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn check(name: &str, ok: bool) -> Check {
        Check { name: name.to_owned(), ok, effect: "required".to_owned(), detail: String::new() }
    }

    fn pre_release_verdict() -> Verdict {
        Verdict {
            root_kind: Some(RootKind::AmdPluton),
            checks: ["ek-chain", "ak-bound-to-ek", "quote", "event-log", "statement", "secure-boot"]
                .iter()
                .map(|name| check(name, true))
                .chain(std::iter::once(check("release", false)))
                .collect(),
            ..Verdict::default()
        }
    }

    #[test]
    fn captures_only_tpm_proof_and_marks_release_unadmitted() {
        let temp = tempfile::tempdir().unwrap();
        let store = CaptureStore { min_interval: Duration::ZERO, ..CaptureStore::new(temp.path().join("private")).unwrap() };
        let ex = Expect { session_id: "session".to_owned(), pcrs: vec![0, 4, 7, 9, 11, 12, 14], ak_activated: true, ..Expect::default() };
        let mut ev = Evidence { nonce: vec![0x11; 32], event_log: b"public TPM log".to_vec(), ..Evidence::default() };
        let mut fake = pre_release_verdict();
        fake.checks[2].ok = false;
        assert!(!store.capture("../../evil", &ev, &ex, &fake).unwrap(), "bad quote was captured");
        assert!(store.capture("../../evil", &ev, &ex, &pre_release_verdict()).unwrap());
        let dir = temp.path().join("private");
        let files = fs::read_dir(&dir).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(files.len(), 1);
        let first = files[0].path();
        assert!(first.starts_with(&dir));
        assert!(!first.file_name().unwrap().to_string_lossy().contains("evil"));
        let raw: serde_json::Value = serde_json::from_slice(&fs::read(&first).unwrap()).unwrap();
        assert_eq!(raw["pre_release_verified"], true);
        assert_eq!(raw["release_admitted"], false);
        assert_eq!(raw["expected_nonce_hex"], "11".repeat(32));
        assert_eq!(raw["evidence"]["event_log"], "cHVibGljIFRQTSBsb2c=");
        // Even if a stale lease timestamp were present, a rejected release
        // cannot satisfy the coordinator's serving predicate.
        let state = crate::ProviderState {
            verdict: Some(std::sync::Arc::new(pre_release_verdict())),
            lease_until: GoTime::now_utc().add(chrono::Duration::minutes(5)),
            ..crate::ProviderState::default()
        };
        assert!(!crate::Server::leased(&state, &GoTime::now_utc()));
        assert!(!state.verdict.as_ref().unwrap().ok);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
            assert_eq!(fs::metadata(&first).unwrap().permissions().mode() & 0o777, 0o600);
        }
        ev.nonce.fill(0x22);
        assert!(store.capture("../../evil", &ev, &ex, &pre_release_verdict()).unwrap());
        let files = fs::read_dir(&dir).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(files.len(), 1, "old nonce capture retained");
        assert_ne!(files[0].path(), first);
    }

    #[test]
    fn capture_rate_and_size_are_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let store = CaptureStore::new(temp.path().join("private")).unwrap();
        let ex = Expect { session_id: "s".to_owned(), ak_activated: true, ..Expect::default() };
        let mut ev = Evidence { nonce: vec![1; 32], ..Evidence::default() };
        let v = pre_release_verdict();
        assert!(store.capture("provider", &ev, &ex, &v).unwrap());
        ev.nonce.fill(2);
        assert!(!store.capture("provider", &ev, &ex, &v).unwrap(), "second capture inside rate window was written");
        ev.event_log = vec![0; 6 << 20];
        let no_rate = CaptureStore { min_interval: Duration::ZERO, ..CaptureStore::new(temp.path().join("private")).unwrap() };
        assert!(no_rate.capture("other", &ev, &ex, &v).is_err(), "oversized capture was written");
        assert_eq!(fs::read_dir(temp.path().join("private")).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_capture_directory_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(CaptureStore::new(link).is_err());
    }
}
