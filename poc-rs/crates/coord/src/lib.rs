//! A development coordinator for the Darkbloom AMD text PoC.
//! It shows the shape of darkbloom-platform support for TPM-attested
//! providers: enrollment (EK chain + credential activation), per-connection
//! serving leases renewed by fresh quotes, fail-closed dispatch, and
//! consumer-sealed jobs that the coordinator routes and bills without seeing
//! prompts or outputs. The convenience image/video/text endpoints trust the
//! coordinator with plaintext; private text should use consumer sealing.

#![forbid(unsafe_code)]

mod capture;
mod consumer;
mod dashboard;
mod dispatch;
mod generate;
mod provider;
mod text;
mod tls;

pub use tls::TlsListener;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post};
use db_gojson::GoTime;
use db_log::Logger;
use db_release::{Log, TrustedKeys};
use db_tpmattest::{Evidence, Statement, Tier, Verdict, Verifier};
use db_wire as wire;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

/// Coordinator configuration.
pub struct Config {
    /// Evidence verifier (roots, releases, release policy).
    pub verifier: Verifier,
    /// Signs enrollment records.
    pub enrollment_key: SigningKey,
    /// The release transparency log.
    pub release_log: Arc<Log>,
    /// The release log's public key (published).
    pub release_log_key: VerifyingKey,
    /// Trusted release keys (published).
    pub release_keys: TrustedKeys,
    /// Pairing token -> account ID.
    pub provider_tokens: BTreeMap<String, String>,
    /// Consumer API keys.
    pub consumer_keys: BTreeSet<String>,
    /// Attestation challenge interval (default 30 s).
    pub challenge_interval: Duration,
    /// Serving lease TTL (default 3x the challenge interval).
    pub lease_ttl: Duration,
    /// Minimum tier for leases and routing; `None` means attested. A tier
    /// that names no rank (rejected, or an unknown string) is refused by
    /// [`Server::new`] rather than read as "unset".
    pub min_tier: Option<Tier>,
    /// Per-job result cap (default 256 MiB).
    pub max_result_bytes: i64,
    /// Optional private directory for pre-release TPM calibration evidence.
    /// Capturing never grants a lease or changes routing eligibility.
    pub capture_attestation: Option<PathBuf>,
    /// Logger.
    pub logger: Logger,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("verifier", &self.verifier)
            .field("challenge_interval", &self.challenge_interval)
            .field("lease_ttl", &self.lease_ttl)
            .field("min_tier", &self.min_tier)
            .finish_non_exhaustive()
    }
}

/// A billed job.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LedgerEntry {
    /// The consumer (not serialized).
    #[serde(skip)]
    pub owner: String,
    /// Job ID.
    pub job_id: String,
    /// Provider.
    pub provider_id: String,
    /// Provider account.
    #[serde(rename = "provider_account")]
    pub account: String,
    /// Model.
    pub model: String,
    /// Units (from validated metadata; GPU time from the receipt).
    pub units: wire::Units,
    /// Price in micro-USD.
    #[serde(rename = "price_micro_usd")]
    pub price_micro: i64,
    /// Release that served the job.
    pub release: String,
    /// Billing time.
    pub at: GoTime,
}

// Resource bounds (as the Go coordinator).
/// A sealed request holds two prompts and an optional input image.
pub(crate) const MAX_SEALED_REQUEST: usize = 2 * wire::MAX_PROMPT_BYTES + wire::MAX_INPUT_IMAGE_BYTES + 4096;
/// Base64 in JSON.
pub(crate) const MAX_SUBMIT_BYTES: usize = MAX_SEALED_REQUEST * 4 / 3 + (64 << 10);
/// All retained ciphertext.
pub(crate) const MAX_STORED_RESULT_BYTES: i64 = 4 << 30;
pub(crate) const MAX_LEDGER: usize = 10_000;
pub(crate) const MAX_JOBS_PER_CONSUMER: usize = 16;
pub(crate) const MAX_JOBS_TOTAL: usize = 2000;
pub(crate) const MAX_ACTIVE_JOBS_PER_PROVIDER: usize = 8;
/// Provider frames (event logs are at most 2 MiB).
pub(crate) const PROVIDER_READ_LIMIT: usize = 4 << 20;

/// An outgoing provider frame; the writer reports whether it was written.
pub(crate) enum Outgoing {
    Text(String, Option<oneshot::Sender<bool>>),
    Job(String, dispatch::DispatchGuard, oneshot::Sender<bool>),
    Close(u16, &'static str, oneshot::Sender<bool>),
}

/// Immutable facts about one provider connection.
pub(crate) struct Provider {
    pub(crate) conn_id: u64,
    pub(crate) id: String,
    pub(crate) session_id: String,
    pub(crate) account_id: String,
    pub(crate) hello: wire::Hello,
    pub(crate) device_id: String,
    pub(crate) root_name: String,
    pub(crate) activated: bool,
    pub(crate) enrollment: wire::SignedBlob,
    pub(crate) tx: mpsc::Sender<Outgoing>,
    pub(crate) cancel: CancellationToken,
}

/// A verified quote (or failure) for a consumer waiting on its own nonce.
pub(crate) type Attested = Result<(Arc<Evidence>, Arc<Verdict>), String>;

/// Mutable per-connection state (guarded by the server mutex).
#[derive(Default)]
pub(crate) struct ProviderState {
    pub(crate) nonces: HashMap<Vec<u8>, Instant>,
    pub(crate) waiters: HashMap<Vec<u8>, oneshot::Sender<Attested>>,
    /// Consumer credential challenges awaiting the TPM, by request ID.
    pub(crate) activations: HashMap<String, oneshot::Sender<zeroize::Zeroizing<Vec<u8>>>>,
    pub(crate) verdict: Option<Arc<Verdict>>,
    pub(crate) evidence: Option<Arc<Evidence>>,
    pub(crate) stmt: Option<Statement>,
    pub(crate) first_reset: u32,
    pub(crate) first_restart: u32,
    pub(crate) last_clock: u64,
    pub(crate) have_quote: bool,
    pub(crate) lease_until: GoTime,
    pub(crate) lease_id: String,
    pub(crate) quotes: u64,
    pub(crate) close_reason: String,
}

pub(crate) struct Job {
    pub(crate) id: String,
    pub(crate) provider_id: String,
    pub(crate) session_id: String,
    pub(crate) owner: String,
    pub(crate) meta: Vec<u8>,
    pub(crate) parsed: wire::JobMeta,
    /// The sealed request is not kept after dispatch.
    pub(crate) request_digest: String,
    pub(crate) state: &'static str,
    pub(crate) step: i64,
    pub(crate) total: i64,
    /// `None` once released (Go's nil chunks).
    pub(crate) chunks: Option<Vec<Bytes>>,
    pub(crate) size: i64,
    pub(crate) receipt: Vec<u8>,
    pub(crate) receipt_sig: Vec<u8>,
    pub(crate) err: String,
    pub(crate) created: GoTime,
    pub(crate) created_at: Instant,
    /// Set to true when the job reaches "done" or "error" (Go's done channel).
    pub(crate) done: tokio::sync::watch::Sender<bool>,
}

impl Job {
    pub(crate) fn finished(&self) -> bool {
        self.state == "done" || self.state == "error"
    }

    /// Wakes anyone waiting for the job to end (idempotent).
    pub(crate) fn mark_finished(&self) {
        self.done.send_replace(true);
    }
}

#[derive(Default)]
pub(crate) struct State {
    /// Connections by ID: facts and mutable state.
    pub(crate) conns: HashMap<u64, (Arc<Provider>, ProviderState)>,
    /// Provider ID -> current connection.
    pub(crate) providers: HashMap<String, u64>,
    pub(crate) jobs: HashMap<String, Job>,
    pub(crate) ledger: Vec<LedgerEntry>,
    pub(crate) stored_bytes: i64,
    pub(crate) next_conn: u64,
}

impl State {
    /// Forgets a job and releases its ciphertext from the budget.
    pub(crate) fn drop_job(&mut self, id: &str) {
        if let Some(j) = self.jobs.remove(id)
            && j.chunks.is_some()
        {
            self.stored_bytes -= j.size;
        }
    }

    /// Drops the oldest half of finished jobs.
    pub(crate) fn evict_finished(&mut self) {
        let mut done: Vec<(Instant, String)> = self.jobs.values().filter(|j| j.finished()).map(|j| (j.created_at, j.id.clone())).collect();
        done.sort();
        let half = done.len() / 2;
        for (_, id) in done.into_iter().take(half) {
            self.drop_job(&id);
        }
    }
}

/// The coordinator.
pub struct Server {
    pub(crate) cfg: Config,
    pub(crate) verifier: Arc<Verifier>,
    pub(crate) capture: Option<Arc<capture::CaptureStore>>,
    /// The resolved minimum tier.
    pub(crate) min_tier: Tier,
    pub(crate) state: Mutex<State>,
    pub(crate) started: GoTime,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server").field("cfg", &self.cfg).finish_non_exhaustive()
    }
}

/// An invalid coordinator configuration.
#[derive(Debug, thiserror::Error)]
#[error("coord: {0}")]
pub struct ConfigError(String);

impl Server {
    /// Creates a coordinator and starts its janitor (call inside a tokio
    /// runtime).
    pub fn new(mut cfg: Config) -> Result<Arc<Self>, ConfigError> {
        let min_tier = match &cfg.min_tier {
            None => Tier::Attested,
            Some(t) if t.rank() > 0 => t.clone(),
            Some(t) => return Err(ConfigError(format!("minimum tier {:?} is not a serving tier", t.as_str()))),
        };
        if cfg.capture_attestation.is_some()
            && (min_tier.rank() < Tier::Attested.rank()
                || cfg.verifier.allow_dev_roots
                || cfg.verifier.release_policy.as_ref().is_some_and(|p| p.allow_dev))
        {
            return Err(ConfigError("attestation capture requires production-only roots, releases and serving tier".to_owned()));
        }
        if cfg.challenge_interval.is_zero() {
            cfg.challenge_interval = Duration::from_secs(30);
        }
        if cfg.lease_ttl.is_zero() {
            cfg.lease_ttl = 3 * cfg.challenge_interval;
        }
        if cfg.max_result_bytes == 0 {
            cfg.max_result_bytes = 256 << 20;
        }
        let capture = cfg
            .capture_attestation
            .as_ref()
            .map(|dir| capture::CaptureStore::new(dir.clone()).map(Arc::new))
            .transpose()
            .map_err(ConfigError)?;
        let verifier = Arc::new(cfg.verifier.clone());
        let s = Arc::new(Self { cfg, verifier, capture, min_tier, state: Mutex::new(State::default()), started: GoTime::now_utc() });
        let weak = Arc::downgrade(&s);
        tokio::spawn(janitor(weak));
        Ok(s)
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The HTTP routes.
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/v1/provider/ws", get(provider::handle_ws))
            .route("/v1/coordinator", get(consumer::handle_info))
            .route("/v1/providers", get(consumer::handle_providers))
            .route("/v1/providers/{id}/attestation", get(consumer::handle_bundle))
            .route("/v1/providers/{id}/activate", post(consumer::handle_activate))
            .route("/v1/releases", get(consumer::handle_releases))
            .route("/v1/jobs", post(consumer::handle_submit))
            .route("/v1/jobs/{id}", get(consumer::handle_job))
            .route("/v1/jobs/{id}/result", get(consumer::handle_result))
            .route("/v1/ledger", get(consumer::handle_ledger))
            .route("/v1/images/generations", post(generate::handle_images))
            .route("/v1/videos/generations", post(generate::handle_videos))
            .route("/v1/completions", post(text::handle_completions))
            .route("/", get(dashboard::handle_dashboard))
            .with_state(self.clone())
    }

    /// Whether a provider connection holds a live lease.
    pub(crate) fn leased(st: &ProviderState, now: &GoTime) -> bool {
        st.verdict.as_ref().is_some_and(|v| v.ok) && now.before(&st.lease_until)
    }
}

/// Serves the coordinator on `listener` (plain HTTP and WS).
pub async fn serve(listener: tokio::net::TcpListener, server: Arc<Server>) -> std::io::Result<()> {
    axum::serve(listener, server.router()).await
}

/// Serves the coordinator on `listener` over TLS (HTTPS, and WSS for
/// providers) with `tls` (see `db_tls::server_config`: TLS 1.3 only).
pub async fn serve_tls(
    listener: tokio::net::TcpListener,
    server: Arc<Server>,
    tls: Arc<db_tls::rustls::ServerConfig>,
) -> std::io::Result<()> {
    let listener = TlsListener::new(listener, tls, server.cfg.logger.clone())?;
    axum::serve(listener, server.router()).await
}

/// Drops jobs (and their ciphertext) after a retention window, so the
/// coordinator does not accumulate results.
async fn janitor(server: Weak<Server>) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.tick().await;
    loop {
        tick.tick().await;
        let Some(s) = server.upgrade() else { return };
        let mut st = s.lock();
        let old: Vec<String> =
            st.jobs.values().filter(|j| j.created_at.elapsed() > Duration::from_secs(30 * 60)).map(|j| j.id.clone()).collect();
        for id in old {
            st.drop_job(&id);
        }
    }
}

/// Lowercase hex of `n` random bytes.
pub(crate) fn random_id(n: usize) -> String {
    let mut b = vec![0u8; n];
    // The OS CSPRNG does not fail in practice; an all-zero ID would only
    // collide, never leak.
    let _ = getrandom::fill(&mut b);
    hex::encode(b)
}

/// A JSON response encoded like Go's `json.NewEncoder(w).Encode(v)`.
pub(crate) fn json_response<T: Serialize>(code: StatusCode, v: &T) -> Response {
    let body = db_gojson::to_vec_line(v).unwrap_or_else(|_| b"{}\n".to_vec());
    Response::builder()
        .status(code)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// `{"error": "..."}` with a status code.
pub(crate) fn http_error(code: StatusCode, msg: impl Into<String>) -> Response {
    let m: BTreeMap<&str, String> = [("error", msg.into())].into_iter().collect();
    json_response(code, &m)
}

/// The caller's consumer identity (hex of the first 8 bytes of SHA-256 of
/// the API key), or `None` without a configured key. The "Bearer " prefix is
/// trimmed exactly like Go's strings.TrimPrefix.
pub(crate) fn consumer_of(server: &Server, headers: &HeaderMap) -> Option<String> {
    let auth = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or_default();
    let key = auth.strip_prefix("Bearer ").unwrap_or(auth);
    let mut ok = false;
    for k in &server.cfg.consumer_keys {
        ok |= k.len() == key.len() && bool::from(subtle::ConstantTimeEq::ct_eq(k.as_bytes(), key.as_bytes()));
    }
    ok.then(|| hex::encode(Sha256::digest(key.as_bytes()).get(..8).unwrap_or_default()))
}

/// Checks a renewal quote against the session's first quote: the same boot
/// (no TPM reset or restart), a TPM clock that did not go backwards, and the
/// same job and receipt keys.
pub fn continuity(first_reset: u32, first_restart: u32, last_clock: u64, prev: Option<&Statement>, v: &Verdict) -> Result<(), String> {
    if v.reset_count != first_reset || v.restart_count != first_restart {
        return Err(format!(
            "TPM resetCount/restartCount changed ({first_reset}/{first_restart} -> {}/{}): the machine rebooted; re-register",
            v.reset_count, v.restart_count
        ));
    }
    // Equal is fine: quotes taken within the same millisecond share a clock
    // value; every quote is over a fresh single-use nonce anyway.
    if v.clock < last_clock {
        return Err("TPM clock went backwards".to_owned());
    }
    let (Some(prev), Some(cur)) = (prev, v.statement.as_ref()) else {
        return Err("missing statement".to_owned());
    };
    if cur.job_public_key != prev.job_public_key || cur.receipt_public_key != prev.receipt_public_key {
        return Err("job or receipt key changed within a session".to_owned());
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn stmt(job: &[u8], rcpt: &[u8]) -> Statement {
        Statement { job_public_key: job.to_vec(), receipt_public_key: rcpt.to_vec(), ..Statement::default() }
    }

    fn verdict(reset: u32, restart: u32, clock: u64, st: Option<Statement>) -> Verdict {
        Verdict { reset_count: reset, restart_count: restart, clock, statement: st, ..Verdict::default() }
    }

    fn config(min_tier: Option<Tier>) -> Config {
        let k = SigningKey::from_bytes(&[7u8; 32]);
        Config {
            verifier: Verifier::default(),
            enrollment_key: SigningKey::from_bytes(&[9u8; 32]),
            release_log: Arc::new(Log::new(k.clone())),
            release_log_key: k.verifying_key(),
            release_keys: TrustedKeys::default(),
            provider_tokens: BTreeMap::new(),
            consumer_keys: BTreeSet::new(),
            challenge_interval: Duration::ZERO,
            lease_ttl: Duration::ZERO,
            min_tier,
            max_result_bytes: 0,
            capture_attestation: None,
            logger: Logger::discard(),
        }
    }

    #[tokio::test]
    async fn capture_cannot_enable_development_serving() {
        let mut cfg = config(Some(Tier::DevSimulated));
        cfg.capture_attestation = Some(std::path::PathBuf::from("unused-private-capture"));
        assert!(Server::new(cfg).is_err());
        let mut cfg = config(Some(Tier::Attested));
        cfg.capture_attestation = Some(std::path::PathBuf::from("unused-private-capture"));
        cfg.verifier.allow_dev_roots = true;
        assert!(Server::new(cfg).is_err());
        let mut cfg = config(Some(Tier::Attested));
        cfg.capture_attestation = Some(std::path::PathBuf::from("unused-private-capture"));
        cfg.verifier.release_policy = Some(db_release::Policy { allow_dev: true, ..Default::default() });
        assert!(Server::new(cfg).is_err());
    }

    /// An unset minimum tier means attested; a tier string that names no
    /// serving tier is a configuration error, not "unset".
    #[tokio::test]
    async fn minimum_tier_is_explicit() {
        assert_eq!(Server::new(config(None)).unwrap().min_tier, Tier::Attested);
        assert_eq!(Server::new(config(Some(Tier::DevSimulated))).unwrap().min_tier, Tier::DevSimulated);
        for bad in [Tier::Rejected, Tier::parse("attested-plus"), Tier::parse("")] {
            let err = Server::new(config(Some(bad.clone()))).unwrap_err().to_string();
            assert!(err.contains("is not a serving tier"), "{bad:?}: {err}");
        }
    }

    #[test]
    fn continuity_rules() {
        let st = stmt(b"job", b"rcpt");
        assert_eq!(continuity(5, 0, 1000, Some(&st), &verdict(5, 0, 2000, Some(st.clone()))), Ok(()));
        // Two quotes in the same millisecond share a clock value.
        assert_eq!(continuity(5, 0, 1000, Some(&st), &verdict(5, 0, 1000, Some(st.clone()))), Ok(()));
        let cases = [
            ("reboot (resetCount)", verdict(6, 0, 2000, Some(st.clone()))),
            ("resume (restartCount)", verdict(5, 1, 2000, Some(st.clone()))),
            ("clock went backwards", verdict(5, 0, 999, Some(st.clone()))),
            ("job key changed", verdict(5, 0, 2000, Some(stmt(b"other", b"rcpt")))),
            ("receipt key changed", verdict(5, 0, 2000, Some(stmt(b"job", b"other")))),
            ("statement missing", verdict(5, 0, 2000, None)),
        ];
        for (name, v) in cases {
            assert!(continuity(5, 0, 1000, Some(&st), &v).is_err(), "{name}: accepted");
        }
        assert!(continuity(5, 0, 1000, None, &verdict(5, 0, 2000, Some(st))).is_err(), "no previous statement accepted");
    }
}
