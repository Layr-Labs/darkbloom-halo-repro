//! The provider agent: connects out to the coordinator, enrolls (EK chain,
//! credential activation), answers attestation challenges with quotes that
//! bind a per-session job key and receipt key, and serves sealed jobs.

use crate::status::collect_status;
use db_engine::Engine;
use db_gojson::GoTime;
use db_log::{Logger, logf};
use db_sealbox::KeyPair;
use db_tpmattest::{RuntimeReport, STATEMENT_DOMAIN, Statement, Status};
use db_tpmdev::{AttestError, Attester, BoundKey};
use db_wire as wire;
use ed25519_dalek::{Signer as _, SigningKey};
use futures_util::{SinkExt as _, StreamExt as _};
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use zeroize::{Zeroize as _, Zeroizing};

/// Agent version.
pub const VERSION: &str = "0.1.0-poc";

/// Bound on accepted-but-unfinished jobs per session.
const MAX_QUEUED_JOBS: usize = 8;
/// Jobs may carry an input image (up to 16 MiB sealed, base64 in JSON).
const READ_LIMIT: usize = 40 << 20;
/// Per-frame write timeout.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Per-job deadline.
const JOB_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Reports firmware/kernel/GPU status for statements.
pub type StatusFn = Arc<dyn Fn() -> Status + Send + Sync>;

/// Agent configuration.
#[derive(Clone)]
pub struct Config {
    /// `wss://host/v1/provider/ws` (or `ws://` over loopback or a tunnel).
    pub coordinator_url: String,
    /// TLS for `wss://` URLs. `None`: Mozilla's roots (webpki-roots), TLS 1.3
    /// only; a pinned CA bundle comes from `db_tls::client_config`.
    pub tls: Option<Arc<db_tls::rustls::ClientConfig>>,
    /// Pairing token.
    pub account_token: String,
    /// Job KEM (default X-Wing).
    pub job_kem: String,
    /// Status source (default [`collect_status`]).
    pub status: Option<StatusFn>,
    /// Logger.
    pub logger: Logger,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config").field("coordinator_url", &self.coordinator_url).field("job_kem", &self.job_kem).finish_non_exhaustive()
    }
}

/// Ends the agent: the TPM no longer holds its keys (a TPM reset, i.e. a
/// reboot), so the service manager must restart the agent, which re-enrolls.
#[derive(Debug, thiserror::Error)]
#[error("fatal: {0}")]
pub struct FatalError(pub String);

/// Why a session ended.
#[derive(Debug, thiserror::Error)]
enum SessionError {
    #[error("{0}")]
    Fatal(#[from] FatalError),
    #[error("{0}")]
    Other(String),
}

impl SessionError {
    fn other(e: impl std::fmt::Display) -> Self {
        Self::Other(e.to_string())
    }
}

/// A provider agent.
pub struct Agent {
    cfg: Config,
    status: StatusFn,
    att: Arc<Attester>,
    engine: Arc<dyn Engine>,
    agent_hash: String,
    log: Logger,
}

impl std::fmt::Debug for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent").field("cfg", &self.cfg).field("agent_hash", &self.agent_hash).finish_non_exhaustive()
    }
}

/// SHA-256 of the running executable (what a release pins).
fn self_hash() -> String {
    let Ok(exe) = std::env::current_exe() else { return String::new() };
    db_release::file_sha256(&exe).map(|(sum, _)| hex::encode(sum)).unwrap_or_default()
}

impl Agent {
    /// Creates an agent.
    pub fn new(mut cfg: Config, att: Arc<Attester>, engine: Arc<dyn Engine>) -> Arc<Self> {
        if cfg.job_kem.is_empty() {
            cfg.job_kem = db_sealbox::KEM_XWING.to_owned();
        }
        let status = cfg.status.clone().unwrap_or_else(|| Arc::new(collect_status));
        let log = cfg.logger.clone();
        Arc::new(Self { cfg, status, att, engine, agent_hash: self_hash(), log })
    }

    /// SHA-256 of the running agent binary.
    pub fn agent_sha256(&self) -> &str {
        &self.agent_hash
    }

    /// Connects to the coordinator and serves until `shutdown` fires,
    /// reconnecting with backoff. Each connection is a new session with
    /// fresh job and receipt keys, so keys from a previous session cannot
    /// open new jobs. Returns an error only for fatal TPM failures.
    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) -> Result<(), FatalError> {
        let mut backoff = Duration::from_secs(1);
        loop {
            let res = self.clone().session(shutdown.clone()).await;
            if shutdown.is_cancelled() {
                return Ok(());
            }
            match res {
                Err(SessionError::Fatal(e)) => return Err(e),
                Err(SessionError::Other(e)) => logf!(self.log, "session ended: {e}; reconnecting in {}s", backoff.as_secs()),
                Ok(()) => logf!(self.log, "session ended; reconnecting in {}s", backoff.as_secs()),
            }
            tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                () = tokio::time::sleep(backoff) => {}
            }
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    }

    async fn session(self: Arc<Self>, shutdown: CancellationToken) -> Result<(), SessionError> {
        let ws_cfg = WebSocketConfig::default().max_message_size(Some(READ_LIMIT)).max_frame_size(Some(READ_LIMIT));
        // Used for wss:// only; ws:// stays plain.
        let tls = match &self.cfg.tls {
            Some(c) => c.clone(),
            None => Arc::new(db_tls::client_config(&db_tls::Trust::WebPki).map_err(SessionError::other)?),
        };
        let connect = tokio_tungstenite::connect_async_tls_with_config(
            self.cfg.coordinator_url.as_str(),
            Some(ws_cfg),
            false,
            Some(tokio_tungstenite::Connector::Rustls(tls)),
        );
        let (ws, _) = tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            r = tokio::time::timeout(Duration::from_secs(30), connect) => {
                r.map_err(|_| SessionError::other("connect timed out"))?.map_err(SessionError::other)?
            }
        };
        let (sink, mut stream) = ws.split();
        let token = shutdown.child_token();
        // One writer per connection: job tasks and the control loop queue
        // frames; order is preserved (chunks before job_done).
        let (tx, rx) = mpsc::channel::<Message>(32);
        let writer = tokio::spawn(write_frames(sink, rx, token.clone(), self.log.clone(), WRITE_TIMEOUT));
        let session = Arc::new(Session {
            agent: self.clone(),
            tx,
            token: token.clone(),
            welcome: Mutex::new(wire::Welcome::default()),
            release: Mutex::new(String::new()),
            jobs: Mutex::new(HashMap::new()),
            gpu: Semaphore::new(1),
            job_key: KeyPair::generate(&self.cfg.job_kem).map_err(SessionError::other)?,
            receipt_key: SigningKey::from_bytes(&*random32().map_err(SessionError::other)?),
            bound: Mutex::new(None),
            tasks: TaskTracker::new(),
        });
        let result = session.clone().serve(&mut stream).await;
        // The session's TPM-bound key dies with the session, but only after
        // the jobs that may still be using it have stopped.
        let flush = async {
            let bound = lock(&session.bound).take();
            if let Some(bk) = bound {
                let att = self.att.clone();
                let _ = tokio::task::spawn_blocking(move || att.flush_bound(&bk)).await;
            }
        };
        end_session(&token, &session.tasks, flush).await;
        let _ = writer.await;
        result
    }
}

/// Ends a session: cancels it, waits for its in-flight job tasks (Go: the
/// session's WaitGroup), then runs `flush`.
async fn end_session(token: &CancellationToken, tasks: &TaskTracker, flush: impl Future<Output = ()>) {
    token.cancel();
    tasks.close();
    tasks.wait().await;
    flush.await;
}

/// Writes queued frames to the connection in order. A frame the coordinator
/// does not take within `timeout` (a stalled connection) cancels the session
/// instead of wedging the agent; so does any write error.
async fn write_frames<S>(mut sink: S, mut rx: mpsc::Receiver<Message>, token: CancellationToken, log: Logger, timeout: Duration)
where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::fmt::Display,
{
    loop {
        let msg = tokio::select! {
            () = token.cancelled() => break,
            m = rx.recv() => match m { Some(m) => m, None => break },
        };
        let sent = tokio::select! {
            () = token.cancelled() => break,
            r = tokio::time::timeout(timeout, sink.send(msg)) => r,
        };
        match sent {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                logf!(log, "write: {e}");
                token.cancel();
                break;
            }
            Err(_) => {
                logf!(log, "write: the coordinator took no frame for {}s; ending the session", timeout.as_secs());
                token.cancel();
                break;
            }
        }
    }
    let _ = tokio::time::timeout(timeout.min(Duration::from_secs(5)), sink.close()).await;
}

/// Records the release a lease names and reports whether it is the
/// session's first. A malformed lease, or one naming no release, is ignored
/// (`None`) instead of clearing the release reported in receipts.
fn record_lease(release: &Mutex<String>, data: &[u8]) -> Option<(wire::Lease, bool)> {
    let l = db_gojson::from_slice::<wire::Lease>(data).ok().filter(|l| !l.release.is_empty())?;
    let mut rel = lock(release);
    let first = rel.is_empty();
    rel.clone_from(&l.release);
    Some((l, first))
}

fn random32() -> Result<Zeroizing<[u8; 32]>, getrandom::Error> {
    let mut b = Zeroizing::new([0u8; 32]);
    getrandom::fill(b.as_mut_slice())?;
    Ok(b)
}

struct Session {
    agent: Arc<Agent>,
    tx: mpsc::Sender<Message>,
    token: CancellationToken,
    welcome: Mutex<wire::Welcome>,
    release: Mutex<String>,
    jobs: Mutex<HashMap<String, CancellationToken>>,
    gpu: Semaphore,
    job_key: KeyPair,
    receipt_key: SigningKey,
    /// TPM-enforced decryption share for this session.
    bound: Mutex<Option<Arc<BoundKey>>>,
    /// In-flight job tasks, joined before the bound key is flushed.
    tasks: TaskTracker,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Session {
    fn log(&self) -> &Logger {
        &self.agent.log
    }

    async fn send<T: serde::Serialize>(&self, v: &T) -> Result<(), SessionError> {
        let body = wire::marshal(v).map_err(SessionError::other)?;
        let text = String::from_utf8(body).map_err(SessionError::other)?;
        match tokio::time::timeout(WRITE_TIMEOUT, self.tx.send(Message::text(text))).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(SessionError::other("connection closed")),
            Err(_) => Err(SessionError::other("write timed out")),
        }
    }

    /// Queues a frame without waiting (progress updates may be dropped).
    fn try_send<T: serde::Serialize>(&self, v: &T) {
        if let Ok(body) = wire::marshal(v)
            && let Ok(text) = String::from_utf8(body)
        {
            let _ = self.tx.try_send(Message::text(text));
        }
    }

    async fn serve<S>(self: Arc<Self>, stream: &mut S) -> Result<(), SessionError>
    where
        S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
    {
        let a = &self.agent;
        let att = a.att.clone();
        let (cert, icas) = att.ek_certificate();
        self.send(&wire::Hello {
            msg_type: wire::msg::HELLO.to_owned(),
            protocol: wire::PROTOCOL.to_owned(),
            account_token: a.cfg.account_token.clone(),
            agent_version: VERSION.to_owned(),
            tpm_mode: att.mode().to_owned(),
            ek_public: att.ek_public().to_vec(),
            ek_cert: cert.to_vec(),
            ek_icas: icas.to_vec(),
            ak_public: att.ak_public().to_vec(),
            models: a.engine.caps(),
            gpu: (a.status)().gpu.target,
        })
        .await?;
        loop {
            let msg = tokio::select! {
                () = self.token.cancelled() => return Err(SessionError::other("connection closed")),
                m = stream.next() => match m {
                    None => return Err(SessionError::other("connection closed by coordinator")),
                    Some(Err(e)) => return Err(SessionError::other(e)),
                    Some(Ok(m)) => m,
                },
            };
            let data = match msg {
                Message::Text(t) => t.as_bytes().to_vec(),
                Message::Binary(b) => b.to_vec(),
                Message::Close(_) => return Err(SessionError::other("connection closed by coordinator")),
                _ => continue,
            };
            self.clone().on_frame(&data).await?;
        }
    }

    async fn on_frame(self: Arc<Self>, data: &[u8]) -> Result<(), SessionError> {
        let t: wire::Typed = db_gojson::from_slice(data).map_err(|e| SessionError::other(format!("bad frame: {e}")))?;
        let a = self.agent.clone();
        match t.msg_type.as_str() {
            wire::msg::WELCOME => {
                let w: wire::Welcome = db_gojson::from_slice(data).map_err(SessionError::other)?;
                if w.provider_id != a.att.provider_id() {
                    return Err(SessionError::other("coordinator derived a different provider ID"));
                }
                if lock(&self.bound).is_none() {
                    let (att, sid) = (a.att.clone(), w.session_id.clone());
                    let bk = tokio::task::spawn_blocking(move || att.new_bound_key(&sid))
                        .await
                        .map_err(SessionError::other)?
                        .map_err(|e| FatalError(e.to_string()))?;
                    *lock(&self.bound) = Some(Arc::new(bk));
                }
                logf!(a.log, "session {} for account {} (provider {})", w.session_id, w.account_id, w.provider_id);
                *lock(&self.welcome) = w;
            }
            wire::msg::CREDENTIAL_CHALLENGE => {
                let ch: wire::CredentialChallenge = db_gojson::from_slice(data).map_err(SessionError::other)?;
                let att = a.att.clone();
                let (id_object, enc_secret) = (ch.id_object, ch.enc_secret);
                let res = tokio::task::spawn_blocking(move || att.activate(&id_object, &enc_secret)).await.map_err(SessionError::other)?;
                let secret = match res {
                    Ok(s) => s,
                    // A consumer's challenge that does not match our EK/AK gets
                    // an empty answer; it must not end the session.
                    Err(e) if !ch.request_id.is_empty() => {
                        logf!(a.log, "consumer activation challenge failed: {e}");
                        Zeroizing::new(Vec::new())
                    }
                    Err(e) => return Err(SessionError::other(format!("activate credential: {e}"))),
                };
                self.send(&wire::CredentialResponse {
                    msg_type: wire::msg::CREDENTIAL_RESPONSE.to_owned(),
                    request_id: ch.request_id,
                    secret,
                })
                .await?;
            }
            wire::msg::ATTEST_CHALLENGE => {
                let ch: wire::AttestChallenge = db_gojson::from_slice(data).map_err(SessionError::other)?;
                if lock(&self.welcome).session_id.is_empty() {
                    return Err(SessionError::other("attestation challenge before welcome"));
                }
                let stmt = self.statement().map_err(SessionError::other)?;
                let att = a.att.clone();
                let (nonce, pcrs, st) = (ch.nonce.clone(), ch.pcrs.clone(), stmt.clone());
                let res = tokio::task::spawn_blocking(move || att.attest(&nonce, &st, &pcrs)).await.map_err(SessionError::other)?;
                let ev = match res {
                    Ok(ev) => ev,
                    // A malformed challenge is the coordinator's problem, not
                    // a reason to crash or to leave: answer nothing.
                    Err(AttestError::BadChallenge(e)) => {
                        logf!(a.log, "ignoring challenge: {e}");
                        return Ok(());
                    }
                    // The TPM lost our keys (TPM reset = reboot): stop serving;
                    // the service manager restarts the agent, which re-enrolls.
                    Err(e) => return Err(FatalError(e.to_string()).into()),
                };
                self.send(&wire::Attestation {
                    msg_type: wire::msg::ATTESTATION.to_owned(),
                    nonce: ch.nonce,
                    statement: stmt,
                    quote_attest: ev.quote_attest,
                    quote_sig: ev.quote_sig,
                    event_log: ev.event_log,
                })
                .await?;
            }
            wire::msg::LEASE => match record_lease(&self.release, data) {
                None => logf!(a.log, "ignoring malformed lease"),
                Some((l, true)) => logf!(a.log, "lease granted: tier={} release={} until {}", l.tier, l.release, l.expires_at.rfc3339()),
                Some(_) => {}
            },
            wire::msg::JOB => {
                let j: wire::Job = db_gojson::from_slice(data).map_err(SessionError::other)?;
                // Bound the work a coordinator can queue on this machine, and
                // refuse duplicate job IDs instead of losing track of one.
                let token = {
                    let mut jobs = lock(&self.jobs);
                    if j.job_id.is_empty() || jobs.contains_key(&j.job_id) || jobs.len() >= MAX_QUEUED_JOBS {
                        None
                    } else {
                        let t = self.token.child_token();
                        jobs.insert(j.job_id.clone(), t.clone());
                        Some(t)
                    }
                };
                let Some(token) = token else {
                    let why = format!("duplicate job or queue full ({MAX_QUEUED_JOBS})");
                    self.fail(&j.job_id, wire::codes::REJECTED, &why).await;
                    return Ok(());
                };
                let s = self.clone();
                self.tasks.spawn(async move {
                    let deadline = token.clone();
                    let timer = tokio::spawn(async move {
                        tokio::select! {
                            () = deadline.cancelled() => {}
                            () = tokio::time::sleep(JOB_TIMEOUT) => deadline.cancel(),
                        }
                    });
                    let id = j.job_id.clone();
                    s.run_job(j, token.clone()).await;
                    token.cancel();
                    timer.abort();
                    lock(&s.jobs).remove(&id);
                });
            }
            wire::msg::JOB_CANCEL => {
                let c: wire::JobCancel = db_gojson::from_slice(data).unwrap_or_default();
                if let Some(t) = lock(&self.jobs).get(&c.job_id) {
                    t.cancel();
                }
            }
            wire::msg::ERROR => {
                let e: wire::ErrorMsg = db_gojson::from_slice(data).unwrap_or_default();
                return Err(SessionError::other(format!("coordinator: {}", e.message)));
            }
            _ => {}
        }
        Ok(())
    }

    /// The statement is re-collected for every quote so status changes (for
    /// example DASH being enabled from another OS) show up at the next
    /// challenge.
    fn statement(&self) -> Result<Vec<u8>, serde_json::Error> {
        let a = &self.agent;
        let w = lock(&self.welcome).clone();
        let st = Statement {
            version: 1,
            domain: STATEMENT_DOMAIN.to_owned(),
            provider_id: a.att.provider_id(),
            account_id: w.account_id,
            session_id: w.session_id,
            job_kem: self.job_key.kem_name().to_owned(),
            job_public_key: self.job_key.public().to_vec(),
            receipt_public_key: self.receipt_key.verifying_key().to_bytes().to_vec(),
            tpm_mode: a.att.mode().to_owned(),
            status: (a.status)(),
            runtime: RuntimeReport {
                agent_sha256: a.agent_hash.clone(),
                engine: a.engine.name(),
                workflows: a.engine.workflows(),
                models: a.engine.models(),
            },
            bound_key: lock(&self.bound).as_ref().map(|bk| bk.public.clone()),
            created_at: GoTime::now_utc().truncate_secs(),
        };
        db_gojson::to_vec(&st)
    }

    /// Reports a job failure with a fixed code and message only. Error text
    /// from the engine or from decoding can contain request content (a
    /// ComfyUI validation error may echo the prompt), so details stay in the
    /// local log and never reach the coordinator.
    async fn fail(&self, job_id: &str, code: &str, detail: &str) {
        if std::env::var("DBNODE_DEBUG").as_deref() == Ok("1") {
            // Development only: the detail may contain request content.
            logf!(self.log(), "job {job_id} failed: {code}: {detail}");
        } else {
            logf!(self.log(), "job {job_id} failed: {code}");
        }
        let _ = self
            .send(&wire::JobError {
                msg_type: wire::msg::JOB_ERROR.to_owned(),
                job_id: job_id.to_owned(),
                code: code.to_owned(),
                message: wire::error_text(code).to_owned(),
            })
            .await;
    }

    async fn run_job(&self, j: wire::Job, token: CancellationToken) {
        let a = &self.agent;
        let meta: wire::JobMeta = match db_gojson::from_slice(&j.meta) {
            Ok(m) if m_job_ok(&m, &j) => m,
            _ => {
                self.fail(&j.job_id, wire::codes::BAD_META, "job metadata does not parse or names another job").await;
                return;
            }
        };
        let session_id = lock(&self.welcome).session_id.clone();
        if meta.provider_id != a.att.provider_id() || meta.session_id != session_id {
            self.fail(&j.job_id, wire::codes::WRONG_SESSION, "job was sealed for another provider session").await;
            return;
        }
        // Take the GPU slot before decrypting: queued jobs stay sealed, so at
        // most one job's plaintext exists in this process at any time. The
        // slot is held until the job ends.
        let _gpu = tokio::select! {
            p = self.gpu.acquire() => match p { Ok(p) => p, Err(_) => return },
            () = token.cancelled() => {
                self.fail(&j.job_id, wire::codes::CANCELLED, "cancelled while queued").await;
                return;
            }
        };
        let info = db_sealbox::info(&meta.provider_id, &meta.session_id);
        let bound = lock(&self.bound).clone();
        let opened = match bound {
            Some(bk) if !j.sealed.tpm_ephemeral.is_empty() => {
                // The TPM performs the ECDH only while the PCRs hold the
                // attested values (PolicyPCR); then HPKE PSK mode.
                let (att, eph, bk2) = (a.att.clone(), j.sealed.tpm_ephemeral.clone(), bk.clone());
                match tokio::task::spawn_blocking(move || att.bound_ecdh(&bk2, &eph)).await {
                    Ok(Ok(z)) => {
                        self.job_key.open_request_bound(&info, &j.meta, &j.sealed, &z, bk.public_bytes()).map_err(|e| e.to_string())
                    }
                    Ok(Err(e)) => Err(e.to_string()),
                    Err(e) => Err(e.to_string()),
                }
            }
            // This provider offers TPM-enforced decryption; a job sealed
            // without it is refused rather than accepted at lower assurance.
            Some(_) => Err("job is not bound to the TPM key".to_owned()),
            None => self.job_key.open_request(&info, &j.meta, &j.sealed).map_err(|e| e.to_string()),
        };
        let (plain, result_key) = match opened {
            Ok(v) => v,
            Err(e) => {
                self.fail(&j.job_id, wire::codes::DECRYPT, &e).await;
                return;
            }
        };
        let mut req: wire::JobRequest = match serde_json::from_slice(&plain) {
            Ok(r) => r,
            Err(e) => {
                drop(plain);
                self.fail(&j.job_id, wire::codes::BAD_REQUEST, &e.to_string()).await;
                return;
            }
        };
        drop(plain);
        if let Err(e) = req.check_against(&meta) {
            self.fail(&j.job_id, wire::codes::META_MISMATCH, &e.to_string()).await;
            return;
        }
        if !req.input_image.is_empty() {
            // Consumer-supplied media never reaches the engine's decoders as
            // sent: it is decoded by memory-safe decoders and re-encoded.
            let clean = db_engine::sanitize_image(&req.input_image);
            req.input_image.zeroize();
            match clean {
                Ok(clean) => req.input_image = clean,
                Err(e) => {
                    self.fail(&j.job_id, wire::codes::BAD_REQUEST, &e.to_string()).await;
                    return;
                }
            }
        }
        let accepted = wire::JobAccepted { msg_type: wire::msg::JOB_ACCEPTED.to_owned(), job_id: j.job_id.clone() };
        if self.send(&accepted).await.is_err() {
            return;
        }
        let started = GoTime::now_utc();
        let job_id = j.job_id.clone();
        let progress = |step: i64, total: i64| {
            self.try_send(&wire::JobProgress { msg_type: wire::msg::JOB_PROGRESS.to_owned(), job_id: job_id.clone(), step, total });
        };
        let out = a.engine.generate(&req, &progress, token.clone()).await;
        drop(req);
        let out = match out {
            Ok(o) => o,
            Err(e) => {
                let code = if token.is_cancelled() {
                    wire::codes::CANCELLED
                } else if e.is_unavailable() {
                    wire::codes::ENGINE_UNAVAILABLE
                } else {
                    wire::codes::ENGINE
                };
                self.fail(&j.job_id, code, &e.to_string()).await;
                return;
            }
        };
        let chunks = match db_sealbox::seal_result(&result_key, &j.job_id, &out.data) {
            Ok(c) => c,
            Err(e) => {
                self.fail(&j.job_id, wire::codes::SEAL, &e.to_string()).await;
                return;
            }
        };
        drop(result_key);
        let (mime, units) = (out.mime.clone(), out.units.clone());
        drop(out);
        for (seq, c) in chunks.iter().enumerate() {
            let chunk =
                wire::JobChunk { msg_type: wire::msg::JOB_CHUNK.to_owned(), job_id: j.job_id.clone(), seq: seq as u64, data: c.clone() };
            if self.send(&chunk).await.is_err() {
                return;
            }
        }
        let release = lock(&self.release).clone();
        let gpu_ms = units.gpu_millis;
        let receipt = wire::Receipt {
            v: 1,
            job_id: j.job_id.clone(),
            provider_id: meta.provider_id.clone(),
            session_id: meta.session_id.clone(),
            release,
            model: meta.model.clone(),
            workflow: meta.workflow.clone(),
            meta_sha256: hex::encode(Sha256::digest(&j.meta)),
            request_sha256: wire::request_digest(&j.sealed),
            result_sha256: wire::result_digest(&chunks),
            result_bytes: wire::result_bytes(&chunks),
            result_mime: mime,
            units,
            started_at: started,
            finished_at: GoTime::now_utc(),
        };
        let Ok(rb) = wire::marshal(&receipt) else { return };
        let sig = self.receipt_key.sign(&rb).to_bytes().to_vec();
        let done = wire::JobDone { msg_type: wire::msg::JOB_DONE.to_owned(), job_id: j.job_id.clone(), receipt: rb, receipt_sig: sig };
        if self.send(&done).await.is_err() {
            return;
        }
        logf!(
            self.log(),
            "job {} done: {} {}x{} {} steps in {}ms ({} sealed chunks)",
            j.job_id,
            meta.model,
            meta.width,
            meta.height,
            meta.steps,
            gpu_ms,
            chunks.len()
        );
    }
}

fn m_job_ok(m: &wire::JobMeta, j: &wire::Job) -> bool {
    m.job_id == j.job_id
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};

    /// A connection that never takes a frame (a stalled coordinator).
    struct Stalled;

    impl futures_util::Sink<Message> for Stalled {
        type Error = std::io::Error;
        fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }
        fn start_send(self: Pin<&mut Self>, _: Message) -> Result<(), Self::Error> {
            Ok(())
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }
    }

    /// A connection whose writes fail.
    struct Broken;

    impl futures_util::Sink<Message> for Broken {
        type Error = std::io::Error;
        fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Err(std::io::Error::other("broken pipe")))
        }
        fn start_send(self: Pin<&mut Self>, _: Message) -> Result<(), Self::Error> {
            Ok(())
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn stalled_connection_ends_the_session() {
        for broken in [false, true] {
            let (tx, rx) = mpsc::channel(4);
            let token = CancellationToken::new();
            let timeout = Duration::from_millis(100);
            let log = Logger::stderr("test ");
            let writer = if broken {
                tokio::spawn(write_frames(Broken, rx, token.clone(), log, timeout))
            } else {
                tokio::spawn(write_frames(Stalled, rx, token.clone(), log, timeout))
            };
            tx.send(Message::text("frame")).await.unwrap();
            tokio::time::timeout(Duration::from_secs(5), writer).await.expect("writer wedged on the connection").unwrap();
            assert!(token.is_cancelled(), "session not ended (broken={broken})");
        }
    }

    #[test]
    fn malformed_leases_keep_the_release() {
        let release = Mutex::new(String::new());
        let lease = |rel: &str| format!(r#"{{"type":"lease","lease_id":"l","tier":"attested","release":"{rel}"}}"#);
        assert!(record_lease(&release, b"{not json").is_none());
        let (l, first) = record_lease(&release, lease("rel-1").as_bytes()).unwrap();
        assert!(first && l.release == "rel-1");
        for bad in [lease(""), r#"{"type":"lease"}"#.to_owned(), "[]".to_owned(), r#"{"type":"lease","release":7}"#.to_owned()] {
            assert!(record_lease(&release, bad.as_bytes()).is_none(), "{bad}");
            assert_eq!(*lock(&release), "rel-1", "{bad} cleared the release");
        }
        let (_, first) = record_lease(&release, lease("rel-2").as_bytes()).unwrap();
        assert!(!first);
        assert_eq!(*lock(&release), "rel-2");
    }

    #[tokio::test]
    async fn jobs_finish_before_the_bound_key_is_flushed() {
        let token = CancellationToken::new();
        let tasks = TaskTracker::new();
        let finished = Arc::new(AtomicBool::new(false));
        for _ in 0..3 {
            let (t, done) = (token.child_token(), finished.clone());
            tasks.spawn(async move {
                t.cancelled().await;
                // A job still using the key (a TPM ECDH) after cancellation.
                tokio::time::sleep(Duration::from_millis(100)).await;
                done.store(true, Ordering::SeqCst);
            });
        }
        let flushed_after_jobs = Arc::new(AtomicBool::new(false));
        let (f, done) = (flushed_after_jobs.clone(), finished.clone());
        end_session(&token, &tasks, async move { f.store(done.load(Ordering::SeqCst), Ordering::SeqCst) }).await;
        assert!(flushed_after_jobs.load(Ordering::SeqCst), "bound key flushed while jobs were running");
    }
}
