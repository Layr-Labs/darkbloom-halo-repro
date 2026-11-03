//! The provider side: WebSocket enrollment (hello -> EK chain -> credential
//! activation), attestation challenges, leases and job frames.

use crate::dispatch::{self, DispatchGuard};
use crate::{
    Attested, Job, LedgerEntry, MAX_LEDGER, MAX_STORED_RESULT_BYTES, Outgoing, PROVIDER_READ_LIMIT, Provider, ProviderState, Server,
    continuity, random_id,
};
use axum::body::Bytes;
use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use db_gojson::GoTime;
use db_log::logf;
use db_tpmattest::{Evidence, Expect};
use db_wire as wire;
use ed25519_dalek::Signer as _;
use futures_util::stream::SplitStream;
use futures_util::{Sink as _, SinkExt as _, StreamExt as _};
use sha2::{Digest as _, Sha256};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

/// `GET /v1/provider/ws`.
pub(crate) async fn handle_ws(State(s): State<Arc<Server>>, ws: WebSocketUpgrade) -> Response {
    ws.max_message_size(PROVIDER_READ_LIMIT).max_frame_size(PROVIDER_READ_LIMIT).on_upgrade(move |socket| connection(s, socket))
}

/// Queues a frame and waits until it is written (or `timeout` passes).
pub(crate) async fn send_frame<T: serde::Serialize>(tx: &mpsc::Sender<Outgoing>, v: &T, timeout: Duration) -> Result<(), String> {
    let text = String::from_utf8(wire::marshal(v).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let (ack_tx, ack_rx) = oneshot::channel();
    let send = async {
        tx.send(Outgoing::Text(text, Some(ack_tx))).await.map_err(|_| "connection closed".to_owned())?;
        match ack_rx.await {
            Ok(true) => Ok(()),
            _ => Err("write failed".to_owned()),
        }
    };
    tokio::time::timeout(timeout, send).await.map_err(|_| "write timed out".to_owned())?
}

/// Queues a sealed job with its attested destination facts. The provider
/// writer rechecks those facts just before it enqueues the WebSocket frame.
pub(crate) async fn send_job_frame(
    tx: &mpsc::Sender<Outgoing>,
    v: &wire::Job,
    guard: DispatchGuard,
    timeout: Duration,
) -> Result<(), String> {
    let text = String::from_utf8(wire::marshal(v).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let (ack_tx, ack_rx) = oneshot::channel();
    let send = async {
        tx.send(Outgoing::Job(text, guard, ack_tx)).await.map_err(|_| "connection closed".to_owned())?;
        match ack_rx.await {
            Ok(true) => Ok(()),
            _ => Err("dispatch authorization or write failed".to_owned()),
        }
    };
    tokio::time::timeout(timeout, send).await.map_err(|_| "write timed out".to_owned())?
}

/// A long timeout for frames written on the connection's own context.
const CONN_WRITE: Duration = Duration::from_secs(60);

async fn connection(s: Arc<Server>, socket: WebSocket) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::channel::<Outgoing>(64);
    let cancel = CancellationToken::new();
    let writer_cancel = cancel.clone();
    let writer_server = s.clone();
    let writer = tokio::spawn(async move {
        loop {
            // Drain queued frames (an error frame and the close frame) before
            // honouring cancellation.
            let out = tokio::select! {
                biased;
                o = rx.recv() => match o { Some(o) => o, None => break },
                () = writer_cancel.cancelled() => break,
            };
            match out {
                Outgoing::Text(t, ack) => {
                    let ok = sink.send(Message::Text(t.into())).await.is_ok();
                    if let Some(a) = ack {
                        let _ = a.send(ok);
                    }
                    if !ok {
                        writer_cancel.cancel();
                        break;
                    }
                }
                Outgoing::Job(t, guard, ack) => {
                    // Sink readiness can wait. Check the live provider map,
                    // lease, tier and attested key only after it is ready,
                    // then start the send synchronously under the state lock.
                    // Revocation/replacement cannot interleave between the
                    // check and this handoff to the WebSocket sink.
                    let ready = tokio::time::timeout(
                        Duration::from_secs(30),
                        futures_util::future::poll_fn(|cx| Pin::new(&mut sink).poll_ready(cx)),
                    )
                    .await;
                    let Ok(Ok(())) = ready else {
                        let _ = ack.send(false);
                        writer_cancel.cancel();
                        break;
                    };
                    let started = {
                        let st = writer_server.lock();
                        if !dispatch::authorized(&writer_server, &st, &guard, &GoTime::now_utc()) {
                            false
                        } else {
                            match Pin::new(&mut sink).start_send(Message::Text(t.into())) {
                                Ok(()) => true,
                                Err(_) => {
                                    let _ = ack.send(false);
                                    writer_cancel.cancel();
                                    break;
                                }
                            }
                        }
                    };
                    if !started {
                        let _ = ack.send(false);
                        continue;
                    }
                    let ok = tokio::time::timeout(Duration::from_secs(30), sink.flush()).await.is_ok_and(|r| r.is_ok());
                    let _ = ack.send(ok);
                    if !ok {
                        writer_cancel.cancel();
                        break;
                    }
                }
                Outgoing::Close(code, reason, ack) => {
                    let ok = sink.send(Message::Close(Some(CloseFrame { code, reason: reason.into() }))).await.is_ok();
                    let _ = ack.send(ok);
                    break;
                }
            }
        }
        let _ = sink.close().await;
    });
    let p = match enroll(&s, &mut stream, &tx).await {
        Ok(p) => p,
        Err(e) => {
            logf!(s.cfg.logger, "provider rejected: {e}");
            reject(&tx, &e, "rejected").await;
            cancel.cancel();
            let _ = writer.await;
            return;
        }
    };
    let challenger = tokio::spawn(challenge_loop(s.clone(), p.clone()));
    loop {
        let msg = tokio::select! {
            () = p.cancel.cancelled() => {
                set_close_reason(&s, &p, "connection cancelled");
                break;
            }
            m = stream.next() => m,
        };
        let data = match msg {
            Some(Ok(Message::Text(t))) => t.as_bytes().to_vec(),
            Some(Ok(Message::Binary(b))) => b.to_vec(),
            Some(Ok(Message::Close(_))) | None => {
                set_close_reason(&s, &p, "connection closed");
                break;
            }
            Some(Ok(_)) => continue,
            Some(Err(e)) => {
                set_close_reason(&s, &p, &e.to_string());
                break;
            }
        };
        if let Err(e) = on_provider_frame(&s, &p, &data).await {
            logf!(s.cfg.logger, "provider {}: {e}", p.id);
            set_close_reason(&s, &p, &e);
            reject(&tx, &e, "policy").await;
            break;
        }
    }
    challenger.abort();
    disconnect(&s, &p);
    p.cancel.cancel();
    cancel.cancel();
    let _ = writer.await;
}

/// Sends an `error` frame and closes with 1008 (policy violation).
async fn reject(tx: &mpsc::Sender<Outgoing>, msg: &str, reason: &'static str) {
    let err = wire::ErrorMsg { msg_type: wire::msg::ERROR.to_owned(), message: msg.to_owned() };
    let _ = send_frame(tx, &err, Duration::from_secs(5)).await;
    let (ack, done) = oneshot::channel();
    if tx.send(Outgoing::Close(1008, reason, ack)).await.is_ok() {
        let _ = tokio::time::timeout(Duration::from_secs(5), done).await;
    }
}

fn set_close_reason(s: &Server, p: &Provider, reason: &str) {
    let mut st = s.lock();
    if let Some((_, ps)) = st.conns.get_mut(&p.conn_id)
        && ps.close_reason.is_empty()
    {
        ps.close_reason = reason.to_owned();
    }
}

async fn read_frame<T: serde::de::DeserializeOwned>(
    stream: &mut SplitStream<WebSocket>,
    typ: &str,
    timeout: Duration,
) -> Result<T, String> {
    let next = async {
        loop {
            match stream.next().await {
                Some(Ok(Message::Text(t))) => return Ok(t.as_bytes().to_vec()),
                Some(Ok(Message::Binary(b))) => return Ok(b.to_vec()),
                Some(Ok(Message::Close(_))) | None => return Err("connection closed".to_owned()),
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(e.to_string()),
            }
        }
    };
    let data = tokio::time::timeout(timeout, next).await.map_err(|_| "timed out".to_owned())??;
    let t: wire::Typed = db_gojson::from_slice(&data).map_err(|_| format!("expected {typ}"))?;
    if t.msg_type != typ {
        return Err(format!("expected {typ}"));
    }
    db_gojson::from_slice(&data).map_err(|e| e.to_string())
}

/// hello -> EK chain -> credential activation.
async fn enroll(s: &Arc<Server>, stream: &mut SplitStream<WebSocket>, tx: &mpsc::Sender<Outgoing>) -> Result<Arc<Provider>, String> {
    let hello: wire::Hello = read_frame(stream, wire::msg::HELLO, Duration::from_secs(15)).await.map_err(|e| format!("hello: {e}"))?;
    if hello.protocol != wire::PROTOCOL {
        return Err(format!("unsupported protocol {:?}", hello.protocol));
    }
    let account = s.cfg.provider_tokens.get(&hello.account_token).cloned().ok_or("unknown account token (pair the machine first)")?;
    let ek = db_tpmattest::parse_ek_public(&hello.ek_public).map_err(|e| e.to_string())?;
    let ak = db_tpmattest::parse_attestation_key(&hello.ak_public).map_err(|e| e.to_string())?;
    let chain = s.verifier.bundle.verify_ek(&hello.ek_cert, &hello.ek_icas, &ek.key, &GoTime::now_utc()).map_err(|e| e.to_string())?;
    if !chain.production && !s.verifier.allow_dev_roots {
        return Err(format!("endorsement root {:?} is a development root", chain.root_name));
    }
    let id = db_tpmattest::provider_id_from_ek(&hello.ek_public);
    let session_id = random_id(16);
    let welcome = wire::Welcome {
        msg_type: wire::msg::WELCOME.to_owned(),
        session_id: session_id.clone(),
        account_id: account.clone(),
        provider_id: id.clone(),
        challenge_interval: s.cfg.challenge_interval.as_secs() as i64,
        lease_ttl: s.cfg.lease_ttl.as_secs() as i64,
    };
    send_frame(tx, &welcome, CONN_WRITE).await?;
    // Credential activation: proves the AK is in the TPM that owns the
    // AMD-certified EK (Pluton's EK can only decrypt, never sign).
    let ch = db_tpmattest::make_credential(&ek, &ak.name).map_err(|e| e.to_string())?;
    let challenge = wire::CredentialChallenge {
        msg_type: wire::msg::CREDENTIAL_CHALLENGE.to_owned(),
        request_id: String::new(),
        id_object: ch.id_object.clone(),
        enc_secret: ch.enc_secret.clone(),
    };
    send_frame(tx, &challenge, CONN_WRITE).await?;
    let resp: wire::CredentialResponse = read_frame(stream, wire::msg::CREDENTIAL_RESPONSE, Duration::from_secs(30))
        .await
        .map_err(|e| format!("credential response: {e}"))?;
    let ok =
        resp.secret.len() == ch.secret.len() && bool::from(subtle::ConstantTimeEq::ct_eq(resp.secret.as_slice(), ch.secret.as_slice()));
    if !ok {
        return Err("credential activation failed: the AK is not in the EK's TPM".to_owned());
    }
    let enrollment = wire::Enrollment {
        v: 1,
        provider_id: id.clone(),
        device_id: chain.device_id.clone(),
        ek_public_sha256: hex::encode(Sha256::digest(&hello.ek_public)),
        ak_name: ak.name.clone(),
        root: chain.root_name.clone(),
        root_kind: chain.root_kind.as_str().to_owned(),
        session_id: session_id.clone(),
        activated_at: GoTime::now_utc(),
    };
    let payload = wire::marshal(&enrollment).map_err(|e| e.to_string())?;
    let sig = s.cfg.enrollment_key.sign(&payload).to_bytes().to_vec();
    let keyid = db_release::key_id(&s.cfg.enrollment_key.verifying_key());
    let tpm_mode = hello.tpm_mode.clone();
    let mut st = s.lock();
    st.next_conn += 1;
    let conn_id = st.next_conn;
    let p = Arc::new(Provider {
        conn_id,
        id: id.clone(),
        session_id: session_id.clone(),
        account_id: account.clone(),
        hello,
        device_id: chain.device_id.clone(),
        root_name: chain.root_name.clone(),
        activated: true,
        enrollment: wire::SignedBlob { payload, sig, keyid },
        tx: tx.clone(),
        cancel: CancellationToken::new(),
    });
    // One connection per device: a second connection replaces the first.
    if let Some(old) = st.providers.get(&id).copied()
        && let Some((old_p, old_s)) = st.conns.get_mut(&old)
    {
        old_s.close_reason = "replaced by a new session".to_owned();
        old_p.cancel.cancel();
    }
    st.conns.insert(conn_id, (p.clone(), ProviderState::default()));
    st.providers.insert(id.clone(), conn_id);
    drop(st);
    logf!(
        s.cfg.logger,
        "provider {id} enrolled: device={} root={:?} account={account} session={session_id} tpm={tpm_mode}",
        chain.device_id,
        chain.root_name
    );
    Ok(p)
}

async fn challenge_loop(s: Arc<Server>, p: Arc<Provider>) {
    let interval = s.cfg.challenge_interval;
    let mut tick = tokio::time::interval(interval);
    loop {
        tick.tick().await;
        let mut nonce = vec![0u8; 32];
        if getrandom::fill(&mut nonce).is_err() {
            return;
        }
        {
            let mut st = s.lock();
            let Some((_, ps)) = st.conns.get_mut(&p.conn_id) else { return };
            ps.nonces.retain(|_, at| at.elapsed() <= 2 * interval);
            ps.nonces.insert(nonce.clone(), Instant::now());
        }
        let ch = wire::AttestChallenge {
            msg_type: wire::msg::ATTEST_CHALLENGE.to_owned(),
            nonce,
            pcrs: s.cfg.verifier.pcrs().iter().map(|&p| i64::from(p)).collect(),
        };
        if send_frame(&p.tx, &ch, CONN_WRITE).await.is_err() {
            return;
        }
    }
}

async fn on_provider_frame(s: &Arc<Server>, p: &Arc<Provider>, data: &[u8]) -> Result<(), String> {
    let t: wire::Typed = db_gojson::from_slice(data).map_err(|_| "bad frame".to_owned())?;
    match t.msg_type.as_str() {
        wire::msg::ATTESTATION => {
            let a: wire::Attestation = db_gojson::from_slice(data).map_err(|e| e.to_string())?;
            on_attestation(s, p, a).await
        }
        wire::msg::JOB_ACCEPTED | wire::msg::JOB_PROGRESS | wire::msg::JOB_CHUNK | wire::msg::JOB_DONE | wire::msg::JOB_ERROR => {
            on_job_frame(s, p, &t.msg_type, data)
        }
        wire::msg::CREDENTIAL_RESPONSE => {
            let r: wire::CredentialResponse = match db_gojson::from_slice::<wire::CredentialResponse>(data) {
                Ok(r) if !r.request_id.is_empty() => r,
                _ => return Err("unsolicited credential response".to_owned()),
            };
            let waiter = s.lock().conns.get_mut(&p.conn_id).and_then(|(_, ps)| ps.activations.remove(&r.request_id));
            if let Some(w) = waiter {
                let _ = w.send(r.secret);
            }
            Ok(())
        }
        other => Err(format!("unexpected frame {other:?}")),
    }
}

fn revoke(s: &Server, p: &Provider, why: &str) {
    if let Some((_, ps)) = s.lock().conns.get_mut(&p.conn_id) {
        ps.lease_until = GoTime::zero();
    }
    logf!(s.cfg.logger, "provider {}: lease revoked: {why}", p.id);
}

/// Hands a verified (or failed) quote to a consumer waiting on its nonce.
fn notify(s: &Server, p: &Provider, nonce: &[u8], r: Attested) {
    let waiter = s.lock().conns.get_mut(&p.conn_id).and_then(|(_, ps)| ps.waiters.remove(nonce));
    if let Some(w) = waiter {
        let _ = w.send(r);
    }
}

enum AttestError {
    Stale,
    Fatal(String),
}

async fn on_attestation(s: &Arc<Server>, p: &Arc<Provider>, a: wire::Attestation) -> Result<(), String> {
    let nonce = a.nonce.clone();
    match verify_attestation(s, p, a).await {
        Ok(()) => Ok(()),
        Err(AttestError::Stale) => {
            logf!(s.cfg.logger, "provider {}: dropped an attestation for an unknown or expired nonce", p.id);
            Ok(())
        }
        Err(AttestError::Fatal(e)) => {
            notify(s, p, &nonce, Err(e.clone()));
            Err(e)
        }
    }
}

async fn verify_attestation(s: &Arc<Server>, p: &Arc<Provider>, a: wire::Attestation) -> Result<(), AttestError> {
    let fresh = s.lock().conns.get_mut(&p.conn_id).is_some_and(|(_, ps)| ps.nonces.remove(&a.nonce).is_some());
    if !fresh {
        // Not evidence of anything: a late answer to an expired challenge,
        // or a duplicate. Drop it without ending the session.
        return Err(AttestError::Stale);
    }
    let nonce = a.nonce.clone();
    let ev = Arc::new(Evidence {
        ek_cert: p.hello.ek_cert.clone(),
        ek_icas: p.hello.ek_icas.clone(),
        ek_public: p.hello.ek_public.clone(),
        ak_public: p.hello.ak_public.clone(),
        statement: a.statement,
        nonce: a.nonce,
        quote_attest: a.quote_attest,
        quote_sig: a.quote_sig,
        event_log: a.event_log,
    });
    let ex = Expect {
        session_id: p.session_id.clone(),
        account_id: p.account_id.clone(),
        pcrs: s.cfg.verifier.pcrs().to_vec(),
        ak_activated: p.activated,
    };
    let capture_expect = ex.clone();
    let (vf, ev2) = (s.verifier.clone(), ev.clone());
    let v = tokio::task::spawn_blocking(move || vf.evaluate(&ev2, &ex)).await.map_err(|e| AttestError::Fatal(e.to_string()))?;
    if let Some(store) = &s.capture {
        let (store, provider_id, evidence, verdict) = (store.clone(), p.id.clone(), ev.clone(), v.clone());
        match tokio::task::spawn_blocking(move || store.capture(&provider_id, &evidence, &capture_expect, &verdict)).await {
            Ok(Ok(true)) => {
                logf!(s.cfg.logger, "provider {}: captured fresh TPM evidence for operator review (release admitted={})", p.id, v.ok)
            }
            Ok(Ok(false)) => {}
            Ok(Err(e)) => logf!(s.cfg.logger, "provider {}: attestation capture failed: {e}", p.id),
            Err(e) => logf!(s.cfg.logger, "provider {}: attestation capture task failed: {e}", p.id),
        }
    }
    if !v.ok {
        revoke(s, p, "attestation rejected");
        let reasons: Vec<String> = v.failed().iter().map(|c| format!("{}: {}", c.name, c.detail)).collect();
        return Err(AttestError::Fatal(format!("attestation rejected: {}", reasons.join("; "))));
    }
    if v.tier.rank() < s.min_tier.rank() {
        revoke(s, p, "tier below minimum");
        return Err(AttestError::Fatal(format!("tier {} is below the minimum {}", v.tier, s.min_tier)));
    }
    let v = Arc::new(v);
    let (lease, first) = {
        let mut st = s.lock();
        let Some((_, ps)) = st.conns.get_mut(&p.conn_id) else {
            return Err(AttestError::Fatal("connection closed".to_owned()));
        };
        if ps.have_quote {
            if let Err(e) = continuity(ps.first_reset, ps.first_restart, ps.last_clock, ps.stmt.as_ref(), &v) {
                drop(st);
                revoke(s, p, &e);
                return Err(AttestError::Fatal(e));
            }
        } else {
            ps.first_reset = v.reset_count;
            ps.first_restart = v.restart_count;
            ps.have_quote = true;
        }
        ps.last_clock = v.clock;
        ps.verdict = Some(v.clone());
        ps.evidence = Some(ev.clone());
        ps.stmt = v.statement.clone();
        ps.quotes += 1;
        if ps.lease_id.is_empty() {
            ps.lease_id = random_id(8);
        }
        let ttl = chrono::Duration::from_std(s.cfg.lease_ttl).unwrap_or(chrono::Duration::zero());
        ps.lease_until = GoTime::now_utc().add(ttl);
        let lease = wire::Lease {
            msg_type: wire::msg::LEASE.to_owned(),
            lease_id: ps.lease_id.clone(),
            tier: v.tier.clone(),
            expires_at: ps.lease_until,
            release: v.release.clone(),
            checks: v.checks.clone(),
        };
        (lease, ps.quotes == 1)
    };
    if first {
        logf!(
            s.cfg.logger,
            "provider {} attested: tier={} release={} device={} firmware={} resetCount={}",
            p.id,
            v.tier,
            v.release,
            v.device_id,
            v.tpm_firmware,
            v.reset_count
        );
    }
    // The provider learns its lease before any consumer can act on this
    // quote, so a job never reaches the agent ahead of its first lease.
    send_frame(&p.tx, &lease, CONN_WRITE).await.map_err(AttestError::Fatal)?;
    notify(s, p, &nonce, Ok((ev, v)));
    Ok(())
}

fn disconnect(s: &Server, p: &Provider) {
    let mut st = s.lock();
    let reason = st.conns.remove(&p.conn_id).map(|(_, ps)| ps.close_reason).unwrap_or_default();
    if st.providers.get(&p.id) == Some(&p.conn_id) {
        st.providers.remove(&p.id);
    }
    let mut released = 0;
    for j in st.jobs.values_mut() {
        if j.provider_id == p.id && j.session_id == p.session_id && (j.state == "queued" || j.state == "running") {
            if j.chunks.take().is_some() {
                released += j.size;
            }
            j.state = "error";
            j.err = "provider disconnected".to_owned();
            j.mark_finished();
        }
    }
    st.stored_bytes -= released;
    drop(st);
    logf!(s.cfg.logger, "provider {} disconnected: {reason}", p.id);
}

/// Keeps a provider error code if it is a known short token.
fn code_only(code: &str) -> &'static str {
    match code {
        "rejected" => "rejected",
        "bad_meta" => "bad_meta",
        "meta_mismatch" => "meta_mismatch",
        "wrong_session" => "wrong_session",
        "bad_request" => "bad_request",
        "decrypt" => "decrypt",
        "cancelled" => "cancelled",
        "engine" => "engine",
        "engine_unavailable" => "engine_unavailable",
        "seal" => "seal",
        _ => "unknown",
    }
}

/// Billable units from validated routing metadata.
pub(crate) fn units_from_meta(m: &wire::JobMeta) -> wire::Units {
    if m.kind == "text" {
        return wire::Units::default();
    }
    let mut u = wire::Units { megapixels: (m.width * m.height) as f64 / 1e6, steps: m.steps, ..wire::Units::default() };
    if m.kind == "video" {
        u.video_seconds = m.frames as f64 / m.fps.max(1) as f64;
    } else {
        u.images = 1;
    }
    u
}

/// Price from validated routing metadata (not provider claims).
pub(crate) fn price(m: &wire::JobMeta) -> i64 {
    // Text billing is not part of the PoC; never bill it as a zero-pixel image.
    if m.kind == "text" {
        return 0;
    }
    let mp = (m.width * m.height) as f64 / 1e6;
    if m.kind == "video" { (20000.0 * m.frames as f64 / m.fps.max(1) as f64 * mp) as i64 } else { (1000.0 * mp) as i64 + 50 * m.steps }
}

fn on_job_frame(s: &Server, p: &Provider, typ: &str, data: &[u8]) -> Result<(), String> {
    let head: wire::JobHead = db_gojson::from_slice(data).unwrap_or_default();
    let mut guard = s.lock();
    let st = &mut *guard;
    let Some(j) = st.jobs.get_mut(&head.job_id).filter(|j| j.provider_id == p.id && j.session_id == p.session_id) else {
        return Err(format!("frame for unknown job {:?}", head.job_id));
    };
    if j.finished() {
        return Ok(());
    }
    match typ {
        wire::msg::JOB_ACCEPTED => j.state = "running",
        wire::msg::JOB_PROGRESS => {
            let m: wire::JobProgress = db_gojson::from_slice(data).unwrap_or_default();
            j.step = m.step;
            j.total = m.total;
        }
        wire::msg::JOB_CHUNK => {
            let m: wire::JobChunk = db_gojson::from_slice(data).map_err(|e| e.to_string())?;
            let have = j.chunks.as_ref().map_or(0, Vec::len);
            if m.seq != have as u64 {
                return Err(format!("job {}: chunk {} out of order", j.id, m.seq));
            }
            if m.data.is_empty() || m.data.len() > db_sealbox::CHUNK_SIZE + 64 {
                return Err(format!("job {}: chunk of {} bytes", j.id, m.data.len()));
            }
            let n = m.data.len() as i64;
            j.size += n;
            st.stored_bytes += n;
            let max_job_bytes = if j.parsed.kind == "text" { 1 << 20 } else { s.cfg.max_result_bytes };
            let max_chunks = usize::try_from(max_job_bytes / db_sealbox::CHUNK_SIZE as i64).unwrap_or(0) + 2;
            if j.size > max_job_bytes || have >= max_chunks || st.stored_bytes > MAX_STORED_RESULT_BYTES {
                st.stored_bytes -= j.size;
                j.state = "error";
                j.err = "result too large".to_owned();
                j.chunks = None;
                j.mark_finished();
                return Ok(());
            }
            j.chunks.get_or_insert_with(Vec::new).push(Bytes::from(m.data));
        }
        wire::msg::JOB_ERROR => {
            let m: wire::JobError = db_gojson::from_slice(data).unwrap_or_default();
            if j.chunks.take().is_some() {
                st.stored_bytes -= j.size;
            }
            // Codes only: provider-supplied text is never stored or displayed.
            j.state = "error";
            j.err = format!("provider: {}", code_only(&m.code));
            j.mark_finished();
        }
        wire::msg::JOB_DONE => {
            let m: wire::JobDone = db_gojson::from_slice(data).map_err(|e| e.to_string())?;
            let ps = st.conns.get(&p.conn_id).map(|(_, ps)| ps);
            let checked = check_receipt(p, ps, j, &m.receipt, &m.receipt_sig);
            let rc = match checked {
                Ok(rc) => rc,
                Err(e) => {
                    if j.chunks.take().is_some() {
                        st.stored_bytes -= j.size;
                    }
                    j.state = "error";
                    j.err = format!("invalid receipt: {e}");
                    j.mark_finished();
                    let id = j.id.clone();
                    if let Some((_, ps)) = st.conns.get_mut(&p.conn_id) {
                        ps.lease_until = GoTime::zero();
                    }
                    return Err(format!("job {id}: {e}"));
                }
            };
            j.state = "done";
            j.receipt = m.receipt;
            j.receipt_sig = m.receipt_sig;
            j.mark_finished();
            // Billable units come from the routed metadata the coordinator
            // validated; the provider's own figures are kept for GPU time only.
            let mut units = units_from_meta(&j.parsed);
            units.gpu_millis = rc.units.gpu_millis;
            if j.parsed.kind == "text" {
                units.prompt_tokens = rc.units.prompt_tokens;
                units.completion_tokens = rc.units.completion_tokens;
            }
            let entry = LedgerEntry {
                owner: j.owner.clone(),
                job_id: j.id.clone(),
                provider_id: p.id.clone(),
                account: p.account_id.clone(),
                model: j.parsed.model.clone(),
                units,
                price_micro: price(&j.parsed),
                release: rc.release.clone(),
                at: GoTime::now_utc(),
            };
            let (id, size) = (j.id.clone(), j.size);
            st.ledger.push(entry);
            if st.ledger.len() > MAX_LEDGER {
                let excess = st.ledger.len() - MAX_LEDGER;
                st.ledger.drain(..excess);
            }
            logf!(s.cfg.logger, "job {id} done on {}: {size} sealed bytes, receipt verified", p.id);
        }
        _ => {}
    }
    Ok(())
}

fn check_receipt(p: &Provider, ps: Option<&ProviderState>, j: &Job, raw: &[u8], sig: &[u8]) -> Result<wire::Receipt, String> {
    let bad_sig = || "signature does not verify with the attested receipt key".to_owned();
    let stmt = ps.and_then(|ps| ps.stmt.as_ref()).ok_or_else(bad_sig)?;
    let key: [u8; 32] = stmt.receipt_public_key.as_slice().try_into().map_err(|_| bad_sig())?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| bad_sig())?;
    let sig = ed25519_dalek::Signature::from_slice(sig).map_err(|_| bad_sig())?;
    key.verify_strict(raw, &sig).map_err(|_| bad_sig())?;
    let rc: wire::Receipt = db_gojson::from_slice(raw).map_err(|e| e.to_string())?;
    let chunks: &[Bytes] = j.chunks.as_deref().unwrap_or_default();
    if rc.v != 1 || rc.job_id != j.id || rc.provider_id != p.id || rc.session_id != p.session_id {
        return Err("receipt names another job, provider or session".to_owned());
    }
    if rc.meta_sha256 != hex::encode(Sha256::digest(&j.meta)) {
        return Err("receipt metadata hash mismatch".to_owned());
    }
    if rc.request_sha256 != j.request_digest {
        return Err("receipt request hash mismatch".to_owned());
    }
    if rc.result_sha256 != wire::result_digest(chunks) || rc.result_bytes != j.size {
        return Err("receipt does not match the delivered ciphertext".to_owned());
    }
    if rc.model != j.parsed.model || rc.workflow != j.parsed.workflow || rc.units.steps != j.parsed.steps {
        return Err("receipt units disagree with the routed job".to_owned());
    }
    if j.parsed.kind == "text" && (rc.units.prompt_tokens < 0 || !(0..=j.parsed.max_tokens).contains(&rc.units.completion_tokens)) {
        return Err("receipt text usage is out of range".to_owned());
    }
    match ps.and_then(|ps| ps.verdict.as_ref()) {
        Some(v) if v.release == rc.release => Ok(rc),
        _ => Err("receipt names another release".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_and_price() {
        let m = wire::JobMeta { kind: "image".to_owned(), width: 1024, height: 1024, steps: 8, ..wire::JobMeta::default() };
        let u = units_from_meta(&m);
        assert_eq!((u.images, u.steps), (1, 8));
        assert!((u.megapixels - 1.048576).abs() < 1e-12);
        assert_eq!(price(&m), 1048 + 400);
        let v =
            wire::JobMeta { kind: "video".to_owned(), width: 832, height: 480, steps: 20, frames: 33, fps: 16, ..wire::JobMeta::default() };
        let u = units_from_meta(&v);
        assert!((u.video_seconds - 2.0625).abs() < 1e-12);
        assert_eq!(price(&v), (20000.0 * 33.0 / 16.0 * (832.0 * 480.0 / 1e6)) as i64);
        let t = wire::JobMeta { kind: "text".to_owned(), max_tokens: 64, ..wire::JobMeta::default() };
        assert_eq!(units_from_meta(&t), wire::Units::default());
        assert_eq!(price(&t), 0);
        assert_eq!(code_only("decrypt"), "decrypt");
        assert_eq!(code_only("validation failed for text \"secret\""), "unknown");
    }
}
