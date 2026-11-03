//! The consumer HTTP API.

use crate::dispatch::{DispatchGuard, tier_allows};
use crate::provider::{send_frame, send_job_frame};
use crate::{
    Attested, Job, LedgerEntry, MAX_ACTIVE_JOBS_PER_PROVIDER, MAX_JOBS_PER_CONSUMER, MAX_JOBS_TOTAL, MAX_SEALED_REQUEST, MAX_SUBMIT_BYTES,
    Server, consumer_of, http_error, json_response,
};
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use db_gojson::GoTime;
use db_wire as wire;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

macro_rules! consumer {
    ($s:expr, $headers:expr) => {
        match consumer_of(&$s, &$headers) {
            Some(c) => c,
            None => return http_error(StatusCode::UNAUTHORIZED, "missing or unknown API key"),
        }
    };
}

/// `GET /v1/coordinator`: the coordinator's published keys and policy.
pub(crate) async fn handle_info(State(s): State<Arc<Server>>) -> Response {
    let policy = s.verifier.release_policy.as_ref();
    let info = wire::CoordinatorInfo {
        enrollment_key: s.cfg.enrollment_key.verifying_key().as_bytes().to_vec(),
        release_log_key: s.cfg.release_log_key.as_bytes().to_vec(),
        release_keys: s.cfg.release_keys.iter().map(|(id, k)| (id.clone(), k.as_bytes().to_vec())).collect(),
        min_svn: policy.map_or(0, |p| p.min_svn),
        allow_dev: policy.is_some_and(|p| p.allow_dev),
    };
    json_response(StatusCode::OK, &info)
}

/// `GET /v1/providers`: leased providers.
pub(crate) async fn handle_providers(State(s): State<Arc<Server>>, headers: HeaderMap) -> Response {
    consumer!(s, headers);
    let st = s.lock();
    let now = GoTime::now_utc();
    let mut out: Vec<wire::ProviderInfo> = Vec::new();
    for conn in st.providers.values() {
        let Some((p, ps)) = st.conns.get(conn) else { continue };
        if !Server::leased(ps, &now) {
            continue;
        }
        let (Some(v), Some(stmt)) = (&ps.verdict, &ps.stmt) else { continue };
        out.push(wire::ProviderInfo {
            provider_id: p.id.clone(),
            session_id: p.session_id.clone(),
            tier: v.tier.clone(),
            release: v.release.clone(),
            lease_until: ps.lease_until,
            models: p.hello.models.clone(),
            job_kem: stmt.job_kem.clone(),
            gpu: p.hello.gpu.clone(),
            tpm_mode: p.hello.tpm_mode.clone(),
        });
    }
    drop(st);
    out.sort_by(|a, b| a.provider_id.cmp(&b.provider_id));
    // Go marshals its nil slice as null when no provider is leased.
    if out.is_empty() { json_response(StatusCode::OK, &serde_json::Value::Null) } else { json_response(StatusCode::OK, &out) }
}

/// `GET /v1/providers/{id}/attestation[?nonce=<64 hex>]`: the provider's
/// latest evidence or, with a consumer nonce, a quote made for that nonce
/// (freshness then no longer rests on the coordinator's word).
pub(crate) async fn handle_bundle(
    State(s): State<Arc<Server>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    consumer!(s, headers);
    let mut nonce = None;
    if let Some(n) = q.get("nonce").filter(|n| !n.is_empty()) {
        match hex::decode(n) {
            Ok(b) if b.len() == 32 => nonce = Some(b),
            _ => return http_error(StatusCode::BAD_REQUEST, "nonce must be 32 bytes of hex"),
        }
    }
    let (p, ev, verdict, mut wait) = {
        let mut st = s.lock();
        let now = GoTime::now_utc();
        let conn = st.providers.get(&id).copied();
        let Some((p, ps)) = conn.and_then(|c| st.conns.get_mut(&c)).filter(|(_, ps)| Server::leased(ps, &now)) else {
            return http_error(StatusCode::NOT_FOUND, format!("no leased provider {id:?}"));
        };
        let mut wait = None;
        if let Some(n) = &nonce {
            if ps.waiters.len() >= 4 {
                return http_error(StatusCode::TOO_MANY_REQUESTS, "too many fresh-quote requests for this provider");
            }
            if ps.nonces.contains_key(n) {
                return http_error(StatusCode::CONFLICT, "nonce already in use");
            }
            let (tx, rx) = oneshot::channel::<Attested>();
            ps.waiters.insert(n.clone(), tx);
            ps.nonces.insert(n.clone(), Instant::now());
            wait = Some(rx);
        }
        (p.clone(), ps.evidence.clone(), ps.verdict.clone(), wait)
    };
    let (mut ev, mut verdict) = (ev, verdict);
    if let (Some(n), Some(rx)) = (&nonce, wait.take()) {
        let forget = |s: &Server| {
            if let Some((_, ps)) = s.lock().conns.get_mut(&p.conn_id) {
                ps.waiters.remove(n);
                ps.nonces.remove(n);
            }
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        let ch = wire::AttestChallenge {
            msg_type: wire::msg::ATTEST_CHALLENGE.to_owned(),
            nonce: n.clone(),
            pcrs: s.verifier.pcrs().iter().map(|&p| i64::from(p)).collect(),
        };
        if send_frame(&p.tx, &ch, Duration::from_secs(20)).await.is_err() {
            forget(&s);
            return http_error(StatusCode::BAD_GATEWAY, "provider unreachable");
        }
        match tokio::time::timeout_at(deadline.into(), rx).await {
            Ok(Ok(Ok((e, v)))) => {
                ev = Some(e);
                verdict = Some(v);
            }
            Ok(Ok(Err(e))) => return http_error(StatusCode::BAD_GATEWAY, format!("fresh quote rejected: {e}")),
            _ => {
                forget(&s);
                return http_error(StatusCode::GATEWAY_TIMEOUT, "provider did not answer the fresh-quote challenge");
            }
        }
    }
    let (Some(ev), Some(verdict)) = (ev, verdict) else {
        return http_error(StatusCode::NOT_FOUND, format!("no leased provider {id:?}"));
    };
    let lease_until = s.lock().conns.get(&p.conn_id).map(|(_, ps)| ps.lease_until).unwrap_or_default();
    let release = verdict.manifest.as_ref().and_then(|rel| {
        s.verifier.releases.iter().find(|tr| Arc::ptr_eq(&tr.manifest, rel)).and_then(|tr| s.cfg.release_log.prove(&tr.envelope).ok())
    });
    let b = wire::AttestationBundle {
        provider_id: p.id.clone(),
        session_id: p.session_id.clone(),
        evidence: (*ev).clone(),
        enrollment: p.enrollment.clone(),
        release,
        verdict: Some((*verdict).clone()),
        lease_until,
    };
    json_response(StatusCode::OK, &b)
}

/// `POST /v1/providers/{id}/activate`: relays a consumer's own
/// TPM2_MakeCredential challenge to the provider and returns the TPM's
/// answer. The coordinator cannot answer it (the secret is encrypted to the
/// provider's EK), so a consumer that checks the answer no longer needs the
/// coordinator's enrollment record.
pub(crate) async fn handle_activate(State(s): State<Arc<Server>>, headers: HeaderMap, Path(id): Path<String>, body: Body) -> Response {
    consumer!(s, headers);
    let req = match axum::body::to_bytes(body, 16 << 10).await.ok().and_then(|b| db_gojson::from_slice::<wire::ActivateRequest>(&b).ok()) {
        Some(r) if (1..=1024).contains(&r.id_object.len()) && (1..=1024).contains(&r.enc_secret.len()) => r,
        _ => return http_error(StatusCode::BAD_REQUEST, "bad activation request"),
    };
    let request_id = crate::random_id(12);
    let (p, rx) = {
        let mut st = s.lock();
        let now = GoTime::now_utc();
        let conn = st.providers.get(&id).copied();
        let Some((p, ps)) = conn.and_then(|c| st.conns.get_mut(&c)).filter(|(_, ps)| Server::leased(ps, &now)) else {
            return http_error(StatusCode::NOT_FOUND, format!("no leased provider {id:?}"));
        };
        if ps.activations.len() >= 4 {
            return http_error(StatusCode::TOO_MANY_REQUESTS, "too many activation requests for this provider");
        }
        let (tx, rx) = oneshot::channel();
        ps.activations.insert(request_id.clone(), tx);
        (p.clone(), rx)
    };
    let cleanup = |s: &Server| {
        if let Some((_, ps)) = s.lock().conns.get_mut(&p.conn_id) {
            ps.activations.remove(&request_id);
        }
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    let ch = wire::CredentialChallenge {
        msg_type: wire::msg::CREDENTIAL_CHALLENGE.to_owned(),
        request_id: request_id.clone(),
        id_object: req.id_object,
        enc_secret: req.enc_secret,
    };
    if send_frame(&p.tx, &ch, Duration::from_secs(20)).await.is_err() {
        cleanup(&s);
        return http_error(StatusCode::BAD_GATEWAY, "provider unreachable");
    }
    match tokio::time::timeout_at(deadline.into(), rx).await {
        Ok(Ok(secret)) => json_response(StatusCode::OK, &wire::ActivateResponse { secret }),
        _ => {
            cleanup(&s);
            http_error(StatusCode::GATEWAY_TIMEOUT, "provider did not answer the activation challenge")
        }
    }
}

/// `GET /v1/releases`: every trusted release with its log inclusion proof.
pub(crate) async fn handle_releases(State(s): State<Arc<Server>>) -> Response {
    let out: Vec<db_release::Inclusion> = s.verifier.releases.iter().filter_map(|tr| s.cfg.release_log.prove(&tr.envelope).ok()).collect();
    if out.is_empty() { json_response(StatusCode::OK, &serde_json::Value::Null) } else { json_response(StatusCode::OK, &out) }
}

/// `POST /v1/jobs`: a consumer's sealed job.
pub(crate) async fn handle_submit(State(s): State<Arc<Server>>, headers: HeaderMap, body: Body) -> Response {
    let me = consumer!(s, headers);
    let body = match axum::body::to_bytes(body, MAX_SUBMIT_BYTES).await {
        Ok(b) => b,
        Err(_) => return http_error(StatusCode::BAD_REQUEST, "bad request: http: request body too large"),
    };
    let req: wire::SubmitJob = match db_gojson::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return http_error(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };
    let meta: wire::JobMeta = match db_gojson::from_slice(&req.meta) {
        Ok(m) => m,
        Err(e) => return http_error(StatusCode::BAD_REQUEST, format!("bad job metadata: {e}")),
    };
    if let Err(e) = meta.validate() {
        return http_error(StatusCode::BAD_REQUEST, e.to_string());
    }
    if req.sealed.ciphertext.len() > MAX_SEALED_REQUEST
        || req.sealed.enc.len() > 2048
        || req.sealed.tpm_ephemeral.len() > 65
        || req.meta.len() > 4096
    {
        return http_error(StatusCode::PAYLOAD_TOO_LARGE, "sealed request too large");
    }
    if meta.kind == "text" && req.sealed.tpm_ephemeral.len() != 65 {
        return http_error(StatusCode::BAD_REQUEST, "text requests require TPM-bound sealing");
    }
    let (tx, job_id, dispatch_guard) = {
        let mut guard = s.lock();
        let st = &mut *guard;
        let now = GoTime::now_utc();
        let current = st.providers.get(&req.provider_id).copied().and_then(|c| st.conns.get(&c));
        let (p, ps) = match current {
            Some((p, ps)) if meta.provider_id == req.provider_id => (p.clone(), ps),
            _ => return http_error(StatusCode::NOT_FOUND, "unknown provider"),
        };
        if meta.session_id != p.session_id {
            return http_error(
                StatusCode::CONFLICT,
                format!(
                    "job was sealed for session {}; the provider is now in session {} (fetch a fresh attestation bundle)",
                    meta.session_id, p.session_id
                ),
            );
        }
        if !Server::leased(ps, &now) {
            return http_error(StatusCode::SERVICE_UNAVAILABLE, "provider has no live serving lease (fail closed)");
        }
        if !ps.verdict.as_ref().is_some_and(|v| tier_allows(&s, &meta.kind, &v.tier)) {
            return http_error(StatusCode::SERVICE_UNAVAILABLE, "provider tier cannot serve this job kind");
        }
        let bound_key = ps.verdict.as_ref().and_then(|v| v.bound_key.as_ref()).map(|key| key.to_sec1_bytes().to_vec());
        if (meta.kind == "text" || !req.sealed.tpm_ephemeral.is_empty()) && bound_key.is_none() {
            return http_error(StatusCode::SERVICE_UNAVAILABLE, "provider has no TPM-bound job key");
        }
        if st.jobs.contains_key(&meta.job_id) {
            return http_error(StatusCode::CONFLICT, "duplicate job id");
        }
        let stmt = ps.stmt.clone().unwrap_or_default();
        // Resource caps: per consumer, per provider and overall.
        let (mut active, mut mine, mut prov) = (0usize, 0usize, 0usize);
        for oj in st.jobs.values().filter(|j| j.state == "queued" || j.state == "running") {
            active += 1;
            mine += usize::from(oj.owner == me);
            prov += usize::from(oj.provider_id == p.id);
        }
        if st.jobs.len() >= 4 * MAX_JOBS_TOTAL {
            st.evict_finished();
        }
        if active >= MAX_JOBS_TOTAL
            || st.jobs.len() >= 4 * MAX_JOBS_TOTAL
            || mine >= MAX_JOBS_PER_CONSUMER
            || prov >= MAX_ACTIVE_JOBS_PER_PROVIDER
        {
            return http_error(StatusCode::TOO_MANY_REQUESTS, "too many jobs in flight");
        }
        // Serve only models and workflows the attested statement reports (and
        // the release therefore approved), within the advertised limits.
        let attested_model = stmt.runtime.models.iter().any(|m| m.id == meta.model);
        let attested_wf = stmt.runtime.workflows.iter().any(|w| w.name == meta.workflow);
        let served = attested_model
            && attested_wf
            && p.hello.models.iter().any(|m| {
                m.id == meta.model
                    && m.kind == meta.kind
                    && m.workflows.contains(&meta.workflow)
                    && meta.width <= m.max_width
                    && meta.height <= m.max_height
                    && meta.steps <= m.max_steps
                    && (meta.kind != "text" || (m.max_tokens > 0 && meta.max_tokens <= m.max_tokens))
                    && (meta.kind != "video" || meta.frames <= m.max_frames)
            });
        if !served {
            return http_error(
                StatusCode::BAD_REQUEST,
                format!("provider does not serve {}/{} at {}x{}, {} steps", meta.model, meta.workflow, meta.width, meta.height, meta.steps),
            );
        }
        let j = Job {
            id: meta.job_id.clone(),
            provider_id: p.id.clone(),
            session_id: p.session_id.clone(),
            owner: me,
            meta: req.meta.clone(),
            parsed: meta.clone(),
            request_digest: wire::request_digest(&req.sealed),
            state: "queued",
            step: 0,
            total: 0,
            chunks: Some(Vec::new()),
            size: 0,
            receipt: Vec::new(),
            receipt_sig: Vec::new(),
            err: String::new(),
            created: now,
            created_at: Instant::now(),
            done: tokio::sync::watch::Sender::new(false),
        };
        st.jobs.insert(j.id.clone(), j);
        let dispatch_guard = DispatchGuard::new(&p, &meta.job_id, &meta.kind, &stmt.job_kem, &stmt.job_public_key, bound_key);
        (p.tx.clone(), meta.job_id.clone(), dispatch_guard)
    };
    // A consumer abandoning its HTTP request must not interrupt the provider
    // connection mid-frame: the frame is handed to the connection's writer.
    let frame = wire::Job { msg_type: wire::msg::JOB.to_owned(), job_id: job_id.clone(), meta: req.meta, sealed: req.sealed };
    if send_job_frame(&tx, &frame, dispatch_guard, Duration::from_secs(30)).await.is_err() {
        if let Some(j) = s.lock().jobs.get_mut(&job_id) {
            j.state = "error";
            j.err = "dispatch failed".to_owned();
            j.mark_finished();
        }
        return http_error(StatusCode::BAD_GATEWAY, "dispatch failed");
    }
    let accepted: BTreeMap<&str, String> = [("job_id", job_id)].into_iter().collect();
    json_response(StatusCode::ACCEPTED, &accepted)
}

/// `GET /v1/jobs/{id}`.
pub(crate) async fn handle_job(State(s): State<Arc<Server>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let me = consumer!(s, headers);
    let st = s.lock();
    let Some(j) = st.jobs.get(&id).filter(|j| j.owner == me) else {
        return http_error(StatusCode::NOT_FOUND, "unknown job");
    };
    let status = wire::JobStatus {
        job_id: j.id.clone(),
        state: j.state.to_owned(),
        step: j.step,
        total: j.total,
        receipt: j.receipt.clone(),
        receipt_sig: j.receipt_sig.clone(),
        error: j.err.clone(),
        chunks: j.chunks.as_ref().map_or(0, |c| c.len() as i64),
    };
    json_response(StatusCode::OK, &status)
}

/// `GET /v1/jobs/{id}/result`: the sealed result, 4-byte big-endian length
/// + chunk, repeated.
pub(crate) async fn handle_result(State(s): State<Arc<Server>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let me = consumer!(s, headers);
    let chunks: Vec<Bytes> = {
        let st = s.lock();
        match st.jobs.get(&id).filter(|j| j.state == "done" && j.owner == me) {
            Some(j) => j.chunks.clone().unwrap_or_default(),
            None => return http_error(StatusCode::NOT_FOUND, "no result"),
        }
    };
    let parts = chunks.into_iter().flat_map(|c| [Bytes::copy_from_slice(&(c.len() as u32).to_be_bytes()), c]);
    let stream = futures_util::stream::iter(parts.map(Ok::<_, std::convert::Infallible>));
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// `GET /v1/ledger`: the caller's billed jobs.
pub(crate) async fn handle_ledger(State(s): State<Arc<Server>>, headers: HeaderMap) -> Response {
    let me = consumer!(s, headers);
    let out: Vec<LedgerEntry> = s.lock().ledger.iter().filter(|e| e.owner == me).cloned().collect();
    json_response(StatusCode::OK, &out)
}
