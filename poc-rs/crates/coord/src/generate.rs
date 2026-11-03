//! The default consumer API (`POST /v1/images/generations`,
//! `/v1/videos/generations`). Darkbloom's coordinator is trusted: consumers
//! send prompts to it over TLS (as with today's Darkbloom), and it seals each
//! job to the job key that the provider's TPM quote binds to an approved,
//! measured Node OS (plus the TPM-bound key when the provider offers one),
//! waits, opens the result and returns it. The provider machine, the
//! untrusted party, only ever sees ciphertext outside that OS.
//! Consumer-side end-to-end sealing (`/v1/jobs` with client-side
//! verification) remains available as optional defense in depth.

use crate::dispatch::DispatchGuard;
use crate::provider::{send_frame, send_job_frame, units_from_meta};
use crate::{
    Job, MAX_ACTIVE_JOBS_PER_PROVIDER, MAX_JOBS_PER_CONSUMER, MAX_JOBS_TOTAL, Provider, Server, consumer_of, http_error, json_response,
};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use base64::Engine as _;
use db_gojson::GoTime;
use db_tpmattest::{Statement, Verdict};
use db_wire as wire;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroize as _;

/// Request body cap (Go: `http.MaxBytesReader` 64 KiB).
const MAX_GENERATE_BODY: usize = 64 << 10;

/// `POST /v1/images/generations`.
pub(crate) async fn handle_images(State(s): State<Arc<Server>>, headers: HeaderMap, body: Body) -> Response {
    generate(s, headers, body, "image").await
}

/// `POST /v1/videos/generations`.
pub(crate) async fn handle_videos(State(s): State<Arc<Server>>, headers: HeaderMap, body: Body) -> Response {
    generate(s, headers, body, "video").await
}

/// A provider chosen for a job, with what sealing needs from its attestation.
#[derive(Clone)]
struct Candidate {
    provider: Arc<Provider>,
    workflow: String,
    job_kem: String,
    job_public_key: Vec<u8>,
    verdict: Arc<Verdict>,
}

async fn generate(s: Arc<Server>, headers: HeaderMap, body: Body, kind: &'static str) -> Response {
    let start = Instant::now();
    let Some(me) = consumer_of(&s, &headers) else {
        return http_error(StatusCode::UNAUTHORIZED, "missing or unknown API key");
    };
    let raw = match axum::body::to_bytes(body, MAX_GENERATE_BODY).await {
        Ok(b) => b,
        Err(_) => return http_error(StatusCode::BAD_REQUEST, "bad request: http: request body too large"),
    };
    let decoded = db_gojson::from_slice::<wire::GenerateRequest>(&raw);
    // Best effort: the body holds the prompt.
    if let Ok(mut b) = raw.try_into_mut() {
        b.as_mut().zeroize();
    }
    let mut gr = match decoded {
        Ok(r) => r,
        Err(e) => return http_error(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };
    let Some((width, height)) = parse_size(&gr.size, kind) else {
        return http_error(StatusCode::BAD_REQUEST, "size must be WIDTHxHEIGHT");
    };
    if gr.steps == 0 {
        gr.steps = if kind == "video" { 20 } else { 8 };
    }
    if kind == "video" {
        if gr.frames == 0 {
            gr.frames = 33;
        }
        if gr.fps == 0 {
            gr.fps = 16;
        }
    } else {
        gr.frames = 0;
        gr.fps = 0;
    }
    if gr.seed == 0 {
        gr.seed = random_seed();
    }

    // Route and register the job under one lock, so the caps hold.
    let job_id = format!("job-{}", crate::random_id(12));
    let (chosen, meta, mut done) = {
        let mut guard = s.lock();
        let st = &mut *guard;
        if st.jobs.len() >= 4 * MAX_JOBS_TOTAL {
            st.evict_finished();
        }
        let (mut active, mut mine) = (0usize, 0usize);
        let mut per_provider: HashMap<&str, usize> = HashMap::new();
        for j in st.jobs.values().filter(|j| j.state == "queued" || j.state == "running") {
            active += 1;
            mine += usize::from(j.owner == me);
            *per_provider.entry(j.provider_id.as_str()).or_default() += 1;
        }
        // A leased provider serving the model at the best tier, among those
        // whose attested statement lists the model and workflow and whose
        // advertised limits allow the request.
        let now = GoTime::now_utc();
        let mut best = 0u8;
        let mut cands: Vec<Candidate> = Vec::new();
        for conn in st.providers.values() {
            let Some((p, ps)) = st.conns.get(conn) else { continue };
            if !Server::leased(ps, &now) {
                continue;
            }
            let (Some(verdict), Some(stmt)) = (&ps.verdict, &ps.stmt) else { continue };
            for m in &p.hello.models {
                let Some(wf) = m.workflows.first() else { continue };
                if m.id != gr.model
                    || m.kind != kind
                    || !attests(stmt, &m.id, wf)
                    || width > m.max_width
                    || height > m.max_height
                    || gr.steps > m.max_steps
                    || (kind == "video" && gr.frames > m.max_frames)
                {
                    continue;
                }
                // Defense in depth: leases already require the minimum tier.
                let rank = verdict.tier.rank();
                if rank < s.min_tier.rank() {
                    continue;
                }
                if rank > best {
                    best = rank;
                    cands.clear();
                }
                if rank == best {
                    cands.push(Candidate {
                        provider: p.clone(),
                        workflow: wf.clone(),
                        job_kem: stmt.job_kem.clone(),
                        job_public_key: stmt.job_public_key.clone(),
                        verdict: verdict.clone(),
                    });
                }
            }
        }
        if cands.is_empty() {
            return http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("no attested provider with a live lease serves {} at {width}x{height}", gr.model),
            );
        }
        // Resource caps: per consumer, per provider (busy providers are
        // skipped within the tier) and overall.
        cands.retain(|c| per_provider.get(c.provider.id.as_str()).copied().unwrap_or(0) < MAX_ACTIVE_JOBS_PER_PROVIDER);
        if cands.is_empty() || active >= MAX_JOBS_TOTAL || st.jobs.len() >= 4 * MAX_JOBS_TOTAL || mine >= MAX_JOBS_PER_CONSUMER {
            return http_error(StatusCode::TOO_MANY_REQUESTS, "too many jobs in flight");
        }
        let Some(c) = cands.get(uniform_index(cands.len())).cloned() else {
            return http_error(StatusCode::SERVICE_UNAVAILABLE, "no provider");
        };
        let meta = wire::JobMeta {
            v: 1,
            job_id: job_id.clone(),
            provider_id: c.provider.id.clone(),
            session_id: c.provider.session_id.clone(),
            model: gr.model.clone(),
            workflow: c.workflow.clone(),
            kind: kind.to_owned(),
            width,
            height,
            steps: gr.steps,
            frames: gr.frames,
            fps: gr.fps,
            max_tokens: 0,
            created_at: now.truncate_secs(),
        };
        if let Err(e) = meta.validate() {
            return http_error(StatusCode::BAD_REQUEST, e.to_string());
        }
        let done = tokio::sync::watch::Sender::new(false);
        let rx = done.subscribe();
        st.jobs.insert(
            job_id.clone(),
            Job {
                id: job_id.clone(),
                provider_id: c.provider.id.clone(),
                session_id: c.provider.session_id.clone(),
                owner: me,
                meta: Vec::new(),
                parsed: meta.clone(),
                request_digest: String::new(),
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
                done,
            },
        );
        (c, meta, rx)
    };
    // From here on, an abandoned job is cancelled on the provider and its
    // ciphertext released.
    let mut job = Abandon { s: s.clone(), job_id: job_id.clone(), provider: chosen.provider.clone(), armed: true };

    let Ok(meta_bytes) = wire::marshal(&meta) else {
        return job.fail(StatusCode::INTERNAL_SERVER_ERROR, "sealing failed");
    };
    let mut jr = wire::JobRequest::default();
    jr.v = 1;
    jr.job_id.clone_from(&job_id);
    jr.model.clone_from(&gr.model);
    jr.workflow.clone_from(&chosen.workflow);
    jr.prompt = std::mem::take(&mut gr.prompt);
    jr.negative_prompt = std::mem::take(&mut gr.negative_prompt);
    jr.seed = gr.seed;
    jr.width = width;
    jr.height = height;
    jr.steps = gr.steps;
    jr.frames = gr.frames;
    jr.fps = gr.fps;
    if let Err(e) = jr.check_against(&meta) {
        return job.fail(StatusCode::BAD_REQUEST, &e.to_string());
    }
    let Ok(plain) = wire::pad_request(&mut jr) else {
        return job.fail(StatusCode::INTERNAL_SERVER_ERROR, "sealing failed");
    };
    drop(jr);
    let info = db_sealbox::info(&meta.provider_id, &meta.session_id);
    let sealed = match &chosen.verdict.bound_key {
        // TPM-enforced: only the attested boot can complete the ECDH.
        Some(bound) => db_sealbox::seal_request_bound(&chosen.job_kem, &chosen.job_public_key, bound, &info, &meta_bytes, &plain),
        None => db_sealbox::seal_request(&chosen.job_kem, &chosen.job_public_key, &info, &meta_bytes, &plain),
    };
    drop(plain);
    let Ok((sealed, result_key)) = sealed else {
        return job.fail(StatusCode::INTERNAL_SERVER_ERROR, "sealing failed");
    };
    if let Some(j) = s.lock().jobs.get_mut(&job_id) {
        j.meta.clone_from(&meta_bytes);
        j.request_digest = wire::request_digest(&sealed);
    }

    let frame = wire::Job { msg_type: wire::msg::JOB.to_owned(), job_id: job_id.clone(), meta: meta_bytes, sealed };
    let guard = DispatchGuard::new(
        &chosen.provider,
        &job_id,
        kind,
        &chosen.job_kem,
        &chosen.job_public_key,
        chosen.verdict.bound_key.as_ref().map(|key| key.to_sec1_bytes().to_vec()),
    );
    if send_job_frame(&chosen.provider.tx, &frame, guard, Duration::from_secs(30)).await.is_err() {
        return job.fail(StatusCode::BAD_GATEWAY, "dispatch failed");
    }
    drop(frame);
    let timeout = Duration::from_secs(if kind == "video" { 20 * 60 } else { 5 * 60 });
    match tokio::time::timeout(timeout, done.wait_for(|d| *d)).await {
        Ok(Ok(_)) => {}
        Ok(Err(_)) => return http_error(StatusCode::BAD_GATEWAY, "job failed: job expired"),
        Err(_) => return http_error(StatusCode::GATEWAY_TIMEOUT, "job timed out"),
    }
    // The coordinator keeps no copy: the result is returned once.
    let (state, err, chunks, receipt) = {
        let mut guard = s.lock();
        let st = &mut *guard;
        let Some(j) = st.jobs.get_mut(&job_id) else {
            return http_error(StatusCode::BAD_GATEWAY, "job failed: job expired");
        };
        let (state, err, chunks, receipt, size) = (j.state, j.err.clone(), j.chunks.take(), j.receipt.clone(), j.size);
        if chunks.is_some() {
            st.stored_bytes -= size;
        }
        (state, err, chunks.unwrap_or_default(), receipt)
    };
    job.armed = false;
    if state != "done" {
        return http_error(StatusCode::BAD_GATEWAY, format!("job failed: {err}"));
    }
    let data = match db_sealbox::open_result(&result_key, &job_id, &chunks) {
        Ok(d) => d,
        Err(e) => return http_error(StatusCode::BAD_GATEWAY, format!("result does not open: {e}")),
    };
    drop(chunks);
    let rc: wire::Receipt = db_gojson::from_slice(&receipt).unwrap_or_default();
    let mut mime = rc.result_mime.clone();
    if kind == "image" && !data.starts_with(b"\x89PNG") {
        mime = "application/octet-stream".to_owned();
    }
    let rsp = wire::GenerateResponse {
        created: chrono::Utc::now().timestamp(),
        data: vec![wire::GeneratedObject { b64_json: base64::engine::general_purpose::STANDARD.encode(&*data), mime_type: mime }],
        provenance: wire::Provenance {
            provider_id: meta.provider_id.clone(),
            tier: chosen.verdict.tier.as_str().to_owned(),
            release: chosen.verdict.release.clone(),
            tpm_bound_decryption: chosen.verdict.bound_key.is_some(),
            units: units_from_meta(&meta),
            elapsed: db_gojson::duration_ms_string(start.elapsed()),
        },
    };
    json_response(StatusCode::OK, &rsp)
}

/// Cancels a job on its provider and releases its ciphertext when the
/// request ends without collecting the result (timeout, consumer gone,
/// dispatch failure).
pub(crate) struct Abandon {
    pub(crate) s: Arc<Server>,
    pub(crate) job_id: String,
    pub(crate) provider: Arc<Provider>,
    pub(crate) armed: bool,
}

impl Abandon {
    /// Marks the job failed (it never reached the provider, or was refused
    /// before dispatch) and answers with `msg`.
    pub(crate) fn fail(&mut self, code: StatusCode, msg: &str) -> Response {
        let mut guard = self.s.lock();
        let st = &mut *guard;
        if let Some(j) = st.jobs.get_mut(&self.job_id) {
            j.state = "error";
            j.err = msg.to_owned();
            j.mark_finished();
        }
        drop(guard);
        http_error(code, msg)
    }
}

impl Drop for Abandon {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut guard = self.s.lock();
        let st = &mut *guard;
        let Some(j) = st.jobs.get_mut(&self.job_id) else { return };
        let running = !j.finished();
        if j.chunks.take().is_some() {
            let size = j.size;
            st.stored_bytes -= size;
        }
        if running {
            j.state = "error";
            j.err = "consumer abandoned".to_owned();
            j.mark_finished();
        }
        drop(guard);
        if running && let Ok(rt) = tokio::runtime::Handle::try_current() {
            let tx = self.provider.tx.clone();
            let cancel = wire::JobCancel { msg_type: wire::msg::JOB_CANCEL.to_owned(), job_id: self.job_id.clone() };
            rt.spawn(async move {
                let _ = send_frame(&tx, &cancel, Duration::from_secs(10)).await;
            });
        }
    }
}

/// Whether the attested statement lists the model and workflow.
fn attests(stmt: &Statement, model: &str, workflow: &str) -> bool {
    stmt.runtime.models.iter().any(|m| m.id == model) && stmt.runtime.workflows.iter().any(|w| w.name == workflow)
}

/// "WIDTHxHEIGHT" (Go: strings.Cut + strconv.Atoi); empty gives the kind's
/// default.
fn parse_size(size: &str, kind: &str) -> Option<(i64, i64)> {
    if size.is_empty() {
        return Some(if kind == "video" { (832, 480) } else { (1024, 1024) });
    }
    let (w, h) = size.split_once('x')?;
    Some((w.parse().ok()?, h.parse().ok()?))
}

/// A random seed in [1, 2^31] (0 means "random" on the wire).
fn random_seed() -> i64 {
    let mut b = [0u8; 4];
    let _ = getrandom::fill(&mut b);
    i64::from(u32::from_le_bytes(b) & 0x7fff_ffff) + 1
}

/// A uniform index below `n` (rejection sampling; no modulo bias).
fn uniform_index(n: usize) -> usize {
    let n = n as u64;
    if n <= 1 {
        return 0;
    }
    let zone = u64::MAX - (u64::MAX % n);
    loop {
        let mut b = [0u8; 8];
        let _ = getrandom::fill(&mut b);
        let v = u64::from_le_bytes(b);
        if v < zone {
            return usize::try_from(v % n).unwrap_or(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_parse_like_go() {
        assert_eq!(parse_size("", "image"), Some((1024, 1024)));
        assert_eq!(parse_size("", "video"), Some((832, 480)));
        assert_eq!(parse_size("512x768", "image"), Some((512, 768)));
        assert_eq!(parse_size("+512x768", "image"), Some((512, 768)));
        for bad in ["512", "x512", "512x", "512x512x2", " 512x512", "0x200x300", "abcxdef"] {
            assert_eq!(parse_size(bad, "image"), None, "{bad}");
        }
    }

    #[test]
    fn seeds_and_indices_stay_in_range() {
        for _ in 0..1000 {
            let s = random_seed();
            assert!((1..=1 << 31).contains(&s));
            assert!(uniform_index(3) < 3);
        }
        assert_eq!(uniform_index(0), 0);
        assert_eq!(uniform_index(1), 0);
    }
}
