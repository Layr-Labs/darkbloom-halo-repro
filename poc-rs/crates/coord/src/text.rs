//! A trusted-coordinator text API. The coordinator sees the prompt and result;
//! `/v1/jobs` is the consumer-sealed path for end-to-end privacy.

use crate::dispatch::{DispatchGuard, tier_allows};
use crate::generate::Abandon;
use crate::provider::send_job_frame;
use crate::{Job, MAX_ACTIVE_JOBS_PER_PROVIDER, MAX_JOBS_PER_CONSUMER, MAX_JOBS_TOTAL, Provider, Server, consumer_of, http_error};
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use db_gojson::GoTime;
use db_tpmattest::Verdict;
use db_wire as wire;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::{Zeroize as _, Zeroizing};

const MAX_TEXT_BODY: usize = 16 << 10;

struct Candidate {
    provider: Arc<Provider>,
    workflow: String,
    job_kem: String,
    job_public_key: Vec<u8>,
    verdict: Arc<Verdict>,
}

/// `POST /v1/completions`. This convenient API trusts the coordinator with
/// plaintext. Text is never dispatched to a development tier.
pub(crate) async fn handle_completions(State(s): State<Arc<Server>>, headers: HeaderMap, body: Body) -> Response {
    let start = Instant::now();
    let Some(me) = consumer_of(&s, &headers) else {
        return http_error(StatusCode::UNAUTHORIZED, "missing or unknown API key");
    };
    let raw = match axum::body::to_bytes(body, MAX_TEXT_BODY).await {
        Ok(b) => b,
        Err(_) => return http_error(StatusCode::BAD_REQUEST, "bad request: body too large"),
    };
    let decoded = db_gojson::from_slice::<wire::GenerateTextRequest>(&raw);
    if let Ok(mut b) = raw.try_into_mut() {
        b.as_mut().zeroize();
    }
    let mut gr = match decoded {
        Ok(r) => r,
        Err(_) => return http_error(StatusCode::BAD_REQUEST, "bad text request"),
    };
    if gr.model.is_empty() || gr.prompt.is_empty() || gr.prompt.len() > wire::MAX_PROMPT_BYTES {
        return http_error(StatusCode::BAD_REQUEST, "model or prompt length out of range");
    }
    if !(1..=wire::MAX_TEXT_TOKENS).contains(&gr.max_tokens) {
        return http_error(StatusCode::BAD_REQUEST, "max_tokens must be 1..1024");
    }

    // Select a production-attested, leased provider under the same lock that
    // reserves the job. The writer repeats the trust check at actual send.
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
        if active >= MAX_JOBS_TOTAL || st.jobs.len() >= 4 * MAX_JOBS_TOTAL || mine >= MAX_JOBS_PER_CONSUMER {
            return http_error(StatusCode::TOO_MANY_REQUESTS, "too many jobs in flight");
        }
        let now = GoTime::now_utc();
        let mut cands = Vec::new();
        let mut best_tier = 0;
        for conn in st.providers.values() {
            let Some((p, ps)) = st.conns.get(conn) else { continue };
            if !Server::leased(ps, &now) {
                continue;
            }
            let (Some(verdict), Some(stmt)) = (&ps.verdict, &ps.stmt) else { continue };
            if !tier_allows(&s, "text", &verdict.tier) || verdict.bound_key.is_none() {
                continue;
            }
            for m in &p.hello.models {
                let Some(wf) = m.workflows.first() else { continue };
                if m.id != gr.model
                    || m.kind != "text"
                    || m.max_tokens <= 0
                    || gr.max_tokens > m.max_tokens
                    || !stmt.runtime.models.iter().any(|r| r.id == m.id)
                    || !stmt.runtime.workflows.iter().any(|w| w.name == *wf)
                    || per_provider.get(p.id.as_str()).copied().unwrap_or(0) >= MAX_ACTIVE_JOBS_PER_PROVIDER
                {
                    continue;
                }
                let rank = verdict.tier.rank();
                if rank > best_tier {
                    best_tier = rank;
                    cands.clear();
                }
                if rank != best_tier {
                    continue;
                }
                cands.push(Candidate {
                    provider: p.clone(),
                    workflow: wf.clone(),
                    job_kem: stmt.job_kem.clone(),
                    job_public_key: stmt.job_public_key.clone(),
                    verdict: verdict.clone(),
                });
            }
        }
        let Some(chosen) = cands.into_iter().next() else {
            return http_error(StatusCode::SERVICE_UNAVAILABLE, "no attested text provider with a live lease");
        };
        let meta = wire::JobMeta {
            v: 1,
            job_id: job_id.clone(),
            provider_id: chosen.provider.id.clone(),
            session_id: chosen.provider.session_id.clone(),
            model: gr.model.clone(),
            workflow: chosen.workflow.clone(),
            kind: "text".to_owned(),
            max_tokens: gr.max_tokens,
            created_at: now.truncate_secs(),
            ..wire::JobMeta::default()
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
                provider_id: chosen.provider.id.clone(),
                session_id: chosen.provider.session_id.clone(),
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
        (chosen, meta, rx)
    };
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
    jr.seed = gr.seed;
    jr.max_tokens = gr.max_tokens;
    if let Err(e) = jr.check_against(&meta) {
        return job.fail(StatusCode::BAD_REQUEST, &e.to_string());
    }
    let Ok(plain) = wire::pad_request(&mut jr) else {
        return job.fail(StatusCode::INTERNAL_SERVER_ERROR, "sealing failed");
    };
    drop(jr);
    let info = db_sealbox::info(&meta.provider_id, &meta.session_id);
    let Some(bound) = &chosen.verdict.bound_key else {
        return job.fail(StatusCode::SERVICE_UNAVAILABLE, "provider has no TPM-bound job key");
    };
    let sealed = db_sealbox::seal_request_bound(&chosen.job_kem, &chosen.job_public_key, bound, &info, &meta_bytes, &plain);
    drop(plain);
    let Ok((sealed, result_key)) = sealed else {
        return job.fail(StatusCode::INTERNAL_SERVER_ERROR, "sealing failed");
    };
    if let Some(j) = s.lock().jobs.get_mut(&job_id) {
        j.meta.clone_from(&meta_bytes);
        j.request_digest = wire::request_digest(&sealed);
    }
    let frame = wire::Job { msg_type: wire::msg::JOB.to_owned(), job_id: job_id.clone(), meta: meta_bytes, sealed };
    let dispatch_guard = DispatchGuard::new(
        &chosen.provider,
        &job_id,
        "text",
        &chosen.job_kem,
        &chosen.job_public_key,
        chosen.verdict.bound_key.as_ref().map(|key| key.to_sec1_bytes().to_vec()),
    );
    if send_job_frame(&chosen.provider.tx, &frame, dispatch_guard, Duration::from_secs(30)).await.is_err() {
        return job.fail(StatusCode::BAD_GATEWAY, "dispatch failed");
    }
    drop(frame);
    match tokio::time::timeout(Duration::from_secs(5 * 60), done.wait_for(|d| *d)).await {
        Ok(Ok(_)) => {}
        Ok(Err(_)) => return http_error(StatusCode::BAD_GATEWAY, "job failed: job expired"),
        Err(_) => return http_error(StatusCode::GATEWAY_TIMEOUT, "job timed out"),
    }
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
    let mut data = match db_sealbox::open_result(&result_key, &job_id, &chunks) {
        Ok(d) => d,
        Err(_) => return http_error(StatusCode::BAD_GATEWAY, "result does not open"),
    };
    drop(chunks);
    let mut text = match String::from_utf8(std::mem::take(&mut *data)) {
        Ok(text) => Zeroizing::new(text),
        Err(e) => {
            let mut bytes = e.into_bytes();
            bytes.zeroize();
            return http_error(StatusCode::BAD_GATEWAY, "result is not UTF-8 text");
        }
    };
    let rc: wire::Receipt = match db_gojson::from_slice(&receipt) {
        Ok(r) => r,
        Err(_) => return http_error(StatusCode::BAD_GATEWAY, "invalid receipt"),
    };
    let mut rsp = wire::GenerateTextResponse {
        id: job_id,
        model: meta.model,
        text: std::mem::take(&mut *text),
        usage: wire::TextUsage { prompt_tokens: rc.units.prompt_tokens, completion_tokens: rc.units.completion_tokens },
        provenance: wire::Provenance {
            provider_id: meta.provider_id,
            tier: chosen.verdict.tier.as_str().to_owned(),
            release: chosen.verdict.release.clone(),
            tpm_bound_decryption: true,
            units: rc.units,
            elapsed: db_gojson::duration_ms_string(start.elapsed()),
        },
    };
    let encoded = db_gojson::to_vec_line(&rsp);
    rsp.text.zeroize();
    let Ok(encoded) = encoded else {
        return http_error(StatusCode::INTERNAL_SERVER_ERROR, "response encoding failed");
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(Bytes::from_owner(Zeroizing::new(encoded))))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}
