//! Sealed job flows through a real coordinator and agent on swtpm.
//! On the end-to-end path the coordinator only ever
//! sees ciphertext; on the default path it seals the job itself (TPM-bound)
//! and cancels jobs a consumer abandons. The ledger bills from receipts,
//! dispatch fails closed after the provider stops answering, tampered
//! metadata is refused by the provider, and engine error text never leaves
//! the provider. With TLS, the agent (WSS) and the consumer (HTTPS) reach
//! the coordinator only through its pinned CA.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use db_engine::{BoxFuture, Engine, EngineError, Fake, Output, Progress};
use db_log::Logger;
use db_release::{Model, Runtime, TrustedKeys};
use db_testenv::{Fixture, TEST_CMDLINE};
use db_tls::rustls;
use db_tpmattest::{GpuStatus, Status, Tier, TrustedRelease, Verifier};
use db_wire as wire;
use ed25519_dalek::SigningKey;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// A plain-HTTP client for the tests' raw requests (reqwest's default TLS
/// backend needs a process-wide provider, as the binaries install one).
fn http() -> reqwest::Client {
    db_tls::install_default_provider();
    reqwest::Client::new()
}

/// TLS for a flow: the coordinator's certificate, and the trust anchors the
/// agent and the consumer pin.
struct Tls {
    server: Arc<rustls::ServerConfig>,
    agent: Arc<rustls::ClientConfig>,
    client: rustls::ClientConfig,
}

/// A development certificate for 127.0.0.1 in `dir`.
fn devcert(dir: &Path) -> (Arc<rustls::ServerConfig>, std::path::PathBuf) {
    db_tls::devcert::write(dir, &["127.0.0.1", "localhost"]).unwrap();
    let server = db_tls::server_config(&dir.join("server.pem"), &dir.join("server.key")).unwrap();
    (Arc::new(server), dir.join("ca.pem"))
}

fn pinned(ca: &Path) -> rustls::ClientConfig {
    db_tls::client_config_for(Some(ca)).unwrap()
}

fn random_key() -> SigningKey {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    SigningKey::from_bytes(&seed)
}

struct Flow {
    _fixture: Fixture,
    base: String,
    client: db_client::Client,
    tap: Arc<Mutex<Vec<Vec<u8>>>>,
    shutdown: CancellationToken,
    agent_done: tokio::task::JoinHandle<()>,
}

fn test_status() -> Status {
    Status {
        lockdown: "confidentiality".to_owned(),
        dash_enabled: Some(false),
        gpu: GpuStatus { enforce_isolation: Some(1), owner: "node".to_owned(), target: "gfx1151".to_owned(), ..GpuStatus::default() },
        ..Status::default()
    }
}

/// Starts swtpm, a coordinator and an agent; `None` when swtpm is missing.
async fn start_flow(challenge: Duration, engine: Arc<dyn Engine>) -> Option<Flow> {
    start_flow_with(challenge, engine, None, Logger::stderr("node ")).await
}

/// [`start_flow`] with an optional TLS coordinator and the agent's logger.
async fn start_flow_with(challenge: Duration, engine: Arc<dyn Engine>, tls: Option<Tls>, agent_log: Logger) -> Option<Flow> {
    start_flow_profile(challenge, engine, tls, agent_log, false).await
}

/// `synthetic_production` is a test-only production policy exercise. It
/// relabels the fixture CA as production and presents swtpm as hardware so
/// protocol tests can reach Attested; it does not represent an AMD root or
/// validate a physical Halo.
async fn start_flow_profile(
    challenge: Duration,
    engine: Arc<dyn Engine>,
    tls: Option<Tls>,
    agent_log: Logger,
    synthetic_production: bool,
) -> Option<Flow> {
    let mut f = Fixture::new(TEST_CMDLINE)?;
    if synthetic_production {
        f.manifest.channel = "production".to_owned();
    }
    // The signed release must pin exactly what this engine reports.
    let caps = engine.caps();
    f.manifest.runtime = Runtime {
        engine: db_release::Artifact { name: engine.name(), ..Default::default() },
        workflows: Some(engine.workflows()),
        models: Some(
            engine
                .models()
                .into_iter()
                .map(|m| {
                    let kind = caps.iter().find(|c| c.id == m.id).map_or_else(String::new, |c| c.kind.clone());
                    Model { id: m.id, kind, files: Some(m.files) }
                })
                .collect(),
        ),
        ..Runtime::default()
    };
    let env = db_release::sign_manifest(&f.manifest, &f.release_key).unwrap();
    let env_bytes = db_gojson::to_vec(&env).unwrap();
    let rel_pub = f.release_key.verifying_key();
    let keys: TrustedKeys = [(db_release::key_id(&rel_pub), rel_pub)].into_iter().collect();
    let log_key = random_key();
    let release_log = Arc::new(db_release::Log::new(log_key.clone()));
    release_log.append(&env_bytes);
    let m = db_release::open_manifest(&env, &keys, 1).unwrap();
    let enrollment_key = random_key();
    let policy = db_release::Policy { keys: keys.clone(), min_svn: 1, allow_dev: true, require_logged: true, ..Default::default() };
    let mut bundle = f.dev_bundle();
    if synthetic_production {
        bundle.roots[0].name = "test-only synthetic production root".to_owned();
        bundle.roots[0].production = true;
    }
    let verifier = Verifier {
        bundle: bundle.clone(),
        releases: vec![TrustedRelease { manifest: Arc::new(m), envelope: env_bytes, logged: true }],
        release_policy: Some(policy),
        allow_dev_roots: true,
        ..Verifier::default()
    };
    let server = db_coord::Server::new(db_coord::Config {
        verifier,
        enrollment_key: enrollment_key.clone(),
        release_log,
        release_log_key: log_key.verifying_key(),
        release_keys: keys.clone(),
        provider_tokens: BTreeMap::from([("pair-token".to_owned(), "acct-halo-owner".to_owned())]),
        consumer_keys: BTreeSet::from(["consumer-key".to_owned()]),
        challenge_interval: challenge,
        lease_ttl: challenge * 3,
        min_tier: Some(Tier::DevSimulated),
        max_result_bytes: 0,
        capture_attestation: None,
        logger: Logger::stderr("coord "),
    })
    .unwrap();
    // Record every request body the coordinator receives.
    let tap: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let tap2 = tap.clone();
    let app = server.router().layer(axum::middleware::from_fn(move |req: Request, next: Next| {
        let tap = tap2.clone();
        async move {
            if req.method() == axum::http::Method::POST {
                let (parts, body) = req.into_parts();
                let bytes = axum::body::to_bytes(body, 64 << 20).await.unwrap_or_default();
                tap.lock().unwrap().push(bytes.to_vec());
                next.run(Request::from_parts(parts, Body::from(bytes))).await
            } else {
                next.run(req).await
            }
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (http_scheme, ws_scheme) = if tls.is_some() { ("https", "wss") } else { ("http", "ws") };
    match &tls {
        None => {
            tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
        }
        Some(t) => {
            let listener = db_coord::TlsListener::new(listener, t.server.clone(), Logger::stderr("coord ")).unwrap();
            tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
        }
    }
    let base = format!("{http_scheme}://{addr}");

    let device = if synthetic_production {
        // swtpm's raw socket serves one data client at a time; release the
        // fixture's provisioning connection before opening the test wrapper.
        f.dev.close();
        let (transport, _) = db_tpmdev::transport::open(&f.tpm.spec()).unwrap();
        db_tpmdev::Device::with_transport(transport, db_tpmdev::Mode::Hardware)
    } else {
        f.dev.clone()
    };
    let att = Arc::new(db_node::Attester::new(device, Some(f.event_log.clone())).unwrap());
    let agent = db_node::Agent::new(
        db_node::Config {
            coordinator_url: format!("{ws_scheme}://{addr}/v1/provider/ws"),
            tls: tls.as_ref().map(|t| t.agent.clone()),
            account_token: "pair-token".to_owned(),
            job_kem: String::new(),
            status: Some(Arc::new(test_status)),
            logger: agent_log,
        },
        att.clone(),
        engine,
    );
    let shutdown = CancellationToken::new();
    let token = shutdown.clone();
    let agent_done = tokio::spawn(async move {
        let _ = agent.run(token).await;
        att.close();
    });
    let mut client = match tls {
        None => db_client::Client::new(&base, "consumer-key").unwrap(),
        Some(t) => db_client::Client::with_tls(&base, "consumer-key", t.client).unwrap(),
    };
    client.bundle = bundle;
    client.release_keys = keys;
    client.release_log_key = Some(log_key.verifying_key());
    client.enrollment_key = Some(enrollment_key.verifying_key());
    client.min_svn = 1;
    client.allow_dev = true;
    Some(Flow { _fixture: f, base, client, tap, shutdown, agent_done })
}

async fn wait_provider(cl: &db_client::Client) -> wire::ProviderInfo {
    for _ in 0..200 {
        if let Ok(ps) = cl.providers().await
            && let [p] = ps.as_slice()
        {
            return p.clone();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("provider never got a lease");
}

async fn get(base: &str, path: &str) -> (u16, Vec<u8>) {
    let rsp = http().get(format!("{base}{path}")).header("Authorization", "Bearer consumer-key").send().await.unwrap();
    let status = rsp.status().as_u16();
    (status, rsp.bytes().await.unwrap().to_vec())
}

async fn post(base: &str, path: &str, body: Vec<u8>) -> u16 {
    http().post(format!("{base}{path}")).header("Authorization", "Bearer consumer-key").body(body).send().await.unwrap().status().as_u16()
}

fn image_request(prompt: &str, steps: i64) -> db_client::ImageRequest {
    db_client::ImageRequest {
        model: "fake-image".to_owned(),
        workflow: "fake-t2i".to_owned(),
        prompt: zeroize::Zeroizing::new(prompt.to_owned()),
        width: 512,
        height: 512,
        steps,
        ..Default::default()
    }
}

#[derive(Clone, Copy)]
enum TextMode {
    Normal,
    ExcessTokens,
    InvalidUtf8,
    Oversize,
}

/// A deterministic text engine for the protocol test. It models llama's
/// engine identity, caps, MIME and receipt units, but does not claim to run
/// llama.cpp or any GPU inference.
struct MockTextEngine {
    mode: TextMode,
    calls: AtomicUsize,
}

impl MockTextEngine {
    fn new(mode: TextMode) -> Self {
        Self { mode, calls: AtomicUsize::new(0) }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Engine for MockTextEngine {
    fn name(&self) -> String {
        "llama.cpp".to_owned()
    }

    fn workflows(&self) -> Vec<db_release::Artifact> {
        vec![db_release::Artifact { name: "llama-text-greedy-v1".to_owned(), sha256: "aa".repeat(32), bytes: 100 }]
    }

    fn models(&self) -> Vec<db_tpmattest::ModelReport> {
        vec![db_tpmattest::ModelReport {
            id: "mock-text".to_owned(),
            files: vec![db_release::Artifact { name: "model.gguf".to_owned(), sha256: "bb".repeat(32), bytes: 100 }],
        }]
    }

    fn caps(&self) -> Vec<wire::ModelCap> {
        vec![wire::ModelCap {
            id: "mock-text".to_owned(),
            kind: "text".to_owned(),
            workflows: vec!["llama-text-greedy-v1".to_owned()],
            max_tokens: 64,
            ..wire::ModelCap::default()
        }]
    }

    fn generate<'a>(
        &'a self,
        req: &'a wire::JobRequest,
        progress: Progress<'a>,
        _cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<Output, EngineError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if req.model != "mock-text" || req.workflow != "llama-text-greedy-v1" || !(1..=64).contains(&req.max_tokens) {
                return Err(EngineError("mock text request out of range".to_owned()));
            }
            progress(0, req.max_tokens);
            let data = match self.mode {
                TextMode::Normal | TextMode::ExcessTokens => format!("answer to {}", req.prompt).into_bytes(),
                TextMode::InvalidUtf8 => vec![0xff, 0xfe],
                TextMode::Oversize => vec![b'x'; (1 << 20) + 1],
            };
            let completion_tokens = if matches!(self.mode, TextMode::ExcessTokens) { req.max_tokens + 1 } else { 3 };
            Ok(Output {
                data: zeroize::Zeroizing::new(data),
                mime: "text/plain; charset=utf-8".to_owned(),
                units: wire::Units { prompt_tokens: 4, completion_tokens, ..wire::Units::default() },
            })
        })
    }
}

fn text_request(prompt: &str, max_tokens: i64) -> db_client::TextRequest {
    db_client::TextRequest {
        model: "mock-text".to_owned(),
        workflow: "llama-text-greedy-v1".to_owned(),
        prompt: zeroize::Zeroizing::new(prompt.to_owned()),
        max_tokens,
        seed: 7,
    }
}

fn text_meta(provider_id: &str, session_id: &str, job_id: &str, max_tokens: i64) -> wire::JobMeta {
    wire::JobMeta {
        v: 1,
        job_id: job_id.to_owned(),
        provider_id: provider_id.to_owned(),
        session_id: session_id.to_owned(),
        model: "mock-text".to_owned(),
        workflow: "llama-text-greedy-v1".to_owned(),
        kind: "text".to_owned(),
        max_tokens,
        ..wire::JobMeta::default()
    }
}

fn sealed_text(ver: &db_client::Verified, meta: &wire::JobMeta, prompt: &str, bound: bool) -> db_sealbox::Sealed {
    let mut req = wire::JobRequest::default();
    req.v = 1;
    req.job_id.clone_from(&meta.job_id);
    req.model.clone_from(&meta.model);
    req.workflow.clone_from(&meta.workflow);
    req.prompt = prompt.to_owned();
    req.max_tokens = meta.max_tokens;
    let plain = wire::pad_request(&mut req).unwrap();
    let meta_bytes = wire::marshal(meta).unwrap();
    let info = db_sealbox::info(&meta.provider_id, &meta.session_id);
    if bound {
        let key = ver.verdict.bound_key.as_ref().unwrap();
        db_sealbox::seal_request_bound(&ver.statement.job_kem, &ver.statement.job_public_key, key, &info, &meta_bytes, &plain).unwrap().0
    } else {
        db_sealbox::seal_request(&ver.statement.job_kem, &ver.statement.job_public_key, &info, &meta_bytes, &plain).unwrap().0
    }
}

async fn wait_job_error(base: &str, job_id: &str) -> String {
    for _ in 0..100 {
        let (status, body) = get(base, &format!("/v1/jobs/{job_id}")).await;
        if status == 200 {
            let js: wire::JobStatus = db_gojson::from_slice(&body).unwrap();
            if js.state == "error" {
                return js.error;
            }
            assert_ne!(js.state, "done", "invalid text job completed");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("text job {job_id} never failed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sealed_image_job() {
    let Some(fl) = start_flow(Duration::from_millis(500), Arc::new(Fake { delay: Duration::from_millis(5) })).await else {
        eprintln!("skipped: swtpm not installed");
        return;
    };
    let p = wait_provider(&fl.client).await;
    assert_eq!(p.tier, Tier::DevSimulated);
    const PROMPT: &str = "SECRET-PROMPT a lighthouse at dusk";
    let res = fl.client.generate(&p.provider_id, &image_request(PROMPT, 4), |_, _, _| {}).await.unwrap();
    assert!(res.data.starts_with(b"\x89PNG"), "result is not a PNG");
    eprintln!("job {}: {}-byte PNG, receipt {:?}", res.job_id, res.data.len(), res.receipt.units);
    // The coordinator only ever saw ciphertext.
    for body in fl.tap.lock().unwrap().iter() {
        assert!(!body.windows(13).any(|w| w == b"SECRET-PROMPT"), "prompt reached the coordinator in plaintext");
    }
    let (status, body) = get(&fl.base, "/v1/ledger").await;
    assert_eq!(status, 200);
    let ledger: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(ledger.len(), 1, "{ledger:?}");
    assert_eq!(ledger[0]["units"]["steps"], 4);
    fl.shutdown.cancel();
    let _ = fl.agent_done.await;
}

/// This uses a *test-only* CA root labelled production and a swtpm transport
/// presented as hardware. It exercises the Attested protocol branch and
/// TPM-bound job key; it makes no claim about AMD EK certificates or a Halo.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sealed_text_job_synthetic_attested_profile() {
    let engine = Arc::new(MockTextEngine::new(TextMode::Normal));
    let Some(fl) = start_flow_profile(Duration::from_millis(500), engine.clone(), None, Logger::discard(), true).await else {
        eprintln!("skipped: swtpm not installed");
        return;
    };
    let p = wait_provider(&fl.client).await;
    assert_eq!(p.tier, Tier::Attested);
    let ver = fl.client.verify(&p.provider_id).await.unwrap();
    assert!(ver.verdict.bound_key.is_some(), "synthetic attested profile lacks a TPM-bound job key");
    const CANARY: &str = "PRIVATE-TEXT-CANARY-4172";
    let result = fl.client.generate_text(&p.provider_id, &text_request(CANARY, 16), |_, _, _| {}).await.unwrap();
    assert_eq!(&*result.data, format!("answer to {CANARY}").as_bytes());
    assert_eq!(result.mime, "text/plain; charset=utf-8");
    assert_eq!((result.receipt.units.prompt_tokens, result.receipt.units.completion_tokens), (4, 3));
    assert_eq!(engine.calls(), 1);
    for body in fl.tap.lock().unwrap().iter() {
        assert!(!body.windows(CANARY.len()).any(|w| w == CANARY.as_bytes()), "coordinator received the private prompt in plaintext");
    }
    let (status, body) = get(&fl.base, "/v1/ledger").await;
    assert_eq!(status, 200);
    let ledger: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(ledger.len(), 1);
    assert_eq!((ledger[0]["units"]["prompt_tokens"].as_i64(), ledger[0]["units"]["completion_tokens"].as_i64()), (Some(4), Some(3)));
    assert_eq!(ledger[0]["price_micro_usd"], 0);
    fl.shutdown.cancel();
    let _ = fl.agent_done.await;
}

/// Even with allow_dev enabled, neither the client nor coordinator may send
/// private text to a development tier, and the server rejects unbound text.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_text_refuses_development_tier_and_unbound_sealing() {
    let engine = Arc::new(MockTextEngine::new(TextMode::Normal));
    let Some(fl) = start_flow(Duration::from_millis(500), engine.clone()).await else {
        eprintln!("skipped: swtpm not installed");
        return;
    };
    let p = wait_provider(&fl.client).await;
    assert_eq!(p.tier, Tier::DevSimulated);
    let ver = fl.client.verify(&p.provider_id).await.unwrap();
    assert!(ver.verdict.bound_key.is_some(), "development TPM did not offer a bound key");
    let err = fl.client.generate_text(&p.provider_id, &text_request("PRIVATE-TEXT-CANARY", 16), |_, _, _| {}).await.unwrap_err();
    assert!(err.to_string().contains("private text requires an approved boot"), "{err}");
    assert_eq!(engine.calls(), 0);

    let unbound_meta = text_meta(&p.provider_id, &ver.statement.session_id, "text-unbound", 16);
    let body = wire::marshal(&wire::SubmitJob {
        provider_id: p.provider_id.clone(),
        meta: wire::marshal(&unbound_meta).unwrap(),
        sealed: sealed_text(&ver, &unbound_meta, "PRIVATE-TEXT-CANARY", false),
    })
    .unwrap();
    assert_eq!(post(&fl.base, "/v1/jobs", body).await, 400, "unbound text was accepted");
    let bound_meta = text_meta(&p.provider_id, &ver.statement.session_id, "text-dev-bound", 16);
    let body = wire::marshal(&wire::SubmitJob {
        provider_id: p.provider_id.clone(),
        meta: wire::marshal(&bound_meta).unwrap(),
        sealed: sealed_text(&ver, &bound_meta, "PRIVATE-TEXT-CANARY", true),
    })
    .unwrap();
    assert_eq!(post(&fl.base, "/v1/jobs", body).await, 503, "development tier served private text");
    assert_eq!(engine.calls(), 0);
    fl.shutdown.cancel();
    let _ = fl.agent_done.await;
}

/// max_tokens is public routing metadata and part of the sealed AAD. A
/// coordinator that lowers it after sealing cannot make the provider run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn text_max_tokens_metadata_tamper_fails_aad() {
    let engine = Arc::new(MockTextEngine::new(TextMode::Normal));
    let Some(fl) = start_flow_profile(Duration::from_millis(500), engine.clone(), None, Logger::discard(), true).await else {
        eprintln!("skipped: swtpm not installed");
        return;
    };
    let p = wait_provider(&fl.client).await;
    let ver = fl.client.verify(&p.provider_id).await.unwrap();
    let mut meta = text_meta(&p.provider_id, &ver.statement.session_id, "text-tamper", 16);
    let sealed = sealed_text(&ver, &meta, "PRIVATE-TEXT-CANARY", true);
    meta.max_tokens = 8;
    let body = wire::marshal(&wire::SubmitJob { provider_id: p.provider_id.clone(), meta: wire::marshal(&meta).unwrap(), sealed }).unwrap();
    assert_eq!(post(&fl.base, "/v1/jobs", body).await, 202);
    let error = wait_job_error(&fl.base, &meta.job_id).await;
    assert!(error.contains("decrypt"), "unexpected tamper error: {error}");
    assert_eq!(engine.calls(), 0);
    fl.shutdown.cancel();
    let _ = fl.agent_done.await;
}

/// Signed receipts cannot claim more generated tokens than authorized, and
/// consumers refuse malformed or oversized text even from a signed engine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_text_result_limits() {
    for mode in [TextMode::ExcessTokens, TextMode::InvalidUtf8, TextMode::Oversize] {
        let engine = Arc::new(MockTextEngine::new(mode));
        let Some(fl) = start_flow_profile(Duration::from_millis(500), engine.clone(), None, Logger::discard(), true).await else {
            eprintln!("skipped: swtpm not installed");
            return;
        };
        let p = wait_provider(&fl.client).await;
        let err = fl.client.generate_text(&p.provider_id, &text_request("PRIVATE-TEXT-CANARY", 16), |_, _, _| {}).await.unwrap_err();
        assert!(!err.to_string().contains("PRIVATE-TEXT-CANARY"), "text error leaked the prompt: {err}");
        assert_eq!(engine.calls(), 1);
        fl.shutdown.cancel();
        let _ = fl.agent_done.await;
    }
}

/// When the provider stops answering challenges, its lease expires and
/// dispatch is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fail_closed_after_provider_stops() {
    let Some(fl) = start_flow(Duration::from_millis(300), Arc::new(Fake { delay: Duration::from_millis(5) })).await else {
        eprintln!("skipped: swtpm not installed");
        return;
    };
    let p = wait_provider(&fl.client).await;
    let ver = fl.client.verify(&p.provider_id).await.unwrap();
    fl.shutdown.cancel();
    let _ = fl.agent_done.await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(fl.client.providers().await.unwrap().is_empty(), "provider still listed after it stopped");
    // A job sealed to the old session is refused, not queued.
    let meta = wire::JobMeta {
        v: 1,
        job_id: "job-late".to_owned(),
        provider_id: p.provider_id.clone(),
        session_id: ver.statement.session_id.clone(),
        model: "fake-image".to_owned(),
        workflow: "fake-t2i".to_owned(),
        kind: "image".to_owned(),
        width: 512,
        height: 512,
        steps: 2,
        ..wire::JobMeta::default()
    };
    let body =
        wire::marshal(&wire::SubmitJob { provider_id: p.provider_id.clone(), meta: wire::marshal(&meta).unwrap(), ..Default::default() })
            .unwrap();
    let status = post(&fl.base, "/v1/jobs", body).await;
    assert!(status >= 400, "dispatch to a provider without a lease returned {status}");
}

/// The coordinator (or anyone on the path) changes the routed size after
/// sealing; the provider refuses.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tampered_metadata_rejected_by_provider() {
    let Some(fl) = start_flow(Duration::from_millis(500), Arc::new(Fake { delay: Duration::from_millis(5) })).await else {
        eprintln!("skipped: swtpm not installed");
        return;
    };
    let p = wait_provider(&fl.client).await;
    let ver = fl.client.verify(&p.provider_id).await.unwrap();
    let st = &ver.statement;
    let mut meta = wire::JobMeta {
        v: 1,
        job_id: "job-tamper".to_owned(),
        provider_id: p.provider_id.clone(),
        session_id: st.session_id.clone(),
        model: "fake-image".to_owned(),
        workflow: "fake-t2i".to_owned(),
        kind: "image".to_owned(),
        width: 512,
        height: 512,
        steps: 2,
        ..wire::JobMeta::default()
    };
    let meta_bytes = wire::marshal(&meta).unwrap();
    let mut req = wire::JobRequest::default();
    req.v = 1;
    req.job_id = "job-tamper".to_owned();
    req.model = "fake-image".to_owned();
    req.workflow = "fake-t2i".to_owned();
    req.prompt = "x".to_owned();
    req.width = 512;
    req.height = 512;
    req.steps = 2;
    let plain = wire::marshal(&req).unwrap();
    let (sealed, _) =
        db_sealbox::seal_request(&st.job_kem, &st.job_public_key, &db_sealbox::info(&p.provider_id, &st.session_id), &meta_bytes, &plain)
            .unwrap();
    meta.width = 256; // a cheaper size in plaintext metadata than what was sealed
    let body = wire::marshal(&wire::SubmitJob { provider_id: p.provider_id.clone(), meta: wire::marshal(&meta).unwrap(), sealed }).unwrap();
    post(&fl.base, "/v1/jobs", body).await;
    for _ in 0..100 {
        let (status, body) = get(&fl.base, "/v1/jobs/job-tamper").await;
        if status == 200 {
            let js: wire::JobStatus = db_gojson::from_slice(&body).unwrap();
            match js.state.as_str() {
                "error" => {
                    assert!(js.error.contains("decrypt"), "unexpected error {:?}", js.error);
                    fl.shutdown.cancel();
                    return;
                }
                "done" => panic!("provider ran a job whose metadata was altered after sealing"),
                _ => {}
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("tampered job never failed");
}

/// Fails with an error that echoes the prompt, as a real engine validation
/// error can.
struct LeakyEngine(Fake);

impl Engine for LeakyEngine {
    fn name(&self) -> String {
        self.0.name()
    }
    fn workflows(&self) -> Vec<db_release::Artifact> {
        self.0.workflows()
    }
    fn models(&self) -> Vec<db_tpmattest::ModelReport> {
        self.0.models()
    }
    fn caps(&self) -> Vec<wire::ModelCap> {
        self.0.caps()
    }
    fn generate<'a>(
        &'a self,
        req: &'a wire::JobRequest,
        _progress: Progress<'a>,
        _cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<Output, EngineError>> {
        Box::pin(async move { Err(EngineError(format!("validation failed for text {:?}", req.prompt))) })
    }
}

/// A failing engine's error text stays on the provider; the coordinator and
/// its dashboard see only a fixed code.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engine_errors_do_not_leak_prompts() {
    let Some(fl) = start_flow(Duration::from_millis(500), Arc::new(LeakyEngine(Fake { delay: Duration::ZERO }))).await else {
        eprintln!("skipped: swtpm not installed");
        return;
    };
    let p = wait_provider(&fl.client).await;
    const SECRET: &str = "SECRET-PROMPT-7731";
    let err = fl.client.generate(&p.provider_id, &image_request(SECRET, 2), |_, _, _| {}).await.expect_err("leaky engine job succeeded");
    assert!(!err.to_string().contains(SECRET), "job error carried the prompt to the consumer: {err}");
    let (_, page) = get(&fl.base, "/").await;
    assert!(!String::from_utf8_lossy(&page).contains(SECRET), "dashboard shows the prompt");
    eprintln!("consumer saw: {err}");
    fl.shutdown.cancel();
}

/// The consumer's own credential-activation challenge (relayed by the
/// coordinator) succeeds for the provider's AK; a challenge for another AK
/// gets no secret and does not end the provider's session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consumer_activation() {
    let Some(fl) = start_flow(Duration::from_millis(500), Arc::new(Fake { delay: Duration::from_millis(5) })).await else {
        eprintln!("skipped: swtpm not installed");
        return;
    };
    let p = wait_provider(&fl.client).await;
    // verify() runs the consumer challenge (trust_enrollment is off).
    let ver = fl.client.verify(&p.provider_id).await.unwrap();
    let ek = db_tpmattest::parse_ek_public(&ver.bundle.evidence.ek_public).unwrap();
    let mut fake_name = vec![0x00, 0x0b];
    fake_name.extend_from_slice(&[0u8; 32]);
    fake_name[5] = 7;
    let ch = db_tpmattest::make_credential(&ek, &fake_name).unwrap();
    let body = wire::marshal(&wire::ActivateRequest { id_object: ch.id_object.clone(), enc_secret: ch.enc_secret.clone() }).unwrap();
    let rsp = http()
        .post(format!("{}/v1/providers/{}/activate", fl.base, p.provider_id))
        .header("Authorization", "Bearer consumer-key")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(rsp.status().as_u16(), 200);
    let out: wire::ActivateResponse = db_gojson::from_slice(&rsp.bytes().await.unwrap()).unwrap();
    assert_ne!(out.secret.as_slice(), ch.secret.as_slice(), "TPM answered a credential challenge for an AK it does not hold");
    // The provider is still serving.
    fl.client
        .generate(&p.provider_id, &image_request("x", 2), |_, _, _| {})
        .await
        .unwrap_or_else(|e| panic!("provider session did not survive a bad challenge: {e}"));
    // The trusted-enrollment path still works too.
    let mut trusting = fl.client.clone();
    trusting.trust_enrollment = true;
    trusting.verify(&p.provider_id).await.unwrap();
    fl.shutdown.cancel();
}

async fn post_generate(base: &str, path: &str, key: Option<&str>, body: &str, timeout: Duration) -> Result<(u16, String), reqwest::Error> {
    let mut req = http().post(format!("{base}{path}")).timeout(timeout).body(body.to_owned());
    if let Some(k) = key {
        req = req.header("Authorization", format!("Bearer {k}"));
    }
    let rsp = req.send().await?;
    let status = rsp.status().as_u16();
    Ok((status, rsp.text().await?))
}

/// Port of TestCoordinatorSealedAPI: the default API, where the trusted
/// coordinator seals the job to the attested provider (TPM-bound) and
/// returns the result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn coordinator_sealed_api() {
    let Some(fl) = start_flow(Duration::from_millis(500), Arc::new(Fake { delay: Duration::from_millis(5) })).await else {
        eprintln!("skipped: swtpm not installed");
        return;
    };
    let p = wait_provider(&fl.client).await;
    let mut req = image_request("SECRET-PROMPT-2 a fern", 3);
    req.workflow.clear();
    let res = fl.client.generate_simple(&req).await.unwrap();
    assert!(res.data.starts_with(b"\x89PNG"), "result is not a PNG");
    assert!(res.tpm_bound, "the job was not sealed to the TPM-bound key");
    assert_eq!(res.units.steps, 3);
    assert_eq!((res.provider_id.as_str(), res.tier.as_str(), res.mime.as_str()), (p.provider_id.as_str(), "dev-simulated", "image/png"));
    assert_eq!(res.release, p.release);
    eprintln!("coordinator-sealed job: {}-byte PNG from {} (tier {}) in {:?}", res.data.len(), res.provider_id, res.tier, res.elapsed);
    // Billed like any job; the coordinator keeps no ciphertext afterwards.
    let (status, body) = get(&fl.base, "/v1/ledger").await;
    assert_eq!(status, 200);
    let ledger: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(ledger.len(), 1, "{ledger:?}");
    let job_id = ledger[0]["job_id"].as_str().unwrap().to_owned();
    let (status, body) = get(&fl.base, &format!("/v1/jobs/{job_id}")).await;
    assert_eq!(status, 200);
    let st: wire::JobStatus = serde_json::from_slice(&body).unwrap();
    assert_eq!((st.state.as_str(), st.chunks), ("done", 0), "result kept after delivery");
    assert_eq!(get(&fl.base, &format!("/v1/jobs/{job_id}/result")).await.0, 200);
    fl.shutdown.cancel();
    let _ = fl.agent_done.await;
}

/// Requests the coordinator-sealed API must refuse.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn coordinator_sealed_api_refusals() {
    let Some(fl) = start_flow(Duration::from_millis(500), Arc::new(Fake { delay: Duration::from_millis(5) })).await else {
        eprintln!("skipped: swtpm not installed");
        return;
    };
    wait_provider(&fl.client).await;
    let t = Duration::from_secs(30);
    let images = "/v1/images/generations";
    let ok = r#"{"model":"fake-image","prompt":"x","size":"512x512","steps":2}"#;
    let cases: [(&str, Option<&str>, &str, u16, &str); 8] = [
        (images, None, ok, 401, "missing or unknown API key"),
        (images, Some("wrong-key"), ok, 401, "missing or unknown API key"),
        (images, Some("consumer-key"), r#"{"model":"fake-image","prompt":"x","sizes":"512x512"}"#, 400, "bad request"),
        (images, Some("consumer-key"), r#"{"model":"fake-image","prompt":"x","size":"512"}"#, 400, "size must be WIDTHxHEIGHT"),
        (images, Some("consumer-key"), r#"{"model":"no-such-model","prompt":"x"}"#, 503, "no attested provider"),
        (images, Some("consumer-key"), r#"{"model":"fake-image","prompt":"x","size":"9000x9000"}"#, 503, "no attested provider"),
        ("/v1/videos/generations", Some("consumer-key"), r#"{"model":"fake-image","prompt":"x"}"#, 503, "no attested provider"),
        (images, Some("consumer-key"), r#"{"model":"fake-image","prompt":"x","size":"512x512","steps":-1}"#, 400, "steps"),
    ];
    for (path, key, body, want, text) in cases {
        let (status, rsp) = post_generate(&fl.base, path, key, body, t).await.unwrap();
        assert_eq!(status, want, "{body}: {rsp}");
        assert!(rsp.contains(text), "{body}: {rsp}");
    }
    let big = format!(r#"{{"model":"fake-image","prompt":"{}"}}"#, "a".repeat(70 << 10));
    assert_eq!(post_generate(&fl.base, images, Some("consumer-key"), &big, t).await.unwrap().0, 400, "oversized body accepted");
    // Still serving afterwards.
    assert_eq!(post_generate(&fl.base, images, Some("consumer-key"), ok, t).await.unwrap().0, 200);
    fl.shutdown.cancel();
    let _ = fl.agent_done.await;
}

/// A consumer that gives up does not leave its job occupying the provider:
/// the coordinator cancels it, so the next job runs at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn abandoned_coordinator_sealed_job_is_cancelled() {
    let Some(fl) = start_flow(Duration::from_millis(500), Arc::new(Fake { delay: Duration::from_secs(1) })).await else {
        eprintln!("skipped: swtpm not installed");
        return;
    };
    wait_provider(&fl.client).await;
    let images = "/v1/images/generations";
    // 8 steps x 1 s: the consumer gives up after 1.5 s.
    let slow = r#"{"model":"fake-image","prompt":"slow","size":"512x512","steps":8}"#;
    let gave_up = post_generate(&fl.base, images, Some("consumer-key"), slow, Duration::from_millis(1500)).await;
    assert!(gave_up.is_err(), "{gave_up:?}");
    let start = std::time::Instant::now();
    let quick = r#"{"model":"fake-image","prompt":"quick","size":"512x512","steps":2}"#;
    let (status, rsp) = post_generate(&fl.base, images, Some("consumer-key"), quick, Duration::from_secs(30)).await.unwrap();
    assert_eq!(status, 200, "{rsp}");
    assert!(start.elapsed() < Duration::from_secs(6), "the abandoned job kept the GPU for {:?}", start.elapsed());
    fl.shutdown.cancel();
    let _ = fl.agent_done.await;
}

/// The coordinator serves HTTPS and WSS from a development certificate; the
/// agent (WSS) and the consumer (HTTPS) pin its CA. Both API paths work; a
/// consumer pinned to another CA, trusting only Mozilla's roots, or speaking
/// plain HTTP to the TLS port cannot connect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_coordinator_agent_and_consumer() {
    let tmp = tempfile::tempdir().unwrap();
    let (server, ca) = devcert(&tmp.path().join("tls"));
    let tls = Tls { server, agent: Arc::new(pinned(&ca)), client: pinned(&ca) };
    let Some(fl) =
        start_flow_with(Duration::from_millis(500), Arc::new(Fake { delay: Duration::from_millis(5) }), Some(tls), Logger::stderr("node "))
            .await
    else {
        eprintln!("skipped: swtpm not installed");
        return;
    };
    assert!(fl.base.starts_with("https://127.0.0.1:"), "{}", fl.base);
    // The agent enrolled and attests over WSS.
    let p = wait_provider(&fl.client).await;
    let mut req = image_request("SECRET-PROMPT-TLS a fern", 3);
    req.workflow.clear();
    let res = fl.client.generate_simple(&req).await.unwrap();
    assert!(res.data.starts_with(b"\x89PNG") && res.tpm_bound);
    let res = fl.client.generate(&p.provider_id, &image_request("SECRET-PROMPT-TLS e2e", 2), |_, _, _| {}).await.unwrap();
    assert!(res.data.starts_with(b"\x89PNG"));

    let (_, other_ca) = devcert(&tmp.path().join("other"));
    let wrong = db_client::Client::with_tls(&fl.base, "consumer-key", pinned(&other_ca)).unwrap();
    let err = wrong.providers().await.unwrap_err().to_string();
    assert!(err.contains("UnknownIssuer"), "a consumer pinned to another CA: {err}");
    let webpki = db_client::Client::new(&fl.base, "consumer-key").unwrap();
    let err = webpki.providers().await.unwrap_err().to_string();
    assert!(err.contains("UnknownIssuer"), "a consumer trusting Mozilla's roots: {err}");
    let plain = db_client::Client::new(&fl.base.replacen("https", "http", 1), "consumer-key").unwrap();
    assert!(plain.providers().await.is_err(), "plain HTTP answered on the TLS port");
    fl.shutdown.cancel();
    let _ = fl.agent_done.await;
}

/// An agent that pins another CA never reaches the coordinator: the TLS
/// handshake fails, so it neither enrolls nor attests.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_pinned_to_another_ca_cannot_connect() {
    let tmp = tempfile::tempdir().unwrap();
    let (server, ca) = devcert(&tmp.path().join("tls"));
    let (_, other_ca) = devcert(&tmp.path().join("other"));
    let (log, lines) = Logger::memory("node ");
    let tls = Tls { server, agent: Arc::new(pinned(&other_ca)), client: pinned(&ca) };
    let Some(fl) = start_flow_with(Duration::from_millis(300), Arc::new(Fake { delay: Duration::ZERO }), Some(tls), log).await else {
        eprintln!("skipped: swtpm not installed");
        return;
    };
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(fl.client.providers().await.unwrap().is_empty(), "an agent pinned to another CA enrolled");
    let logs = lines.lock().unwrap().join("\n");
    assert!(logs.contains("invalid peer certificate: UnknownIssuer"), "{logs}");
    assert!(!logs.contains("for account") && !logs.contains("lease granted"), "{logs}");
    fl.shutdown.cancel();
    let _ = fl.agent_done.await;
}

/// A recycling engine whose restart never completed: the job fails with the
/// fixed `engine_unavailable` code.
struct UnavailableEngine(Fake);

impl Engine for UnavailableEngine {
    fn name(&self) -> String {
        self.0.name()
    }
    fn workflows(&self) -> Vec<db_release::Artifact> {
        self.0.workflows()
    }
    fn models(&self) -> Vec<db_tpmattest::ModelReport> {
        self.0.models()
    }
    fn caps(&self) -> Vec<wire::ModelCap> {
        self.0.caps()
    }
    fn generate<'a>(
        &'a self,
        _req: &'a wire::JobRequest,
        _progress: Progress<'a>,
        _cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<Output, EngineError>> {
        Box::pin(async move { Err(EngineError::unavailable()) })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engine_unavailable_is_a_fixed_code() {
    let Some(fl) = start_flow(Duration::from_millis(500), Arc::new(UnavailableEngine(Fake { delay: Duration::ZERO }))).await else {
        eprintln!("skipped: swtpm not installed");
        return;
    };
    let p = wait_provider(&fl.client).await;
    let mut req = image_request("SECRET-PROMPT-8812", 2);
    req.workflow.clear();
    let err = fl.client.generate_simple(&req).await.unwrap_err().to_string();
    assert!(err.contains("job failed: provider: engine_unavailable"), "{err}");
    let err = fl.client.generate(&p.provider_id, &image_request("SECRET-PROMPT-8812", 2), |_, _, _| {}).await.unwrap_err().to_string();
    assert!(err.contains("provider: engine_unavailable") && !err.contains("SECRET"), "{err}");
    fl.shutdown.cancel();
    let _ = fl.agent_done.await;
}
