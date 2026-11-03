//! Coordinator HTTP and WebSocket behaviour that needs no TPM. Full provider
//! flows on swtpm are in the e2e and cli crates.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use db_coord::{Config, Server};
use db_log::Logger;
use db_tpmattest::{Tier, Verifier};
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt as _, StreamExt as _};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

/// A plain-HTTP client (reqwest's default TLS backend needs a process-wide
/// provider, as the binaries install one).
fn http() -> reqwest::Client {
    db_tls::install_default_provider();
    reqwest::Client::new()
}

fn config() -> Config {
    let log_key = SigningKey::from_bytes(&[7u8; 32]);
    Config {
        verifier: Verifier {
            release_policy: Some(db_release::Policy { min_svn: 3, allow_dev: true, ..Default::default() }),
            ..Default::default()
        },
        enrollment_key: SigningKey::from_bytes(&[9u8; 32]),
        release_log: Arc::new(db_release::Log::new(log_key.clone())),
        release_log_key: log_key.verifying_key(),
        release_keys: Default::default(),
        provider_tokens: BTreeMap::from([("tok".to_owned(), "acct".to_owned())]),
        consumer_keys: BTreeSet::from(["ck".to_owned()]),
        challenge_interval: Duration::from_secs(1),
        lease_ttl: Duration::ZERO,
        min_tier: Some(Tier::DevSimulated),
        max_result_bytes: 0,
        capture_attestation: None,
        logger: Logger::discard(),
    }
}

async fn start() -> (String, Arc<Server>) {
    let server = Server::new(config()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(db_coord::serve(listener, server.clone()));
    (format!("127.0.0.1:{addr}", addr = addr.port()), server)
}

/// A coordinator serving HTTPS/WSS with a development certificate in `dir`;
/// returns its address and the CA to pin.
async fn start_tls(dir: &Path) -> (String, PathBuf) {
    db_tls::devcert::write(dir, &["127.0.0.1", "localhost"]).unwrap();
    let tls = db_tls::server_config(&dir.join("server.pem"), &dir.join("server.key")).unwrap();
    let server = Server::new(config()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(db_coord::serve_tls(listener, server, Arc::new(tls)));
    (format!("127.0.0.1:{}", addr.port()), dir.join("ca.pem"))
}

fn pinned_http(ca: &Path) -> reqwest::Client {
    reqwest::Client::builder().tls_backend_preconfigured(db_tls::client_config_for(Some(ca)).unwrap()).build().unwrap()
}

/// An error with its causes (reqwest's `Display` omits them).
fn chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        s.push_str(&format!(": {c}"));
        cur = c.source();
    }
    s
}

async fn get(addr: &str, path: &str, key: Option<&str>) -> (u16, String) {
    let mut req = http().get(format!("http://{addr}{path}"));
    if let Some(k) = key {
        req = req.header("Authorization", format!("Bearer {k}"));
    }
    let rsp = req.send().await.unwrap();
    let code = rsp.status().as_u16();
    (code, rsp.text().await.unwrap())
}

async fn post(addr: &str, path: &str, body: Vec<u8>) -> (u16, String) {
    let rsp = http().post(format!("http://{addr}{path}")).header("Authorization", "Bearer ck").body(body).send().await.unwrap();
    let code = rsp.status().as_u16();
    (code, rsp.text().await.unwrap())
}

#[tokio::test]
async fn consumer_api_shapes_and_auth() {
    let (addr, _s) = start().await;
    assert_eq!(get(&addr, "/v1/providers", None).await, (401, "{\"error\":\"missing or unknown API key\"}\n".to_owned()));
    assert_eq!(get(&addr, "/v1/providers", Some("wrong")).await.0, 401);
    // Go trims only a literal "Bearer " prefix: the bare key also works.
    let rsp = http().get(format!("http://{addr}/v1/ledger")).header("Authorization", "ck").send().await.unwrap();
    assert_eq!(rsp.status().as_u16(), 200);
    assert_eq!(get(&addr, "/v1/providers", Some("ck")).await, (200, "null\n".to_owned()));
    assert_eq!(get(&addr, "/v1/ledger", Some("ck")).await, (200, "[]\n".to_owned()));
    assert_eq!(get(&addr, "/v1/releases", None).await, (200, "null\n".to_owned()));
    let (code, info) = get(&addr, "/v1/coordinator", None).await;
    assert_eq!(code, 200);
    let v: serde_json::Value = serde_json::from_str(&info).unwrap();
    assert_eq!(v["min_svn"], 3);
    assert_eq!(v["allow_dev"], true);
    assert!(v["enrollment_key"].as_str().unwrap().len() == 44);
    assert_eq!(v["release_keys"], serde_json::json!({}));
    assert_eq!(get(&addr, "/v1/jobs/nope", Some("ck")).await.0, 404);
    assert_eq!(get(&addr, "/v1/jobs/nope/result", Some("ck")).await.0, 404);
    let (code, body) = get(&addr, "/v1/providers/abc/attestation?nonce=zz", Some("ck")).await;
    assert_eq!((code, body.as_str()), (400, "{\"error\":\"nonce must be 32 bytes of hex\"}\n"));
    assert_eq!(get(&addr, "/v1/providers/abc/attestation", Some("ck")).await.0, 404);
    // Wrong method.
    let rsp = http().delete(format!("http://{addr}/v1/ledger")).send().await.unwrap();
    assert_eq!(rsp.status().as_u16(), 405);
    let (code, page) = get(&addr, "/", None).await;
    assert_eq!(code, 200);
    assert!(page.contains("No providers connected."));
}

#[tokio::test]
async fn submit_validation() {
    let (addr, _s) = start().await;
    let meta = br#"{"v":1,"job_id":"j1","provider_id":"p","session_id":"s","model":"m","workflow":"w","kind":"image","width":512,"height":512,"steps":4,"created_at":"2026-11-02T00:00:00Z"}"#;
    let b64 = |b: &[u8]| {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(b)
    };
    let ok_body = format!(r#"{{"provider_id":"p","meta":"{}","sealed":{{"enc":"","ciphertext":""}}}}"#, b64(meta));
    let (code, body) = post(&addr, "/v1/jobs", ok_body.into_bytes()).await;
    assert_eq!((code, body.as_str()), (404, "{\"error\":\"unknown provider\"}\n"));
    let text_meta = br#"{"v":1,"job_id":"t1","provider_id":"p","session_id":"s","model":"m","workflow":"w","kind":"text","max_tokens":16,"created_at":"2026-11-02T00:00:00Z"}"#;
    let unbound_text = format!(r#"{{"provider_id":"p","meta":"{}","sealed":{{"enc":"","ciphertext":""}}}}"#, b64(text_meta));
    let (code, body) = post(&addr, "/v1/jobs", unbound_text.into_bytes()).await;
    assert_eq!((code, body.as_str()), (400, "{\"error\":\"text requests require TPM-bound sealing\"}\n"));
    let (code, body) = post(&addr, "/v1/jobs", br#"{"provider_id":"p","extra":1}"#.to_vec()).await;
    assert_eq!(code, 400);
    assert!(body.contains("bad request"), "{body}");
    let bad_meta = format!(r#"{{"provider_id":"p","meta":"{}"}}"#, b64(br#"{"v":1,"unknown":true}"#));
    let (code, body) = post(&addr, "/v1/jobs", bad_meta.into_bytes()).await;
    assert_eq!(code, 400);
    assert!(body.contains("bad job metadata"), "{body}");
    let small = format!(r#"{{"provider_id":"p","meta":"{}"}}"#, b64(&String::from_utf8_lossy(meta).replace("512", "100").into_bytes()));
    let (code, body) = post(&addr, "/v1/jobs", small.into_bytes()).await;
    assert_eq!(code, 400);
    assert!(body.contains("out of range"), "{body}");
    // Over the body cap: the server answers 400 and stops reading (the
    // client may see the connection reset while still sending).
    let huge = format!(r#"{{"provider_id":"p","meta":"{}","sealed":{{"ciphertext":"{}"}}}}"#, b64(meta), "A".repeat(30 << 20));
    let rsp = http().post(format!("http://{addr}/v1/jobs")).header("Authorization", "Bearer ck").body(huge).send().await;
    if let Ok(r) = rsp {
        assert_eq!(r.status().as_u16(), 400, "oversized body accepted");
    }
    let big_ct = format!(
        r#"{{"provider_id":"p","meta":"{}","sealed":{{"ciphertext":"{}"}}}}"#,
        b64(meta),
        b64(&vec![0u8; (16 << 20) + 2 * 8192 + 4096 + 1])
    );
    let (code, body) = post(&addr, "/v1/jobs", big_ct.into_bytes()).await;
    assert_eq!((code, body.as_str()), (413, "{\"error\":\"sealed request too large\"}\n"));
}

#[tokio::test]
async fn text_completion_validates_before_routing() {
    let (addr, _s) = start().await;
    let (code, body) = post(&addr, "/v1/completions", br#"{"model":"m","prompt":"PRIVATE-CANARY","max_tokens":0}"#.to_vec()).await;
    assert_eq!(code, 400);
    assert!(body.contains("max_tokens"));
    assert!(!body.contains("PRIVATE-CANARY"));
    let (code, body) = post(&addr, "/v1/completions", br#"{"model":"m","prompt":"PRIVATE-CANARY","max_tokens":16}"#.to_vec()).await;
    assert_eq!(code, 503);
    assert!(body.contains("no attested text provider"));
    assert!(!body.contains("PRIVATE-CANARY"));
}

async fn ws_reject(addr: &str, hello: serde_json::Value) -> String {
    let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/v1/provider/ws")).await.unwrap();
    ws_reject_on(ws, hello).await
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn ws_reject_on(mut ws: Ws, hello: serde_json::Value) -> String {
    ws.send(Message::text(hello.to_string())).await.unwrap();
    let mut error = String::new();
    let mut closed = None;
    while let Some(Ok(m)) = ws.next().await {
        match m {
            Message::Text(t) => {
                let v: serde_json::Value = serde_json::from_str(&t).unwrap();
                assert_eq!(v["type"], "error");
                error = v["message"].as_str().unwrap().to_owned();
            }
            Message::Close(f) => {
                closed = f.map(|f| u16::from(f.code));
                break;
            }
            _ => {}
        }
    }
    assert_eq!(closed, Some(1008), "not closed with policy violation");
    error
}

#[tokio::test]
async fn provider_enrollment_rejections() {
    let (addr, _s) = start().await;
    let e = ws_reject(&addr, serde_json::json!({"type":"hello","protocol":"darkbloom-amd/provider/v9","account_token":"tok"})).await;
    assert_eq!(e, "unsupported protocol \"darkbloom-amd/provider/v9\"");
    let e = ws_reject(&addr, serde_json::json!({"type":"hello","protocol":"darkbloom-amd/provider/v0","account_token":"nope"})).await;
    assert_eq!(e, "unknown account token (pair the machine first)");
    let e = ws_reject(
        &addr,
        serde_json::json!({"type":"hello","protocol":"darkbloom-amd/provider/v0","account_token":"tok","ek_public":"AAAA"}),
    )
    .await;
    assert!(e.contains("EK public area"), "{e}");
    let e = ws_reject(&addr, serde_json::json!({"type":"attestation"})).await;
    assert_eq!(e, "hello: expected hello");
}

/// With a certificate the coordinator serves HTTPS and WSS (TLS 1.3) to
/// clients that pin its CA, and nothing to clients pinned to another CA or
/// speaking plain HTTP/WS to the TLS port.
#[tokio::test]
async fn tls_serves_https_and_wss() {
    let tmp = tempfile::tempdir().unwrap();
    let (addr, ca) = start_tls(&tmp.path().join("tls")).await;
    let client = pinned_http(&ca);
    for host in [addr.clone(), addr.replace("127.0.0.1", "localhost")] {
        let rsp = client.get(format!("https://{host}/v1/coordinator")).send().await.unwrap();
        assert_eq!(rsp.status().as_u16(), 200, "{host}");
        assert_eq!(rsp.version(), reqwest::Version::HTTP_11);
    }
    let rsp = client.get(format!("https://{addr}/v1/providers")).header("Authorization", "Bearer ck").send().await.unwrap();
    assert_eq!((rsp.status().as_u16(), rsp.text().await.unwrap()), (200, "null\n".to_owned()));

    db_tls::devcert::write(&tmp.path().join("other"), &["127.0.0.1"]).unwrap();
    let wrong = pinned_http(&tmp.path().join("other/ca.pem"));
    let err = wrong.get(format!("https://{addr}/v1/coordinator")).send().await.unwrap_err();
    assert!(chain(&err).contains("UnknownIssuer"), "{}", chain(&err));
    assert!(http().get(format!("http://{addr}/v1/coordinator")).send().await.is_err(), "plain HTTP answered on the TLS port");

    // The provider WebSocket over TLS: the enrollment rejections work as on
    // plain WS.
    let tls = Arc::new(db_tls::client_config_for(Some(&ca)).unwrap());
    let connector = tokio_tungstenite::Connector::Rustls(tls);
    let url = format!("wss://{addr}/v1/provider/ws");
    let (ws, _) = tokio_tungstenite::connect_async_tls_with_config(url.as_str(), None, false, Some(connector)).await.unwrap();
    let e = ws_reject_on(ws, serde_json::json!({"type":"hello","protocol":"darkbloom-amd/provider/v0","account_token":"nope"})).await;
    assert_eq!(e, "unknown account token (pair the machine first)");
    let wrong = tokio_tungstenite::Connector::Rustls(Arc::new(db_tls::client_config_for(Some(&tmp.path().join("other/ca.pem"))).unwrap()));
    let err = tokio_tungstenite::connect_async_tls_with_config(url.as_str(), None, false, Some(wrong)).await.unwrap_err();
    assert!(err.to_string().contains("UnknownIssuer"), "{err}");
    assert!(tokio_tungstenite::connect_async(format!("ws://{addr}/v1/provider/ws")).await.is_err(), "plain WS answered on the TLS port");
}
