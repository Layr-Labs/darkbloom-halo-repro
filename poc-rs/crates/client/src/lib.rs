//! The consumer side. By default the trusted coordinator seals each job to
//! an attested provider and returns the result ([`Client::generate_simple`]).
//! As optional defense in depth, the consumer can instead verify a
//! provider's attestation itself (against AMD and Darkbloom-release roots it
//! pins, with its own nonce and credential-activation challenge), seal the
//! job end to end to the provider's attested keys and open the result
//! ([`Client::verify`], [`Client::generate`]); the coordinator then only
//! relays ciphertext.

#![forbid(unsafe_code)]

use db_gojson::GoTime;
use db_release::{Envelope, Manifest, Policy, TrustedKeys};
use db_sealbox::ResultKey;
use db_tpmattest::{DEFAULT_PCRS, Expect, Statement, Tier, TrustBundle, TrustedRelease, UKI_PCRS, Verdict, Verifier};
use db_wire as wire;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Client errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// HTTP transport or status failure.
    #[error("{0}")]
    Http(String),
    /// The provider failed independent verification (the verdict explains why).
    #[error("client: provider failed verification: {message}")]
    Verification {
        /// Failed checks, joined.
        message: String,
        /// The verdict, for display.
        verdict: Box<Verdict>,
    },
    /// Any other check failed.
    #[error("client: {0}")]
    Invalid(String),
}

/// Result alias.
pub type Result<T> = std::result::Result<T, Error>;

fn invalid(msg: impl Into<String>) -> Error {
    Error::Invalid(msg.into())
}

/// Talks to a coordinator.
#[derive(Debug, Clone)]
pub struct Client {
    /// Coordinator base URL (`https://host:port`, or `http://` over loopback
    /// or a tunnel).
    pub base_url: String,
    /// Consumer API key.
    pub api_key: String,
    /// HTTP client.
    pub http: reqwest::Client,
    /// Pinned endorsement roots.
    pub bundle: TrustBundle,
    /// Pinned release-signing keys.
    pub release_keys: TrustedKeys,
    /// Signatures required from `release_keys` (0 means 1).
    pub release_threshold: usize,
    /// Pinned release-log key.
    pub release_log_key: Option<VerifyingKey>,
    /// Pinned coordinator enrollment key.
    pub enrollment_key: Option<VerifyingKey>,
    /// Release security-version floor.
    pub min_svn: u32,
    /// Accept development tiers (dev-channel releases, dev roots); never for
    /// private data.
    pub allow_dev: bool,
    /// Accept the coordinator's signed enrollment record instead of running
    /// the consumer's own credential-activation challenge.
    pub trust_enrollment: bool,
}

/// A provider the consumer has verified itself.
#[derive(Debug, Clone)]
pub struct Verified {
    /// The bundle as received.
    pub bundle: wire::AttestationBundle,
    /// The consumer's own verdict.
    pub verdict: Verdict,
    /// The verified statement.
    pub statement: Statement,
    /// The verified release.
    pub manifest: Arc<Manifest>,
}

/// What the consumer asks for. The prompts are zeroized on drop and never
/// shown by `Debug`.
#[derive(Clone, Default)]
pub struct ImageRequest {
    /// Model.
    pub model: String,
    /// Workflow.
    pub workflow: String,
    /// Prompt (sealed end to end).
    pub prompt: Zeroizing<String>,
    /// Negative prompt.
    pub negative_prompt: Zeroizing<String>,
    /// Width.
    pub width: i64,
    /// Height.
    pub height: i64,
    /// Steps.
    pub steps: i64,
    /// Frames (video when > 0).
    pub frames: i64,
    /// Frames per second.
    pub fps: i64,
    /// Seed (0 = random).
    pub seed: i64,
}

/// A private text job. The client independently verifies the provider and
/// seals the prompt; development tiers are never eligible for this path.
#[derive(Clone, Default)]
pub struct TextRequest {
    /// Model identifier pinned by the approved release.
    pub model: String,
    /// Fixed workflow identifier pinned by the approved release.
    pub workflow: String,
    /// Prompt, wiped on drop and redacted from debug output.
    pub prompt: Zeroizing<String>,
    /// Maximum generated tokens, included in the authenticated job metadata.
    pub max_tokens: i64,
    /// Seed (0 chooses a fresh random seed).
    pub seed: i64,
}

impl std::fmt::Debug for TextRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TextRequest")
            .field("model", &self.model)
            .field("workflow", &self.workflow)
            .field("prompt", &wire::Redacted(self.prompt.len()))
            .field("max_tokens", &self.max_tokens)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ImageRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageRequest")
            .field("model", &self.model)
            .field("workflow", &self.workflow)
            .field("prompt", &wire::Redacted(self.prompt.len()))
            .field("negative_prompt", &wire::Redacted(self.negative_prompt.len()))
            .field("width", &self.width)
            .field("height", &self.height)
            .field("steps", &self.steps)
            .field("frames", &self.frames)
            .field("fps", &self.fps)
            .field("seed", &self.seed)
            .finish()
    }
}

/// A result from the coordinator-sealed API. The content is zeroized on drop
/// and never shown by `Debug`.
pub struct SimpleResult {
    /// Decrypted content.
    pub data: Zeroizing<Vec<u8>>,
    /// MIME type.
    pub mime: String,
    /// Provider that ran the job.
    pub provider_id: String,
    /// Its attested tier.
    pub tier: String,
    /// Its attested release.
    pub release: String,
    /// Whether decryption needed the provider TPM's PolicyPCR-gated ECDH.
    pub tpm_bound: bool,
    /// Billable units.
    pub units: wire::Units,
    /// Wall time.
    pub elapsed: Duration,
}

impl std::fmt::Debug for SimpleResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimpleResult")
            .field("data", &wire::Redacted(self.data.len()))
            .field("mime", &self.mime)
            .field("provider_id", &self.provider_id)
            .field("tier", &self.tier)
            .field("release", &self.release)
            .field("tpm_bound", &self.tpm_bound)
            .field("units", &self.units)
            .field("elapsed", &self.elapsed)
            .finish()
    }
}

/// A decrypted, receipt-checked result. The content is zeroized on drop and
/// never shown by `Debug`.
pub struct GenerateResult {
    /// Job ID.
    pub job_id: String,
    /// Decrypted content.
    pub data: Zeroizing<Vec<u8>>,
    /// MIME type from the receipt.
    pub mime: String,
    /// The verified receipt.
    pub receipt: wire::Receipt,
    /// The provider verification this job relied on.
    pub verified: Verified,
    /// Wall time.
    pub elapsed: Duration,
}

impl std::fmt::Debug for GenerateResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenerateResult")
            .field("job_id", &self.job_id)
            .field("data", &wire::Redacted(self.data.len()))
            .field("mime", &self.mime)
            .field("receipt", &self.receipt)
            .field("elapsed", &self.elapsed)
            .finish_non_exhaustive()
    }
}

/// An error with its causes (reqwest's `Display` omits them, e.g. why a TLS
/// handshake failed).
fn chain(e: &dyn std::error::Error) -> String {
    use std::fmt::Write as _;
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        let _ = write!(s, ": {c}");
        cur = c.source();
    }
    s
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| invalid(format!("random: {e}")))?;
    Ok(b)
}

enum Body {
    Json(Vec<u8>),
    None,
}

impl Client {
    /// A client with a 2-minute HTTP timeout and no pinned keys. An
    /// `https://` coordinator must present a certificate from Mozilla's root
    /// program (TLS 1.3 only); see [`Client::with_tls`] to pin a CA instead.
    pub fn new(base_url: &str, api_key: &str) -> Result<Self> {
        let tls = db_tls::client_config(&db_tls::Trust::WebPki).map_err(|e| Error::Http(e.to_string()))?;
        Self::with_tls(base_url, api_key, tls)
    }

    /// [`Client::new`] with this TLS configuration for `https://`
    /// coordinators (e.g. `db_tls::client_config_for(Some(ca_file))`: the
    /// pinned CA bundle is the only trust anchor).
    pub fn with_tls(base_url: &str, api_key: &str, tls: db_tls::rustls::ClientConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .tls_backend_preconfigured(tls)
            .build()
            .map_err(|e| Error::Http(e.to_string()))?;
        Ok(Self {
            base_url: base_url.to_owned(),
            api_key: api_key.to_owned(),
            http,
            bundle: TrustBundle::default(),
            release_keys: TrustedKeys::new(),
            release_threshold: 1,
            release_log_key: None,
            enrollment_key: None,
            min_svn: 1,
            allow_dev: false,
            trust_enrollment: false,
        })
    }

    async fn request(&self, method: reqwest::Method, path: &str, body: Body) -> Result<Vec<u8>> {
        self.request_timeout(method, path, body, None).await
    }

    async fn request_timeout(&self, method: reqwest::Method, path: &str, body: Body, timeout: Option<Duration>) -> Result<Vec<u8>> {
        let body = match body {
            Body::Json(b) => Some(Zeroizing::new(b)),
            Body::None => None,
        };
        self.exchange(method, path, body, timeout).await
    }

    /// One HTTP exchange. The request body (it can carry a prompt) is handed
    /// over without a copy and dropped, so zeroized, when the HTTP stack
    /// releases it, whatever the outcome.
    async fn exchange<O: AsRef<[u8]> + Send + 'static>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<O>,
        timeout: Option<Duration>,
    ) -> Result<Vec<u8>> {
        let url = format!("{}{}", self.base_url.trim_end_matches('/'), path);
        let mut req = self.http.request(method.clone(), &url).header("Authorization", format!("Bearer {}", self.api_key));
        if let Some(t) = timeout {
            req = req.timeout(t);
        }
        if let Some(owner) = body {
            req = req.header("Content-Type", "application/json").body(bytes::Bytes::from_owner(owner));
        }
        let rsp = req.send().await.map_err(|e| Error::Http(format!("{method} {path}: {}", chain(&e))))?;
        let status = rsp.status();
        let limit: u64 = 2 << 30;
        let mut out = Vec::new();
        let mut rsp = rsp;
        while let Some(chunk) = rsp.chunk().await.map_err(|e| Error::Http(format!("{method} {path}: {}", chain(&e))))? {
            if out.len() as u64 + chunk.len() as u64 > limit {
                return Err(Error::Http(format!("{method} {path}: response too large")));
            }
            out.extend_from_slice(&chunk);
        }
        if status.as_u16() >= 300 {
            let text = String::from_utf8_lossy(&out);
            return Err(Error::Http(format!("{method} {path}: {status}: {}", text.trim())));
        }
        Ok(out)
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let b = self.request(reqwest::Method::GET, path, Body::None).await?;
        db_gojson::from_slice(&b).map_err(|e| Error::Http(format!("GET {path}: {e}")))
    }

    /// The default API: the trusted coordinator seals the job to an
    /// attested provider (TPM-bound when offered), waits, and returns the
    /// result. Blocks for the whole job.
    pub async fn generate_simple(&self, r: &ImageRequest) -> Result<SimpleResult> {
        use base64::Engine as _;
        let start = Instant::now();
        let path = if r.frames > 0 { "/v1/videos/generations" } else { "/v1/images/generations" };
        let mut req = wire::GenerateRequest::default();
        req.model.clone_from(&r.model);
        req.prompt = String::clone(&r.prompt);
        req.negative_prompt = String::clone(&r.negative_prompt);
        req.size = format!("{}x{}", r.width, r.height);
        req.steps = r.steps;
        req.seed = r.seed;
        if r.frames > 0 {
            req.frames = r.frames;
            req.fps = r.fps;
        }
        let body = wire::marshal(&req).map_err(|e| invalid(e.to_string()))?;
        drop(req);
        // The coordinator waits up to 5 minutes for an image, 20 for a video.
        let raw =
            Zeroizing::new(self.request_timeout(reqwest::Method::POST, path, Body::Json(body), Some(Duration::from_secs(21 * 60))).await?);
        let rsp: wire::GenerateResponse = db_gojson::from_slice(&raw).map_err(|e| Error::Http(format!("POST {path}: {e}")))?;
        drop(raw);
        let [obj] = rsp.data.as_slice() else {
            return Err(invalid("no result"));
        };
        let data = Zeroizing::new(
            base64::engine::general_purpose::STANDARD.decode(&obj.b64_json).map_err(|e| invalid(format!("result encoding: {e}")))?,
        );
        let p = &rsp.provenance;
        Ok(SimpleResult {
            data,
            mime: obj.mime_type.clone(),
            provider_id: p.provider_id.clone(),
            tier: p.tier.clone(),
            release: p.release.clone(),
            tpm_bound: p.tpm_bound_decryption,
            units: p.units.clone(),
            elapsed: start.elapsed(),
        })
    }

    /// Fetches the coordinator's published keys.
    pub async fn info(&self) -> Result<wire::CoordinatorInfo> {
        self.get_json("/v1/coordinator").await
    }

    /// Lists leased providers.
    pub async fn providers(&self) -> Result<Vec<wire::ProviderInfo>> {
        let v: Option<Vec<wire::ProviderInfo>> = self.get_json("/v1/providers").await?;
        Ok(v.unwrap_or_default())
    }

    /// Asks the provider, through the coordinator, for a quote over a nonce
    /// the consumer chose, and verifies it independently.
    pub async fn verify(&self, provider_id: &str) -> Result<Verified> {
        let nonce = random::<32>()?;
        let path = format!("/v1/providers/{provider_id}/attestation?nonce={}", hex::encode(nonce));
        let b: wire::AttestationBundle = self.get_json(&path).await?;
        // Freshness: the quote must be over our nonce (evaluate checks the
        // quote's qualifying data against evidence.nonce).
        if b.evidence.nonce != nonce {
            return Err(invalid("evidence is not over this consumer's nonce"));
        }
        if b.provider_id != provider_id || db_tpmattest::provider_id_from_ek(&b.evidence.ek_public) != provider_id {
            return Err(invalid("bundle is for another provider"));
        }
        let ak = db_tpmattest::parse_attestation_key(&b.evidence.ak_public).map_err(|e| invalid(e.to_string()))?;
        // 1. The AK lives in the TPM that holds the AMD-certified EK.
        if self.trust_enrollment {
            // Shortcut: the coordinator's signed record of its own activation.
            let enrollment_key = self.enrollment_key.as_ref().ok_or_else(|| invalid("no pinned enrollment key"))?;
            let sig = ed25519_dalek::Signature::from_slice(&b.enrollment.sig)
                .map_err(|_| invalid("enrollment record is not signed by the pinned coordinator key"))?;
            if enrollment_key.verify_strict(&b.enrollment.payload, &sig).is_err() {
                return Err(invalid("enrollment record is not signed by the pinned coordinator key"));
            }
            // Strict: unknown fields and trailing data are rejected.
            let enr: wire::Enrollment = match db_gojson::from_slice::<wire::Enrollment>(&b.enrollment.payload) {
                Ok(e) if e.v == 1 => e,
                _ => return Err(invalid("enrollment record is malformed or of an unknown version")),
            };
            let ek_sum = hex::encode(Sha256::digest(&b.evidence.ek_public));
            if enr.provider_id != provider_id || enr.session_id != b.session_id || enr.ek_public_sha256 != ek_sum || enr.ak_name != ak.name
            {
                return Err(invalid("enrollment record does not match the evidence"));
            }
        } else {
            // Default: our own TPM2_MakeCredential challenge, which only the
            // provider's TPM can answer; the coordinator just relays it.
            self.activate(provider_id, &b.evidence, &ak).await?;
        }
        // 2. Release: logged (pinned log key) and signed (pinned release keys).
        let inclusion = b.release.as_ref().ok_or_else(|| invalid("bundle carries no release inclusion proof"))?;
        let log_key = self.release_log_key.as_ref().ok_or_else(|| invalid("no pinned release-log key"))?;
        inclusion.verify(log_key).map_err(|e| invalid(e.to_string()))?;
        let env: Envelope = db_gojson::from_slice(&inclusion.envelope).map_err(|e| invalid(format!("release envelope: {e}")))?;
        let policy = Policy {
            keys: self.release_keys.clone(),
            threshold: self.release_threshold.max(1),
            min_svn: self.min_svn,
            allow_dev: self.allow_dev,
            require_logged: true,
            ..Policy::default()
        };
        let manifest = Arc::new(policy.open(&env).map_err(|e| invalid(e.to_string()))?);
        let required_pcrs = if manifest.boot.path == "uki" { UKI_PCRS.to_vec() } else { DEFAULT_PCRS.to_vec() };
        // 3. Everything else, with the same verifier the coordinator runs.
        let vf = Verifier {
            bundle: self.bundle.clone(),
            releases: vec![TrustedRelease { manifest: manifest.clone(), envelope: inclusion.envelope.clone(), logged: true }],
            release_policy: Some(policy),
            allow_dev_roots: self.allow_dev,
            required_pcrs: required_pcrs.clone(),
            ..Verifier::default()
        };
        let ex = Expect { session_id: b.session_id.clone(), pcrs: required_pcrs, ak_activated: true, ..Expect::default() };
        let mut v = vf.evaluate(&b.evidence, &ex);
        if v.ok && matches!(v.tier, Tier::Attested | Tier::AttestedEncryptedMemory) && v.bound_key.is_none() {
            // Private data only goes where the TPM itself enforces decryption.
            v.ok = false;
            v.tier = Tier::Rejected;
            v.checks.push(db_tpmattest::Check {
                name: "tpm-bound-key".to_owned(),
                ok: false,
                effect: "required".to_owned(),
                detail: "production provider offers no TPM-bound key".to_owned(),
            });
        }
        if !v.ok {
            let why: Vec<String> = v.failed().iter().map(|c| format!("{}: {}", c.name, c.detail)).collect();
            return Err(Error::Verification { message: why.join("; "), verdict: Box::new(v) });
        }
        let statement = v.statement.clone().ok_or_else(|| invalid("verdict without a statement"))?;
        Ok(Verified { bundle: b, verdict: v, statement, manifest })
    }

    /// Runs the consumer's own credential-activation challenge.
    async fn activate(&self, provider_id: &str, ev: &db_tpmattest::Evidence, ak: &db_tpmattest::AttestationKey) -> Result<()> {
        let ek = db_tpmattest::parse_ek_public(&ev.ek_public).map_err(|e| invalid(e.to_string()))?;
        let ch = db_tpmattest::make_credential(&ek, &ak.name).map_err(|e| invalid(e.to_string()))?;
        let req = wire::ActivateRequest { id_object: ch.id_object.clone(), enc_secret: ch.enc_secret.clone() };
        let body = wire::marshal(&req).map_err(|e| invalid(e.to_string()))?;
        let raw = self.request(reqwest::Method::POST, &format!("/v1/providers/{provider_id}/activate"), Body::Json(body)).await?;
        let rsp: wire::ActivateResponse = db_gojson::from_slice(&raw).map_err(|e| invalid(format!("activation: {e}")))?;
        let ok =
            rsp.secret.len() == ch.secret.len() && bool::from(subtle::ConstantTimeEq::ct_eq(rsp.secret.as_slice(), ch.secret.as_slice()));
        if !ok {
            return Err(invalid("the provider's TPM did not answer our credential challenge (AK not bound to the EK)"));
        }
        Ok(())
    }

    /// Verifies the provider, seals the job to it, waits, checks the receipt
    /// and decrypts the result.
    pub async fn generate(&self, provider_id: &str, r: &ImageRequest, progress: impl FnMut(&str, i64, i64)) -> Result<GenerateResult> {
        let kind = if r.frames > 0 { "video" } else { "image" };
        self.generate_job(provider_id, r, kind, 0, progress).await
    }

    /// Run a text job with consumer-side attestation, TPM-bound sealing and
    /// receipt verification. `allow_dev` cannot lower this method's tier floor.
    pub async fn generate_text(&self, provider_id: &str, r: &TextRequest, progress: impl FnMut(&str, i64, i64)) -> Result<GenerateResult> {
        if !(1..=wire::MAX_TEXT_TOKENS).contains(&r.max_tokens) || r.prompt.is_empty() || r.prompt.len() > wire::MAX_PROMPT_BYTES {
            return Err(invalid("text prompt or token limit out of range"));
        }
        let request = ImageRequest {
            model: r.model.clone(),
            workflow: r.workflow.clone(),
            prompt: r.prompt.clone(),
            seed: r.seed,
            ..ImageRequest::default()
        };
        self.generate_job(provider_id, &request, "text", r.max_tokens, progress).await
    }

    async fn generate_job(
        &self,
        provider_id: &str,
        r: &ImageRequest,
        kind: &str,
        max_tokens: i64,
        mut progress: impl FnMut(&str, i64, i64),
    ) -> Result<GenerateResult> {
        let start = Instant::now();
        let ver = self.verify(provider_id).await?;
        if kind == "text" {
            if !matches!(ver.verdict.tier, Tier::Attested | Tier::AttestedEncryptedMemory) || ver.verdict.bound_key.is_none() {
                return Err(invalid("private text requires an approved boot and a TPM-bound job key"));
            }
            if !ver.statement.runtime.models.iter().any(|m| m.id == r.model)
                || !ver.statement.runtime.workflows.iter().any(|w| w.name == r.workflow)
            {
                return Err(invalid("text model or workflow is absent from the attested statement"));
            }
        }
        let st = &ver.statement;
        let seed = if r.seed == 0 { i64::from(u32::from_le_bytes(random::<4>()?) & 0x7fff_ffff) } else { r.seed };
        let job_id = format!("job-{}", hex::encode(random::<12>()?));
        let meta = wire::JobMeta {
            v: 1,
            job_id: job_id.clone(),
            provider_id: provider_id.to_owned(),
            session_id: st.session_id.clone(),
            model: r.model.clone(),
            workflow: r.workflow.clone(),
            kind: kind.to_owned(),
            width: r.width,
            height: r.height,
            steps: r.steps,
            frames: r.frames,
            fps: r.fps,
            max_tokens,
            created_at: GoTime::now_utc().truncate_secs(),
        };
        let meta_bytes = wire::marshal(&meta).map_err(|e| invalid(e.to_string()))?;
        let mut req = wire::JobRequest::default();
        req.v = 1;
        req.job_id.clone_from(&job_id);
        req.model.clone_from(&r.model);
        req.workflow.clone_from(&r.workflow);
        req.prompt = String::clone(&r.prompt);
        req.negative_prompt = String::clone(&r.negative_prompt);
        req.seed = seed;
        req.width = r.width;
        req.height = r.height;
        req.steps = r.steps;
        req.frames = r.frames;
        req.fps = r.fps;
        req.max_tokens = max_tokens;
        req.check_against(&meta).map_err(|e| invalid(e.to_string()))?;
        // Padded to a size bucket so the ciphertext hides the prompt length.
        let plain = wire::pad_request(&mut req).map_err(|e| invalid(e.to_string()))?;
        drop(req);
        let info = db_sealbox::info(provider_id, &st.session_id);
        let sealed_result = match &ver.verdict.bound_key {
            // TPM-enforced: only the attested boot can complete the ECDH.
            Some(bound) => db_sealbox::seal_request_bound(&st.job_kem, &st.job_public_key, bound, &info, &meta_bytes, &plain),
            None => db_sealbox::seal_request(&st.job_kem, &st.job_public_key, &info, &meta_bytes, &plain),
        };
        let (sealed, result_key): (db_sealbox::Sealed, ResultKey) = sealed_result.map_err(|e| invalid(e.to_string()))?;
        drop(plain);
        let submit = wire::SubmitJob { provider_id: provider_id.to_owned(), meta: meta_bytes.clone(), sealed: sealed.clone() };
        let body = wire::marshal(&submit).map_err(|e| invalid(e.to_string()))?;
        self.request(reqwest::Method::POST, "/v1/jobs", Body::Json(body)).await?;
        let status = loop {
            let s: wire::JobStatus = self.get_json(&format!("/v1/jobs/{job_id}")).await?;
            progress(&s.state, s.step, s.total);
            if s.state == "done" || s.state == "error" {
                break s;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        };
        if status.state == "error" {
            return Err(invalid(format!("job failed: {}", status.error)));
        }
        let raw = self.request(reqwest::Method::GET, &format!("/v1/jobs/{job_id}/result"), Body::None).await?;
        let chunks = split_result_stream(&raw)?;
        // The receipt must be signed by the attested receipt key and describe
        // exactly this job and these ciphertext bytes.
        let receipt_key: [u8; 32] =
            st.receipt_public_key.as_slice().try_into().map_err(|_| invalid("attested receipt key is not 32 bytes"))?;
        let receipt_key = VerifyingKey::from_bytes(&receipt_key).map_err(|_| invalid("attested receipt key is invalid"))?;
        let sig = ed25519_dalek::Signature::from_slice(&status.receipt_sig)
            .map_err(|_| invalid("receipt is not signed by the attested provider"))?;
        if receipt_key.verify_strict(&status.receipt, &sig).is_err() {
            return Err(invalid("receipt is not signed by the attested provider"));
        }
        let rc: wire::Receipt = db_gojson::from_slice(&status.receipt).map_err(|e| invalid(format!("receipt: {e}")))?;
        let meta_sum = hex::encode(Sha256::digest(&meta_bytes));
        if rc.job_id != job_id
            || rc.provider_id != provider_id
            || rc.session_id != st.session_id
            || rc.meta_sha256 != meta_sum
            || rc.request_sha256 != wire::request_digest(&sealed)
            || rc.result_sha256 != wire::result_digest(&chunks)
            || rc.release != ver.verdict.release
            || rc.v != 1
            || rc.result_bytes != wire::result_bytes(&chunks)
            || rc.units.steps != r.steps
            || (kind == "text" && (rc.units.completion_tokens < 0 || rc.units.completion_tokens > max_tokens || rc.units.prompt_tokens < 0))
        {
            return Err(invalid("receipt does not match this job"));
        }
        let data = db_sealbox::open_result(&result_key, &job_id, &chunks).map_err(|e| invalid(e.to_string()))?;
        if kind == "text" && (rc.result_mime != "text/plain; charset=utf-8" || data.len() > 1 << 20 || std::str::from_utf8(&data).is_err())
        {
            return Err(invalid("invalid text result type or size"));
        }
        Ok(GenerateResult { job_id, data, mime: rc.result_mime.clone(), receipt: rc, verified: ver, elapsed: start.elapsed() })
    }
}

/// Splits the coordinator's result stream (4-byte big-endian length +
/// chunk, repeated). Chunks are never empty, and there are at most as many
/// as the largest result needs.
pub fn split_result_stream(mut raw: &[u8]) -> Result<Vec<Vec<u8>>> {
    let max_chunks = db_sealbox::MAX_RESULT_BYTES / db_sealbox::CHUNK_SIZE + 2;
    let mut chunks = Vec::new();
    while !raw.is_empty() {
        let (len, rest) = raw.split_first_chunk::<4>().ok_or_else(|| invalid("truncated result stream"))?;
        let n = u32::from_be_bytes(*len) as usize;
        if n == 0 || n > rest.len() || chunks.len() >= max_chunks {
            return Err(invalid("malformed result stream"));
        }
        let (chunk, tail) = rest.split_at(n);
        chunks.push(chunk.to_vec());
        raw = tail;
    }
    Ok(chunks)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// A one-route HTTP/1.1 responder: reads each request fully, answers `{}`.
    async fn tiny_server() -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    loop {
                        let n = sock.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
                        let headers = String::from_utf8_lossy(&buf[..end]).to_lowercase();
                        let len: usize = headers
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                        if buf.len() >= end + 4 + len {
                            break;
                        }
                    }
                    let _ = sock.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\ncontent-type: application/json\r\n\r\n{}").await;
                });
            }
        });
        addr
    }

    /// A request body that records when the HTTP stack drops it (in
    /// production the owner is `Zeroizing`, so that drop wipes the prompt).
    struct Tracked(Zeroizing<Vec<u8>>, Arc<std::sync::atomic::AtomicBool>);

    impl AsRef<[u8]> for Tracked {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl Drop for Tracked {
        fn drop(&mut self) {
            self.1.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// The request body (for the coordinator-sealed API it carries the
    /// prompt) is released, and so wiped, by the time the exchange is over,
    /// on success and on failure.
    #[tokio::test]
    async fn request_bodies_are_wiped_after_the_exchange() {
        let addr = tiny_server().await;
        let cl = Client::new(&format!("http://{addr}"), "k").unwrap();
        let dead = Client::new("http://127.0.0.1:9", "k").unwrap();
        for (cl, ok) in [(&cl, true), (&cl, true), (&dead, false)] {
            let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let body = Tracked(Zeroizing::new(br#"{"model":"m","prompt":"SECRET-PROMPT"}"#.to_vec()), dropped.clone());
            let out = cl.exchange(reqwest::Method::POST, "/v1/images/generations", Some(body), None).await;
            assert_eq!(out.is_ok(), ok, "{out:?}");
            assert!(dropped.load(std::sync::atomic::Ordering::SeqCst), "request body still held after the exchange (ok={ok})");
        }
    }

    #[test]
    fn debug_output_redacts_prompts_and_results() {
        let r = ImageRequest {
            prompt: Zeroizing::new("SECRET-PROMPT".to_owned()),
            negative_prompt: Zeroizing::new("SECRET-NEG".to_owned()),
            ..Default::default()
        };
        let res = SimpleResult {
            data: Zeroizing::new(b"SECRET-IMAGE".to_vec()),
            mime: "image/png".to_owned(),
            provider_id: String::new(),
            tier: String::new(),
            release: String::new(),
            tpm_bound: true,
            units: wire::Units::default(),
            elapsed: Duration::ZERO,
        };
        let text = TextRequest { prompt: Zeroizing::new("SECRET-TEXT-PROMPT".to_owned()), ..Default::default() };
        for out in [format!("{r:?}"), format!("{res:?}"), format!("{text:?}")] {
            assert!(!out.contains("SECRET"), "{out}");
        }
    }

    #[test]
    fn result_stream_framing() {
        let raw = [0, 0, 0, 2, b'a', b'b', 0, 0, 0, 1, b'c'];
        assert_eq!(split_result_stream(&raw).unwrap(), vec![b"ab".to_vec(), b"c".to_vec()]);
        assert!(split_result_stream(&[0, 0, 0]).unwrap_err().to_string().contains("truncated result stream"));
        assert!(split_result_stream(&[0, 0, 0, 5, 1]).unwrap_err().to_string().contains("malformed result stream"));
        assert!(split_result_stream(&[]).unwrap().is_empty());
        // Go: zero-length chunks are malformed.
        let empty = [0, 0, 0, 2, b'a', b'b', 0, 0, 0, 0, 0, 0, 0, 1, b'c'];
        assert!(split_result_stream(&empty).unwrap_err().to_string().contains("malformed result stream"));
    }

    #[test]
    fn result_stream_chunk_count_is_bounded() {
        let max = db_sealbox::MAX_RESULT_BYTES / db_sealbox::CHUNK_SIZE + 2;
        let one = [0u8, 0, 0, 1, 7];
        assert_eq!(split_result_stream(&one.repeat(max)).unwrap().len(), max);
        let err = split_result_stream(&one.repeat(max + 1)).unwrap_err().to_string();
        assert!(err.contains("malformed result stream"), "{err}");
    }
}
