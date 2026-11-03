//! The protocol between provider agents, the coordinator and consumers.
//!
//! Provider <-> coordinator: JSON text frames over an outbound WebSocket
//! from the provider (no inbound ports on the provider; NAT friendly).
//! Consumer <-> coordinator: HTTP JSON plus a binary result stream.

#![forbid(unsafe_code)]

use db_gojson::GoTime;
use db_release::Inclusion;
use db_sealbox::Sealed;
use db_tpmattest::{Check, Evidence, Tier, Verdict};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// The provider protocol version.
pub const PROTOCOL: &str = "darkbloom-amd/provider/v0";

/// Message types.
pub mod msg {
    // provider -> coordinator
    /// [`super::Hello`].
    pub const HELLO: &str = "hello";
    /// [`super::CredentialResponse`].
    pub const CREDENTIAL_RESPONSE: &str = "credential_response";
    /// [`super::Attestation`].
    pub const ATTESTATION: &str = "attestation";
    /// [`super::JobAccepted`].
    pub const JOB_ACCEPTED: &str = "job_accepted";
    /// [`super::JobProgress`].
    pub const JOB_PROGRESS: &str = "job_progress";
    /// [`super::JobChunk`].
    pub const JOB_CHUNK: &str = "job_chunk";
    /// [`super::JobDone`].
    pub const JOB_DONE: &str = "job_done";
    /// [`super::JobError`].
    pub const JOB_ERROR: &str = "job_error";
    // coordinator -> provider
    /// [`super::Welcome`].
    pub const WELCOME: &str = "welcome";
    /// [`super::CredentialChallenge`].
    pub const CREDENTIAL_CHALLENGE: &str = "credential_challenge";
    /// [`super::AttestChallenge`].
    pub const ATTEST_CHALLENGE: &str = "attest_challenge";
    /// [`super::Lease`].
    pub const LEASE: &str = "lease";
    /// [`super::Job`].
    pub const JOB: &str = "job";
    /// [`super::JobCancel`].
    pub const JOB_CANCEL: &str = "job_cancel";
    /// [`super::ErrorMsg`].
    pub const ERROR: &str = "error";
}

/// Encodes a frame or API body exactly like Go's `json.Marshal`.
pub fn marshal<T: Serialize + ?Sized>(v: &T) -> Result<Vec<u8>, serde_json::Error> {
    db_gojson::to_vec(v)
}

/// Peeks at a frame's type (unknown fields allowed).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Typed {
    /// Message type.
    #[serde(rename = "type")]
    pub msg_type: String,
}

/// Peeks at a job frame's job ID (unknown fields allowed).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct JobHead {
    /// Job ID.
    pub job_id: String,
}

/// A model a provider serves.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ModelCap {
    /// Model ID.
    pub id: String,
    /// `"image"` or `"video"`.
    pub kind: String,
    /// Workflows.
    #[serde(with = "db_gojson::nil_vec")]
    pub workflows: Vec<String>,
    /// Max width.
    pub max_width: i64,
    /// Max height.
    pub max_height: i64,
    /// Max steps.
    pub max_steps: i64,
    /// Max frames (video).
    #[serde(skip_serializing_if = "db_gojson::is_zero_i64")]
    pub max_frames: i64,
    /// Maximum generated tokens for text models (zero for media models).
    #[serde(skip_serializing_if = "db_gojson::is_zero_i64")]
    pub max_tokens: i64,
}

/// The provider's first frame.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Hello {
    /// [`msg::HELLO`].
    #[serde(rename = "type")]
    pub msg_type: String,
    /// [`PROTOCOL`].
    pub protocol: String,
    /// Pairing token.
    pub account_token: String,
    /// Agent version.
    pub agent_version: String,
    /// `"hardware"` or `"swtpm"`.
    pub tpm_mode: String,
    /// EK TPMT_PUBLIC.
    #[serde(with = "db_gojson::b64")]
    pub ek_public: Vec<u8>,
    /// EK certificate.
    #[serde(with = "db_gojson::b64")]
    pub ek_cert: Vec<u8>,
    /// On-chip ICAs.
    #[serde(with = "db_gojson::b64_list")]
    pub ek_icas: Vec<Vec<u8>>,
    /// AK TPMT_PUBLIC.
    #[serde(with = "db_gojson::b64")]
    pub ak_public: Vec<u8>,
    /// Models served.
    #[serde(with = "db_gojson::nil_vec")]
    pub models: Vec<ModelCap>,
    /// GPU target.
    pub gpu: String,
}

/// Binds the connection to an account and a session.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Welcome {
    /// [`msg::WELCOME`].
    #[serde(rename = "type")]
    pub msg_type: String,
    /// Session.
    pub session_id: String,
    /// Account.
    pub account_id: String,
    /// Provider ID (from the EK).
    pub provider_id: String,
    /// Challenge interval (s).
    #[serde(rename = "challenge_interval_s")]
    pub challenge_interval: i64,
    /// Lease TTL (s).
    #[serde(rename = "lease_ttl_s")]
    pub lease_ttl: i64,
}

/// TPM2_MakeCredential output for the provider's AK. `request_id` is set
/// when a consumer made the challenge (relayed by the coordinator, which
/// cannot answer it because it lacks the EK).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CredentialChallenge {
    /// [`msg::CREDENTIAL_CHALLENGE`].
    #[serde(rename = "type")]
    pub msg_type: String,
    /// Consumer request this challenge belongs to.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub request_id: String,
    /// TPM2B_ID_OBJECT contents.
    #[serde(with = "db_gojson::b64")]
    pub id_object: Vec<u8>,
    /// TPM2B_ENCRYPTED_SECRET contents.
    #[serde(with = "db_gojson::b64")]
    pub enc_secret: Vec<u8>,
}

/// Returns the activated secret.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CredentialResponse {
    /// [`msg::CREDENTIAL_RESPONSE`].
    #[serde(rename = "type")]
    pub msg_type: String,
    /// The consumer request being answered.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub request_id: String,
    /// Recovered secret (zeroized on drop).
    #[serde(with = "db_gojson::b64_zeroizing")]
    pub secret: Zeroizing<Vec<u8>>,
}

/// A consumer's own credential-activation challenge
/// (`POST /v1/providers/{id}/activate`). Decoded strictly.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ActivateRequest {
    /// TPM2B_ID_OBJECT contents.
    #[serde(with = "db_gojson::b64")]
    pub id_object: Vec<u8>,
    /// TPM2B_ENCRYPTED_SECRET contents.
    #[serde(with = "db_gojson::b64")]
    pub enc_secret: Vec<u8>,
}

/// The provider TPM's answer to an [`ActivateRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ActivateResponse {
    /// The recovered secret (empty when the TPM could not activate; zeroized
    /// on drop).
    #[serde(with = "db_gojson::b64_zeroizing")]
    pub secret: Zeroizing<Vec<u8>>,
}

/// Asks for a fresh quote.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AttestChallenge {
    /// [`msg::ATTEST_CHALLENGE`].
    #[serde(rename = "type")]
    pub msg_type: String,
    /// Nonce.
    #[serde(with = "db_gojson::b64")]
    pub nonce: Vec<u8>,
    /// PCRs to quote (Go ints; validated by the agent).
    #[serde(with = "db_gojson::nil_vec")]
    pub pcrs: Vec<i64>,
}

/// Answers an [`AttestChallenge`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Attestation {
    /// [`msg::ATTESTATION`].
    #[serde(rename = "type")]
    pub msg_type: String,
    /// The challenge nonce.
    #[serde(with = "db_gojson::b64")]
    pub nonce: Vec<u8>,
    /// Statement JSON.
    #[serde(with = "db_gojson::b64")]
    pub statement: Vec<u8>,
    /// TPMS_ATTEST.
    #[serde(with = "db_gojson::b64")]
    pub quote_attest: Vec<u8>,
    /// TPMT_SIGNATURE.
    #[serde(with = "db_gojson::b64")]
    pub quote_sig: Vec<u8>,
    /// Event log.
    #[serde(with = "db_gojson::b64")]
    pub event_log: Vec<u8>,
}

/// Grants (or extends) the right to receive jobs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Lease {
    /// [`msg::LEASE`].
    #[serde(rename = "type")]
    pub msg_type: String,
    /// Lease ID.
    pub lease_id: String,
    /// Tier.
    pub tier: Tier,
    /// Expiry.
    pub expires_at: GoTime,
    /// Release ID.
    pub release: String,
    /// Verdict checks.
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "db_gojson::null_default")]
    pub checks: Vec<Check>,
}

/// A terminal error.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ErrorMsg {
    /// [`msg::ERROR`].
    #[serde(rename = "type")]
    pub msg_type: String,
    /// Message.
    pub message: String,
}

/// The plaintext routing metadata of a job. It is also the HPKE additional
/// authenticated data, so the provider rejects a job whose sealed request
/// disagrees with what the coordinator routed and priced. Decoded strictly.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct JobMeta {
    /// Version (1).
    pub v: i64,
    /// Job ID.
    pub job_id: String,
    /// Provider.
    pub provider_id: String,
    /// Provider session the job is sealed for.
    pub session_id: String,
    /// Model.
    pub model: String,
    /// Workflow.
    pub workflow: String,
    /// `"image"` or `"video"`.
    pub kind: String,
    /// Width.
    pub width: i64,
    /// Height.
    pub height: i64,
    /// Steps.
    pub steps: i64,
    /// Frames (video).
    #[serde(skip_serializing_if = "db_gojson::is_zero_i64")]
    pub frames: i64,
    /// Frames per second (video).
    #[serde(skip_serializing_if = "db_gojson::is_zero_i64")]
    pub fps: i64,
    /// Generated-token limit for text jobs (zero for media jobs).
    #[serde(skip_serializing_if = "db_gojson::is_zero_i64")]
    pub max_tokens: i64,
    /// Creation time.
    pub created_at: GoTime,
}

/// The sealed part of a job. Zeroized on drop (prompt and input image are
/// the private content).
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct JobRequest {
    /// Version (1).
    #[serde(default)]
    pub v: i64,
    /// Job ID.
    #[serde(default)]
    pub job_id: String,
    /// Model.
    #[serde(default)]
    pub model: String,
    /// Workflow.
    #[serde(default)]
    pub workflow: String,
    /// Prompt.
    #[serde(default)]
    pub prompt: String,
    /// Negative prompt.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub negative_prompt: String,
    /// Seed.
    #[serde(default)]
    pub seed: i64,
    /// Width.
    #[serde(default)]
    pub width: i64,
    /// Height.
    #[serde(default)]
    pub height: i64,
    /// Steps.
    #[serde(default)]
    pub steps: i64,
    /// Frames (video).
    #[serde(default, skip_serializing_if = "db_gojson::is_zero_i64")]
    pub frames: i64,
    /// Frames per second (video).
    #[serde(default, skip_serializing_if = "db_gojson::is_zero_i64")]
    pub fps: i64,
    /// Generated-token limit, authenticated against the routing metadata.
    #[serde(default, skip_serializing_if = "db_gojson::is_zero_i64")]
    pub max_tokens: i64,
    /// Optional input image.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "db_gojson::b64")]
    pub input_image: Vec<u8>,
    /// Hides the prompt length from anyone who sees the ciphertext size:
    /// clients fill the request up to a size bucket (see [`pad_request`]).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pad: String,
}

/// Smallest padded request size; larger requests pad to the next power of two.
pub const REQUEST_PAD_BUCKET: usize = 4096;

/// Returns the request encoded and padded to the next bucket (powers of two
/// from [`REQUEST_PAD_BUCKET`]), so the sealed size reveals only a coarse
/// class. Byte-identical to Go's `wire.PadRequest`; `r.pad` is left empty.
pub fn pad_request(r: &mut JobRequest) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
    // `"pad":""` plus its separating comma; the pad (spaces, never escaped)
    // fills the rest of the bucket.
    const PAD_FIELD: usize = r#","pad":"""#.len();
    r.pad = String::new();
    let plain = Zeroizing::new(marshal(r)?);
    let mut target = REQUEST_PAD_BUCKET;
    while target < plain.len() + 16 {
        target = target.saturating_mul(2);
    }
    r.pad = " ".repeat(target - plain.len() - PAD_FIELD);
    let out = marshal(r).map(Zeroizing::new);
    r.pad = String::new();
    out
}

impl std::fmt::Debug for JobRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobRequest")
            .field("job_id", &self.job_id)
            .field("model", &self.model)
            .field("workflow", &self.workflow)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("steps", &self.steps)
            .finish_non_exhaustive()
    }
}

/// Bound on prompt bytes.
pub const MAX_PROMPT_BYTES: usize = 8 << 10;
/// Bound on input image bytes.
pub const MAX_INPUT_IMAGE_BYTES: usize = 16 << 20;
/// Smallest side.
pub const MIN_SIDE: i64 = 256;
/// Largest side.
pub const MAX_SIDE: i64 = 2048;
/// Most steps.
pub const MAX_STEPS: i64 = 64;
/// Most video frames.
pub const MAX_FRAMES: i64 = 241;
/// Maximum generated-token limit accepted by the private text pilot.
pub const MAX_TEXT_TOKENS: i64 = 1024;

/// A job request or metadata that fails validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("wire: {0}")]
pub struct ValidationError(pub String);

impl JobRequest {
    /// Validates a decrypted request against its routing metadata.
    pub fn check_against(&self, m: &JobMeta) -> Result<(), ValidationError> {
        if self.v != 1 || m.v != 1 {
            return Err(ValidationError("unknown job version".to_owned()));
        }
        if self.job_id != m.job_id
            || self.model != m.model
            || self.workflow != m.workflow
            || self.width != m.width
            || self.height != m.height
            || self.steps != m.steps
            || self.frames != m.frames
            || self.fps != m.fps
            || self.max_tokens != m.max_tokens
        {
            return Err(ValidationError("sealed request does not match its routing metadata".to_owned()));
        }
        if self.prompt.is_empty() || self.prompt.len() > MAX_PROMPT_BYTES || self.negative_prompt.len() > MAX_PROMPT_BYTES {
            return Err(ValidationError("prompt length out of range".to_owned()));
        }
        if self.input_image.len() > MAX_INPUT_IMAGE_BYTES {
            return Err(ValidationError("input image too large".to_owned()));
        }
        if m.kind == "text" && (!self.input_image.is_empty() || !self.negative_prompt.is_empty()) {
            return Err(ValidationError("text jobs cannot contain media inputs".to_owned()));
        }
        m.validate()
    }
}

impl JobMeta {
    /// Checks routing metadata bounds.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.v != 1 || self.job_id.is_empty() || self.job_id.len() > 64 || self.model.is_empty() || self.workflow.is_empty() {
            return Err(ValidationError("incomplete job metadata".to_owned()));
        }
        if self.kind == "text" {
            if [self.width, self.height, self.steps, self.frames, self.fps].iter().any(|v| *v != 0)
                || !(1..=MAX_TEXT_TOKENS).contains(&self.max_tokens)
            {
                return Err(ValidationError("text token limit or media fields out of range".to_owned()));
            }
            return Ok(());
        }
        if self.max_tokens != 0 {
            return Err(ValidationError("media jobs cannot contain text limits".to_owned()));
        }
        let side_ok = |s: i64| (MIN_SIDE..=MAX_SIDE).contains(&s) && s % 16 == 0;
        if !side_ok(self.width) || !side_ok(self.height) {
            return Err(ValidationError(format!("size {}x{} out of range", self.width, self.height)));
        }
        if !(1..=MAX_STEPS).contains(&self.steps) {
            return Err(ValidationError(format!("steps {} out of range", self.steps)));
        }
        match self.kind.as_str() {
            "image" => {
                if self.frames != 0 {
                    return Err(ValidationError("image jobs have no frames".to_owned()));
                }
            }
            "video" => {
                if !(1..=MAX_FRAMES).contains(&self.frames) || !(1..=60).contains(&self.fps) {
                    return Err(ValidationError("video frames/fps out of range".to_owned()));
                }
            }
            other => return Err(ValidationError(format!("unknown job kind {other:?}"))),
        }
        Ok(())
    }
}

/// Dispatches a sealed job to a provider.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Job {
    /// [`msg::JOB`].
    #[serde(rename = "type")]
    pub msg_type: String,
    /// Job ID.
    pub job_id: String,
    /// Exact routing metadata bytes (the HPKE AAD).
    #[serde(with = "db_gojson::b64")]
    pub meta: Vec<u8>,
    /// Sealed request.
    pub sealed: Sealed,
}

/// Acknowledges a job.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct JobAccepted {
    /// [`msg::JOB_ACCEPTED`].
    #[serde(rename = "type")]
    pub msg_type: String,
    /// Job ID.
    pub job_id: String,
}

/// Reports progress (metadata only).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct JobProgress {
    /// [`msg::JOB_PROGRESS`].
    #[serde(rename = "type")]
    pub msg_type: String,
    /// Job ID.
    pub job_id: String,
    /// Current step.
    pub step: i64,
    /// Total steps.
    pub total: i64,
}

/// Carries one sealed result chunk.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct JobChunk {
    /// [`msg::JOB_CHUNK`].
    #[serde(rename = "type")]
    pub msg_type: String,
    /// Job ID.
    pub job_id: String,
    /// Sequence number.
    pub seq: u64,
    /// Ciphertext.
    #[serde(with = "db_gojson::b64")]
    pub data: Vec<u8>,
}

/// Ends a job with a signed receipt.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct JobDone {
    /// [`msg::JOB_DONE`].
    #[serde(rename = "type")]
    pub msg_type: String,
    /// Job ID.
    pub job_id: String,
    /// Receipt JSON (exact signed bytes).
    #[serde(with = "db_gojson::b64")]
    pub receipt: Vec<u8>,
    /// Ed25519 signature by the attested receipt key.
    #[serde(with = "db_gojson::b64")]
    pub receipt_sig: Vec<u8>,
}

/// Ends a job without a result. Carries only a fixed code and the fixed
/// text for it ([`error_text`]): failure details can contain request
/// content, so they stay in the provider's local log.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct JobError {
    /// [`msg::JOB_ERROR`].
    #[serde(rename = "type")]
    pub msg_type: String,
    /// Job ID.
    pub job_id: String,
    /// Fixed error code.
    pub code: String,
    /// Fixed text for the code.
    pub message: String,
}

/// Cancels a job.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct JobCancel {
    /// [`msg::JOB_CANCEL`].
    #[serde(rename = "type")]
    pub msg_type: String,
    /// Job ID.
    pub job_id: String,
}

/// Job error codes.
pub mod codes {
    /// Duplicate job or queue full.
    pub const REJECTED: &str = "rejected";
    /// Metadata does not parse or names another job.
    pub const BAD_META: &str = "bad_meta";
    /// Sealed for another provider session.
    pub const WRONG_SESSION: &str = "wrong_session";
    /// Does not open with the attested key.
    pub const DECRYPT: &str = "decrypt";
    /// Sealed request does not parse.
    pub const BAD_REQUEST: &str = "bad_request";
    /// Sealed request differs from its metadata.
    pub const META_MISMATCH: &str = "meta_mismatch";
    /// Cancelled or timed out.
    pub const CANCELLED: &str = "cancelled";
    /// The engine failed.
    pub const ENGINE: &str = "engine";
    /// The engine did not come back from its per-job restart in time.
    pub const ENGINE_UNAVAILABLE: &str = "engine_unavailable";
    /// Result sealing failed.
    pub const SEAL: &str = "seal";
}

/// The only text a provider may attach to a job error: a fixed message per
/// code, so failures cannot carry request content.
pub fn error_text(code: &str) -> &'static str {
    match code {
        "rejected" => "provider rejected the job (duplicate or queue full)",
        "bad_meta" | "meta_mismatch" | "wrong_session" | "bad_request" => "job does not match its routing metadata or session",
        "decrypt" => "job does not open with the attested key",
        "cancelled" => "job cancelled",
        "engine" => "generation failed",
        "engine_unavailable" => "engine unavailable (restarting)",
        "seal" => "result sealing failed",
        _ => "job failed",
    }
}

/// `POST /v1/images/generations` and `/v1/videos/generations`: an
/// OpenAI-style request to the trusted coordinator, which seals the job to an
/// attested provider. Decoded strictly; the prompts are zeroized on drop.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct GenerateRequest {
    /// Model ID.
    #[serde(default, deserialize_with = "db_gojson::null_default")]
    pub model: String,
    /// Prompt.
    #[serde(default, deserialize_with = "db_gojson::null_default")]
    pub prompt: String,
    /// Negative prompt.
    #[serde(default, deserialize_with = "db_gojson::null_default", skip_serializing_if = "String::is_empty")]
    pub negative_prompt: String,
    /// "WIDTHxHEIGHT" (default 1024x1024 images, 832x480 video).
    #[serde(default, deserialize_with = "db_gojson::null_default", skip_serializing_if = "String::is_empty")]
    pub size: String,
    /// Steps (0 = model default).
    #[serde(default, deserialize_with = "db_gojson::null_default", skip_serializing_if = "db_gojson::is_zero_i64")]
    pub steps: i64,
    /// Seed (0 = random).
    #[serde(default, deserialize_with = "db_gojson::null_default", skip_serializing_if = "db_gojson::is_zero_i64")]
    pub seed: i64,
    /// Video frames (0 = 33).
    #[serde(default, deserialize_with = "db_gojson::null_default", skip_serializing_if = "db_gojson::is_zero_i64")]
    pub frames: i64,
    /// Video frames per second (0 = 16).
    #[serde(default, deserialize_with = "db_gojson::null_default", skip_serializing_if = "db_gojson::is_zero_i64")]
    pub fps: i64,
}

/// The coordinator-sealed API's answer: the result inline (base64) and where
/// and under which attestation the job ran.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GenerateResponse {
    /// Unix seconds.
    pub created: i64,
    /// One output.
    pub data: Vec<GeneratedObject>,
    /// Provenance.
    #[serde(rename = "darkbloom")]
    pub provenance: Provenance,
}

/// One output; the content is zeroized on drop.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct GeneratedObject {
    /// Base64 (standard, padded) content.
    #[serde(default)]
    pub b64_json: String,
    /// MIME type.
    #[serde(default)]
    pub mime_type: String,
}

/// Debug output for private content: its size, never the content.
pub struct Redacted(pub usize);

impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted {} bytes>", self.0)
    }
}

impl std::fmt::Debug for GenerateRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenerateRequest")
            .field("model", &self.model)
            .field("prompt", &Redacted(self.prompt.len()))
            .field("negative_prompt", &Redacted(self.negative_prompt.len()))
            .field("size", &self.size)
            .field("steps", &self.steps)
            .field("seed", &self.seed)
            .field("frames", &self.frames)
            .field("fps", &self.fps)
            .finish()
    }
}

impl std::fmt::Debug for GeneratedObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedObject").field("b64_json", &Redacted(self.b64_json.len())).field("mime_type", &self.mime_type).finish()
    }
}

/// Where and under which attestation a job ran.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Provenance {
    /// Provider ID.
    pub provider_id: String,
    /// Attested tier.
    pub tier: String,
    /// Release ID.
    pub release: String,
    /// Whether decryption needed the provider TPM's PolicyPCR-gated ECDH.
    pub tpm_bound_decryption: bool,
    /// Billable units (from the routed metadata).
    pub units: Units,
    /// Coordinator-side wall time, Go duration syntax.
    pub elapsed: String,
}

/// What the consumer is billed for.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Units {
    /// Images.
    #[serde(skip_serializing_if = "db_gojson::is_zero_i64")]
    pub images: i64,
    /// Megapixels.
    #[serde(skip_serializing_if = "db_gojson::is_zero_f64")]
    pub megapixels: f64,
    /// Steps.
    pub steps: i64,
    /// Seconds of video.
    #[serde(skip_serializing_if = "db_gojson::is_zero_f64")]
    pub video_seconds: f64,
    /// GPU time.
    #[serde(rename = "gpu_ms")]
    pub gpu_millis: i64,
    /// Input tokens reported by the approved text engine.
    #[serde(skip_serializing_if = "db_gojson::is_zero_i64")]
    pub prompt_tokens: i64,
    /// Generated tokens reported by the approved text engine.
    #[serde(skip_serializing_if = "db_gojson::is_zero_i64")]
    pub completion_tokens: i64,
}

/// A bounded, one-prompt text generation request to the trusted coordinator.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct GenerateTextRequest {
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub prompt: String,
    #[serde(default)]
    pub max_tokens: i64,
    #[serde(default)]
    pub seed: i64,
}

impl std::fmt::Debug for GenerateTextRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenerateTextRequest")
            .field("model", &self.model)
            .field("prompt", &Redacted(self.prompt.len()))
            .field("max_tokens", &self.max_tokens)
            .finish_non_exhaustive()
    }
}

/// Text token accounting; content is never included in these metadata.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, Zeroize)]
pub struct TextUsage {
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
}

/// A text result from the trusted-coordinator API. The consumer-sealed API
/// transports the same text in encrypted result chunks instead.
#[derive(Clone, PartialEq, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct GenerateTextResponse {
    pub id: String,
    pub model: String,
    pub text: String,
    pub usage: TextUsage,
    #[serde(rename = "darkbloom")]
    #[zeroize(skip)]
    pub provenance: Provenance,
}

impl std::fmt::Debug for GenerateTextResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenerateTextResponse")
            .field("id", &self.id)
            .field("model", &self.model)
            .field("text", &Redacted(self.text.len()))
            .field("usage", &self.usage)
            .finish_non_exhaustive()
    }
}

/// Signed by the provider's attested receipt key. The coordinator bills from
/// receipts without seeing prompts or outputs; consumers can check that
/// their result came from the attested provider. Decoded strictly.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Receipt {
    /// Version (1).
    pub v: i64,
    /// Job ID.
    pub job_id: String,
    /// Provider.
    pub provider_id: String,
    /// Session.
    pub session_id: String,
    /// Release ID of the lease.
    pub release: String,
    /// Model.
    pub model: String,
    /// Workflow.
    pub workflow: String,
    /// SHA-256 of the exact metadata bytes.
    pub meta_sha256: String,
    /// [`request_digest`] of the sealed request.
    pub request_sha256: String,
    /// [`result_digest`] of the delivered chunks.
    pub result_sha256: String,
    /// Total ciphertext bytes.
    pub result_bytes: i64,
    /// Result MIME type.
    pub result_mime: String,
    /// Units.
    pub units: Units,
    /// Start time.
    pub started_at: GoTime,
    /// Finish time.
    pub finished_at: GoTime,
}

/// A provider as listed to consumers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderInfo {
    /// Provider.
    pub provider_id: String,
    /// Session.
    pub session_id: String,
    /// Tier.
    pub tier: Tier,
    /// Release.
    pub release: String,
    /// Lease expiry.
    pub lease_until: GoTime,
    /// Models.
    #[serde(with = "db_gojson::nil_vec")]
    pub models: Vec<ModelCap>,
    /// Job KEM.
    pub job_kem: String,
    /// GPU.
    pub gpu: String,
    /// TPM mode.
    pub tpm_mode: String,
}

/// The coordinator's signed record that an AK was activated against an EK
/// with a verified AMD (or dev) chain: the one fact a consumer cannot
/// re-derive. Decoded strictly.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Enrollment {
    /// Version (1).
    pub v: i64,
    /// Provider.
    pub provider_id: String,
    /// Device identity.
    pub device_id: String,
    /// SHA-256 of the EK TPMT_PUBLIC.
    pub ek_public_sha256: String,
    /// AK name.
    #[serde(with = "db_gojson::b64")]
    pub ak_name: Vec<u8>,
    /// Endorsement root.
    pub root: String,
    /// Root kind.
    pub root_kind: String,
    /// Session.
    pub session_id: String,
    /// Activation time.
    pub activated_at: GoTime,
}

/// A JSON payload with an Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SignedBlob {
    /// Payload bytes.
    #[serde(with = "db_gojson::b64")]
    pub payload: Vec<u8>,
    /// Signature.
    #[serde(with = "db_gojson::b64")]
    pub sig: Vec<u8>,
    /// Signing key ID.
    pub keyid: String,
}

/// Lets a consumer verify a provider before sealing a job.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AttestationBundle {
    /// Provider.
    pub provider_id: String,
    /// Session.
    pub session_id: String,
    /// Evidence (quote over the consumer's nonce when requested).
    pub evidence: Evidence,
    /// Signed enrollment record.
    pub enrollment: SignedBlob,
    /// Release envelope with its log inclusion proof.
    pub release: Option<Inclusion>,
    /// The coordinator's verdict (informational).
    pub verdict: Option<Verdict>,
    /// Lease expiry.
    pub lease_until: GoTime,
}

/// Publishes the coordinator's keys and policy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CoordinatorInfo {
    /// Enrollment record signing key.
    #[serde(with = "db_gojson::b64")]
    pub enrollment_key: Vec<u8>,
    /// Release-log key.
    #[serde(with = "db_gojson::b64")]
    pub release_log_key: Vec<u8>,
    /// Trusted release keys by key ID.
    #[serde(with = "b64_map")]
    pub release_keys: BTreeMap<String, Vec<u8>>,
    /// SVN floor.
    pub min_svn: u32,
    /// Whether dev releases are accepted.
    pub allow_dev: bool,
}

/// A consumer's sealed job. Decoded strictly.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SubmitJob {
    /// Provider.
    pub provider_id: String,
    /// Exact metadata bytes.
    #[serde(with = "db_gojson::b64")]
    pub meta: Vec<u8>,
    /// Sealed request.
    pub sealed: Sealed,
}

/// A job's status.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct JobStatus {
    /// Job ID.
    pub job_id: String,
    /// queued, running, done, error.
    pub state: String,
    /// Current step.
    #[serde(skip_serializing_if = "db_gojson::is_zero_i64")]
    pub step: i64,
    /// Total steps.
    #[serde(skip_serializing_if = "db_gojson::is_zero_i64")]
    pub total: i64,
    /// Receipt.
    #[serde(skip_serializing_if = "Vec::is_empty", with = "db_gojson::b64")]
    pub receipt: Vec<u8>,
    /// Receipt signature.
    #[serde(skip_serializing_if = "Vec::is_empty", with = "db_gojson::b64")]
    pub receipt_sig: Vec<u8>,
    /// Error.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// Chunks held.
    pub chunks: i64,
}

/// SHA-256 (hex) of a sealed request: each of `enc`, `tpm_ephemeral` and
/// `ciphertext` with a 4-byte big-endian length prefix.
pub fn request_digest(s: &Sealed) -> String {
    let mut h = Sha256::new();
    for f in [&s.enc, &s.tpm_ephemeral, &s.ciphertext] {
        h.update((f.len() as u32).to_be_bytes());
        h.update(f);
    }
    hex::encode(h.finalize())
}

/// SHA-256 (hex) of a sealed result stream with 4-byte big-endian length
/// framing per chunk.
pub fn result_digest<C: AsRef<[u8]>>(chunks: &[C]) -> String {
    let mut h = Sha256::new();
    for c in chunks {
        let c = c.as_ref();
        h.update((c.len() as u32).to_be_bytes());
        h.update(c);
    }
    hex::encode(h.finalize())
}

/// Total ciphertext bytes of a result stream.
pub fn result_bytes<C: AsRef<[u8]>>(chunks: &[C]) -> i64 {
    chunks.iter().map(|c| c.as_ref().len() as i64).sum()
}

/// Base64 values in a string-keyed map (Go `map[string][]byte`).
mod b64_map {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::ser::SerializeMap;
    use serde::{Deserialize, Deserializer, Serializer};
    use std::collections::BTreeMap;

    pub fn serialize<S: Serializer>(m: &BTreeMap<String, Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(m.len()))?;
        for (k, v) in m {
            map.serialize_entry(k, &STANDARD.encode(v))?;
        }
        map.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<BTreeMap<String, Vec<u8>>, D::Error> {
        let m: Option<BTreeMap<String, Option<String>>> = Option::deserialize(d)?;
        m.unwrap_or_default()
            .into_iter()
            .map(|(k, v)| {
                let b = match v {
                    None => Vec::new(),
                    Some(v) => STANDARD.decode(v.as_bytes()).map_err(serde::de::Error::custom)?,
                };
                Ok((k, b))
            })
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_private_content() {
        let mut jr = JobRequest::default();
        jr.prompt = "SECRET-PROMPT".to_owned();
        jr.negative_prompt = "SECRET-NEGATIVE".to_owned();
        jr.input_image = b"SECRET-IMAGE".to_vec();
        let mut gr = GenerateRequest::default();
        gr.prompt = "SECRET-PROMPT".to_owned();
        gr.negative_prompt = "SECRET-NEGATIVE".to_owned();
        let mut obj = GeneratedObject::default();
        obj.b64_json = "SECRET-IMAGE".to_owned();
        for out in [
            format!("{jr:?}"),
            format!("{gr:?}"),
            format!("{obj:?}"),
            format!("{:?}", GenerateResponse { data: vec![obj.clone()], ..Default::default() }),
        ] {
            assert!(!out.contains("SECRET"), "{out}");
        }
        assert!(format!("{gr:?}").contains("prompt: <redacted 13 bytes>"));
    }

    /// Port of Go's TestPadRequestBuckets.
    #[test]
    fn pad_request_buckets() {
        let mut sizes = std::collections::BTreeSet::new();
        for n in [1usize, 50, 900, 3000] {
            let mut r = JobRequest::default();
            r.v = 1;
            r.job_id = "j".to_owned();
            r.model = "m".to_owned();
            r.workflow = "w".to_owned();
            r.prompt = "a".repeat(n);
            r.width = 512;
            r.height = 512;
            r.steps = 8;
            let b = pad_request(&mut r).unwrap();
            assert!(r.pad.is_empty());
            sizes.insert(b.len());
            let back: JobRequest = serde_json::from_slice(&b).unwrap();
            assert_eq!(back.prompt, r.prompt, "padded request does not round-trip");
            assert!(back.pad.bytes().all(|c| c == b' '));
        }
        assert_eq!(sizes.into_iter().collect::<Vec<_>>(), vec![4096], "prompts of different lengths should pad to one 4 KiB bucket");
        let mut big = JobRequest::default();
        big.v = 1;
        big.prompt = "b".repeat(5000);
        assert_eq!(pad_request(&mut big).unwrap().len(), 8192, "5000-byte prompt");
        // HTML-escaped characters count at their encoded length, as in Go.
        let mut esc = JobRequest::default();
        esc.prompt = "<&>".repeat(1000);
        assert_eq!(pad_request(&mut esc).unwrap().len(), 32768);
    }

    fn meta() -> JobMeta {
        JobMeta {
            v: 1,
            job_id: "job-1".to_owned(),
            provider_id: "p".to_owned(),
            session_id: "s".to_owned(),
            model: "m".to_owned(),
            workflow: "w".to_owned(),
            kind: "image".to_owned(),
            width: 512,
            height: 512,
            steps: 4,
            ..JobMeta::default()
        }
    }

    #[test]
    fn meta_validation() {
        meta().validate().unwrap();
        for bad in [
            JobMeta { width: 500, ..meta() },
            JobMeta { height: 4096, ..meta() },
            JobMeta { steps: 0, ..meta() },
            JobMeta { steps: 65, ..meta() },
            JobMeta { frames: 1, ..meta() },
            JobMeta { kind: "audio".to_owned(), ..meta() },
            JobMeta { kind: "video".to_owned(), frames: 33, fps: 0, ..meta() },
            JobMeta { job_id: "x".repeat(65), ..meta() },
            JobMeta { v: 2, ..meta() },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        JobMeta { kind: "video".to_owned(), frames: 33, fps: 16, ..meta() }.validate().unwrap();
    }

    #[test]
    fn request_checks() {
        let m = meta();
        let mut req = JobRequest::default();
        req.v = 1;
        req.job_id = m.job_id.clone();
        req.model = m.model.clone();
        req.workflow = m.workflow.clone();
        req.prompt = "a lighthouse".to_owned();
        req.width = 512;
        req.height = 512;
        req.steps = 4;
        req.check_against(&m).unwrap();
        let mut other = req.clone();
        other.width = 256;
        assert!(other.check_against(&m).is_err(), "sealed size differs from metadata");
        let mut empty = req.clone();
        empty.prompt.clear();
        assert!(empty.check_against(&m).is_err());
        let mut long = req.clone();
        long.prompt = "x".repeat(MAX_PROMPT_BYTES + 1);
        assert!(long.check_against(&m).is_err());
    }

    #[test]
    fn private_text_is_bounded_and_cannot_mix_media_or_change_its_limit() {
        let m = JobMeta { kind: "text".to_owned(), width: 0, height: 0, steps: 0, max_tokens: 64, ..meta() };
        m.validate().unwrap();
        let mut req = JobRequest::default();
        req.v = 1;
        req.job_id = m.job_id.clone();
        req.model = m.model.clone();
        req.workflow = m.workflow.clone();
        req.prompt = "private canary".to_owned();
        req.max_tokens = 64;
        req.check_against(&m).unwrap();
        req.max_tokens = 65;
        assert!(req.check_against(&m).is_err());
        req.max_tokens = 64;
        req.input_image.push(1);
        assert!(req.check_against(&m).is_err());
        for invalid in [
            JobMeta { max_tokens: 0, ..m.clone() },
            JobMeta { max_tokens: MAX_TEXT_TOKENS + 1, ..m.clone() },
            JobMeta { steps: 1, ..m.clone() },
            JobMeta { width: 512, ..m.clone() },
        ] {
            assert!(invalid.validate().is_err());
        }
        assert!(JobMeta { max_tokens: 64, ..meta() }.validate().is_err());
    }

    #[test]
    fn text_api_is_strict_and_debug_redacts_content() {
        let request: GenerateTextRequest = db_gojson::from_slice(br#"{"model":"qwen","prompt":"secret-canary","max_tokens":64}"#).unwrap();
        assert_eq!(request.seed, 0);
        assert!(!format!("{request:?}").contains("secret-canary"));
        assert!(
            db_gojson::from_slice::<GenerateTextRequest>(br#"{"model":"qwen","prompt":"secret-canary","max_tokens":64,"debug":true}"#,)
                .is_err()
        );
        let mut response = GenerateTextResponse::default();
        response.text = "private-response".to_owned();
        assert!(!format!("{response:?}").contains("private-response"));
    }

    #[test]
    fn go_shapes() {
        let m = JobMeta { created_at: GoTime::parse("2026-11-02T15:04:05Z").unwrap(), ..meta() };
        assert_eq!(
            String::from_utf8(marshal(&m).unwrap()).unwrap(),
            r#"{"v":1,"job_id":"job-1","provider_id":"p","session_id":"s","model":"m","workflow":"w","kind":"image","width":512,"height":512,"steps":4,"created_at":"2026-11-02T15:04:05Z"}"#
        );
        let u = Units { images: 1, megapixels: 1.048576, steps: 8, video_seconds: 0.0, gpu_millis: 21000, ..Units::default() };
        assert_eq!(String::from_utf8(marshal(&u).unwrap()).unwrap(), r#"{"images":1,"megapixels":1.048576,"steps":8,"gpu_ms":21000}"#);
        let st = JobStatus { job_id: "j".to_owned(), state: "queued".to_owned(), ..JobStatus::default() };
        assert_eq!(String::from_utf8(marshal(&st).unwrap()).unwrap(), r#"{"job_id":"j","state":"queued","chunks":0}"#);
        // Strict types reject unknown fields; lenient ones do not.
        assert!(db_gojson::from_slice::<JobMeta>(br#"{"v":1,"extra":1}"#).is_err());
        assert!(db_gojson::from_slice::<Welcome>(br#"{"type":"welcome","extra":1}"#).is_ok());
        let sub: SubmitJob =
            db_gojson::from_slice(br#"{"provider_id":"p","meta":"e30=","sealed":{"enc":null,"ciphertext":null}}"#).unwrap();
        assert_eq!(sub.meta, b"{}");
        assert!(sub.sealed.enc.is_empty());
    }

    #[test]
    fn digests() {
        let s = Sealed { enc: b"enc".to_vec(), tpm_ephemeral: Vec::new(), ciphertext: b"ct".to_vec() };
        assert_eq!(request_digest(&s), hex::encode(Sha256::digest(b"\0\0\0\x03enc\0\0\0\0\0\0\0\x02ct")));
        let chunks = vec![b"ab".to_vec(), b"c".to_vec()];
        let mut framed = vec![0, 0, 0, 2, b'a', b'b', 0, 0, 0, 1, b'c'];
        assert_eq!(result_digest(&chunks), hex::encode(Sha256::digest(&framed)));
        framed.clear();
        assert_eq!(result_bytes(&chunks), 3);
        assert_eq!(error_text("decrypt"), "job does not open with the attested key");
        assert_eq!(error_text("anything else"), "job failed");
    }
}
