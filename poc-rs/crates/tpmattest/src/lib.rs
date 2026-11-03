//! Verifies TPM evidence from Darkbloom AMD providers.
//!
//! The coordinator-side (and consumer-side) half of the PoC: endorsement
//! key (EK) chain verification against pinned AMD roots, credential
//! activation (MakeCredential), quote verification, TCG event-log parsing
//! and replay, and policy evaluation against signed Node OS release
//! manifests. Pure Rust with no TPM access.

#![forbid(unsafe_code)]

pub mod boundkey;
pub mod credential;
pub mod ekchain;
pub mod eventlog;
pub mod keys;
pub mod policy;
pub mod quote;
pub mod statement;
pub mod x509;

pub use boundkey::{BoundKey, CC_POLICY_PCR, bound_key_certify_data, policy_pcr_digest, verify_bound_key};
pub use credential::{CredentialChallenge, EndorsementKey, make_credential, make_credential_with_secret, parse_ek_public};
pub use ekchain::{
    EkChain, PLUTON_GLOBAL_FACTORY_ICA_SHA256, RootKind, TrustBundle, TrustRoot, cert_fingerprint, key_type, load_certificates,
    pinned_root, pluton_root,
};
pub use eventlog::{
    ALG_SHA1, ALG_SHA256, ALG_SHA384, ALG_SHA512, EFI_GLOBAL_VARIABLE_GUID, Event, EventLog, LogEvent, build_event_log, decode_utf16,
    digest_of, digests_of, hash_for, parse_event_log, parse_tagged_event, parse_uefi_variable, tagged_event_data, uefi_variable_data,
    utf16le,
};
pub use keys::PublicKey;
pub use policy::{
    Check, Clock, DEFAULT_PCRS, Evidence, Expect, PRODUCTION_CMDLINE_FLAGS, Tier, TrustedRelease, UKI_PCRS, Verdict, Verifier,
    compare_firmware_version,
};
pub use quote::{
    AttestationKey, Certification, Quote, endorsement_primary_qn, parse_attestation_key, pcr_digest, verify_certify, verify_quote,
};
pub use statement::{
    BootHealth, GpuStatus, ModelReport, RuntimeReport, STATEMENT_DOMAIN, Statement, Status, UnknownSummary, parse_statement,
    provider_id_from_ek, quote_extra_data,
};
pub use x509::Certificate;

/// Errors from verification helpers. `Evaluate` never returns errors; it
/// records them as failed checks in the verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A structural problem in an event log.
    #[error("tpmattest: malformed event log: {0}")]
    MalformedLog(String),
    /// Any other verification failure.
    #[error("tpmattest: {0}")]
    Invalid(String),
}

/// Result alias.
pub type Result<T> = std::result::Result<T, Error>;
