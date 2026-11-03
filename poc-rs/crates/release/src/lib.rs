//! Signed Darkbloom Node OS release manifests: the "signed trust" half of
//! the design.
//!
//! Darkbloom signs each release's expected measurements with a long-lived
//! release key; verifiers accept any release that is (1) signed by a
//! trusted key, (2) at or above a security-version floor, (3) unexpired and
//! unrevoked, and (4) logged in the release transparency log. New releases
//! attest without a coordinator change, and providers never enroll a key
//! (no MOK, no IMA keyring, Secure Boot keys untouched): signatures are
//! checked by the verifier, not by the provider's kernel.

#![forbid(unsafe_code)]

mod authenticode;
mod dsse;
mod manifest;
mod predict;
mod tlog;
mod uki;

pub use authenticode::{authenticode_digest, authenticode_ranges};
pub use dsse::{
    Envelope, Policy, Signature, TrustedKeys, generate_key, key_id, load_private_key, load_public_key, open_manifest, pae, sign,
    sign_manifest, write_private_key,
};
pub use manifest::{Artifact, Boot, Manifest, Model, PAYLOAD_TYPE, Platform, Requires, Runtime, SCHEMA};
pub use predict::{Prediction, file_sha256, load_options_digest, predict, predict_pcr4};
pub use tlog::{Inclusion, Log, TreeHead, leaf_hash, node_hash, verify_inclusion};
pub use uki::{predict_pcr11, sections as uki_sections};

/// Errors from the release library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A manifest, envelope or proof failed a check.
    #[error("release: {0}")]
    Invalid(String),
    /// File I/O.
    #[error("release: {path}: {source}")]
    Io {
        /// File involved.
        path: String,
        /// Underlying error.
        source: std::io::Error,
    },
    /// JSON encoding or decoding.
    #[error("release: {0}")]
    Json(#[from] serde_json::Error),
}

impl Error {
    pub(crate) fn invalid(msg: impl Into<String>) -> Self {
        Self::Invalid(msg.into())
    }

    pub(crate) fn io(path: &std::path::Path, source: std::io::Error) -> Self {
        Self::Io { path: path.display().to_string(), source }
    }
}

/// Result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Whether `s` is valid hex (any even length, either case), as Go's
/// `hex.DecodeString` accepts.
pub fn is_hex(s: &str) -> bool {
    s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether `s` is a 64-character hex SHA-256 digest.
pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && is_hex(s)
}

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| Error::invalid(format!("random: {e}")))?;
    Ok(b)
}

#[cfg(test)]
mod tests;
