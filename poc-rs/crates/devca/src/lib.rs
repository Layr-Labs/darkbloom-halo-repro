//! A development endorsement CA standing in for a TPM vendor.
//!
//! Development-only: it lets a fresh swtpm look like a Halo to the verifier
//! (the provider-side `db-tpmdev` stores the EK certificate and the ICA in
//! NV, where Pluton keeps them). The verifier only accepts the resulting EK
//! chain when it is explicitly configured with the dev root, and then only
//! grants the dev-simulated tier.
//!
//! Certificates follow Go's `x509.CreateCertificate` layout (the Go
//! reference `tpmdev.CreateDevCA` / `ProvisionEK`): P-384 ECDSA keys with
//! ecdsa-with-SHA384 signatures, PrintableString names in Go's attribute
//! order, random 120-bit serials, extensions in Go's order (keyUsage,
//! extKeyUsage, basicConstraints, subjectKeyIdentifier,
//! authorityKeyIdentifier). The on-disk format is the Go one (`dev-root.pem`,
//! `dev-ica.pem`, SEC1 `dev-ica.key`), so either implementation can load a
//! directory the other created.

#![forbid(unsafe_code)]

mod devca;
mod issue;
mod name;

pub use crate::devca::{DevCa, create_dev_ca, generate_dev_ca, load_dev_ca};
pub use crate::issue::{CaKey, CertSpec, issue_ca, issue_cert, issue_ek_cert, random_serial, self_signed_ca};
pub use crate::name::{go_string_tag, subject_name};
pub use const_oid::ObjectIdentifier;

/// File name of the dev root certificate (PEM).
pub const ROOT_FILE: &str = "dev-root.pem";
/// File name of the dev ICA certificate (PEM).
pub const ICA_FILE: &str = "dev-ica.pem";
/// File name of the dev ICA private key (SEC1 "EC PRIVATE KEY" PEM, 0600).
pub const ICA_KEY_FILE: &str = "dev-ica.key";

/// Subject organization of the dev CA certificates.
pub const DEV_ORG: &str = "Darkbloom DEVELOPMENT";
/// Subject CN of the dev root.
pub const DEV_ROOT_CN: &str = "Darkbloom DEV Simulated TPM Root (NOT AMD, NOT FOR PRODUCTION)";
/// Subject CN of the dev ICA (named like Pluton's firmware ICA, SVN 1).
pub const DEV_ICA_CN: &str = "Darkbloom DEV Simulated TPM Firmware ICA SVN01";
/// Subject OU of simulated EK certificates.
pub const EK_OU: &str = "swtpm";

/// tcg-kp-EKCertificate (TCG EK Credential Profile): marks an EK certificate.
pub const TCG_EK_CERTIFICATE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.8.1");

/// Key usage bits in Go's numbering (`x509.KeyUsage`): bit `i` is the
/// RFC 5280 KeyUsage bit `i`.
pub mod key_usage {
    /// digitalSignature.
    pub const DIGITAL_SIGNATURE: u16 = 1 << 0;
    /// keyEncipherment.
    pub const KEY_ENCIPHERMENT: u16 = 1 << 2;
    /// keyAgreement.
    pub const KEY_AGREEMENT: u16 = 1 << 4;
    /// keyCertSign.
    pub const CERT_SIGN: u16 = 1 << 5;
    /// cRLSign.
    pub const CRL_SIGN: u16 = 1 << 6;
}

/// Errors from the dev CA.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// File I/O.
    #[error("devca: {path}: {source}")]
    Io {
        /// File or directory involved.
        path: String,
        /// Underlying error.
        source: std::io::Error,
    },
    /// Anything else (encoding, keys, malformed files).
    #[error("devca: {0}")]
    Invalid(String),
}

impl Error {
    pub(crate) fn invalid(msg: impl std::fmt::Display) -> Self {
        Self::Invalid(msg.to_string())
    }

    pub(crate) fn io(path: &std::path::Path, source: std::io::Error) -> Self {
        Self::Io { path: path.display().to_string(), source }
    }
}

/// Result alias.
pub type Result<T> = std::result::Result<T, Error>;
