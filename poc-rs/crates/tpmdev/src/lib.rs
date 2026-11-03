//! The provider-side TPM layer: it reads the endorsement certificates,
//! creates the attestation key, answers credential-activation challenges,
//! produces quotes and runs the TPM-bound decryption keys (PolicyPCR-only
//! ECDH keys certified by the AK). The same code drives the Halo's Pluton TPM
//! (`/dev/tpmrm0`) and a software TPM (swtpm) for development; only the
//! transport differs, and the verifier tells them apart by their EK roots.
//!
//! Pure Rust: commands are marshaled by hand with `db-tpm2` and every
//! response is parsed strictly (sizes bounded, structures canonical, no
//! trailing bytes). [`Attester`] exposes the provider-side TPM operations.

#![forbid(unsafe_code)]

mod activate;
pub mod attester;
mod bound;
mod bound_key;
mod cmd;
mod device;
mod nv;
mod pcr;
mod rc;
mod sim;
pub mod transport;

pub use crate::attester::{AttestError, Attester};
pub use crate::bound::bound_key_template;
pub use crate::bound_key::BoundKey;
#[doc(hidden)]
pub use crate::cmd::{Command, Response, parse_response};
pub use crate::device::Device;
pub use crate::nv::trim_der;
pub use crate::rc::{Position, ResponseCode};
pub use crate::transport::Transport;
pub use db_tpm2::{NvPublic, Public};

/// NV index of the RSA EK certificate (TCG EK Credential Profile).
pub const NV_RSA_EK_CERT: u32 = 0x01C0_0002;
/// NV index of the ECC EK certificate.
pub const NV_ECC_EK_CERT: u32 = 0x01C0_000A;
/// NV index of Pluton's "PLUTON Firmware SVNxx" ICA.
pub const NV_PLUTON_FW_ICA: u32 = 0x01C0_0100;
/// NV index of Pluton's per-chip "DEVICE EKICA".
pub const NV_PLUTON_DEV_CA: u32 = 0x01C0_0101;
/// Where Linux exposes the firmware's TCG event log.
pub const EVENT_LOG_PATH: &str = "/sys/kernel/security/tpm0/binary_bios_measurements";

/// How the TPM is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// The platform TPM through the kernel resource manager.
    Hardware,
    /// A software TPM (development only).
    Swtpm,
}

impl Mode {
    /// `"hardware"` or `"swtpm"` (the statement's `tpm_mode`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hardware => "hardware",
            Self::Swtpm => "swtpm",
        }
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A loaded TPM object. Not flushed on drop: call [`Device::flush`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    /// Transient handle.
    pub handle: u32,
    /// TPM name (`nameAlg || H(TPMT_PUBLIC)`).
    pub name: Vec<u8>,
    /// TPMT_PUBLIC as the TPM returned it (canonical).
    pub public_raw: Vec<u8>,
    /// Parsed public area.
    pub public: Public,
}

/// What the provider presents for enrollment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endorsement {
    /// The EK (loaded).
    pub ek: Key,
    /// EK certificate (DER, NV padding removed).
    pub cert_der: Vec<u8>,
    /// On-chip ICAs (DER).
    pub icas: Vec<Vec<u8>>,
    /// Whether the EK is the ECC P-256 one (else RSA-2048).
    pub ecc: bool,
}

/// Errors from the TPM layer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The TPM rejected a command.
    #[error("tpmdev: {command}: {rc}")]
    Tpm {
        /// Command name, e.g. `TPM2_Quote`.
        command: &'static str,
        /// The response code.
        rc: ResponseCode,
    },
    /// The transport failed.
    #[error("tpmdev: {context}: {source}")]
    Io {
        /// What was being done.
        context: String,
        /// Underlying error.
        source: std::io::Error,
    },
    /// A response did not parse.
    #[error("tpmdev: malformed {command} response: {detail}")]
    Malformed {
        /// Command name.
        command: &'static str,
        /// What was wrong.
        detail: String,
    },
    /// Anything else (refusals, missing data, bad arguments).
    #[error("tpmdev: {0}")]
    Invalid(String),
    /// A failure with what was being done.
    #[error("tpmdev: {context}: {}", .source.detail())]
    Context {
        /// What was being done, e.g. "TPM refused the bound ECDH".
        context: String,
        /// The failure.
        source: Box<Error>,
    },
}

impl Error {
    /// The TPM response code, if the TPM rejected a command.
    pub fn response_code(&self) -> Option<ResponseCode> {
        match self {
            Self::Tpm { rc, .. } => Some(*rc),
            Self::Context { source, .. } => source.response_code(),
            _ => None,
        }
    }

    /// The message without the "tpmdev: " prefix.
    fn detail(&self) -> String {
        let s = self.to_string();
        s.strip_prefix("tpmdev: ").map(str::to_owned).unwrap_or(s)
    }

    pub(crate) fn invalid(msg: impl std::fmt::Display) -> Self {
        Self::Invalid(msg.to_string())
    }

    pub(crate) fn context(context: impl Into<String>) -> impl FnOnce(Error) -> Error {
        let context = context.into();
        move |e| Error::Context { context, source: Box::new(e) }
    }
}

/// Result alias.
pub type Result<T> = std::result::Result<T, Error>;
