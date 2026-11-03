//! Provider statements: what a provider asserts about itself, bound into
//! the TPM quote's qualifying data.

use crate::{Error, Result};
use db_gojson::GoTime;
use db_release::Artifact;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

/// Separates provider statements from any other signed data.
pub const STATEMENT_DOMAIN: &str = "darkbloom-amd/provider-statement/v1";

/// Prefixes the quote's qualifying data.
const QUOTE_DOMAIN: &str = "darkbloom-amd/quote/v1";

/// What a provider asserts about itself. It is not signed by itself: its
/// SHA-256 is bound into the TPM quote's qualifying data together with the
/// verifier's nonce, so the TPM's signature covers it. That binds the
/// per-process job key, the receipt key, the account and the coordinator
/// session to the measured boot state.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Statement {
    /// Version (1).
    #[serde(rename = "v")]
    pub version: i64,
    /// [`STATEMENT_DOMAIN`].
    pub domain: String,
    /// Provider ID derived from the EK.
    pub provider_id: String,
    /// Account the coordinator bound the connection to.
    pub account_id: String,
    /// Coordinator session.
    pub session_id: String,
    /// KEM of the job key.
    pub job_kem: String,
    /// HPKE job public key.
    #[serde(with = "db_gojson::b64")]
    pub job_public_key: Vec<u8>,
    /// Ed25519 receipt public key.
    #[serde(with = "db_gojson::b64")]
    pub receipt_public_key: Vec<u8>,
    /// `"hardware"` or `"swtpm"`.
    pub tpm_mode: String,
    /// Firmware and kernel/GPU state report.
    pub status: Status,
    /// What the agent loaded.
    pub runtime: RuntimeReport,
    /// TPM-enforced decryption share (a TPM-resident ECDH key).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_key: Option<crate::BoundKey>,
    /// Creation time.
    pub created_at: GoTime,
}

/// The provider's report on firmware settings and kernel/GPU state that
/// boot measurements do not cover. Only as trustworthy as the code that
/// produced it, so verifiers act on it only when the boot measurements
/// prove an approved Node OS produced it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Status {
    /// `uname -r`.
    pub kernel_release: String,
    /// `/proc/cmdline`.
    pub cmdline: String,
    /// Active kernel lockdown mode.
    pub lockdown: String,
    /// Whether debugfs is mounted.
    pub debugfs_mounted: bool,
    /// UEFI SecureBoot variable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_boot: Option<bool>,
    /// UEFI SetupMode variable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup_mode: Option<bool>,
    /// TSME (transparent memory encryption) active, from the PSP driver.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tsme_active: Option<bool>,
    /// AMD DASH remote management enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dash_enabled: Option<bool>,
    /// SHA-256 of MokListRT.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub moklist_sha256: String,
    /// Whether swap is active.
    pub swap_active: bool,
    /// AMD PSP state from the ccp driver.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", deserialize_with = "db_gojson::null_default")]
    pub psp: BTreeMap<String, String>,
    /// GPU state.
    pub gpu: GpuStatus,
    /// Bounded, pre-admission boot warning census from the measured Node OS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_health: Option<BootHealth>,
    /// Free-form notes.
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "db_gojson::null_default")]
    pub notes: Vec<String>,
}

/// Operational boot diagnostics, never raw journal messages. This report is
/// bound into the fresh TPM quote as part of the provider statement, but a
/// compromised running OS can still falsify its own observations.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootHealth {
    pub v: u8,
    pub boot_id: String,
    pub warning_count: u32,
    pub amdxdna_unknown_revision: u32,
    /// Numeric firmware-reported revision and fuse from that fixed warning.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amdxdna_reported_revision: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amdxdna_raw_fuse: Option<u32>,
    pub amdtee_firmware_missing: u32,
    /// At most four AMD TEE firmware paths, each `amdtee/8-4-4-16.bin`.
    pub amdtee_missing_firmware: Vec<String>,
    pub amd_pmf_ta_failure: u32,
    pub ima_sha384_unavailable: u32,
    pub bpf_restrict_fs_failure: u32,
    pub unknown_warning_count: u32,
    /// First at most 32 unknown system warnings captured before any request.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unknown_summaries: Vec<UnknownSummary>,
    pub collection_error_count: u32,
    pub failed_unit_count: u32,
    pub failed_units: Vec<String>,
}

/// Fixed, bounded operational detail. The collector never includes user
/// process records, and the sealed unit runs only once before dbnode starts.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownSummary {
    pub priority: u8,
    pub transport: String,
    pub unit: String,
    pub sha256: String,
    pub excerpt: String,
}

pub const BOOT_HEALTH_MAX_BYTES: usize = 16 * 1024;

impl BootHealth {
    /// Reject malformed or internally inconsistent reports. The fixed schema
    /// has no fields capable of carrying journal text or request content.
    pub fn valid(&self) -> bool {
        fn uuid_shape(s: &str) -> bool {
            let uuid = s.as_bytes();
            uuid.len() == 36
                && uuid.iter().enumerate().all(|(i, b)| if [8, 13, 18, 23].contains(&i) { *b == b'-' } else { b.is_ascii_hexdigit() })
        }
        fn ta_shape(s: &str) -> bool {
            let Some(name) = s.strip_prefix("amdtee/").and_then(|s| s.strip_suffix(".bin")) else {
                return false;
            };
            let bytes = name.as_bytes();
            bytes.len() == 35
                && bytes.iter().enumerate().all(|(i, b)| if [8, 13, 18].contains(&i) { *b == b'-' } else { b.is_ascii_hexdigit() })
        }
        if self.v != 1
            || !uuid_shape(&self.boot_id)
            || self.warning_count > 10_000
            || self.collection_error_count > 10_000
            || self.failed_unit_count > 10_000
            || self.unknown_summaries.len() > 32
            || usize::try_from(self.unknown_warning_count).ok().is_none_or(|n| n < self.unknown_summaries.len())
            || self.unknown_summaries.iter().any(|s| {
                s.priority > 4
                    || !matches!(s.transport.as_str(), "kernel" | "systemd")
                    || s.unit.len() > 96
                    || !s.unit.bytes().all(|b| b.is_ascii_alphanumeric() || b"@_.-".contains(&b))
                    || s.sha256.len() != 64
                    || !s.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    || s.excerpt.len() > 256
                    || !s.excerpt.bytes().all(|b| (32..=126).contains(&b))
            })
            || self.amdxdna_reported_revision.is_some_and(|n| n > 999 || self.amdxdna_unknown_revision == 0)
            || self.amdxdna_raw_fuse.is_some() && self.amdxdna_reported_revision.is_none()
            || self.amdtee_missing_firmware.len() > 4
            || usize::try_from(self.amdtee_firmware_missing).ok().is_none_or(|n| n < self.amdtee_missing_firmware.len())
            || self.amdtee_missing_firmware.iter().any(|name| !ta_shape(name))
            || self.failed_units.len() > 16
            || usize::try_from(self.failed_unit_count).ok().is_none_or(|n| n < self.failed_units.len())
            || self
                .failed_units
                .iter()
                .any(|u| u.is_empty() || u.len() > 96 || !u.bytes().all(|b| b.is_ascii_alphanumeric() || b"@_.-".contains(&b)))
        {
            return false;
        }
        let known = [
            self.amdxdna_unknown_revision,
            self.amdtee_firmware_missing,
            self.amd_pmf_ta_failure,
            self.ima_sha384_unavailable,
            self.bpf_restrict_fs_failure,
            self.unknown_warning_count,
        ];
        known.into_iter().try_fold(0u32, u32::checked_add) == Some(self.warning_count)
    }

    /// Admission requires the collector to have run and found no warnings or
    /// failed units. This is operational health, not an immutable boot fact.
    pub fn is_clean(&self) -> bool {
        self.valid() && self.warning_count == 0 && self.collection_error_count == 0 && self.failed_unit_count == 0
    }
}

/// The GPU the provider serves on.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GpuStatus {
    /// PCI address.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub pci: String,
    /// Kernel driver.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub driver: String,
    /// GPU target, e.g. gfx1151.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub target: String,
    /// amdgpu `enforce_isolation`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforce_isolation: Option<i64>,
    /// IOMMU group.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub iommu_group: String,
    /// IOMMU domain type (identity or DMA/DMA-FQ).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub iommu_type: String,
    /// GTT size.
    #[serde(skip_serializing_if = "db_gojson::is_zero_u64")]
    pub gtt_bytes: u64,
    /// `"node"` while serving; `"lent"` while the owner borrows it.
    pub owner: String,
}

/// What the agent loaded.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeReport {
    /// SHA-256 of the running agent binary.
    pub agent_sha256: String,
    /// Engine identity.
    pub engine: String,
    /// Workflow templates and their hashes.
    #[serde(with = "db_gojson::nil_vec")]
    pub workflows: Vec<Artifact>,
    /// Models with verified file hashes.
    #[serde(with = "db_gojson::nil_vec")]
    pub models: Vec<ModelReport>,
}

/// A model the agent verified before loading.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelReport {
    /// Model ID.
    pub id: String,
    /// Files and hashes.
    #[serde(with = "db_gojson::nil_vec")]
    pub files: Vec<Artifact>,
}

/// The qualifying data a provider passes to TPM2_Quote:
/// `SHA-256(domain || 0x00 || nonce || SHA-256(statement))`.
pub fn quote_extra_data(nonce: &[u8], statement: &[u8]) -> Vec<u8> {
    let st = Sha256::digest(statement);
    let mut h = Sha256::new();
    h.update(QUOTE_DOMAIN.as_bytes());
    h.update([0u8]);
    h.update(nonce);
    h.update(st);
    h.finalize().to_vec()
}

/// Strictly decodes a statement (unknown fields and trailing data rejected)
/// and checks its shape.
pub fn parse_statement(raw: &[u8]) -> Result<Statement> {
    let s: Statement = db_gojson::from_slice(raw).map_err(|e| Error::Invalid(format!("statement: {e}")))?;
    if s.version != 1 || s.domain != STATEMENT_DOMAIN {
        return Err(Error::Invalid("unknown statement version or domain".to_owned()));
    }
    let size = db_sealbox::public_key_size(&s.job_kem).map_err(|e| Error::Invalid(format!("statement: {e}")))?;
    if s.job_public_key.len() != size {
        return Err(Error::Invalid(format!("job key is {} bytes, {} needs {size}", s.job_public_key.len(), s.job_kem)));
    }
    if s.receipt_public_key.len() != 32 {
        return Err(Error::Invalid("receipt key must be a 32-byte Ed25519 key".to_owned()));
    }
    if s.account_id.is_empty() || s.session_id.is_empty() || s.provider_id.is_empty() {
        return Err(Error::Invalid("statement must name provider, account and session".to_owned()));
    }
    if let Some(health) = &s.status.boot_health {
        let encoded = db_gojson::to_vec(health).map_err(|e| Error::Invalid(format!("boot health: {e}")))?;
        if encoded.len() > BOOT_HEALTH_MAX_BYTES || !health.valid() {
            return Err(Error::Invalid("invalid boot health report".to_owned()));
        }
    }
    Ok(s)
}

/// The provider ID the agent and verifier agree on: the first 16 bytes of
/// SHA-256 over the EK's TPMT_PUBLIC, hex encoded.
pub fn provider_id_from_ek(ek_public: &[u8]) -> String {
    hex::encode(Sha256::digest(ek_public).get(..16).unwrap_or_default())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn good() -> Statement {
        Statement {
            version: 1,
            domain: STATEMENT_DOMAIN.to_owned(),
            provider_id: "p".to_owned(),
            account_id: "a".to_owned(),
            session_id: "s".to_owned(),
            job_kem: db_sealbox::KEM_X25519.to_owned(),
            job_public_key: vec![1; 32],
            receipt_public_key: vec![2; 32],
            tpm_mode: "swtpm".to_owned(),
            ..Statement::default()
        }
    }

    #[test]
    fn strict_parsing() {
        let raw = db_gojson::to_vec(&good()).unwrap();
        assert_eq!(parse_statement(&raw).unwrap(), good());
        // Unknown fields (also nested) and trailing data are rejected.
        let s = String::from_utf8(raw.clone()).unwrap();
        assert!(parse_statement(s.replacen("{\"v\":1", "{\"v\":1,\"x\":1", 1).as_bytes()).is_err());
        assert!(parse_statement(s.replacen("\"owner\":\"\"", "\"owner\":\"\",\"x\":1", 1).as_bytes()).is_err());
        assert!(parse_statement(format!("{s} {{}}").as_bytes()).is_err());
        for bad in [
            Statement { version: 2, ..good() },
            Statement { domain: "other".to_owned(), ..good() },
            Statement { job_kem: "RSA".to_owned(), ..good() },
            Statement { job_public_key: vec![1; 31], ..good() },
            Statement { job_kem: db_sealbox::KEM_XWING.to_owned(), ..good() },
            Statement { receipt_public_key: vec![2; 33], ..good() },
            Statement { account_id: String::new(), ..good() },
            Statement { session_id: String::new(), ..good() },
            Statement { provider_id: String::new(), ..good() },
        ] {
            assert!(parse_statement(&db_gojson::to_vec(&bad).unwrap()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn quote_binding() {
        // SHA-256("darkbloom-amd/quote/v1" || 0 || nonce || SHA-256(statement)).
        let mut pre = b"darkbloom-amd/quote/v1\0".to_vec();
        pre.extend_from_slice(b"nonce");
        pre.extend_from_slice(&Sha256::digest(b"statement"));
        assert_eq!(quote_extra_data(b"nonce", b"statement"), Sha256::digest(&pre).to_vec());
        assert_eq!(provider_id_from_ek(b"ek").len(), 32);
        assert_eq!(provider_id_from_ek(b"ek"), hex::encode(&Sha256::digest(b"ek")[..16]));
    }

    #[test]
    fn boot_health_has_fixed_shape_and_consistent_counts() {
        assert!(serde_json::from_slice::<BootHealth>(br#"{"v":1}"#).is_err());
        let mut statement = good();
        let mut health = BootHealth { v: 1, boot_id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(), ..BootHealth::default() };
        assert!(health.is_clean());
        statement.status.boot_health = Some(health.clone());
        assert!(parse_statement(&db_gojson::to_vec(&statement).unwrap()).is_ok());

        health.amdxdna_unknown_revision = 1;
        statement.status.boot_health = Some(health.clone());
        assert!(parse_statement(&db_gojson::to_vec(&statement).unwrap()).is_err());
        health.warning_count = 1;
        health.amdxdna_reported_revision = Some(9);
        health.amdxdna_raw_fuse = Some(0x10170);
        statement.status.boot_health = Some(health.clone());
        assert!(!health.is_clean());
        assert!(parse_statement(&db_gojson::to_vec(&statement).unwrap()).is_ok());

        health.failed_units = vec!["dbnode.service".to_owned()];
        statement.status.boot_health = Some(health.clone());
        assert!(parse_statement(&db_gojson::to_vec(&statement).unwrap()).is_err());
        health.failed_unit_count = 1;
        health.amdtee_firmware_missing = 1;
        health.amdtee_missing_firmware = vec!["amdtee/773bd96f-b83f-4d52-b12dc529b13d8543.bin".to_owned()];
        health.warning_count = 2;
        statement.status.boot_health = Some(health);
        assert!(parse_statement(&db_gojson::to_vec(&statement).unwrap()).is_ok());
    }

    #[test]
    fn unknown_boot_summaries_are_bounded_and_never_make_health_clean() {
        let summary = UnknownSummary {
            priority: 3,
            transport: "kernel".to_owned(),
            unit: String::new(),
            sha256: "a".repeat(64),
            excerpt: "synthetic kernel warning".to_owned(),
        };
        let mut health = BootHealth {
            v: 1,
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
            warning_count: 1,
            unknown_warning_count: 1,
            unknown_summaries: vec![summary.clone()],
            ..BootHealth::default()
        };
        assert!(health.valid());
        assert!(!health.is_clean());
        health.unknown_summaries[0].excerpt.push('\n');
        assert!(!health.valid());
        health.unknown_summaries = vec![summary.clone(); 33];
        health.unknown_warning_count = 33;
        health.warning_count = 33;
        assert!(!health.valid());
    }
}
