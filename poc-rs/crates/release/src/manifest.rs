//! Release manifests.

use crate::predict::{load_options_digest, predict, predict_pcr4};
use crate::uki::predict_pcr11;
use crate::{Error, Result, is_sha256_hex};
use db_gojson::GoTime;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The manifest schema identifier.
pub const SCHEMA: &str = "darkbloom-amd/nodeos-release/v1";

/// The DSSE payload type of a release manifest.
pub const PAYLOAD_TYPE: &str = "application/vnd.darkbloom.nodeos-release.v1+json";

/// One Node OS release and the measurements it produces.
///
/// Slices that Go encodes as `null` when nil are `Option<Vec<_>>` here, so
/// a parsed manifest re-marshals to exactly the bytes Go would produce and
/// [`Manifest::digest`] agrees with the Go verifier.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Manifest {
    /// Schema identifier ([`SCHEMA`]).
    pub schema: String,
    /// Release name.
    pub name: String,
    /// Release version.
    pub version: String,
    /// Monotonic security version; verifiers enforce a floor.
    pub svn: u32,
    /// `"production"` or `"dev"`.
    pub channel: String,
    /// Issue time.
    pub issued_at: GoTime,
    /// Expiry time.
    pub expires_at: GoTime,
    /// Firmware constraints.
    pub platform: Platform,
    /// Boot-chain measurements.
    pub boot: Boot,
    /// Runtime contents.
    pub runtime: Runtime,
    /// Extra requirements (can only add to the verifier's).
    pub requires: Requires,
    /// Free-form notes.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub notes: String,
}

/// Firmware the release may run on. Secure Boot on is always required by
/// the verifier and cannot be relaxed by a release.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Platform {
    /// Informational product list.
    pub products: Option<Vec<String>>,
    /// Minimum S-CRTM (BIOS) version, e.g. `LFGB0.03.03`, from PCR 0.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub min_scrtm_version: String,
}

/// The measurements the release's boot path produces.
///
/// On today's Halo boot path (AMD-signed shim -> systemd-boot -> AMD kernel)
/// the firmware measures each boot application's Authenticode hash into
/// PCR 4, the Linux EFI stub measures LoadOptions and then the initrd into
/// PCR 9, and systemd-boot measures the command line into PCR 12.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Boot {
    /// `"type1-amd-signed-chain"` or `"uki"`.
    pub path: String,
    /// shim, systemd-boot, kernel: Authenticode SHA-256 in load order.
    pub boot_apps: Option<Vec<Artifact>>,
    /// Expected PCR 4.
    pub pcr4_sha256: String,
    /// Kernel command line as measured.
    pub load_options: String,
    /// SHA-256 of the UTF-16LE command line with its NUL.
    pub load_options_sha256: String,
    /// SHA-256 of the initrd.
    pub initrd_sha256: String,
    /// Expected PCR 9.
    pub pcr9_sha256: String,
    /// Expected PCR 12.
    pub pcr12_sha256: String,
    /// UKI section measurement (PCR 11); omitted for the Type #1 wire shape.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub pcr11_sha256: String,
    /// UKI sections in canonical PCR 11 measurement order, with VirtualSize
    /// digests. Omitted for the Type #1 wire shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uki_sections: Option<Vec<Artifact>>,
    /// Platform profile: firmware (PCR 0).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub pcr0_sha256: String,
    /// Platform profile: Secure Boot configuration (PCR 7).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub pcr7_sha256: String,
    /// Platform profile: shim MOK state (PCR 14).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub pcr14_sha256: String,
}

/// A named file and its SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Artifact {
    /// File name or identity.
    pub name: String,
    /// Lowercase hex SHA-256.
    pub sha256: String,
    /// Size in bytes (omitted when zero).
    #[serde(skip_serializing_if = "db_gojson::is_zero_i64")]
    pub bytes: i64,
}

/// An approved model and its weight files.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Model {
    /// Model identifier.
    pub id: String,
    /// `"image"`, `"video"` or `"text"`.
    pub kind: String,
    /// Weight files.
    pub files: Option<Vec<Artifact>>,
}

/// What runs inside the image.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Runtime {
    /// Provider agent binary.
    pub agent: Artifact,
    /// Engine identity, e.g. `comfyui@<commit>`.
    pub engine: Artifact,
    /// Approved workflow templates.
    pub workflows: Option<Vec<Artifact>>,
    /// Approved models.
    pub models: Option<Vec<Model>>,
}

/// Release-specific requirements; they only add to the verifier's fixed
/// production requirements.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Requires {
    /// Extra flags the measured command line must carry.
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "db_gojson::null_default")]
    pub cmdline_flags: Vec<String>,
    /// Require the measured worker's bounded pre-admission boot health report.
    #[serde(skip_serializing_if = "db_gojson::is_false")]
    pub boot_health: bool,
}

impl Model {
    /// The model's files (empty when absent).
    pub fn files(&self) -> &[Artifact] {
        self.files.as_deref().unwrap_or_default()
    }
}

impl Runtime {
    /// Approved workflows (empty when absent).
    pub fn workflows(&self) -> &[Artifact] {
        self.workflows.as_deref().unwrap_or_default()
    }

    /// Approved models (empty when absent).
    pub fn models(&self) -> &[Model] {
        self.models.as_deref().unwrap_or_default()
    }
}

impl Boot {
    /// Boot applications (empty when absent).
    pub fn boot_apps(&self) -> &[Artifact] {
        self.boot_apps.as_deref().unwrap_or_default()
    }
}

impl Manifest {
    /// Checks internal consistency: schema, channel, validity window, digest
    /// formats, and that PCR 4/9/12 follow from the listed boot apps, command
    /// line and initrd.
    pub fn validate(&self) -> Result<()> {
        if self.schema != SCHEMA {
            return Err(Error::invalid(format!("unknown schema {:?}", self.schema)));
        }
        if self.name.is_empty() || self.version.is_empty() {
            return Err(Error::invalid("name and version are required"));
        }
        if self.channel != "production" && self.channel != "dev" {
            return Err(Error::invalid(format!("channel must be production or dev, not {:?}", self.channel)));
        }
        if !self.expires_at.after(&self.issued_at) {
            return Err(Error::invalid("expires_at must be after issued_at"));
        }
        let b = &self.boot;
        for h in [&b.pcr0_sha256, &b.pcr7_sha256, &b.pcr14_sha256] {
            if !h.is_empty() && !is_sha256_hex(h) {
                return Err(Error::invalid("platform PCR pins must be 64 hex characters"));
            }
        }
        // Runtime pins, when set, must be SHA-256 digests, and every
        // approved model must pin its files.
        let rt = &self.runtime;
        let mut runtime: Vec<&Artifact> = vec![&rt.agent];
        runtime.extend(rt.workflows());
        for m in rt.models() {
            if m.files().is_empty() {
                return Err(Error::invalid(format!("model {:?} pins no files", m.id)));
            }
            runtime.extend(m.files());
        }
        for a in runtime {
            if !a.sha256.is_empty() && !is_sha256_hex(&a.sha256) {
                return Err(Error::invalid(format!("{:?} digest must be 64 hex characters", a.name)));
            }
        }
        if self.channel == "production" && (b.pcr7_sha256.is_empty() || b.pcr14_sha256.is_empty()) {
            return Err(Error::invalid("production releases must pin PCR 7 and PCR 14 (platform profile)"));
        }
        for h in [&b.pcr4_sha256, &b.load_options_sha256, &b.initrd_sha256, &b.pcr9_sha256, &b.pcr12_sha256] {
            if !is_sha256_hex(h) {
                return Err(Error::invalid("boot digests must be 64 hex characters"));
            }
        }
        if b.boot_apps().is_empty() {
            return Err(Error::invalid("boot_apps must list the measured boot chain"));
        }
        let mut apps = Vec::with_capacity(b.boot_apps().len());
        for a in b.boot_apps() {
            match hex::decode(&a.sha256) {
                Ok(d) if d.len() == 32 => apps.push(d),
                _ => return Err(Error::invalid(format!("boot app {:?} digest is not SHA-256 hex", a.name))),
            }
        }
        if !hex::encode(predict_pcr4(&apps)).eq_ignore_ascii_case(&b.pcr4_sha256) {
            return Err(Error::invalid("pcr4_sha256 does not match boot_apps"));
        }
        match b.path.as_str() {
            "" | "type1-amd-signed-chain" => {
                if !b.pcr11_sha256.is_empty() || b.uki_sections.is_some() {
                    return Err(Error::invalid("Type #1 release must not carry UKI PCR 11 fields"));
                }
                if !hex::encode(load_options_digest(&b.load_options)).eq_ignore_ascii_case(&b.load_options_sha256) {
                    return Err(Error::invalid("load_options_sha256 does not match load_options"));
                }
                // On Type #1, PCR 9 and 12 follow from the externally
                // supplied command line and initrd.
                let initrd = hex::decode(&b.initrd_sha256).map_err(|e| Error::invalid(e.to_string()))?;
                let p = predict(&b.load_options, &initrd);
                if !p.pcr9_sha256.eq_ignore_ascii_case(&b.pcr9_sha256) || !p.pcr12_sha256.eq_ignore_ascii_case(&b.pcr12_sha256) {
                    return Err(Error::invalid("pcr9/pcr12 do not follow from load_options and initrd_sha256"));
                }
            }
            "uki" => {
                if self.channel == "production" && b.pcr0_sha256.is_empty() {
                    return Err(Error::invalid("production UKI releases must pin PCR 0 firmware profile"));
                }
                if !is_sha256_hex(&b.pcr11_sha256) {
                    return Err(Error::invalid("UKI must pin PCR 11"));
                }
                if b.load_options.is_empty() || b.load_options.contains('\0') {
                    return Err(Error::invalid("UKI embedded .cmdline must be nonempty UTF-8 without NUL"));
                }
                let sections = b.uki_sections.as_deref().ok_or_else(|| Error::invalid("UKI section digests missing"))?;
                let predicted = predict_pcr11(sections)?;
                if !hex::encode(predicted).eq_ignore_ascii_case(&b.pcr11_sha256) {
                    return Err(Error::invalid("pcr11_sha256 does not match UKI sections"));
                }
                let cmdline = sections.iter().find(|s| s.name == ".cmdline").ok_or_else(|| Error::invalid("UKI .cmdline missing"))?;
                let initrd = sections.iter().find(|s| s.name == ".initrd").ok_or_else(|| Error::invalid("UKI .initrd missing"))?;
                if cmdline.bytes != b.load_options.len() as i64
                    || !hex::encode(Sha256::digest(b.load_options.as_bytes())).eq_ignore_ascii_case(&cmdline.sha256)
                    || !b.load_options_sha256.eq_ignore_ascii_case(&cmdline.sha256)
                {
                    return Err(Error::invalid("UKI embedded .cmdline does not match measured command line"));
                }
                if !b.initrd_sha256.eq_ignore_ascii_case(&initrd.sha256) {
                    return Err(Error::invalid("UKI initrd digest does not match measured .initrd"));
                }
                if b.pcr12_sha256 != "0".repeat(64) {
                    return Err(Error::invalid("UKI profile requires zero PCR 12 (no cmdline override, addon or credentials)"));
                }
                // systemd-stub can append a synthetic initrd (for example
                // carrying .osrel), so Linux's PCR 9 measurement is not the
                // digest of embedded .initrd alone. PCR 9 remains a signed
                // pin checked against a fresh quote and reference log.
            }
            path => return Err(Error::invalid(format!("unknown boot path {path:?}"))),
        }
        Ok(())
    }

    /// A stable identifier: `name@version#svn<N>`.
    pub fn id(&self) -> String {
        format!("{}@{}#svn{}", self.name, self.version, self.svn)
    }

    /// SHA-256 (hex) of the manifest's Go `json.Marshal` encoding.
    pub fn digest(&self) -> String {
        match db_gojson::to_vec(self) {
            Ok(b) => hex::encode(Sha256::digest(&b)),
            // Only unrepresentable times (years outside 0..9999) fail; such a
            // manifest never validates, and an empty digest matches nothing.
            Err(_) => String::new(),
        }
    }

    /// Looks up an approved model.
    pub fn model_by_id(&self, id: &str) -> Option<&Model> {
        self.runtime.models().iter().find(|m| m.id == id)
    }
}
