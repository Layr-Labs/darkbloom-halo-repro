//! Endorsement-key certificate chains to pinned AMD (or development) roots.

use crate::keys::PublicKey;
use crate::x509::{Certificate, KEY_USAGE_CERT_SIGN, parse_certificates};
use crate::{Error, Result};
use db_gojson::GoTime;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use std::path::Path;

/// A family of TPM endorsement roots.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RootKind {
    /// The Microsoft Pluton TPM on 2025 AMD client silicon (Strix Halo),
    /// certified under AMD's Pluton Global Factory ICA.
    AmdPluton,
    /// AMD's firmware TPM (2026+ AMD client silicon); anchors configured.
    AmdFtpm,
    /// A locally generated CA for swtpm-based development. Never accepted
    /// for production traffic.
    DevSimulated,
    /// Any other value received over the wire.
    Other(String),
}

impl RootKind {
    /// The wire string.
    pub fn as_str(&self) -> &str {
        match self {
            Self::AmdPluton => "amd-pluton",
            Self::AmdFtpm => "amd-ftpm",
            Self::DevSimulated => "dev-simulated",
            Self::Other(s) => s,
        }
    }

    /// Parses the wire string.
    pub fn parse(s: &str) -> Self {
        match s {
            "amd-pluton" => Self::AmdPluton,
            "amd-ftpm" => Self::AmdFtpm,
            "dev-simulated" => Self::DevSimulated,
            other => Self::Other(other.to_owned()),
        }
    }
}

impl std::fmt::Display for RootKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for RootKind {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RootKind {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s: String = db_gojson::null_default(d)?;
        Ok(Self::parse(&s))
    }
}

/// The SHA-256 pin of the AMD Pluton Global Factory ICA (fetched from
/// ftpm.amd.com on 2026-10-18; see certs/amd-pluton/README.md). Its issuer,
/// "AMD Root CA R4", is unpublished, so this ICA is the anchor.
pub const PLUTON_GLOBAL_FACTORY_ICA_SHA256: &str = "593a1794f9e17476c7ad427d2908a97c451451c9e0939fdc80d5d662c232d401";

const MAX_CHAIN_DEPTH: usize = 8;

/// One accepted endorsement root.
#[derive(Debug, Clone)]
pub struct TrustRoot {
    /// Display name.
    pub name: String,
    /// Root family.
    pub kind: RootKind,
    /// Anchor certificates (each pinned by `anchor_sha256`).
    pub anchors: Vec<Certificate>,
    /// Pinned anchor fingerprints.
    pub anchor_sha256: Vec<String>,
    /// Public intermediates (for Pluton: the per-product EK ICAs).
    pub intermediates: Vec<Certificate>,
    /// Minimum firmware security version, when the root encodes one.
    pub min_svn: i64,
    /// Whether the root may carry production traffic.
    pub production: bool,
}

/// The set of endorsement roots a verifier accepts.
#[derive(Debug, Clone, Default)]
pub struct TrustBundle {
    /// Accepted roots, tried in order.
    pub roots: Vec<TrustRoot>,
}

/// The outcome of a successful EK chain verification.
#[derive(Debug, Clone)]
pub struct EkChain {
    /// Index of the root in the bundle.
    pub root_index: usize,
    /// Root name.
    pub root_name: String,
    /// Root kind.
    pub root_kind: RootKind,
    /// Whether the root is a production root.
    pub production: bool,
    /// Leaf first, anchor last.
    pub path: Vec<Certificate>,
    /// Stable per-chip identity.
    pub device_id: String,
    /// Pluton firmware SVN, or -1 if the root does not encode one.
    pub svn: i64,
    /// TPM firmware version from the EK subject, if present.
    pub firmware: String,
}

/// Lowercase hex SHA-256 of a certificate's DER.
pub fn cert_fingerprint(c: &Certificate) -> String {
    c.fingerprint()
}

fn key_id_links(child: &Certificate, parent: &Certificate) -> bool {
    if child.authority_key_id.is_empty() || parent.subject_key_id.is_empty() {
        // Without key identifiers we rely on the signature alone.
        return true;
    }
    child.authority_key_id == parent.subject_key_id
}

/// Finds the first `SVN<digits>` in `s` (Go regexp `SVN(\d+)`).
fn svn_in(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let mut from = 0;
    while let Some(pos) = s.get(from..).and_then(|t| t.find("SVN")) {
        let start = from + pos + 3;
        let digits: String = b.get(start..).unwrap_or_default().iter().take_while(|c| c.is_ascii_digit()).map(|&c| char::from(c)).collect();
        if !digits.is_empty() {
            return digits.parse().ok();
        }
        from = start;
    }
    None
}

/// Matches `^PlutonId\s+([0-9A-Za-z+/=_-]+)$`.
fn pluton_id(cn: &str) -> Option<&str> {
    let rest = cn.strip_prefix("PlutonId")?;
    let id = rest.trim_start_matches(['\t', '\n', '\x0c', '\r', ' ']);
    if id.len() == rest.len() || id.is_empty() {
        return None;
    }
    id.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=' | b'_' | b'-')).then_some(id)
}

impl TrustRoot {
    fn is_anchor(&self, c: &Certificate) -> bool {
        let fp = c.fingerprint();
        self.anchor_sha256.iter().any(|w| w.eq_ignore_ascii_case(&fp))
    }

    fn build_path(&self, leaf: &Certificate, device: &[Certificate], now: &GoTime) -> Result<Vec<Certificate>> {
        let candidates: Vec<&Certificate> = device.iter().chain(&self.intermediates).chain(&self.anchors).collect();
        let mut path = vec![leaf.clone()];
        let mut cur = leaf.clone();
        for _ in 0..MAX_CHAIN_DEPTH {
            if self.is_anchor(&cur) {
                if !cur.valid_at(now) {
                    return Err(Error::Invalid(format!("pinned anchor {:?} is not valid now", cur.subject_cn)));
                }
                return Ok(path);
            }
            let mut next = None;
            let mut expired = false;
            for c in &candidates {
                if c.raw == cur.raw {
                    continue;
                }
                if !(c.basic_constraints_valid && c.is_ca) {
                    continue;
                }
                if c.key_usage != 0 && c.key_usage & KEY_USAGE_CERT_SIGN == 0 {
                    continue;
                }
                if !key_id_links(&cur, c) || !cur.signed_by(c) {
                    continue;
                }
                if !c.valid_at(now) {
                    expired = true;
                    continue;
                }
                next = Some((*c).clone());
                break;
            }
            let Some(next) = next else {
                if expired {
                    return Err(Error::Invalid(format!("the issuer of {:?} is not valid now", cur.subject_cn)));
                }
                return Err(Error::Invalid(format!("no issuer found for {:?} under root {}", cur.subject_cn, self.name)));
            };
            path.push(next.clone());
            cur = next;
        }
        Err(Error::Invalid("EK chain too long".to_owned()))
    }

    fn identity(&self, leaf: &Certificate, path: &[Certificate], ek: &PublicKey) -> (String, i64, String) {
        let mut svn = -1;
        let firmware = leaf.subject_ou.first().cloned().unwrap_or_default();
        if self.kind == RootKind::AmdPluton {
            // Issuing CAs only, never the leaf's PlutonId text.
            for c in path.iter().skip(1) {
                if let Some(v) = svn_in(&c.subject_cn)
                    && c.subject_cn.to_uppercase().contains("PLUTON")
                {
                    svn = v;
                    break;
                }
            }
            if let Some(id) = pluton_id(&leaf.subject_cn) {
                return (format!("pluton:{id}"), svn, firmware);
            }
        }
        match ek.to_spki_der() {
            Ok(der) => {
                let sum = Sha256::digest(&der);
                (format!("{}:ek-{}", self.kind, hex::encode(sum.get(..16).unwrap_or_default())), svn, firmware)
            }
            Err(_) => ("ek:unknown".to_owned(), svn, firmware),
        }
    }
}

impl TrustBundle {
    /// Verifies an EK certificate (DER) and its chain to one of the bundle's
    /// pinned anchors. `device_icas` are certificates read from the TPM's NV
    /// storage (Pluton keeps its per-chip and firmware ICAs there); they are
    /// untrusted and only used if they verify by signature. `tpm_ek` must be
    /// the public key of the EK the TPM actually holds.
    pub fn verify_ek(&self, ek_cert_der: &[u8], device_icas: &[Vec<u8>], tpm_ek: &PublicKey, now: &GoTime) -> Result<EkChain> {
        let leaf = Certificate::parse(ek_cert_der).map_err(|e| Error::Invalid(format!("EK certificate: {e}")))?;
        if leaf.basic_constraints_valid && leaf.is_ca {
            return Err(Error::Invalid("EK certificate is a CA certificate".to_owned()));
        }
        if !leaf.valid_at(now) {
            return Err(Error::Invalid("EK certificate is not valid now".to_owned()));
        }
        if leaf.public_key.as_ref() != Some(tpm_ek) {
            return Err(Error::Invalid("EK certificate does not certify the TPM's endorsement key".to_owned()));
        }
        let mut device = Vec::with_capacity(device_icas.len());
        for (i, der) in device_icas.iter().enumerate() {
            device.push(Certificate::parse(der).map_err(|e| Error::Invalid(format!("device ICA {i}: {e}")))?);
        }
        let mut last_err = Error::Invalid("EK chain does not reach a pinned anchor".to_owned());
        for (i, root) in self.roots.iter().enumerate() {
            let path = match root.build_path(&leaf, &device, now) {
                Ok(p) => p,
                Err(e) => {
                    last_err = e;
                    continue;
                }
            };
            let (device_id, svn, firmware) = root.identity(&leaf, &path, tpm_ek);
            if root.min_svn > 0 && svn < root.min_svn {
                return Err(Error::Invalid(format!("TPM firmware SVN {svn} is below the minimum {}", root.min_svn)));
            }
            return Ok(EkChain {
                root_index: i,
                root_name: root.name.clone(),
                root_kind: root.kind.clone(),
                production: root.production,
                path,
                device_id,
                svn,
                firmware,
            });
        }
        Err(last_err)
    }
}

/// Reads PEM or DER certificates from files.
pub fn load_certificates<P: AsRef<Path>>(paths: &[P]) -> Result<Vec<Certificate>> {
    let mut out = Vec::new();
    for p in paths {
        let p = p.as_ref();
        let data = std::fs::read(p).map_err(|e| Error::Invalid(format!("{}: {e}", p.display())))?;
        out.extend(parse_certificates(&data).map_err(|e| Error::Invalid(format!("{}: {e}", p.display())))?);
    }
    Ok(out)
}

/// Loads the AMD Pluton root from a directory holding the Global Factory ICA
/// (the pinned anchor) and AMD's per-product EK ICAs, as in
/// darkbloom-amd/certs/amd-pluton. The anchor must match the pinned hash.
pub fn pluton_root(dir: &Path, min_svn: i64) -> Result<TrustRoot> {
    let anchors = load_certificates(&[dir.join("amd-pluton-global-factory-ica.pem")])?;
    match anchors.as_slice() {
        [a] if a.fingerprint() == PLUTON_GLOBAL_FACTORY_ICA_SHA256 => {}
        _ => return Err(Error::Invalid("Pluton Global Factory ICA does not match the pinned fingerprint".to_owned())),
    }
    let mut ica_files: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| Error::Invalid(format!("{}: {e}", dir.display())))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("amd-pluton-") && n.ends_with("-ek-ica.pem")))
        .collect();
    ica_files.sort();
    let intermediates = load_certificates(&ica_files)?;
    Ok(TrustRoot {
        name: "AMD Pluton Global Factory ICA".to_owned(),
        kind: RootKind::AmdPluton,
        anchors,
        anchor_sha256: vec![PLUTON_GLOBAL_FACTORY_ICA_SHA256.to_owned()],
        intermediates,
        min_svn,
        production: true,
    })
}

/// Builds a root from anchor certificates pinned by their own fingerprints
/// (AMD fTPM roots or development CAs supplied as files).
pub fn pinned_root(name: &str, kind: RootKind, anchors: Vec<Certificate>, intermediates: Vec<Certificate>, production: bool) -> TrustRoot {
    let anchor_sha256 = anchors.iter().map(Certificate::fingerprint).collect();
    TrustRoot { name: name.to_owned(), kind, anchors, anchor_sha256, intermediates, min_svn: 0, production }
}

/// Describes a public key for logs and evidence summaries.
pub fn key_type(k: &PublicKey) -> String {
    k.key_type()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns() {
        assert_eq!(svn_in("PLUTON Firmware SVN06"), Some(6));
        assert_eq!(svn_in("SVN SVN12x"), Some(12));
        assert_eq!(svn_in("no version"), None);
        assert_eq!(pluton_id("PlutonId abc+/=_-9"), Some("abc+/=_-9"));
        assert_eq!(pluton_id("PlutonId\tX"), Some("X"));
        assert_eq!(pluton_id("PlutonIdX"), None);
        assert_eq!(pluton_id("PlutonId "), None);
        assert_eq!(pluton_id("PlutonId a b"), None);
    }
}
