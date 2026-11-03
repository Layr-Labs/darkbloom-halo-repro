//! DSSE envelopes, release keys and the verifier's release policy.

use crate::manifest::{Manifest, PAYLOAD_TYPE};
use crate::{Error, Result, random_bytes};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use db_gojson::GoTime;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use zeroize::Zeroizing;

/// A DSSE envelope (<https://github.com/secure-systems-lab/dsse>), the same
/// format Keylime uses for signed runtime policies.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Envelope {
    /// Payload type.
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// Base64 payload.
    pub payload: String,
    /// Signatures.
    #[serde(with = "db_gojson::nil_vec")]
    pub signatures: Vec<Signature>,
}

/// One DSSE signature.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Signature {
    /// Key identifier ([`key_id`]).
    pub keyid: String,
    /// Base64 Ed25519 signature.
    pub sig: String,
}

/// DSSE's pre-authentication encoding.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!("DSSEv1 {} {} {} ", payload_type.len(), payload_type, payload.len()).into_bytes();
    out.extend_from_slice(payload);
    out
}

/// A key identifier: hex of the first 8 bytes of SHA-256 over the Ed25519
/// public key.
pub fn key_id(public: &VerifyingKey) -> String {
    hex::encode(Sha256::digest(public.as_bytes()).get(..8).unwrap_or_default())
}

/// Wraps a payload in an envelope signed by `key`.
pub fn sign(payload_type: &str, payload: &[u8], key: &SigningKey) -> Envelope {
    let sig = key.sign(&pae(payload_type, payload));
    Envelope {
        payload_type: payload_type.to_owned(),
        payload: STANDARD.encode(payload),
        signatures: vec![Signature { keyid: key_id(&key.verifying_key()), sig: STANDARD.encode(sig.to_bytes()) }],
    }
}

/// Release-signing public keys by key ID.
pub type TrustedKeys = BTreeMap<String, VerifyingKey>;

impl Envelope {
    /// Checks that at least `threshold` distinct trusted keys signed the
    /// envelope over `payload_type`, and returns the payload.
    pub fn verify(&self, payload_type: &str, keys: &TrustedKeys, threshold: usize) -> Result<Vec<u8>> {
        if self.payload_type != payload_type {
            return Err(Error::invalid(format!("payload type {:?}, want {:?}", self.payload_type, payload_type)));
        }
        let payload = STANDARD.decode(self.payload.as_bytes()).map_err(|_| Error::invalid("payload is not base64"))?;
        let threshold = threshold.max(1);
        let pae = pae(&self.payload_type, &payload);
        let mut seen = BTreeSet::new();
        for s in &self.signatures {
            let Some(public) = keys.get(&s.keyid) else { continue };
            if seen.contains(&s.keyid) {
                continue;
            }
            let Ok(raw) = STANDARD.decode(s.sig.as_bytes()) else { continue };
            let Ok(sig) = ed25519_dalek::Signature::from_slice(&raw) else { continue };
            if public.verify_strict(&pae, &sig).is_ok() {
                seen.insert(s.keyid.clone());
            }
        }
        if seen.len() < threshold {
            return Err(Error::invalid(format!("{} valid signatures from trusted keys, need {}", seen.len(), threshold)));
        }
        Ok(payload)
    }
}

/// Validates and signs a manifest (payload: its Go JSON encoding).
pub fn sign_manifest(m: &Manifest, key: &SigningKey) -> Result<Envelope> {
    m.validate()?;
    let payload = db_gojson::to_vec(m)?;
    Ok(sign(PAYLOAD_TYPE, &payload, key))
}

/// Verifies a signed manifest envelope and strictly decodes it (unknown
/// fields and trailing data are rejected). It does not apply the SVN floor,
/// expiry or revocation; [`Policy::admit`] does.
pub fn open_manifest(env: &Envelope, keys: &TrustedKeys, threshold: usize) -> Result<Manifest> {
    let payload = env.verify(PAYLOAD_TYPE, keys, threshold)?;
    let m: Manifest = db_gojson::from_slice(&payload).map_err(|e| Error::invalid(format!("manifest: {e}")))?;
    m.validate()?;
    Ok(m)
}

/// The verifier's release policy: trusted keys and signature threshold, the
/// security-version floor (signatures alone do not stop downgrades),
/// revocations, the dev channel switch and the transparency requirement.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Trusted release keys.
    pub keys: TrustedKeys,
    /// Signatures required (0 means 1).
    pub threshold: usize,
    /// Security-version floor.
    pub min_svn: u32,
    /// Revoked manifest IDs or digests.
    pub revoked: BTreeSet<String>,
    /// Accept `dev` channel releases (never in production).
    pub allow_dev: bool,
    /// Require inclusion in the release log.
    pub require_logged: bool,
}

impl Policy {
    /// The effective signature threshold.
    pub fn threshold(&self) -> usize {
        self.threshold.max(1)
    }

    /// Opens a manifest envelope under this policy's keys and threshold.
    pub fn open(&self, env: &Envelope) -> Result<Manifest> {
        open_manifest(env, &self.keys, self.threshold())
    }

    /// Applies the floor, expiry, channel and revocation rules.
    pub fn admit(&self, m: &Manifest, now: &GoTime) -> Result<()> {
        if m.svn < self.min_svn {
            return Err(Error::invalid(format!("{} is below the security-version floor {}", m.id(), self.min_svn)));
        }
        if now.after(&m.expires_at) {
            return Err(Error::invalid(format!("{} expired at {}", m.id(), m.expires_at.rfc3339())));
        }
        if now.before(&m.issued_at.add(chrono::Duration::minutes(-5))) {
            return Err(Error::invalid(format!("{} is not yet valid", m.id())));
        }
        if m.channel == "dev" && !self.allow_dev {
            return Err(Error::invalid(format!("{} is a dev release", m.id())));
        }
        if self.revoked.contains(&m.id()) || self.revoked.contains(&m.digest()) {
            return Err(Error::invalid(format!("{} is revoked", m.id())));
        }
        Ok(())
    }
}

fn write_file(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = opts.open(path).map_err(|e| Error::io(path, e))?;
    f.write_all(data).map_err(|e| Error::io(path, e))
}

/// Writes an Ed25519 private key as a hex seed file (mode 0600).
pub fn write_private_key(path: &Path, key: &SigningKey) -> Result<()> {
    let mut text = Zeroizing::new(hex::encode(key.to_bytes()));
    text.push('\n');
    write_file(path, text.as_bytes(), 0o600)
}

/// Generates an Ed25519 key pair and writes `<prefix>.key` (hex seed, 0600)
/// and `<prefix>.pub` (hex public key). Production keys belong in an HSM.
pub fn generate_key(prefix: &str) -> Result<VerifyingKey> {
    let seed = Zeroizing::new(random_bytes::<32>()?);
    let key = SigningKey::from_bytes(&seed);
    write_private_key(Path::new(&format!("{prefix}.key")), &key)?;
    let public = key.verifying_key();
    write_file(Path::new(&format!("{prefix}.pub")), format!("{}\n", hex::encode(public.as_bytes())).as_bytes(), 0o644)?;
    Ok(public)
}

/// Reads a hex Ed25519 seed file.
pub fn load_private_key(path: &Path) -> Result<SigningKey> {
    let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?);
    let seed = Zeroizing::new(hex::decode(text.trim()).unwrap_or_default());
    let seed: &[u8; 32] =
        seed.as_slice().try_into().map_err(|_| Error::invalid(format!("{} is not a hex Ed25519 seed", path.display())))?;
    Ok(SigningKey::from_bytes(seed))
}

/// Reads a hex Ed25519 public key file.
pub fn load_public_key(path: &Path) -> Result<VerifyingKey> {
    let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
    let raw = hex::decode(text.trim()).unwrap_or_default();
    let raw: [u8; 32] = raw.try_into().map_err(|_| Error::invalid(format!("{} is not a hex Ed25519 public key", path.display())))?;
    VerifyingKey::from_bytes(&raw).map_err(|_| Error::invalid(format!("{} is not a hex Ed25519 public key", path.display())))
}
