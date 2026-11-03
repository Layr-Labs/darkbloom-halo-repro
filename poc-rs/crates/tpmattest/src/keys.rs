//! Public keys from TPM public areas and X.509 SubjectPublicKeyInfo, and
//! X.509 signature verification (the algorithms Go's `x509.CheckSignature`
//! accepts: ECDSA, RSA PKCS #1 v1.5, RSA-PSS and Ed25519; SHA-1 refused).

use crate::{Error, Result};
use const_oid::ObjectIdentifier;
use db_tpm2::consts::{ECC_NIST_P256, ECC_NIST_P384};
use db_tpm2::{Public, PublicParams, Unique};
use der::{Decode as _, Encode as _};
use ecdsa::signature::hazmat::PrehashVerifier as _;
use rsa::signature::Verifier as _;
use rsa::traits::PublicKeyParts as _;
use rsa::{BoxedUint, RsaPublicKey};
use sha2::Digest as _;
use spki::{DecodePublicKey as _, EncodePublicKey as _};

/// A public key the verifier understands.
#[derive(Debug, Clone)]
pub enum PublicKey {
    /// ECDSA / ECDH on NIST P-256.
    P256(p256::PublicKey),
    /// ECDSA / ECDH on NIST P-384.
    P384(p384::PublicKey),
    /// RSA.
    Rsa(RsaPublicKey),
    /// Ed25519 (X.509 issuers only).
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::P256(a), Self::P256(b)) => a.to_sec1_bytes() == b.to_sec1_bytes(),
            (Self::P384(a), Self::P384(b)) => a.to_sec1_bytes() == b.to_sec1_bytes(),
            (Self::Rsa(a), Self::Rsa(b)) => a.n() == b.n() && a.e() == b.e(),
            (Self::Ed25519(a), Self::Ed25519(b)) => a == b,
            _ => false,
        }
    }
}

/// Left-pads (or strips leading zeros from) a big-endian integer to `n` bytes.
pub(crate) fn fixed_be(v: &[u8], n: usize) -> Option<Vec<u8>> {
    let first = v.iter().position(|&b| b != 0).unwrap_or(v.len());
    let trimmed = v.get(first..)?;
    if trimmed.len() > n {
        return None;
    }
    let mut out = vec![0u8; n - trimmed.len()];
    out.extend_from_slice(trimmed);
    Some(out)
}

pub(crate) const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
pub(crate) const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
pub(crate) const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
pub(crate) const OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
pub(crate) const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const OID_SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_SHA384_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_SHA512_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const OID_RSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
const OID_MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }

    fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        match *oid {
            OID_SHA256 => Some(Self::Sha256),
            OID_SHA384 => Some(Self::Sha384),
            OID_SHA512 => Some(Self::Sha512),
            _ => None,
        }
    }

    fn size(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

impl PublicKey {
    /// The public key of a TPM RSA or ECC (P-256/P-384) object.
    pub fn from_tpm(p: &Public) -> Result<Self> {
        match (&p.params, &p.unique) {
            (PublicParams::Ecc(e), Unique::Ecc { x, y }) => {
                let size = match e.curve_id {
                    ECC_NIST_P256 => 32,
                    ECC_NIST_P384 => 48,
                    c => return Err(Error::Invalid(format!("unsupported ECC curve 0x{c:04x}"))),
                };
                let bad = || Error::Invalid("ECC point is not on the curve".to_owned());
                let mut sec1 = vec![4u8];
                sec1.extend(fixed_be(x, size).ok_or_else(bad)?);
                sec1.extend(fixed_be(y, size).ok_or_else(bad)?);
                if size == 32 {
                    p256::PublicKey::from_sec1_bytes(&sec1).map(Self::P256).map_err(|_| bad())
                } else {
                    p384::PublicKey::from_sec1_bytes(&sec1).map(Self::P384).map_err(|_| bad())
                }
            }
            (PublicParams::Rsa(r), Unique::Rsa(n)) => {
                let exp = if r.exponent == 0 { 65537 } else { r.exponent };
                let bits = u32::try_from(n.len() * 8).map_err(|_| Error::Invalid("RSA modulus too large".to_owned()))?;
                let n = BoxedUint::from_be_slice(n, bits).map_err(|_| Error::Invalid("RSA modulus".to_owned()))?;
                let e = BoxedUint::from(u64::from(exp));
                RsaPublicKey::new(n, e).map(Self::Rsa).map_err(|e| Error::Invalid(format!("RSA public key: {e}")))
            }
            _ => Err(Error::Invalid("public parameters and unique field disagree".to_owned())),
        }
    }

    /// Parses a DER SubjectPublicKeyInfo. Unknown algorithms yield `None`.
    pub fn from_spki_der(der: &[u8]) -> Result<Option<Self>> {
        let spki = spki::SubjectPublicKeyInfoRef::from_der(der).map_err(|e| Error::Invalid(format!("public key: {e}")))?;
        let bad = |e: &dyn std::fmt::Display| Error::Invalid(format!("public key: {e}"));
        Ok(match spki.algorithm.oid {
            OID_EC_PUBLIC_KEY => {
                let curve: ObjectIdentifier = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .ok_or_else(|| Error::Invalid("EC public key without curve".to_owned()))?
                    .decode_as()
                    .map_err(|e| bad(&e))?;
                match curve {
                    OID_P256 => Some(Self::P256(p256::PublicKey::from_public_key_der(der).map_err(|e| bad(&e))?)),
                    OID_P384 => Some(Self::P384(p384::PublicKey::from_public_key_der(der).map_err(|e| bad(&e))?)),
                    _ => None,
                }
            }
            OID_RSA => Some(Self::Rsa(RsaPublicKey::from_public_key_der(der).map_err(|e| bad(&e))?)),
            OID_ED25519 => {
                let raw: [u8; 32] = spki
                    .subject_public_key
                    .as_bytes()
                    .ok_or_else(|| Error::Invalid("Ed25519 key".to_owned()))?
                    .try_into()
                    .map_err(|_| Error::Invalid("Ed25519 key".to_owned()))?;
                Some(Self::Ed25519(ed25519_dalek::VerifyingKey::from_bytes(&raw).map_err(|e| bad(&e))?))
            }
            _ => None,
        })
    }

    /// The PKIX (SubjectPublicKeyInfo) DER encoding, as Go's
    /// `x509.MarshalPKIXPublicKey`.
    pub fn to_spki_der(&self) -> Result<Vec<u8>> {
        let doc = match self {
            Self::P256(k) => k.to_public_key_der(),
            Self::P384(k) => k.to_public_key_der(),
            Self::Rsa(k) => k.to_public_key_der(),
            Self::Ed25519(k) => {
                // SEQUENCE { SEQUENCE { id-Ed25519 }, BIT STRING key }
                let mut out = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
                out.extend_from_slice(k.as_bytes());
                return Ok(out);
            }
        }
        .map_err(|e| Error::Invalid(format!("encode public key: {e}")))?;
        Ok(doc.as_bytes().to_vec())
    }

    /// A short description for logs ("ecdsa-P-256", "rsa-2048").
    pub fn key_type(&self) -> String {
        match self {
            Self::P256(_) => "ecdsa-P-256".to_owned(),
            Self::P384(_) => "ecdsa-P-384".to_owned(),
            Self::Rsa(k) => format!("rsa-{}", k.n().bits()),
            Self::Ed25519(_) => "unknown".to_owned(),
        }
    }

    /// RSA modulus size in bits (0 for other keys).
    pub fn rsa_bits(&self) -> u32 {
        match self {
            Self::Rsa(k) => k.n().bits(),
            _ => 0,
        }
    }

    /// Verifies an ECDSA signature (r, s big-endian) over a prehashed message.
    pub(crate) fn verify_ecdsa_prehash(&self, digest: &[u8], r: &[u8], s: &[u8]) -> bool {
        match self {
            Self::P256(k) => {
                let (Some(r), Some(s)) = (fixed_be(r, 32), fixed_be(s, 32)) else { return false };
                let (Ok(r), Ok(s)) = (<[u8; 32]>::try_from(r), <[u8; 32]>::try_from(s)) else { return false };
                let Ok(sig) = p256::ecdsa::Signature::from_scalars(r, s) else { return false };
                p256::ecdsa::VerifyingKey::from(k).verify_prehash(digest, &sig).is_ok()
            }
            Self::P384(k) => {
                let (Some(r), Some(s)) = (fixed_be(r, 48), fixed_be(s, 48)) else { return false };
                let (Ok(r), Ok(s)) = (<[u8; 48]>::try_from(r), <[u8; 48]>::try_from(s)) else { return false };
                let Ok(sig) = p384::ecdsa::Signature::from_scalars(r, s) else { return false };
                p384::ecdsa::VerifyingKey::from(k).verify_prehash(digest, &sig).is_ok()
            }
            _ => false,
        }
    }

    /// Verifies an RSASSA-PKCS1-v1_5 SHA-256 signature over `msg`.
    pub(crate) fn verify_rsassa_sha256(&self, msg: &[u8], sig: &[u8]) -> bool {
        let Self::Rsa(k) = self else { return false };
        let Ok(sig) = rsa::pkcs1v15::Signature::try_from(sig) else { return false };
        rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(k.clone()).verify(msg, &sig).is_ok()
    }

    /// Verifies an X.509 signature by this (issuer) key over `tbs`, for the
    /// signature algorithm `alg` with DER `params`.
    pub fn verify_x509(&self, alg: &ObjectIdentifier, params: Option<&[u8]>, tbs: &[u8], sig: &[u8]) -> bool {
        let ecdsa_hash = match *alg {
            OID_ECDSA_SHA256 => Some(Hash::Sha256),
            OID_ECDSA_SHA384 => Some(Hash::Sha384),
            OID_ECDSA_SHA512 => Some(Hash::Sha512),
            _ => None,
        };
        if let Some(h) = ecdsa_hash {
            let digest = h.digest(tbs);
            return match self {
                Self::P256(k) => p256::ecdsa::Signature::from_der(sig)
                    .is_ok_and(|s| p256::ecdsa::VerifyingKey::from(k).verify_prehash(&digest, &s).is_ok()),
                Self::P384(k) => p384::ecdsa::Signature::from_der(sig)
                    .is_ok_and(|s| p384::ecdsa::VerifyingKey::from(k).verify_prehash(&digest, &s).is_ok()),
                _ => false,
            };
        }
        match (*alg, self) {
            (OID_SHA256_RSA | OID_SHA384_RSA | OID_SHA512_RSA, Self::Rsa(k)) => {
                let Ok(sig) = rsa::pkcs1v15::Signature::try_from(sig) else { return false };
                match *alg {
                    OID_SHA256_RSA => rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(k.clone()).verify(tbs, &sig).is_ok(),
                    OID_SHA384_RSA => rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(k.clone()).verify(tbs, &sig).is_ok(),
                    _ => rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(k.clone()).verify(tbs, &sig).is_ok(),
                }
            }
            (OID_RSA_PSS, Self::Rsa(k)) => {
                let Some(h) = params.and_then(pss_hash) else { return false };
                let Ok(sig) = rsa::pss::Signature::try_from(sig) else { return false };
                match h {
                    Hash::Sha256 => rsa::pss::VerifyingKey::<sha2::Sha256>::new(k.clone()).verify(tbs, &sig).is_ok(),
                    Hash::Sha384 => rsa::pss::VerifyingKey::<sha2::Sha384>::new(k.clone()).verify(tbs, &sig).is_ok(),
                    Hash::Sha512 => rsa::pss::VerifyingKey::<sha2::Sha512>::new(k.clone()).verify(tbs, &sig).is_ok(),
                }
            }
            (OID_ED25519, Self::Ed25519(k)) => ed25519_dalek::Signature::from_slice(sig).is_ok_and(|s| k.verify_strict(tbs, &s).is_ok()),
            _ => false,
        }
    }
}

/// Accepts only the three RSA-PSS parameter sets Go's x509 recognizes:
/// MGF1 with the message hash, salt length equal to the hash length and the
/// default trailer field.
fn pss_hash(params: &[u8]) -> Option<Hash> {
    let p: rsa::pkcs1::RsaPssParams<der::Any> = rsa::pkcs1::RsaPssParams::from_der(params).ok()?;
    let h = Hash::from_oid(&p.hash.oid)?;
    let null_or_absent = |a: &Option<der::Any>| a.as_ref().is_none_or(|v| v.is_null());
    if !null_or_absent(&p.hash.parameters) || p.mask_gen.oid != OID_MGF1 {
        return None;
    }
    let mgf_hash = p.mask_gen.parameters.as_ref()?;
    if mgf_hash.oid != p.hash.oid || !null_or_absent(&mgf_hash.parameters) {
        return None;
    }
    if usize::from(p.salt_len) != h.size() || p.trailer_field != rsa::pkcs1::TrailerField::BC {
        return None;
    }
    // Re-encode to make sure the parameters were DER.
    (p.to_der().ok()? == params).then_some(h)
}
