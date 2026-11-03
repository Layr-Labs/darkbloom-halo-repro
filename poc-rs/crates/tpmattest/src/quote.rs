//! Attestation keys and TPM2_Quote / TPM2_Certify verification.

use crate::keys::PublicKey;
use crate::{Error, Result};
use db_tpm2::consts::*;
use db_tpm2::{Attest, Attested, Public, PublicParams, Signature};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use subtle::ConstantTimeEq as _;

/// A verified TPM attestation key public area.
#[derive(Debug, Clone)]
pub struct AttestationKey {
    /// The TPMT_PUBLIC.
    pub public: Public,
    /// Its canonical encoding.
    pub public_raw: Vec<u8>,
    /// TPM2B_NAME contents: `nameAlg || H(TPMT_PUBLIC)`.
    pub name: Vec<u8>,
    /// The public key.
    pub key: PublicKey,
}

/// Parses a TPMT_PUBLIC and checks it is a TPM-resident, restricted signing
/// key, as required for an AK whose signatures can only cover TPM-generated
/// structures. A restricted key cannot sign arbitrary data that starts with
/// TPM_GENERATED_VALUE, which is what makes quotes unforgeable even by
/// someone holding the AK's authorization.
pub fn parse_attestation_key(raw: &[u8]) -> Result<AttestationKey> {
    let public = Public::parse(raw).map_err(|e| Error::Invalid(format!("AK public area: {e}")))?;
    let required = OBJ_FIXED_TPM | OBJ_FIXED_PARENT | OBJ_SENSITIVE_DATA_ORIGIN | OBJ_RESTRICTED | OBJ_SIGN_ENCRYPT;
    if !public.has(required) || public.has(OBJ_DECRYPT) {
        return Err(Error::Invalid("AK must be a fixedTPM, fixedParent, TPM-generated, restricted signing key".to_owned()));
    }
    if public.name_alg != ALG_SHA256 {
        return Err(Error::Invalid("AK name algorithm must be SHA-256".to_owned()));
    }
    let key = PublicKey::from_tpm(&public).map_err(|e| Error::Invalid(format!("AK public key: {e}")))?;
    match (&key, &public.params) {
        (PublicKey::P256(_), PublicParams::Ecc(p)) => {
            if p.scheme.scheme != ALG_ECDSA || p.scheme.hash() != Some(ALG_SHA256) {
                return Err(Error::Invalid("ECC AK must fix ECDSA with SHA-256".to_owned()));
            }
        }
        (PublicKey::P384(_), _) => return Err(Error::Invalid("ECC AK must use P-256".to_owned())),
        (PublicKey::Rsa(_), PublicParams::Rsa(p)) => {
            if key.rsa_bits() < 2048 {
                return Err(Error::Invalid("RSA AK must be at least 2048 bits".to_owned()));
            }
            if p.scheme.scheme != ALG_RSASSA || p.scheme.hash() != Some(ALG_SHA256) {
                return Err(Error::Invalid("RSA AK must fix RSASSA with SHA-256".to_owned()));
            }
        }
        _ => return Err(Error::Invalid("unsupported AK key type".to_owned())),
    }
    let name = public.name().map_err(|e| Error::Invalid(e.to_string()))?;
    Ok(AttestationKey { public, public_raw: raw.to_vec(), name, key })
}

/// The qualified name of a primary object of the endorsement hierarchy with
/// the given (SHA-256) name: `nameAlg || H(TPM_RH_ENDORSEMENT || name)`
/// (TPM 2.0 Part 1, 16.6).
pub fn endorsement_primary_qn(name: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(RH_ENDORSEMENT.to_be_bytes());
    h.update(name);
    let mut out = ALG_SHA256.to_be_bytes().to_vec();
    out.extend_from_slice(&h.finalize());
    out
}

/// A verified TPM2_Quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quote {
    /// Qualifying data.
    pub extra_data: Vec<u8>,
    /// TPM clock (ms).
    pub clock: u64,
    /// TPM resets (reboots) since the endorsement seed was set.
    pub reset_count: u32,
    /// TPM restarts (resume from hibernation) since the last reset.
    pub restart_count: u32,
    /// Whether the clock is "safe".
    pub safe: bool,
    /// TPM firmware version.
    pub firmware_version: u64,
    /// PCR bank.
    pub bank: u16,
    /// Quoted PCR indices (ascending).
    pub pcrs: Vec<u32>,
    /// Digest of the quoted PCR values.
    pub pcr_digest: Vec<u8>,
}

impl Quote {
    /// The firmware version as major.minor.build.rev (Pluton reports e.g.
    /// 10.6.0.4).
    pub fn firmware_string(&self) -> String {
        let f = self.firmware_version;
        format!("{}.{}.{}.{}", f >> 48, (f >> 32) & 0xffff, (f >> 16) & 0xffff, f & 0xffff)
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

impl AttestationKey {
    /// Checks a TPMT_SIGNATURE over `msg` with the AK.
    fn verify_signature(&self, msg: &[u8], sig_raw: &[u8]) -> Result<()> {
        let sig = Signature::parse(sig_raw).map_err(|e| Error::Invalid(format!("signature: {e}")))?;
        let digest = Sha256::digest(msg);
        match &self.key {
            PublicKey::P256(_) => {
                let Signature::Ecc { alg: ALG_ECDSA, hash, r, s } = &sig else {
                    return Err(Error::Invalid("expected an ECDSA signature".to_owned()));
                };
                if *hash != ALG_SHA256 {
                    return Err(Error::Invalid("expected ECDSA with SHA-256".to_owned()));
                }
                if !self.key.verify_ecdsa_prehash(&digest, r, s) {
                    return Err(Error::Invalid("ECDSA signature does not verify".to_owned()));
                }
            }
            PublicKey::Rsa(_) => {
                let Signature::Rsa { alg: ALG_RSASSA, hash, sig } = &sig else {
                    return Err(Error::Invalid("expected an RSASSA signature".to_owned()));
                };
                if *hash != ALG_SHA256 {
                    return Err(Error::Invalid("expected RSASSA with SHA-256".to_owned()));
                }
                if !self.key.verify_rsassa_sha256(msg, sig) {
                    return Err(Error::Invalid("RSA signature does not verify".to_owned()));
                }
            }
            _ => return Err(Error::Invalid("unsupported AK key type".to_owned())),
        }
        Ok(())
    }
}

fn parse_attest(raw: &[u8]) -> Result<Attest> {
    let att = Attest::parse(raw).map_err(|e| Error::Invalid(format!("attestation structure: {e}")))?;
    if att.magic != GENERATED_VALUE {
        return Err(Error::Invalid("attestation was not generated by a TPM".to_owned()));
    }
    Ok(att)
}

/// Verifies a TPM2_Quote signed by `ak`: the signature, the TPM magic, the
/// structure type, the qualified signer and the caller's qualifying data
/// (compared in constant time). It does not judge PCR values; compare
/// [`Quote::pcr_digest`] with a replayed event log for that.
pub fn verify_quote(ak: &AttestationKey, attest_raw: &[u8], sig_raw: &[u8], want_extra_data: &[u8]) -> Result<Quote> {
    ak.verify_signature(attest_raw, sig_raw)?;
    let att = parse_attest(attest_raw)?;
    if att.attest_type != ST_ATTEST_QUOTE {
        return Err(Error::Invalid("attestation is not a quote".to_owned()));
    }
    // The signer must be a primary key of the endorsement hierarchy: keys in
    // other hierarchies get obfuscated resetCount/restartCount in quotes,
    // which would hide reboots from the lease logic.
    if !ct_eq(&att.qualified_signer, &endorsement_primary_qn(&ak.name)) {
        return Err(Error::Invalid("quote signer is not an endorsement-hierarchy primary key".to_owned()));
    }
    if !ct_eq(&att.extra_data, want_extra_data) {
        return Err(Error::Invalid("quote does not carry the expected qualifying data (nonce binding)".to_owned()));
    }
    let Attested::Quote { pcr_select, pcr_digest } = att.attested else {
        return Err(Error::Invalid("attestation is not a quote".to_owned()));
    };
    let [sel] = pcr_select.0.as_slice() else {
        return Err(Error::Invalid("quote must select exactly one PCR bank".to_owned()));
    };
    Ok(Quote {
        extra_data: att.extra_data,
        clock: att.clock,
        reset_count: att.reset_count,
        restart_count: att.restart_count,
        safe: att.safe,
        firmware_version: att.firmware_version,
        bank: sel.hash,
        pcrs: sel.indices(),
        pcr_digest,
    })
}

/// A verified TPM2_Certify: the AK vouches that an object with this name is
/// loaded in the same TPM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certification {
    /// Name of the certified object.
    pub object_name: Vec<u8>,
    /// Qualifying data.
    pub extra_data: Vec<u8>,
    /// resetCount at certification time.
    pub reset_count: u32,
}

/// Verifies a TPM2_Certify signed by `ak`.
pub fn verify_certify(ak: &AttestationKey, attest_raw: &[u8], sig_raw: &[u8], want_extra_data: &[u8]) -> Result<Certification> {
    ak.verify_signature(attest_raw, sig_raw)?;
    let att = parse_attest(attest_raw)?;
    if att.attest_type != ST_ATTEST_CERTIFY {
        return Err(Error::Invalid("attestation is not a certification".to_owned()));
    }
    if !ct_eq(&att.extra_data, want_extra_data) {
        return Err(Error::Invalid("certification does not carry the expected qualifying data".to_owned()));
    }
    let Attested::Certify { name, .. } = att.attested else {
        return Err(Error::Invalid("attestation is not a certification".to_owned()));
    };
    Ok(Certification { object_name: name, extra_data: att.extra_data, reset_count: att.reset_count })
}

/// The digest a TPM quote reports for a PCR selection: SHA-256 of the
/// selected PCR values concatenated in ascending index order.
pub fn pcr_digest(values: &BTreeMap<u32, Vec<u8>>, pcrs: &[u32]) -> Result<Vec<u8>> {
    let mut sorted = pcrs.to_vec();
    sorted.sort_unstable();
    let mut h = Sha256::new();
    for p in sorted {
        let v = values.get(&p).ok_or_else(|| Error::Invalid(format!("no value for PCR {p}")))?;
        h.update(v);
    }
    Ok(h.finalize().to_vec())
}
