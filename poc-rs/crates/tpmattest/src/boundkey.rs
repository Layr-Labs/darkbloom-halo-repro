//! TPM-bound decryption.
//!
//! Attestation alone says "this job key lives in an approved Node OS". A
//! bound key makes the TPM enforce it: each session the provider creates a
//! TPM-resident ECC P-256 decryption key whose authorization policy is
//! PolicyPCR over the attested boot state, with no password path
//! (userWithAuth clear). Consumers mix an ECDH with that key into HPKE as the
//! pre-shared key, so opening a job needs both the in-memory HPKE key and the
//! TPM performing ECDH while the PCRs still hold the attested values. A RAM
//! dump (no TSME) or a different boot cannot decrypt recorded jobs, and the
//! AK's TPM2_Certify proves the key is TPM-resident with exactly that policy.

use crate::keys::PublicKey;
use crate::quote::{AttestationKey, pcr_digest, verify_certify};
use crate::{Error, Result};
use db_tpm2::consts::{
    ALG_ECC, ALG_SHA256, OBJ_DECRYPT, OBJ_FIXED_PARENT, OBJ_FIXED_TPM, OBJ_RESTRICTED, OBJ_SENSITIVE_DATA_ORIGIN, OBJ_SIGN_ENCRYPT,
    OBJ_USER_WITH_AUTH,
};
use db_tpm2::{PcrSelection, PcrSelectionList, Public};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

/// TPM_CC_PolicyPCR.
pub const CC_POLICY_PCR: u32 = 0x0000_017F;

const BOUND_KEY_DOMAIN: &str = "darkbloom-amd/bound-key/v1";

/// The provider's TPM-resident ECDH key, as published in its statement.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BoundKey {
    /// TPMT_PUBLIC of the key.
    #[serde(with = "db_gojson::b64")]
    pub public: Vec<u8>,
    /// PolicyPCR selection (SHA-256 bank).
    #[serde(with = "db_gojson::nil_vec")]
    pub pcrs: Vec<i64>,
    /// TPMS_ATTEST of the AK's TPM2_Certify.
    #[serde(with = "db_gojson::b64")]
    pub certify_attest: Vec<u8>,
    /// TPMT_SIGNATURE of the certification.
    #[serde(with = "db_gojson::b64")]
    pub certify_sig: Vec<u8>,
}

/// The qualifying data the AK signs when certifying a bound key: it ties the
/// certification to one provider session.
pub fn bound_key_certify_data(provider_id: &str, session_id: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(BOUND_KEY_DOMAIN.as_bytes());
    h.update([0u8]);
    h.update(provider_id.as_bytes());
    h.update([0u8]);
    h.update(session_id.as_bytes());
    h.finalize().to_vec()
}

/// The policy digest of a single TPM2_PolicyPCR over the SHA-256 bank:
/// `H(0^32 || TPM_CC_PolicyPCR || TPML_PCR_SELECTION || H(selected values in
/// ascending order))` (TPM 2.0 Part 3, 23.7).
pub fn policy_pcr_digest(pcrs: &[u32], values: &BTreeMap<u32, Vec<u8>>) -> Result<Vec<u8>> {
    let digest = pcr_digest(values, pcrs)?;
    let sel = PcrSelectionList(vec![PcrSelection::new(ALG_SHA256, pcrs)]).to_bytes().map_err(|e| Error::Invalid(e.to_string()))?;
    let mut h = Sha256::new();
    h.update([0u8; 32]);
    h.update(CC_POLICY_PCR.to_be_bytes());
    h.update(&sel);
    h.update(&digest);
    Ok(h.finalize().to_vec())
}

fn bad(msg: &str) -> Error {
    Error::Invalid(msg.to_owned())
}

/// Checks a bound key against a verified AK and the PCR values the quote
/// attested, and returns its P-256 ECDH public key.
pub fn verify_bound_key(
    bk: &BoundKey,
    ak: &AttestationKey,
    quoted: &BTreeMap<u32, Vec<u8>>,
    provider_id: &str,
    session_id: &str,
) -> Result<p256::PublicKey> {
    // The policy must cover exactly the attested PCRs: a key bound to fewer
    // (say PCR 0 alone) is also usable from another OS on the same firmware.
    if bk.pcrs.len() != quoted.len() {
        let list: Vec<String> = bk.pcrs.iter().map(i64::to_string).collect();
        return Err(Error::Invalid(format!("bound key policy covers PCRs [{}], not the attested set", list.join(" "))));
    }
    let mut seen = std::collections::BTreeSet::new();
    for &p in &bk.pcrs {
        if !seen.insert(p) {
            return Err(Error::Invalid(format!("bound key policy repeats PCR {p}")));
        }
    }
    let public = Public::parse(&bk.public).map_err(|e| Error::Invalid(format!("bound key: {e}")))?;
    if public.alg_type() != ALG_ECC || public.name_alg != ALG_SHA256 {
        return Err(bad("bound key must be ECC with a SHA-256 name"));
    }
    if !public.has(OBJ_FIXED_TPM | OBJ_FIXED_PARENT | OBJ_SENSITIVE_DATA_ORIGIN) {
        return Err(bad("bound key must be generated in and never leave the TPM"));
    }
    if !public.has(OBJ_DECRYPT) || public.has(OBJ_SIGN_ENCRYPT) || public.has(OBJ_RESTRICTED) {
        return Err(bad("bound key must be an unrestricted decryption (ECDH) key"));
    }
    if public.has(OBJ_USER_WITH_AUTH) {
        // With userWithAuth set, the (empty) password would authorize ECDH
        // without satisfying the PCR policy.
        return Err(bad("bound key is usable with a password (userWithAuth)"));
    }
    if bk.pcrs.is_empty() {
        return Err(bad("bound key policy selects no PCRs"));
    }
    let mut pcrs = Vec::with_capacity(bk.pcrs.len());
    for &p in &bk.pcrs {
        match u32::try_from(p).ok().filter(|p| quoted.contains_key(p)) {
            Some(p) => pcrs.push(p),
            None => return Err(Error::Invalid(format!("bound key policy covers PCR {p}, which the quote does not attest"))),
        }
    }
    let want = policy_pcr_digest(&pcrs, quoted)?;
    if public.auth_policy != want {
        return Err(bad("bound key policy is not PolicyPCR over the attested PCR values"));
    }
    let name = public.name().map_err(|e| Error::Invalid(e.to_string()))?;
    let cert = verify_certify(ak, &bk.certify_attest, &bk.certify_sig, &bound_key_certify_data(provider_id, session_id))
        .map_err(|e| Error::Invalid(format!("bound key certification: {e}")))?;
    if cert.object_name != name {
        return Err(bad("the AK certified a different object"));
    }
    match PublicKey::from_tpm(&public) {
        Ok(PublicKey::P256(k)) => Ok(k),
        _ => Err(bad("bound key must be on P-256")),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn policy_digest_layout() {
        let values: BTreeMap<u32, Vec<u8>> = [(0u32, vec![1u8; 32]), (7, vec![2u8; 32])].into_iter().collect();
        let got = policy_pcr_digest(&[7, 0], &values).unwrap();
        let mut sel = vec![0, 0, 0, 1, 0, 0x0b, 3, 0x81, 0, 0];
        let pcr = Sha256::digest([vec![1u8; 32], vec![2u8; 32]].concat());
        let mut pre = vec![0u8; 32];
        pre.extend_from_slice(&[0, 0, 1, 0x7f]);
        pre.append(&mut sel);
        pre.extend_from_slice(&pcr);
        assert_eq!(got, Sha256::digest(&pre).to_vec());
        assert!(policy_pcr_digest(&[1], &values).is_err(), "missing PCR value accepted");
        let d = bound_key_certify_data("p", "s");
        assert_eq!(d, Sha256::digest(b"darkbloom-amd/bound-key/v1\0p\0s").to_vec());
    }
}
