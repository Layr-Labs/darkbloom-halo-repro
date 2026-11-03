//! TPM-bound decryption keys (Go `tpmdev/bound.go`): a session-unique,
//! TPM-resident ECC P-256 ECDH key usable only under PolicyPCR over the
//! attested PCR values, its TPM2_Certify by the AK, and the ECDH itself.

use crate::activate::nonce;
use crate::cmd::{Command, Params, policy_session};
use crate::device::{Device, Tpm, signed_attestation};
use crate::{Error, Key, Result};
use db_tpm2::consts::*;
use db_tpm2::{
    AsymScheme, EccParms, KdfScheme, PcrSelection, PcrSelectionList, Public, PublicParams, SchemeDetails, SymDefObject, Unique, Writer,
};
use zeroize::Zeroizing;

/// TPM_CC_Certify.
const CC_CERTIFY: u32 = 0x0000_0148;
/// TPM_CC_ECDH_ZGen.
const CC_ECDH_ZGEN: u32 = 0x0000_0154;
/// TPM_CC_PolicyPCR.
const CC_POLICY_PCR: u32 = 0x0000_017F;
/// P-256 coordinate size.
const P256_BYTES: usize = 32;

/// The bound-key template: an ECC P-256 ECDH(SHA-256) decryption key,
/// fixedTPM|fixedParent|sensitiveDataOrigin|decrypt|noDA. userWithAuth is
/// clear (no password can use it: only `auth_policy`), adminWithPolicy is
/// clear (TPM2_Certify, an admin-role command, may use the empty auth).
pub fn bound_key_template(auth_policy: &[u8], unique_x: &[u8], unique_y: &[u8]) -> Public {
    Public {
        name_alg: ALG_SHA256,
        attributes: OBJ_FIXED_TPM | OBJ_FIXED_PARENT | OBJ_SENSITIVE_DATA_ORIGIN | OBJ_DECRYPT | OBJ_NO_DA,
        auth_policy: auth_policy.to_vec(),
        params: PublicParams::Ecc(EccParms {
            symmetric: SymDefObject::Null,
            scheme: AsymScheme { scheme: ALG_ECDH, details: SchemeDetails::Hash(ALG_SHA256) },
            curve_id: ECC_NIST_P256,
            kdf: KdfScheme::NULL,
        }),
        unique: Unique::Ecc { x: unique_x.to_vec(), y: unique_y.to_vec() },
    }
}

fn sha256_selection(pcrs: &[u32]) -> Result<Vec<u8>> {
    if let Some(p) = pcrs.iter().find(|&&p| p > 23) {
        return Err(Error::invalid(format!("PCR {p} out of range")));
    }
    PcrSelectionList(vec![PcrSelection::new(ALG_SHA256, pcrs)]).to_bytes().map_err(Error::invalid)
}

impl Tpm<'_> {
    fn certify(&mut self, obj: &Key, ak: &Key, extra: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        const NAME: &str = "TPM2_Certify";
        let mut w = Writer::new();
        w.tpm2b(extra).map_err(Error::invalid)?;
        w.u16(ALG_NULL); // inScheme: the AK's scheme
        // objectHandle (admin role: empty auth value), signHandle (the AK).
        let cmd = Command::new(CC_CERTIFY).handle(obj.handle).handle(ak.handle).password().password().params(w.into_vec());
        let rsp = self.run(NAME, &cmd, 0)?;
        signed_attestation(NAME, &rsp.params, ST_ATTEST_CERTIFY)
    }

    /// TPM2_PolicyPCR with an empty pcrDigest: the TPM uses the current
    /// values of the selected SHA-256 PCRs.
    fn policy_pcr(&mut self, session: u32, selection: &[u8]) -> Result<()> {
        const NAME: &str = "TPM2_PolicyPCR";
        let mut w = Writer::new();
        w.u16(0).bytes(selection);
        let rsp = self.run(NAME, &Command::new(CC_POLICY_PCR).handle(session).params(w.into_vec()), 0)?;
        Params::new(NAME, &rsp.params).finish()
    }

    /// TPM2_ECDH_ZGen authorized by `session`: the shared point's x
    /// coordinate, left-padded to 32 bytes.
    fn ecdh_zgen(&mut self, obj: &Key, session: u32, x: &[u8], y: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        const NAME: &str = "TPM2_ECDH_ZGen";
        let mut point = Writer::new();
        point.tpm2b(x).map_err(Error::invalid)?;
        point.tpm2b(y).map_err(Error::invalid)?;
        let mut w = Writer::new();
        w.tpm2b(point.as_slice()).map_err(Error::invalid)?;
        let cmd = Command::new(CC_ECDH_ZGEN).handle(obj.handle).session(policy_session(session, &nonce()?)?).params(w.into_vec());
        let rsp = self.run(NAME, &cmd, 0)?;
        let mut p = Params::new(NAME, &rsp.params);
        let out = p.tpm2b("outPoint", 2 * (2 + P256_BYTES))?;
        p.finish()?;
        let mut q = Params::new(NAME, out);
        let zx = q.tpm2b("outPoint.x", P256_BYTES)?;
        q.tpm2b("outPoint.y", P256_BYTES)?;
        q.finish()?;
        let mut z = Zeroizing::new(vec![0u8; P256_BYTES]);
        if let Some(dst) = z.get_mut(P256_BYTES - zx.len()..) {
            dst.copy_from_slice(zx);
        }
        Ok(z)
    }
}

impl Device {
    /// Creates a session-unique, TPM-resident ECC P-256 ECDH key whose only
    /// authorization path is PolicyPCR over the current values of `pcrs`
    /// (SHA-256 bank). A primary in the endorsement hierarchy with a random
    /// unique field, so every session gets a fresh key; recreating it
    /// elsewhere would still require the PCRs.
    pub fn create_bound_key(&self, pcrs: &[u32]) -> Result<Key> {
        sha256_selection(pcrs)?;
        let values = self.read_pcrs(pcrs)?;
        let policy = db_tpmattest::policy_pcr_digest(pcrs, &values).map_err(|e| Error::invalid(format!("bound key policy: {e}")))?;
        let mut xy = Zeroizing::new([0u8; 2 * P256_BYTES]);
        getrandom::fill(xy.as_mut_slice()).map_err(|e| Error::invalid(format!("random: {e}")))?;
        let (x, y) = xy.split_at(P256_BYTES);
        self.create_primary(RH_ENDORSEMENT, &bound_key_template(&policy, x, y))
    }

    /// Has the AK sign a TPM2_Certify of `obj` over `extra`. Returns the
    /// TPMS_ATTEST and TPMT_SIGNATURE encodings.
    pub fn certify(&self, obj: &Key, ak: &Key, extra: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        self.tpm().certify(obj, ak, extra)
    }

    /// The ECDH shared secret (x coordinate, 32 bytes) between the bound key
    /// and a peer's uncompressed P-256 point. The TPM performs it only in a
    /// policy session satisfying PolicyPCR, i.e. while `pcrs` still hold the
    /// values the key was created (and attested) with. The session is
    /// flushed unless the ECDH consumed it.
    pub fn bound_ecdh(&self, obj: &Key, pcrs: &[u32], peer_uncompressed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let (x, y) = match peer_uncompressed.split_first() {
            Some((4, xy)) if xy.len() == 2 * P256_BYTES => xy.split_at(P256_BYTES),
            _ => return Err(Error::invalid("peer key must be an uncompressed P-256 point")),
        };
        let selection = sha256_selection(pcrs)?;
        let mut tpm = self.tpm();
        let refused = Error::context("TPM refused the bound ECDH");
        let (session, _) = tpm.start_policy_session().map_err(Error::context("TPM refused the bound ECDH"))?;
        let out = tpm.policy_pcr(session, &selection).and_then(|()| tpm.ecdh_zgen(obj, session, x, y));
        if out.is_err() {
            // A failed command leaves the session loaded.
            let _ = tpm.flush(session);
        }
        out.map_err(refused)
    }
}
