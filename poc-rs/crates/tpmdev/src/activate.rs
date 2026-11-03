//! TPM2_ActivateCredential with the TCG default EK policy
//! (PolicySecret(TPM_RH_ENDORSEMENT) in a policy session).

use crate::cmd::{Command, Params, policy_session};
use crate::device::{Device, Tpm};
use crate::{Error, Key, Result};
use db_tpm2::Writer;
use db_tpm2::consts::*;
use zeroize::Zeroizing;

const NONCE_SIZE: usize = 16;

pub(crate) fn nonce() -> Result<[u8; NONCE_SIZE]> {
    let mut n = [0u8; NONCE_SIZE];
    getrandom::fill(&mut n).map_err(|e| Error::invalid(format!("random: {e}")))?;
    Ok(n)
}

impl Tpm<'_> {
    /// StartAuthSession: an unbound, unsalted SHA-256 policy session.
    /// Returns its handle and nonceTPM.
    pub(crate) fn start_policy_session(&mut self) -> Result<(u32, Vec<u8>)> {
        const NAME: &str = "TPM2_StartAuthSession";
        let mut w = Writer::new();
        w.tpm2b(&nonce()?).map_err(Error::invalid)?; // nonceCaller
        w.u16(0); // encryptedSalt
        w.u8(SE_POLICY);
        w.u16(ALG_NULL); // symmetric
        w.u16(ALG_SHA256); // authHash
        let cmd = Command::new(CC_START_AUTH_SESSION).handle(RH_NULL).handle(RH_NULL).params(w.into_vec());
        let rsp = self.run(NAME, &cmd, 1)?;
        let handle = rsp.handles.first().copied().unwrap_or_default();
        let parsed = (|| {
            let mut p = Params::new(NAME, &rsp.params);
            let nonce_tpm = p.tpm2b("nonceTPM", MAX_DIGEST)?.to_vec();
            p.finish()?;
            Ok(nonce_tpm)
        })();
        match parsed {
            Ok(n) => Ok((handle, n)),
            Err(e) => {
                let _ = self.flush(handle);
                Err(e)
            }
        }
    }

    /// PolicySecret(TPM_RH_ENDORSEMENT) with the empty endorsement password.
    fn policy_secret_endorsement(&mut self, session: u32, nonce_tpm: &[u8]) -> Result<()> {
        const NAME: &str = "TPM2_PolicySecret";
        let mut w = Writer::new();
        w.tpm2b(nonce_tpm).map_err(Error::invalid)?;
        w.u16(0); // cpHashA
        w.u16(0); // policyRef
        w.u32(0); // expiration
        let cmd = Command::new(CC_POLICY_SECRET).handle(RH_ENDORSEMENT).handle(session).password().params(w.into_vec());
        let rsp = self.run(NAME, &cmd, 0)?;
        let mut p = Params::new(NAME, &rsp.params);
        p.tpm2b("timeout", 8)?;
        p.u16()?; // policyTicket: tag, hierarchy, digest
        p.u32()?;
        p.tpm2b("policyTicket digest", MAX_DIGEST)?;
        p.finish()
    }

    fn activate(&mut self, ak: &Key, ek: &Key, session: u32, id_object: &[u8], enc_secret: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        const NAME: &str = "TPM2_ActivateCredential";
        let mut w = Writer::new();
        w.tpm2b(id_object).map_err(Error::invalid)?;
        w.tpm2b(enc_secret).map_err(Error::invalid)?;
        let cmd = Command::new(CC_ACTIVATE_CREDENTIAL)
            .handle(ak.handle)
            .handle(ek.handle)
            .password()
            .session(policy_session(session, &nonce()?)?)
            .params(w.into_vec());
        let rsp = self.run(NAME, &cmd, 0)?;
        let mut p = Params::new(NAME, &rsp.params);
        let secret = Zeroizing::new(p.tpm2b("certInfo", MAX_DIGEST)?.to_vec());
        p.finish()?;
        Ok(secret)
    }
}

impl Device {
    /// Recovers a verifier's credential secret (TPM2_MakeCredential output:
    /// `id_object` is the TPM2B_ID_OBJECT contents, `enc_secret` the
    /// TPM2B_ENCRYPTED_SECRET contents). The TPM releases it only if it
    /// holds the EK private key and the AK named in the credential is
    /// loaded. The lock is held for the whole policy-session sequence; the
    /// session is flushed unless ActivateCredential consumed it.
    pub fn activate_credential(&self, ak: &Key, ek: &Key, id_object: &[u8], enc_secret: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut tpm = self.tpm();
        let (session, nonce_tpm) = tpm.start_policy_session()?;
        let out = tpm.policy_secret_endorsement(session, &nonce_tpm).and_then(|()| tpm.activate(ak, ek, session, id_object, enc_secret));
        if out.is_err() {
            // A failed command leaves the session loaded.
            let _ = tpm.flush(session);
        }
        out
    }
}
