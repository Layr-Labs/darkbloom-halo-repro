//! The provider's TPM keys (port of the Go `node/attest.go`): loads the EK
//! and its certificates, creates the AK, answers credential-activation
//! challenges and produces evidence for nonces and statements.

use crate::{Device, EVENT_LOG_PATH, Endorsement, Key};
use db_tpmattest::{ALG_SHA256, DEFAULT_PCRS, Evidence, UKI_PCRS, parse_event_log, provider_id_from_ek, quote_extra_data};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use zeroize::Zeroizing;

/// Attester errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttestError {
    /// A malformed challenge: the agent ignores it (answers nothing).
    #[error("node: bad challenge: {0}")]
    BadChallenge(String),
    /// Anything else. From [`Attester::attest`] this means the TPM state is
    /// gone (e.g. after a TPM reset): the agent must restart and re-enroll.
    #[error("{0}")]
    Tpm(String),
}

/// Owns the provider's TPM keys. Send + Sync; TPM use is serialized.
pub struct Attester {
    pub(crate) dev: Arc<Device>,
    end: Endorsement,
    pub(crate) ak: Key,
    event_log: Vec<u8>,
    pub(crate) pcrs: Vec<u32>,
    closed: Mutex<bool>,
}

impl std::fmt::Debug for Attester {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attester").field("mode", &self.dev.mode()).field("provider_id", &self.provider_id()).finish_non_exhaustive()
    }
}

fn tpm_err(e: impl std::fmt::Display) -> AttestError {
    AttestError::Tpm(e.to_string())
}

impl Attester {
    /// Loads the EK (and its certificates) and creates the AK. Without an
    /// event log the firmware log in securityfs ([`EVENT_LOG_PATH`]) is read.
    /// Refuses to start when the log does not replay to the live PCRs (a
    /// stale log would only produce rejected quotes).
    pub fn new(dev: Arc<Device>, event_log: Option<Vec<u8>>) -> Result<Attester, AttestError> {
        Self::new_with_pcrs(dev, event_log, &DEFAULT_PCRS)
    }

    /// Loads keys and self-checks the event log against the selected boot
    /// profile's PCRs. The coordinator must challenge the same selection.
    pub fn new_with_pcrs(dev: Arc<Device>, event_log: Option<Vec<u8>>, pcrs: &[u32]) -> Result<Attester, AttestError> {
        if pcrs != DEFAULT_PCRS && pcrs != UKI_PCRS {
            return Err(AttestError::Tpm("node: PCR selection must be the Type #1 or UKI boot profile".to_owned()));
        }
        let event_log = match event_log {
            Some(b) => b,
            None => std::fs::read(EVENT_LOG_PATH).map_err(|e| AttestError::Tpm(format!("node: read firmware event log: {e}")))?,
        };
        let end = dev.load_endorsement().map_err(tpm_err)?;
        let ak = match dev.create_ak() {
            Ok(k) => k,
            Err(e) => {
                dev.flush(&end.ek);
                return Err(AttestError::Tpm(format!("node: create AK: {e}")));
            }
        };
        let a = Attester { dev, end, ak, event_log, pcrs: pcrs.to_vec(), closed: Mutex::new(false) };
        // On failure, dropping `a` flushes the keys.
        a.self_check()?;
        Ok(a)
    }

    fn self_check(&self) -> Result<(), AttestError> {
        let elog = parse_event_log(&self.event_log).map_err(tpm_err)?;
        let replayed = elog.replay(ALG_SHA256, &self.pcrs).map_err(tpm_err)?;
        let live = self.dev.read_pcrs(&self.pcrs).map_err(tpm_err)?;
        for &p in &self.pcrs {
            if replayed.get(&p) != live.get(&p) {
                return Err(AttestError::Tpm(format!("node: event log does not replay to the live PCR {p}")));
            }
        }
        Ok(())
    }

    /// Serializes TPM use; `true` once closed.
    pub(crate) fn lock(&self) -> MutexGuard<'_, bool> {
        self.closed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Flushes the AK and EK. Idempotent; also done on drop.
    pub fn close(&self) {
        let mut closed = self.lock();
        if !*closed {
            self.dev.flush(&self.ak);
            self.dev.flush(&self.end.ek);
            *closed = true;
        }
    }

    /// `"hardware"` or `"swtpm"`.
    pub fn mode(&self) -> &'static str {
        self.dev.mode().as_str()
    }

    /// The PCR selection enforced by self-check and TPM-bound decryption.
    pub fn pcrs(&self) -> &[u32] {
        &self.pcrs
    }

    /// The EK's TPMT_PUBLIC.
    pub fn ek_public(&self) -> &[u8] {
        &self.end.ek.public_raw
    }

    /// The AK's TPMT_PUBLIC.
    pub fn ak_public(&self) -> &[u8] {
        &self.ak.public_raw
    }

    /// The AK's TPM name.
    pub fn ak_name(&self) -> &[u8] {
        &self.ak.name
    }

    /// The EK certificate and on-chip ICAs (DER).
    pub fn ek_certificate(&self) -> (&[u8], &[Vec<u8>]) {
        (&self.end.cert_der, &self.end.icas)
    }

    /// The provider ID derived from the EK, so verifier and agent agree.
    pub fn provider_id(&self) -> String {
        provider_id_from_ek(&self.end.ek.public_raw)
    }

    /// The TPM.
    pub fn device(&self) -> &Arc<Device> {
        &self.dev
    }

    /// The endorsement (EK and certificates).
    pub fn endorsement(&self) -> &Endorsement {
        &self.end
    }

    /// The event log presented with every quote.
    pub fn event_log(&self) -> &[u8] {
        &self.event_log
    }

    /// Answers a credential-activation challenge.
    pub fn activate(&self, id_object: &[u8], enc_secret: &[u8]) -> Result<Zeroizing<Vec<u8>>, AttestError> {
        let closed = self.lock();
        if *closed {
            return Err(AttestError::Tpm("node: attester closed".to_owned()));
        }
        self.dev.activate_credential(&self.ak, &self.end.ek, id_object, enc_secret).map_err(tpm_err)
    }

    /// Produces evidence for a verifier nonce (16-64 bytes) and a statement:
    /// a quote of `pcrs` (1-24 PCRs in 0..=23) over
    /// `quote_extra_data(nonce, statement)`, with the EK chain and the log.
    pub fn attest(&self, nonce: &[u8], statement: &[u8], pcrs: &[i64]) -> Result<Evidence, AttestError> {
        if !(16..=64).contains(&nonce.len()) {
            return Err(AttestError::BadChallenge("nonce must be 16-64 bytes".to_owned()));
        }
        if pcrs.is_empty() || pcrs.len() > 24 {
            return Err(AttestError::BadChallenge("PCR selection size".to_owned()));
        }
        let mut selection = Vec::with_capacity(pcrs.len());
        for &p in pcrs {
            match u32::try_from(p) {
                Ok(v) if v <= 23 => selection.push(v),
                _ => return Err(AttestError::BadChallenge(format!("PCR {p} out of range"))),
            }
        }
        let closed = self.lock();
        if *closed {
            return Err(AttestError::Tpm("node: attester closed".to_owned()));
        }
        let (quote_attest, quote_sig) = self
            .dev
            .quote(&self.ak, &quote_extra_data(nonce, statement), &selection)
            .map_err(|e| AttestError::Tpm(format!("node: quote: {e}")))?;
        drop(closed);
        Ok(Evidence {
            ek_cert: self.end.cert_der.clone(),
            ek_icas: self.end.icas.clone(),
            ek_public: self.end.ek.public_raw.clone(),
            ak_public: self.ak.public_raw.clone(),
            statement: statement.to_vec(),
            nonce: nonce.to_vec(),
            quote_attest,
            quote_sig,
            event_log: self.event_log.clone(),
        })
    }
}

impl Drop for Attester {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send_sync<T: Send + Sync>() {}

    #[test]
    fn shareable_across_threads() {
        send_sync::<Attester>();
        send_sync::<Device>();
        send_sync::<crate::BoundKey>();
        send_sync::<AttestError>();
    }
}
