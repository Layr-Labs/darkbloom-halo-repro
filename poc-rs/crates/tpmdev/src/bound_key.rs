//! A session's TPM-bound decryption key on the attester (Go `node/attest.go`:
//! NewBoundKey, BoundECDH, FlushBound, Certify).

use crate::Key;
use crate::attester::{AttestError, Attester};
use db_tpmattest::{PublicKey, bound_key_certify_data};
use zeroize::Zeroizing;

/// A session's TPM-resident ECDH key. Not flushed on drop: call
/// [`Attester::flush_bound`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundKey {
    /// The loaded key.
    pub key: Key,
    /// The PolicyPCR selection (SHA-256 bank).
    pub pcrs: Vec<u32>,
    /// What the statement publishes (public area, PCRs, AK certification).
    pub public: db_tpmattest::BoundKey,
    point: Vec<u8>,
}

impl BoundKey {
    /// The key's uncompressed P-256 point (65 bytes).
    pub fn public_bytes(&self) -> &[u8] {
        &self.point
    }
}

fn closed() -> AttestError {
    AttestError::Tpm("node: attester closed".to_owned())
}

impl Attester {
    /// Creates and certifies a TPM-bound decryption key for one provider
    /// session: PolicyPCR over the attester's selected PCRs, certified by the AK over
    /// `bound_key_certify_data(provider_id, session_id)`.
    pub fn new_bound_key(&self, session_id: &str) -> Result<BoundKey, AttestError> {
        let guard = self.lock();
        if *guard {
            return Err(closed());
        }
        let pcrs = self.pcrs.clone();
        let key = self.dev.create_bound_key(&pcrs).map_err(|e| AttestError::Tpm(format!("node: create bound key: {e}")))?;
        let certified = self.dev.certify(&key, &self.ak, &bound_key_certify_data(&self.provider_id(), session_id));
        let (certify_attest, certify_sig) = match certified {
            Ok(c) => c,
            Err(e) => {
                self.dev.flush(&key);
                return Err(AttestError::Tpm(format!("node: certify bound key: {e}")));
            }
        };
        let point = match PublicKey::from_tpm(&key.public) {
            Ok(PublicKey::P256(p)) => p.to_sec1_bytes().to_vec(),
            _ => {
                self.dev.flush(&key);
                return Err(AttestError::Tpm("node: bound key is not a P-256 key".to_owned()));
            }
        };
        let public = db_tpmattest::BoundKey {
            public: key.public_raw.clone(),
            pcrs: pcrs.iter().map(|&p| i64::from(p)).collect(),
            certify_attest,
            certify_sig,
        };
        Ok(BoundKey { key, pcrs, public, point })
    }

    /// Asks the TPM for the ECDH secret with a consumer's ephemeral P-256
    /// key (uncompressed point). A malformed key is
    /// [`AttestError::BadChallenge`]; the TPM refuses (as
    /// [`AttestError::Tpm`]) unless the PCRs still match the key's policy.
    pub fn bound_ecdh(&self, bk: &BoundKey, ephemeral: &[u8]) -> Result<Zeroizing<Vec<u8>>, AttestError> {
        let on_curve = ephemeral.len() == 65 && ephemeral.first() == Some(&4) && p256::PublicKey::from_sec1_bytes(ephemeral).is_ok();
        if !on_curve {
            return Err(AttestError::BadChallenge("bad TPM ephemeral key (want an uncompressed P-256 point)".to_owned()));
        }
        let guard = self.lock();
        if *guard {
            return Err(closed());
        }
        self.dev.bound_ecdh(&bk.key, &bk.pcrs, ephemeral).map_err(|e| AttestError::Tpm(e.to_string()))
    }

    /// Unloads a bound key.
    pub fn flush_bound(&self, bk: &BoundKey) {
        let _guard = self.lock();
        self.dev.flush(&bk.key);
    }

    /// Has the AK certify another TPM object (tests and tools).
    pub fn certify(&self, obj: &Key, extra: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AttestError> {
        let guard = self.lock();
        if *guard {
            return Err(closed());
        }
        self.dev.certify(obj, &self.ak, extra).map_err(|e| AttestError::Tpm(e.to_string()))
    }
}
