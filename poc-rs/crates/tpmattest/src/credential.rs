//! Endorsement keys and TPM2_MakeCredential (credential activation).

use crate::keys::{PublicKey, fixed_be};
use crate::{Error, Result};
use db_tpm2::consts::*;
use db_tpm2::{EK_POLICY_DIGEST, HashAlg, Public, PublicParams, SymDefObject, Writer, kdfa, kdfe};
use rand_core::UnwrapErr;
use rsa::traits::PublicKeyParts as _;
use zeroize::Zeroizing;

/// A parsed EK public area.
#[derive(Debug, Clone)]
pub struct EndorsementKey {
    /// The TPMT_PUBLIC.
    pub public: Public,
    /// Its canonical encoding.
    pub public_raw: Vec<u8>,
    /// The public key.
    pub key: PublicKey,
}

/// Parses an EK TPMT_PUBLIC and checks the TCG default EK shape: a
/// restricted decryption key that never leaves the TPM and whose use
/// requires endorsement-hierarchy authorization. The certificate check then
/// proves that this key belongs to a genuine TPM.
pub fn parse_ek_public(raw: &[u8]) -> Result<EndorsementKey> {
    let public = Public::parse(raw).map_err(|e| Error::Invalid(format!("EK public area: {e}")))?;
    let required = OBJ_FIXED_TPM | OBJ_FIXED_PARENT | OBJ_SENSITIVE_DATA_ORIGIN | OBJ_RESTRICTED | OBJ_DECRYPT;
    if !public.has(required) || public.has(OBJ_SIGN_ENCRYPT) {
        return Err(Error::Invalid("EK must be a fixedTPM restricted decryption key".to_owned()));
    }
    if !public.has(OBJ_ADMIN_WITH_POLICY) || public.has(OBJ_USER_WITH_AUTH) || public.auth_policy != EK_POLICY_DIGEST {
        return Err(Error::Invalid("EK does not carry the TCG default endorsement policy".to_owned()));
    }
    let key = PublicKey::from_tpm(&public)?;
    Ok(EndorsementKey { public, public_raw: raw.to_vec(), key })
}

/// A TPM2_MakeCredential output: only a TPM that holds the EK private key
/// AND has an object named `name` loaded can recover `secret` with
/// TPM2_ActivateCredential.
pub struct CredentialChallenge {
    /// The challenge secret (zeroized on drop).
    pub secret: Zeroizing<Vec<u8>>,
    /// TPM2B_ID_OBJECT contents: TPM2B integrity HMAC || encIdentity.
    pub id_object: Vec<u8>,
    /// TPM2B_ENCRYPTED_SECRET contents (OAEP ciphertext or TPMS_ECC_POINT).
    pub enc_secret: Vec<u8>,
}

impl std::fmt::Debug for CredentialChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialChallenge").field("id_object_len", &self.id_object.len()).finish_non_exhaustive()
    }
}

fn rng() -> UnwrapErr<getrandom::SysRng> {
    UnwrapErr(getrandom::SysRng)
}

/// Labeled encapsulation to the EK ("IDENTITY"): returns (seed, encrypted seed).
fn encapsulate(ek: &EndorsementKey, name_hash: HashAlg) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    use p256::elliptic_curve::Generate as _;
    const LABEL: &str = "IDENTITY";
    let rand_err = |e: getrandom::Error| Error::Invalid(format!("random: {e}"));
    match (&ek.key, &ek.public.params) {
        (PublicKey::P256(pk), _) => {
            let eph = p256::ecdh::EphemeralSecret::try_generate_from_rng(&mut getrandom::SysRng).map_err(rand_err)?;
            let z = eph.diffie_hellman(pk);
            ecc_encapsulate(name_hash, LABEL, z.raw_secret_bytes(), &eph.public_key().to_sec1_bytes(), &pk.to_sec1_bytes())
        }
        (PublicKey::P384(pk), _) => {
            let eph = p384::ecdh::EphemeralSecret::try_generate_from_rng(&mut getrandom::SysRng).map_err(rand_err)?;
            let z = eph.diffie_hellman(pk);
            ecc_encapsulate(name_hash, LABEL, z.raw_secret_bytes(), &eph.public_key().to_sec1_bytes(), &pk.to_sec1_bytes())
        }
        (PublicKey::Rsa(pk), PublicParams::Rsa(parms)) => {
            // OAEP with the scheme hash if the key fixes OAEP with a hash,
            // otherwise the name algorithm.
            let mut hash_id = ek.public.name_alg;
            if parms.scheme.scheme == ALG_OAEP
                && let Some(h) = parms.scheme.hash().filter(|&h| h != ALG_NULL)
            {
                hash_id = h;
            }
            let oaep_hash = HashAlg::from_id(hash_id).ok_or_else(|| Error::Invalid(format!("unsupported OAEP hash 0x{hash_id:04x}")))?;
            let mut seed = Zeroizing::new(vec![0u8; oaep_hash.size()]);
            getrandom::fill(&mut seed).map_err(rand_err)?;
            let label = format!("{LABEL}\0").into_bytes();
            let ct = match oaep_hash {
                HashAlg::Sha1 => pk.encrypt(&mut rng(), rsa::Oaep::<sha1::Sha1>::new_with_label(label), &seed),
                HashAlg::Sha256 => pk.encrypt(&mut rng(), rsa::Oaep::<sha2::Sha256>::new_with_label(label), &seed),
                HashAlg::Sha384 => pk.encrypt(&mut rng(), rsa::Oaep::<sha2::Sha384>::new_with_label(label), &seed),
                HashAlg::Sha512 => pk.encrypt(&mut rng(), rsa::Oaep::<sha2::Sha512>::new_with_label(label), &seed),
            }
            .map_err(|e| Error::Invalid(format!("RSA-OAEP: {e}")))?;
            // The TPM expects the ciphertext as long as the modulus.
            let ct = fixed_be(&ct, pk.size()).unwrap_or(ct);
            Ok((seed, ct))
        }
        _ => Err(Error::Invalid("EK cannot encapsulate".to_owned())),
    }
}

/// KDFe seed and TPMS_ECC_POINT ciphertext from uncompressed SEC1 points.
fn ecc_encapsulate(name_hash: HashAlg, label: &str, z: &[u8], eph_sec1: &[u8], ek_sec1: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let bad = || Error::Invalid("bad ephemeral ECC key".to_owned());
    let coords = |p: &[u8]| -> Result<(Vec<u8>, Vec<u8>)> {
        match p.split_first() {
            Some((4, xy)) if xy.len() % 2 == 0 => {
                let (x, y) = xy.split_at(xy.len() / 2);
                Ok((x.to_vec(), y.to_vec()))
            }
            _ => Err(bad()),
        }
    };
    let (ex, ey) = coords(eph_sec1)?;
    let (kx, _) = coords(ek_sec1)?;
    let bits = u32::try_from(name_hash.size() * 8).map_err(|_| bad())?;
    let seed = kdfe(name_hash, z, label, &ex, &kx, bits);
    let mut w = Writer::new();
    w.tpm2b(&ex).map_err(|e| Error::Invalid(e.to_string()))?;
    w.tpm2b(&ey).map_err(|e| Error::Invalid(e.to_string()))?;
    Ok((seed, w.into_vec()))
}

fn aes_cfb_encrypt(key: &[u8], data: &mut [u8]) -> Result<()> {
    use aes::cipher::KeyIvInit as _;
    let iv = [0u8; 16];
    let bad = |_| Error::Invalid("bad symmetric key".to_owned());
    match key.len() {
        16 => cfb_mode::Encryptor::<aes::Aes128>::new_from_slices(key, &iv).map_err(bad)?.encrypt(data),
        24 => cfb_mode::Encryptor::<aes::Aes192>::new_from_slices(key, &iv).map_err(bad)?.encrypt(data),
        32 => cfb_mode::Encryptor::<aes::Aes256>::new_from_slices(key, &iv).map_err(bad)?.encrypt(data),
        n => return Err(Error::Invalid(format!("unsupported AES key size {n}"))),
    }
    Ok(())
}

/// Builds a credential-activation challenge binding an object (by `name`)
/// to the EK, with a caller-chosen secret (TPM 2.0 Part 1, 24 "Credential
/// Protection"). Matches go-tpm's `CreateCredential`.
pub fn make_credential_with_secret(ek: &EndorsementKey, name: &[u8], secret: &[u8]) -> Result<CredentialChallenge> {
    let name_hash = HashAlg::from_id(ek.public.name_alg)
        .ok_or_else(|| Error::Invalid(format!("unsupported EK name algorithm 0x{:04x}", ek.public.name_alg)))?;
    let key_bits = match ek.public.symmetric() {
        SymDefObject::Cipher { algorithm: ALG_AES, key_bits, mode: ALG_CFB } => u32::from(key_bits),
        SymDefObject::Cipher { algorithm: ALG_AES, mode, .. } => {
            return Err(Error::Invalid(format!("unsupported block cipher mode of operation 0x{mode:04x}")));
        }
        other => return Err(Error::Invalid(format!("unsupported block cipher {other:?}"))),
    };
    let (seed, enc_secret) = encapsulate(ek, name_hash)?;
    // The credential is marshaled as a TPM2B_DIGEST before encryption.
    let mut cred = Zeroizing::new(Vec::with_capacity(2 + secret.len()));
    cred.extend_from_slice(&u16::try_from(secret.len()).map_err(|_| Error::Invalid("secret too long".to_owned()))?.to_be_bytes());
    cred.extend_from_slice(secret);
    let sym = kdfa(name_hash, &seed, "STORAGE", name, &[], key_bits);
    aes_cfb_encrypt(&sym, &mut cred)?;
    let enc_identity = cred.to_vec();
    let hmac_bits = u32::try_from(name_hash.size() * 8).map_err(|_| Error::Invalid("hash size".to_owned()))?;
    let hmac_key = kdfa(name_hash, &seed, "INTEGRITY", &[], &[], hmac_bits);
    let integrity = name_hash.hmac(&hmac_key, &[&enc_identity, name]);
    let mut id_object = Vec::with_capacity(2 + integrity.len() + enc_identity.len());
    id_object.extend_from_slice(&u16::try_from(integrity.len()).map_err(|_| Error::Invalid("hmac".to_owned()))?.to_be_bytes());
    id_object.extend_from_slice(&integrity);
    id_object.extend_from_slice(&enc_identity);
    Ok(CredentialChallenge { secret: Zeroizing::new(secret.to_vec()), id_object, enc_secret })
}

/// Creates a credential-activation challenge with a fresh 32-byte secret,
/// binding an AK (by name) to the EK. This is the step that proves the AK
/// lives in the same TPM as the AMD-certified EK; Pluton's EK cannot sign,
/// so this is how the verifier learns that quotes from the AK come from
/// genuine AMD hardware.
pub fn make_credential(ek: &EndorsementKey, ak_name: &[u8]) -> Result<CredentialChallenge> {
    let mut secret = Zeroizing::new([0u8; 32]);
    getrandom::fill(secret.as_mut_slice()).map_err(|e| Error::Invalid(format!("random: {e}")))?;
    make_credential_with_secret(ek, ak_name, secret.as_slice())
}
