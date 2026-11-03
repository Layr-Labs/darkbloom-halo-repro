//! End-to-end encryption between a consumer and an attested provider. The
//! coordinator relays ciphertext and routes on plaintext metadata only; it
//! never holds a key that opens a prompt, an input image or a generated
//! image/video.
//!
//! * Request: HPKE (RFC 9180) base mode to the provider's attested job key.
//!   Default KEM is X-Wing (ML-KEM-768 + X25519 hybrid, post-quantum, KEM id
//!   0x647a), with DHKEM(X25519) as a fallback; KDF HKDF-SHA256; AEAD
//!   ChaCha20-Poly1305. The routing metadata is the HPKE AAD, so the provider
//!   can refuse a job whose sealed parameters differ from what the
//!   coordinator priced and routed.
//! * Result: a key exported from the same HPKE context, used for a chunked
//!   ChaCha20-Poly1305 stream with sequence numbers and a final-chunk flag
//!   (truncation and reordering are detected), padded to a size bucket so
//!   ciphertext length leaks less about the content.
//!
//! Byte-compatible with the Go reference (cloudflare/circl HPKE).

#![forbid(unsafe_code)]

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hpke::aead::ChaCha20Poly1305 as HpkeChaCha;
use hpke::kdf::HkdfSha256;
use hpke::kem::{X25519HkdfSha256, XWing};
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// KEM name of X-Wing as it appears in provider statements.
pub const KEM_XWING: &str = "X-Wing(ML-KEM-768,X25519)";
/// KEM name of DHKEM(X25519) as it appears in provider statements.
pub const KEM_X25519: &str = "DHKEM(X25519,HKDF-SHA256)";

const INFO_PREFIX: &str = "darkbloom-amd/job/v1";
const EXPORT_CONTEXT: &[u8] = b"darkbloom-amd/result/v1";
const CHUNK_DOMAIN: &str = "darkbloom-amd/result-chunk/v1";

/// Plaintext size of each result chunk.
pub const CHUNK_SIZE: usize = 1 << 20;
/// Smallest padded result size; larger results are padded to the next power
/// of two, so the size reveals only a coarse class (at most 2x overhead).
pub const PAD_BUCKET: usize = 256 << 10;
/// Bound on a single decrypted result (long videos are split into jobs).
pub const MAX_RESULT_BYTES: usize = 2 << 30;

/// Errors from sealing or opening.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The KEM name is not supported.
    #[error("sealbox: unsupported KEM {0:?}")]
    UnsupportedKem(String),
    /// A key or encapsulation has the wrong size or is invalid.
    #[error("sealbox: {0}")]
    BadKey(String),
    /// The request did not open (wrong key, info or metadata).
    #[error("sealbox: request does not open (wrong key, info or metadata)")]
    RequestDoesNotOpen,
    /// A result chunk did not open.
    #[error("sealbox: result chunk {0} does not open (tampered, reordered or truncated)")]
    ChunkDoesNotOpen(usize),
    /// Any other failure.
    #[error("sealbox: {0}")]
    Other(String),
}

/// Result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// A supported KEM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kem {
    /// X-Wing (ML-KEM-768 + X25519).
    XWing,
    /// DHKEM(X25519, HKDF-SHA256).
    X25519,
}

impl Kem {
    /// Looks up a KEM by its statement name.
    pub fn from_name(name: &str) -> Result<Self> {
        match name {
            KEM_XWING => Ok(Self::XWing),
            KEM_X25519 => Ok(Self::X25519),
            _ => Err(Error::UnsupportedKem(name.to_owned())),
        }
    }

    /// The statement name.
    pub fn name(self) -> &'static str {
        match self {
            Self::XWing => KEM_XWING,
            Self::X25519 => KEM_X25519,
        }
    }

    /// Encoded public key size.
    pub fn public_key_size(self) -> usize {
        match self {
            Self::XWing => 1216,
            Self::X25519 => 32,
        }
    }
}

/// The encoded public key size for a KEM name.
pub fn public_key_size(name: &str) -> Result<usize> {
    Ok(Kem::from_name(name)?.public_key_size())
}

/// Binds the HPKE context to the provider and its attested session, so a
/// sealed job cannot be replayed to another provider or session.
pub fn info(provider_id: &str, session_id: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(INFO_PREFIX.len() + provider_id.len() + session_id.len() + 2);
    b.extend_from_slice(INFO_PREFIX.as_bytes());
    for s in [provider_id, session_id] {
        b.push(0);
        b.extend_from_slice(s.as_bytes());
    }
    b
}

/// A sealed job request. `tpm_ephemeral` is set when the job is bound to
/// the provider's TPM-resident key (HPKE PSK mode).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Sealed {
    /// HPKE encapsulated key.
    #[serde(with = "db_gojson::b64")]
    pub enc: Vec<u8>,
    /// The consumer's ephemeral P-256 point (uncompressed) for the TPM ECDH.
    #[serde(skip_serializing_if = "Vec::is_empty", with = "db_gojson::b64")]
    pub tpm_ephemeral: Vec<u8>,
    /// HPKE ciphertext.
    #[serde(with = "db_gojson::b64")]
    pub ciphertext: Vec<u8>,
}

const PSK_INFO: &str = "darkbloom-amd/tpm-psk/v1";
const PSK_ID: &[u8] = b"darkbloom-amd/tpm-p256-ecdh";

/// The HPKE pre-shared key from the P-256 ECDH secret with the provider's
/// TPM-resident key, bound to both public keys:
/// `HKDF-SHA256(ikm = z, salt = none, info = "darkbloom-amd/tpm-psk/v1" ||
/// 0x00 || ephemeral || bound)`, 32 bytes.
fn bound_psk(z: &[u8], ephemeral: &[u8], bound: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut info = Vec::with_capacity(PSK_INFO.len() + 1 + ephemeral.len() + bound.len());
    info.extend_from_slice(PSK_INFO.as_bytes());
    info.push(0);
    info.extend_from_slice(ephemeral);
    info.extend_from_slice(bound);
    let mut psk = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(None, z).expand(&info, psk.as_mut_slice()).map_err(|_| Error::Other("psk derivation".to_owned()))?;
    Ok(psk)
}

/// The 32-byte result-stream key exported from the HPKE context. Zeroized
/// on drop.
#[derive(Clone)]
pub struct ResultKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for ResultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResultKey(..)")
    }
}

impl ResultKey {
    /// Wraps raw key bytes (for tests and interop vectors).
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(Zeroizing::new(b))
    }

    /// The raw key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

enum Private {
    XWing(Box<<XWing as KemTrait>::PrivateKey>),
    X25519(Box<<X25519HkdfSha256 as KemTrait>::PrivateKey>),
}

/// A provider's job key. It lives only in the provider process; the private
/// half is zeroized on drop.
pub struct KeyPair {
    kem: Kem,
    public: Vec<u8>,
    private: Private,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair").field("kem", &self.kem).field("public_len", &self.public.len()).finish_non_exhaustive()
    }
}

fn exported(export: impl FnOnce(&mut [u8]) -> std::result::Result<(), hpke::HpkeError>) -> Result<ResultKey> {
    let mut out = Zeroizing::new([0u8; 32]);
    export(out.as_mut_slice()).map_err(|e| Error::Other(format!("export: {e}")))?;
    Ok(ResultKey(out))
}

impl KeyPair {
    /// Generates a fresh job key.
    pub fn generate(kem_name: &str) -> Result<Self> {
        let kem = Kem::from_name(kem_name)?;
        Ok(match kem {
            Kem::XWing => {
                let (sk, pk) = XWing::gen_keypair();
                Self { kem, public: pk.to_bytes().to_vec(), private: Private::XWing(Box::new(sk)) }
            }
            Kem::X25519 => {
                let (sk, pk) = X25519HkdfSha256::gen_keypair();
                Self { kem, public: pk.to_bytes().to_vec(), private: Private::X25519(Box::new(sk)) }
            }
        })
    }

    /// Restores a key pair from its private key bytes (the X-Wing 32-byte
    /// seed, or the X25519 scalar). For test vectors and tools.
    pub fn from_private_bytes(kem_name: &str, private: &[u8]) -> Result<Self> {
        let kem = Kem::from_name(kem_name)?;
        let bad = |e: hpke::HpkeError| Error::BadKey(format!("private key: {e}"));
        Ok(match kem {
            Kem::XWing => {
                let sk = <XWing as KemTrait>::PrivateKey::from_bytes(private).map_err(bad)?;
                let pk = XWing::sk_to_pk(&sk);
                Self { kem, public: pk.to_bytes().to_vec(), private: Private::XWing(Box::new(sk)) }
            }
            Kem::X25519 => {
                let sk = <X25519HkdfSha256 as KemTrait>::PrivateKey::from_bytes(private).map_err(bad)?;
                let pk = X25519HkdfSha256::sk_to_pk(&sk);
                Self { kem, public: pk.to_bytes().to_vec(), private: Private::X25519(Box::new(sk)) }
            }
        })
    }

    /// The KEM.
    pub fn kem(&self) -> Kem {
        self.kem
    }

    /// The KEM name for statements.
    pub fn kem_name(&self) -> &'static str {
        self.kem.name()
    }

    /// The encoded public key.
    pub fn public(&self) -> &[u8] {
        &self.public
    }

    /// Opens a TPM-bound request. `z` is the ECDH secret the provider's TPM
    /// computed between its bound key and `sealed.tpm_ephemeral`; `bound` is
    /// the bound key's uncompressed point.
    pub fn open_request_bound(
        &self,
        info: &[u8],
        aad: &[u8],
        sealed: &Sealed,
        z: &[u8],
        bound: &[u8],
    ) -> Result<(Zeroizing<Vec<u8>>, ResultKey)> {
        fn open<K: KemTrait>(
            sk: &K::PrivateKey,
            psk: &[u8],
            info: &[u8],
            aad: &[u8],
            sealed: &Sealed,
        ) -> Result<(Zeroizing<Vec<u8>>, ResultKey)> {
            let enc = K::EncappedKey::from_bytes(&sealed.enc).map_err(|e| Error::BadKey(format!("encapsulated key: {e}")))?;
            let bundle = hpke::PskBundle::new(psk, PSK_ID).map_err(|e| Error::Other(format!("psk: {e}")))?;
            let mut ctx = hpke::setup_receiver::<HpkeChaCha, HkdfSha256, K>(&OpModeR::Psk(bundle), sk, &enc, info)
                .map_err(|e| Error::BadKey(format!("decapsulation: {e}")))?;
            let pt = Zeroizing::new(ctx.open(&sealed.ciphertext, aad).map_err(|_| Error::RequestDoesNotOpen)?);
            let key = exported(|out| ctx.export(EXPORT_CONTEXT, out))?;
            Ok((pt, key))
        }
        let psk = bound_psk(z, &sealed.tpm_ephemeral, bound)?;
        match &self.private {
            Private::XWing(sk) => open::<XWing>(sk, psk.as_slice(), info, aad, sealed),
            Private::X25519(sk) => open::<X25519HkdfSha256>(sk, psk.as_slice(), info, aad, sealed),
        }
    }

    /// Opens a sealed request and returns the plaintext and the result key.
    pub fn open_request(&self, info: &[u8], aad: &[u8], sealed: &Sealed) -> Result<(Zeroizing<Vec<u8>>, ResultKey)> {
        fn open<K: KemTrait>(sk: &K::PrivateKey, info: &[u8], aad: &[u8], sealed: &Sealed) -> Result<(Zeroizing<Vec<u8>>, ResultKey)> {
            let enc = K::EncappedKey::from_bytes(&sealed.enc).map_err(|e| Error::BadKey(format!("encapsulated key: {e}")))?;
            let mut ctx = hpke::setup_receiver::<HpkeChaCha, HkdfSha256, K>(&OpModeR::Base, sk, &enc, info)
                .map_err(|e| Error::BadKey(format!("decapsulation: {e}")))?;
            let pt = Zeroizing::new(ctx.open(&sealed.ciphertext, aad).map_err(|_| Error::RequestDoesNotOpen)?);
            let key = exported(|out| ctx.export(EXPORT_CONTEXT, out))?;
            Ok((pt, key))
        }
        match &self.private {
            Private::XWing(sk) => open::<XWing>(sk, info, aad, sealed),
            Private::X25519(sk) => open::<X25519HkdfSha256>(sk, info, aad, sealed),
        }
    }
}

/// [`seal_request`] with the TPM-enforced share: an ECDH between a fresh
/// P-256 key and the provider's TPM-resident bound key is mixed in as the
/// HPKE PSK, so the job only opens where that TPM performs the ECDH, i.e. in
/// the attested boot state.
pub fn seal_request_bound(
    kem_name: &str,
    provider_public: &[u8],
    bound: &p256::PublicKey,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Sealed, ResultKey)> {
    use p256::elliptic_curve::Generate as _;
    let eph =
        p256::ecdh::EphemeralSecret::try_generate_from_rng(&mut getrandom::SysRng).map_err(|e| Error::Other(format!("random: {e}")))?;
    let eph_pub = eph.public_key().to_sec1_bytes().to_vec();
    let bound_pub = bound.to_sec1_bytes();
    let z = eph.diffie_hellman(bound);
    let psk = bound_psk(z.raw_secret_bytes(), &eph_pub, &bound_pub)?;
    drop(z);
    fn seal<K: KemTrait>(pk: &[u8], psk: &[u8], info: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>, ResultKey)> {
        let pk = K::PublicKey::from_bytes(pk).map_err(|e| Error::BadKey(format!("provider key: {e}")))?;
        let bundle = hpke::PskBundle::new(psk, PSK_ID).map_err(|e| Error::Other(format!("psk: {e}")))?;
        let (enc, mut ctx) = hpke::setup_sender::<HpkeChaCha, HkdfSha256, K>(&OpModeS::Psk(bundle), &pk, info)
            .map_err(|e| Error::BadKey(format!("encapsulation: {e}")))?;
        let ct = ctx.seal(plaintext, aad).map_err(|e| Error::Other(format!("seal: {e}")))?;
        let key = exported(|out| ctx.export(EXPORT_CONTEXT, out))?;
        Ok((enc.to_bytes().to_vec(), ct, key))
    }
    let (enc, ciphertext, key) = match Kem::from_name(kem_name)? {
        Kem::XWing => seal::<XWing>(provider_public, psk.as_slice(), info, aad, plaintext)?,
        Kem::X25519 => seal::<X25519HkdfSha256>(provider_public, psk.as_slice(), info, aad, plaintext)?,
    };
    Ok((Sealed { enc, tpm_ephemeral: eph_pub, ciphertext }, key))
}

/// Seals `plaintext` to the provider's job key with `aad` as the HPKE AAD.
/// Returns the sealed request and the result key the consumer later uses to
/// open the result stream.
pub fn seal_request(kem_name: &str, provider_public: &[u8], info: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<(Sealed, ResultKey)> {
    fn seal<K: KemTrait>(pk: &[u8], info: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<(Sealed, ResultKey)> {
        let pk = K::PublicKey::from_bytes(pk).map_err(|e| Error::BadKey(format!("provider key: {e}")))?;
        let (enc, mut ctx) = hpke::setup_sender::<HpkeChaCha, HkdfSha256, K>(&OpModeS::Base, &pk, info)
            .map_err(|e| Error::BadKey(format!("encapsulation: {e}")))?;
        let ct = ctx.seal(plaintext, aad).map_err(|e| Error::Other(format!("seal: {e}")))?;
        let key = exported(|out| ctx.export(EXPORT_CONTEXT, out))?;
        Ok((Sealed { enc: enc.to_bytes().to_vec(), tpm_ephemeral: Vec::new(), ciphertext: ct }, key))
    }
    match Kem::from_name(kem_name)? {
        Kem::XWing => seal::<XWing>(provider_public, info, aad, plaintext),
        Kem::X25519 => seal::<X25519HkdfSha256>(provider_public, info, aad, plaintext),
    }
}

fn chunk_aad(job_id: &str, seq: u64, last: bool) -> Vec<u8> {
    let mut b = Vec::with_capacity(CHUNK_DOMAIN.len() + job_id.len() + 11);
    b.extend_from_slice(CHUNK_DOMAIN.as_bytes());
    b.push(0);
    b.extend_from_slice(job_id.as_bytes());
    b.push(0);
    b.extend_from_slice(&seq.to_be_bytes());
    b.push(u8::from(last));
    b
}

fn chunk_nonce(seq: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    Nonce::from(n)
}

fn cipher(key: &ResultKey) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(&Key::from(*key.as_bytes()))
}

/// Whether content of `len` bytes, with its 8-byte length prefix, stays
/// within [`MAX_RESULT_BYTES`] (the bound the sealed stream is sized for).
fn result_fits(len: usize) -> bool {
    len.checked_add(8).is_some_and(|total| total <= MAX_RESULT_BYTES)
}

/// Encrypts a result as a padded chunk stream: an 8-byte big-endian length,
/// the content, zero padding up to [`PAD_BUCKET`] or the next power of two
/// above it, split into [`CHUNK_SIZE`] chunks with sequence numbers and a
/// final flag in the AAD.
pub fn seal_result(key: &ResultKey, job_id: &str, content: &[u8]) -> Result<Vec<Vec<u8>>> {
    if !result_fits(content.len()) {
        return Err(Error::Other("result too large".to_owned()));
    }
    let aead = cipher(key);
    let total = 8 + content.len();
    let mut padded = PAD_BUCKET;
    while padded < total {
        padded = padded.checked_mul(2).ok_or_else(|| Error::Other("result too large".to_owned()))?;
    }
    let mut plain = Zeroizing::new(Vec::with_capacity(padded));
    plain.extend_from_slice(&(content.len() as u64).to_be_bytes());
    plain.extend_from_slice(content);
    plain.resize(padded, 0);
    let mut out = Vec::with_capacity(padded.div_ceil(CHUNK_SIZE));
    for (seq, chunk) in plain.chunks(CHUNK_SIZE).enumerate() {
        let seq = seq as u64;
        let last = (seq as usize + 1) * CHUNK_SIZE >= padded;
        let aad = chunk_aad(job_id, seq, last);
        let ct =
            aead.encrypt(&chunk_nonce(seq), Payload { msg: chunk, aad: &aad }).map_err(|_| Error::Other("seal result chunk".to_owned()))?;
        out.push(ct);
    }
    Ok(out)
}

/// Decrypts and checks a chunk stream; the plaintext is zeroized on drop.
pub fn open_result<C: AsRef<[u8]>>(key: &ResultKey, job_id: &str, chunks: &[C]) -> Result<Zeroizing<Vec<u8>>> {
    let aead = cipher(key);
    let mut plain: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    for (i, c) in chunks.iter().enumerate() {
        let last = i + 1 == chunks.len();
        let aad = chunk_aad(job_id, i as u64, last);
        let mut p = aead.decrypt(&chunk_nonce(i as u64), Payload { msg: c.as_ref(), aad: &aad }).map_err(|_| Error::ChunkDoesNotOpen(i))?;
        if plain.len() + p.len() > MAX_RESULT_BYTES + PAD_BUCKET {
            p.zeroize();
            return Err(Error::Other("result too large".to_owned()));
        }
        // Grow through a zeroizing buffer so no stale plaintext copy remains.
        if plain.capacity() < plain.len() + p.len() {
            let mut bigger = Zeroizing::new(Vec::with_capacity((plain.len() + p.len()).max(plain.capacity() * 2)));
            bigger.extend_from_slice(&plain);
            plain = bigger;
        }
        plain.extend_from_slice(&p);
        p.zeroize();
    }
    let Some((len, body)) = plain.split_first_chunk::<8>() else {
        return Err(Error::Other("empty result stream".to_owned()));
    };
    let n = usize::try_from(u64::from_be_bytes(*len)).map_err(|_| Error::Other("bad result length".to_owned()))?;
    if n > body.len() {
        return Err(Error::Other("bad result length".to_owned()));
    }
    let (content, padding) = body.split_at(n);
    if padding.iter().any(|&b| b != 0) {
        return Err(Error::Other("non-zero padding".to_owned()));
    }
    Ok(Zeroizing::new(content.to_vec()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn request_and_result_round_trip() {
        for kem in [KEM_XWING, KEM_X25519] {
            let kp = KeyPair::generate(kem).unwrap();
            assert_eq!(kp.public().len(), public_key_size(kem).unwrap());
            let inf = info("prov", "sess");
            let aad = br#"{"job_id":"j1","width":1024}"#;
            let (sealed, ck) = seal_request(kem, kp.public(), &inf, aad, b"a private prompt").unwrap();
            let (pt, pk) = kp.open_request(&inf, aad, &sealed).unwrap();
            assert_eq!(pt.as_slice(), b"a private prompt");
            assert_eq!(ck.as_bytes(), pk.as_bytes());
            assert!(kp.open_request(&inf, br#"{"job_id":"j1","width":512}"#, &sealed).is_err(), "{kem}: altered AAD accepted");
            assert!(kp.open_request(&info("prov", "other-session"), aad, &sealed).is_err(), "{kem}: replayed into another session");
            let other = KeyPair::generate(kem).unwrap();
            assert!(other.open_request(&inf, aad, &sealed).is_err(), "{kem}: wrong key opened the job");
            let mut content = vec![0u8; 2 * CHUNK_SIZE + 12345];
            getrandom::fill(&mut content).unwrap();
            let chunks = seal_result(&pk, "j1", &content).unwrap();
            assert_eq!(open_result(&ck, "j1", &chunks).unwrap().as_slice(), content.as_slice());
            assert!(open_result(&ck, "j1", &chunks[..chunks.len() - 1]).is_err(), "truncated stream accepted");
            if chunks.len() > 1 {
                let mut sw = chunks.clone();
                sw.swap(0, 1);
                assert!(open_result(&ck, "j1", &sw).is_err(), "reordered stream accepted");
            }
            assert!(open_result(&ck, "j2", &chunks).is_err(), "stream for another job accepted");
            let mut bad = chunks.clone();
            bad[0][10] ^= 1;
            assert!(open_result(&ck, "j1", &bad).is_err(), "tampered chunk accepted");
            assert!(open_result::<Vec<u8>>(&ck, "j1", &[]).is_err(), "empty stream accepted");
        }
    }

    /// Go: `len(content)+8 > MaxResultBytes` is refused (the length prefix
    /// counts), so seal and open agree on the largest result.
    #[test]
    fn result_size_boundary_counts_the_length_prefix() {
        assert!(result_fits(0));
        assert!(result_fits(MAX_RESULT_BYTES - 8));
        assert!(!result_fits(MAX_RESULT_BYTES - 7));
        assert!(!result_fits(MAX_RESULT_BYTES));
        assert!(!result_fits(usize::MAX));
    }

    #[test]
    fn padding_hides_exact_size() {
        let kp = KeyPair::generate(KEM_X25519).unwrap();
        let (_, key) = seal_request(KEM_X25519, kp.public(), &info("p", "s"), &[], b"x").unwrap();
        let sizes = |n: usize| -> Vec<usize> { seal_result(&key, "j", &vec![0u8; n]).unwrap().iter().map(Vec::len).collect() };
        assert_eq!(sizes(1000), sizes(200_000), "same bucket, same ciphertext size");
        assert_eq!(sizes(1000), vec![PAD_BUCKET + 16]);
        // Exactly at the first bucket boundary, then powers of two.
        assert_eq!(sizes(PAD_BUCKET - 8), vec![PAD_BUCKET + 16]);
        assert_eq!(sizes(PAD_BUCKET - 7), vec![2 * PAD_BUCKET + 16]);
        assert_eq!(sizes(3 * PAD_BUCKET), vec![CHUNK_SIZE + 16]);
        assert_eq!(sizes(CHUNK_SIZE), vec![CHUNK_SIZE + 16, CHUNK_SIZE + 16]);
        assert_eq!(sizes(2 * CHUNK_SIZE + 12345), vec![CHUNK_SIZE + 16; 4]);
        let d = seal_result(&key, "j", &vec![7u8; PAD_BUCKET - 7]).unwrap();
        assert_eq!(open_result(&key, "j", &d).unwrap().as_slice(), vec![7u8; PAD_BUCKET - 7].as_slice());
    }

    #[test]
    fn bound_round_trip() {
        use p256::elliptic_curve::Generate as _;
        // The provider's "TPM" key, held in software for this unit test.
        let tpm = p256::SecretKey::try_generate_from_rng(&mut getrandom::SysRng).unwrap();
        let bound = tpm.public_key();
        let bound_bytes = bound.to_sec1_bytes();
        for kem in [KEM_XWING, KEM_X25519] {
            let kp = KeyPair::generate(kem).unwrap();
            let inf = info("prov", "sess");
            let (sealed, ck) = seal_request_bound(kem, kp.public(), &bound, &inf, b"meta", b"private prompt").unwrap();
            assert_eq!(sealed.tpm_ephemeral.len(), 65);
            let eph = p256::PublicKey::from_sec1_bytes(&sealed.tpm_ephemeral).unwrap();
            let z = p256::ecdh::diffie_hellman(tpm.to_nonzero_scalar(), eph.as_affine());
            let (pt, pk) = kp.open_request_bound(&inf, b"meta", &sealed, z.raw_secret_bytes(), &bound_bytes).unwrap();
            assert_eq!(pt.as_slice(), b"private prompt");
            assert_eq!(pk.as_bytes(), ck.as_bytes());
            // A RAM dump yields the HPKE key, but not the TPM share.
            assert!(kp.open_request(&inf, b"meta", &sealed).is_err(), "bound job opened without the TPM share");
            assert!(kp.open_request_bound(&inf, b"meta", &sealed, &[7u8; 32], &bound_bytes).is_err(), "guessed share accepted");
            assert!(kp.open_request_bound(&inf, b"other", &sealed, z.raw_secret_bytes(), &bound_bytes).is_err());
        }
        // tpm_ephemeral is omitted from JSON when empty, present otherwise.
        let s = Sealed { enc: vec![1], tpm_ephemeral: vec![], ciphertext: vec![2] };
        assert_eq!(String::from_utf8(db_gojson::to_vec(&s).unwrap()).unwrap(), r#"{"enc":"AQ==","ciphertext":"Ag=="}"#);
        let s = Sealed { tpm_ephemeral: vec![3], ..s };
        assert_eq!(
            String::from_utf8(db_gojson::to_vec(&s).unwrap()).unwrap(),
            r#"{"enc":"AQ==","tpm_ephemeral":"Aw==","ciphertext":"Ag=="}"#
        );
    }

    #[test]
    fn rejects_bad_inputs() {
        assert!(KeyPair::generate("RSA").is_err());
        assert!(seal_request(KEM_XWING, &[0u8; 10], b"", b"", b"x").is_err());
        let kp = KeyPair::generate(KEM_XWING).unwrap();
        let bad = Sealed { enc: vec![0u8; 3], tpm_ephemeral: Vec::new(), ciphertext: vec![0u8; 40] };
        assert!(kp.open_request(b"", b"", &bad).is_err());
        let empty = Sealed::default();
        assert!(kp.open_request(b"", b"", &empty).is_err());
    }
}
