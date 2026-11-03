//! TPM hash algorithms.

use crate::consts::{ALG_SHA1, ALG_SHA256, ALG_SHA384, ALG_SHA512};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Digest;

/// A hash algorithm a TPM PCR bank or name algorithm may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HashAlg {
    /// SHA-1 (legacy PCR bank).
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl HashAlg {
    /// Looks up a TPM_ALG_ID.
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            ALG_SHA1 => Some(Self::Sha1),
            ALG_SHA256 => Some(Self::Sha256),
            ALG_SHA384 => Some(Self::Sha384),
            ALG_SHA512 => Some(Self::Sha512),
            _ => None,
        }
    }

    /// The TPM_ALG_ID.
    pub fn id(self) -> u16 {
        match self {
            Self::Sha1 => ALG_SHA1,
            Self::Sha256 => ALG_SHA256,
            Self::Sha384 => ALG_SHA384,
            Self::Sha512 => ALG_SHA512,
        }
    }

    /// Digest size in bytes.
    pub fn size(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Hashes one buffer.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        self.digest_parts(&[data])
    }

    /// Hashes the concatenation of several buffers.
    pub fn digest_parts(self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut h = D::new();
            for p in parts {
                h.update(p);
            }
            h.finalize().to_vec()
        }
        match self {
            Self::Sha1 => run::<sha1::Sha1>(parts),
            Self::Sha256 => run::<sha2::Sha256>(parts),
            Self::Sha384 => run::<sha2::Sha384>(parts),
            Self::Sha512 => run::<sha2::Sha512>(parts),
        }
    }

    /// HMAC over the concatenation of several buffers.
    pub fn hmac(self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        fn run<M: Mac + KeyInit>(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
            // HMAC accepts keys of any length; new_from_slice cannot fail.
            match <M as KeyInit>::new_from_slice(key) {
                Ok(mut m) => {
                    for p in parts {
                        m.update(p);
                    }
                    m.finalize().into_bytes().to_vec()
                }
                Err(_) => Vec::new(),
            }
        }
        match self {
            Self::Sha1 => run::<Hmac<sha1::Sha1>>(key, parts),
            Self::Sha256 => run::<Hmac<sha2::Sha256>>(key, parts),
            Self::Sha384 => run::<Hmac<sha2::Sha384>>(key, parts),
            Self::Sha512 => run::<Hmac<sha2::Sha512>>(key, parts),
        }
    }
}

/// An incremental hash for one [`HashAlg`].
#[derive(Debug, Clone)]
pub enum Hasher {
    /// SHA-1 state.
    Sha1(sha1::Sha1),
    /// SHA-256 state.
    Sha256(sha2::Sha256),
    /// SHA-384 state.
    Sha384(sha2::Sha384),
    /// SHA-512 state.
    Sha512(sha2::Sha512),
}

impl HashAlg {
    /// A fresh incremental hasher.
    pub fn hasher(self) -> Hasher {
        match self {
            Self::Sha1 => Hasher::Sha1(sha1::Sha1::new()),
            Self::Sha256 => Hasher::Sha256(sha2::Sha256::new()),
            Self::Sha384 => Hasher::Sha384(sha2::Sha384::new()),
            Self::Sha512 => Hasher::Sha512(sha2::Sha512::new()),
        }
    }
}

impl Hasher {
    /// Absorbs data.
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha1(h) => h.update(data),
            Self::Sha256(h) => h.update(data),
            Self::Sha384(h) => h.update(data),
            Self::Sha512(h) => h.update(data),
        }
    }

    /// The digest.
    pub fn finalize(self) -> Vec<u8> {
        match self {
            Self::Sha1(h) => h.finalize().to_vec(),
            Self::Sha256(h) => h.finalize().to_vec(),
            Self::Sha384(h) => h.finalize().to_vec(),
            Self::Sha512(h) => h.finalize().to_vec(),
        }
    }
}
