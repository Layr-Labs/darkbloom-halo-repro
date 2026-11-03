//! TPMT_SIGNATURE.

use crate::consts::*;
use crate::{Error, Reader, Result, Writer};

/// TPMT_SIGNATURE for the supported schemes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// TPM_ALG_NULL.
    Null,
    /// RSASSA-PKCS1-v1_5 or RSA-PSS.
    Rsa {
        /// TPM_ALG_RSASSA or TPM_ALG_RSAPSS.
        alg: u16,
        /// Hash algorithm.
        hash: u16,
        /// Signature bytes.
        sig: Vec<u8>,
    },
    /// ECDSA (or another (r, s) ECC scheme).
    Ecc {
        /// TPM_ALG_ECDSA, ECDAA, SM2 or ECSCHNORR.
        alg: u16,
        /// Hash algorithm.
        hash: u16,
        /// r, big-endian.
        r: Vec<u8>,
        /// s, big-endian.
        s: Vec<u8>,
    },
}

impl Signature {
    /// Parses a complete TPMT_SIGNATURE and checks it is canonical.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let mut r = Reader::new(raw);
        let s = Self::parse_from(&mut r)?;
        r.finish()?;
        if s.to_bytes()? != raw {
            return Err(Error::Invalid("signature encoding is not canonical".to_owned()));
        }
        Ok(s)
    }

    /// Parses a TPMT_SIGNATURE from a reader.
    pub fn parse_from(r: &mut Reader<'_>) -> Result<Self> {
        match r.u16()? {
            ALG_NULL => Ok(Self::Null),
            alg @ (ALG_RSASSA | ALG_RSAPSS) => {
                let hash = r.u16()?;
                let sig = r.tpm2b("RSA signature", MAX_RSA_BYTES)?.to_vec();
                Ok(Self::Rsa { alg, hash, sig })
            }
            alg @ (ALG_ECDSA | ALG_ECDAA | ALG_SM2 | ALG_ECSCHNORR) => {
                let hash = r.u16()?;
                let rr = r.tpm2b("ECC signature r", MAX_ECC_BYTES)?.to_vec();
                let s = r.tpm2b("ECC signature s", MAX_ECC_BYTES)?.to_vec();
                Ok(Self::Ecc { alg, hash, r: rr, s })
            }
            other => Err(Error::Unsupported { what: "signature algorithm", value: u32::from(other) }),
        }
    }

    /// Canonical encoding.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        match self {
            Self::Null => {
                w.u16(ALG_NULL);
            }
            Self::Rsa { alg, hash, sig } => {
                w.u16(*alg).u16(*hash);
                w.tpm2b(sig)?;
            }
            Self::Ecc { alg, hash, r, s } => {
                w.u16(*alg).u16(*hash);
                w.tpm2b(r)?;
                w.tpm2b(s)?;
            }
        }
        Ok(w.into_vec())
    }
}
