//! TPMT_PUBLIC for RSA and ECC objects.

use crate::consts::*;
use crate::{Error, Reader, Result, Writer, object_name};

/// TPMT_SYM_DEF_OBJECT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymDefObject {
    /// TPM_ALG_NULL.
    Null,
    /// A block cipher (AES, SM4 or Camellia) with key size and mode.
    Cipher {
        /// Cipher algorithm.
        algorithm: u16,
        /// Key size in bits.
        key_bits: u16,
        /// Mode (CFB for storage/EK keys).
        mode: u16,
    },
}

impl SymDefObject {
    fn parse(r: &mut Reader<'_>) -> Result<Self> {
        match r.u16()? {
            ALG_NULL => Ok(Self::Null),
            algorithm @ (ALG_AES | ALG_SM4 | ALG_CAMELLIA) => Ok(Self::Cipher { algorithm, key_bits: r.u16()?, mode: r.u16()? }),
            other => Err(Error::Unsupported { what: "symmetric algorithm", value: u32::from(other) }),
        }
    }

    fn marshal(&self, w: &mut Writer) {
        match *self {
            Self::Null => {
                w.u16(ALG_NULL);
            }
            Self::Cipher { algorithm, key_bits, mode } => {
                w.u16(algorithm).u16(key_bits).u16(mode);
            }
        }
    }
}

/// Details of an asymmetric scheme (TPMU_ASYM_SCHEME).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemeDetails {
    /// No details (TPM_ALG_NULL or RSAES).
    None,
    /// A hash algorithm.
    Hash(u16),
    /// ECDAA: hash algorithm and commit count.
    HashCount(u16, u16),
}

/// TPMT_RSA_SCHEME / TPMT_ECC_SCHEME.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsymScheme {
    /// Scheme selector (TPM_ALG_NULL when unrestricted).
    pub scheme: u16,
    /// Scheme parameters.
    pub details: SchemeDetails,
}

impl AsymScheme {
    /// The NULL scheme.
    pub const NULL: Self = Self { scheme: ALG_NULL, details: SchemeDetails::None };

    /// The scheme's hash algorithm, if it has one.
    pub fn hash(&self) -> Option<u16> {
        match self.details {
            SchemeDetails::Hash(h) | SchemeDetails::HashCount(h, _) => Some(h),
            SchemeDetails::None => None,
        }
    }

    fn parse(r: &mut Reader<'_>) -> Result<Self> {
        let scheme = r.u16()?;
        let details = match scheme {
            ALG_NULL | ALG_RSAES => SchemeDetails::None,
            ALG_RSASSA | ALG_RSAPSS | ALG_OAEP | ALG_ECDSA | ALG_SM2 | ALG_ECSCHNORR | ALG_ECDH | ALG_ECMQV => {
                SchemeDetails::Hash(r.u16()?)
            }
            ALG_ECDAA => SchemeDetails::HashCount(r.u16()?, r.u16()?),
            other => return Err(Error::Unsupported { what: "asymmetric scheme", value: u32::from(other) }),
        };
        Ok(Self { scheme, details })
    }

    fn marshal(&self, w: &mut Writer) {
        w.u16(self.scheme);
        match self.details {
            SchemeDetails::None => {}
            SchemeDetails::Hash(h) => {
                w.u16(h);
            }
            SchemeDetails::HashCount(h, c) => {
                w.u16(h).u16(c);
            }
        }
    }
}

/// TPMT_KDF_SCHEME.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfScheme {
    /// KDF selector.
    pub scheme: u16,
    /// Hash algorithm (absent for TPM_ALG_NULL).
    pub hash: Option<u16>,
}

impl KdfScheme {
    /// The NULL KDF.
    pub const NULL: Self = Self { scheme: ALG_NULL, hash: None };

    fn parse(r: &mut Reader<'_>) -> Result<Self> {
        let scheme = r.u16()?;
        let hash = match scheme {
            ALG_NULL => None,
            ALG_MGF1 | ALG_KDF1_SP800_56A | ALG_KDF2 | ALG_KDF1_SP800_108 => Some(r.u16()?),
            other => return Err(Error::Unsupported { what: "KDF scheme", value: u32::from(other) }),
        };
        Ok(Self { scheme, hash })
    }

    fn marshal(&self, w: &mut Writer) {
        w.u16(self.scheme);
        if let Some(h) = self.hash {
            w.u16(h);
        }
    }
}

/// TPMS_RSA_PARMS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsaParms {
    /// Symmetric algorithm for restricted decryption keys.
    pub symmetric: SymDefObject,
    /// Signing or encryption scheme.
    pub scheme: AsymScheme,
    /// Modulus size.
    pub key_bits: u16,
    /// Public exponent (0 means 65537).
    pub exponent: u32,
}

/// TPMS_ECC_PARMS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EccParms {
    /// Symmetric algorithm for restricted decryption keys.
    pub symmetric: SymDefObject,
    /// Signing or key-exchange scheme.
    pub scheme: AsymScheme,
    /// TPM_ECC_CURVE.
    pub curve_id: u16,
    /// KDF.
    pub kdf: KdfScheme,
}

/// TPMU_PUBLIC_PARMS for the supported object types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicParams {
    /// RSA key.
    Rsa(RsaParms),
    /// ECC key.
    Ecc(EccParms),
}

/// TPMU_PUBLIC_ID for the supported object types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unique {
    /// RSA modulus (big-endian).
    Rsa(Vec<u8>),
    /// ECC point coordinates (big-endian).
    Ecc {
        /// X coordinate.
        x: Vec<u8>,
        /// Y coordinate.
        y: Vec<u8>,
    },
}

/// TPMT_PUBLIC (RSA and ECC objects only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Public {
    /// Name algorithm.
    pub name_alg: u16,
    /// TPMA_OBJECT bits.
    pub attributes: u32,
    /// Authorization policy digest.
    pub auth_policy: Vec<u8>,
    /// Type-specific parameters (also determines the type).
    pub params: PublicParams,
    /// Type-specific public key.
    pub unique: Unique,
}

impl Public {
    /// The TPM_ALG_ID of the object type.
    pub fn alg_type(&self) -> u16 {
        match self.params {
            PublicParams::Rsa(_) => ALG_RSA,
            PublicParams::Ecc(_) => ALG_ECC,
        }
    }

    /// Whether every bit in `bits` is set.
    pub fn has(&self, bits: u32) -> bool {
        self.attributes & bits == bits
    }

    /// Parses a complete TPMT_PUBLIC and checks that it is canonical (it
    /// re-marshals to exactly `raw`).
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let mut r = Reader::new(raw);
        let p = Self::parse_from(&mut r)?;
        r.finish()?;
        if p.to_bytes()? != raw {
            return Err(Error::Invalid("public area is not canonical".to_owned()));
        }
        Ok(p)
    }

    /// Parses a TPMT_PUBLIC from a reader.
    pub fn parse_from(r: &mut Reader<'_>) -> Result<Self> {
        let typ = r.u16()?;
        if typ != ALG_RSA && typ != ALG_ECC {
            return Err(Error::Unsupported { what: "object type", value: u32::from(typ) });
        }
        let name_alg = r.u16()?;
        let attributes = r.u32()?;
        let auth_policy = r.tpm2b("authPolicy", MAX_DIGEST)?.to_vec();
        let (params, unique) = if typ == ALG_RSA {
            let symmetric = SymDefObject::parse(r)?;
            let scheme = AsymScheme::parse(r)?;
            let key_bits = r.u16()?;
            let exponent = r.u32()?;
            let n = r.tpm2b("RSA modulus", MAX_RSA_BYTES)?.to_vec();
            (PublicParams::Rsa(RsaParms { symmetric, scheme, key_bits, exponent }), Unique::Rsa(n))
        } else {
            let symmetric = SymDefObject::parse(r)?;
            let scheme = AsymScheme::parse(r)?;
            let curve_id = r.u16()?;
            let kdf = KdfScheme::parse(r)?;
            let x = r.tpm2b("ECC x", MAX_ECC_BYTES)?.to_vec();
            let y = r.tpm2b("ECC y", MAX_ECC_BYTES)?.to_vec();
            (PublicParams::Ecc(EccParms { symmetric, scheme, curve_id, kdf }), Unique::Ecc { x, y })
        };
        match (&params, &unique) {
            (PublicParams::Rsa(_), Unique::Rsa(_)) | (PublicParams::Ecc(_), Unique::Ecc { .. }) => {}
            _ => return Err(Error::Invalid("public parameters and unique field disagree".to_owned())),
        }
        Ok(Self { name_alg, attributes, auth_policy, params, unique })
    }

    /// Canonical TPMT_PUBLIC encoding.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        self.marshal(&mut w)?;
        Ok(w.into_vec())
    }

    /// Marshals into a writer.
    pub fn marshal(&self, w: &mut Writer) -> Result<()> {
        w.u16(self.alg_type()).u16(self.name_alg).u32(self.attributes);
        w.tpm2b(&self.auth_policy)?;
        match (&self.params, &self.unique) {
            (PublicParams::Rsa(p), Unique::Rsa(n)) => {
                p.symmetric.marshal(w);
                p.scheme.marshal(w);
                w.u16(p.key_bits).u32(p.exponent);
                w.tpm2b(n)?;
            }
            (PublicParams::Ecc(p), Unique::Ecc { x, y }) => {
                p.symmetric.marshal(w);
                p.scheme.marshal(w);
                w.u16(p.curve_id);
                p.kdf.marshal(w);
                w.tpm2b(x)?;
                w.tpm2b(y)?;
            }
            _ => return Err(Error::Invalid("public parameters and unique field disagree".to_owned())),
        }
        Ok(())
    }

    /// The object's TPM name (`nameAlg || H(TPMT_PUBLIC)`).
    pub fn name(&self) -> Result<Vec<u8>> {
        object_name(self.name_alg, &self.to_bytes()?)
    }

    /// The symmetric definition of a storage/endorsement key.
    pub fn symmetric(&self) -> SymDefObject {
        match self.params {
            PublicParams::Rsa(p) => p.symmetric,
            PublicParams::Ecc(p) => p.symmetric,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::{ak_template, ecc_ek_template, rsa_ek_template};
    use rand::RngExt as _;

    #[test]
    fn templates_round_trip() {
        for t in [ak_template(), ecc_ek_template(), rsa_ek_template()] {
            let b = t.to_bytes().unwrap();
            assert_eq!(Public::parse(&b).unwrap(), t);
        }
    }

    // Truncated or corrupted public areas must fail cleanly, never panic,
    // and anything accepted must be canonical.
    #[test]
    fn robustness() {
        let mut rng = rand::rng();
        for t in [ak_template(), ecc_ek_template(), rsa_ek_template()] {
            let b = t.to_bytes().unwrap();
            for n in 0..b.len() {
                assert!(Public::parse(&b[..n]).is_err());
            }
            let mut extra = b.clone();
            extra.push(0);
            assert!(Public::parse(&extra).is_err());
            for _ in 0..5000 {
                let mut m = b.clone();
                for _ in 0..rng.random_range(1..4) {
                    let i = rng.random_range(0..m.len());
                    m[i] = rng.random();
                }
                if let Ok(p) = Public::parse(&m) {
                    assert_eq!(p.to_bytes().unwrap(), m);
                }
            }
        }
    }
}
