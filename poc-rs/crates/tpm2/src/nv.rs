//! TPMS_NV_PUBLIC.

use crate::consts::*;
use crate::{Error, Reader, Result, Writer, object_name};

/// TPMS_NV_PUBLIC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvPublic {
    /// NV index handle.
    pub index: u32,
    /// Name algorithm.
    pub name_alg: u16,
    /// TPMA_NV bits.
    pub attributes: u32,
    /// Authorization policy.
    pub auth_policy: Vec<u8>,
    /// Size of the data area.
    pub data_size: u16,
}

impl NvPublic {
    /// Parses a complete TPMS_NV_PUBLIC.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let mut r = Reader::new(raw);
        let p = Self {
            index: r.u32()?,
            name_alg: r.u16()?,
            attributes: r.u32()?,
            auth_policy: r.tpm2b("authPolicy", MAX_DIGEST)?.to_vec(),
            data_size: r.u16()?,
        };
        r.finish()?;
        if p.to_bytes()? != raw {
            return Err(Error::Invalid("NV public area is not canonical".to_owned()));
        }
        Ok(p)
    }

    /// Canonical encoding.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.u32(self.index).u16(self.name_alg).u32(self.attributes);
        w.tpm2b(&self.auth_policy)?;
        w.u16(self.data_size);
        Ok(w.into_vec())
    }

    /// The NV index name.
    pub fn name(&self) -> Result<Vec<u8>> {
        object_name(self.name_alg, &self.to_bytes()?)
    }

    /// Whether every bit in `bits` is set.
    pub fn has(&self, bits: u32) -> bool {
        self.attributes & bits == bits
    }
}
