//! NV indices: endorsement certificates and (development) platform indices.

use crate::cmd::{Command, Params};
use crate::device::{Device, MAX_STRUCT, Tpm};
use crate::{Endorsement, Error, NV_ECC_EK_CERT, NV_PLUTON_DEV_CA, NV_PLUTON_FW_ICA, NV_RSA_EK_CERT, Result};
use db_tpm2::consts::*;
use db_tpm2::{NvPublic, Writer};

/// Attributes of the platform-created certificate indices the dev path
/// writes (Go `writePlatformNV`).
pub const PLATFORM_NV_ATTRIBUTES: u32 = NV_PPWRITE | NV_PPREAD | NV_OWNERREAD | NV_AUTHREAD | NV_NO_DA | NV_PLATFORMCREATE;

impl Tpm<'_> {
    pub(crate) fn nv_read_public(&mut self, index: u32) -> Result<(NvPublic, Vec<u8>)> {
        const NAME: &str = "TPM2_NV_ReadPublic";
        let rsp = self.run(NAME, &Command::new(CC_NV_READ_PUBLIC).handle(index), 0)?;
        let mut p = Params::new(NAME, &rsp.params);
        let raw = p.tpm2b("nvPublic", MAX_STRUCT)?;
        let name = p.tpm2b("nvName", MAX_NAME)?.to_vec();
        p.finish()?;
        let public = NvPublic::parse(raw).map_err(|e| p.err(format!("TPMS_NV_PUBLIC: {e}")))?;
        if public.index != index {
            return Err(p.err(format!("public area of index 0x{:08x}, asked for 0x{index:08x}", public.index)));
        }
        if public.name().map_err(|e| p.err(e))? != name {
            return Err(p.err("name does not match the public area"));
        }
        Ok((public, name))
    }

    fn nv_read(&mut self, auth: u32, index: u32, size: u16, offset: u16) -> Result<Vec<u8>> {
        const NAME: &str = "TPM2_NV_Read";
        let mut w = Writer::new();
        w.u16(size).u16(offset);
        let cmd = Command::new(CC_NV_READ).handle(auth).handle(index).password().params(w.into_vec());
        let rsp = self.run(NAME, &cmd, 0)?;
        let mut p = Params::new(NAME, &rsp.params);
        let data = p.tpm2b("data", usize::from(u16::MAX))?.to_vec();
        p.finish()?;
        if data.len() != usize::from(size) {
            return Err(p.err(format!("{} bytes, asked for {size}", data.len())));
        }
        Ok(data)
    }

    fn nv_define(&mut self, auth: u32, public: &NvPublic) -> Result<()> {
        let mut w = Writer::new();
        w.u16(0); // empty index auth value
        w.tpm2b(&public.to_bytes().map_err(Error::invalid)?).map_err(Error::invalid)?;
        let cmd = Command::new(CC_NV_DEFINE_SPACE).handle(auth).password().params(w.into_vec());
        self.run("TPM2_NV_DefineSpace", &cmd, 0).map(drop)
    }

    fn nv_write(&mut self, auth: u32, index: u32, data: &[u8], offset: u16) -> Result<()> {
        let mut w = Writer::new();
        w.tpm2b(data).map_err(Error::invalid)?;
        w.u16(offset);
        let cmd = Command::new(CC_NV_WRITE).handle(auth).handle(index).password().params(w.into_vec());
        self.run("TPM2_NV_Write", &cmd, 0).map(drop)
    }

    fn nv_undefine(&mut self, auth: u32, index: u32) -> Result<()> {
        let cmd = Command::new(CC_NV_UNDEFINE_SPACE).handle(auth).handle(index).password();
        self.run("TPM2_NV_UndefineSpace", &cmd, 0).map(drop)
    }
}

/// Drops NV padding after a DER certificate (NV indices are often larger
/// than the certificate they hold). Anything that is not a definite-length
/// SEQUENCE that fits is returned unchanged.
pub fn trim_der(b: &[u8]) -> &[u8] {
    let (Some(&0x30), Some(&l), true) = (b.first(), b.get(1), b.len() >= 4) else { return b };
    let total = match l {
        0..=0x7f => Some(2 + usize::from(l)),
        0x81 => b.get(2).map(|&n| 3 + usize::from(n)),
        0x82 => match (b.get(2), b.get(3)) {
            (Some(&hi), Some(&lo)) => Some(4 + (usize::from(hi) << 8) + usize::from(lo)),
            _ => None,
        },
        _ => None,
    };
    total.and_then(|n| b.get(..n)).unwrap_or(b)
}

impl Device {
    fn nv_chunk(&self, tpm: &mut Tpm<'_>) -> usize {
        self.nv_chunk_override().unwrap_or_else(|| tpm.nv_buffer_max()).clamp(1, usize::from(u16::MAX))
    }

    /// TPM2_NV_ReadPublic: the index's public area and name (validated).
    pub fn nv_read_public(&self, index: u32) -> Result<(NvPublic, Vec<u8>)> {
        self.tpm().nv_read_public(index)
    }

    /// Reads a whole NV index, authorizing with the index itself
    /// (AUTHREAD), the owner (OWNERREAD) or the platform (PPREAD), all with
    /// empty auth, in TPM_PT_NV_BUFFER_MAX chunks.
    pub fn read_nv(&self, index: u32) -> Result<Vec<u8>> {
        let mut tpm = self.tpm();
        let (public, _) = tpm.nv_read_public(index)?;
        let auth = if public.has(NV_AUTHREAD) {
            index
        } else if public.has(NV_OWNERREAD) {
            RH_OWNER
        } else if public.has(NV_PPREAD) {
            RH_PLATFORM
        } else {
            return Err(Error::invalid(format!("NV index 0x{index:08x} is not readable")));
        };
        let size = public.data_size;
        let chunk = u16::try_from(self.nv_chunk(&mut tpm)).unwrap_or(u16::MAX);
        let mut out = Vec::with_capacity(usize::from(size));
        let mut off: u16 = 0;
        while off < size {
            let n = chunk.min(size - off);
            out.extend(tpm.nv_read(auth, index, n, off)?);
            off += n;
        }
        Ok(out)
    }

    /// Stores `data` in a platform-created NV index (development only):
    /// removes any previous index, defines PPWRITE|PPREAD|OWNERREAD|
    /// AUTHREAD|NO_DA|PLATFORMCREATE with name algorithm SHA-256 and writes
    /// in TPM_PT_NV_BUFFER_MAX chunks (Go `writePlatformNV`).
    pub fn write_platform_nv(&self, index: u32, data: &[u8]) -> Result<()> {
        self.require_dev("write platform NV indices")?;
        let size = u16::try_from(data.len()).map_err(|_| Error::invalid(format!("{} bytes do not fit an NV index", data.len())))?;
        let mut tpm = self.tpm();
        if tpm.nv_read_public(index).is_ok() {
            let _ = tpm.nv_undefine(RH_PLATFORM, index);
        }
        let public = NvPublic { index, name_alg: ALG_SHA256, attributes: PLATFORM_NV_ATTRIBUTES, auth_policy: Vec::new(), data_size: size };
        tpm.nv_define(RH_PLATFORM, &public).map_err(Error::context(format!("define NV 0x{index:08x}")))?;
        let chunk = self.nv_chunk(&mut tpm);
        for (i, part) in data.chunks(chunk).enumerate() {
            let off = u16::try_from(i * chunk).map_err(Error::invalid)?;
            tpm.nv_write(RH_PLATFORM, index, part, off).map_err(Error::context(format!("write NV 0x{index:08x}")))?;
        }
        Ok(())
    }

    /// Removes a platform-created NV index (development only).
    pub fn undefine_platform_nv(&self, index: u32) -> Result<()> {
        self.require_dev("undefine platform NV indices")?;
        self.tpm().nv_undefine(RH_PLATFORM, index)
    }

    /// Creates the EK whose certificate is present (ECC preferred) and reads
    /// the certificate and any on-chip ICAs.
    pub fn load_endorsement(&self) -> Result<Endorsement> {
        for ecc in [true, false] {
            let idx = if ecc { NV_ECC_EK_CERT } else { NV_RSA_EK_CERT };
            let cert = match self.read_nv(idx) {
                Ok(c) if !c.is_empty() => c,
                _ => continue,
            };
            let ek = self.create_ek(ecc).map_err(Error::context("create EK"))?;
            let mut icas = Vec::new();
            for ica in [NV_PLUTON_FW_ICA, NV_PLUTON_DEV_CA] {
                if let Ok(b) = self.read_nv(ica)
                    && !b.is_empty()
                {
                    icas.push(trim_der(&b).to_vec());
                }
            }
            return Ok(Endorsement { ek, cert_der: trim_der(&cert).to_vec(), icas, ecc });
        }
        Err(Error::invalid("no EK certificate in NV (0x01C0000A or 0x01C00002)"))
    }
}

#[cfg(test)]
mod tests {
    use super::trim_der;

    #[test]
    fn trims_padding() {
        assert_eq!(trim_der(&[0x30, 0x02, 1, 2, 0xff, 0xff]), &[0x30, 0x02, 1, 2]);
        let mut long = vec![0x30, 0x81, 0x03, 1, 2, 3];
        long.extend([0u8; 10]);
        assert_eq!(trim_der(&long), &[0x30, 0x81, 0x03, 1, 2, 3]);
        let mut two = vec![0x30, 0x82, 0x01, 0x00];
        two.extend(vec![7u8; 256 + 5]);
        assert_eq!(trim_der(&two).len(), 260);
        // Unchanged: too short, not a SEQUENCE, length beyond the data.
        assert_eq!(trim_der(&[0x30, 0x05, 1]), &[0x30, 0x05, 1]);
        assert_eq!(trim_der(&[0x31, 0x01, 1, 2]), &[0x31, 0x01, 1, 2]);
        assert_eq!(trim_der(&[0x30, 0x82, 0xff, 0xff, 0]), &[0x30, 0x82, 0xff, 0xff, 0]);
        assert_eq!(trim_der(&[0x30, 0x83, 0, 0, 1]), &[0x30, 0x83, 0, 0, 1]);
        assert_eq!(trim_der(&[]), &[] as &[u8]);
    }
}
