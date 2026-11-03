//! PCR_Read, PCR_Extend and GetCapability.

use crate::cmd::{Command, Params};
use crate::device::{Device, Tpm};
use crate::{Error, Result};
use db_tpm2::consts::*;
use db_tpm2::{HashAlg, PcrSelection, PcrSelectionList, Writer};
use std::collections::BTreeMap;

/// Default NV chunk size when the TPM does not report TPM_PT_NV_BUFFER_MAX.
pub(crate) const DEFAULT_NV_BUFFER: usize = 512;
const MAX_PROPERTIES: usize = 256;
/// TPM_CAP_HANDLES.
const CAP_HANDLES: u32 = 0x0000_0001;
/// The first transient object handle (TPM_HT_TRANSIENT << 24).
const TRANSIENT_FIRST: u32 = 0x8000_0000;
const MAX_DIGESTS: usize = 64;

impl Tpm<'_> {
    /// One TPM2_PCR_Read: (selected PCRs in order, values).
    fn pcr_read(&mut self, bank: u16, pcrs: &[u32]) -> Result<(Vec<u32>, Vec<Vec<u8>>)> {
        const NAME: &str = "TPM2_PCR_Read";
        let mut w = Writer::new();
        PcrSelectionList(vec![PcrSelection::new(bank, pcrs)]).marshal(&mut w).map_err(Error::invalid)?;
        let rsp = self.run(NAME, &Command::new(CC_PCR_READ).params(w.into_vec()), 0)?;
        let mut p = Params::new(NAME, &rsp.params);
        p.u32()?; // pcrUpdateCounter
        let sels = p.pcr_selection()?;
        let count = usize::try_from(p.u32()?).map_err(|e| p.err(e))?;
        if count > MAX_DIGESTS {
            return Err(p.err(format!("{count} PCR values")));
        }
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(p.tpm2b("PCR value", MAX_DIGEST)?.to_vec());
        }
        p.finish()?;
        let mut got = Vec::new();
        for s in &sels.0 {
            if s.hash != bank {
                return Err(p.err(format!("returned bank 0x{:04x}, asked for 0x{bank:04x}", s.hash)));
            }
            got.extend(s.indices());
        }
        if got.len() != values.len() {
            return Err(p.err(format!("{} values for {} selected PCRs", values.len(), got.len())));
        }
        Ok((got, values))
    }

    /// Reads PCR values of one bank, looping because a TPM returns at most
    /// eight values per call (Go `ReadPCRs`).
    pub(crate) fn read_pcr_bank(&mut self, bank: u16, pcrs: &[u32]) -> Result<BTreeMap<u32, Vec<u8>>> {
        let size = HashAlg::from_id(bank).ok_or_else(|| Error::invalid(format!("unsupported PCR bank 0x{bank:04x}")))?.size();
        if let Some(p) = pcrs.iter().find(|&&p| p > 23) {
            return Err(Error::invalid(format!("PCR {p} out of range")));
        }
        let mut out = BTreeMap::new();
        let mut remaining = pcrs.to_vec();
        while !remaining.is_empty() {
            let (got, values) = self.pcr_read(bank, &remaining)?;
            if got.is_empty() || values.is_empty() {
                return Err(Error::invalid("PCR_Read returned nothing"));
            }
            for (p, v) in got.into_iter().zip(values) {
                if v.len() != size {
                    return Err(Error::Malformed { command: "TPM2_PCR_Read", detail: format!("PCR {p} value is {} bytes", v.len()) });
                }
                if remaining.contains(&p) {
                    out.insert(p, v);
                }
            }
            let next: Vec<u32> = remaining.iter().copied().filter(|p| !out.contains_key(p)).collect();
            if next.len() == remaining.len() {
                return Err(Error::invalid("PCR_Read made no progress"));
            }
            remaining = next;
        }
        Ok(out)
    }

    /// TPM2_GetCapability: the capability data after the selector.
    fn get_capability(&mut self, capability: u32, property: u32, count: u32) -> Result<Vec<u8>> {
        const NAME: &str = "TPM2_GetCapability";
        let mut w = Writer::new();
        w.u32(capability).u32(property).u32(count);
        let rsp = self.run(NAME, &Command::new(CC_GET_CAPABILITY).params(w.into_vec()), 0)?;
        let mut p = Params::new(NAME, &rsp.params);
        if p.u8()? > 1 {
            return Err(p.err("moreData is not a boolean"));
        }
        let got = p.u32()?;
        if got != capability {
            return Err(p.err(format!("capability 0x{got:08x}, asked for 0x{capability:08x}")));
        }
        Ok(p.r.rest().to_vec())
    }

    /// Allocated PCR banks (those with at least one PCR selected).
    pub(crate) fn active_banks(&mut self) -> Result<Vec<u16>> {
        let data = self.get_capability(CAP_PCRS, 0, 8)?;
        let mut p = Params::new("TPM2_GetCapability", &data);
        let sels = p.pcr_selection()?;
        p.finish()?;
        Ok(sels.0.iter().filter(|s| s.select.iter().any(|&b| b != 0)).map(|s| s.hash).collect())
    }

    /// TPM_PT_NV_BUFFER_MAX (512 if unavailable).
    pub(crate) fn nv_buffer_max(&mut self) -> usize {
        let Ok(data) = self.get_capability(CAP_TPM_PROPERTIES, PT_NV_BUFFER_MAX, 1) else {
            return DEFAULT_NV_BUFFER;
        };
        let mut p = Params::new("TPM2_GetCapability", &data);
        let props = (|| {
            let n = usize::try_from(p.u32()?).unwrap_or(usize::MAX);
            if n > MAX_PROPERTIES {
                return Err(p.err("too many properties"));
            }
            let mut out = Vec::with_capacity(n);
            for _ in 0..n {
                out.push((p.u32()?, p.u32()?));
            }
            p.finish()?;
            Ok(out)
        })();
        props
            .ok()
            .and_then(|ps| ps.into_iter().find(|&(prop, v)| prop == PT_NV_BUFFER_MAX && v > 0))
            .and_then(|(_, v)| usize::try_from(v).ok())
            .unwrap_or(DEFAULT_NV_BUFFER)
    }

    /// Flushes every loaded transient object (swtpm has no resource manager:
    /// objects a previous, killed client left loaded exhaust its few slots;
    /// the kernel's /dev/tpmrm0 does this cleanup for real TPMs). Errors are
    /// ignored, as in the Go reference.
    pub(crate) fn flush_transient(&mut self) {
        let Ok(data) = self.get_capability(CAP_HANDLES, TRANSIENT_FIRST, 64) else { return };
        let mut p = Params::new("TPM2_GetCapability", &data);
        let handles = (|| {
            let n = usize::try_from(p.u32()?).unwrap_or(usize::MAX);
            if n > MAX_PROPERTIES {
                return Err(p.err("too many handles"));
            }
            let mut out = Vec::with_capacity(n);
            for _ in 0..n {
                out.push(p.u32()?);
            }
            p.finish()?;
            Ok(out)
        })();
        for h in handles.unwrap_or_default() {
            if h >> 24 == TRANSIENT_FIRST >> 24 {
                let _ = self.flush(h);
            }
        }
    }

    /// TPM2_PCR_Extend with one digest per bank.
    pub(crate) fn pcr_extend(&mut self, pcr: u32, digests: &[(u16, &[u8])]) -> Result<()> {
        if pcr > 23 {
            return Err(Error::invalid(format!("PCR {pcr} out of range")));
        }
        let mut w = Writer::new();
        w.u32(u32::try_from(digests.len()).map_err(Error::invalid)?);
        for &(alg, d) in digests {
            let h = HashAlg::from_id(alg).ok_or_else(|| Error::invalid(format!("unsupported PCR bank 0x{alg:04x}")))?;
            if d.len() != h.size() {
                return Err(Error::invalid(format!("digest for bank 0x{alg:04x} is {} bytes, want {}", d.len(), h.size())));
            }
            w.u16(alg).bytes(d);
        }
        let cmd = Command::new(CC_PCR_EXTEND).handle(pcr).password().params(w.into_vec());
        self.run("TPM2_PCR_Extend", &cmd, 0).map(drop)
    }
}

impl Device {
    /// Reads SHA-256 PCR values.
    pub fn read_pcrs(&self, pcrs: &[u32]) -> Result<BTreeMap<u32, Vec<u8>>> {
        self.read_pcr_bank(ALG_SHA256, pcrs)
    }

    /// Reads PCR values of any supported bank.
    pub fn read_pcr_bank(&self, bank: u16, pcrs: &[u32]) -> Result<BTreeMap<u32, Vec<u8>>> {
        self.tpm().read_pcr_bank(bank, pcrs)
    }

    /// Lists allocated PCR banks (TPM_ALG_ID values).
    pub fn active_banks(&self) -> Result<Vec<u16>> {
        self.tpm().active_banks()
    }

    /// The NV chunk size: TPM_PT_NV_BUFFER_MAX (512 if unavailable).
    pub fn nv_buffer_max(&self) -> usize {
        match self.nv_chunk_override() {
            Some(n) => n,
            None => self.tpm().nv_buffer_max(),
        }
    }
}
