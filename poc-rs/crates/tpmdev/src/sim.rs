//! Development only: turns a fresh swtpm into something that looks like a
//! Halo to the verifier. It plays the TPM manufacturer (EK certificate and
//! on-chip ICA in NV) and the firmware (PCR extends and event log). Every
//! operation here refuses a hardware TPM.

use crate::device::Device;
use crate::{Error, NV_ECC_EK_CERT, NV_PLUTON_FW_ICA, Result};
use db_devca::DevCa;
use db_tpmattest::{LogEvent, PublicKey, build_event_log, hash_for};
use std::collections::BTreeMap;

/// PCRs that must still be in their reset state before a simulated boot.
const FRESH_PCRS: [u32; 4] = [0, 4, 9, 12];

impl Device {
    /// Extends `pcr` with one digest per bank (development only: on real
    /// hardware this would let software forge firmware measurements).
    pub fn pcr_extend(&self, pcr: u32, digests: &BTreeMap<u16, Vec<u8>>) -> Result<()> {
        self.require_dev("extend PCRs")?;
        let list: Vec<(u16, &[u8])> = digests.iter().map(|(&alg, d)| (alg, d.as_slice())).collect();
        self.tpm().pcr_extend(pcr, &list)
    }

    /// Extends the PCRs with the plan's events in all active banks with a
    /// supported hash and returns the matching TCG2 event log. Run it once
    /// per swtpm start (PCRs reset at TPM2_Startup(CLEAR)); PCRs 0, 4, 9 and
    /// 12 must be fresh. `plan` receives the banks and returns the events.
    pub fn simulate_boot<F>(&self, plan: F) -> Result<Vec<u8>>
    where
        F: FnOnce(&[u16]) -> std::result::Result<Vec<LogEvent>, String>,
    {
        self.require_dev("extend PCRs")?;
        let banks: Vec<u16> = self.active_banks()?.into_iter().filter(|&b| hash_for(b).is_some()).collect();
        if banks.is_empty() {
            return Err(Error::invalid("no supported PCR banks"));
        }
        let pcrs = self.read_pcrs(&FRESH_PCRS)?;
        if pcrs.values().any(|v| v.iter().any(|&b| b != 0)) {
            return Err(Error::invalid("PCRs are not fresh; restart swtpm before simulating a boot"));
        }
        let events = plan(&banks).map_err(|e| Error::invalid(format!("boot plan: {e}")))?;
        let mut tpm = self.tpm();
        for (i, ev) in events.iter().enumerate() {
            let mut list = Vec::with_capacity(banks.len());
            for &b in &banks {
                let d = ev
                    .digests
                    .get(&b)
                    .ok_or_else(|| Error::invalid(format!("event {i} (PCR {}) has no digest for bank 0x{b:04x}", ev.pcr)))?;
                list.push((b, d.as_slice()));
            }
            tpm.pcr_extend(ev.pcr, &list).map_err(Error::context(format!("extend PCR {}", ev.pcr)))?;
        }
        drop(tpm);
        build_event_log(&banks, &events).map_err(|e| Error::invalid(format!("event log: {e}")))
    }

    /// Plays TPM manufacturer: creates the ECC EK, issues an EK certificate
    /// from the dev ICA and stores it, plus the ICA, at the NV indices where
    /// Pluton keeps them (0x01C0000A and 0x01C00100).
    pub fn provision_ek(&self, ca: &DevCa) -> Result<()> {
        self.require_dev("provision an EK certificate")?;
        let ek = self.create_ek(true)?;
        let out = (|| {
            let spki =
                PublicKey::from_tpm(&ek.public).and_then(|k| k.to_spki_der()).map_err(|e| Error::invalid(format!("EK public key: {e}")))?;
            let der = ca.issue_ek_certificate(&spki, &ek.public_raw).map_err(|e| Error::invalid(format!("EK certificate: {e}")))?;
            self.write_platform_nv(NV_ECC_EK_CERT, &der)?;
            self.write_platform_nv(NV_PLUTON_FW_ICA, ca.ica_der())
        })();
        self.flush(&ek);
        out
    }
}
