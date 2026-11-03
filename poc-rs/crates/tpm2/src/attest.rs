//! TPMS_ATTEST (quote and certify attestations).

use crate::consts::*;
use crate::{Error, PcrSelectionList, Reader, Result, Writer};

/// The type-specific part of an attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attested {
    /// TPMS_QUOTE_INFO.
    Quote {
        /// The quoted PCRs.
        pcr_select: PcrSelectionList,
        /// Digest of the selected PCR values.
        pcr_digest: Vec<u8>,
    },
    /// TPMS_CERTIFY_INFO.
    Certify {
        /// Name of the certified object.
        name: Vec<u8>,
        /// Qualified name of the certified object.
        qualified_name: Vec<u8>,
    },
}

/// TPMS_ATTEST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attest {
    /// Must be TPM_GENERATED_VALUE.
    pub magic: u32,
    /// TPM_ST_ATTEST_*.
    pub attest_type: u16,
    /// Qualified name of the signing key.
    pub qualified_signer: Vec<u8>,
    /// Caller-supplied qualifying data.
    pub extra_data: Vec<u8>,
    /// TPMS_CLOCK_INFO.clock (ms).
    pub clock: u64,
    /// TPMS_CLOCK_INFO.resetCount.
    pub reset_count: u32,
    /// TPMS_CLOCK_INFO.restartCount.
    pub restart_count: u32,
    /// TPMS_CLOCK_INFO.safe.
    pub safe: bool,
    /// TPM firmware version.
    pub firmware_version: u64,
    /// Type-specific data.
    pub attested: Attested,
}

impl Attest {
    /// Parses a complete TPMS_ATTEST and checks it is canonical. Only quote
    /// and certify attestations are accepted.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let mut r = Reader::new(raw);
        let magic = r.u32()?;
        let attest_type = r.u16()?;
        let qualified_signer = r.tpm2b("qualifiedSigner", MAX_NAME)?.to_vec();
        let extra_data = r.tpm2b("extraData", MAX_NAME)?.to_vec();
        let clock = r.u64()?;
        let reset_count = r.u32()?;
        let restart_count = r.u32()?;
        let safe = match r.u8()? {
            0 => false,
            1 => true,
            v => return Err(Error::Invalid(format!("clockInfo.safe is {v}"))),
        };
        let firmware_version = r.u64()?;
        let attested = match attest_type {
            ST_ATTEST_QUOTE => {
                let pcr_select = PcrSelectionList::parse(&mut r)?;
                let pcr_digest = r.tpm2b("pcrDigest", MAX_DIGEST)?.to_vec();
                Attested::Quote { pcr_select, pcr_digest }
            }
            ST_ATTEST_CERTIFY => {
                let name = r.tpm2b("name", MAX_NAME)?.to_vec();
                let qualified_name = r.tpm2b("qualifiedName", MAX_NAME)?.to_vec();
                Attested::Certify { name, qualified_name }
            }
            other => return Err(Error::Unsupported { what: "attestation type", value: u32::from(other) }),
        };
        r.finish()?;
        let a =
            Self { magic, attest_type, qualified_signer, extra_data, clock, reset_count, restart_count, safe, firmware_version, attested };
        if a.to_bytes()? != raw {
            return Err(Error::Invalid("attestation structure is not canonical".to_owned()));
        }
        Ok(a)
    }

    /// Canonical encoding.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.u32(self.magic).u16(self.attest_type);
        w.tpm2b(&self.qualified_signer)?;
        w.tpm2b(&self.extra_data)?;
        w.u64(self.clock).u32(self.reset_count).u32(self.restart_count).u8(u8::from(self.safe));
        w.u64(self.firmware_version);
        match &self.attested {
            Attested::Quote { pcr_select, pcr_digest } => {
                pcr_select.marshal(&mut w)?;
                w.tpm2b(pcr_digest)?;
            }
            Attested::Certify { name, qualified_name } => {
                w.tpm2b(name)?;
                w.tpm2b(qualified_name)?;
            }
        }
        Ok(w.into_vec())
    }
}
