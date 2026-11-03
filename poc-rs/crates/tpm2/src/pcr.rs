//! TPMS_PCR_SELECTION / TPML_PCR_SELECTION.

use crate::consts::{MAX_PCR_BANKS, MAX_PCR_SELECT};
use crate::{Error, Reader, Result, Writer};

/// One bank's PCR bitmap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrSelection {
    /// Hash algorithm of the bank.
    pub hash: u16,
    /// Bitmap: bit `i % 8` of byte `i / 8` selects PCR `i`.
    pub select: Vec<u8>,
}

impl PcrSelection {
    /// A 3-byte (24 PCR) bitmap selecting `pcrs` in `bank`. Out-of-range
    /// indices are ignored, as in the Go reference.
    pub fn new(bank: u16, pcrs: &[u32]) -> Self {
        let mut select = vec![0u8; 3];
        for &p in pcrs {
            if p < 24
                && let Some(b) = select.get_mut((p / 8) as usize)
            {
                *b |= 1 << (p % 8);
            }
        }
        Self { hash: bank, select }
    }

    /// The selected PCR indices in ascending order.
    pub fn indices(&self) -> Vec<u32> {
        let mut out = Vec::new();
        for (i, b) in (0u32..).zip(self.select.iter()) {
            for bit in 0..8u32 {
                if b & (1 << bit) != 0 {
                    out.push(i * 8 + bit);
                }
            }
        }
        out
    }

    fn parse(r: &mut Reader<'_>) -> Result<Self> {
        let hash = r.u16()?;
        let n = usize::from(r.u8()?);
        if n > MAX_PCR_SELECT {
            return Err(Error::TooLarge { what: "PCR bitmap", len: n, max: MAX_PCR_SELECT });
        }
        Ok(Self { hash, select: r.take(n)?.to_vec() })
    }

    fn marshal(&self, w: &mut Writer) -> Result<()> {
        let n = u8::try_from(self.select.len()).map_err(|_| Error::TooLarge {
            what: "PCR bitmap",
            len: self.select.len(),
            max: MAX_PCR_SELECT,
        })?;
        w.u16(self.hash).u8(n).bytes(&self.select);
        Ok(())
    }
}

/// A TPML_PCR_SELECTION.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PcrSelectionList(pub Vec<PcrSelection>);

impl PcrSelectionList {
    /// Parses from a reader (used inside larger structures).
    pub fn parse(r: &mut Reader<'_>) -> Result<Self> {
        let count = usize::try_from(r.u32()?).unwrap_or(usize::MAX);
        if count > MAX_PCR_BANKS {
            return Err(Error::TooLarge { what: "PCR selection list", len: count, max: MAX_PCR_BANKS });
        }
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(PcrSelection::parse(r)?);
        }
        Ok(Self(out))
    }

    /// Marshals into a writer.
    pub fn marshal(&self, w: &mut Writer) -> Result<()> {
        let n = u32::try_from(self.0.len()).map_err(|_| Error::TooLarge {
            what: "PCR selection list",
            len: self.0.len(),
            max: MAX_PCR_BANKS,
        })?;
        w.u32(n);
        for s in &self.0 {
            s.marshal(w)?;
        }
        Ok(())
    }

    /// Standalone encoding.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        self.marshal(&mut w)?;
        Ok(w.into_vec())
    }
}
