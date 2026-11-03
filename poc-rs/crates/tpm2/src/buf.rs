//! Big-endian TPM marshaling primitives with bounds checks.

use crate::{Error, Result};

/// A cursor over untrusted bytes. Every read is bounds checked.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    /// Starts reading `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, off: 0 }
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.off)
    }

    /// Current offset.
    pub fn offset(&self) -> usize {
        self.off
    }

    /// Takes `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let have = self.remaining();
        if n > have {
            return Err(Error::Truncated { at: self.off, need: n, have });
        }
        let end = self.off + n;
        let out = self.buf.get(self.off..end).ok_or(Error::Truncated { at: self.off, need: n, have })?;
        self.off = end;
        Ok(out)
    }

    /// Takes a fixed-size array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let b = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(b);
        Ok(out)
    }

    /// Reads a byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    /// Reads a big-endian u16.
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    /// Reads a big-endian u32.
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// Reads a big-endian u64.
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// Reads a TPM2B (u16 size + bytes) no longer than `max`.
    pub fn tpm2b(&mut self, what: &'static str, max: usize) -> Result<&'a [u8]> {
        let n = usize::from(self.u16()?);
        if n > max {
            return Err(Error::TooLarge { what, len: n, max });
        }
        self.take(n)
    }

    /// Everything not yet consumed.
    pub fn rest(&mut self) -> &'a [u8] {
        let out = self.buf.get(self.off..).unwrap_or_default();
        self.off = self.buf.len();
        out
    }

    /// Fails unless the input was consumed exactly.
    pub fn finish(&self) -> Result<()> {
        match self.remaining() {
            0 => Ok(()),
            n => Err(Error::Trailing(n)),
        }
    }
}

/// A growable big-endian output buffer.
#[derive(Debug, Clone, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// An empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a byte.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    /// Appends a big-endian u16.
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Appends a big-endian u32.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Appends a big-endian u64.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Appends raw bytes.
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    /// Appends a TPM2B (u16 size + bytes).
    pub fn tpm2b(&mut self, v: &[u8]) -> Result<&mut Self> {
        let n = u16::try_from(v.len()).map_err(|_| Error::TooLarge { what: "TPM2B", len: v.len(), max: usize::from(u16::MAX) })?;
        self.u16(n);
        self.buf.extend_from_slice(v);
        Ok(self)
    }

    /// Current length.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing was written.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The bytes written.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Mutable access (for patching size fields).
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    /// Consumes the writer.
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}
