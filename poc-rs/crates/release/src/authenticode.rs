//! Authenticode PE image hashing (what UEFI firmware and shim measure into
//! PCR 4 for EV_EFI_BOOT_SERVICES_APPLICATION events).

use crate::{Error, Result};
use db_tpm2::HashAlg;
use std::ops::Range;

fn bad() -> Error {
    Error::invalid("not a PE image")
}

fn field<const N: usize>(pe: &[u8], off: usize) -> Result<[u8; N]> {
    let b = pe.get(off..off.checked_add(N).ok_or_else(bad)?).ok_or_else(bad)?;
    b.try_into().map_err(|_| bad())
}

fn le16(pe: &[u8], off: usize) -> Result<usize> {
    Ok(usize::from(u16::from_le_bytes(field(pe, off)?)))
}

fn le32(pe: &[u8], off: usize) -> Result<usize> {
    usize::try_from(u32::from_le_bytes(field(pe, off)?)).map_err(|_| bad())
}

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or_else(bad)
}

fn num_sections_hint(pe: &[u8]) -> usize {
    pe.len().min(96)
}

/// The byte ranges of `pe` that the Authenticode hash covers, in hashing
/// order. Follows the Authenticode PE specification as implemented by EDK2:
/// the headers without the checksum and the certificate-table directory
/// entry, then the sections in file order, then trailing data excluding the
/// certificate table.
pub fn authenticode_ranges(pe: &[u8]) -> Result<Vec<Range<usize>>> {
    if pe.len() < 0x40 || pe.get(..2) != Some(b"MZ") {
        return Err(bad());
    }
    let pe_off = le32(pe, 0x3c)?;
    if add(pe_off, 24)? > pe.len() || pe.get(pe_off..add(pe_off, 4)?) != Some(b"PE\0\0") {
        return Err(bad());
    }
    let coff = pe_off + 4;
    let num_sections = le16(pe, coff + 2)?;
    let opt_size = le16(pe, coff + 16)?;
    let opt = coff + 20;
    if add(opt, opt_size)? > pe.len() || opt_size < 96 {
        return Err(bad());
    }
    let (num_dirs_off, dirs_off) = match le16(pe, opt)? {
        0x10b => (opt + 92, opt + 96),   // PE32
        0x20b => (opt + 108, opt + 112), // PE32+
        _ => return Err(bad()),
    };
    let opt_end = opt + opt_size;
    let checksum_off = opt + 64;
    let size_of_headers = le32(pe, opt + 60)?;
    if size_of_headers > pe.len() || size_of_headers < checksum_off + 4 {
        return Err(bad());
    }
    // Every field read below must lie inside the optional header.
    if num_dirs_off + 4 > opt_end {
        return Err(bad());
    }
    let num_dirs = le32(pe, num_dirs_off)?;
    if num_dirs > 16 || add(dirs_off, 8 * num_dirs)? > opt_end {
        return Err(bad());
    }
    let cert_dir_off = dirs_off + 4 * 8;
    let mut cert_size = 0usize;
    let mut ranges = Vec::with_capacity(4 + num_sections_hint(pe));
    ranges.push(0..checksum_off);
    if num_dirs > 4 && cert_dir_off + 8 <= size_of_headers {
        ranges.push(checksum_off + 4..cert_dir_off);
        cert_size = le32(pe, cert_dir_off + 4)?;
        ranges.push(cert_dir_off + 8..size_of_headers);
    } else {
        ranges.push(checksum_off + 4..size_of_headers);
    }
    let sec_table = opt_end;
    if num_sections > 96 || add(sec_table, 40 * num_sections)? > pe.len() {
        return Err(bad());
    }
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let s = sec_table + 40 * i;
        let size = le32(pe, s + 16)?;
        let off = le32(pe, s + 20)?;
        if size == 0 {
            continue;
        }
        if add(off, size)? > pe.len() {
            return Err(bad());
        }
        sections.push(off..off + size);
    }
    sections.sort_by_key(|r| r.start);
    let mut sum = size_of_headers;
    for s in sections {
        sum = add(sum, s.len())?;
        ranges.push(s);
    }
    if pe.len() > sum {
        let covered = add(cert_size, sum)?;
        if pe.len() < covered {
            return Err(Error::invalid("PE certificate table overlaps sections"));
        }
        let extra = pe.len() - covered;
        if extra > 0 {
            ranges.push(sum..sum + extra);
        }
    }
    Ok(ranges)
}

/// The Authenticode digest of a PE image with the given hash algorithm.
pub fn authenticode_digest(pe: &[u8], alg: HashAlg) -> Result<Vec<u8>> {
    let ranges = authenticode_ranges(pe)?;
    let mut parts = Vec::with_capacity(ranges.len());
    for r in ranges {
        parts.push(pe.get(r).ok_or_else(bad)?);
    }
    Ok(alg.digest_parts(&parts))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
pub(crate) mod tests {
    use super::*;
    use rand::{RngExt as _, SeedableRng as _};

    /// A PE32+ image with one section and a certificate table (the Go
    /// test's `minimalPE`).
    pub(crate) fn minimal_pe(cert: &[u8]) -> Vec<u8> {
        let mut pe = vec![0u8; 0x400];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        pe[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        pe[coff + 16..coff + 18].copy_from_slice(&0xF0u16.to_le_bytes());
        let opt = coff + 20;
        pe[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        pe[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes());
        pe[opt + 64..opt + 68].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
        pe[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        let sec = opt + 0xF0;
        pe[sec..sec + 5].copy_from_slice(b".text");
        pe[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes());
        pe[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
        for (i, b) in pe.iter_mut().enumerate().skip(0x200) {
            *b = i as u8;
        }
        let cert_off = pe.len();
        pe.extend_from_slice(cert);
        pe[opt + 112 + 32..opt + 112 + 36].copy_from_slice(&(cert_off as u32).to_le_bytes());
        pe[opt + 112 + 36..opt + 112 + 40].copy_from_slice(&(cert.len() as u32).to_le_bytes());
        pe
    }

    #[test]
    fn ignores_signature_and_checksum() {
        let a = minimal_pe(b"signature-A");
        let mut b = minimal_pe(b"a different, longer signature blob");
        b[0x84 + 20 + 64..0x84 + 20 + 68].copy_from_slice(&0x12345678u32.to_le_bytes());
        let da = authenticode_digest(&a, HashAlg::Sha256).unwrap();
        assert_eq!(da, authenticode_digest(&b, HashAlg::Sha256).unwrap(), "must not cover checksum or certificate table");
        let mut c = minimal_pe(b"signature-A");
        c[0x300] ^= 1;
        assert_ne!(da, authenticode_digest(&c, HashAlg::Sha256).unwrap(), "must cover section data");
        assert!(authenticode_digest(b"not a PE", HashAlg::Sha256).is_err());
    }

    // Malformed PE images must be rejected, never crash the release tooling.
    #[test]
    fn malformed() {
        let good = minimal_pe(b"sig");
        let mut short = good.clone();
        short[0x84 + 16..0x84 + 18].copy_from_slice(&100u16.to_le_bytes());
        assert!(authenticode_digest(&short, HashAlg::Sha256).is_err(), "short PE32+ optional header accepted");
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        for i in 0..20000 {
            let mut b = good.clone();
            match i % 3 {
                0 => {
                    let n = rng.random_range(0..b.len());
                    b.truncate(n);
                }
                1 => {
                    for _ in 0..1 + rng.random_range(0..4) {
                        let j = rng.random_range(0..0x200);
                        b[j] = rng.random();
                    }
                }
                _ => {
                    let off = (0x84 + 20 + rng.random_range(0..0xF0)) & !3;
                    let v: u32 = rng.random();
                    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
                }
            }
            let _ = authenticode_digest(&b, HashAlg::Sha256);
        }
        // Fully random inputs, including ones that start like a PE.
        for _ in 0..5000 {
            let n = rng.random_range(0..0x600);
            let mut b: Vec<u8> = (0..n).map(|_| rng.random()).collect();
            if b.len() >= 0x40 {
                b[0] = b'M';
                b[1] = b'Z';
                b[0x3c..0x40].copy_from_slice(&(rng.random_range(0..0x500u32)).to_le_bytes());
            }
            let _ = authenticode_digest(&b, HashAlg::Sha1);
        }
    }
}
