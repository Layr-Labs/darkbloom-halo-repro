//! Deterministic PCR 11 measurement of a single-profile systemd UKI.
//!
//! UAPI.5 measures each UKI-defined PE section in canonical order: first
//! SHA-256(section name including NUL), then SHA-256(section's VirtualSize
//! bytes). The PE file order and raw padding do not enter PCR 11.

use crate::{Artifact, Error, Result, is_sha256_hex};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// UKI-defined PE sections in UAPI.5 measurement order (excluding `.pcrsig`).
const ORDER: [&str; 10] = [".linux", ".osrel", ".cmdline", ".initrd", ".ucode", ".splash", ".dtb", ".uname", ".sbat", ".pcrpkey"];

fn invalid(msg: impl Into<String>) -> Error {
    Error::invalid(format!("UKI: {}", msg.into()))
}

fn field<const N: usize>(data: &[u8], at: usize) -> Result<[u8; N]> {
    data.get(at..at.checked_add(N).ok_or_else(|| invalid("offset overflow"))?)
        .ok_or_else(|| invalid("truncated PE"))?
        .try_into()
        .map_err(|_| invalid("truncated PE"))
}

fn u16_at(data: &[u8], at: usize) -> Result<usize> {
    Ok(u16::from_le_bytes(field(data, at)?) as usize)
}

fn u32_at(data: &[u8], at: usize) -> Result<usize> {
    Ok(u32::from_le_bytes(field(data, at)?) as usize)
}

fn checked_end(at: usize, len: usize, limit: usize) -> Result<usize> {
    let end = at.checked_add(len).ok_or_else(|| invalid("offset overflow"))?;
    if end > limit {
        return Err(invalid("section exceeds PE image"));
    }
    Ok(end)
}

/// Parsed UKI sections in canonical measurement order. Dynamic profile and
/// hardware-selected sections are refused because their PCR 11 cannot be
/// predicted from the image alone.
pub fn sections(pe: &[u8]) -> Result<Vec<(Artifact, Vec<u8>)>> {
    if pe.get(..2) != Some(b"MZ") {
        return Err(invalid("missing MZ header"));
    }
    let pe_off = u32_at(pe, 0x3c)?;
    if pe.get(pe_off..checked_end(pe_off, 4, pe.len())?) != Some(b"PE\0\0") {
        return Err(invalid("missing PE signature"));
    }
    let coff = pe_off + 4;
    let count = u16_at(pe, coff + 2)?;
    if count > 96 {
        return Err(invalid("too many PE sections"));
    }
    let optional = coff + 20;
    let opt_len = u16_at(pe, coff + 16)?;
    let table = checked_end(optional, opt_len, pe.len())?;
    if !matches!(u16_at(pe, optional)?, 0x10b | 0x20b) {
        return Err(invalid("unsupported PE optional header"));
    }
    checked_end(table, count.checked_mul(40).ok_or_else(|| invalid("section table overflow"))?, pe.len())?;
    let mut found: BTreeMap<String, (Artifact, Vec<u8>)> = BTreeMap::new();
    for i in 0..count {
        let at = table + i * 40;
        let name_raw = field::<8>(pe, at)?;
        let name_end = name_raw.iter().position(|&b| b == 0).unwrap_or(8);
        let name = std::str::from_utf8(name_raw.get(..name_end).ok_or_else(|| invalid("bad section name length"))?)
            .map_err(|_| invalid("non-ASCII section name"))?;
        if matches!(name, ".profile" | ".dtbauto" | ".efifw" | ".hwids") {
            return Err(invalid(format!("selection-dependent section {name} is unsupported")));
        }
        if name == ".pcrsig" || !ORDER.contains(&name) {
            continue;
        }
        let virtual_size = u32_at(pe, at + 8)?;
        let raw_size = u32_at(pe, at + 16)?;
        let raw_at = u32_at(pe, at + 20)?;
        if virtual_size == 0 || virtual_size > raw_size {
            return Err(invalid(format!("{name} has no complete on-disk virtual data")));
        }
        let end = checked_end(raw_at, virtual_size, pe.len())?;
        let data = pe.get(raw_at..end).ok_or_else(|| invalid("section exceeds PE image"))?.to_vec();
        let artifact = Artifact { name: name.to_owned(), sha256: hex::encode(Sha256::digest(&data)), bytes: virtual_size as i64 };
        if found.insert(name.to_owned(), (artifact, data)).is_some() {
            return Err(invalid(format!("duplicate {name} section")));
        }
    }
    for name in [".linux", ".cmdline", ".initrd"] {
        if !found.contains_key(name) {
            return Err(invalid(format!("required {name} section missing")));
        }
    }
    Ok(ORDER.iter().filter_map(|name| found.remove(*name)).collect())
}

/// Compute the SHA-256 PCR 11 value from the exact measured section names
/// and content digests. The list must be in canonical order and complete.
pub fn predict_pcr11(sections: &[Artifact]) -> Result<[u8; 32]> {
    if sections.is_empty() {
        return Err(invalid("no measured sections"));
    }
    let mut last = None;
    let mut have = [false; 3];
    let mut pcr = [0u8; 32];
    for s in sections {
        let idx = ORDER.iter().position(|&name| name == s.name).ok_or_else(|| invalid(format!("unsupported section {}", s.name)))?;
        if last.is_some_and(|previous| idx <= previous) {
            return Err(invalid("sections are duplicated or out of canonical order"));
        }
        last = Some(idx);
        if idx == 0 {
            have[0] = true;
        }
        if idx == 2 {
            have[1] = true;
        }
        if idx == 3 {
            have[2] = true;
        }
        if s.bytes <= 0 || !is_sha256_hex(&s.sha256) {
            return Err(invalid(format!("invalid size or digest for {}", s.name)));
        }
        let mut name = s.name.as_bytes().to_vec();
        name.push(0);
        pcr = Sha256::digest([pcr.as_slice(), Sha256::digest(&name).as_slice()].concat()).into();
        let digest = hex::decode(&s.sha256).map_err(|_| invalid("bad section digest"))?;
        pcr = Sha256::digest([pcr.as_slice(), digest.as_slice()].concat()).into();
    }
    if !have.iter().all(|&x| x) {
        return Err(invalid(".linux, .cmdline and .initrd are required"));
    }
    Ok(pcr)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn tiny_uki() -> Vec<u8> {
        let mut pe = crate::authenticode::tests::minimal_pe(&[]);
        pe.resize(0x800, 0);
        pe[0x84 + 2..0x84 + 4].copy_from_slice(&3u16.to_le_bytes());
        let table = 0x84 + 20 + 0xf0;
        for (i, (name, content)) in
            [(".linux", b"kernel".as_slice()), (".cmdline", b"quiet\n".as_slice()), (".initrd", b"initrd".as_slice())].iter().enumerate()
        {
            let at = table + i * 40;
            pe[at..at + 8].fill(0);
            pe[at..at + name.len()].copy_from_slice(name.as_bytes());
            pe[at + 8..at + 12].copy_from_slice(&(content.len() as u32).to_le_bytes());
            pe[at + 16..at + 20].copy_from_slice(&0x200u32.to_le_bytes());
            pe[at + 20..at + 24].copy_from_slice(&(0x200u32 + i as u32 * 0x200).to_le_bytes());
            let off = 0x200 + i * 0x200;
            pe[off..off + content.len()].copy_from_slice(content);
            pe[off + content.len()..off + 0x200].fill(0xa5); // raw padding must be ignored
        }
        pe
    }

    #[test]
    fn extracts_virtual_size_and_predicts_canonical_order() {
        let pe = tiny_uki();
        let measured = sections(&pe).unwrap();
        assert_eq!(measured.iter().map(|(a, _)| a.name.as_str()).collect::<Vec<_>>(), [".linux", ".cmdline", ".initrd"]);
        assert_eq!(measured[1].1, b"quiet\n");
        let artifacts = measured.iter().map(|(a, _)| a.clone()).collect::<Vec<_>>();
        let expected = predict_pcr11(&artifacts).unwrap();
        let mut padding_changed = pe.clone();
        padding_changed[0x400 + 40] ^= 1;
        let again = sections(&padding_changed).unwrap();
        assert_eq!(predict_pcr11(&again.iter().map(|(a, _)| a.clone()).collect::<Vec<_>>()).unwrap(), expected);
        let mut cmdline_changed = pe;
        cmdline_changed[0x400] ^= 1;
        let changed = sections(&cmdline_changed).unwrap();
        assert_ne!(predict_pcr11(&changed.iter().map(|(a, _)| a.clone()).collect::<Vec<_>>()).unwrap(), expected);
    }
}
