//! Offline prediction of the Halo's boot-chain PCRs from public artifacts.

use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::io::Read as _;
use std::path::Path;

/// The digest systemd-boot (PCR 12) and the Linux EFI stub (PCR 9) measure
/// for a kernel command line: SHA-256 over the UTF-16LE string including its
/// NUL terminator (systemd's `strsize16()`).
pub fn load_options_digest(cmdline: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    for u in cmdline.encode_utf16().chain(std::iter::once(0)) {
        h.update(u.to_le_bytes());
    }
    h.finalize().into()
}

fn extend(pcr: &[u8], digest: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(pcr);
    h.update(digest);
    h.finalize().into()
}

/// PCR 4 for a boot through a firmware Boot#### option: EV_EFI_ACTION
/// "Calling EFI Application from Boot Option", EV_SEPARATOR, then one
/// EV_EFI_BOOT_SERVICES_APPLICATION per boot application with its
/// Authenticode SHA-256 (shim, systemd-boot, kernel).
pub fn predict_pcr4(apps: &[Vec<u8>]) -> [u8; 32] {
    let action: [u8; 32] = Sha256::digest(b"Calling EFI Application from Boot Option").into();
    let separator: [u8; 32] = Sha256::digest([0u8; 4]).into();
    let mut p = extend(&[0u8; 32], &action);
    p = extend(&p, &separator);
    for a in apps {
        p = extend(&p, a);
    }
    p
}

/// PCR values a Type #1 boot of a given initrd and command line produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prediction {
    /// The command line.
    pub load_options: String,
    /// Its load-options digest (hex).
    pub load_options_sha256: String,
    /// Initrd SHA-256 (hex).
    pub initrd_sha256: String,
    /// Expected PCR 9 (hex).
    pub pcr9_sha256: String,
    /// Expected PCR 12 (hex).
    pub pcr12_sha256: String,
}

/// Computes PCR 9 and PCR 12 offline:
///
/// ```text
/// PCR12 = H(0^32 || H(utf16(cmdline)||NUL))                  systemd-boot
/// PCR9  = H(H(0^32 || H(utf16(cmdline)||NUL)) || H(initrd))  EFI stub: LoadOptions, then initrd
/// ```
pub fn predict(cmdline: &str, initrd_sha256: &[u8]) -> Prediction {
    let lo = load_options_digest(cmdline);
    let pcr12 = extend(&[0u8; 32], &lo);
    Prediction {
        load_options: cmdline.to_owned(),
        load_options_sha256: hex::encode(lo),
        initrd_sha256: hex::encode(initrd_sha256),
        pcr12_sha256: hex::encode(pcr12),
        pcr9_sha256: hex::encode(extend(&pcr12, initrd_sha256)),
    }
}

/// Hashes a file, returning its SHA-256 and size.
pub fn file_sha256(path: &Path) -> Result<([u8; 32], u64)> {
    let mut f = std::fs::File::open(path).map_err(|e| Error::io(path, e))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut n: u64 = 0;
    loop {
        let k = f.read(&mut buf).map_err(|e| Error::io(path, e))?;
        if k == 0 {
            break;
        }
        h.update(buf.get(..k).unwrap_or_default());
        n += k as u64;
    }
    Ok((h.finalize().into(), n))
}
