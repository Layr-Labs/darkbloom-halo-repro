//! The TCG event sequence of a Halo boot through the AMD-signed Type #1
//! chain (firmware -> shim -> systemd-boot -> kernel EFI stub), for the
//! development TPM (swtpm) and for tests.
//!
//! The Darkbloom-controlled measurements (PCR 4 boot applications, PCR 9
//! initrd and load options, PCR 12 command line) are computed exactly as the
//! real firmware, shim, systemd-boot and kernel do; on amd-halo the same
//! computation reproduced the live Pluton PCR 4, 9 and 12. Firmware-owned
//! PCRs (0-3, 5-7, 14) are synthetic and labelled as such in their event data.

#![forbid(unsafe_code)]

use db_tpm2::HashAlg;
use db_tpmattest::eventlog::{
    EFI_GLOBAL_VARIABLE_GUID, EV_EFI_ACTION, EV_EFI_BOOT_SERVICES_APPLICATION, EV_EFI_PLATFORM_FIRMWARE_BLOB2, EV_EFI_VARIABLE_AUTHORITY,
    EV_EFI_VARIABLE_BOOT2, EV_EFI_VARIABLE_DRIVER_CONFIG, EV_EVENT_TAG, EV_IPL, EV_SCRTM_VERSION, EV_SEPARATOR, LogEvent, TAG_LINUX_INITRD,
    TAG_LOAD_OPTIONS, digests_of, tagged_event_data, uefi_variable_data, utf16le,
};
use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::Path;

/// Errors from loading boot artifacts.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A bank this implementation cannot hash.
    #[error("simboot: unsupported bank 0x{0:04x}")]
    UnsupportedBank(u16),
    /// File I/O.
    #[error("simboot: {path}: {source}")]
    Io {
        /// File.
        path: String,
        /// Cause.
        source: std::io::Error,
    },
    /// A boot application that is not a PE image.
    #[error("simboot: {name}: {source}")]
    Pe {
        /// Artifact name.
        name: String,
        /// Cause.
        source: db_release::Error,
    },
}

/// Inputs of a simulated boot.
#[derive(Debug, Clone, Default)]
pub struct Artifacts {
    /// S-CRTM version string, e.g. "LFGB0.03.03".
    pub bios_version: String,
    /// Whether Secure Boot is on.
    pub secure_boot: bool,
    /// shim, systemd-boot, kernel, in load order.
    pub boot_apps: Vec<Pe>,
    /// Kernel load options.
    pub cmdline: String,
    /// Initrd digest per bank.
    pub initrd: BTreeMap<u16, Vec<u8>>,
}

/// A boot application with per-bank Authenticode digests.
#[derive(Debug, Clone, Default)]
pub struct Pe {
    /// Name logged as event data.
    pub name: String,
    /// Authenticode digest per bank.
    pub digests: BTreeMap<u16, Vec<u8>>,
}

fn hash(alg: u16) -> Result<HashAlg, Error> {
    HashAlg::from_id(alg).ok_or(Error::UnsupportedBank(alg))
}

/// Computes Authenticode digests of a PE file for each bank.
pub fn load_pe(name: &str, path: &Path, banks: &[u16]) -> Result<Pe, Error> {
    let data = std::fs::read(path).map_err(|source| Error::Io { path: path.display().to_string(), source })?;
    pe_from_bytes(name, &data, banks)
}

/// Computes Authenticode digests of a PE image for each bank.
pub fn pe_from_bytes(name: &str, data: &[u8], banks: &[u16]) -> Result<Pe, Error> {
    let mut digests = BTreeMap::new();
    for &b in banks {
        let d = db_release::authenticode_digest(data, hash(b)?).map_err(|source| Error::Pe { name: name.to_owned(), source })?;
        digests.insert(b, d);
    }
    Ok(Pe { name: name.to_owned(), digests })
}

/// Hashes a file with every bank's algorithm in one pass.
pub fn hash_file(path: &Path, banks: &[u16]) -> Result<BTreeMap<u16, Vec<u8>>, Error> {
    let io = |source| Error::Io { path: path.display().to_string(), source };
    let mut states = banks.iter().map(|&b| Ok((b, hash(b)?.hasher()))).collect::<Result<Vec<_>, Error>>()?;
    let mut f = std::fs::File::open(path).map_err(io)?;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).map_err(io)?;
        if n == 0 {
            break;
        }
        let block = buf.get(..n).unwrap_or_default();
        for (_, h) in &mut states {
            h.update(block);
        }
    }
    Ok(states.into_iter().map(|(b, h)| (b, h.finalize())).collect())
}

fn ev(banks: &[u16], pcr: u32, event_type: u32, data: Vec<u8>, measured: Option<&[u8]>) -> LogEvent {
    let digests = digests_of(banks, measured.unwrap_or(&data));
    LogEvent { pcr, event_type, digests, data }
}

/// The boot's events in log order.
pub fn halo_plan(banks: &[u16], a: &Artifacts) -> Vec<LogEvent> {
    let g = &EFI_GLOBAL_VARIABLE_GUID;
    let sep = vec![0u8; 4];
    let mut evs = Vec::new();

    // PCR 0: BIOS version and (synthetic) firmware.
    evs.push(ev(banks, 0, EV_SCRTM_VERSION, utf16le(&a.bios_version, true), None));
    evs.push(ev(
        banks,
        0,
        EV_EFI_PLATFORM_FIRMWARE_BLOB2,
        b"SIMULATED platform firmware volume".to_vec(),
        Some(format!("simulated-firmware-{}", a.bios_version).as_bytes()),
    ));
    // PCR 1: boot variables (synthetic).
    evs.push(ev(banks, 1, EV_EFI_VARIABLE_BOOT2, uefi_variable_data(g, "BootOrder", &[1, 0]), None));
    // PCR 7: Secure Boot configuration.
    let sb = [u8::from(a.secure_boot)];
    for (name, val) in [
        ("SecureBoot", &sb[..]),
        ("PK", b"SIMULATED PK"),
        ("KEK", b"SIMULATED KEK"),
        ("db", b"SIMULATED db: Microsoft UEFI CA 2011/2023, Collabora Rex secure boot - CA 2026"),
        ("dbx", b"SIMULATED dbx"),
    ] {
        evs.push(ev(banks, 7, EV_EFI_VARIABLE_DRIVER_CONFIG, uefi_variable_data(g, name, val), None));
    }
    // PCR 4: the firmware's boot-option action precedes the separator (as
    // measured on amd-halo).
    evs.push(ev(banks, 4, EV_EFI_ACTION, b"Calling EFI Application from Boot Option".to_vec(), None));
    for p in 0..=7 {
        evs.push(ev(banks, p, EV_SEPARATOR, sep.clone(), None));
    }
    evs.push(ev(banks, 7, EV_EFI_VARIABLE_AUTHORITY, uefi_variable_data(g, "db", b"SIMULATED authority: Microsoft UEFI CA"), None));
    // PCR 4: boot applications, with their real Authenticode digests.
    let opts = utf16le(&a.cmdline, true);
    for (i, app) in a.boot_apps.iter().enumerate() {
        evs.push(LogEvent {
            pcr: 4,
            event_type: EV_EFI_BOOT_SERVICES_APPLICATION,
            digests: app.digests.clone(),
            data: app.name.as_bytes().to_vec(),
        });
        if i == 0 {
            // shim measures its MOK state into PCR 14 (synthetic contents).
            for n in ["MokList", "MokListX", "MokListTrusted"] {
                evs.push(ev(banks, 14, EV_IPL, format!("{n}\0").into_bytes(), Some(format!("SIMULATED {n}").as_bytes())));
            }
        }
        if i == 1 {
            // systemd-boot measures the kernel command line into PCR 12 as an
            // EV_IPL event whose data is the UTF-16 string (as on amd-halo).
            evs.push(LogEvent { pcr: 12, event_type: EV_IPL, digests: digests_of(banks, &opts), data: opts.clone() });
        }
    }
    // PCR 9: the kernel's EFI stub measures LoadOptions, then the initrd.
    evs.push(LogEvent {
        pcr: 9,
        event_type: EV_EVENT_TAG,
        digests: digests_of(banks, &opts),
        data: tagged_event_data(TAG_LOAD_OPTIONS, b"LOADED_IMAGE::LoadOptions\0"),
    });
    evs.push(LogEvent {
        pcr: 9,
        event_type: EV_EVENT_TAG,
        digests: a.initrd.clone(),
        data: tagged_event_data(TAG_LINUX_INITRD, b"Linux initrd\0"),
    });
    // PCR 5: ExitBootServices.
    evs.push(ev(banks, 5, EV_EFI_ACTION, b"Exit Boot Services Invocation".to_vec(), None));
    evs.push(ev(banks, 5, EV_EFI_ACTION, b"Exit Boot Services Returned with Success".to_vec(), None));
    evs
}
