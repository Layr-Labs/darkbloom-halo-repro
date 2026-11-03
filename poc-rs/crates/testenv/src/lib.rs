//! Development TPMs and fixtures for tests and demos (port of the Go
//! `internal/testenv`): a swtpm process ([`Swtpm`]), and a [`Fixture`] with
//! a provisioned dev EK, a simulated Halo boot and a matching signed
//! release.

#![forbid(unsafe_code)]

mod fixture;
mod swtpm;

pub use crate::fixture::Fixture;
pub use crate::swtpm::Swtpm;

use chrono::Duration;
use db_gojson::GoTime;
use db_release::{Artifact, Boot, Manifest, Platform, Runtime, SCHEMA, predict, predict_pcr4};
use db_simboot::{Artifacts, Pe, halo_plan};
use db_tpmattest::{ALG_SHA256, build_event_log, digests_of, parse_event_log};
use sha2::{Digest as _, Sha256};

/// The measured kernel command line of the test releases (the Go
/// `testCmdline`): dm-verity root hash plus every production hardening flag.
pub const TEST_CMDLINE: &str = "root=/dev/mapper/root ro roothash=6a2b0c6d3f9e8a7b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b lockdown=confidentiality debugfs=off iommu.strict=1 module.sig_enforce=1";

/// Errors from the test environment.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No swtpm binary ($SWTPM or PATH).
    #[error("swtpm not installed (brew install swtpm / apt install swtpm)")]
    NotInstalled,
    /// File or process I/O.
    #[error("testenv: {context}: {source}")]
    Io {
        /// What was being done.
        context: String,
        /// Underlying error.
        source: std::io::Error,
    },
    /// Any other setup failure.
    #[error("testenv: {0}")]
    Setup(String),
}

impl Error {
    pub(crate) fn setup(msg: impl std::fmt::Display) -> Self {
        Self::Setup(msg.to_string())
    }

    pub(crate) fn io(context: impl Into<String>) -> impl FnOnce(std::io::Error) -> Self {
        let context = context.into();
        move |source| Self::Io { context, source }
    }
}

/// Synthetic but structurally real boot inputs (Go `TestArtifacts`).
pub fn test_artifacts(banks: &[u16], cmdline: &str) -> Artifacts {
    let boot_apps = ["shimx64.efi", "systemd-bootx64.efi", "linux"]
        .iter()
        .map(|n| Pe { name: (*n).to_owned(), digests: digests_of(banks, format!("test PE {n}").as_bytes()) })
        .collect();
    Artifacts {
        bios_version: "LFGB0.03.03".to_owned(),
        secure_boot: true,
        boot_apps,
        cmdline: cmdline.to_owned(),
        initrd: digests_of(banks, b"test initrd"),
    }
}

/// A release manifest matching `a` (Go `ManifestFor`), with the platform
/// profile (PCR 0, 7, 14) replayed from a simulated reference boot.
pub fn manifest_for(a: &Artifacts, channel: &str, svn: u32) -> Manifest {
    let mut apps = Vec::new();
    let mut app_digests = Vec::new();
    for p in &a.boot_apps {
        let d = p.digests.get(&ALG_SHA256).cloned().unwrap_or_default();
        apps.push(Artifact { name: p.name.clone(), sha256: hex::encode(&d), bytes: 0 });
        app_digests.push(d);
    }
    let pred = predict(&a.cmdline, a.initrd.get(&ALG_SHA256).map(Vec::as_slice).unwrap_or_default());
    let now = GoTime::now_utc();
    // Platform profile from the (simulated) reference boot.
    let banks = [ALG_SHA256];
    let plat = build_event_log(&banks, &halo_plan(&banks, a))
        .ok()
        .and_then(|b| parse_event_log(&b).ok())
        .and_then(|l| l.replay(ALG_SHA256, &[0, 7, 14]).ok())
        .unwrap_or_default();
    let pin = |p: u32| plat.get(&p).map(hex::encode).unwrap_or_default();
    Manifest {
        schema: SCHEMA.to_owned(),
        name: "darkbloom-nodeos".to_owned(),
        version: format!("0.{svn}.0-test"),
        svn,
        channel: channel.to_owned(),
        issued_at: now.add(Duration::minutes(-1)),
        expires_at: now.add(Duration::hours(24)),
        platform: Platform { products: Some(vec!["AMD Ryzen AI Halo (RAH-001)".to_owned()]), min_scrtm_version: "LFGB0.03.03".to_owned() },
        boot: Boot {
            path: "type1-amd-signed-chain".to_owned(),
            boot_apps: (!apps.is_empty()).then_some(apps),
            pcr4_sha256: hex::encode(predict_pcr4(&app_digests)),
            load_options: pred.load_options,
            load_options_sha256: pred.load_options_sha256,
            initrd_sha256: pred.initrd_sha256,
            pcr9_sha256: pred.pcr9_sha256,
            pcr12_sha256: pred.pcr12_sha256,
            pcr0_sha256: pin(0),
            pcr7_sha256: pin(7),
            pcr14_sha256: pin(14),
            ..Boot::default()
        },
        runtime: Runtime { engine: Artifact { name: "fake-engine".to_owned(), ..Artifact::default() }, ..Runtime::default() },
        ..Manifest::default()
    }
}

/// A short hash for logs: hex of the first 6 bytes of SHA-256.
pub fn fingerprint(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b).get(..6).unwrap_or_default())
}
