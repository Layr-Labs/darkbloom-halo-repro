//! A provisioned dev TPM with a simulated Halo boot and a matching signed
//! release (Go `testenv.NewFixture`).

use crate::{Error, Swtpm, manifest_for, test_artifacts};
use db_devca::{create_dev_ca, load_dev_ca};
use db_release::{Envelope, Manifest, TrustedKeys, key_id, sign_manifest};
use db_simboot::{Artifacts, halo_plan};
use db_tpmattest::{LogEvent, RootKind, TrustBundle, load_certificates, pinned_root};
use db_tpmdev::Device;
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroizing;

/// A provisioned dev TPM, a simulated boot and a signed dev-channel release.
/// Fields drop in order: the TPM connection, then swtpm, then the
/// temporary directory.
#[derive(Debug)]
pub struct Fixture {
    /// The TPM (swtpm).
    pub dev: Arc<Device>,
    /// The swtpm process.
    pub tpm: Swtpm,
    /// The dev CA directory (dev-root.pem, dev-ica.pem, dev-ica.key).
    pub ca_dir: PathBuf,
    /// The simulated boot's event log.
    pub event_log: Vec<u8>,
    /// The simulated boot's inputs.
    pub artifacts: Artifacts,
    /// The matching dev-channel release (svn 3).
    pub manifest: Manifest,
    /// The manifest signed with `release_key`.
    pub envelope: Envelope,
    /// A fresh release-signing key.
    pub release_key: ed25519_dalek::SigningKey,
    /// Holds the TPM state and the dev CA.
    pub dir: tempfile::TempDir,
}

fn release_key() -> Result<ed25519_dalek::SigningKey, Error> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut_slice()).map_err(|e| Error::setup(format!("random: {e}")))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

impl Fixture {
    /// Starts swtpm, provisions a dev EK and simulates a boot of `cmdline`.
    /// `None` (after printing "skipped: swtpm not installed") when swtpm is
    /// missing; panics on any other setup failure (test support).
    pub fn new(cmdline: &str) -> Option<Fixture> {
        Self::new_with(cmdline, |_| {})
    }

    /// Like [`Fixture::new`], letting the test change the simulated boot
    /// (e.g. Secure Boot off).
    #[allow(clippy::panic)]
    pub fn new_with(cmdline: &str, mutate: impl FnOnce(&mut Artifacts)) -> Option<Fixture> {
        match Self::try_new_with(cmdline, mutate) {
            Ok(f) => Some(f),
            Err(Error::NotInstalled) => {
                eprintln!("skipped: swtpm not installed");
                None
            }
            Err(e) => panic!("fixture: {e}"),
        }
    }

    /// The fallible constructor behind [`Fixture::new_with`].
    pub fn try_new_with(cmdline: &str, mutate: impl FnOnce(&mut Artifacts)) -> Result<Fixture, Error> {
        if Swtpm::binary().is_none() {
            return Err(Error::NotInstalled);
        }
        let dir = tempfile::Builder::new().prefix("dbtest").tempdir().map_err(Error::io("temporary directory"))?;
        let tpm = Swtpm::start(dir.path())?;
        let dev = tpm.open_device()?;
        let ca_dir = dir.path().join("devca");
        create_dev_ca(&ca_dir).map_err(Error::setup)?;
        let ca = load_dev_ca(&ca_dir).map_err(Error::setup)?;
        dev.provision_ek(&ca).map_err(Error::setup)?;
        let mut arts = None;
        let event_log = dev
            .simulate_boot(|banks| {
                let mut a = test_artifacts(banks, cmdline);
                mutate(&mut a);
                let plan = halo_plan(banks, &a);
                arts = Some(a);
                Ok(plan)
            })
            .map_err(Error::setup)?;
        let artifacts = arts.ok_or_else(|| Error::setup("boot plan not run"))?;
        let release_key = release_key()?;
        let manifest = manifest_for(&artifacts, "dev", 3);
        let envelope = sign_manifest(&manifest, &release_key).map_err(Error::setup)?;
        Ok(Fixture { dev, tpm, ca_dir, event_log, artifacts, manifest, envelope, release_key, dir })
    }

    /// Regenerates the fixture's boot events (for a simulated reboot).
    pub fn plan(&self, banks: &[u16]) -> Vec<LogEvent> {
        halo_plan(banks, &test_artifacts(banks, &self.artifacts.cmdline))
    }

    /// A trust bundle with only the fixture's dev root (development kind,
    /// not production). Panics if the dev root cannot be read.
    #[allow(clippy::panic)]
    pub fn dev_bundle(&self) -> TrustBundle {
        match load_certificates(&[self.ca_dir.join(db_devca::ROOT_FILE)]) {
            Ok(certs) => TrustBundle { roots: vec![pinned_root("dev", RootKind::DevSimulated, certs, Vec::new(), false)] },
            Err(e) => panic!("fixture: dev root: {e}"),
        }
    }

    /// The release key as a trusted-key set.
    pub fn trusted_keys(&self) -> TrustedKeys {
        let public = self.release_key.verifying_key();
        TrustedKeys::from([(key_id(&public), public)])
    }
}
