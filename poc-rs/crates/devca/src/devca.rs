//! The dev CA directory (Go `tpmdev.CreateDevCA` / `LoadDevCA`) and the
//! simulated EK certificate (Go `tpmdev.ProvisionEK`).

use crate::issue::{CaKey, issue_ca, issue_ek_cert, self_signed_ca};
use crate::{DEV_ICA_CN, DEV_ORG, DEV_ROOT_CN, EK_OU, Error, ICA_FILE, ICA_KEY_FILE, ROOT_FILE, Result};
use der::Decode as _;
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;
use std::path::Path;
use std::time::{Duration, SystemTime};
use zeroize::Zeroizing;

const HOUR: Duration = Duration::from_secs(3600);

/// A development endorsement CA: the dev root certificate and the ICA that
/// issues EK certificates (the root key is discarded after creation, as in
/// the Go reference).
#[derive(Debug)]
pub struct DevCa {
    root_der: Vec<u8>,
    ica: CaKey,
}

impl DevCa {
    /// The dev root certificate (DER).
    pub fn root_der(&self) -> &[u8] {
        &self.root_der
    }

    /// The issuing CA.
    pub fn ica(&self) -> &CaKey {
        &self.ica
    }

    /// The ICA certificate (DER), stored in NV 0x01C00100 next to the EK
    /// certificate.
    pub fn ica_der(&self) -> &[u8] {
        self.ica.cert_der()
    }

    /// Issues the EK certificate Go's `ProvisionEK` stores: subject
    /// OU=swtpm, CN="SimulatedTPM <hex(SHA-256(EK TPMT_PUBLIC)[:8])>",
    /// valid from an hour ago for three years.
    pub fn issue_ek_certificate(&self, ek_spki_der: &[u8], ek_public_area: &[u8]) -> Result<Vec<u8>> {
        let sum = Sha256::digest(ek_public_area);
        let mut cn = String::from("SimulatedTPM ");
        for b in sum.get(..8).unwrap_or_default() {
            let _ = write!(cn, "{b:02x}");
        }
        let now = hour_ago()?;
        issue_ek_cert(&self.ica, ek_spki_der, &cn, Some(EK_OU), now, add_years(now, 3)?, false)
    }
}

fn hour_ago() -> Result<SystemTime> {
    SystemTime::now().checked_sub(HOUR).ok_or_else(|| Error::invalid("clock before 1970"))
}

/// Go's `t.AddDate(years, 0, 0)` at second precision (Feb 29 rolls over to
/// Mar 1 in non-leap years, as Go normalizes it).
fn add_years(t: SystemTime, years: u16) -> Result<SystemTime> {
    let bad = |e: der::Error| Error::invalid(format!("certificate time: {e}"));
    let dt = der::DateTime::from_system_time(t).map_err(bad)?;
    let year = dt.year().checked_add(years).ok_or_else(|| Error::invalid("certificate time overflow"))?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let (month, day) = if dt.month() == 2 && dt.day() == 29 && !leap { (3, 1) } else { (dt.month(), dt.day()) };
    Ok(der::DateTime::new(year, month, day, dt.hour(), dt.minutes(), dt.seconds()).map_err(bad)?.to_system_time())
}

/// Generates a dev CA in memory: P-384 root and ICA, subject
/// O="Darkbloom DEVELOPMENT", valid from an hour ago for five years.
pub fn generate_dev_ca() -> Result<DevCa> {
    let now = hour_ago()?;
    let until = add_years(now, 5)?;
    let root = self_signed_ca(DEV_ROOT_CN, Some(DEV_ORG), None, now, until)?;
    let ica = issue_ca(&root, DEV_ICA_CN, Some(DEV_ORG), None, now, until)?;
    Ok(DevCa { root_der: root.cert_der().to_vec(), ica })
}

fn create_dir(dir: &Path) -> Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        b.mode(0o700);
    }
    b.create(dir).map_err(|e| Error::io(dir, e))
}

fn write_file(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        opts.mode(mode);
        let mut f = opts.open(path).map_err(|e| Error::io(path, e))?;
        // A pre-existing file keeps its mode with O_CREAT; enforce it.
        f.set_permissions(std::fs::Permissions::from_mode(mode)).map_err(|e| Error::io(path, e))?;
        f.write_all(data).map_err(|e| Error::io(path, e))
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        let mut f = opts.open(path).map_err(|e| Error::io(path, e))?;
        f.write_all(data).map_err(|e| Error::io(path, e))
    }
}

fn cert_pem(der_bytes: &[u8]) -> Result<String> {
    der::pem::encode_string("CERTIFICATE", der::pem::LineEnding::LF, der_bytes).map_err(Error::invalid)
}

/// Writes dev-root.pem, dev-ica.pem (0644) and dev-ica.key (0600) into
/// `dir` (created 0700 if missing), like Go's `tpmdev.CreateDevCA`.
pub fn create_dev_ca(dir: &Path) -> Result<()> {
    create_dir(dir)?;
    let ca = generate_dev_ca()?;
    write_file(&dir.join(ROOT_FILE), cert_pem(&ca.root_der)?.as_bytes(), 0o644)?;
    write_file(&dir.join(ICA_FILE), cert_pem(ca.ica_der())?.as_bytes(), 0o644)?;
    write_file(&dir.join(ICA_KEY_FILE), ca.ica.key_sec1_pem()?.as_bytes(), 0o600)
}

/// The first PEM block with `label` in `text`, from BEGIN through END.
fn pem_block<'a>(text: &'a str, label: &str) -> Option<&'a str> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text.find(&begin)?;
    let stop = start + text.get(start..)?.find(&end)? + end.len();
    text.get(start..stop)
}

fn read_cert(path: &Path) -> Result<Vec<u8>> {
    let data = std::fs::read(path).map_err(|e| Error::io(path, e))?;
    let der_bytes = match std::str::from_utf8(&data).ok().and_then(|t| pem_block(t, "CERTIFICATE")) {
        Some(block) => der::pem::decode_vec(block.as_bytes()).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))?.1,
        None => data,
    };
    x509_cert::Certificate::from_der(&der_bytes).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))?;
    Ok(der_bytes)
}

/// Reads a dev CA directory written by [`create_dev_ca`] or by the Go
/// reference (`dbnode devca`).
pub fn load_dev_ca(dir: &Path) -> Result<DevCa> {
    let root_der = read_cert(&dir.join(ROOT_FILE))?;
    let ica_der = read_cert(&dir.join(ICA_FILE))?;
    let key_path = dir.join(ICA_KEY_FILE);
    let text = Zeroizing::new(std::fs::read_to_string(&key_path).map_err(|e| Error::io(&key_path, e))?);
    let block = pem_block(&text, "EC PRIVATE KEY").ok_or_else(|| Error::invalid("bad dev ICA key"))?;
    let (_, key_der) = der::pem::decode_vec(block.as_bytes()).map_err(|e| Error::invalid(format!("dev ICA key: {e}")))?;
    let key_der = Zeroizing::new(key_der);
    let secret = p384::SecretKey::from_sec1_der(&key_der).map_err(|e| Error::invalid(format!("dev ICA key: {e}")))?;
    let ica = CaKey::from_parts(p384::ecdsa::SigningKey::from(&secret), ica_der)?;
    Ok(DevCa { root_der, ica })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn calendar_years() {
        let t = der::DateTime::new(2028, 2, 29, 12, 30, 15).unwrap().to_system_time();
        assert_eq!(der::DateTime::from_system_time(add_years(t, 5).unwrap()).unwrap(), der::DateTime::new(2033, 3, 1, 12, 30, 15).unwrap());
        assert_eq!(
            der::DateTime::from_system_time(add_years(t, 4).unwrap()).unwrap(),
            der::DateTime::new(2032, 2, 29, 12, 30, 15).unwrap()
        );
    }

    #[test]
    fn pem_blocks() {
        let text = "junk\n-----BEGIN A-----\nQUJD\n-----END A-----\n-----BEGIN B-----\nREVG\n-----END B-----\n";
        assert_eq!(pem_block(text, "B"), Some("-----BEGIN B-----\nREVG\n-----END B-----"));
        assert_eq!(pem_block(text, "C"), None);
    }
}
