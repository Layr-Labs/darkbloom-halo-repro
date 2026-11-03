//! Development TLS certificates for the coordinator (`dbcoord devcert`): a
//! self-signed ECDSA P-256 CA and a server certificate it issues, built with
//! the pure-Rust `x509-cert` builder. The CA key is discarded once the server
//! certificate is signed, so the CA vouches for nothing else.
//!
//! Development only: clients pin `ca.pem` with `-ca-cert`. A production
//! coordinator uses a certificate from a real CA.

use crate::{Error, Result};
use const_oid::ObjectIdentifier;
use der::Encode as _;
use der::asn1::{Ia5String, OctetString};
use der::flagset::FlagSet;
use p256::ecdsa::{DerSignature, SigningKey};
use p256::elliptic_curve::Generate as _;
use p256::pkcs8::EncodePrivateKey as _;
use sha2::{Digest as _, Sha256};
use spki::{EncodePublicKey as _, SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr as _;
use std::time::{Duration, SystemTime};
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder as _, CertificateBuilder};
use x509_cert::certificate::TbsCertificate;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::ext::{Extension, ToExtension as _};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use zeroize::Zeroizing;

/// The CA certificate clients pin (`-ca-cert`).
pub const CA_FILE: &str = "ca.pem";
/// The server certificate (`dbcoord -tls-cert`).
pub const CERT_FILE: &str = "server.pem";
/// The server key, PKCS#8 PEM, mode 0600 (`dbcoord -tls-key`).
pub const KEY_FILE: &str = "server.key";

/// The CA is valid for a year, the server certificate for 90 days, both from
/// an hour ago (clock skew).
const CA_VALIDITY: Duration = Duration::from_secs(365 * 24 * 3600);
const CERT_VALIDITY: Duration = Duration::from_secs(90 * 24 * 3600);
const BACKDATE: Duration = Duration::from_secs(3600);

/// id-kp-serverAuth.
const ID_KP_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

const SERVER_NAME: &str = "CN=Darkbloom DEV coordinator,O=Darkbloom DEVELOPMENT";

/// Each dev CA gets its own name (from its key identifier), so a client
/// pinned to another dev CA reports an unknown issuer rather than a bad
/// signature from a same-named CA.
fn unique_ca_name(skid: &[u8]) -> Result<Name> {
    let id: String = skid.iter().take(4).map(|b| format!("{b:02x}")).collect();
    name(&format!("CN=Darkbloom DEV coordinator TLS CA {id} (NOT FOR PRODUCTION),O=Darkbloom DEVELOPMENT"))
}

/// A generated development certificate.
pub struct DevCert {
    /// The CA certificate (PEM): what clients pin.
    pub ca_pem: String,
    /// The server certificate (PEM).
    pub cert_pem: String,
    /// The server's private key (PKCS#8 PEM).
    pub key_pem: Zeroizing<String>,
    /// The names the server certificate covers.
    pub hosts: Vec<String>,
    /// When the server certificate expires.
    pub not_after: SystemTime,
}

impl std::fmt::Debug for DevCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DevCert").field("hosts", &self.hosts).field("not_after", &self.not_after).finish_non_exhaustive()
    }
}

/// A subject alternative name: an IP address (optionally in brackets) or a
/// DNS name.
fn subject_alt_name(host: &str) -> Result<GeneralName> {
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(GeneralName::from(ip));
    }
    if rustls_pki_types::DnsName::try_from(host).is_err() {
        return Err(Error::invalid(format!("{host:?} is neither an IP address nor a DNS name")));
    }
    Ok(GeneralName::DnsName(Ia5String::new(host).map_err(Error::invalid)?))
}

fn new_key() -> Result<SigningKey> {
    SigningKey::try_generate_from_rng(&mut getrandom::SysRng).map_err(|e| Error::invalid(format!("random: {e}")))
}

fn spki_of(key: &SigningKey) -> Result<SubjectPublicKeyInfoOwned> {
    let doc = key.verifying_key().to_public_key_der().map_err(Error::invalid)?;
    der::Decode::from_der(doc.as_bytes()).map_err(Error::invalid)
}

/// Subject key identifier: the leftmost 160 bits of SHA-256 over the public
/// key bits (RFC 7093 method 1, as Go 1.25 computes it).
fn key_id(spki: &SubjectPublicKeyInfoOwned) -> Vec<u8> {
    Sha256::digest(spki.subject_public_key.raw_bytes()).get(..20).unwrap_or_default().to_vec()
}

/// A random positive 128-bit serial number.
fn random_serial() -> Result<SerialNumber> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| Error::invalid(format!("random: {e}")))?;
    if let Some(first) = b.first_mut() {
        *first = (*first & 0x3f) | 0x40;
    }
    SerialNumber::new(&b).map_err(Error::invalid)
}

fn name(s: &str) -> Result<Name> {
    Name::from_str(s).map_err(Error::invalid)
}

/// The two certificates' extensions.
struct Profile {
    subject: Name,
    issuer: Name,
    ca: bool,
    sans: Vec<GeneralName>,
    skid: Vec<u8>,
    akid: Option<Vec<u8>>,
}

impl BuilderProfile for Profile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let subject = tbs.subject();
        let mut exts: Vec<Extension> = Vec::new();
        let bc = BasicConstraints { ca: self.ca, path_len_constraint: self.ca.then_some(0) };
        exts.push((true, &bc).to_extension(subject, &exts)?);
        let usage: FlagSet<KeyUsages> =
            if self.ca { KeyUsages::KeyCertSign | KeyUsages::CRLSign } else { KeyUsages::DigitalSignature.into() };
        exts.push((true, &KeyUsage(usage)).to_extension(subject, &exts)?);
        if !self.ca {
            exts.push((false, &ExtendedKeyUsage(vec![ID_KP_SERVER_AUTH])).to_extension(subject, &exts)?);
            exts.push((false, &SubjectAltName(self.sans.clone())).to_extension(subject, &exts)?);
        }
        let skid = SubjectKeyIdentifier(OctetString::new(self.skid.clone())?);
        exts.push((false, &skid).to_extension(subject, &exts)?);
        if let Some(akid) = &self.akid {
            let akid = AuthorityKeyIdentifier { key_identifier: Some(OctetString::new(akid.clone())?), ..Default::default() };
            exts.push((false, &akid).to_extension(subject, &exts)?);
        }
        Ok(exts)
    }
}

fn time(t: SystemTime) -> Result<Time> {
    Time::try_from(t).map_err(|e| Error::invalid(format!("certificate time: {e}")))
}

fn later(t: SystemTime, d: Duration) -> Result<SystemTime> {
    t.checked_add(d).ok_or_else(|| Error::invalid("certificate time overflow"))
}

fn sign(
    profile: Profile,
    spki: SubjectPublicKeyInfoOwned,
    not_before: SystemTime,
    not_after: SystemTime,
    signer: &SigningKey,
) -> Result<Vec<u8>> {
    let validity = Validity::new(time(not_before)?, time(not_after)?);
    let builder = CertificateBuilder::new(profile, random_serial()?, validity, spki).map_err(Error::invalid)?;
    let cert = builder.build::<_, DerSignature>(signer).map_err(Error::invalid)?;
    cert.to_der().map_err(Error::invalid)
}

fn pem(der_bytes: &[u8]) -> Result<String> {
    der::pem::encode_string("CERTIFICATE", der::pem::LineEnding::LF, der_bytes).map_err(Error::invalid)
}

/// Generates a CA (CA:true, pathlen 0, keyCertSign|cRLSign, one year) and a
/// server certificate for `hosts` (IP or DNS subject alternative names,
/// serverAuth, digitalSignature, 90 days). Empty entries are ignored; at
/// least one host is required.
pub fn generate<S: AsRef<str>>(hosts: &[S]) -> Result<DevCert> {
    let hosts: Vec<String> = hosts.iter().map(|h| h.as_ref().trim()).filter(|h| !h.is_empty()).map(str::to_owned).collect();
    if hosts.is_empty() {
        return Err(Error::invalid("the server certificate needs at least one host"));
    }
    let sans = hosts.iter().map(|h| subject_alt_name(h)).collect::<Result<Vec<_>>>()?;
    let now = SystemTime::now();
    let not_before = now.checked_sub(BACKDATE).ok_or_else(|| Error::invalid("clock before 1970"))?;
    let ca_key = new_key()?;
    let ca_spki = spki_of(&ca_key)?;
    let ca_skid = key_id(&ca_spki);
    let ca_name = unique_ca_name(&ca_skid)?;
    let ca_profile =
        Profile { subject: ca_name.clone(), issuer: ca_name.clone(), ca: true, sans: Vec::new(), skid: ca_skid.clone(), akid: None };
    let ca_der = sign(ca_profile, ca_spki, not_before, later(now, CA_VALIDITY)?, &ca_key)?;
    let key = new_key()?;
    let spki = spki_of(&key)?;
    let not_after = later(now, CERT_VALIDITY)?;
    let profile = Profile { subject: name(SERVER_NAME)?, issuer: ca_name, ca: false, sans, skid: key_id(&spki), akid: Some(ca_skid) };
    let cert_der = sign(profile, spki, not_before, not_after, &ca_key)?;
    drop(ca_key);
    let key_pem = key.to_pkcs8_pem(der::pem::LineEnding::LF).map_err(|_| Error::invalid("encode the server key"))?;
    Ok(DevCert { ca_pem: pem(&ca_der)?, cert_pem: pem(&cert_der)?, key_pem, hosts, not_after })
}

fn write_file(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        opts.mode(mode);
        let mut f = opts.open(path).map_err(|e| Error::file(path, e))?;
        // A pre-existing file keeps its mode with O_CREAT: enforce it before
        // writing the key.
        f.set_permissions(std::fs::Permissions::from_mode(mode)).map_err(|e| Error::file(path, e))?;
        f.write_all(data).map_err(|e| Error::file(path, e))
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        opts.open(path).and_then(|mut f| f.write_all(data)).map_err(|e| Error::file(path, e))
    }
}

/// Generates a development certificate for `hosts` and writes `ca.pem`,
/// `server.pem` (0644) and `server.key` (0600) into `dir` (created 0700 if
/// missing).
pub fn write<S: AsRef<str>>(dir: &Path, hosts: &[S]) -> Result<DevCert> {
    let dc = generate(hosts)?;
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        b.mode(0o700);
    }
    b.create(dir).map_err(|e| Error::file(dir, e))?;
    write_file(&dir.join(KEY_FILE), dc.key_pem.as_bytes(), 0o600)?;
    write_file(&dir.join(CERT_FILE), dc.cert_pem.as_bytes(), 0o644)?;
    write_file(&dir.join(CA_FILE), dc.ca_pem.as_bytes(), 0o644)?;
    Ok(dc)
}
