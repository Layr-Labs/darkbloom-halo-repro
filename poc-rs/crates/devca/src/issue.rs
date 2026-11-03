//! Certificate issuance with Go's `x509.CreateCertificate` layout.

use crate::name::subject_name;
use crate::{Error, Result, TCG_EK_CERTIFICATE_OID, key_usage};
use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::flagset::FlagSet;
use der::{Decode as _, Encode as _};
use p384::ecdsa::{DerSignature, SigningKey};
use p384::elliptic_curve::Generate as _;
use sha2::{Digest as _, Sha256};
use spki::{EncodePublicKey as _, SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use std::time::SystemTime;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder as _, CertificateBuilder};
use x509_cert::certificate::TbsCertificate;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectKeyIdentifier};
use x509_cert::ext::{Extension, ToExtension as _};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use zeroize::Zeroizing;

/// What to put into a certificate (a subset of Go's `x509.Certificate`
/// template; basicConstraints is always present and critical).
#[derive(Debug, Clone)]
pub struct CertSpec<'a> {
    /// Subject O (omitted when `None`).
    pub organization: Option<&'a str>,
    /// Subject OU (omitted when `None`).
    pub organizational_unit: Option<&'a str>,
    /// Subject CN (omitted when empty).
    pub common_name: &'a str,
    /// Validity start (encoded with second precision).
    pub not_before: SystemTime,
    /// Validity end.
    pub not_after: SystemTime,
    /// basicConstraints cA.
    pub is_ca: bool,
    /// Key usage bits in Go's numbering ([`key_usage`]); 0 omits the extension.
    pub key_usage: u16,
    /// Extended key usages (none: extension omitted).
    pub ext_key_usage: Vec<ObjectIdentifier>,
    /// Explicit subject key identifier. Without one, CA certificates get
    /// Go's default (leftmost 160 bits of SHA-256 over the subjectPublicKey
    /// bits) and other certificates none.
    pub subject_key_id: Option<Vec<u8>>,
}

/// A CA: its signing key (P-384, zeroized on drop) and certificate.
pub struct CaKey {
    key: SigningKey,
    cert_der: Vec<u8>,
    subject: Name,
    skid: Vec<u8>,
}

impl std::fmt::Debug for CaKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaKey").field("subject", &self.subject.to_string()).finish_non_exhaustive()
    }
}

impl CaKey {
    /// Pairs a signing key with its certificate (DER). Fails unless the
    /// certificate certifies exactly this key.
    pub fn from_parts(key: SigningKey, cert_der: Vec<u8>) -> Result<Self> {
        let cert = x509_cert::Certificate::from_der(&cert_der).map_err(|e| Error::invalid(format!("CA certificate: {e}")))?;
        let tbs = cert.tbs_certificate();
        let cert_spki = tbs.subject_public_key_info().to_der().map_err(Error::invalid)?;
        if cert_spki != spki_of(&key)? {
            return Err(Error::invalid("CA certificate does not match its private key"));
        }
        let skid = tbs
            .get_extension::<SubjectKeyIdentifier>()
            .map_err(|e| Error::invalid(format!("CA subject key identifier: {e}")))?
            .map(|(_, id)| id.0.as_bytes().to_vec())
            .unwrap_or_default();
        Ok(Self { key, subject: tbs.subject().clone(), skid, cert_der })
    }

    /// The certificate (DER).
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// The subject key identifier (empty if the certificate has none).
    pub fn skid(&self) -> &[u8] {
        &self.skid
    }

    /// The subject name (DER).
    pub fn subject_der(&self) -> Result<Vec<u8>> {
        self.subject.to_der().map_err(Error::invalid)
    }

    /// The CA public key as DER SubjectPublicKeyInfo.
    pub fn spki_der(&self) -> Result<Vec<u8>> {
        spki_of(&self.key)
    }

    /// The signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    /// The private key as SEC1 "EC PRIVATE KEY" PEM (Go's
    /// `x509.MarshalECPrivateKey` + `pem.Encode`).
    pub fn key_sec1_pem(&self) -> Result<Zeroizing<String>> {
        let secret = p384::SecretKey::from(self.key.as_nonzero_scalar());
        secret.to_sec1_pem(der::pem::LineEnding::LF).map_err(|_| Error::invalid("encode EC private key"))
    }

    /// Issues a certificate for `subject_spki_der` (DER SubjectPublicKeyInfo).
    pub fn issue(&self, spec: &CertSpec<'_>, subject_spki_der: &[u8]) -> Result<Vec<u8>> {
        build(spec, subject_spki_der, Some(self), &self.key)
    }
}

/// Issues a certificate signed by `parent`.
pub fn issue_cert(parent: &CaKey, spec: &CertSpec<'_>, subject_spki_der: &[u8]) -> Result<Vec<u8>> {
    parent.issue(spec, subject_spki_der)
}

fn spki_of(key: &SigningKey) -> Result<Vec<u8>> {
    Ok(key.verifying_key().to_public_key_der().map_err(Error::invalid)?.as_bytes().to_vec())
}

fn new_key() -> Result<SigningKey> {
    SigningKey::try_generate_from_rng(&mut getrandom::SysRng).map_err(|e| Error::invalid(format!("random: {e}")))
}

/// The dev CA's subject key identifier: SHA-256 over the DER
/// SubjectPublicKeyInfo, first 20 bytes (Go `tpmdev.skid`).
fn dev_skid(spki_der: &[u8]) -> Vec<u8> {
    Sha256::digest(spki_der).get(..20).unwrap_or_default().to_vec()
}

/// A random serial in [1, 2^120] (Go: `rand.Int(rand.Reader, 2^120) + 1`),
/// big-endian.
pub fn random_serial() -> Result<Vec<u8>> {
    let mut b = [0u8; 16];
    getrandom::fill(b.get_mut(1..).unwrap_or_default()).map_err(|e| Error::invalid(format!("random: {e}")))?;
    for byte in b.iter_mut().rev() {
        let (v, carry) = byte.overflowing_add(1);
        *byte = v;
        if !carry {
            break;
        }
    }
    Ok(b.to_vec())
}

fn ca_spec<'a>(cn: &'a str, org: Option<&'a str>, skid: Vec<u8>, not_before: SystemTime, not_after: SystemTime) -> CertSpec<'a> {
    CertSpec {
        organization: org,
        organizational_unit: None,
        common_name: cn,
        not_before,
        not_after,
        is_ca: true,
        key_usage: key_usage::CERT_SIGN | key_usage::CRL_SIGN,
        ext_key_usage: Vec::new(),
        subject_key_id: Some(skid),
    }
}

/// Creates a self-signed CA with a fresh P-384 key (keyUsage certSign|cRLSign,
/// CA:TRUE). `skid` defaults to SHA-256(SPKI DER)[:20].
pub fn self_signed_ca(cn: &str, org: Option<&str>, skid: Option<&[u8]>, not_before: SystemTime, not_after: SystemTime) -> Result<CaKey> {
    let key = new_key()?;
    let spki = spki_of(&key)?;
    let skid = skid.map_or_else(|| dev_skid(&spki), <[u8]>::to_vec);
    let der = build(&ca_spec(cn, org, skid, not_before, not_after), &spki, None, &key)?;
    CaKey::from_parts(key, der)
}

/// Creates an intermediate CA with a fresh P-384 key, signed by `parent`
/// (its authority key identifier is the parent's SKID).
pub fn issue_ca(
    parent: &CaKey,
    cn: &str,
    org: Option<&str>,
    skid: Option<&[u8]>,
    not_before: SystemTime,
    not_after: SystemTime,
) -> Result<CaKey> {
    let key = new_key()?;
    let spki = spki_of(&key)?;
    let skid = skid.map_or_else(|| dev_skid(&spki), <[u8]>::to_vec);
    let der = parent.issue(&ca_spec(cn, org, skid, not_before, not_after), &spki)?;
    CaKey::from_parts(key, der)
}

/// Issues an EK certificate (keyUsage keyAgreement, extKeyUsage
/// tcg-kp-EKCertificate, critical basicConstraints). `is_ca` produces the
/// malformed "CA certificate as EK" variant (adds certSign) for tests.
#[allow(clippy::too_many_arguments)]
pub fn issue_ek_cert(
    parent: &CaKey,
    subject_spki_der: &[u8],
    cn: &str,
    ou: Option<&str>,
    not_before: SystemTime,
    not_after: SystemTime,
    is_ca: bool,
) -> Result<Vec<u8>> {
    let spec = CertSpec {
        organization: None,
        organizational_unit: ou,
        common_name: cn,
        not_before,
        not_after,
        is_ca,
        key_usage: key_usage::KEY_AGREEMENT | if is_ca { key_usage::CERT_SIGN } else { 0 },
        ext_key_usage: vec![TCG_EK_CERTIFICATE_OID],
        subject_key_id: None,
    };
    parent.issue(&spec, subject_spki_der)
}

/// Go's `buildCertExtensions` for the fields `CertSpec` supports.
struct GoProfile {
    subject: Name,
    issuer: Name,
    key_usage: u16,
    ext_key_usage: Vec<ObjectIdentifier>,
    is_ca: bool,
    skid: Vec<u8>,
    akid: Vec<u8>,
}

impl BuilderProfile for GoProfile {
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
        if self.key_usage != 0 {
            let ku = KeyUsage(FlagSet::<KeyUsages>::new_truncated(self.key_usage));
            exts.push((true, &ku).to_extension(subject, &exts)?);
        }
        if !self.ext_key_usage.is_empty() {
            let eku = ExtendedKeyUsage(self.ext_key_usage.clone());
            exts.push((false, &eku).to_extension(subject, &exts)?);
        }
        let bc = BasicConstraints { ca: self.is_ca, path_len_constraint: None };
        exts.push((true, &bc).to_extension(subject, &exts)?);
        if !self.skid.is_empty() {
            let skid = SubjectKeyIdentifier(OctetString::new(self.skid.clone())?);
            exts.push((false, &skid).to_extension(subject, &exts)?);
        }
        if !self.akid.is_empty() {
            let akid = AuthorityKeyIdentifier { key_identifier: Some(OctetString::new(self.akid.clone())?), ..Default::default() };
            exts.push((false, &akid).to_extension(subject, &exts)?);
        }
        Ok(exts)
    }
}

/// Builds and signs a certificate. `parent` is `None` for self-signed
/// certificates (issuer = subject, signed by `signer`).
fn build(spec: &CertSpec<'_>, subject_spki_der: &[u8], parent: Option<&CaKey>, signer: &SigningKey) -> Result<Vec<u8>> {
    let subject = subject_name(spec.organization, spec.organizational_unit, spec.common_name)?;
    let issuer = parent.map_or_else(|| subject.clone(), |p| p.subject.clone());
    let spki = SubjectPublicKeyInfoOwned::from_der(subject_spki_der).map_err(|e| Error::invalid(format!("subject public key: {e}")))?;
    let mut skid = spec.subject_key_id.clone().unwrap_or_default();
    if skid.is_empty() && spec.is_ca {
        // Go 1.25+: leftmost 160 bits of SHA-256 over the key bits.
        skid = Sha256::digest(spki.subject_public_key.raw_bytes()).get(..20).unwrap_or_default().to_vec();
    }
    // Go: the AKID is the parent's SKID unless the certificate is self-issued.
    let self_issued = issuer.to_der().map_err(Error::invalid)? == subject.to_der().map_err(Error::invalid)?;
    let akid = match parent {
        Some(p) if !self_issued => p.skid.clone(),
        _ => Vec::new(),
    };
    let profile =
        GoProfile { subject, issuer, key_usage: spec.key_usage, ext_key_usage: spec.ext_key_usage.clone(), is_ca: spec.is_ca, skid, akid };
    let serial = SerialNumber::new(&random_serial()?).map_err(Error::invalid)?;
    let time = |t: SystemTime| Time::try_from(t).map_err(|e| Error::invalid(format!("certificate time: {e}")));
    let validity = Validity::new(time(spec.not_before)?, time(spec.not_after)?);
    let builder = CertificateBuilder::new(profile, serial, validity, spki).map_err(Error::invalid)?;
    let cert = builder.build::<_, DerSignature>(signer).map_err(Error::invalid)?;
    cert.to_der().map_err(Error::invalid)
}
