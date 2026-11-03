//! The parts of X.509 certificates the EK chain check needs, parsed the way
//! Go's `x509.ParseCertificate` interprets them (key usage bit mask, basic
//! constraints, key identifiers, the last CN and every OU of the subject).

use crate::keys::PublicKey;
use crate::{Error, Result};
use chrono::{DateTime, NaiveDate, Utc};
use const_oid::ObjectIdentifier;
use db_gojson::GoTime;
use der::{Decode as _, Encode as _, Tag, Tagged as _};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use x509_cert::Certificate as X509;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, BasicConstraints, SubjectKeyIdentifier};

const OID_CN: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const OID_OU: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");
const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_SKID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const OID_AKID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");

/// Extensions that may be critical. Besides the four parsed above, these
/// carry identity or informational data that constrains nothing the EK chain
/// check relies on: extended key usage, certificate policies, CRL
/// distribution points, authority information access, and the TCG EK
/// profile's subject alternative name and subject directory attributes
/// (TPM manufacturer, model and specification; the SAN is critical when the
/// subject is empty). Any other critical extension (name or policy
/// constraints, private extensions) is a constraint this verifier does not
/// enforce, so such certificates are refused.
const HANDLED_EXTENSIONS: [ObjectIdentifier; 10] = [
    ObjectIdentifier::new_unwrap("2.5.29.15"),         // key usage
    ObjectIdentifier::new_unwrap("2.5.29.19"),         // basic constraints
    ObjectIdentifier::new_unwrap("2.5.29.14"),         // subject key identifier
    ObjectIdentifier::new_unwrap("2.5.29.35"),         // authority key identifier
    ObjectIdentifier::new_unwrap("2.5.29.37"),         // extended key usage
    ObjectIdentifier::new_unwrap("2.5.29.32"),         // certificate policies
    ObjectIdentifier::new_unwrap("2.5.29.31"),         // CRL distribution points
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1"), // authority information access
    ObjectIdentifier::new_unwrap("2.5.29.17"),         // subject alternative name
    ObjectIdentifier::new_unwrap("2.5.29.9"),          // subject directory attributes
];

/// Go's `x509.KeyUsageCertSign`.
pub const KEY_USAGE_CERT_SIGN: u32 = 1 << 5;
/// Go's `x509.KeyUsageKeyAgreement`.
pub const KEY_USAGE_KEY_AGREEMENT: u32 = 1 << 4;

/// A parsed certificate.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// The DER encoding.
    pub raw: Vec<u8>,
    tbs_raw: Vec<u8>,
    sig_alg: ObjectIdentifier,
    sig_params: Option<Vec<u8>>,
    signature: Vec<u8>,
    /// Subject common name (the last CN, as Go keeps).
    pub subject_cn: String,
    /// Subject organizational units, in order.
    pub subject_ou: Vec<String>,
    /// Issuer common name.
    pub issuer_cn: String,
    /// Validity start.
    pub not_before: DateTime<Utc>,
    /// Validity end.
    pub not_after: DateTime<Utc>,
    /// Whether a basicConstraints extension is present.
    pub basic_constraints_valid: bool,
    /// basicConstraints cA.
    pub is_ca: bool,
    /// Key usage bit mask in Go's numbering (0 when absent).
    pub key_usage: u32,
    /// Subject key identifier.
    pub subject_key_id: Vec<u8>,
    /// Authority key identifier (keyIdentifier).
    pub authority_key_id: Vec<u8>,
    /// The subject public key, if its algorithm is supported.
    pub public_key: Option<PublicKey>,
}

/// Returns the complete TLV at the start of `input` and the remainder.
/// Definite-length DER only.
fn tlv(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let first_len = *input.get(1)?;
    let (len, hdr) = if first_len < 0x80 {
        (usize::from(first_len), 2)
    } else {
        let n = usize::from(first_len & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | usize::from(*input.get(2 + i)?);
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    Some((input.get(..end)?, input.get(end..)?))
}

/// The raw TBSCertificate bytes, sliced from the original encoding (so the
/// signature check never depends on re-encoding).
fn raw_tbs(cert_der: &[u8]) -> Option<Vec<u8>> {
    let (outer, rest) = tlv(cert_der)?;
    if !rest.is_empty() || *outer.first()? != 0x30 {
        return None;
    }
    // Skip the outer header to reach the content.
    let content_start = if *outer.get(1)? < 0x80 { 2 } else { 2 + usize::from(outer.get(1)? & 0x7f) };
    let (tbs, _) = tlv(outer.get(content_start..)?)?;
    Some(tbs.to_vec())
}

fn der_time(t: &x509_cert::time::Time) -> Result<DateTime<Utc>> {
    let dt = t.to_date_time();
    let d = NaiveDate::from_ymd_opt(i32::from(dt.year()), u32::from(dt.month()), u32::from(dt.day()))
        .and_then(|d| d.and_hms_opt(u32::from(dt.hour()), u32::from(dt.minutes()), u32::from(dt.seconds())))
        .ok_or_else(|| Error::Invalid("certificate time out of range".to_owned()))?;
    Ok(DateTime::from_naive_utc_and_offset(d, Utc))
}

/// Go's `isPrintable` (PrintableString plus the '*' and '&' Go tolerates).
fn is_printable(b: u8) -> bool {
    b.is_ascii_alphanumeric() || (b'\''..=b')').contains(&b) || (b'+'..=b'/').contains(&b) || b" :=?*&".contains(&b)
}

/// Decodes an X.520 string value exactly as Go's `parseASN1String` does,
/// including its errors.
fn asn1_string(v: &der::asn1::AnyRef<'_>) -> std::result::Result<String, &'static str> {
    let b = v.value();
    match v.tag() {
        // Go returns the raw bytes; Rust strings must be UTF-8.
        Tag::TeletexString => Ok(String::from_utf8_lossy(b).into_owned()),
        Tag::PrintableString if b.iter().all(|&c| is_printable(c)) => Ok(String::from_utf8_lossy(b).into_owned()),
        Tag::PrintableString => Err("invalid PrintableString"),
        Tag::Utf8String => std::str::from_utf8(b).map(str::to_owned).map_err(|_| "invalid UTF-8 string"),
        Tag::BmpString => {
            if b.len() % 2 != 0 {
                return Err("invalid BMPString");
            }
            // Strip a terminator if present.
            let b = b.strip_suffix(&[0, 0]).unwrap_or(b);
            let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
            Ok(char::decode_utf16(units).map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER)).collect())
        }
        Tag::Ia5String if b.is_ascii() => Ok(String::from_utf8_lossy(b).into_owned()),
        Tag::Ia5String => Err("invalid IA5String"),
        Tag::NumericString if b.iter().all(|&c| c.is_ascii_digit() || c == b' ') => Ok(String::from_utf8_lossy(b).into_owned()),
        Tag::NumericString => Err("invalid NumericString"),
        _ => Err("unsupported string type"),
    }
}

/// The last CN and every OU of a name. Like Go's `parseName`, every
/// attribute value must be a valid string of a supported type.
fn name_fields(name: &x509_cert::name::Name) -> Result<(String, Vec<String>)> {
    let mut cn = String::new();
    let mut ou = Vec::new();
    for atv in name.iter() {
        let any = der::asn1::AnyRef::from(&atv.value);
        let value = asn1_string(&any).map_err(|e| Error::Invalid(format!("x509: invalid RDNSequence: invalid attribute value: {e}")))?;
        if atv.oid == OID_CN {
            cn = value;
        } else if atv.oid == OID_OU {
            ou.push(value);
        }
    }
    Ok((cn, ou))
}

impl Certificate {
    /// Parses a DER certificate.
    pub fn parse(der_bytes: &[u8]) -> Result<Self> {
        let bad = |e: &dyn std::fmt::Display| Error::Invalid(format!("x509: {e}"));
        let cert = X509::from_der(der_bytes).map_err(|e| bad(&e))?;
        let tbs_raw = raw_tbs(der_bytes).ok_or_else(|| bad(&"malformed certificate"))?;
        let tbs = cert.tbs_certificate();
        // Go: "x509: inner and outer signature algorithm identifiers don't match".
        if tbs.signature() != cert.signature_algorithm() {
            return Err(bad(&"inner and outer signature algorithm identifiers don't match"));
        }
        let sig_alg = cert.signature_algorithm().oid;
        let sig_params = match &cert.signature_algorithm().parameters {
            Some(p) => Some(p.to_der().map_err(|e| bad(&e))?),
            None => None,
        };
        let signature = cert.signature().as_bytes().ok_or_else(|| bad(&"signature has unused bits"))?.to_vec();
        let (subject_cn, subject_ou) = name_fields(tbs.subject())?;
        let (issuer_cn, _) = name_fields(tbs.issuer())?;
        let not_before = der_time(&tbs.validity().not_before)?;
        let not_after = der_time(&tbs.validity().not_after)?;
        let spki_der = tbs.subject_public_key_info().to_der().map_err(|e| bad(&e))?;
        let public_key = PublicKey::from_spki_der(&spki_der)?;

        let mut c = Self {
            raw: der_bytes.to_vec(),
            tbs_raw,
            sig_alg,
            sig_params,
            signature,
            subject_cn,
            subject_ou,
            issuer_cn,
            not_before,
            not_after,
            basic_constraints_valid: false,
            is_ca: false,
            key_usage: 0,
            subject_key_id: Vec::new(),
            authority_key_id: Vec::new(),
            public_key,
        };
        let mut seen = BTreeSet::new();
        for ext in tbs.extensions().map(|e| e.as_slice()).unwrap_or_default() {
            if !seen.insert(ext.extn_id) {
                return Err(bad(&"certificate contains duplicate extensions"));
            }
            if ext.critical && !HANDLED_EXTENSIONS.contains(&ext.extn_id) {
                return Err(bad(&format!("unhandled critical extension {}", ext.extn_id)));
            }
            let value = ext.extn_value.as_bytes();
            match ext.extn_id {
                OID_BASIC_CONSTRAINTS => {
                    let bc = BasicConstraints::from_der(value).map_err(|e| bad(&e))?;
                    c.basic_constraints_valid = true;
                    c.is_ca = bc.ca;
                }
                OID_KEY_USAGE => {
                    let bits = der::asn1::BitStringRef::from_der(value).map_err(|e| bad(&e))?;
                    let raw = bits.raw_bytes();
                    let bit_len = bits.bit_len();
                    let mut usage = 0u32;
                    for i in 0..9usize {
                        let set = i < bit_len && raw.get(i / 8).is_some_and(|b| b & (0x80 >> (i % 8)) != 0);
                        if set {
                            usage |= 1 << i;
                        }
                    }
                    c.key_usage = usage;
                }
                OID_SKID => {
                    c.subject_key_id = SubjectKeyIdentifier::from_der(value).map_err(|e| bad(&e))?.0.as_bytes().to_vec();
                }
                OID_AKID => {
                    let akid = AuthorityKeyIdentifier::from_der(value).map_err(|e| bad(&e))?;
                    c.authority_key_id = akid.key_identifier.map(|k| k.as_bytes().to_vec()).unwrap_or_default();
                }
                _ => {}
            }
        }
        Ok(c)
    }

    /// Lowercase hex SHA-256 of the DER encoding.
    pub fn fingerprint(&self) -> String {
        hex::encode(Sha256::digest(&self.raw))
    }

    /// Whether `now` lies within the validity period (inclusive).
    pub fn valid_at(&self, now: &GoTime) -> bool {
        let now = now.datetime().with_timezone(&Utc);
        now >= self.not_before && now <= self.not_after
    }

    /// Whether `parent`'s key signed this certificate (signature only:
    /// issuer names are deliberately not compared, see the EK chain notes).
    pub fn signed_by(&self, parent: &Certificate) -> bool {
        match &parent.public_key {
            Some(k) => k.verify_x509(&self.sig_alg, self.sig_params.as_deref(), &self.tbs_raw, &self.signature),
            None => false,
        }
    }
}

/// Reads PEM (`CERTIFICATE` blocks only) or DER certificates.
pub fn parse_certificates(data: &[u8]) -> Result<Vec<Certificate>> {
    let text = String::from_utf8_lossy(data);
    if !text.contains("-----BEGIN") {
        return Ok(vec![Certificate::parse(data)?]);
    }
    let mut out = Vec::new();
    let mut rest: &str = &text;
    while let Some(start) = rest.find("-----BEGIN ") {
        let after = rest.get(start + 11..).unwrap_or_default();
        let Some(label_end) = after.find("-----") else { break };
        let label = after.get(..label_end).unwrap_or_default();
        let body_start = label_end + 5;
        let end_marker = format!("-----END {label}-----");
        let Some(end) = after.find(&end_marker) else { break };
        let body = after.get(body_start..end).unwrap_or_default();
        rest = after.get(end + end_marker.len()..).unwrap_or_default();
        if label != "CERTIFICATE" {
            continue;
        }
        let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        use base64::Engine as _;
        let der_bytes =
            base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()).map_err(|e| Error::Invalid(format!("PEM: {e}")))?;
        out.push(Certificate::parse(&der_bytes)?);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use rand::{RngExt as _, SeedableRng as _};

    fn amd_certs() -> Vec<Certificate> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../certs/amd-pluton");
        let mut out = Vec::new();
        for f in ["amd-pluton-global-factory-ica.pem", "amd-pluton-00b70f00-non-fips-ek-ica.pem"] {
            out.extend(parse_certificates(&std::fs::read(dir.join(f)).unwrap()).unwrap());
        }
        out
    }

    #[test]
    fn parses_amd_certificates_like_go() {
        let certs = amd_certs();
        let (anchor, ica) = (&certs[0], &certs[1]);
        assert_eq!(anchor.fingerprint(), crate::PLUTON_GLOBAL_FACTORY_ICA_SHA256);
        assert_eq!(anchor.subject_cn, "AMD Pluton Global Factory ICA");
        assert_eq!(anchor.issuer_cn, "AMD Root CA R4");
        assert!(anchor.basic_constraints_valid && anchor.is_ca);
        assert_eq!(anchor.key_usage, KEY_USAGE_CERT_SIGN | (1 << 6));
        assert_eq!(hex::encode(&anchor.subject_key_id), "2e072f821961bdf29339f6215f0d78ff4a5a8cbb");
        assert_eq!(hex::encode(&ica.authority_key_id), "2e072f821961bdf29339f6215f0d78ff4a5a8cbb");
        assert!(ica.signed_by(anchor), "per-product ICA not signed by the anchor");
        assert!(!anchor.signed_by(ica));
        assert_eq!(anchor.public_key.as_ref().map(|k| k.key_type()), Some("ecdsa-P-384".to_owned()));
    }

    /// `cert` with one more extension appended to its TBS (the signature no
    /// longer verifies; parsing does not check it).
    fn with_extension(cert: &[u8], oid: &str, critical: bool) -> Vec<u8> {
        use der::{Any, Reader as _, SliceReader};
        fn kids(v: &[u8]) -> Vec<Any> {
            let mut r = SliceReader::new(v).unwrap();
            let mut out = Vec::new();
            while !r.is_finished() {
                out.push(Any::decode(&mut r).unwrap());
            }
            out
        }
        fn join(tag: Tag, parts: &[Any]) -> Any {
            let mut v = Vec::new();
            for p in parts {
                p.encode_to_vec(&mut v).unwrap();
            }
            Any::new(tag, v).unwrap()
        }
        let ext = x509_cert::ext::Extension {
            extn_id: ObjectIdentifier::new(oid).unwrap(),
            critical,
            extn_value: der::asn1::OctetString::new(vec![0x30, 0x00]).unwrap(),
        };
        let mut top = kids(Any::from_der(cert).unwrap().value());
        let mut tbs = kids(top[0].value());
        let i = tbs.iter().position(|a| matches!(a.tag(), Tag::ContextSpecific { number, .. } if number.value() == 3)).unwrap();
        let mut exts = kids(kids(tbs[i].value())[0].value());
        exts.push(Any::from_der(&ext.to_der().unwrap()).unwrap());
        tbs[i] = join(tbs[i].tag(), &[join(Tag::Sequence, &exts)]);
        top[0] = join(Tag::Sequence, &tbs);
        join(Tag::Sequence, &top).to_der().unwrap()
    }

    #[test]
    fn unhandled_critical_extensions_are_refused() {
        let ica = amd_certs()[1].raw.clone();
        let private = "1.3.6.1.4.1.99999.1";
        let err = Certificate::parse(&with_extension(&ica, private, true)).unwrap_err().to_string();
        assert!(err.contains("unhandled critical extension 1.3.6.1.4.1.99999.1"), "{err}");
        assert!(Certificate::parse(&with_extension(&ica, private, false)).is_ok(), "non-critical unknown extension refused");
        // Name constraints, policy constraints, inhibitAnyPolicy, policy
        // mappings: constraints this verifier does not enforce.
        for oid in ["2.5.29.30", "2.5.29.36", "2.5.29.54", "2.5.29.33"] {
            assert!(Certificate::parse(&with_extension(&ica, oid, true)).is_err(), "critical {oid} accepted");
        }
        // TCG EK profile: the SAN is critical when the subject is empty.
        assert!(Certificate::parse(&with_extension(&ica, "2.5.29.17", true)).is_ok(), "critical SAN refused");
        // The unmodified chain still parses and links.
        assert!(Certificate::parse(&ica).unwrap().signed_by(&amd_certs()[0]));
    }

    #[test]
    fn names_follow_go_string_rules() {
        let anchor = amd_certs()[0].raw.clone();
        let hits: Vec<usize> = anchor.windows(11).enumerate().filter(|(_, w)| *w == b"Santa Clara").map(|(i, _)| i).collect();
        let (issuer_l, subject_l) = (hits[0], *hits.last().unwrap());
        let err = |m: &[u8]| Certificate::parse(m).unwrap_err().to_string();
        // The subject's L is a PrintableString: '@' is not allowed.
        let mut m = anchor.clone();
        m[subject_l + 5] = b'@';
        assert!(err(&m).contains("invalid attribute value: invalid PrintableString"), "{}", err(&m));
        // The issuer's L is a UTF8String.
        let mut m = anchor.clone();
        m[issuer_l] = 0xff;
        assert!(err(&m).contains("invalid UTF-8 string"), "{}", err(&m));
        // Retagged as a BMPString, its 11 bytes are an odd length.
        let mut m = anchor.clone();
        m[issuer_l - 2] = 0x1e;
        assert!(err(&m).contains("invalid BMPString"), "{}", err(&m));
    }

    #[test]
    fn asn1_strings_like_go() {
        let s = |tag: Tag, b: &[u8]| asn1_string(&der::asn1::AnyRef::new(tag, b).unwrap());
        assert_eq!(s(Tag::BmpString, &[0, b'A', 0, b'B', 0, 0]), Ok("AB".to_owned()), "terminator kept");
        assert_eq!(s(Tag::BmpString, &[0, b'A', 0]), Err("invalid BMPString"));
        assert_eq!(s(Tag::PrintableString, b"a*b&c (x)"), Ok("a*b&c (x)".to_owned()));
        assert_eq!(s(Tag::PrintableString, b"a@b"), Err("invalid PrintableString"));
        assert_eq!(s(Tag::Ia5String, b"a@b"), Ok("a@b".to_owned()));
        assert_eq!(s(Tag::Ia5String, &[0xc3, 0xa9]), Err("invalid IA5String"));
        assert_eq!(s(Tag::NumericString, b"12 3"), Ok("12 3".to_owned()));
        assert_eq!(s(Tag::NumericString, b"12a"), Err("invalid NumericString"));
        assert_eq!(s(Tag::Utf8String, &[0xff]), Err("invalid UTF-8 string"));
        assert_eq!(s(Tag::OctetString, b"x"), Err("unsupported string type"));
    }

    // Truncated or mutated certificates must fail cleanly, never panic.
    #[test]
    fn robustness() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        for c in amd_certs() {
            for n in (0..c.raw.len()).step_by(7) {
                let _ = Certificate::parse(&c.raw[..n]);
            }
            for _ in 0..3000 {
                let mut m = c.raw.clone();
                for _ in 0..rng.random_range(1..4) {
                    let i = rng.random_range(0..m.len());
                    m[i] = rng.random();
                }
                if let Ok(p) = Certificate::parse(&m) {
                    let _ = p.signed_by(&p);
                }
            }
        }
        assert!(parse_certificates(b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n").is_err());
        assert!(parse_certificates(b"-----BEGIN CERTIFICATE-----\nAAAA\n").unwrap().is_empty());
    }
}
