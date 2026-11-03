//! X.501 names encoded the way Go's `pkix.Name.ToRDNSequence` and
//! `encoding/asn1` encode them.

use crate::{Error, Result};
use const_oid::ObjectIdentifier;
use der::asn1::Any;
use der::{Decode as _, Encode as _, Tag};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};

const OID_ORGANIZATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
const OID_ORGANIZATIONAL_UNIT: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");
const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

/// Go's `encoding/asn1` `isPrintable` with asterisks and ampersands
/// rejected (the marshaling rules).
fn go_printable(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'\''..=b')' | b'+'..=b'/' | b' ' | b':' | b'=' | b'?')
}

/// The string type Go's `encoding/asn1` picks for a Go string inside a
/// name: PrintableString when every character allows it, else UTF8String.
pub fn go_string_tag(s: &str) -> Tag {
    if s.bytes().all(go_printable) { Tag::PrintableString } else { Tag::Utf8String }
}

/// Builds a subject name in Go's attribute order (O, OU, then CN; each a
/// single-valued RDN). Absent attributes and an empty CN are omitted, as
/// Go omits them.
pub fn subject_name(organization: Option<&str>, organizational_unit: Option<&str>, common_name: &str) -> Result<Name> {
    let cn = Some(common_name).filter(|s| !s.is_empty());
    let mut rdns = RdnSequence::default();
    for (oid, value) in [(OID_ORGANIZATION, organization), (OID_ORGANIZATIONAL_UNIT, organizational_unit), (OID_COMMON_NAME, cn)] {
        let Some(v) = value else { continue };
        let value = Any::new(go_string_tag(v), v.as_bytes()).map_err(Error::invalid)?;
        let rdn = RelativeDistinguishedName::try_from(vec![AttributeTypeAndValue { oid, value }]).map_err(Error::invalid)?;
        rdns.push(rdn);
    }
    // `Name` has no public constructor from an RDN sequence (without the
    // hazmat feature); its DER is the RDN sequence's DER.
    Name::from_der(&rdns.to_der().map_err(Error::invalid)?).map_err(Error::invalid)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn go_string_types() {
        assert_eq!(go_string_tag("Darkbloom DEV Simulated TPM Root (NOT AMD, NOT FOR PRODUCTION)"), Tag::PrintableString);
        assert_eq!(go_string_tag("SimulatedTPM 0123abcd"), Tag::PrintableString);
        assert_eq!(go_string_tag("a*b"), Tag::Utf8String);
        assert_eq!(go_string_tag("R&D"), Tag::Utf8String);
        assert_eq!(go_string_tag("caf\u{e9}"), Tag::Utf8String);
        assert_eq!(go_string_tag("under_score"), Tag::Utf8String);
    }

    #[test]
    fn go_name_layout() {
        // pkix.Name{OrganizationalUnit: ["swtpm"], CommonName: "EK"} as Go
        // encodes it: SEQUENCE { SET { OU }, SET { CN } }.
        let n = subject_name(None, Some("swtpm"), "EK").unwrap();
        let want: &[u8] = &[
            0x30, 0x1d, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x05, b's', b'w', b't', b'p', b'm', 0x31, 0x0b, 0x30,
            0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x02, b'E', b'K',
        ];
        assert_eq!(n.to_der().unwrap(), want);
        assert_eq!(subject_name(None, None, "").unwrap().to_der().unwrap(), [0x30, 0x00]);
    }
}
