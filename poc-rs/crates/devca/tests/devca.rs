#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use db_devca::*;
use der::{Decode as _, Encode as _};
use p256::elliptic_curve::Generate as _;
use p384::ecdsa::signature::Verifier as _;
use std::path::Path;
use std::time::{Duration, SystemTime};
use x509_cert::Certificate;

fn parse(der_bytes: &[u8]) -> Certificate {
    let c = Certificate::from_der(der_bytes).unwrap();
    assert_eq!(c.to_der().unwrap(), der_bytes, "certificate does not re-encode identically");
    c
}

/// Verifies `child`'s signature with `parent`'s P-384 key (ecdsa-with-SHA384).
fn signed_by(child: &Certificate, parent: &Certificate) -> bool {
    if child.signature_algorithm().oid.to_string() != "1.2.840.10045.4.3.3" || child.signature_algorithm().parameters.is_some() {
        return false;
    }
    let spki = parent.tbs_certificate().subject_public_key_info().to_der().unwrap();
    let Ok(vk) = <p384::ecdsa::VerifyingKey as spki::DecodePublicKey>::from_public_key_der(&spki) else { return false };
    let Ok(sig) = p384::ecdsa::DerSignature::from_bytes(child.signature().raw_bytes()) else { return false };
    vk.verify(&child.tbs_certificate().to_der().unwrap(), &sig).is_ok()
}

/// (oid, critical, value DER) in order.
fn extensions(c: &Certificate) -> Vec<(String, bool, Vec<u8>)> {
    c.tbs_certificate()
        .extensions()
        .unwrap()
        .iter()
        .map(|e| (e.extn_id.to_string(), e.critical, e.extn_value.as_bytes().to_vec()))
        .collect()
}

fn octets(b: &[u8]) -> Vec<u8> {
    let mut v = vec![0x04, b.len() as u8];
    v.extend_from_slice(b);
    v
}

fn akid(b: &[u8]) -> Vec<u8> {
    let mut v = vec![0x30, b.len() as u8 + 2, 0x80, b.len() as u8];
    v.extend_from_slice(b);
    v
}

fn check_dev_ca(ca: &DevCa) {
    let root = parse(ca.root_der());
    let ica = parse(ca.ica_der());
    assert_eq!(root.tbs_certificate().subject().to_string(), format!("CN={},O={DEV_ORG}", DEV_ROOT_CN.replace(',', "\\,")));
    assert_eq!(ica.tbs_certificate().subject().to_string(), format!("CN={DEV_ICA_CN},O={DEV_ORG}"));
    assert_eq!(ica.tbs_certificate().issuer(), root.tbs_certificate().subject());
    assert!(signed_by(&root, &root) && signed_by(&ica, &root), "dev CA signatures");
    let root_skid = ca_skid(&root);
    assert_eq!(root_skid.len(), 20);
    // keyUsage certSign|cRLSign (critical), CA:TRUE (critical), SKID; the
    // ICA adds the root's SKID as AKID.
    let ku = vec![0x03, 0x02, 0x01, 0x06];
    let bc = vec![0x30, 0x03, 0x01, 0x01, 0xff];
    assert_eq!(
        extensions(&root),
        vec![
            ("2.5.29.15".into(), true, ku.clone()),
            ("2.5.29.19".into(), true, bc.clone()),
            ("2.5.29.14".into(), false, octets(&root_skid))
        ]
    );
    assert_eq!(
        extensions(&ica),
        vec![
            ("2.5.29.15".into(), true, ku),
            ("2.5.29.19".into(), true, bc),
            ("2.5.29.14".into(), false, octets(ca.ica().skid())),
            ("2.5.29.35".into(), false, akid(&root_skid)),
        ]
    );
}

fn ca_skid(c: &Certificate) -> Vec<u8> {
    let (_, id) = c.tbs_certificate().get_extension::<x509_cert::ext::pkix::SubjectKeyIdentifier>().unwrap().unwrap();
    id.0.as_bytes().to_vec()
}

fn check_ek_cert(ca: &DevCa) {
    let ek = p256::SecretKey::try_generate_from_rng(&mut getrandom::SysRng).unwrap();
    let spki = spki::EncodePublicKey::to_public_key_der(&ek.public_key()).unwrap().as_bytes().to_vec();
    let der_bytes = ca.issue_ek_certificate(&spki, b"fake TPMT_PUBLIC").unwrap();
    let c = parse(&der_bytes);
    let ica = parse(ca.ica_der());
    assert!(signed_by(&c, &ica), "EK certificate signature");
    assert_eq!(c.tbs_certificate().issuer(), ica.tbs_certificate().subject());
    assert_eq!(c.tbs_certificate().subject_public_key_info().to_der().unwrap(), spki);
    // sha256("fake TPMT_PUBLIC")[:8]
    use sha2::Digest as _;
    let sum = sha2::Sha256::digest(b"fake TPMT_PUBLIC");
    let want_cn = format!("SimulatedTPM {}", sum[..8].iter().map(|b| format!("{b:02x}")).collect::<String>());
    assert_eq!(c.tbs_certificate().subject().to_string(), format!("CN={want_cn},OU=swtpm"));
    assert_eq!(
        extensions(&c),
        vec![
            ("2.5.29.15".into(), true, vec![0x03, 0x02, 0x03, 0x08]),
            ("2.5.29.37".into(), false, vec![0x30, 0x07, 0x06, 0x05, 0x67, 0x81, 0x05, 0x08, 0x01]),
            ("2.5.29.19".into(), true, vec![0x30, 0x00]),
            ("2.5.29.35".into(), false, akid(ca.ica().skid())),
        ]
    );
    let v = c.tbs_certificate().validity();
    let span = v.not_after.to_system_time().duration_since(v.not_before.to_system_time()).unwrap();
    assert!(span >= Duration::from_secs(3 * 365 * 86400) && span <= Duration::from_secs(3 * 366 * 86400));
    let age = SystemTime::now().duration_since(v.not_before.to_system_time()).unwrap();
    assert!(age >= Duration::from_secs(3599) && age <= Duration::from_secs(3700));
}

#[cfg(unix)]
fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn create_and_load() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("devca");
    create_dev_ca(&dir).unwrap();
    #[cfg(unix)]
    {
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join(ICA_KEY_FILE)), 0o600);
        assert_eq!(mode(&dir.join(ROOT_FILE)) & 0o600, 0o600);
    }
    let key = std::fs::read_to_string(dir.join(ICA_KEY_FILE)).unwrap();
    assert!(key.starts_with("-----BEGIN EC PRIVATE KEY-----\n") && key.ends_with("-----END EC PRIVATE KEY-----\n"));
    let root = std::fs::read_to_string(dir.join(ROOT_FILE)).unwrap();
    assert!(root.starts_with("-----BEGIN CERTIFICATE-----\n") && root.ends_with("-----END CERTIFICATE-----\n"));
    assert!(root.lines().all(|l| l.len() <= 64));
    let ca = load_dev_ca(&dir).unwrap();
    check_dev_ca(&ca);
    check_ek_cert(&ca);
    // A second CA in the same place replaces the first.
    create_dev_ca(&dir).unwrap();
    let ca2 = load_dev_ca(&dir).unwrap();
    assert_ne!(ca2.root_der(), ca.root_der());
    // A key that does not match the ICA certificate is refused.
    let other = tmp.path().join("other");
    create_dev_ca(&other).unwrap();
    std::fs::copy(other.join(ICA_KEY_FILE), dir.join(ICA_KEY_FILE)).unwrap();
    assert!(load_dev_ca(&dir).is_err(), "mismatched ICA key accepted");
    assert!(load_dev_ca(&tmp.path().join("missing")).is_err());
}

#[test]
fn explicit_identifiers_and_validity() {
    let now = SystemTime::now();
    let hour = Duration::from_secs(3600);
    let root = self_signed_ca("root", None, Some(b"root-skid"), now - hour, now + hour).unwrap();
    assert_eq!(root.skid(), b"root-skid");
    let ica = issue_ca(&root, "ica", None, Some(b"ica-skid"), now - hour, now - Duration::from_secs(60)).unwrap();
    let c = parse(ica.cert_der());
    assert_eq!(c.tbs_certificate().subject().to_string(), "CN=ica");
    assert_eq!(extensions(&c)[3], ("2.5.29.35".into(), false, akid(b"root-skid")));
    assert!(c.tbs_certificate().validity().not_after.to_system_time() < now);
    // A CA certificate presented as an EK certificate gets Go's automatic
    // SKID (SHA-256 over the key bits, 20 bytes) and keyAgreement|certSign.
    let ek = p256::SecretKey::try_generate_from_rng(&mut getrandom::SysRng).unwrap();
    let spki = spki::EncodePublicKey::to_public_key_der(&ek.public_key()).unwrap().as_bytes().to_vec();
    let bad = parse(&issue_ek_cert(&ica, &spki, "EK", None, now - hour, now + hour, true).unwrap());
    let ext = extensions(&bad);
    assert_eq!(ext[0], ("2.5.29.15".into(), true, vec![0x03, 0x02, 0x02, 0x0c]));
    assert_eq!(ext[2], ("2.5.29.19".into(), true, vec![0x30, 0x03, 0x01, 0x01, 0xff]));
    assert_eq!(ext[3].0, "2.5.29.14");
    assert_eq!(ext[3].2.len(), 22);
    assert_eq!(ext[4], ("2.5.29.35".into(), false, akid(b"ica-skid")));
    // Serial numbers are positive and at most 16 bytes of value.
    for _ in 0..200 {
        let s = random_serial().unwrap();
        assert_eq!(s.len(), 16);
        assert!(s[0] <= 1 && s.iter().any(|&b| b != 0));
    }
}
