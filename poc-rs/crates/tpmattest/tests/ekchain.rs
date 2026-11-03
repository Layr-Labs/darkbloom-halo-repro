//! Port of the Go `tpmattest/ekchain_test.go`: adversarial EK chains, the
//! pinned AMD Pluton anchor and expired anchors.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use db_devca::{CaKey, issue_ca, issue_ek_cert, self_signed_ca};
use db_gojson::GoTime;
use db_tpmattest::{Certificate, PublicKey, RootKind, TrustBundle, pinned_root, pluton_root};
use p256::elliptic_curve::Generate as _;
use std::path::Path;
use std::time::{Duration, SystemTime};

const HOUR: Duration = Duration::from_secs(3600);

fn year() -> SystemTime {
    SystemTime::now() + Duration::from_secs(365 * 86400)
}

/// A P-384 CA named `name` (self-signed without a parent), valid from an
/// hour ago until `not_after`, with an explicit subject key ID.
fn new_ca(name: &str, parent: Option<&CaKey>, skid: &[u8], not_after: SystemTime) -> CaKey {
    let not_before = SystemTime::now() - HOUR;
    match parent {
        None => self_signed_ca(name, None, Some(skid), not_before, not_after),
        Some(p) => issue_ca(p, name, None, Some(skid), not_before, not_after),
    }
    .unwrap()
}

/// An EK certificate (CN "EK", valid ±1h) for `ek`; `is_ca` makes it a CA
/// certificate.
fn ek_cert(ica: &CaKey, ek: &PublicKey, is_ca: bool) -> Vec<u8> {
    let now = SystemTime::now();
    issue_ek_cert(ica, &ek.to_spki_der().unwrap(), "EK", None, now - HOUR, now + HOUR, is_ca).unwrap()
}

fn ek_key() -> PublicKey {
    PublicKey::P256(p256::SecretKey::try_generate_from_rng(&mut getrandom::SysRng).unwrap().public_key())
}

/// Asserts a rejection whose message contains `why`.
fn rejected(r: db_tpmattest::Result<db_tpmattest::EkChain>, why: &str, what: &str) {
    match r {
        Ok(_) => panic!("{what} accepted"),
        Err(e) => assert!(e.to_string().contains(why), "{what} rejected for another reason: {e}"),
    }
}

fn bundle(root: &CaKey) -> TrustBundle {
    let anchor = Certificate::parse(root.cert_der()).unwrap();
    TrustBundle { roots: vec![pinned_root("test", RootKind::DevSimulated, vec![anchor], Vec::new(), false)] }
}

#[test]
fn ek_chain_adversarial() {
    let root = new_ca("root", None, b"root-skid", year());
    let ica = new_ca("ica", Some(&root), b"ica-skid", year());
    let b = bundle(&root);
    let ek = ek_key();
    let good = ek_cert(&ica, &ek, false);
    let icas = |cas: &[&CaKey]| cas.iter().map(|c| c.cert_der().to_vec()).collect::<Vec<_>>();
    let now = GoTime::now_utc();
    let chain = b.verify_ek(&good, &icas(&[&ica]), &ek, &now).unwrap_or_else(|e| panic!("genuine chain rejected: {e}"));
    assert_eq!(chain.path.len(), 3);
    assert_eq!(chain.root_kind, RootKind::DevSimulated);

    // An impostor ICA with the same subject key ID (and name) but its own key.
    let fake = new_ca("ica", Some(&new_ca("other-root", None, b"root-skid", year())), b"ica-skid", year());
    let forged = ek_cert(&fake, &ek, false);
    rejected(
        b.verify_ek(&forged, &icas(&[&fake, &ica]), &ek, &now),
        "no issuer found for \"ica\"",
        "EK signed by an impostor ICA (same key ID)",
    );
    // The forged leaf presented with the real ICA does not get through either.
    rejected(b.verify_ek(&forged, &icas(&[&ica]), &ek, &now), "no issuer found for \"EK\"", "forged leaf");
    // A CA certificate presented as the EK.
    rejected(
        b.verify_ek(&ek_cert(&ica, &ek, true), &icas(&[&ica]), &ek, &now),
        "is a CA certificate",
        "CA certificate as an EK certificate",
    );
    // A certificate for a different key than the TPM's EK.
    rejected(
        b.verify_ek(&good, &icas(&[&ica]), &ek_key(), &now),
        "does not certify the TPM's endorsement key",
        "certificate for another key",
    );
    // An expired intermediate.
    let old = new_ca("old-ica", Some(&root), b"old-skid", SystemTime::now() - Duration::from_secs(60));
    rejected(b.verify_ek(&ek_cert(&old, &ek, false), &icas(&[&old]), &ek, &now), "is not valid now", "chain through an expired ICA");
    // A missing intermediate.
    rejected(b.verify_ek(&good, &[], &ek, &now), "no issuer found for \"EK\"", "chain without its ICA");
    // A root that is not pinned (same name and key ID, different key) is not an anchor.
    let other = new_ca("root", None, b"root-skid", year());
    let b2 = bundle(&other);
    rejected(b2.verify_ek(&good, &icas(&[&ica, &root]), &ek, &now), "no issuer found for \"root\"", "chain to an unpinned root");
}

#[test]
fn pluton_anchor_pinned() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../certs/amd-pluton");
    let r = pluton_root(&dir, 6).unwrap();
    assert!(
        r.anchors.len() == 1 && r.anchors[0].subject_cn.contains("Global Factory") && !r.intermediates.is_empty(),
        "Pluton root did not load the pinned anchor and per-product ICA"
    );
    // The AMD per-product ICA chains to the pinned anchor by signature.
    assert!(r.intermediates[0].signed_by(&r.anchors[0]), "AMD per-product EK ICA is not signed by the Global Factory ICA");
}

#[test]
fn expired_anchor_rejected() {
    let root = new_ca("root", None, b"root-skid", SystemTime::now() - Duration::from_secs(60));
    let ica = new_ca("ica", Some(&root), b"ica-skid", year());
    let ek = ek_key();
    let b = bundle(&root);
    let r = b.verify_ek(&ek_cert(&ica, &ek, false), &[ica.cert_der().to_vec()], &ek, &GoTime::now_utc());
    rejected(r, "the issuer of \"ica\" is not valid now", "chain to an expired pinned anchor");
}
