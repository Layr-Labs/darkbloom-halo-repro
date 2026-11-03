//! Port of the Go `e2e/bound_test.go`: TPM-bound decryption keys are
//! enforced by the TPM (PolicyPCR), and the verifier checks their attributes,
//! policy, certification and PCR coverage.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

mod common;

use common::{Harness, Subtests, default_pcrs, expect, nonce, random};
use db_tpm2::consts::{OBJ_USER_WITH_AUTH, RH_ENDORSEMENT};
use db_tpm2::{AsymScheme, PublicParams};
use db_tpmattest::{ALG_SHA256, DEFAULT_PCRS, Statement, bound_key_certify_data, digests_of, policy_pcr_digest};
use db_tpmdev::{AttestError, bound_key_template};
use p256::elliptic_curve::Generate as _;

fn with_bound_key(h: &Harness, bk: db_tpmattest::BoundKey) -> Vec<u8> {
    let mut st: Statement = db_gojson::from_slice(&h.stmt).unwrap();
    st.bound_key = Some(bk);
    db_gojson::to_vec(&st).unwrap()
}

/// A job sealed to the TPM-bound key opens only with the TPM's ECDH under
/// the attested PCR policy. The in-memory HPKE key alone (a RAM dump) does
/// not open it, and after a PCR changes the TPM refuses the ECDH outright.
#[test]
fn bound_key_enforced_by_tpm() {
    let Some(mut h) = Harness::new() else { return };
    h.activate();
    let bk = h.att.new_bound_key("session-1").unwrap();
    let stmt = with_bound_key(&h, bk.public.clone());
    let st: Statement = db_gojson::from_slice(&stmt).unwrap();
    let ev = h.att.attest(&nonce(), &stmt, &default_pcrs()).unwrap();
    let v = h.evaluate(&ev, &expect("session-1", "acct-1", true));
    assert!(v.ok && v.bound_key.is_some(), "bound key not verified: {:?}", v.failed());
    let bound = v.bound_key.unwrap();
    assert_eq!(&*bound.to_sec1_bytes(), bk.public_bytes(), "verifier and agent disagree on the bound key");
    let info = db_sealbox::info(&st.provider_id, "session-1");
    let aad = br#"{"job_id":"j"}"#;
    let (sealed, ck) = db_sealbox::seal_request_bound(&st.job_kem, &st.job_public_key, &bound, &info, aad, b"private prompt").unwrap();
    // The provider path: TPM ECDH under PolicyPCR, then HPKE PSK open.
    let z = h.att.bound_ecdh(&bk, &sealed.tpm_ephemeral).unwrap();
    let (pt, pk) = h.job.open_request_bound(&info, aad, &sealed, &z, bk.public_bytes()).unwrap();
    assert_eq!(pt.as_slice(), b"private prompt");
    assert_eq!(pk.as_bytes(), ck.as_bytes(), "result keys differ");
    // A RAM dump yields the HPKE private key, but not the TPM share.
    assert!(h.job.open_request(&info, aad, &sealed).is_err(), "bound job opened without the TPM share");
    assert!(
        h.job.open_request_bound(&info, aad, &sealed, &random::<32>(), bk.public_bytes()).is_err(),
        "bound job opened with a guessed TPM share"
    );
    // Any change to a policy PCR (another boot, or tampering) and the TPM refuses.
    h.f.dev.pcr_extend(14, &digests_of(&[ALG_SHA256], b"tamper")).unwrap();
    let err = h.att.bound_ecdh(&bk, &sealed.tpm_ephemeral).expect_err("TPM performed the bound ECDH after a policy PCR changed");
    println!("TPM refused after PCR 14 changed: {err}");
    assert!(err.to_string().contains("TPM refused the bound ECDH"), "{err}");
    h.att.flush_bound(&bk);
}

/// The TPM's ECDH_ZGen output is the x coordinate a software ECDH computes,
/// malformed peers are refused before reaching the TPM, and failed policy
/// sessions are flushed (swtpm holds only three loaded sessions).
#[test]
fn bound_ecdh_interop_and_session_hygiene() {
    let Some(h) = Harness::new() else { return };
    let bk = h.att.new_bound_key("session-1").unwrap();
    let bound = p256::PublicKey::from_sec1_bytes(bk.public_bytes()).unwrap();
    for _ in 0..5 {
        let eph = p256::ecdh::EphemeralSecret::try_generate_from_rng(&mut getrandom::SysRng).unwrap();
        let z = h.att.bound_ecdh(&bk, &eph.public_key().to_sec1_bytes()).unwrap();
        assert_eq!(z.as_slice(), eph.diffie_hellman(&bound).raw_secret_bytes().as_slice());
    }
    let eph = p256::ecdh::EphemeralSecret::try_generate_from_rng(&mut getrandom::SysRng).unwrap();
    let peer = eph.public_key().to_sec1_bytes();
    // Not a point, compressed, off the curve.
    let mut compressed = vec![2 + (peer[64] & 1)];
    compressed.extend_from_slice(&peer[1..33]);
    let mut off_curve = peer.to_vec();
    off_curve[64] ^= 1;
    for bad in [&[4u8; 10][..], &compressed, &off_curve, &[]] {
        assert!(matches!(h.att.bound_ecdh(&bk, bad), Err(AttestError::BadChallenge(_))), "{bad:02x?}");
    }
    // A policy over other PCRs than the key's: PolicyPCR passes, ECDH fails.
    let mut other = bk.clone();
    other.pcrs = vec![0];
    for _ in 0..5 {
        let err = h.f.dev.bound_ecdh(&other.key, &other.pcrs, &peer).unwrap_err();
        assert!(err.to_string().starts_with("tpmdev: TPM refused the bound ECDH: "), "{err}");
        assert!(err.response_code().is_some(), "{err}");
    }
    assert!(h.att.bound_ecdh(&bk, &peer).is_ok(), "policy sessions leaked");
    // Certification of the bound key verifies under another session only if asked.
    let (attest, sig) = h.att.certify(&bk.key, b"other qualifying data").unwrap();
    let ak = db_tpmattest::parse_attestation_key(h.att.ak_public()).unwrap();
    let cert = db_tpmattest::verify_certify(&ak, &attest, &sig, b"other qualifying data").unwrap();
    assert_eq!(cert.object_name, bk.key.name);
    assert!(db_tpmattest::verify_certify(&ak, &attest, &sig, b"other").is_err());
    h.att.flush_bound(&bk);
    assert!(h.att.bound_ecdh(&bk, &peer).is_err(), "flushed key still usable");
}

/// A P-256 ECDH key with chosen attributes and policy, certified by the AK
/// (Go `boundKeyWith`), to exercise the verifier's checks.
fn bound_key_with(h: &Harness, user_with_auth: bool, policy: &[u8], certify_session: &str, pcrs: Vec<i64>) -> db_tpmattest::BoundKey {
    let mut tmpl = bound_key_template(policy, &[], &[]);
    if let PublicParams::Ecc(p) = &mut tmpl.params {
        p.scheme = AsymScheme::NULL;
    }
    if user_with_auth {
        tmpl.attributes |= OBJ_USER_WITH_AUTH;
    }
    let key = h.f.dev.create_primary(RH_ENDORSEMENT, &tmpl).unwrap();
    // Only the public area and the certification are needed afterwards.
    let certified = h.att.certify(&key, &bound_key_certify_data(&h.att.provider_id(), certify_session));
    h.f.dev.flush(&key);
    let (certify_attest, certify_sig) = certified.unwrap();
    db_tpmattest::BoundKey { public: key.public_raw, pcrs, certify_attest, certify_sig }
}

#[test]
fn bound_key_verification() {
    let Some(mut h) = Harness::new() else { return };
    h.activate();
    let live = h.f.dev.read_pcrs(&DEFAULT_PCRS).unwrap();
    let good = policy_pcr_digest(&DEFAULT_PCRS, &live).unwrap();
    let mut fake = live.clone();
    fake.get_mut(&9).unwrap()[0] ^= 1;
    let other = policy_pcr_digest(&DEFAULT_PCRS, &fake).unwrap();
    let mut with16 = default_pcrs();
    with16.push(16);
    // Same length as the quoted set, but not the same set.
    let mut repeated = default_pcrs();
    *repeated.last_mut().unwrap() = 0;
    let mut swapped = default_pcrs();
    *swapped.last_mut().unwrap() = 16;
    let cases = [
        ("password-usable", bound_key_with(&h, true, &good, "session-1", default_pcrs()), "userWithAuth"),
        ("policy-other-pcrs", bound_key_with(&h, false, &other, "session-1", default_pcrs()), "not PolicyPCR"),
        ("certified-other-sess", bound_key_with(&h, false, &good, "session-9", default_pcrs()), "certification"),
        ("unquoted-pcr", bound_key_with(&h, false, &good, "session-1", with16), "not the attested set"),
        ("repeated-pcr", bound_key_with(&h, false, &good, "session-1", repeated), "repeats PCR 0"),
        ("swapped-pcr", bound_key_with(&h, false, &good, "session-1", swapped), "does not attest"),
    ];
    let mut t = Subtests::default();
    for (name, bk, want) in cases {
        let ev = h.att.attest(&nonce(), &with_bound_key(&h, bk), &default_pcrs()).unwrap();
        let v = h.evaluate(&ev, &expect("session-1", "acct-1", true));
        let first = v.failed().first().map(|c| c.detail.clone()).unwrap_or_default();
        let r = if v.ok || !first.contains(want) { Err(format!("accepted or wrong reason: {:?}", v.failed())) } else { Ok(()) };
        t.run(name, r);
    }
    // Control: a correct key passes.
    let ok = bound_key_with(&h, false, &good, "session-1", default_pcrs());
    let ev = h.att.attest(&nonce(), &with_bound_key(&h, ok), &default_pcrs()).unwrap();
    let v = h.evaluate(&ev, &expect("session-1", "acct-1", true));
    t.run("control", if v.ok { Ok(()) } else { Err(format!("correct bound key rejected: {:?}", v.failed())) });
    t.finish();
}

/// Port of Go's TestBoundKeyMustCoverAttestedPCRs: a key whose policy covers
/// a subset of the quoted PCRs (PCR 0 alone, which another OS on the same
/// firmware also satisfies) is refused, although the TPM certified it and its
/// policy matches the live PCR 0.
#[test]
fn bound_key_must_cover_attested_pcrs() {
    let Some(mut h) = Harness::new() else { return };
    h.activate();
    let live = h.f.dev.read_pcrs(&[0]).unwrap();
    let pcr0_only = policy_pcr_digest(&[0], &live).unwrap();
    let bk = bound_key_with(&h, false, &pcr0_only, "session-1", vec![0]);
    let ev = h.att.attest(&nonce(), &with_bound_key(&h, bk), &default_pcrs()).unwrap();
    let v = h.evaluate(&ev, &expect("session-1", "acct-1", true));
    let first = v.failed().first().map(|c| c.detail.clone()).unwrap_or_default();
    assert!(
        !v.ok && first.contains("bound key policy covers PCRs [0], not the attested set"),
        "under-scoped bound key accepted or wrong reason: {:?}",
        v.failed()
    );
}
