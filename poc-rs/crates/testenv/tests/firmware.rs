//! Port of the Go `e2e/firmware_test.go`: firmware state from measured
//! events, the job KEM policy and the AK hierarchy.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

mod common;

use common::{Harness, default_pcrs, expect, nonce};
use db_simboot::halo_plan;
use db_testenv::{Fixture, TEST_CMDLINE, test_artifacts};
use db_tpm2::ak_template;
use db_tpm2::consts::RH_OWNER;
use db_tpmattest::eventlog::EV_EFI_VARIABLE_DRIVER_CONFIG;
use db_tpmattest::{
    DEFAULT_PCRS, EFI_GLOBAL_VARIABLE_GUID, LogEvent, build_event_log, digests_of, hash_for, quote_extra_data, uefi_variable_data,
};
use db_tpmdev::Attester;

/// Boot with Secure Boot off, then (as software with TPM access would)
/// extend PCR 7 with a "SecureBoot=1" event and append it to the log. The
/// quote and replay are genuine, PCR 4/9/12 still match the release, but
/// firmware state is only read from before the PCR 7 separator, so the
/// appended event is refused.
#[test]
fn secure_boot_off_cannot_be_relabelled() {
    let Some(f) = Fixture::new_with(TEST_CMDLINE, |a| a.secure_boot = false) else { return };
    let banks: Vec<u16> = f.dev.active_banks().unwrap().into_iter().filter(|&b| hash_for(b).is_some()).collect();
    let mut arts = test_artifacts(&banks, TEST_CMDLINE);
    arts.secure_boot = false;
    let mut events = halo_plan(&banks, &arts);
    let data = uefi_variable_data(&EFI_GLOBAL_VARIABLE_GUID, "SecureBoot", &[1]);
    let fake = LogEvent { pcr: 7, event_type: EV_EFI_VARIABLE_DRIVER_CONFIG, digests: digests_of(&banks, &data), data };
    f.dev.pcr_extend(7, &fake.digests).unwrap();
    events.push(fake);
    let log = build_event_log(&banks, &events).unwrap();
    let att = Attester::new(f.dev.clone(), Some(log)).unwrap();
    let h = Harness::with(f, att);
    let ev = h.att.attest(&nonce(), &h.stmt, &default_pcrs()).unwrap();
    let v = h.evaluate(&ev, &expect("session-1", "acct-1", true));
    assert!(!v.ok, "Secure Boot off was relabelled as on by an appended event");
    let first = v.failed().first().map(|c| c.detail.clone()).unwrap_or_default();
    assert!(first.contains("after the PCR 7 separator"), "rejected for the wrong reason: {:?}", v.failed());
}

/// Providers must offer the post-quantum hybrid KEM unless the verifier
/// explicitly allows X25519.
#[test]
fn kem_policy() {
    let Some(mut h) = Harness::new() else { return };
    h.activate();
    h.job = db_sealbox::KeyPair::generate(db_sealbox::KEM_X25519).unwrap();
    h.stmt = h.statement("session-1", "acct-1");
    let ev = h.attest(&h.stmt);
    let ex = expect("session-1", "acct-1", true);
    assert!(!h.evaluate(&ev, &ex).ok, "X25519-only job key accepted by default");
    h.vf.allowed_kems = vec![db_sealbox::KEM_XWING.to_owned(), db_sealbox::KEM_X25519.to_owned()];
    let v = h.evaluate(&ev, &ex);
    assert!(v.ok, "explicitly allowed KEM rejected: {:?}", v.failed());
}

/// An AK under the owner hierarchy would get obfuscated reset/restart
/// counters (reboots hidden); its quotes are refused even though credential
/// activation with the EK would succeed.
#[test]
fn owner_hierarchy_ak_rejected() {
    let Some(h) = Harness::new() else { return };
    let dev = h.f.dev.clone();
    let ak = dev.create_primary(RH_OWNER, &ak_template()).unwrap();
    let n = nonce();
    let quoted = dev.quote(&ak, &quote_extra_data(&n, &h.stmt), &DEFAULT_PCRS);
    dev.flush(&ak);
    let (attest, sig) = quoted.unwrap();
    let mut ev = h.attest(&h.stmt);
    ev.ak_public = ak.public_raw.clone();
    ev.nonce = n;
    ev.quote_attest = attest;
    ev.quote_sig = sig;
    let v = h.evaluate(&ev, &expect("session-1", "acct-1", true));
    let first = v.failed().first().map(|c| c.detail.clone()).unwrap_or_default();
    assert!(
        !v.ok && first.contains("endorsement-hierarchy"),
        "owner-hierarchy AK accepted or rejected for another reason: {:?}",
        v.failed()
    );
}
