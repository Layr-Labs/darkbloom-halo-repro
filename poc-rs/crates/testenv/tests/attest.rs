//! Port of the Go `e2e/attest_test.go`: end-to-end attestation against
//! swtpm, adversarial edits, reboot detection and trust tiers.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

mod common;

use common::{Harness, Subtests, default_pcrs, expect, nonce};
use db_testenv::{Swtpm, TEST_CMDLINE, manifest_for};
use db_tpmattest::{
    ALG_SHA256, Evidence, Expect, RootKind, Statement, Status, Tier, TrustBundle, TrustedRelease, load_certificates, parse_event_log,
    pinned_root,
};
use db_tpmdev::Attester;
use std::sync::Arc;

fn policy(h: &mut Harness) -> &mut db_release::Policy {
    h.vf.release_policy.as_mut().unwrap()
}

fn last_index(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).rposition(|w| w == needle)
}

fn not_ok(h: &Harness, ev: &Evidence, ex: &Expect, what: &str) -> Result<(), String> {
    if h.evaluate(ev, ex).ok { Err(format!("{what} accepted")) } else { Ok(()) }
}

#[test]
fn attestation_end_to_end() {
    let Some(mut h) = Harness::new() else { return };
    h.activate();
    let ev = h.att.attest(&nonce(), &h.stmt, &default_pcrs()).unwrap();
    let ex = expect("session-1", "acct-1", h.activated);
    let v = h.evaluate(&ev, &ex);
    assert!(v.ok && v.tier == Tier::DevSimulated, "genuine evidence rejected: tier={} failed={:?}", v.tier, v.failed());

    let mut t = Subtests::default();
    // Freshness: a quote over another nonce.
    let mut e = ev.clone();
    e.nonce = nonce();
    t.run("wrong-nonce", h.reject(&e, &ex, "quote"));

    // Binding: swapping in another job key breaks the quote.
    let mut e = ev.clone();
    let other = db_sealbox::KeyPair::generate(db_sealbox::KEM_XWING).unwrap();
    let mut st: Statement = db_gojson::from_slice(&h.stmt).unwrap();
    st.job_public_key = other.public().to_vec();
    e.statement = db_gojson::to_vec(&st).unwrap();
    t.run("swapped-job-key", h.reject(&e, &ex, "quote"));

    // Event log edited: one byte of the PCR 9 initrd event's SHA-256 digest
    // (other banks are not replayed, so not relied upon).
    let mut e = ev.clone();
    let parsed = parse_event_log(&ev.event_log).unwrap();
    let initrd = parsed.events_for(9).last().unwrap().digests[&ALG_SHA256].clone();
    let at = last_index(&e.event_log, &initrd).unwrap();
    e.event_log[at] ^= 0xff;
    t.run("edited-event-log-digest", h.reject(&e, &ex, "event-log"));

    // Editing only an event's description leaves the PCRs intact; policy
    // never trusts descriptions it has not re-hashed, and reports them.
    let mut e = ev.clone();
    let n = e.event_log.len();
    e.event_log[n - 40] ^= 0xff;
    let v = h.evaluate(&e, &ex);
    let r = if !v.ok {
        Err(format!("description-only edit changed the verdict: {:?}", v.failed()))
    } else if v.checks.iter().any(|c| c.name == "event-descriptions" && c.ok) {
        Err("description-only edit was not reported".to_owned())
    } else {
        Ok(())
    };
    t.run("edited-event-description", r);

    // One byte of the quote changed.
    let mut e = ev.clone();
    *e.quote_attest.last_mut().unwrap() ^= 1;
    t.run("edited-quote", h.reject(&e, &ex, "quote"));

    // Session and account binding (relay / cuckoo attacks).
    t.run("other-session", h.reject(&ev, &expect("session-2", "acct-1", true), "statement"));
    t.run("other-account", h.reject(&ev, &expect("session-1", "acct-2", true), "statement"));
    // AK not bound to the EK (no credential activation).
    t.run("ak-not-activated", h.reject(&ev, &expect("session-1", "acct-1", false), "ak-bound-to-ek"));
    // Different PCR selection than requested.
    let ex047 = Expect { pcrs: vec![0, 4, 7], ..expect("session-1", "acct-1", true) };
    t.run("pcr-selection", h.reject(&ev, &ex047, "quote"));

    // Foreign EK chain: the dev root is not trusted.
    let saved = h.vf.bundle.clone();
    let other_dir = tempfile::tempdir().unwrap();
    db_devca::create_dev_ca(other_dir.path()).unwrap();
    let certs = load_certificates(&[other_dir.path().join("dev-root.pem")]).unwrap();
    h.vf.bundle = TrustBundle { roots: vec![pinned_root("other", RootKind::DevSimulated, certs, Vec::new(), false)] };
    let v = h.evaluate(&ev, &ex);
    let first = v.failed().first().map(|c| c.name.clone()).unwrap_or_default();
    let r = if v.ok || first != "ek-chain" {
        Err(format!("foreign EK chain accepted or rejected for the wrong reason: {:?}", v.failed()))
    } else {
        Ok(())
    };
    t.run("foreign-ek-root", r);
    h.vf.bundle = saved;

    // Development roots are refused unless explicitly allowed.
    h.vf.allow_dev_roots = false;
    t.run("dev-root-refused", not_ok(&h, &ev, &ex, "dev root with allow_dev_roots=false"));
    h.vf.allow_dev_roots = true;

    // Release policy: SVN floor, revocation, unlogged, dev channel, cmdline.
    policy(&mut h).min_svn = 4;
    let v = h.evaluate(&ev, &ex);
    let floor = v.failed().first().is_some_and(|c| c.detail.contains("floor"));
    t.run("release-floor", if v.ok || !floor { Err(format!("release below floor accepted: {:?}", v.failed())) } else { Ok(()) });
    policy(&mut h).min_svn = 1;

    let id = h.f.manifest.id();
    policy(&mut h).revoked.insert(id);
    t.run("release-revoked", not_ok(&h, &ev, &ex, "revoked release"));
    policy(&mut h).revoked.clear();

    h.vf.releases[0].logged = false;
    t.run("release-unlogged", not_ok(&h, &ev, &ex, "unlogged release"));
    h.vf.releases[0].logged = true;

    policy(&mut h).allow_dev = false;
    t.run("release-dev-channel-in-production", not_ok(&h, &ev, &ex, "dev release under a production policy"));
    policy(&mut h).allow_dev = true;

    let saved = h.vf.releases.clone();
    let mut arts = h.f.artifacts.clone();
    arts.cmdline = TEST_CMDLINE.replacen("debugfs=off", "debugfs=on", 1);
    let m = manifest_for(&arts, "dev", 3);
    h.vf.releases = vec![TrustedRelease { manifest: Arc::new(m), envelope: Vec::new(), logged: true }];
    t.run("release-other-cmdline", not_ok(&h, &ev, &ex, "evidence matching a release with another command line"));
    h.vf.releases = saved;

    // Sanity: everything restored.
    assert!(h.evaluate(&ev, &ex).ok, "restored verifier rejects the genuine evidence");
    t.finish();
}

/// Restarts swtpm (same chip state = a reboot) and checks that the TPM's
/// resetCount exposes it.
#[test]
fn reboot_detection() {
    let Some(mut h) = Harness::new() else { return };
    h.activate();
    let ex = expect("session-1", "acct-1", true);
    let ev1 = h.attest(&h.stmt);
    let v1 = h.evaluate(&ev1, &ex);
    assert!(v1.ok, "{:?}", v1.failed());
    h.att.close();
    h.f.dev.close();
    h.f.tpm.stop();
    let sw = Swtpm::start(h.f.tpm.dir()).unwrap();
    let dev = sw.open_device().unwrap();
    // After the "reboot" the PCRs are fresh; an attacker who boots something
    // else cannot reproduce them, and even replaying the same boot shows a
    // new resetCount.
    let log = dev.simulate_boot(|banks| Ok(h.f.plan(banks))).unwrap();
    let att = Attester::new(dev.clone(), Some(log)).unwrap();
    assert_eq!(att.provider_id(), h.att.provider_id(), "same chip, same EK");
    assert_eq!(att.ak_public(), h.att.ak_public(), "same template, same AK");
    let ev2 = att.attest(&nonce(), &h.stmt, &default_pcrs()).unwrap();
    let v2 = h.evaluate(&ev2, &ex);
    assert!(v2.ok, "{:?}", v2.failed());
    assert_ne!(v2.reset_count, v1.reset_count, "resetCount did not change across a reboot");
    println!("resetCount {} -> {}: the coordinator ends the lease and requires re-registration", v1.reset_count, v2.reset_count);
    // The old attester's keys are gone with the old TPM session.
    assert!(h.att.attest(&nonce(), &h.stmt, &default_pcrs()).is_err());
    drop(att);
    drop(dev);
    drop(sw);
}

/// Treats the dev root as if it were AMD's (production) to check how the
/// release channel and the status decide the tier on genuine hardware.
#[test]
fn tiers() {
    let Some(mut h) = Harness::new() else { return };
    h.activate();
    h.vf.bundle.roots[0].production = true;
    let ex = expect("session-1", "acct-1", true);

    // Dev-channel release on genuine hardware: never private.
    let v = h.evaluate(&h.attest(&h.stmt), &ex);
    assert!(v.ok && v.tier == Tier::HardwareDevOs, "dev release on hardware: ok={} tier={}", v.ok, v.tier);

    // Production release: requirements become fatal.
    let prod = manifest_for(&h.f.artifacts, "production", 3);
    h.vf.releases = vec![TrustedRelease { manifest: Arc::new(prod), envelope: Vec::new(), logged: true }];
    // Production requires the TPM-bound job key.
    let bk = h.att.new_bound_key("session-1").unwrap();
    let status_stmt = |h: &Harness, mutate: &dyn Fn(&mut Status)| -> Vec<u8> {
        let mut st: Statement = db_gojson::from_slice(&h.stmt).unwrap();
        st.tpm_mode = "hardware".to_owned();
        st.bound_key = Some(bk.public.clone());
        mutate(&mut st.status);
        db_gojson::to_vec(&st).unwrap()
    };
    let good = status_stmt(&h, &|_| {});
    let v = h.evaluate(&h.attest(&good), &ex);
    assert!(v.ok && v.tier == Tier::Attested, "production release: ok={} tier={} {:?}", v.ok, v.tier, v.failed());
    let tsme = status_stmt(&h, &|s| s.tsme_active = Some(true));
    let v = h.evaluate(&h.attest(&tsme), &ex);
    assert!(v.ok && v.tier == Tier::AttestedEncryptedMemory, "TSME: ok={} tier={}", v.ok, v.tier);

    let mut t = Subtests::default();
    // A production release whose measured command line pins no root hash.
    let saved = h.vf.releases.clone();
    let mut no_verity = manifest_for(&h.f.artifacts, "production", 3);
    no_verity.boot.load_options = no_verity.boot.load_options.replacen(" roothash=", " x-roothash=", 1);
    h.vf.releases = vec![TrustedRelease { manifest: Arc::new(no_verity), envelope: Vec::new(), logged: true }];
    t.run("production-without-verity-root", not_ok(&h, &h.attest(&good), &ex, "production release without a dm-verity root hash"));
    h.vf.releases = saved;

    type Mutation<'a> = (&'a str, &'a dyn Fn(&mut Status));
    let cases: [Mutation<'_>; 6] = [
        ("swap", &|s| s.swap_active = true),
        ("debugfs", &|s| s.debugfs_mounted = true),
        ("lockdown", &|s| s.lockdown = "integrity".to_owned()),
        ("isolation", &|s| s.gpu.enforce_isolation = Some(0)),
        ("dash", &|s| s.dash_enabled = Some(true)),
        ("gpu-lent", &|s| s.gpu.owner = "lent".to_owned()),
    ];
    for (name, mutate) in cases {
        let ev = h.attest(&status_stmt(&h, mutate));
        t.run(name, not_ok(&h, &ev, &ex, &format!("production release with {name} violated")));
    }
    // Without the bound key a production release is refused.
    let mut st: Statement = db_gojson::from_slice(&good).unwrap();
    st.bound_key = None;
    let unbound = db_gojson::to_vec(&st).unwrap();
    t.run("production-without-bound-key", not_ok(&h, &h.attest(&unbound), &ex, "production release without a TPM-bound job key"));
    h.att.flush_bound(&bk);
    t.finish();
}
