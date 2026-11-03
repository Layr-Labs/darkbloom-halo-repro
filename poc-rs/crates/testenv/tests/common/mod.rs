//! The harness of the Go `e2e` attestation tests: a fixture, an attester,
//! a verifier configured like the coordinator, and helpers.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use db_gojson::GoTime;
use db_release::{Policy, open_manifest};
use db_sealbox::{KEM_XWING, KeyPair};
use db_testenv::{Fixture, TEST_CMDLINE};
use db_tpmattest::{
    DEFAULT_PCRS, Evidence, Expect, GpuStatus, RuntimeReport, STATEMENT_DOMAIN, Statement, Status, TrustedRelease, Verdict, Verifier,
    make_credential, parse_attestation_key, parse_ek_public,
};
use db_tpmdev::Attester;
use std::sync::Arc;

pub struct Harness {
    pub att: Attester,
    pub vf: Verifier,
    pub job: KeyPair,
    pub receipt: ed25519_dalek::VerifyingKey,
    pub stmt: Vec<u8>,
    pub activated: bool,
    // Last: the TPM outlives the attester's keys.
    pub f: Fixture,
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).unwrap();
    b
}

pub fn nonce() -> Vec<u8> {
    random::<32>().to_vec()
}

pub fn default_pcrs() -> Vec<i64> {
    DEFAULT_PCRS.iter().map(|&p| i64::from(p)).collect()
}

pub fn expect(session: &str, account: &str, activated: bool) -> Expect {
    Expect { session_id: session.to_owned(), account_id: account.to_owned(), pcrs: Vec::new(), ak_activated: activated }
}

impl Harness {
    /// `None` when swtpm is not installed.
    pub fn new() -> Option<Harness> {
        let f = Fixture::new(TEST_CMDLINE)?;
        let att = Attester::new(f.dev.clone(), Some(f.event_log.clone())).expect("attester");
        Some(Self::with(f, att))
    }

    pub fn with(f: Fixture, att: Attester) -> Harness {
        let keys = f.trusted_keys();
        let m = open_manifest(&f.envelope, &keys, 1).expect("open manifest");
        let vf = Verifier {
            bundle: f.dev_bundle(),
            releases: vec![TrustedRelease { manifest: Arc::new(m), envelope: Vec::new(), logged: true }],
            release_policy: Some(Policy { keys, min_svn: 1, allow_dev: true, require_logged: true, ..Policy::default() }),
            allow_dev_roots: true,
            ..Verifier::default()
        };
        let job = KeyPair::generate(KEM_XWING).expect("job key");
        let receipt = ed25519_dalek::SigningKey::from_bytes(&random::<32>()).verifying_key();
        let mut h = Harness { att, vf, job, receipt, stmt: Vec::new(), activated: false, f };
        h.stmt = h.statement("session-1", "acct-1");
        h
    }

    pub fn statement(&self, session: &str, account: &str) -> Vec<u8> {
        let st = Statement {
            version: 1,
            domain: STATEMENT_DOMAIN.to_owned(),
            provider_id: self.att.provider_id(),
            account_id: account.to_owned(),
            session_id: session.to_owned(),
            job_kem: self.job.kem_name().to_owned(),
            job_public_key: self.job.public().to_vec(),
            receipt_public_key: self.receipt.as_bytes().to_vec(),
            tpm_mode: self.att.mode().to_owned(),
            status: Status {
                lockdown: "confidentiality".to_owned(),
                dash_enabled: Some(false),
                gpu: GpuStatus { enforce_isolation: Some(1), owner: "node".to_owned(), ..GpuStatus::default() },
                ..Status::default()
            },
            runtime: RuntimeReport { engine: "fake-engine".to_owned(), ..RuntimeReport::default() },
            created_at: GoTime::now_utc(),
            ..Statement::default()
        };
        db_gojson::to_vec(&st).unwrap()
    }

    /// Credential activation the way the coordinator runs it.
    pub fn activate(&mut self) {
        let ek = parse_ek_public(self.att.ek_public()).unwrap();
        let ak = parse_attestation_key(self.att.ak_public()).unwrap();
        let ch = make_credential(&ek, &ak.name).unwrap();
        let got = self.att.activate(&ch.id_object, &ch.enc_secret).unwrap();
        self.activated = got.as_slice() == ch.secret.as_slice();
        assert!(self.activated, "credential activation returned the wrong secret");
    }

    pub fn attest(&self, stmt: &[u8]) -> Evidence {
        self.att.attest(&nonce(), stmt, &default_pcrs()).expect("attest")
    }

    pub fn evaluate(&self, ev: &Evidence, ex: &Expect) -> Verdict {
        let mut ex = ex.clone();
        if ex.pcrs.is_empty() {
            ex.pcrs = DEFAULT_PCRS.to_vec();
        }
        let v = self.vf.evaluate(ev, &ex);
        for c in &v.checks {
            println!("  {:<28} ok={:<5} {:<8} {}", c.name, c.ok, c.effect, c.detail);
        }
        v
    }

    /// Ok if the evidence is rejected with a failed `want` check.
    pub fn reject(&self, ev: &Evidence, ex: &Expect, want: &str) -> Result<(), String> {
        let v = self.evaluate(ev, ex);
        if v.ok {
            return Err("accepted".to_owned());
        }
        if !v.failed().iter().any(|c| c.name == want) {
            return Err(format!("rejected, but not by {want:?}: {:?}", v.failed()));
        }
        Ok(())
    }
}

/// Runs named subtests and fails at the end with every failure (Go's t.Run).
#[derive(Default)]
pub struct Subtests(Vec<String>);

impl Subtests {
    pub fn run(&mut self, name: &str, r: Result<(), String>) {
        match r {
            Ok(()) => println!("--- PASS: {name}"),
            Err(e) => {
                println!("--- FAIL: {name}: {e}");
                self.0.push(format!("{name}: {e}"));
            }
        }
    }

    pub fn finish(self) {
        assert!(self.0.is_empty(), "failed subtests:\n{}", self.0.join("\n"));
    }
}
