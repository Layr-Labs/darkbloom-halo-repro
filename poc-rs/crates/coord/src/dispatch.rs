//! Authorization for the final provider-writer handoff of a sealed job.

use crate::{Provider, Server, State};
use db_gojson::GoTime;
use db_tpmattest::Tier;

/// Facts the caller sealed a job against. The writer checks them again when
/// it enqueues the frame into the WebSocket sink, after any queue delay.
pub(crate) struct DispatchGuard {
    pub(crate) conn_id: u64,
    pub(crate) provider_id: String,
    pub(crate) session_id: String,
    pub(crate) job_id: String,
    pub(crate) kind: String,
    pub(crate) job_kem: String,
    pub(crate) job_public_key: Vec<u8>,
    pub(crate) bound_key: Option<Vec<u8>>,
}

impl DispatchGuard {
    pub(crate) fn new(p: &Provider, job_id: &str, kind: &str, job_kem: &str, job_public_key: &[u8], bound_key: Option<Vec<u8>>) -> Self {
        Self {
            conn_id: p.conn_id,
            provider_id: p.id.clone(),
            session_id: p.session_id.clone(),
            job_id: job_id.to_owned(),
            kind: kind.to_owned(),
            job_kem: job_kem.to_owned(),
            job_public_key: job_public_key.to_vec(),
            bound_key,
        }
    }
}

/// Text requests always require the production attested tier, even when a
/// coordinator also has development roots or releases configured.
pub(crate) fn tier_allows(s: &Server, kind: &str, tier: &Tier) -> bool {
    tier.rank() >= s.min_tier.rank() && (kind != "text" || tier.rank() >= Tier::Attested.rank())
}

/// Called with the server state lock held immediately before Sink::start_send.
/// No await may occur between this check and start_send.
pub(crate) fn authorized(s: &Server, st: &State, g: &DispatchGuard, now: &GoTime) -> bool {
    if st.providers.get(&g.provider_id) != Some(&g.conn_id) {
        return false;
    }
    let Some((p, ps)) = st.conns.get(&g.conn_id) else { return false };
    if p.id != g.provider_id || p.session_id != g.session_id || p.cancel.is_cancelled() || !Server::leased(ps, now) {
        return false;
    }
    let (Some(verdict), Some(stmt)) = (&ps.verdict, &ps.stmt) else { return false };
    if !tier_allows(s, &g.kind, &verdict.tier)
        || (g.kind == "text" && g.bound_key.is_none())
        || verdict.bound_key.as_ref().map(|key| key.to_sec1_bytes().to_vec()) != g.bound_key
        || stmt.session_id != g.session_id
        || stmt.job_kem != g.job_kem
        || stmt.job_public_key != g.job_public_key
    {
        return false;
    }
    let Some(j) = st.jobs.get(&g.job_id) else { return false };
    j.state == "queued" && j.provider_id == g.provider_id && j.session_id == g.session_id && j.parsed.kind == g.kind
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{Config, Job, ProviderState};
    use db_log::Logger;
    use db_release::{Log, TrustedKeys};
    use db_tpmattest::{Statement, Verdict, Verifier};
    use db_wire as wire;
    use ed25519_dalek::SigningKey;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    async fn setup(kind: &str, tier: Tier) -> (Arc<Server>, DispatchGuard) {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let bound_key = p256::SecretKey::from_slice(&[1u8; 32]).unwrap().public_key();
        let log = Arc::new(Log::new(key.clone()));
        let s = Server::new(Config {
            verifier: Verifier::default(),
            enrollment_key: key.clone(),
            release_log: log,
            release_log_key: key.verifying_key(),
            release_keys: TrustedKeys::default(),
            provider_tokens: BTreeMap::new(),
            consumer_keys: BTreeSet::new(),
            challenge_interval: Duration::from_secs(30),
            lease_ttl: Duration::from_secs(90),
            min_tier: Some(Tier::DevSimulated),
            max_result_bytes: 0,
            capture_attestation: None,
            logger: Logger::discard(),
        })
        .unwrap();
        let (tx, _rx) = mpsc::channel(2);
        let p = Arc::new(Provider {
            conn_id: 1,
            id: "provider".to_owned(),
            session_id: "session".to_owned(),
            account_id: "account".to_owned(),
            hello: wire::Hello::default(),
            device_id: String::new(),
            root_name: String::new(),
            activated: true,
            enrollment: wire::SignedBlob::default(),
            tx,
            cancel: CancellationToken::new(),
        });
        let ps = ProviderState {
            verdict: Some(Arc::new(Verdict { ok: true, tier, bound_key: Some(bound_key), ..Verdict::default() })),
            stmt: Some(Statement {
                session_id: p.session_id.clone(),
                job_kem: "kem".to_owned(),
                job_public_key: vec![1, 2, 3],
                ..Statement::default()
            }),
            lease_until: GoTime::now_utc().add(chrono::Duration::minutes(1)),
            ..ProviderState::default()
        };
        let guard = DispatchGuard::new(&p, "job", kind, "kem", &[1, 2, 3], Some(bound_key.to_sec1_bytes().to_vec()));
        {
            let mut st = s.lock();
            st.providers.insert(p.id.clone(), p.conn_id);
            st.conns.insert(p.conn_id, (p, ps));
            st.jobs.insert(
                "job".to_owned(),
                Job {
                    id: "job".to_owned(),
                    provider_id: "provider".to_owned(),
                    session_id: "session".to_owned(),
                    owner: "consumer".to_owned(),
                    meta: Vec::new(),
                    parsed: wire::JobMeta { kind: kind.to_owned(), ..wire::JobMeta::default() },
                    request_digest: String::new(),
                    state: "queued",
                    step: 0,
                    total: 0,
                    chunks: Some(Vec::new()),
                    size: 0,
                    receipt: Vec::new(),
                    receipt_sig: Vec::new(),
                    err: String::new(),
                    created: GoTime::now_utc(),
                    created_at: std::time::Instant::now(),
                    done: tokio::sync::watch::Sender::new(false),
                },
            );
        }
        (s, guard)
    }

    #[tokio::test]
    async fn final_handoff_rechecks_lease_session_key_and_job() {
        let (s, g) = setup("text", Tier::Attested).await;
        let now = GoTime::now_utc();
        assert!(authorized(&s, &s.lock(), &g, &now));
        s.lock().conns.get_mut(&1).unwrap().1.lease_until = GoTime::zero();
        assert!(!authorized(&s, &s.lock(), &g, &now));
        s.lock().conns.get_mut(&1).unwrap().1.lease_until = GoTime::now_utc().add(chrono::Duration::minutes(1));
        s.lock().conns.get_mut(&1).unwrap().1.stmt.as_mut().unwrap().job_public_key = vec![9];
        assert!(!authorized(&s, &s.lock(), &g, &now));
        s.lock().conns.get_mut(&1).unwrap().1.stmt.as_mut().unwrap().job_public_key = vec![1, 2, 3];
        s.lock().conns.get_mut(&1).unwrap().1.verdict = Some(Arc::new(Verdict { ok: true, tier: Tier::Attested, ..Verdict::default() }));
        assert!(!authorized(&s, &s.lock(), &g, &now));
        let replacement_key = p256::SecretKey::from_slice(&[2u8; 32]).unwrap().public_key();
        s.lock().conns.get_mut(&1).unwrap().1.verdict =
            Some(Arc::new(Verdict { ok: true, tier: Tier::Attested, bound_key: Some(replacement_key), ..Verdict::default() }));
        assert!(!authorized(&s, &s.lock(), &g, &now));
        let bound_key = p256::SecretKey::from_slice(&[1u8; 32]).unwrap().public_key();
        s.lock().conns.get_mut(&1).unwrap().1.verdict =
            Some(Arc::new(Verdict { ok: true, tier: Tier::Attested, bound_key: Some(bound_key), ..Verdict::default() }));
        s.lock().jobs.get_mut("job").unwrap().state = "error";
        assert!(!authorized(&s, &s.lock(), &g, &now));
        s.lock().jobs.get_mut("job").unwrap().state = "queued";
        s.lock().providers.insert("provider".to_owned(), 2);
        assert!(!authorized(&s, &s.lock(), &g, &now));
    }

    #[tokio::test]
    async fn private_text_never_uses_development_tier() {
        let (s, g) = setup("text", Tier::DevSimulated).await;
        assert!(!authorized(&s, &s.lock(), &g, &GoTime::now_utc()));
        assert!(!tier_allows(&s, "text", &Tier::HardwareDevOs));
        assert!(tier_allows(&s, "image", &Tier::DevSimulated));
    }
}
