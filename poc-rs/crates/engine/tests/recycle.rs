//! Engine recycling (a fresh ComfyUI process per job) against the mock
//! ComfyUI and a fake `run-engine.sh` supervisor: a restart is requested
//! after every job that reached the engine (finished, failed, rejected,
//! cancelled or abandoned), the result returns before the restart, the next
//! job waits for the new generation and a live engine, an unconfirmed
//! restart fails jobs with `engine_unavailable`, and the warm-up runs once
//! per restart and is purged.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

mod mock;
mod support;

use db_engine::{Comfy, ComfyConfig, EngineError, Output};
use mock::Mode;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use support::{Env, Supervisor, Z_FILES, env, generate, image_request, pos};
use tokio_util::sync::CancellationToken;

const TIMEOUT: Duration = Duration::from_secs(10);

async fn job(c: &Comfy, prompt: &str) -> Result<Output, EngineError> {
    generate(c, &image_request(prompt), CancellationToken::new()).await.0
}

/// A recycling adapter whose startup restart has completed (warm-up off).
async fn recycling(e: &Env, sup: &Supervisor, restart_timeout: Duration) -> Comfy {
    let c = Comfy::new(e.recycling_config(sup, false, restart_timeout)).await.unwrap();
    e.eventually("the startup restart", |e| e.server.events().contains(&"engine-up 2".to_owned())).await;
    c
}

/// Every consumer prompt reached a ComfyUI that came up after the previous
/// consumer prompt (warm-up prompts excepted).
fn assert_fresh_engine_per_job(events: &[String], warmups: &BTreeSet<String>) {
    let mut fresh = false;
    for ev in events {
        if ev.starts_with("engine-up ") {
            fresh = true;
        } else if let Some(id) = ev.strip_prefix("prompt ")
            && !warmups.contains(id)
        {
            assert!(fresh, "prompt {id} ran in an engine that served an earlier job: {events:?}");
            fresh = false;
        }
    }
}

fn positions(events: &[String], e: &str) -> Vec<usize> {
    events.iter().enumerate().filter(|(_, x)| *x == e).map(|(i, _)| i).collect()
}

#[tokio::test]
async fn restart_after_every_job_that_reached_the_engine() {
    let e = env(Mode::Complete, &Z_FILES).await;
    let sup = e.supervisor(Duration::from_millis(100));
    let c = recycling(&e, &sup, TIMEOUT).await;
    // The engine may hold a job from before the agent started: one restart
    // at startup.
    assert_eq!(sup.restarts(), 1);

    job(&c, "finished").await.unwrap();
    e.eventually("a restart after a finished job", |_| sup.restarts() == 2).await;
    assert!(e.job_files().is_empty());

    e.server.with(|m| m.mode = Mode::ExecError);
    assert!(job(&c, "failed").await.is_err());
    e.eventually("a restart after a failed job", |_| sup.restarts() == 3).await;

    // ComfyUI parsed (and refused) the prompt: it was in engine memory.
    e.server.with(|m| m.mode = Mode::Reject);
    assert!(job(&c, "rejected").await.is_err());
    e.eventually("a restart after a rejected prompt", |_| sup.restarts() == 4).await;

    e.server.with(|m| m.mode = Mode::Hang);
    let accepted = e.accepted().len();
    let cancel = CancellationToken::new();
    let canceller = async {
        e.eventually("the job to run", |e| e.accepted().len() > accepted).await;
        cancel.cancel();
    };
    let req = image_request("cancelled");
    let ((res, _), ()) = tokio::join!(generate(&c, &req, cancel.clone()), canceller);
    assert!(res.unwrap_err().is_cancelled());
    e.eventually("a restart after a cancelled job", |_| sup.restarts() == 5).await;

    // Abandoned mid-run (the generate future is dropped).
    let accepted = e.accepted().len();
    let req = image_request("abandoned");
    let timed = tokio::time::timeout(Duration::from_millis(1500), generate(&c, &req, CancellationToken::new())).await;
    assert!(timed.is_err(), "job should still be running");
    assert!(e.accepted().len() > accepted);
    e.eventually("a restart after an abandoned job", |_| sup.restarts() == 6).await;

    // Refused before reaching ComfyUI: no restart.
    e.server.with(|m| m.mode = Mode::Complete);
    let mut big = image_request("too big");
    big.width = 4096;
    assert!(generate(&c, &big, CancellationToken::new()).await.0.is_err());
    job(&c, "last").await.unwrap();
    e.eventually("the last restart", |_| sup.restarts() == 7).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(sup.restarts(), 7);
    assert_fresh_engine_per_job(&e.server.events(), &BTreeSet::new());
    assert!(e.job_files().is_empty());
    assert!(!sup.dir.join("restart").exists(), "a restart request was left behind");
}

#[tokio::test]
async fn result_returns_before_the_restart_and_the_next_job_waits() {
    let e = env(Mode::Complete, &Z_FILES).await;
    // ComfyUI takes 1.5 s to come back after each restart.
    let sup = e.supervisor(Duration::from_millis(1500));
    let c = recycling(&e, &sup, TIMEOUT).await;
    let t = Instant::now();
    job(&c, "first").await.unwrap();
    let first = t.elapsed();
    assert!(!e.server.events().contains(&"engine-up 3".to_owned()), "the result waited for the restart");
    assert!(first < Duration::from_millis(1400), "{first:?}");
    assert!(e.job_files().is_empty());
    // The job was purged before the restart was requested.
    e.eventually("the restart request", |_| sup.restarts() == 2).await;
    let ev = e.server.events();
    let first_id = e.accepted()[0].0.clone();
    assert!(pos(&ev, &format!("history-delete {first_id}")) < positions(&ev, "engine-killed")[1], "{ev:?}");

    let t = Instant::now();
    job(&c, "second").await.unwrap();
    let second_id = e.accepted()[1].0.clone();
    let ev = e.server.events();
    assert!(pos(&ev, "engine-up 3") < pos(&ev, &format!("prompt {second_id}")), "{ev:?}");
    assert!(t.elapsed() >= Duration::from_millis(800), "the second job did not wait for the restarted engine");
}

#[tokio::test]
async fn unconfirmed_restart_fails_jobs_with_engine_unavailable() {
    let e = env(Mode::Complete, &Z_FILES).await;
    let sup = e.supervisor(Duration::from_millis(50));
    let c = recycling(&e, &sup, Duration::from_millis(800)).await;
    // The supervisor stops serving requests.
    sup.with(|s| s.stuck = true);
    job(&c, "first").await.unwrap();
    let t = Instant::now();
    let err = job(&c, "SECRET-PROMPT second").await.unwrap_err();
    assert!(err.is_unavailable(), "{err}");
    assert!(!err.to_string().contains("SECRET"), "{err}");
    // Bounded by the restart timeout (from the job's arrival).
    assert!(t.elapsed() < Duration::from_secs(3), "waited {:?}", t.elapsed());
    assert_eq!(e.accepted().len(), 1, "a job reached the engine that served the previous job");
    // Still unavailable while the restart is pending.
    assert!(job(&c, "third").await.unwrap_err().is_unavailable());
    // Once the supervisor serves the request, jobs run again, in the fresh
    // engine.
    sup.with(|s| s.stuck = false);
    job(&c, "fourth").await.unwrap();
    let ev = e.server.events();
    let fourth = e.accepted()[1].0.clone();
    assert!(pos(&ev, "engine-up 3") < pos(&ev, &format!("prompt {fourth}")), "{ev:?}");
    assert_fresh_engine_per_job(&ev, &BTreeSet::new());
}

#[tokio::test]
async fn warmup_runs_once_per_restart_and_is_purged() {
    let e = env(Mode::Complete, &Z_FILES).await;
    let sup = e.supervisor(Duration::from_millis(50));
    let c = Comfy::new(e.recycling_config(&sup, true, TIMEOUT)).await.unwrap();
    let warmups = |e: &Env| -> Vec<(String, Value)> {
        e.server.with(|m| m.accepted.iter().filter(|(_, g)| mock::find_text(g) == "warmup").cloned().collect())
    };
    let purged = |e: &Env, n: usize| {
        let (w, ev) = (warmups(e), e.server.events());
        w.len() == n && w.iter().all(|(id, _)| ev.contains(&format!("history-delete {id}")))
    };
    e.eventually("the startup warm-up", |e| purged(e, 1)).await;
    job(&c, "first").await.unwrap();
    job(&c, "second").await.unwrap();
    e.eventually("a warm-up after each restart", |e| purged(e, 3)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let warm = warmups(&e);
    assert_eq!((sup.restarts(), warm.len()), (3, 3), "one warm-up per restart");

    let ev = e.server.events();
    let ids: BTreeSet<String> = warm.iter().map(|(id, _)| id.clone()).collect();
    assert_fresh_engine_per_job(&ev, &ids);
    for (n, (id, graph)) in warm.iter().enumerate() {
        // Fixed: the constant prompt, the smallest size, one step.
        assert_eq!(graph["13"]["inputs"], json!({"width": 256, "height": 256, "batch_size": 1}));
        assert_eq!(graph["3"]["inputs"]["steps"], json!(1));
        // Run in the freshly restarted engine and purged.
        let up = pos(&ev, &format!("engine-up {}", n + 2));
        let (prompt, deleted) = (pos(&ev, &format!("prompt {id}")), pos(&ev, &format!("history-delete {id}")));
        assert!(up < prompt && prompt < deleted, "{ev:?}");
    }
    // Each consumer job ran after the warm-up of its engine was purged.
    let consumer: Vec<String> = e.accepted().into_iter().filter(|(_, t)| t != "warmup").map(|(id, _)| id).collect();
    assert_eq!(consumer.len(), 2);
    for (i, id) in consumer.iter().enumerate() {
        assert!(pos(&ev, &format!("history-delete {}", warm[i].0)) < pos(&ev, &format!("prompt {id}")), "{ev:?}");
    }
    assert!(e.job_files().is_empty());
    assert_eq!(e.server.retained(), 0);
}

#[tokio::test]
async fn recycling_needs_the_supervisor() {
    let e = env(Mode::Complete, &Z_FILES).await;
    let dir = e.tmp.path().join("no-supervisor");
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = ComfyConfig { recycle_dir: Some(dir.clone()), ..e.config() };
    let err = Comfy::new(cfg).await.unwrap_err();
    assert!(err.0.contains("ENGINE_CONTROL_DIR"), "{err}");
    std::fs::write(dir.join("engine.gen"), "not a generation\n").unwrap();
    let cfg = ComfyConfig { recycle_dir: Some(dir), ..e.config() };
    assert!(Comfy::new(cfg).await.is_err());
}
