//! ComfyUI adapter setup: loopback-only URLs, model discovery and hashing,
//! the Go-compatible hash cache, and stable workflow hashes.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

mod mock;
mod support;

use db_engine::{Comfy, ComfyConfig, Engine, comfy_release};
use mock::Mode;
use sha2::{Digest as _, Sha256};
use std::path::Path;
use support::{WAN_FILES, WAN_WORKFLOW_SHA256, Z_FILES, Z_WORKFLOW_SHA256, env, weights};

#[tokio::test]
async fn reports_identity_caps_and_verified_models() {
    let e = env(Mode::Complete, &[&Z_FILES[..], &WAN_FILES[..]].concat()).await;
    let c = e.comfy().await;
    assert_eq!(c.name(), "comfyui@abc123");
    assert_eq!(
        String::from_utf8(db_gojson::to_vec(&c.caps()).unwrap()).unwrap(),
        concat!(
            r#"[{"id":"z-image-turbo","kind":"image","workflows":["z-image-turbo-t2i"],"max_width":2048,"max_height":2048,"max_steps":16},"#,
            r#"{"id":"wan2.1-t2v-1.3b","kind":"video","workflows":["wan2.1-t2v"],"max_width":832,"max_height":480,"max_steps":30,"max_frames":81}]"#
        )
    );
    let wf: Vec<(String, String)> = c.workflows().into_iter().map(|a| (a.name, a.sha256)).collect();
    assert_eq!(
        wf,
        vec![("z-image-turbo-t2i".to_owned(), Z_WORKFLOW_SHA256.to_owned()), ("wan2.1-t2v".to_owned(), WAN_WORKFLOW_SHA256.to_owned())]
    );
    let models = c.models();
    assert_eq!(models.len(), 2);
    for (m, files) in models.iter().zip([Z_FILES, WAN_FILES]) {
        for (a, rel) in m.files.iter().zip(files) {
            assert_eq!(a.name, Path::new(rel).file_name().unwrap().to_string_lossy());
            assert_eq!(a.sha256, hex::encode(Sha256::digest(weights(rel).as_bytes())));
            assert_eq!(a.bytes, weights(rel).len() as i64);
        }
    }
    // The release tool pins the same workflows and models.
    let (rwf, rmodels) = comfy_release(&[&e.models], None).unwrap();
    assert_eq!(rwf, c.workflows());
    assert_eq!(rmodels.len(), 2);
    assert_eq!((rmodels[0].id.as_str(), rmodels[0].kind.as_str()), ("z-image-turbo", "image"));
    assert_eq!((rmodels[1].id.as_str(), rmodels[1].kind.as_str()), ("wan2.1-t2v-1.3b", "video"));
    assert_eq!(rmodels[0].files.as_deref().unwrap(), models[0].files.as_slice());
}

#[tokio::test]
async fn only_fully_present_models_are_served() {
    let e = env(Mode::Complete, &[&Z_FILES[..], &WAN_FILES[..2]].concat()).await;
    let c = e.comfy().await;
    let ids: Vec<String> = c.caps().into_iter().map(|m| m.id).collect();
    assert_eq!(ids, vec!["z-image-turbo"]);
    assert_eq!(c.workflows().len(), 1);
    let err = support::generate(&c, &support::video_request("x"), Default::default()).await.0.unwrap_err();
    assert!(err.0.contains("is not served"), "{err}");
    // Models found across several roots, in order.
    let second = e.tmp.path().join("second");
    let rel = WAN_FILES[2];
    std::fs::create_dir_all(second.join(rel).parent().unwrap()).unwrap();
    std::fs::write(second.join(rel), weights(rel)).unwrap();
    let mut cfg = e.config();
    cfg.models_dirs.push(second);
    assert_eq!(Comfy::new(cfg).await.unwrap().caps().len(), 2);
}

#[tokio::test]
async fn missing_models_are_an_error() {
    for files in [&[][..], &Z_FILES[..2], &WAN_FILES[1..]] {
        let e = env(Mode::Complete, files).await;
        let err = Comfy::new(e.config()).await.unwrap_err();
        assert!(err.0.contains("no approved model is fully present"), "{err}");
        let (wf, models) = comfy_release(&[&e.models], None).unwrap();
        assert!(wf.is_empty() && models.is_empty());
    }
}

#[tokio::test]
async fn non_loopback_urls_are_refused() {
    let e = env(Mode::Complete, &Z_FILES).await;
    for url in ["http://10.1.2.3:8190", "http://example.com:8190", "http://127.0.0.2:8190", "http://[::2]:8190", "http://0.0.0.0:8190"] {
        let cfg = ComfyConfig { url: url.to_owned(), ..e.config() };
        let err = Comfy::new(cfg).await.unwrap_err();
        assert!(err.0.contains("must be on loopback"), "{url}: {err}");
    }
    for url in ["https://127.0.0.1:8190", "http://127.0.0.1:8190/?a=1", "not a url", ""] {
        let cfg = ComfyConfig { url: url.to_owned(), ..e.config() };
        assert!(Comfy::new(cfg).await.is_err(), "{url}");
    }
    let port = e.server.url.rsplit(':').next().unwrap().to_owned();
    let cfg = ComfyConfig { url: format!("http://localhost:{port}/"), ..e.config() };
    Comfy::new(cfg).await.unwrap();
    let cfg = ComfyConfig { url: "http://127.0.0.1:1".to_owned(), ..e.config() };
    let err = Comfy::new(cfg).await.unwrap_err();
    assert!(err.0.contains("not reachable"), "{err}");
}

fn mtime_ns(p: &Path) -> i64 {
    let t = std::fs::metadata(p).unwrap().modified().unwrap();
    t.duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as i64
}

#[test]
fn hash_cache_is_go_compatible() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("models");
    for f in Z_FILES {
        std::fs::create_dir_all(root.join(f).parent().unwrap()).unwrap();
        std::fs::write(root.join(f), weights(f)).unwrap();
    }
    let cache = tmp.path().join("cache.json");
    // A cache written by the Go adapter (json.MarshalIndent) with a planted
    // digest for one file: it is used while size and mtime match.
    let first = std::fs::canonicalize(root.join(Z_FILES[0])).unwrap();
    let planted = "ab".repeat(32);
    let go_cache = format!(
        "{{\n  \"entries\": {{\n    {}: {{\n      \"size\": {},\n      \"mtime\": {},\n      \"sha256\": \"{planted}\"\n    }}\n  }}\n}}",
        serde_json::to_string(&first.to_string_lossy()).unwrap(),
        weights(Z_FILES[0]).len(),
        mtime_ns(&first)
    );
    std::fs::write(&cache, &go_cache).unwrap();
    let (_, models) = comfy_release(&[&root], Some(&cache)).unwrap();
    let files = models[0].files.clone().unwrap();
    assert_eq!(files[0].sha256, planted);
    assert_eq!(files[1].sha256, hex::encode(Sha256::digest(weights(Z_FILES[1]).as_bytes())));

    // The saved cache has Go's MarshalIndent layout with every entry.
    let mut want = String::from("{\n  \"entries\": {");
    let mut entries: Vec<(String, String)> = Z_FILES
        .iter()
        .map(|f| {
            let real = std::fs::canonicalize(root.join(f)).unwrap();
            let sum = if *f == Z_FILES[0] { planted.clone() } else { hex::encode(Sha256::digest(weights(f).as_bytes())) };
            (
                real.to_string_lossy().into_owned(),
                format!("\"size\": {},\n      \"mtime\": {},\n      \"sha256\": \"{sum}\"", weights(f).len(), mtime_ns(&real)),
            )
        })
        .collect();
    entries.sort();
    let body: Vec<String> =
        entries.iter().map(|(k, v)| format!("\n    {}: {{\n      {v}\n    }}", serde_json::to_string(k).unwrap())).collect();
    want.push_str(&body.join(","));
    want.push_str("\n  }\n}");
    assert_eq!(std::fs::read_to_string(&cache).unwrap(), want);

    // A changed file is re-hashed.
    std::fs::write(&first, "new weights").unwrap();
    let (_, models) = comfy_release(&[&root], Some(&cache)).unwrap();
    assert_eq!(models[0].files.as_ref().unwrap()[0].sha256, hex::encode(Sha256::digest(b"new weights")));
    // A corrupt cache is ignored.
    std::fs::write(&cache, "{not json").unwrap();
    let (_, models) = comfy_release(&[&root], Some(&cache)).unwrap();
    assert_eq!(models[0].files.as_ref().unwrap()[0].sha256, hex::encode(Sha256::digest(b"new weights")));
    let fresh = tmp.path().join("fresh.json");
    comfy_release(&[&root], Some(&fresh)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn workflow_hashes_are_stable() {
    let tmp = tempfile::tempdir().unwrap();
    for f in [&Z_FILES[..], &WAN_FILES[..]].concat() {
        let p = tmp.path().join(f);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, weights(f)).unwrap();
    }
    let (wf, _) = comfy_release(&[tmp.path()], None).unwrap();
    let got: Vec<(&str, &str)> = wf.iter().map(|a| (a.name.as_str(), a.sha256.as_str())).collect();
    assert_eq!(got, vec![("z-image-turbo-t2i", Z_WORKFLOW_SHA256), ("wan2.1-t2v", WAN_WORKFLOW_SHA256)]);
    assert!(wf.iter().all(|a| a.bytes == 0));
}
