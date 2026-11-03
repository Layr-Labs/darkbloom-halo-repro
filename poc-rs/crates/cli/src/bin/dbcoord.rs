//! dbcoord runs the PoC coordinator.
//!
//! ```text
//! dbcoord -listen 127.0.0.1:8787 -state state/ -pluton-certs ../certs/amd-pluton \
//!   -releases releases/ -release-pub keys/release.pub -min-svn 1 \
//!   -provider-token TOKEN=account -consumer-key KEY [-dev-root devca/dev-root.pem -allow-dev-releases] \
//!   [-tls-cert tls/server.pem -tls-key tls/server.key] [-capture-attestation private-dir/]
//! dbcoord devcert -out tls/ -hosts 127.0.0.1,localhost      (development TLS certificate)
//! ```
//!
//! With `-tls-cert`/`-tls-key` it serves HTTPS, and WSS for providers (TLS
//! 1.3 only). Plain HTTP is only served on loopback unless
//! `-insecure-plain-http` is given.

#![forbid(unsafe_code)]

use db_cli::goflag::FlagSet;
use db_cli::{cli_args, die, glob_suffix};
use db_log::{Logger, logf};
use db_release::{Envelope, Policy, TrustedKeys};
use db_tls::Listen;
use db_tpmattest::{RootKind, Tier, TrustBundle, TrustedRelease, UKI_PCRS, Verifier, load_certificates, pinned_root, pluton_root};
use ed25519_dalek::SigningKey;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const TOOL: &str = "dbcoord";

fn fail(msg: impl std::fmt::Display) -> ! {
    die(TOOL, msg)
}

fn load_or_create_key(path: &Path) -> SigningKey {
    if let Ok(k) = db_release::load_private_key(path) {
        return k;
    }
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut_slice()).unwrap_or_else(|e| fail(format!("random: {e}")));
    let key = SigningKey::from_bytes(&seed);
    db_release::write_private_key(path, &key).unwrap_or_else(|e| fail(e));
    key
}

fn write_pub(path: &Path, key: &SigningKey) {
    let text = format!("{}\n", hex::encode(key.verifying_key().as_bytes()));
    std::fs::write(path, text).unwrap_or_else(|e| fail(format!("{}: {e}", path.display())));
}

/// `dbcoord devcert`: a development CA and server certificate.
fn devcert(args: &[String]) {
    let mut fs = FlagSet::new("devcert");
    fs.string("out", "tls", "output directory (ca.pem, server.pem, server.key)").string(
        "hosts",
        "127.0.0.1,localhost",
        "comma-separated IP addresses and DNS names the certificate covers",
    );
    fs.parse_or_exit(args);
    let out = fs.str("out");
    let hosts = fs.str("hosts");
    let hosts: Vec<&str> = hosts.split(',').collect();
    let dc = db_tls::devcert::write(Path::new(&out), &hosts).unwrap_or_else(|e| fail(e));
    let until = chrono::DateTime::<chrono::Utc>::from(dc.not_after).format("%Y-%m-%d");
    println!(
        "development TLS certificate for {} (until {until}) in {out}/: {} (pin with -ca-cert), {}, {} (NOT FOR PRODUCTION)",
        dc.hosts.join(", "),
        db_tls::devcert::CA_FILE,
        db_tls::devcert::CERT_FILE,
        db_tls::devcert::KEY_FILE
    );
}

fn main() {
    db_tls::install_default_provider();
    let args = cli_args();
    if args.first().map(String::as_str) == Some("devcert") {
        devcert(args.get(1..).unwrap_or_default());
        return;
    }
    let mut fs = FlagSet::new("dbcoord");
    fs.string("listen", "127.0.0.1:8787", "listen address")
        .string("tls-cert", "", "PEM certificate chain: serve HTTPS and WSS (TLS 1.3 only); see dbcoord devcert")
        .string("tls-key", "", "PEM private key for -tls-cert")
        .boolean("insecure-plain-http", false, "allow plain HTTP on a non-loopback address (only behind a TLS-terminating proxy)")
        .string("state", "coord-state", "state directory (enrollment and release-log keys)")
        .string("pluton-certs", "", "directory with AMD Pluton anchors (darkbloom-amd/certs/amd-pluton)")
        .int("min-pluton-svn", 6, "minimum Pluton firmware SVN")
        .multi("ftpm-root", "AMD fTPM endorsement anchor (PEM), pinned by fingerprint (2026+ silicon)")
        .multi("dev-root", "development (swtpm) endorsement root; enables the dev-simulated tier")
        .multi("release-pub", "trusted release-signing public key file")
        .multi("provider-token", "TOKEN=account pairing")
        .multi("consumer-key", "consumer API key")
        .string("releases", "releases", "directory of signed release envelopes (*.dsse.json)")
        .string("boot-profile", "type1", "boot measurement profile: type1 or uki")
        .string("capture-attestation", "", "private 0700 directory for pre-release TPM evidence; never changes admission")
        .uint("min-svn", 1, "release security-version floor")
        .int("release-threshold", 1, "signatures required from distinct trusted release keys")
        .boolean("allow-dev-releases", false, "accept channel=dev releases")
        .duration("challenge", Duration::from_secs(30), "attestation challenge interval")
        .duration("lease", Duration::ZERO, "serving lease TTL (default 3x challenge)");
    fs.parse_or_exit(&args);

    let listen = fs.str("listen");
    let (tls_cert, tls_key) = (fs.str("tls-cert"), fs.str("tls-key"));
    if tls_cert.is_empty() != tls_key.is_empty() {
        fail("-tls-cert and -tls-key go together");
    }
    let mode = db_tls::check_listen(&listen, !tls_cert.is_empty(), fs.bool("insecure-plain-http")).unwrap_or_else(|e| fail(e));
    let tls = (mode == Listen::Tls)
        .then(|| Arc::new(db_tls::server_config(Path::new(&tls_cert), Path::new(&tls_key)).unwrap_or_else(|e| fail(e))));

    let logger = Logger::stderr("dbcoord ");
    if mode == Listen::PlainExposed {
        logf!(
            logger,
            "WARNING: plain HTTP on {listen} (-insecure-plain-http): prompts and provider traffic are unprotected unless a TLS proxy is in front"
        );
    }
    let state = std::path::PathBuf::from(fs.str("state"));
    std::fs::create_dir_all(&state).unwrap_or_else(|e| fail(e));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700));
    }
    let enrollment_key = load_or_create_key(&state.join("enrollment.key"));
    let log_key = load_or_create_key(&state.join("release-log.key"));

    let mut bundle = TrustBundle::default();
    let pluton = fs.str("pluton-certs");
    if !pluton.is_empty() {
        bundle.roots.push(pluton_root(Path::new(&pluton), fs.int_value("min-pluton-svn")).unwrap_or_else(|e| fail(e)));
    }
    let ftpm = fs.multi_values("ftpm-root");
    if !ftpm.is_empty() {
        let certs = load_certificates(&ftpm).unwrap_or_else(|e| fail(e));
        bundle.roots.push(pinned_root("AMD fTPM", RootKind::AmdFtpm, certs, Vec::new(), true));
    }
    let dev_roots = fs.multi_values("dev-root");
    if !dev_roots.is_empty() {
        let certs = load_certificates(&dev_roots).unwrap_or_else(|e| fail(e));
        bundle.roots.push(pinned_root("DEV simulated TPM root", RootKind::DevSimulated, certs, Vec::new(), false));
    }
    if bundle.roots.is_empty() {
        fail("no endorsement roots: pass -pluton-certs (and/or -ftpm-root, -dev-root)");
    }
    let mut keys = TrustedKeys::new();
    for p in fs.multi_values("release-pub") {
        let public = db_release::load_public_key(Path::new(&p)).unwrap_or_else(|e| fail(e));
        keys.insert(db_release::key_id(&public), public);
    }
    let threshold = usize::try_from(fs.int_value("release-threshold").max(1)).unwrap_or(1);
    let required_pcrs = match fs.str("boot-profile").as_str() {
        "type1" => Vec::new(),
        "uki" => UKI_PCRS.to_vec(),
        other => fail(format!("unknown -boot-profile {other:?}; use type1 or uki")),
    };
    let release_log = Arc::new(db_release::Log::new(log_key.clone()));
    let mut trusted = Vec::new();
    for f in glob_suffix(Path::new(&fs.str("releases")), ".dsse.json") {
        let raw = std::fs::read(&f).unwrap_or_else(|e| fail(format!("{}: {e}", f.display())));
        let env: Envelope = db_gojson::from_slice(&raw).unwrap_or_else(|e| fail(format!("{}: {e}", f.display())));
        let m = match db_release::open_manifest(&env, &keys, threshold) {
            Ok(m) => m,
            Err(e) => {
                logf!(logger, "skipping {}: {e}", f.display());
                continue;
            }
        };
        release_log.append(&raw);
        logf!(
            logger,
            "release {} ({}) logged; PCR4 {}… PCR9 {}… PCR12 {}…",
            m.id(),
            m.channel,
            m.boot.pcr4_sha256.get(..12).unwrap_or_default(),
            m.boot.pcr9_sha256.get(..12).unwrap_or_default(),
            m.boot.pcr12_sha256.get(..12).unwrap_or_default()
        );
        trusted.push(TrustedRelease { manifest: Arc::new(m), envelope: raw, logged: true });
    }
    let mut provider_tokens = BTreeMap::new();
    for t in fs.multi_values("provider-token") {
        let Some((k, v)) = t.split_once('=') else { fail("-provider-token wants TOKEN=account") };
        provider_tokens.insert(k.to_owned(), v.to_owned());
    }
    let consumer_keys: BTreeSet<String> = fs.multi_values("consumer-key").into_iter().collect();
    let min_svn = u32::try_from(fs.uint_value("min-svn")).unwrap_or_else(|_| fail("-min-svn out of range"));
    let allow_dev_releases = fs.bool("allow-dev-releases");
    let roots: Vec<String> = bundle.roots.iter().map(|r| format!("{} ({})", r.name, r.kind)).collect();
    let verifier = Verifier {
        bundle,
        releases: trusted,
        release_policy: Some(Policy {
            keys: keys.clone(),
            threshold,
            min_svn,
            allow_dev: allow_dev_releases,
            require_logged: true,
            ..Policy::default()
        }),
        allow_dev_roots: !dev_roots.is_empty(),
        required_pcrs,
        ..Verifier::default()
    };
    // Development tiers (swtpm roots, or real hardware on a dev-channel OS)
    // are only routable when explicitly allowed; they never carry private data.
    let min_tier = if !dev_roots.is_empty() || allow_dev_releases { Tier::DevSimulated } else { Tier::Attested };
    let releases_count = verifier.releases.len();
    write_pub(&state.join("enrollment.pub"), &enrollment_key);
    write_pub(&state.join("release-log.pub"), &log_key);
    let cfg = db_coord::Config {
        verifier,
        enrollment_key,
        release_log,
        release_log_key: log_key.verifying_key(),
        release_keys: keys,
        provider_tokens,
        consumer_keys,
        challenge_interval: fs.duration_value("challenge"),
        lease_ttl: fs.duration_value("lease"),
        min_tier: Some(min_tier),
        max_result_bytes: 0,
        capture_attestation: match fs.str("capture-attestation") {
            dir if dir.is_empty() => None,
            dir => Some(std::path::PathBuf::from(dir)),
        },
        logger: logger.clone(),
    };
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap_or_else(|e| fail(e));
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&listen).await.unwrap_or_else(|e| fail(e));
        let scheme = if tls.is_some() { "https and wss (TLS 1.3)" } else { "plain http and ws" };
        logf!(
            logger,
            "listening on {listen} ({scheme}); endorsement roots: {}; {releases_count} releases; min SVN {min_svn}",
            roots.join(", ")
        );
        let server = db_coord::Server::new(cfg).unwrap_or_else(|e| fail(e));
        let serve = async move {
            match tls {
                Some(tls) => db_coord::serve_tls(listener, server, tls).await,
                None => db_coord::serve(listener, server).await,
            }
        };
        tokio::select! {
            r = serve => if let Err(e) = r { fail(e) },
            () = db_cli::shutdown_signal() => {}
        }
    });
}
