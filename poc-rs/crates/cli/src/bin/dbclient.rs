//! dbclient is a consumer. By default it sends image and video jobs to the
//! trusted coordinator, which seals them to an attested provider; with
//! `-e2e` it verifies the provider itself and seals end to end (optional
//! defense in depth).
//! Text jobs always use independent verification and TPM-bound end-to-end
//! sealing. Development tiers cannot serve text jobs, even with `-allow-dev`.
//!
//! ```text
//! dbclient [flags] providers
//! dbclient [trust flags] verify <provider-id>
//! dbclient [flags] image -prompt "…" -out fox.png [-width 1024 -height 1024 -steps 8] [-e2e [-provider ID]]
//! dbclient [flags] video -prompt "…" -out clip.mp4 [-frames 33 -fps 16 -width 832 -height 480 -steps 20] [-e2e [-provider ID]]
//! dbclient [trust flags] text -prompt-file prompt.txt -out answer.txt [-max-tokens 64]
//! ```
//!
//! `-coordinator https://…` uses TLS 1.3; `-ca-cert` pins the CA bundle that
//! must have issued the coordinator's certificate (default: Mozilla's roots).

#![forbid(unsafe_code)]

use db_cli::goflag::{FlagSet, format_duration};
use db_cli::{cli_args, die};
use db_client::{Client, ImageRequest, TextRequest};
use db_tpmattest::{RootKind, TrustBundle, Verdict, load_certificates, pinned_root, pluton_root};
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

const TOOL: &str = "dbclient";

fn fail(msg: impl std::fmt::Display) -> ! {
    die(TOOL, msg)
}

/// A uniform index in `0..n` from the OS CSPRNG (rejection sampling).
fn uniform_index(n: usize) -> usize {
    let n64 = n as u64;
    if n64 <= 1 {
        return 0;
    }
    let zone = u64::MAX - (u64::MAX % n64);
    loop {
        let mut b = [0u8; 8];
        if getrandom::fill(&mut b).is_err() {
            return 0;
        }
        let v = u64::from_le_bytes(b);
        if v < zone {
            return usize::try_from(v % n64).unwrap_or(0);
        }
    }
}

fn print_verdict(v: &Verdict) {
    for c in &v.checks {
        let mark = if c.ok { "✓" } else { "✗" };
        println!("{mark} {:<28} [{}] {}", c.name, c.effect, c.detail);
    }
    println!("tier: {}  device: {}  release: {}", v.tier, v.device_id, v.release);
}

fn main() {
    db_tls::install_default_provider();
    let mut fs = FlagSet::new("dbclient");
    fs.string("coordinator", "http://127.0.0.1:8787", "coordinator URL (https:// for TLS)")
        .string("ca-cert", "", "PEM bundle: the only trust anchors for an https:// coordinator (default: Mozilla's roots)")
        .string("key", "", "consumer API key")
        .string("pluton-certs", "", "AMD Pluton anchors directory")
        .multi("dev-root", "accept a development endorsement root (dev-simulated tier)")
        .multi("ftpm-root", "AMD fTPM anchor")
        .multi("release-pub", "pinned release-signing public key")
        .string("enrollment-pub", "", "pinned coordinator enrollment key file (hex)")
        .string("log-pub", "", "pinned release-log key file (hex)")
        .uint("min-svn", 1, "release security-version floor")
        .boolean("allow-dev", false, "accept development tiers (dev-channel releases, dev roots); never for private data")
        .boolean(
            "trust-enrollment",
            false,
            "accept the coordinator's signed enrollment record instead of our own credential-activation challenge",
        );
    fs.parse_or_exit(&cli_args());
    let Some((cmd, rest)) = fs.args().split_first() else {
        fail("usage: dbclient [flags] providers|verify|image|video|text ...");
    };
    let (cmd, rest) = (cmd.clone(), rest.to_vec());

    let mut bundle = TrustBundle::default();
    let pluton = fs.str("pluton-certs");
    if !pluton.is_empty() {
        bundle.roots.push(pluton_root(Path::new(&pluton), 6).unwrap_or_else(|e| fail(e)));
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
    let coordinator = fs.str("coordinator");
    let ca = fs.str("ca-cert");
    let mut cl = if ca.is_empty() {
        Client::new(&coordinator, &fs.str("key")).unwrap_or_else(|e| fail(e))
    } else {
        if !coordinator.starts_with("https://") {
            fail("-ca-cert needs an https:// coordinator URL");
        }
        let tls = db_tls::client_config_for(Some(Path::new(&ca))).unwrap_or_else(|e| fail(e));
        Client::with_tls(&coordinator, &fs.str("key"), tls).unwrap_or_else(|e| fail(e))
    };
    cl.bundle = bundle;
    for p in fs.multi_values("release-pub") {
        let public = db_release::load_public_key(Path::new(&p)).unwrap_or_else(|e| fail(e));
        cl.release_keys.insert(db_release::key_id(&public), public);
    }
    cl.min_svn = u32::try_from(fs.uint_value("min-svn")).unwrap_or_else(|_| fail("-min-svn out of range"));
    cl.allow_dev = fs.bool("allow-dev") || !dev_roots.is_empty();
    cl.trust_enrollment = fs.bool("trust-enrollment");
    let load_pub = |flag: &str| {
        let path = fs.str(flag);
        if path.is_empty() {
            fail(format!("-{flag} is required (pin the coordinator's key)"));
        }
        db_release::load_public_key(Path::new(&path)).unwrap_or_else(|e| fail(e))
    };

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap_or_else(|e| fail(e));
    rt.block_on(async move {
        let run = async {
            match cmd.as_str() {
                "providers" => {
                    let ps = cl.providers().await.unwrap_or_else(|e| fail(e));
                    let out = if ps.is_empty() { b"null".to_vec() } else { db_gojson::to_vec_indent(&ps).unwrap_or_else(|e| fail(e)) };
                    println!("{}", String::from_utf8_lossy(&out));
                }
                "verify" => {
                    let Some(id) = rest.first() else { fail("usage: dbclient verify <provider-id>") };
                    cl.release_log_key = Some(load_pub("log-pub"));
                    if cl.trust_enrollment {
                        cl.enrollment_key = Some(load_pub("enrollment-pub"));
                    }
                    match cl.verify(id).await {
                        Ok(v) => print_verdict(&v.verdict),
                        Err(db_client::Error::Verification { message, verdict }) => {
                            print_verdict(&verdict);
                            fail(format!("client: provider failed verification: {message}"));
                        }
                        Err(e) => fail(e),
                    }
                }
                "image" | "video" => generate(&mut cl, &cmd, &rest, &load_pub).await,
                "text" => generate_text(&mut cl, &rest, &load_pub).await,
                other => fail(format!("unknown command {other:?}")),
            }
        };
        tokio::select! {
            () = run => {}
            () = tokio::time::sleep(Duration::from_secs(20 * 60)) => fail("timed out"),
        }
    });
}

async fn generate_text(cl: &mut Client, args: &[String], load_pub: &dyn Fn(&str) -> ed25519_dalek::VerifyingKey) {
    let mut fs = FlagSet::new("text");
    fs.string("provider", "", "provider ID (default: a leased text provider)")
        .string("model", "qwen3-coder-30b-a3b-instruct-q4-k-m", "approved text model")
        .string("workflow", "llama-text-greedy-v1", "approved text workflow")
        .string("prompt", "", "prompt; prefer -prompt-file for private content")
        .string("prompt-file", "", "read the private prompt from a local UTF-8 file")
        .int("max-tokens", 64, "generated-token limit (1..1024)")
        .int("seed", 0, "seed (0 = random)")
        .string("out", "out.txt", "private completion output file");
    fs.parse_or_exit(args);
    let prompt_path = fs.str("prompt-file");
    let prompt = if prompt_path.is_empty() {
        Zeroizing::new(fs.str("prompt"))
    } else {
        if !fs.str("prompt").is_empty() {
            fail("choose either -prompt or -prompt-file");
        }
        Zeroizing::new(std::fs::read_to_string(&prompt_path).unwrap_or_else(|_| fail("could not read prompt file")))
    };
    if prompt.is_empty() {
        fail("-prompt-file or -prompt is required");
    }
    cl.release_log_key = Some(load_pub("log-pub"));
    if cl.trust_enrollment {
        cl.enrollment_key = Some(load_pub("enrollment-pub"));
    }
    let model = fs.str("model");
    let mut provider = fs.str("provider");
    if provider.is_empty() {
        let providers = cl.providers().await.unwrap_or_else(|e| fail(e));
        let candidates: Vec<String> = providers
            .iter()
            .filter(|p| p.models.iter().any(|m| m.id == model && m.kind == "text"))
            .map(|p| p.provider_id.clone())
            .collect();
        provider = candidates.get(uniform_index(candidates.len())).cloned().unwrap_or_else(|| fail("no leased text provider is available"));
    }
    let request =
        TextRequest { model, workflow: fs.str("workflow"), prompt, max_tokens: fs.int_value("max-tokens"), seed: fs.int_value("seed") };
    println!("verifying provider {provider}; sealing the text job to its TPM-bound key...");
    let mut last = String::new();
    let result = cl
        .generate_text(&provider, &request, |state, step, total| {
            let status = format!("job {state} {step}/{total}");
            if status != last {
                println!("{status}");
                last = status;
            }
        })
        .await
        .unwrap_or_else(|e| fail(e));
    let output = fs.str("out");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&output).unwrap_or_else(|e| fail(format!("output: {e}")));
    std::io::Write::write_all(&mut file, &result.data).unwrap_or_else(|e| fail(format!("output: {e}")));
    println!(
        "wrote {output} ({} bytes); tier={} release={} tokens={}/{} receipt verified",
        result.data.len(),
        result.verified.verdict.tier,
        result.verified.verdict.release,
        result.receipt.units.prompt_tokens,
        result.receipt.units.completion_tokens
    );
}

async fn generate(cl: &mut Client, cmd: &str, args: &[String], load_pub: &dyn Fn(&str) -> ed25519_dalek::VerifyingKey) {
    let video = cmd == "video";
    let mut fs = FlagSet::new(cmd);
    fs.string("provider", "", "provider ID (default: first leased provider)")
        .string("model", if video { "wan2.1-t2v-1.3b" } else { "z-image-turbo" }, "model")
        .string("workflow", if video { "wan2.1-t2v" } else { "z-image-turbo-t2i" }, "workflow")
        .string("prompt", "", "prompt (sealed end to end)")
        .int("width", if video { 832 } else { 1024 }, "width")
        .int("height", if video { 480 } else { 1024 }, "height")
        .int("steps", if video { 20 } else { 8 }, "steps")
        .int("frames", 33, "video frames (4n+1)")
        .int("fps", 16, "video frames per second")
        .int("seed", 0, "seed (0 = random)")
        .string("out", if video { "out.mp4" } else { "out.png" }, "output file")
        .boolean("e2e", false, "optional mode: verify the provider here and seal end to end (default: the trusted coordinator seals)");
    fs.parse_or_exit(args);
    let (mut frames, mut fps) = (fs.int_value("frames"), fs.int_value("fps"));
    if !video {
        frames = 0;
        fps = 0;
    }
    let prompt = Zeroizing::new(fs.str("prompt"));
    if prompt.is_empty() {
        fail("-prompt is required");
    }
    let model = fs.str("model");
    let out = fs.str("out");
    if !fs.bool("e2e") {
        println!("sending the job to the coordinator, which seals it to an attested provider...");
        let req = ImageRequest {
            model,
            workflow: String::new(),
            prompt,
            negative_prompt: Zeroizing::new(String::new()),
            width: fs.int_value("width"),
            height: fs.int_value("height"),
            steps: fs.int_value("steps"),
            frames,
            fps,
            seed: fs.int_value("seed"),
        };
        let res = cl.generate_simple(&req).await.unwrap_or_else(|e| fail(e));
        std::fs::write(&out, res.data.as_slice()).unwrap_or_else(|e| fail(format!("{out}: {e}")));
        println!("wrote {out} ({} bytes, {}) in {}", res.data.len(), res.mime, format_duration(res.elapsed));
        println!("provider {} tier={} release={} tpm-bound-decryption={}", res.provider_id, res.tier, res.release, res.tpm_bound);
        return;
    }
    cl.release_log_key = Some(load_pub("log-pub"));
    if cl.trust_enrollment {
        cl.enrollment_key = Some(load_pub("enrollment-pub"));
    }
    let mut provider = fs.str("provider");
    if provider.is_empty() {
        // The consumer, not the coordinator, picks the provider, uniformly at
        // random among those serving the model, so a coordinator cannot steer
        // a chosen consumer to a chosen machine.
        let ps = cl.providers().await.unwrap_or_else(|e| fail(e));
        let candidates: Vec<String> =
            ps.iter().flat_map(|p| p.models.iter().filter(|m| m.id == model).map(|_| p.provider_id.clone())).collect();
        if candidates.is_empty() {
            fail(format!("no leased provider serves {model}"));
        }
        provider = candidates.get(uniform_index(candidates.len())).cloned().unwrap_or_default();
    }
    println!("verifying provider {provider} ourselves, then sealing the job to its attested key...");
    let req = ImageRequest {
        model,
        workflow: fs.str("workflow"),
        prompt,
        negative_prompt: Zeroizing::new(String::new()),
        width: fs.int_value("width"),
        height: fs.int_value("height"),
        steps: fs.int_value("steps"),
        frames,
        fps,
        seed: fs.int_value("seed"),
    };
    let mut last = String::new();
    let res = cl
        .generate(&provider, &req, |state, step, total| {
            let s = format!("  job {state} {step}/{total}");
            if s != last {
                println!("{s}");
                last = s;
            }
        })
        .await
        .unwrap_or_else(|e| fail(e));
    std::fs::write(&out, res.data.as_slice()).unwrap_or_else(|e| fail(format!("{out}: {e}")));
    let v = &res.verified.verdict;
    println!("wrote {out} ({} bytes, {}) in {}", res.data.len(), res.mime, format_duration(res.elapsed));
    println!("provider {provider} tier={} release={} device={} TPM={}", v.tier, v.release, v.device_id, res.verified.statement.tpm_mode);
    let u = &res.receipt.units;
    println!(
        "receipt verified: {} image(s), {:.1} s video, {:.2} MP, {} steps, GPU {} ms, result {} sealed bytes",
        u.images, u.video_seconds, u.megapixels, u.steps, u.gpu_millis, res.receipt.result_bytes
    );
}
