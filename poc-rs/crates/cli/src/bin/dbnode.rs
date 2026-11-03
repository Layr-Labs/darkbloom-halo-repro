//! dbnode is the Darkbloom provider agent for AMD machines.
//!
//! ```text
//! dbnode run       -tpm /dev/tpmrm0 -coordinator wss://… [-ca-cert ca.pem] -token T -engine comfy \
//!                  [-engine-recycle /run/dbnode-engine/control [-engine-warmup=false]] …
//! dbnode identity  -tpm /dev/tpmrm0          (needs root or the tss group on a real TPM)
//! ```
//!
//! Development-only (swtpm; refuses a hardware TPM):
//!
//! ```text
//! dbnode devca     -out devca/
//! dbnode provision -tpm swtpm:unix:/run/…/swtpm.sock -ca devca/
//! dbnode simboot   -tpm swtpm:unix:… -out eventlog.bin -kernel … -initrd … -cmdline-from-proc
//! ```

#![forbid(unsafe_code)]

use db_cli::goflag::FlagSet;
use db_cli::{cli_args, die, proc_cmdline};
use db_engine::Engine;
use db_log::{Logger, logf};
use db_tpmdev::Device;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

const TOOL: &str = "dbnode";

fn fail(msg: impl std::fmt::Display) -> ! {
    die(TOOL, msg)
}

fn main() {
    db_tls::install_default_provider();
    let args = cli_args();
    let Some((cmd, rest)) = args.split_first() else {
        fail("usage: dbnode run|identity|devca|provision|simboot [flags]");
    };
    match cmd.as_str() {
        "run" => run(rest),
        "identity" => identity(rest),
        "devca" => {
            let mut fs = FlagSet::new("devca");
            fs.string("out", "devca", "directory");
            fs.parse_or_exit(rest);
            let out = fs.str("out");
            db_devca::create_dev_ca(Path::new(&out)).unwrap_or_else(|e| fail(e));
            println!("dev CA written to {out} (NOT AMD; verifiers accept it only with an explicit dev root)");
        }
        "provision" => {
            let mut fs = FlagSet::new("provision");
            fs.string("tpm", "", "swtpm spec").string("ca", "devca", "dev CA directory");
            fs.parse_or_exit(rest);
            let dev = open(&fs.str("tpm"));
            let ca = db_devca::load_dev_ca(Path::new(&fs.str("ca"))).unwrap_or_else(|e| fail(e));
            dev.provision_ek(&ca).unwrap_or_else(|e| fail(e));
            println!("dev EK certificate and ICA written to NV 0x01C0000A / 0x01C00100");
        }
        "simboot" => simulate(rest),
        other => fail(format!("unknown command {other:?}")),
    }
}

fn open(spec: &str) -> Arc<Device> {
    if spec.is_empty() {
        fail("-tpm is required (/dev/tpmrm0 or swtpm:unix:PATH)");
    }
    Device::open(spec).unwrap_or_else(|e| fail(e))
}

fn simulate(args: &[String]) {
    let mut fs = FlagSet::new("simboot");
    fs.string("tpm", "", "swtpm spec")
        .string("out", "eventlog.bin", "event log output")
        .string("bios", "LFGB0.03.03", "S-CRTM (BIOS) version to log")
        .string("shim", "/usr/lib/shim/shimx64.efi.signed", "shim")
        .string("sdboot", "/usr/lib/systemd/boot/efi/systemd-bootx64.efi.signed", "systemd-boot")
        .string("kernel", "", "kernel")
        .string("initrd", "", "initrd")
        .string("cmdline", "", "kernel command line")
        .boolean("cmdline-from-proc", false, "use /proc/cmdline");
    fs.parse_or_exit(args);
    let mut cmdline = fs.str("cmdline");
    if fs.bool("cmdline-from-proc") {
        cmdline = proc_cmdline().unwrap_or_else(|e| fail(e));
    }
    let (kernel, initrd) = (fs.str("kernel"), fs.str("initrd"));
    if kernel.is_empty() || initrd.is_empty() || cmdline.is_empty() {
        fail("-kernel, -initrd and -cmdline are required");
    }
    let dev = open(&fs.str("tpm"));
    let (bios, shim, sdboot) = (fs.str("bios"), fs.str("shim"), fs.str("sdboot"));
    let log = dev
        .simulate_boot(|banks: &[u16]| {
            let mut a =
                db_simboot::Artifacts { bios_version: bios.clone(), secure_boot: true, cmdline: cmdline.clone(), ..Default::default() };
            for (name, path) in [("shimx64.efi", &shim), ("systemd-bootx64.efi", &sdboot), ("linux", &kernel)] {
                a.boot_apps.push(db_simboot::load_pe(name, Path::new(path), banks).map_err(|e| e.to_string())?);
            }
            a.initrd = db_simboot::hash_file(Path::new(&initrd), banks).map_err(|e| e.to_string())?;
            Ok(db_simboot::halo_plan(banks, &a))
        })
        .unwrap_or_else(|e| fail(e));
    let out = fs.str("out");
    std::fs::write(&out, &log).unwrap_or_else(|e| fail(format!("{out}: {e}")));
    println!("simulated Halo boot into swtpm; event log {out} ({} bytes)", log.len());
}

fn identity(args: &[String]) {
    let mut fs = FlagSet::new("identity");
    fs.string("tpm", "/dev/tpmrm0", "TPM");
    fs.parse_or_exit(args);
    let dev = open(&fs.str("tpm"));
    let end = dev.load_endorsement().unwrap_or_else(|e| fail(e));
    let cert = db_tpmattest::Certificate::parse(&end.cert_der).unwrap_or_else(|e| fail(format!("EK certificate: {e}")));
    println!("TPM mode:      {}", dev.mode().as_str());
    let kind = if end.ecc { "ECC P-256" } else { "RSA-2048" };
    let ou = cert.subject_ou.join(",");
    println!("EK ({kind}):  subject CN={:?} OU={ou:?} issuer {:?}", cert.subject_cn, cert.issuer_cn);
    for (i, der) in end.icas.iter().enumerate() {
        if let Ok(c) = db_tpmattest::Certificate::parse(der) {
            println!("on-chip ICA {i}: {:?} (issuer {:?})", c.subject_cn, c.issuer_cn);
        }
    }
    println!("provider ID:   {}", db_tpmattest::provider_id_from_ek(&end.ek.public_raw));
    let certifies = db_tpmattest::parse_ek_public(&end.ek.public_raw).ok().is_some_and(|k| cert.public_key.as_ref() == Some(&k.key));
    println!("EK certificate certifies the TPM's EK: {}", if certifies { "yes" } else { "NO" });
    dev.flush(&end.ek);
}

fn run(args: &[String]) {
    let mut fs = FlagSet::new("run");
    fs.string("tpm", "/dev/tpmrm0", "TPM")
        .string("event-log", "", "event log file (default: firmware log in securityfs; swtpm needs the simboot log)")
        .string("coordinator", "", "coordinator WebSocket URL, e.g. wss://coordinator.example/v1/provider/ws")
        .string("ca-cert", "", "PEM bundle: the only trust anchors for a wss:// coordinator (default: Mozilla's roots)")
        .string("token", "", "account pairing token")
        .string("token-file", "", "file holding the pairing token (Node OS: written once at pairing)")
        .string("engine", "comfy", "comfy, llama or fake")
        .string("boot-profile", "type1", "type1 or uki (must match coordinator PCR policy)")
        .string("llama-url", "http://127.0.0.1:8080", "llama-server loopback URL")
        .string("text-model-id", "qwen3-coder-30b-a3b-instruct-q4-k-m", "approved text model ID")
        .string("text-model", "", "approved GGUF file")
        .string("text-model-sha256", "", "expected GGUF SHA-256")
        .string("text-workflow", "", "approved fixed text workflow JSON")
        .int("text-max-tokens", 1024, "maximum generated text tokens")
        .string("comfy-url", "http://127.0.0.1:8190", "ComfyUI (loopback)")
        .string("comfy-out", "/dev/shm/dbpoc-engine/out", "ComfyUI output directory (tmpfs)")
        .string("models-dir", "/var/cache/models/comfyui", "model roots, comma separated (searched in order)")
        .string("comfy-commit", "unknown", "ComfyUI build identity")
        .string("hash-cache", "", "model hash cache (dev OS convenience)")
        .string(
            "engine-recycle",
            "",
            "engine control directory (run-engine.sh ENGINE_CONTROL_DIR): restart ComfyUI after every job, so each job runs in a fresh process",
        )
        .boolean("engine-warmup", true, "with -engine-recycle: one fixed warm-up generation after each restart (no consumer data)")
        .string("kem", "", "job KEM (default X-Wing)");
    fs.parse_or_exit(args);
    let mut token = zeroize::Zeroizing::new(fs.str("token"));
    let token_file = fs.str("token-file");
    if !token_file.is_empty() {
        let t = std::fs::read_to_string(&token_file).unwrap_or_else(|e| fail(format!("{token_file}: {e}")));
        token = zeroize::Zeroizing::new(t.trim().to_owned());
    }
    let coordinator = fs.str("coordinator");
    if coordinator.is_empty() || token.is_empty() {
        fail("-coordinator and -token (or -token-file) are required");
    }
    let ca = fs.str("ca-cert");
    let tls = if ca.is_empty() {
        None
    } else {
        if !coordinator.starts_with("wss://") {
            fail("-ca-cert needs a wss:// coordinator URL");
        }
        Some(Arc::new(db_tls::client_config_for(Some(Path::new(&ca))).unwrap_or_else(|e| fail(e))))
    };
    let recycle = fs.str("engine-recycle");
    if !recycle.is_empty() && !matches!(fs.str("engine").as_str(), "comfy" | "llama") {
        fail("-engine-recycle needs -engine comfy or llama");
    }
    let logger = Logger::stderr("dbnode ");
    let dev = open(&fs.str("tpm"));
    let event_log = fs.str("event-log");
    let elog = (!event_log.is_empty()).then(|| std::fs::read(&event_log).unwrap_or_else(|e| fail(format!("{event_log}: {e}"))));
    let att = Arc::new(
        match fs.str("boot-profile").as_str() {
            "type1" => db_node::Attester::new(dev, elog),
            "uki" => db_node::Attester::new_with_pcrs(dev, elog, &db_tpmattest::UKI_PCRS),
            other => fail(format!("unknown boot profile {other:?}")),
        }
        .unwrap_or_else(|e| fail(e)),
    );
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap_or_else(|e| fail(e));
    let res = rt.block_on(async {
        let shutdown = CancellationToken::new();
        let engine: Arc<dyn Engine> = match fs.str("engine").as_str() {
            "fake" => Arc::new(db_engine::Fake { delay: std::time::Duration::ZERO }),
            "llama" => Arc::new(
                db_engine::Llama::connect(db_engine::LlamaConfig {
                    url: fs.str("llama-url"),
                    model_id: fs.str("text-model-id"),
                    model_path: PathBuf::from(fs.str("text-model")),
                    model_sha256: fs.str("text-model-sha256"),
                    workflow_path: PathBuf::from(fs.str("text-workflow")),
                    max_tokens: fs.int_value("text-max-tokens"),
                    recycle: (!recycle.is_empty()).then(|| PathBuf::from(&recycle)),
                    warmup: fs.bool("engine-warmup"),
                })
                .await
                .unwrap_or_else(|e| fail(e)),
            ),
            "comfy" => {
                let models_dir = fs.str("models-dir");
                logf!(logger, "checking engine at {} and hashing approved models in {models_dir} ...", fs.str("comfy-url"));
                let cache = fs.str("hash-cache");
                let cfg = db_engine::ComfyConfig {
                    url: fs.str("comfy-url"),
                    output_dir: Some(PathBuf::from(fs.str("comfy-out"))).filter(|p| !p.as_os_str().is_empty()),
                    models_dirs: models_dir.split(',').map(PathBuf::from).collect(),
                    commit: fs.str("comfy-commit"),
                    hash_cache: (!cache.is_empty()).then(|| PathBuf::from(cache)),
                    recycle_dir: (!recycle.is_empty()).then(|| PathBuf::from(&recycle)),
                    warmup: fs.bool("engine-warmup"),
                    restart_timeout: std::time::Duration::ZERO,
                    logger: Some(logger.clone()),
                };
                Arc::new(db_engine::Comfy::new(cfg).await.unwrap_or_else(|e| fail(e)))
            }
            other => fail(format!("unknown engine {other:?}")),
        };
        let agent = db_node::Agent::new(
            db_node::Config {
                coordinator_url: coordinator.clone(),
                tls,
                account_token: token.to_string(),
                job_kem: fs.str("kem"),
                status: None,
                logger: logger.clone(),
            },
            att.clone(),
            engine.clone(),
        );
        let hash = agent.agent_sha256();
        let short = if hash.len() > 12 { format!("{}…", hash.get(..12).unwrap_or_default()) } else { hash.to_owned() };
        logf!(logger, "provider {} (TPM {}, engine {}, agent sha256 {short})", att.provider_id(), att.mode(), engine.name());
        let stop = shutdown.clone();
        tokio::spawn(async move {
            db_cli::shutdown_signal().await;
            stop.cancel();
        });
        agent.run(shutdown).await
    });
    att.close();
    if let Err(e) = res {
        fail(e);
    }
}
