//! dbrelease builds, predicts and signs Darkbloom Node OS release manifests
//! ("signed trust"), and checks predictions against a live TPM.
//!
//! ```text
//! dbrelease keygen  -out keys/release
//! dbrelease predict -shim F -sdboot F -kernel F -initrd F -cmdline S [-live]
//! dbrelease predict -shim F -uki signed.efi -pcr9 LIVE_SHA256 [-live]
//! dbrelease build   -name N -version V -svn N -channel dev|production ... -out manifest.json
//! dbrelease build   ... -text-model-id ID -text-model model.gguf -text-workflow workflow.json
//! dbrelease build   ... -runtime-from reviewed-dev-manifest.json
//! dbrelease sign    -key keys/release.key -in manifest.json -out release.dsse.json
//! dbrelease verify  -pub keys/release.pub -in release.dsse.json
//! dbrelease inspect-log -in /sys/kernel/security/tpm0/binary_bios_measurements
//! ```

#![forbid(unsafe_code)]

use db_cli::goflag::FlagSet;
use db_cli::{cli_args, die, proc_cmdline};
use db_gojson::GoTime;
use db_release::{Artifact, Boot, Manifest, Platform, Prediction, Runtime, TrustedKeys};
use db_tpm2::HashAlg;
use db_tpmattest::eventlog as el;
use sha2::Digest as _;
use std::path::Path;

const TOOL: &str = "dbrelease";

fn fail(msg: impl std::fmt::Display) -> ! {
    die(TOOL, msg)
}

fn main() {
    // No TLS here today; the same process-wide provider as the other tools.
    db_tls::install_default_provider();
    let args = cli_args();
    let Some((cmd, rest)) = args.split_first() else {
        fail("usage: dbrelease keygen|predict|build|sign|verify|inspect-log [flags]");
    };
    match cmd.as_str() {
        "keygen" => keygen(rest),
        "predict" => predict(rest),
        "build" => build(rest),
        "sign" => sign(rest),
        "verify" => verify(rest),
        "inspect-log" => inspect_log(rest),
        other => fail(format!("unknown command {other:?}")),
    }
}

fn keygen(args: &[String]) {
    let mut fs = FlagSet::new("keygen");
    fs.string("out", "release", "key file prefix (<out>.key, <out>.pub)");
    fs.parse_or_exit(args);
    let out = fs.str("out");
    let public = db_release::generate_key(&out).unwrap_or_else(|e| fail(e));
    println!("key id {} written to {out}.key / {out}.pub", db_release::key_id(&public));
}

fn add_boot_flags(fs: &mut FlagSet) {
    fs.string("shim", "/usr/lib/shim/shimx64.efi.signed", "shim EFI binary")
        .string("sdboot", "/usr/lib/systemd/boot/efi/systemd-bootx64.efi.signed", "systemd-boot EFI binary")
        .string("uki", "", "signed single-profile UKI (direct shim -> UKI boot)")
        .string("kernel", "", "kernel image (EFI stub PE)")
        .string("initrd", "", "initrd image")
        .string("cmdline", "", "kernel command line (load options) exactly as booted")
        .string("pcr9", "", "observed SHA-256 PCR 9 for UKI boot; must come from the target's measured boot")
        .boolean("cmdline-from-proc", false, "use /proc/cmdline (this machine's current boot)");
}

struct BootResult {
    apps: Vec<Artifact>,
    pcr4: [u8; 32],
    pred: Prediction,
    pcr11: String,
    uki_sections: Option<Vec<Artifact>>,
    path: String,
}

fn compute_boot(fs: &FlagSet) -> BootResult {
    let uki = fs.str("uki");
    if !uki.is_empty() {
        if !fs.str("kernel").is_empty() || !fs.str("initrd").is_empty() || !fs.str("cmdline").is_empty() || fs.bool("cmdline-from-proc") {
            fail("-uki embeds its own kernel, initrd and cmdline; do not pass -kernel, -initrd or -cmdline");
        }
        let data = std::fs::read(&uki).unwrap_or_else(|e| fail(format!("{uki}: {e}")));
        let measured = db_release::uki_sections(&data).unwrap_or_else(|e| fail(e));
        let cmd = measured.iter().find(|(a, _)| a.name == ".cmdline").map(|(_, d)| d).unwrap_or_else(|| fail("UKI has no .cmdline"));
        let cmdline = std::str::from_utf8(cmd).unwrap_or_else(|_| fail("UKI .cmdline is not UTF-8")).to_owned();
        if cmdline.contains('\0') {
            fail("UKI .cmdline contains NUL; this simple profile cannot safely describe it");
        }
        let initrd_sha256 =
            measured.iter().find(|(a, _)| a.name == ".initrd").map(|(a, _)| a.sha256.clone()).unwrap_or_else(|| fail("UKI has no .initrd"));
        let section_artifacts: Vec<Artifact> = measured.into_iter().map(|(a, _)| a).collect();
        let pcr11 = hex::encode(db_release::predict_pcr11(&section_artifacts).unwrap_or_else(|e| fail(e)));
        let pcr9 = fs.str("pcr9");
        if !db_release::is_sha256_hex(&pcr9) {
            fail("-pcr9 is required for UKI and must be 64 hex characters from the target's TPM");
        }
        let mut apps = Vec::new();
        let mut digests = Vec::new();
        for (name, path, bytes) in [("shimx64.efi", fs.str("shim"), None), ("uki", uki, Some(data))] {
            let bytes = bytes.unwrap_or_else(|| std::fs::read(&path).unwrap_or_else(|e| fail(format!("{path}: {e}"))));
            let d = db_release::authenticode_digest(&bytes, HashAlg::Sha256).unwrap_or_else(|e| fail(format!("{path}: {e}")));
            apps.push(Artifact { name: name.to_owned(), sha256: hex::encode(&d), bytes: bytes.len() as i64 });
            digests.push(d);
        }
        let pcr4 = db_release::predict_pcr4(&digests);
        return BootResult {
            apps,
            pcr4,
            pred: Prediction {
                load_options: cmdline.clone(),
                load_options_sha256: hex::encode(sha2::Sha256::digest(cmdline.as_bytes())),
                initrd_sha256,
                pcr9_sha256: pcr9.to_lowercase(),
                pcr12_sha256: "0".repeat(64),
            },
            pcr11,
            uki_sections: Some(section_artifacts),
            path: "uki".to_owned(),
        };
    }
    let mut cmdline = fs.str("cmdline");
    if fs.bool("cmdline-from-proc") {
        cmdline = proc_cmdline().unwrap_or_else(|e| fail(e));
    }
    let (kernel, initrd) = (fs.str("kernel"), fs.str("initrd"));
    if kernel.is_empty() || initrd.is_empty() || cmdline.is_empty() {
        fail("-kernel, -initrd and -cmdline (or -cmdline-from-proc) are required");
    }
    let mut apps = Vec::new();
    let mut digests = Vec::new();
    for (name, path) in [("shimx64.efi", fs.str("shim")), ("systemd-bootx64.efi", fs.str("sdboot")), ("linux", kernel)] {
        let data = std::fs::read(&path).unwrap_or_else(|e| fail(format!("{path}: {e}")));
        let d = db_release::authenticode_digest(&data, HashAlg::Sha256).unwrap_or_else(|e| fail(format!("{path}: {e}")));
        apps.push(Artifact { name: name.to_owned(), sha256: hex::encode(&d), bytes: data.len() as i64 });
        digests.push(d);
    }
    let pcr4 = db_release::predict_pcr4(&digests);
    let (initrd_sum, _) = db_release::file_sha256(Path::new(&initrd)).unwrap_or_else(|e| fail(e));
    BootResult {
        apps,
        pcr4,
        pred: db_release::predict(&cmdline, &initrd_sum),
        pcr11: String::new(),
        uki_sections: None,
        path: "type1-amd-signed-chain".to_owned(),
    }
}

fn live_pcr(i: u32) -> String {
    std::fs::read_to_string(format!("/sys/class/tpm/tpm0/pcr-sha256/{i}")).map(|s| s.trim().to_lowercase()).unwrap_or_default()
}

fn predict(args: &[String]) {
    let mut fs = FlagSet::new("predict");
    add_boot_flags(&mut fs);
    fs.boolean("live", false, "compare with this machine's TPM (sysfs, no root needed)");
    fs.parse_or_exit(args);
    let r = compute_boot(&fs);
    for (i, a) in r.apps.iter().enumerate() {
        println!("boot app {}  {:<20} authenticode sha256 {}", i + 1, a.name, a.sha256);
    }
    println!("initrd sha256         {}", r.pred.initrd_sha256);
    println!("load options sha256   {}", r.pred.load_options_sha256);
    let mut rows = vec![
        (4, hex::encode(r.pcr4), if r.path == "uki" { "boot chain (shim, UKI)" } else { "boot chain (shim, systemd-boot, kernel)" }),
        (
            9,
            r.pred.pcr9_sha256.clone(),
            if r.path == "uki" { "observed Linux EFI stub PCR 9" } else { "kernel EFI stub: load options, initrd" },
        ),
        (12, r.pred.pcr12_sha256.clone(), if r.path == "uki" { "no UKI overrides or addons" } else { "systemd-boot: kernel command line" }),
    ];
    if r.path == "uki" {
        rows.push((11, r.pcr11.clone(), "UKI section names and VirtualSize data"));
    }
    let live = fs.bool("live");
    let mut ok = true;
    for (pcr, pred, what) in rows {
        let source = if r.path == "uki" && pcr == 9 { "observed " } else { "predicted" };
        let mut line = format!("PCR {pcr:<2} {source} {pred}  ({what})");
        if live {
            let l = live_pcr(pcr);
            let matched = l == pred;
            ok &= matched;
            line.push_str(&format!("\n       live TPM  {l}  {}", if matched { "MATCH" } else { "MISMATCH" }));
        }
        println!("{line}");
    }
    if live && !ok {
        std::process::exit(2);
    }
}

/// The Go flag parser does not expose whether a flag was explicitly supplied.
/// Walk its accepted syntax so an empty conflicting flag is still rejected,
/// without mistaking a flag-shaped value for a second flag.
fn explicit_flag(args: &[String], name: &str) -> bool {
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        let Some(raw) = arg.strip_prefix('-') else { break };
        let raw = raw.strip_prefix('-').unwrap_or(raw);
        if raw.is_empty() {
            break;
        }
        let (flag, inline) = raw.split_once('=').map_or((raw, false), |(flag, _)| (flag, true));
        if flag == name {
            return true;
        }
        i += 1;
        if !inline && !matches!(flag, "cmdline-from-proc" | "require-boot-health") {
            i += 1;
        }
    }
    false
}

fn complete_runtime(runtime: &Runtime) -> Result<(), String> {
    let pinned = |a: &Artifact, what: &str| {
        if a.name.is_empty() || a.bytes <= 0 || !db_release::is_sha256_hex(&a.sha256) {
            Err(format!("{what} must have a name, positive byte size and SHA-256 pin"))
        } else {
            Ok(())
        }
    };
    pinned(&runtime.agent, "runtime agent")?;
    if runtime.engine.name.is_empty() {
        return Err("runtime engine identity is required".to_owned());
    }
    if runtime.engine.bytes != 0 || !runtime.engine.sha256.is_empty() {
        pinned(&runtime.engine, "runtime engine")?;
    }
    let workflows = runtime.workflows.as_deref().ok_or("runtime workflows are required")?;
    if workflows.is_empty() {
        return Err("runtime workflows are required".to_owned());
    }
    for workflow in workflows {
        pinned(workflow, "runtime workflow")?;
    }
    let models = runtime.models.as_deref().ok_or("runtime models are required")?;
    if models.is_empty() {
        return Err("runtime models are required".to_owned());
    }
    for model in models {
        if model.id.is_empty() || model.kind.is_empty() {
            return Err("runtime model ID and kind are required".to_owned());
        }
        let files = model.files.as_deref().ok_or("runtime model files are required")?;
        if files.is_empty() {
            return Err("runtime model files are required".to_owned());
        }
        for file in files {
            pinned(file, "runtime model file")?;
        }
    }
    Ok(())
}

fn runtime_from_template(path: &str) -> Result<Runtime, String> {
    let raw = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let template: Manifest = db_gojson::from_slice(&raw).map_err(|e| format!("{path}: {e}"))?;
    template.validate().map_err(|e| format!("{path}: invalid reviewed template: {e}"))?;
    if template.channel != "dev" || template.boot.path != "uki" {
        return Err("-runtime-from requires a reviewed dev UKI manifest template".to_owned());
    }
    complete_runtime(&template.runtime)?;
    Ok(template.runtime)
}

fn require_production_uki_eventlog(boot_path: &str, channel: &str, platform_log: &str) -> Result<(), &'static str> {
    if boot_path == "uki" && channel == "production" && platform_log.is_empty() {
        return Err(
            "production UKI release requires -platform-eventlog from the reviewed target boot to verify PCR 4/9/11/12 and pin PCR 0/7/14",
        );
    }
    Ok(())
}

fn build(args: &[String]) {
    let mut fs = FlagSet::new("build");
    add_boot_flags(&mut fs);
    fs.string("name", "darkbloom-nodeos", "release name")
        .string("version", "", "release version")
        .uint("svn", 1, "security version (monotonic)")
        .string("channel", "dev", "dev or production")
        .int("valid-days", 30, "validity")
        .string("agent", "", "agent binary to pin (sha256)")
        .string("engine", "", "engine identity, e.g. comfyui@<commit>")
        .string("models-dir", "", "ComfyUI model roots (comma separated) to hash approved models from")
        .string("hash-cache", "", "model hash cache")
        .string("text-model-id", "", "text model ID published to consumers")
        .string("text-model", "", "GGUF text model file to stream-hash and pin")
        .string("text-workflow", "", "reviewed llama.cpp text workflow JSON to hash and pin")
        .string("runtime-from", "", "operator-reviewed dev UKI manifest supplying only its pinned runtime")
        .boolean("require-boot-health", false, "require a clean bounded pre-admission boot health report")
        .string("notes", "", "release notes")
        .string("min-bios", "LFGB0.03.03", "minimum S-CRTM (BIOS) version, empty for none")
        .string(
            "platform-eventlog",
            "",
            "reference machine's firmware event log (binary_bios_measurements) to pin PCR 0, 7 and 14 (required for production)",
        )
        .string("out", "manifest.json", "output");
    fs.parse_or_exit(args);
    let runtime_from = fs.str("runtime-from");
    if explicit_flag(args, "runtime-from") {
        if runtime_from.is_empty() {
            fail("-runtime-from requires a manifest file");
        }
        if fs.str("uki").is_empty() {
            fail("-runtime-from requires -uki so the target boot is independently measured");
        }
        if let Some(flag) = ["agent", "engine", "models-dir", "hash-cache", "text-model-id", "text-model", "text-workflow"]
            .into_iter()
            .find(|name| explicit_flag(args, name))
        {
            fail(format!("-runtime-from cannot be combined with -{flag}"));
        }
    }
    let runtime_template = (!runtime_from.is_empty()).then(|| runtime_from_template(&runtime_from).unwrap_or_else(|e| fail(e)));
    let version = fs.str("version");
    if version.is_empty() {
        fail("-version is required");
    }
    let r = compute_boot(&fs);
    let now = GoTime::now_utc().truncate_secs();
    let svn = u32::try_from(fs.uint_value("svn")).unwrap_or_else(|_| fail("-svn out of range"));
    let mut m = Manifest {
        schema: db_release::SCHEMA.to_owned(),
        name: fs.str("name"),
        version,
        svn,
        channel: fs.str("channel"),
        issued_at: now,
        expires_at: now.add(chrono::Duration::days(fs.int_value("valid-days"))),
        notes: fs.str("notes"),
        platform: Platform {
            products: Some(vec![if r.path == "uki" { "AMD Ryzen AI Halo (RAH-002)" } else { "AMD Ryzen AI Halo (RAH-001)" }.to_owned()]),
            min_scrtm_version: fs.str("min-bios"),
        },
        boot: Boot {
            path: r.path,
            boot_apps: Some(r.apps),
            pcr4_sha256: hex::encode(r.pcr4),
            load_options: r.pred.load_options,
            load_options_sha256: r.pred.load_options_sha256,
            initrd_sha256: r.pred.initrd_sha256,
            pcr9_sha256: r.pred.pcr9_sha256,
            pcr12_sha256: r.pred.pcr12_sha256,
            pcr11_sha256: r.pcr11,
            uki_sections: r.uki_sections,
            ..Boot::default()
        },
        ..Manifest::default()
    };
    if let Some(runtime) = runtime_template {
        m.runtime = runtime;
    }
    let platform_log = fs.str("platform-eventlog");
    m.requires.boot_health = fs.bool("require-boot-health");
    require_production_uki_eventlog(&m.boot.path, &m.channel, &platform_log).unwrap_or_else(|e| fail(e));
    if !platform_log.is_empty() {
        let raw = std::fs::read(&platform_log).unwrap_or_else(|e| fail(format!("{platform_log}: {e}")));
        let elog = el::parse_event_log(&raw).unwrap_or_else(|e| fail(format!("platform event log: {e}")));
        let pcrs = elog.replay(el::ALG_SHA256, &[0, 7, 14]).unwrap_or_else(|e| fail(format!("platform event log: {e}")));
        let get = |p: u32| pcrs.get(&p).map(hex::encode).unwrap_or_default();
        m.boot.pcr0_sha256 = get(0);
        m.boot.pcr7_sha256 = get(7);
        m.boot.pcr14_sha256 = get(14);
        if m.boot.path == "uki" {
            let observed = elog.replay(el::ALG_SHA256, &[4, 9, 11, 12]).unwrap_or_else(|e| fail(format!("boot event log: {e}")));
            for (pcr, want) in
                [(4u32, &m.boot.pcr4_sha256), (9, &m.boot.pcr9_sha256), (11, &m.boot.pcr11_sha256), (12, &m.boot.pcr12_sha256)]
            {
                if observed.get(&pcr).map(hex::encode).as_deref() != Some(want.as_str()) {
                    fail(format!("reference event log PCR {pcr} does not match signed UKI release; capture a log from this boot"));
                }
            }
        }
    }
    let agent = fs.str("agent");
    if !agent.is_empty() {
        let (sum, n) = db_release::file_sha256(Path::new(&agent)).unwrap_or_else(|e| fail(e));
        m.runtime.agent = Artifact { name: "dbnode".to_owned(), sha256: hex::encode(sum), bytes: n as i64 };
    }
    let engine = fs.str("engine");
    if !engine.is_empty() {
        m.runtime.engine = Artifact { name: engine, ..Artifact::default() };
    }
    let models_dir = fs.str("models-dir");
    let text_model_id = fs.str("text-model-id");
    let text_model = fs.str("text-model");
    let text_workflow = fs.str("text-workflow");
    let text_requested = !text_model_id.is_empty() || !text_model.is_empty() || !text_workflow.is_empty();
    if text_requested {
        if text_model_id.is_empty() || text_model.is_empty() || text_workflow.is_empty() {
            fail("-text-model-id, -text-model and -text-workflow must be supplied together");
        }
        if !models_dir.is_empty() {
            fail("-models-dir cannot be combined with text model flags");
        }
        if !m.runtime.engine.name.is_empty() && m.runtime.engine.name != "llama.cpp" {
            fail("-engine must be llama.cpp for a text model release");
        }
        eprintln!("hashing approved GGUF text model and workflow...");
        let (workflows, models) =
            db_engine::llama_release(&text_model_id, Path::new(&text_model), Path::new(&text_workflow)).unwrap_or_else(|e| fail(e));
        m.runtime.engine = Artifact { name: "llama.cpp".to_owned(), ..Artifact::default() };
        m.runtime.workflows = Some(workflows);
        m.runtime.models = Some(models);
    }
    if !models_dir.is_empty() {
        eprintln!("hashing approved model weights (cached by size+mtime)...");
        let dirs: Vec<std::path::PathBuf> = models_dir.split(',').map(std::path::PathBuf::from).collect();
        let cache = fs.str("hash-cache");
        let cache = (!cache.is_empty()).then(|| std::path::PathBuf::from(cache));
        let (wfs, models) = db_engine::comfy_release(&dirs, cache.as_deref()).unwrap_or_else(|e| fail(e));
        m.runtime.workflows = (!wfs.is_empty()).then_some(wfs);
        m.runtime.models = (!models.is_empty()).then_some(models);
    }
    if let Err(e) = m.validate() {
        fail(e);
    }
    let out = fs.str("out");
    let body = db_gojson::to_vec_indent(&m).unwrap_or_else(|e| fail(e));
    std::fs::write(&out, body).unwrap_or_else(|e| fail(format!("{out}: {e}")));
    println!(
        "wrote {out}: {} PCR4={}… PCR9={}… PCR12={}…{}",
        m.id(),
        m.boot.pcr4_sha256.get(..12).unwrap_or_default(),
        m.boot.pcr9_sha256.get(..12).unwrap_or_default(),
        m.boot.pcr12_sha256.get(..12).unwrap_or_default(),
        if m.boot.path == "uki" { format!(" PCR11={}…", m.boot.pcr11_sha256.get(..12).unwrap_or_default()) } else { String::new() }
    );
}

fn sign(args: &[String]) {
    let mut fs = FlagSet::new("sign");
    fs.string("key", "", "release signing key").string("in", "manifest.json", "manifest").string(
        "out",
        "release.dsse.json",
        "signed envelope",
    );
    fs.parse_or_exit(args);
    let key = db_release::load_private_key(Path::new(&fs.str("key"))).unwrap_or_else(|e| fail(e));
    let input = fs.str("in");
    let raw = std::fs::read(&input).unwrap_or_else(|e| fail(format!("{input}: {e}")));
    let m: Manifest = db_gojson::from_slice(&raw).unwrap_or_else(|e| fail(e));
    let env = db_release::sign_manifest(&m, &key).unwrap_or_else(|e| fail(e));
    let out = fs.str("out");
    std::fs::write(&out, db_gojson::to_vec(&env).unwrap_or_else(|e| fail(e))).unwrap_or_else(|e| fail(format!("{out}: {e}")));
    let keyid = env.signatures.first().map(|s| s.keyid.clone()).unwrap_or_default();
    println!("signed {} with key {keyid} -> {out}", m.id());
}

fn verify(args: &[String]) {
    let mut fs = FlagSet::new("verify");
    fs.string("pub", "", "release public key").string("in", "release.dsse.json", "signed envelope");
    fs.parse_or_exit(args);
    let public = db_release::load_public_key(Path::new(&fs.str("pub"))).unwrap_or_else(|e| fail(e));
    let input = fs.str("in");
    let raw = std::fs::read(&input).unwrap_or_else(|e| fail(format!("{input}: {e}")));
    let env: db_release::Envelope = db_gojson::from_slice(&raw).unwrap_or_else(|e| fail(e));
    let keys: TrustedKeys = [(db_release::key_id(&public), public)].into_iter().collect();
    let m = db_release::open_manifest(&env, &keys, 1).unwrap_or_else(|e| fail(e));
    println!("OK {} (channel {}) PCR4={} PCR9={} PCR12={}", m.id(), m.channel, m.boot.pcr4_sha256, m.boot.pcr9_sha256, m.boot.pcr12_sha256);
}

fn event_name(t: u32) -> String {
    let name = match t {
        el::EV_PREBOOT_CERT => "EV_PREBOOT_CERT",
        el::EV_POST_CODE => "EV_POST_CODE",
        el::EV_NO_ACTION => "EV_NO_ACTION",
        el::EV_SEPARATOR => "EV_SEPARATOR",
        el::EV_ACTION => "EV_ACTION",
        el::EV_EVENT_TAG => "EV_EVENT_TAG",
        el::EV_SCRTM_CONTENTS => "EV_S_CRTM_CONTENTS",
        el::EV_SCRTM_VERSION => "EV_S_CRTM_VERSION",
        el::EV_CPU_MICROCODE => "EV_CPU_MICROCODE",
        el::EV_PLATFORM_CONFIG_FLAGS => "EV_PLATFORM_CONFIG_FLAGS",
        el::EV_TABLE_OF_DEVICES => "EV_TABLE_OF_DEVICES",
        el::EV_IPL => "EV_IPL",
        el::EV_NONHOST_CODE => "EV_NONHOST_CODE",
        el::EV_NONHOST_CONFIG => "EV_NONHOST_CONFIG",
        el::EV_NONHOST_INFO => "EV_NONHOST_INFO",
        el::EV_EFI_VARIABLE_DRIVER_CONFIG => "EV_EFI_VARIABLE_DRIVER_CONFIG",
        el::EV_EFI_VARIABLE_BOOT => "EV_EFI_VARIABLE_BOOT",
        el::EV_EFI_BOOT_SERVICES_APPLICATION => "EV_EFI_BOOT_SERVICES_APPLICATION",
        el::EV_EFI_BOOT_SERVICES_DRIVER => "EV_EFI_BOOT_SERVICES_DRIVER",
        el::EV_EFI_RUNTIME_SERVICES_DRIVER => "EV_EFI_RUNTIME_SERVICES_DRIVER",
        el::EV_EFI_GPT_EVENT => "EV_EFI_GPT_EVENT",
        el::EV_EFI_ACTION => "EV_EFI_ACTION",
        el::EV_EFI_PLATFORM_FIRMWARE_BLOB => "EV_EFI_PLATFORM_FIRMWARE_BLOB",
        el::EV_EFI_HANDOFF_TABLES => "EV_EFI_HANDOFF_TABLES",
        el::EV_EFI_PLATFORM_FIRMWARE_BLOB2 => "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
        el::EV_EFI_HANDOFF_TABLES2 => "EV_EFI_HANDOFF_TABLES2",
        el::EV_EFI_VARIABLE_BOOT2 => "EV_EFI_VARIABLE_BOOT2",
        el::EV_EFI_HCRTM_EVENT => "EV_EFI_HCRTM_EVENT",
        el::EV_EFI_VARIABLE_AUTHORITY => "EV_EFI_VARIABLE_AUTHORITY",
        _ => return format!("0x{t:08x}"),
    };
    name.to_owned()
}

/// Prints a structural summary of a TCG event log. PCR 1, 5 and 6 contents
/// can be device-specific (boot entries, GPT), so only their event types are
/// shown.
fn inspect_log(args: &[String]) {
    let mut fs = FlagSet::new("inspect-log");
    fs.string("in", "/sys/kernel/security/tpm0/binary_bios_measurements", "event log");
    fs.parse_or_exit(args);
    let input = fs.str("in");
    let raw = std::fs::read(&input).unwrap_or_else(|e| fail(format!("{input}: {e}")));
    let l = el::parse_event_log(&raw).unwrap_or_else(|e| fail(e));
    let banks: Vec<String> = l.digest_sizes.iter().map(|(alg, size)| format!("0x{alg:04x}/{size}B")).collect();
    println!(
        "{} bytes, {} events, banks [{}], startup locality {}, spec errata {}",
        raw.len(),
        l.events.len(),
        banks.join(" "),
        l.startup_locality,
        l.spec_errata
    );
    let wanted = db_tpmattest::DEFAULT_PCRS;
    let pcrs = l.replay(el::ALG_SHA256, &wanted).unwrap_or_else(|e| fail(e));
    for p in wanted {
        println!("\nPCR {p} replay {}", pcrs.get(&p).map(hex::encode).unwrap_or_default());
        let mut sep = false;
        for ev in l.events_for(p) {
            let detail = if matches!(p, 1 | 5 | 6) {
                "(device-specific detail omitted)".to_owned()
            } else {
                match ev.event_type {
                    el::EV_EFI_VARIABLE_DRIVER_CONFIG | el::EV_EFI_VARIABLE_AUTHORITY => match el::parse_uefi_variable(&ev.data) {
                        Ok(v) => {
                            let val = match v.data.as_slice() {
                                [b] => format!("value {b}"),
                                d => format!("{} bytes", d.len()),
                            };
                            format!("{} ({val}) spec-digest={}", v.name, ev.verify_data_digest(el::ALG_SHA256))
                        }
                        Err(_) => String::new(),
                    },
                    el::EV_SCRTM_VERSION => {
                        format!("{:?} digest-matches-data={}", el::decode_utf16(&ev.data), ev.verify_data_digest(el::ALG_SHA256))
                    }
                    el::EV_EFI_ACTION | el::EV_IPL | el::EV_ACTION => {
                        let d = String::from_utf8_lossy(&ev.data).trim_end_matches('\0').to_owned();
                        let shown: String = d.chars().take(60).collect();
                        if shown.len() < d.len() { format!("{:?}", format!("{shown}…")) } else { format!("{d:?}") }
                    }
                    el::EV_EVENT_TAG => el::parse_tagged_event(&ev.data).map(|t| format!("tag 0x{:08x}", t.id)).unwrap_or_default(),
                    el::EV_EFI_BOOT_SERVICES_APPLICATION => format!(
                        "authenticode {}…",
                        hex::encode(ev.digests.get(&el::ALG_SHA256).and_then(|d| d.get(..8)).unwrap_or_default())
                    ),
                    el::EV_SEPARATOR => format!("data {}", hex::encode(&ev.data)),
                    _ => String::new(),
                }
            };
            let after = if sep && ev.event_type != el::EV_SEPARATOR { " [after separator]" } else { "" };
            if ev.event_type == el::EV_SEPARATOR {
                sep = true;
            }
            println!("  #{:<3} {:<34} {detail}{after}", ev.index, event_name(ev.event_type));
        }
    }
}
