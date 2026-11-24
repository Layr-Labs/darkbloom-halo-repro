//! The Mac release builder may reuse reviewed Halo runtime pins while it
//! independently measures the signed production UKI and reference event log.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use db_gojson::GoTime;
use db_release::{Artifact, Boot, Manifest, Model, Runtime};
use sha2::{Digest as _, Sha256};
use std::path::Path;
use std::process::Command;

fn artifact(name: &str, data: &[u8]) -> Artifact {
    Artifact { name: name.to_owned(), sha256: hex::encode(Sha256::digest(data)), bytes: data.len() as i64 }
}

fn reviewed_template() -> Manifest {
    let cmdline = "root=/dev/mapper/root ro lockdown=confidentiality\n";
    let sections = vec![artifact(".linux", b"kernel"), artifact(".cmdline", cmdline.as_bytes()), artifact(".initrd", b"initrd")];
    let digests = vec![vec![0x11u8; 32], vec![0x22u8; 32]];
    let now = GoTime::now_utc().truncate_secs();
    Manifest {
        schema: db_release::SCHEMA.to_owned(),
        name: "reviewed-dev-template".to_owned(),
        version: "preboot".to_owned(),
        svn: 1,
        channel: "dev".to_owned(),
        issued_at: now,
        expires_at: now.add(chrono::Duration::days(1)),
        notes: "reviewed template notes must not carry over".to_owned(),
        requires: db_release::Requires { cmdline_flags: vec!["template-only-flag".to_owned()], ..Default::default() },
        boot: Boot {
            path: "uki".to_owned(),
            boot_apps: Some(vec![
                Artifact { name: "shimx64.efi".to_owned(), sha256: hex::encode(&digests[0]), bytes: 1 },
                Artifact { name: "uki".to_owned(), sha256: hex::encode(&digests[1]), bytes: 1 },
            ]),
            pcr4_sha256: hex::encode(db_release::predict_pcr4(&digests)),
            load_options: cmdline.to_owned(),
            load_options_sha256: sections[1].sha256.clone(),
            initrd_sha256: sections[2].sha256.clone(),
            pcr9_sha256: "00".repeat(32),
            pcr12_sha256: "00".repeat(32),
            pcr11_sha256: hex::encode(db_release::predict_pcr11(&sections).unwrap()),
            uki_sections: Some(sections),
            ..Boot::default()
        },
        runtime: Runtime {
            agent: artifact("dbnode", b"actual-node-binary"),
            engine: Artifact { name: "llama.cpp".to_owned(), ..Artifact::default() },
            workflows: Some(vec![artifact("llama-text-greedy-v1", b"reviewed workflow")]),
            models: Some(vec![Model {
                id: "qwen3".to_owned(),
                kind: "text".to_owned(),
                files: Some(vec![artifact("model.gguf", b"GGUF test bytes")]),
            }]),
        },
        ..Manifest::default()
    }
}

fn tiny_pe(sections: &[(&str, &[u8])]) -> Vec<u8> {
    let mut pe = vec![0u8; 0x200 + sections.len() * 0x200];
    pe[..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe[0x84 + 2..0x84 + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
    pe[0x84 + 16..0x84 + 18].copy_from_slice(&0xf0u16.to_le_bytes());
    let optional = 0x84 + 20;
    pe[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    pe[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
    pe[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
    let table = optional + 0xf0;
    for (i, (name, content)) in sections.iter().enumerate() {
        let at = table + i * 40;
        pe[at..at + name.len()].copy_from_slice(name.as_bytes());
        pe[at + 8..at + 12].copy_from_slice(&(content.len() as u32).to_le_bytes());
        pe[at + 16..at + 20].copy_from_slice(&0x200u32.to_le_bytes());
        pe[at + 20..at + 24].copy_from_slice(&(0x200u32 + i as u32 * 0x200).to_le_bytes());
        pe[0x200 + i * 0x200..0x200 + i * 0x200 + content.len()].copy_from_slice(content);
    }
    pe
}

fn path(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

#[test]
fn reviewed_runtime_is_copied_but_new_uki_is_measured() {
    let dir = tempfile::tempdir().unwrap();
    let template = reviewed_template();
    template.validate().unwrap();
    let input = dir.path().join("reviewed.json");
    let output = dir.path().join("new.json");
    let shim = dir.path().join("shim.efi");
    let uki = dir.path().join("new.efi");
    std::fs::write(&input, db_gojson::to_vec_indent(&template).unwrap()).unwrap();
    std::fs::write(&shim, tiny_pe(&[(".text", b"shim")])).unwrap();
    std::fs::write(&uki, tiny_pe(&[(".linux", b"new kernel"), (".cmdline", b"root=/dev/mapper/root ro\n"), (".initrd", b"new initrd")]))
        .unwrap();
    let bin = env!("CARGO_BIN_EXE_dbrelease");
    let base = [
        "build",
        "-version",
        "production-candidate",
        "-shim",
        &path(&shim),
        "-uki",
        &path(&uki),
        "-pcr9",
        &"33".repeat(32),
        "-runtime-from",
        &path(&input),
        "-out",
        &path(&output),
    ];
    let dev = Command::new(bin).args(base).output().unwrap();
    assert!(dev.status.success(), "{}", String::from_utf8_lossy(&dev.stderr));
    let built: Manifest = db_gojson::from_slice(&std::fs::read(&output).unwrap()).unwrap();
    assert_eq!(built.runtime, template.runtime);
    assert_ne!(built.boot.pcr4_sha256, template.boot.pcr4_sha256);
    assert_ne!(built.boot.pcr9_sha256, template.boot.pcr9_sha256);
    assert_ne!(built.boot.pcr11_sha256, template.boot.pcr11_sha256);
    assert_eq!(built.boot.path, "uki");
    assert_ne!(built.name, template.name);
    assert_ne!(built.notes, template.notes);
    assert!(built.requires.cmdline_flags.is_empty());
    let production = Command::new(bin).args(base).args(["-channel", "production"]).output().unwrap();
    assert!(!production.status.success());
    assert!(String::from_utf8_lossy(&production.stderr).contains("production UKI release requires -platform-eventlog"));
    for conflict in ["agent", "engine", "models-dir", "hash-cache", "text-model-id", "text-model", "text-workflow"] {
        let failed = Command::new(bin).args(base).arg(format!("-{conflict}")).arg("").output().unwrap();
        assert!(!failed.status.success(), "-{conflict} should conflict even when empty");
        assert!(String::from_utf8_lossy(&failed.stderr).contains(&format!("cannot be combined with -{conflict}")));
    }
}

#[test]
fn incomplete_runtime_template_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("incomplete.json");
    let mut template = reviewed_template();
    template.runtime.models.as_mut().unwrap()[0].files.as_mut().unwrap()[0].sha256.clear();
    // The generic schema permits an absent hash; template reuse does not.
    template.validate().unwrap();
    std::fs::write(&input, db_gojson::to_vec_indent(&template).unwrap()).unwrap();
    let failed = Command::new(env!("CARGO_BIN_EXE_dbrelease"))
        .args(["build", "-version", "v", "-uki", "missing.efi", "-runtime-from", &path(&input)])
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("runtime model file must have a name, positive byte size and SHA-256 pin"));
    let no_uki =
        Command::new(env!("CARGO_BIN_EXE_dbrelease")).args(["build", "-version", "v", "-runtime-from", &path(&input)]).output().unwrap();
    assert!(!no_uki.status.success());
    assert!(String::from_utf8_lossy(&no_uki.stderr).contains("-runtime-from requires -uki"));
}
