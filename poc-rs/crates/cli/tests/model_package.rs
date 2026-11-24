//! Independent model package pins flow through the actual command parser.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn tiny_pe(sections: &[(&str, &[u8])]) -> Vec<u8> {
    let mut pe = vec![0u8; 0x200 + sections.len() * 0x200];
    pe[..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe[0x86..0x88].copy_from_slice(&(sections.len() as u16).to_le_bytes());
    pe[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
    let optional = 0x98;
    pe[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    pe[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
    pe[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
    for (i, (name, data)) in sections.iter().enumerate() {
        let at = optional + 0xf0 + i * 40;
        pe[at..at + name.len()].copy_from_slice(name.as_bytes());
        pe[at + 8..at + 12].copy_from_slice(&(data.len() as u32).to_le_bytes());
        pe[at + 16..at + 20].copy_from_slice(&0x200u32.to_le_bytes());
        pe[at + 20..at + 24].copy_from_slice(&(0x200u32 + i as u32 * 0x200).to_le_bytes());
        pe[0x200 + i * 0x200..0x200 + i * 0x200 + data.len()].copy_from_slice(data);
    }
    pe
}

struct Inputs {
    dir: tempfile::TempDir,
    workflow: PathBuf,
    package: Vec<u8>,
}

impl Inputs {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        let workflow = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../nodeos/text/workflow.json");
        let model = b"GGUF independent package model";
        std::fs::write(path.join("source.gguf"), model).unwrap();
        std::fs::write(path.join("agent"), b"agent").unwrap();
        std::fs::write(path.join("shim.efi"), tiny_pe(&[(".text", b"shim")])).unwrap();
        std::fs::write(
            path.join("uki.efi"),
            tiny_pe(&[(".linux", b"kernel"), (".cmdline", b"ro nodeos.model-mode=catalog\n"), (".initrd", b"initrd")]),
        )
        .unwrap();
        let value = json!({"v":1,"domain":"darkbloom/model-package/v1","model_id":"test-model","model_sha256":hex::encode(Sha256::digest(model)),"model_size":model.len(),"image_sha256":"ab".repeat(32),"image_size":4096,"tree_sha256":"cd".repeat(32),"tree_size":4096,"verity_root":"ef".repeat(32),"workflow_sha256":hex::encode(Sha256::digest(std::fs::read(&workflow).unwrap())),"engine_version":"1:0.2.0+dfsg1-1+rex2bvdebian13.1","security_version":1});
        let mut package = serde_json::to_vec(&value).unwrap();
        package.push(b'\n');
        std::fs::write(path.join("signed-package-manifest.json"), &package).unwrap();
        Self { dir, workflow, package }
    }
    fn build(&self, with_model: bool, with_manifest: bool, output: &str) -> Output {
        let p = self.dir.path();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_dbrelease"));
        cmd.args(["build", "-version", "model-package-v1", "-shim"])
            .arg(p.join("shim.efi"))
            .arg("-uki")
            .arg(p.join("uki.efi"))
            .args(["-pcr9", &"00".repeat(32)])
            .arg("-agent")
            .arg(p.join("agent"))
            .arg("-out")
            .arg(p.join(output));
        if with_model {
            cmd.args(["-text-model-id", "test-model", "-text-model"]).arg(p.join("source.gguf")).arg("-text-workflow").arg(&self.workflow);
        }
        if with_manifest {
            cmd.arg("-text-model-manifest").arg(p.join("signed-package-manifest.json"));
        }
        cmd.output().unwrap()
    }
}

#[test]
fn cli_release_pins_model_and_exact_package_manifest() {
    let input = Inputs::new();
    let result = input.build(true, true, "release.json");
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let manifest: db_release::Manifest = db_gojson::from_slice(&std::fs::read(input.dir.path().join("release.json")).unwrap()).unwrap();
    let model = manifest.runtime.models().first().unwrap();
    assert_eq!(model.id, "test-model");
    assert_eq!(model.files().len(), 2);
    assert_eq!(model.files()[0].name, "model.gguf");
    assert_eq!(model.files()[1].name, "manifest.json");
    assert_eq!(model.files()[1].sha256, hex::encode(Sha256::digest(&input.package)));
    assert_eq!(model.files()[1].bytes, input.package.len() as i64);
    let missing = input.build(false, true, "missing.json");
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("must be supplied together"));
    let unpinned = input.build(true, false, "unpinned.json");
    assert!(!unpinned.status.success());
    assert!(String::from_utf8_lossy(&unpinned.stderr).contains("catalog mode requires exactly one model and its manifest.json pin"));
    let mut bad: serde_json::Value = serde_json::from_slice(&input.package).unwrap();
    bad["model_sha256"] = "00".repeat(32).into();
    let mut raw = serde_json::to_vec(&bad).unwrap();
    raw.push(b'\n');
    std::fs::write(input.dir.path().join("signed-package-manifest.json"), raw).unwrap();
    let mismatch = input.build(true, true, "bad.json");
    assert!(!mismatch.status.success());
    assert!(String::from_utf8_lossy(&mismatch.stderr).contains("model-package manifest"));
    assert!(!input.dir.path().join("bad.json").exists());
    std::fs::write(input.dir.path().join("uki.efi"), tiny_pe(&[(".linux", b"kernel"), (".cmdline", b"ro\n"), (".initrd", b"initrd")]))
        .unwrap();
    assert!(input.build(true, false, "legacy.json").status.success(), "legacy pinned model unexpectedly requires a package manifest");
}

#[test]
fn model_manifest_flag_requires_llama_engine_before_tpm_access() {
    let result = Command::new(env!("CARGO_BIN_EXE_dbnode"))
        .args(["run", "-engine", "fake", "-text-model-manifest", "manifest.json"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("-text-model-manifest needs -engine llama"));
}
