//! Ports of the Go release tests (release_test.go, robust_test.go).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use super::*;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use db_gojson::GoTime;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

fn new_key() -> SigningKey {
    SigningKey::from_bytes(&random_bytes::<32>().unwrap())
}

fn trusted(keys: &[&SigningKey]) -> TrustedKeys {
    keys.iter().map(|k| (key_id(&k.verifying_key()), k.verifying_key())).collect()
}

#[test]
fn predict_matches_spec() {
    // PCR 12 = H(0 || H(utf16le(cmdline) || 0x0000)); PCR 9 = H(H(0 || lo) || H(initrd)).
    let cmd = "root=PARTLABEL=x ro quiet";
    let initrd: [u8; 32] = Sha256::digest(b"initrd").into();
    let p = predict(cmd, &initrd);
    let mut u16le = Vec::new();
    for c in cmd.bytes() {
        u16le.extend_from_slice(&[c, 0]);
    }
    u16le.extend_from_slice(&[0, 0]);
    let lo = Sha256::digest(&u16le);
    assert_eq!(p.load_options_sha256, hex::encode(lo));
    let mut z = vec![0u8; 32];
    z.extend_from_slice(&lo);
    let pcr12 = Sha256::digest(&z);
    assert_eq!(p.pcr12_sha256, hex::encode(pcr12));
    let mut x = pcr12.to_vec();
    x.extend_from_slice(&initrd);
    assert_eq!(p.pcr9_sha256, hex::encode(Sha256::digest(&x)));
}

pub(crate) fn test_manifest(svn: u32) -> Manifest {
    let apps = vec![vec![0u8; 32], vec![0u8; 32], vec![0u8; 32]];
    let p = predict("root=PARTLABEL=x", &[0u8; 32]);
    let now = GoTime::now_utc();
    Manifest {
        schema: SCHEMA.to_owned(),
        name: "n".to_owned(),
        version: "v".to_owned(),
        svn,
        channel: "production".to_owned(),
        issued_at: now.add(chrono::Duration::minutes(-1)),
        expires_at: now.add(chrono::Duration::hours(1)),
        boot: Boot {
            boot_apps: Some(
                ["a", "b", "c"]
                    .iter()
                    .zip(&apps)
                    .map(|(n, d)| Artifact { name: (*n).to_owned(), sha256: hex::encode(d), bytes: 0 })
                    .collect(),
            ),
            pcr4_sha256: hex::encode(predict_pcr4(&apps)),
            load_options: p.load_options,
            load_options_sha256: p.load_options_sha256,
            initrd_sha256: p.initrd_sha256,
            pcr9_sha256: p.pcr9_sha256,
            pcr12_sha256: p.pcr12_sha256,
            pcr7_sha256: hex::encode(&apps[0]),
            pcr14_sha256: hex::encode(&apps[1]),
            ..Boot::default()
        },
        ..Manifest::default()
    }
}

#[test]
fn signed_trust_policy() {
    let key = new_key();
    let other = new_key();
    let keys = trusted(&[&key]);
    let m = test_manifest(5);
    let env = sign_manifest(&m, &key).unwrap();
    open_manifest(&env, &keys, 1).unwrap();
    let bad = sign_manifest(&m, &other).unwrap();
    assert!(open_manifest(&bad, &keys, 1).is_err(), "untrusted signer accepted");
    assert!(open_manifest(&env, &keys, 2).is_err(), "threshold not enforced");
    // A signature over a different payload type does not verify.
    let mut env2 = env.clone();
    env2.payload_type = "application/json".to_owned();
    assert!(open_manifest(&env2, &keys, 1).is_err(), "payload type not bound");
    // Tampered payload.
    let mut mm = m.clone();
    mm.svn = 99;
    let mut env3 = env.clone();
    env3.payload = STANDARD.encode(db_gojson::to_vec(&mm).unwrap());
    assert!(open_manifest(&env3, &keys, 1).is_err(), "tampered payload accepted");
    // The policy's threshold is what open uses.
    let mut pol = Policy { keys: keys.clone(), threshold: 2, min_svn: 6, ..Policy::default() };
    assert!(pol.open(&env).is_err(), "policy threshold not passed through");
    pol.threshold = 0;
    pol.open(&env).unwrap();
    let now = GoTime::now_utc();
    assert!(pol.admit(&m, &now).is_err(), "below-floor release admitted (signatures alone do not stop downgrades)");
    pol.min_svn = 5;
    pol.admit(&m, &now).unwrap();
    assert!(pol.admit(&m, &m.expires_at.add(chrono::Duration::seconds(1))).is_err(), "expired release admitted");
    assert!(pol.admit(&m, &m.issued_at.add(chrono::Duration::minutes(-6))).is_err(), "not-yet-valid release admitted");
    pol.revoked.insert(m.id());
    assert!(pol.admit(&m, &now).is_err(), "revoked release admitted");
    pol.revoked.clear();
    pol.revoked.insert(m.digest());
    assert!(pol.admit(&m, &now).is_err(), "release revoked by digest admitted");
    let mut dev = m.clone();
    dev.channel = "dev".to_owned();
    pol.revoked.clear();
    assert!(pol.admit(&dev, &now).is_err(), "dev release admitted without allow_dev");
}

#[test]
fn transparency_log_inclusion() {
    let key = new_key();
    let public = key.verifying_key();
    for n in 1..=17u8 {
        let log = Log::new(key.clone());
        let entries: Vec<Vec<u8>> = (0..n).map(|i| vec![n, i, b'e']).collect();
        for e in &entries {
            log.append(e);
        }
        for (i, e) in entries.iter().enumerate() {
            let inc = log.prove(e).unwrap();
            inc.verify(&public).unwrap_or_else(|err| panic!("n={n} i={i}: {err}"));
            // Wrong index, wrong size and a foreign entry must fail.
            let mut bad = inc.clone();
            bad.index = (inc.index + 1) % u64::from(n);
            if n > 1 {
                assert!(bad.verify(&public).is_err(), "n={n} i={i}: wrong index verified");
            }
            let mut bad = inc.clone();
            bad.head.size += 1;
            assert!(bad.verify(&public).is_err(), "n={n} i={i}: wrong size verified");
            let mut bad = inc.clone();
            bad.envelope = b"not logged".to_vec();
            assert!(bad.verify(&public).is_err(), "foreign entry verified");
        }
    }
    // A tree head signed by another key is rejected.
    let log = Log::new(new_key());
    log.append(b"x");
    assert!(log.prove(b"x").unwrap().verify(&public).is_err(), "tree head from another log key verified");
    // Leaf/node domain separation: an interior node presented as a leaf.
    let log = Log::new(key);
    log.append(b"a");
    log.append(b"b");
    let root = hex::decode(log.head().root).unwrap();
    let mut inner = leaf_hash(b"a").to_vec();
    inner.extend_from_slice(&leaf_hash(b"b"));
    assert!(!verify_inclusion(&inner, 0, 1, &[], &root), "second-preimage: interior node accepted as a leaf");
}

#[test]
fn dsse_threshold() {
    let (k1, k2, k3) = (new_key(), new_key(), new_key());
    let keys = trusted(&[&k1, &k2]);
    let payload = br#"{"x":1}"#;
    let e1 = sign(PAYLOAD_TYPE, payload, &k1);
    let e2 = sign(PAYLOAD_TYPE, payload, &k2);
    let e3 = sign(PAYLOAD_TYPE, payload, &k3);
    let with = |sigs: Vec<Signature>| Envelope { payload_type: PAYLOAD_TYPE.to_owned(), payload: e1.payload.clone(), signatures: sigs };
    let both = with([e1.signatures.clone(), e2.signatures.clone()].concat());
    both.verify(PAYLOAD_TYPE, &keys, 2).unwrap();
    let dup = with([e1.signatures.clone(), e1.signatures.clone()].concat());
    assert!(dup.verify(PAYLOAD_TYPE, &keys, 2).is_err(), "the same key counted twice");
    let untrusted = with([e1.signatures.clone(), e3.signatures.clone()].concat());
    assert!(untrusted.verify(PAYLOAD_TYPE, &keys, 2).is_err(), "an untrusted signer counted");
    let forged =
        with([e1.signatures.clone(), vec![Signature { keyid: key_id(&k2.verifying_key()), sig: STANDARD.encode([0u8; 64]) }]].concat());
    assert!(forged.verify(PAYLOAD_TYPE, &keys, 2).is_err(), "an invalid signature counted");
    let garbage = with([e1.signatures.clone(), vec![Signature { keyid: key_id(&k2.verifying_key()), sig: "!!".to_owned() }]].concat());
    assert!(garbage.verify(PAYLOAD_TYPE, &keys, 2).is_err(), "a malformed signature counted");
}

#[test]
fn manifest_pcr_consistency() {
    let mut m = test_manifest(1);
    m.validate().unwrap();
    m.boot.pcr9_sha256 = m.boot.pcr12_sha256.clone();
    assert!(m.validate().is_err(), "PCR 9 inconsistent with load options and initrd accepted");
    let mut m = test_manifest(1);
    m.runtime.agent.sha256 = "abc".to_owned();
    assert!(m.validate().is_err(), "short agent hash accepted");
    let mut m = test_manifest(1);
    m.runtime.models = Some(vec![Model {
        id: "m".to_owned(),
        kind: "image".to_owned(),
        files: Some(vec![Artifact { name: "f".to_owned(), sha256: "zz".repeat(32), bytes: 1 }]),
    }]);
    assert!(m.validate().is_err(), "non-hex model hash accepted");
    let mut m = test_manifest(1);
    m.runtime.models = Some(vec![Model { id: "m".to_owned(), kind: "image".to_owned(), files: None }]);
    assert!(m.validate().is_err(), "model without files accepted");
    let mut m = test_manifest(1);
    m.runtime.engine.sha256 = "not-checked".to_owned();
    m.validate().unwrap();
    let mut m = test_manifest(1);
    m.channel = "production".to_owned();
    m.boot.pcr14_sha256.clear();
    assert!(m.validate().is_err(), "production release without PCR 14 accepted");
}

#[test]
fn signed_halo_uki_pcr11_matches_hardware() {
    // RAH-002 signed Poc04 UKI, actual PE VirtualSize section digests and
    // live TPM PCR 11 from signed-boot-evidence.txt. This catches PE-order,
    // raw-padding and section-name measurement mistakes.
    let entries = [
        (".linux", 14293960, "0fb8bbabd7fcd800e49ee5daf8e959a8c7c4e4c7d6b6a5130aaaa1a83acc7d04"),
        (".osrel", 163, "da99359d652d06814fcd93a00b59bc46b9cc434ae47609c467497372fbde0181"),
        (".cmdline", 86, "47aa154a4a096c5ca725c7110694b21aa1a616a7e6ad6f3e734f799ef198e81f"),
        (".initrd", 2428868, "8ac4fb8cb674d10ab24a54e478696a8f48052440928a9ba7bc14bba4b9e98cb5"),
        (".uname", 15, "2afbdd01f6ef2ea16873385d12c1aa66ce2a23614b2ba772c5ced1f76ad4b257"),
        (".sbat", 343, "f6b5942545e079524db80827235843fef67105be9674af806c5bfb311f351bb7"),
    ];
    let sections: Vec<Artifact> =
        entries.iter().map(|&(name, bytes, sha256)| Artifact { name: name.to_owned(), bytes, sha256: sha256.to_owned() }).collect();
    assert_eq!(hex::encode(predict_pcr11(&sections).unwrap()), "ef88e02a472f351422f4f33c1c27160aa1a21887b174d821f99752d74724154c");
    let mut changed = sections.clone();
    changed[2].sha256.replace_range(..1, "0");
    assert_ne!(predict_pcr11(&changed).unwrap(), predict_pcr11(&sections).unwrap());
    changed = sections.clone();
    changed.swap(0, 1);
    assert!(predict_pcr11(&changed).is_err());
}

#[test]
fn signed_halo_direct_shim_uki_pcr4_matches_hardware() {
    // RAH-002 signed Poc04 boot measures exactly shim then the UKI as EFI
    // applications; no separate inner kernel application is measured.
    let apps = [
        "f4166948f7adafa71e45c7ca5d30d97f78f382ecf1e3c8e4767b1ec1770cd52f",
        "d6f267dd7be4be70915e94018466c12116db5c3b5587ab97c2aa61af75d7513d",
    ]
    .iter()
    .map(|s| hex::decode(s).unwrap())
    .collect::<Vec<_>>();
    assert_eq!(hex::encode(predict_pcr4(&apps)), "9a4d420d7d5d43cadf2356fc5471e5d66d229e5798d15f72336fe7c6a56617d2");
}

#[test]
fn uki_manifest_binds_embedded_cmdline_and_initrd() {
    let mut m = test_manifest(1);
    let cmdline = "root=PARTLABEL=x lockdown=confidentiality debugfs=off iommu.strict=1 module.sig_enforce=1\n";
    let cmd_hash = hex::encode(Sha256::digest(cmdline.as_bytes()));
    let initrd_hash = hex::encode(Sha256::digest(b"initrd"));
    let sections = vec![
        Artifact { name: ".linux".to_owned(), sha256: hex::encode(Sha256::digest(b"kernel")), bytes: 6 },
        Artifact { name: ".cmdline".to_owned(), sha256: cmd_hash.clone(), bytes: cmdline.len() as i64 },
        Artifact { name: ".initrd".to_owned(), sha256: initrd_hash.clone(), bytes: 6 },
    ];
    m.boot.path = "uki".to_owned();
    m.boot.pcr0_sha256 = "cc".repeat(32);
    m.boot.load_options = cmdline.to_owned();
    m.boot.load_options_sha256 = cmd_hash;
    m.boot.initrd_sha256 = initrd_hash;
    m.boot.pcr9_sha256 = "ab".repeat(32); // independently observed PCR 9
    m.boot.pcr12_sha256 = "0".repeat(64);
    m.boot.pcr11_sha256 = hex::encode(predict_pcr11(&sections).unwrap());
    m.boot.uki_sections = Some(sections);
    m.validate().unwrap();
    let mut bad = m.clone();
    bad.boot.pcr0_sha256.clear();
    assert!(bad.validate().is_err(), "production UKI without firmware pin accepted");
    let mut bad = m.clone();
    bad.boot.pcr11_sha256.clear();
    assert!(bad.validate().is_err(), "missing PCR 11 accepted");
    let mut bad = m.clone();
    bad.boot.load_options.push_str(" init=/bin/sh");
    assert!(bad.validate().is_err(), "unmeasured cmdline accepted");
    let mut bad = m.clone();
    bad.boot.initrd_sha256 = "ff".repeat(32);
    assert!(bad.validate().is_err(), "unmeasured initrd accepted");
    let mut bad = m.clone();
    bad.boot.pcr12_sha256 = "ff".repeat(32);
    assert!(bad.validate().is_err(), "UKI override/addon PCR 12 accepted");
}

#[test]
fn manifest_json_round_trip_is_go_shaped() {
    let m = test_manifest(3);
    let b = db_gojson::to_vec(&m).unwrap();
    let s = String::from_utf8(b.clone()).unwrap();
    assert!(!s.contains("pcr11_sha256") && !s.contains("uki_sections"));
    // nil slices are null, omitempty fields absent, struct order kept.
    assert!(
        s.starts_with(
            r#"{"schema":"darkbloom-amd/nodeos-release/v1","name":"n","version":"v","svn":3,"channel":"production","issued_at":""#
        ),
        "{s}"
    );
    assert!(s.contains(r#""platform":{"products":null},"#), "{s}");
    assert!(
        s.contains(
            r#""runtime":{"agent":{"name":"","sha256":""},"engine":{"name":"","sha256":""},"workflows":null,"models":null},"requires":{}}"#
        ),
        "{s}"
    );
    let back: Manifest = db_gojson::from_slice(&b).unwrap();
    assert_eq!(back, m);
    assert_eq!(db_gojson::to_vec(&back).unwrap(), b);
    // Unknown fields and trailing data are rejected (DisallowUnknownFields).
    let mut extra = s.trim_end_matches('}').to_owned();
    extra.push_str(r#","extra":1}"#);
    assert!(db_gojson::from_slice::<Manifest>(extra.as_bytes()).is_err());
}

#[test]
fn key_files() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("release");
    let public = generate_key(prefix.to_str().unwrap()).unwrap();
    let private = load_private_key(&dir.path().join("release.key")).unwrap();
    assert_eq!(private.verifying_key(), public);
    assert_eq!(load_public_key(&dir.path().join("release.pub")).unwrap(), public);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(dir.path().join("release.key")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    std::fs::write(dir.path().join("bad.key"), "nothex\n").unwrap();
    assert!(load_private_key(&dir.path().join("bad.key")).is_err());
}

#[test]
fn open_manifest_rejects_trailing_data() {
    let key = new_key();
    let m = test_manifest(1);
    let mut payload = db_gojson::to_vec(&m).unwrap();
    payload.extend_from_slice(br#" {"svn":99}"#);
    let env = sign(PAYLOAD_TYPE, &payload, &key);
    assert!(open_manifest(&env, &trusted(&[&key]), 1).is_err(), "signed manifest with trailing JSON accepted");
}
