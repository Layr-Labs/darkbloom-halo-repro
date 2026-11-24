//! The calibration verifier must authenticate the quote and match reviewed
//! inputs; self-consistent, attacker-supplied measurements are insufficient.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use base64::Engine as _;
use db_cli::calibration::verify;
use db_gojson::GoTime;
use db_release::{Artifact, Boot, Manifest};
use db_tpm2::consts::*;
use db_tpm2::{Attest, Attested, PcrSelection, PcrSelectionList, Signature, Unique};
use db_tpmattest::{UKI_PCRS, eventlog as el};
use ecdsa::signature::hazmat::PrehashSigner as _;
use p256::ecdsa::SigningKey;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::process::Command;

struct Fixture {
    key: SigningKey,
    quote: Value,
    pin: Value,
    nonce: Vec<u8>,
    manifest: Manifest,
    events: Vec<el::LogEvent>,
}

fn measured_event(pcr: u32, event_type: u32, data: &[u8], digest: Vec<u8>) -> el::LogEvent {
    el::LogEvent { pcr, event_type, data: data.to_vec(), digests: BTreeMap::from([(ALG_SHA256, digest)]) }
}

fn artifact(name: &str, data: &[u8]) -> Artifact {
    Artifact { name: name.to_owned(), sha256: hex::encode(Sha256::digest(data)), bytes: data.len() as i64 }
}

fn resign(f: &Fixture, quote: &mut Value, mutate: impl FnOnce(&mut Attest)) {
    let raw = hex::decode(quote["attest"].as_str().unwrap()).unwrap();
    let mut att = Attest::parse(&raw).unwrap();
    mutate(&mut att);
    let raw = att.to_bytes().unwrap();
    let sig: p256::ecdsa::Signature = f.key.sign_prehash(&Sha256::digest(&raw)).unwrap();
    let (r, s) = sig.split_bytes();
    quote["attest"] = hex::encode(&raw).into();
    quote["signature"] =
        hex::encode(Signature::Ecc { alg: ALG_ECDSA, hash: ALG_SHA256, r: r.to_vec(), s: s.to_vec() }.to_bytes().unwrap()).into();
}

fn fixture() -> Fixture {
    // A software key is appropriate only for a cryptographic unit fixture.
    // The real command's independently provisioned AK pin is the trust anchor.
    let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let point = key.verifying_key().to_sec1_point(false);
    let mut public = db_tpm2::ak_template();
    public.unique = Unique::Ecc { x: point.x().unwrap().to_vec(), y: point.y().unwrap().to_vec() };
    let public_raw = public.to_bytes().unwrap();
    let nonce = vec![0x42; 32];
    let cmdline = "ro rdinit=/init lockdown=confidentiality\n";
    let sections =
        vec![artifact(".linux", b"reviewed kernel"), artifact(".cmdline", cmdline.as_bytes()), artifact(".initrd", b"reviewed initrd")];
    let apps = vec![
        artifact("shimx64.efi", b"reviewed shim"),
        artifact("systemd-bootx64.efi", b"reviewed menu"),
        artifact("uki", b"reviewed UKI"),
    ];
    let mut events = vec![
        measured_event(
            4,
            el::EV_EFI_ACTION,
            b"Calling EFI Application from Boot Option",
            Sha256::digest(b"Calling EFI Application from Boot Option").to_vec(),
        ),
        measured_event(4, el::EV_SEPARATOR, &[0; 4], Sha256::digest([0; 4]).to_vec()),
    ];
    for app in &apps {
        events.push(measured_event(4, el::EV_EFI_BOOT_SERVICES_APPLICATION, app.name.as_bytes(), hex::decode(&app.sha256).unwrap()));
    }
    for section in &sections {
        let name = [section.name.as_bytes(), &[0]].concat();
        events.push(measured_event(11, el::EV_IPL, &name, Sha256::digest(&name).to_vec()));
        events.push(measured_event(11, el::EV_IPL, section.name.as_bytes(), hex::decode(&section.sha256).unwrap()));
    }
    for (pcr, description) in
        [(0, "reviewed firmware"), (7, "reviewed secure boot policy"), (9, "reviewed combined initrd"), (14, "reviewed MOK policy")]
    {
        events.push(measured_event(pcr, el::EV_IPL, description.as_bytes(), Sha256::digest(description.as_bytes()).to_vec()));
    }
    let event_raw = el::build_event_log(&[ALG_SHA256], &events).unwrap();
    let pcrs = el::parse_event_log(&event_raw).unwrap().replay(ALG_SHA256, &UKI_PCRS).unwrap();
    let get = |p: u32| hex::encode(&pcrs[&p]);
    let now = GoTime::now_utc().truncate_secs();
    let manifest = Manifest {
        schema: db_release::SCHEMA.to_owned(),
        name: "reviewed-nodeos".to_owned(),
        version: "v1".to_owned(),
        svn: 3,
        channel: "dev".to_owned(),
        issued_at: now,
        expires_at: now.add(chrono::Duration::days(1)),
        boot: Boot {
            path: "uki".to_owned(),
            boot_apps: Some(apps),
            pcr4_sha256: get(4),
            load_options: cmdline.to_owned(),
            load_options_sha256: sections[1].sha256.clone(),
            initrd_sha256: sections[2].sha256.clone(),
            pcr9_sha256: get(9),
            pcr12_sha256: get(12),
            pcr11_sha256: get(11),
            uki_sections: Some(sections),
            pcr0_sha256: get(0),
            pcr7_sha256: get(7),
            pcr14_sha256: get(14),
        },
        ..Default::default()
    };
    manifest.validate().unwrap();
    let att = Attest {
        magic: GENERATED_VALUE,
        attest_type: ST_ATTEST_QUOTE,
        qualified_signer: db_tpmattest::endorsement_primary_qn(&public.name().unwrap()),
        extra_data: nonce.clone(),
        clock: 1000,
        reset_count: 2,
        restart_count: 0,
        safe: true,
        firmware_version: 0x000a_0007_0000_0004,
        attested: Attested::Quote {
            pcr_select: PcrSelectionList(vec![PcrSelection::new(ALG_SHA256, &UKI_PCRS)]),
            pcr_digest: db_tpmattest::pcr_digest(&pcrs, &UKI_PCRS).unwrap(),
        },
    };
    let read: BTreeMap<String, String> = pcrs.iter().map(|(p, value)| (p.to_string(), hex::encode(value))).collect();
    let quote = json!({"quoted_pcrs":UKI_PCRS,"ak_public":hex::encode(&public_raw),"attest":hex::encode(att.to_bytes().unwrap()),"signature":"", "pcr_read_sha256":read,"event_log":base64::engine::general_purpose::STANDARD.encode(event_raw)});
    let mut f = Fixture { key, quote, pin: json!({"ak_public":hex::encode(public_raw)}), nonce, manifest, events };
    let mut quote = f.quote.clone();
    resign(&f, &mut quote, |_| {});
    f.quote = quote;
    f
}

fn check(f: &Fixture, quote: &Value, manifest: &Manifest) -> Result<Vec<u8>, String> {
    verify(&serde_json::to_vec(quote).unwrap(), &serde_json::to_vec(&f.pin).unwrap(), &f.nonce, manifest, "halo-wizard-v1")
}

#[test]
fn authentic_pinned_quote_produces_only_canonical_wizard_reference() {
    let f = fixture();
    let output = check(&f, &f.quote, &f.manifest).unwrap();
    let pcrs: BTreeMap<String, Value> =
        [4, 7, 9, 11, 12, 14].iter().map(|p| (p.to_string(), f.quote["pcr_read_sha256"][p.to_string()].clone())).collect();
    let expected =
        format!("{{\"bank\":\"sha256\",\"install_id\":\"halo-wizard-v1\",\"pcrs\":{},\"v\":1}}\n", serde_json::to_string(&pcrs).unwrap());
    assert_eq!(output, expected.as_bytes());
    assert!(!String::from_utf8(output).unwrap().contains("ak_public"));
}

#[test]
fn rejects_bad_signature_nonce_and_self_selected_ak() {
    let f = fixture();
    let mut bad = f.quote.clone();
    let mut signature = hex::decode(bad["signature"].as_str().unwrap()).unwrap();
    *signature.last_mut().unwrap() ^= 1;
    bad["signature"] = hex::encode(signature).into();
    assert!(check(&f, &bad, &f.manifest).unwrap_err().contains("signature does not verify"));
    assert!(
        verify(&serde_json::to_vec(&f.quote).unwrap(), &serde_json::to_vec(&f.pin).unwrap(), &[1; 32], &f.manifest, "halo")
            .unwrap_err()
            .contains("nonce binding")
    );
    let mut pin = f.pin.clone();
    pin["ak_public"] = "00".into();
    assert!(
        verify(&serde_json::to_vec(&f.quote).unwrap(), &serde_json::to_vec(&pin).unwrap(), &f.nonce, &f.manifest, "halo")
            .unwrap_err()
            .contains("separately pinned")
    );
    let mut bad = f.quote.clone();
    resign(&f, &mut bad, |att| att.qualified_signer = vec![0; 34]);
    assert!(check(&f, &bad, &f.manifest).unwrap_err().contains("endorsement-hierarchy"));
}

#[test]
fn requires_exact_deterministic_restricted_ak_template_even_when_pinned() {
    let mut f = fixture();
    let mut public = db_tpm2::Public::parse(&hex::decode(f.quote["ak_public"].as_str().unwrap()).unwrap()).unwrap();
    public.attributes &= !OBJ_NO_DA; // still a valid restricted AK to the general verifier
    f.quote["ak_public"] = hex::encode(public.to_bytes().unwrap()).into();
    f.pin["ak_public"] = f.quote["ak_public"].clone();
    assert!(check(&f, &f.quote, &f.manifest).unwrap_err().contains("CreatePrimary AK template"));
    public.attributes &= !OBJ_RESTRICTED;
    f.quote["ak_public"] = hex::encode(public.to_bytes().unwrap()).into();
    f.pin["ak_public"] = f.quote["ak_public"].clone();
    assert!(check(&f, &f.quote, &f.manifest).unwrap_err().contains("restricted signing key"));
}

#[test]
fn full_signed_uki_pcr_selection_and_exact_read_indices_are_mandatory() {
    let f = fixture();
    let without_11: Vec<u32> = UKI_PCRS.into_iter().filter(|p| *p != 11).collect();
    let mut bad = f.quote.clone();
    resign(&f, &mut bad, |att| {
        if let Attested::Quote { pcr_select, .. } = &mut att.attested {
            pcr_select.0[0] = PcrSelection::new(ALG_SHA256, &without_11);
        }
    });
    assert!(check(&f, &bad, &f.manifest).unwrap_err().contains("including PCR 11"));
    let mut bad = f.quote.clone();
    bad["quoted_pcrs"] = json!(without_11);
    assert!(check(&f, &bad, &f.manifest).is_err());
    for key in ["11", "04"] {
        let mut bad = f.quote.clone();
        if key == "11" {
            bad["pcr_read_sha256"].as_object_mut().unwrap().remove(key);
        } else {
            bad["pcr_read_sha256"][key] = "00".repeat(32).into();
        }
        assert!(check(&f, &bad, &f.manifest).unwrap_err().contains("exactly the canonical full UKI"));
    }
    let mut bad = f.quote.clone();
    resign(&f, &mut bad, |att| {
        if let Attested::Quote { pcr_select, .. } = &mut att.attested {
            pcr_select.0[0].hash = ALG_SHA384;
        }
    });
    assert!(check(&f, &bad, &f.manifest).is_err());
}

#[test]
fn every_pcr_read_value_and_full_log_replay_are_bound_to_quote_digest() {
    let f = fixture();
    let mut bad = f.quote.clone();
    bad["pcr_read_sha256"]["2"] = "01".repeat(32).into();
    assert!(check(&f, &bad, &f.manifest).unwrap_err().contains("signed quoted PCR digest"));
    let changed: BTreeMap<u32, Vec<u8>> =
        UKI_PCRS.iter().map(|p| (*p, hex::decode(bad["pcr_read_sha256"][p.to_string()].as_str().unwrap()).unwrap())).collect();
    resign(&f, &mut bad, |att| {
        if let Attested::Quote { pcr_digest, .. } = &mut att.attested {
            *pcr_digest = db_tpmattest::pcr_digest(&changed, &UKI_PCRS).unwrap();
        }
    });
    assert!(check(&f, &bad, &f.manifest).unwrap_err().contains("full SHA-256 event-log replay"));
    let mut changed_events = f.events.clone();
    changed_events[0].digests.get_mut(&ALG_SHA256).unwrap()[0] ^= 1;
    let mut bad = f.quote.clone();
    bad["event_log"] =
        base64::engine::general_purpose::STANDARD.encode(el::build_event_log(&[ALG_SHA256], &changed_events).unwrap()).into();
    assert!(check(&f, &bad, &f.manifest).unwrap_err().contains("full SHA-256 event-log replay"));
}

#[test]
fn reviewed_manifest_must_pin_platform_and_predict_exact_boot() {
    let f = fixture();
    for pcr in [0, 7, 9, 14] {
        let mut manifest = f.manifest.clone();
        let slot = match pcr {
            0 => &mut manifest.boot.pcr0_sha256,
            7 => &mut manifest.boot.pcr7_sha256,
            9 => &mut manifest.boot.pcr9_sha256,
            _ => &mut manifest.boot.pcr14_sha256,
        };
        *slot = "ff".repeat(32);
        assert!(check(&f, &f.quote, &manifest).unwrap_err().contains(&format!("quoted PCR {pcr} differs")));
    }
    let mut manifest = f.manifest.clone();
    manifest.boot.pcr0_sha256.clear();
    assert!(check(&f, &f.quote, &manifest).unwrap_err().contains("independently pin PCR 0"));
    let mut manifest = f.manifest.clone();
    manifest.boot.pcr4_sha256 = "ff".repeat(32);
    assert!(check(&f, &f.quote, &manifest).unwrap_err().contains("does not match boot_apps"));
    let mut manifest = f.manifest.clone();
    manifest.boot.boot_apps.as_mut().unwrap()[0].sha256 = "ff".repeat(32);
    let apps: Vec<Vec<u8>> = manifest.boot.boot_apps().iter().map(|a| hex::decode(&a.sha256).unwrap()).collect();
    manifest.boot.pcr4_sha256 = hex::encode(db_release::predict_pcr4(&apps));
    assert!(check(&f, &f.quote, &manifest).unwrap_err().contains("quoted PCR 4 differs"));
    let mut manifest = f.manifest.clone();
    manifest.boot.uki_sections.as_mut().unwrap()[0].sha256 = "ff".repeat(32);
    manifest.boot.pcr11_sha256 = hex::encode(db_release::predict_pcr11(manifest.boot.uki_sections.as_ref().unwrap()).unwrap());
    assert!(check(&f, &f.quote, &manifest).unwrap_err().contains("quoted PCR 11 differs"));
    let mut manifest = f.manifest.clone();
    manifest.boot.pcr12_sha256 = "ff".repeat(32);
    assert!(check(&f, &f.quote, &manifest).unwrap_err().contains("zero PCR 12"));
}

#[test]
fn duplicate_unknown_and_malformed_inputs_cannot_create_reference() {
    let f = fixture();
    let capture = serde_json::to_string(&f.quote).unwrap();
    let duplicate = capture.replacen("\"pcr_read_sha256\":{", "\"pcr_read_sha256\":{\"4\":\"00\",", 1);
    assert!(
        verify(duplicate.as_bytes(), &serde_json::to_vec(&f.pin).unwrap(), &f.nonce, &f.manifest, "halo")
            .unwrap_err()
            .contains("duplicate PCR index")
    );
    let mut unknown = f.quote.clone();
    unknown["trust_me"] = true.into();
    assert!(check(&f, &unknown, &f.manifest).unwrap_err().contains("unknown field"));
    for id in ["", "../other", "a b", "é", &"a".repeat(81)] {
        assert!(
            verify(capture.as_bytes(), &serde_json::to_vec(&f.pin).unwrap(), &f.nonce, &f.manifest, id).unwrap_err().contains("release-id")
        );
    }
    for nonce in [vec![0; 15], vec![0; 33]] {
        assert!(
            verify(capture.as_bytes(), &serde_json::to_vec(&f.pin).unwrap(), &nonce, &f.manifest, "halo")
                .unwrap_err()
                .contains("nonce must")
        );
    }
}

#[test]
fn cli_stdout_is_only_canonical_reference_and_empty_on_failure() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    for (name, bytes) in [
        ("quote.json", serde_json::to_vec(&f.quote).unwrap()),
        ("ak.json", serde_json::to_vec(&f.pin).unwrap()),
        ("manifest.json", db_gojson::to_vec(&f.manifest).unwrap()),
    ] {
        std::fs::write(dir.path().join(name), bytes).unwrap();
    }
    let run = |nonce: &str| {
        Command::new(env!("CARGO_BIN_EXE_dbrelease"))
            .args([
                "verify-calibration",
                "-in",
                dir.path().join("quote.json").to_str().unwrap(),
                "-ak-public",
                dir.path().join("ak.json").to_str().unwrap(),
                "-manifest",
                dir.path().join("manifest.json").to_str().unwrap(),
                "-nonce",
                nonce,
                "-release-id",
                "halo-wizard-v1",
            ])
            .output()
            .unwrap()
    };
    let success = run(&hex::encode(&f.nonce));
    assert!(success.status.success(), "{}", String::from_utf8_lossy(&success.stderr));
    assert_eq!(success.stdout, check(&f, &f.quote, &f.manifest).unwrap());
    assert!(success.stderr.is_empty());
    let fail = run(&hex::encode([1; 32]));
    assert!(!fail.status.success());
    assert!(fail.stdout.is_empty());
}
