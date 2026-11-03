//! Device-level tests of the pure-Rust TPM layer against swtpm: credential
//! activation with ECC and RSA EKs (the verifier's MakeCredential must
//! interoperate with a real TPM implementation), public areas, NV, PCRs and
//! quotes.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use db_testenv::Swtpm;
use db_tpm2::consts::*;
use db_tpm2::{HashAlg, rsa_ek_template};
use db_tpmattest::{DEFAULT_PCRS, make_credential, parse_attestation_key, parse_ek_public, pcr_digest, quote_extra_data, verify_quote};
use db_tpmdev::{Device, Key};
use std::collections::BTreeMap;
use std::sync::Arc;

/// A bare swtpm (no provisioning, no simulated boot).
struct Tpm {
    dev: Arc<Device>,
    sw: Swtpm,
    _dir: tempfile::TempDir,
}

fn tpm() -> Option<Tpm> {
    Swtpm::binary()?;
    let dir = tempfile::tempdir().unwrap();
    let sw = Swtpm::start(dir.path()).unwrap();
    let dev = sw.open_device().unwrap();
    Some(Tpm { dev, sw, _dir: dir })
}

fn random(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).unwrap();
    b
}

/// MakeCredential (verifier side) -> ActivateCredential (TPM).
fn activate_round_trip(dev: &Device, ek: &Key, ak: &Key) {
    let ekp = parse_ek_public(&ek.public_raw).unwrap();
    let akp = parse_attestation_key(&ak.public_raw).unwrap();
    assert_eq!(akp.name, ak.name, "verifier and TPM disagree on the AK name");
    let ch = make_credential(&ekp, &ak.name).unwrap();
    let got = dev.activate_credential(ak, ek, &ch.id_object, &ch.enc_secret).unwrap();
    assert_eq!(got.as_slice(), ch.secret.as_slice(), "recovered the wrong secret");
}

#[test]
fn credential_activation_ecc_and_rsa_eks() {
    let Some(t) = tpm() else { return };
    let dev = &t.dev;
    let ak = dev.create_ak().unwrap();
    // ECC P-256 EK: ECDH + KDFe seed.
    let ek = dev.create_ek(true).unwrap();
    activate_round_trip(dev, &ek, &ak);
    // A credential bound to another name fails the TPM's integrity check;
    // repeated failures must not leak policy sessions (3 session slots).
    let ekp = parse_ek_public(&ek.public_raw).unwrap();
    let mut wrong = ak.name.clone();
    *wrong.last_mut().unwrap() ^= 1;
    for _ in 0..5 {
        let ch = make_credential(&ekp, &wrong).unwrap();
        let err = dev.activate_credential(&ak, &ek, &ch.id_object, &ch.enc_secret).unwrap_err();
        assert_eq!(err.response_code().map(|rc| rc.base()), Some(0x09F), "want TPM_RC_INTEGRITY, got {err}");
    }
    // Garbage blobs fail cleanly too.
    assert!(dev.activate_credential(&ak, &ek, &[0u8; 10], &[0u8; 10]).is_err());
    activate_round_trip(dev, &ek, &ak);
    // swtpm holds three transient objects.
    dev.flush(&ek);
    // RSA-2048 EK: RSA-OAEP(SHA-256, "IDENTITY") seed.
    let rsa = dev.create_primary(RH_ENDORSEMENT, &rsa_ek_template()).unwrap();
    assert_eq!(
        dev.create_ek(false)
            .map(|k| {
                dev.flush(&k);
                k.public_raw
            })
            .unwrap(),
        rsa.public_raw,
        "create_ek(false) is the TCG RSA template"
    );
    activate_round_trip(dev, &rsa, &ak);
    // A credential for the RSA EK does not open with the ECC EK.
    let ek = dev.create_ek(true).unwrap();
    let ch = make_credential(&parse_ek_public(&rsa.public_raw).unwrap(), &ak.name).unwrap();
    assert!(dev.activate_credential(&ak, &ek, &ch.id_object, &ch.enc_secret).is_err());
    for k in [&rsa, &ek, &ak] {
        dev.flush(k);
    }
}

#[test]
fn primary_keys_are_stable_and_read_public_matches() {
    let Some(t) = tpm() else { return };
    let dev = &t.dev;
    let ek = dev.create_ek(true).unwrap();
    let ak = dev.create_ak().unwrap();
    for k in [&ek, &ak] {
        assert_eq!(dev.read_public(k.handle).unwrap(), (k.public_raw.clone(), k.name.clone()));
        assert_eq!(k.public.name().unwrap(), k.name);
    }
    // CreatePrimary is deterministic: the same EK and AK again.
    let ek2 = dev.create_ek(true).unwrap();
    assert_eq!((ek2.public_raw.clone(), ek2.name.clone()), (ek.public_raw.clone(), ek.name.clone()));
    assert_ne!(ek2.handle, ek.handle);
    for k in [&ek2, &ek, &ak] {
        dev.flush(k);
    }
    let err = dev.read_public(ak.handle).unwrap_err();
    assert!(err.response_code().is_some(), "flushed handle: {err}");
    assert!(dev.flush_handle(ak.handle).is_err());
}

#[test]
fn nv_define_write_read_undefine() {
    let Some(t) = tpm() else { return };
    let dev = &t.dev;
    let max = dev.nv_buffer_max();
    assert!(max >= 512, "nvBufferMax {max}");
    let idx = 0x01C0_0200;
    // Larger than one NV buffer: chunked writes and reads.
    let data = random(max + max / 2 + 3);
    dev.write_platform_nv(idx, &data).unwrap();
    assert_eq!(dev.read_nv(idx).unwrap(), data);
    let (public, name) = dev.nv_read_public(idx).unwrap();
    assert_eq!(public.data_size as usize, data.len());
    assert_eq!(public.name_alg, ALG_SHA256);
    assert!(public.has(db_tpmdev_attrs()) && public.has(NV_WRITTEN), "attributes 0x{:08x}", public.attributes);
    assert_eq!(public.name().unwrap(), name);
    // Rewriting replaces the index (undefine + define), even with another size.
    let short = random(100);
    dev.write_platform_nv(idx, &short).unwrap();
    assert_eq!(dev.read_nv(idx).unwrap(), short);
    // Small chunks both ways, and mixed chunk sizes.
    dev.override_nv_chunk(Some(97));
    assert_eq!(dev.nv_buffer_max(), 97);
    let data = random(1500);
    dev.write_platform_nv(idx, &data).unwrap();
    assert_eq!(dev.read_nv(idx).unwrap(), data);
    dev.override_nv_chunk(None);
    assert_eq!(dev.read_nv(idx).unwrap(), data);
    dev.undefine_platform_nv(idx).unwrap();
    assert!(dev.read_nv(idx).is_err());
    assert!(dev.undefine_platform_nv(idx).is_err());
    // Nothing provisioned on a fresh TPM.
    assert!(dev.load_endorsement().is_err());
    assert!(dev.write_platform_nv(idx, &vec![0u8; 70_000]).is_err());
}

fn db_tpmdev_attrs() -> u32 {
    NV_PPWRITE | NV_PPREAD | NV_OWNERREAD | NV_AUTHREAD | NV_NO_DA | NV_PLATFORMCREATE
}

#[test]
fn pcr_extend_matches_software() {
    let Some(t) = tpm() else { return };
    let dev = &t.dev;
    let banks: Vec<u16> = dev.active_banks().unwrap().into_iter().filter(|&b| HashAlg::from_id(b).is_some()).collect();
    assert!(banks.contains(&ALG_SHA256), "banks {banks:04x?}");
    let all: Vec<u32> = (0..24).collect();
    for &b in &banks {
        // 24 PCRs need several PCR_Read calls (at most 8 values per call).
        assert_eq!(dev.read_pcr_bank(b, &all).unwrap().len(), 24);
    }
    for pcr in [16u32, 23, 7] {
        let before: BTreeMap<u16, Vec<u8>> = banks.iter().map(|&b| (b, dev.read_pcr_bank(b, &[pcr]).unwrap()[&pcr].clone())).collect();
        let digests: BTreeMap<u16, Vec<u8>> = banks.iter().map(|&b| (b, HashAlg::from_id(b).unwrap().digest(&random(16)))).collect();
        dev.pcr_extend(pcr, &digests).unwrap();
        for &b in &banks {
            let h = HashAlg::from_id(b).unwrap();
            let want = h.digest_parts(&[&before[&b], &digests[&b]]);
            assert_eq!(dev.read_pcr_bank(b, &[pcr]).unwrap()[&pcr], want, "PCR {pcr} bank 0x{b:04x}");
        }
    }
    // Client-side checks: wrong digest length, unknown bank, PCR range.
    let mut bad = BTreeMap::new();
    bad.insert(ALG_SHA256, vec![0u8; 31]);
    assert!(dev.pcr_extend(16, &bad).is_err());
    bad.clear();
    bad.insert(0x1234, vec![0u8; 32]);
    assert!(dev.pcr_extend(16, &bad).is_err());
    assert!(dev.pcr_extend(24, &BTreeMap::new()).is_err());
    assert!(dev.read_pcrs(&[24]).is_err());
}

#[test]
fn quote_verifies_and_binds_the_nonce() {
    let Some(t) = tpm() else { return };
    let dev = &t.dev;
    let ak = dev.create_ak().unwrap();
    let akp = parse_attestation_key(&ak.public_raw).unwrap();
    for pcrs in [DEFAULT_PCRS.to_vec(), (0..24).collect::<Vec<u32>>(), vec![7]] {
        let nonce = random(32);
        let extra = quote_extra_data(&nonce, b"statement");
        let (attest, sig) = dev.quote(&ak, &extra, &pcrs).unwrap();
        let q = verify_quote(&akp, &attest, &sig, &extra).unwrap();
        assert_eq!((q.bank, q.pcrs.clone()), (ALG_SHA256, pcrs.clone()));
        let live = dev.read_pcrs(&pcrs).unwrap();
        assert_eq!(pcr_digest(&live, &q.pcrs).unwrap(), q.pcr_digest);
        let other = quote_extra_data(&random(32), b"statement");
        assert!(verify_quote(&akp, &attest, &sig, &other).is_err(), "quote verified under another nonce");
        let mut edited = attest.clone();
        *edited.last_mut().unwrap() ^= 1;
        assert!(verify_quote(&akp, &edited, &sig, &extra).is_err());
    }
    // Qualifying data is a TPM2B_DATA (at most a TPMT_HA).
    assert!(dev.quote(&ak, &[0u8; 67], &DEFAULT_PCRS).is_err());
    dev.flush(&ak);
}

/// swtpm has no resource manager: objects a previous client left loaded
/// would exhaust its three object slots. Opening it flushes them.
#[test]
fn open_flushes_stale_transient_objects() {
    let Some(t) = tpm() else { return };
    let leaked = [t.dev.create_ek(true).unwrap(), t.dev.create_ak().unwrap(), t.dev.create_ek(false).unwrap()];
    let full = t.dev.create_ak().unwrap_err();
    assert_eq!(full.response_code().map(|rc| rc.0), Some(0x902), "want TPM_RC_OBJECT_MEMORY, got {full}");
    // A new client (the first one "crashed" without flushing).
    t.dev.close();
    let fresh = t.sw.open_device().unwrap();
    for k in &leaked {
        assert!(fresh.read_public(k.handle).is_err(), "handle 0x{:08x} survived", k.handle);
    }
    let keys: Vec<Key> = (0..3).map(|_| fresh.create_ak().unwrap()).collect();
    for k in &keys {
        fresh.flush(k);
    }
}
