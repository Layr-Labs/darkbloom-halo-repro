//! Robustness of the TPM layer: mutated TPM responses (recorded from
//! swtpm) never panic the parsers, Startup on TPM_RC_INITIALIZE, the TCP
//! transport's framing and redial, hardware-mode refusals and the
//! attester's challenge validation.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use db_testenv::{Fixture, TEST_CMDLINE};
use db_tpm2::consts::*;
use db_tpmattest::{DEFAULT_PCRS, make_credential, parse_attestation_key, parse_ek_public};
use db_tpmdev::{AttestError, Attester, Device, Mode, NV_ECC_EK_CERT, Transport};
use rand::RngExt as _;
use std::collections::VecDeque;
use std::io::{self, Read as _, Write as _};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

struct Recorder {
    inner: Box<dyn Transport>,
    log: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Transport for Recorder {
    fn send(&mut self, cmd: &[u8]) -> io::Result<Vec<u8>> {
        let r = self.inner.send(cmd)?;
        self.log.lock().unwrap().push(r.clone());
        Ok(r)
    }
}

/// Answers with canned responses (ignoring the commands) and records the
/// command codes.
struct Script {
    rsps: VecDeque<Vec<u8>>,
    codes: Arc<Mutex<Vec<u32>>>,
}

impl Transport for Script {
    fn send(&mut self, cmd: &[u8]) -> io::Result<Vec<u8>> {
        if let Some(c) = cmd.get(6..10) {
            self.codes.lock().unwrap().push(u32::from_be_bytes(c.try_into().unwrap()));
        }
        self.rsps.pop_front().ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "end of script"))
    }
}

fn script(rsps: Vec<Vec<u8>>) -> (Arc<Device>, Arc<Mutex<Vec<u32>>>) {
    let codes = Arc::new(Mutex::new(Vec::new()));
    let t = Script { rsps: rsps.into(), codes: codes.clone() };
    (Device::with_transport(Box::new(t), Mode::Swtpm), codes)
}

fn rsp(rc: u32, body: &[u8]) -> Vec<u8> {
    let mut b = vec![0x80, 0x01];
    b.extend_from_slice(&(10 + body.len() as u32).to_be_bytes());
    b.extend_from_slice(&rc.to_be_bytes());
    b.extend_from_slice(body);
    b
}

/// GetCapability(TPM_CAP_PCRS) body: SHA-256 with PCRs 0-23.
const BANKS: [u8; 15] = [0, 0, 0, 0, 5, 0, 0, 0, 1, 0x00, 0x0B, 3, 0xff, 0xff, 0xff];

/// Everything the agent does with the TPM.
fn scenario(dev: &Device, id_object: &[u8], enc_secret: &[u8], peer: &[u8]) -> db_tpmdev::Result<()> {
    let end = dev.load_endorsement()?;
    let ak = dev.create_ak()?;
    dev.read_public(ak.handle)?;
    dev.read_pcrs(&DEFAULT_PCRS)?;
    dev.active_banks()?;
    dev.quote(&ak, &[7u8; 32], &DEFAULT_PCRS)?;
    dev.activate_credential(&ak, &end.ek, id_object, enc_secret)?;
    dev.nv_read_public(NV_ECC_EK_CERT)?;
    let bound = dev.create_bound_key(&DEFAULT_PCRS)?;
    dev.certify(&bound, &ak, &[9u8; 32])?;
    dev.bound_ecdh(&bound, &DEFAULT_PCRS, peer)?;
    dev.flush_handle(bound.handle)?;
    dev.flush_handle(ak.handle)?;
    dev.flush_handle(end.ek.handle)
}

fn peer_point() -> Vec<u8> {
    use p256::elliptic_curve::Generate as _;
    p256::SecretKey::try_generate_from_rng(&mut getrandom::SysRng).unwrap().public_key().to_sec1_bytes().to_vec()
}

#[test]
fn mutated_responses_never_panic() {
    let Some(f) = Fixture::new(TEST_CMDLINE) else { return };
    let end = f.dev.load_endorsement().unwrap();
    let ak = f.dev.create_ak().unwrap();
    let ch = make_credential(&parse_ek_public(&end.ek.public_raw).unwrap(), &ak.name).unwrap();
    f.dev.flush(&ak);
    f.dev.flush(&end.ek);
    // Record a real session (swtpm serves one connection at a time).
    f.dev.close();
    let log = Arc::new(Mutex::new(Vec::new()));
    let (inner, _) = db_tpmdev::transport::open(&f.tpm.spec()).unwrap();
    let rec = Device::with_transport(Box::new(Recorder { inner, log: log.clone() }), Mode::Swtpm);
    let peer = peer_point();
    scenario(&rec, &ch.id_object, &ch.enc_secret, &peer).unwrap();
    drop(rec);
    let recorded = log.lock().unwrap().clone();
    assert!(recorded.len() >= 15, "{} responses", recorded.len());
    let replay = |i: usize, m: &[u8]| {
        let mut rsps = recorded.clone();
        rsps[i] = m.to_vec();
        let (dev, _) = script(rsps);
        let r = std::panic::catch_unwind(AssertUnwindSafe(|| scenario(&dev, &ch.id_object, &ch.enc_secret, &peer)));
        match r {
            Ok(r) => r.is_ok(),
            Err(_) => panic!("panic with response {i} replaced by {m:02x?}"),
        }
    };
    // The verbatim recording replays.
    assert!(replay(0, &recorded[0]), "verbatim replay failed");
    let mut rng = rand::rng();
    let (mut runs, mut accepted) = (0usize, 0usize);
    for (i, orig) in recorded.iter().enumerate() {
        for n in 0..orig.len() {
            // Truncated as sent, and with the size field fixed up so the
            // body parsers see the short structure.
            let mut m = orig[..n].to_vec();
            accepted += usize::from(replay(i, &m));
            if m.len() >= 6 {
                m[2..6].copy_from_slice(&(n as u32).to_be_bytes());
                accepted += usize::from(replay(i, &m));
            }
            runs += 2;
        }
        for _ in 0..300 {
            let mut m = orig.clone();
            for _ in 0..rng.random_range(1..4) {
                let at = rng.random_range(0..m.len());
                m[at] = rng.random();
            }
            if rng.random::<bool>() && m.len() >= 6 {
                let extra: Vec<u8> = (0..rng.random_range(1..40)).map(|_| rng.random()).collect();
                m.extend(extra);
                let n = m.len() as u32;
                m[2..6].copy_from_slice(&n.to_be_bytes());
            }
            accepted += usize::from(replay(i, &m));
            runs += 1;
        }
    }
    println!("{runs} mutated replays, {accepted} still completed");
    // Direct parser fuzzing with random headers and bodies.
    for _ in 0..20_000 {
        let n = rng.random_range(0..64);
        let b: Vec<u8> = (0..n).map(|_| rng.random()).collect();
        let _ = db_tpmdev::parse_response("fuzz", &b, rng.random_range(0..3), rng.random_range(0..3));
    }
}

#[test]
fn startup_on_rc_initialize() {
    // Not started: Startup(CLEAR), then the command again.
    let (dev, codes) = script(vec![rsp(RC_INITIALIZE, &[]), rsp(0, &[]), rsp(0, &BANKS)]);
    assert_eq!(dev.active_banks().unwrap(), vec![ALG_SHA256]);
    assert_eq!(*codes.lock().unwrap(), vec![CC_GET_CAPABILITY, CC_STARTUP, CC_GET_CAPABILITY]);
    // Startup answering "already initialized" is fine.
    let (dev, _) = script(vec![rsp(RC_INITIALIZE, &[]), rsp(RC_INITIALIZE, &[]), rsp(0, &BANKS)]);
    assert_eq!(dev.active_banks().unwrap(), vec![ALG_SHA256]);
    // A failing Startup, or a second TPM_RC_INITIALIZE, is an error (one retry).
    let (dev, codes) = script(vec![rsp(RC_INITIALIZE, &[]), rsp(0x101, &[])]);
    let err = dev.active_banks().unwrap_err();
    assert!(err.to_string().contains("TPM_RC_FAILURE"), "{err}");
    assert_eq!(codes.lock().unwrap().len(), 2);
    let (dev, codes) = script(vec![rsp(RC_INITIALIZE, &[]), rsp(0, &[]), rsp(RC_INITIALIZE, &[])]);
    assert_eq!(dev.active_banks().unwrap_err().response_code().map(|r| r.0), Some(RC_INITIALIZE));
    assert_eq!(codes.lock().unwrap().len(), 3);
}

/// A fake TPM on TCP: GetCapability answers; FlushContext gets a header
/// claiming 5 bytes, PCR_Read one claiming 2 MiB, anything else a header
/// claiming 100 bytes followed by EOF.
fn fake_tcp_tpm() -> (String, Arc<AtomicUsize>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let conns = Arc::new(AtomicUsize::new(0));
    let c = conns.clone();
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { return };
            c.fetch_add(1, Ordering::SeqCst);
            let mut hdr = [0u8; 10];
            while s.read_exact(&mut hdr).is_ok() {
                let size = u32::from_be_bytes(hdr[2..6].try_into().unwrap()) as usize;
                let mut rest = vec![0u8; size.saturating_sub(10)];
                if s.read_exact(&mut rest).is_err() {
                    break;
                }
                let (reply, hang_up) = match u32::from_be_bytes(hdr[6..10].try_into().unwrap()) {
                    CC_GET_CAPABILITY => (rsp(0, &BANKS), false),
                    CC_FLUSH_CONTEXT => (vec![0x80, 0x01, 0, 0, 0, 5, 0, 0, 0, 0], false),
                    CC_PCR_READ => (vec![0x80, 0x01, 0, 0x20, 0, 0, 0, 0, 0, 0], false),
                    _ => (vec![0x80, 0x01, 0, 0, 0, 100, 0, 0, 0, 0], true),
                };
                if s.write_all(&reply).is_err() || hang_up {
                    break;
                }
            }
        }
    });
    (addr, conns)
}

#[test]
fn tcp_transport_framing_and_redial() {
    let (addr, conns) = fake_tcp_tpm();
    let dev = Device::open(&format!("swtpm:tcp:{addr}")).unwrap();
    assert_eq!(dev.mode(), Mode::Swtpm);
    assert_eq!(dev.active_banks().unwrap(), vec![ALG_SHA256]);
    let conn = |n: usize| assert_eq!(conns.load(Ordering::SeqCst), n);
    conn(1);
    let err = dev.flush_handle(0x8000_0000).unwrap_err();
    assert!(err.to_string().contains("bad response size 5"), "{err}");
    assert_eq!(dev.active_banks().unwrap(), vec![ALG_SHA256]);
    conn(2);
    assert!(dev.read_pcrs(&[0]).unwrap_err().to_string().contains("bad response size"));
    assert_eq!(dev.active_banks().unwrap(), vec![ALG_SHA256]);
    conn(3);
    assert!(dev.read_public(0x8000_0000).is_err(), "truncated response accepted");
    assert_eq!(dev.active_banks().unwrap(), vec![ALG_SHA256]);
    conn(4);
    dev.close();
    assert_eq!(dev.active_banks().unwrap(), vec![ALG_SHA256]);
    conn(5);
}

#[test]
fn open_errors() {
    assert!(Device::open("tpm0").unwrap_err().to_string().contains("unknown TPM"));
    assert!(Device::open("swtpm:unix:/nonexistent-dbtpm/swtpm.sock").is_err());
    assert!(Device::open("/dev/nonexistent-dbtpm").is_err());
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    assert!(Device::open(&format!("swtpm:tcp:{free}")).is_err());
}

#[test]
fn hardware_mode_refusals_and_attester_contract() {
    let Some(f) = Fixture::new(TEST_CMDLINE) else { return };
    let ca = db_devca::load_dev_ca(&f.ca_dir).unwrap();
    f.dev.close();
    let (t, mode) = db_tpmdev::transport::open(&f.tpm.spec()).unwrap();
    assert_eq!(mode, Mode::Swtpm);
    let hw = Device::with_transport(t, Mode::Hardware);
    let all: Vec<u32> = (0..24).collect();
    let pcrs = hw.read_pcrs(&all).unwrap();
    let cert = hw.read_nv(NV_ECC_EK_CERT).unwrap();
    let refused = |r: db_tpmdev::Result<()>| assert!(r.unwrap_err().to_string().contains("refusing"));
    refused(hw.simulate_boot(|_| panic!("boot plan ran on hardware")).map(drop));
    refused(hw.provision_ek(&ca));
    refused(hw.pcr_extend(16, &db_tpmattest::digests_of(&[ALG_SHA256], b"x")));
    refused(hw.write_platform_nv(NV_ECC_EK_CERT, b"forged"));
    refused(hw.undefine_platform_nv(NV_ECC_EK_CERT));
    assert_eq!(hw.read_pcrs(&all).unwrap(), pcrs, "PCRs changed");
    assert_eq!(hw.read_nv(NV_ECC_EK_CERT).unwrap(), cert, "EK certificate changed");

    // The attester works on "hardware" and validates challenges.
    let att = Attester::new(hw.clone(), Some(f.event_log.clone())).unwrap();
    assert_eq!(att.mode(), "hardware");
    let bad = |nonce: &[u8], pcrs: &[i64]| matches!(att.attest(nonce, b"{}", pcrs), Err(AttestError::BadChallenge(_)));
    let ok_pcrs: Vec<i64> = DEFAULT_PCRS.iter().map(|&p| i64::from(p)).collect();
    assert!(bad(&[0; 15], &ok_pcrs) && bad(&[0; 65], &ok_pcrs));
    assert!(bad(&[0; 16], &[]) && bad(&[0; 16], &[0; 25]) && bad(&[0; 16], &[-1]) && bad(&[0; 16], &[24]));
    assert!(att.attest(&[0; 16], b"{}", &[0, 23]).is_ok() && att.attest(&[0; 64], b"{}", &[0; 24]).is_ok());
    // Garbage challenges fail without breaking the attester.
    assert!(matches!(att.activate(&[1, 2, 3], &[4, 5]), Err(AttestError::Tpm(_))));
    let ch = make_credential(&parse_ek_public(att.ek_public()).unwrap(), att.ak_name()).unwrap();
    assert_eq!(att.activate(&ch.id_object, &ch.enc_secret).unwrap().as_slice(), ch.secret.as_slice());
    assert_eq!(parse_attestation_key(att.ak_public()).unwrap().name, att.ak_name());
    att.close();
    att.close();
    assert!(matches!(att.attest(&[0; 32], b"{}", &ok_pcrs), Err(AttestError::Tpm(_))));
    assert!(matches!(att.activate(&ch.id_object, &ch.enc_secret), Err(AttestError::Tpm(_))));
    drop(att);
    // A stale event log is refused at startup (and the keys are flushed).
    let mut stale = f.event_log.clone();
    let initrd = db_tpmattest::digest_of(ALG_SHA256, b"test initrd");
    let at = stale.windows(initrd.len()).rposition(|w| w == initrd.as_slice()).unwrap();
    stale[at] ^= 1;
    assert!(Attester::new(hw.clone(), Some(stale)).is_err());
    assert!(Attester::new(hw.clone(), Some(Vec::new())).is_err());
    for _ in 0..4 {
        drop(Attester::new(hw.clone(), Some(f.event_log.clone())).unwrap());
    }
    drop(hw);
    // The fixture's own connection redials.
    assert_eq!(f.dev.read_pcrs(&all).unwrap(), pcrs);
}
