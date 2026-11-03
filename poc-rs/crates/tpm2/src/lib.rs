//! TPM 2.0 data structures for the Darkbloom AMD PoC.
//!
//! Pure functions only (no device I/O): strict, bounds-checked parsing and
//! canonical marshaling of the handful of structures the verifier and the
//! provider exchange (`TPMT_PUBLIC`, `TPMS_ATTEST`, `TPMT_SIGNATURE`,
//! `TPML_PCR_SELECTION`, `TPMS_NV_PUBLIC`), object names, the TPM KDFs
//! (KDFa, KDFe) and the TCG EK / Darkbloom AK templates.
//!
//! Every parser consumes its whole input, rejects trailing bytes, bounds
//! every size field and never panics on untrusted input. Unknown algorithm
//! selectors are rejected rather than skipped, so a structure that parses
//! re-marshals to exactly the same bytes (the Go verifier's "canonical
//! encoding" check).

#![forbid(unsafe_code)]

mod attest;
mod buf;
pub mod consts;
mod hash;
mod kdf;
mod nv;
mod pcr;
mod public;
mod signature;
mod templates;

pub use attest::{Attest, Attested};
pub use buf::{Reader, Writer};
pub use hash::{HashAlg, Hasher};
pub use kdf::{kdfa, kdfe};
pub use nv::NvPublic;
pub use pcr::{PcrSelection, PcrSelectionList};
pub use public::{AsymScheme, EccParms, KdfScheme, Public, PublicParams, RsaParms, SchemeDetails, SymDefObject, Unique};
pub use signature::Signature;
pub use templates::{EK_POLICY_DIGEST, ak_template, ecc_ek_template, rsa_ek_template};

/// Errors from parsing or marshaling TPM structures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The input ended early.
    #[error("tpm2: truncated at offset {at} (need {need} bytes, have {have})")]
    Truncated {
        /// Offset at which more data was needed.
        at: usize,
        /// Bytes needed.
        need: usize,
        /// Bytes available.
        have: usize,
    },
    /// Bytes left over after a complete structure.
    #[error("tpm2: {0} trailing bytes")]
    Trailing(usize),
    /// A sized field exceeds its structure's limit.
    #[error("tpm2: {what} is {len} bytes, above the {max} byte limit")]
    TooLarge {
        /// Field name.
        what: &'static str,
        /// Declared length.
        len: usize,
        /// Limit.
        max: usize,
    },
    /// An algorithm or selector this implementation does not accept.
    #[error("tpm2: unsupported {what} 0x{value:04x}")]
    Unsupported {
        /// What was selected.
        what: &'static str,
        /// The selector value.
        value: u32,
    },
    /// Any other structural problem.
    #[error("tpm2: {0}")]
    Invalid(String),
}

/// Result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Computes a TPM object name: `nameAlg || H_nameAlg(publicArea)`.
pub fn object_name(name_alg: u16, public_area: &[u8]) -> Result<Vec<u8>> {
    let h = HashAlg::from_id(name_alg).ok_or(Error::Unsupported { what: "name algorithm", value: u32::from(name_alg) })?;
    let mut out = Vec::with_capacity(2 + h.size());
    out.extend_from_slice(&name_alg.to_be_bytes());
    out.extend_from_slice(&h.digest(public_area));
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod fuzz_tests {
    //! Randomized robustness: truncated, mutated and random inputs must be
    //! rejected cleanly (no panics), and anything accepted must re-marshal to
    //! the exact input bytes.
    use super::*;
    use rand::{RngExt as _, SeedableRng as _};

    fn sample_attest() -> Vec<u8> {
        let a = Attest {
            magic: consts::GENERATED_VALUE,
            attest_type: consts::ST_ATTEST_QUOTE,
            qualified_signer: vec![0, 0x0b, 1, 2, 3],
            extra_data: vec![9; 32],
            clock: 123_456,
            reset_count: 2,
            restart_count: 0,
            safe: true,
            firmware_version: 0x000a_0006_0000_0004,
            attested: Attested::Quote {
                pcr_select: PcrSelectionList(vec![PcrSelection::new(consts::ALG_SHA256, &[0, 1, 2, 3, 4, 5, 6, 7, 9, 12, 14])]),
                pcr_digest: vec![7; 32],
            },
        };
        a.to_bytes().unwrap()
    }

    fn sample_signature() -> Vec<u8> {
        Signature::Ecc { alg: consts::ALG_ECDSA, hash: consts::ALG_SHA256, r: vec![1; 32], s: vec![2; 32] }.to_bytes().unwrap()
    }

    fn sample_nv() -> Vec<u8> {
        NvPublic {
            index: 0x01C0_000A,
            name_alg: consts::ALG_SHA256,
            attributes: consts::NV_AUTHREAD | consts::NV_PPREAD,
            auth_policy: vec![],
            data_size: 700,
        }
        .to_bytes()
        .unwrap()
    }

    fn check<T>(sample: &[u8], parse: impl Fn(&[u8]) -> Result<T>, remarshal: impl Fn(&T) -> Vec<u8>) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let parsed = parse(sample).unwrap();
        assert_eq!(remarshal(&parsed), sample);
        for n in 0..sample.len() {
            assert!(parse(&sample[..n]).is_err(), "truncated at {n} accepted");
        }
        let mut extra = sample.to_vec();
        extra.push(0);
        assert!(parse(&extra).is_err(), "trailing byte accepted");
        for _ in 0..20_000 {
            let mut m = sample.to_vec();
            for _ in 0..rng.random_range(1..4) {
                let i = rng.random_range(0..m.len());
                m[i] = rng.random();
            }
            if let Ok(p) = parse(&m) {
                assert_eq!(remarshal(&p), m, "accepted a non-canonical encoding");
            }
        }
        for _ in 0..5_000 {
            let n = rng.random_range(0..256);
            let b: Vec<u8> = (0..n).map(|_| rng.random()).collect();
            let _ = parse(&b);
        }
    }

    #[test]
    fn attest_parser() {
        check(&sample_attest(), Attest::parse, |a| a.to_bytes().unwrap());
        let mut bad_safe = sample_attest();
        // clockInfo.safe sits after magic(4) type(2) signer(2+5) extra(2+32) clock(8) reset(4) restart(4).
        bad_safe[4 + 2 + 7 + 34 + 16] = 2;
        assert!(Attest::parse(&bad_safe).is_err(), "safe=2 accepted");
    }

    #[test]
    fn signature_parser() {
        check(&sample_signature(), Signature::parse, |s| s.to_bytes().unwrap());
        let rsa = Signature::Rsa { alg: consts::ALG_RSASSA, hash: consts::ALG_SHA256, sig: vec![5; 256] }.to_bytes().unwrap();
        check(&rsa, Signature::parse, |s| s.to_bytes().unwrap());
    }

    #[test]
    fn nv_public_parser() {
        check(&sample_nv(), NvPublic::parse, |p| p.to_bytes().unwrap());
    }

    #[test]
    fn pcr_selection_list_parser() {
        let l =
            PcrSelectionList(vec![PcrSelection::new(consts::ALG_SHA256, &[0, 7, 23, 24, 99]), PcrSelection::new(consts::ALG_SHA1, &[1])]);
        assert_eq!(l.0[0].indices(), vec![0, 7, 23]);
        let b = l.to_bytes().unwrap();
        let parse = |b: &[u8]| {
            let mut r = Reader::new(b);
            let l = PcrSelectionList::parse(&mut r)?;
            r.finish()?;
            Ok(l)
        };
        check(&b, parse, |l| l.to_bytes().unwrap());
    }

    #[test]
    fn kdf_known_lengths() {
        let k = kdfa(HashAlg::Sha256, b"key", "STORAGE", b"ctx", b"", 128);
        assert_eq!(k.len(), 16);
        let k = kdfa(HashAlg::Sha256, b"key", "INTEGRITY", b"", b"", 256);
        assert_eq!(k.len(), 32);
        let k = kdfe(HashAlg::Sha256, b"z", "IDENTITY", b"u", b"v", 256);
        assert_eq!(k.len(), 32);
        // Odd bit counts mask the top byte.
        let k = kdfa(HashAlg::Sha256, b"key", "X", b"", b"", 9);
        assert_eq!(k.len(), 2);
        assert!(k[0] <= 1);
    }
}
