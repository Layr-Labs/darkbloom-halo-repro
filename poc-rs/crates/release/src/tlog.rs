//! A minimal RFC 6962/9162 Merkle-tree transparency log for Node OS
//! releases. Verifiers accept only logged releases, so a release signed
//! with a stolen or coerced key cannot be used without appearing in a
//! public, append-only log that providers, auditors and AMD can monitor.

use crate::dsse::key_id;
use crate::{Error, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use db_gojson::GoTime;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

/// RFC 6962 leaf hash: `SHA-256(0x00 || data)`.
pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(data);
    h.finalize().into()
}

/// RFC 6962 interior node hash: `SHA-256(0x01 || l || r)`.
pub fn node_hash(l: &[u8], r: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

fn largest_power_of_two_below(n: usize) -> usize {
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves {
        [] => Sha256::digest([]).into(),
        [one] => *one,
        _ => {
            let k = largest_power_of_two_below(leaves.len());
            let (l, r) = leaves.split_at(k);
            node_hash(&mth(l), &mth(r))
        }
    }
}

fn path(m: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    if leaves.len() <= 1 {
        return Vec::new();
    }
    let k = largest_power_of_two_below(leaves.len());
    let (l, r) = leaves.split_at(k);
    if m < k {
        let mut p = path(m, l);
        p.push(mth(r));
        p
    } else {
        let mut p = path(m - k, r);
        p.push(mth(l));
        p
    }
}

/// Checks an RFC 9162 inclusion proof of `entry` at `index` in a tree of
/// `size` leaves with root `root`.
pub fn verify_inclusion(entry: &[u8], index: u64, size: u64, proof: &[Vec<u8>], root: &[u8]) -> bool {
    if index >= size {
        return false;
    }
    let (mut fn_, mut sn) = (index, size - 1);
    let mut r = leaf_hash(entry);
    for p in proof {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node_hash(p, &r);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && r.as_slice() == root
}

/// A signed tree head.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TreeHead {
    /// Number of leaves.
    pub size: u64,
    /// Root hash (hex).
    pub root: String,
    /// Signing time.
    pub timestamp: GoTime,
    /// Log key ID.
    pub keyid: String,
    /// Base64 Ed25519 signature over [`TreeHead::signed_bytes`].
    pub sig: String,
}

impl TreeHead {
    /// The bytes the log key signs.
    pub fn signed_bytes(&self) -> Vec<u8> {
        format!("darkbloom-amd/release-log/v1\n{}\n{}\n{}\n", self.size, self.root, self.timestamp.unix_nano()).into_bytes()
    }

    /// Checks the tree head signature.
    pub fn verify(&self, public: &VerifyingKey) -> Result<()> {
        let bad = || Error::invalid("tree head signature does not verify");
        let raw = STANDARD.decode(self.sig.as_bytes()).map_err(|_| bad())?;
        let sig = ed25519_dalek::Signature::from_slice(&raw).map_err(|_| bad())?;
        public.verify_strict(&self.signed_bytes(), &sig).map_err(|_| bad())
    }
}

/// A release envelope with its log inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Inclusion {
    /// Exact DSSE envelope bytes that were logged.
    #[serde(with = "db_gojson::b64")]
    pub envelope: Vec<u8>,
    /// Leaf index.
    pub index: u64,
    /// Audit path (hex).
    #[serde(with = "db_gojson::nil_vec")]
    pub proof: Vec<String>,
    /// Signed tree head the proof is against.
    pub head: TreeHead,
}

impl Inclusion {
    /// Checks the tree head signature and the inclusion proof.
    pub fn verify(&self, log_key: &VerifyingKey) -> Result<()> {
        self.head.verify(log_key)?;
        let root = hex::decode(&self.head.root).map_err(|e| Error::invalid(e.to_string()))?;
        let proof =
            self.proof.iter().map(hex::decode).collect::<std::result::Result<Vec<_>, _>>().map_err(|e| Error::invalid(e.to_string()))?;
        if !verify_inclusion(&self.envelope, self.index, self.head.size, &proof, &root) {
            return Err(Error::invalid("envelope is not included in the release log"));
        }
        Ok(())
    }
}

#[derive(Default)]
struct LogState {
    entries: Vec<Vec<u8>>,
    leaves: Vec<[u8; 32]>,
}

/// An in-memory append-only log (the PoC's stand-in for a public, witnessed
/// log such as Trillian/Tessera or Sigstore Rekor).
pub struct Log {
    key: SigningKey,
    state: Mutex<LogState>,
}

impl std::fmt::Debug for Log {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Log").field("keyid", &key_id(&self.key.verifying_key())).finish_non_exhaustive()
    }
}

impl Log {
    /// Creates a log signed by `key`.
    pub fn new(key: SigningKey) -> Self {
        Self { key, state: Mutex::new(LogState::default()) }
    }

    /// The log's public key.
    pub fn public_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LogState> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Adds an entry (idempotently) and returns its index.
    pub fn append(&self, entry: &[u8]) -> u64 {
        let mut st = self.lock();
        if let Some(i) = st.entries.iter().position(|e| e == entry) {
            return i as u64;
        }
        st.entries.push(entry.to_vec());
        st.leaves.push(leaf_hash(entry));
        (st.entries.len() - 1) as u64
    }

    fn head_locked(&self, st: &LogState) -> TreeHead {
        let mut t = TreeHead {
            size: st.leaves.len() as u64,
            root: hex::encode(mth(&st.leaves)),
            timestamp: GoTime::now_utc(),
            keyid: key_id(&self.key.verifying_key()),
            sig: String::new(),
        };
        t.sig = STANDARD.encode(self.key.sign(&t.signed_bytes()).to_bytes());
        t
    }

    /// A freshly signed tree head.
    pub fn head(&self) -> TreeHead {
        let st = self.lock();
        self.head_locked(&st)
    }

    /// An inclusion proof for `entry` against the current head.
    pub fn prove(&self, entry: &[u8]) -> Result<Inclusion> {
        let st = self.lock();
        let i = st.entries.iter().position(|e| e == entry).ok_or_else(|| Error::invalid("entry is not in the log"))?;
        Ok(Inclusion {
            envelope: entry.to_vec(),
            index: i as u64,
            proof: path(i, &st.leaves).iter().map(hex::encode).collect(),
            head: self.head_locked(&st),
        })
    }
}
