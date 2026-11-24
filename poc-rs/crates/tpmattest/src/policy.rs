//! Evidence evaluation: the end-to-end verifier and trust tiers.

use crate::credential::{EndorsementKey, parse_ek_public};
use crate::ekchain::{RootKind, TrustBundle};
use crate::eventlog::{
    ALG_SHA256, EFI_GLOBAL_VARIABLE_GUID, EV_ACTION, EV_EFI_ACTION, EV_EFI_VARIABLE_DRIVER_CONFIG, EV_SCRTM_VERSION, EV_SEPARATOR,
    EventLog, decode_utf16, digest_of, parse_event_log, parse_uefi_variable,
};
use crate::quote::{AttestationKey, Quote, parse_attestation_key, pcr_digest, verify_quote};
use crate::statement::{Statement, parse_statement, provider_id_from_ek, quote_extra_data};
use db_gojson::GoTime;
use db_release::{Manifest, Policy};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::fmt::Display;
use std::sync::Arc;

/// The trust tier a verdict grants.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum Tier {
    /// Rejected.
    #[default]
    Rejected,
    /// swtpm + dev CA: demo traffic only.
    DevSimulated,
    /// Genuine AMD TPM, but a dev-channel OS: demo traffic only.
    HardwareDevOs,
    /// Genuine AMD TPM + approved Node OS.
    Attested,
    /// The above + TSME active.
    AttestedEncryptedMemory,
    /// Any other value received over the wire.
    Other(String),
}

impl Tier {
    /// The wire string.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Rejected => "rejected",
            Self::DevSimulated => "dev-simulated",
            Self::HardwareDevOs => "hardware-dev-os",
            Self::Attested => "attested",
            Self::AttestedEncryptedMemory => "attested+encrypted-memory",
            Self::Other(s) => s,
        }
    }

    /// Parses the wire string.
    pub fn parse(s: &str) -> Self {
        match s {
            "rejected" => Self::Rejected,
            "dev-simulated" => Self::DevSimulated,
            "hardware-dev-os" => Self::HardwareDevOs,
            "attested" => Self::Attested,
            "attested+encrypted-memory" => Self::AttestedEncryptedMemory,
            other => Self::Other(other.to_owned()),
        }
    }

    /// Ordering used for minimum-tier routing decisions.
    pub fn rank(&self) -> u8 {
        match self {
            Self::DevSimulated | Self::HardwareDevOs => 1,
            Self::Attested => 2,
            Self::AttestedEncryptedMemory => 3,
            _ => 0,
        }
    }
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Tier {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Tier {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s: String = db_gojson::null_default(d)?;
        Ok(Self::parse(&s))
    }
}

/// The quoted PCR set for the Type #1 boot path: firmware and configuration
/// (0-7), Linux EFI stub initrd + load options (9), kernel command line (12)
/// and shim MOK state (14). A UKI boot adds PCR 11.
pub const DEFAULT_PCRS: [u32; 11] = [0, 1, 2, 3, 4, 5, 6, 7, 9, 12, 14];
/// The same platform and boot checks, adding the UKI section measurement.
pub const UKI_PCRS: [u32; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 9, 11, 12, 14];

/// Flags that must appear in a production release's measured kernel command
/// line (debugfs=off closes the 0444 amdgpu_vram file lockdown leaves
/// readable).
pub const PRODUCTION_CMDLINE_FLAGS: [&str; 4] = ["lockdown=confidentiality", "debugfs=off", "iommu.strict=1", "module.sig_enforce=1"];

/// Everything a provider sends to be verified. All of it is untrusted.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Evidence {
    /// EK certificate (DER).
    #[serde(with = "db_gojson::b64")]
    pub ek_cert: Vec<u8>,
    /// On-chip ICAs (DER).
    #[serde(with = "db_gojson::b64_list")]
    pub ek_icas: Vec<Vec<u8>>,
    /// EK TPMT_PUBLIC.
    #[serde(with = "db_gojson::b64")]
    pub ek_public: Vec<u8>,
    /// AK TPMT_PUBLIC.
    #[serde(with = "db_gojson::b64")]
    pub ak_public: Vec<u8>,
    /// Statement JSON (exact bytes the quote binds).
    #[serde(with = "db_gojson::b64")]
    pub statement: Vec<u8>,
    /// Verifier nonce.
    #[serde(with = "db_gojson::b64")]
    pub nonce: Vec<u8>,
    /// TPMS_ATTEST.
    #[serde(with = "db_gojson::b64")]
    pub quote_attest: Vec<u8>,
    /// TPMT_SIGNATURE.
    #[serde(with = "db_gojson::b64")]
    pub quote_sig: Vec<u8>,
    /// TCG event log.
    #[serde(with = "db_gojson::b64")]
    pub event_log: Vec<u8>,
}

/// What the verifier knows independently of the evidence.
#[derive(Debug, Clone, Default)]
pub struct Expect {
    /// Expected session (empty: not checked).
    pub session_id: String,
    /// Expected account (empty: not checked, e.g. consumer-side).
    pub account_id: String,
    /// Expected PCR selection.
    pub pcrs: Vec<u32>,
    /// Credential activation (or a verified enrollment record) binds the AK
    /// to this EK.
    pub ak_activated: bool,
}

/// A release manifest whose signature was verified.
#[derive(Debug, Clone)]
pub struct TrustedRelease {
    /// The manifest.
    pub manifest: Arc<Manifest>,
    /// The exact envelope bytes (as logged).
    pub envelope: Vec<u8>,
    /// Whether it is in the release transparency log.
    pub logged: bool,
}

/// One policy decision, kept for the verdict's audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Check {
    /// Check name.
    pub name: String,
    /// Outcome.
    pub ok: bool,
    /// `"required"`, `"tier"` or `"info"`.
    pub effect: String,
    /// Detail.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

/// The outcome of [`Verifier::evaluate`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Verdict {
    /// Overall outcome.
    pub ok: bool,
    /// Granted tier.
    pub tier: Tier,
    /// Device identity.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub device_id: String,
    /// Endorsement root name.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub root: String,
    /// Endorsement root kind.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_kind: Option<RootKind>,
    /// TPM firmware SVN (-1 when unknown).
    #[serde(rename = "tpm_firmware_svn")]
    pub svn: i64,
    /// TPM firmware version from the EK subject.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tpm_firmware: String,
    /// Quote resetCount.
    pub reset_count: u32,
    /// Quote restartCount.
    pub restart_count: u32,
    /// Quote clock (ms).
    #[serde(rename = "clock_ms")]
    pub clock: u64,
    /// Matched release ID.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub release: String,
    /// Matched release digest.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub release_digest: String,
    /// Replayed PCR values (hex) and the S-CRTM version.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", deserialize_with = "db_gojson::null_default")]
    pub pcrs: BTreeMap<String, String>,
    /// Audit trail.
    #[serde(with = "db_gojson::nil_vec")]
    pub checks: Vec<Check>,
    /// The parsed statement (not serialized).
    #[serde(skip)]
    pub statement: Option<Statement>,
    /// The verified quote (not serialized).
    #[serde(skip)]
    pub quote: Option<Quote>,
    /// The matched release (not serialized).
    #[serde(skip)]
    pub manifest: Option<Arc<Manifest>>,
    /// The EK (not serialized).
    #[serde(skip)]
    pub ek: Option<EndorsementKey>,
    /// The AK (not serialized).
    #[serde(skip)]
    pub ak: Option<AttestationKey>,
    /// The verified TPM-resident ECDH key, if the provider offers one (not
    /// serialized).
    #[serde(skip)]
    pub bound_key: Option<p256::PublicKey>,
}

impl Verdict {
    fn add(&mut self, name: &str, ok: bool, effect: &str, detail: impl Into<String>) -> bool {
        self.checks.push(Check { name: name.to_owned(), ok, effect: effect.to_owned(), detail: detail.into() });
        ok
    }

    fn reject(mut self, name: &str, detail: impl Into<String>) -> Self {
        self.add(name, false, "required", detail);
        self.ok = false;
        self.tier = Tier::Rejected;
        self
    }

    fn rejected(mut self) -> Self {
        self.ok = false;
        self.tier = Tier::Rejected;
        self
    }

    /// The failed required checks.
    pub fn failed(&self) -> Vec<&Check> {
        self.checks.iter().filter(|c| !c.ok && c.effect == "required").collect()
    }
}

/// Formats a list like Go's `%v` of a slice: `[a b c]`.
pub(crate) fn go_list<T: Display>(items: impl IntoIterator<Item = T>) -> String {
    let v: Vec<String> = items.into_iter().map(|i| i.to_string()).collect();
    format!("[{}]", v.join(" "))
}

/// A clock for verifiers (tests pin time).
pub type Clock = Arc<dyn Fn() -> GoTime + Send + Sync>;

/// Evaluates provider evidence.
#[derive(Clone, Default)]
pub struct Verifier {
    /// Accepted endorsement roots.
    pub bundle: TrustBundle,
    /// Signed releases.
    pub releases: Vec<TrustedRelease>,
    /// Release policy (none: nothing is admitted).
    pub release_policy: Option<Policy>,
    /// Accept development endorsement roots.
    pub allow_dev_roots: bool,
    /// Accepted job KEMs (default: X-Wing only).
    pub allowed_kems: Vec<String>,
    /// Required SHA-256 PCR selection. Empty selects the legacy Type #1 set.
    pub required_pcrs: Vec<u32>,
    /// Clock override.
    pub now: Option<Clock>,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier")
            .field("roots", &self.bundle.roots.len())
            .field("releases", &self.releases.len())
            .field("allow_dev_roots", &self.allow_dev_roots)
            .finish_non_exhaustive()
    }
}

fn same_set(a: &[u32], b: &[u32]) -> bool {
    let mut a = a.to_vec();
    let mut b = b.to_vec();
    a.sort_unstable();
    b.sort_unstable();
    a == b
}

fn short(s: &str) -> &str {
    s.get(..12).unwrap_or(s)
}

fn is_hex(s: &str) -> bool {
    db_release::is_hex(s)
}

/// Compares firmware versions like "LFGB0.03.03". `None` when the two are
/// from different firmware families.
pub fn compare_firmware_version(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    fn split(s: &str) -> Option<(String, Vec<u64>)> {
        let s = s.trim();
        let alpha = s.bytes().take_while(u8::is_ascii_alphabetic).count();
        let (fam, rest) = s.split_at(alpha);
        if fam.is_empty() || rest.is_empty() {
            return None;
        }
        let parts: Vec<&str> = rest.split('.').collect();
        if parts.iter().any(|p| p.is_empty() || !p.bytes().all(|c| c.is_ascii_digit())) {
            return None;
        }
        // Go's strconv.Atoi failure (overflow) reads as 0.
        Some((fam.to_ascii_lowercase(), parts.iter().map(|p| p.parse().unwrap_or(0)).collect()))
    }
    let (fa, pa) = split(a)?;
    let (fb, pb) = split(b)?;
    if fa != fb {
        return None;
    }
    for i in 0..pa.len().max(pb.len()) {
        let x = pa.get(i).copied().unwrap_or(0);
        let y = pb.get(i).copied().unwrap_or(0);
        if x != y {
            return Some(x.cmp(&y));
        }
    }
    Some(std::cmp::Ordering::Equal)
}

/// Whether `flag` is satisfied by the measured command line `fields`: a
/// `key=value` flag needs at least one `key=value` and no `key=` with
/// another value (the kernel honours the last occurrence); a bare flag
/// needs to be present.
fn cmdline_flag_ok(fields: &[&str], flag: &str) -> bool {
    match flag.split_once('=') {
        Some((key, _)) => {
            let prefix = format!("{key}=");
            let mut found = false;
            for f in fields {
                if f.starts_with(&prefix) {
                    if *f != flag {
                        return false;
                    }
                    found = true;
                }
            }
            found
        }
        None => fields.contains(&flag),
    }
}

impl Verifier {
    /// The exact PCR selection required for quotes and TPM-bound keys.
    pub fn pcrs(&self) -> &[u32] {
        if self.required_pcrs.is_empty() { &DEFAULT_PCRS } else { &self.required_pcrs }
    }

    fn now(&self) -> GoTime {
        match &self.now {
            Some(f) => f(),
            None => GoTime::now_utc(),
        }
    }

    /// Verifies evidence end to end and decides a trust tier. Fails closed:
    /// any parsing or cryptographic failure rejects.
    pub fn evaluate(&self, ev: &Evidence, ex: &Expect) -> Verdict {
        let mut v = Verdict { svn: -1, ..Verdict::default() };
        let now = self.now();

        // 1. Keys.
        let ek = match parse_ek_public(&ev.ek_public) {
            Ok(k) => k,
            Err(e) => return v.reject("ek-public", e.to_string()),
        };
        let ak = match parse_attestation_key(&ev.ak_public) {
            Ok(k) => k,
            Err(e) => return v.reject("ak-public", e.to_string()),
        };
        v.add("ak-public", true, "required", format!("restricted fixedTPM signing key ({})", ak.key.key_type()));

        // 2. Hardware identity: EK certificate chain to a pinned AMD root.
        let chain = match self.bundle.verify_ek(&ev.ek_cert, &ev.ek_icas, &ek.key, &now) {
            Ok(c) => c,
            Err(e) => {
                v.ek = Some(ek);
                v.ak = Some(ak);
                return v.reject("ek-chain", e.to_string());
            }
        };
        v.device_id = chain.device_id.clone();
        v.root = chain.root_name.clone();
        v.root_kind = Some(chain.root_kind.clone());
        v.svn = chain.svn;
        v.tpm_firmware = chain.firmware.clone();
        let names: Vec<&str> = chain.path.iter().map(|c| c.subject_cn.as_str()).collect();
        v.add("ek-chain", true, "required", names.join(" <- "));
        v.ek = Some(ek);
        v.ak = Some(ak.clone());
        if !chain.production && !self.allow_dev_roots {
            return v.reject("ek-root-production", format!("root {:?} is a development root", chain.root_name));
        }

        // 3. The AK lives in the same TPM as the EK (credential activation).
        if !ex.ak_activated {
            return v.reject("ak-bound-to-ek", "no credential activation for this AK");
        }
        v.add("ak-bound-to-ek", true, "required", "TPM2_ActivateCredential recovered the challenge secret");

        // 4. Fresh quote over the statement and the verifier's nonce.
        if ev.nonce.len() < 16 {
            return v.reject("quote", "nonce shorter than 16 bytes");
        }
        let q = match verify_quote(&ak, &ev.quote_attest, &ev.quote_sig, &quote_extra_data(&ev.nonce, &ev.statement)) {
            Ok(q) => q,
            Err(e) => return v.reject("quote", e.to_string()),
        };
        v.reset_count = q.reset_count;
        v.restart_count = q.restart_count;
        v.clock = q.clock;
        v.quote = Some(q.clone());
        if q.bank != ALG_SHA256 {
            return v.reject("quote", format!("quoted bank 0x{:04x}, want SHA-256", q.bank));
        }
        if !same_set(&ex.pcrs, self.pcrs()) {
            return v.reject("quote", format!("challenge PCRs {}, policy requires {}", go_list(&ex.pcrs), go_list(self.pcrs())));
        }
        if !same_set(&q.pcrs, &ex.pcrs) {
            return v.reject("quote", format!("quoted PCRs {}, want {}", go_list(&q.pcrs), go_list(&ex.pcrs)));
        }
        v.add(
            "quote",
            true,
            "required",
            format!(
                "signed by the AK over nonce+statement; TPM firmware {}, resetCount {}, restartCount {}",
                q.firmware_string(),
                q.reset_count,
                q.restart_count
            ),
        );

        // 5. Event log replays to the quoted digest.
        let elog = match parse_event_log(&ev.event_log) {
            Ok(l) => l,
            Err(e) => return v.reject("event-log", e.to_string()),
        };
        let pcrs = match elog.replay(ALG_SHA256, &q.pcrs) {
            Ok(p) => p,
            Err(e) => return v.reject("event-log", e.to_string()),
        };
        let digest_ok = pcr_digest(&pcrs, &q.pcrs).is_ok_and(|d| d == q.pcr_digest);
        if !digest_ok {
            return v.reject("event-log", "replayed PCRs do not match the quoted digest");
        }
        for p in &q.pcrs {
            if let Some(val) = pcrs.get(p) {
                v.pcrs.insert(p.to_string(), hex::encode(val));
            }
        }
        v.add("event-log", true, "required", format!("{} events replay to the quoted digest", elog.events.len()));
        // Descriptions are untrusted unless re-hashed. Report events whose
        // digest is defined over their own data but does not match it.
        let inconsistent: Vec<String> = elog
            .events
            .iter()
            .filter(|e| matches!(e.event_type, EV_SEPARATOR | EV_EFI_ACTION | EV_ACTION | EV_SCRTM_VERSION))
            .filter(|e| !e.verify_data_digest(ALG_SHA256))
            .map(|e| format!("#{}(PCR{})", e.index, e.pcr))
            .collect();
        let consistent = inconsistent.is_empty();
        v.add(
            "event-descriptions",
            consistent,
            "info",
            format!("events whose data does not match their digest: {}", go_list(&inconsistent)),
        );

        // 6. Statement: keys and identity bound by the quote.
        let st = match parse_statement(&ev.statement) {
            Ok(s) => s,
            Err(e) => return v.reject("statement", e.to_string()),
        };
        if st.provider_id != provider_id_from_ek(&ev.ek_public) {
            v.statement = Some(st);
            return v.reject("statement", "provider_id does not match the EK");
        }
        if !ex.session_id.is_empty() && st.session_id != ex.session_id {
            let msg = format!("statement is for session {:?}, not {:?}", st.session_id, ex.session_id);
            v.statement = Some(st);
            return v.reject("statement", msg);
        }
        if !ex.account_id.is_empty() && st.account_id != ex.account_id {
            let msg = format!("statement names account {:?}, connection is {:?}", st.account_id, ex.account_id);
            v.statement = Some(st);
            return v.reject("statement", msg);
        }
        let default_kems = [db_sealbox::KEM_XWING.to_owned()];
        let allowed: &[String] = if self.allowed_kems.is_empty() { &default_kems } else { &self.allowed_kems };
        if !allowed.contains(&st.job_kem) {
            let msg = format!("job KEM {:?} is not allowed (allowed: {})", st.job_kem, go_list(allowed));
            v.statement = Some(st);
            return v.reject("statement", msg);
        }
        v.add(
            "statement",
            true,
            "required",
            format!(
                "job key ({}) {}…, receipt key {}… bound by the quote",
                st.job_kem,
                hex::encode(st.job_public_key.get(..4).unwrap_or_default()),
                hex::encode(st.receipt_public_key.get(..4).unwrap_or_default())
            ),
        );
        if let Some(bk) = &st.bound_key {
            match crate::verify_bound_key(bk, &ak, &pcrs, &st.provider_id, &st.session_id) {
                Ok(k) => {
                    v.bound_key = Some(k);
                    let detail =
                        format!("TPM-resident ECDH key certified by the AK, usable only under PolicyPCR over PCRs {}", go_list(&bk.pcrs));
                    v.add("tpm-bound-key", true, "required", detail);
                }
                Err(e) => {
                    v.statement = Some(st);
                    return v.reject("tpm-bound-key", e.to_string());
                }
            }
        }

        // 7. Firmware policy from measured events.
        if !firmware_policy(&mut v, &elog) {
            v.statement = Some(st);
            return v.rejected();
        }

        // 8. Node OS release: signed, logged, above the floor, and matching
        // PCR 9/12 (and PCR 4 boot chain).
        let Some(rel) = self.match_release(&mut v, &pcrs, &now) else {
            v.statement = Some(st);
            return v.rejected();
        };
        v.release = rel.id();
        v.release_digest = rel.digest();
        v.manifest = Some(rel.clone());

        // 9. Runtime and requirements.
        let prod = rel.channel == "production" && chain.production;
        if !runtime_policy(&mut v, &rel, &st) || !requirements(&mut v, &rel, &st, prod) {
            v.statement = Some(st);
            return v.rejected();
        }

        // 10. Tier.
        let tsme = st.status.tsme_active == Some(true);
        v.ok = true;
        v.tier = if !chain.production {
            Tier::DevSimulated
        } else if rel.channel != "production" {
            // Real AMD hardware running a development OS: identity and boot
            // chain are proven, but the owner has root there, so it is never
            // eligible for private data.
            Tier::HardwareDevOs
        } else if tsme {
            Tier::AttestedEncryptedMemory
        } else {
            Tier::Attested
        };
        v.add("memory-encryption", tsme, "tier", format!("TSME active={tsme} (needed for the encrypted-memory tier)"));
        v.statement = Some(st);
        v
    }

    fn match_release(&self, v: &mut Verdict, pcrs: &BTreeMap<u32, Vec<u8>>, now: &GoTime) -> Option<Arc<Manifest>> {
        let hex_of = |p: u32| pcrs.get(&p).map(hex::encode).unwrap_or_default();
        let (pcr4, pcr9, pcr11, pcr12) = (hex_of(4), hex_of(9), hex_of(11), hex_of(12));
        let mut reasons = Vec::new();
        for tr in &self.releases {
            let m = &tr.manifest;
            if (m.boot.path == "uki") != self.pcrs().contains(&11) {
                continue;
            }
            if !m.boot.pcr9_sha256.eq_ignore_ascii_case(&pcr9) || !m.boot.pcr12_sha256.eq_ignore_ascii_case(&pcr12) {
                continue;
            }
            if m.boot.path == "uki" && (pcr11.is_empty() || !m.boot.pcr11_sha256.eq_ignore_ascii_case(&pcr11)) {
                reasons.push(format!("{}: PCR 11 differs from signed UKI sections", m.id()));
                continue;
            }
            if !m.boot.pcr4_sha256.eq_ignore_ascii_case(&pcr4) {
                reasons.push(format!("{}: PCR 4 differs from the release's boot chain", m.id()));
                continue;
            }
            if let Some(why) = platform_mismatch(m, pcrs) {
                reasons.push(format!("{}: {why}", m.id()));
                continue;
            }
            let Some(policy) = &self.release_policy else {
                reasons.push("no release policy configured".to_owned());
                continue;
            };
            if policy.require_logged && !tr.logged {
                reasons.push(format!("{}: not in the release transparency log", m.id()));
                continue;
            }
            if let Err(e) = policy.admit(m, now) {
                reasons.push(e.to_string());
                continue;
            }
            if !m.platform.min_scrtm_version.is_empty() {
                let have = v.pcrs.get("scrtm_version").cloned().unwrap_or_default();
                let ok = compare_firmware_version(&have, &m.platform.min_scrtm_version).is_some_and(|c| c != std::cmp::Ordering::Less);
                if !ok {
                    reasons.push(format!("{}: BIOS {:?} is below {:?}", m.id(), have, m.platform.min_scrtm_version));
                    continue;
                }
            }
            v.add(
                "release",
                true,
                "required",
                format!(
                    "{} ({} channel, svn {}) matches PCR 4, 9, 12{}",
                    m.id(),
                    m.channel,
                    m.svn,
                    if m.boot.path == "uki" { " and 11 (UKI sections)" } else { "" }
                ),
            );
            return Some(m.clone());
        }
        if reasons.is_empty() {
            reasons.push(format!("no signed release measures PCR9={}… PCR12={}…", short(&pcr9), short(&pcr12)));
        }
        v.add("release", false, "required", reasons.join("; "));
        None
    }
}

/// Firmware state from measured events. Firmware measures the Secure Boot
/// configuration into PCR 7 and the S-CRTM (BIOS) version into PCR 0 before
/// it caps those PCRs with an EV_SEPARATOR at ready-to-boot. Anyone with TPM
/// access can extend a PCR later, so a value is taken only from the single
/// pre-separator event, and a log that measures these again after the
/// separator is refused rather than allowed to override the firmware's
/// value. Platform profiles in the release can additionally pin PCR 0 and 7.
fn firmware_policy(v: &mut Verdict, elog: &EventLog) -> bool {
    let mut sb: i32 = -1;
    let mut sep7 = false;
    for ev in elog.events_for(7) {
        if ev.event_type == EV_SEPARATOR {
            sep7 = true;
            continue;
        }
        if ev.event_type != EV_EFI_VARIABLE_DRIVER_CONFIG {
            continue;
        }
        let Ok(uv) = parse_uefi_variable(&ev.data) else { continue };
        if uv.name != "SecureBoot" || uv.guid != EFI_GLOBAL_VARIABLE_GUID {
            continue;
        }
        if sep7 {
            v.add("secure-boot", false, "required", "SecureBoot measured after the PCR 7 separator (not firmware state)");
            return false;
        }
        if sb != -1 {
            v.add("secure-boot", false, "required", "SecureBoot measured more than once");
            return false;
        }
        // The digest must commit to the whole UEFI_VARIABLE_DATA (TCG PFP);
        // a value-only digest would let a host pair it with another name.
        if ev.digests.get(&ALG_SHA256) != Some(&digest_of(ALG_SHA256, &ev.data)) {
            v.add("secure-boot", false, "required", "SecureBoot event digest does not match its data");
            return false;
        }
        let [value] = uv.data.as_slice() else {
            v.add("secure-boot", false, "required", format!("SecureBoot value is {} bytes", uv.data.len()));
            return false;
        };
        sb = i32::from(*value);
    }
    if !sep7 {
        v.add("secure-boot", false, "required", "no PCR 7 separator in the log");
        return false;
    }
    if !v.add("secure-boot", sb == 1, "required", format!("measured SecureBoot={sb} before the PCR 7 separator")) {
        return false;
    }
    let mut ver = String::new();
    let mut n = 0;
    let mut sep0 = false;
    for ev in elog.events_for(0) {
        if ev.event_type == EV_SEPARATOR {
            sep0 = true;
            continue;
        }
        if ev.event_type != EV_SCRTM_VERSION {
            continue;
        }
        if sep0 || !ev.verify_data_digest(ALG_SHA256) {
            v.add("bios-version", false, "required", "S-CRTM version event after the PCR 0 separator or not matching its digest");
            return false;
        }
        n += 1;
        ver = decode_utf16(&ev.data);
        if ver.is_empty() {
            ver = String::from_utf8_lossy(&ev.data).trim_end_matches('\0').to_owned();
        }
    }
    if !sep0 {
        v.add("bios-version", false, "required", "no PCR 0 separator in the log");
        return false;
    }
    if n > 1 {
        v.add("bios-version", false, "required", format!("S-CRTM version measured {n} times"));
        return false;
    }
    v.add("bios-version", !ver.is_empty(), "info", format!("S-CRTM version {ver:?}"));
    v.pcrs.insert("scrtm_version".to_owned(), ver);
    true
}

/// Compares the optional platform-profile pins (PCR 0 firmware, PCR 7
/// Secure Boot configuration, PCR 14 MOK state).
fn platform_mismatch(m: &Manifest, pcrs: &BTreeMap<u32, Vec<u8>>) -> Option<String> {
    for (pcr, want, what) in [
        (0u32, &m.boot.pcr0_sha256, "firmware"),
        (7, &m.boot.pcr7_sha256, "Secure Boot configuration"),
        (14, &m.boot.pcr14_sha256, "MOK state"),
    ] {
        let have = pcrs.get(&pcr).map(hex::encode).unwrap_or_default();
        if !want.is_empty() && !want.eq_ignore_ascii_case(&have) {
            return Some(format!("PCR {pcr} ({what}) differs from the release's platform profile"));
        }
    }
    None
}

fn runtime_policy(v: &mut Verdict, m: &Manifest, st: &Statement) -> bool {
    const EFFECT: &str = "required";
    let mut ok = true;
    let rt = &m.runtime;
    if !rt.engine.name.is_empty() && st.runtime.engine != rt.engine.name {
        ok &= v.add("engine", false, EFFECT, format!("engine {:?}, release pins {:?}", st.runtime.engine, rt.engine.name));
    }
    if !rt.agent.sha256.is_empty() && !st.runtime.agent_sha256.eq_ignore_ascii_case(&rt.agent.sha256) {
        ok &=
            v.add("agent", false, EFFECT, format!("agent {}…, release pins {}…", short(&st.runtime.agent_sha256), short(&rt.agent.sha256)));
    }
    let approved_wf: BTreeMap<&str, String> = rt.workflows().iter().map(|w| (w.name.as_str(), w.sha256.to_lowercase())).collect();
    for w in &st.runtime.workflows {
        if approved_wf.get(w.name.as_str()) != Some(&w.sha256.to_lowercase()) {
            ok &= v.add("workflow", false, EFFECT, format!("workflow {:?} is not approved by the release", w.name));
        }
    }
    for rm in &st.runtime.models {
        let Some(am) = m.model_by_id(&rm.id) else {
            ok &= v.add("model", false, EFFECT, format!("model {:?} is not approved by the release", rm.id));
            continue;
        };
        // The reported file set must be exactly the release's, hash for hash.
        let want: BTreeMap<&str, String> = am.files().iter().map(|f| (f.name.as_str(), f.sha256.to_lowercase())).collect();
        let got: BTreeMap<&str, String> = rm.files.iter().map(|f| (f.name.as_str(), f.sha256.to_lowercase())).collect();
        let complete = got.len() == want.len() && rm.files.len() == got.len() && want.iter().all(|(n, h)| got.get(n) == Some(h));
        if !complete {
            ok &= v.add("model", false, EFFECT, format!("model {:?} files do not match the release's pinned weights", rm.id));
        }
    }
    if ok {
        v.add(
            "runtime",
            true,
            EFFECT,
            format!("engine, agent, {} workflows and {} models match the release", st.runtime.workflows.len(), st.runtime.models.len()),
        );
    }
    ok
}

fn requirements(v: &mut Verdict, m: &Manifest, st: &Statement, prod: bool) -> bool {
    // In production every requirement is fatal. For dev releases (the PoC
    // runs on the owner's development OS) they are reported as what a
    // production verifier would reject.
    let effect = if prod { "required" } else { "info" };
    let mut ok = true;
    let mut note = |v: &mut Verdict, name: &str, pass: bool, mut detail: String| {
        if !pass && !prod {
            detail.push_str(" [would reject in production]");
        }
        if !v.add(name, pass, effect, detail) && prod {
            ok = false;
        }
    };
    // Command-line flags are judged on the measured command line (PCR 9/12
    // via the release), not on the self-reported status. A release may add
    // flags but never replace the verifier's own, and a flag only counts if
    // no later occurrence of its key overrides it.
    let fields: Vec<&str> = m.boot.load_options.split_whitespace().collect();
    let flags: Vec<&str> = PRODUCTION_CMDLINE_FLAGS.iter().copied().chain(m.requires.cmdline_flags.iter().map(String::as_str)).collect();
    let missing: Vec<&str> = flags.iter().copied().filter(|f| !cmdline_flag_ok(&fields, f)).collect();
    note(
        v,
        "measured-cmdline-hardening",
        missing.is_empty(),
        format!("missing or contradicted {} in the measured command line", go_list(&missing)),
    );
    // The root filesystem must be pinned by a dm-verity root hash on the
    // measured command line; otherwise PCR 4/9/12 would admit any userspace.
    let mut verity = String::new();
    for f in &fields {
        for prefix in ["roothash=", "usrhash="] {
            if let Some(h) = f.strip_prefix(prefix)
                && h.len() >= 64
                && is_hex(h)
            {
                verity = (*f).to_owned();
            }
        }
    }
    note(v, "measured-verity-root", !verity.is_empty(), format!("dm-verity root hash on the measured command line: {verity:?}"));
    let s = &st.status;
    note(v, "no-swap", !s.swap_active, format!("swap active={}", s.swap_active));
    let bound = st.bound_key.is_some();
    note(v, "tpm-bound-job-key", bound, format!("TPM-enforced decryption share offered={bound}"));
    note(v, "lockdown", s.lockdown == "confidentiality", format!("kernel lockdown {:?}", s.lockdown));
    note(v, "debugfs", !s.debugfs_mounted, format!("debugfs mounted={}", s.debugfs_mounted));
    let iso = s.gpu.enforce_isolation == Some(1);
    let iso_text = s.gpu.enforce_isolation.map_or_else(|| "unknown".to_owned(), |i| i.to_string());
    note(v, "gpu-isolation", iso, format!("amdgpu enforce_isolation={iso_text}"));
    let dash = s.dash_enabled == Some(false);
    note(v, "dash-off", dash, format!("AMD DASH remote management disabled={dash}"));
    note(v, "gpu-owner", s.gpu.owner == "node", format!("GPU owner {:?}", s.gpu.owner));
    note(v, "tpm-mode", st.tpm_mode == "hardware", format!("TPM mode {:?}", st.tpm_mode));
    if m.requires.boot_health {
        let clean = st.status.boot_health.as_ref().is_some_and(crate::BootHealth::is_clean);
        note(v, "boot-health", clean, "bounded pre-admission boot report present and clean".to_owned());
    }
    ok
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::eventlog::{EV_SCRTM_VERSION, LogEvent, build_event_log, digests_of, uefi_variable_data, utf16le};
    use crate::statement::{GpuStatus, ModelReport, RuntimeReport, Status};
    use db_release::{Artifact, Boot, Model, Runtime};

    fn log_with(evs: &[LogEvent]) -> EventLog {
        parse_event_log(&build_event_log(&[ALG_SHA256], evs).unwrap()).unwrap()
    }

    #[test]
    fn uki_release_requires_quoted_pcr11() {
        let now = GoTime::now_utc();
        let m = Manifest {
            name: "uki-test".to_owned(),
            version: "1".to_owned(),
            svn: 1,
            channel: "dev".to_owned(),
            issued_at: now.add(chrono::Duration::minutes(-1)),
            expires_at: now.add(chrono::Duration::hours(1)),
            boot: Boot {
                path: "uki".to_owned(),
                pcr4_sha256: "04".repeat(32),
                pcr9_sha256: "09".repeat(32),
                pcr11_sha256: "0b".repeat(32),
                pcr12_sha256: "00".repeat(32),
                ..Boot::default()
            },
            ..Manifest::default()
        };
        let verifier = Verifier {
            releases: vec![TrustedRelease { manifest: Arc::new(m), envelope: Vec::new(), logged: true }],
            release_policy: Some(Policy { allow_dev: true, ..Policy::default() }),
            required_pcrs: UKI_PCRS.to_vec(),
            ..Verifier::default()
        };
        let mut pcrs = BTreeMap::from([(4, vec![4u8; 32]), (9, vec![9u8; 32]), (12, vec![0u8; 32])]);
        assert!(verifier.match_release(&mut Verdict::default(), &pcrs, &now).is_none(), "omitted PCR 11 admitted");
        pcrs.insert(11, vec![1u8; 32]);
        assert!(verifier.match_release(&mut Verdict::default(), &pcrs, &now).is_none(), "changed PCR 11 admitted");
        pcrs.insert(11, vec![11u8; 32]);
        assert!(verifier.match_release(&mut Verdict::default(), &pcrs, &now).is_some(), "matching UKI PCR 11 rejected");
        let legacy = Verifier { required_pcrs: Vec::new(), ..verifier };
        assert!(legacy.match_release(&mut Verdict::default(), &pcrs, &now).is_none(), "UKI release admitted under Type #1 profile");
    }

    fn sep(pcr: u32) -> LogEvent {
        let d = vec![0u8; 4];
        LogEvent { pcr, event_type: EV_SEPARATOR, digests: digests_of(&[ALG_SHA256], &d), data: d }
    }

    fn scrtm() -> LogEvent {
        let d = utf16le("LFGB0.03.03", true);
        LogEvent { pcr: 0, event_type: EV_SCRTM_VERSION, digests: digests_of(&[ALG_SHA256], &d), data: d }
    }

    // A SecureBoot event whose digest covers only the value (not the
    // variable record with its GUID and name) could be a relabelled event.
    #[test]
    fn secure_boot_requires_spec_digest() {
        let data = uefi_variable_data(&EFI_GLOBAL_VARIABLE_GUID, "SecureBoot", &[1]);
        let value_only =
            LogEvent { pcr: 7, event_type: EV_EFI_VARIABLE_DRIVER_CONFIG, digests: digests_of(&[ALG_SHA256], &[1]), data: data.clone() };
        let spec = LogEvent { pcr: 7, event_type: EV_EFI_VARIABLE_DRIVER_CONFIG, digests: digests_of(&[ALG_SHA256], &data), data };
        let mut v = Verdict::default();
        assert!(!firmware_policy(&mut v, &log_with(&[scrtm(), sep(0), value_only, sep(7)])), "value-only digest accepted");
        let mut v = Verdict::default();
        assert!(firmware_policy(&mut v, &log_with(&[scrtm(), sep(0), spec.clone(), sep(7)])), "spec digest rejected: {:?}", v.checks);
        // No PCR 0 separator: an S-CRTM event could have been appended later.
        let mut v = Verdict::default();
        assert!(!firmware_policy(&mut v, &log_with(&[scrtm(), spec.clone(), sep(7)])), "log without a PCR 0 separator accepted");
        // S-CRTM version after the separator, or twice.
        let mut v = Verdict::default();
        assert!(!firmware_policy(&mut v, &log_with(&[sep(0), scrtm(), spec.clone(), sep(7)])));
        let mut v = Verdict::default();
        assert!(!firmware_policy(&mut v, &log_with(&[scrtm(), scrtm(), sep(0), spec.clone(), sep(7)])));
        // SecureBoot twice, or after the separator.
        let mut v = Verdict::default();
        assert!(!firmware_policy(&mut v, &log_with(&[scrtm(), sep(0), spec.clone(), spec.clone(), sep(7)])));
        let mut v = Verdict::default();
        assert!(!firmware_policy(&mut v, &log_with(&[scrtm(), sep(0), sep(7), spec])));
    }

    // The kernel honours the last occurrence of a parameter, so a later
    // lockdown=none must defeat a required lockdown=confidentiality.
    #[test]
    fn conflicting_cmdline_flags() {
        let st = Statement {
            tpm_mode: "hardware".to_owned(),
            bound_key: Some(crate::BoundKey::default()),
            status: Status {
                lockdown: "confidentiality".to_owned(),
                dash_enabled: Some(false),
                gpu: GpuStatus { enforce_isolation: Some(1), owner: "node".to_owned(), ..GpuStatus::default() },
                ..Status::default()
            },
            ..Statement::default()
        };
        let base = format!("ro roothash={} lockdown=confidentiality debugfs=off iommu.strict=1 module.sig_enforce=1", "ab".repeat(32));
        for (cmd, want) in [
            (base.clone(), true),
            (format!("{base} lockdown=none"), false),
            (format!("{base} debugfs=on"), false),
            (format!("{base} iommu.strict=0"), false),
            (base.replace(" module.sig_enforce=1", ""), false),
            (base.replace("roothash=", "x-roothash="), false),
        ] {
            let m = Manifest { boot: Boot { load_options: cmd.clone(), ..Boot::default() }, ..Manifest::default() };
            let mut v = Verdict::default();
            assert_eq!(requirements(&mut v, &m, &st, true), want, "{cmd:?}: {:?}", v.failed());
        }
    }

    #[test]
    fn signed_boot_health_requirement_refuses_missing_dirty_or_invalid_report() {
        let mut st = Statement {
            tpm_mode: "hardware".to_owned(),
            bound_key: Some(crate::BoundKey::default()),
            status: Status {
                lockdown: "confidentiality".to_owned(),
                dash_enabled: Some(false),
                gpu: GpuStatus { enforce_isolation: Some(1), owner: "node".to_owned(), ..GpuStatus::default() },
                ..Status::default()
            },
            ..Statement::default()
        };
        let mut m = Manifest {
            boot: Boot {
                load_options: format!(
                    "roothash={} lockdown=confidentiality debugfs=off iommu.strict=1 module.sig_enforce=1",
                    "ab".repeat(32)
                ),
                ..Boot::default()
            },
            ..Manifest::default()
        };
        m.requires.boot_health = true;
        let check = |st: &Statement| {
            let mut v = Verdict::default();
            let pass = requirements(&mut v, &m, st, true);
            assert!(v.checks.iter().any(|c| c.name == "boot-health" && c.ok == pass));
            pass
        };
        assert!(!check(&st));
        st.status.boot_health =
            Some(crate::BootHealth { v: 1, boot_id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(), ..crate::BootHealth::default() });
        assert!(check(&st));
        if let Some(h) = st.status.boot_health.as_mut() {
            h.warning_count = 1;
            h.ima_sha384_unavailable = 1;
        }
        assert!(!check(&st));
        if let Some(h) = st.status.boot_health.as_mut() {
            h.warning_count = 0;
            h.ima_sha384_unavailable = 0;
            h.collection_error_count = 1;
        }
        assert!(!check(&st));
        if let Some(h) = st.status.boot_health.as_mut() {
            h.collection_error_count = 0;
            h.failed_unit_count = 1;
            h.failed_units = vec!["dbnode-llama.service".to_owned()];
        }
        assert!(!check(&st));
    }

    // A statement must report every pinned weight file, not just a subset.
    #[test]
    fn model_files_must_be_complete() {
        let art = |n: &str, h: &str| Artifact { name: n.to_owned(), sha256: h.to_owned(), bytes: 0 };
        let m = Manifest {
            runtime: Runtime {
                models: Some(vec![Model { id: "m".to_owned(), kind: String::new(), files: Some(vec![art("a", "aa"), art("b", "bb")]) }]),
                ..Runtime::default()
            },
            ..Manifest::default()
        };
        for (name, files) in [
            ("none", vec![]),
            ("subset", vec![art("a", "aa")]),
            ("wrong", vec![art("a", "aa"), art("b", "cc")]),
            ("extra", vec![art("a", "aa"), art("b", "bb"), art("c", "dd")]),
            ("dup-name", vec![art("a", "aa"), art("a", "aa")]),
        ] {
            let st = Statement {
                runtime: RuntimeReport { models: vec![ModelReport { id: "m".to_owned(), files }], ..RuntimeReport::default() },
                ..Statement::default()
            };
            assert!(!runtime_policy(&mut Verdict::default(), &m, &st), "{name}: incomplete model file set accepted");
        }
        let st = Statement {
            runtime: RuntimeReport {
                models: vec![ModelReport { id: "m".to_owned(), files: vec![art("a", "AA"), art("b", "bb")] }],
                ..RuntimeReport::default()
            },
            ..Statement::default()
        };
        assert!(runtime_policy(&mut Verdict::default(), &m, &st), "complete model file set rejected");
        let unknown = Statement {
            runtime: RuntimeReport { models: vec![ModelReport { id: "x".to_owned(), files: vec![] }], ..RuntimeReport::default() },
            ..Statement::default()
        };
        assert!(!runtime_policy(&mut Verdict::default(), &m, &unknown), "unapproved model accepted");
    }

    #[test]
    fn firmware_versions() {
        use std::cmp::Ordering::*;
        assert_eq!(compare_firmware_version("LFGB0.03.03", "LFGB0.03.03"), Some(Equal));
        assert_eq!(compare_firmware_version("LFGB0.03.04", "lfgb0.03.03"), Some(Greater));
        assert_eq!(compare_firmware_version("LFGB0.03", "LFGB0.03.01"), Some(Less));
        assert_eq!(compare_firmware_version("LFGB0.03.03", "ABCD0.03.03"), None);
        assert_eq!(compare_firmware_version("", "LFGB0.03.03"), None);
        assert_eq!(compare_firmware_version("LFGB0..3", "LFGB0.3"), None);
    }

    #[test]
    fn cmdline_flags() {
        let f: Vec<&str> = "root=x lockdown=confidentiality debugfs=off lockdown=none".split_whitespace().collect();
        assert!(!cmdline_flag_ok(&f, "lockdown=confidentiality"), "conflicting later occurrence accepted");
        assert!(cmdline_flag_ok(&f, "debugfs=off"));
        assert!(!cmdline_flag_ok(&f, "iommu.strict=1"));
        assert!(cmdline_flag_ok(&f, "root=x"));
        let g: Vec<&str> = vec!["quiet"];
        assert!(cmdline_flag_ok(&g, "quiet"));
        assert!(!cmdline_flag_ok(&g, "splash"));
    }

    #[test]
    fn tier_strings() {
        for t in [Tier::Rejected, Tier::DevSimulated, Tier::HardwareDevOs, Tier::Attested, Tier::AttestedEncryptedMemory] {
            assert_eq!(Tier::parse(t.as_str()), t);
        }
        assert_eq!(go_list([1, 2, 3]), "[1 2 3]");
        assert_eq!(go_list(Vec::<u8>::new()), "[]");
    }
}
