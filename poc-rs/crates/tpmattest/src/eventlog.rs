//! TCG crypto-agile (TCG2) event logs: strict parsing, replay and building.

use crate::{Error, Result};
use db_tpm2::HashAlg;
use std::collections::BTreeMap;

/// TPM_ALG_SHA1.
pub const ALG_SHA1: u16 = 0x0004;
/// TPM_ALG_SHA256.
pub const ALG_SHA256: u16 = 0x000B;
/// TPM_ALG_SHA384.
pub const ALG_SHA384: u16 = 0x000C;
/// TPM_ALG_SHA512.
pub const ALG_SHA512: u16 = 0x000D;

// TCG PC Client event types (TCG PC Client Platform Firmware Profile, 10.4.1).
/// EV_PREBOOT_CERT.
pub const EV_PREBOOT_CERT: u32 = 0x0000_0000;
/// EV_POST_CODE.
pub const EV_POST_CODE: u32 = 0x0000_0001;
/// EV_NO_ACTION.
pub const EV_NO_ACTION: u32 = 0x0000_0003;
/// EV_SEPARATOR.
pub const EV_SEPARATOR: u32 = 0x0000_0004;
/// EV_ACTION.
pub const EV_ACTION: u32 = 0x0000_0005;
/// EV_EVENT_TAG.
pub const EV_EVENT_TAG: u32 = 0x0000_0006;
/// EV_S_CRTM_CONTENTS.
pub const EV_SCRTM_CONTENTS: u32 = 0x0000_0007;
/// EV_S_CRTM_VERSION.
pub const EV_SCRTM_VERSION: u32 = 0x0000_0008;
/// EV_CPU_MICROCODE.
pub const EV_CPU_MICROCODE: u32 = 0x0000_0009;
/// EV_PLATFORM_CONFIG_FLAGS.
pub const EV_PLATFORM_CONFIG_FLAGS: u32 = 0x0000_000A;
/// EV_TABLE_OF_DEVICES.
pub const EV_TABLE_OF_DEVICES: u32 = 0x0000_000B;
/// EV_COMPACT_HASH.
pub const EV_COMPACT_HASH: u32 = 0x0000_000C;
/// EV_IPL.
pub const EV_IPL: u32 = 0x0000_000D;
/// EV_IPL_PARTITION_DATA.
pub const EV_IPL_PARTITION_DATA: u32 = 0x0000_000E;
/// EV_NONHOST_CODE.
pub const EV_NONHOST_CODE: u32 = 0x0000_000F;
/// EV_NONHOST_CONFIG.
pub const EV_NONHOST_CONFIG: u32 = 0x0000_0010;
/// EV_NONHOST_INFO.
pub const EV_NONHOST_INFO: u32 = 0x0000_0011;
/// EV_OMIT_BOOT_DEVICE_EVENTS.
pub const EV_OMIT_BOOT_DEVICE_EVENTS: u32 = 0x0000_0012;
/// EV_EFI_VARIABLE_DRIVER_CONFIG.
pub const EV_EFI_VARIABLE_DRIVER_CONFIG: u32 = 0x8000_0001;
/// EV_EFI_VARIABLE_BOOT.
pub const EV_EFI_VARIABLE_BOOT: u32 = 0x8000_0002;
/// EV_EFI_BOOT_SERVICES_APPLICATION.
pub const EV_EFI_BOOT_SERVICES_APPLICATION: u32 = 0x8000_0003;
/// EV_EFI_BOOT_SERVICES_DRIVER.
pub const EV_EFI_BOOT_SERVICES_DRIVER: u32 = 0x8000_0004;
/// EV_EFI_RUNTIME_SERVICES_DRIVER.
pub const EV_EFI_RUNTIME_SERVICES_DRIVER: u32 = 0x8000_0005;
/// EV_EFI_GPT_EVENT.
pub const EV_EFI_GPT_EVENT: u32 = 0x8000_0006;
/// EV_EFI_ACTION.
pub const EV_EFI_ACTION: u32 = 0x8000_0007;
/// EV_EFI_PLATFORM_FIRMWARE_BLOB.
pub const EV_EFI_PLATFORM_FIRMWARE_BLOB: u32 = 0x8000_0008;
/// EV_EFI_HANDOFF_TABLES.
pub const EV_EFI_HANDOFF_TABLES: u32 = 0x8000_0009;
/// EV_EFI_PLATFORM_FIRMWARE_BLOB2.
pub const EV_EFI_PLATFORM_FIRMWARE_BLOB2: u32 = 0x8000_000A;
/// EV_EFI_HANDOFF_TABLES2.
pub const EV_EFI_HANDOFF_TABLES2: u32 = 0x8000_000B;
/// EV_EFI_VARIABLE_BOOT2.
pub const EV_EFI_VARIABLE_BOOT2: u32 = 0x8000_000C;
/// EV_EFI_HCRTM_EVENT.
pub const EV_EFI_HCRTM_EVENT: u32 = 0x8000_0010;
/// EV_EFI_VARIABLE_AUTHORITY.
pub const EV_EFI_VARIABLE_AUTHORITY: u32 = 0x8000_00E0;
/// EV_EFI_SPDM_FIRMWARE_BLOB.
pub const EV_EFI_SPDM_FIRMWARE_BLOB: u32 = 0x8000_00E1;
/// EV_EFI_SPDM_FIRMWARE_CONFIG.
pub const EV_EFI_SPDM_FIRMWARE_CONFIG: u32 = 0x8000_00E2;

/// Tagged event ID "Linux initrd" (PCR 9).
pub const TAG_LINUX_INITRD: u32 = 0x8F3B_22EC;
/// Tagged event ID "LOADED_IMAGE::LoadOptions" (PCR 9 stub, PCR 12 systemd-boot).
pub const TAG_LOAD_OPTIONS: u32 = 0x8F3B_22ED;

/// Largest accepted event log (real logs are tens of KiB).
pub const MAX_EVENT_LOG_BYTES: usize = 2 << 20;
const MAX_EVENT_DATA_BYTES: usize = 1 << 20;
const MAX_EVENTS: usize = 1 << 16;
const SPEC_ID_SIGNATURE: &[u8] = b"Spec ID Event03\0";
const STARTUP_LOCALITY_SIG: &[u8] = b"StartupLocality\0";
/// Highest PCR index.
pub const MAX_PCR_INDEX: u32 = 23;

/// EFI global variable GUID 8BE4DF61-93CA-11D2-AA0D-00E098032B8C in its
/// little-endian in-memory layout.
pub const EFI_GLOBAL_VARIABLE_GUID: [u8; 16] =
    [0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c];

/// The hash for a TPM algorithm ID, if supported.
pub fn hash_for(alg: u16) -> Option<HashAlg> {
    HashAlg::from_id(alg)
}

/// Hashes `data` with a TPM algorithm (empty for unknown algorithms).
pub fn digest_of(alg: u16, data: &[u8]) -> Vec<u8> {
    hash_for(alg).map(|h| h.digest(data)).unwrap_or_default()
}

fn malformed(msg: impl std::fmt::Display) -> Error {
    Error::MalformedLog(msg.to_string())
}

/// Little-endian reader for event logs.
struct Le<'a> {
    b: &'a [u8],
    off: usize,
}

impl<'a> Le<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, off: 0 }
    }

    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.off)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let have = self.remaining();
        if n > have {
            return Err(malformed(format!("truncated at offset {} (need {n} bytes, have {have})", self.off)));
        }
        let out = self.b.get(self.off..self.off + n).ok_or_else(|| malformed("truncated"))?;
        self.off += n;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| malformed("truncated"))
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(u8::from_le_bytes(self.array()?))
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn rest_is_zero(&self, from: usize) -> bool {
        self.b.get(from..).unwrap_or_default().iter().all(|&b| b == 0)
    }
}

/// One parsed TCG_PCR_EVENT2. `data` is a description supplied by the
/// untrusted host; only `digests` are bound to PCRs unless a policy
/// re-hashes the data ([`Event::verify_data_digest`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Position in the log (the Spec ID header is not counted).
    pub index: usize,
    /// PCR index.
    pub pcr: u32,
    /// Event type.
    pub event_type: u32,
    /// Digest per algorithm.
    pub digests: BTreeMap<u16, Vec<u8>>,
    /// Raw event data.
    pub data: Vec<u8>,
}

impl Event {
    /// Whether the event's digest for `alg` is the hash of its own data.
    /// Policies must check this before trusting the content of events whose
    /// digest is defined over the event data (separators, S-CRTM version,
    /// EFI actions, UEFI variables).
    pub fn verify_data_digest(&self, alg: u16) -> bool {
        match (self.digests.get(&alg), hash_for(alg)) {
            (Some(d), Some(h)) => *d == h.digest(&self.data),
            _ => false,
        }
    }
}

/// A parsed crypto-agile event log.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EventLog {
    /// Digest size per declared bank.
    pub digest_sizes: BTreeMap<u16, usize>,
    /// Events after the Spec ID header.
    pub events: Vec<Event>,
    /// Startup locality (from the StartupLocality EV_NO_ACTION event).
    pub startup_locality: u8,
    /// Spec errata.
    pub spec_errata: u8,
    /// Platform class.
    pub platform_class: u32,
}

/// Parses a TCG2 crypto-agile event log as exposed by Linux at
/// `/sys/kernel/security/tpm0/binary_bios_measurements`. The first event must
/// be the SHA-1 format Spec ID event; the rest are TCG_PCR_EVENT2 records.
pub fn parse_event_log(raw: &[u8]) -> Result<EventLog> {
    if raw.len() > MAX_EVENT_LOG_BYTES {
        return Err(malformed(format!("log is {} bytes, above the {MAX_EVENT_LOG_BYTES} byte limit", raw.len())));
    }
    let mut r = Le::new(raw);
    let pcr = r.u32()?;
    let typ = r.u32()?;
    if pcr != 0 || typ != EV_NO_ACTION {
        return Err(malformed("first event is not the Spec ID EV_NO_ACTION event"));
    }
    r.take(20)?;
    let spec_size = usize::try_from(r.u32()?).map_err(|_| malformed("spec size"))?;
    let spec = r.take(spec_size)?;
    let mut log = EventLog::default();
    let mut sr = Le::new(spec);
    let sig = sr.take(16)?;
    if sig != SPEC_ID_SIGNATURE {
        return Err(malformed(format!("not a crypto-agile log (signature {:?})", String::from_utf8_lossy(sig))));
    }
    log.platform_class = sr.u32()?;
    sr.take(2)?; // spec version minor, major
    log.spec_errata = sr.u8()?;
    sr.u8()?; // uintnSize
    let count = sr.u32()?;
    if count == 0 || count > 8 {
        return Err(malformed(format!("implausible algorithm count {count}")));
    }
    for _ in 0..count {
        let alg = sr.u16()?;
        let size = usize::from(sr.u16()?);
        if size == 0 || size > 64 {
            return Err(malformed(format!("implausible digest size {size} for alg 0x{alg:04x}")));
        }
        if let Some(h) = hash_for(alg)
            && h.size() != size
        {
            return Err(malformed(format!("digest size {size} does not match alg 0x{alg:04x}")));
        }
        log.digest_sizes.insert(alg, size);
    }

    let mut idx = 0usize;
    while r.remaining() > 0 {
        if idx >= MAX_EVENTS {
            return Err(malformed(format!("more than {MAX_EVENTS} events")));
        }
        if r.remaining() < 12 {
            // Some firmware pads the log tail with zeros.
            if r.rest_is_zero(r.off) {
                break;
            }
            return Err(malformed(format!("trailing garbage at offset {}", r.off)));
        }
        let start = r.off;
        let pcr = r.u32()?;
        let typ = r.u32()?;
        let ndig = r.u32()?;
        if pcr == 0 && typ == 0 && ndig == 0 {
            // Zero-filled tail.
            if r.rest_is_zero(start) {
                break;
            }
            return Err(malformed(format!("zero event header followed by data at offset {start}")));
        }
        if pcr > MAX_PCR_INDEX {
            return Err(malformed(format!("event {idx} extends PCR {pcr}")));
        }
        if ndig == 0 || ndig as usize > log.digest_sizes.len() {
            return Err(malformed(format!("event {idx} carries {ndig} digests")));
        }
        let mut digests = BTreeMap::new();
        for _ in 0..ndig {
            let alg = r.u16()?;
            let size = *log
                .digest_sizes
                .get(&alg)
                .ok_or_else(|| malformed(format!("event {idx} uses algorithm 0x{alg:04x} not declared in the Spec ID event")))?;
            if digests.contains_key(&alg) {
                return Err(malformed(format!("event {idx} repeats algorithm 0x{alg:04x}")));
            }
            digests.insert(alg, r.take(size)?.to_vec());
        }
        let dsize = usize::try_from(r.u32()?).map_err(|_| malformed("event size"))?;
        if dsize > MAX_EVENT_DATA_BYTES {
            return Err(malformed(format!("event {idx} data is {dsize} bytes")));
        }
        let data = r.take(dsize)?.to_vec();
        if typ == EV_NO_ACTION
            && pcr == 0
            && data.starts_with(STARTUP_LOCALITY_SIG)
            && let Some(&loc) = data.get(16)
        {
            log.startup_locality = loc;
        }
        log.events.push(Event { index: idx, pcr, event_type: typ, digests, data });
        idx += 1;
    }
    Ok(log)
}

impl EventLog {
    /// Recomputes PCR values for one bank. EV_NO_ACTION events are not
    /// extended. PCR 0 starts at the StartupLocality value (TCG PC Client
    /// PFP 10.4.5.3). A missing digest for an extended event is an error,
    /// because silently skipping it would let a log omit measurements.
    pub fn replay(&self, alg: u16, pcrs: &[u32]) -> Result<BTreeMap<u32, Vec<u8>>> {
        let size = *self.digest_sizes.get(&alg).ok_or_else(|| Error::Invalid(format!("log has no 0x{alg:04x} bank")))?;
        let h = hash_for(alg).ok_or_else(|| Error::Invalid(format!("unsupported hash algorithm 0x{alg:04x}")))?;
        let mut out: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        for &p in pcrs {
            if p > MAX_PCR_INDEX {
                return Err(Error::Invalid(format!("PCR {p} out of range")));
            }
            out.insert(p, vec![0u8; size]);
        }
        if let Some(last) = out.get_mut(&0).and_then(|pcr0| pcr0.last_mut()) {
            *last = self.startup_locality;
        }
        for ev in &self.events {
            if ev.event_type == EV_NO_ACTION {
                continue;
            }
            let Some(cur) = out.get_mut(&ev.pcr) else { continue };
            let d =
                ev.digests.get(&alg).ok_or_else(|| malformed(format!("event {} (PCR {}) has no 0x{alg:04x} digest", ev.index, ev.pcr)))?;
            *cur = h.digest_parts(&[cur, d]);
        }
        Ok(out)
    }

    /// The extended (non EV_NO_ACTION) events of one PCR, in order.
    pub fn events_for(&self, pcr: u32) -> impl Iterator<Item = &Event> {
        self.events.iter().filter(move |e| e.pcr == pcr && e.event_type != EV_NO_ACTION)
    }
}

/// A parsed UEFI_VARIABLE_DATA event payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UefiVariable {
    /// Vendor GUID (in-memory layout).
    pub guid: [u8; 16],
    /// Variable name.
    pub name: String,
    /// Variable value.
    pub data: Vec<u8>,
}

/// Parses UEFI_VARIABLE_DATA (TCG PFP 10.4.4).
pub fn parse_uefi_variable(data: &[u8]) -> Result<UefiVariable> {
    let mut r = Le::new(data);
    let guid = r.array::<16>()?;
    let name_len = r.u64()?;
    let data_len = r.u64()?;
    if name_len > 256 || data_len > MAX_EVENT_DATA_BYTES as u64 {
        return Err(malformed("implausible UEFI variable sizes"));
    }
    let name_raw = r.take(name_len as usize * 2)?;
    let value = r.take(data_len as usize)?.to_vec();
    if r.remaining() != 0 {
        return Err(malformed(format!("UEFI variable event has {} trailing bytes", r.remaining())));
    }
    Ok(UefiVariable { guid, name: decode_utf16(name_raw), data: value })
}

/// A TCG_PCClientTaggedEvent payload (EV_EVENT_TAG).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaggedEvent {
    /// Tag ID.
    pub id: u32,
    /// Tagged data.
    pub data: Vec<u8>,
}

/// Parses an EV_EVENT_TAG payload.
pub fn parse_tagged_event(data: &[u8]) -> Result<TaggedEvent> {
    let mut r = Le::new(data);
    let id = r.u32()?;
    let size = usize::try_from(r.u32()?).map_err(|_| malformed("tagged event size"))?;
    Ok(TaggedEvent { id, data: r.take(size)?.to_vec() })
}

/// Decodes UTF-16LE up to the first NUL (unpaired surrogates become
/// U+FFFD, as Go's `utf16.Decode`).
pub fn decode_utf16(b: &[u8]) -> String {
    let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).take_while(|&c| c != 0).collect();
    char::decode_utf16(units).map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER)).collect()
}

/// Encodes `s` as UTF-16LE, optionally NUL-terminated: the form in which
/// systemd-boot and the Linux EFI stub measure kernel load options.
pub fn utf16le(s: &str, nul: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 * s.len() + 2);
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    if nul {
        out.extend_from_slice(&[0, 0]);
    }
    out
}

/// An event to write into a synthetic TCG2 event log. `digests` must hold
/// one digest per bank of the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEvent {
    /// PCR index.
    pub pcr: u32,
    /// Event type.
    pub event_type: u32,
    /// Digest per bank.
    pub digests: BTreeMap<u16, Vec<u8>>,
    /// Event data.
    pub data: Vec<u8>,
}

/// Serializes a crypto-agile event log (Spec ID header plus
/// TCG_PCR_EVENT2 records). Used by the development TPM path (swtpm) and
/// tests; real logs come from firmware.
pub fn build_event_log(banks: &[u16], events: &[LogEvent]) -> Result<Vec<u8>> {
    let mut spec = Vec::new();
    spec.extend_from_slice(SPEC_ID_SIGNATURE);
    spec.extend_from_slice(&0u32.to_le_bytes()); // platformClass: client
    spec.extend_from_slice(&[0, 2, 0, 2]); // spec 2.0, errata 0, uintnSize 2 (64-bit)
    spec.extend_from_slice(&(banks.len() as u32).to_le_bytes());
    for &b in banks {
        let h = hash_for(b).ok_or_else(|| Error::Invalid(format!("unsupported hash algorithm 0x{b:04x}")))?;
        spec.extend_from_slice(&b.to_le_bytes());
        spec.extend_from_slice(&(h.size() as u16).to_le_bytes());
    }
    spec.push(0); // vendorInfoSize

    let mut out = Vec::new();
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&EV_NO_ACTION.to_le_bytes());
    out.extend_from_slice(&[0u8; 20]);
    out.extend_from_slice(&(spec.len() as u32).to_le_bytes());
    out.extend_from_slice(&spec);
    for (i, ev) in events.iter().enumerate() {
        out.extend_from_slice(&ev.pcr.to_le_bytes());
        out.extend_from_slice(&ev.event_type.to_le_bytes());
        out.extend_from_slice(&(banks.len() as u32).to_le_bytes());
        for &b in banks {
            let d = ev.digests.get(&b).ok_or_else(|| Error::Invalid(format!("event {i} has no digest for bank 0x{b:04x}")))?;
            out.extend_from_slice(&b.to_le_bytes());
            out.extend_from_slice(d);
        }
        let len = u32::try_from(ev.data.len()).map_err(|_| Error::Invalid(format!("event {i} data too large")))?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&ev.data);
    }
    Ok(out)
}

/// Hashes measured bytes for every bank.
pub fn digests_of(banks: &[u16], measured: &[u8]) -> BTreeMap<u16, Vec<u8>> {
    banks.iter().map(|&b| (b, digest_of(b, measured))).collect()
}

/// Encodes a UEFI_VARIABLE_DATA payload.
pub fn uefi_variable_data(guid: &[u8; 16], name: &str, value: &[u8]) -> Vec<u8> {
    let name16 = utf16le(name, false);
    let mut b = Vec::with_capacity(32 + name16.len() + value.len());
    b.extend_from_slice(guid);
    b.extend_from_slice(&((name16.len() / 2) as u64).to_le_bytes());
    b.extend_from_slice(&(value.len() as u64).to_le_bytes());
    b.extend_from_slice(&name16);
    b.extend_from_slice(value);
    b
}

/// Encodes a TCG_PCClientTaggedEvent payload.
pub fn tagged_event_data(id: u32, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(8 + data.len());
    b.extend_from_slice(&id.to_le_bytes());
    b.extend_from_slice(&(data.len() as u32).to_le_bytes());
    b.extend_from_slice(data);
    b
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::policy::DEFAULT_PCRS;
    use rand::RngExt as _;

    fn sample_log() -> Vec<u8> {
        let banks = [ALG_SHA1, ALG_SHA256, ALG_SHA384];
        let sep = [0u8; 4];
        let ver = utf16le("LFGB0.03.03", true);
        let sb = uefi_variable_data(&EFI_GLOBAL_VARIABLE_GUID, "SecureBoot", &[1]);
        let act = b"Calling EFI Application from Boot Option".to_vec();
        let evs = vec![
            LogEvent { pcr: 0, event_type: EV_SCRTM_VERSION, digests: digests_of(&banks, &ver), data: ver.clone() },
            LogEvent { pcr: 7, event_type: EV_EFI_VARIABLE_DRIVER_CONFIG, digests: digests_of(&banks, &sb), data: sb },
            LogEvent { pcr: 4, event_type: EV_EFI_ACTION, digests: digests_of(&banks, &act), data: act },
            LogEvent { pcr: 0, event_type: EV_SEPARATOR, digests: digests_of(&banks, &sep), data: sep.to_vec() },
            LogEvent {
                pcr: 9,
                event_type: EV_EVENT_TAG,
                digests: digests_of(&banks, b"initrd"),
                data: tagged_event_data(TAG_LINUX_INITRD, b"Linux initrd\0"),
            },
        ];
        build_event_log(&banks, &evs).unwrap()
    }

    #[test]
    fn parse_and_replay() {
        let raw = sample_log();
        let l = parse_event_log(&raw).unwrap();
        assert_eq!(l.events.len(), 5);
        assert_eq!(l.digest_sizes.len(), 3);
        let pcrs = l.replay(ALG_SHA256, &[0, 4, 7, 9]).unwrap();
        // PCR 0 = H(H(0||v)||sep)
        let mut z = vec![0u8; 32];
        z.extend(digest_of(ALG_SHA256, &utf16le("LFGB0.03.03", true)));
        let mut v = digest_of(ALG_SHA256, &z);
        v.extend(digest_of(ALG_SHA256, &[0, 0, 0, 0]));
        assert_eq!(pcrs[&0], digest_of(ALG_SHA256, &v));
        for ev in &l.events[..4] {
            assert!(ev.verify_data_digest(ALG_SHA256), "event {} data digest", ev.index);
        }
        assert!(!l.events[4].verify_data_digest(ALG_SHA256), "tagged initrd event digests external data");
        let uv = parse_uefi_variable(&l.events[1].data).unwrap();
        assert_eq!((uv.name.as_str(), uv.data.as_slice(), uv.guid), ("SecureBoot", &[1u8][..], EFI_GLOBAL_VARIABLE_GUID));
        let te = parse_tagged_event(&l.events[4].data).unwrap();
        assert_eq!(te.id, TAG_LINUX_INITRD);
        assert!(l.replay(0x1234, &[0]).is_err());
        assert!(l.replay(ALG_SHA256, &[24]).is_err());
    }

    // Truncated or corrupted logs must fail cleanly, never panic.
    #[test]
    fn robustness() {
        let raw = sample_log();
        for n in 0..raw.len() {
            let _ = parse_event_log(&raw[..n]);
        }
        let mut rng = rand::rng();
        for _ in 0..20000 {
            let mut b = raw.clone();
            for _ in 0..rng.random_range(1..4) {
                let i = rng.random_range(0..b.len());
                b[i] ^= rng.random::<u8>() | 1;
            }
            if let Ok(l) = parse_event_log(&b) {
                let _ = l.replay(ALG_SHA256, &DEFAULT_PCRS);
                for e in &l.events {
                    let _ = parse_uefi_variable(&e.data);
                    let _ = parse_tagged_event(&e.data);
                    let _ = e.verify_data_digest(ALG_SHA1);
                }
            }
        }
        for _ in 0..2000 {
            let n = rng.random_range(0..512);
            let b: Vec<u8> = (0..n).map(|_| rng.random()).collect();
            let _ = parse_event_log(&b);
            let _ = parse_uefi_variable(&b);
            let _ = parse_tagged_event(&b);
        }
        assert!(parse_event_log(&[0u8; 64]).is_err(), "zero log accepted");
        assert!(parse_event_log(&vec![0u8; MAX_EVENT_LOG_BYTES + 1]).is_err(), "oversized log accepted");
        // A zero-padded tail is accepted, garbage after it is not.
        let mut padded = raw.clone();
        padded.extend_from_slice(&[0u8; 40]);
        assert_eq!(parse_event_log(&padded).unwrap().events.len(), 5);
        padded.push(1);
        assert!(parse_event_log(&padded).is_err());
    }

    #[test]
    fn utf16_helpers() {
        assert_eq!(decode_utf16(&utf16le("LFGB0.03.03", true)), "LFGB0.03.03");
        assert_eq!(decode_utf16(&[0x00, 0xd8, 0x41, 0x00]), "\u{fffd}A");
        assert_eq!(decode_utf16(&[0x41]), "");
    }
}
