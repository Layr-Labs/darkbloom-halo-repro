//! The device: serialized command execution and object commands
//! (CreatePrimary, FlushContext, ReadPublic, Quote).

use crate::cmd::{Command, Params, Response, parse_response};
use crate::transport::{self, Transport};
use crate::{Error, Key, Mode, Result};
use db_tpm2::consts::*;
use db_tpm2::{
    Attest, PcrSelection, PcrSelectionList, Public, Signature, Writer, ak_template, ecc_ek_template, object_name, rsa_ek_template,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use zeroize::Zeroize as _;

/// Bound on TPM2B_PUBLIC and other variable structures in responses.
pub(crate) const MAX_STRUCT: usize = 4096;

/// An open TPM. Commands are serialized; multi-command sequences hold the
/// lock throughout.
pub struct Device {
    transport: Mutex<Box<dyn Transport>>,
    mode: Mode,
    nv_chunk_override: AtomicUsize,
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device").field("mode", &self.mode).finish_non_exhaustive()
    }
}

/// Exclusive access to the TPM for one command or a sequence of commands.
pub(crate) struct Tpm<'a> {
    t: MutexGuard<'a, Box<dyn Transport>>,
}

impl Tpm<'_> {
    fn send(&mut self, raw: &[u8]) -> Result<Vec<u8>> {
        self.t.send(raw).map_err(|source| Error::Io { context: "TPM transport".to_owned(), source })
    }

    /// Runs a command; on TPM_RC_INITIALIZE it sends TPM2_Startup(CLEAR)
    /// and retries once.
    pub(crate) fn run(&mut self, name: &'static str, cmd: &Command, n_handles: usize) -> Result<Response> {
        let raw = cmd.encode()?;
        let mut rsp = self.send(&raw)?;
        let mut out = parse_response(name, &rsp, n_handles, cmd.sessions.len());
        if cmd.code != CC_STARTUP && matches!(&out, Err(Error::Tpm { rc, .. }) if rc.0 == RC_INITIALIZE) {
            self.startup()?;
            rsp.zeroize();
            rsp = self.send(&raw)?;
            out = parse_response(name, &rsp, n_handles, cmd.sessions.len());
        }
        rsp.zeroize();
        out
    }

    /// TPM2_Startup(CLEAR); "already started" is fine.
    fn startup(&mut self) -> Result<()> {
        let cmd = Command::new(CC_STARTUP).params(SU_CLEAR.to_be_bytes().to_vec());
        match self.run("TPM2_Startup", &cmd, 0) {
            Err(Error::Tpm { rc, .. }) if rc.0 == RC_INITIALIZE => Ok(()),
            other => other.map(drop),
        }
    }

    pub(crate) fn flush(&mut self, handle: u32) -> Result<()> {
        let cmd = Command::new(CC_FLUSH_CONTEXT).params(handle.to_be_bytes().to_vec());
        self.run("TPM2_FlushContext", &cmd, 0).map(drop)
    }

    pub(crate) fn create_primary(&mut self, hierarchy: u32, template: &Public) -> Result<Key> {
        const NAME: &str = "TPM2_CreatePrimary";
        let mut w = Writer::new();
        w.bytes(&[0, 4, 0, 0, 0, 0]); // inSensitive: empty userAuth and data
        w.tpm2b(&template.to_bytes().map_err(Error::invalid)?).map_err(Error::invalid)?;
        w.u16(0); // outsideInfo
        w.u32(0); // creationPCR: no selections
        let cmd = Command::new(CC_CREATE_PRIMARY).handle(hierarchy).password().params(w.into_vec());
        let rsp = self.run(NAME, &cmd, 1)?;
        let handle = rsp.handles.first().copied().unwrap_or_default();
        let key = (|| {
            let mut p = Params::new(NAME, &rsp.params);
            let out_public = p.tpm2b("outPublic", MAX_STRUCT)?;
            p.tpm2b("creationData", MAX_STRUCT)?;
            p.tpm2b("creationHash", MAX_DIGEST)?;
            p.u16()?; // creationTicket: tag, hierarchy, digest
            p.u32()?;
            p.tpm2b("creationTicket digest", MAX_DIGEST)?;
            let name = p.tpm2b("name", MAX_NAME)?;
            p.finish()?;
            checked_key(NAME, handle, out_public, name)
        })();
        if key.is_err() {
            let _ = self.flush(handle);
        }
        key
    }

    pub(crate) fn read_public(&mut self, handle: u32) -> Result<(Vec<u8>, Vec<u8>)> {
        const NAME: &str = "TPM2_ReadPublic";
        let rsp = self.run(NAME, &Command::new(CC_READ_PUBLIC).handle(handle), 0)?;
        let mut p = Params::new(NAME, &rsp.params);
        let out_public = p.tpm2b("outPublic", MAX_STRUCT)?;
        let name = p.tpm2b("name", MAX_NAME)?;
        p.tpm2b("qualifiedName", MAX_NAME)?;
        p.finish()?;
        let k = checked_key(NAME, handle, out_public, name)?;
        Ok((k.public_raw, k.name))
    }

    pub(crate) fn quote(&mut self, ak: &Key, extra_data: &[u8], pcrs: &[u32]) -> Result<(Vec<u8>, Vec<u8>)> {
        const NAME: &str = "TPM2_Quote";
        if let Some(p) = pcrs.iter().find(|&&p| p > 23) {
            return Err(Error::invalid(format!("PCR {p} out of range")));
        }
        let mut w = Writer::new();
        w.tpm2b(extra_data).map_err(Error::invalid)?;
        w.u16(ALG_NULL); // inScheme: the key's scheme
        PcrSelectionList(vec![PcrSelection::new(ALG_SHA256, pcrs)]).marshal(&mut w).map_err(Error::invalid)?;
        let cmd = Command::new(CC_QUOTE).handle(ak.handle).password().params(w.into_vec());
        let rsp = self.run(NAME, &cmd, 0)?;
        signed_attestation(NAME, &rsp.params, ST_ATTEST_QUOTE)
    }
}

/// Parses `TPM2B_ATTEST || TPMT_SIGNATURE` (Quote, Certify): both must be
/// canonical and the attestation of type `want`. Returns their encodings.
pub(crate) fn signed_attestation(command: &'static str, params: &[u8], want: u16) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut p = Params::new(command, params);
    let attest = p.tpm2b("TPM2B_ATTEST", MAX_STRUCT)?;
    let start = p.r.offset();
    p.signature()?;
    let sig = params.get(start..p.r.offset()).unwrap_or_default();
    p.finish()?;
    let parsed = Attest::parse(attest).map_err(|e| p.err(format!("TPMS_ATTEST: {e}")))?;
    if parsed.attest_type != want {
        return Err(p.err(format!("attestation type 0x{:04x}, want 0x{want:04x}", parsed.attest_type)));
    }
    Signature::parse(sig).map_err(|e| p.err(format!("TPMT_SIGNATURE: {e}")))?;
    Ok((attest.to_vec(), sig.to_vec()))
}

/// Validates a returned public area and its name.
fn checked_key(command: &'static str, handle: u32, public_raw: &[u8], name: &[u8]) -> Result<Key> {
    let bad = |detail: String| Error::Malformed { command, detail };
    let public = Public::parse(public_raw).map_err(|e| bad(format!("public area: {e}")))?;
    let want = object_name(public.name_alg, public_raw).map_err(|e| bad(e.to_string()))?;
    if want != name {
        return Err(bad("name does not match the public area".to_owned()));
    }
    Ok(Key { handle, name: name.to_vec(), public_raw: public_raw.to_vec(), public })
}

impl Device {
    /// Opens a TPM (see [`transport::open`] for the spec syntax). A swtpm
    /// has no resource manager, so stale transient objects left by earlier
    /// clients are flushed first.
    pub fn open(spec: &str) -> Result<Arc<Device>> {
        let (t, mode) = transport::open(spec)?;
        let dev = Self::with_transport(t, mode);
        if mode == Mode::Swtpm {
            dev.tpm().flush_transient();
        }
        Ok(dev)
    }

    /// Wraps any transport (tests: a recorded TPM, or swtpm presented as
    /// hardware to check the development-only refusals).
    #[doc(hidden)]
    pub fn with_transport(t: Box<dyn Transport>, mode: Mode) -> Arc<Device> {
        Arc::new(Device { transport: Mutex::new(t), mode, nv_chunk_override: AtomicUsize::new(0) })
    }

    /// Runs a raw command and parses the response (tests and tools; the
    /// typed methods are the API).
    #[doc(hidden)]
    pub fn run(&self, name: &'static str, cmd: &Command, n_handles: usize) -> Result<Response> {
        self.tpm().run(name, cmd, n_handles)
    }

    /// How the TPM is reached.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Drops the transport connection (a socket transport reconnects on
    /// the next command).
    pub fn close(&self) {
        self.tpm().t.close();
    }

    pub(crate) fn tpm(&self) -> Tpm<'_> {
        Tpm { t: self.transport.lock().unwrap_or_else(PoisonError::into_inner) }
    }

    /// Fails on a hardware TPM (development-only operations).
    pub(crate) fn require_dev(&self, what: &str) -> Result<()> {
        match self.mode {
            Mode::Swtpm => Ok(()),
            Mode::Hardware => Err(Error::invalid(format!("refusing to {what} on a hardware TPM"))),
        }
    }

    /// Overrides the NV chunk size (tests; `None` restores TPM_PT_NV_BUFFER_MAX).
    #[doc(hidden)]
    pub fn override_nv_chunk(&self, n: Option<usize>) {
        self.nv_chunk_override.store(n.unwrap_or(0), Ordering::Relaxed);
    }

    pub(crate) fn nv_chunk_override(&self) -> Option<usize> {
        Some(self.nv_chunk_override.load(Ordering::Relaxed)).filter(|&n| n > 0)
    }

    /// Creates a primary object (empty auth, no outside info) in `hierarchy`
    /// (a TPM_RH_* handle).
    pub fn create_primary(&self, hierarchy: u32, template: &Public) -> Result<Key> {
        self.tpm().create_primary(hierarchy, template)
    }

    /// Creates the TCG default endorsement key (ECC P-256 or RSA-2048).
    /// CreatePrimary is deterministic for a given hierarchy seed and
    /// template, so this recreates the key the manufacturer certified.
    pub fn create_ek(&self, ecc: bool) -> Result<Key> {
        let template = if ecc { ecc_ek_template() } else { rsa_ek_template() };
        self.create_primary(RH_ENDORSEMENT, &template)
    }

    /// Creates the attestation key (restricted ECDSA P-256 signing key in
    /// the endorsement hierarchy; the same key on every boot).
    pub fn create_ak(&self) -> Result<Key> {
        self.create_primary(RH_ENDORSEMENT, &ak_template())
    }

    /// Unloads a transient object (errors ignored, as in the Go reference).
    pub fn flush(&self, k: &Key) {
        let _ = self.flush_handle(k.handle);
    }

    /// Unloads a transient object or session.
    pub fn flush_handle(&self, handle: u32) -> Result<()> {
        self.tpm().flush(handle)
    }

    /// TPM2_ReadPublic: the object's TPMT_PUBLIC and name (validated).
    pub fn read_public(&self, handle: u32) -> Result<(Vec<u8>, Vec<u8>)> {
        self.tpm().read_public(handle)
    }

    /// Signs the SHA-256 PCR bank over `extra_data` with the AK. Returns the
    /// TPMS_ATTEST and TPMT_SIGNATURE encodings.
    pub fn quote(&self, ak: &Key, extra_data: &[u8], pcrs: &[u32]) -> Result<(Vec<u8>, Vec<u8>)> {
        self.tpm().quote(ak, extra_data, pcrs)
    }
}
