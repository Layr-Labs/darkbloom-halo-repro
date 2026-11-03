//! TPM command marshaling and strict response parsing.
//!
//! Command: tag (ST_NO_SESSIONS / ST_SESSIONS) u16, size u32, code u32,
//! handles, [authorizationSize u32 + sessions], parameters. Response: tag,
//! size, rc; handles; with sessions a parameterSize u32, the parameters and
//! one TPMS_AUTH_RESPONSE per command session.

use crate::{Error, ResponseCode, Result};
use db_tpm2::consts::{RC_SUCCESS, RS_PW, SESSION_CONTINUE, ST_NO_SESSIONS, ST_SESSIONS};
use db_tpm2::{PcrSelectionList, Reader, Signature, Writer};
use zeroize::Zeroizing;

/// TPMS_AUTH_COMMAND for the empty password: TPM_RS_PW, empty nonce,
/// continueSession, empty password.
pub(crate) fn password_session() -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(RS_PW).u16(0).u8(SESSION_CONTINUE).u16(0);
    w.into_vec()
}

/// TPMS_AUTH_COMMAND for a policy session without an auth value: the
/// session handle, `nonce_caller`, attributes 0 (the session ends with a
/// successful command) and an empty HMAC.
pub(crate) fn policy_session(handle: u32, nonce_caller: &[u8]) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.u32(handle);
    w.tpm2b(nonce_caller).map_err(Error::invalid)?;
    w.u8(0).u16(0);
    Ok(w.into_vec())
}

/// A TPM command.
#[derive(Debug, Clone, Default)]
pub struct Command {
    /// TPM_CC.
    pub code: u32,
    /// Handle area.
    pub handles: Vec<u32>,
    /// Marshaled TPMS_AUTH_COMMANDs.
    pub sessions: Vec<Vec<u8>>,
    /// Parameter area.
    pub params: Vec<u8>,
}

impl Command {
    /// A command with no handles, sessions or parameters yet.
    pub fn new(code: u32) -> Self {
        Self { code, ..Self::default() }
    }

    /// Appends a handle.
    pub fn handle(mut self, h: u32) -> Self {
        self.handles.push(h);
        self
    }

    /// Appends an empty-password session.
    pub fn password(mut self) -> Self {
        self.sessions.push(password_session());
        self
    }

    /// Appends a marshaled session.
    pub fn session(mut self, s: Vec<u8>) -> Self {
        self.sessions.push(s);
        self
    }

    /// Sets the parameter area.
    pub fn params(mut self, p: Vec<u8>) -> Self {
        self.params = p;
        self
    }

    /// The command bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let tag = if self.sessions.is_empty() { ST_NO_SESSIONS } else { ST_SESSIONS };
        let mut w = Writer::new();
        w.u16(tag).u32(0).u32(self.code);
        for &h in &self.handles {
            w.u32(h);
        }
        if !self.sessions.is_empty() {
            let auth = self.sessions.concat();
            w.u32(u32::try_from(auth.len()).map_err(Error::invalid)?);
            w.bytes(&auth);
        }
        w.bytes(&self.params);
        let size = u32::try_from(w.len()).map_err(Error::invalid)?.to_be_bytes();
        if let Some(field) = w.as_mut_slice().get_mut(2..6) {
            field.copy_from_slice(&size);
        }
        Ok(w.into_vec())
    }
}

/// A successful response.
#[derive(Debug, Default)]
pub struct Response {
    /// Handle area.
    pub handles: Vec<u32>,
    /// Parameter area (zeroized on drop: it may carry secrets).
    pub params: Zeroizing<Vec<u8>>,
}

/// Parses a response to a command with `n_handles` response handles and
/// `n_sessions` sessions. A non-zero response code becomes [`Error::Tpm`].
pub fn parse_response(command: &'static str, raw: &[u8], n_handles: usize, n_sessions: usize) -> Result<Response> {
    let bad = |detail: String| Error::Malformed { command, detail };
    let mut r = Reader::new(raw);
    let tag = r.u16().map_err(|e| bad(e.to_string()))?;
    let size = r.u32().map_err(|e| bad(e.to_string()))?;
    let rc = r.u32().map_err(|e| bad(e.to_string()))?;
    if usize::try_from(size).ok() != Some(raw.len()) {
        return Err(bad(format!("size field {size}, but {} bytes", raw.len())));
    }
    if rc != RC_SUCCESS {
        return Err(Error::Tpm { command, rc: ResponseCode(rc) });
    }
    let want = if n_sessions == 0 { ST_NO_SESSIONS } else { ST_SESSIONS };
    if tag != want {
        return Err(bad(format!("tag 0x{tag:04x}, want 0x{want:04x}")));
    }
    let mut p = Params { r, command };
    let mut handles = Vec::with_capacity(n_handles);
    for _ in 0..n_handles {
        handles.push(p.u32()?);
    }
    if n_sessions == 0 {
        return Ok(Response { handles, params: Zeroizing::new(p.r.rest().to_vec()) });
    }
    let n = usize::try_from(p.u32()?).map_err(|e| bad(e.to_string()))?;
    let params = Zeroizing::new(p.take(n)?.to_vec());
    for _ in 0..n_sessions {
        p.tpm2b("session nonce", 64)?;
        p.u8()?;
        p.tpm2b("session hmac", 64)?;
    }
    p.finish()?;
    Ok(Response { handles, params })
}

/// A bounds-checked reader over a response parameter area.
pub(crate) struct Params<'a> {
    pub(crate) r: Reader<'a>,
    command: &'static str,
}

impl<'a> Params<'a> {
    pub(crate) fn new(command: &'static str, b: &'a [u8]) -> Self {
        Self { r: Reader::new(b), command }
    }

    pub(crate) fn err(&self, detail: impl std::fmt::Display) -> Error {
        Error::Malformed { command: self.command, detail: detail.to_string() }
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        self.r.u8().map_err(|e| self.err(e))
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        self.r.u16().map_err(|e| self.err(e))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        self.r.u32().map_err(|e| self.err(e))
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        self.r.take(n).map_err(|e| self.err(e))
    }

    pub(crate) fn tpm2b(&mut self, what: &'static str, max: usize) -> Result<&'a [u8]> {
        self.r.tpm2b(what, max).map_err(|e| self.err(e))
    }

    pub(crate) fn pcr_selection(&mut self) -> Result<PcrSelectionList> {
        PcrSelectionList::parse(&mut self.r).map_err(|e| self.err(e))
    }

    pub(crate) fn signature(&mut self) -> Result<Signature> {
        Signature::parse_from(&mut self.r).map_err(|e| self.err(e))
    }

    pub(crate) fn finish(&self) -> Result<()> {
        self.r.finish().map_err(|e| self.err(e))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn encode_layout() {
        let c = Command::new(0x17E).params(vec![1, 2]);
        assert_eq!(c.encode().unwrap(), [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x7E, 1, 2]);
        let c = Command::new(0x131).handle(0x4000_000B).password().params(vec![9]);
        let b = c.encode().unwrap();
        assert_eq!(&b[..2], &[0x80, 0x02]);
        assert_eq!(u32::from_be_bytes(b[2..6].try_into().unwrap()) as usize, b.len());
        assert_eq!(&b[10..14], &[0x40, 0, 0, 0x0B]);
        assert_eq!(&b[14..27], &[0, 0, 0, 9, 0x40, 0, 0, 9, 0, 0, 1, 0, 0]);
        assert_eq!(b[27], 9);
    }

    #[test]
    fn strict_responses() {
        // Success with one handle and one session.
        let ok = [0x80, 0x02, 0, 0, 0, 25, 0, 0, 0, 0, 0x80, 0, 0, 1, 0, 0, 0, 2, 0xAA, 0xBB, 0, 0, 1, 0, 0];
        let r = parse_response("x", &ok, 1, 1).unwrap();
        assert_eq!(r.handles, vec![0x8000_0001]);
        assert_eq!(r.params.as_slice(), &[0xAA, 0xBB]);
        // Every truncation and any extension fails without panicking.
        for n in 0..ok.len() {
            assert!(parse_response("x", &ok[..n], 1, 1).is_err());
        }
        let mut long = ok.to_vec();
        long.push(0);
        long[5] = 26;
        assert!(parse_response("x", &long, 1, 1).is_err());
        // Error codes win over everything after the header.
        let err = [0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x8B];
        match parse_response("x", &err, 1, 1) {
            Err(Error::Tpm { rc, .. }) => assert_eq!(rc.0, 0x18B),
            other => panic!("{other:?}"),
        }
        // A success response with the wrong tag is refused.
        let mut tag = ok;
        tag[1] = 0x01;
        assert!(parse_response("x", &tag, 1, 1).is_err());
    }
}
