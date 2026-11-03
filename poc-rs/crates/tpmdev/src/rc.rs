//! TPM response codes (TPM 2.0 Part 2, 6.6) decoded into readable errors.

/// A TPM_RC value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResponseCode(pub u32);

const FMT1: u32 = 0x080;
const VER1: u32 = 0x100;
const WARN: u32 = 0x900;

/// (base code, name, description)
const CODES: &[(u32, &str, &str)] = &[
    (FMT1 + 0x01, "TPM_RC_ASYMMETRIC", "asymmetric algorithm not supported or not correct"),
    (FMT1 + 0x02, "TPM_RC_ATTRIBUTES", "inconsistent attributes"),
    (FMT1 + 0x03, "TPM_RC_HASH", "hash algorithm not supported or not appropriate"),
    (FMT1 + 0x04, "TPM_RC_VALUE", "value is out of range or is not correct for the context"),
    (FMT1 + 0x05, "TPM_RC_HIERARCHY", "hierarchy is not enabled or is not correct for the use"),
    (FMT1 + 0x07, "TPM_RC_KEY_SIZE", "key size is not supported"),
    (FMT1 + 0x08, "TPM_RC_MGF", "mask generation function not supported"),
    (FMT1 + 0x09, "TPM_RC_MODE", "mode of operation not supported"),
    (FMT1 + 0x0A, "TPM_RC_TYPE", "the type of the value is not appropriate for the use"),
    (FMT1 + 0x0B, "TPM_RC_HANDLE", "the handle is not correct for the use"),
    (FMT1 + 0x0C, "TPM_RC_KDF", "unsupported key derivation function or function not appropriate for use"),
    (FMT1 + 0x0D, "TPM_RC_RANGE", "value was out of allowed range"),
    (FMT1 + 0x0E, "TPM_RC_AUTH_FAIL", "the authorization HMAC check failed and DA counter incremented"),
    (FMT1 + 0x0F, "TPM_RC_NONCE", "invalid nonce size or nonce value mismatch"),
    (FMT1 + 0x10, "TPM_RC_PP", "authorization requires assertion of PP"),
    (FMT1 + 0x12, "TPM_RC_SCHEME", "unsupported or incompatible scheme"),
    (FMT1 + 0x15, "TPM_RC_SIZE", "structure is the wrong size"),
    (FMT1 + 0x16, "TPM_RC_SYMMETRIC", "unsupported symmetric algorithm or key size, or not appropriate for instance"),
    (FMT1 + 0x17, "TPM_RC_TAG", "incorrect structure tag"),
    (FMT1 + 0x18, "TPM_RC_SELECTOR", "union selector is incorrect"),
    (
        FMT1 + 0x1A,
        "TPM_RC_INSUFFICIENT",
        "the TPM was unable to unmarshal a value because there were not enough octets in the input buffer",
    ),
    (FMT1 + 0x1B, "TPM_RC_SIGNATURE", "the signature is not valid"),
    (FMT1 + 0x1C, "TPM_RC_KEY", "key fields are not compatible with the selected use"),
    (FMT1 + 0x1D, "TPM_RC_POLICY_FAIL", "a policy check failed"),
    (FMT1 + 0x1F, "TPM_RC_INTEGRITY", "integrity check failed"),
    (FMT1 + 0x20, "TPM_RC_TICKET", "invalid ticket"),
    (FMT1 + 0x21, "TPM_RC_RESERVED_BITS", "reserved bits not set to zero as required"),
    (FMT1 + 0x22, "TPM_RC_BAD_AUTH", "authorization failure without DA implications"),
    (FMT1 + 0x23, "TPM_RC_EXPIRED", "the policy has expired"),
    (FMT1 + 0x24, "TPM_RC_POLICY_CC", "the command code in the policy is not the command code of the command"),
    (FMT1 + 0x25, "TPM_RC_BINDING", "public and sensitive portions of an object are not cryptographically bound"),
    (FMT1 + 0x26, "TPM_RC_CURVE", "curve not supported"),
    (FMT1 + 0x27, "TPM_RC_ECC_POINT", "point is not on the required curve"),
    (VER1, "TPM_RC_INITIALIZE", "TPM not initialized by TPM2_Startup or already initialized"),
    (VER1 + 0x01, "TPM_RC_FAILURE", "commands not being accepted because of a TPM failure"),
    (VER1 + 0x03, "TPM_RC_SEQUENCE", "improper use of a sequence handle"),
    (VER1 + 0x20, "TPM_RC_DISABLED", "the command is disabled"),
    (VER1 + 0x21, "TPM_RC_EXCLUSIVE", "command failed because audit sequence required exclusivity"),
    (VER1 + 0x24, "TPM_RC_AUTH_TYPE", "authorization handle is not correct for command"),
    (VER1 + 0x25, "TPM_RC_AUTH_MISSING", "command requires an authorization session for handle and it is not present"),
    (VER1 + 0x26, "TPM_RC_POLICY", "policy failure in math operation or an invalid authPolicy value"),
    (VER1 + 0x27, "TPM_RC_PCR", "PCR check fail"),
    (VER1 + 0x28, "TPM_RC_PCR_CHANGED", "PCR have changed since checked"),
    (VER1 + 0x2D, "TPM_RC_UPGRADE", "TPM is in field upgrade mode"),
    (VER1 + 0x2E, "TPM_RC_TOO_MANY_CONTEXTS", "context ID counter is at maximum"),
    (VER1 + 0x2F, "TPM_RC_AUTH_UNAVAILABLE", "authValue or authPolicy is not available for selected entity"),
    (VER1 + 0x30, "TPM_RC_REBOOT", "a _TPM_Init and Startup(CLEAR) is required before the TPM can resume operation"),
    (VER1 + 0x31, "TPM_RC_UNBALANCED", "the protection algorithms (hash and symmetric) are not reasonably balanced"),
    (VER1 + 0x42, "TPM_RC_COMMAND_SIZE", "command size is inconsistent with the contents of the command buffer"),
    (VER1 + 0x43, "TPM_RC_COMMAND_CODE", "command code not supported"),
    (VER1 + 0x44, "TPM_RC_AUTHSIZE", "the authorization area size is out of range"),
    (VER1 + 0x45, "TPM_RC_AUTH_CONTEXT", "use of an authorization session with a command that cannot have one"),
    (VER1 + 0x46, "TPM_RC_NV_RANGE", "NV offset+size is out of range"),
    (VER1 + 0x47, "TPM_RC_NV_SIZE", "requested allocation size is larger than allowed"),
    (VER1 + 0x48, "TPM_RC_NV_LOCKED", "NV access locked"),
    (VER1 + 0x49, "TPM_RC_NV_AUTHORIZATION", "NV access authorization fails in command actions"),
    (VER1 + 0x4A, "TPM_RC_NV_UNINITIALIZED", "an NV index is used before being initialized"),
    (VER1 + 0x4B, "TPM_RC_NV_SPACE", "insufficient space for NV allocation"),
    (VER1 + 0x4C, "TPM_RC_NV_DEFINED", "NV index or persistent object already defined"),
    (VER1 + 0x50, "TPM_RC_BAD_CONTEXT", "context in TPM2_ContextLoad() is not valid"),
    (VER1 + 0x51, "TPM_RC_CPHASH", "cpHash value already set or not correct for use"),
    (VER1 + 0x52, "TPM_RC_PARENT", "handle for parent is not a valid parent"),
    (VER1 + 0x53, "TPM_RC_NEEDS_TEST", "some function needs testing"),
    (VER1 + 0x54, "TPM_RC_NO_RESULT", "an internal function could not process the request"),
    (VER1 + 0x55, "TPM_RC_SENSITIVE", "the sensitive area did not unmarshal correctly after decryption"),
    (WARN + 0x01, "TPM_RC_CONTEXT_GAP", "gap for context ID is too large"),
    (WARN + 0x02, "TPM_RC_OBJECT_MEMORY", "out of memory for object contexts"),
    (WARN + 0x03, "TPM_RC_SESSION_MEMORY", "out of memory for session contexts"),
    (WARN + 0x04, "TPM_RC_MEMORY", "out of shared object/session memory or need space for internal operations"),
    (WARN + 0x05, "TPM_RC_SESSION_HANDLES", "out of session handles"),
    (WARN + 0x06, "TPM_RC_OBJECT_HANDLES", "out of object handles"),
    (WARN + 0x07, "TPM_RC_LOCALITY", "bad locality"),
    (WARN + 0x08, "TPM_RC_YIELDED", "the TPM has suspended operation on the command"),
    (WARN + 0x09, "TPM_RC_CANCELED", "the command was canceled"),
    (WARN + 0x0A, "TPM_RC_TESTING", "TPM is performing self-tests"),
    (WARN + 0x20, "TPM_RC_NV_RATE", "the TPM is rate-limiting accesses to prevent wearout of NV"),
    (WARN + 0x21, "TPM_RC_LOCKOUT", "the TPM is in DA lockout mode"),
    (WARN + 0x22, "TPM_RC_RETRY", "the TPM was not able to start the command"),
    (WARN + 0x23, "TPM_RC_NV_UNAVAILABLE", "the command may require writing of NV and NV is not currently accessible"),
];

/// Where a format-one error points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    /// Parameter number (1-based).
    Parameter(u8),
    /// Handle number (1-based).
    Handle(u8),
    /// Session number (1-based).
    Session(u8),
}

impl ResponseCode {
    /// Whether this is TPM_RC_SUCCESS.
    pub fn is_success(self) -> bool {
        self.0 == 0
    }

    /// Whether the code is format-one (carries a parameter, handle or
    /// session number).
    pub fn is_format_one(self) -> bool {
        self.0 & FMT1 != 0
    }

    /// The code without its position: `TPM_RC_FMT1 + E` for format-one
    /// codes, the code itself otherwise. Compare with e.g. 0x09F
    /// (TPM_RC_INTEGRITY) or 0x14A (TPM_RC_NV_UNINITIALIZED).
    pub fn base(self) -> u32 {
        if self.is_format_one() { FMT1 | (self.0 & 0x3F) } else { self.0 }
    }

    /// The parameter, handle or session a format-one code refers to.
    pub fn position(self) -> Option<Position> {
        if !self.is_format_one() {
            return None;
        }
        let n = ((self.0 >> 8) & 0xF) as u8;
        if self.0 & 0x40 != 0 {
            Some(Position::Parameter(n))
        } else if n & 0x8 != 0 {
            Some(Position::Session(n & 0x7))
        } else if n != 0 {
            Some(Position::Handle(n))
        } else {
            None
        }
    }

    /// The TPM_RC_* name, if known.
    pub fn name(self) -> Option<&'static str> {
        self.lookup().map(|(n, _)| n)
    }

    fn lookup(self) -> Option<(&'static str, &'static str)> {
        let base = self.base();
        if !self.is_format_one() {
            // TCG vendor codes and TPM 1.2 codes are not in the table.
            if base & 0x400 != 0 || base & VER1 == 0 || base & !0xFFF != 0 {
                return None;
            }
            if (WARN + 0x10..=WARN + 0x16).contains(&base) {
                return Some(("TPM_RC_REFERENCE_H", "a handle references a transient object or session that is not loaded"));
            }
            if (WARN + 0x18..=WARN + 0x1E).contains(&base) {
                return Some(("TPM_RC_REFERENCE_S", "a session handle references a session that is not loaded"));
            }
        }
        CODES.iter().find(|(c, _, _)| *c == base).map(|&(_, n, d)| (n, d))
    }
}

impl std::fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.lookup() {
            Some((name, desc)) => {
                write!(f, "{name}")?;
                let base = self.base();
                if name.ends_with("_H") || name.ends_with("_S") {
                    write!(f, "{}", base & 0x7)?;
                }
                match self.position() {
                    Some(Position::Parameter(n)) => write!(f, " (parameter {n})")?,
                    Some(Position::Handle(n)) => write!(f, " (handle {n})")?,
                    Some(Position::Session(n)) => write!(f, " (session {n})")?,
                    None => {}
                }
                write!(f, ": {desc} (0x{:03x})", self.0)
            }
            None => write!(f, "TPM error 0x{:08x}", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoding() {
        assert_eq!(ResponseCode(0x9a2).to_string(), "TPM_RC_BAD_AUTH (session 1): authorization failure without DA implications (0x9a2)");
        assert_eq!(ResponseCode(0x1df).base(), 0x09f);
        assert_eq!(ResponseCode(0x1df).position(), Some(Position::Parameter(1)));
        assert!(ResponseCode(0x1df).to_string().starts_with("TPM_RC_INTEGRITY (parameter 1)"));
        assert_eq!(ResponseCode(0x18b).position(), Some(Position::Handle(1)));
        assert_eq!(ResponseCode(0x14a).name(), Some("TPM_RC_NV_UNINITIALIZED"));
        assert_eq!(ResponseCode(0x100).name(), Some("TPM_RC_INITIALIZE"));
        assert!(ResponseCode(0x911).to_string().starts_with("TPM_RC_REFERENCE_H1"));
        assert_eq!(ResponseCode(0x902).name(), Some("TPM_RC_OBJECT_MEMORY"));
        assert_eq!(ResponseCode(0x8_0001).to_string(), "TPM error 0x00080001");
        assert_eq!(ResponseCode(0x501).name(), None);
    }
}
