//! Object templates: the TCG default EK templates (EK Credential Profile,
//! L-1 RSA-2048 and L-2 ECC P-256) and the Darkbloom attestation key.

use crate::consts::*;
use crate::{AsymScheme, EccParms, KdfScheme, Public, PublicParams, RsaParms, SchemeDetails, SymDefObject, Unique};

/// The TCG default EK authPolicy, PolicySecret(TPM_RH_ENDORSEMENT)
/// (TCG EK Credential Profile, B.3.2).
pub const EK_POLICY_DIGEST: [u8; 32] = [
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52,
    0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
];

const EK_ATTRIBUTES: u32 =
    OBJ_FIXED_TPM | OBJ_FIXED_PARENT | OBJ_SENSITIVE_DATA_ORIGIN | OBJ_ADMIN_WITH_POLICY | OBJ_RESTRICTED | OBJ_DECRYPT;

const EK_SYMMETRIC: SymDefObject = SymDefObject::Cipher { algorithm: ALG_AES, key_bits: 128, mode: ALG_CFB };

/// The TCG default ECC P-256 EK template (go-tpm `ECCEKTemplate`).
pub fn ecc_ek_template() -> Public {
    Public {
        name_alg: ALG_SHA256,
        attributes: EK_ATTRIBUTES,
        auth_policy: EK_POLICY_DIGEST.to_vec(),
        params: PublicParams::Ecc(EccParms {
            symmetric: EK_SYMMETRIC,
            scheme: AsymScheme::NULL,
            curve_id: ECC_NIST_P256,
            kdf: KdfScheme::NULL,
        }),
        unique: Unique::Ecc { x: vec![0; 32], y: vec![0; 32] },
    }
}

/// The TCG default RSA-2048 EK template (go-tpm `RSAEKTemplate`).
pub fn rsa_ek_template() -> Public {
    Public {
        name_alg: ALG_SHA256,
        attributes: EK_ATTRIBUTES,
        auth_policy: EK_POLICY_DIGEST.to_vec(),
        params: PublicParams::Rsa(RsaParms { symmetric: EK_SYMMETRIC, scheme: AsymScheme::NULL, key_bits: 2048, exponent: 0 }),
        unique: Unique::Rsa(vec![0; 256]),
    }
}

/// The Darkbloom attestation key: a restricted ECDSA P-256 signing key in
/// the endorsement hierarchy. Keys outside the endorsement and platform
/// hierarchies get obfuscated resetCount/restartCount in quotes, which
/// would hide reboots. The template is fixed, so the AK is the same key on
/// every boot (go-tpm `tpmdev.AKTemplate`).
pub fn ak_template() -> Public {
    Public {
        name_alg: ALG_SHA256,
        attributes: OBJ_FIXED_TPM
            | OBJ_FIXED_PARENT
            | OBJ_SENSITIVE_DATA_ORIGIN
            | OBJ_USER_WITH_AUTH
            | OBJ_NO_DA
            | OBJ_RESTRICTED
            | OBJ_SIGN_ENCRYPT,
        auth_policy: Vec::new(),
        params: PublicParams::Ecc(EccParms {
            symmetric: SymDefObject::Null,
            scheme: AsymScheme { scheme: ALG_ECDSA, details: SchemeDetails::Hash(ALG_SHA256) },
            curve_id: ECC_NIST_P256,
            kdf: KdfScheme::NULL,
        }),
        unique: Unique::Ecc { x: Vec::new(), y: Vec::new() },
    }
}
