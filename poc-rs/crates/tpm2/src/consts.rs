//! TPM 2.0 constants (TPM 2.0 Library, Part 2) used by the PoC.

// Algorithm identifiers (TPM_ALG_ID).
/// TPM_ALG_ERROR.
pub const ALG_ERROR: u16 = 0x0000;
/// TPM_ALG_RSA.
pub const ALG_RSA: u16 = 0x0001;
/// TPM_ALG_SHA1.
pub const ALG_SHA1: u16 = 0x0004;
/// TPM_ALG_HMAC.
pub const ALG_HMAC: u16 = 0x0005;
/// TPM_ALG_AES.
pub const ALG_AES: u16 = 0x0006;
/// TPM_ALG_MGF1.
pub const ALG_MGF1: u16 = 0x0007;
/// TPM_ALG_KEYEDHASH.
pub const ALG_KEYEDHASH: u16 = 0x0008;
/// TPM_ALG_XOR.
pub const ALG_XOR: u16 = 0x000A;
/// TPM_ALG_SHA256.
pub const ALG_SHA256: u16 = 0x000B;
/// TPM_ALG_SHA384.
pub const ALG_SHA384: u16 = 0x000C;
/// TPM_ALG_SHA512.
pub const ALG_SHA512: u16 = 0x000D;
/// TPM_ALG_NULL.
pub const ALG_NULL: u16 = 0x0010;
/// TPM_ALG_SM4.
pub const ALG_SM4: u16 = 0x0013;
/// TPM_ALG_RSASSA.
pub const ALG_RSASSA: u16 = 0x0014;
/// TPM_ALG_RSAES.
pub const ALG_RSAES: u16 = 0x0015;
/// TPM_ALG_RSAPSS.
pub const ALG_RSAPSS: u16 = 0x0016;
/// TPM_ALG_OAEP.
pub const ALG_OAEP: u16 = 0x0017;
/// TPM_ALG_ECDSA.
pub const ALG_ECDSA: u16 = 0x0018;
/// TPM_ALG_ECDH.
pub const ALG_ECDH: u16 = 0x0019;
/// TPM_ALG_ECDAA.
pub const ALG_ECDAA: u16 = 0x001A;
/// TPM_ALG_SM2.
pub const ALG_SM2: u16 = 0x001B;
/// TPM_ALG_ECSCHNORR.
pub const ALG_ECSCHNORR: u16 = 0x001C;
/// TPM_ALG_ECMQV.
pub const ALG_ECMQV: u16 = 0x001D;
/// TPM_ALG_KDF1_SP800_56A.
pub const ALG_KDF1_SP800_56A: u16 = 0x0020;
/// TPM_ALG_KDF2.
pub const ALG_KDF2: u16 = 0x0021;
/// TPM_ALG_KDF1_SP800_108.
pub const ALG_KDF1_SP800_108: u16 = 0x0022;
/// TPM_ALG_ECC.
pub const ALG_ECC: u16 = 0x0023;
/// TPM_ALG_SYMCIPHER.
pub const ALG_SYMCIPHER: u16 = 0x0025;
/// TPM_ALG_CAMELLIA.
pub const ALG_CAMELLIA: u16 = 0x0026;
/// TPM_ALG_CFB.
pub const ALG_CFB: u16 = 0x0043;

// ECC curves (TPM_ECC_CURVE).
/// TPM_ECC_NIST_P256.
pub const ECC_NIST_P256: u16 = 0x0003;
/// TPM_ECC_NIST_P384.
pub const ECC_NIST_P384: u16 = 0x0004;
/// TPM_ECC_NIST_P521.
pub const ECC_NIST_P521: u16 = 0x0005;

// Structure tags (TPM_ST).
/// TPM_ST_ATTEST_CERTIFY.
pub const ST_ATTEST_CERTIFY: u16 = 0x8017;
/// TPM_ST_ATTEST_QUOTE.
pub const ST_ATTEST_QUOTE: u16 = 0x8018;
/// TPM_ST_NO_SESSIONS.
pub const ST_NO_SESSIONS: u16 = 0x8001;
/// TPM_ST_SESSIONS.
pub const ST_SESSIONS: u16 = 0x8002;
/// TPM_ST_HASHCHECK (null validation tickets).
pub const ST_HASHCHECK: u16 = 0x8024;

/// TPM_GENERATED_VALUE: the magic that only the TPM writes into attestations.
pub const GENERATED_VALUE: u32 = 0xff54_4347;

// Command codes (TPM_CC).
/// TPM2_NV_UndefineSpace.
pub const CC_NV_UNDEFINE_SPACE: u32 = 0x0000_0122;
/// TPM2_NV_DefineSpace.
pub const CC_NV_DEFINE_SPACE: u32 = 0x0000_012A;
/// TPM2_CreatePrimary.
pub const CC_CREATE_PRIMARY: u32 = 0x0000_0131;
/// TPM2_NV_Write.
pub const CC_NV_WRITE: u32 = 0x0000_0137;
/// TPM2_Startup.
pub const CC_STARTUP: u32 = 0x0000_0144;
/// TPM2_ActivateCredential.
pub const CC_ACTIVATE_CREDENTIAL: u32 = 0x0000_0147;
/// TPM2_NV_Read.
pub const CC_NV_READ: u32 = 0x0000_014E;
/// TPM2_PolicySecret.
pub const CC_POLICY_SECRET: u32 = 0x0000_0151;
/// TPM2_Quote.
pub const CC_QUOTE: u32 = 0x0000_0158;
/// TPM2_FlushContext.
pub const CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
/// TPM2_NV_ReadPublic.
pub const CC_NV_READ_PUBLIC: u32 = 0x0000_0169;
/// TPM2_ReadPublic.
pub const CC_READ_PUBLIC: u32 = 0x0000_0173;
/// TPM2_StartAuthSession.
pub const CC_START_AUTH_SESSION: u32 = 0x0000_0176;
/// TPM2_GetCapability.
pub const CC_GET_CAPABILITY: u32 = 0x0000_017A;
/// TPM2_PCR_Read.
pub const CC_PCR_READ: u32 = 0x0000_017E;
/// TPM2_PCR_Extend.
pub const CC_PCR_EXTEND: u32 = 0x0000_0182;

// Permanent handles (TPM_RH) and the password session (TPM_RS_PW).
/// TPM_RH_OWNER.
pub const RH_OWNER: u32 = 0x4000_0001;
/// TPM_RH_NULL.
pub const RH_NULL: u32 = 0x4000_0007;
/// TPM_RS_PW.
pub const RS_PW: u32 = 0x4000_0009;
/// TPM_RH_ENDORSEMENT.
pub const RH_ENDORSEMENT: u32 = 0x4000_000B;
/// TPM_RH_PLATFORM.
pub const RH_PLATFORM: u32 = 0x4000_000C;

// Session types and attributes.
/// TPM_SE_POLICY.
pub const SE_POLICY: u8 = 0x01;
/// TPMA_SESSION continueSession.
pub const SESSION_CONTINUE: u8 = 0x01;

// Startup types.
/// TPM_SU_CLEAR.
pub const SU_CLEAR: u16 = 0x0000;

// Capabilities and properties.
/// TPM_CAP_PCRS.
pub const CAP_PCRS: u32 = 0x0000_0005;
/// TPM_CAP_TPM_PROPERTIES.
pub const CAP_TPM_PROPERTIES: u32 = 0x0000_0006;
/// TPM_PT_NV_BUFFER_MAX (PT_FIXED + 44).
pub const PT_NV_BUFFER_MAX: u32 = 0x0000_012C;

// Response codes.
/// TPM_RC_SUCCESS.
pub const RC_SUCCESS: u32 = 0x000;
/// TPM_RC_INITIALIZE (TPM2_Startup not yet run).
pub const RC_INITIALIZE: u32 = 0x100;

// TPMA_OBJECT bits.
/// fixedTPM.
pub const OBJ_FIXED_TPM: u32 = 1 << 1;
/// stClear.
pub const OBJ_ST_CLEAR: u32 = 1 << 2;
/// fixedParent.
pub const OBJ_FIXED_PARENT: u32 = 1 << 4;
/// sensitiveDataOrigin.
pub const OBJ_SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
/// userWithAuth.
pub const OBJ_USER_WITH_AUTH: u32 = 1 << 6;
/// adminWithPolicy.
pub const OBJ_ADMIN_WITH_POLICY: u32 = 1 << 7;
/// noDA.
pub const OBJ_NO_DA: u32 = 1 << 10;
/// encryptedDuplication.
pub const OBJ_ENCRYPTED_DUPLICATION: u32 = 1 << 11;
/// restricted.
pub const OBJ_RESTRICTED: u32 = 1 << 16;
/// decrypt.
pub const OBJ_DECRYPT: u32 = 1 << 17;
/// sign / encrypt.
pub const OBJ_SIGN_ENCRYPT: u32 = 1 << 18;

// TPMA_NV bits.
/// TPMA_NV_PPWRITE.
pub const NV_PPWRITE: u32 = 1 << 0;
/// TPMA_NV_OWNERWRITE.
pub const NV_OWNERWRITE: u32 = 1 << 1;
/// TPMA_NV_AUTHWRITE.
pub const NV_AUTHWRITE: u32 = 1 << 2;
/// TPMA_NV_PPREAD.
pub const NV_PPREAD: u32 = 1 << 16;
/// TPMA_NV_OWNERREAD.
pub const NV_OWNERREAD: u32 = 1 << 17;
/// TPMA_NV_AUTHREAD.
pub const NV_AUTHREAD: u32 = 1 << 18;
/// TPMA_NV_POLICYREAD.
pub const NV_POLICYREAD: u32 = 1 << 19;
/// TPMA_NV_NO_DA.
pub const NV_NO_DA: u32 = 1 << 25;
/// TPMA_NV_WRITTEN.
pub const NV_WRITTEN: u32 = 1 << 29;
/// TPMA_NV_PLATFORMCREATE.
pub const NV_PLATFORMCREATE: u32 = 1 << 30;

// Size limits (TPM 2.0 Part 2, implementation-dependent maxima chosen
// generously for real TPMs; anything larger is rejected).
/// Largest digest (SHA-512).
pub const MAX_DIGEST: usize = 64;
/// TPMU_HA plus the algorithm id (TPMT_HA): bound for TPM2B_DATA / TPM2B_NAME.
pub const MAX_NAME: usize = 2 + MAX_DIGEST;
/// Largest RSA modulus or signature (RSA-4096).
pub const MAX_RSA_BYTES: usize = 512;
/// Largest ECC coordinate.
pub const MAX_ECC_BYTES: usize = 128;
/// Bound on TPML_PCR_SELECTION entries.
pub const MAX_PCR_BANKS: usize = 16;
/// Bound on a PCR bitmap (256 PCRs).
pub const MAX_PCR_SELECT: usize = 32;
