//! TPM 2.0 key derivation functions (Part 1, 11.4.10).

use crate::HashAlg;
use zeroize::Zeroizing;

fn counter_kdf(h: HashAlg, bits: u32, mut block: impl FnMut(u32) -> Vec<u8>) -> Zeroizing<Vec<u8>> {
    let bytes = usize::try_from(bits.div_ceil(8)).unwrap_or(0);
    let mut out = Zeroizing::new(Vec::with_capacity(bytes + h.size()));
    let mut counter: u32 = 1;
    while out.len() < bytes {
        let b = Zeroizing::new(block(counter));
        out.extend_from_slice(&b);
        counter = counter.wrapping_add(1);
    }
    out.truncate(bytes);
    // Mask the unused high bits of the most significant octet.
    let mask_bits = bits % 8;
    if mask_bits > 0
        && let Some(first) = out.first_mut()
    {
        *first &= (1u8 << mask_bits) - 1;
    }
    out
}

/// KDFa (SP 800-108 counter mode with HMAC): derives `bits` bits from `key`
/// with a NUL-terminated `label` and the two context values.
pub fn kdfa(h: HashAlg, key: &[u8], label: &str, context_u: &[u8], context_v: &[u8], bits: u32) -> Zeroizing<Vec<u8>> {
    let bits_be = bits.to_be_bytes();
    counter_kdf(h, bits, |i| h.hmac(key, &[&i.to_be_bytes(), label.as_bytes(), &[0], context_u, context_v, &bits_be]))
}

/// KDFe (SP 800-56A concatenation KDF): derives `bits` bits from the ECDH
/// shared x-coordinate `z`, a NUL-terminated `label` and both parties' x
/// coordinates.
pub fn kdfe(h: HashAlg, z: &[u8], label: &str, party_u: &[u8], party_v: &[u8], bits: u32) -> Zeroizing<Vec<u8>> {
    counter_kdf(h, bits, |i| h.digest_parts(&[&i.to_be_bytes(), z, label.as_bytes(), &[0], party_u, party_v]))
}
