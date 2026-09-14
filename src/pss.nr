use crate::constants::{
    MAX_SALT_LEN, SHA1_HASH_LEN, SHA256_HASH_LEN, SHA384_HASH_LEN, SHA512_HASH_LEN,
};

use crate::utils::get_array_slice;

use crate::mgf1::{mgf1_sha1, mgf1_sha256, mgf1_sha384, mgf1_sha512};
use crate::rsa::exponentiate_signature;

use bignum::RuntimeBigNum;

use sha1::sha1;
use sha256::sha256_var;
use sha512::{sha384, sha512};

/// Parse the (big-endian) PSS encoded message EM = maskedDB || H || 0xBC.
///
/// Verifies the trailing 0xBC byte and the "leftmost bits are zero" requirement,
/// then returns (maskedDB, H). Hash-independent: parameterized only by HASH_LEN.
fn pss_split<let NumLimbs: u32, let ModBits: u32, let HASH_LEN: u32>(
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
) -> ([u8; (ModBits + 7) / 8 - HASH_LEN - 1], [u8; HASH_LEN]) {
    let exponentiated = exponentiate_signature(sig, exponent);

    // Encoded message in big-endian order.
    // Must stay `to_be_bytes` (safe), not `to_be_bytes_unsafe`: it validates sig^e is
    // canonical in [0, n) before EM is parsed. Switching to the unsafe variant would
    // let a prover pass a non-canonical sig^e and is a soundness hole.
    let em: [u8; (ModBits + 7) / 8] = exponentiated.to_be_bytes();

    let em_bits: u32 = ModBits - 1;
    let em_len: u32 = (em_bits + 7) / 8; // EM length ignoring any leading zero byte
    let key_len: u32 = (ModBits + 7) / 8; // modulus length in bytes
    let h_len: u32 = HASH_LEN;

    // EM must end with 0xBC
    assert_eq(em[em.len() - 1], 0xBC);

    let db_mask_len: u32 = em_len - h_len - 1;
    // For non-multiple-of-8 moduli, em_len < key_len and EM has a leading zero
    // byte to skip. offset == 0 for all standard sizes (2048/3072/4096).
    let offset: u32 = key_len - em_len;

    let masked_db: [u8; (ModBits + 7) / 8 - HASH_LEN - 1] =
        get_array_slice(em, offset, db_mask_len + offset);
    let h: [u8; HASH_LEN] = get_array_slice(em, db_mask_len + offset, em.len() - 1);

    // The leftmost (8 * em_len - em_bits) bits of maskedDB must be zero
    let bits_to_mask: u32 = 8 - (8 * em_len - em_bits);
    assert_eq(masked_db[0] as u32 >> bits_to_mask, 0);

    (masked_db, h)
}

/// Unmask DB, verify the PS zero-run and 0x01 separator, extract the salt, and
/// build M' = (0x00 * 8) || msg_hash || salt. Returns (M', M'_len).
/// Hash-independent: parameterized only by HASH_LEN.
fn pss_recover_mprime<let ModBits: u32, let HASH_LEN: u32>(
    masked_db: [u8; (ModBits + 7) / 8 - HASH_LEN - 1],
    db_mask: [u8; (ModBits + 7) / 8 - HASH_LEN - 1],
    msg_hash: [u8; HASH_LEN],
    salt_len: u32,
) -> ([u8; 8 + HASH_LEN + MAX_SALT_LEN], u32) {
    let em_bits: u32 = ModBits - 1;
    let em_len: u32 = (em_bits + 7) / 8;
    let h_len: u32 = HASH_LEN;

    // The salt must fit (emLen >= hLen + saltLen + 2) and stay within the buffer.
    // Both guard the index arithmetic below against u32 underflow.
    assert(em_len >= h_len + salt_len + 2);
    assert(salt_len <= MAX_SALT_LEN);

    // DB = maskedDB XOR dbMask
    let mut db = [0 as u8; (ModBits + 7) / 8 - HASH_LEN - 1];
    for i in 0..(ModBits + 7) / 8 - HASH_LEN - 1 {
        db[i] = masked_db[i] ^ db_mask[i];
    }
    // Clear only the leftmost (8 * em_len - em_bits) bits of DB's first byte,
    // per RFC 8017 §9.1.2 step 8 - NOT the whole byte. Wiping all 8 bits makes
    // the PS-zero check below pass trivially, leaving the low bits of
    // masked_db[0] ^ db_mask[0] unconstrained (a ~2^(8 - n) relaxation of the
    // accepted set). Keeping them lets the PS-zero / separator checks pin them.
    let leftmost_bits: u8 = (8 * em_len - em_bits) as u8;
    db[0] &= 0xff >> leftmost_bits;

    // DB = PS (0x00 run) || 0x01 || salt. Check the zero run and the separator.
    for i in 0..(ModBits + 7) / 8 - HASH_LEN - 2 {
        if i < em_len - h_len - salt_len - 2 {
            assert_eq(db[i], 0);
        }
    }
    assert_eq(db[em_len - h_len - salt_len - 2], 1);

    // The salt is the last salt_len bytes of DB (whose real length is em_len - h_len - 1)
    let db_len: u32 = em_len - h_len - 1;
    let salt: [u8; MAX_SALT_LEN] = get_array_slice(db, db_len - salt_len, db_len);

    // M' = (0x00 * 8) || msg_hash || salt
    let mut m_prime = [0 as u8; 8 + HASH_LEN + MAX_SALT_LEN];
    for i in 8..8 + HASH_LEN {
        m_prime[i] = msg_hash[i - 8];
    }
    for i in 8 + HASH_LEN..8 + HASH_LEN + MAX_SALT_LEN {
        if i < 8 + h_len + salt_len {
            m_prime[i] = salt[i - 8 - HASH_LEN];
        }
    }

    (m_prime, 8 + HASH_LEN + salt_len)
}

/**
 * @brief Verify an RSA-PSS signature over a SHA-1 message hash.
 * @note The exponent `e` can be any positive integer (commonly 3 or 65537 are used for RSA).
 */
pub fn verify_sha1_pss<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; SHA1_HASH_LEN],
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
    salt_len: u32,
) -> bool {
    let (masked_db, h) = pss_split::<NumLimbs, ModBits, SHA1_HASH_LEN>(sig, exponent);
    let db_mask: [u8; (ModBits + 7) / 8 - SHA1_HASH_LEN - 1] = mgf1_sha1(h);
    let (m_prime, len) =
        pss_recover_mprime::<ModBits, SHA1_HASH_LEN>(masked_db, db_mask, msg_hash, salt_len);
    let h_prime = sha1::sha1_var(BoundedVec::from_parts(m_prime, len));
    h == h_prime
}

/**
 * @brief Verify an RSA-PSS signature over a SHA-256 message hash.
 * @note The exponent `e` can be any positive integer (commonly 3 or 65537 are used for RSA).
 */
pub fn verify_sha256_pss<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; SHA256_HASH_LEN],
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
    salt_len: u32,
) -> bool {
    let (masked_db, h) = pss_split::<NumLimbs, ModBits, SHA256_HASH_LEN>(sig, exponent);
    let db_mask: [u8; (ModBits + 7) / 8 - SHA256_HASH_LEN - 1] = mgf1_sha256(h);
    let (m_prime, len) =
        pss_recover_mprime::<ModBits, SHA256_HASH_LEN>(masked_db, db_mask, msg_hash, salt_len);
    let h_prime = sha256_var(m_prime, len);
    h == h_prime
}

/**
 * @brief Verify an RSA-PSS signature over a SHA-384 message hash.
 * @note The exponent `e` can be any positive integer (commonly 3 or 65537 are used for RSA).
 */
pub fn verify_sha384_pss<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; SHA384_HASH_LEN],
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
    salt_len: u32,
) -> bool {
    let (masked_db, h) = pss_split::<NumLimbs, ModBits, SHA384_HASH_LEN>(sig, exponent);
    let db_mask: [u8; (ModBits + 7) / 8 - SHA384_HASH_LEN - 1] = mgf1_sha384(h);
    let (m_prime, len) =
        pss_recover_mprime::<ModBits, SHA384_HASH_LEN>(masked_db, db_mask, msg_hash, salt_len);
    let h_prime = sha384::sha384_var(BoundedVec::from_parts(m_prime, len));
    h == h_prime
}

/**
 * @brief Verify an RSA-PSS signature over a SHA-512 message hash.
 * @note The exponent `e` can be any positive integer (commonly 3 or 65537 are used for RSA).
 */
pub fn verify_sha512_pss<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; SHA512_HASH_LEN],
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
    salt_len: u32,
) -> bool {
    let (masked_db, h) = pss_split::<NumLimbs, ModBits, SHA512_HASH_LEN>(sig, exponent);
    let db_mask: [u8; (ModBits + 7) / 8 - SHA512_HASH_LEN - 1] = mgf1_sha512(h);
    let (m_prime, len) =
        pss_recover_mprime::<ModBits, SHA512_HASH_LEN>(masked_db, db_mask, msg_hash, salt_len);
    let h_prime = sha512::sha512_var(BoundedVec::from_parts(m_prime, len));
    h == h_prime
}

mod tests {
    use super::pss_recover_mprime;

    // RFC 8017 §9.1.2 step 8: only the leftmost (8*emLen - emBits) bits of DB[0]
    // may be cleared. A low bit set in DB[0] is part of PS and must be rejected;
    // the old `db[0] = 0` wiped the whole byte and let this through.
    #[test(should_fail)]
    fn pss_step8_rejects_low_bit_of_db0() {
        let mut masked_db = [0 as u8; (2048 + 7) / 8 - 32 - 1];
        masked_db[256 - 32 - 32 - 2] = 1; // 0x01 separator
        masked_db[0] = 0x01; // low bit in PS region -> must fail
        let _ =
            pss_recover_mprime::<2048, 32>(masked_db, [0; (2048 + 7) / 8 - 32 - 1], [0; 32], 32);
    }
}
