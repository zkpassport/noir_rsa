use crate::constants::{SHA1_HASH_LEN, SHA256_HASH_LEN, SHA384_HASH_LEN, SHA512_HASH_LEN};

use crate::rsa::exponentiate_signature;

use bignum::RuntimeBigNum;

/// Compare a recovered byte hash from an RSA signature to the original message hash
fn compare_signature<let N: u32, let HASH_LEN: u32, let HASH_PREFIX_LEN: u32>(
    padded_hash: [u8; N],
    msg_hash: [u8; HASH_LEN],
    hash_prefix: [u8; HASH_PREFIX_LEN],
) -> bool {
    for i in 0..HASH_LEN {
        // Padded hash is reversed
        assert(padded_hash[HASH_LEN - 1 - i] == msg_hash[i], "PKCS#1 v1.5: message hash mismatch");
    }

    for i in HASH_LEN..(HASH_LEN + HASH_PREFIX_LEN) {
        assert(
            hash_prefix[i - HASH_LEN] == padded_hash[i],
            "PKCS#1 v1.5: DigestInfo prefix mismatch",
        )
    }

    assert(padded_hash[HASH_LEN + HASH_PREFIX_LEN] == 0, "PKCS#1 v1.5: missing 0x00 separator");

    for i in (HASH_LEN + HASH_PREFIX_LEN + 1)..N - 2 {
        assert(padded_hash[i] == 0xff, "PKCS#1 v1.5: PS padding byte is not 0xFF");
    }
    assert(padded_hash[N - 2] == 0x01, "PKCS#1 v1.5: block type is not 0x01");
    assert(padded_hash[N - 1] == 0x00, "PKCS#1 v1.5: leading byte is not 0x00");

    true
}

/// Compare a recovered byte hash from an RSA signature using SHA-1 to the original message hash
fn compare_signature_sha1<let N: u32>(
    padded_sha1_hash: [u8; N],
    msg_hash: [u8; SHA1_HASH_LEN],
) -> bool {
    // SHA-1 ASN.1 DER identifier
    let hash_prefix: [u8; 15] = [20, 4, 0, 5, 26, 2, 3, 14, 43, 5, 6, 9, 48, 33, 48];
    compare_signature::<N, SHA1_HASH_LEN, 15>(padded_sha1_hash, msg_hash, hash_prefix)
}

/// Compare a recovered byte hash from an RSA signature to the original message hash
///
/// Taken from https://github.com/richardliang/noir-rsa
fn compare_signature_sha256<let N: u32>(
    padded_sha256_hash: [u8; N],
    msg_hash: [u8; SHA256_HASH_LEN],
) -> bool {
    // SHA-256 ASN.1 DER identifier
    let hash_prefix: [u8; 19] =
        [32, 4, 0, 5, 1, 2, 4, 3, 101, 1, 72, 134, 96, 9, 6, 13, 48, 49, 48];

    compare_signature::<N, SHA256_HASH_LEN, 19>(padded_sha256_hash, msg_hash, hash_prefix)
}

/// Compare a recovered byte hash from an RSA signature using SHA-384 to the original message hash
fn compare_signature_sha384<let N: u32>(
    padded_sha384_hash: [u8; N],
    msg_hash: [u8; SHA384_HASH_LEN],
) -> bool {
    // SHA-384 ASN.1 DER identifier
    let hash_prefix: [u8; 19] =
        [48, 4, 0, 5, 2, 2, 4, 3, 101, 1, 72, 134, 96, 9, 6, 13, 48, 65, 48];
    compare_signature::<N, SHA384_HASH_LEN, 19>(padded_sha384_hash, msg_hash, hash_prefix)
}

/// Compare a recovered byte hash from an RSA signature using SHA-512 to the original message hash
fn compare_signature_sha512<let N: u32>(
    padded_sha512_hash: [u8; N],
    msg_hash: [u8; SHA512_HASH_LEN],
) -> bool {
    // SHA-512 ASN.1 DER identifier
    let hash_prefix: [u8; 19] =
        [64, 4, 0, 5, 3, 2, 4, 3, 101, 1, 72, 134, 96, 9, 6, 13, 48, 81, 48];
    compare_signature::<N, SHA512_HASH_LEN, 19>(padded_sha512_hash, msg_hash, hash_prefix)
}

/**
 * @brief Verify an RSA signature using the PKCS#1 v1.5 padding scheme with SHA-1
 *
 * @param msg_hash The SHA-1 hash of the message being verified
 * @param sig The RSA signature
 * @param exponent The public exponent (odd, in [3, 2^17 - 1])
 * @return `true` if the signature is valid. An invalid signature never returns `false`:
 *         it fails a constraint inside this function, with a message naming the failed encoded-message check.
 */
pub fn verify_sha1_pkcs1v15<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; 20],
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
) -> bool {
    let exponentiated = exponentiate_signature(sig, exponent);
    // Must stay `to_le_bytes` (safe), not `to_le_bytes_unsafe`: it validates sig^e is
    // canonical in [0, n) before the padding checks. Switching to the unsafe variant
    // would let a prover pass a non-canonical sig^e and is a soundness hole.
    let padded_sha1_hash_bytes: [u8; (ModBits + 7) / 8] = exponentiated.to_le_bytes();
    compare_signature_sha1(padded_sha1_hash_bytes, msg_hash)
}

/**
 * @brief Verify an RSA signature generated via the pkcs1v15 signature scheme with SHA-256
 * @note The `exponent` must be odd and in [3, 2^17 - 1] (commonly 3 or 65537 are used for RSA)
 * Rough cost: 2,048 bit RSA: 26,888 gates per verification
 *             1,024 bit RSA: 11,983 gates per verification
 * A circuit that verifies 1 signature (and does nothing else) will cost ~32k due to initialization costs of lookup tables
 * @return `true` if the signature is valid. An invalid signature never returns `false`:
 *         it fails a constraint inside this function, with a message naming the failed encoded-message check.
 **/
pub fn verify_sha256_pkcs1v15<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; 32],
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
) -> bool {
    let exponentiated = exponentiate_signature(sig, exponent);
    // Must stay `to_le_bytes` (safe), not `to_le_bytes_unsafe`: it validates sig^e is
    // canonical in [0, n) before the padding checks. Switching to the unsafe variant
    // would let a prover pass a non-canonical sig^e and is a soundness hole.
    let padded_sha256_hash_bytes: [u8; (ModBits + 7) / 8] = exponentiated.to_le_bytes();
    compare_signature_sha256(padded_sha256_hash_bytes, msg_hash)
}

/**
 * @brief Verify an RSA signature using the PKCS#1 v1.5 padding scheme with SHA-384
 *
 * @param msg_hash The SHA-384 hash of the message being verified
 * @param sig The RSA signature
 * @param exponent The public exponent (odd, in [3, 2^17 - 1])
 * @return `true` if the signature is valid. An invalid signature never returns `false`:
 *         it fails a constraint inside this function, with a message naming the failed encoded-message check.
 */
pub fn verify_sha384_pkcs1v15<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; 48],
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
) -> bool {
    let exponentiated = exponentiate_signature(sig, exponent);
    // Must stay `to_le_bytes` (safe), not `to_le_bytes_unsafe`: it validates sig^e is
    // canonical in [0, n) before the padding checks. Switching to the unsafe variant
    // would let a prover pass a non-canonical sig^e and is a soundness hole.
    let padded_sha384_hash_bytes: [u8; (ModBits + 7) / 8] = exponentiated.to_le_bytes();
    compare_signature_sha384(padded_sha384_hash_bytes, msg_hash)
}

/**
 * @brief Verify an RSA signature using the PKCS#1 v1.5 padding scheme with SHA-512
 *
 * @param msg_hash The SHA-512 hash of the message being verified
 * @param sig The RSA signature
 * @param exponent The public exponent (odd, in [3, 2^17 - 1])
 * @return `true` if the signature is valid. An invalid signature never returns `false`:
 *         it fails a constraint inside this function, with a message naming the failed encoded-message check.
 */
pub fn verify_sha512_pkcs1v15<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; 64],
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
) -> bool {
    let exponentiated = exponentiate_signature(sig, exponent);
    // Must stay `to_le_bytes` (safe), not `to_le_bytes_unsafe`: it validates sig^e is
    // canonical in [0, n) before the padding checks. Switching to the unsafe variant
    // would let a prover pass a non-canonical sig^e and is a soundness hole.
    let padded_sha512_hash_bytes: [u8; (ModBits + 7) / 8] = exponentiated.to_le_bytes();
    compare_signature_sha512(padded_sha512_hash_bytes, msg_hash)
}

mod tests {
    use super::compare_signature;

    // A well-formed little-endian EM for a 2-byte hash [0x11, 0x22] and a 2-byte
    // DigestInfo prefix [0xAA, 0xBB]: hash, prefix, separator, PS, block type, leading byte.
    global EM: [u8; 8] = [0x22, 0x11, 0xAA, 0xBB, 0x00, 0xFF, 0x01, 0x00];

    fn check(em: [u8; 8]) {
        let _ = compare_signature::<8, 2, 2>(em, [0x11, 0x22], [0xAA, 0xBB]);
    }

    #[test]
    fn accepts_well_formed_em() {
        assert(compare_signature::<8, 2, 2>(EM, [0x11, 0x22], [0xAA, 0xBB]));
    }

    #[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
    fn rejects_bad_hash() {
        let mut em = EM;
        em[0] = 0;
        check(em);
    }

    #[test(should_fail_with = "PKCS#1 v1.5: DigestInfo prefix mismatch")]
    fn rejects_bad_prefix() {
        let mut em = EM;
        em[3] = 0;
        check(em);
    }

    #[test(should_fail_with = "PKCS#1 v1.5: missing 0x00 separator")]
    fn rejects_bad_separator() {
        let mut em = EM;
        em[4] = 0xFF;
        check(em);
    }

    #[test(should_fail_with = "PKCS#1 v1.5: PS padding byte is not 0xFF")]
    fn rejects_bad_padding() {
        let mut em = EM;
        em[5] = 0xFE;
        check(em);
    }

    #[test(should_fail_with = "PKCS#1 v1.5: block type is not 0x01")]
    fn rejects_bad_block_type() {
        let mut em = EM;
        em[6] = 0x02;
        check(em);
    }

    #[test(should_fail_with = "PKCS#1 v1.5: leading byte is not 0x00")]
    fn rejects_bad_leading_byte() {
        let mut em = EM;
        em[7] = 0x01;
        check(em);
    }
}
