use crate::rsa::exponentiate_signature;

use bignum::RuntimeBigNum;

/**
 * @brief Compare a recovered byte hash from an RSA signature using SHA-1 to the original message hash
 **/
fn compare_signature_sha1<let N: u32>(padded_sha1_hash: [u8; N], msg_hash: [u8; 20]) -> bool {
    // Get length of sig (e.g. 1048 = 128 bytes, 2048 = 256 bytes)
    for i in 0..20 {
        // Padded hash is reversed
        assert(padded_sha1_hash[19 - i] == msg_hash[i]);
    }

    // SHA-1 ASN.1 DER identifier
    let hash_prefix: [u8; 15] = [20, 4, 0, 5, 26, 2, 3, 14, 43, 5, 6, 9, 48, 33, 48];

    for i in 20..35 {
        assert(hash_prefix[i - 20] == padded_sha1_hash[i]);
    }

    assert(padded_sha1_hash[35] == 0);

    // Sub 20 bytes for hash, 15 bytes for prefix, 1 byte for 0, 1 byte for 1, 1 byte for 0
    let ps_len = N - 38;
    for i in 36..N {
        if i < 36 + ps_len {
            // PS padding
            assert(padded_sha1_hash[i] == 255);
        } else if i == 36 + ps_len {
            // Pad 0x01
            assert(padded_sha1_hash[i] == 1);
        } else if i == 37 + ps_len {
            // 0x00
            assert(padded_sha1_hash[i] == 0);
        } else {
            // Padded with 0 until MAX_BYTES
            assert(padded_sha1_hash[i] == 0);
        }
    }

    true
}

/**
 * @brief Compare a recovered byte hash from an RSA signature to the original message hash
 * @details Taken from https://github.com/richardliang/noir-rsa
 **/
fn compare_signature_sha256<let N: u32>(padded_sha256_hash: [u8; N], msg_hash: [u8; 32]) -> bool {
    // Get length of sig (e.g. 1048 = 128 bytes, 2048 = 256 bytes)
    // NOTE: Assume MAX_BYTES < 2^32 bit number. MAX_BYTES of 259 > 2^8 bits so need to cast it to u32
    for i in 0..32 {
        // Padded hash is reversed
        assert(padded_sha256_hash[31 - i] == msg_hash[i]);
    }

    let hash_prefix: [u8; 19] =
        [32, 4, 0, 5, 1, 2, 4, 3, 101, 1, 72, 134, 96, 9, 6, 13, 48, 49, 48];

    for i in 32..51 {
        assert(hash_prefix[i - 32] == padded_sha256_hash[i]);
    }

    assert(padded_sha256_hash[51] == 0);

    // Sub 32 bytes for hash, 19 bytes for prefix, 1 byte for 0, 1 byte for 1, 1 byte for 0
    let ps_len = N - 54;
    for i in 52..N {
        if i < 52 + ps_len {
            // PS padding which depends on RSA modulus / sig length. 1024 bits = 128 bytes = 128 - 54 = 74 bytes of 0xFF padding
            assert(padded_sha256_hash[i] == 255);
        } else if i == 52 + ps_len {
            // Pad 0x01
            assert(padded_sha256_hash[i] == 1);
        } else if i == 53 + ps_len {
            // 0x00
            assert(padded_sha256_hash[i] == 0);
        } else {
            // Padded with 0 until MAX_BYTES
            assert(padded_sha256_hash[i] == 0);
        }
    }

    true
}

/**
 * @brief Compare a recovered byte hash from an RSA signature using SHA-384 to the original message hash
 **/
fn compare_signature_sha384<let N: u32>(padded_sha384_hash: [u8; N], msg_hash: [u8; 48]) -> bool {
    // Get length of sig (e.g. 1048 = 128 bytes, 2048 = 256 bytes)
    for i in 0..48 {
        // Padded hash is reversed
        assert(padded_sha384_hash[47 - i] == msg_hash[i]);
    }

    // SHA-384 ASN.1 DER identifier
    let hash_prefix: [u8; 19] =
        [48, 4, 0, 5, 2, 2, 4, 3, 101, 1, 72, 134, 96, 9, 6, 13, 48, 65, 48];

    for i in 48..67 {
        assert(hash_prefix[i - 48] == padded_sha384_hash[i]);
    }

    assert(padded_sha384_hash[67] == 0);

    // Sub 48 bytes for hash, 19 bytes for prefix, 1 byte for 0, 1 byte for 1, 1 byte for 0
    let ps_len = N - 70;
    for i in 68..N {
        if i as u32 < 68 + ps_len as u32 {
            // PS padding
            assert(padded_sha384_hash[i] == 255);
        } else if i as u32 == 68 + ps_len as u32 {
            // Pad 0x01
            assert(padded_sha384_hash[i] == 1);
        } else if i as u32 == 69 + ps_len as u32 {
            // 0x00
            assert(padded_sha384_hash[i] == 0);
        } else {
            // Padded with 0 until MAX_BYTES
            assert(padded_sha384_hash[i] == 0);
        }
    }

    true
}

/**
 * @brief Compare a recovered byte hash from an RSA signature using SHA-512 to the original message hash
 **/
fn compare_signature_sha512<let N: u32>(padded_sha512_hash: [u8; N], msg_hash: [u8; 64]) -> bool {
    // Get length of sig (e.g. 1048 = 128 bytes, 2048 = 256 bytes)
    for i in 0..64 {
        // Padded hash is reversed
        assert(padded_sha512_hash[63 - i] == msg_hash[i]);
    }

    // SHA-512 ASN.1 DER identifier
    let hash_prefix: [u8; 19] =
        [64, 4, 0, 5, 3, 2, 4, 3, 101, 1, 72, 134, 96, 9, 6, 13, 48, 81, 48];

    for i in 64..83 {
        assert(hash_prefix[i - 64] == padded_sha512_hash[i]);
    }

    assert(padded_sha512_hash[83] == 0);

    // Sub 64 bytes for hash, 19 bytes for prefix, 1 byte for 0, 1 byte for 1, 1 byte for 0
    let ps_len = N - 86;
    for i in 84..N {
        if i as u32 < 84 + ps_len as u32 {
            // PS padding
            assert(padded_sha512_hash[i] == 255);
        } else if i as u32 == 84 + ps_len as u32 {
            // Pad 0x01
            assert(padded_sha512_hash[i] == 1);
        } else if i as u32 == 85 + ps_len as u32 {
            // 0x00
            assert(padded_sha512_hash[i] == 0);
        } else {
            // Padded with 0 until MAX_BYTES
            assert(padded_sha512_hash[i] == 0);
        }
    }

    true
}

/**
 * @brief Verify an RSA signature using the PKCS#1 v1.5 padding scheme with SHA-1
 *
 * @param msg_hash The SHA-1 hash of the message being verified
 * @param sig The RSA signature
 * @param exponent The public exponent (any positive integer)
 * @return True if the signature is valid, false otherwise
 */
pub fn verify_sha1_pkcs1v15<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; 20],
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
) -> bool {
    let exponentiated = exponentiate_signature(sig, exponent);
    let mut padded_sha1_hash_bytes: [u8; (ModBits + 7) / 8] = exponentiated.to_le_bytes();
    compare_signature_sha1(padded_sha1_hash_bytes, msg_hash)
}

/**
 * @brief Verify an RSA signature generated via the pkcs1v15 signature scheme with SHA-256
 * @note The `exponent` can be any positive integer (commonly 3 or 65537 are used for RSA)
 * Rough cost: 2,048 bit RSA: 26,888 gates per verification
 *             1,024 bit RSA: 11,983 gates per verification
 * A circuit that verifies 1 signature (and does nothing else) will cost ~32k due to initialization costs of lookup tables
 **/
pub fn verify_sha256_pkcs1v15<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; 32],
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
) -> bool {
    let exponentiated = exponentiate_signature(sig, exponent);
    let mut padded_sha256_hash_bytes: [u8; (ModBits + 7) / 8] = exponentiated.to_le_bytes();
    compare_signature_sha256(padded_sha256_hash_bytes, msg_hash)
}

/**
 * @brief Verify an RSA signature using the PKCS#1 v1.5 padding scheme with SHA-384
 *
 * @param msg_hash The SHA-384 hash of the message being verified
 * @param sig The RSA signature
 * @param exponent The public exponent (any positive integer)
 * @return True if the signature is valid, false otherwise
 */
pub fn verify_sha384_pkcs1v15<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; 48],
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
) -> bool {
    let exponentiated = exponentiate_signature(sig, exponent);
    let mut padded_sha384_hash_bytes: [u8; (ModBits + 7) / 8] = exponentiated.to_le_bytes();
    compare_signature_sha384(padded_sha384_hash_bytes, msg_hash)
}

/**
 * @brief Verify an RSA signature using the PKCS#1 v1.5 padding scheme with SHA-512
 *
 * @param msg_hash The SHA-512 hash of the message being verified
 * @param sig The RSA signature
 * @param exponent The public exponent (any positive integer)
 * @return True if the signature is valid, false otherwise
 */
pub fn verify_sha512_pkcs1v15<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; 64],
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
) -> bool {
    let exponentiated = exponentiate_signature(sig, exponent);
    let mut padded_sha512_hash_bytes: [u8; (ModBits + 7) / 8] = exponentiated.to_le_bytes();
    compare_signature_sha512(padded_sha512_hash_bytes, msg_hash)
}
