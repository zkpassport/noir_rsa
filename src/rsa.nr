use bignum::RuntimeBigNum;
use sha1::sha1;
use sha256;
use sha512::{sha384, sha512};

global SHA1_HASH_LEN: u32 = 20;
global SHA256_HASH_LEN: u32 = 32;
global SHA384_HASH_LEN: u32 = 48;
global SHA512_HASH_LEN: u32 = 64;

global MAX_SALT_LEN: u32 = 64;

fn reverse_array<let N: u32>(array: [u8; N]) -> [u8; N] {
    let mut reversed = [0 as u8; N];
    for i in 0..N {
        reversed[i] = array[N - i - 1];
    }
    reversed
}

fn get_array_slice<let N: u32, let M: u32>(array: [u8; N], start: u32, end: u32) -> [u8; M] {
    assert(end - start <= M);
    let mut slice = [0 as u8; M];
    for i in 0..M {
        if i < end - start {
            slice[i] = array[start + i];
        }
    }
    slice
}

fn pow(base: u32, exp: u32) -> u32 {
    let mut result = 1;
    for _ in 0..exp {
        result *= base;
    }
    result
}

/**
 * @brief Generate a mask from a seed using the MGF1 algorithm with SHA1 as the hash function
 **/
fn mgf1_sha1<let SEED_LEN: u32, let MASK_LEN: u32>(seed: [u8; SEED_LEN]) -> [u8; MASK_LEN] {
    // MASK_LEN must be less than 2^32 * SHA1_HASH_LEN
    std::field::bn254::assert_lt(MASK_LEN as Field, 0xffffffff * SHA1_HASH_LEN as Field + 1);

    // SHA1_HASH_LEN bytes are added at each iteration
    let iterations = (MASK_LEN / SHA1_HASH_LEN) + 1;

    let mut mask: [u8; MASK_LEN] = [0; MASK_LEN];
    let mut hashed: [u8; SHA1_HASH_LEN] = [0; SHA1_HASH_LEN];

    for i in 0..iterations {
        let mut block: [u8; SEED_LEN + 4] = [0; SEED_LEN + 4];

        // Copy seed to block
        for j in 0..SEED_LEN {
            block[j] = seed[j];
        }

        // Add counter to block
        let counter_bytes: [u8; 4] = (i as Field).to_be_bytes();
        for j in 0..4 {
            block[SEED_LEN + j] = counter_bytes[j];
        }

        // Hash the block using SHA-1
        let block_vec = BoundedVec::from_parts(block, SEED_LEN + 4);
        hashed = sha1::sha1_var(block_vec);

        // Copy hashed output to mask
        for j in 0..SHA1_HASH_LEN {
            if i * SHA1_HASH_LEN + j < MASK_LEN {
                mask[i * SHA1_HASH_LEN + j] = hashed[j];
            }
        }
    }

    mask
}

/**
 * @brief Generate a mask from a seed using the MGF1 algorithm with SHA256 as the hash function
 **/
fn mgf1_sha256<let SEED_LEN: u32, let MASK_LEN: u32>(seed: [u8; SEED_LEN]) -> [u8; MASK_LEN] {
    // MASK_LEN must be less than 2^32 * SHA256_HASH_LEN
    std::field::bn254::assert_lt(MASK_LEN as Field, 0xffffffff * SHA256_HASH_LEN as Field + 1);

    // SHA256_HASH_LEN bytes are added at each iteration and there is at least 1 iteration
    // so if SHA256_HASH_LEN is not enough to fill MASK_LEN bytes in one iteration,
    // another one is required and so on.
    let iterations = (MASK_LEN / SHA256_HASH_LEN) + 1;

    let mut mask: [u8; MASK_LEN] = [0; MASK_LEN];
    let mut hashed: [u8; SHA256_HASH_LEN] = [0; SHA256_HASH_LEN];

    for i in 0..iterations {
        let mut block: [u8; SEED_LEN + 4] = [0; SEED_LEN + 4];

        // Copy seed to block
        for j in 0..SEED_LEN {
            block[j] = seed[j];
        }

        // Add counter to block
        let counter_bytes: [u8; 4] = (i as Field).to_be_bytes();
        for j in 0..4 {
            block[SEED_LEN + j] = counter_bytes[j];
        }

        // Hash the block
        // First SEED_LEN bytes are the seed, next 4 bytes are the counter
        hashed = sha256::sha256_var(block, SEED_LEN + 4);

        // Copy hashed output to mask
        for j in 0..SHA256_HASH_LEN {
            if i * SHA256_HASH_LEN + j < MASK_LEN {
                mask[i * SHA256_HASH_LEN + j] = hashed[j];
            }
        }
    }

    mask
}

/**
 * @brief Generate a mask from a seed using the MGF1 algorithm with SHA384 as the hash function
 **/
fn mgf1_sha384<let SEED_LEN: u32, let MASK_LEN: u32>(seed: [u8; SEED_LEN]) -> [u8; MASK_LEN] {
    // MASK_LEN must be less than 2^32 * SHA384_HASH_LEN
    std::field::bn254::assert_lt(MASK_LEN as Field, 0xffffffff * SHA384_HASH_LEN as Field + 1);

    // SHA384_HASH_LEN bytes are added at each iteration
    let iterations = (MASK_LEN / SHA384_HASH_LEN) + 1;

    let mut mask: [u8; MASK_LEN] = [0; MASK_LEN];
    let mut hashed: [u8; SHA384_HASH_LEN] = [0; SHA384_HASH_LEN];

    for i in 0..iterations {
        let mut block: [u8; SEED_LEN + 4] = [0; SEED_LEN + 4];

        // Copy seed to block
        for j in 0..SEED_LEN {
            block[j] = seed[j];
        }

        // Add counter to block
        let counter_bytes: [u8; 4] = (i as Field).to_be_bytes();
        for j in 0..4 {
            block[SEED_LEN + j] = counter_bytes[j];
        }

        let block_vec = BoundedVec::from_parts(block, SEED_LEN + 4);
        hashed = sha384::sha384_var(block_vec);

        // Copy hashed output to mask
        for j in 0..SHA384_HASH_LEN {
            if i * SHA384_HASH_LEN + j < MASK_LEN {
                mask[i * SHA384_HASH_LEN + j] = hashed[j];
            }
        }
    }

    mask
}

/**
 * @brief Generate a mask from a seed using the MGF1 algorithm with SHA512 as the hash function
 **/
fn mgf1_sha512<let SEED_LEN: u32, let MASK_LEN: u32>(seed: [u8; SEED_LEN]) -> [u8; MASK_LEN] {
    // MASK_LEN must be less than 2^32 * SHA512_HASH_LEN
    std::field::bn254::assert_lt(MASK_LEN as Field, 0xffffffff * SHA512_HASH_LEN as Field + 1);

    // SHA512_HASH_LEN bytes are added at each iteration
    let iterations = (MASK_LEN / SHA512_HASH_LEN) + 1;

    let mut mask: [u8; MASK_LEN] = [0; MASK_LEN];
    let mut hashed: [u8; SHA512_HASH_LEN] = [0; SHA512_HASH_LEN];

    for i in 0..iterations {
        let mut block: [u8; SEED_LEN + 4] = [0; SEED_LEN + 4];

        // Copy seed to block
        for j in 0..SEED_LEN {
            block[j] = seed[j];
        }

        // Add counter to block
        let counter_bytes: [u8; 4] = (i as Field).to_be_bytes();
        for j in 0..4 {
            block[SEED_LEN + j] = counter_bytes[j];
        }

        let block_vec = BoundedVec::from_parts(block, SEED_LEN + 4);
        hashed = sha512::sha512_var(block_vec);

        // Copy hashed output to mask
        for j in 0..SHA512_HASH_LEN {
            if i * SHA512_HASH_LEN + j < MASK_LEN {
                mask[i * SHA512_HASH_LEN + j] = hashed[j];
            }
        }
    }

    mask
}

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
 * @brief Exponentiate a signature by a given exponent using binary exponentiation
 * @details This function handles the exponentiation of a signature by any given exponent.
 * Uses the square-and-multiply algorithm for efficient modular exponentiation.
 * @param sig The signature to exponentiate
 * @param exponent The exponent to use (any positive integer)
 * @return The exponentiated signature
 */
fn exponentiate_signature<let NumLimbs: u32, let ModBits: u32>(
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
) -> RuntimeBigNum<NumLimbs, ModBits> {
    assert((exponent > 1) & (exponent < 131072), "Exponent must be more than 1 and less than 2^17");

    // Binary exponentiation (square-and-multiply algorithm)
    let mut result = RuntimeBigNum::one(sig.params);
    let mut base = sig;
    let mut exp = exponent;

    // We assume the exponent won't be more than to 2^17 so we can
    // have less iterations
    for _ in 0..17 {
        if exp > 0 {
            // If the exponent is odd, multiply result by current base
            if exp % 2 == 1 {
                result = result * base;
            }

            // Square the base for the next bit
            base = base * base;

            // Divide exponent by 2 (move to the next bit)
            exp = exp / 2;
        }
    }

    result
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

/**
    * @brief Verify an RSA signature generated via the PSS signature scheme using SHA-1.
    *
    * @note The exponent `e` can be any positive integer (commonly 3 or 65537 are used for RSA)
    **/
pub fn verify_sha1_pss<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; 20],
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
    salt_len: u32,
) -> bool {
    let exponentiated = exponentiate_signature(sig, exponent);

    // Convert the exponentiated signature to a byte array and reverse it to
    // get it in big endian order, which is much easier to work with for
    // the rest of the verification process
    let em: [u8; (ModBits + 7) / 8] = reverse_array(exponentiated.to_le_bytes());

    // The modulus size in bits minus 1
    let em_bits = ModBits - 1;
    // The actual length of the encoded message without any of the leftmost 0s
    let em_len = (em_bits + 7) / 8;
    // The length of the modulus in bytes
    let key_len = (ModBits + 7) / 8;
    let h_len = 20; // SHA-1 produces 20-byte hashes

    // Check if emLen < hLen + salt_len + 2
    assert(em_len >= h_len + salt_len + 2);

    // Check if eM ends with 0xBC
    assert_eq(em[em.len() - 1], 0xBC);

    let db_mask_len = em_len - h_len - 1;
    // In some rare cases, em_len is not equal to key_len (e.g. 1025 bit RSA)
    // In this case, we'll have a leading zero byte in em that we need to ignore
    // c.f. https://github.com/RustCrypto/RSA/blob/aeedb5adf5297892fcb9e11f7c0f6c0157005c58/src/algorithms/pss.rs#L242
    let offset = key_len - em_len;
    // As the hash is 20 bytes and we also remove the 0xBC at the end, we have up to NumBytes - 21 bytes left for DB
    // For example, for 2048 bit RSA (i.e. 256 bytes), we have 256 - 21 = 235 bytes left for DB
    // and for 1024 bit RSA (i.e. 128 bytes), we have 128 - 21 = 107 bytes left for DB
    let masked_db: [u8; (ModBits + 7) / 8 - 21] = get_array_slice(em, offset, db_mask_len + offset);
    let h = get_array_slice(em, db_mask_len + offset, em.len() - 1);

    // Make sure the 8 * em_len - em_bits leftmost bits are 0
    // c.f. https://github.com/RustCrypto/RSA/blob/aeedb5adf5297892fcb9e11f7c0f6c0157005c58/src/algorithms/pss.rs#L205
    let bits_to_mask = 8 - (8 * em_len - em_bits);
    let mask_value = pow(2, bits_to_mask as u32);
    assert_eq(masked_db[0] as u32 / mask_value, 0);

    // Generate dbMask using MGF1 with SHA-1
    let db_mask: [u8; (ModBits + 7) / 8 - 21] = mgf1_sha1(h);

    // Compute DB = maskedDB xor dbMask
    let mut db = [0 as u8; (ModBits + 7) / 8 - 21];
    for i in 0..db_mask_len {
        db[i] = masked_db[i] ^ db_mask[i];
    }

    // Set leftmost byte of DB to 0
    db[0] = 0;

    // Check if the leftmost octets of DB are zero
    for i in 0..(em_len - h_len - 2) {
        if i < em_len - h_len - salt_len - 2 {
            assert_eq(db[i], 0);
        }
    }

    // Check if the octet at position emLen - hLen - salt_len - 2 is 1
    assert_eq(db[em_len - h_len - salt_len - 2], 1);

    // Extract salt
    let salt: [u8; MAX_SALT_LEN] = get_array_slice(db, db_mask_len - salt_len, db_mask_len);

    // Construct M'
    // M' = (0x)00 00 00 00 00 00 00 00 || msg_hash || salt
    let mut m_prime = [0 as u8; 28 + MAX_SALT_LEN]; // 8 + h_len + salt_len = 8 + 20 + salt_len = 38 + salt_len
    for i in 8..28 {
        m_prime[i] = msg_hash[i - 8];
    }
    for i in 28..28 + MAX_SALT_LEN {
        if i < (28 + salt_len) {
            m_prime[i] = salt[i - 28];
        }
    }

    // Compute H' using SHA-1
    let m_prime_vec = BoundedVec::from_parts(m_prime, 28 + salt_len);
    let h_prime = sha1::sha1_var(m_prime_vec);

    // Compare H and H'
    h == h_prime
}

/**
    * @brief Verify an RSA signature generated via the PSS signature scheme.
    *
    * @note The exponent `e` can be any positive integer (commonly 3 or 65537 are used for RSA)
    **/
pub fn verify_sha256_pss<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; 32],
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
    salt_len: u32,
) -> bool {
    let exponentiated = exponentiate_signature(sig, exponent);

    // Convert the exponentiated signature to a byte array and reverse it to
    // get it in big endian order, which is much easier to work with for
    // the rest of the verification process
    let em: [u8; (ModBits + 7) / 8] = reverse_array(exponentiated.to_le_bytes());

    // The modulus size in bits minus 1
    let em_bits = ModBits - 1;
    // The actual length of the encoded message without any of the leftmost 0s
    let em_len = (em_bits + 7) / 8;
    // The length of the modulus in bytes
    let key_len = (ModBits + 7) / 8;
    let h_len = 32;

    // Check if emLen < hLen + salt_len + 2
    assert(em_len >= h_len + salt_len + 2);

    // Check if eM ends with 0xBC
    assert_eq(em[em.len() - 1], 0xBC);

    let db_mask_len = em_len - h_len - 1;
    // In some rare cases, em_len is not equal to key_len (e.g. 1025 bit RSA)
    // In this case, we'll have a leading zero byte in em that we need to ignore
    // c.f. https://github.com/RustCrypto/RSA/blob/aeedb5adf5297892fcb9e11f7c0f6c0157005c58/src/algorithms/pss.rs#L242
    let offset = key_len - em_len;
    // As the hash is 32 bytes and we also remove the 0xBC at the end, we have up to NumBytes - 33 bytes left for DB
    // For example, for 2048 bit RSA (i.e. 256 bytes), we have 256 - 33 = 223 bytes left for DB
    // and for 1024 bit RSA (i.e. 128 bytes), we have 128 - 33 = 95 bytes left for DB
    let masked_db: [u8; (ModBits + 7) / 8 - 33] = get_array_slice(em, offset, db_mask_len + offset);
    let h = get_array_slice(em, db_mask_len + offset, em.len() - 1);

    // Make sure the 8 * em_len - em_bits leftmost bits are 0
    // c.f. https://github.com/RustCrypto/RSA/blob/aeedb5adf5297892fcb9e11f7c0f6c0157005c58/src/algorithms/pss.rs#L205
    let bits_to_mask = 8 - (8 * em_len - em_bits);
    let mask_value = pow(2, bits_to_mask as u32);
    assert_eq(masked_db[0] as u32 / mask_value, 0);

    // Generate dbMask using MGF1
    let db_mask: [u8; (ModBits + 7) / 8 - 33] = mgf1_sha256(h);

    // Compute DB = maskedDB xor dbMask
    let mut db = [0 as u8; (ModBits + 7) / 8 - 33];
    for i in 0..db_mask_len {
        db[i] = masked_db[i] ^ db_mask[i];
    }

    // Set leftmost byte of DB to 0
    db[0] = 0;

    // Check if the leftmost octets of DB are zero
    for i in 0..(em_len - h_len - 2) {
        if i < em_len - h_len - salt_len - 2 {
            assert_eq(db[i], 0);
        }
    }

    // Check if the octet at position emLen - hLen - sLen - 2 is 1
    assert_eq(db[em_len - h_len - salt_len - 2], 1);

    // Extract salt
    let salt: [u8; MAX_SALT_LEN] = get_array_slice(db, db_mask_len - salt_len, db_mask_len);

    // Construct M'
    // M' = (0x)00 00 00 00 00 00 00 00 || msg_hash || salt
    let mut m_prime = [0 as u8; 40 + MAX_SALT_LEN]; // 8 + h_len + salt_len = 8 + 32 + salt_len = 40 + salt_len
    for i in 8..40 {
        m_prime[i] = msg_hash[i - 8];
    }
    for i in 40..40 + MAX_SALT_LEN {
        if i < (40 + salt_len) {
            m_prime[i] = salt[i - 40];
        }
    }

    // Compute H'
    let h_prime = sha256::sha256_var(m_prime, 40 + salt_len);

    // Compare H and H'
    h == h_prime
}

/**
    * @brief Verify an RSA signature generated via the PSS signature scheme using SHA-384.
    *
    * @note The exponent `e` can be any positive integer (commonly 3 or 65537 are used for RSA)
    **/
pub fn verify_sha384_pss<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; 48],
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
    salt_len: u32,
) -> bool {
    let exponentiated = exponentiate_signature(sig, exponent);

    // Convert the exponentiated signature to a byte array and reverse it to
    // get it in big endian order, which is much easier to work with for
    // the rest of the verification process
    let em: [u8; (ModBits + 7) / 8] = reverse_array(exponentiated.to_le_bytes());

    // The modulus size in bits minus 1
    let em_bits = ModBits - 1;
    // The actual length of the encoded message without any of the leftmost 0s
    let em_len = (em_bits + 7) / 8;
    // The length of the modulus in bytes
    let key_len = (ModBits + 7) / 8;
    let h_len = 48; // SHA-384 produces 48-byte hashes

    // Check if emLen < hLen + salt_len + 2
    assert(em_len >= h_len + salt_len + 2);

    // Check if eM ends with 0xBC
    assert_eq(em[em.len() - 1], 0xBC);

    let db_mask_len = em_len - h_len - 1;
    // In some rare cases, em_len is not equal to key_len (e.g. 1025 bit RSA)
    // In this case, we'll have a leading zero byte in em that we need to ignore
    let offset = key_len - em_len;

    // The array slice sizes will be different for SHA-384 compared to SHA-256
    let masked_db: [u8; (ModBits + 7) / 8 - 49] = get_array_slice(em, offset, db_mask_len + offset);
    let h = get_array_slice(em, db_mask_len + offset, em.len() - 1);

    // Make sure the 8 * em_len - em_bits leftmost bits are 0
    let bits_to_mask = 8 - (8 * em_len - em_bits);
    let mask_value = pow(2, bits_to_mask as u32);
    assert_eq(masked_db[0] as u32 / mask_value, 0);

    // Generate dbMask using MGF1 with SHA-384
    let db_mask: [u8; (ModBits + 7) / 8 - 49] = mgf1_sha384(h);

    // Compute DB = maskedDB xor dbMask
    let mut db = [0 as u8; (ModBits + 7) / 8 - 49];
    for i in 0..db_mask_len {
        db[i] = masked_db[i] ^ db_mask[i];
    }

    // Set leftmost byte of DB to 0
    db[0] = 0;

    // Check if the leftmost octets of DB are zero
    for i in 0..(em_len - h_len - 2) {
        if i < em_len - h_len - salt_len - 2 {
            assert_eq(db[i], 0);
        }
    }

    // Check if the octet at position emLen - hLen - sLen - 2 is 1
    assert_eq(db[em_len - h_len - salt_len - 2], 1);

    // Extract salt
    let salt: [u8; MAX_SALT_LEN] = get_array_slice(db, db_mask_len - salt_len, db_mask_len);

    // Construct M'
    // M' = (0x)00 00 00 00 00 00 00 00 || msg_hash || salt
    let mut m_prime = [0 as u8; 104]; // 8 + h_len + salt_len = 8 + 48 + salt_len = 56 + salt_len
    for i in 8..56 {
        m_prime[i] = msg_hash[i - 8];
    }
    for i in 56..56 + MAX_SALT_LEN {
        if i < (56 + salt_len) {
            m_prime[i] = salt[i - 56];
        }
    }

    // Compute H' using SHA-384
    let m_prime_vec = BoundedVec::from_parts(m_prime, 56 + salt_len);
    let h_prime = sha384::sha384_var(m_prime_vec);

    // Compare H and H'
    h == h_prime
}

/**
    * @brief Verify an RSA signature generated via the PSS signature scheme using SHA-512.
    *
    * @note The exponent `e` can be any positive integer (commonly 3 or 65537 are used for RSA)
    **/
pub fn verify_sha512_pss<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; 64],
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
    salt_len: u32,
) -> bool {
    let exponentiated = exponentiate_signature(sig, exponent);

    // Convert the exponentiated signature to a byte array and reverse it to
    // get it in big endian order, which is much easier to work with for
    // the rest of the verification process
    let em: [u8; (ModBits + 7) / 8] = reverse_array(exponentiated.to_le_bytes());

    // The modulus size in bits minus 1
    let em_bits = ModBits - 1;
    // The actual length of the encoded message without any of the leftmost 0s
    let em_len = (em_bits + 7) / 8;
    // The length of the modulus in bytes
    let key_len = (ModBits + 7) / 8;
    let h_len = 64; // SHA-512 produces 64-byte hashes

    // Check if emLen < hLen + salt_len + 2
    assert(em_len >= h_len + salt_len + 2);

    // Check if eM ends with 0xBC
    assert_eq(em[em.len() - 1], 0xBC);

    let db_mask_len = em_len - h_len - 1;
    // In some rare cases, em_len is not equal to key_len (e.g. 1025 bit RSA)
    // In this case, we'll have a leading zero byte in em that we need to ignore
    let offset = key_len - em_len;

    // The array slice sizes will be different for SHA-512 compared to SHA-256
    let masked_db: [u8; (ModBits + 7) / 8 - 65] = get_array_slice(em, offset, db_mask_len + offset);
    let h = get_array_slice(em, db_mask_len + offset, em.len() - 1);

    // Make sure the 8 * em_len - em_bits leftmost bits are 0
    let bits_to_mask = 8 - (8 * em_len - em_bits);
    let mask_value = pow(2, bits_to_mask as u32);
    assert_eq(masked_db[0] as u32 / mask_value, 0);

    // Generate dbMask using MGF1 with SHA-512
    let db_mask: [u8; (ModBits + 7) / 8 - 65] = mgf1_sha512(h);

    // Compute DB = maskedDB xor dbMask
    let mut db = [0 as u8; (ModBits + 7) / 8 - 65];
    for i in 0..db_mask_len {
        db[i] = masked_db[i] ^ db_mask[i];
    }

    // Set leftmost byte of DB to 0
    db[0] = 0;

    // Check if the leftmost octets of DB are zero
    for i in 0..(em_len - h_len - 2) {
        if i < em_len - h_len - salt_len - 2 {
            assert_eq(db[i], 0);
        }
    }

    // Check if the octet at position emLen - hLen - sLen - 2 is 1
    assert_eq(db[em_len - h_len - salt_len - 2], 1);

    // Extract salt
    let salt: [u8; MAX_SALT_LEN] = get_array_slice(db, db_mask_len - salt_len, db_mask_len);

    // Construct M'
    // M' = (0x)00 00 00 00 00 00 00 00 || msg_hash || salt
    let mut m_prime = [0 as u8; 72 + MAX_SALT_LEN]; // 8 + h_len + salt_len = 8 + 64 + salt_len = 72 + salt_len
    for i in 8..72 {
        m_prime[i] = msg_hash[i - 8];
    }
    for i in 72..72 + MAX_SALT_LEN {
        if i < (72 + salt_len) {
            m_prime[i] = salt[i - 72];
        }
    }

    // Compute H' using SHA-512
    let m_prime_vec = BoundedVec::from_parts(m_prime, 72 + salt_len);
    let h_prime = sha512::sha512_var(m_prime_vec);

    // Compare H and H'
    h == h_prime
}

mod tests {

    use crate::types::{
        Params1024, Params1025, Params2048, Params4096, RBN1024, RBN1025, RBN2048, RBN4096,
    };
    use super::{
        mgf1_sha1, mgf1_sha256, mgf1_sha384, mgf1_sha512, verify_sha1_pkcs1v15, verify_sha1_pss,
        verify_sha256_pkcs1v15, verify_sha256_pss, verify_sha384_pkcs1v15, verify_sha384_pss,
        verify_sha512_pkcs1v15, verify_sha512_pss,
    };
    use bignum::params::BigNumParams;
    use bignum::RuntimeBigNum;
    use sha1::sha1;
    use sha512::{sha384, sha512};

    #[test]
    fn test_verify_sha256_pkcs1v15_1024() {
        // Output of `cargo run -- --msg "hello world! test#123" --bits 1024` in the `signature_gen` directory
        let sha256_hash: [u8; 32] = [
            220, 155, 229, 143, 122, 133, 55, 215, 75, 44, 132, 111, 57, 33, 248, 84, 213, 170, 193,
            96, 253, 57, 124, 13, 251, 42, 92, 147, 105, 172, 233, 85,
        ];

        let params: BigNumParams<9, 1024> = BigNumParams::new(
            false,
            [
                0xab238ad9cb37979a43aefbf10be8fb,
                0x31347febe45fe8c2dac1dd30900704,
                0xa5a9a6b9cd0cc2b9d13bbd4e068263,
                0x5eac6390f7873fe97ff9bb14a173ea,
                0xbc41f700c91fd733a2c63177bbdbd4,
                0x41442bd58769a3595b659a2ec9c6be,
                0x4ddc91395f330382aa2e2d3fbe147,
                0x3d008ff255a0bc71c7887f5728ba1,
                0xb640c3a8f511c64e,
            ],
            [
                0x754f498d31a8246099810e5a33898c,
                0x7752f8f7380c8e924bba4d02bb136d,
                0xe0b438b9720c67c0691831cb006151,
                0x8db9bf1b98ba287548ab3697ece24b,
                0x6bdd5586759b9602406a889340c5d0,
                0xd98a458592039f87c80b6f3b76a1f,
                0x2e848094df47a515873301499561a,
                0xa6e64f615eea27a977a608abad2e4d,
                0x59e5a300001d8689cd,
            ],
        );

        let signature: RuntimeBigNum<9, 1024> = RuntimeBigNum {
            params,
            limbs: [
                0xc3850e84ea02da3f028ff422f4d6a9,
                0x9761f0bd9021f76d45c60df0670a19,
                0xc1ede421a43607ab623ed4d5a17fc8,
                0x86197b4315206f4d53200b42555831,
                0xe95783b69db28c26a83706f39d04cd,
                0x18b178dc1a9ec76fb22b57e4dfa703,
                0xdd0e19cd5a09ab48e7af4d0e3470e3,
                0x10004dfab1cf91304e80e6baa4dfc7,
                0x241c3fd77b90adef,
            ],
        };

        assert(verify_sha256_pkcs1v15(sha256_hash, signature, 65537));
    }

    #[test]
    fn test_verify_sha256_pkcs1v15_2048() {
        // Output of `cargo run -- --msg "Hello World! This is Noir-RSA"` in the `signature_gen` directory
        let sha256_hash: [u8; 32] = [
            91, 207, 46, 60, 22, 153, 217, 144, 2, 127, 224, 143, 181, 45, 32, 120, 122, 131, 166,
            79, 166, 183, 43, 158, 116, 105, 73, 207, 196, 77, 33, 5,
        ];

        let params: BigNumParams<18, 2048> = BigNumParams::new(
            false,
            [
                0x8d5e7d9daedd6cfd1c9bdf0227e05b,
                0xbfb937fc4d3cf02cc0af780f3cab44,
                0xd20637ef7adcf5d238ee87bccc9bca,
                0xb9db4f2663108e2f8b673f7612ae8b,
                0x85f894ef669b36bfd3d86b0a28873,
                0xdcc70e1884e38b8229cce3b884121d,
                0x35488d1138e0b03e1676f7f5d8a5b3,
                0xe1a97820e7dcbb4eab35c9b71bb273,
                0x97d19eb3c63249ddbfcff915863f54,
                0x3a78c7af6da0f6af0d67b1ca4b6065,
                0xd7a3c433c020f624821e5e678c7d69,
                0x52d5b53240feae82ffea3d2a3d9b09,
                0xb8aad5e19e2163f68997c6fdd71906,
                0x5db432d06e8b0bf59511100c7894e2,
                0xadc0bbc4c54da10d1cc88438ea3127,
                0xece1cf6a1501109cd2734d5893c8d9,
                0x7196b90acdf06c31b1288064fd0c27,
                0xc8,
            ],
            [
                0x6c77b33d36f7a14b0d2975a42283c,
                0xf2796f6ac8bc08fef32961a4af33d4,
                0x7d950e5a1588f914e5bfd55d470efe,
                0xadab4b17e38eab0574332eae05afe8,
                0x728ba38c12090f05b1c22a00c2ac34,
                0xc01e6ffac7e947954056045cf28671,
                0xfe357dafa9217f7309c58c9fda6ad0,
                0xdad66760562505ad6d7c0de61ae667,
                0xd584b8d293fca7c28669e08d44bd60,
                0xa22da25e4a6d530ec9a97ea81f003d,
                0x2d59d7e84eadd113c7c11f4fac6ef8,
                0xae82b1843be7c99eacc3f896ec7211,
                0x8e1ad23b80c5a3573a8fb2e772407d,
                0xb3c6807df6e913814325d850bec7da,
                0x5e98ed72dfbf1834d40a51abb18f3e,
                0x4b307572ac4287a788e634a6e78fbe,
                0x18d73c9719b9daeea00d37d18813ec,
                0x51bd,
            ],
        );

        let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum {
            params,
            limbs: [
                0xad29e07d16a278de49a371b9760a27,
                0x86311920cc0e17a3c20cdff4c56dbb,
                0x863556c6c5247dd83668dd825716ae,
                0xc247c960945f4485b46c33b87425ca,
                0x7326463c5c4cd5b08e21b938d9ed9a,
                0x4f89fe0c82da08a0259eddb34d0da1,
                0x43a74e76d4e1bd2666f1591889af0d,
                0x240f7b80f0ff29f4253ee3019f832d,
                0xc6edd131fbaaf725fd423dac52b362,
                0x85f9732679242163e8afff44f6104d,
                0xd3c3bbcb1757013fd6fb80f31dd9a6,
                0x9008633f15df440e6df6d21ee585a2,
                0x324df3425ed256e283be5b6b761741,
                0xc60c1302929bd0e07caa4aeff4e8fd,
                0x600d804ff13ba8d0e1bc9508714212,
                0x50f7e75e5751d7edd61167027926be,
                0x0db41d39442023e1420a8a84fe81d9,
                0xab,
            ],
        };
        assert(verify_sha256_pkcs1v15(sha256_hash, signature, 65537));
    }

    #[test]
    fn test_verify_sha256_pkcs1v15_2048_exponent_3() {
        // Output of `cargo run -- --msg "hello world" -e 3` in the `signature_gen` directory
        let sha256_hash: [u8; 32] = [
            185, 77, 39, 185, 147, 77, 62, 8, 165, 46, 82, 215, 218, 125, 171, 250, 196, 132, 239,
            227, 122, 83, 128, 238, 144, 136, 247, 172, 226, 239, 205, 233,
        ];

        let params: BigNumParams<18, 2048> = BigNumParams::new(
            false,
            [
                0xe40ee47801326543c8e84b85d567c1,
                0x5b54ea87f0ce29de1995697b0696fd,
                0x457078f8fdce68b437cac0970b2452,
                0x473ec776fee3731b6ab06e35875ddc,
                0x62dedd594e5f12c80c3ccb5791a6cd,
                0xecb934b9d8272c5e3a418145345499,
                0xd1af643b3d785470ed0c6cd633f706,
                0xb58a57b9e96eccbdfc7c17f0333d4,
                0x2ebd34b5039fc596504927c282c60d,
                0x3a44928a74f25fc1043bb37ce4dfa8,
                0x91448459f9617fac33a2816162ac9e,
                0x70cb910d9f3e1a78864640ec6c8240,
                0x9aed33f6b31f1c9de67248a98c180,
                0x7f1416e032c79488c94b311e87bd9c,
                0x7191b4ebb1b3fffa949fa48ed01e5,
                0x350a75cbaeca6bfdd71ca83cdbcae9,
                0xfb1d274fa207457c6814d42c09f9cf,
                0xd4,
            ],
            [
                0xefd34e04429f4dff7417d6437ba4,
                0x9a34c5f24cfcdf2ad6ad39f0028ee6,
                0x1da81694dafd7caa86e214051b2e9e,
                0x28a5faa2d54a3647520dbfc9f0c2ad,
                0xd73cbaaaddbbbe84aef55c3c6baa7f,
                0x3daa2ae1df6716f36630def7170b4d,
                0x525f6c7dbafa0f7b2b2a991feafa9a,
                0xa1ac9f28cc38979e9f3c65fd90cfbf,
                0xf78134889720c22c1d602bc016283d,
                0x8a7eda5ddf03a45a5d890ecac26157,
                0xe60d648a1614b9f870b2ceba5a0c8e,
                0x9cd82005fe7d6b3d9e806dcdca35c3,
                0xbbfe0948702f10ca817d2dd113eb01,
                0x16a271348a7d82aa8ea9eb1f6b078b,
                0x3fb3fe4ef27eff835b7fd8247cb6e2,
                0xc83c11f72c892d111ef426301fe30b,
                0x552ed4f2b7acfaaae4468627e4089f,
                0x4ced,
            ],
        );

        let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum {
            params,
            limbs: [
                0xa250eff812c63eaaeaa3f04641c05f,
                0xecc09613cb8b289c1f37c8f92e6a05,
                0x2c0a0510058360c07af65d46f594fd,
                0x943d67513363d3de430c94a1dafe7c,
                0x511ec8e9b10bc6c6ff0d6c232ccf92,
                0x50ffd07b3c093b3f5fc027de847731,
                0xc268e1489449943fdafdf89ff168c3,
                0x0b8b7f9f49b492f78fda58d252f23a,
                0x491c6c4ef836a6a8730b7bf81e865e,
                0x8746c75fb079d014e419543f56d7f0,
                0x65804c417d6168a8bc0025d255cebf,
                0xf695e91b77890b8e3fd775fa56e627,
                0x5e90001c0218550f4083ae28025a2f,
                0x526bd4eff34f25f62a698f0470e0a6,
                0x7f224306a7d9daf536b1559434c6c6,
                0x88809f16fe1fcea3c87511d9319735,
                0x7694685fee0bfab4a9196b92ec6f2e,
                0xa7,
            ],
        };

        assert(verify_sha256_pkcs1v15(sha256_hash, signature, 3));
    }

    #[test]
    fn test_verify_sha256_pkcs1v15_2048_exponent_38129() {
        let sha256_hash: [u8; 32] =
            sha256::sha256_var("Hello World! This is Noir-RSA".as_bytes(), 29);

        let params: Params2048 = BigNumParams::new(
            false,
            [
                0x4f79aee9e865ee89b9695c2ac44903,
                0xe33ac311e740f4dfc39492d38186d4,
                0xf513677b71c4cdf88b9011d109402d,
                0x940eba50ebc0a50b539268b2c9edee,
                0x6d7b7dc633b0ba7deb34669da59af9,
                0x69f0b92bd973d83643b54c86302bc8,
                0xbee39cd038bb54491cab410bc1382d,
                0xe59688c01aa8491c6522aa467fbdba,
                0x8731b6ff98f9e1f792d4a4dff8c81d,
                0x9d1773f064f1ce81301053e3abcc43,
                0xe80e6137f3ccf06ca669e0d0f14c30,
                0xefbf9d55ae96471f9fef8d5ac29c46,
                0x284807c893f7e7af1a39d9c599ba76,
                0x17491bdeafd3a2c796dd50f2444997,
                0x21742c4e2dc66d064e36abb50f9c67,
                0x58f1503ad765979883692dcff55252,
                0xf613ad8641b9195cb742ac5d3ff778,
                0xad,
            ],
            [
                0xf6192bd60ea644724f16e4aada15a0,
                0x4358fb630320fa47a515a0c184116e,
                0xce26089e290f3eb990e0d22ba5326c,
                0xd44cfa962eb16affd529b9e8594a0f,
                0x4d1251d3a5dce3d31a8b610dc89e0d,
                0x78ecf023cd8367e59d05abe6fb3e13,
                0x3500205a22bb765d8027cd2a590d5a,
                0x89eb7a8a0b8089f9a7fd1c80d1032f,
                0x67e04a55bf64ddec2fb637ad50fb7a,
                0x7d955057b448f7c64e635751e50076,
                0x61f572b8f4296cd38fe2cb290eb785,
                0x293f79b1fcdfaa099f4860d4673ac5,
                0x6e96fb02ecdb19c946a9d9e3df05a4,
                0xb8776b8e4f5a93c68c82c56c8ee5d0,
                0xf185463bf419ad644ad833f475d1d0,
                0xe153115efce422bc7924d35f1cb47f,
                0x91095f3ff0315e6fc2b774f1d7537f,
                0x5e2e,
            ],
        );

        let signature: RBN2048 = RuntimeBigNum {
            params,
            limbs: [
                0x98156ae7cbad0e0fbaa9b254c445cf,
                0x6f3ea82d1faf48ecb60f3f7481f020,
                0xea0f2df747bbe8a8629c9dc6246da7,
                0xb635b9de66aa7e600e924c0932b43b,
                0xa010df8938db4c035c8473f0fd167d,
                0xe37d1709aae17c76199c99efa5e5a7,
                0xf8336b32c807dfb62d149fb8353f4e,
                0xf852a4cc6a84981cd8a0d9eef5510f,
                0x10c5cae74e75c83e3835906e5eea2a,
                0xd83e21dc7e49277c86d81144837750,
                0x72e367e8e2db3320145626438e6e93,
                0x2129c9c0c2ce89e77661a15c8c7647,
                0xe9c0b584a2ed003dbe4cadd2cfd87f,
                0x6e5bd7521c235ab9e18356d089863a,
                0x28e861ed03b6acc39fa7af5c068fa7,
                0x4d1a681de2ce54f0d19eb736723af8,
                0x2042cf79eb42702aab8526c68a64fd,
                0x90,
            ],
        };
        assert(verify_sha256_pkcs1v15(sha256_hash, signature, 38129));
    }

    #[test]
    fn test_verify_sha256_pkcs1v15_2048_exponent_107903() {
        let sha256_hash: [u8; 32] =
            sha256::sha256_var("Hello World! This is Noir-RSA".as_bytes(), 29);

        let params: Params2048 = BigNumParams::new(
            false,
            [
                0xf2bc2f4fd3637bb9ccc7e163324dbf,
                0x88ac5e7a9abee89a393533168e8743,
                0xa9d1ef7f5677329e23336052001928,
                0x2fa85860b512fed4ecc0c94388e4dc,
                0x61b27bbdb48fd8dcf155a1d3242029,
                0x8119d20bb357bee95c9e6038448ea2,
                0x4e8759208ccbfc555d32e3fa487af4,
                0x7608d025ac5a266c1e795b7dc0840b,
                0xd9df24711a6d2fed0d9248057cf278,
                0xfbcd7907dc0dacc66a855324c5ae85,
                0xcf3eca7c8405dfaf7ce39c1b1e526d,
                0xf2c0a24eb8fd5b2b49eb261b01e5cb,
                0xb7be784d951012ec79c8df7bb35e10,
                0x2f7a97fe187189f04fead5f1b00850,
                0x8246d382cd0821b066e801665eb949,
                0xbca14eae9a7d4b426639eb99d15c3e,
                0xfd0f6549b224f1be363e496501a0d8,
                0xd0,
            ],
            [
                0x9bacaa9aa845072b32401312aabf2e,
                0xe60f7694ff31d5232b141c262344a1,
                0xa52e3335ef0df271b01d3b27710638,
                0x5f5bb2541353c0960e69d93320335a,
                0x6a676961b755cf1e42b42c33d0123d,
                0x131d0c80819dc8c94e7422e03134d,
                0xce3dd4246bc6272c74892f4df18924,
                0xb9aa26f8938dad7dfc79f0e3eb9ee8,
                0x519210f72dab7de695dd76d8691873,
                0x8103a14dbf3e95e798163fa3f8bebc,
                0x24ecaec1375ddd1296b711b64194b1,
                0xbd25a65a21a03cafb580eaee26fcc5,
                0x761bf6c40d779c08f6e2057fa9e7bf,
                0xdb92c2b2954c757036a51c26e85e91,
                0x90c9e80cc829a60a98180eaf26072c,
                0x75500cbda65dc906cd5aaf1164221e,
                0x8afe5c1e6967a7398c83691e623a65,
                0x4e65,
            ],
        );

        let signature: RBN2048 = RuntimeBigNum {
            params,
            limbs: [
                0x4b2f40b350af5cf9b4cd5e4a48484b,
                0x2d45da942f02e9c1ca4d0b5c8891eb,
                0x95e181ee7a25546bb5f06881ed06ab,
                0x96daf6f89a37583781ac3cadc3b474,
                0xca3d251f57ab831e38da4a72febd6b,
                0xd331a8762354c7a21a205bd00a56e4,
                0x30e1612ca0c22b20df7e3b13ce20ab,
                0x0e44e8752d7f365a5be65666a695c7,
                0x2f9371a16fac95bdbe2bdd29fe3660,
                0xb5aa14bd29c9cead7fe248cc8d8fef,
                0x5152b5458eac4871b2dad8ae6f82a9,
                0xb440d47429dfc47c83afa416a4f6e2,
                0x6c71eb1897abe36235364ea0257868,
                0xd2d51b57e037b494d663d8238f7ee5,
                0xcc7fdf728797297df1292e63fd6e3c,
                0x4eaf8992cf23b65390e2dfa7b012d7,
                0xe84bdde98147a17f3a9297786a9b84,
                0xaa,
            ],
        };
        assert(verify_sha256_pkcs1v15(sha256_hash, signature, 107903));
    }

    #[test]
    fn smoke_test() {
        // Output of `cargo run -- --msg "hello world"` in the `signature_gen` directory
        // Create runtime params:
        let modulus_limbs = [
            0x65af46d235241cf0e8fbe8cff4abb7,
            0xeead39ba3f377ddd5ccb2ef2085190,
            0xe483f94c0a98e8b618d92fb926f596,
            0x1fa8c1b2c62cca6db090cd74a29db2,
            0xc38e22042fcb74585a7e535301f50f,
            0xcbc4378e5212752743ae78a75a44a9,
            0xf5acc41788d9a346a0f75630a8b2b6,
            0xf7a741bb3ecf1aadd5a327f362abd8,
            0x4d5f24e815db43a1b2cc2ba40f8715,
            0xe501f1a01305cb198475a4bff0da2e,
            0xd541b78cfbc2b314083c340840c82c,
            0xa0ab069c26b2a0458f4c642bf72526,
            0x2ccb676d8f22517116fee0d2340533,
            0x7cf2a7cf772025c0a83747bbc18228,
            0xf9475f17988a56f17b3bdf88dc72dc,
            0x4ff228bee24415fae7a7c05771e830,
            0x55acd96b485515c38906106cf0d189,
            0xb9,
        ];
        let redc_limbs = [
            0x5cb23c55bc082b6234c3e8ee91fc0f,
            0x5d0290e99f2e69ef86b0508b5dc918,
            0xb659ef87b7cda60d0c5f81215b9644,
            0x9767e83797f6ad66301366945455a8,
            0x19e469987a9d8876df9b13b123d199,
            0x92869f01b4fa282f2f15031abd9e23,
            0x72bffac527d6fd91b2a8035cd55c56,
            0xdd51c58c2a743fbed72d8799a64687,
            0x5f010683f0c3f7fcf57b45a65f680a,
            0xfef9f485da52c9a787b4de0670bc5e,
            0x6d13ff0c6014c78aae2f7de1228ea6,
            0x7c012bc444cb2da2ed56663b5d85a8,
            0x6c576eee5b3a03d1e5c92ef5da2832,
            0x66e8506424eb9bb4964bfecc19619c,
            0x8d6da6bfe8eecfd1c4fcc57942d611,
            0x2a1cc843e0e9b783632ee05abcf8de,
            0xf93f9f3e636a1fb21d8e00c1e5fa48,
            0x5866,
        ];

        let signature_limbs = [
            0x2f397c4611d4a4271453e1e50e1578,
            0xe506a7f47c721a4943783e8ad459e6,
            0x6cc4ae1d91cb381cba9673470999fb,
            0x1e127364d07f94e58227f50fbf5687,
            0xf64a2579c7189f882d68832d16faa4,
            0x3b014b74c6c6f76f2f8af170fa0fe4,
            0x7df41e68c86815a6fdc33968c66b67,
            0x6a57ac06282527242fddb6ed08dbdc,
            0xac40d37b819c4b6193f90a634e4fc7,
            0x96606ed166a7f032d858cd40ac73a5,
            0x8eb7d4351159a46733f92610d5c597,
            0xc8e8e9faa9738e82dbe774a3f5cf07,
            0x89ca84fd54ee3d5cca87c9f178375e,
            0xdb7a1465fc76507ea498a351af70dd,
            0x6ac6fe14f51c711f983125c776f712,
            0x3254c17fef51bf4194a8a1674634e3,
            0xee38c83c77c6e1ff7b70a5d9d1dd0f,
            0x26,
        ];

        let hash: [u8; 32] = [
            0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d,
            0xab, 0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac,
            0xe2, 0xef, 0xcd, 0xe9,
        ];

        let has_multiplicative_inverse = false;
        let params: BigNumParams<18, 2048> =
            BigNumParams::new(has_multiplicative_inverse, modulus_limbs, redc_limbs);

        let signature: RBN2048 = RBN2048::from_array(params, signature_limbs);

        assert(verify_sha256_pkcs1v15(hash, signature, 65537));
    }

    #[test]
    fn test_verify_sha384_pkcs1v15_2048() {
        let sha384_hash: [u8; 48] = sha384::sha384_var(BoundedVec::from_parts(
            "Hello World! This is Noir-RSA".as_bytes(),
            29,
        ));

        let params: Params2048 = BigNumParams::new(
            false,
            [
                0x1dccbc1b553aef560cd665aa2ca411,
                0xdf1b70d8f0ff39013065a5a886490f,
                0xc3952220c2f6ba45b86fd1842f6db5,
                0x13403323f2e86127e7d30ca5c3741f,
                0xdd9593e1b80868ee660cff6aed224d,
                0xa768ff67951f621cf220c3f11fb7d0,
                0x827a30c8fc6da6d9e0002ccbab7354,
                0xd4f4b3326c1822490ba84bf7d8f2ff,
                0xbc1aed9983525cf9795c5ee886efbe,
                0x95eca388e0ef68d9e1b51bfdb3f38b,
                0x5f250161202b7d91724180734cd057,
                0x5f6a6e4b2adf9db128af321e90bc61,
                0x2b395ebbeaaf0c6c40a8e7ab2f041b,
                0x8fea1754c39077bbc232d8380c4eac,
                0xa113212c3d6ba516cdf08b1c0c0cae,
                0x9ba6c1d51332cd846f88cfe28dabb,
                0x57a8d8bfcb8839f3ef85c7ee2dc2e0,
                0xb4,
            ],
            [
                0xae64f790c98c8b1f4b9e5e6dc1594c,
                0x75847c62aa0c217bce14ccfb11530f,
                0xde8efb9cc54f6b895dde07a690d6c0,
                0xb9666f2765929d271cd9cec15670b2,
                0xd706b6ef2ffa183dc86a9e83f0fc4f,
                0xa30a33fdcf5aadda7fc1fddc918188,
                0x9898fbfb183b5f4e57d21a82a5acb6,
                0x9b6a1b8f0eaf5efb10adbeae249efe,
                0x1689f625399f8c42f11241d8b94f76,
                0xa8a70f190c2216b9eda344e67750bb,
                0x2d6a08a2090441f7300b93413303f7,
                0xe76f90a4d70844644fc164ccd1aee0,
                0x20bd7b281382daac9f36f157b473db,
                0xf1b4f80564fa74724e649168c1b337,
                0xd76a788f952deb3953f053a6e3fa26,
                0x21eaaf7dd1b8684aa1e4b3deb1747,
                0x72096cb20d4d56374dc755ec74c6bf,
                0x5ad9,
            ],
        );

        let signature: RBN2048 = RuntimeBigNum {
            params,
            limbs: [
                0x0d643395f61610f78e0965ff28b34a,
                0x991a18b16cd776f8ba0dc7d3a2c0ac,
                0x59ad92fdc6573338573a5ec3a8ac1f,
                0x39fa3c545c220904560f89449e0cb6,
                0x77c0492bb5f8faeab6484258164fef,
                0x32f66a824fc81c4bc3a10228c9d875,
                0xaf5a933d03c5c769af3e1c43112418,
                0xe4b3c71e29d230dbcd784dfd344cc6,
                0x08f5fd6f3b0782eaae154fe56fbe0f,
                0x9b785970ee35b2cd656cd9f098565c,
                0xc6c649021334fff3d4ba072255eb0e,
                0x1fb7d5c84e2fc4e975ea5793a92fc9,
                0xcbb718f2f6c780b4f6e3a17575b89f,
                0x04f7eb7174814ff492727916397bb8,
                0x77790f451d53ce4d4229791f142d38,
                0xd9ab6403501d48c29b3abbad760d43,
                0x20d90ee7975dcbd1761fa7f6487391,
                0x17,
            ],
        };
        assert(verify_sha384_pkcs1v15(sha384_hash, signature, 65537));
    }

    #[test]
    fn test_verify_sha512_pkcs1v15_2048() {
        let sha512_hash: [u8; 64] = sha512::sha512_var(BoundedVec::from_parts(
            "Hello World! This is Noir-RSA".as_bytes(),
            29,
        ));

        let params: Params2048 = BigNumParams::new(
            false,
            [
                0x56acc9475dd0568166f6d519d2b123,
                0x4388e4291f2a16d58441e4c966d869,
                0x3b6cbbf6524f2e12e274d96a598cf3,
                0xcb7b28845e13e53fc8827fadcbf5c2,
                0xc2f20ecad4360634ca81a3f2700df9,
                0x71b5ed85f3cc58e9820fa9cdabf2b4,
                0x8e15d0237c7dbee5369ccbf8f6e25e,
                0x280d4771bcddaebaa691b4870d4a92,
                0x3f8ab4c278a35f45149814c95c1c6a,
                0x4b88bb3a4f16adaa8a9ffa781086ad,
                0xb4e8dad6bc3fd7d666683e872832e1,
                0x3135b2958becadcb9e25ec25e55b23,
                0x405ef523d210399f9def6302a36221,
                0xb9aaf3a3c5b2e3f4f86393bde7b852,
                0x5f66a3d278b5759b92269481eb94ca,
                0xb0ae491acfb3d0a8a46a92b7adffb7,
                0xa61f0e1720a3cc4594121de7aedf34,
                0xc0,
            ],
            [
                0x860620cf11a8b11e6452367c499366,
                0x244022f0cb45fcc713ca2d4f3cee6a,
                0xfd44a5c6ac04952bdc47cde0dc9e6c,
                0x13e6381c976f1f54bee8bd75520b56,
                0x3018d0ed65c5b100b4ceb834573a6c,
                0x5b88d81e7b00e28840a6ae93fdffec,
                0xdba4713ba21c2c74701adce803c3e6,
                0x1406350e50a0e4c2ad9331006ce025,
                0x22d3cfe18ec06c3f888e08bc58d54b,
                0xaa53b1a98dc2154ab02adaa093ce03,
                0xf3d1f475cac20a13e7013899696f1,
                0xa7618f1a083cbb0734d77a4c9ec54f,
                0x1660fb00b3ff619a0079e42efe9f4a,
                0x7ba27df263b382abd0542db16daafa,
                0xc957bcc6653cf2d2dcc742efddb15d,
                0xeae8b94dfa400fd11f18854f0f735d,
                0xc015c9b6e0df9833fc3faab234c9b4,
                0x550b,
            ],
        );

        let signature: RBN2048 = RuntimeBigNum {
            params,
            limbs: [
                0x8c1ac22b4f25479bd4d63adc5647a5,
                0xc226d235d17e3ce2d6303804edd317,
                0x75992147cd0883367aac32c28927e2,
                0x7f131d0a5dc76ac9a3982bc3430a66,
                0x1e5c5471a794bede59e42c5125df77,
                0x7d4d8bffa69b08eb5a9338c96eb042,
                0x44bc5745bdb2ed1944e61939c9b325,
                0xa9c536593f93201b1493257bfceedb,
                0x9f00b9f27e424f9724c1486fb54314,
                0xeae7e1250521e254ee2d31f94002f9,
                0x9ee4db7dbe46139670393a1250fa79,
                0x014039fcd5bcfa3db273bf7188b3ce,
                0x4967a88c2ddaf359c3c813cfa3ccc6,
                0x9c3f74383a8c3326b47401d5815c45,
                0x2f666d5fbe8464dcfaf569bffa0248,
                0xfeccacb7e9e0e44320651e58344e8e,
                0x8942c708df7e40a175d44fee7cf5ec,
                0x4c,
            ],
        };
        assert(verify_sha512_pkcs1v15(sha512_hash, signature, 65537));
    }

    #[test]
    fn test_mgf1_sha256() {
        let seed: [u8; 32] = sha256::sha256_var("Hello World! This is Noir-RSA".as_bytes(), 29);
        let expected_mask: [u8; 32] = [
            106, 93, 232, 46, 236, 203, 51, 228, 103, 104, 145, 29, 197, 74, 26, 194, 135, 200, 40,
            232, 179, 172, 220, 135, 51, 185, 209, 35, 194, 131, 176, 190,
        ];
        let mask: [u8; 32] = mgf1_sha256(seed);
        assert(mask == expected_mask);
    }

    #[test]
    fn test_verify_sha256_pss_2048() {
        let sha256_hash: [u8; 32] =
            sha256::sha256_var("Hello World! This is Noir-RSA".as_bytes(), 29);
        let params: Params2048 = BigNumParams::new(
            false,
            [
                0xb2cae9b4d726643aef459696fb80d7,
                0x46585d789783e6f0ea6a4a17001b8e,
                0xfdf7476659c117564ca991f3d635f4,
                0x9bb5835a63f78d2ff06927d5f5a64d,
                0x18ce92c21c9a7dad5ed41c66790811,
                0x38003b2699273864cc87b363714855,
                0x7c19d41f8dbe41e03505fe1e061a5a,
                0xd63a7a6d91625495e46db9161b0d7c,
                0x3dffb1f7121946f6e04dc642a85da9,
                0x389eabe29dbf38c1be95c9b9c0c029,
                0x77a14dc6452603a154cc463e4c2a3a,
                0x68eaeef1963fa3866c934d1225ac67,
                0x3a66b9b64048ed95cec6bbe4235189,
                0x113fd1c23822a8dd63e7d97b034eeb,
                0x28b7376afc6109602ed94eb40284f6,
                0x4d331f4da82c798979e7d9d2c5f7bf,
                0x716d8b401bea115cf1265f976aaccf,
                0xaf,
            ],
            [
                0xe67a936b1d351d5e9e8a55ad6c124d,
                0x553102694f3a35c3cd6f842e534a10,
                0xb934cc00cb54a99799bd53e78247d2,
                0xd48adb2a502ff144cee3f5df292f23,
                0xd2170b1ab2536010716815b69e52d,
                0x9192493ce8a2ac8f17fe8124f777b9,
                0x3f8fc6f1a8278440eb2ed4eb2fdbc6,
                0x791d65e427a1b05a2d5d2330227386,
                0x21adad378aa9e1b851343bd555b0c1,
                0xd16a76764fef83357cb77288c59923,
                0x7b6ac8ca2c2d8e501fe71dce81b173,
                0xd87538a1f031aa5a7d77b3f40dba95,
                0x51e193d1f92734383b0d3c482e8292,
                0xfaaa53de66c9dbbda9e43ad85c8b53,
                0x7063684d060473b9779bddbb468618,
                0x7bc190769f2b03116e9d350d56fbe9,
                0xec116198c3a4ba97b3a3976d172ba9,
                0x5d62,
            ],
        );
        let signature: RBN2048 = RuntimeBigNum {
            params,
            limbs: [
                0x6d3125fde00a57fb5971460c38a826,
                0xba2092dd58c4de8ffff2bf13f5ef57,
                0xf0ad4ed46727881e7e7f6a103d7713,
                0x7e8b2203a7a6e3a3a30219d6edf8a2,
                0x9b0b861dd1cb2751f30d54d07ad167,
                0x4373e863b15edba97439182a6a9043,
                0x61621211db5f34a0786d5ef38cd90c,
                0x63001609f7dffdc70761c67617b580,
                0x8b2b817a0508e4be6f2c50df23962d,
                0x6d6f9396978782a90fe06ca78c4f88,
                0xc567a9fe5f7175225384d7c1e4c991,
                0x38926dfee8636b9e36728c1cf51198,
                0x0eb84e90f89a0bd21536a537618b92,
                0x23dbdcda1fee2b57c8dc2e605777b7,
                0x6acac69b2fc1c12c204e790034a01e,
                0xee44b77264385863ccef2e133241cd,
                0xe9c67049c219997cc8c43b0b1f420b,
                0x78,
            ],
        };
        assert(verify_sha256_pss(sha256_hash, signature, 65537, 32));
    }

    #[test]
    fn test_verify_sha384_pss_2048() {
        let sha384_hash: [u8; 48] = sha384::sha384_var(BoundedVec::from_parts(
            "Hello World! This is Noir-RSA".as_bytes(),
            29,
        ));
        let params: Params2048 = BigNumParams::new(
            false,
            [
                0xc3034c17b5578d9c029b22158a8e45,
                0xa84c80b43a68c9eb7cde67f1f60e07,
                0xa8d82a4aef2cd733a9fdf43439ffbb,
                0xa1b9aae31832c2815b81f0db70962e,
                0xcfcbc51338d691443e702bd18354a7,
                0xaa2c5f465a247efc9d97fb052579b8,
                0x571f3c233fa322a933a4cfc0c4b213,
                0x3280f1f7238a3416c5e1140077537a,
                0x8685f03e3076c1bb62550cb363ae08,
                0x55ebdcb84073ad2dfd3553c5e2d21a,
                0x1e5a0a662b44f5250377abcd1069e6,
                0x178357493184215e38603004f6c9f3,
                0x75cb8889b33c6b78bab0a378453376,
                0x4f5f7baa56492d5ac52c1bf7b998b,
                0x16cf48a7c416bbf67657a263376e22,
                0x1d8ab41c7021ebcb15da705dab5343,
                0xc5e43d48377059df0aa5d7e5441586,
                0xc7,
            ],
            [
                0xc8694aa1f2a0898fa5bf5b4afcd05e,
                0xd2ff5d0abdc00837c07db2ba581e4d,
                0x4247b72b504736ff0952eecaaca419,
                0x7468a546a39437a7242e00f0f524c4,
                0x41ab45d8341ad49c233303b67f98a6,
                0x46e5899941698948fe73e84406a721,
                0xf9490ec3cc3b824310607867d17c68,
                0x8a95bb6bb23e7f84b5341f5c964c7a,
                0x41c8ede03dfbc60e4c0c73b53c5226,
                0x7bdf63716d59f6c2c6996dd15897c9,
                0xe7cded7bfaa6a4c0a75f577689af08,
                0xd6491f3fd55c32e41d6b83a2d73fbb,
                0xecb9b002d3383fbb7103cd8cf4d539,
                0x24146b53e44b9e95d4f98536248c83,
                0xf3de3614bd7ddaf099ec3af3c4f0e7,
                0xecf2cb7c98668c083c82037555595c,
                0x5927980c9617d08942b1b254447025,
                0x5203,
            ],
        );
        let signature: RBN2048 = RuntimeBigNum {
            params,
            limbs: [
                0x06d24f9dbd859780c7684e7733ebb1,
                0x3acb7e4bd7c9f42a5f9649e1fef5c4,
                0x67878f2493de5cb48ae107df08dbf1,
                0xf268bc940d64e42b8719216fef188e,
                0x2c4701120db41532e6d195ba1f8faa,
                0x03d3b537eefd6f0c99fbb7c1f359d9,
                0x35b732ca45b03bb17b1f3564f18464,
                0x468584d7dac0a4ba51032e2a5f95e2,
                0xe10042eb30d1662517aed3b89e1154,
                0x0e5743acb366c6251627e64f751256,
                0xb06e6af3e06ed5c656e66aa0295f63,
                0x67378aabfe17e33e305825eb4f6c5a,
                0x8cd4c7aa81b660325dba4b0d899a9c,
                0x40c83a9c74f99c026aa845fa222b69,
                0xd52f8e19032a33a1d9a01063fff8f9,
                0x7dc36972054edf46bbfe918711e693,
                0xb035fca3baf4329ff5d588baf7b034,
                0x1c,
            ],
        };

        assert(verify_sha384_pss(sha384_hash, signature, 65537, 48));
    }

    #[test]
    fn test_verify_sha512_pss_2048() {
        let sha512_hash: [u8; 64] = sha512::sha512_var(BoundedVec::from_parts(
            "Hello World! This is Noir-RSA".as_bytes(),
            29,
        ));
        let params: Params2048 = BigNumParams::new(
            false,
            [
                0x928a173c3947c058b084e258b8a4c1,
                0x5f1179c22cfacb440464695cfa393e,
                0xc409e532b3077ce4d90e66e913f125,
                0x29e8696374f86380ff45d0f29a98d5,
                0xf931d155d89d3753ee931433a8e2fd,
                0xfc3d1c2a999f0112f5c5416c2e0428,
                0x4d21692b210bec2ab8e1b52fe78e66,
                0x9df364fad350d314b146e84f114203,
                0x8511a74031596831dda8ac9d18dcf7,
                0xab5f9ad71b33284aae738988284229,
                0x3332aa31681f69a5f470caadad7469,
                0xf1fcad281e0fea144e1f4208d38e38,
                0xe83d3b0afb20bc39814ea22df000ef,
                0x3d9244664808f54fc4f0702adc9399,
                0xc087b5dc693953e6371b9c7c175a21,
                0xd5910d0d4232e8f92148482a72baec,
                0x44e57b58ec4e75250116ce2f1abf3b,
                0xd2,
            ],
            [
                0xd2cfd3241c49698541526e2d68e1fa,
                0x70bb32660757f09fd69a9ed3c8dd59,
                0x5fb8653b112d29137c662027e359ce,
                0xffea687b1f66a6e45786af1d7124fd,
                0x78ce565b09f264c4d69fb84cb3ddd1,
                0xf6de225474dddebba9abfb85c6d5a7,
                0x376a4c49a5c09c3b50ab9817a6093f,
                0xfe9b81ed10a7c3ba0dc3262154fb8e,
                0x9b65790fb47865828c5bbafdacec2c,
                0xf4556e409745bb36f6b1cdc9766a24,
                0xbd691c41fb00ec17d6843ee93e877f,
                0x86914a171770cd55d05c4f5b5c6890,
                0x1913c7d1b3b3600f94c444368ef57d,
                0xbe62755b1504afb99662bc960a5c8e,
                0x4bde09fdebb914fe70fae5d4fef92e,
                0x7ce35bd7c68ffc350318075e676ec1,
                0x5006f45883f7481904ea25df798dd6,
                0x4deb,
            ],
        );
        let signature: RBN2048 = RuntimeBigNum {
            params,
            limbs: [
                0x2058f7115f339e55a93f8dcefe81b9,
                0x38a20cdbfc439a1fea423c119f2879,
                0x7ac4e03a5fa662754e6e21a78984d4,
                0x69d714829d29b235d588476152b5af,
                0xce3db2102990c27bb66bc32da8dec4,
                0xb4914f6f0e73718b5f1e422fac6ddf,
                0x7d812b554c81ccb7932d1e78c6e002,
                0x438fe60d9e0912328374513ab91b69,
                0x56abaf2b8d9a6dcb9201586d2f0d0a,
                0x4151c524481066bd81b4cd17829481,
                0x7c63b445e245d09ca91057032ad22b,
                0x9f242d5a655035a028a68d337ae40d,
                0xb5f91b99b495862044bc7122913806,
                0xc123aa56dff5b23d7d8ad097748efb,
                0x6892e3a32a7b6963d97b3bdd81b91d,
                0xcd7aa9e3e77f68f0ed195bff92a162,
                0x583a32fd5a399f3acd867dd7d6a1b6,
                0x7f,
            ],
        };

        assert(verify_sha512_pss(sha512_hash, signature, 65537, 64));
    }

    #[test]
    fn test_verify_sha256_pss_4096() {
        let sha256_hash: [u8; 32] =
            sha256::sha256_var("Hello World! This is Noir-RSA".as_bytes(), 29);
        let params: Params4096 = BigNumParams::new(
            false,
            [
                0xd78653b3d43a72784415fc0537129b,
                0xc725d4fb19419a03b58e0fb5ea4ad2,
                0x1d866cfc050224a0eb317e835ee283,
                0xd298018e86d3225a264a449c63d69d,
                0x824db5365a077bf704acd2446baa7f,
                0x5c419e562b5b5ccb0dcb151a3f48c9,
                0x198a6627edcbc2afce1893217c2e25,
                0x29a693a0bb3f6f02d80e660f681d6d,
                0x5656562a9622f87bfb969db2542f63,
                0xb9408b08a3ee3b25b6dc6ae12899ef,
                0x4ce9b767219e1e0593782ce46a041f,
                0xc5a4f318b34ff79121677f283ceea1,
                0xbd5e62c599453a94e0bf5f48c6b58a,
                0x6ce23c4978ae07af4c46ea9b9964ad,
                0x68d4db6209ac89538e6d986cb77459,
                0xf2ada72cff01696e2efdf123ab60f3,
                0xf951c3c1965c355f460fa815587ed2,
                0x6063ac0275e6592b878d5a66e68501,
                0x594eb3db288ad091bc1db2b2a90101,
                0xb72899c91edcdf890053f87d5b1dab,
                0xdfd45eab0c435e275202bff1e22f5d,
                0x3da05e1d0d3cd0012e6c40e1878ab7,
                0x4fe053feaf486a27dd119cbee9ce1e,
                0xa3781b036bd3a3411c2af8377ad0d9,
                0xdf4410ba8397cbe580fc5eca7d230d,
                0xdc34151036d459fc3c21d8ba0702fc,
                0x4ea71eb1b0b1a2f36741b61e8765d8,
                0x22cb66b4eb0b34b34320402ef652dd,
                0xd19167b88620fc6b60709fd39cd48b,
                0x524e4fbe4d75e4817de075ac70c72f,
                0xd0de26679602cd331c3e5534ce668a,
                0xf5aa120ff51d4bd3d57c1d68359f95,
                0xaa06f0791b623cddd53d787035bd66,
                0x122e014d565fa26417a5ed0f786fbb,
                0xb95e,
            ],
            [
                0x130efdb324cd712edc667e7ad1e975,
                0xef2f9ed6cf3eda5f1addff86a819bf,
                0xfa4daed45b1837b1b9ef7a42950159,
                0xe2a4bb6faa59e8dc3724a2cbd32d4c,
                0x677c25de54b509e39ad31e4acc70e5,
                0xf6253afb61c0ac5631e9477fd40ae2,
                0xb6a4fcdfaaeb76395753d142fd2299,
                0xed66b2eb40ce15af8e22fd66dcf129,
                0x191374cb71dcf9784b80ce036ffc07,
                0x7fd67a2bbedeb3206f78c3dec8a242,
                0x2991b0fdaa6206551fab99dfa659e7,
                0x31ddf5f68162de83622dfb21100298,
                0x1ae942df31342bafe289747ab283b0,
                0xbcb322eaf779d68c621cae54a217eb,
                0xbf246ab7233889fa40e723cc523671,
                0x9ddcfe01088753d6328ef44654af1d,
                0x3d6882bff168266b496aed6e731889,
                0xd82a4423acdb201a3a4f949308d44b,
                0x2d9ebe1d85f736538e298a9ca5d9cf,
                0x958d0fe38600ba3010ec9887d6c236,
                0x60b2386a34f91639e5e69df35d9091,
                0x4afde0f1e1ef8d02f59bee281f475f,
                0x25345b8ba920da7d5eaf296426e073,
                0xbfd10950ad3a412b4f288341bb847f,
                0x87e88159589f75fae5ad009ed9c53c,
                0x4ea0b52137d260f6d7eb75ee4c122a,
                0x17d3a64ec2742ae06e0c4af027c1a7,
                0x344d69b6a988ee41bed8b1b8a3a784,
                0x696af95957d8a828343651e6b9d9d7,
                0x33ea26b6e822e491c97250295ab678,
                0x808ec74c24dbae7b952fde2409b888,
                0x27a47c46a89a7ce0448994f1c13355,
                0x845ba5db5649cdf8315f70489a7bf0,
                0x3a228c80a826f7aa8f6da6be629944,
                0x5862f8,
            ],
        );
        let signature: RBN4096 = RuntimeBigNum {
            params,
            limbs: [
                0x5d9212d0c25acc14b61c6ce61a844e,
                0x9d369ae765eb0545f83f552b8d7bb6,
                0x5f0f5d383bd70d7726a851c422fe29,
                0xcff5886575636efcde5d9843e59a10,
                0x5820fa1e3158154641adb2c28a8954,
                0x03ce0301512be13c0317fb679e6348,
                0x13ec0af966303ca69b6f7fece6c2f4,
                0x58dcc592b80e4756a8d01224e6174f,
                0x73610ba199750de1e35cd658cbae92,
                0xeb1d49f1ecc3bf332b4048d978a46a,
                0x8c9ad13691accdce88ce1e6fda0bf5,
                0x425e80441351444e751cd86b97b464,
                0xd25a9581921c44fba102ed92a75658,
                0x698c73a7fc85fee22b1c7f04fb4600,
                0x70267fc50db236dfcf1e9405e25856,
                0x1a35b94cf56f801be96defed712afe,
                0xa3ecae6965b3bdee416f8d506f64fd,
                0xc875faf0fb4e4fa47ff65aba633529,
                0x3ca01bcaf3c4a5eee7fa8fdf0e98,
                0xa666b5d8c9f3217c412610ae91c862,
                0x517ccc77102fa7799e521ef0e6d4e7,
                0x7a50f7e553db75f0e0bd18d43bd622,
                0x98e8da14444b6cf3d2b91d84da3506,
                0xd1f5e4f7a725babc988cc7822c3d0a,
                0x09ee2caa2e6f8b02db37ebe2352624,
                0xd500b790312328a681b89b5de51b4f,
                0x5ce0ebb445d4c82c3ecf21134c00bf,
                0x83b6fafae79bc59f07e9b6802ef018,
                0x8efd78556c637f8af6299ace0cd790,
                0x5e99cf54d0f7e491cd72bcf20701fe,
                0x19f15da137fe1bbe44c5531300829a,
                0x0aae159f54317b49ec6b083292f57e,
                0x37c2bba2237a59a35556f2d351c728,
                0x7ec51821f03bde0c862e19e6ebe62c,
                0x2081,
            ],
        };

        assert(verify_sha256_pss(sha256_hash, signature, 65537, 32));
    }

    #[test]
    fn test_verify_sha256_pss_2048_exponent_3() {
        let sha256_hash: [u8; 32] =
            sha256::sha256_var("Hello World! This is Noir-RSA".as_bytes(), 29);
        let params: Params2048 = BigNumParams::new(
            false,
            [
                0x1c961b234309c24fdab3f3e8a09da1,
                0xf4aa851a30a198c359f3779b6bf4e0,
                0x844034a1488c79edf31b1711a5e547,
                0xc83ad2f9b30cfcb6d5f7c152a78e62,
                0x16e97e0f8d8bad08da76d859c575c6,
                0x6a85158069b211820a596359d0dc47,
                0x1b834ed69818f1aa7d9944dee07b20,
                0x4d7148da361f1881cd4fd396ef46d2,
                0xc4cf36bbfa2781703699abf19a1e6d,
                0xca4bd632c8eb2c8051915c3530aef9,
                0x9cbfd5681aa95ade8eb256925d60ea,
                0x3b8153585ff5f1d7b1ed37ac709dc6,
                0x7d741c118fd653af3c21848f789ed8,
                0x7aefa65093c124e46405849ca82ad1,
                0xf9dbb9414e8eb849e2532d3f55d0b9,
                0x35aeee862ac76c20be58527220f6a,
                0xa3b6f81f07963c34ff0168634f8a99,
                0xc4,
            ],
            [
                0xbe38b5d269659ae63fe843a81c7505,
                0xdc12c3be2b9c78fc69f49361c555a,
                0xa40ef90a16716f572ee4d74425fee,
                0x6f713878999c3b5cd6038b23051306,
                0x3945e3fdc067129b0289d0eacbeb85,
                0xf66e9cd953b3c8082f7e9bb6771ddf,
                0x6ea578f9d547b898693c43b28d7c17,
                0x7826dc49d3977c4381a9b398c670fe,
                0xc51e07beb646f82223d4541dc7ba96,
                0x574bd2435ae8f3c96b64797894e6c2,
                0xe21eb28f7c865336fb64139b50a5dc,
                0xde5fc8600a814b047970816f2df485,
                0x53456cd7abd1b8bf9a7cad8300a48a,
                0xce053c7458041e8ffc4206c3347faa,
                0xa930c6d860e7106602a2ee7248a831,
                0x48f327c2b421d1d4a45c68b8a1bada,
                0xea2d963f93a6d1237afc8763a83300,
                0x5351,
            ],
        );
        let signature: RBN2048 = RuntimeBigNum {
            params,
            limbs: [
                0x091a8c417287e046ec96c62b5ac66f,
                0xbe71db0fe3122ea5624e8e7a0a72dc,
                0xf35e5f3537c0ad0e938fdedd454de9,
                0xd53c652cc3aac5d11fe6f5bc7ec536,
                0x5d6869f0dd8b00697743f956b9b112,
                0x5d46286274a1128a8fe0d96e859837,
                0x951ee9dcb59dacebba972e9b9d7cfd,
                0xd22245a462bff840a882f6869689a5,
                0xcf7605b64a20dc2c3e6d5ceb88a03a,
                0x7831aa25052c11411c3e5bdbe7dc10,
                0x8e3bce799814987c984a2cc0e5d283,
                0x7fdb0ce6e413e0f32742f4652f14a2,
                0xa896a360bd70243209390e00761c57,
                0x0d326051ac677371678f92bd182f13,
                0xfcc593faaa9f45448ab756d70def,
                0x2fd6d46ec8d25a6648dadf8246daf0,
                0xe4aea2700222e610c1d94d82dd0f52,
                0x9b,
            ],
        };

        assert(verify_sha256_pss(sha256_hash, signature, 3, 32));
    }

    // Test an unusual key length that is not a multiple of 8
    /*#[test]
fn test_verify_sha256_pss_1964() {
    let sha256_hash: [u8; 32] = sha256::sha256_var("Hello World! This is Noir-RSA".as_bytes(), 29);
    let params: Params1964 = BigNumParams::new(
        false,
        [
            0x75ac0d9987aebebd25983ab5a48fdf,
            0xae0a5ffc69f51e789ea8f90a72745b,
            0x9b8c92fb6ea3ca021a894ae52025f1,
            0x50de84cce0d856376083aa1785fd38,
            0xa912e3aabd4191e143128ce89e2086,
            0xcf361d0e7f4fb458b950ca7f58414e,
            0xe27bbefff3820e512b05a07d2d7e1c,
            0x7a2fd42d837098a67f056f1b15ed33,
            0x4ebeddd5d6fde42dc68ba5bb2a3732,
            0x2d1cbcf87c37b430c33b04aa35ce2b,
            0x9e9cd702ef1e7191c78e712ac6e151,
            0x9aef318e4318c313c0cf0c71ba378b,
            0xc1cd2e631f327acf58dca9f4e63bfd,
            0xc828e43ce8acda48fa1fff12de4df4,
            0x2d91364c2a898031a0ea615c82fe50,
            0x3fed935e1e73af131b48aafef030d7,
            0xc278be706ab,
        ],
        [
            0x350d0ee9d50a1df6d2998f04b45673,
            0xdfcfaed7a69f91aaed7e97afafc1a0,
            0xbcaadb1caef7361efcf354d0fdc166,
            0x90dfaba583cab15c53de8d6e00d661,
            0xb806fbb0424112212164cd85758ada,
            0xe5426980135d977e89d4da223c9d5e,
            0x5f6f75563ea20c698ca1276ebb37eb,
            0x9f1009e88ebcbbcc251876c7e558a5,
            0xe228ade031e36a095a4bc73b14157b,
            0x4192b14fb0f1416e3a3896e4d4339c,
            0x4a6c4dd21da8eefe3a0f9748e735a7,
            0xc81b22fd28344595486481f7a646d1,
            0x7f844d41ded6dd834c6f6ff2d3da61,
            0x6c034744336db24703e4fd2c686321,
            0xca48932878f17bd0572c58a7e0b63,
            0xb3283ec30f94ab7f4596efe16cd3ae,
            0x543fb0213861f,
        ],
    );
    let signature: RBN1964 = RuntimeBigNum {
        params,
        limbs: [
            0xbd4bab3d5a9af46cac40fc2f6c9547,
            0xd3e04f0b8e833f1e80a4022684694f,
            0xbb4267e4fc29ec83dc8398dc547fca,
            0xba625b4fdf379883f6ccabede3574a,
            0xc9736193ab3cc0d1ef8ea63fdba46f,
            0x72dc058e8abcbe15ed09e97c1bb58a,
            0x98d8c915cb9447bcce3bbfc0f92032,
            0x9a0778461e9dec09e41c0ea354a41f,
            0xe4a6b80a5f62abf93268cde64b5e9c,
            0xd36dc0ccfdc6d9d8e8a939a3e762d0,
            0x1b2593bff17ff433ee20f1a60c6861,
            0x78115ebfd2484df0b59abfa3222e79,
            0x7693ac9aa8acfb4b5379c0adbcb7d1,
            0xd76979aa97b41f1f58c65ad896f1cf,
            0xe1f7c4fa2dc6cbe0162be9adb01c14,
            0x5f5a8f5b9ca6fe12c4fe3c00795f10,
            0x8b4a98cedd,
        ],
    };

    assert(verify_sha256_pss(sha256_hash, signature, 65537));
}*/

    // Test an edge case where the key length in bytes is greater than the encoded message length
    #[test]
    fn test_verify_sha256_pss_1025() {
        let sha256_hash: [u8; 32] =
            sha256::sha256_var("Hello World! This is Noir-RSA".as_bytes(), 29);
        let params: Params1025 = BigNumParams::new(
            false,
            [
                0xf278b138628000b2652c779e852235,
                0x6d0676977e76ef0429002673ce9be2,
                0x6cfc0db4d97f20ad2a1ad48cd899a0,
                0x64024c19a1b1540e23ba4531e677f2,
                0x3696125dd256ffed9567fccff06be6,
                0x2dc09476b0c7629eed3c7c2cb591e3,
                0x2e007f2f978504c5cfea0ec51ba0e9,
                0x84ec9458cc6d0e95e06a7f404f26b4,
                0x174fd186dca48668a,
            ],
            [
                0xeac2318fedbbbb98812f60534c4d2b,
                0x83547154701ba2b91c7310fa1344c5,
                0x7ab0faba08e31b0b0df07396fb101c,
                0x3fd858caf4ba9af077236800aa8315,
                0x707a144de15b129b7230941e2967,
                0x73a3b89232b04b2f0fea909ab3562e,
                0x9c8e12ee0c0aeede28dd9bf18717c1,
                0xba9c5b02995e4cee46cb5222ca73b3,
                0xafb47fe562d6306531,
            ],
        );

        let signature: RBN1025 = RuntimeBigNum {
            params,
            limbs: [
                0xa90e06eff7cbd20dd9c1241fe89290,
                0x9ff719ce8f34229cd248e1f0ef4246,
                0xd1d032dbf236cd711aa4fb49f0c71f,
                0x454abf136ae14c7617df3b4d505e08,
                0x45f30ac2c023205d35803f114f8ee3,
                0xc8b1265c786d6da808ab31d35795a1,
                0x1f75005a85f3636b099c58edd9fb8e,
                0xac251bf9bb342b551c0f5c80449a3f,
                0x03e2bc114292962b,
            ],
        };

        assert(verify_sha256_pss(sha256_hash, signature, 65537, 32));
    }

    #[test]
    fn test_verify_sha1_pkcs1v15_2048() {
        let sha1_hash: [u8; 20] = sha1::sha1_var(BoundedVec::from_parts(
            "Hello World! This is Noir-RSA".as_bytes(),
            29,
        ));

        let params: Params2048 = BigNumParams::new(
            false,
            [
                0x156ceaf444d8819f2aedf0ba175481,
                0xd3bf95380882ed1e760191e383dc84,
                0x8585e65def5c89b3b3aeab9ceb6c80,
                0xf215a93f61d5165db91d88a871368c,
                0x5274e088a95fb4053f26fcc5619e6d,
                0xf4494a491b66f30025ee633bed7a72,
                0x801bdf85598a082dbac2b26a4fbff9,
                0x9cd2905057dcca8c319d294785aa89,
                0xb155d5581ec0bfd4096e6878b3bc25,
                0xa0cfdf3decd16f8dde113e85a38c7b,
                0x9452a725f9f2f3e82ebef589345c23,
                0x1984df6bd68eaf0cc88b42b166ab6c,
                0xff925851486b26af0a896eae9c7fe9,
                0xe6fd92b72a2381389820a8ab283ff3,
                0xbd5a35556d716ba8685d106a944555,
                0xd9102f1ca16442372df5234fc4c23,
                0xae1aa56a4a4e1b155af1ac4fbef88a,
                0xdc,
            ],
            [
                0x2b4f279979c0d76db55e9060a93ecb,
                0x277d76d3aaed8f2e0c1ae85eadf666,
                0x5df03d4052a89c5cc1a61f67fe09c,
                0xcd7ebb63305a70cfbb3eb08d0751f5,
                0xfd7ebe36f2997c50c6976534e9b582,
                0x2f526ae261281ce6999aa06f3d07d3,
                0xe5fbe61aa9228fe714582c6a459714,
                0xecd341a9e19f72303a5046ece27cc2,
                0x9b33fcd44a5301ce0478380638245c,
                0x2ec3b9a307d777aedc6a774e9b7ce1,
                0xa74b5543b0b5524c83fb14075c4421,
                0x9827948daed5428c38a4de0967b404,
                0x30cf8fd4901f31e5ae906b3ea8c01d,
                0xb9bb1452ed3c9b02b065ea8be657c9,
                0x1e59cda2cd13df13f83a12f7770101,
                0x7724865d4f6fad2a800f206c843839,
                0x436f8e65577c752a9f1bbf38aa2cf4,
                0x4a3e,
            ],
        );

        let signature: RBN2048 = RuntimeBigNum {
            params,
            limbs: [
                0x1999f7717a7fd287d0b3e2d66a3437,
                0xc8fb6805554123679c362e6f002aae,
                0x3facdc5f1def4f49606b908e2a2538,
                0xc05aa4965a11190493a6f4e7fd5984,
                0x1672f3416fb95821efcb5375f1779e,
                0x2f81eb13f1894268f4acb1b0ae7513,
                0x15d997bac63df6624c2603e93cb0fa,
                0x536c959eea6cb9fc3980b86d9877b7,
                0x4296d1c42936c208b6ae13cd06d60b,
                0x39144ec79fc42ccc160b14c8b793e4,
                0xc40a783835d9df4c5f69ba68faaa,
                0xde2af88216d83b8136f094d8945b95,
                0x4ecac07a39171bd9a01383a4919924,
                0x737d8ffc839f4a503c431c507ba5f3,
                0x844f4957cf4b01c277f67a7591b7f5,
                0x0291a8afc7cda7e4c6e73e011c181f,
                0x7afcd49577ffbc75fbe9a2e2959b82,
                0x83,
            ],
        };

        assert(verify_sha1_pkcs1v15(sha1_hash, signature, 65537));
    }

    #[test]
    fn test_verify_sha1_pss_2048() {
        let sha1_hash: [u8; 20] = sha1::sha1_var(BoundedVec::from_parts(
            "Hello World! This is Noir-RSA".as_bytes(),
            29,
        ));
        let params: Params2048 = BigNumParams::new(
            false,
            [
                0x8076ee27cf6ed266e737de20b03e47,
                0xbd07415cda0752a917b4f40d19c992,
                0xd473ccfa4dc8a5690c17eceab674d4,
                0xdf2645d4e31531b5e68d7b30152182,
                0xe4e6d87d9b3222f56ddc48b46dc544,
                0x587c5d66e6970f42fe18afa99b5e5b,
                0x30261d8162c75fe7ba96ab0c2a6dd3,
                0xdc69073390846c7fb3c98c9c316d60,
                0x4b6a2bc2c1e5131129539c38b0ac3b,
                0xf05187e8d7cf34d2c1685409173080,
                0x2d26be5b0d792a3d92b7d4062b3d44,
                0x4eb7f21f6c4e3df8d2829f6b3e6eaa,
                0x9f1cd4d18bd53d4bbcf804651435f3,
                0x3d266b2f1223e08dd2159d58cb48d4,
                0x873625d48c8244c51924bfdee0c6ac,
                0xfcbf5c61a9d3cf2d0e13686af8d0de,
                0xb4345e8b5be7510698390901722861,
                0xba,
            ],
            [
                0x46d03675a8a2294e5a85be7f217ca9,
                0xf0daa6fd0fff3bb589bc46368eca41,
                0x73fc141cfe4c5e2d626ae4fb73ea76,
                0xbfa2cb047ee7ae250cb3405fb2b8f,
                0xf1d30ac0f7029bbe5cc660879ab6a9,
                0xcd71a546426aa510d9b6397e3d0d7d,
                0x846d473a83a7a76c068600ffe76657,
                0xa58cab8aeffd7b3ec4cd11c5a5daa8,
                0x6b26347dfe5e5b17d0d829b14f02b3,
                0x872b5749f336526ae0ce13984f7c3d,
                0xcc175294f0c4860129f958d98eb064,
                0xbdfe14537208fd73b200a6543d475,
                0x22bc3564a0eb67a33ab75c9d7e5995,
                0x8ddfd4c7ae1178eb9572c7d3c02116,
                0x18f68aa8ef553b722db69ddd898d03,
                0xa4b727519c55d49262a3b69dda80e6,
                0x79319e4fc2f1fd76a017697356ef,
                0x57c1,
            ],
        );
        let signature: RBN2048 = RuntimeBigNum {
            params,
            limbs: [
                0x835c0b9302499888acedea4013ec92,
                0xe1f4b56b2ca0ad8c1ee3b8a9a85d93,
                0x5d4fecc54034eb1091ca9fc28e3ff1,
                0xab316868780469b1621c789b8d8b75,
                0x13205cae60d93b387ef282c901bb,
                0x776e846d321b59b584c6de6ae6da18,
                0x6170c33330baeaee6a3de84e32f031,
                0x3862d9f28a50c32f0f09a6e5e60560,
                0x83e54c8d5a9522e5addc4cb35078b1,
                0xf4cd91425b0b042fb1cbb81d0ce6d6,
                0x33c49780bb4c00637bfd9f5de1d1cc,
                0xcbd14e26c78a769ff0e47854ff9d72,
                0x459db8d780c5287c894d8d419ec583,
                0x19909716db20e09223fbc169d58ed4,
                0x62efd0331023145d761b8568fc93c9,
                0xcac052c722d08645d4ad31464f665a,
                0x33c6a0e25cd27dbfd1d15fc2197aa5,
                0x89,
            ],
        };

        assert(verify_sha1_pss(sha1_hash, signature, 65537, 20));
    }

    #[test]
    fn test_verify_sha256_pss_2048_salt_len_64() {
        let sha256_hash: [u8; 32] =
            sha256::sha256_var("Hello World! This is Noir-RSA".as_bytes(), 29);
        let params: Params2048 = BigNumParams::new(
            false,
            [
                0x93f3d892703247d5f4bdb3e3864a8f,
                0xeeb6fe2e10ba74b661ede57de66f32,
                0x22651fe330d4c4112b37bdf4b66e50,
                0x95737da8b410591ef8cf9a5147ec82,
                0x36795c89b09d4b2bb1286b3eb02408,
                0xed2fd4e16a15e340c4823ed14d05c0,
                0xf341f7d5db9b59a0cee7b49926df51,
                0xab3d6a418ae21553c0218db4bd539d,
                0x5a44ef24779a5ff840ebecf8954d91,
                0xbea7ac89cee886658623e593beb453,
                0x994b0f172962a7765e45fe554b6249,
                0x992308a3c4f3f47a60f94ebab0241b,
                0x5f282ac7fb2acaf2bec3459ca99ea5,
                0xa0342e2c4c14edb82ca07cfbca5320,
                0xe97df079c947e20f8a709d96271dd6,
                0x9fa5990ee6e97183646e8d22c8e57d,
                0x844dff0cf2b0a2956116138f6e8c86,
                0xcc,
            ],
            [
                0xea31089f1107eb8c25f45673a55ae7,
                0x755c765fac1ef0bb2207d2b30f444d,
                0xafc4a4487e94792b21a48021621f6a,
                0x1c07a280480f453b3c65e5bb6a6a21,
                0x1ea3cc5348312e48a4bf2b727a9d5e,
                0xde15d39c5e7032b06a467c46a0e42c,
                0xe92a1e61a4763dcf93cd8af11103ac,
                0x3153088a6766c7c67a69af85e44c5d,
                0x939e8b17c1378cb0e78c3352e81953,
                0xba0c37026a839e5019aade93a6734d,
                0x4e4532261b27241f4cd9110d1208ab,
                0xb4c1714853298ef242c3459cdae247,
                0x588fb6ed0023bd191e491a48b9017f,
                0xe584ce3c57b7722797ce07a984fc42,
                0x3bff0d3a58afe4dc5b8ccc6c137bb,
                0x7c3a73e8933291f7aa1dcf8e2af90e,
                0x5b921f23c559f2b0b7b5f6fd991c10,
                0x501c,
            ],
        );
        let signature: RBN2048 = RuntimeBigNum {
            params,
            limbs: [
                0x7112edfa6f6fd5bfb0c38c50b10ecf,
                0xfcf8394640dd0c461b31e1139cfce1,
                0xfc63070c16fa641577632dd483f62a,
                0xf80b84f90cddbb6838f7b572ecd8a9,
                0x6db9213f70fa40d11e1ea0b71807e4,
                0x9a1c6f96a7753164bd0402beb70e23,
                0x2cdead0b775f54c33c8b33c73848f2,
                0xf1140865734f5ff9f03c783400824d,
                0x36eb972e53b5acb6c0217d1b470cb8,
                0x5ee60ccd804ebab686b51adbd759be,
                0x4d2349a887d2d707f8c2fe0a53dc83,
                0x86bf074d73c11f919157fe4a05bf49,
                0x0de6169875ea10baf96cf7b53fcdef,
                0x6703f35e54cc01ce5345d216dabea9,
                0xa27e236d8bcc572fc5585ea7289de4,
                0x222c277074191eb0c3b8816813f87d,
                0xf74e23fc27c1df4f43b528b43eb4d9,
                0x43,
            ],
        };

        assert(verify_sha256_pss(sha256_hash, signature, 65537, 64));
    }

}
