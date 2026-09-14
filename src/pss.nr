use crate::constants::MAX_SALT_LEN;
use crate::utils::{get_array_slice, pow, reverse_array};

use crate::mgf1::{mgf1_sha1, mgf1_sha256, mgf1_sha384, mgf1_sha512};
use crate::rsa::exponentiate_signature;

use bignum::RuntimeBigNum;

use sha1::sha1;
use sha256;
use sha512::{sha384, sha512};

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
