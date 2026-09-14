use crate::constants::{SHA1_HASH_LEN, SHA256_HASH_LEN, SHA384_HASH_LEN, SHA512_HASH_LEN};

use sha1::sha1;
use sha256;
use sha512::{sha384, sha512};

/**
 * @brief Generate a mask from a seed using the MGF1 algorithm with SHA1 as the hash function
 **/
pub(crate) fn mgf1_sha1<let SEED_LEN: u32, let MASK_LEN: u32>(
    seed: [u8; SEED_LEN],
) -> [u8; MASK_LEN] {
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
pub(crate) fn mgf1_sha256<let SEED_LEN: u32, let MASK_LEN: u32>(
    seed: [u8; SEED_LEN],
) -> [u8; MASK_LEN] {
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
pub(crate) fn mgf1_sha384<let SEED_LEN: u32, let MASK_LEN: u32>(
    seed: [u8; SEED_LEN],
) -> [u8; MASK_LEN] {
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
pub(crate) fn mgf1_sha512<let SEED_LEN: u32, let MASK_LEN: u32>(
    seed: [u8; SEED_LEN],
) -> [u8; MASK_LEN] {
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
