use crate::constants::{SHA1_HASH_LEN, SHA256_HASH_LEN, SHA384_HASH_LEN, SHA512_HASH_LEN};

use sha1::sha1;
use sha256;
use sha512::{sha384, sha512};

/// Generalized MGF1 algorithm that derives a mask from seed
fn mgf1<let SEED_LEN: u32, let MASK_LEN: u32, let HASH_LEN: u32>(
    seed: [u8; SEED_LEN],
    hasher: fn([u8; SEED_LEN + 4], u32) -> [u8; HASH_LEN],
) -> [u8; MASK_LEN] {
    let iterations: u32 = (MASK_LEN + HASH_LEN - 1) / HASH_LEN;

    let mut mask: [u8; MASK_LEN] = [0; MASK_LEN];

    let mut block: [u8; SEED_LEN + 4] = [0; SEED_LEN + 4];
    for j in 0..SEED_LEN {
        block[j] = seed[j];
    }

    for i in 0..iterations {
        let counter_bytes: [u8; 4] = (i as Field).to_be_bytes();
        for j in 0..4 {
            block[SEED_LEN + j] = counter_bytes[j];
        }

        let hashed: [u8; HASH_LEN] = hasher(block, SEED_LEN + 4);

        for j in 0..HASH_LEN {
            if i * HASH_LEN + j < MASK_LEN {
                mask[i * HASH_LEN + j] = hashed[j];
            }
        }
    }
    mask
}

/// Generate a mask from a seed using the MGF1 algorithm with SHA1 as the hash function
pub(crate) fn mgf1_sha1<let SEED_LEN: u32, let MASK_LEN: u32>(
    seed: [u8; SEED_LEN],
) -> [u8; MASK_LEN] {
    mgf1::<SEED_LEN, MASK_LEN, SHA1_HASH_LEN>(
        seed,
        |block: [u8; SEED_LEN + 4], len: u32| sha1::sha1_var(BoundedVec::from_parts(block, len)),
    )
}

/// Generate a mask from a seed using the MGF1 algorithm with SHA256 as the hash function
pub(crate) fn mgf1_sha256<let SEED_LEN: u32, let MASK_LEN: u32>(
    seed: [u8; SEED_LEN],
) -> [u8; MASK_LEN] {
    mgf1::<SEED_LEN, MASK_LEN, SHA256_HASH_LEN>(
        seed,
        |block: [u8; SEED_LEN + 4], len: u32| sha256::sha256_var(block, len),
    )
}

/// Generate a mask from a seed using the MGF1 algorithm with SHA384 as the hash function
pub(crate) fn mgf1_sha384<let SEED_LEN: u32, let MASK_LEN: u32>(
    seed: [u8; SEED_LEN],
) -> [u8; MASK_LEN] {
    mgf1::<SEED_LEN, MASK_LEN, SHA384_HASH_LEN>(
        seed,
        |block: [u8; SEED_LEN + 4], len: u32| {
            sha384::sha384_var(BoundedVec::from_parts(block, len))
        },
    )
}

/// Generate a mask from a seed using the MGF1 algorithm with SHA512 as the hash function
pub(crate) fn mgf1_sha512<let SEED_LEN: u32, let MASK_LEN: u32>(
    seed: [u8; SEED_LEN],
) -> [u8; MASK_LEN] {
    mgf1::<SEED_LEN, MASK_LEN, SHA512_HASH_LEN>(
        seed,
        |block: [u8; SEED_LEN + 4], len: u32| {
            sha512::sha512_var(BoundedVec::from_parts(block, len))
        },
    )
}
