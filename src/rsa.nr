use dep::bignum::RuntimeBigNum;
use dep::bignum::params::BigNumParams;
use crate::types::{
    RBN1024, RBN2048, RBN4096, RBN1025, Params1024, Params2048, Params4096, Params1025,
};

global HASH_LEN: u32 = 32;

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
 * @brief Generate a mask from a seed using the MGF1 algorithm with SHA256 as the hash function
 **/
fn mgf1_sha256<let SEED_LEN: u32, let MASK_LEN: u32>(seed: [u8; SEED_LEN]) -> [u8; MASK_LEN] {
    // MASK_LEN must be less than 2^32 * HASH_LEN
    dep::std::field::bn254::assert_lt(MASK_LEN as Field, 0xffffffff * HASH_LEN as Field + 1);

    // HASH_LEN bytes are added at each iteration and there is at least 1 iteration
    // so if HASH_LEN is not enough to fill MASK_LEN bytes in one iteration,
    // another one is required and so on.
    let iterations = (MASK_LEN / HASH_LEN) + 1;

    let mut mask: [u8; MASK_LEN] = [0; MASK_LEN];
    let mut hashed: [u8; HASH_LEN] = [0; HASH_LEN];

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
        hashed = dep::std::hash::sha256_var(block, SEED_LEN as u64 + 4);

        // Copy hashed output to mask
        for j in 0..HASH_LEN {
            if i * HASH_LEN + j < MASK_LEN {
                mask[i * HASH_LEN + j] = hashed[j];
            }
        }
    }

    mask
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
        if i as u32 < 52 + ps_len as u32 {
            // PS padding which depends on RSA modulus / sig length. 1024 bits = 128 bytes = 128 - 54 = 74 bytes of 0xFF padding
            assert(padded_sha256_hash[i] == 255);
        } else if i as u32 == 52 + ps_len as u32 {
            // Pad 0x01
            assert(padded_sha256_hash[i] == 1);
        } else if i as u32 == 53 + ps_len as u32 {
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
    * @brief Verify an RSA signature generated via the PSS signature scheme.
    *
    * @note The exponent `e` can be either 65537 or 3 (i.e. the most common values in use for RSA)
    **/
pub fn verify_sha256_pss<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; 32],
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
) -> bool {
    assert((exponent == 3) | (exponent == 65537), "Exponent must be 65537 or 3");
    let mut exponentiated = sig * sig;
    if exponent == 65537 {
        // Exponentiate the signature assuming e = 65537
        for _ in 0..15 {
            exponentiated = exponentiated * exponentiated;
        }
    }
    // Otherwise, e = 3 = 11
    exponentiated = exponentiated * sig;
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
    let s_len = 32;

    // Check if emLen < hLen + sLen + 2
    assert(em_len >= h_len + s_len + 2);

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
    for i in 0..(em_len - h_len - s_len - 2) {
        assert_eq(db[i], 0);
    }

    // Check if the octet at position emLen - hLen - sLen - 2 is 1
    assert_eq(db[em_len - h_len - s_len - 2], 1);

    // Extract salt
    let salt: [u8; 32] = get_array_slice(db, db_mask_len - s_len, db_mask_len);

    // Construct M'
    // M' = (0x)00 00 00 00 00 00 00 00 || msg_hash || salt
    let mut m_prime = [0 as u8; 72]; // 8 + h_len + s_len
    for i in 8..40 {
        m_prime[i] = msg_hash[i - 8];
    }
    for i in 40..72 {
        m_prime[i] = salt[i - 40];
    }

    // Compute H'
    let h_prime = dep::std::hash::sha256(m_prime);

    // Compare H and H'
    h == h_prime
}

/**
 * @brief Verify an RSA signature generated via the pkcs1v15 signature scheme.
 * @details The fourth function parameter is required to define the value of `NBytes`
 *          when converting a BigNum into a byte array, the number of bytes is required and currently cannot be inferred.
 *          Once numeric generics can be derived by applying operations to other numeric generics the need for this will go away.
 *
 * @note The exponent `e` can be either 65537 or 3 (i.e. the most common values in use for RSA)
 * Rough cost: 2,048 bit RSA: 26,888 gates per verification
 *             1,024 bit RSA: 11,983 gates per verification
 * A circuit that verifies 1 signature (and does nothing else) will cost ~32k due to initialization costs of lookup tables
 **/
pub fn verify_sha256_pkcs1v15<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; 32],
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
) -> bool {
    assert((exponent == 3) | (exponent == 65537), "Exponent must be 65537 or 3");
    let mut exponentiated = sig * sig; // sig^2
    if exponent == 65537 {
        for _ in 0..15 {
            exponentiated = exponentiated * exponentiated;
        }
    }
    // otherwise, e = 3 = 11
    exponentiated = exponentiated * sig; // either sig^2 * sig = sig^3 or sig^65536 * sig = sig^65537
    let mut padded_sha256_hash_bytes: [u8; (ModBits + 7) / 8] = exponentiated.to_le_bytes();
    compare_signature_sha256(padded_sha256_hash_bytes, msg_hash)
}

#[test]
fn test_verify_sha256_pkcs1v15_1024() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("hello world! test#123".as_bytes());
    let params: Params1024 = BigNumParams::new(
        false,
        [
            0x483fd4238ca29c3a06f8161ee16faf,
            0xf366b16a37c2db80d2977eab0ebbdc,
            0x92ba4d77ff2425727ad38eea1cc2fe,
            0x3fc50862a0e6afbcae13d5f85c220a,
            0xe634dcea239a6a896597d4f75af455,
            0x32e1448d1489bca56d983562715680,
            0x1a81ef873140c0cfc191a44bfe6e88,
            0x96066f4df0e14de07329df952aba45,
            0xc2e161b4944381bb,
        ],
        [
            0x9c0b9f33d5b6960db5d70095a87724,
            0xfb5245423548a808b8aee833d783b8,
            0x790c0d7558b38dc24122455bf48f92,
            0x39227725aaea9c83a99acf4b847682,
            0xbd468a00b83cb026568150030eff3a,
            0xcbb4f5cef905ca04f92f266e0493e8,
            0xe19ad572a7bc2bb8168c81b0867c04,
            0xbe2075bf10bc8a16725befb36d7f49,
            0x15049cee2f37078121,
        ],
    );

    let signature: RBN1024 = RuntimeBigNum {
        params,
        limbs: [
            0xe6fe1016893fed66550af77d706698,
            0x9dd3b648afbbdb748ab97b4d609f0d,
            0x83098d3b45c588c69c0e36ff9b210a,
            0x5a793d529a382b34a491f68e4d959d,
            0xa8c43b964794a4c11da2e57ef226df,
            0x68654e3681728df9daff17a3b0bc66,
            0x8aa4c9accfffae4fd5cd453c8c5335,
            0x8b243f7074dacdcd869b94f3eef7fe,
            0x3a8c12564704f5ad,
        ],
    };

    assert(verify_sha256_pkcs1v15(sha256_hash, signature, 65537));
}

#[test]
fn test_verify_sha256_pkcs1v15_2048() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());

    let params: Params2048 = BigNumParams::new(
        false,
        [
            0x6d235ca5aab99a4c05ff2a03574427,
            0xec267a6bbe7ffe4b6e8da9cf24897c,
            0xcdaa2e64a6116d5bdf82460a108af3,
            0xf6c184c2d2f4cc7ed3b7eaf28e257e,
            0x7511d2771cdf315a07ba2e0058cb8b,
            0x641d6eb5119b1b8e643eda5ade2dc3,
            0xffc28bdb9f8f0ddc596675feae14fc,
            0xcbc67f77f37393c3419a2340f859ad,
            0x5cd500e0341275ce468e62db47107d,
            0x3049eba2be3f9408f2c9ed2ae27d90,
            0xc2f431dd169858ac5269d2512f4189,
            0x36ace99a589959ea0425444cfb440d,
            0x825fbf23e4e49a3b8f1fa714681f77,
            0x8125cd82c2776832cf839ee1a9332c,
            0xacbefb6a860c88ecbef30d52472137,
            0x24166d0e0b434e207d4e8ecfd66cc9,
            0x180955377f255f7bc29506fb45a8cb,
            0xf7,
        ],
        [
            0xd08ee8d0e8ac5ce306aa570cfe1c05,
            0xed045b877e042b6c144e6aa9cce044,
            0x845096769616e1351bd198cb0938ae,
            0xe4512a74991f500c166befa3c2f524,
            0x81a05d9646ce1212d658399b5b566d,
            0x1211121678c29a52c6d66eeca965b9,
            0x93dfb350c2b86c8a2a2464cd84e03c,
            0x9747aff06e0b9527bc5ad313c8173e,
            0x1ca0a8eb7986c264406bf2a8752034,
            0xe6abe17cf0f33ec2f655a85c027269,
            0xd157b2f2739eec33b38908711b45df,
            0xecc0246c32b828f0f603c9feea2daf,
            0x76cb733ba6093e7fc2cfc29e07d7c4,
            0x7c6f3519480fc9490894acf0c7087f,
            0xb92c0644fa19196c5be9d142611269,
            0x4db094df57cae1fa0bf4e8faec435b,
            0xa2426a309776b8e5d0be5257586c59,
            0x1093,
        ],
    );

    let signature: RBN2048 = RuntimeBigNum {
        params,
        limbs: [
            0xad8c7c5ec9162b4769e0cfe5ebf840,
            0x0d57cdde315319930d4e9eda1a7c1e,
            0xafc455e0e01ef5a57160f0df8a786c,
            0xbf1c1e64e91e316ec3ec02e68c23d6,
            0x8df9a02bb6a52c932ad0d2832e33a6,
            0xa3eacb4ebcb99a4a48be662698a9b8,
            0x4fef3847f3e94050802ab50f29a01d,
            0xa493fa7d68bd2b0d9e1a1d768053c0,
            0x707d984f377f71262954eabd10e268,
            0xfec30d40733948f36919b3ffa07366,
            0xc9bf002b29ce6a860ba284a4426e34,
            0xbc839ec24aad3c05a9aaccefca9e63,
            0x07fe1918a7d98dd52e49e9d775461c,
            0x098fdfe7d87d48732502814ee90808,
            0x64de99868676d8b02d7b43b0474636,
            0x27910e77bdc54ba42a4322a5ce8200,
            0xc3b7b95e779c9a11895c88fe24bced,
            0x96,
        ],
    };
    assert(verify_sha256_pkcs1v15(sha256_hash, signature, 65537));
}

#[test]
fn test_verify_sha256_pkcs1v15_2048_exponent_3() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("hello world".as_bytes());

    let params: Params2048 = BigNumParams::new(
        false,
        [
            0xea12ae77c634ac18e8914b0f112919,
            0x7a385b52ed45602b3166e3006cab17,
            0xce91edcb26009ae4ca5ec9032ace54,
            0xec45aa323af9389e814dfa59e4e106,
            0x50332220bbc7184b2b54c87acb79fb,
            0x1fead59aea9260a545bb9b1e098753,
            0xb362f1fc50b04e6581b34f97a769b5,
            0x409c9d7b3a3ecb214e9dc5524e21a3,
            0x88974631f1a1eed0c9d1fa6cc3c622,
            0xadacc23ed4a6e2c0e968ad1da6e5b5,
            0x480a5bbcc4e18d45937957d44adff2,
            0x4d54fd4d3ab7ac249866b6aeaaf37f,
            0x7eb6e94460e5dab5f15c55faf1bf5b,
            0xc0bca2fb49828eb02a02cb3d95f48a,
            0xeeb45b7149ee2bffe342120c8ef177,
            0x9108e90248dfab616da128279b0391,
            0xd446716c4e0be2123afd277a2cf8a7,
            0xe5,
        ],
        [
            0x8653d918663eb92721c6efedf149e4,
            0x3dbb26bf3a033499240fd8ef578107,
            0x69a15f7a032e80ef1496b60b3b95ae,
            0xc9aff3026bae96644fc904d80d3c0a,
            0x4cb0ae9774e8045235dd864f81314f,
            0x65c558cd398b18126e7f3788d196c6,
            0x5d7cdb26a9343a94726693b0b5a6c6,
            0x4b3cd2b0ef752aa26ba6a7fba6f795,
            0x6632fa88182883e987e0db1bcaaaea,
            0x38098156f929b4fda6d3026667b3a0,
            0x5d5bee367212e64a7d1bd3307082a4,
            0xf2622828a7f6e5d906388ec2aa850c,
            0xacfdba93e953a71ce0a75f3f88c96f,
            0xf8a2b79dfe7264e30b058d44747277,
            0x8cf6a50c2e0723546a03d684e3fda,
            0xc95e8eb25fe50e2ad34e494492abf,
            0x6a078f758586eb4b1e60059a1826b1,
            0x11d2,
        ],
    );

    let signature: RBN2048 = RuntimeBigNum {
        params,
        limbs: [
            0xcd01362e23da8aa633cb5a0fb9808d,
            0xd3be03e14b0c1eea086ef6aca3d51a,
            0xc7bb806d6723bb12c95ce0e3bc5588,
            0x05f9843f35688f97a88273cc30b661,
            0x25679e918a53da7baa6840d660305c,
            0xb89d2c648f85e1372ae090aa89e19c,
            0xb90686c46e3c9be1e0f4006047bf5b,
            0xd2d27921c3c5b8613d4fec51eb7045,
            0xf5e86133acb02bd34dbac6805c5958,
            0x84fe10899677d060461b0c3619dcfc,
            0x8c9a26f5a68450509aca9d347f0d51,
            0xccb9f4406f2c75407b871d39a06cb1,
            0xcc95879813f3f90c64f7b5c21b3b0e,
            0xc519654312dce978c9f368724d8c8f,
            0x5ec258287e34b65bd13cb4c05381ae,
            0xd8b5e5f82508cde542538a1973f37f,
            0xe035ef2e15b18975521e6ff25072c0,
            0x34,
        ],
    };

    assert(verify_sha256_pkcs1v15(sha256_hash, signature, 3));
}

#[test]
fn test_mgf1_sha256() {
    let seed: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
    let expected_mask: [u8; 32] = [
        106, 93, 232, 46, 236, 203, 51, 228, 103, 104, 145, 29, 197, 74, 26, 194, 135, 200, 40, 232,
        179, 172, 220, 135, 51, 185, 209, 35, 194, 131, 176, 190,
    ];
    let mask: [u8; 32] = mgf1_sha256(seed);
    assert(mask == expected_mask);
}

#[test]
fn test_verify_sha256_pss_2048() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
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
            0x399ea4dac74d4757a7a2956b5b0493,
            0x954c409a53ce8d70f35be10b94d284,
            0xee4d330032d52a65e66f54f9e091f4,
            0x7522b6ca940bfc5133b8fd77ca4bc8,
            0x43485c2c6ac94d8041c5a056da794b,
            0xa464924f3a28ab23c5ffa0493dddee,
            0x8fe3f1bc6a09e1103acbb53acbf6f1,
            0x5e47597909e86c168b5748cc089ce1,
            0xc86b6b4de2aa786e144d0ef5556c30,
            0xf45a9d9d93fbe0cd5f2ddca2316648,
            0x5edab2328b0b639407f9c773a06c5c,
            0xb61d4e287c0c6a969f5decfd036ea5,
            0xd47864f47e49cd0e0ec34f120ba0a4,
            0x3eaa94f799b276ef6a790eb61722d4,
            0x5c18da1341811cee5de6f76ed1a186,
            0x5ef0641da7cac0c45ba74d4355befa,
            0xbb04586630e92ea5ece8e5db45caea,
            0x1758,
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
    assert(verify_sha256_pss(sha256_hash, signature, 65537));
}

#[test]
fn test_verify_sha256_pss_4096() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
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
            0xc4c3bf6cc9335c4bb7199f9eb47a5d,
            0x7bcbe7b5b3cfb697c6b77fe1aa066f,
            0x3e936bb516c60dec6e7bde90a54056,
            0x78a92edbea967a370dc928b2f4cb53,
            0x99df0977952d4278e6b4c792b31c39,
            0x7d894ebed8702b158c7a51dff502b8,
            0x6da93f37eabadd8e55d4f450bf48a6,
            0xfb59acbad033856be388bf59b73c4a,
            0x8644dd32dc773e5e12e03380dbff01,
            0xdff59e8aefb7acc81bde30f7b22890,
            0xa646c3f6a98819547eae677e99679,
            0xc777d7da058b7a0d88b7ec84400a6,
            0xc6ba50b7cc4d0aebf8a25d1eaca0ec,
            0x6f2cc8babdde75a318872b952885fa,
            0x6fc91aadc8ce227e9039c8f3148d9c,
            0x67773f804221d4f58ca3bd11952bc7,
            0xcf5a20affc5a099ad25abb5b9cc622,
            0xf60a9108eb36c8068e93e524c23512,
            0x8b67af87617dcd94e38a62a7297673,
            0x656343f8e1802e8c043b2621f5b08d,
            0xd82c8e1a8d3e458e7979a77cd76424,
            0xd2bf783c787be340bd66fb8a07d1d7,
            0xc94d16e2ea48369f57abca5909b81c,
            0x2ff442542b4e904ad3ca20d06ee11f,
            0xa1fa20565627dd7eb96b4027b6714f,
            0xd3a82d484df4983db5fadd7b93048a,
            0x5f4e993b09d0ab81b8312bc09f069,
            0xcd135a6daa623b906fb62c6e28e9e1,
            0x1a5abe5655f62a0a0d0d9479ae7675,
            0xcfa89adba08b924725c940a56ad9e,
            0x6023b1d30936eb9ee54bf789026e22,
            0x9e91f11aa269f381122653c704cd5,
            0x2116e976d592737e0c57dc12269efc,
            0xe88a3202a09bdeaa3db69af98a651,
            0x1618be,
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

    assert(verify_sha256_pss(sha256_hash, signature, 65537));
}

#[test]
fn test_verify_sha256_pss_2048_exponent_3() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
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
            0xaf8e2d749a5966b98ffa10ea071d41,
            0x83704b0ef8ae71e3f1a7d24d871556,
            0x82903be42859c5bd5cbb935d1097fb,
            0x5bdc4e1e26670ed73580e2c8c144c1,
            0xce5178ff7019c4a6c0a2743ab2fae1,
            0xfd9ba73654ecf2020bdfa6ed9dc777,
            0x9ba95e3e7551ee261a4f10eca35f05,
            0x9e09b71274e5df10e06a6ce6319c3f,
            0xb14781efad91be0888f5150771eea5,
            0x15d2f490d6ba3cf25ad91e5e2539b0,
            0x7887aca3df2194cdbed904e6d42977,
            0xb797f21802a052c11e5c205bcb7d21,
            0x94d15b35eaf46e2fe69f2b60c02922,
            0x73814f1d160107a3ff1081b0cd1fea,
            0xaa4c31b61839c41980a8bb9c922a0c,
            0x123cc9f0ad08747529171a2e286eb6,
            0x7a8b658fe4e9b448debf21d8ea0cc0,
            0x14d4,
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
    assert(verify_sha256_pss(sha256_hash, signature, 3));
}

// Test an unusual key length that is not a multiple of 8
/*#[test]
fn test_verify_sha256_pss_1964() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
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
            0xd4343ba7542877db4a663c12d159c,
            0xb7f3ebb5e9a7e46abb5fa5ebebf068,
            0x6f2ab6c72bbdcd87bf3cd5343f7059,
            0xa437eae960f2ac5714f7a35b803598,
            0xae01beec10904488485933615d62b6,
            0xf9509a6004d765dfa27536888f2757,
            0x57dbdd558fa8831a632849dbaecdfa,
            0xe7c4027a23af2ef309461db1f95629,
            0x388a2b780c78da825692f1cec5055e,
            0xd064ac53ec3c505b8e8e25b9350ce7,
            0x529b1374876a3bbf8e83e5d239cd69,
            0x7206c8bf4a0d11655219207de991b4,
            0x5fe1135077b5b760d31bdbfcb4f698,
            0xdb00d1d10cdb6c91c0f93f4b1a18c8,
            0x8329224ca1e3c5ef415cb1629f82d8,
            0xecca0fb0c3e52adfd165bbf85b34eb,
            0x150fec084e187,
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
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
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
            0x7ab08c63fb6eeee6204bd814d3134a,
            0x20d51c551c06e8ae471cc43e84d131,
            0x5eac3eae8238c6c2c37c1ce5bec407,
            0xcff61632bd2ea6bc1dc8da002aa0c5,
            0x801c1e85137856c4a6dc8c25078a59,
            0x5ce8ee248cac12cbc3faa426acd58b,
            0xe72384bb8302bbb78a3766fc61c5f0,
            0x6ea716c0a657933b91b2d488b29cec,
            0x2bed1ff958b58c194c,
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

    assert(verify_sha256_pss(sha256_hash, signature, 65537));
}
