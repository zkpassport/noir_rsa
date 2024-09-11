use dep::bignum::BigNum;
use dep::bignum::runtime_bignum::BigNumInstance;
use dep::bignum::runtime_bignum::BigNumTrait;
use dep::bignum::runtime_bignum::BigNumInstanceTrait;
use dep::bignum::runtime_bignum::BigNumParamsTrait;
use crate::types::{
    RSA, BN1024, BN2048, BNInst1024, BNInst2048, RSA1024, RSA2048, BN1025, BNInst1025, RSA1025, BN1964,
    BNInst1964, RSA1964, BN4096, BNInst4096, RSA4096
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

    let hash_prefix: [u8; 19] = [32, 4, 0, 5, 1, 2, 4, 3, 101, 1, 72, 134, 96, 9, 6, 13, 48, 49, 48];

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
impl<BN, BNInstance, let NumBytes: u32> RSA<BN, BNInstance, NumBytes>  where BN: BigNumTrait, BNInstance: BigNumInstanceTrait<BN> {
    /**
    * @brief Verify an RSA signature generated via the PSS signature scheme.
    * @details `key_size` is the size of the RSA modulus in bits and is required to correctly decode the signature.
    *
    * @note We assume the public key exponent `e` is 65537
    **/
    pub fn verify_sha256_pss(
        _: Self,
        instance: BNInstance,
        msg_hash: [u8; 32],
        sig: BN,
        key_size: u32
    ) -> bool {
        // Exponentiate the signature assuming e = 65537
        let mut exponentiated = instance.mul(sig, sig);
        for _ in 0..15 {
            exponentiated = instance.mul(exponentiated, exponentiated);
        }
        exponentiated = instance.mul(exponentiated, sig);
        // Convert the exponentiated signature to a byte array and reverse it to 
        // get it in big endian order, which is much easier to work with for 
        // the rest of the verification process
        let em:[u8; NumBytes] = reverse_array(exponentiated.to_le_bytes());

        // The modulus size in bits minus 1
        let em_bits = key_size - 1;
        // The actual length of the encoded message without any of the leftmost 0s
        let em_len = (em_bits + 7) / 8;
        // The length of the modulus in bytes
        let key_len = (key_size + 7) / 8;
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
        let masked_db: [u8; NumBytes - 33] = get_array_slice(em, offset, db_mask_len + offset);
        let h = get_array_slice(em, db_mask_len + offset, em.len() - 1);

        // Make sure the 8 * em_len - em_bits leftmost bits are 0
        // c.f. https://github.com/RustCrypto/RSA/blob/aeedb5adf5297892fcb9e11f7c0f6c0157005c58/src/algorithms/pss.rs#L205
        let bits_to_mask = 8 - (8 * em_len - em_bits);
        let mask_value = pow(2, bits_to_mask as u32);
        assert_eq(masked_db[0] as u32 / mask_value, 0);

        // Generate dbMask using MGF1
        let db_mask:[u8; NumBytes - 33] = mgf1_sha256(h);

        // Compute DB = maskedDB xor dbMask
        let mut db = [0 as u8; NumBytes - 33];
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
    pub fn verify_sha256_pkcs1v15(_: Self, instance: BNInstance, msg_hash: [u8; 32], sig: BN, exponent: u32) -> bool {
        assert((exponent == 3) | (exponent == 65537), "Exponent must be 65537 or 3");
        let mut exponentiated = instance.mul(sig, sig); // sig^2

        if exponent == 65537 {
            // e = 65537 = 1 0000 0000 0000 0001
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^2 * sig^2 = sig^4
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^8
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^16
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^32
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^64
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^128
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^256
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^512
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^1024
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^2048
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^4096
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^8192
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^16384
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^32768
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^65536
        }
        // otherwise, e = 3 = 11

        exponentiated = instance.mul(exponentiated, sig); // either sig^2 * sig = sig^3 or sig^65536 * sig = sig^65537

        let mut padded_sha256_hash_bytes: [u8; NumBytes] = exponentiated.to_le_bytes();
        compare_signature_sha256(padded_sha256_hash_bytes, msg_hash)
    }
}

#[test]
fn test_verify_sha256_pkcs1v15_1024() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("hello world! test#123".as_bytes());
    let BNInstance: BNInst1024 = BigNumInstance::new(
        [
        0x483fd4238ca29c3a06f8161ee16faf, 0xf366b16a37c2db80d2977eab0ebbdc, 0x92ba4d77ff2425727ad38eea1cc2fe, 0x3fc50862a0e6afbcae13d5f85c220a, 0xe634dcea239a6a896597d4f75af455, 0x32e1448d1489bca56d983562715680, 0x1a81ef873140c0cfc191a44bfe6e88, 0x96066f4df0e14de07329df952aba45, 0xc2e161b4944381bb
    ],
        [
        0x9c0b9f33d5b6960db5d70095a87724, 0xfb5245423548a808b8aee833d783b8, 0x790c0d7558b38dc24122455bf48f92, 0x39227725aaea9c83a99acf4b847682, 0xbd468a00b83cb026568150030eff3a, 0xcbb4f5cef905ca04f92f266e0493e8, 0xe19ad572a7bc2bb8168c81b0867c04, 0xbe2075bf10bc8a16725befb36d7f49, 0x15049cee2f37078121
    ]
    );

    let signature: BN1024 = BigNum::from_array(
        [
        0xe6fe1016893fed66550af77d706698, 0x9dd3b648afbbdb748ab97b4d609f0d, 0x83098d3b45c588c69c0e36ff9b210a, 0x5a793d529a382b34a491f68e4d959d, 0xa8c43b964794a4c11da2e57ef226df, 0x68654e3681728df9daff17a3b0bc66, 0x8aa4c9accfffae4fd5cd453c8c5335, 0x8b243f7074dacdcd869b94f3eef7fe, 0x3a8c12564704f5ad
    ]
    );

    let rsa: RSA1024 = RSA {};
    assert(rsa.verify_sha256_pkcs1v15(BNInstance, sha256_hash, signature, 65537));
}

#[test]
fn test_verify_sha256_pkcs1v15_2048() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());

    let signature: BN2048 = BigNum::from_array(
        [
        0xad8c7c5ec9162b4769e0cfe5ebf840, 0x0d57cdde315319930d4e9eda1a7c1e, 0xafc455e0e01ef5a57160f0df8a786c, 0xbf1c1e64e91e316ec3ec02e68c23d6, 0x8df9a02bb6a52c932ad0d2832e33a6, 0xa3eacb4ebcb99a4a48be662698a9b8, 0x4fef3847f3e94050802ab50f29a01d, 0xa493fa7d68bd2b0d9e1a1d768053c0, 0x707d984f377f71262954eabd10e268, 0xfec30d40733948f36919b3ffa07366, 0xc9bf002b29ce6a860ba284a4426e34, 0xbc839ec24aad3c05a9aaccefca9e63, 0x07fe1918a7d98dd52e49e9d775461c, 0x098fdfe7d87d48732502814ee90808, 0x64de99868676d8b02d7b43b0474636, 0x27910e77bdc54ba42a4322a5ce8200, 0xc3b7b95e779c9a11895c88fe24bced, 0x96
    ]
    );
    let BNInstance: BNInst2048 = BigNumInstance::new(
        [
        0x6d235ca5aab99a4c05ff2a03574427, 0xec267a6bbe7ffe4b6e8da9cf24897c, 0xcdaa2e64a6116d5bdf82460a108af3, 0xf6c184c2d2f4cc7ed3b7eaf28e257e, 0x7511d2771cdf315a07ba2e0058cb8b, 0x641d6eb5119b1b8e643eda5ade2dc3, 0xffc28bdb9f8f0ddc596675feae14fc, 0xcbc67f77f37393c3419a2340f859ad, 0x5cd500e0341275ce468e62db47107d, 0x3049eba2be3f9408f2c9ed2ae27d90, 0xc2f431dd169858ac5269d2512f4189, 0x36ace99a589959ea0425444cfb440d, 0x825fbf23e4e49a3b8f1fa714681f77, 0x8125cd82c2776832cf839ee1a9332c, 0xacbefb6a860c88ecbef30d52472137, 0x24166d0e0b434e207d4e8ecfd66cc9, 0x180955377f255f7bc29506fb45a8cb, 0xf7
    ],
        [
        0xd08ee8d0e8ac5ce306aa570cfe1c05, 0xed045b877e042b6c144e6aa9cce044, 0x845096769616e1351bd198cb0938ae, 0xe4512a74991f500c166befa3c2f524, 0x81a05d9646ce1212d658399b5b566d, 0x1211121678c29a52c6d66eeca965b9, 0x93dfb350c2b86c8a2a2464cd84e03c, 0x9747aff06e0b9527bc5ad313c8173e, 0x1ca0a8eb7986c264406bf2a8752034, 0xe6abe17cf0f33ec2f655a85c027269, 0xd157b2f2739eec33b38908711b45df, 0xecc0246c32b828f0f603c9feea2daf, 0x76cb733ba6093e7fc2cfc29e07d7c4, 0x7c6f3519480fc9490894acf0c7087f, 0xb92c0644fa19196c5be9d142611269, 0x4db094df57cae1fa0bf4e8faec435b, 0xa2426a309776b8e5d0be5257586c59, 0x1093
    ]
    );

    let rsa: RSA2048 = RSA {};
    assert(rsa.verify_sha256_pkcs1v15(BNInstance, sha256_hash, signature, 65537));
}

#[test]
fn test_verify_sha256_pkcs1v15_2048_exponent_3() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("hello world".as_bytes());

    let signature: BN2048 = BigNum::from_array(
        [
        0xcd01362e23da8aa633cb5a0fb9808d, 0xd3be03e14b0c1eea086ef6aca3d51a, 0xc7bb806d6723bb12c95ce0e3bc5588, 0x05f9843f35688f97a88273cc30b661, 0x25679e918a53da7baa6840d660305c, 0xb89d2c648f85e1372ae090aa89e19c, 0xb90686c46e3c9be1e0f4006047bf5b, 0xd2d27921c3c5b8613d4fec51eb7045, 0xf5e86133acb02bd34dbac6805c5958, 0x84fe10899677d060461b0c3619dcfc, 0x8c9a26f5a68450509aca9d347f0d51, 0xccb9f4406f2c75407b871d39a06cb1, 0xcc95879813f3f90c64f7b5c21b3b0e, 0xc519654312dce978c9f368724d8c8f, 0x5ec258287e34b65bd13cb4c05381ae, 0xd8b5e5f82508cde542538a1973f37f, 0xe035ef2e15b18975521e6ff25072c0, 0x34
    ]
    );
    let BNInstance: BNInst2048 = BigNumInstance::new(
        [
        0xea12ae77c634ac18e8914b0f112919, 0x7a385b52ed45602b3166e3006cab17, 0xce91edcb26009ae4ca5ec9032ace54, 0xec45aa323af9389e814dfa59e4e106, 0x50332220bbc7184b2b54c87acb79fb, 0x1fead59aea9260a545bb9b1e098753, 0xb362f1fc50b04e6581b34f97a769b5, 0x409c9d7b3a3ecb214e9dc5524e21a3, 0x88974631f1a1eed0c9d1fa6cc3c622, 0xadacc23ed4a6e2c0e968ad1da6e5b5, 0x480a5bbcc4e18d45937957d44adff2, 0x4d54fd4d3ab7ac249866b6aeaaf37f, 0x7eb6e94460e5dab5f15c55faf1bf5b, 0xc0bca2fb49828eb02a02cb3d95f48a, 0xeeb45b7149ee2bffe342120c8ef177, 0x9108e90248dfab616da128279b0391, 0xd446716c4e0be2123afd277a2cf8a7, 0xe5
    ],
        [
        0x8653d918663eb92721c6efedf149e4, 0x3dbb26bf3a033499240fd8ef578107, 0x69a15f7a032e80ef1496b60b3b95ae, 0xc9aff3026bae96644fc904d80d3c0a, 0x4cb0ae9774e8045235dd864f81314f, 0x65c558cd398b18126e7f3788d196c6, 0x5d7cdb26a9343a94726693b0b5a6c6, 0x4b3cd2b0ef752aa26ba6a7fba6f795, 0x6632fa88182883e987e0db1bcaaaea, 0x38098156f929b4fda6d3026667b3a0, 0x5d5bee367212e64a7d1bd3307082a4, 0xf2622828a7f6e5d906388ec2aa850c, 0xacfdba93e953a71ce0a75f3f88c96f, 0xf8a2b79dfe7264e30b058d44747277, 0x8cf6a50c2e0723546a03d684e3fda, 0xc95e8eb25fe50e2ad34e494492abf, 0x6a078f758586eb4b1e60059a1826b1, 0x11d2
    ]
    );

    let rsa: RSA2048 = RSA {};
    assert(rsa.verify_sha256_pkcs1v15(BNInstance, sha256_hash, signature, 3));
}

#[test]
fn test_mgf1_sha256() {
    let seed: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
    let expected_mask: [u8; 32] = [
        106, 93, 232, 46, 236, 203, 51, 228, 103, 104, 145, 29, 197, 74, 26, 194, 135, 200, 40, 232, 179, 172, 220, 135, 51, 185, 209, 35, 194, 131, 176, 190
    ];
    let mask: [u8; 32] = mgf1_sha256(seed);
    assert(mask == expected_mask);
}

#[test]
fn test_verify_sha256_pss_2048() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
    let BNInstance: BNInst2048 = BigNumInstance::new(
        [
        0x9c149f9aa49db0ee279be7b1b9f2b1, 0x472c42ef0019a179b36a37313423d5, 0x6796724132fb7b7b14db1078126604, 0xafbc95dc121ab99608b8f4145536b7, 0xef72836154b7feaaa7b4a79e07a3fa, 0x44ef7a3c294a863a2b8820c17a5ce6, 0x7bbb5c1d1160b1136cf310155d04d3, 0x81e11b000f6d1a72cdd0c57225a29c, 0x9d02c16e2643b7d38e082bdde79b0a, 0xd8d1905fde1d7bafc516ef0a544793, 0x41aa69097fc68ca3efb4a20e953f45, 0xc1580306d50a17bdeef26eeace7d9e, 0x69ecdf56a571e2349c615851b28f62, 0x79d7c408c01d0d601a318c3c3fb840, 0x94c5ac3935445baf4de56e50c50b30, 0x4d5c5d278e3a0f7f0617908b86ef71, 0x2ad08f95d923c8c04d9d93d072e13d, 0xaf
    ],
        [
        0xabdcccb22151f142cbaa207bf6cc89, 0xeaad15b6065fcff60108c268554cfd, 0xc508f4e0a4559a78166f1739577c8e, 0xb140e6600daaeb1038e38081ed338c, 0x72e332e60e3c44cdedbe157b539714, 0xf60bff05409ef357f90d0087def9b3, 0x9c82957c546f138ee9c7edd6e8fe18, 0xe04e36bd481ece291a557975dab90, 0xfd7c8ea97e11164495d881394d304b, 0xfa5a096283f960b1256700d772e9, 0x61c0057ea007659e58ac8754fec77c, 0x57bc9dd907a5065cd6ba3d6bd6b0e9, 0x517515a3fd6408b5e5766be7a692c5, 0x2b817d4eb0fe5afd47900c0e56f93f, 0xf604e52448f245c64e0e66198018e8, 0x8db41fd0ec788dec05113586c205ea, 0x224597fab441cd104694d7d61e0a57, 0x176
    ]
    );
    let signature: BN2048 = BigNum::from_array(
        [
        0x17b138e0afc2893ae13d2eea1ce349, 0x5d18d222dfc4af50aa6eb31eeb8403, 0x29d2a6d0fc929addd1785228f0f350, 0x162ff4f4bfc98867ff1e9ae7e4dfa2, 0xd38c9fe831a9acb84eb5754fde653f, 0xd9629bcc05a5ba2fd4edbd257c8b22, 0xc130ab593612459d247b0a1430515f, 0x20f1b3ca2724f0f811a8c793130196, 0x507cc26d77029853a1ef7a46c7f3c1, 0xb335060a4a9f58b25173d84e50b600, 0x5836975b3491cfe85a98204fca00f2, 0x17f96851d11d36ab2b93adb7aa3c07, 0x8e36e106516fded0e68a2a1be0d6b6, 0x697f2906a826b9dee8f3f497596db6, 0x38fdb5f7ca447d7b55e3f4ab592050, 0x2511143f27e0ce03e03100532b68a5, 0x01db0955c41de01a6c2e4bb902b621, 0x3d
    ]
    );

    let rsa: RSA2048 = RSA {};
    assert(rsa.verify_sha256_pss(BNInstance, sha256_hash, signature, 2048));
}

#[test]
fn test_verify_sha256_pss_4096() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
    let BNInstance: BNInst4096 = BigNumInstance::new(
        [
        0x172c834a6c2cb4f31cc7da80a6d4ff, 0x3633ac0b04176a7f16148924521b56, 0x94c82f8234b93e3cbca4de38be10, 0x8e89f65add2f6157d5484d396f7a07, 0x4552316deadc8a8453db1f2a5159a, 0x1139cd8f8560a6d2b03d55f0f28571, 0x74769b23449c8205a41e74127ba49c, 0x651d03683409bb671e5d74f8dab10f, 0xc35e8201ddceba963a91d882e69237, 0xc6635b7cc5369183677acb3618921f, 0xa058599e7196ea42d2729280108a37, 0xea79254e2521cf42489bbe3bdf4b59, 0x629214b33b173ac358db741b90c667, 0xd3396ad57619c601094d5e08ea181, 0xa583d1fa64979e18b53de89c678b52, 0xd86de4089ded807f28d92207bba1e8, 0x8f5bc7f249e84c2552c703e3a9d0fc, 0x8a9b1691456d7f9bd99d7855334db8, 0x57e44689db0d6ed82a4e166fa28485, 0xadf0dcebe17500c30b9edc2641520c, 0x243a0946b38a0862e9a400893c9827, 0x66ebc31eaf407031839967a4899c6d, 0xf2781a383e2d42d1e075f765b20596, 0xc19b52bb49364a3a56951912dcaf50, 0x360c4f265bbf79090e4dac2d449fa8, 0xc5196e0564a34b49bc490dd612d0b7, 0xcbc03557aa82584fddf791b590356c, 0xd36c22792441df5da9ddfaa6f79112, 0xb7faff9d1562a975d75ae8a4491036, 0xfe86a124b5a6fe5fd8940d46722445, 0xeeb6ad4b659197f5df7612f48b0694, 0x513b467ad6395fb05c99e7a9a066ad, 0x85e1b3835c3a04db1ce1ccab4feaa9, 0x18f03e52dd2f7f414769d14ff43457, 0xc716
    ],
        [
        0x9c3983c7c603ff128f131c61d3c71b, 0x2cc551814d00618b18789cd422d7dd, 0x4dbf02faeac0b4552091c7478e3ea9, 0x4a848f7a35e9296becc65f09f28041, 0xb5830f01768ae16d97c52a270ec5ef, 0x66e85db157060f7edf8e6f68accf6a, 0xae57871783d80ee70fbd14a9f4ad17, 0x754fa2fc322ab5973d85c954988bda, 0xc7151e7b2795b798fc150ab3dbacda, 0xe82ba5ecf13121aa2a9b8dbd8a68c7, 0x1ea267a29f40b4609b79d88cc2aa7c, 0x90af60e6176adf65813655cf152d5, 0x114ed1348379358e75347ab58f021, 0x701128fe95074c62750f2ca4df489a, 0xc5b02fe16f2a521c05f31e06547e97, 0xae7612cb115ce25e052a544d941977, 0x29b3c3dff2000d2f5240316eb6d99e, 0x3dff26cf76af256b2f8ae869327ec5, 0x4826c0fe245faaa15b5976ab4266c7, 0x1e43eee79212f02c2ff01de3d95a73, 0x1513ebcbdadf6acc2cce1f6d8436d8, 0x165aa074631832bdd1a1cfb65842c9, 0xdfac592ddcc24d1705d9a0d0b90982, 0xc2398daf5362d927c7138eea76df19, 0xba6644ba19668aaeef6e6d323fa5c, 0xeebb9a7ad00dc8767794b6dff4fdaa, 0x6b57930afde8e2f1f63e01744d3565, 0x851c15dd79ca3381d2908c94826542, 0x731df26adb519307c801b84c1a816a, 0x67aafb51f23d3f0791f4b55397a141, 0xce08dfb26c5382ad6621eff091cfa3, 0xd8e12d533d7f5fddee9532a874817c, 0x98ff1339043d4ebd5c0a9b08b0c721, 0x10943f9a8dd91d2a80bf2e45e06d9c, 0x1492f
    ]
    );
    let signature: BN4096 = BigNum::from_array(
        [
        0xac63ce14a64cd6a4b1f9659b26410b, 0x2a62d62e7d4413af3069c8fbddf5b0, 0xe17b8aee2ee89352eb6e9cb2bfe062, 0x17e844d0677907e149cd629559feb3, 0xc16074f86a1cf529d7d32a16b478ee, 0x7bbaea6accb92b0614cbbdc116efe8, 0xdea05ae4eb38a9f4cba514ed72ad18, 0x3fac6e2c09dd0e24483d88d941fbd5, 0x7645909bf765ffcab50cafa5ee437c, 0x6777f5a02029f5a0be50642edc360d, 0x6eeda2a036083a760ca77355694642, 0x4e0d0bef8f1f0cc1b37632e690d010, 0x5a81b80bafcb97374f0e0633716511, 0x3a0f822ad84f67a058c54e393c01f7, 0x62cc1dc3d45f6a51a47e033b8f5c15, 0x8e5cf5f214a5ce03563ccb3c2f2a04, 0xfe88463e315b818623f9c5470ed94f, 0x1a306b6f2391e9462d0e9a140629b2, 0x7c13e6dc02c5ea54f2c0dfd9c51c71, 0x60139d47ecb9331ce210492aed7a48, 0x024a4cc780f1c5eae1eb7ea58d46b6, 0x6d13a3e0f28d19ea0af8eedd7443ed, 0xd8ccd0d376f1fa28b19ac3a96dc039, 0x8527abd1dd1069bccd10ed4259d760, 0x2e62b482b2e4e44d11a0ff654d4fee, 0x65d4c5758c3f55bc17292659082163, 0x4e416cdaa103d4fe81f1df2ec11b1d, 0x7210cae86a9b2a7c9df3774fd58697, 0x7ca25424e38b9ce650140de93654f4, 0x3113e18f792ac55485403f1a5a210a, 0x394652d79237868c93c9267c6f08ab, 0x23fbb3ec2db7690ebf1f1b98499530, 0x649ebbd77bf42c4b560661d60ccc16, 0x9af7cae878f8ca65e568718ba20ef5, 0x2a98
    ]
    );

    let rsa: RSA4096 = RSA {};
    assert(rsa.verify_sha256_pss(BNInstance, sha256_hash, signature, 4096));
}

// Test an unusual key length that is not a multiple of 8
#[test]
fn test_verify_sha256_pss_1964() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
    let BNInstance: BNInst1964 = BigNumInstance::new(
        [
        0x2a035f94929bb130deaf854028f433, 0xbcfe17113a631a59158c3a81b85d4d, 0x136b271c541b8dbad5672777c48d9a, 0xa7f9a26a6fcebd3299c1604c501818, 0x8eb621862ba1bb8c432bc64c21e0a0, 0x1e0be8f31f728998e1e8783d06271d, 0x70f2a1450579e00f86bb39abe44cd8, 0xf26823e29557176366145bad958caa, 0x5b11eb8d6d8d5f0afb047b8826747a, 0xbfd7ee9d32a932bf274c75b63c8f40, 0x26bf6dc058ec401fd5f34c7ec1755e, 0xa04110ce6ae975c6f9075dc8917565, 0x24b194b23c695ba8eea35a6f336c2a, 0x153f3fec0be28f1f1636069149ba47, 0xca764dc95c1f96a325f9d51254a790, 0x67ea496073a3adcb0d093afec3c2a2, 0xcdd00d115e5
    ],
        [
        0xeb858462288906c78264566f2517bf, 0x307764ae5c67f7b179be6178742f97, 0x2eadd630b79ccfbea22e68e50701b9, 0x2683b85d13dffa94d1c986870489f1, 0x6d9f9788a78c52cab1918b4070842b, 0xd93261e5f34c5508a47183b62fb3b4, 0xd4b3a75c20554347708df7583ff81f, 0x63d7878156e7ea6a62f8c3f7e6f15f, 0x6cc531bba9e02310e414a3aa4e1a06, 0x19b50bf06c4444b2a788ec44c41c91, 0xd6bad67102a89597684b9d53f5370f, 0x726cc1262518f1b59aded3184d3ae4, 0xd018338b704c0a2535dee1fe70ce60, 0x9ec435e1f1652d2dde4e56cce77901, 0x41460a18f3fed1112e41afc93a2464, 0xc19e91fbbab21f155e4b71dbe9a7dc, 0x13e6ce9d6a14
    ]
    );
    let signature: BN1964 = BigNum::from_array(
        [
        0x29787913470259aee2641be22694c6, 0xec09bc1e2d77c6585d183298e7821f, 0x44b3474a5a85c68fd5b1c0d58b8a14, 0xb4305577f64847c7365e4c50bd3ce6, 0x6fa468f111116d3b240bc26a6f7aa1, 0xfa4e31aea797f4e13d832798e84698, 0x318e9578a49fa2cfea99f604597688, 0xc8be4cf64d62c6342b7ee14be70cb5, 0xc7a942ab90fbff9e8791d6a24ae841, 0xd75dc97acf08b6c3d6fbe52ed2d025, 0x06708e15a6d7649eac7c37ab06c9d6, 0xc5602556b8d74f4e98983b65eb698b, 0xd1ce86b68f8737ef86c35344f4d55e, 0xff6c2b0f9e8a62758c36bdcfe31ce9, 0xbadab8d8f0a51ff4d8d94600eb7c58, 0xcefdcd5b6b58a024020ee703e313b3, 0x0a1a27008f49
    ]
    );

    let rsa: RSA1964 = RSA {};
    assert(rsa.verify_sha256_pss(BNInstance, sha256_hash, signature, 1964));
}

// Test an edge case where the key length in bytes is greater than the encoded message length
#[test]
fn test_verify_sha256_pss_1025() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
    let BNInstance: BNInst1025 = BigNumInstance::new(
        [
        0xaf85e53c4a91594f53511cd0e31935, 0x3f1a6f7232de53b8e8f075b6a3255a, 0x5d0f4f309b50b941e81b9d9d7e0364, 0x62a7e60f9aebbcd2db80809794b70f, 0xf24315c4e69e164e614c80f80dc4e2, 0x473400e641fb7a6b7a501242aa6815, 0xe730eb24ffe6e87bccf85e1e51de5d, 0x7ef4a0642a5c91a8a1aace977a0de7, 0x19e161fb03d331727
    ],
        [
        0x3d7911a3b192c0efffc574af224d4, 0xb494691ec48cdd2431e652bc6c74d7, 0x6b834607b80ce1f23ced01292df8af, 0x5a9936397b92b1802bc92a8165f1a7, 0x6392a3c0de8280cabbc562ce47c90b, 0x80b65d80217ffd1325d40ba739d70e, 0xa8810d2055f941b137eb21f9b58c3c, 0x6220993e32e55cda527741114bf51a, 0x27910dff60925c592
    ]
    );
    let signature: BN1025 = BigNum::from_array(
        [
        0x577f3f0b0fb8562169a0e15bd1c464, 0x67fecee7f7b7a447cbf37113604abb, 0x2955ac083854e3c3df1bd086b282c5, 0xe04c2e7d863e232e8499b334b85b4f, 0x7401d581dd3982d024bbfea9006084, 0x6a72f4117c02af92da185dbd0ce150, 0x34ec364bca2403037e52322cbc798e, 0xf3f8efbb3fb4eff880d9ae565e64fe, 0x57e81dd84359d0f2
    ]
    );

    let rsa: RSA1025 = RSA {};
    assert(rsa.verify_sha256_pss(BNInstance, sha256_hash, signature, 1025));
}
