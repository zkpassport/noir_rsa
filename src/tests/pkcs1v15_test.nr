use crate::types::{
    Params1024, Params1025, Params2048, Params4096, RBN1024, RBN1025, RBN2048, RBN4096,
};

use crate::pkcs1v15::{verify_sha1_pkcs1v15, verify_sha384_pkcs1v15, verify_sha512_pkcs1v15};
// verify_sha256_pkcs1v15 is imported through the backward-compatible `noir_rsa::rsa::*`
// re-export path so that path stays covered by the test suite.
use crate::rsa::verify_sha256_pkcs1v15;

use bignum::params::BigNumParams;
use bignum::RuntimeBigNum;

use sha1::sha1;
use sha512::{sha384, sha512};

#[test]
fn test_verify_sha256_pkcs1v15_1024() {
    // Output of `cargo run -- --msg "hello world! test#123" --bits 1024` in the `signature_gen` directory
    let sha256_hash: [u8; 32] = [
        220, 155, 229, 143, 122, 133, 55, 215, 75, 44, 132, 111, 57, 33, 248, 84, 213, 170, 193, 96,
        253, 57, 124, 13, 251, 42, 92, 147, 105, 172, 233, 85,
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
        91, 207, 46, 60, 22, 153, 217, 144, 2, 127, 224, 143, 181, 45, 32, 120, 122, 131, 166, 79,
        166, 183, 43, 158, 116, 105, 73, 207, 196, 77, 33, 5,
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
        185, 77, 39, 185, 147, 77, 62, 8, 165, 46, 82, 215, 218, 125, 171, 250, 196, 132, 239, 227,
        122, 83, 128, 238, 144, 136, 247, 172, 226, 239, 205, 233,
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
    let sha256_hash: [u8; 32] = sha256::sha256_var("Hello World! This is Noir-RSA".as_bytes(), 29);

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
    let sha256_hash: [u8; 32] = sha256::sha256_var("Hello World! This is Noir-RSA".as_bytes(), 29);

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
        0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab,
        0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef,
        0xcd, 0xe9,
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
