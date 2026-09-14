use crate::rsa::exponentiate_signature;
use crate::types::{Params1024, RBN1024};
use bignum::params::BigNumParams;
use bignum::RuntimeBigNum;

fn params_and_base() -> (Params1024, RBN1024) {
    let params: Params1024 = BigNumParams::new(
        false,
        [
            0xb55d751aa6aedcf6a8c8fee667e7b5,
            0x946509cdfc0a3e712cf877e27d2a6d,
            0xe72cefb6fc013a8eb46a00e4c5e497,
            0xd37ad9e73fb8ffc6a7deb16e5def1,
            0x78adebc1a04e6df77e1cf263bf6db3,
            0x5c543fd771e19553ed1490b8d71157,
            0x6af24bdfa68c92d8dca8fd1ffb5527,
            0x181aef81f10ae24e1a6c6e964d082c,
            0x8cfb9a9226f4655d,
        ],
        [
            0x4c3e9d3d7a1e6a979ffb7e0afc0b39,
            0x11d1fe48342dbb40d29fcdd3ebbda2,
            0xdc537fa4b3b761bf4bcf91ef12dd47,
            0x44004739c56e0d50f4cbb56f11a58c,
            0x5c28123a6816842ad7a9863b261e46,
            0xc70fe49269327a789f4f59186a1244,
            0x8fcc0f512cf911f53cc1994e1a77a6,
            0x41f8f717ae6aeea4dae06a64a25728,
            0x743675d2f60309b331,
        ],
    );
    let base: RBN1024 = RuntimeBigNum {
        params,
        limbs: [
            0x61275c9e6b6cf8950e87d7f5606617,
            0xa290a9eab7061f00bca0042db9232c,
            0x4cc4fd394d4c10a4fe30cffdda6dbc,
            0x6c8042c56814a2bc786a6d2df26fff,
            0xa4666d54760e7fbc051c6ca26b351e,
            0x13e529610ae0eed8f1e7d4c08880a5,
            0x9d6c50afb6e9fb123dc34bd8e2fe52,
            0x4e385994ebac94af6f28d015a2aa0b,
            0x194f9545adba52ce,
        ],
    };
    (params, base)
}

// e = 3
#[test]
fn test_exponentiate_signature_e3() {
    let (params, base) = params_and_base();
    let expected: RBN1024 = RuntimeBigNum {
        params,
        limbs: [
            0xc3ec36fe3c96e29bcb13e34a0255df,
            0xc054adccf966bf2fd397e8eabaa9e5,
            0xe4ccd20d50db5424a629ff73820082,
            0x87e2056d1bf9c1847646adb958cf26,
            0x1deeb19524b91c86c96de34302d461,
            0x963fff20382b8a49a833e1f3969d21,
            0xffb387d53b1269ae4d09b5a632e556,
            0x141c465e99febceaae3f3eddfdea1e,
            0x1ffa7032ac48d03d,
        ],
    };
    assert(exponentiate_signature(base, 3) == expected);
}

// e = 0x10001
#[test]
fn test_exponentiate_signature_e65537() {
    let (params, base) = params_and_base();
    let expected: RBN1024 = RuntimeBigNum {
        params,
        limbs: [
            0xb8dce986fbb83e213fc81e39473b1e,
            0x4bae6aeb42305e3d414ae7f4405e18,
            0x7829dfb645f34580d591afc4fcee56,
            0x83176dc6d93e9e5cc96c0b70e910d8,
            0x5d08fad33f30f1f986137485d88fcc,
            0x9fb26536d352b9dfc072ebbdbc19f4,
            0xb0befea295aeb1bcb2a8510d97293,
            0x4b2dd070ee2d8889375aa6026d71b4,
            0x3bb4c3b3f8c003b4,
        ],
    };
    assert(exponentiate_signature(base, 65537) == expected);
}

// e = 45345 (a random exponent in [2, 2^17), covers an arbitrary bit pattern)
#[test]
fn test_exponentiate_signature_random() {
    let (params, base) = params_and_base();
    let expected: RBN1024 = RuntimeBigNum {
        params,
        limbs: [
            0x56afffc8db956bd9b16069237adde7,
            0xb85803d7c171365997966320673409,
            0x78cfa8b8b2ff11b1480731fee2d51a,
            0xa9d5a13db1a2b2944e19ca434d69ef,
            0x836a611c3e855886300875eca7d7f,
            0x9503058ee99b07e41971c653708f21,
            0x3cbc7828aa19e3aec375208b185c6f,
            0x5fb29f77866a8f7568535e656276b7,
            0x1901d94cf813eac2,
        ],
    };
    assert(exponentiate_signature(base, 45345) == expected);
}
