use crate::pkcs1v15::verify_sha256_pkcs1v15;
use crate::pss::verify_sha256_pss;
use crate::rsa::exponentiate_signature;
use bignum::{params::BigNumParams, RuntimeBigNum};

#[export]
fn exponentiate(base: RuntimeBigNum<18, 2048>, exponent: u32) -> RuntimeBigNum<18, 2048> {
    exponentiate_signature(base, exponent)
}

#[export]
fn exponentiate_const(base: RuntimeBigNum<18, 2048>) -> RuntimeBigNum<18, 2048> {
    exponentiate_signature(base, 0x10001)
}

#[export]
fn verify_sha256_pkcs1v15_2048(
    params: BigNumParams<18, 2048>,
    sha256_hash: [u8; 32],
    signature: [u128; 18],
    exponent: u32,
) {
    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum { params, limbs: signature };
    assert(verify_sha256_pkcs1v15(sha256_hash, signature, exponent));
}

#[export]
fn verify_sha256_pss_2048(
    params: BigNumParams<18, 2048>,
    sha256_hash: [u8; 32],
    signature: [u128; 18],
    exponent: u32,
) {
    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum { params, limbs: signature };
    assert(verify_sha256_pss(sha256_hash, signature, exponent, 32));
}

#[export]
fn verify_sha256_pkcs1v15_2048_const(
    params: BigNumParams<18, 2048>,
    sha256_hash: [u8; 32],
    signature: [u128; 18],
) {
    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum { params, limbs: signature };
    assert(verify_sha256_pkcs1v15(sha256_hash, signature, 0x10001));
}

#[export]
fn verify_sha256_pss_2048_const(
    params: BigNumParams<18, 2048>,
    sha256_hash: [u8; 32],
    signature: [u128; 18],
) {
    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum { params, limbs: signature };
    assert(verify_sha256_pss(sha256_hash, signature, 0x10001, 32));
}
