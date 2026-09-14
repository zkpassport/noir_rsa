use bignum::RuntimeBigNum;

// Backward-compatible re-exports. Before the pkcs1v15/pss split these verification
// functions lived in this module, so consumers imported them as `noir_rsa::rsa::verify_*`.
// Re-export them here so that path keeps resolving; the same functions are also available
// under `noir_rsa::pkcs1v15::*` and `noir_rsa::pss::*`.
pub use crate::pkcs1v15::{
    verify_sha1_pkcs1v15, verify_sha256_pkcs1v15, verify_sha384_pkcs1v15, verify_sha512_pkcs1v15,
};
pub use crate::pss::{verify_sha1_pss, verify_sha256_pss, verify_sha384_pss, verify_sha512_pss};

/// Raise a signature to a public exponent using binary (square-and-multiply)
/// modular exponentiation.
///
/// The exponent is a runtime value, constrained to [2, 2^17 - 1]. That range
/// covers the public exponents RSA certificates use in practice (e.g. 3 and 65537).
pub(crate) fn exponentiate_signature<let NumLimbs: u32, let ModBits: u32>(
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
) -> RuntimeBigNum<NumLimbs, ModBits> {
    // Constrain the exponent to [2, 2^17 - 1].
    // Lower bound: for exponent < 2 the subtraction wraps modulo the field prime,
    // producing a large value that fails the 17-bit range check.
    (exponent as Field - 2).assert_max_bit_size::<17>();
    // Upper bound: exponent < 2^17.
    (exponent as Field).assert_max_bit_size::<17>();

    // The exponent is < 2^17, so 17 bits describe it fully. Decompose it up front
    // (least-significant bit first) so the loop can read each bit directly instead
    // of doing a division every iteration.
    let bits: [bool; 17] = (exponent as Field).to_le_bits::<17>();

    // Binary exponentiation (square-and-multiply algorithm)
    let mut result = RuntimeBigNum::one(sig.params);
    let mut base = sig;

    for i in 0..17 {
        // If bit i is set, multiply the result by the current base, which is sig^(2^i).
        if bits[i] {
            result = result * base;
        }
        // Square the base to get sig^(2^(i+1)) for the next bit. Skip on the last
        // iteration: sig^(2^17) is never used, so that squaring would be wasted.
        if i != 16 {
            base = base * base;
        }
    }
    result
}
