use bignum::RuntimeBigNum;

/**
 * @brief Exponentiate a signature by a given exponent using binary exponentiation
 * @details This function handles the exponentiation of a signature by any given exponent.
 * Uses the square-and-multiply algorithm for efficient modular exponentiation.
 * @param sig The signature to exponentiate
 * @param exponent The exponent to use (any positive integer)
 * @return The exponentiated signature
 */
pub(crate) fn exponentiate_signature<let NumLimbs: u32, let ModBits: u32>(
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
