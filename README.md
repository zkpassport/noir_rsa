# noir_rsa

Optimized Noir library that evaluates RSA signatures.

This library supports verification of RSA signatures for both standard padding schemes, PKCS#1 v1.5 and PSS (Probabilistic Signature Scheme), across the SHA-1, SHA-256, SHA-384, and SHA-512 hash functions. Key sizes are generic and cover the standard RSA modulus sizes, with convenience types provided for the common ones.

This library uses [noir-bignum](https://github.com/zkpassport/noir-bignum) as a dependency for big number arithmetic operations.

## Supported Schemes

### Padding Schemes

- **PKCS#1 v1.5**: the deterministic `RSASSA-PKCS1-v1_5` scheme
- **PSS**: the probabilistic `RSASSA-PSS` scheme (salted, uses MGF1)

### Hash Functions

- **SHA-1** (20-byte digest)
- **SHA-256** (32-byte digest)
- **SHA-384** (48-byte digest)
- **SHA-512** (64-byte digest)

### Key Sizes and Exponents

- **Generic modulus bit length**, parameterized by the `NumLimbs` and `ModBits` generics, covering the standard RSA key sizes. Convenience types are provided for 1024, 1025, 1964, 2048, and 4096-bit keys (see `src/types.nr`). Note that this is bounded by noir-bignum: its modular multiplication is no longer fully complete for very large moduli (around 8000 bits), so such sizes are not supported.
- **Any public exponent in the range `[2, 2^17 - 1]`**, which covers the exponents used in practice (e.g. 3 and 65537).

## Noir version compatibility

This library requires Noir `v1.0.0-beta.21` or later. Earlier releases will not build/pass the test suite.

## Installation

In your `Nargo.toml` file, add the version of this library you would like to install under dependency:

```toml
[dependencies]
noir_rsa = { tag = "v0.12.0", git = "https://github.com/zkpassport/noir_rsa" }
bignum = { tag = "v0.10.0-2", git = "https://github.com/zkpassport/noir-bignum" }
```

## Usage

### Basic Usage

The library provides a verification function for each combination of padding scheme and hash function, exposed under `noir_rsa::rsa`. Each returns a `bool` that you must `assert`. Here are examples for the two padding schemes using SHA-256; the other hash variants follow the same shape.

> The same functions are also available under the per-scheme modules `noir_rsa::pkcs1v15` and `noir_rsa::pss` if you prefer to import them from there.

#### PKCS#1 v1.5 (SHA-256)

```rust
use noir_rsa::rsa::verify_sha256_pkcs1v15;
use noir_rsa::types::{Params2048, RBN2048};
use bignum::params::BigNumParams;
use bignum::RuntimeBigNum;

// The SHA-256 hash of the signed message (computed by the caller)
let message_hash: [u8; 32] = [/* your 32-byte hash */];

// The RSA public key, expressed as bignum params (modulus + reduction parameter)
let params: Params2048 = BigNumParams::new(false, modulus_limbs, redc_param_limbs);

// The signature, as a RuntimeBigNum over that modulus
let signature: RBN2048 = RuntimeBigNum { params, limbs: signature_limbs };

// The public exponent (commonly 3 or 65537)
let exponent: u32 = 65537;

let is_valid = verify_sha256_pkcs1v15(message_hash, signature, exponent);
assert(is_valid);
```

#### PSS (SHA-256)

PSS is probabilistic, so verification additionally takes the `salt_len` (in bytes) that the signer used.

```rust
use noir_rsa::rsa::verify_sha256_pss;
use noir_rsa::types::{Params2048, RBN2048};
use bignum::params::BigNumParams;
use bignum::RuntimeBigNum;

let message_hash: [u8; 32] = [/* your 32-byte hash */];
let params: Params2048 = BigNumParams::new(false, modulus_limbs, redc_param_limbs);
let signature: RBN2048 = RuntimeBigNum { params, limbs: signature_limbs };
let exponent: u32 = 65537;
let salt_len: u32 = 32; // must match the salt length used by the signer

let is_valid = verify_sha256_pss(message_hash, signature, exponent, salt_len);
assert(is_valid);
```

### Variable Hash Sizes

There is one function per supported hash. The message hash array size is what selects the hash, and for PKCS#1 v1.5 the hash identity is additionally pinned by the embedded ASN.1 DigestInfo prefix.

```rust
use noir_rsa::rsa::{
    // PKCS#1 v1.5
    verify_sha1_pkcs1v15,   // msg_hash: [u8; 20]
    verify_sha256_pkcs1v15, // msg_hash: [u8; 32]
    verify_sha384_pkcs1v15, // msg_hash: [u8; 48]
    verify_sha512_pkcs1v15, // msg_hash: [u8; 64]
    // PSS (each additionally takes a `salt_len: u32`)
    verify_sha1_pss,   // msg_hash: [u8; 20]
    verify_sha256_pss, // msg_hash: [u8; 32]
    verify_sha384_pss, // msg_hash: [u8; 48]
    verify_sha512_pss, // msg_hash: [u8; 64]
};
```

## Security Features

### Input Assumptions

- **The message hash must be computed by the caller.** The verification functions take the digest, not the message, and each function fixes the hash algorithm (e.g. `verify_sha256_*` expects a SHA-256 digest). For PKCS#1 v1.5 the hash identity is further pinned by the ASN.1 DigestInfo prefix, so passing, say, a SHA-256 digest to the SHA-512 verifier fails.
- **The public exponent is constrained to `[2, 2^17 - 1]`.** Exponent `1` is rejected (it would make the signature equal to the encoded message and accept trivially), and exponents `>= 2^17` fail a range check. The standard exponents `3` and `65537` are within range.
- **`signature` must be a valid field element.** Build the `RuntimeBigNum` with the correct `BigNumParams` (modulus and Barrett reduction parameter). If the signature was not already validated, either call `validate_in_field` on it, or construct it with noir-bignum's `from_be_bytes` / `from_le_bytes`, which range-check the value into the field. Skipping this on an unchecked, byte-imported value can let an out-of-range limb encoding through.
- **The modulus (public key) must NOT be a free private witness.** This is a soundness requirement, not a nicety. The library verifies the signature against whatever `BigNumParams` modulus you hand it, and does nothing to pin that modulus down. If `params` is supplied as a private, prover-controlled input, verification is **unsound**: an attacker can choose a modulus for which they can produce a valid signature over any message (e.g. one whose factorization they know, or one crafted so `sig^e mod n` equals the target encoded message) and thereby prove a "valid signature" for arbitrary data. Always bind the modulus to something the verifier trusts, e.g. expose it as a public input, hash it into the public inputs, or check it against a trusted key registry.
- **PSS `salt_len` is a caller input** and must equal the salt length used by the signer, and be at most `MAX_SALT_LEN` (64 bytes). A mismatched salt length fails verification.
- **The return value is a `bool` that you must `assert`.** Calling a `verify_*` function without asserting its result constrains nothing.

## Examples

See the test functions under `src/tests/` for complete working examples of each scheme, hash, and key size. Each test sets up the public key params, the signature, and the message hash, then asserts the verification result.

To run the tests:

```bash
nargo test
```

## Algorithm Details

### PKCS#1 v1.5

1. **Validate the exponent**: constrain `e` to `[2, 2^17 - 1]`, which rejects `e = 1` (it would accept the signature as the encoded message) and exponents that are out of range.
2. **Exponentiate**: recover the encoded message `EM = sig^e mod n`.
3. **Convert** `EM` to bytes.
4. **Compare against the expected structure** `0x00 || 0x01 || PS(0xFF..) || 0x00 || DigestInfo || H`: check the message-hash bytes, the ASN.1 DigestInfo prefix, the `0x00` separator, and the `0xFF` padding string.

### PSS

1. **Validate the exponent**: constrain `e` to `[2, 2^17 - 1]`, which rejects `e = 1` and exponents that are out of range.
2. **Exponentiate**: recover the encoded message `EM = sig^e mod n`.
3. **Parse** `EM = maskedDB || H || 0xBC`; verify the trailing `0xBC` and the leftmost-zero-bits requirement.
4. **Bound the salt**: check `salt_len <= MAX_SALT_LEN` and `emLen >= hLen + salt_len + 2`.
5. **Unmask**: `dbMask = MGF1(H)`, `DB = maskedDB XOR dbMask`, then clear the leftmost bits of `DB` per the spec.
6. **Check** `DB = PS(0x00..) || 0x01 || salt` and extract the `salt`.
7. **Recompute and compare**: `H' = Hash(0x00 * 8 || message_hash || salt)` and verify `H' == H`.

Where `e` is the public exponent, `n` is the modulus, and `H` is the hash embedded in the signature.

## Benchmarks

The benchmarking source code and its details can be found in [this repository](https://github.com/hashcloak/noir_rsa_bench).

For the results, "UP" stands for UltraPlonk and "UH" stands for UltraHonk.

The benchmark results for the verification of one signature are the following:

| **Bit length** | **Circuit size** | **Avg. proving time (UP) [ms]** | **Avg. proving time (UH) [ms]** |
| -------------- | ---------------- | ------------------------------- | ------------------------------- |
| 1024           | 2204             | 234.8                           | 181                             |
| 2048           | 7131             | 345.6                           | 261.9                           |

Also, the results for the verification of 10 signatures are the following:

| **Bit length** | **Circuit size** | **Avg. proving time (UP) [ms]** | **Avg. proving time (UH) [ms]** |
| -------------- | ---------------- | ------------------------------- | ------------------------------- |
| 1024           | 21516            | 970.9                           | 514.4                           |
| 2048           | 63821            | 1801.7                          | 964.2                           |

The benchmarks were executed using a laptop with Intel(R) Core(TM) i7-13700H CPU and 32 GB of RAM.

## End-to-end example

### Generate an RSA signature

To verify an RSA signature, you first need a signature.

Depending on the application you are building, you might be expecting user signatures from existing signing services (e.g. emails, passports, git commits), or you might be building the ability for users to sign directly in your application.

Either way, you are free to choose how you collect / generate the signatures as long as they comply with the RSA cryptography specifications (ex. by following <https://docs.rs/rsa/latest/rsa/>).

You need to install Rustup and run it in order to install Rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup
```

Then move into the `signature_gen` folder and run `cargo run`, optionally with the message to sign:

```bash
cd signature_gen
cargo run # or cargo run -- --msg "hello world!"
```

The program prints the hash of the message, the RSA signature, and the BigNumber instance you should use, parsed into a format ready to be used in this library.

### Prove it

Run `nargo check` to initialize `Prover.toml`, paste in the generated values, then execute and prove with, for example, barretenberg:

```bash
nargo execute rsa
bb prove -b ./target/example.json -w ./target/rsa.gz -o ./target/proof
```

### Verify it

Export the verification key and verify the proof:

```bash
bb write_vk -b ./target/example.json -o ./target/vk
bb verify -k ./target/vk -p ./target/proof
```

## Contributing

We welcome contributions! Please feel free to submit issues and pull requests.

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
