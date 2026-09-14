# Changelog

## [0.8.0](https://github.com/zkpassport/noir_rsa/compare/v0.7.0...v0.8.0) (2026-09-14)


### ⚠ BREAKING CHANGES

* bump bignum to `v0.6.0` ([#47](https://github.com/zkpassport/noir_rsa/issues/47))
* bump bignum to `v0.5.4` ([#45](https://github.com/zkpassport/noir_rsa/issues/45))
* bump `noir-bignum` to `v0.5.0` ([#40](https://github.com/zkpassport/noir_rsa/issues/40))
* update to noir-bignum v0.4.1 ([#30](https://github.com/zkpassport/noir_rsa/issues/30))

### Features

* Add support for public exponent 3 ([882fcc5](https://github.com/zkpassport/noir_rsa/commit/882fcc5e064b5ff29f4ef72e5cf2c2ad092e581d))
* Add support for public exponent 3 ([41f0d0d](https://github.com/zkpassport/noir_rsa/commit/41f0d0d72dc13bc3a972a7d57f3a486125a21707))
* Bump `bignum` to `v0.5.2` ([#43](https://github.com/zkpassport/noir_rsa/issues/43)) ([1000347](https://github.com/zkpassport/noir_rsa/commit/10003472e526e477aa433eff49410f4980e96db9))
* Bump `noir-bignum` to `v0.5.0` ([#40](https://github.com/zkpassport/noir_rsa/issues/40)) ([068cf97](https://github.com/zkpassport/noir_rsa/commit/068cf971a6670d9075eb2a4febfb300fb79d4186))
* **optimization:** Simplification of `verify_sha256_pkcs1v15` logic ([9e2dbd3](https://github.com/zkpassport/noir_rsa/commit/9e2dbd327a00e0ab2413bdeb3fd71dce74631a7b))
* Reorg, adding an example, refactoring the readme ([0e18d18](https://github.com/zkpassport/noir_rsa/commit/0e18d18815f571233151171a7d5909613b5116a6))
* Rsa pss - increase limit to 4096 bit RSA ([7dfad51](https://github.com/zkpassport/noir_rsa/commit/7dfad514dbbb66be8f1beca84a7fc0a0b91c2420))
* Support for sha256 rsa pss signatures ([4298055](https://github.com/zkpassport/noir_rsa/commit/4298055c39b02eafc71f04924a2065de01dad90b))
* Switch to a more generic exponentation algorithm to support all exponents up to 2^17 ([c00717a](https://github.com/zkpassport/noir_rsa/commit/c00717a18e7c5c36356797301bc256dee2ed90d8))
* Update to bignum `v0.4.2` ([#32](https://github.com/zkpassport/noir_rsa/issues/32)) ([536c436](https://github.com/zkpassport/noir_rsa/commit/536c436412240b3b53682d0898a35690327dc2dc))
* Update to noir-bignum 0.3.6 and nargo 0.35.0 ([#23](https://github.com/zkpassport/noir_rsa/issues/23)) ([8784b19](https://github.com/zkpassport/noir_rsa/commit/8784b1910ccc4c0eda0a75f1a40d416162487335))
* Update to noir-bignum v0.4.1 ([#30](https://github.com/zkpassport/noir_rsa/issues/30)) ([e54d13d](https://github.com/zkpassport/noir_rsa/commit/e54d13dd71c83eb926cdfdb5a6ae37e242461a91))


### Bug Fixes

* Correct Params1964/RBN1964 modulus size and enable 1964 test ([b37ffa4](https://github.com/zkpassport/noir_rsa/commit/b37ffa4cb86ff2533d08ac4a0cf72817927e1617))
* Correct sha384 pss out-of-bounds and generalize pss verification ([58a1a73](https://github.com/zkpassport/noir_rsa/commit/58a1a73af6c52bf16b71a8147dfe153108318c41))
* Issue with rsa pss and modulus size not divisible by 8 ([6dbd432](https://github.com/zkpassport/noir_rsa/commit/6dbd4326cfa2436d343ab5217b9d22741c7d4c32))
* Rsa pss - calculate offset for encoded message correctly ([de24840](https://github.com/zkpassport/noir_rsa/commit/de24840e3c974d84dcbc97156246ef816fdb5744))
* Rsa pss - wrong index for masked db bit check ([71c81a5](https://github.com/zkpassport/noir_rsa/commit/71c81a5b148994fd322b99b7a68571d06889f4ff))
* Switch to u32 numeric generics and update to 0.3.0 bignum ([46a6eb1](https://github.com/zkpassport/noir_rsa/commit/46a6eb1ffbaa0c5d57e3382af0268c069eace591))
* Update bignum dependency ([#18](https://github.com/zkpassport/noir_rsa/issues/18)) ([499a7f8](https://github.com/zkpassport/noir_rsa/commit/499a7f81348a7ba03120801cd2a1a4e091ab0ed5))


### Miscellaneous Chores

* Bump bignum to `v0.5.4` ([#45](https://github.com/zkpassport/noir_rsa/issues/45)) ([be8889d](https://github.com/zkpassport/noir_rsa/commit/be8889d0abf2629407e06d4aa4213d272c619428))
* Bump bignum to `v0.6.0` ([#47](https://github.com/zkpassport/noir_rsa/issues/47)) ([944c159](https://github.com/zkpassport/noir_rsa/commit/944c159ac8e0ed14a5d381421d0dd2248bc00940))

## [0.7.0](https://github.com/noir-lang/noir_rsa/compare/v0.6.0...v0.7.0) (2025-03-03)


### ⚠ BREAKING CHANGES

* bump bignum to `v0.6.0` ([#47](https://github.com/noir-lang/noir_rsa/issues/47))

### Miscellaneous Chores

* Bump bignum to `v0.6.0` ([#47](https://github.com/noir-lang/noir_rsa/issues/47)) ([944c159](https://github.com/noir-lang/noir_rsa/commit/944c159ac8e0ed14a5d381421d0dd2248bc00940))

## [0.6.0](https://github.com/noir-lang/noir_rsa/compare/v0.5.1...v0.6.0) (2025-02-18)


### ⚠ BREAKING CHANGES

* bump bignum to `v0.5.4` ([#45](https://github.com/noir-lang/noir_rsa/issues/45))

### Miscellaneous Chores

* Bump bignum to `v0.5.4` ([#45](https://github.com/noir-lang/noir_rsa/issues/45)) ([be8889d](https://github.com/noir-lang/noir_rsa/commit/be8889d0abf2629407e06d4aa4213d272c619428))

## [0.5.1](https://github.com/noir-lang/noir_rsa/compare/v0.5.0...v0.5.1) (2025-01-29)


### Features

* Bump `bignum` to `v0.5.2` ([#43](https://github.com/noir-lang/noir_rsa/issues/43)) ([1000347](https://github.com/noir-lang/noir_rsa/commit/10003472e526e477aa433eff49410f4980e96db9))

## [0.5.0](https://github.com/noir-lang/noir_rsa/compare/v0.4.1...v0.5.0) (2025-01-09)


### ⚠ BREAKING CHANGES

* bump `noir-bignum` to `v0.5.0` ([#40](https://github.com/noir-lang/noir_rsa/issues/40))

### Features

* Bump `noir-bignum` to `v0.5.0` ([#40](https://github.com/noir-lang/noir_rsa/issues/40)) ([068cf97](https://github.com/noir-lang/noir_rsa/commit/068cf971a6670d9075eb2a4febfb300fb79d4186))

## [0.4.1](https://github.com/noir-lang/noir_rsa/compare/v0.4.0...v0.4.1) (2024-12-04)


### Features

* Update to bignum `v0.4.2` ([#32](https://github.com/noir-lang/noir_rsa/issues/32)) ([536c436](https://github.com/noir-lang/noir_rsa/commit/536c436412240b3b53682d0898a35690327dc2dc))

## [0.4.0](https://github.com/noir-lang/noir_rsa/compare/v0.3.1...v0.4.0) (2024-11-08)


### ⚠ BREAKING CHANGES

* update to noir-bignum v0.4.1 ([#30](https://github.com/noir-lang/noir_rsa/issues/30))

### Features

* Update to noir-bignum 0.3.6 and nargo 0.35.0 ([#23](https://github.com/noir-lang/noir_rsa/issues/23)) ([8784b19](https://github.com/noir-lang/noir_rsa/commit/8784b1910ccc4c0eda0a75f1a40d416162487335))
* Update to noir-bignum v0.4.1 ([#30](https://github.com/noir-lang/noir_rsa/issues/30)) ([e54d13d](https://github.com/noir-lang/noir_rsa/commit/e54d13dd71c83eb926cdfdb5a6ae37e242461a91))

## [0.3.1](https://github.com/noir-lang/noir_rsa/compare/v0.3.0...v0.3.1) (2024-10-04)


### Bug Fixes

* Update bignum dependency ([#18](https://github.com/noir-lang/noir_rsa/issues/18)) ([499a7f8](https://github.com/noir-lang/noir_rsa/commit/499a7f81348a7ba03120801cd2a1a4e091ab0ed5))
