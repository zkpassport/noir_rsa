# Changelog

## [0.3.2](https://github.com/madztheo/noir_rsa/compare/v0.3.1...v0.3.2) (2024-10-30)


### Features

* Add support for public exponent 3 ([41f0d0d](https://github.com/madztheo/noir_rsa/commit/41f0d0d72dc13bc3a972a7d57f3a486125a21707))
* **optimization:** Simplification of `verify_sha256_pkcs1v15` logic ([9e2dbd3](https://github.com/madztheo/noir_rsa/commit/9e2dbd327a00e0ab2413bdeb3fd71dce74631a7b))
* Rsa pss - increase limit to 4096 bit RSA ([7dfad51](https://github.com/madztheo/noir_rsa/commit/7dfad514dbbb66be8f1beca84a7fc0a0b91c2420))
* Support for sha256 rsa pss signatures ([4298055](https://github.com/madztheo/noir_rsa/commit/4298055c39b02eafc71f04924a2065de01dad90b))
* Update to noir-bignum 0.3.6 and nargo 0.35.0 ([#23](https://github.com/madztheo/noir_rsa/issues/23)) ([8784b19](https://github.com/madztheo/noir_rsa/commit/8784b1910ccc4c0eda0a75f1a40d416162487335))


### Bug Fixes

* Issue with rsa pss and modulus size not divisible by 8 ([6dbd432](https://github.com/madztheo/noir_rsa/commit/6dbd4326cfa2436d343ab5217b9d22741c7d4c32))
* Rsa pss - calculate offset for encoded message correctly ([de24840](https://github.com/madztheo/noir_rsa/commit/de24840e3c974d84dcbc97156246ef816fdb5744))
* Rsa pss - wrong index for masked db bit check ([71c81a5](https://github.com/madztheo/noir_rsa/commit/71c81a5b148994fd322b99b7a68571d06889f4ff))
* Update bignum dependency ([#18](https://github.com/madztheo/noir_rsa/issues/18)) ([499a7f8](https://github.com/madztheo/noir_rsa/commit/499a7f81348a7ba03120801cd2a1a4e091ab0ed5))

## [0.3.1](https://github.com/noir-lang/noir_rsa/compare/v0.3.0...v0.3.1) (2024-10-04)


### Bug Fixes

* Update bignum dependency ([#18](https://github.com/noir-lang/noir_rsa/issues/18)) ([499a7f8](https://github.com/noir-lang/noir_rsa/commit/499a7f81348a7ba03120801cd2a1a4e091ab0ed5))
