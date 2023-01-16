# Changelog

## 0.6 (2023-01-16)

* Update to `signature` 2.0.

## 0.5.2 (2022-09-26)

* Switch to `libpicnic-sys`

## 0.5.1 (2022-08-31)

* Add optional dependency in `zeroize` and implement `Zeroize` and `ZeroizeOnDrop` for private keys.
* Remove implicit features from optional dependencies.
* Require Rust 1.60.

## 0.5 (2022-08-19)

* Never print private keys.
* Remove `Signer` trait.
* Implement `Verifier` trait for private keys.

## 0.4.2 (2022-04-05)

* Extend the documentation with an example for `RawVerifier`.
* Refactor serialization (no functional change).

## 0.4.1 (2021-12-06)

* Add `RawVerifier` trait and implementations for `VerificationKey<P>` and `DynamicVerificationKey`.

## 0.4 (2021-12-06)

* Make it possible to build as `no_std` crate. The `alloc` crate is still required, though.
* Implement serialization with `serde`.
* Implement constant-time comparison for `SigningKey<P>` using `subtle`.
* Bump edition to 2021 and require Rust 1.56.

## 0.3 (2021-11-05)

* Provide conversion from/to `&[u8]` for `DynamicSigningKey` and `DynamicVerificationKey`.
* Rework error handling once again and follow `signature`'s example. `Error` is now `signature::Error`.
* Use Newtype pattern to wrap private and public keys. This reduces the amount of duplicated code a bit.
* Require `picnic-sys` 3.0.5.
* Require Rust 1.47.

## 0.2 (2021-10-21)

* Add `static-fallback` to the default features.
* Rework error handling. `Error` is now an enum to cover more error cases.

## 0.1.1 (2021-10-20)

* Remove superfluous parameter
* Require `picnic-sys` 3.0.3.

## 0.1 (2021-10-19)

* Initial release.
