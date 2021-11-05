# Changelog

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
