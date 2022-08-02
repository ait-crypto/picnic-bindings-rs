# Changelog

## 3.0.16 (2022-08-02)

* Bump Picnic to 3.0.16.

## 3.0.15 (2022-06-29)

* Bump Picnic to 3.0.15.
* Add more tests.
* Enable stack protector.

## 3.0.14 (2022-04-15)

* Disable use of `__builtin_cpu_supports`. When cross compiling, the toolchain does not seem to link the necessary libraries.

## 3.0.13 (2022-04-15)

* Bump Picnic to 3.0.13.
* Fix AVX2/SSE2/NEON activation while cross compiling.

## 3.0.12 (2022-04-05)

* Bump Picnic to 3.0.12.

## 3.0.11 (2022-01-31)

* Bump Picnic to 3.0.11.

## 3.0.8 (2021-12-17)

* Bump Picnic to 3.0.8.
* Remove unused `doc-rs` feature.

## 3.0.7 (2021-12-15)

* Bump Picnic to 3.0.6.

## 3.0.6 (2021-11-09)

* Do not set `no_std` if building tests.

## 3.0.5 (2021-11-05)

* Add new constants from Picnic 3.0.5.

## 3.0.4 (2021-10-21)

* Make crate self-contained by including Picnic's 3.0.5 source.

## 3.0.3 (2021-10-20)

* Add new functions introduced in Picnic 3.0.5.

## 3.0.2 (2021-10-19)

* Skip the build when build building for docs.rs.

## 3.0.1 (2021-10-19)

* Fix the docs.rs build.

## 3.0 (2021-10-19)

* Initial release compatible with Picnic 3.0.
