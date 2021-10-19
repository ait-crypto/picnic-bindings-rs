# Bindings for the Picnic digital signature scheme

This crate provides bindings for the [optimized implementation](https://github.com/IAIK/Picnic) of the [Picnic](https://microsoft.github.io/Picnic/) digital signature scheme. It implements the traits of the [signature](https://crates.io/crates/signature) crate.

Per default, it is required that Picnic's shared library is installed. To fall back to a static  build, enable the `static-fallback` feature.

## Features

This crate supports the following features:
* `picnic` (default): Enable the Picnic parameter sets with ZKB++/Fiat-Shamir as proof system.
* `unruh-transform`: Enable the Picnic parameter sets with ZKB++/Unruh as proof system.
* `picnic3` (default): Enable the Picnic parameter sets with KKW/Fiat-Shamir as proof system.
* `system` (default): Use the shared library of Picnic per default.
* `static-fallback`: Build Picnic on demand if shared library is not available.

## Security Notes

This crate has received no security audit. Use at your own risk.

## License

This crate is licensed under the MIT license.
