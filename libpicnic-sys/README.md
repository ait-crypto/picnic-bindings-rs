# Declarations for the Picnic digital signature scheme

This crate provides the declarations to interact with the shared library of the [optimized implementation](https://github.com/IAIK/Picnic) of the [Picnic](https://microsoft.github.io/Picnic/) digital signature scheme.

Per default, it is required that Picnic's shared library is installed. To fall back to an on-demand static build, enable the `static-fallback` feature.

## Features

This crate supports the following features:
* `param-bindings`: Produce bindings for parameter set specific functions.
* `picnic3` (default): Enable Picnic3 parameter sets.
* `picnic` (default): Enable Picnic parameter sets.
* `vendored` (default): Use vendored copy of `libpicnic` library if not found otherwise.
* `system` (default): Check for `libpicnic` via `pkg-config`.
* `unruh-transform`: Enable Picnic parameter sets with Unruh transform.

## License

This crate is licensed under the MIT license. For Picnic's license, please check its [license file](https://github.com/IAIK/Picnic/blob/master/LICENSE).
