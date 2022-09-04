//! # Declarations for Picnic's shared library
//!
//! This crate provides declarations to call the functions from Picnic's shared library. The shared
//! library is available as part of the [optimized Picnic implementation](https://github.com/IAIK/Picnic).
//! More information on Picnic is available on the project website:
//! <https://microsoft.github.io/Picnic/>

#![cfg_attr(not(test), no_std)]
#![allow(non_upper_case_globals, non_camel_case_types)]

pub use libc::{c_char, c_int, size_t};
#[cfg(feature = "param-bindings")]
use paste::paste;
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const LOWMC_BLOCK_SIZE_Picnic_L1_FS: usize = 16;
pub const LOWMC_BLOCK_SIZE_Picnic_L1_UR: usize = 16;
pub const LOWMC_BLOCK_SIZE_Picnic_L3_FS: usize = 24;
pub const LOWMC_BLOCK_SIZE_Picnic_L3_UR: usize = 24;
pub const LOWMC_BLOCK_SIZE_Picnic_L5_FS: usize = 32;
pub const LOWMC_BLOCK_SIZE_Picnic_L5_UR: usize = 32;
pub const LOWMC_BLOCK_SIZE_Picnic3_L1: usize = 17;
pub const LOWMC_BLOCK_SIZE_Picnic3_L3: usize = 24;
pub const LOWMC_BLOCK_SIZE_Picnic3_L5: usize = 32;
pub const LOWMC_BLOCK_SIZE_Picnic_L1_full: usize = 17;
pub const LOWMC_BLOCK_SIZE_Picnic_L3_full: usize = 24;
pub const LOWMC_BLOCK_SIZE_Picnic_L5_full: usize = 32;
pub const PICNIC_SIGNATURE_SIZE_Picnic_L1_FS: usize = 34032;
pub const PICNIC_SIGNATURE_SIZE_Picnic_L1_UR: usize = 53961;
pub const PICNIC_SIGNATURE_SIZE_Picnic_L3_FS: usize = 76772;
pub const PICNIC_SIGNATURE_SIZE_Picnic_L3_UR: usize = 121845;
pub const PICNIC_SIGNATURE_SIZE_Picnic_L5_FS: usize = 132856;
pub const PICNIC_SIGNATURE_SIZE_Picnic_L5_UR: usize = 209506;
pub const PICNIC_SIGNATURE_SIZE_Picnic3_L1: usize = 14608;
pub const PICNIC_SIGNATURE_SIZE_Picnic3_L3: usize = 35024;
pub const PICNIC_SIGNATURE_SIZE_Picnic3_L5: usize = 61024;
pub const PICNIC_SIGNATURE_SIZE_Picnic_L1_full: usize = 32061;
pub const PICNIC_SIGNATURE_SIZE_Picnic_L3_full: usize = 71179;
pub const PICNIC_SIGNATURE_SIZE_Picnic_L5_full: usize = 126286;
pub const PICNIC_MAX_PUBLICKEY_SIZE: usize = 65;
pub const PICNIC_MAX_PRIVATEKEY_SIZE: usize = 97;
pub const PICNIC_PRIVATE_KEY_SIZE_Picnic_L1_FS: usize = 1 + 3 * LOWMC_BLOCK_SIZE_Picnic_L1_FS;
pub const PICNIC_PRIVATE_KEY_SIZE_Picnic_L1_UR: usize = 1 + 3 * LOWMC_BLOCK_SIZE_Picnic_L1_UR;
pub const PICNIC_PRIVATE_KEY_SIZE_Picnic_L3_FS: usize = 1 + 3 * LOWMC_BLOCK_SIZE_Picnic_L3_FS;
pub const PICNIC_PRIVATE_KEY_SIZE_Picnic_L3_UR: usize = 1 + 3 * LOWMC_BLOCK_SIZE_Picnic_L3_UR;
pub const PICNIC_PRIVATE_KEY_SIZE_Picnic_L5_FS: usize = 1 + 3 * LOWMC_BLOCK_SIZE_Picnic_L5_FS;
pub const PICNIC_PRIVATE_KEY_SIZE_Picnic_L5_UR: usize = 1 + 3 * LOWMC_BLOCK_SIZE_Picnic_L5_UR;
pub const PICNIC_PRIVATE_KEY_SIZE_Picnic3_L1: usize = 1 + 3 * LOWMC_BLOCK_SIZE_Picnic3_L1;
pub const PICNIC_PRIVATE_KEY_SIZE_Picnic3_L3: usize = 1 + 3 * LOWMC_BLOCK_SIZE_Picnic3_L3;
pub const PICNIC_PRIVATE_KEY_SIZE_Picnic3_L5: usize = 1 + 3 * LOWMC_BLOCK_SIZE_Picnic3_L5;
pub const PICNIC_PRIVATE_KEY_SIZE_Picnic_L1_full: usize = 1 + 3 * LOWMC_BLOCK_SIZE_Picnic_L1_full;
pub const PICNIC_PRIVATE_KEY_SIZE_Picnic_L3_full: usize = 1 + 3 * LOWMC_BLOCK_SIZE_Picnic_L3_full;
pub const PICNIC_PRIVATE_KEY_SIZE_Picnic_L5_full: usize = 1 + 3 * LOWMC_BLOCK_SIZE_Picnic_L5_full;
pub const PICNIC_PUBLIC_KEY_SIZE_Picnic_L1_FS: usize = 1 + 2 * LOWMC_BLOCK_SIZE_Picnic_L1_FS;
pub const PICNIC_PUBLIC_KEY_SIZE_Picnic_L1_UR: usize = 1 + 2 * LOWMC_BLOCK_SIZE_Picnic_L1_UR;
pub const PICNIC_PUBLIC_KEY_SIZE_Picnic_L3_FS: usize = 1 + 2 * LOWMC_BLOCK_SIZE_Picnic_L3_FS;
pub const PICNIC_PUBLIC_KEY_SIZE_Picnic_L3_UR: usize = 1 + 2 * LOWMC_BLOCK_SIZE_Picnic_L3_UR;
pub const PICNIC_PUBLIC_KEY_SIZE_Picnic_L5_FS: usize = 1 + 2 * LOWMC_BLOCK_SIZE_Picnic_L5_FS;
pub const PICNIC_PUBLIC_KEY_SIZE_Picnic_L5_UR: usize = 1 + 2 * LOWMC_BLOCK_SIZE_Picnic_L5_UR;
pub const PICNIC_PUBLIC_KEY_SIZE_Picnic3_L1: usize = 1 + 2 * LOWMC_BLOCK_SIZE_Picnic3_L1;
pub const PICNIC_PUBLIC_KEY_SIZE_Picnic3_L3: usize = 1 + 2 * LOWMC_BLOCK_SIZE_Picnic3_L3;
pub const PICNIC_PUBLIC_KEY_SIZE_Picnic3_L5: usize = 1 + 2 * LOWMC_BLOCK_SIZE_Picnic3_L5;
pub const PICNIC_PUBLIC_KEY_SIZE_Picnic_L1_full: usize = 1 + 2 * LOWMC_BLOCK_SIZE_Picnic_L1_full;
pub const PICNIC_PUBLIC_KEY_SIZE_Picnic_L3_full: usize = 1 + 2 * LOWMC_BLOCK_SIZE_Picnic_L3_full;
pub const PICNIC_PUBLIC_KEY_SIZE_Picnic_L5_full: usize = 1 + 2 * LOWMC_BLOCK_SIZE_Picnic_L5_full;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum picnic_params_t {
    PARAMETER_SET_INVALID = 0,
    Picnic_L1_FS = 1,
    Picnic_L1_UR = 2,
    Picnic_L3_FS = 3,
    Picnic_L3_UR = 4,
    Picnic_L5_FS = 5,
    Picnic_L5_UR = 6,
    Picnic3_L1 = 7,
    Picnic3_L3 = 8,
    Picnic3_L5 = 9,
    Picnic_L1_full = 10,
    Picnic_L3_full = 11,
    Picnic_L5_full = 12,
    PARAMETER_SET_MAX_INDEX = 13,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct picnic_publickey_t {
    pub data: [u8; PICNIC_MAX_PUBLICKEY_SIZE],
}

#[repr(C)]
#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct picnic_privatekey_t {
    pub data: [u8; PICNIC_MAX_PRIVATEKEY_SIZE],
}

extern "system" {
    pub fn picnic_get_param_name(parameters: picnic_params_t) -> *const c_char;
    pub fn picnic_get_private_key_size(parameters: picnic_params_t) -> size_t;
    pub fn picnic_get_public_key_size(parameters: picnic_params_t) -> size_t;
    pub fn picnic_keygen(
        parameters: picnic_params_t,
        pk: *mut picnic_publickey_t,
        sk: *mut picnic_privatekey_t,
    ) -> c_int;
    pub fn picnic_sign(
        sk: *const picnic_privatekey_t,
        message: *const u8,
        message_len: size_t,
        signature: *mut u8,
        signature_len: *mut size_t,
    ) -> c_int;
    pub fn picnic_signature_size(parameters: picnic_params_t) -> size_t;
    pub fn picnic_verify(
        pk: *const picnic_publickey_t,
        message: *const u8,
        message_len: size_t,
        signature: *const u8,
        signature_len: size_t,
    ) -> c_int;
    pub fn picnic_write_public_key(
        key: *const picnic_publickey_t,
        buf: *mut u8,
        buflen: size_t,
    ) -> c_int;
    pub fn picnic_read_public_key(
        key: *mut picnic_publickey_t,
        buf: *const u8,
        buflen: size_t,
    ) -> c_int;
    pub fn picnic_write_private_key(
        key: *const picnic_privatekey_t,
        buf: *mut u8,
        buflen: size_t,
    ) -> c_int;
    pub fn picnic_read_private_key(
        key: *mut picnic_privatekey_t,
        buf: *const u8,
        buflen: size_t,
    ) -> c_int;
    pub fn picnic_validate_keypair(
        privatekey: *const picnic_privatekey_t,
        publickey: *const picnic_publickey_t,
    ) -> c_int;
    pub fn picnic_clear_private_key(key: *mut picnic_privatekey_t);
    pub fn picnic_sk_to_pk(
        privatekey: *const picnic_privatekey_t,
        publickey: *mut picnic_publickey_t,
    ) -> c_int;
    pub fn picnic_get_private_key_param(privatekey: *const picnic_privatekey_t) -> picnic_params_t;
    pub fn picnic_get_public_key_param(publickey: *const picnic_publickey_t) -> picnic_params_t;
}

#[cfg(feature = "param-bindings")]
/// Define a parameters set and its associated implementations and types
macro_rules! define_types_and_functions {
    ($param:ident) => {
        paste! {
            #[repr(C)]
            #[derive(Debug, Copy, Clone)]
            pub struct [<$param:lower _publickey_t>] {
                pub data: [u8; [<PICNIC_PUBLIC_KEY_SIZE_ $param>] - 1],
            }

            #[repr(C)]
            #[derive(Clone)]
            #[cfg_attr(feature="zeroize", derive(Zeroize, ZeroizeOnDrop))]
            pub struct [<$param:lower _privatekey_t>] {
                pub data: [u8; [<PICNIC_PRIVATE_KEY_SIZE_ $param>] - 1],
            }

            extern "system" {
                pub fn [<$param:lower _get_param_name>]() -> *const c_char;
                pub fn [<$param:lower _get_private_key_size>]() -> size_t;
                pub fn [<$param:lower _get_public_key_size>]() -> size_t;
                pub fn [<$param:lower _keygen>](
                    pk: *mut [<$param:lower _publickey_t>],
                    sk: *mut [<$param:lower _privatekey_t>],
                ) -> c_int;
                pub fn [<$param:lower _sign>](
                    sk: *const [<$param:lower _privatekey_t>],
                    message: *const u8,
                    message_len: size_t,
                    signature: *mut u8,
                    signature_len: *mut size_t,
                ) -> c_int;
                pub fn [<$param:lower _signature_size>]() -> size_t;
                pub fn [<$param:lower _verify>](
                    pk: *const [<$param:lower _publickey_t>],
                    message: *const u8,
                    message_len: size_t,
                    signature: *const u8,
                    signature_len: size_t,
                ) -> c_int;
                pub fn [<$param:lower _write_public_key>](
                    key: *const [<$param:lower _publickey_t>],
                    buf: *mut u8,
                    buflen: size_t,
                ) -> c_int;
                pub fn [<$param:lower _read_public_key>](
                    key: *mut [<$param:lower _publickey_t>],
                    buf: *const u8,
                    buflen: size_t,
                ) -> c_int;
                pub fn [<$param:lower _write_private_key>](
                    key: *const [<$param:lower _privatekey_t>],
                    buf: *mut u8,
                    buflen: size_t,
                ) -> c_int;
                pub fn [<$param:lower _read_private_key>](
                    key: *mut [<$param:lower _privatekey_t>],
                    buf: *const u8,
                    buflen: size_t,
                ) -> c_int;
                pub fn [<$param:lower _validate_keypair>](
                    privatekey: *const [<$param:lower _privatekey_t>],
                    publickey: *const [<$param:lower _publickey_t>],
                ) -> c_int;
                pub fn [<$param:lower _clear_private_key>](key: *mut [<$param:lower _privatekey_t>]);
                pub fn [<$param:lower _sk_to_pk>](
                    privatekey: *const [<$param:lower _privatekey_t>],
                    publickey: *mut [<$param:lower _publickey_t>],
                ) -> c_int;
            }
        }
    };
}

#[cfg(not(feature = "param-bindings"))]
/// No-op
macro_rules! define_types_and_functions {
    ($param:ident) => {};
}

#[cfg(feature = "picnic")]
define_types_and_functions!(Picnic_L1_FS);
#[cfg(feature = "picnic")]
define_types_and_functions!(Picnic_L3_FS);
#[cfg(feature = "picnic")]
define_types_and_functions!(Picnic_L5_FS);
#[cfg(feature = "picnic")]
define_types_and_functions!(Picnic_L1_full);
#[cfg(feature = "picnic")]
define_types_and_functions!(Picnic_L3_full);
#[cfg(feature = "picnic")]
define_types_and_functions!(Picnic_L5_full);
#[cfg(all(feature = "picnic", feature = "unruh-transform"))]
define_types_and_functions!(Picnic_L1_UR);
#[cfg(all(feature = "picnic", feature = "unruh-transform"))]
define_types_and_functions!(Picnic_L3_UR);
#[cfg(all(feature = "picnic", feature = "unruh-transform"))]
define_types_and_functions!(Picnic_L5_UR);
#[cfg(feature = "picnic3")]
define_types_and_functions!(Picnic3_L1);
#[cfg(feature = "picnic3")]
define_types_and_functions!(Picnic3_L3);
#[cfg(feature = "picnic3")]
define_types_and_functions!(Picnic3_L5);

#[cfg(test)]
mod tests {
    use crate::*;

    fn run_basic_test(params: picnic_params_t) {
        unsafe {
            assert!(picnic_get_private_key_size(params) > 0);
            let pk_size = picnic_get_public_key_size(params);
            assert!(pk_size > 0);
            assert!(pk_size <= PICNIC_MAX_PUBLICKEY_SIZE);

            let mut sk = picnic_privatekey_t {
                data: [0; PICNIC_MAX_PRIVATEKEY_SIZE],
            };
            let mut pk = picnic_publickey_t {
                data: [0; PICNIC_MAX_PUBLICKEY_SIZE],
            };
            let mut pk2 = picnic_publickey_t {
                data: [0; PICNIC_MAX_PUBLICKEY_SIZE],
            };
            assert_eq!(picnic_keygen(params, &mut pk, &mut sk), 0);
            assert_eq!(picnic_get_private_key_param(&sk), params);
            assert_eq!(picnic_get_public_key_param(&pk), params);
            assert_eq!(picnic_validate_keypair(&sk, &pk), 0);
            assert_eq!(picnic_sk_to_pk(&sk, &mut pk2), 0);
            assert_eq!(pk.data[0..pk_size], pk2.data[0..pk_size]);

            let max_length = picnic_signature_size(params);
            assert!(max_length > 0);
            let msg = b"message";
            let mut length = max_length;
            let mut signature = vec![0; length];
            assert_eq!(
                picnic_sign(
                    &sk,
                    msg.as_ptr(),
                    msg.len(),
                    signature.as_mut_ptr(),
                    &mut length
                ),
                0
            );
            assert!(length > 0);
            assert!(length <= max_length);
            if params == picnic_params_t::Picnic_L1_UR
                || params == picnic_params_t::Picnic_L3_UR
                || params == picnic_params_t::Picnic_L5_UR
            {
                assert!(length == max_length);
            }
            signature.resize(length, 0);
            assert_eq!(
                picnic_verify(&pk, msg.as_ptr(), msg.len(), signature.as_ptr(), length),
                0
            );
        }
    }

    #[cfg(feature = "picnic")]
    #[test]
    fn picnic_l1_fs() {
        run_basic_test(picnic_params_t::Picnic_L1_FS);
    }

    #[cfg(all(feature = "picnic", feature = "unruh-transform"))]
    #[test]
    fn picnic_l1_ur() {
        run_basic_test(picnic_params_t::Picnic_L1_UR);
    }

    #[cfg(feature = "picnic")]
    #[test]
    fn picnic_l1_full() {
        run_basic_test(picnic_params_t::Picnic_L1_full);
    }

    #[cfg(feature = "picnic3")]
    #[test]
    fn picnic3_l1() {
        run_basic_test(picnic_params_t::Picnic3_L1);
    }

    #[cfg(feature = "picnic")]
    #[test]
    fn picnic_l3_fs() {
        run_basic_test(picnic_params_t::Picnic_L3_FS);
    }

    #[cfg(all(feature = "picnic", feature = "unruh-transform"))]
    #[test]
    fn picnic_l3_ur() {
        run_basic_test(picnic_params_t::Picnic_L3_UR);
    }

    #[cfg(feature = "picnic")]
    #[test]
    fn picnic_l3_full() {
        run_basic_test(picnic_params_t::Picnic_L3_full);
    }

    #[cfg(feature = "picnic3")]
    #[test]
    fn picnic3_l3() {
        run_basic_test(picnic_params_t::Picnic3_L3);
    }

    #[cfg(feature = "picnic")]
    #[test]
    fn picnic_l5_fs() {
        run_basic_test(picnic_params_t::Picnic_L5_FS);
    }

    #[cfg(all(feature = "picnic", feature = "unruh-transform"))]
    #[test]
    fn picnic_l5_ur() {
        run_basic_test(picnic_params_t::Picnic_L5_UR);
    }

    #[cfg(feature = "picnic")]
    #[test]
    fn picnic_l5_full() {
        run_basic_test(picnic_params_t::Picnic_L5_full);
    }

    #[cfg(feature = "picnic3")]
    #[test]
    fn picnic3_l5_full() {
        run_basic_test(picnic_params_t::Picnic3_L5);
    }
}
