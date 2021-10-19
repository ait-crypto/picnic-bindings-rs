//! # Bindings for Picnic
//!
//! This crate provides bindings to call the functions from shared library of the [optimized Picnic
//! implementation](https://github.com/IAIK/Picnic). More information on Picnic is available on the
//! project website: https://microsoft.github.io/Picnic/

#![allow(non_upper_case_globals, non_camel_case_types)]

pub use libc::{c_char, c_int, size_t};

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
#[derive(Debug, Copy, Clone)]
pub struct picnic_privatekey_t {
    pub data: [u8; PICNIC_MAX_PRIVATEKEY_SIZE],
}

extern "system" {
    pub fn picnic_get_param_name(parameters: picnic_params_t) -> *const c_char;
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
}

#[cfg(test)]
mod tests {
    use crate::*;

    fn run_basic_test(params: picnic_params_t) {
        unsafe {
            let mut sk = picnic_privatekey_t {
                data: [0; PICNIC_MAX_PRIVATEKEY_SIZE],
            };
            let mut pk = picnic_publickey_t {
                data: [0; PICNIC_MAX_PUBLICKEY_SIZE],
            };
            assert_eq!(picnic_keygen(params, &mut pk, &mut sk), 0);

            let mut length: size_t = picnic_signature_size(params);
            assert!(length > 0);
            let msg = b"message";
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
