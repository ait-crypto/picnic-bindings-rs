//! # Bindings for Picnic: Post-Quantum Signatures
//!
//! The Picnic signature scheme is a family of digital signature schemes secure against attacks by
//! quantum computers. This crate provides bindings that implements the traits from the [signature]
//! crate.
//!
//! More information on Picnic is available on the project website:
//! <https://microsoft.github.io/Picnic/>
//!
//! ## Usage
//!
//! Key generation, signing and verification can be implemented as follows:
//! ```
//! # #[cfg(feature="picnic")] {
//! use picnic_bindings::{PicnicL1FSSigningKey, signature::{Signer, Verifier}};
//!
//! let (signing_key, verification_key) = PicnicL1FSSigningKey::random().expect("Key generation failed");
//! let msg = "some message".as_bytes();
//! let signature = signing_key.sign(msg);
//! verification_key.verify(msg, &signature).expect("Verification failed");
//! # }
//! ```
//!
//! Keys and signatures support conversions to and from `&[u8]`. The following code example
//! demonstrates the necessary steps for [SigningKey]:
//! ```
//! # #[cfg(feature="picnic")] {
//! use picnic_bindings::{PicnicL1FSSigningKey};
//! use std::convert::TryFrom;
//!
//! let (signing_key, verification_key) = PicnicL1FSSigningKey::random().expect("Key generation failed");
//! let signing_key_2 = PicnicL1FSSigningKey::try_from(signing_key.as_ref()).expect("Deserialization failed");
//! assert_eq!(signing_key, signing_key_2);
//! # }
//! ```
//!
//! Alternatively:
//! ```
//! # #[cfg(feature="picnic")] {
//! use picnic_bindings::{DynamicSigningKey, PicnicL1FS, Parameters, signature::{Signer, Verifier}};
//!
//! let (signing_key, verification_key) = DynamicSigningKey::random(PicnicL1FS::PARAM).expect("Key generation failed");
//! let msg = "some message".as_bytes();
//! let signature = signing_key.sign(msg);
//! verification_key.verify(msg, &signature).expect("Verification failed");
//! # }
//! ```

#![warn(missing_docs)]

// If neither is specified, the crate is essentially empty.
#[cfg(all(not(feature = "picnic"), not(feature = "picnic3")))]
compile_error!("One of the features \"picnic\" and \"picnic3\" is required.");

use core::convert::TryFrom;
use core::fmt::{Debug, Formatter};
use core::marker::PhantomData;
use picnic_sys::*;
pub use signature::{self, Error};
use std::ffi::CStr;

/// Newtype pattern for `picnic_privatekey_t`
#[derive(Clone, Debug)]
struct PrivateKey(picnic_privatekey_t);

impl Default for PrivateKey {
    fn default() -> Self {
        Self {
            0: picnic_privatekey_t {
                data: [0; PICNIC_MAX_PRIVATEKEY_SIZE],
            },
        }
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        unsafe {
            picnic_clear_private_key(&mut self.0);
        }
    }
}

/// Newtype pattern for `picnic_publickey_t`
#[derive(Clone, Debug)]
struct PublicKey(picnic_publickey_t);

impl Default for PublicKey {
    fn default() -> Self {
        Self {
            0: picnic_publickey_t {
                data: [0; PICNIC_MAX_PUBLICKEY_SIZE],
            },
        }
    }
}

/// Helper trait to returns the serialized size keys
trait SerializedSize {
    /// Retrieve the size of the serialized object
    fn serialized_size(&self) -> usize;
}

/// Trait to describe Picnic parameters
pub trait Parameters {
    /// Internal parameter
    const PARAM: picnic_params_t;
    /// Max size of a signature
    const MAX_SIGNATURE_SIZE: usize;
    /// Size of the serialized private key
    const PRIVATE_KEY_SIZE: usize;
    /// Size of the serialized public key
    const PUBLIC_KEY_SIZE: usize;

    /// Retrieve name of the parameter set
    fn parameter_name() -> String {
        unsafe {
            CStr::from_ptr(picnic_get_param_name(Self::PARAM))
                .to_string_lossy()
                .into_owned()
        }
    }
}

/// Extension of the [signature::Signer] trait that allows to retrieve to corresponding verifier
pub trait Signer<S>: signature::Signer<S>
where
    S: signature::Signature,
{
    /// The verifier type
    type Verifier: signature::Verifier<S>;

    /// Return corresponding verifier, i.e. verification key
    fn verifier(&self) -> Result<Self::Verifier, Error>;
}

#[cfg(feature = "picnic")]
/// Picnic-L1-FS parameters
pub struct PicnicL1FS {}

#[cfg(feature = "picnic")]
impl Parameters for PicnicL1FS {
    const PARAM: picnic_params_t = picnic_params_t::Picnic_L1_FS;
    const MAX_SIGNATURE_SIZE: usize = PICNIC_SIGNATURE_SIZE_Picnic_L1_FS;
    const PRIVATE_KEY_SIZE: usize = PICNIC_PRIVATE_KEY_SIZE_Picnic_L1_FS;
    const PUBLIC_KEY_SIZE: usize = PICNIC_PUBLIC_KEY_SIZE_Picnic_L1_FS;
}

#[cfg(feature = "unruh-transform")]
/// Picnic-L1-UR parameters
pub struct PicnicL1UR {}

#[cfg(feature = "unruh-transform")]
impl Parameters for PicnicL1UR {
    const PARAM: picnic_params_t = picnic_params_t::Picnic_L1_UR;
    const MAX_SIGNATURE_SIZE: usize = PICNIC_SIGNATURE_SIZE_Picnic_L1_UR;
    const PRIVATE_KEY_SIZE: usize = PICNIC_PRIVATE_KEY_SIZE_Picnic_L1_UR;
    const PUBLIC_KEY_SIZE: usize = PICNIC_PUBLIC_KEY_SIZE_Picnic_L1_UR;
}

#[cfg(feature = "picnic")]
/// Picnic-L1-full parameters
pub struct PicnicL1Full {}

#[cfg(feature = "picnic")]
impl Parameters for PicnicL1Full {
    const PARAM: picnic_params_t = picnic_params_t::Picnic_L1_full;
    const MAX_SIGNATURE_SIZE: usize = PICNIC_SIGNATURE_SIZE_Picnic_L1_full;
    const PRIVATE_KEY_SIZE: usize = PICNIC_PRIVATE_KEY_SIZE_Picnic_L1_full;
    const PUBLIC_KEY_SIZE: usize = PICNIC_PUBLIC_KEY_SIZE_Picnic_L1_full;
}

#[cfg(feature = "picnic")]
/// Picnic-L3-FS parameters
pub struct PicnicL3FS {}

#[cfg(feature = "picnic")]
impl Parameters for PicnicL3FS {
    const PARAM: picnic_params_t = picnic_params_t::Picnic_L3_FS;
    const MAX_SIGNATURE_SIZE: usize = PICNIC_SIGNATURE_SIZE_Picnic_L3_FS;
    const PRIVATE_KEY_SIZE: usize = PICNIC_PRIVATE_KEY_SIZE_Picnic_L3_FS;
    const PUBLIC_KEY_SIZE: usize = PICNIC_PUBLIC_KEY_SIZE_Picnic_L3_FS;
}

#[cfg(feature = "unruh-transform")]
/// Picnic-L3-UR parameters
pub struct PicnicL3UR {}

#[cfg(feature = "unruh-transform")]
impl Parameters for PicnicL3UR {
    const PARAM: picnic_params_t = picnic_params_t::Picnic_L3_UR;
    const MAX_SIGNATURE_SIZE: usize = PICNIC_SIGNATURE_SIZE_Picnic_L3_UR;
    const PRIVATE_KEY_SIZE: usize = PICNIC_PRIVATE_KEY_SIZE_Picnic_L3_UR;
    const PUBLIC_KEY_SIZE: usize = PICNIC_PUBLIC_KEY_SIZE_Picnic_L3_UR;
}

#[cfg(feature = "picnic")]
/// Picnic-L3-full parameters
pub struct PicnicL3Full {}

#[cfg(feature = "picnic")]
impl Parameters for PicnicL3Full {
    const PARAM: picnic_params_t = picnic_params_t::Picnic_L3_full;
    const MAX_SIGNATURE_SIZE: usize = PICNIC_SIGNATURE_SIZE_Picnic_L3_full;
    const PRIVATE_KEY_SIZE: usize = PICNIC_PRIVATE_KEY_SIZE_Picnic_L3_full;
    const PUBLIC_KEY_SIZE: usize = PICNIC_PUBLIC_KEY_SIZE_Picnic_L3_full;
}

#[cfg(feature = "picnic")]
/// Picnic-L5-FS parameters
pub struct PicnicL5FS {}

#[cfg(feature = "picnic")]
impl Parameters for PicnicL5FS {
    const PARAM: picnic_params_t = picnic_params_t::Picnic_L5_FS;
    const MAX_SIGNATURE_SIZE: usize = PICNIC_SIGNATURE_SIZE_Picnic_L5_FS;
    const PRIVATE_KEY_SIZE: usize = PICNIC_PRIVATE_KEY_SIZE_Picnic_L5_FS;
    const PUBLIC_KEY_SIZE: usize = PICNIC_PUBLIC_KEY_SIZE_Picnic_L5_FS;
}

#[cfg(feature = "unruh-transform")]
/// Picnic-L5-UR parameters
pub struct PicnicL5UR {}

#[cfg(feature = "unruh-transform")]
impl Parameters for PicnicL5UR {
    const PARAM: picnic_params_t = picnic_params_t::Picnic_L5_UR;
    const MAX_SIGNATURE_SIZE: usize = PICNIC_SIGNATURE_SIZE_Picnic_L5_UR;
    const PRIVATE_KEY_SIZE: usize = PICNIC_PRIVATE_KEY_SIZE_Picnic_L5_UR;
    const PUBLIC_KEY_SIZE: usize = PICNIC_PUBLIC_KEY_SIZE_Picnic_L5_UR;
}

#[cfg(feature = "picnic")]
/// Picnic-L5-full parameters
pub struct PicnicL5Full {}

#[cfg(feature = "picnic")]
impl Parameters for PicnicL5Full {
    const PARAM: picnic_params_t = picnic_params_t::Picnic_L5_full;
    const MAX_SIGNATURE_SIZE: usize = PICNIC_SIGNATURE_SIZE_Picnic_L5_full;
    const PRIVATE_KEY_SIZE: usize = PICNIC_PRIVATE_KEY_SIZE_Picnic_L5_full;
    const PUBLIC_KEY_SIZE: usize = PICNIC_PUBLIC_KEY_SIZE_Picnic_L5_full;
}

#[cfg(feature = "picnic3")]
/// Picnic3-L1 parameters
pub struct Picnic3L1 {}

#[cfg(feature = "picnic3")]
impl Parameters for Picnic3L1 {
    const PARAM: picnic_params_t = picnic_params_t::Picnic3_L1;
    const MAX_SIGNATURE_SIZE: usize = PICNIC_SIGNATURE_SIZE_Picnic3_L1;
    const PRIVATE_KEY_SIZE: usize = PICNIC_PRIVATE_KEY_SIZE_Picnic3_L1;
    const PUBLIC_KEY_SIZE: usize = PICNIC_PUBLIC_KEY_SIZE_Picnic3_L1;
}

#[cfg(feature = "picnic3")]
/// Picnic3-L3 parameter
pub struct Picnic3L3 {}

#[cfg(feature = "picnic3")]
impl Parameters for Picnic3L3 {
    const PARAM: picnic_params_t = picnic_params_t::Picnic3_L3;
    const MAX_SIGNATURE_SIZE: usize = PICNIC_SIGNATURE_SIZE_Picnic3_L3;
    const PRIVATE_KEY_SIZE: usize = PICNIC_PRIVATE_KEY_SIZE_Picnic3_L3;
    const PUBLIC_KEY_SIZE: usize = PICNIC_PUBLIC_KEY_SIZE_Picnic3_L3;
}

#[cfg(feature = "picnic3")]
/// Picnic3-L5 parameters
pub struct Picnic3L5 {}

#[cfg(feature = "picnic3")]
impl Parameters for Picnic3L5 {
    const PARAM: picnic_params_t = picnic_params_t::Picnic3_L5;
    const MAX_SIGNATURE_SIZE: usize = PICNIC_SIGNATURE_SIZE_Picnic3_L5;
    const PRIVATE_KEY_SIZE: usize = PICNIC_PRIVATE_KEY_SIZE_Picnic3_L5;
    const PUBLIC_KEY_SIZE: usize = PICNIC_PUBLIC_KEY_SIZE_Picnic3_L5;
}

#[cfg(feature = "picnic")]
/// Signing key for Picnic-L1-FS
pub type PicnicL1FSSigningKey = SigningKey<PicnicL1FS>;
#[cfg(feature = "picnic")]
/// Verification key for Picnic-L1-FS
pub type PicnicL1FSVerificationKey = VerificationKey<PicnicL1FS>;
#[cfg(feature = "unruh-transform")]
/// Signing key for Picnic-L1-UR
pub type PicnicL1URSigningKey = SigningKey<PicnicL1UR>;
#[cfg(feature = "unruh-transform")]
/// Verification key for Picnic-L1-UR
pub type PicnicL1URVerificationKey = VerificationKey<PicnicL1UR>;
#[cfg(feature = "picnic")]
/// Signing key for Picnic-L1-full
pub type PicnicL1FullSigningKey = SigningKey<PicnicL1Full>;
#[cfg(feature = "picnic")]
/// Verification key for Picnic-L1-full
pub type PicnicL1FullVerificationKey = VerificationKey<PicnicL1Full>;
#[cfg(feature = "picnic3")]
/// Signing key for Picnic3-L1
pub type Picnic3L1SigningKey = SigningKey<Picnic3L1>;
#[cfg(feature = "picnic3")]
/// Verification key for Picnic3-L1
pub type Picnic3L1VerificationKey = VerificationKey<Picnic3L1>;

#[cfg(feature = "picnic")]
/// Signing key for Picnic-L3-FS
pub type PicnicL3FSSigningKey = SigningKey<PicnicL3FS>;
#[cfg(feature = "picnic")]
/// Verification key for Picnic-L3-FS
pub type PicnicL3FSVerificationKey = VerificationKey<PicnicL3FS>;
#[cfg(feature = "unruh-transform")]
/// Signing key for Picnic-L3-UR
pub type PicnicL3URSigningKey = SigningKey<PicnicL3UR>;
#[cfg(feature = "unruh-transform")]
/// Verification key for Picnic-L3-UR
pub type PicnicL3URVerificationKey = VerificationKey<PicnicL3UR>;
#[cfg(feature = "picnic")]
/// Signing key for Picnic-L3-full
pub type PicnicL3FullSigningKey = SigningKey<PicnicL3Full>;
#[cfg(feature = "picnic")]
/// Verification key for Picnic-L3-full
pub type PicnicL3FullVerificationKey = VerificationKey<PicnicL3Full>;
#[cfg(feature = "picnic3")]
/// Signing key for Picnic3-L3
pub type Picnic3L3SigningKey = SigningKey<Picnic3L3>;
#[cfg(feature = "picnic3")]
/// Verification key for Picnic3-L3
pub type Picnic3L3VerificationKey = VerificationKey<Picnic3L3>;

#[cfg(feature = "picnic")]
/// Signing key for Picnic-L5-FS
pub type PicnicL5FSSigningKey = SigningKey<PicnicL5FS>;
#[cfg(feature = "picnic")]
/// Verification key for Picnic-L5-FS
pub type PicnicL5FSVerificationKey = VerificationKey<PicnicL5FS>;
#[cfg(feature = "unruh-transform")]
/// Signing key for Picnic-L5-UR
pub type PicnicL5URSigningKey = SigningKey<PicnicL5UR>;
#[cfg(feature = "unruh-transform")]
/// Verification key for Picnic-L5-UR
pub type PicnicL5URVerificationKey = VerificationKey<PicnicL5UR>;
#[cfg(feature = "picnic")]
/// Signing key for Picnic-L5-full
pub type PicnicL5FullSigningKey = SigningKey<PicnicL5Full>;
#[cfg(feature = "picnic")]
/// Verification key for Picnic-L5-full
pub type PicnicL5FullVerificationKey = VerificationKey<PicnicL5Full>;
#[cfg(feature = "picnic3")]
/// Signing key for Picnic3-L5
pub type Picnic3L5SigningKey = SigningKey<Picnic3L5>;
#[cfg(feature = "picnic3")]
/// Verification key for Picnic3-L5
pub type Picnic3L5VerificationKey = VerificationKey<Picnic3L5>;

/// Signature stored in a `Vec`
///
/// While storing signatures in arrays is possible, their size varies even for the same parameter
/// set.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DynamicSignature(Vec<u8>);

impl AsRef<[u8]> for DynamicSignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<&[u8]> for DynamicSignature {
    fn from(bytes: &[u8]) -> Self {
        Self { 0: bytes.into() }
    }
}

impl signature::Signature for DynamicSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(DynamicSignature::from(bytes))
    }
}

/// Signing key generic over the parameters
#[derive(Clone)]
pub struct SigningKey<P: Parameters> {
    data: PrivateKey,
    phantom_data: PhantomData<P>,
}

impl<P> SigningKey<P>
where
    P: Parameters,
{
    fn new() -> Self {
        Self {
            data: Default::default(),
            phantom_data: PhantomData,
        }
    }

    /// Sample a new random signing key and the corresponding verification key
    pub fn random() -> Result<(Self, VerificationKey<P>), Error> {
        let mut sk = SigningKey::new();
        let mut vk = VerificationKey::new();

        match unsafe { picnic_keygen(P::PARAM, &mut vk.data.0, &mut sk.data.0) } {
            0 => Ok((sk, vk)),
            _ => Err(Error::new()),
        }
    }
}

impl<P> Signer<DynamicSignature> for SigningKey<P>
where
    P: Parameters,
{
    type Verifier = VerificationKey<P>;

    fn verifier(&self) -> Result<Self::Verifier, Error> {
        let mut vk = VerificationKey::new();

        match unsafe { picnic_sk_to_pk(&self.data.0, &mut vk.data.0) } {
            0 => Ok(vk),
            _ => Err(Error::new()),
        }
    }
}

impl<P> signature::Signer<DynamicSignature> for SigningKey<P>
where
    P: Parameters,
{
    fn try_sign(&self, msg: &[u8]) -> Result<DynamicSignature, Error> {
        let mut signature = vec![0; P::MAX_SIGNATURE_SIZE];
        let mut length = P::MAX_SIGNATURE_SIZE;

        match unsafe {
            picnic_sign(
                &self.data.0,
                msg.as_ptr(),
                msg.len(),
                signature.as_mut_ptr(),
                &mut length,
            )
        } {
            0 => {
                signature.resize(length, 0);
                Ok(DynamicSignature { 0: signature })
            }
            _ => Err(Error::new()),
        }
    }
}

impl<P> SerializedSize for SigningKey<P>
where
    P: Parameters,
{
    fn serialized_size(&self) -> usize {
        P::PRIVATE_KEY_SIZE
    }
}

impl<P> AsRef<[u8]> for SigningKey<P>
where
    P: Parameters,
{
    fn as_ref(&self) -> &[u8] {
        // FIXME: this breaks the abstraction layer; this should be a call to picnic_write_private_key
        &self.data.0.data[0..P::PRIVATE_KEY_SIZE]
    }
}

impl<P> TryFrom<&[u8]> for SigningKey<P>
where
    P: Parameters,
{
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut sk = Self::new();
        if unsafe { picnic_read_private_key(&mut sk.data.0, value.as_ptr(), value.len()) } != 0 {
            return Err(Self::Error::new());
        }

        match unsafe { picnic_get_private_key_param(&sk.data.0) } == P::PARAM {
            true => Ok(sk),
            false => Err(Self::Error::new()),
        }
    }
}

impl<P> Debug for SigningKey<P>
where
    P: Parameters,
{
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct(format!("SigningKey<{}>", P::parameter_name()).as_str())
            .field("data", &self.data)
            .finish()
    }
}

impl<P> PartialEq for SigningKey<P>
where
    P: Parameters,
{
    fn eq(&self, other: &Self) -> bool {
        self.data.0.data[..P::PRIVATE_KEY_SIZE] == other.data.0.data[..P::PRIVATE_KEY_SIZE]
    }
}

impl<P> Eq for SigningKey<P> where P: Parameters {}

/// Verification key generic over the parameters
#[derive(Clone)]
pub struct VerificationKey<P: Parameters> {
    data: PublicKey,
    phantom_data: PhantomData<P>,
}

impl<P> VerificationKey<P>
where
    P: Parameters,
{
    fn new() -> Self {
        Self {
            data: Default::default(),
            phantom_data: PhantomData,
        }
    }
}

impl<P> signature::Verifier<DynamicSignature> for VerificationKey<P>
where
    P: Parameters,
{
    fn verify(&self, msg: &[u8], signature: &DynamicSignature) -> Result<(), Error> {
        match unsafe {
            picnic_verify(
                &self.data.0,
                msg.as_ptr(),
                msg.len(),
                signature.0.as_ptr(),
                signature.0.len(),
            )
        } {
            0 => Ok(()),
            _ => Err(Error::new()),
        }
    }
}

impl<P> SerializedSize for VerificationKey<P>
where
    P: Parameters,
{
    fn serialized_size(&self) -> usize {
        P::PUBLIC_KEY_SIZE
    }
}

impl<P> AsRef<[u8]> for VerificationKey<P>
where
    P: Parameters,
{
    fn as_ref(&self) -> &[u8] {
        // FIXME: this breaks the abstraction layer; this should be a call to picnic_write_public_key
        &self.data.0.data[0..P::PUBLIC_KEY_SIZE]
    }
}

impl<P> TryFrom<&[u8]> for VerificationKey<P>
where
    P: Parameters,
{
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut vk = Self::new();
        if unsafe { picnic_read_public_key(&mut vk.data.0, value.as_ptr(), value.len()) } != 0 {
            return Err(Self::Error::new());
        }

        match unsafe { picnic_get_public_key_param(&vk.data.0) } == P::PARAM {
            true => Ok(vk),
            false => Err(Self::Error::new()),
        }
    }
}

impl<P> Debug for VerificationKey<P>
where
    P: Parameters,
{
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct(format!("VerificationKey<{}>", P::parameter_name()).as_str())
            .field("data", &self.data)
            .finish()
    }
}

impl<P> PartialEq for VerificationKey<P>
where
    P: Parameters,
{
    fn eq(&self, other: &Self) -> bool {
        self.data.0.data[..P::PUBLIC_KEY_SIZE] == other.data.0.data[..P::PUBLIC_KEY_SIZE]
    }
}

impl<P> Eq for VerificationKey<P> where P: Parameters {}

/// Signing key
#[derive(Clone, Debug)]
pub struct DynamicSigningKey {
    data: PrivateKey,
}

impl DynamicSigningKey {
    fn new() -> Self {
        Self {
            data: Default::default(),
        }
    }

    /// Sample a new random signing key and the corresponding verification key
    pub fn random(params: picnic_params_t) -> Result<(Self, DynamicVerificationKey), Error> {
        let mut sk = DynamicSigningKey::new();
        let mut vk = DynamicVerificationKey::new();

        match unsafe { picnic_keygen(params, &mut vk.data.0, &mut sk.data.0) } {
            0 => Ok((sk, vk)),
            _ => Err(Error::new()),
        }
    }

    fn param(&self) -> picnic_params_t {
        unsafe { picnic_get_private_key_param(&self.data.0) }
    }
}

impl Signer<DynamicSignature> for DynamicSigningKey {
    type Verifier = DynamicVerificationKey;

    fn verifier(&self) -> Result<Self::Verifier, Error> {
        let mut vk = DynamicVerificationKey::new();

        match unsafe { picnic_sk_to_pk(&self.data.0, &mut vk.data.0) } {
            0 => Ok(vk),
            _ => Err(Error::new()),
        }
    }
}

impl signature::Signer<DynamicSignature> for DynamicSigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<DynamicSignature, Error> {
        let mut length = unsafe { picnic_signature_size(self.param()) };
        let mut signature = vec![0; length];

        match unsafe {
            picnic_sign(
                &self.data.0,
                msg.as_ptr(),
                msg.len(),
                signature.as_mut_ptr(),
                &mut length,
            )
        } {
            0 => {
                signature.resize(length, 0);
                Ok(DynamicSignature { 0: signature })
            }
            _ => Err(Error::new()),
        }
    }
}

impl SerializedSize for DynamicSigningKey {
    fn serialized_size(&self) -> usize {
        unsafe { picnic_get_private_key_size(self.param()) }
    }
}

impl AsRef<[u8]> for DynamicSigningKey {
    fn as_ref(&self) -> &[u8] {
        // FIXME: this breaks the abstraction layer; this should be a call to picnic_write_private_key
        &self.data.0.data[0..self.serialized_size()]
    }
}

impl TryFrom<&[u8]> for DynamicSigningKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut sk = Self::new();
        if unsafe { picnic_read_private_key(&mut sk.data.0, value.as_ptr(), value.len()) } != 0 {
            return Err(Self::Error::new());
        }

        match sk.param() != picnic_params_t::PARAMETER_SET_INVALID {
            true => Ok(sk),
            false => Err(Self::Error::new()),
        }
    }
}

impl PartialEq for DynamicSigningKey {
    fn eq(&self, other: &Self) -> bool {
        let self_param = self.param();
        self_param == other.param() && {
            let size = unsafe { picnic_get_private_key_size(self_param) };
            self.data.0.data[..size] == other.data.0.data[..size]
        }
    }
}

impl Eq for DynamicSigningKey {}

/// Verification key
#[derive(Clone, Debug)]
pub struct DynamicVerificationKey {
    data: PublicKey,
}

impl DynamicVerificationKey {
    fn new() -> Self {
        Self {
            data: Default::default(),
        }
    }

    fn param(&self) -> picnic_params_t {
        unsafe { picnic_get_public_key_param(&self.data.0) }
    }
}

impl signature::Verifier<DynamicSignature> for DynamicVerificationKey {
    fn verify(&self, msg: &[u8], signature: &DynamicSignature) -> Result<(), Error> {
        match unsafe {
            picnic_verify(
                &self.data.0,
                msg.as_ptr(),
                msg.len(),
                signature.0.as_ptr(),
                signature.0.len(),
            )
        } {
            0 => Ok(()),
            _ => Err(Error::new()),
        }
    }
}

impl SerializedSize for DynamicVerificationKey {
    fn serialized_size(&self) -> usize {
        unsafe { picnic_get_public_key_size(self.param()) }
    }
}

impl AsRef<[u8]> for DynamicVerificationKey {
    fn as_ref(&self) -> &[u8] {
        // FIXME: this breaks the abstraction layer; this should be a call to picnic_write_public_key
        &self.data.0.data[0..self.serialized_size()]
    }
}

impl TryFrom<&[u8]> for DynamicVerificationKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut vk = Self::new();
        if unsafe { picnic_read_public_key(&mut vk.data.0, value.as_ptr(), value.len()) } != 0 {
            return Err(Self::Error::new());
        }

        match vk.param() != picnic_params_t::PARAMETER_SET_INVALID {
            true => Ok(vk),
            false => Err(Self::Error::new()),
        }
    }
}

impl PartialEq for DynamicVerificationKey {
    fn eq(&self, other: &Self) -> bool {
        self.param() == other.param() && {
            let size = self.serialized_size();
            self.data.0.data[..size] == other.data.0.data[..size]
        }
    }
}

impl Eq for DynamicVerificationKey {}

#[cfg(test)]
mod test {
    #[cfg(feature = "picnic")]
    use crate::{PicnicL1FSSigningKey, PicnicL1FullSigningKey, PicnicL1FullVerificationKey};
    #[cfg(feature = "picnic")]
    use std::convert::TryFrom;

    #[cfg(feature = "picnic")]
    #[test]
    fn serialization_param_mismatch() {
        let (sk1, vk1) = PicnicL1FSSigningKey::random().expect("unable to generate keys");
        PicnicL1FullSigningKey::try_from(sk1.as_ref()).expect_err("deserialization did not fail");
        PicnicL1FullVerificationKey::try_from(vk1.as_ref())
            .expect_err("deserialization did not fail");
    }
}
