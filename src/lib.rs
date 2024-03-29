//! # Bindings for Picnic: Post-Quantum Signatures
//!
//! The Picnic signature scheme is a family of digital signature schemes secure against attacks by
//! quantum computers. This crate provides bindings that implements the traits from the [signature]
//! crate.
//!
//! More information on Picnic is available on the project website:
//! <https://microsoft.github.io/Picnic/>
//!
//! Serialization and deserialization is implemented via the `serde` crate. By enabling the
//! `serialization` feature, all public structs implement the `Serialize` and `Deserialize` traits.
//!
//! ## Usage
//!
//! Key generation, signing and verification can be implemented as follows:
//! ```
//! # #[cfg(feature="picnic")] {
//! use picnic_bindings::{PicnicL1FSSigningKey, Signer, Verifier};
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
//! use picnic_bindings::{DynamicSigningKey, PicnicL1FS, Parameters, Signer, Verifier};
//!
//! let (signing_key, verification_key) = DynamicSigningKey::random(PicnicL1FS::PARAM).expect("Key generation failed");
//! let msg = "some message".as_bytes();
//! let signature = signing_key.sign(msg);
//! verification_key.verify(msg, &signature).expect("Verification failed");
//! # }
//! ```
//!
//! In case a signature as only available as `&[u8]` and taking ownership is not desired, the
//! [RawVerifier] trait offers a method to verify the signature without first converting it into an
//! instance of [DynamicSignature].
//! ```
//! # #[cfg(feature="picnic")] {
//! use picnic_bindings::{PicnicL1FSSigningKey, Signer, RawVerifier};
//!
//! let (signing_key, verification_key) = PicnicL1FSSigningKey::random().expect("Key generation failed");
//! let msg = "some message".as_bytes();
//! let signature = signing_key.sign(msg);
//! // assume that this is the actual signature
//! let signature = signature.as_ref();
//! verification_key.verify_raw(msg, signature).expect("Verification failed");
//! # }
//! ```

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![warn(missing_docs)]

// If neither is specified, the crate is essentially empty.
#[cfg(all(not(feature = "picnic"), not(feature = "picnic3")))]
compile_error!("One of the features \"picnic\" and \"picnic3\" is required.");

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{format, vec, vec::Vec};

use core::fmt::{self, Debug};
use core::marker::PhantomData;
use libpicnic_sys::*;
use paste::paste;
pub use signature::{self, Error, Signer, Verifier};

#[cfg(feature = "serialization")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "subtle")]
use subtle::{Choice, ConstantTimeEq};

mod wrapper;
use crate::wrapper::*;

#[cfg(feature = "serialization")]
mod serialization;

#[cfg(feature = "serialization")]
use serialization::{deserialize, serialize};

/// Trait to describe Picnic parameters
pub trait Parameters: Clone {
    /// Internal parameter
    const PARAM: picnic_params_t;
    /// Max size of a signature
    const MAX_SIGNATURE_SIZE: usize;
    /// Size of the serialized private key
    const PRIVATE_KEY_SIZE: usize;
    /// Size of the serialized public key
    const PUBLIC_KEY_SIZE: usize;

    /// Retrieve name of the parameter set
    fn parameter_name() -> &'static str;
}

/// Trait that allows to directly verify a signature from a `&[u8]`
///
/// With this trait verifiers are able to verify a signature without first storing it in a
/// [DynamicSignature] to satisfy the [Verifier] interface.
pub trait RawVerifier {
    /// Verify a "raw" signature.
    fn verify_raw(&self, msg: &[u8], signature: &[u8]) -> Result<(), Error>;
}

/// Define a parameters set and its associated implementations and types
macro_rules! define_params {
    ($name:ident, $param:ident) => {
        paste! {
            #[doc = $name " parameters"]
            #[derive(Clone, Debug, PartialEq, Eq)]
            #[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
            pub struct $name {}

            impl Parameters for $name {
                const PARAM: picnic_params_t = picnic_params_t::$param;
                const MAX_SIGNATURE_SIZE: usize = [<PICNIC_SIGNATURE_SIZE_ $param>];
                const PRIVATE_KEY_SIZE: usize = [<PICNIC_PRIVATE_KEY_SIZE_ $param>];
                const PUBLIC_KEY_SIZE: usize = [<PICNIC_PUBLIC_KEY_SIZE_ $param>];

                #[inline(always)]
                fn parameter_name() -> &'static str {
                    "$param"
                }
            }

            #[doc = "Signing key for " $name]
            pub type [<$name SigningKey>] = SigningKey<$name>;
            #[doc = "Verification key for " $name]
            pub type [<$name VerificationKey>] = VerificationKey<$name>;
        }
    };
}

#[cfg(feature = "picnic")]
define_params!(PicnicL1FS, Picnic_L1_FS);
#[cfg(feature = "unruh-transform")]
define_params!(PicnicL1UR, Picnic_L1_UR);
#[cfg(feature = "picnic")]
define_params!(PicnicL1Full, Picnic_L1_full);
#[cfg(feature = "picnic3")]
define_params!(Picnic3L1, Picnic3_L1);

#[cfg(feature = "picnic")]
define_params!(PicnicL3FS, Picnic_L3_FS);
#[cfg(feature = "unruh-transform")]
define_params!(PicnicL3UR, Picnic_L3_UR);
#[cfg(feature = "picnic")]
define_params!(PicnicL3Full, Picnic_L3_full);
#[cfg(feature = "picnic3")]
define_params!(Picnic3L3, Picnic3_L3);

#[cfg(feature = "picnic")]
define_params!(PicnicL5FS, Picnic_L5_FS);
#[cfg(feature = "unruh-transform")]
define_params!(PicnicL5UR, Picnic_L5_UR);
#[cfg(feature = "picnic")]
define_params!(PicnicL5Full, Picnic_L5_full);
#[cfg(feature = "picnic3")]
define_params!(Picnic3L5, Picnic3_L5);

/// Signature stored in a `Vec`
///
/// While storing signatures in arrays is possible, their size varies even for the same parameter
/// set.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
pub struct DynamicSignature(
    #[cfg_attr(feature = "serialization", serde(with = "serde_bytes"))] Vec<u8>,
);

impl AsRef<[u8]> for DynamicSignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<&[u8]> for DynamicSignature {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.into())
    }
}

/// Signing key generic over the parameters
#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct SigningKey<P: Parameters> {
    data: PrivateKey,
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    phantom_data: PhantomData<P>,
}

impl<P> SigningKey<P>
where
    P: Parameters,
{
    /// Sample a new random signing key and the corresponding verification key.
    /// This operation may fail if the Picnic library is not built with support
    /// for the given parameter set.
    pub fn random() -> Result<(Self, VerificationKey<P>), Error> {
        PrivateKey::random(P::PARAM).map(|(sk, vk)| {
            (
                Self {
                    data: sk,
                    phantom_data: PhantomData,
                },
                VerificationKey {
                    data: vk,
                    phantom_data: PhantomData,
                },
            )
        })
    }
}

impl<P> Signer<DynamicSignature> for SigningKey<P>
where
    P: Parameters,
{
    fn try_sign(&self, msg: &[u8]) -> Result<DynamicSignature, Error> {
        let mut signature = vec![0; P::MAX_SIGNATURE_SIZE];

        let length = self.data.try_sign(msg, signature.as_mut_slice())?;
        signature.resize(length, 0);
        Ok(DynamicSignature(signature))
    }
}

impl<P> Verifier<DynamicSignature> for SigningKey<P>
where
    P: Parameters,
{
    fn verify(&self, msg: &[u8], signature: &DynamicSignature) -> Result<(), Error> {
        self.data
            .public_key()
            .and_then(|pk| pk.verify(msg, signature.as_ref()))
    }
}

impl<P> PicnicKey for SigningKey<P>
where
    P: Parameters,
{
    #[inline(always)]
    fn param(&self) -> picnic_params_t {
        P::PARAM
    }

    #[inline(always)]
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
        &self.data.as_ref().data[0..P::PRIVATE_KEY_SIZE]
    }
}

impl<P> TryFrom<&[u8]> for SigningKey<P>
where
    P: Parameters,
{
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let sk = PrivateKey::try_from(value)?;
        match sk.param() == P::PARAM {
            true => Ok(Self {
                data: sk,
                phantom_data: PhantomData,
            }),
            false => Err(Self::Error::new()),
        }
    }
}

impl<P> Debug for SigningKey<P>
where
    P: Parameters,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct(&format!("SigningKey<{}>", P::parameter_name()))
            .field("data", &"[...]")
            .finish()
    }
}

impl<P> PartialEq for SigningKey<P>
where
    P: Parameters,
{
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl<P> Eq for SigningKey<P> where P: Parameters {}

#[cfg(feature = "subtle")]
impl<P> ConstantTimeEq for SigningKey<P>
where
    P: Parameters,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_ref().ct_eq(other.as_ref())
    }
}

#[cfg(feature = "serialization")]
impl<P> Serialize for SigningKey<P>
where
    P: Parameters,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize(self, serializer)
    }
}

#[cfg(feature = "serialization")]
impl<'de, P> Deserialize<'de> for SigningKey<P>
where
    P: Parameters,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize(deserializer)
    }
}

/// Verification key generic over the parameters
#[derive(Clone)]
pub struct VerificationKey<P: Parameters> {
    data: PublicKey,
    phantom_data: PhantomData<P>,
}

impl<P> Verifier<DynamicSignature> for VerificationKey<P>
where
    P: Parameters,
{
    fn verify(&self, msg: &[u8], signature: &DynamicSignature) -> Result<(), Error> {
        self.verify_raw(msg, &signature.0)
    }
}

impl<P> RawVerifier for VerificationKey<P>
where
    P: Parameters,
{
    fn verify_raw(&self, msg: &[u8], signature: &[u8]) -> Result<(), Error> {
        self.data.verify(msg, signature)
    }
}

impl<P> PicnicKey for VerificationKey<P>
where
    P: Parameters,
{
    #[inline(always)]
    fn param(&self) -> picnic_params_t {
        P::PARAM
    }

    #[inline(always)]
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
        &self.data.as_ref().data[0..P::PUBLIC_KEY_SIZE]
    }
}

impl<P> TryFrom<&[u8]> for VerificationKey<P>
where
    P: Parameters,
{
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let vk = PublicKey::try_from(value)?;
        match vk.param() == P::PARAM {
            true => Ok(Self {
                data: vk,
                phantom_data: PhantomData,
            }),
            false => Err(Self::Error::new()),
        }
    }
}

impl<P> TryFrom<&SigningKey<P>> for VerificationKey<P>
where
    P: Parameters,
{
    type Error = Error;

    fn try_from(sk: &SigningKey<P>) -> Result<Self, Self::Error> {
        sk.data.public_key().map(|vk| Self {
            data: vk,
            phantom_data: PhantomData,
        })
    }
}

impl<P> Debug for VerificationKey<P>
where
    P: Parameters,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct(&format!("VerificationKey<{}>", P::parameter_name()))
            .field("data", &self.data)
            .finish()
    }
}

impl<P> PartialEq for VerificationKey<P>
where
    P: Parameters,
{
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl<P> Eq for VerificationKey<P> where P: Parameters {}

#[cfg(feature = "serialization")]
impl<P> Serialize for VerificationKey<P>
where
    P: Parameters,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize(self, serializer)
    }
}

#[cfg(feature = "serialization")]
impl<'de, P> Deserialize<'de> for VerificationKey<P>
where
    P: Parameters,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize(deserializer)
    }
}

/// Signing key
#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct DynamicSigningKey {
    data: PrivateKey,
}

impl Debug for DynamicSigningKey {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("DynamicSigningKey")
            .field("param", &self.param())
            .field("data", &"[...]")
            .finish()
    }
}

impl DynamicSigningKey {
    /// Sample a new random signing key and the corresponding verification key.
    /// This operation may fail if the Picnic library is not built with support
    /// for the given parameter set.
    pub fn random(params: picnic_params_t) -> Result<(Self, DynamicVerificationKey), Error> {
        PrivateKey::random(params)
            .map(|(sk, vk)| (Self { data: sk }, DynamicVerificationKey { data: vk }))
    }
}

impl Signer<DynamicSignature> for DynamicSigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<DynamicSignature, Error> {
        let mut signature = vec![0; signature_size(self.param())];
        let length = self.data.try_sign(msg, signature.as_mut_slice())?;
        signature.resize(length, 0);
        Ok(DynamicSignature(signature))
    }
}

impl Verifier<DynamicSignature> for DynamicSigningKey {
    fn verify(&self, msg: &[u8], signature: &DynamicSignature) -> Result<(), Error> {
        self.data
            .public_key()
            .and_then(|pk| pk.verify(msg, signature.as_ref()))
    }
}

impl PicnicKey for DynamicSigningKey {
    #[inline(always)]
    fn param(&self) -> picnic_params_t {
        self.data.param()
    }

    #[inline(always)]
    fn serialized_size(&self) -> usize {
        self.data.serialized_size()
    }
}

impl AsRef<[u8]> for DynamicSigningKey {
    fn as_ref(&self) -> &[u8] {
        // FIXME: this breaks the abstraction layer; this should be a call to picnic_write_private_key
        &self.data.as_ref().data[0..self.serialized_size()]
    }
}

impl TryFrom<&[u8]> for DynamicSigningKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let sk = PrivateKey::try_from(value)?;
        match sk.param() != picnic_params_t::PARAMETER_SET_INVALID {
            true => Ok(DynamicSigningKey { data: sk }),
            false => Err(Self::Error::new()),
        }
    }
}

impl PartialEq for DynamicSigningKey {
    fn eq(&self, other: &Self) -> bool {
        self.param() == other.param() && {
            let size = self.serialized_size();
            self.data.as_ref().data[..size] == other.data.as_ref().data[..size]
        }
    }
}

impl Eq for DynamicSigningKey {}

#[cfg(feature = "serialization")]
impl Serialize for DynamicSigningKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize(self, serializer)
    }
}

#[cfg(feature = "serialization")]
impl<'de> Deserialize<'de> for DynamicSigningKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize(deserializer)
    }
}

/// Verification key
#[derive(Clone, Debug)]
pub struct DynamicVerificationKey {
    data: PublicKey,
}

impl Verifier<DynamicSignature> for DynamicVerificationKey {
    fn verify(&self, msg: &[u8], signature: &DynamicSignature) -> Result<(), Error> {
        self.verify_raw(msg, &signature.0)
    }
}

impl RawVerifier for DynamicVerificationKey {
    fn verify_raw(&self, msg: &[u8], signature: &[u8]) -> Result<(), Error> {
        self.data.verify(msg, signature)
    }
}

impl PicnicKey for DynamicVerificationKey {
    #[inline(always)]
    fn param(&self) -> picnic_params_t {
        self.data.param()
    }

    #[inline(always)]
    fn serialized_size(&self) -> usize {
        self.data.serialized_size()
    }
}

impl AsRef<[u8]> for DynamicVerificationKey {
    fn as_ref(&self) -> &[u8] {
        // FIXME: this breaks the abstraction layer; this should be a call to picnic_write_public_key
        &self.data.as_ref().data[0..self.serialized_size()]
    }
}

impl TryFrom<&[u8]> for DynamicVerificationKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let vk = PublicKey::try_from(value)?;
        match vk.param() != picnic_params_t::PARAMETER_SET_INVALID {
            true => Ok(DynamicVerificationKey { data: vk }),
            false => Err(Self::Error::new()),
        }
    }
}

impl TryFrom<&DynamicSigningKey> for DynamicVerificationKey {
    type Error = Error;

    fn try_from(sk: &DynamicSigningKey) -> Result<Self, Self::Error> {
        sk.data.public_key().map(|vk| Self { data: vk })
    }
}

impl PartialEq for DynamicVerificationKey {
    fn eq(&self, other: &Self) -> bool {
        self.param() == other.param() && {
            let size = self.serialized_size();
            self.data.as_ref().data[..size] == other.data.as_ref().data[..size]
        }
    }
}

impl Eq for DynamicVerificationKey {}

#[cfg(feature = "serialization")]
impl Serialize for DynamicVerificationKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize(self, serializer)
    }
}

#[cfg(feature = "serialization")]
impl<'de> Deserialize<'de> for DynamicVerificationKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize(deserializer)
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "picnic")]
    use crate::{PicnicL1FSSigningKey, PicnicL1FullSigningKey, PicnicL1FullVerificationKey};

    #[cfg(feature = "picnic")]
    #[test]
    fn serialization_param_mismatch() {
        let (sk1, vk1) = PicnicL1FSSigningKey::random().expect("unable to generate keys");
        PicnicL1FullSigningKey::try_from(sk1.as_ref()).expect_err("deserialization did not fail");
        PicnicL1FullVerificationKey::try_from(vk1.as_ref())
            .expect_err("deserialization did not fail");
    }
}
