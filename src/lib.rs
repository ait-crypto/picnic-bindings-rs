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

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![warn(missing_docs)]

// If neither is specified, the crate is essentially empty.
#[cfg(all(not(feature = "picnic"), not(feature = "picnic3")))]
compile_error!("One of the features \"picnic\" and \"picnic3\" is required.");

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{
    fmt::{self, Debug},
    format, vec,
    vec::Vec,
};

#[cfg(feature = "std")]
use std::fmt::{self, Debug};

use core::marker::PhantomData;
use paste::paste;
use picnic_sys::*;
pub use signature::{self, Error};

#[cfg(feature = "serialization")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "subtle")]
use subtle::{Choice, ConstantTimeEq};

mod wrapper;
use crate::wrapper::*;

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
    fn parameter_name() -> &'static str;
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

/// Trait that allows to directly verify a signature from a `&[u8]`
///
/// With this trait verifiers are able to verify a signature without first storing it in a `Vec`.
pub trait RawVerifier {
    /// Verify a "raw" signature
    fn verify_raw(&self, msg: &[u8], signature: &[u8]) -> Result<(), Error>;
}

/// Define a parameters set and its associated implementations and types
// $realparam should be replaced by [<picnic_params_t:: $param>] but that does not compile.
macro_rules! define_params {
    ($name:ident, $param:ident, $realparam:expr) => {
        paste! {
            #[doc = $name " parameters"]
            #[derive(Clone, Debug, PartialEq, Eq)]
            #[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
            pub struct $name {}

            impl Parameters for $name {
                const PARAM: picnic_params_t = $realparam;
                const MAX_SIGNATURE_SIZE: usize = [<PICNIC_SIGNATURE_SIZE_ $param>];
                const PRIVATE_KEY_SIZE: usize = [<PICNIC_PRIVATE_KEY_SIZE_ $param>];
                const PUBLIC_KEY_SIZE: usize = [<PICNIC_PUBLIC_KEY_SIZE_ $param>];

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
define_params!(PicnicL1FS, Picnic_L1_FS, picnic_params_t::Picnic_L1_FS);
#[cfg(feature = "unruh-transform")]
define_params!(PicnicL1UR, Picnic_L1_UR, picnic_params_t::Picnic_L1_UR);
#[cfg(feature = "picnic")]
define_params!(
    PicnicL1Full,
    Picnic_L1_full,
    picnic_params_t::Picnic_L1_full
);
#[cfg(feature = "picnic3")]
define_params!(Picnic3L1, Picnic3_L1, picnic_params_t::Picnic3_L1);

#[cfg(feature = "picnic")]
define_params!(PicnicL3FS, Picnic_L3_FS, picnic_params_t::Picnic_L3_FS);
#[cfg(feature = "unruh-transform")]
define_params!(PicnicL3UR, Picnic_L3_UR, picnic_params_t::Picnic_L3_UR);
#[cfg(feature = "picnic")]
define_params!(
    PicnicL3Full,
    Picnic_L3_full,
    picnic_params_t::Picnic_L3_full
);
#[cfg(feature = "picnic3")]
define_params!(Picnic3L3, Picnic3_L3, picnic_params_t::Picnic3_L3);

#[cfg(feature = "picnic")]
define_params!(PicnicL5FS, Picnic_L5_FS, picnic_params_t::Picnic_L5_FS);
#[cfg(feature = "unruh-transform")]
define_params!(PicnicL5UR, Picnic_L5_UR, picnic_params_t::Picnic_L5_UR);
#[cfg(feature = "picnic")]
define_params!(
    PicnicL5Full,
    Picnic_L5_full,
    picnic_params_t::Picnic_L5_full
);
#[cfg(feature = "picnic3")]
define_params!(Picnic3L5, Picnic3_L5, picnic_params_t::Picnic3_L5);

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
    /// Sample a new random signing key and the corresponding verification key
    pub fn random() -> Result<(Self, VerificationKey<P>), Error> {
        let (sk, vk) = PrivateKey::random(P::PARAM)?;
        Ok((
            Self {
                data: sk,
                phantom_data: PhantomData,
            },
            VerificationKey {
                data: vk,
                phantom_data: PhantomData,
            },
        ))
    }
}

impl<P> Signer<DynamicSignature> for SigningKey<P>
where
    P: Parameters,
{
    type Verifier = VerificationKey<P>;

    fn verifier(&self) -> Result<Self::Verifier, Error> {
        let vk = self.data.public_key()?;
        Ok(Self::Verifier {
            data: vk,
            phantom_data: PhantomData,
        })
    }
}

impl<P> signature::Signer<DynamicSignature> for SigningKey<P>
where
    P: Parameters,
{
    fn try_sign(&self, msg: &[u8]) -> Result<DynamicSignature, Error> {
        let mut signature = vec![0; P::MAX_SIGNATURE_SIZE];

        let length = self.data.try_sign(msg, signature.as_mut_slice())?;
        signature.resize(length, 0);
        Ok(DynamicSignature { 0: signature })
    }
}

impl<P> PicnicKey for SigningKey<P>
where
    P: Parameters,
{
    fn param(&self) -> picnic_params_t {
        P::PARAM
    }

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
            .field("data", &self.data)
            .finish()
    }
}

impl<P> PartialEq for SigningKey<P>
where
    P: Parameters,
{
    fn eq(&self, other: &Self) -> bool {
        self.data.as_ref().data[..P::PRIVATE_KEY_SIZE]
            == other.data.as_ref().data[..P::PRIVATE_KEY_SIZE]
    }
}

impl<P> Eq for SigningKey<P> where P: Parameters {}

#[cfg(feature = "subtle")]
impl<P> ConstantTimeEq for SigningKey<P>
where
    P: Parameters,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.data.as_ref().data[..P::PRIVATE_KEY_SIZE]
            .ct_eq(&other.data.as_ref().data[..P::PRIVATE_KEY_SIZE])
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

impl<P> signature::Verifier<DynamicSignature> for VerificationKey<P>
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
    fn param(&self) -> picnic_params_t {
        P::PARAM
    }

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
        self.data.as_ref().data[..P::PUBLIC_KEY_SIZE]
            == other.data.as_ref().data[..P::PUBLIC_KEY_SIZE]
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
#[derive(Clone, Debug)]
pub struct DynamicSigningKey {
    data: PrivateKey,
}

impl DynamicSigningKey {
    /// Sample a new random signing key and the corresponding verification key
    pub fn random(params: picnic_params_t) -> Result<(Self, DynamicVerificationKey), Error> {
        let (sk, vk) = PrivateKey::random(params)?;
        Ok((Self { data: sk }, DynamicVerificationKey { data: vk }))
    }
}

impl Signer<DynamicSignature> for DynamicSigningKey {
    type Verifier = DynamicVerificationKey;

    fn verifier(&self) -> Result<Self::Verifier, Error> {
        let vk = self.data.public_key()?;
        Ok(Self::Verifier { data: vk })
    }
}

impl signature::Signer<DynamicSignature> for DynamicSigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<DynamicSignature, Error> {
        let mut signature = vec![0; signature_size(self.param())];
        let length = self.data.try_sign(msg, signature.as_mut_slice())?;
        signature.resize(length, 0);
        Ok(DynamicSignature { 0: signature })
    }
}

impl PicnicKey for DynamicSigningKey {
    fn param(&self) -> picnic_params_t {
        self.data.param()
    }

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

impl signature::Verifier<DynamicSignature> for DynamicVerificationKey {
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
    fn param(&self) -> picnic_params_t {
        self.data.param()
    }

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

#[cfg(feature = "serialization")]
fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serde_bytes::serialize(value.as_ref(), serializer)
}

#[cfg(feature = "serialization")]
fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: for<'a> TryFrom<&'a [u8]>,
    D: Deserializer<'de>,
{
    struct BytesVisitor<S>(PhantomData<S>);

    impl<'de, S> de::Visitor<'de> for BytesVisitor<S>
    where
        S: for<'a> TryFrom<&'a [u8]>,
    {
        type Value = S;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "a byte array")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            match S::try_from(v) {
                Ok(t) => Ok(t),
                Err(_) => Err(de::Error::invalid_value(de::Unexpected::Bytes(v), &self)),
            }
        }

        fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            match S::try_from(v) {
                Ok(t) => Ok(t),
                Err(_) => Err(de::Error::invalid_value(de::Unexpected::Bytes(v), &self)),
            }
        }
    }

    deserializer.deserialize_bytes(BytesVisitor::<T>(PhantomData))
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
