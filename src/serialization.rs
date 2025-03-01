//! This modules provides some helpers for serialization and deserialization of keys and signatures.
//!
//! The module is only included if the `serialization` feature is active.

#[cfg(not(feature = "std"))]
use alloc::fmt;

#[cfg(feature = "std")]
use std::fmt;

use core::marker::PhantomData;
use serde::{
    Deserializer, Serializer,
    de::{Error, Unexpected, Visitor},
};

/// Serialize a value as bytes
pub(crate) fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serde_bytes::serialize(value.as_ref(), serializer)
}

/// Helper for the implementation of [serde]'s [Visitor] trait
struct BytesVisitor<T>(PhantomData<T>);

impl<'de, T> Visitor<'de> for BytesVisitor<T>
where
    T: for<'a> TryFrom<&'a [u8]>,
{
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a byte array")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: Error,
    {
        T::try_from(v).map_err(|_| Error::invalid_value(Unexpected::Bytes(v), &self))
    }

    fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
    where
        E: Error,
    {
        T::try_from(v).map_err(|_| Error::invalid_value(Unexpected::Bytes(v), &self))
    }
}

/// Deserialize a value from its byte representation
pub(crate) fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: for<'a> TryFrom<&'a [u8]>,
    D: Deserializer<'de>,
{
    deserializer.deserialize_bytes(BytesVisitor::<T>(PhantomData))
}
