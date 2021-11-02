use core::convert::TryFrom;
use picnic_sys::*;
use signature::Error;

/// Common properties of a Picnic key
pub(crate) trait PicnicKey {
    /// Retrieve the corresponding parameter set
    fn param(&self) -> picnic_params_t;

    /// Retrieve the size of the serialized object
    fn serialized_size(&self) -> usize;
}

/// Newtype pattern for `picnic_privatekey_t`
#[derive(Clone, Debug)]
pub(crate) struct PrivateKey(picnic_privatekey_t);

impl PrivateKey {
    pub(crate) fn random(param: picnic_params_t) -> Result<(PrivateKey, PublicKey), Error> {
        let mut sk = PrivateKey::default();
        let mut vk = PublicKey::default();

        match unsafe { picnic_keygen(param, vk.as_mut(), sk.as_mut()) } {
            0 => Ok((sk, vk)),
            _ => Err(Error::new()),
        }
    }

    pub(crate) fn try_sign(&self, msg: &[u8], signature: &mut [u8]) -> Result<size_t, Error> {
        let mut length: size_t = signature.len();
        match unsafe {
            picnic_sign(
                self.as_ref(),
                msg.as_ptr(),
                msg.len(),
                signature.as_mut_ptr(),
                &mut length,
            )
        } {
            0 => Ok(length),
            _ => Err(Error::new()),
        }
    }

    pub(crate) fn public_key(&self) -> Result<PublicKey, Error> {
        let mut vk = PublicKey::default();
        match unsafe { picnic_sk_to_pk(self.as_ref(), vk.as_mut()) } {
            0 => Ok(vk),
            _ => Err(Error::new()),
        }
    }
}

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
            picnic_clear_private_key(self.as_mut());
        }
    }
}

impl AsMut<picnic_privatekey_t> for PrivateKey {
    fn as_mut(&mut self) -> &mut picnic_privatekey_t {
        &mut self.0
    }
}

impl AsRef<picnic_privatekey_t> for PrivateKey {
    fn as_ref(&self) -> &picnic_privatekey_t {
        &self.0
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut sk = Self::default();
        match unsafe { picnic_read_private_key(sk.as_mut(), value.as_ptr(), value.len()) } {
            0 => Ok(sk),
            _ => Err(Self::Error::new()),
        }
    }
}

impl PicnicKey for PrivateKey {
    fn param(&self) -> picnic_params_t {
        unsafe { picnic_get_private_key_param(self.as_ref()) }
    }

    fn serialized_size(&self) -> usize {
        unsafe { picnic_get_private_key_size(self.param()) }
    }
}

/// Newtype pattern for `picnic_publickey_t`
#[derive(Clone, Debug)]
pub(crate) struct PublicKey(picnic_publickey_t);

impl PublicKey {
    pub(crate) fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), Error> {
        match unsafe {
            picnic_verify(
                self.as_ref(),
                msg.as_ptr(),
                msg.len(),
                signature.as_ptr(),
                signature.len(),
            )
        } {
            0 => Ok(()),
            _ => Err(Error::new()),
        }
    }
}

impl Default for PublicKey {
    fn default() -> Self {
        Self {
            0: picnic_publickey_t {
                data: [0; PICNIC_MAX_PUBLICKEY_SIZE],
            },
        }
    }
}

impl AsMut<picnic_publickey_t> for PublicKey {
    fn as_mut(&mut self) -> &mut picnic_publickey_t {
        &mut self.0
    }
}

impl AsRef<picnic_publickey_t> for PublicKey {
    fn as_ref(&self) -> &picnic_publickey_t {
        &self.0
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut pk = Self::default();
        match unsafe { picnic_read_public_key(pk.as_mut(), value.as_ptr(), value.len()) } {
            0 => Ok(pk),
            _ => Err(Self::Error::new()),
        }
    }
}

impl PicnicKey for PublicKey {
    fn param(&self) -> picnic_params_t {
        unsafe { picnic_get_public_key_param(self.as_ref()) }
    }

    fn serialized_size(&self) -> usize {
        unsafe { picnic_get_public_key_size(self.param()) }
    }
}
