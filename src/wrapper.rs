use picnic_sys::*;
use signature::Error;
use std::convert::TryFrom;

/// Newtype pattern for `picnic_privatekey_t`
#[derive(Clone, Debug)]
pub(crate) struct PrivateKey(picnic_privatekey_t);

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

/// Newtype pattern for `picnic_publickey_t`
#[derive(Clone, Debug)]
pub(crate) struct PublicKey(picnic_publickey_t);

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
        match unsafe { picnic_read_public_key(&mut pk.0, value.as_ptr(), value.len()) } {
            0 => Ok(pk),
            _ => Err(Self::Error::new()),
        }
    }
}

pub(crate) trait PicnicKey {
    fn param(&self) -> picnic_params_t;
}

impl PicnicKey for PrivateKey {
    fn param(&self) -> picnic_params_t {
        unsafe { picnic_get_private_key_param(&self.0) }
    }
}

impl PicnicKey for PublicKey {
    fn param(&self) -> picnic_params_t {
        unsafe { picnic_get_public_key_param(&self.0) }
    }
}
