#[generic_tests::define]
mod tests {
    use picnic_bindings::{
        signature::{Signer, Verifier},
        DynamicSignature, DynamicSigningKey, DynamicVerificationKey, Parameters, SigningKey,
        VerificationKey,
    };
    use std::convert::TryFrom;

    const TEST_MESSAGE: &[u8] = "test message".as_bytes();

    #[cfg(feature = "picnic")]
    use picnic_bindings::{
        PicnicL1FS, PicnicL1Full, PicnicL3FS, PicnicL3Full, PicnicL5FS, PicnicL5Full,
    };

    #[cfg(feature = "unruh-transform")]
    use picnic_bindings::{PicnicL1UR, PicnicL3UR, PicnicL5UR};

    #[cfg(feature = "picnic3")]
    use picnic_bindings::{Picnic3L1, Picnic3L3, Picnic3L5};

    #[test]
    fn keygen<P: Parameters>() {
        assert!(SigningKey::<P>::random().is_ok());
    }

    #[test]
    fn dynamic_keygen<P: Parameters>() {
        assert!(DynamicSigningKey::random(P::PARAM).is_ok());
    }

    #[test]
    fn vk_match<P: Parameters>() {
        let (sk, vk) = SigningKey::<P>::random().unwrap();
        assert_eq!(vk, sk.verifying_key().unwrap());
    }

    #[test]
    fn dynamic_vk_match<P: Parameters>() {
        let (sk, vk) = DynamicSigningKey::random(P::PARAM).unwrap();
        assert_eq!(vk, sk.verifying_key().unwrap());
    }

    #[test]
    fn sign_and_verify<P: Parameters>() {
        let (sk, vk) = SigningKey::<P>::random().unwrap();
        let signature = sk.sign(TEST_MESSAGE);
        vk.verify(TEST_MESSAGE, &signature).unwrap();
    }

    #[test]
    fn dynamic_sign_and_verify<P: Parameters>() {
        let (sk, vk) = DynamicSigningKey::random(P::PARAM).unwrap();
        let signature = sk.sign(TEST_MESSAGE);
        vk.verify(TEST_MESSAGE, &signature).unwrap();
    }

    #[test]
    fn serialize_signature<P: Parameters>() {
        let (sk, vk) = SigningKey::<P>::random().unwrap();
        let signature = sk.sign(TEST_MESSAGE);
        let signature2 = DynamicSignature::from(signature.as_ref());
        assert_eq!(signature, signature2);
        vk.verify(TEST_MESSAGE, &signature2).unwrap();
    }

    #[test]
    fn serialize_keys<P: Parameters>() {
        let (sk, vk) = SigningKey::<P>::random().unwrap();

        let sk2 = SigningKey::<P>::try_from(sk.as_ref()).unwrap();
        let vk2 = VerificationKey::<P>::try_from(vk.as_ref()).unwrap();

        assert_eq!(sk, sk2);
        assert_eq!(vk, vk2)
    }

    #[test]
    fn dynamic_serialize_keys<P: Parameters>() {
        let (sk, vk) = DynamicSigningKey::random(P::PARAM).unwrap();

        let sk2 = DynamicSigningKey::try_from(sk.as_ref()).unwrap();
        let vk2 = DynamicVerificationKey::try_from(vk.as_ref()).unwrap();

        assert_eq!(sk, sk2);
        assert_eq!(vk, vk2)
    }

    #[test]
    fn serialize_keys_dynamic_and_back<P: Parameters>() {
        let (sk1, vk1) = SigningKey::<P>::random().unwrap();

        let sk2 = DynamicSigningKey::try_from(sk1.as_ref()).unwrap();
        let vk2 = DynamicVerificationKey::try_from(vk1.as_ref()).unwrap();

        let sk3 = SigningKey::<P>::try_from(sk2.as_ref()).unwrap();
        let vk3 = VerificationKey::<P>::try_from(vk2.as_ref()).unwrap();

        assert_eq!(sk1, sk3);
        assert_eq!(vk1, vk3);

        let signature1 = sk1.sign(TEST_MESSAGE);
        let signature2 = sk2.sign(TEST_MESSAGE);

        vk1.verify(TEST_MESSAGE, &signature2).unwrap();
        vk2.verify(TEST_MESSAGE, &signature1).unwrap();
    }

    #[cfg(feature = "picnic")]
    #[instantiate_tests(<PicnicL1FS>)]
    mod picnic_l1_fs {}

    #[cfg(feature = "unruh-transform")]
    #[instantiate_tests(<PicnicL1UR>)]
    mod picnic_l1_ur {}

    #[cfg(feature = "picnic")]
    #[instantiate_tests(<PicnicL1Full>)]
    mod picnic_l1_full {}

    #[cfg(feature = "picnic3")]
    #[instantiate_tests(<Picnic3L1>)]
    mod picnic3_l1 {}

    #[cfg(feature = "picnic")]
    #[instantiate_tests(<PicnicL3FS>)]
    mod picnic_l3_fs {}

    #[cfg(feature = "unruh-transform")]
    #[instantiate_tests(<PicnicL3UR>)]
    mod picnic_l3_ur {}

    #[cfg(feature = "picnic")]
    #[instantiate_tests(<PicnicL3Full>)]
    mod picnic_l3_full {}

    #[cfg(feature = "picnic3")]
    #[instantiate_tests(<Picnic3L3>)]
    mod picnic3_l3 {}

    #[cfg(feature = "picnic")]
    #[instantiate_tests(<PicnicL5FS>)]
    mod picnic_l5_fs {}

    #[cfg(feature = "unruh-transform")]
    #[instantiate_tests(<PicnicL5UR>)]
    mod picnic_l5_ur {}

    #[cfg(feature = "picnic")]
    #[instantiate_tests(<PicnicL5Full>)]
    mod picnic_l5_full {}

    #[cfg(feature = "picnic3")]
    #[instantiate_tests(<Picnic3L5>)]
    mod picnic3_l5 {}
}
