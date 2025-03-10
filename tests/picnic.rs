#[generic_tests::define]
mod tests {
    use picnic_bindings::{
        DynamicSignature, DynamicSigningKey, DynamicVerificationKey, Parameters, RawVerifier,
        Signer, SigningKey, VerificationKey, Verifier,
    };

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
        let (sk, vk) = SigningKey::<P>::random().expect("keygen success");
        assert_eq!(vk, (&sk).try_into().expect("sk convertible to vk"));
    }

    #[test]
    fn dynamic_vk_match<P: Parameters>() {
        let (sk, vk) = DynamicSigningKey::random(P::PARAM).expect("keygen success");
        assert_eq!(vk, (&sk).try_into().expect("sk convertible to vk"));
    }

    #[test]
    fn sign_and_verify<P: Parameters>() {
        let (sk, vk) = SigningKey::<P>::random().expect("keygen success");
        let signature: DynamicSignature = sk.sign(TEST_MESSAGE);
        vk.verify(TEST_MESSAGE, &signature)
            .expect("signatures verifies");
        vk.verify_raw(TEST_MESSAGE, signature.as_ref())
            .expect("signature verifies as &[u8]");
        sk.verify(TEST_MESSAGE, &signature)
            .expect("signature verifies with sk");
    }

    #[test]
    fn dynamic_sign_and_verify<P: Parameters>() {
        let (sk, vk) = DynamicSigningKey::random(P::PARAM).expect("keygen success");
        let signature: DynamicSignature = sk.sign(TEST_MESSAGE);
        vk.verify(TEST_MESSAGE, &signature)
            .expect("signatures verifies");
        vk.verify_raw(TEST_MESSAGE, signature.as_ref())
            .expect("signature verifies as &[u8]");
        sk.verify(TEST_MESSAGE, &signature)
            .expect("signature verifies with sk");
    }

    #[test]
    fn serialize_signature<P: Parameters>() {
        let (sk, vk) = SigningKey::<P>::random().expect("keygen success");
        let signature: DynamicSignature = sk.sign(TEST_MESSAGE);
        let signature2 = DynamicSignature::from(signature.as_ref());
        assert_eq!(signature, signature2);
        vk.verify(TEST_MESSAGE, &signature2)
            .expect("signature verifies");
    }

    #[test]
    fn serialize_keys<P: Parameters>() {
        let (sk, vk) = SigningKey::<P>::random().expect("keygen success");

        let sk2 = SigningKey::<P>::try_from(sk.as_ref()).expect("sk -> [u8] -> sk");
        let vk2 = VerificationKey::<P>::try_from(vk.as_ref()).expect("vk -> [u8] -> vk");

        assert_eq!(sk, sk2);
        assert_eq!(vk, vk2)
    }

    #[test]
    fn dynamic_serialize_keys<P: Parameters>() {
        let (sk, vk) = DynamicSigningKey::random(P::PARAM).expect("keygen success");

        let sk2 = DynamicSigningKey::try_from(sk.as_ref()).expect("sk -> [u8] -> sk");
        let vk2 = DynamicVerificationKey::try_from(vk.as_ref()).expect("vk -> [u8] -> vk");

        assert_eq!(sk, sk2);
        assert_eq!(vk, vk2)
    }

    #[test]
    fn serialize_keys_dynamic_and_back<P: Parameters>() {
        let (sk1, vk1) = SigningKey::<P>::random().expect("keygen success");

        let sk2 = DynamicSigningKey::try_from(sk1.as_ref()).expect("sk -> [u8] -> sk");
        let vk2 = DynamicVerificationKey::try_from(vk1.as_ref()).expect("vk -> [u8] -> vk");

        let sk3 = SigningKey::<P>::try_from(sk2.as_ref()).expect("sk -> [u8] -> sk");
        let vk3 = VerificationKey::<P>::try_from(vk2.as_ref()).expect("vk -> [u8] -> vk");

        assert_eq!(sk1, sk3);
        assert_eq!(vk1, vk3);

        let signature1: DynamicSignature = sk1.sign(TEST_MESSAGE);
        let signature2: DynamicSignature = sk2.sign(TEST_MESSAGE);

        vk1.verify(TEST_MESSAGE, &signature2)
            .expect("signature2 verifies under vk1");
        vk2.verify(TEST_MESSAGE, &signature1)
            .expect("signature1 verifies under vk2");
    }

    #[cfg(feature = "subtle")]
    #[test]
    fn subtle_eq<P: Parameters>() {
        use subtle::ConstantTimeEq;

        let (sk1, _vk1) = SigningKey::<P>::random().expect("keygen success");
        let (sk2, _vk2) = SigningKey::<P>::random().expect("keygen success");
        let sk3 = sk1.clone();

        assert!(bool::from(sk1.ct_eq(&sk1)));
        assert!(bool::from(sk1.ct_eq(&sk3)));
        assert!(!bool::from(sk1.ct_eq(&sk2)));
    }

    #[cfg(feature = "serialization")]
    mod serialization_helpers {
        use super::*;
        pub(crate) use serde::{Deserialize, Serialize, de::DeserializeOwned};

        #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
        pub(crate) struct KeyPair<P: Parameters> {
            pub(crate) sk: SigningKey<P>,
            pub(crate) vk: VerificationKey<P>,
        }

        #[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
        pub(crate) struct DynamicKeyPair {
            pub(crate) sk: DynamicSigningKey,
            pub(crate) vk: DynamicVerificationKey,
        }
    }

    #[cfg(feature = "serialization")]
    use serialization_helpers::{
        Deserialize, DeserializeOwned, DynamicKeyPair, KeyPair, Serialize,
    };

    #[cfg(feature = "serialization")]
    #[test]
    fn serde_serialization<P: Parameters>()
    where
        KeyPair<P>: Serialize + DeserializeOwned,
    {
        let mut out = vec![];
        let mut ser = serde_json::Serializer::new(&mut out);
        let ser = serde_bytes_repr::ByteFmtSerializer::hex(&mut ser);

        let (sk1, vk1) = SigningKey::<P>::random().expect("keygen success");
        let kp1 = KeyPair { sk: sk1, vk: vk1 };
        kp1.serialize(ser).expect("serialize key pair");
        let serialized = String::from_utf8(out).expect("serialize to string");

        let mut json_de = serde_json::Deserializer::from_str(&serialized);
        let bytefmt_json_de = serde_bytes_repr::ByteFmtDeserializer::new_hex(&mut json_de);

        let kp2 = KeyPair::deserialize(bytefmt_json_de).expect("deserialize key pair");
        assert_eq!(kp1.sk, kp2.sk);
        assert_eq!(kp1.vk, kp2.vk);
    }

    #[cfg(feature = "serialization")]
    #[test]
    fn dynamic_serde_serialization<P: Parameters>() {
        let mut out = vec![];
        let mut ser = serde_json::Serializer::new(&mut out);
        let ser = serde_bytes_repr::ByteFmtSerializer::hex(&mut ser);

        let (sk1, vk1) = DynamicSigningKey::random(P::PARAM).expect("keygen success");
        let kp1 = DynamicKeyPair { sk: sk1, vk: vk1 };
        kp1.serialize(ser).expect("serialize key pair");
        let serialized = String::from_utf8(out).expect("serialize to string");

        let mut json_de = serde_json::Deserializer::from_str(&serialized);
        let bytefmt_json_de = serde_bytes_repr::ByteFmtDeserializer::new_hex(&mut json_de);

        let kp2 = DynamicKeyPair::deserialize(bytefmt_json_de).expect("deserialize key pair");
        assert_eq!(kp1, kp2);
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
