use picnic_sys::{
    picnic_get_private_key_param, picnic_get_public_key_param, picnic_params_t,
    picnic_privatekey_t, picnic_publickey_t, picnic_read_private_key, picnic_read_public_key,
    picnic_sign, picnic_signature_size, picnic_validate_keypair, picnic_verify,
    PICNIC_MAX_PRIVATEKEY_SIZE, PICNIC_MAX_PUBLICKEY_SIZE,
};

#[derive(Default, Clone)]
struct TestVector {
    message: Vec<u8>,
    pk: Vec<u8>,
    sk: Vec<u8>,
    sm: Vec<u8>,
}

fn parse_hex(value: &str) -> Vec<u8> {
    hex::decode(value).expect("hex value")
}

fn read_kats(kats: &str) -> Vec<TestVector> {
    let mut ret = Vec::new();

    let mut kat = TestVector::default();
    for line in kats.lines() {
        // skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // ignore seed, message and signature lengths
        if line.starts_with("mlen") || line.starts_with("seed") || line.starts_with("smlen") {
            continue;
        }

        let (kind, value) = line.split_once(" = ").expect("kind = value");
        match kind {
            "count" => {}
            "sk" => {
                kat.sk = parse_hex(value);
            }
            "pk" => {
                kat.pk = parse_hex(value);
            }
            "msg" => {
                kat.message = parse_hex(value);
            }
            "sm" => {
                kat.sm = parse_hex(value);
                assert!(
                    !kat.sk.is_empty()
                        && !kat.pk.is_empty()
                        && !kat.message.is_empty()
                        && !kat.sm.is_empty()
                );
                ret.push(kat);
                kat = TestVector::default();
            }
            _ => {
                unreachable!("unknown kind");
            }
        }
    }
    ret
}

fn run_test(param: picnic_params_t, kat: TestVector) {
    let mut sk = picnic_privatekey_t {
        data: [0; PICNIC_MAX_PRIVATEKEY_SIZE],
    };
    let mut pk = picnic_publickey_t {
        data: [0; PICNIC_MAX_PUBLICKEY_SIZE],
    };

    assert_eq!(
        unsafe { picnic_read_private_key(&mut sk, kat.sk.as_ptr(), kat.sk.len()) },
        0
    );
    assert_eq!(
        unsafe { picnic_read_public_key(&mut pk, kat.pk.as_ptr(), kat.pk.len()) },
        0
    );
    assert_eq!(unsafe { picnic_validate_keypair(&sk, &pk) }, 0);
    assert_eq!(unsafe { picnic_get_public_key_param(&pk) }, param);
    assert_eq!(unsafe { picnic_get_private_key_param(&sk) }, param);

    // signatures in test vectors is: 4 bytes length, message, signature
    let original_sig = &kat.sm[4 + kat.message.len()..];
    // verify signature from KAT
    assert_eq!(
        unsafe {
            picnic_verify(
                &pk,
                kat.message.as_ptr(),
                kat.message.len(),
                original_sig.as_ptr(),
                original_sig.len(),
            )
        },
        0
    );

    // recreate signature
    let mut sig = vec![0; unsafe { picnic_signature_size(param) }];
    let mut signature_length = sig.len();
    assert_eq!(
        unsafe {
            picnic_sign(
                &sk,
                kat.message.as_ptr(),
                kat.message.len(),
                sig.as_mut_ptr(),
                &mut signature_length,
            )
        },
        0,
    );
    sig.resize(signature_length, 0u8);
    assert_eq!(original_sig, sig);
}

#[cfg(feature = "picnic")]
#[test]
fn kats_picnic_l1_fs() {
    for kat in read_kats(include_str!("../Picnic/tests/kat_l1_fs.txt")) {
        run_test(picnic_params_t::Picnic_L1_FS, kat);
    }
}

#[cfg(feature = "picnic")]
#[test]
fn kats_picnic_l3_fs() {
    for kat in read_kats(include_str!("../Picnic/tests/kat_l3_fs.txt")) {
        run_test(picnic_params_t::Picnic_L3_FS, kat);
    }
}

#[cfg(feature = "picnic")]
#[test]
fn kats_picnic_l5_fs() {
    for kat in read_kats(include_str!("../Picnic/tests/kat_l5_fs.txt")) {
        run_test(picnic_params_t::Picnic_L5_FS, kat);
    }
}

#[cfg(feature = "unruh-transform")]
#[test]
fn kats_picnic_l1_ur() {
    for kat in read_kats(include_str!("../Picnic/tests/kat_l1_ur.txt")) {
        run_test(picnic_params_t::Picnic_L1_UR, kat);
    }
}

#[cfg(feature = "unruh-transform")]
#[test]
fn kats_picnic_l3_ur() {
    for kat in read_kats(include_str!("../Picnic/tests/kat_l3_ur.txt")) {
        run_test(picnic_params_t::Picnic_L3_UR, kat);
    }
}

#[cfg(feature = "unruh-transform")]
#[test]
fn kats_picnic_l5_ur() {
    for kat in read_kats(include_str!("../Picnic/tests/kat_l5_ur.txt")) {
        run_test(picnic_params_t::Picnic_L5_UR, kat);
    }
}

#[cfg(feature = "picnic")]
#[test]
fn kats_picnic_l1_full() {
    for kat in read_kats(include_str!("../Picnic/tests/kat_l1_full.txt")) {
        run_test(picnic_params_t::Picnic_L1_full, kat);
    }
}

#[cfg(feature = "picnic")]
#[test]
fn kats_picnic_l3_full() {
    for kat in read_kats(include_str!("../Picnic/tests/kat_l3_full.txt")) {
        run_test(picnic_params_t::Picnic_L3_full, kat);
    }
}

#[cfg(feature = "picnic")]
#[test]
fn kats_picnic_l5_full() {
    for kat in read_kats(include_str!("../Picnic/tests/kat_l5_full.txt")) {
        run_test(picnic_params_t::Picnic_L5_full, kat);
    }
}

#[cfg(feature = "picnic3")]
#[test]
fn kats_picnic3_l1() {
    for kat in read_kats(include_str!("../Picnic/tests/kat_picnic3_l1.txt")) {
        run_test(picnic_params_t::Picnic3_L1, kat);
    }
}

#[cfg(feature = "picnic3")]
#[test]
fn kats_picnic3_l3() {
    for kat in read_kats(include_str!("../Picnic/tests/kat_picnic3_l3.txt")) {
        run_test(picnic_params_t::Picnic3_L3, kat);
    }
}

#[cfg(feature = "picnic3")]
#[test]
fn kats_picnic_l5() {
    for kat in read_kats(include_str!("../Picnic/tests/kat_picnic3_l5.txt")) {
        run_test(picnic_params_t::Picnic3_L5, kat);
    }
}
