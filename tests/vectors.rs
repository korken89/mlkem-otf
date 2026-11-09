//! NIST ACVP and Wycheproof vectors through the public API.
//!
//! `data/` holds the ML-KEM-768 cases, trimmed to the fields used here, from
//! usnistgov/ACVP-Server `gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json` and
//! `gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json` (975de31eb83d) and
//! C2SP/wycheproof `testvectors_v1/mlkem_768_{keygen_seed,encaps,semi_expanded_decaps}_test.json`
//! and `testvectors_v1/mlkem_768_test.json` (d17cc89fa5c8). Cases with a wrong key or ciphertext
//! length are left out since the API takes arrays. The ACVP decapsulation cases and the
//! semi-expanded Wycheproof cases give an expanded decapsulation key instead of a seed, so the
//! unit tests run them.

use mlkem_otf::{
    DecapsulationKey, DecapsulationKeySlot, EncapsulationKey, InvalidEncapsulationKey,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    tc_id: u32,
    #[serde(default)]
    comment: String,
    #[serde(default)]
    result: String,
    #[serde(default)]
    test_passed: Option<bool>,
    #[serde(default, with = "hex")]
    d: Vec<u8>,
    #[serde(default, with = "hex")]
    z: Vec<u8>,
    #[serde(default, with = "hex")]
    seed: Vec<u8>,
    #[serde(default, with = "hex")]
    ek: Vec<u8>,
    #[serde(default, with = "hex")]
    m: Vec<u8>,
    #[serde(default, with = "hex")]
    c: Vec<u8>,
    #[serde(default, alias = "K", with = "hex")]
    k: Vec<u8>,
}

fn cases(json: &str) -> Vec<Case> {
    serde_json::from_str(json).unwrap()
}

/// Generates the encapsulation key of `seed`, checks it against `ek` if given and binds it.
fn keygen(mut seed: [u8; 64], ek: &[u8], id: u32) -> [u8; 1184] {
    let mut slot = DecapsulationKeySlot::new();
    let dk = DecapsulationKey::from_seed(&mut slot, &mut seed);
    let mut out = [0; 1184];
    dk.encapsulation_key(&mut out);
    if !ek.is_empty() {
        assert_eq!(out[..], ek[..], "tcId {id}");
    }
    assert!(dk.bind(&out).is_ok(), "tcId {id}");
    out
}

#[test]
fn acvp_keygen() {
    let cases = cases(include_str!("data/acvp_mlkem_768_keygen.json"));
    for case in &cases {
        let seed = [&case.d[..], &case.z[..]].concat().try_into().unwrap();
        keygen(seed, &case.ek, case.tc_id);
    }
    assert_eq!(cases.len(), 25);
}

#[test]
fn acvp_encapsulation() {
    let cases = cases(include_str!("data/acvp_mlkem_768_encap.json"));
    for case in &cases {
        let ek = case.ek[..].try_into().unwrap();
        let ek = EncapsulationKey::new(ek).unwrap();
        let mut ct = [0; 1088];
        let m: [u8; 32] = case.m[..].try_into().unwrap();
        let k = ek.encapsulate_deterministic(&m.into(), &mut ct);
        assert_eq!(ct[..], case.c[..], "tcId {}", case.tc_id);
        assert_eq!(k.expose_secret()[..], case.k[..], "tcId {}", case.tc_id);
    }
    assert_eq!(cases.len(), 25);
}

#[test]
fn acvp_encapsulation_key_check() {
    let cases = cases(include_str!("data/acvp_mlkem_768_ek_check.json"));
    for case in &cases {
        let ek = case.ek[..].try_into().unwrap();
        let passed = case.test_passed.unwrap();
        assert_eq!(
            EncapsulationKey::new(ek).is_ok(),
            passed,
            "tcId {}",
            case.tc_id
        );
    }
    assert_eq!(cases.len(), 10);
}

#[test]
fn wycheproof_keygen() {
    let cases = cases(include_str!("data/wycheproof_mlkem_768_keygen_seed.json"));
    for case in &cases {
        keygen(case.seed[..].try_into().unwrap(), &case.ek, case.tc_id);
    }
    assert_eq!(cases.len(), 100);
}

/// Decapsulation from the seed, including modified ciphertexts that must give the implicit
/// rejection key.
#[test]
fn wycheproof_decapsulation() {
    let cases = cases(include_str!("data/wycheproof_mlkem_768.json"));
    for case in &cases {
        assert_eq!(case.result, "valid", "tcId {}", case.tc_id);
        let mut seed = case.seed[..].try_into().unwrap();
        let ek = keygen(seed, &[], case.tc_id);
        let mut slot = DecapsulationKeySlot::new();
        let k = DecapsulationKey::from_seed(&mut slot, &mut seed)
            .bind(&ek)
            .unwrap()
            .decapsulate(case.c[..].try_into().unwrap());
        let id = (case.tc_id, &case.comment);
        assert_eq!(k.expose_secret()[..], case.k[..], "{id:?}");
    }
    assert_eq!(cases.len(), 161);
}

#[test]
fn wycheproof_encapsulation() {
    let cases = cases(include_str!("data/wycheproof_mlkem_768_encaps.json"));
    let mut invalid = 0;
    for case in &cases {
        let id = (case.tc_id, &case.comment);
        let ek = EncapsulationKey::new(case.ek[..].try_into().unwrap());
        if case.result == "invalid" {
            assert_eq!(ek.err(), Some(InvalidEncapsulationKey), "{id:?}");
            invalid += 1;
            continue;
        }
        let mut ct = [0; 1088];
        let m: [u8; 32] = case.m[..].try_into().unwrap();
        let k = ek.unwrap().encapsulate_deterministic(&m.into(), &mut ct);
        assert_eq!(ct[..], case.c[..], "{id:?}");
        assert_eq!(k.expose_secret()[..], case.k[..], "{id:?}");
    }
    assert_eq!((cases.len(), invalid), (245, 112));
}
