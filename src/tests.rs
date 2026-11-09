//! Tests of the internals, and the vectors that give an expanded decapsulation key.

use serde::Deserialize;

use rand_core::{TryCryptoRng, TryRng};
use zeroize::Zeroize;

use crate::encode::{compress, decode12};
use crate::kpke::SecretVector;
use crate::ntt::{Poly, Q};
use crate::params::{MlKem768, Params};
use crate::{DecapsulationKey, DecapsulationKeySlot};

/// The multiply-and-shift Compress_d equals the definition with a division.
#[test]
fn compress_is_exact() {
    for d in [1, 4, 5, 10, 11] {
        for x in 0..Q as u32 {
            let expected = ((x << (d + 1)) + Q as u32) / (2 * Q as u32) % (1 << d);
            assert_eq!(compress(x, d), expected, "d {d} x {x}");
        }
    }
}

/// A slot is wiped by `zeroize`, which its drop calls, and by a refill before it is filled. A
/// refill that fails leaves it wiped.
#[test]
fn slot_is_wiped() {
    assert!(core::mem::needs_drop::<DecapsulationKeySlot>());
    let mut slot = DecapsulationKeySlot::new();
    DecapsulationKey::from_seed(&mut slot, &mut [7; 64]);
    assert_eq!((slot.0.d, slot.0.z), ([7; 32], [7; 32]));
    slot.zeroize();
    assert_eq!((slot.0.d, slot.0.z), ([0; 32], [0; 32]));

    DecapsulationKey::from_seed(&mut slot, &mut [7; 64]);
    let result = DecapsulationKey::try_generate(&mut slot, &mut OneFill(true));
    assert!(result.is_err());
    assert_eq!((slot.0.d, slot.0.z), ([0; 32], [0; 32]));
}

/// An RNG that fills once with 0x5a and then fails.
struct OneFill(bool);

#[derive(Debug, thiserror::Error)]
#[error("the RNG failed")]
struct Failed;

impl TryRng for OneFill {
    type Error = Failed;

    fn try_next_u32(&mut self) -> Result<u32, Failed> {
        Err(Failed)
    }

    fn try_next_u64(&mut self) -> Result<u64, Failed> {
        Err(Failed)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Failed> {
        if !core::mem::replace(&mut self.0, false) {
            return Err(Failed);
        }
        dst.fill(0x5a);
        Ok(())
    }
}

impl TryCryptoRng for OneFill {}

/// s_hat decoded from an expanded decapsulation key.
struct Expanded<'a>(&'a [u8]);

impl SecretVector for Expanded<'_> {
    fn entry(&self, j: u8, s_hat: &mut Poly) {
        let row = &self.0[384 * usize::from(j)..][..384];
        for (s, (a, b)) in s_hat.0.chunks_exact_mut(2).zip(decode12(row)) {
            s.copy_from_slice(&[a, b]);
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    tc_id: u32,
    #[serde(alias = "reason")]
    comment: String,
    #[serde(with = "hex")]
    dk: Vec<u8>,
    #[serde(with = "hex")]
    c: Vec<u8>,
    #[serde(alias = "K", with = "hex")]
    k: Vec<u8>,
}

/// Decapsulates with an expanded key dk_pke || ek || H(ek) || z (FIPS 203 Algorithm 16).
fn decapsulate_expanded(case: &Case) {
    let (dk_pke, rest) = case.dk.split_at(MlKem768::T_LEN);
    let (ek, rest) = rest.split_at(MlKem768::EK_LEN);
    let (h_ek, z) = rest.split_at(32);
    let k = crate::decapsulate(
        &Expanded(dk_pke),
        z.try_into().unwrap(),
        ek.try_into().unwrap(),
        h_ek.try_into().unwrap(),
        case.c[..].try_into().unwrap(),
    );
    let id = (case.tc_id, &case.comment);
    assert_eq!(k.expose_secret()[..], case.k[..], "{id:?}");
}

/// Valid and modified ciphertexts from usnistgov/ACVP-Server, see `tests/vectors.rs`.
#[test]
fn acvp_decapsulation() {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("../tests/data/acvp_mlkem_768_decap.json")).unwrap();
    cases.iter().for_each(decapsulate_expanded);
    assert_eq!(cases.len(), 10);
}

/// Keys that make a re-encryption compare that skips the last byte of c1 or c2 accept a
/// modified ciphertext, from C2SP/wycheproof, see `tests/vectors.rs`.
#[test]
fn wycheproof_semi_expanded_decapsulation() {
    let cases: Vec<Case> = serde_json::from_str(include_str!(
        "../tests/data/wycheproof_mlkem_768_semi_expanded_decaps.json"
    ))
    .unwrap();
    cases.iter().for_each(decapsulate_expanded);
    assert_eq!(cases.len(), 3);
}
