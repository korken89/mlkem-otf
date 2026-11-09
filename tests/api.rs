//! Key checks and implicit rejection through the public API.

use core::fmt::Debug;

use mlkem_otf::{
    BoundKey, DecapsulationKey, DecapsulationKeySlot, EncapsulationKey, InvalidEncapsulationKey,
    KeyMismatch, Randomness, SharedKey,
};
use rand_core::{TryCryptoRng, TryRng};
use shake::{ExtendableOutput, Shake256, Update};
use static_assertions::{assert_impl_all, assert_not_impl_any};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Secrets are wiped when dropped and cannot be copied, compared or printed.
assert_impl_all!(DecapsulationKey: ZeroizeOnDrop);
assert_impl_all!(DecapsulationKeySlot: Zeroize, ZeroizeOnDrop, Default);
assert_impl_all!(SharedKey: ZeroizeOnDrop);
assert_impl_all!(Randomness: ZeroizeOnDrop);
assert_not_impl_any!(DecapsulationKey: Clone, Copy, Debug, PartialEq, Default);
assert_not_impl_any!(DecapsulationKeySlot: Clone, Copy, Debug, PartialEq);
assert_not_impl_any!(SharedKey: Clone, Copy, Debug);
assert_not_impl_any!(Randomness: Clone, Copy, Debug);

// The key is filled in its slot and only lent out shared, so it cannot be moved out of it, and
// `bind` borrows it.
const _: for<'s> fn(&'s mut DecapsulationKeySlot, &mut [u8; 64]) -> &'s DecapsulationKey =
    DecapsulationKey::from_seed;
// A slot can be a `static`.
static _SLOT: DecapsulationKeySlot = DecapsulationKeySlot::new();
const _: for<'a> fn(&'a DecapsulationKey, &'a [u8; 1184]) -> Result<BoundKey<'a>, KeyMismatch> =
    DecapsulationKey::bind;

fn seed(i: u8) -> [u8; 64] {
    core::array::from_fn(|k| (k as u8).wrapping_mul(31) ^ i)
}

/// The key of `seed`.
fn dk(slot: &mut DecapsulationKeySlot, mut seed: [u8; 64]) -> &DecapsulationKey {
    DecapsulationKey::from_seed(slot, &mut seed)
}

/// An RNG that gives as many bytes of 0x5a as its count and then fails.
struct Limited(usize);

#[derive(Debug, PartialEq, thiserror::Error)]
#[error("the RNG is exhausted")]
struct Exhausted;

impl TryRng for Limited {
    type Error = Exhausted;

    fn try_next_u32(&mut self) -> Result<u32, Exhausted> {
        Err(Exhausted)
    }

    fn try_next_u64(&mut self) -> Result<u64, Exhausted> {
        Err(Exhausted)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Exhausted> {
        self.0 = self.0.checked_sub(dst.len()).ok_or(Exhausted)?;
        dst.fill(0x5a);
        Ok(())
    }
}

impl TryCryptoRng for Limited {}

fn ek_of(dk: &DecapsulationKey) -> [u8; 1184] {
    let mut ek = [0; 1184];
    dk.encapsulation_key(&mut ek);
    ek
}

/// Sets coefficient `n` of the encoded vector t to `value`.
fn set_coefficient(ek: &mut [u8; 1184], n: usize, value: u16) {
    let i = 3 * (n / 2);
    if n.is_multiple_of(2) {
        ek[i] = value as u8;
        ek[i + 1] = (ek[i + 1] & 0xf0) | (value >> 8) as u8;
    } else {
        ek[i + 1] = (ek[i + 1] & 0x0f) | ((value & 0xf) << 4) as u8;
        ek[i + 2] = (value >> 4) as u8;
    }
}

/// FIPS 203 section 7.2: q - 1 passes and q fails, in every polynomial and at both nibble
/// alignments.
#[test]
fn modulus_check_boundary() {
    let ek = ek_of(dk(&mut DecapsulationKeySlot::new(), seed(1)));
    assert!(EncapsulationKey::new(&ek).is_ok());
    for n in [0, 1, 254, 255, 256, 257, 511, 512, 766, 767] {
        for (value, valid) in [(3328, true), (3329, false), (4095, false)] {
            let mut ek = ek;
            set_coefficient(&mut ek, n, value);
            let result = EncapsulationKey::new(&ek).map(|_| ());
            let expected = if valid {
                Ok(())
            } else {
                Err(InvalidEncapsulationKey)
            };
            assert_eq!(result, expected, "coefficient {n} = {value}");
        }
    }
}

fn bind(seed: [u8; 64], ek: &[u8; 1184]) -> Result<(), KeyMismatch> {
    dk(&mut DecapsulationKeySlot::new(), seed)
        .bind(ek)
        .map(|_| ())
}

#[test]
fn from_seed_wipes_the_seed() {
    let mut seed = seed(1);
    let mut slot = DecapsulationKeySlot::new();
    let ek = ek_of(DecapsulationKey::from_seed(&mut slot, &mut seed));
    assert_eq!(seed, [0; 64]);
    assert_eq!(
        ek,
        ek_of(dk(&mut DecapsulationKeySlot::new(), self::seed(1)))
    );
}

#[test]
fn bind_rejects_other_keys() {
    let ek = ek_of(dk(&mut DecapsulationKeySlot::new(), seed(2)));
    assert_eq!(bind(seed(2), &ek), Ok(()));

    let other = ek_of(dk(&mut DecapsulationKeySlot::new(), seed(3)));
    assert_eq!(bind(seed(2), &other), Err(KeyMismatch));

    // A single flipped bit anywhere, in t or in rho.
    for pos in [0, 383, 384, 1151, 1152, 1183] {
        for bit in [0, 7] {
            let mut bad = ek;
            bad[pos] ^= 1 << bit;
            assert_eq!(
                bind(seed(2), &bad),
                Err(KeyMismatch),
                "byte {pos} bit {bit}"
            );
        }
    }

    // ek depends on d only, so a key with another z binds to it.
    let mut other_z = seed(2);
    other_z[63] ^= 1;
    assert_eq!(bind(other_z, &ek), Ok(()));
}

/// A generated key round-trips through its own encapsulation key.
#[test]
fn generate_round_trip() {
    let mut rng = <chacha20::ChaCha20Rng as rand_core::SeedableRng>::from_seed([9; 32]);
    let mut slot = DecapsulationKeySlot::new();
    let dk = DecapsulationKey::generate(&mut slot, &mut rng);
    let ek = ek_of(dk);
    let other = ek_of(DecapsulationKey::generate(
        &mut DecapsulationKeySlot::new(),
        &mut rng,
    ));
    assert_ne!(ek, other);
    let own = dk.bind(&ek).unwrap();

    let mut ct = [0; 1088];
    let k = own.encapsulation_key().encapsulate(&mut rng, &mut ct);
    assert_eq!(own.decapsulate(&ct).expose_secret(), k.expose_secret());
}

/// A modified ciphertext gives J(z || c) (FIPS 203 Algorithm 18), and the bound key's
/// encapsulation key is the stored one.
#[test]
fn implicit_rejection() {
    let seed = seed(4);
    let mut slot = DecapsulationKeySlot::new();
    let dk = dk(&mut slot, seed);
    let ek = ek_of(dk);
    let own = dk.bind(&ek).unwrap();
    assert_eq!(own.encapsulation_key().as_bytes(), &ek);

    let mut ct = [0; 1088];
    let k = own
        .encapsulation_key()
        .encapsulate_deterministic(&[5; 32].into(), &mut ct);
    assert_eq!(own.decapsulate(&ct).expose_secret(), k.expose_secret());

    for pos in [0, 1, 700, 959, 960, 1087] {
        let mut bad = ct;
        bad[pos] ^= 0x10;
        let mut rejection = [0; 32];
        Shake256::default()
            .chain(&seed[32..])
            .chain(bad)
            .finalize_xof_into(&mut rejection);
        assert_eq!(
            own.decapsulate(&bad).expose_secret(),
            &rejection,
            "byte {pos}"
        );
    }
}

/// The fallible forms return the RNG error, and otherwise match the infallible ones.
#[test]
fn rng_errors() {
    let mut slot = DecapsulationKeySlot::new();
    let result = DecapsulationKey::try_generate(&mut slot, &mut Limited(32));
    assert_eq!(result.err(), Some(Exhausted));
    let dk = DecapsulationKey::try_generate(&mut slot, &mut Limited(64)).unwrap();
    let ek = ek_of(dk);
    assert_eq!(
        ek,
        ek_of(self::dk(&mut DecapsulationKeySlot::new(), [0x5a; 64]))
    );

    let peer = EncapsulationKey::new(&ek).unwrap();
    let mut ct = [0x77; 1088];
    assert_eq!(
        peer.try_encapsulate(&mut Limited(31), &mut ct).err(),
        Some(Exhausted)
    );
    assert_eq!(ct, [0x77; 1088]);
    let k = peer.try_encapsulate(&mut Limited(32), &mut ct).unwrap();
    let mut expected = [0; 1088];
    let k_expected = peer.encapsulate_deterministic(&[0x5a; 32].into(), &mut expected);
    assert_eq!(
        (ct, k.expose_secret()),
        (expected, k_expected.expose_secret())
    );
}
