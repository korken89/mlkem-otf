//! ML-KEM-768 (FIPS 203) with streaming matrix expansion and in-place ciphertexts, for small
//! stacks.
//!
//! Neither the matrix A nor the secret and noise vectors are stored. Each matrix entry is
//! sampled into an accumulator as it is needed, and the vectors are regenerated from their seeds
//! where they are used. Keys are encoded, and ciphertexts compressed and encoded, straight into
//! the caller's buffer, or in decapsulation compared with the received ciphertext as they are
//! produced. The working set is at most three polynomials.
//!
//! The private key is kept only as its 64-byte seed. The matching encapsulation key is borrowed
//! from where it is stored, for example flash, and checked against the seed once by
//! [`DecapsulationKey::bind`].
//!
//! # Side channels
//!
//! The source has no branch, memory index or division that depends on secret data, and masks of
//! secret signs and bits pass an optimization barrier. The generated code is checked for
//! Cortex-M0, M3, M4 and M33. Decapsulation always computes the implicit rejection key and
//! selects the result without a branch. Secret temporaries on the stack are wiped when they go
//! out of scope. Copies that the compiler makes, such as register spills, and the stack frames
//! of the SHA-3 implementation are out of reach. So are the stack slots of the optimization
//! barriers, which keep the last mask of a sign or a message bit and, after decapsulation,
//! whether the ciphertext was valid. An interrupt taken during an operation pushes registers
//! that can hold secret intermediates below the stack pointer, where they stay, so mask
//! interrupts around the operation or run it at the lowest priority if that matters.
//!
//! A [`DecapsulationKey`] is filled in place, in a [`DecapsulationKeySlot`] that the caller
//! provides, and only lent out by shared reference after that, so the seed is never moved. A
//! [`BoundKey`] borrows it.
//!
//! ```
//! use mlkem_otf::{DecapsulationKey, DecapsulationKeySlot, EncapsulationKey};
//! use rand_core::Rng;
//! use static_cell::ConstStaticCell;
//! # let mut rng = <chacha20::ChaCha20Rng as rand_core::SeedableRng>::from_seed([7; 32]);
//!
//! // Provisioning: store the seed in secure storage and `ek` where it can be read. The slot on
//! // the stack is wiped when it is dropped.
//! let mut storage = [0; 64];
//! rng.fill_bytes(&mut storage);
//! let mut seed = storage;
//! let mut slot = DecapsulationKeySlot::new();
//! let mut ek = [0; 1184];
//! DecapsulationKey::from_seed(&mut slot, &mut seed).encapsulation_key(&mut ek);
//! drop(slot);
//!
//! // At boot: load the seed into a static slot, which wipes `seed`, and check `ek` once
//! static KEY: ConstStaticCell<DecapsulationKeySlot> =
//!     ConstStaticCell::new(DecapsulationKeySlot::new());
//! let mut seed = storage;
//! let own = DecapsulationKey::from_seed(KEY.take(), &mut seed).bind(&ek)?;
//!
//! // The peer, with `ek` received
//! let peer = EncapsulationKey::new(&ek)?;
//! let mut ct = [0; 1088];
//! let sent = peer.encapsulate(&mut rng, &mut ct);
//!
//! assert_eq!(own.decapsulate(&ct).expose_secret(), sent.expose_secret());
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
#![cfg_attr(not(test), no_std)]

mod encode;
mod kpke;
mod ntt;
mod params;
mod sample;
#[cfg(test)]
mod tests;

use ctutils::{Choice, CtAssign};
use rand_core::{CryptoRng, TryCryptoRng};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::encode::{Compare, Writer, decode12};
use crate::kpke::{FromSigma, SecretVector};
use crate::ntt::Q;
use crate::params::{MlKem768, Params};
use crate::sample::{Secret32, g, h, j};

/// The parameter set behind the public API.
type P = MlKem768;

/// The 64-byte seed `d || z` (FIPS 203 section 7.1), the only form the private key is kept in.
///
/// It is filled in place in a [`DecapsulationKeySlot`] and only lent out by shared reference, so
/// it is never moved.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DecapsulationKey {
    d: [u8; 32],
    z: [u8; 32],
}

/// Where a [`DecapsulationKey`] lives, for example in a `static`, a `ConstStaticCell` or on the
/// stack. A slot that holds no key yet holds zeros, and the key is only reachable through the
/// constructors of [`DecapsulationKey`]. Wiped when dropped. Moving a slot that holds a key copies
/// the key, so keep the slot where it is.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DecapsulationKeySlot(DecapsulationKey);

impl DecapsulationKeySlot {
    /// An empty slot.
    pub const fn new() -> Self {
        Self(DecapsulationKey {
            d: [0; 32],
            z: [0; 32],
        })
    }

    /// The key in the slot, wiped to be filled in place.
    fn wiped(&mut self) -> &mut DecapsulationKey {
        self.zeroize();
        &mut self.0
    }
}

impl Default for DecapsulationKeySlot {
    fn default() -> Self {
        Self::new()
    }
}

impl DecapsulationKey {
    /// Loads the seed `d || z` that ML-KEM.KeyGen_internal (FIPS 203 Algorithm 16) takes into
    /// `slot`, and wipes `seed`. A key already in `slot` is wiped first.
    pub fn from_seed<'s>(slot: &'s mut DecapsulationKeySlot, seed: &mut [u8; 64]) -> &'s Self {
        let dk = slot.wiped();
        let (d, z) = seed.split_at(32);
        dk.d.copy_from_slice(d);
        dk.z.copy_from_slice(z);
        seed.zeroize();
        dk
    }

    /// Draws a new seed from `rng` into `slot` (ML-KEM.KeyGen, FIPS 203 Algorithm 19). A key
    /// already in `slot` is wiped first. The seed cannot be read back, so this is for keys that
    /// are not stored. To store a key, draw the seed and use [`Self::from_seed`].
    pub fn generate<'s>(slot: &'s mut DecapsulationKeySlot, rng: &mut impl CryptoRng) -> &'s Self {
        let Ok(dk) = Self::try_generate(slot, rng);
        dk
    }

    /// [`Self::generate`] with an RNG that can fail. On an error the slot is wiped.
    pub fn try_generate<'s, R: TryCryptoRng + ?Sized>(
        slot: &'s mut DecapsulationKeySlot,
        rng: &mut R,
    ) -> Result<&'s Self, R::Error> {
        let dk = slot.wiped();
        match rng
            .try_fill_bytes(&mut dk.d)
            .and_then(|()| rng.try_fill_bytes(&mut dk.z))
        {
            Ok(()) => Ok(dk),
            Err(e) => {
                dk.zeroize();
                Err(e)
            }
        }
    }

    /// KeyGen (FIPS 203 Algorithm 16). Streams the encapsulation key into `ek`.
    pub fn encapsulation_key(&self, ek: &mut [u8; 1184]) {
        kpke::keygen::<P>(&self.d, &mut Writer::new(ek));
    }

    /// Pairs the key with its stored encapsulation key `ek`. KeyGen runs again and its output is
    /// compared with `ek` as it streams, so a key that does not match is always rejected.
    pub fn bind<'a>(&'a self, ek: &'a [u8; 1184]) -> Result<BoundKey<'a>, KeyMismatch> {
        let mut cmp = Compare::new(ek);
        kpke::keygen::<P>(&self.d, &mut cmp);
        if Choice::from_u8_eq(cmp.diff(), 0).to_bool() {
            Ok(BoundKey {
                dk: self,
                ek,
                h_ek: h(ek),
            })
        } else {
            Err(KeyMismatch)
        }
    }
}

/// A decapsulation key with its own verified encapsulation key and cached `H(ek)`. It borrows
/// both keys and holds no secret of its own.
pub struct BoundKey<'a> {
    dk: &'a DecapsulationKey,
    ek: &'a [u8; 1184],
    h_ek: [u8; 32],
}

impl<'a> BoundKey<'a> {
    /// ML-KEM.Decaps (FIPS 203 Algorithm 21), with [`DecapsulationKey::bind`] in place of the
    /// key checks of section 7.3. Never fails, a modified ciphertext gives the implicit rejection
    /// key `J(z || ct)`. The time does not depend on whether `ct` is valid.
    pub fn decapsulate(&self, ct: &[u8; 1088]) -> SharedKey {
        let (mut rho, mut sigma) = (Secret32::default(), Secret32::default());
        g(&[&self.dk.d, &[P::K as u8]], &mut rho.0, &mut sigma.0);
        decapsulate(&FromSigma(&sigma.0), &self.dk.z, self.ek, &self.h_ek, ct)
    }

    /// The encapsulation key, to send to peers.
    pub fn encapsulation_key(&self) -> EncapsulationKey<'a> {
        EncapsulationKey {
            bytes: self.ek,
            h_ek: self.h_ek,
        }
    }
}

/// An encapsulation key that passed the modulus check (FIPS 203 section 7.2), borrowed, with
/// `H(ek)` computed once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EncapsulationKey<'a> {
    bytes: &'a [u8; 1184],
    h_ek: [u8; 32],
}

impl<'a> EncapsulationKey<'a> {
    /// Checks that every coefficient in `bytes` is below q (FIPS 203 section 7.2), without
    /// decoding the key into memory.
    pub fn new(bytes: &'a [u8; 1184]) -> Result<Self, InvalidEncapsulationKey> {
        let (t, _) = bytes.split_at(P::T_LEN);
        let mut bad = 0;
        for (a, b) in decode12(t) {
            bad |= u8::from(a >= Q) | u8::from(b >= Q);
        }
        if bad == 0 {
            Ok(Self {
                bytes,
                h_ek: h(bytes),
            })
        } else {
            Err(InvalidEncapsulationKey)
        }
    }

    /// The encoded key.
    pub fn as_bytes(&self) -> &'a [u8; 1184] {
        self.bytes
    }

    /// ML-KEM.Encaps (FIPS 203 Algorithm 20), with the ciphertext written into `ct`.
    pub fn encapsulate(&self, rng: &mut impl CryptoRng, ct: &mut [u8; 1088]) -> SharedKey {
        let Ok(key) = self.try_encapsulate(rng, ct);
        key
    }

    /// [`Self::encapsulate`] with an RNG that can fail. On an error `ct` is left as it was.
    pub fn try_encapsulate<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        ct: &mut [u8; 1088],
    ) -> Result<SharedKey, R::Error> {
        let mut m = Secret32::default();
        rng.try_fill_bytes(&mut m.0)?;
        Ok(self.encapsulate_internal(&m.0, ct))
    }

    /// ML-KEM.Encaps_internal (FIPS 203 Algorithm 17) with the given randomness `m`, for
    /// known-answer tests and for protocols that derive `m` themselves. Anyone who knows `m`
    /// knows the shared key.
    #[cfg(feature = "hazmat")]
    pub fn encapsulate_deterministic(&self, m: &Randomness, ct: &mut [u8; 1088]) -> SharedKey {
        self.encapsulate_internal(&m.0, ct)
    }

    fn encapsulate_internal(&self, m: &[u8; 32], ct: &mut [u8; 1088]) -> SharedKey {
        let (mut key, mut r) = (Secret32::default(), Secret32::default());
        g(&[m, &self.h_ek], &mut key.0, &mut r.0);
        let (t, rho) = split_ek(self.bytes);
        kpke::encrypt::<P>(t, &rho, m, &r.0, &mut Writer::new(ct));
        SharedKey(key.0)
    }
}

/// A 32-byte shared key, wiped when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedKey([u8; 32]);

impl SharedKey {
    /// The key bytes.
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The 32-byte randomness `m` of encapsulation, wiped when dropped.
#[cfg(feature = "hazmat")]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Randomness([u8; 32]);

#[cfg(feature = "hazmat")]
impl From<[u8; 32]> for Randomness {
    fn from(m: [u8; 32]) -> Self {
        Self(m)
    }
}

/// An encapsulation key with a coefficient of q or more (FIPS 203 section 7.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[error("encapsulation key is not reduced modulo q")]
pub struct InvalidEncapsulationKey;

/// An encapsulation key that does not belong to the decapsulation key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[error("encapsulation key does not match the decapsulation key")]
pub struct KeyMismatch;

/// Splits an encapsulation key into ByteEncode_12(t_hat) and rho.
fn split_ek(ek: &[u8; 1184]) -> (&[u8], [u8; 32]) {
    let (t, rho_bytes) = ek.split_at(P::T_LEN);
    let mut rho = [0; 32];
    rho.copy_from_slice(rho_bytes);
    (t, rho)
}

/// Decaps_internal (FIPS 203 Algorithm 18) with the decryption key from `s_hat`. The
/// re-encryption is compared with `ct` over every byte as it streams, and the result is
/// selected without a branch.
fn decapsulate(
    s_hat: &impl SecretVector,
    z: &[u8; 32],
    ek: &[u8; 1184],
    h_ek: &[u8; 32],
    ct: &[u8; 1088],
) -> SharedKey {
    let mut m = Secret32::default();
    kpke::decrypt::<P>(s_hat, ct, &mut m.0);
    let (mut k, mut r) = (Secret32::default(), Secret32::default());
    g(&[&m.0, h_ek], &mut k.0, &mut r.0);
    let mut key = Secret32::default();
    j(z, ct, &mut key.0);
    let mut cmp = Compare::new(ct);
    let (t, rho) = split_ek(ek);
    kpke::encrypt::<P>(t, &rho, &m.0, &r.0, &mut cmp);
    key.0.ct_assign(&k.0, Choice::from_u8_eq(cmp.diff(), 0));
    SharedKey(key.0)
}
