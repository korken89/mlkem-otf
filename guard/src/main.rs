//! Calls every operation of `mlkem-otf` so that the linked binary holds all of its code, for
//! `scripts/ct-guard.sh` to inspect.
//!
//! The panic handler calls a function that does not exist, so the link fails if any panic is
//! reachable from the library after optimization. The `allow-panic` feature turns this off.
#![no_std]
#![no_main]

use core::convert::Infallible;
use core::hint::black_box;

use cortex_m_rt::entry;
use mlkem_otf::{DecapsulationKey, DecapsulationKeySlot, EncapsulationKey};
use rand_core::{TryCryptoRng, TryRng};

/// An RNG whose output the optimizer cannot see.
struct OpaqueRng;

impl TryRng for OpaqueRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(black_box(0))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(black_box(0))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        dst.fill(black_box(0));
        Ok(())
    }
}

impl TryCryptoRng for OpaqueRng {}

static mut EK: [u8; 1184] = [0; 1184];
static mut CT: [u8; 1088] = [0; 1088];

#[entry]
fn main() -> ! {
    let ek = black_box(&raw mut EK);
    let ct = black_box(&raw mut CT);
    // SAFETY: The only references to the two buffers, on the only thread.
    let (ek, ct) = unsafe { (&mut *ek, &mut *ct) };
    black_box(DecapsulationKey::generate(
        &mut DecapsulationKeySlot::new(),
        &mut OpaqueRng,
    ));
    let mut slot = DecapsulationKeySlot::new();
    let dk = black_box(DecapsulationKey::from_seed(
        &mut slot,
        black_box(&mut [0; 64]),
    ));
    dk.encapsulation_key(ek);
    if let Ok(own) = dk.bind(black_box(ek)) {
        black_box(own.decapsulate(black_box(ct)));
        let peer = own.encapsulation_key();
        black_box(peer.encapsulate(&mut OpaqueRng, ct));
    }
    if let Ok(peer) = EncapsulationKey::new(black_box(ek)) {
        black_box(peer.encapsulate_deterministic(&black_box([0; 32]).into(), ct));
    }
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(not(feature = "allow-panic"))]
unsafe extern "Rust" {
    /// Not defined anywhere, see the module docs.
    fn mlkem_otf_has_a_reachable_panic() -> !;
}

#[cfg(not(feature = "allow-panic"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // SAFETY: Never runs, the link fails if this is reachable.
    unsafe { mlkem_otf_has_a_reachable_panic() }
}

#[cfg(feature = "allow-panic")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
