//! Links the one operation that a feature selects, or none, for `text-size.sh` to measure the
//! code size of each operation.
#![no_std]
#![no_main]

use core::hint::black_box;

use cortex_m_rt::entry;
use semihosting::process;

#[entry]
fn main() -> ! {
    let ek = black_box([0; 1184]);
    let mut ct = black_box([0; 1088]);
    // The empty binary loads the key too.
    let mut slot = mlkem_otf::DecapsulationKeySlot::new();
    let dk = mlkem_otf::DecapsulationKey::from_seed(&mut slot, &mut black_box([0; 64]));
    #[cfg(feature = "keygen")]
    dk.encapsulation_key(&mut black_box([0; 1184]));
    #[cfg(feature = "ek-check")]
    black_box(mlkem_otf::EncapsulationKey::new(&ek).is_ok());
    #[cfg(feature = "bind")]
    black_box(dk.bind(&ek).is_ok());
    #[cfg(feature = "encapsulate")]
    if let Ok(peer) = mlkem_otf::EncapsulationKey::new(&ek) {
        black_box(peer.encapsulate_deterministic(&black_box([0; 32]).into(), &mut ct));
    }
    #[cfg(feature = "decapsulate")]
    if let Ok(own) = dk.bind(&ek) {
        black_box(own.decapsulate(&ct));
    }
    black_box((dk, &ek, &mut ct));
    process::exit(0)
}
