//! Differential tests against the `ml-kem` crate over many seeds, including implicit rejection.

use ml_kem::{Decapsulate, KeyExport, ml_kem_768};
use mlkem_otf::{DecapsulationKey, DecapsulationKeySlot, EncapsulationKey};
use shake::{ExtendableOutput, Shake128, Update, XofReader};

#[test]
fn matches_ml_kem() {
    let mut rng = Shake128::default().chain(b"cross check").finalize_xof();
    for i in 0..300 {
        let mut seed = [0; 64];
        rng.read(&mut seed);
        let mut m = [0; 32];
        rng.read(&mut m);

        let dk_ref = ml_kem_768::DecapsulationKey::from_seed(seed.into());
        let mut slot = DecapsulationKeySlot::new();
        let dk = DecapsulationKey::from_seed(&mut slot, &mut seed);
        let ek_ref = dk_ref.encapsulation_key().to_bytes();
        let (ct_ref, k_ref) = dk_ref
            .encapsulation_key()
            .encapsulate_deterministic(&m.into());

        let mut ek = [0; 1184];
        dk.encapsulation_key(&mut ek);
        assert_eq!(ek[..], ek_ref[..], "ek {i}");

        let own = dk.bind(&ek).unwrap();
        let peer = EncapsulationKey::new(&ek).unwrap();
        let mut ct = [0; 1088];
        let k = peer.encapsulate_deterministic(&m.into(), &mut ct);
        assert_eq!(ct[..], ct_ref[..], "ct {i}");
        assert_eq!(k.expose_secret()[..], k_ref[..], "k {i}");
        assert_eq!(own.decapsulate(&ct).expose_secret(), k.expose_secret());

        // Implicit rejection on modified ciphertexts, in u and in v.
        let mut pos = [0; 2];
        rng.read(&mut pos);
        for pos in [
            usize::from(u16::from_le_bytes(pos)) % 1088,
            0,
            959,
            960,
            1087,
        ] {
            let mut bad = ct;
            bad[pos] ^= 1 << (i % 8);
            let k_bad = own.decapsulate(&bad);
            assert_eq!(
                k_bad.expose_secret()[..],
                dk_ref.decapsulate(&bad.into())[..]
            );
            assert_ne!(k_bad.expose_secret(), k.expose_secret());
        }

        // Random ciphertexts.
        let mut random = [0; 1088];
        rng.read(&mut random);
        let k_random = own.decapsulate(&random);
        assert_eq!(
            k_random.expose_secret()[..],
            dk_ref.decapsulate(&random.into())[..]
        );
    }
}
