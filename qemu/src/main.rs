//! Measures the peak stack usage and the executed instructions of each ML-KEM-768 operation
//! here, and in the `ml-kem` crate for comparison, on a Cortex-M33.
//!
//! Each measurement fills the free stack with a pattern, runs the operation and finds the lowest
//! word that changed. The instruction count comes from the `icount.c` QEMU plugin and is exact.
//! Run with `make test-qemu`, which builds the plugin and starts QEMU.
//!
//! After each operation it searches the stack that the operation used for the secrets of that
//! operation, whole and in 16-byte parts, and fails if it finds one. These are the seed `d || z`,
//! `d` and `z`, `sigma`, `m`, `K`, `r`, `K_bar`, the PRF outputs drawn from `sigma` and `r`, and
//! the returned shared key. A key generated or loaded into a slot on the stack of the operation
//! must be gone once the slot is dropped.
//!
//! Exits with a failure if encapsulation does not take the same number of instructions for
//! every message `m`, or decapsulation for a valid ciphertext and for modified ones.
#![no_std]
#![no_main]

use core::convert::Infallible;
use core::hint::black_box;
use core::ops::Range;

use cortex_m_rt::entry;
use ml_kem::{Decapsulate, KeyExport, ml_kem_768};
use mlkem_otf::{DecapsulationKey, DecapsulationKeySlot, EncapsulationKey, Randomness};
use rand_core::{TryCryptoRng, TryRng};
use semihosting::{println, process};
use sha3::{Digest, Sha3_256, Sha3_512};
use shake::{ExtendableOutput, Shake256, Update};

/// The seed `d || z`. `z` differs from `d`, so that each is searched for on its own.
static SEED: [u8; 64] = {
    let mut seed = [0x22; 64];
    let mut i = 32;
    while i < 64 {
        seed[i] = (i as u8).wrapping_mul(29) ^ 0x5b;
        i += 1;
    }
    seed
};
/// The messages of encapsulation, all of which must take the same time.
static MESSAGES: [(&str, [u8; 32]); 5] = [
    ("mlkem-otf encapsulate", [0x33; 32]),
    ("mlkem-otf encapsulate, m all 0x00", [0; 32]),
    ("mlkem-otf encapsulate, m all 0xff", [0xff; 32]),
    ("mlkem-otf encapsulate, m all 0x5a", [0x5a; 32]),
    ("mlkem-otf encapsulate, m all 0x01", [0x01; 32]),
];
/// The names of `PRF_2(sigma, i)`, for s with i in 0..3 and e with i in 3..6.
const PRF_SIGMA: [&str; 6] = [
    "PRF(sigma, 0)",
    "PRF(sigma, 1)",
    "PRF(sigma, 2)",
    "PRF(sigma, 3)",
    "PRF(sigma, 4)",
    "PRF(sigma, 5)",
];
/// The names of `PRF_2(r, i)`, for y with i in 0..3, e1 with i in 3..6 and e2 with i = 6.
const PRF_R: [&str; 7] = [
    "PRF(r, 0)",
    "PRF(r, 1)",
    "PRF(r, 2)",
    "PRF(r, 3)",
    "PRF(r, 4)",
    "PRF(r, 5)",
    "PRF(r, 6)",
];

const PAINT: u32 = 0xa5a5_a5a5;

unsafe extern "C" {
    /// Lowest address of the stack, from the `cortex-m-rt` linker script.
    static _stack_end: u32;
}

/// Instructions executed so far, truncated to 32 bits.
#[inline(always)]
fn instructions() -> u32 {
    let n;
    // SAFETY: Moves r12 to itself. The plugin writes the instruction count into r12 first.
    unsafe { core::arch::asm!("mov r12, r12", out("r12") n, options(nostack, preserves_flags)) };
    n
}

/// Returns the bytes of `.0` in order and repeats them, from position `.1`.
struct Replay(&'static [u8], usize);

impl TryRng for Replay {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for b in dst {
            *b = self.0[self.1 % self.0.len()];
            self.1 += 1;
        }
        Ok(())
    }
}

impl TryCryptoRng for Replay {}

/// Peak stack in bytes and executed instructions of one call.
struct Usage {
    stack: usize,
    instructions: u32,
}

/// A secret by name, which an operation must not leave on the stack.
type Secret<'a> = (&'a str, &'a [u8]);

/// The part of a secret found on the stack, all of it or 16 bytes.
struct Hit<'a> {
    name: &'a str,
    part: Range<usize>,
}

/// Runs `f` and returns its result with its usage, and fails if `f` left one of `secrets` on the
/// stack. See [`run`].
fn measure<R>(name: &str, secrets: &[&[Secret]], f: impl FnOnce() -> R) -> (R, Usage) {
    let (result, usage, hit) = run(secrets, f);
    if let Some(Hit { name: s, part }) = hit {
        panic!("{name} left {s}[{}..{}] on the stack", part.start, part.end);
    }
    (result, usage)
}

/// Runs `f` on a painted stack and returns its result, its usage and the first of `secrets` that
/// it left on the stack, whole or in a 16-byte part. Captures and the return value live in the
/// caller's frame and are not counted, and neither is the call itself.
#[inline(never)]
fn run<'a, R>(secrets: &[&[Secret<'a>]], f: impl FnOnce() -> R) -> (R, Usage, Option<Hit<'a>>) {
    let bottom = (&raw const _stack_end).cast_mut();
    let sp = cortex_m::register::msp::read() as *mut u32;
    // SAFETY: Everything from the end of the stack up to the stack pointer is unused.
    let free = unsafe { sp.offset_from(bottom) } as usize;
    for i in 0..free {
        // SAFETY: In bounds of the unused stack, see above.
        unsafe { bottom.add(i).write_volatile(PAINT) };
    }
    let (result, instructions) = call(f);
    // The scans read the stack that `f` used, so they make no calls.
    let mut untouched = 0;
    // SAFETY: In bounds of the unused stack, see above.
    while untouched < free && unsafe { bottom.add(untouched).read_volatile() } == PAINT {
        untouched += 1;
    }
    assert!(untouched > 0, "stack overflow");
    // SAFETY: In bounds of the unused stack, see above.
    let used = unsafe { bottom.add(untouched) }.cast::<u8>();
    let mut hit = None;
    // Whole secrets first, then their 16-byte parts.
    let mut pass = 0;
    while pass < 2 && hit.is_none() {
        let mut g = 0;
        while g < secrets.len() && hit.is_none() {
            let mut k = 0;
            while k < secrets[g].len() && hit.is_none() {
                let (name, bytes) = secrets[g][k];
                if pass == 0 {
                    if left_on_stack(bytes, used) {
                        hit = Some(Hit {
                            name,
                            part: 0..bytes.len(),
                        });
                    }
                } else {
                    let mut p = 0;
                    while bytes.len() > 16 && p + 16 <= bytes.len() && hit.is_none() {
                        if left_on_stack(&bytes[p..p + 16], used) {
                            hit = Some(Hit {
                                name,
                                part: p..p + 16,
                            });
                        }
                        p += 16;
                    }
                }
                k += 1;
            }
            g += 1;
        }
        pass += 1;
    }
    let stack = (free - untouched) * 4;
    (
        result,
        Usage {
            stack,
            instructions,
        },
        hit,
    )
}

/// Whether the stack from `low` up to the stack pointer holds a copy of `secret`. A secret of
/// zeros is not searched for, since wiped memory is zero. Inlined and without calls, so that it
/// does not overwrite what it searches.
#[inline(always)]
fn left_on_stack(secret: &[u8], low: *const u8) -> bool {
    let mut zero = true;
    let mut j = 0;
    while j < secret.len() {
        zero &= secret[j] == 0;
        j += 1;
    }
    let sp = cortex_m::register::msp::read() as *const u8;
    // SAFETY: Everything from the end of the stack up to the stack pointer is unused.
    let len = unsafe { sp.offset_from(low) } as usize;
    let mut i = 0;
    while !zero && i + secret.len() <= len {
        let mut j = 0;
        // SAFETY: In bounds of the unused stack, see above.
        while j < secret.len() && unsafe { low.add(i + j).read_volatile() } == secret[j] {
            j += 1;
        }
        if j == secret.len() {
            return true;
        }
        i += 1;
    }
    false
}

/// Calls `f` in its own frame, so its locals are below the painted stack pointer, and counts
/// its instructions.
#[inline(never)]
fn call<R>(f: impl FnOnce() -> R) -> (R, u32) {
    let start = instructions();
    let result = f();
    let end = instructions();
    (result, end.wrapping_sub(start))
}

fn row(name: &str, usage: &Usage, overhead: u32) {
    let instructions = usage.instructions - overhead;
    println!("  {name:<42} {:>6} {instructions:>12}", usage.stack);
}

/// `(K, r) = G(m || H(ek))` (FIPS 203 Algorithm 17).
fn g(m: &[u8; 32], ek: &[u8; 1184]) -> ([u8; 32], [u8; 32]) {
    let out = Sha3_512::new()
        .chain_update(m)
        .chain_update(Sha3_256::digest(ek))
        .finalize();
    let (k, r) = out.split_at(32);
    // Both halves of the 64-byte output have 32 bytes
    (k.try_into().unwrap(), r.try_into().unwrap())
}

/// The implicit rejection key `J(z || c)` (FIPS 203 Algorithm 18).
fn j(ct: &[u8; 1088]) -> [u8; 32] {
    let mut out = [0; 32];
    Shake256::default()
        .chain(&SEED[32..])
        .chain(ct)
        .finalize_xof_into(&mut out);
    out
}

/// `PRF_2(s, nonce) = SHAKE256(s || nonce)` (FIPS 203 equation 4.3).
fn prf(s: &[u8], nonce: usize) -> [u8; 128] {
    let mut out = [0; 128];
    Shake256::default()
        .chain(s)
        .chain([nonce as u8])
        .finalize_xof_into(&mut out);
    out
}

/// The secret `s` and the PRF outputs drawn from it, named `names`.
fn with_prf<'a, const N: usize>(
    name: &'a str,
    s: &'a [u8],
    names: &[&'a str],
    prf: &'a [[u8; 128]],
) -> [Secret<'a>; N] {
    let mut out = [(name, s); N];
    for (o, (name, prf)) in out[1..].iter_mut().zip(names.iter().zip(prf)) {
        *o = (name, prf);
    }
    out
}

/// Checks that the residue check finds a copy of the 32-byte `secret` that a call leaves on the
/// stack, at an aligned and at an unaligned address, and a copy of only its second half.
fn residue_controls(secret: &[u8]) {
    for offset in [0, 3] {
        for start in [0, 16] {
            let ((), _, hit) = run(&[&[("the planted copy", secret)]], || {
                let mut copy = [0; 35];
                copy[offset + start..offset + 32].copy_from_slice(&black_box(secret)[start..]);
                black_box(&mut copy);
            });
            assert!(
                hit.is_some_and(|hit| hit.part == (start..32)),
                "the residue check missed a planted copy"
            );
        }
    }
}

#[entry]
fn main() -> ! {
    residue_controls(&SEED[32..]);
    let ((), empty) = measure("nothing", &[], || ());
    let overhead = empty.instructions;

    println!("ML-KEM-768 peak stack in bytes and instructions executed:");
    println!("  {:<42} {:>6} {:>12}", "", "stack", "instructions");

    let (d, z) = SEED.split_at(32);
    let seed: [Secret; 3] = [("d || z", &SEED), ("d", d), ("z", z)];
    let sigma = Sha3_512::new().chain_update(d).chain_update([3]).finalize();
    let sigma_prf: [[u8; 128]; 6] = core::array::from_fn(|i| prf(&sigma[32..], i));
    let from_sigma: [Secret; 7] = with_prf("sigma", &sigma[32..], &PRF_SIGMA, &sigma_prf);
    // Decryption regenerates s only.
    let s_only = &from_sigma[..4];

    let mut slot = DecapsulationKeySlot::new();
    let (generated, usage) = measure("generate", &[&seed], || {
        DecapsulationKey::generate(&mut slot, &mut Replay(&SEED, 0))
    });
    row("mlkem-otf generate", &usage, overhead);
    let mut slot = DecapsulationKeySlot::new();
    let mut stored = SEED;
    let (dk, usage) = measure("from_seed", &[&seed], || {
        DecapsulationKey::from_seed(&mut slot, black_box(&mut stored))
    });
    row("mlkem-otf load seed", &usage, overhead);
    assert!(
        stored == [0; 64],
        "from_seed left the seed in the caller's buffer"
    );

    let ((), usage) = measure("generate into a dropped slot", &[&seed], || {
        let mut slot = DecapsulationKeySlot::new();
        black_box(DecapsulationKey::generate(&mut slot, &mut Replay(&SEED, 0)));
    });
    row("mlkem-otf generate into a dropped slot", &usage, overhead);
    let ((), usage) = measure("load seed into a dropped slot", &[&seed], || {
        let mut slot = DecapsulationKeySlot::new();
        let mut stored = SEED;
        black_box(DecapsulationKey::from_seed(&mut slot, &mut stored));
    });
    row("mlkem-otf load seed into a dropped slot", &usage, overhead);

    let mut ek = [0; 1184];
    let ((), keygen) = measure("keygen", &[&seed, &from_sigma], || {
        dk.encapsulation_key(black_box(&mut ek))
    });
    row("mlkem-otf keygen", &keygen, overhead);
    let mut ek_generated = [0; 1184];
    generated.encapsulation_key(&mut ek_generated);
    assert!(ek_generated == ek, "the generated key differs");
    let (peer, check) = measure("key check", &[], || EncapsulationKey::new(black_box(&ek)));
    row("mlkem-otf encapsulation key check", &check, overhead);
    let (own, bind) = measure("bind", &[&seed, &from_sigma], || dk.bind(black_box(&ek)));
    row("mlkem-otf seed and key check (bind)", &bind, overhead);
    let (Ok(peer), Ok(own)) = (peer, own) else {
        panic!("key check failed");
    };

    // The first message gives the ciphertext and key for decapsulation.
    let mut same = true;
    let mut first = None;
    for (name, m) in &MESSAGES {
        let mut ct = [0; 1088];
        let randomness = Randomness::from(*m);
        let (key, r) = g(m, &ek);
        let r_prf: [[u8; 128]; 7] = core::array::from_fn(|i| prf(&r, i));
        let from_r: [Secret; 8] = with_prf("r", &r, &PRF_R, &r_prf);
        let secrets: [&[Secret]; 2] = [&[("K", &key), ("m", m)], &from_r];
        let (k, usage) = measure(name, &secrets, || {
            peer.encapsulate_deterministic(black_box(&randomness), &mut ct)
        });
        row(name, &usage, overhead);
        match &first {
            None => first = Some((ct, k, usage.instructions)),
            Some((_, _, instructions)) => same &= usage.instructions == *instructions,
        }
    }
    let Some((ct, k, _)) = first else {
        panic!("no message");
    };
    let m = &MESSAGES[0].1;
    let (_, r) = g(m, &ek);
    let r_prf: [[u8; 128]; 7] = core::array::from_fn(|i| prf(&r, i));
    let from_r: [Secret; 8] = with_prf("r", &r, &PRF_R, &r_prf);
    let of_m: [Secret; 2] = [("m", m), ("K", k.expose_secret())];
    let name = "mlkem-otf encapsulate with an RNG";
    let mut ct_rng = [0; 1088];
    let (k_rng, usage) = measure(name, &[&of_m, &from_r], || {
        peer.encapsulate(&mut Replay(m, 0), &mut ct_rng)
    });
    row(name, &usage, overhead);
    assert!(ct_rng == ct && k_rng.expose_secret() == k.expose_secret());
    let k_bar = j(&ct);
    let name = "mlkem-otf decapsulate";
    let secrets: [&[Secret]; 5] = [&of_m, &from_r, &[("K_bar", &k_bar)], &seed, s_only];
    let (k2, decaps) = measure(name, &secrets, || own.decapsulate(black_box(&ct)));
    row(name, &decaps, overhead);
    assert!(k.expose_secret() == k2.expose_secret());

    // Ciphertexts that must take the same time: modified in u, in v, everywhere, and unrelated.
    // The result is K_bar. A change of the lowest bit of a coefficient of u, or of one step of a
    // coefficient of v, moves each coefficient of the decrypted polynomial by less than q/4
    // minus the noise bound, and inverting every byte negates the decrypted polynomial. So these
    // decrypt to m and the secrets of the valid ciphertext are searched for too. Byte 700
    // decrypts to an unknown message.
    for (name, pos, mask, decrypts_to_m) in [
        ("mlkem-otf decapsulate, byte 0 modified", 0, 0x01, true),
        ("mlkem-otf decapsulate, byte 700 modified", 700, 0x80, false),
        (
            "mlkem-otf decapsulate, byte 1087 modified",
            1087,
            0x10,
            true,
        ),
        (
            "mlkem-otf decapsulate, all bytes inverted",
            usize::MAX,
            0xff,
            true,
        ),
    ] {
        let mut bad = ct;
        for (i, b) in bad.iter_mut().enumerate() {
            if pos == usize::MAX || i == pos {
                *b ^= mask;
            }
        }
        let k_bar = j(&bad);
        let secrets: [&[Secret]; 5] = [&[("K_bar", &k_bar)], &seed, s_only, &of_m, &from_r];
        let secrets = if decrypts_to_m {
            &secrets[..]
        } else {
            &secrets[..3]
        };
        let (k_bad, usage) = measure(name, secrets, || own.decapsulate(black_box(&bad)));
        row(name, &usage, overhead);
        assert!(k_bad.expose_secret() == &k_bar);
        same &= usage.instructions == decaps.instructions;
    }

    let (dk_ref, keygen) = measure("ml-kem keygen", &[], || {
        ml_kem_768::DecapsulationKey::from_seed(SEED.into())
    });
    row("ml-kem keygen", &keygen, overhead);
    let ek_ref = dk_ref.encapsulation_key().to_bytes();
    assert!(ek_ref[..] == ek[..]);
    let (peer_ref, check) = measure("ml-kem key check", &[], || {
        ml_kem_768::EncapsulationKey::new(black_box(&ek_ref))
    });
    row("ml-kem encapsulation key check", &check, overhead);
    let Ok(peer_ref) = peer_ref else {
        panic!("ml-kem key check failed");
    };
    let ((ct_ref, k_ref), encaps) = measure("ml-kem encapsulate", &[], || {
        peer_ref.encapsulate_deterministic(&(*black_box(&MESSAGES[0].1)).into())
    });
    row("ml-kem encapsulate", &encaps, overhead);
    let (k2_ref, decaps) = measure("ml-kem decapsulate", &[], || {
        dk_ref.decapsulate(black_box(&ct_ref))
    });
    row("ml-kem decapsulate", &decaps, overhead);
    assert!(ct_ref[..] == ct[..] && k_ref[..] == k.expose_secret()[..] && k2_ref == k_ref);

    println!();
    println!(
        "  {:<42} {:>6}",
        "ml-kem decapsulation key size",
        size_of::<ml_kem_768::DecapsulationKey>()
    );
    println!();
    if same {
        println!("Encapsulation and decapsulation take the same instructions for all inputs.");
        process::exit(0)
    } else {
        println!("Encapsulation or decapsulation instructions depend on the input.");
        process::exit(1)
    }
}
