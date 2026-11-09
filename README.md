# mlkem-otf

ML-KEM-768 (FIPS 203) with a small stack, for microcontrollers.

The matrix A, the secret vector and the noise are never stored.
Each matrix entry is sampled into an accumulator as it is needed, and the vectors are regenerated from their seeds where they are used.
Keys and ciphertexts are encoded straight into the caller's buffer, and decapsulation compares the re-encryption with the received ciphertext as it is produced.
The working set is at most three polynomials.

The private key is kept only as its 64-byte seed `d || z`, which is filled in place into a slot that the caller provides and never moved.
The matching encapsulation key is borrowed from where it is stored, for example flash, and checked against the seed once with `bind`.

## ⚠️ Security Warning

The implementation contained in this crate has never been independently audited!

USE AT YOUR OWN RISK!

There is no protection against fault injection, such as voltage glitches, or against power and electromagnetic analysis.

Secret temporaries on the stack (polynomials, seeds, hashes, the noise, the message `m`, the keys `K` and `K_bar` and the randomness `r`) are wiped when they go out of scope.
`make test-qemu` fails if an operation leaves one of its secrets on the stack below the caller, at opt-level s, 2, 3 and z.
It searches for `d || z`, `d` and `z` after the key is generated or loaded, also into a slot on the stack of the operation that is then dropped, and after KeyGen, `bind` and decapsulation.
After KeyGen, `bind` and decapsulation it searches for `sigma`, the seed of the secret vector, and for the PRF outputs `SHAKE256(sigma || i)` that the operation samples the secret and noise vectors from.
After encapsulation it searches for `m`, `K`, `r` and the PRF outputs `SHAKE256(r || i)`.
After decapsulation it also searches for `K_bar` and the returned key, and for `m`, `K`, `r` and `SHAKE256(r || i)` when the ciphertext decrypts to `m`, which holds for the valid ciphertext and three of the four modified ones.
Each secret is searched for whole and in 16-byte parts.
A SHA-3 or SHAKE output is the leading bytes of the sponge state after its last permutation, so a copy of these bytes of the state is found too.
Copies the compiler makes, such as register spills, and earlier sponge states are out of reach.
So are the stack slots of the optimization barriers, which keep the last mask of a sign or a message bit and, after decapsulation, whether the ciphertext was valid.
An interrupt taken during an operation pushes registers that can hold secret intermediates below the stack pointer, where they stay, so mask interrupts around the operation or run it at the lowest priority if that matters.

`DecapsulationKey::from_seed` and `generate` fill the key in place, in a `DecapsulationKeySlot` that the caller provides, and lend it out by shared reference only, so the seed is never moved.
The slot can be a `static`, for example in a `ConstStaticCell`, or on the stack, and it is wiped when it is dropped.
A key that is already in the slot is wiped before the slot is filled again.
Moving a slot that holds a key copies the key, so keep the slot where it is.
`from_seed` wipes the caller's copy of the seed.
`bind` borrows the key, so the `BoundKey` holds no secret of its own and can be moved freely.

## Constant time

The generated code is checked for Cortex-M0 and M0+ (`thumbv6m`), M3 (`thumbv7m`), M4 (`thumbv7em`) and M33 (`thumbv8m.main`).

- No branch, memory index or division in the source depends on secret data.
  Compress uses a multiply and a shift instead of a division by q (KyberSlash).
- Masks of secret signs and bits go through an optimization barrier (`core::hint::black_box`).
  Without it, the compiler turns them into branches on the Cortex-M0 and into conditional instructions on the others (Clangover, CVE-2024-37880).
- Decapsulation always computes the implicit rejection key, compares the re-encryption over the whole ciphertext and selects the result without a branch.
  The select and compare use `ctutils` rather than `subtle`, since its `CtAssign` on arrays selects with `cmov` and the RustCrypto `ml-kem` crate builds on it too.
- The arithmetic wraps explicitly, so a profile with overflow checks adds no branch or panic.
- `make ct-guard` links all operations for each core at opt-level 2, 3, s and z, at 2, 3 and s with overflow checks on, and at s without LTO and with 16 codegen units.
  It checks every instruction of the functions that hold code of this crate, `ctutils` or `cmov`, also code inlined from `core` and other crates, and of every function they call, also the ones the compiler outlines.
  Calls into the SHA-3 crates, the panic functions and the formatting of their messages are not followed.
  Of the `compiler-builtins` helpers, the ones that copy, fill, divide, shift 64-bit values or load and store unaligned data are not followed, and every other helper is.
  It fails on:
  - a division instruction or helper call.
    At opt-level z, without LTO and on the Cortex-M0, `core` keeps divisions of public slice lengths, so there only the checked functions are checked.
  - a conditional branch, IT block or jump table from a line that is not listed in [`guard/public-branches.txt`](guard/public-branches.txt), the lines that branch on public data only.
    The line of each instruction comes from the line table, and an instruction without a source line must be listed by the function it is inlined from.
  - a different number of branches per line than [`guard/branch-counts.txt`](guard/branch-counts.txt) has for the build, so that a new branch on a listed line fails too.
  - a call to a 64-bit shift helper, which branches on the shift amount, from a line other than the SHA-3 padding, which shifts by a public position.
  - a long multiply (`umull`, `smull`, `umlal`, `smlal`) on the Cortex-M3, where they end early for small operands.
  - an indirect call through a register that the caller does not load with a function address.
  - a reachable panic at opt-level 2, 3 and s with LTO, or an instruction that does not decode.
- `make test-qemu` fails unless encapsulation executes the same number of instructions for different messages, and decapsulation for a valid and for modified ciphertexts, at opt-level s, 2, 3 and z on a Cortex-M33.
- Secret arithmetic uses 32-bit multiplies and multiply-accumulates (`mul`, `mla`, `mls`, and the 16-bit DSP forms such as `smlabb` where the core has them).
  These take a fixed time on the cores above.

These checks cover the instruction stream on QEMU and the generated code for the cores above.
Timing has not been measured on hardware.

## Usage

```rust
use mlkem_otf::{DecapsulationKey, DecapsulationKeySlot, EncapsulationKey};
use static_cell::ConstStaticCell;

// Provisioning: store the seed in secure storage and ek where it can be read. The slot on the
// stack is wiped when it is dropped.
let mut seed = [0; 64];
rng.fill_bytes(&mut seed);
storage.write(&seed);
let mut slot = DecapsulationKeySlot::new();
let mut ek = [0; 1184];
DecapsulationKey::from_seed(&mut slot, &mut seed).encapsulation_key(&mut ek);
drop(slot);

// At boot: load the seed into a static slot, which wipes `seed`, and check the stored ek once
static KEY: ConstStaticCell<DecapsulationKeySlot> =
    ConstStaticCell::new(DecapsulationKeySlot::new());
storage.read(&mut seed);
let own = DecapsulationKey::from_seed(KEY.take(), &mut seed).bind(&ek)?;

// A peer: check its key once, then encapsulate into a caller buffer
let peer = EncapsulationKey::new(&peer_ek)?;
let mut ct = [0; 1088];
let sent = peer.encapsulate(&mut rng, &mut ct);

// Decapsulate in place from the received bytes
let received = own.decapsulate(&ct);
```

`DecapsulationKey::generate` draws a seed that cannot be read back, so it is for keys that are not stored.
`DecapsulationKey::try_generate` and `EncapsulationKey::try_encapsulate` take an RNG that can fail (`TryCryptoRng`) and return its error.

The `hazmat` feature adds `encapsulate_deterministic`, for known-answer tests and for protocols that derive the message `m` themselves.
The `defmt` feature derives `defmt::Format` for `EncapsulationKey` and the error types.

## Measurements

On a Cortex-M33 in QEMU (mps2-an505), with opt-level "s", fat LTO and one codegen unit.
The stack is the peak use of a painted stack, the instructions are exact counts from a QEMU plugin (`qemu/icount.c`), and the code size is what the operation adds to an empty binary, SHA-3 included.

| Operation                    | Stack (B) | Instructions | .text (B) | `ml-kem` 0.3.4 stack (B) | `ml-kem` instructions |
| ---------------------------- | --------: | -----------: | --------: | -----------------------: | --------------------: |
| KeyGen                       |     1,952 |    2,306,305 |     3,612 |                   28,328 |             2,721,486 |
| Encapsulation key check      |       448 |      430,443 |     1,216 |                   10,020 |               561,057 |
| Seed and key check (`bind`)  |     1,944 |    2,732,654 |     3,896 |                        - |                     - |
| Encapsulate                  |     2,032 |    2,653,608 |     4,628 |                   29,664 |             2,521,668 |
| Decapsulate                  |     2,648 |    3,463,276 |     5,936 |                   35,040 |             3,257,333 |
| All of the above             |         - |            - |     7,076 |                        - |                     - |

The key check includes `H(ek)`, and `bind` is KeyGen plus `H(ek)`.
`ml-kem` keeps a 3,202-byte decapsulation key in memory, where this crate keeps the 64-byte seed and borrows the encapsulation key.
QEMU does not model cycles, so the instruction counts are a proxy for time.

The exact stack and instruction counts are in [`qemu/stack-usage.txt`](qemu/stack-usage.txt) and `make test-qemu` fails if they change.

## Testing

The flake has the toolchain, QEMU and the tools for the plugin and the guard:

```console
$ nix develop
$ make test      # host tests, QEMU measurements and the constant-time guard
$ make lint      # rustfmt, clippy and rustdoc
$ make size      # code size of each operation
$ make bless     # update qemu/stack-usage.txt and guard/branch-counts.txt after an intended change
```

The host tests run the NIST ACVP and Wycheproof ML-KEM-768 vectors, including modified ciphertexts and keys with a coefficient of q, and cross check against the `ml-kem` crate over many seeds.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
