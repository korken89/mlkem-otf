//! The hash functions (FIPS 203 section 4.1) and the samplers (section 4.2.2).
//!
//! The hash functions of secrets write into the caller's buffers and finalize their hashers in
//! place, since a moved secret leaves a copy on the stack.

use sha3::{Digest, Sha3_256, Sha3_512};
use shake::digest::ExtendableOutputReset;
use shake::{ExtendableOutput, Shake128, Shake256, Update, XofReader};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::ntt::{N, Poly, Q, basemul_acc, ntt};

/// A 32-byte secret (seed, message, key) that is wiped when dropped.
#[derive(Default, Zeroize, ZeroizeOnDrop)]
pub(crate) struct Secret32(pub(crate) [u8; 32]);

/// G (FIPS 203 equation 4.5) of the concatenation of `parts`, into its halves `a` and `b`.
pub(crate) fn g(parts: &[&[u8]], a: &mut [u8; 32], b: &mut [u8; 32]) {
    let mut hash = Sha3_512::new();
    for part in parts {
        Digest::update(&mut hash, part);
    }
    let mut out = Zeroizing::new([0; 64]);
    hash.finalize_into_reset((&mut *out).into());
    a.copy_from_slice(&out[..32]);
    b.copy_from_slice(&out[32..]);
}

/// H (FIPS 203 equation 4.4).
pub(crate) fn h(bytes: &[u8]) -> [u8; 32] {
    Sha3_256::digest(bytes).into()
}

/// J (FIPS 203 equation 4.4), the implicit rejection key `J(z || c)`, into `out`.
pub(crate) fn j(z: &[u8; 32], c: &[u8], out: &mut [u8; 32]) {
    shake256(&[z, c], out);
}

/// SHAKE256 of the concatenation of `parts`, into `out`.
fn shake256(parts: &[&[u8]], out: &mut [u8]) {
    let mut xof = Shake256::default();
    for part in parts {
        xof.update(part);
    }
    xof.finalize_xof_reset_into(out);
}

/// `r = SamplePolyCBD_2(PRF_2(seed, nonce))` (FIPS 203 Algorithm 8 and equation 4.3).
#[inline(never)]
pub(crate) fn cbd2(seed: &[u8; 32], nonce: u8, r: &mut Poly) {
    let mut buf = Zeroizing::new([0; 128]);
    shake256(&[seed, &[nonce]], &mut buf[..]);
    for (r, w) in r.0.chunks_exact_mut(8).zip(buf.chunks_exact(4)) {
        let t = match *w {
            [b0, b1, b2, b3] => u32::from_le_bytes([b0, b1, b2, b3]),
            _ => 0,
        };
        // Each 4-bit group holds two 2-bit sums of adjacent bits.
        let d = (t & 0x5555_5555) + ((t >> 1) & 0x5555_5555);
        for (k, r) in r.iter_mut().enumerate() {
            let a = ((d >> (4 * k)) & 3) as i16;
            let b = ((d >> (4 * k + 2)) & 3) as i16;
            *r = a - b;
        }
    }
}

/// `r = NTT(SamplePolyCBD_2(PRF_2(seed, nonce)))`.
#[inline(never)]
pub(crate) fn cbd2_ntt(seed: &[u8; 32], nonce: u8, r: &mut Poly) {
    cbd2(seed, nonce, r);
    ntt(r);
}

/// `acc += A_hat * b` for one matrix entry `A_hat = SampleNTT(rho || x || y)` (FIPS 203
/// Algorithm 7). The entry is multiplied in as it is sampled and never stored. The rejection
/// depends on `rho` only, which is public.
#[inline(never)]
pub(crate) fn sample_ntt_acc(rho: &[u8; 32], x: u8, y: u8, b: &Poly, acc: &mut Poly) {
    let mut xof = Shake128::default().chain(rho).chain([x, y]).finalize_xof();
    let mut n = 0;
    let mut even = 0;
    while n < N {
        let mut buf = [0; 24];
        xof.read(&mut buf);
        for c in buf.chunks_exact(3) {
            let [c0, c1, c2] = *c else { continue };
            let d1 = i16::from(c0) | (i16::from(c1 & 0xf) << 8);
            let d2 = i16::from(c1 >> 4) | (i16::from(c2) << 4);
            for d in [d1, d2] {
                if d < Q && n < N {
                    if n.is_multiple_of(2) {
                        even = d;
                    } else {
                        basemul_acc(acc, n / 2, even, d, b);
                    }
                    n += 1;
                }
            }
        }
    }
}
