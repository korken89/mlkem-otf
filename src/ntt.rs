//! Arithmetic in R_q = Z_q[X] / (X^256 + 1) and the NTT (FIPS 203 sections 4.3 and 4.3.1).
//!
//! Coefficients are signed and in the Montgomery or plain domain as each function states. The
//! reductions are multiply-and-shift, with no division and no data-dependent branch. The
//! arithmetic wraps, so it has no overflow check even when a profile enables them. The bounds
//! stay within i16 and i32 for every input.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// The modulus q.
pub(crate) const Q: i16 = 3329;
/// Coefficients per polynomial (n).
pub(crate) const N: usize = 256;

/// A polynomial, wiped when dropped since most hold or derive from secrets.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Poly(pub(crate) [i16; N]);

impl Poly {
    pub(crate) const fn zero() -> Self {
        Self([0; N])
    }
}

/// zeta^BitRev7(i) * 2^16 mod q, centered, with zeta = 17 (FIPS 203 Appendix A).
const ZETAS: [i16; 128] = {
    let mut out = [0; 128];
    let mut i = 0;
    while i < 128 {
        let br = (i as u8).reverse_bits() >> 1;
        let mut p = 1;
        let mut e = 0;
        while e < br {
            p = p * 17 % 3329;
            e += 1;
        }
        let m: i32 = p * 2285 % 3329; // 2^16 mod q
        out[i] = if m > 1664 { m - 3329 } else { m } as i16;
        i += 1;
    }
    out
};

/// q^-1 mod 2^16.
const QINV: i16 = -3327;

/// `a * 2^-16 mod q` for `|a| < q * 2^15`, in `(-q, q)`.
pub(crate) fn montgomery_reduce(a: i32) -> i16 {
    let t = (a as i16).wrapping_mul(QINV);
    (a.wrapping_sub(i32::from(t).wrapping_mul(i32::from(Q))) >> 16) as i16
}

/// `a * b * 2^-16 mod q`.
pub(crate) fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce(i32::from(a).wrapping_mul(i32::from(b)))
}

/// The centered representative of `a mod q`.
pub(crate) fn barrett_reduce(a: i16) -> i16 {
    const V: i32 = ((1 << 26) + Q as i32 / 2) / Q as i32;
    let t = (V.wrapping_mul(i32::from(a)).wrapping_add(1 << 25) >> 26) as i16;
    a.wrapping_sub(t.wrapping_mul(Q))
}

/// Hides a mask from the optimizer. Without it, a mask of a secret sign or bit becomes a
/// branch or a conditional instruction on some targets (Clangover, CVE-2024-37880).
pub(crate) fn mask_barrier(mask: i16) -> i16 {
    core::hint::black_box(mask)
}

/// Maps a coefficient in `(-q, q)` to `[0, q)` without a branch.
pub(crate) fn to_unsigned(x: i16) -> u32 {
    x.wrapping_add(mask_barrier(x >> 15) & Q) as u32
}

pub(crate) fn reduce(r: &mut Poly) {
    for x in &mut r.0 {
        *x = barrett_reduce(*x);
    }
}

/// `r += a`, coefficient-wise.
pub(crate) fn add_assign(r: &mut Poly, a: &Poly) {
    for (x, y) in r.0.iter_mut().zip(&a.0) {
        *x = x.wrapping_add(*y);
    }
}

/// NTT (FIPS 203 Algorithm 9), output reduced.
#[inline(never)]
pub(crate) fn ntt(r: &mut Poly) {
    let mut zetas = ZETAS.iter().skip(1);
    let mut len = N / 2;
    while len >= 2 {
        for block in r.0.chunks_exact_mut(2 * len) {
            let zeta = zetas.next().copied().unwrap_or(0);
            let (lo, hi) = block.split_at_mut(len);
            for (a, b) in lo.iter_mut().zip(hi) {
                let t = fqmul(zeta, *b);
                *b = a.wrapping_sub(t);
                *a = a.wrapping_add(t);
            }
        }
        len /= 2;
    }
    reduce(r);
}

/// Inverse NTT (FIPS 203 Algorithm 10), times the Montgomery factor 2^16.
#[inline(never)]
pub(crate) fn inv_ntt_to_mont(r: &mut Poly) {
    /// mont^2 / 128.
    const F: i16 = 1441;
    let mut zetas = ZETAS.iter().rev();
    let mut len = 2;
    while len <= N / 2 {
        for block in r.0.chunks_exact_mut(2 * len) {
            let zeta = zetas.next().copied().unwrap_or(0);
            let (lo, hi) = block.split_at_mut(len);
            for (a, b) in lo.iter_mut().zip(hi) {
                let t = *a;
                *a = barrett_reduce(t.wrapping_add(*b));
                *b = fqmul(zeta, b.wrapping_sub(t));
            }
        }
        len *= 2;
    }
    for x in &mut r.0 {
        *x = fqmul(*x, F);
    }
}

/// `acc += a * b` for the pair `p` of coefficients in the NTT domain, with `a = (a0, a1)`
/// (BaseCaseMultiply, FIPS 203 Algorithm 12). The product carries a factor 2^-16.
pub(crate) fn basemul_acc(acc: &mut Poly, p: usize, a0: i16, a1: i16, b: &Poly) {
    // The masks keep the indices in bounds, so there is no bounds check.
    let zeta = ZETAS[64 + ((p >> 1) & 63)];
    // Odd pairs use the root -zeta.
    let zeta = zeta.wrapping_mul(1 - 2 * (p & 1) as i16);
    let i = (p << 1) & (N - 2);
    let (b0, b1) = (b.0[i], b.0[i + 1]);
    let c0 = fqmul(fqmul(a1, b1), zeta).wrapping_add(fqmul(a0, b0));
    let c1 = fqmul(a0, b1).wrapping_add(fqmul(a1, b0));
    acc.0[i] = acc.0[i].wrapping_add(c0);
    acc.0[i + 1] = acc.0[i + 1].wrapping_add(c1);
}

/// `acc += a * b` in the NTT domain (MultiplyNTTs, FIPS 203 Algorithm 11).
pub(crate) fn basemul_acc_poly(acc: &mut Poly, a: &Poly, b: &Poly) {
    for (p, a) in a.0.chunks_exact(2).enumerate() {
        if let [a0, a1] = *a {
            basemul_acc(acc, p, a0, a1, b);
        }
    }
}
