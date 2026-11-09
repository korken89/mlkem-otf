//! K-PKE (FIPS 203 section 5), one polynomial at a time.
//!
//! The secret and noise vectors are regenerated from their seeds where they are used, and the
//! matrix A is sampled entry by entry into an accumulator. Keys and ciphertexts are streamed into
//! a [`Sink`], so the working set is two or three polynomials whatever the rank k.

use zeroize::Zeroize;

use crate::encode::{Sink, compress, compress_encode, decode_decompress, decode12, encode12};
use crate::ntt::{
    Poly, add_assign, barrett_reduce, basemul_acc, basemul_acc_poly, inv_ntt_to_mont, mask_barrier,
    montgomery_reduce, ntt, reduce, to_unsigned,
};
use crate::params::Params;
use crate::sample::{Secret32, cbd2, cbd2_ntt, g, sample_ntt_acc};

/// Fails the build for a parameter set with a noise width that [`cbd2`] does not sample.
const fn assert_eta2<P: Params>() {
    assert!(P::ETA1 == 2 && P::ETA2 == 2, "only eta = 2 is implemented");
}

/// The source of s_hat for decryption, entry `j` into the polynomial.
pub(crate) trait SecretVector {
    fn entry(&self, j: u8, s_hat: &mut Poly);
}

/// s_hat regenerated from sigma, the second half of G(d || k).
pub(crate) struct FromSigma<'a>(pub(crate) &'a [u8; 32]);

impl SecretVector for FromSigma<'_> {
    fn entry(&self, j: u8, s_hat: &mut Poly) {
        cbd2_ntt(self.0, j, s_hat);
    }
}

/// K-PKE.KeyGen (FIPS 203 Algorithm 13) from `d`, streaming ek = ByteEncode_12(t_hat) || rho.
/// The decryption key is not produced, decryption regenerates it.
pub(crate) fn keygen<P: Params>(d: &[u8; 32], sink: &mut impl Sink) {
    const { assert_eta2::<P>() };
    let (mut rho, mut sigma) = (Secret32::default(), Secret32::default());
    g(&[d, &[P::K as u8]], &mut rho.0, &mut sigma.0);
    let mut t = Poly::zero();
    for i in 0..P::K as u8 {
        t_row::<P>(&rho.0, &sigma.0, i, &mut t);
        encode12(&t, sink);
    }
    for &b in &rho.0 {
        sink.put(b);
    }
}

/// `t_hat[i] = sum_j A_hat[i][j] * s_hat[j] + e_hat[i]`, reduced.
#[inline(never)]
fn t_row<P: Params>(rho: &[u8; 32], sigma: &[u8; 32], i: u8, t: &mut Poly) {
    let mut tmp = Poly::zero();
    t.zeroize();
    for j in 0..P::K as u8 {
        cbd2_ntt(sigma, j, &mut tmp);
        sample_ntt_acc(rho, j, i, &tmp, t);
    }
    // Back from the 2^-16 of the products, times 2^32 mod q.
    for x in &mut t.0 {
        *x = montgomery_reduce(i32::from(*x).wrapping_mul(1353));
    }
    cbd2_ntt(sigma, i.wrapping_add(P::K as u8), &mut tmp);
    add_assign(t, &tmp);
    reduce(t);
}

/// K-PKE.Encrypt (FIPS 203 Algorithm 14) to `ek = t || rho` with message `m` and randomness
/// `r`, streaming the ciphertext into `sink`.
#[inline(never)]
pub(crate) fn encrypt<P: Params>(
    t: &[u8],
    rho: &[u8; 32],
    m: &[u8; 32],
    r: &[u8; 32],
    sink: &mut impl Sink,
) {
    const { assert_eta2::<P>() };
    let mut acc = Poly::zero();
    for i in 0..P::K as u8 {
        u_row::<P>(rho, r, i, &mut acc);
        compress_encode(&acc, P::DU, sink);
    }
    v_poly::<P>(t, m, r, &mut acc);
    compress_encode(&acc, P::DV, sink);
}

/// `u[i] = NTT^-1(sum_j A_hat[j][i] * y_hat[j]) + e1[i]`, reduced.
#[inline(never)]
fn u_row<P: Params>(rho: &[u8; 32], r: &[u8; 32], i: u8, u: &mut Poly) {
    let mut tmp = Poly::zero();
    u.zeroize();
    for j in 0..P::K as u8 {
        cbd2_ntt(r, j, &mut tmp);
        sample_ntt_acc(rho, i, j, &tmp, u);
    }
    reduce(u);
    inv_ntt_to_mont(u);
    cbd2(r, i.wrapping_add(P::K as u8), &mut tmp);
    add_assign(u, &tmp);
    reduce(u);
}

/// `v = NTT^-1(t_hat^T * y_hat) + e2 + Decompress_1(m)`, reduced.
#[inline(never)]
fn v_poly<P: Params>(t: &[u8], m: &[u8; 32], r: &[u8; 32], v: &mut Poly) {
    let mut tmp = Poly::zero();
    v.zeroize();
    // Split instead of chunks_exact, whose length division stays at opt-level z.
    let mut rows = t;
    for j in 0..P::K as u8 {
        let Some((row, rest)) = rows.split_at_checked(384) else {
            break;
        };
        rows = rest;
        cbd2_ntt(r, j, &mut tmp);
        for (p, (a0, a1)) in decode12(row).enumerate() {
            basemul_acc(v, p, a0, a1, &tmp);
        }
    }
    reduce(v);
    inv_ntt_to_mont(v);
    cbd2(r, 2 * P::K as u8, &mut tmp);
    add_assign(v, &tmp);
    for (v, byte) in v.0.chunks_exact_mut(8).zip(m) {
        for (k, v) in (0..8).zip(v) {
            // 0 or round(q / 2), by masking.
            let mask = mask_barrier(-i16::from(byte.wrapping_shr(k) & 1));
            *v = v.wrapping_add(mask & 1665);
        }
    }
    reduce(v);
}

/// K-PKE.Decrypt (FIPS 203 Algorithm 15) of `c` into `m`.
#[inline(never)]
pub(crate) fn decrypt<P: Params>(s_hat: &impl SecretVector, c: &[u8], m: &mut [u8; 32]) {
    let mut acc = Poly::zero();
    let mut u = Poly::zero();
    let mut s = Poly::zero();
    let mut rest = c;
    for j in 0..P::K as u8 {
        let Some((c1, tail)) = rest.split_at_checked(P::U_POLY_LEN) else {
            break;
        };
        rest = tail;
        decode_decompress(c1, P::DU, &mut u);
        ntt(&mut u);
        s_hat.entry(j, &mut s);
        basemul_acc_poly(&mut acc, &s, &u);
    }
    reduce(&mut acc);
    inv_ntt_to_mont(&mut acc);
    let v = &mut u;
    decode_decompress(rest, P::DV, v);
    for (byte, (v, a)) in m
        .iter_mut()
        .zip(v.0.chunks_exact(8).zip(acc.0.chunks_exact(8)))
    {
        *byte = 0;
        for (k, (v, a)) in (0..8).zip(v.iter().zip(a)) {
            let w = to_unsigned(barrett_reduce(v.wrapping_sub(*a)));
            *byte |= (compress(w, 1) as u8).wrapping_shl(k);
        }
    }
}
