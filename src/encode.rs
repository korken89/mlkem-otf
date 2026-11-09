//! Compression and byte encoding (FIPS 203 section 4.2.1), streamed a byte at a time.

use core::slice;

use zeroize::ZeroizeOnDrop;

use crate::ntt::{Poly, Q, to_unsigned};

/// Where key and ciphertext bytes go as they are produced.
pub(crate) trait Sink {
    /// Takes the next byte.
    fn put(&mut self, byte: u8);
}

/// Writes into a buffer and drops what does not fit.
pub(crate) struct Writer<'a>(slice::IterMut<'a, u8>);

impl<'a> Writer<'a> {
    pub(crate) fn new(out: &'a mut [u8]) -> Self {
        Self(out.iter_mut())
    }
}

impl Sink for Writer<'_> {
    fn put(&mut self, byte: u8) {
        if let Some(b) = self.0.next() {
            *b = byte;
        }
    }
}

/// ORs the difference to the expected bytes into `diff`. Every byte goes through the same
/// instructions, so the time does not depend on where or whether the bytes differ. `diff` is
/// wiped when dropped, since in decapsulation it tells whether the ciphertext was valid.
#[derive(ZeroizeOnDrop)]
pub(crate) struct Compare<'a> {
    #[zeroize(skip)]
    expected: slice::Iter<'a, u8>,
    diff: u8,
}

impl<'a> Compare<'a> {
    pub(crate) fn new(expected: &'a [u8]) -> Self {
        Self {
            expected: expected.iter(),
            diff: 0,
        }
    }

    /// Zero if all bytes matched and as many were put as expected.
    pub(crate) fn diff(&self) -> u8 {
        self.diff | u8::from(self.expected.len() != 0)
    }
}

impl Sink for Compare<'_> {
    fn put(&mut self, byte: u8) {
        // A byte past the end is a difference.
        self.diff |= byte ^ self.expected.next().map_or(!byte, |e| *e);
    }
}

/// Compress_d (FIPS 203 equation 4.7) of a coefficient in `[0, q)`, as `round(2^d * x / q)` by
/// multiply-and-shift, so it is constant time for any `d` and compiler (KyberSlash). The
/// constants are exact for every input and `d` in {1, 4, 5, 10, 11}, see the tests.
pub(crate) fn compress(x: u32, d: u32) -> u32 {
    /// round(2^31 / q).
    const M: u32 = 645_084;
    let rounded = x
        .wrapping_mul(M)
        .wrapping_add(1 << (30 - d))
        .wrapping_sub(1 << 9);
    (rounded >> (31 - d)) & ((1 << d) - 1)
}

/// Decompress_d (FIPS 203 equation 4.8).
fn decompress(y: u32, d: u32) -> i16 {
    ((y * Q as u32 + (1 << (d - 1))) >> d) as i16
}

/// ByteEncode_d(Compress_d(r)) (FIPS 203 Algorithm 5 and equation 4.7), for a reduced `r`.
pub(crate) fn compress_encode(r: &Poly, d: u32, sink: &mut impl Sink) {
    let mut acc = 0u32;
    let mut bits = 0;
    for &x in &r.0 {
        acc |= compress(to_unsigned(x), d) << bits;
        bits += d;
        while bits >= 8 {
            sink.put(acc as u8);
            acc >>= 8;
            bits -= 8;
        }
    }
}

/// Decompress_d(ByteDecode_d(bytes)) (FIPS 203 Algorithm 6 and equation 4.8). `bytes` holds
/// `32 * d` bytes.
pub(crate) fn decode_decompress(bytes: &[u8], d: u32, r: &mut Poly) {
    let mut acc = 0u32;
    let mut bits = 0;
    let mut bytes = bytes.iter();
    for x in &mut r.0 {
        while bits < d {
            acc |= u32::from(bytes.next().copied().unwrap_or(0)) << bits;
            bits += 8;
        }
        *x = decompress(acc & ((1 << d) - 1), d);
        acc >>= d;
        bits -= d;
    }
}

/// ByteEncode_12 (FIPS 203 Algorithm 5) of a reduced polynomial.
pub(crate) fn encode12(r: &Poly, sink: &mut impl Sink) {
    for p in r.0.chunks_exact(2) {
        if let [a, b] = *p {
            let (a, b) = (to_unsigned(a), to_unsigned(b));
            sink.put(a as u8);
            sink.put(((a >> 8) | (b << 4)) as u8);
            sink.put((b >> 4) as u8);
        }
    }
}

/// The coefficient pairs of ByteDecode_12 (FIPS 203 Algorithm 6), without the reduction mod q.
pub(crate) fn decode12(bytes: &[u8]) -> impl Iterator<Item = (i16, i16)> + '_ {
    bytes.chunks_exact(3).map(|c| match *c {
        [c0, c1, c2] => {
            let (c0, c1, c2) = (i16::from(c0), i16::from(c1), i16::from(c2));
            (c0 | ((c1 & 0xf) << 8), (c1 >> 4) | (c2 << 4))
        }
        _ => (0, 0),
    })
}
