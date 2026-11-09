//! The ML-KEM parameter sets (FIPS 203 section 8).

/// The constants of a parameter set.
pub(crate) trait Params {
    /// Rank of the module, the side of the square matrix A (k).
    const K: usize;
    /// Noise width of s, e and y (eta1).
    const ETA1: usize;
    /// Noise width of e1 and e2 (eta2).
    const ETA2: usize;
    /// Bits per compressed coefficient of u (d_u).
    const DU: u32;
    /// Bits per compressed coefficient of v (d_v).
    const DV: u32;

    /// Bytes of the encoded vector t, the encapsulation key without rho.
    const T_LEN: usize = 384 * Self::K;
    /// Bytes of an encapsulation key, ByteEncode_12(t) || rho.
    const EK_LEN: usize = Self::T_LEN + 32;
    /// Bytes of one compressed polynomial of u.
    const U_POLY_LEN: usize = 32 * Self::DU as usize;
    /// Bytes of the compressed vector u.
    const U_LEN: usize = Self::U_POLY_LEN * Self::K;
    /// Bytes of a ciphertext, c1 || c2.
    const CT_LEN: usize = Self::U_LEN + 32 * Self::DV as usize;
}

/// ML-KEM-768, security category 3.
pub(crate) struct MlKem768;

impl Params for MlKem768 {
    const K: usize = 3;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: u32 = 10;
    const DV: u32 = 4;
}

// The public API spells the ML-KEM-768 lengths out.
const _: () = assert!(MlKem768::EK_LEN == 1184 && MlKem768::CT_LEN == 1088);
