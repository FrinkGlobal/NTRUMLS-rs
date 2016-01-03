//! NTRUMLS parameter module
//!
//! This module includes the needed parameters for NTRUMLS key generation.
use libc::c_char;

#[repr(C)]
enum ParamSetId {
    Xxx20140508401,
    Xxx20140508439,
    Xxx20140508593,
    Xxx20140508743,

    Xxx20151024401,
    Xxx20151024443,
    Xxx20151024563,
    // Xxx20151024509,
    Xxx20151024743,
    Xxx20151024907,
}

/// NTRUMLS parameter set
///
/// This struct represents a parameter set for NTRUMLS key generation.
#[repr(C)]
pub struct ParamSet {
    /// Parameter set id
    id: ParamSetId,
    /// Human readable name
    name: *const c_char,
    /// OID
    oid: [u8; 3],
    /// ceil(log2(N))
    n_bits: u8,
    /// ceil(log2(q))
    q_bits: u8,
    /// Ring degree
    n: u16,
    /// Message space prime
    p: i8,
    /// Ring modulus
    q: i64,
    /// Max norm of f*a convolution
    b_s: i64,
    /// Max norm of g*a convolution
    b_t: i64,
    /// q/2 - b_s
    norm_bound_s: i64,
    /// q/2 - b_t
    norm_bound_t: i64,
    /// Product form +1/-1 counts
    d1: u8,
    d2: u8,
    d3: u8,
    /// Polynomial coefficients for Karatsuba
    padded_n: u16,
}

impl ParamSet {
    /// Ring degree
    pub fn get_n(&self) -> u16 {
        self.n
    }
    /// Message space prime
    pub fn get_p(&self) -> i8 {
        self.p
    }
    /// Product form +1/-1 counts
    pub fn get_d1(&self) -> u8 {
        self.d1
    }
    /// Product form +1/-1 counts
    pub fn get_d2(&self) -> u8 {
        self.d2
    }
    /// Product form +1/-1 counts
    pub fn get_d3(&self) -> u8 {
        self.d3
    }

    /// No. of bytes in packed mod q polynomial, e.g. h
    pub fn product_form_bytes(&self) -> usize {
        4 * (self.d1 as usize + self.d2 as usize + self.d3 as usize)
    }

    /// No. of bytes in padded polynomials used in Karatsuba multiplication
    pub fn polynomial_bytes(&self) -> usize {
        self.padded_n as usize * 8
    }

    /// **UNSTABLE** Private key blob
    ///
    /// TAG (1 byte), OID_LEN (1 byte), OID (3 bytes), product form f and g, g^-1 mod p
    ///
    /// **Note**: assumes p = 3.
    /// **Note**: not standardized. subject to change
    pub fn privkey_packed_bytes(&self) -> usize {
        5 +
        2 *
        ((2 * (self.d1 as usize + self.d2 as usize + self.d3 as usize) *
          self.n_bits as usize + 7) / 8) + ((self.n as usize + 4) / 5)
    }

    /// **UNSTABLE** Public key blob
    ///
    /// TAG (1 byte), OID_LEN (1 byte), OID (3 bytes), h (N * ceil(log2(q)) bits),
    /// digest (HASH_BYTES bytes)
    ///
    /// **Note**: not standardized. subject to change
    pub fn pubkey_packed_bytes(&self) -> usize {
        5 + (self.n as usize * self.q_bits as usize + 7) / 8 + 64
    }
}

/// 112 bit security parameter
pub const XXX_20140508_401: ParamSet = ParamSet {
    id: ParamSetId::Xxx20140508401,
    name: &[120, 120, 120, 45, 50, 48, 49, 52, 48, 53, 48, 56, 45, 52, 48, 49i8, 0][0],
    oid: [0xff, 0xff, 0xff],
    n_bits: 9,
    q_bits: 18,
    n: 401,
    p: 3,
    q: 1 << 18,
    b_s: 240,
    b_t: 80,
    norm_bound_s: (1 << 17) - 240,
    norm_bound_t: (1 << 17) - 80,
    d1: 8,
    d2: 8,
    d3: 6,
    padded_n: 416,
};

/// 128 bit security parameter
pub const XXX_20140508_439: ParamSet = ParamSet {
    id: ParamSetId::Xxx20140508439,
    name: &[120, 120, 120, 45, 50, 48, 49, 52, 48, 53, 48, 56, 45, 52, 51, 57, 0][0],
    oid: [0xff, 0xff, 0xfe],
    n_bits: 9,
    q_bits: 19,
    n: 439,
    p: 3,
    q: 1 << 19,
    b_s: 264,
    b_t: 88,
    norm_bound_s: (1 << 18) - 264,
    norm_bound_t: (1 << 18) - 88,
    d1: 9,
    d2: 8,
    d3: 5,
    padded_n: 448,
};

/// 192 bit security parameter
pub const XXX_20140508_593: ParamSet = ParamSet {
    id: ParamSetId::Xxx20140508593,
    name: &[120, 120, 120, 45, 50, 48, 49, 52, 48, 53, 48, 56, 45, 53, 57, 51, 0][0],
    oid: [0xff, 0xff, 0xfd],
    n_bits: 10,
    q_bits: 19,
    n: 593,
    p: 3,
    q: 1 << 19,
    b_s: 300,
    b_t: 100,
    norm_bound_s: (1 << 18) - 300,
    norm_bound_t: (1 << 18) - 100,
    d1: 10,
    d2: 10,
    d3: 8,
    padded_n: 608,
};

/// 256 bit security parameter
pub const XXX_20140508_743: ParamSet = ParamSet {
    id: ParamSetId::Xxx20140508743,
    name: &[120, 120, 120, 45, 50, 48, 49, 52, 48, 53, 48, 56, 45, 55, 52, 51, 0][0],
    oid: [0xff, 0xff, 0xfc],
    n_bits: 10,
    q_bits: 20,
    n: 743,
    p: 3,
    q: 1 << 20,
    b_s: 336,
    b_t: 112,
    norm_bound_s: (1 << 19) - 336,
    norm_bound_t: (1 << 19) - 112,
    d1: 11,
    d2: 11,
    d3: 15,
    padded_n: 768,
};

pub const XXX_20151024_401: ParamSet = ParamSet {
    id: ParamSetId::Xxx20151024401,
    name: &[120, 120, 120, 45, 50, 48, 49, 53, 49, 48, 50, 52, 45, 52, 48, 49, 0][0],
    oid: [0xff, 0xff, 0xfb],
    n_bits: 9,
    q_bits: 15,
    n: 401,
    p: 3,
    q: 1 << 15,
    b_s: 138,
    b_t: 46,
    norm_bound_s: (1 << 14) - 138,
    norm_bound_t: (1 << 14) - 46,
    d1: 8,
    d2: 8,
    d3: 6,
    padded_n: 416,
};

pub const XXX_20151024_443: ParamSet = ParamSet {
    id: ParamSetId::Xxx20151024443,
    name: &[120, 120, 120, 45, 50, 48, 49, 53, 49, 48, 50, 52, 45, 52, 52, 51, 0][0],
    oid: [0xff, 0xff, 0xfa],
    n_bits: 9,
    q_bits: 16,
    n: 443,
    p: 3,
    q: 1 << 16,
    b_s: 138,
    b_t: 46,
    norm_bound_s: (1 << 15) - 138,
    norm_bound_t: (1 << 15) - 46,
    d1: 9,
    d2: 8,
    d3: 5,
    padded_n: 448,
};

pub const XXX_20151024_563: ParamSet = ParamSet {
    id: ParamSetId::Xxx20151024563,
    name: &[120, 120, 120, 45, 50, 48, 49, 53, 49, 48, 50, 52, 45, 53, 54, 51, 0][0],
    oid: [0xff, 0xff, 0xf9],
    n_bits: 10,
    q_bits: 16,
    n: 563,
    p: 3,
    q: 1 << 16,
    b_s: 174,
    b_t: 58,
    norm_bound_s: (1 << 15) - 174,
    norm_bound_t: (1 << 15) - 58,
    d1: 10,
    d2: 9,
    d3: 8,
    padded_n: 592,
};

// Test parameter set that is not formally transcript secure
// pub const XXX_20151024_509: ParamSet = ParamSet {
//     id: ParamSetId::Xxx20151024509,
//     name: &[120, 120, 120, 45, 50, 48, 49, 53, 49, 48, 50, 52, 45, 53, 48, 57, 0][0],
//     oid: [0xff, 0xff, 0xf8],
//     n_bits: 9,
//     q_bits: 14,
//     n: 509,
//     p: 3,
//     q: 1<<14,
//     b_s: 10000,
//     b_t: 10000,
//     norm_bound_s: (1<<13) - 1,
//     norm_bound_t: (1<<13) - 1,
//     d1: 9,
//     d2: 9,
//     d3: 8,
//     padded_n: 512,
// };

pub const XXX_20151024_743: ParamSet = ParamSet {
    id: ParamSetId::Xxx20151024743,
    name: &[120, 120, 120, 45, 50, 48, 49, 53, 49, 48, 50, 52, 45, 55, 52, 51, 0][0],
    oid: [0xff, 0xff, 0xf7],
    n_bits: 10,
    q_bits: 17,
    n: 743,
    p: 3,
    q: 1 << 17,
    b_s: 186,
    b_t: 62,
    norm_bound_s: (1 << 16) - 186,
    norm_bound_t: (1 << 16) - 62,
    d1: 11,
    d2: 11,
    d3: 6,
    padded_n: 752,
};

pub const XXX_20151024_907: ParamSet = ParamSet {
    id: ParamSetId::Xxx20151024907,
    name: &[120, 120, 120, 45, 50, 48, 49, 53, 49, 48, 50, 52, 45, 57, 48, 55, 0][0],
    oid: [0xff, 0xff, 0xf6],
    n_bits: 10,
    q_bits: 17,
    n: 907,
    p: 3,
    q: 1 << 17,
    b_s: 225,
    b_t: 75,
    norm_bound_s: (1 << 16) - 225,
    norm_bound_t: (1 << 16) - 75,
    d1: 13,
    d2: 12,
    d3: 7,
    padded_n: 912,
};
