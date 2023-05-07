use crate::cbd::*;
use crate::ntt::*;
use crate::params::*;
use crate::sha3::*;

#[derive(Clone)]
pub struct Poly {
    pub coeffs: [i16; KYBER_N],
}

impl Copy for Poly {}

impl Default for Poly {
    fn default() -> Self {
        Poly {
            coeffs: [0; KYBER_N],
        }
    }
}

impl Poly {
    pub fn new() -> Self {
        Self::default()
    }
}

pub fn poly_getnoise_eta1(out: &mut Poly, seed: &[u8], nonce: u8) {
    const LENGTH: usize = KYBER_ETA1 * KYBER_N / 4;
    let mut buf = [0u8; LENGTH];
    kyber_shake256_prf(&mut buf, LENGTH, seed, nonce);
    poly_cbd_eta1(out, &buf);
}

pub fn poly_ntt(poly: &mut Poly) {
    ntt(&mut poly.coeffs);
    poly_reduce(poly);
}

pub fn poly_basemul(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..(KYBER_N / 4) {
        basemul(
            &mut r.coeffs[4 * i..],
            &a.coeffs[4 * i..],
            &b.coeffs[4 * i..],
            ZETAS[64 + i],
        );
        basemul(
            &mut r.coeffs[4 * i + 2..],
            &a.coeffs[4 * i + 2..],
            &b.coeffs[4 * i + 2..],
            -ZETAS[64 + i],
        );
    }
}

pub fn poly_add(r: &mut Poly, a: &Poly) {
    for i in 0..KYBER_N {
        r.coeffs[i] += a.coeffs[i];
    }
}

pub fn poly_reduce(r: &mut Poly) {
    for i in 0..KYBER_N {
        r.coeffs[i] = barrett_reduce(r.coeffs[i]);
    }
}

pub fn barrett_reduce(a: i16) -> i16 {
    let v = ((1u32 << 26) / KYBER_Q as u32 + 1) as i32;
    let mut t = v * a as i32 + (1 << 25);
    t >>= 26;
    t *= KYBER_Q as i32;
    a - t as i16
}

//r.coeffs[i] = MT(r.coeffs[i])
pub fn poly_to_mont(r: &mut Poly) {
    let f = ((1u64 << 32) % KYBER_Q as u64) as i16; //2^32 mod q
    for i in 0..KYBER_N {
        let a = r.coeffs[i] as i32 * f as i32; //a <- r[i] * f
        r.coeffs[i] = montgomery_reduce(a);
    }
}

pub fn poly_tobytes(r: &mut [u8], a: Poly) {
    let (mut t0, mut t1);

    for i in 0..(KYBER_N / 2) {
        t0 = a.coeffs[2 * i];
        t0 += (t0 >> 15) & KYBER_Q as i16;
        t1 = a.coeffs[2 * i + 1];
        t1 += (t1 >> 15) & KYBER_Q as i16;
        r[3 * i + 0] = (t0 >> 0) as u8;
        r[3 * i + 1] = ((t0 >> 8) | (t1 << 4)) as u8;
        r[3 * i + 2] = (t1 >> 4) as u8;
    }
}
