use crate::params::*;
use crate::polynomial::*;

#[derive(Clone)]
pub struct Polyvec {
    pub vec: [Poly; KYBER_K],
}

impl Copy for Polyvec {}

impl Default for Polyvec {
    fn default() -> Self {
        Polyvec {
            vec: [Poly::new(); KYBER_K],
        }
    }
}

impl Polyvec {
    pub fn new() -> Self {
        Self::default()
    }
}

pub fn polyvec_ntt(polyvec: &mut Polyvec) {
    for i in 0..KYBER_K {
        poly_ntt(&mut polyvec.vec[i]);
    }
}

pub fn polyvec_mul_montgomery(r: &mut Poly, a: &Polyvec, b: &Polyvec) {
    let mut t = Poly::new();
    poly_basemul(r, &a.vec[0], &b.vec[0]);
    for i in 1..KYBER_K {
        poly_basemul(&mut t, &a.vec[i], &b.vec[i]);
        poly_add(r, &t);
    }
    poly_reduce(r);
}

pub fn polyvec_add(r: &mut Polyvec, a: &Polyvec) {
    for i in 0..KYBER_K {
        poly_add(&mut r.vec[i], &a.vec[i]);
    }
}

pub fn polyvec_reduce(r: &mut Polyvec) {
    for i in 0..KYBER_K {
        poly_reduce(&mut r.vec[i]);
    }
}

pub fn polyvec_tobytes(r: &mut [u8], a: &Polyvec) {
    for i in 0..KYBER_K {
        poly_tobytes(&mut r[i * KYBER_POLYBYTES..], a.vec[i]);
    }
}