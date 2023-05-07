pub mod sha3;
pub mod polynomial;
pub mod polynomial_vec;
pub mod random;
pub mod indcpa;
pub mod params;
pub mod cbd;
pub mod ntt;

pub use rand_core::{RngCore, CryptoRng};

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
