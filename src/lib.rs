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
    use rand;

    #[test]
    fn test_keygen(){
        let mut rng = rand::thread_rng();
        let mut pk = [0u8; params::KYBER_PUBLICKEYBYTES];
        let mut sk = [0u8; params::KYBER_SECRETKEYBYTES];

        indcpa::indcpa_keypair(&mut pk, &mut sk, None, &mut rng);
        println!("pk: {:?}", pk);
        println!("sk: {:?}", sk);
    }
}
