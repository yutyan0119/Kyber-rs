use rand_core::*;

pub fn randombytes<R>(outbuf: &mut [u8], len: usize, rng: &mut R)
where
    R: RngCore + CryptoRng,
{
    rng.fill_bytes(&mut outbuf[..len]);
}
