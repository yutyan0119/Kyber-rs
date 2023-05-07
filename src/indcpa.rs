use crate::params::*;
use crate::polynomial::*;
use crate::polynomial_vec::*;
use crate::random::randombytes;
use crate::sha3::*;
use rand_core::{CryptoRng, RngCore};

fn rej_uniform(outbuf: &mut [i16], len: usize, buf: &[u8], buflen: usize) -> usize {
    let mut ctr: usize = 0;
    let mut pos: usize = 0;
    let mut val0: u16;
    let mut val1: u16;

    while ctr < len && pos + 3 <= buflen {
        val0 = buf[pos] as u16 | ((buf[pos + 1] as u16) << 8) & 0xFFF;
        val1 = (buf[pos + 2] >> 4) as u16 | ((buf[pos + 3] as u16) << 4) & 0xFFF;
        if val0 < KYBER_Q as u16 {
            outbuf[ctr] = val0 as i16;
            ctr += 1;
        }
        if val1 < KYBER_Q as u16 && ctr < len {
            outbuf[ctr] = val1 as i16;
            ctr += 1;
        }
        pos += 3;
    }
    ctr
}

fn gen_matrix(a: &mut [Polyvec], seed: &[u8], transposed: bool) {
    let mut state: KeccakState = KeccakState::new();
    const XOF_BLOCKBYTES: usize = SHAKE_128_RATE;
    const GEN_MATRIX_NBLOCKS: usize =
        (12 * KYBER_N / 8 * (1 << 12) / KYBER_Q as usize + XOF_BLOCKBYTES) / XOF_BLOCKBYTES;
    let mut buf = [0u8; GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES + 2]; //TODO:長さどうなってるか確認する
    let mut offset: usize;
    let mut buflen: usize;
    let mut ctr: usize;

    for i in 0..KYBER_K {
        for j in 0..KYBER_K {
            if transposed {
                kyber_shake128_absorb(&mut state, seed, i as u8, j as u8);
            } else {
                kyber_shake128_absorb(&mut state, seed, j as u8, i as u8);
            }
            kyber_shake128_squeezeblocks(&mut buf, GEN_MATRIX_NBLOCKS, &mut state); //XOF
            buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
            ctr = rej_uniform(&mut a[i].vec[j].coeffs, KYBER_N, &buf, buflen); //Parse

            while ctr < KYBER_N {
                offset = buflen % 3;
                for k in 0..offset {
                    buf[k] = buf[buflen - offset + k]; //ずらす
                }
                kyber_shake128_squeezeblocks(&mut buf[offset..], 1, &mut state); //XOF
                buflen = offset + XOF_BLOCKBYTES;
                ctr += rej_uniform(&mut a[i].vec[j].coeffs[ctr..], KYBER_N - ctr, &buf, buflen);
                //Parse
            }
        }
    }
}

pub fn indcpa_keypair<R>(
    pk: &mut [u8], //public key
    sk: &mut [u8], //secret key
    seed: Option<(&[u8], &[u8])>,
    rng: &mut R,
) where
    R: CryptoRng + RngCore,
{
    let mut a = [Polyvec::new(); KYBER_K]; //多項式ベクトル
    let mut e = Polyvec::new(); //errorベクトル
    let mut pkpv = Polyvec::new(); //公開鍵ベクトル
    let mut skpv = Polyvec::new(); //秘密鍵ベクトル
    let mut nonce = 0u8; //nonce N
    let mut seed_buf = [0u8; 2 * KYBER_SYMBYTES]; //2つのseedを入れておくバッファ
    let mut randbuf = [0u8; 2 * KYBER_SYMBYTES]; //seed生成に使う乱数バッファ

    if let Some(s) = seed {
        randbuf[..KYBER_SYMBYTES].copy_from_slice(&s.0);
    } else {
        randombytes(&mut randbuf, KYBER_SYMBYTES, rng); // d <= B^32
    }

    sha3_512(&mut seed_buf, &randbuf, KYBER_SYMBYTES); // (ρ, σ) <- G(d)
    let (pubseed, noiseseed) = seed_buf.split_at(KYBER_SYMBYTES); //ρ, σ

    gen_matrix(&mut a, pubseed, false); //A <- Parse(XOF(ρ, j , i))
                                        //s <- B_η
    for i in 0..KYBER_K {
        poly_getnoise_eta1(&mut skpv.vec[i], noiseseed, nonce); // s[i] <= CBD_η(PRF(ρ, N))
        nonce += 1;
    }
    for i in 0..KYBER_K {
        poly_getnoise_eta1(&mut e.vec[i], noiseseed, nonce); // e[i] <= CBD_η(PRF(ρ, N))
        nonce += 1;
    }

    polyvec_ntt(&mut skpv); // s <- NTT(s)
    polyvec_ntt(&mut e); // e <- NTT(e)

    for i in 0..KYBER_K {
        polyvec_mul_montgomery(&mut pkpv.vec[i], &skpv, &a[i]); // pk[i] <- (A[i] * s)
        poly_to_mont(&mut pkpv.vec[i]); // pk[i] <- A[i] * s
    }

    polyvec_add(&mut pkpv, &e); // pk <- pk + e = As + e
    polyvec_reduce(&mut pkpv); // pk <- As + e mod q

    pack_pk(pk, &pkpv, pubseed); // pk <- Encode(pk)
    pack_sk(sk, &skpv); // sk <- Encode(s)
}

fn pack_sk(sk: &mut [u8], skpv: &Polyvec) {
    polyvec_tobytes(sk, skpv);
}

fn pack_pk(pk: &mut [u8], pkpv: &Polyvec, seed: &[u8]) {
    const END: usize = KYBER_POLYVECBYTES + KYBER_SYMBYTES;
    polyvec_tobytes(pk, pkpv);
    pk[KYBER_POLYVECBYTES..END].copy_from_slice(&seed[..KYBER_SYMBYTES]);
}
