use crate::params::*;

pub const SHA_512_RATE: usize = 72; // 1600[f size bit] - (512*2)[capacity bit] = 576 = 72*8 [bit]
pub const SHA_256_RATE: usize = 136; // 1600[f size bit] - (256*2)[capacity bit] = 1088 = 136*8 [bit]
pub const SHAKE_128_RATE: usize = 168; // 1600[f size bit] - (128*2)[capacity bit] = 1344 = 168*8 [bit]
pub const SHAKE_256_RATE: usize = 136; // 1600[f size bit] - (256*2)[capacity bit] = 1088 = 136*8 [bit]

#[derive(Copy, Clone)]
pub struct KeccakState {
    pub state: [u64; 25],
    pub pos: usize,
}

impl KeccakState {
    pub fn new() -> Self {
        KeccakState {
            state: [0; 25],
            pos: 0,
        }
    }

    pub fn reset(&mut self) {
        self.state = [0; 25];
        self.pos = 0;
    }
}

pub fn sha3_512(out: &mut [u8; 64], input: &[u8], len: usize) {
    let mut state: [u64; 25] = [0; 25]; //state 1600 bits
    keccak_absorb_once(&mut state, SHA_512_RATE, input, len, 0x06);
    keccak_f1600(&mut state);
    for i in 0..64 {
        out[i] = (state[i / 8] >> (8 * (i % 8))) as u8;
    }
}

pub fn sha3_256(out: &mut [u8; 32], input: &[u8], len: usize) {
    let mut state: [u64; 25] = [0; 25]; //state 1600 bits
    keccak_absorb_once(&mut state, SHA_256_RATE, input, len, 0x06);
    keccak_f1600(&mut state);
    for i in 0..32 {
        out[i] = (state[i / 8] >> (8 * (i % 8))) as u8;
    }
}

pub fn kyber_shake128_absorb(state: &mut KeccakState, input: &[u8], x: u8, y: u8) {
    let mut seed: [u8; 34] = [0u8; 32 + 2];
    seed[..32].copy_from_slice(input);
    seed[32] = x;
    seed[33] = y;
    shake128_absorb_once(state, &seed, 34 as usize);
}

pub fn shake128_absorb_once(state: &mut KeccakState, input: &[u8], len: usize) {
    keccak_absorb_once(&mut state.state, SHAKE_128_RATE, input, len, 0x1F);
    state.pos = SHAKE_128_RATE;
}

pub fn kyber_shake128_squeezeblocks(output: &mut [u8], nblocks: usize, state: &mut KeccakState) {
    keccak_squeezeblocks(output, nblocks, &mut state.state, SHAKE_128_RATE);
}

pub fn kyber_shake256_prf(out: &mut [u8], outlen: usize, seed: &[u8], nonce: u8) {
    let mut input = [0u8; KYBER_SYMBYTES + 1];
    input[..KYBER_SYMBYTES].copy_from_slice(seed);
    input[KYBER_SYMBYTES] = nonce;
    shake256(out, outlen, &input, KYBER_SYMBYTES + 1);
}

fn shake256(out: &mut [u8], mut outlen: usize, input: &[u8], inlen: usize) {
    let mut state = KeccakState::new();
    let mut idx = 0;
    shake256_absorb_once(&mut state, input, inlen);
    let nblocks = outlen / SHAKE_256_RATE;
    shake256_sqeezeblocks(&mut out[idx..], nblocks, &mut state);
    outlen -= nblocks * SHAKE_256_RATE;
    idx += nblocks * SHAKE_256_RATE;
    shake256_squeeze(&mut out[idx..], outlen, &mut state);
}

fn shake256_absorb_once(state: &mut KeccakState, input: &[u8], len: usize) {
    keccak_absorb_once(&mut state.state, SHAKE_256_RATE, input, len, 0x1F);
    state.pos = SHAKE_256_RATE;
}

fn shake256_sqeezeblocks(output: &mut [u8], nblocks: usize, state: &mut KeccakState) {
    keccak_squeezeblocks(output, nblocks, &mut state.state, SHAKE_256_RATE);
}

fn shake256_squeeze(output: &mut [u8], outlen: usize, state: &mut KeccakState) {
    state.pos = keccak_squeeze(output, outlen, &mut state.state, state.pos, SHAKE_256_RATE);
}

pub fn keccak_squeezeblocks(output: &mut [u8], mut nblocks: usize, state: &mut [u64], rate: usize) {
    let mut idx: usize = 0;
    while nblocks > 0 {
        keccak_f1600(state);
        for i in 0..rate / 8 {
            output[idx..idx + 8].copy_from_slice(&state[i].to_le_bytes());
            idx += 8;
        }
        nblocks -= 1;
    }
}

fn keccak_squeeze(
    out: &mut [u8],
    mut outlen: usize,
    state: &mut [u64],
    mut pos: usize,
    rate: usize,
) -> usize {
    let mut idx = 0;
    while outlen > 0 {
        if pos == rate {
            keccak_f1600(state);
            pos = 0
        }
        let mut i = pos;
        while i < rate && i < pos + outlen {
            out[idx] = (state[i / 8] >> 8 * (i % 8)) as u8;
            i += 1;
            idx += 1;
        }
        outlen -= i - pos;
        pos = i;
    }
    pos
}

fn rotl64(x: u64, offset: usize) -> u64 {
    if offset == 0 {
        return x;
    }
    (x << offset) | (x >> (64 - offset))
}

pub fn keccak_absorb_once(state: &mut [u64], rate: usize, input: &[u8], mut len: usize, pad: u8) {
    //state initialization
    for i in state.iter_mut() {
        *i = 0;
    }

    let mut idx: usize = 0;
    //長いメッセージをrate bit = rate/8 byteずつ吸収する
    while len >= rate {
        //64bit = 8byteずつ吸収する
        for i in 0..rate / 8 {
            //inputをlittle endian 64bitとしてstateにxorする
            state[i] ^= u64::from_le_bytes(input[idx..idx + 8].try_into().unwrap());
            idx += 8;
        }
        len -= rate;
        //状態を更新する
        keccak_f1600(state);
    }
    //残ったメッセージを吸収する
    for i in 0..len {
        state[i / 8] ^= (input[idx + i] as u64) << (8 * (i % 8));
    }
    //先頭にpadをつける
    state[len / 8] ^= (pad as u64) << (8 * (len % 8));
    //最後のブロックに対してパディングを行う
    state[rate / 8 - 1] ^= 1u64 << 63;
}

fn keccak_f1600(state: &mut [u64]) {
    for round in 0..24 {
        theta(state);
        rho(state);
        pi(state);
        chi(state);
        iota(state, round);
    }
}

fn theta(state: &mut [u64]) {
    let mut c: [u64; 5] = [0; 5];
    let mut d: [u64; 5] = [0; 5];
    for x in 0..5 {
        c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for x in 0..5 {
        d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
    }
    for x in 0..5 {
        for y in 0..5 {
            state[x + 5 * y] ^= d[x];
        }
    }
}

const ROT: [[usize; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

fn rho(state: &mut [u64]) {
    let mut current: [u64; 25] = state.try_into().unwrap();
    for x in 0..5 {
        for y in 0..5 {
            current[x + 5 * y] = rotl64(state[x + 5 * y], ROT[x][y]);
        }
    }
    state.copy_from_slice(&current);
}

fn pi(state: &mut [u64]) {
    let mut current: [u64; 25] = state.try_into().unwrap();
    for x in 0..5 {
        for y in 0..5 {
            current[x + 5 * y] = state[(x + 3 * y) % 5 + 5 * x];
        }
    }
    state.copy_from_slice(&current);
}

fn chi(state: &mut [u64]) {
    let mut current: [u64; 25] = state.try_into().unwrap();
    for x in 0..5 {
        for y in 0..5 {
            current[x + 5 * y] =
                state[x + 5 * y] ^ ((!state[(x + 1) % 5 + 5 * y]) & state[(x + 2) % 5 + 5 * y]);
        }
    }
    state.copy_from_slice(&current);
}

const IOTA_CONSTANT: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

fn iota(state: &mut [u64], round: u32) {
    state[0] ^= IOTA_CONSTANT[round as usize];
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    #[test]
    fn test_sha3_512() {
        // input is sha3
        let mut input: [u8; 64] = [0 as u8; 64];
        input[0] = b's';
        input[1] = b'h';
        input[2] = b'a';
        input[3] = b'3';
        let mut output: [u8; 64] = [0; 64];
        sha3_512(&mut output, &input, 4);
        // print output as hex
        for i in 0..64 {
            print!("{:02x}", output[i]);
        }
    }
    #[test]
    fn test_sha3_512_2() {
        let input_str: &str =
            "sha3hogehogehogehogehogehogehogehogehogehogehogehogehogehogehogehogehogehoge";
        let input: &[u8] = input_str.as_bytes();
        let mut output: [u8; 64] = [0; 64];
        sha3_512(&mut output, input, input.len());
        // print output as hex
        for i in 0..64 {
            print!("{:02x}", output[i]);
        }
        let expected_str = "1b962e8304ad426490d78da4f2bcc91773e6c4f3f523ca58714d74d6b00c2776bf4b65e637ffebaa05b4007c97d19c563cbe07070ecccbd6efc928db33993bbe";
        let expected_bytes = hex::decode(expected_str).unwrap();
        assert_eq!(output, expected_bytes.as_slice());
    }

    #[test]
    fn test_sha3_256() {
        // input is sha3
        let mut input: [u8; 64] = [0 as u8; 64];
        input[0] = b's';
        input[1] = b'h';
        input[2] = b'a';
        input[3] = b'3';
        let mut output: [u8; 32] = [0; 32];
        sha3_256(&mut output, &input, 4);
        // print output as hex
        for i in 0..32 {
            print!("{:02x}", output[i]);
        }
        let expected_str = "6f8c90edbfe5c62f414208f03f62d3c4347774108ba5d6204733bc1fd5700015";
        let expected_bytes = hex::decode(expected_str).unwrap();
        assert_eq!(output, expected_bytes.as_slice());
    }
}
