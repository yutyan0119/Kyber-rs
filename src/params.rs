pub const KYBER_Q: usize = 3329; //多項式環の係数の最大値
pub const KYBER_N: usize = 256; //分母の次数
pub const QINV: i32 = 62209; //q^-1 mod 2^16

pub const KYBER_ETA1: usize = if cfg!(feature = "kyber512") {
    3
} else {2};

pub const KYBER_ETA2: usize = 2;

pub const KYBER_K: usize = if cfg!(feature = "kyber512") {
    2
} else if cfg!(feature = "kyber1024") {
    4
} else {
    3
};

pub const KYBER_SYMBYTES: usize = 32; //seedのバイト数
pub const KYBER_POLYBYTES: usize = 384; //多項式のバイト数 256*3/2
pub const KYBER_POLYVECBYTES: usize = KYBER_K * KYBER_POLYBYTES;

pub const KYBER_PUBLICKEYBYTES : usize = KYBER_POLYVECBYTES + KYBER_SYMBYTES;
pub const KYBER_SECRETKEYBYTES : usize = 2 * KYBER_SYMBYTES + KYBER_PUBLICKEYBYTES + KYBER_POLYVECBYTES;