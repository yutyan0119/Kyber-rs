use crate::params::*;

//モンゴメリ領域におけるzeta
//ZETAS[i] = 17^(reverse i)*R mod q ここで R = 2^16
//reverse i はiのビットを逆順にしたもの
pub const ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246,
    778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097,
    603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
    -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

pub fn ntt(coeffs: &mut [i16; 256]) {
    let mut j;
    let mut k = 1;
    let mut len = 128;
    let mut t;
    let mut zeta;
    while len > 2 {
        let mut start = 0;
        while start < 256 {
            zeta = ZETAS[k];
            k += 1;
            j = start;
            while j < start + len {
                t = montgomery_half_mul(zeta, coeffs[j + len]);
                coeffs[j + len] = coeffs[j] - t;
                coeffs[j] = coeffs[j] + t;
                j += 1;
            }
            start += j + len;
        }
        len >>= 1;
    }
}

//掛け算してから、モンゴメリーreductionで元に戻す
//注意：この関数は、aかbがモンゴメリ領域にあることを仮定している
pub fn montgomery_half_mul(a: i16, b: i16) -> i16 {
    montgomery_reduce(a as i32 * b as i32)
}

//a*b*R^-1 mod qが入る
pub fn basemul(r: &mut [i16], a: &[i16], b: &[i16], zeta: i16) {
    r[0] = montgomery_half_mul(a[1], b[1]);
    r[0] = montgomery_half_mul(r[0], zeta);
    r[0] += montgomery_half_mul(a[0], b[0]);
    r[1] = montgomery_half_mul(a[0], b[1]);
    r[1] += montgomery_half_mul(a[1], b[0]);
}

pub fn montgomery_reduce(a: i32) -> i16 {
    let u: i16 = a.wrapping_mul(QINV) as i16; //val * QINV mod 2^16
    let mut t: i32 = u as i32 * KYBER_Q as i32; // (val*QINV)mod 2^16 * Q
    t = a - t; //val - (val*QINV)mod 2^16 * Q
    t >>= 16; //(val - (val*QINV)mod 2^16 * Q) / 2^16
    t as i16
}
