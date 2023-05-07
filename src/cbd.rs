use crate::polynomial::Poly;
use crate::params::KYBER_N;

fn load32_littleendian(x: &[u8]) -> u32 
{
  let mut r = x[0] as u32;
  r |= (x[1] as u32) << 8;
  r |= (x[2] as u32) << 16;
  r |= (x[3] as u32) << 24;
  r
}

fn load24_littleendian(x: &[u8]) -> u32 
{
  let mut r = x[0] as u32;
  r |= (x[1] as u32) << 8;
  r |= (x[2] as u32) << 16;
  r
}

pub fn cbd3(out: &mut Poly, buf: &[u8])
{
  let (mut d, mut t, mut a, mut b); 
  for i in 0..(KYBER_N/4) {
    t = load24_littleendian(&buf[3*i..]);
    d  = t & 0x00249249;
    d += (t>>1) & 0x00249249;
    d += (t>>2) & 0x00249249;
    for j in 0..4 {
      a = ((d >>  (6*j))  & 0x7) as i16;
      b = ((d >> (6*j+3)) & 0x7) as i16;
      out.coeffs[4*i+j] = a - b;
    }
  }
}

pub fn cbd2(out: &mut Poly, buf: &[u8])
{
  let (mut d, mut t, mut a, mut b); 
  for i in 0..(KYBER_N/8) {
    t = load32_littleendian(&buf[4*i..]);
    // t = u32::from_le_bytes(buf[4*i..4*i+4].try_into().unwrap());でも可能
    d = t & 0x55555555;
    d += (t>>1) & 0x55555555;
    for j in 0..8 {
      a = ((d >>  (4*j))  & 0x3) as i16;
      b = ((d >> (4*j+2)) & 0x3) as i16;
      out.coeffs[8*i+j] = a - b;
    }
  }
}

pub fn poly_cbd_eta1(out: &mut Poly, buf: &[u8]){
    if cfg!(feature="kyber512") {
        cbd3(out, buf)
      } 
      else {
        cbd2(out, buf)
      }
}

pub fn poly_cbd_eta2(out: &mut Poly, buf: &[u8]){
    cbd2(out, buf)
}
