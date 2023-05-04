use crate::params::*;

fn rej_uniform(outbuf: &mut [i16], len: usize, buf: &[u8], buflen: usize) -> usize {
    let mut ctr: usize = 0;
    let mut pos: usize = 0;
    let mut val0: u32 = 0;
    let mut val1: u32 = 0;
    
    while ctr < len && pos + 3 <= buflen {
        val0 = buf[pos] as u16 | ((buf[pos + 1] as u16) << 8) & 0xFFF;
        val1 = (buf[pos + 2] >> 4) as u16 | ((buf[pos + 3] as u16) << 4) & 0xFFF;
        if val0 < KYBER_Q as u16 {
            outbuf[ctr] = val0 as i16;
            ctr += 1;
        }
        if val1 < KYBER_Q && ctr < len {
            outbuf[ctr] = val1 as i16;
            ctr += 1;
        }
        pos += 3;
    }
    ctr
}
