//! Explicit wire-word and byte ordering; no units or scaling are inferred.
use warpin_errors::protocol::{Kind, Phase, ProtocolError, Result};
#[derive(Clone, Copy, Debug)]
pub enum Order {
    Big,
    Little,
}
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    /// Order of the 16-bit registers in the composite value.
    pub words: Order,
    /// Byte order within each register of the composite value.
    pub bytes: Order,
}
impl Layout {
    fn ordered<const N: usize>(&self, registers: &[u16]) -> Result<[u8; N]> {
        if registers.len() != N / 2 {
            return Err(ProtocolError::new(Kind::Protocol, Phase::Decode));
        }
        let mut out = [0; N];
        for i in 0..registers.len() {
            let index = match self.words {
                Order::Big => i,
                Order::Little => registers.len() - 1 - i,
            };
            let bytes = match self.bytes {
                Order::Big => registers[index].to_be_bytes(),
                Order::Little => registers[index].to_le_bytes(),
            };
            out[i * 2..i * 2 + 2].copy_from_slice(&bytes);
        }
        Ok(out)
    }
    /// Decodes exactly two registers using both explicit ordering rules.
    pub fn u32(&self, r: &[u16]) -> Result<u32> {
        Ok(u32::from_be_bytes(self.ordered(r)?))
    }
    /// Decodes exactly two registers as a signed two-complement integer.
    pub fn i32(&self, r: &[u16]) -> Result<i32> {
        Ok(i32::from_be_bytes(self.ordered(r)?))
    }
    /// Decodes exactly two registers as IEEE 754 bits, preserving NaN and infinity.
    pub fn f32(&self, r: &[u16]) -> Result<f32> {
        Ok(f32::from_bits(self.u32(r)?))
    }
    /// Decodes exactly four registers using both explicit ordering rules.
    pub fn u64(&self, r: &[u16]) -> Result<u64> {
        Ok(u64::from_be_bytes(self.ordered(r)?))
    }
    /// Decodes exactly four registers as a signed two-complement integer.
    pub fn i64(&self, r: &[u16]) -> Result<i64> {
        Ok(i64::from_be_bytes(self.ordered(r)?))
    }
    /// Decodes exactly four registers as IEEE 754 bits, preserving NaN and infinity.
    pub fn f64(&self, r: &[u16]) -> Result<f64> {
        Ok(f64::from_bits(self.u64(r)?))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn order_and_invalid() {
        for (words, bytes, r) in [
            (Order::Big, Order::Big, [0x1234, 0x5678]),
            (Order::Little, Order::Big, [0x5678, 0x1234]),
            (Order::Big, Order::Little, [0x3412, 0x7856]),
            (Order::Little, Order::Little, [0x7856, 0x3412]),
        ] {
            let l = Layout { words, bytes };
            assert_eq!(l.u32(&r).expect("decode"), 0x12345678);
            assert!(l.u32(&[1]).is_err());
        }
        assert!(
            Layout {
                words: Order::Big,
                bytes: Order::Big
            }
            .f32(&[0x7fc0, 0])
            .expect("NaN")
            .is_nan()
        );
    }
}
