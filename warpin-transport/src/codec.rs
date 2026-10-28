//! Incremental framing. A codec returns the complete wire frame length.
use warpin_errors::protocol::{Kind, Phase, ProtocolError, Result};
/// Implementations must not consume input; partial bytes remain owned by the connection.
pub trait FrameDecoder: Send {
    fn frame_len(&mut self, buffered: &[u8], maximum: usize) -> Result<Option<usize>>;
}
/// Fixed wire frame length.
pub struct Fixed(pub usize);
impl FrameDecoder for Fixed {
    fn frame_len(&mut self, b: &[u8], m: usize) -> Result<Option<usize>> {
        if self.0 == 0 || self.0 > m {
            return Err(ProtocolError::new(Kind::Configuration, Phase::Decode));
        }
        Ok((b.len() >= self.0).then_some(self.0))
    }
}
/// A one-byte delimiter included in the returned frame.
pub struct Delimited(pub u8);
impl FrameDecoder for Delimited {
    fn frame_len(&mut self, b: &[u8], _: usize) -> Result<Option<usize>> {
        Ok(b.iter().position(|x| *x == self.0).map(|i| i + 1))
    }
}
#[derive(Clone, Copy, Debug)]
pub enum Endian {
    Big,
    Little,
}
/// Configurable unsigned length field. Frames include the header.
pub struct LengthPrefixed {
    /// Zero-based byte offset of the length field within the header.
    pub offset: usize,
    /// Unsigned length field width: exactly 1, 2, 4 or 8 bytes.
    pub width: usize,
    /// Complete wire-header size, including the length field.
    pub header_bytes: usize,
    /// Byte order used to interpret the unsigned length field.
    pub endian: Endian,
    /// Whether the declared length already includes all header bytes.
    pub includes_header: bool,
}
impl FrameDecoder for LengthPrefixed {
    fn frame_len(&mut self, b: &[u8], m: usize) -> Result<Option<usize>> {
        let invalid = || ProtocolError::new(Kind::Configuration, Phase::Decode);
        if !matches!(self.width, 1 | 2 | 4 | 8)
            || self.header_bytes == 0
            || self.header_bytes > m
            || self
                .offset
                .checked_add(self.width)
                .is_none_or(|v| v > self.header_bytes)
        {
            return Err(invalid());
        }
        if b.len() < self.header_bytes {
            return Ok(None);
        }
        let bytes = &b[self.offset..self.offset + self.width];
        let n = match self.endian {
            Endian::Big => bytes.iter().fold(0u64, |a, v| (a << 8) | u64::from(*v)),
            Endian::Little => bytes
                .iter()
                .rev()
                .fold(0u64, |a, v| (a << 8) | u64::from(*v)),
        };
        let n =
            usize::try_from(n).map_err(|_| ProtocolError::new(Kind::Capacity, Phase::Decode))?;
        let n = if self.includes_header {
            n
        } else {
            n.checked_add(self.header_bytes)
                .ok_or(ProtocolError::new(Kind::Capacity, Phase::Decode))?
        };
        if n < self.header_bytes {
            return Err(ProtocolError::new(Kind::Protocol, Phase::Decode));
        }
        if n > m {
            return Err(ProtocolError::new(Kind::Capacity, Phase::Decode));
        }
        Ok((b.len() >= n).then_some(n))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_and_invalid_lengths() {
        let mut c = LengthPrefixed {
            offset: 1,
            width: 2,
            header_bytes: 3,
            endian: Endian::Big,
            includes_header: false,
        };
        assert_eq!(c.frame_len(&[9, 0], 10).unwrap(), None);
        assert_eq!(c.frame_len(&[9, 0, 2, 1, 2, 8], 10).unwrap(), Some(5));
        assert_eq!(
            c.frame_len(&[9, 0, 20], 10).unwrap_err().kind,
            Kind::Capacity
        );
        c.includes_header = true;
        assert_eq!(
            c.frame_len(&[9, 0, 1], 10).unwrap_err().kind,
            Kind::Protocol
        );
    }
}
