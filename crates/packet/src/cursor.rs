use std::fmt;

/// Error returned when a read would go past the end of the buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncated {
    /// Absolute offset (in the frame) at which the read was attempted.
    pub offset: usize,
    /// Number of bytes that were requested.
    pub wanted: usize,
}

impl fmt::Display for Truncated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "truncated: wanted {} bytes at offset {}", self.wanted, self.offset)
    }
}

impl std::error::Error for Truncated {}

/// Bounds-checked big/little-endian reader over a byte slice.
///
/// `base` is the absolute offset of `data[0]` inside the frame, so every
/// position reported by the cursor can be used directly for hex highlighting.
#[derive(Debug, Clone)]
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
    base: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0, base: 0 }
    }

    pub fn with_base(data: &'a [u8], base: usize) -> Self {
        Self { data, pos: 0, base }
    }

    /// Absolute offset of the next byte to be read.
    pub fn offset(&self) -> usize {
        self.base + self.pos
    }

    /// Position relative to the start of this cursor.
    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn base(&self) -> usize {
        self.base
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn rest(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or(&[])
    }

    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    fn err(&self, wanted: usize) -> Truncated {
        Truncated { offset: self.offset(), wanted }
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Truncated> {
        let end = self.pos.checked_add(n).ok_or_else(|| self.err(n))?;
        let slice = self.data.get(self.pos..end).ok_or_else(|| self.err(n))?;
        self.pos = end;
        Ok(slice)
    }

    pub fn skip(&mut self, n: usize) -> Result<(), Truncated> {
        self.take(n).map(|_| ())
    }

    pub fn peek(&self, n: usize) -> Result<&'a [u8], Truncated> {
        let end = self.pos.checked_add(n).ok_or_else(|| self.err(n))?;
        self.data.get(self.pos..end).ok_or_else(|| self.err(n))
    }

    /// Splits off a sub-cursor of `n` bytes and advances past it.
    pub fn sub(&mut self, n: usize) -> Result<Cursor<'a>, Truncated> {
        let base = self.offset();
        let data = self.take(n)?;
        Ok(Cursor::with_base(data, base))
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Truncated> {
        let slice = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8, Truncated> {
        Ok(self.array::<1>()?[0])
    }

    pub fn be_u16(&mut self) -> Result<u16, Truncated> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub fn be_u24(&mut self) -> Result<u32, Truncated> {
        let b = self.array::<3>()?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    pub fn be_u32(&mut self) -> Result<u32, Truncated> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub fn be_u64(&mut self) -> Result<u64, Truncated> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub fn le_u16(&mut self) -> Result<u16, Truncated> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub fn le_u32(&mut self) -> Result<u32, Truncated> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn le_u64(&mut self) -> Result<u64, Truncated> {
        Ok(u64::from_le_bytes(self.array()?))
    }
}

/// Reads a big-endian u16 at `at` without a cursor.
pub fn be_u16_at(data: &[u8], at: usize) -> Option<u16> {
    let b = data.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_big_and_little_endian() {
        let data = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc];
        let mut c = Cursor::new(&data);
        assert_eq!(c.be_u16().unwrap(), 0x1234);
        assert_eq!(c.le_u16().unwrap(), 0x7856);
        assert_eq!(c.remaining(), 2);
        assert_eq!(c.u8().unwrap(), 0x9a);
    }

    #[test]
    fn truncated_read_reports_offset_and_does_not_advance() {
        let data = [1, 2, 3];
        let mut c = Cursor::with_base(&data, 100);
        c.u8().unwrap();
        let err = c.be_u32().unwrap_err();
        assert_eq!(err, Truncated { offset: 101, wanted: 4 });
        assert_eq!(c.position(), 1);
        assert_eq!(c.be_u16().unwrap(), 0x0203);
    }

    #[test]
    fn huge_take_does_not_overflow() {
        let data = [0u8; 4];
        let mut c = Cursor::new(&data);
        c.skip(2).unwrap();
        assert!(c.take(usize::MAX).is_err());
        assert!(c.peek(usize::MAX).is_err());
    }

    #[test]
    fn sub_cursor_keeps_absolute_offsets() {
        let data = [0u8, 1, 2, 3, 4, 5];
        let mut c = Cursor::with_base(&data, 10);
        c.skip(2).unwrap();
        let mut s = c.sub(3).unwrap();
        assert_eq!(s.offset(), 12);
        assert_eq!(s.u8().unwrap(), 2);
        assert_eq!(s.offset(), 13);
        assert_eq!(c.offset(), 15);
        assert!(s.take(3).is_err());
    }

    #[test]
    fn be_u16_at_bounds() {
        assert_eq!(be_u16_at(&[1, 2, 3], 1), Some(0x0203));
        assert_eq!(be_u16_at(&[1, 2, 3], 2), None);
        assert_eq!(be_u16_at(&[1, 2, 3], usize::MAX), None);
    }
}
