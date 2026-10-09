//! Serial-number arithmetic for 32-bit TCP sequence numbers (RFC 1982).

pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

pub fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

pub fn seq_gt(a: u32, b: u32) -> bool {
    seq_lt(b, a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraparound() {
        assert!(seq_lt(1, 2));
        assert!(seq_lt(u32::MAX - 5, 3));
        assert!(seq_gt(3, u32::MAX - 5));
        assert!(seq_le(7, 7));
        assert!(!seq_lt(7, 7));
    }
}
