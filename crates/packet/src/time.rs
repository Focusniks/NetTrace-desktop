use std::fmt;

/// Capture timestamp with nanosecond resolution, relative to the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp {
    nanos: i64,
}

impl Timestamp {
    pub const ZERO: Timestamp = Timestamp { nanos: 0 };

    pub fn from_nanos(nanos: i64) -> Self {
        Self { nanos }
    }

    pub fn from_parts(secs: i64, nanos: u32) -> Self {
        Self { nanos: secs.saturating_mul(1_000_000_000).saturating_add(i64::from(nanos)) }
    }

    /// Builds a timestamp from a raw 64-bit tick count and a resolution of
    /// `ticks_per_sec` (pcapng `if_tsresol`). Saturates instead of overflowing.
    pub fn from_ticks(ticks: u64, ticks_per_sec: u64) -> Self {
        if ticks_per_sec == 0 {
            return Self::ZERO;
        }
        let secs = ticks / ticks_per_sec;
        let frac = ticks % ticks_per_sec;
        // frac < ticks_per_sec, so frac * 1e9 / tps < 1e9; use u128 to avoid overflow.
        let nanos = (u128::from(frac) * 1_000_000_000 / u128::from(ticks_per_sec)) as i64;
        let secs = i64::try_from(secs).unwrap_or(i64::MAX / 1_000_000_000);
        Self { nanos: secs.saturating_mul(1_000_000_000).saturating_add(nanos) }
    }

    pub fn nanos(self) -> i64 {
        self.nanos
    }

    pub fn secs(self) -> i64 {
        self.nanos.div_euclid(1_000_000_000)
    }

    pub fn subsec_nanos(self) -> u32 {
        self.nanos.rem_euclid(1_000_000_000) as u32
    }

    pub fn saturating_sub(self, other: Timestamp) -> i64 {
        self.nanos.saturating_sub(other.nanos)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:09}", self.secs(), self.subsec_nanos())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parts_and_display() {
        let t = Timestamp::from_parts(1_700_000_000, 123_456_789);
        assert_eq!(t.secs(), 1_700_000_000);
        assert_eq!(t.subsec_nanos(), 123_456_789);
        assert_eq!(t.to_string(), "1700000000.123456789");
    }

    #[test]
    fn ticks_resolution() {
        assert_eq!(Timestamp::from_ticks(1_500_000, 1_000_000), Timestamp::from_parts(1, 500_000_000));
        assert_eq!(Timestamp::from_ticks(3, 2), Timestamp::from_parts(1, 500_000_000));
        assert_eq!(Timestamp::from_ticks(5, 0), Timestamp::ZERO);
        // Must not panic for absurd values.
        let _ = Timestamp::from_ticks(u64::MAX, 1);
        let _ = Timestamp::from_ticks(u64::MAX, u64::MAX);
    }

    #[test]
    fn negative_timestamps() {
        let t = Timestamp::from_nanos(-1);
        assert_eq!(t.secs(), -1);
        assert_eq!(t.subsec_nanos(), 999_999_999);
    }
}
