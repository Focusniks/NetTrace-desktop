//! Formatting helpers for field display strings.

use std::fmt::Write;

/// `a1b2c3…` preview of at most `max` bytes.
pub fn hex_preview(data: &[u8], max: usize) -> String {
    let mut s = String::with_capacity(data.len().min(max) * 2 + 1);
    for b in data.iter().take(max) {
        let _ = write!(s, "{b:02x}");
    }
    if data.len() > max {
        s.push('…');
    }
    s
}

/// Escapes non-printable characters so packet content can never inject
/// control sequences into the UI.
pub fn printable(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len());
    for &b in data {
        match b {
            b'\\' => s.push_str("\\\\"),
            0x20..=0x7e => s.push(b as char),
            b'\r' => s.push_str("\\r"),
            b'\n' => s.push_str("\\n"),
            b'\t' => s.push_str("\\t"),
            _ => {
                let _ = write!(s, "\\x{b:02x}");
            }
        }
    }
    s
}

/// Lossy UTF-8 with control characters escaped.
pub fn text(data: &[u8]) -> String {
    let lossy = String::from_utf8_lossy(data);
    let mut s = String::with_capacity(lossy.len());
    for c in lossy.chars() {
        if c.is_control() {
            let _ = write!(s, "\\x{:02x}", c as u32 & 0xff);
        } else {
            s.push(c);
        }
    }
    s
}

/// Bit mask display, e.g. `.... ..1. ` for bit 1 of a byte.
pub fn bits(value: u64, mask: u64, width_bits: u32) -> String {
    let mut s = String::with_capacity(width_bits as usize + width_bits as usize / 4);
    for i in (0..width_bits).rev() {
        let bit = 1u64 << i;
        if mask & bit != 0 {
            s.push(if value & bit != 0 { '1' } else { '0' });
        } else {
            s.push('.');
        }
        if i % 4 == 0 && i != 0 {
            s.push(' ');
        }
    }
    s
}

/// Days since 1970-01-01 → (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `YYYY-MM-DD hh:mm:ss.nnnnnnnnn UTC`
pub fn utc(secs: i64, nanos: u32) -> String {
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{nanos:09} UTC",
        tod / 3600,
        (tod / 60) % 60,
        tod % 60
    )
}

/// Seconds with nanosecond precision: `0.038123456 seconds`.
pub fn seconds(nanos: i64) -> String {
    let sign = if nanos < 0 { "-" } else { "" };
    let n = nanos.unsigned_abs();
    format!("{sign}{}.{:09} seconds", n / 1_000_000_000, n % 1_000_000_000)
}

pub fn plural_bytes(n: usize) -> String {
    if n == 1 { "1 byte".to_owned() } else { format!("{n} bytes") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_strings() {
        assert_eq!(bits(0x02, 0x02, 8), ".... ..1.");
        assert_eq!(bits(0x00, 0x02, 8), ".... ..0.");
        assert_eq!(bits(0x4000, 0x4000, 16), ".1.. .... .... ....");
        assert_eq!(bits(0b101, 0b111, 8), ".... .101");
    }

    #[test]
    fn utc_dates() {
        assert_eq!(utc(0, 0), "1970-01-01 00:00:00.000000000 UTC");
        assert_eq!(utc(1_700_000_000, 5), "2023-11-14 22:13:20.000000005 UTC");
        assert_eq!(utc(951_782_400, 0), "2000-02-29 00:00:00.000000000 UTC");
        assert_eq!(utc(-1, 0), "1969-12-31 23:59:59.000000000 UTC");
    }

    #[test]
    fn escaping() {
        assert_eq!(printable(b"GET /\r\n\x00\x1b["), "GET /\\r\\n\\x00\\x1b[");
        assert_eq!(text("héllo\u{7}".as_bytes()), "héllo\\x07");
        assert_eq!(hex_preview(&[1, 2, 3], 2), "0102…");
    }

    #[test]
    fn seconds_format() {
        assert_eq!(seconds(38_000_000), "0.038000000 seconds");
        assert_eq!(seconds(-1_500_000_000), "-1.500000000 seconds");
    }
}
