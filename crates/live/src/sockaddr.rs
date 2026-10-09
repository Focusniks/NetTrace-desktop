//! Decoding of `struct sockaddr` bytes returned by `pcap_findalldevs`.
//! Pure functions over byte slices so they can be unit-tested.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Platform constants for address families.
#[derive(Debug, Clone, Copy)]
pub struct Families {
    pub inet: u16,
    pub inet6: u16,
    /// BSD-style `sockaddr` starts with a length byte (`sa_len`).
    pub has_len_byte: bool,
}

pub const fn platform() -> Families {
    if cfg!(windows) {
        Families { inet: 2, inet6: 23, has_len_byte: false }
    } else if cfg!(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")) {
        Families { inet: 2, inet6: if cfg!(target_os = "macos") || cfg!(target_os = "ios") { 30 } else { 28 }, has_len_byte: true }
    } else {
        Families { inet: 2, inet6: 10, has_len_byte: false }
    }
}

/// Formats an IPv4/IPv6 socket address; other families yield `None`.
/// `raw` must contain at least the bytes of `sockaddr_in6` (28) when available.
pub fn format(raw: &[u8], fam: Families) -> Option<String> {
    let family = if fam.has_len_byte {
        u16::from(*raw.get(1)?)
    } else {
        u16::from_ne_bytes([*raw.first()?, *raw.get(1)?])
    };
    if family == fam.inet {
        let b = raw.get(4..8)?;
        Some(Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string())
    } else if family == fam.inet6 {
        let b: [u8; 16] = raw.get(8..24)?.try_into().ok()?;
        Some(Ipv6Addr::from(b).to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIN: Families = Families { inet: 2, inet6: 23, has_len_byte: false };
    const BSD: Families = Families { inet: 2, inet6: 30, has_len_byte: true };

    #[test]
    fn ipv4_and_ipv6() {
        let mut v4 = vec![0u8; 16];
        v4[..2].copy_from_slice(&2u16.to_ne_bytes());
        v4[4..8].copy_from_slice(&[192, 168, 1, 10]);
        assert_eq!(format(&v4, WIN).as_deref(), Some("192.168.1.10"));

        let mut v6 = vec![0u8; 28];
        v6[..2].copy_from_slice(&23u16.to_ne_bytes());
        v6[8] = 0xfe;
        v6[9] = 0x80;
        v6[23] = 1;
        assert_eq!(format(&v6, WIN).as_deref(), Some("fe80::1"));
    }

    #[test]
    fn bsd_layout_and_unknown_family() {
        let mut v4 = vec![0u8; 16];
        v4[0] = 16;
        v4[1] = 2;
        v4[4..8].copy_from_slice(&[10, 0, 0, 1]);
        assert_eq!(format(&v4, BSD).as_deref(), Some("10.0.0.1"));
        let mut other = vec![0u8; 16];
        other[..2].copy_from_slice(&17u16.to_ne_bytes());
        assert_eq!(format(&other, WIN), None);
        assert_eq!(format(&[2], WIN), None);
    }
}
