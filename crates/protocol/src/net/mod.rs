pub mod icmp;
pub mod icmpv6;
pub mod ipv4;
pub mod ipv6;

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::names;

/// One-line description of the datagram embedded in an ICMP error.
pub(crate) fn describe_embedded(data: &[u8]) -> Option<String> {
    let version = data.first()? >> 4;
    let (src, dst, proto, rest) = match version {
        4 => {
            let ihl = usize::from(data[0] & 0x0f) * 4;
            if ihl < 20 || data.len() < 20 {
                return None;
            }
            let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]).to_string();
            let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]).to_string();
            (src, dst, data[9], data.get(ihl..).unwrap_or(&[]))
        }
        6 => {
            if data.len() < 40 {
                return None;
            }
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s.copy_from_slice(&data[8..24]);
            d.copy_from_slice(&data[24..40]);
            (Ipv6Addr::from(s).to_string(), Ipv6Addr::from(d).to_string(), data[6], &data[40..])
        }
        _ => return None,
    };
    let mut out = format!("{src} → {dst} ({})", names::ip_proto(proto));
    if matches!(proto, 6 | 17) && rest.len() >= 4 {
        let sp = u16::from_be_bytes([rest[0], rest[1]]);
        let dp = u16::from_be_bytes([rest[2], rest[3]]);
        out.push_str(&format!(", ports {sp} → {dp}"));
    }
    Some(out)
}
