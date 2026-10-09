use nettrace_model::{FieldValue, ProtocolId};
use nettrace_packet::Address;

use crate::context::{m, Ctx, Malformed};
use crate::fields as f;
use crate::format::bits;
use crate::names;
use crate::registry::{Dissector, Handoff, Layer};

pub struct Ipv4;
pub static IPV4: Ipv4 = Ipv4;

const P: ProtocolId = ProtocolId::Ipv4;

/// RFC 1071 internet checksum over `data`.
pub(crate) fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn dscp_name(d: u8) -> &'static str {
    match d {
        0 => "CS0",
        8 => "CS1",
        10 => "AF11",
        16 => "CS2",
        18 => "AF21",
        24 => "CS3",
        26 => "AF31",
        32 => "CS4",
        34 => "AF41",
        40 => "CS5",
        46 => "EF",
        48 => "CS6",
        56 => "CS7",
        _ => "Unknown",
    }
}

fn ecn_name(e: u8) -> &'static str {
    match e {
        0 => "Not-ECT",
        1 => "ECT(1)",
        2 => "ECT(0)",
        _ => "CE",
    }
}

impl Dissector for Ipv4 {
    fn protocol(&self) -> ProtocolId {
        P
    }

    fn dissect(&self, ctx: &mut Ctx, layer: Layer) -> Result<Handoff, Malformed> {
        let mut c = layer.cursor();
        let start = c.offset();
        let vihl = c.u8().map_err(m(P))?;
        let version = vihl >> 4;
        let ihl = usize::from(vihl & 0x0f) * 4;
        if version != 4 || ihl < 20 {
            return Err(Malformed::at(P, start));
        }
        let ds = c.u8().map_err(m(P))?;
        let total_len = c.be_u16().map_err(m(P))?;
        let id = c.be_u16().map_err(m(P))?;
        let flags_frag = c.be_u16().map_err(m(P))?;
        let ttl = c.u8().map_err(m(P))?;
        let proto = c.u8().map_err(m(P))?;
        let checksum = c.be_u16().map_err(m(P))?;
        let src = c.array::<4>().map_err(m(P))?;
        let dst = c.array::<4>().map_err(m(P))?;
        let options = c.take(ihl - 20).map_err(m(P))?;

        ctx.summary.net_src = Address::V4(src);
        ctx.summary.net_dst = Address::V4(dst);
        ctx.summary.hop_limit = Some(ttl);
        if total_len != 0 && usize::from(total_len) >= ihl {
            ctx.summary.ip_end = Some(start + usize::from(total_len));
        }

        // total_len == 0 happens with TSO captures: use what was captured.
        let end = if total_len == 0 {
            layer.end
        } else if usize::from(total_len) < ihl {
            return Err(Malformed::at(P, start + 2));
        } else {
            (start + usize::from(total_len)).min(layer.end)
        };
        let mf = flags_frag & 0x2000 != 0;
        let frag_offset = (flags_frag & 0x1fff) * 8;

        let t = &mut ctx.tree;
        if t.enabled() {
            let header = layer.frame.get(start..start + ihl).unwrap_or(&[]);
            let correct = internet_checksum(header) == 0;
            t.open(&f::IP, start, ihl);
            t.heading(|| {
                format!(
                    "Internet Protocol Version 4, Src: {}, Dst: {}",
                    Address::V4(src),
                    Address::V4(dst)
                )
            });
            t.add(&f::IP_VERSION, start, 1, FieldValue::U64(4), || format!("{} = Version: 4", bits(u64::from(vihl), 0xf0, 8)));
            t.add(&f::IP_HDR_LEN, start, 1, FieldValue::U64(ihl as u64), || {
                format!("{} = Header Length: {ihl} bytes ({})", bits(u64::from(vihl), 0x0f, 8), ihl / 4)
            });
            let (dscp, ecn) = (ds >> 2, ds & 0x03);
            t.open_value(&f::IP_DSFIELD, start + 1, 1, FieldValue::U64(u64::from(ds)), || {
                format!("0x{ds:02x} (DSCP: {}, ECN: {})", dscp_name(dscp), ecn_name(ecn))
            });
            t.add(&f::IP_DSCP, start + 1, 1, FieldValue::U64(u64::from(dscp)), || {
                format!("{} = {} ({dscp})", bits(u64::from(ds), 0xfc, 8), dscp_name(dscp))
            });
            t.add(&f::IP_ECN, start + 1, 1, FieldValue::U64(u64::from(ecn)), || {
                format!("{} = {} ({ecn})", bits(u64::from(ds), 0x03, 8), ecn_name(ecn))
            });
            t.close();
            t.uint(&f::IP_LEN, start + 2, 2, u64::from(total_len));
            t.add(&f::IP_ID, start + 4, 2, FieldValue::U64(u64::from(id)), || format!("0x{id:04x} ({id})"));
            let ff = u64::from(flags_frag);
            let flags = flags_frag >> 13;
            t.open_value(&f::IP_FLAGS, start + 6, 1, FieldValue::U64(u64::from(flags)), || {
                let mut names = Vec::new();
                if flags & 0x2 != 0 {
                    names.push("Don't fragment");
                }
                if flags & 0x1 != 0 {
                    names.push("More fragments");
                }
                if names.is_empty() { format!("0x{flags:x}") } else { format!("0x{flags:x}, {}", names.join(", ")) }
            });
            t.flag(&f::IP_FLAGS_RB, start + 6, 1, flags_frag & 0x8000 != 0, || format!("{} Reserved bit", bits(ff >> 8, 0x80, 8)));
            t.flag(&f::IP_FLAGS_DF, start + 6, 1, flags_frag & 0x4000 != 0, || format!("{} Don't fragment", bits(ff >> 8, 0x40, 8)));
            t.flag(&f::IP_FLAGS_MF, start + 6, 1, mf, || format!("{} More fragments", bits(ff >> 8, 0x20, 8)));
            t.close();
            t.uint(&f::IP_FRAG_OFFSET, start + 6, 2, u64::from(frag_offset));
            t.uint(&f::IP_TTL, start + 8, 1, u64::from(ttl));
            t.named(&f::IP_PROTO, start + 9, 1, u64::from(proto), names::ip_proto(proto));
            t.add(&f::IP_CHECKSUM, start + 10, 2, FieldValue::U64(u64::from(checksum)), || {
                format!("0x{checksum:04x} [{}]", if correct { "correct" } else { "incorrect" })
            });
            let status = if correct { "Good" } else { "Bad" };
            t.generated(&f::IP_CHECKSUM_STATUS, FieldValue::Str(status.into()), || status.to_owned());
            t.ipv4(&f::IP_SRC, start + 12, src);
            t.ipv4(&f::IP_DST, start + 16, dst);
            if !options.is_empty() {
                t.bytes(&f::IP_OPTIONS, start + 20, options);
            }
            t.close();
        }

        if frag_offset != 0 {
            ctx.info.set(P, || {
                format!(
                    "Fragmented IP protocol (proto={} {proto}, off={frag_offset}, ID={id:04x})",
                    names::ip_proto(proto)
                )
            });
            return Ok(Handoff::Data { start: start + ihl, end });
        }
        ctx.info.set(P, || format!("IPv4 protocol {} ({proto})", names::ip_proto(proto)));
        Ok(Handoff::IpProto { proto, start: start + ihl, end })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_valid_header_is_zero() {
        let hdr = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01,
            0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(internet_checksum(&hdr), 0);
        assert_eq!(internet_checksum(&[0x01]), !0x0100);
    }
}
