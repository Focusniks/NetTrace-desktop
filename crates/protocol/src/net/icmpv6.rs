use std::net::Ipv6Addr;

use nettrace_model::{FieldValue, ProtocolId};
use nettrace_packet::{Cursor, MacAddr};

use crate::context::{m, Ctx, Malformed};
use crate::fields as f;
use crate::names;
use crate::net::describe_embedded;
use crate::registry::{Dissector, Handoff, Layer};
use crate::tree::Tree;

pub struct Icmpv6;
pub static ICMPV6: Icmpv6 = Icmpv6;

const P: ProtocolId = ProtocolId::Icmpv6;
const MAX_OPTIONS: usize = 64;

fn option_name(t: u8) -> &'static str {
    match t {
        1 => "Source link-layer address",
        2 => "Target link-layer address",
        3 => "Prefix information",
        4 => "Redirected header",
        5 => "MTU",
        25 => "Recursive DNS Server",
        _ => "Unknown",
    }
}

/// Parses Neighbor Discovery options; returns the first link-layer address.
fn nd_options(t: &mut Tree, c: &mut Cursor) -> Result<Option<MacAddr>, Malformed> {
    let mut lladdr = None;
    for _ in 0..MAX_OPTIONS {
        if c.remaining() == 0 {
            break;
        }
        let at = c.offset();
        let ty = c.u8().map_err(m(P))?;
        let len8 = c.u8().map_err(m(P))?;
        if len8 == 0 {
            return Err(Malformed::at(P, at + 1));
        }
        let size = usize::from(len8) * 8;
        let body = c.take(size - 2).map_err(m(P))?;
        t.open(&f::ICMPV6_OPT, at, size);
        t.heading(|| format!("ICMPv6 Option ({})", option_name(ty)));
        if matches!(ty, 1 | 2) && body.len() >= 6 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&body[..6]);
            t.mac(&f::ICMPV6_OPT_LINKADDR, at + 2, mac);
            lladdr.get_or_insert(MacAddr(mac));
        } else if ty == 5 && body.len() >= 6 {
            let mtu = u32::from_be_bytes([body[2], body[3], body[4], body[5]]);
            t.uint(&f::ICMPV6_MTU, at + 4, 4, u64::from(mtu));
        }
        t.close();
    }
    Ok(lladdr)
}

impl Dissector for Icmpv6 {
    fn protocol(&self) -> ProtocolId {
        P
    }

    fn dissect(&self, ctx: &mut Ctx, layer: Layer) -> Result<Handoff, Malformed> {
        let mut c = layer.cursor();
        let start = c.offset();
        let ty = c.u8().map_err(m(P))?;
        let code = c.u8().map_err(m(P))?;
        let checksum = c.be_u16().map_err(m(P))?;
        let hlim = ctx.summary.hop_limit;

        let t = &mut ctx.tree;
        t.open(&f::ICMPV6, start, layer.len());
        t.heading(|| "Internet Control Message Protocol v6".to_owned());
        t.named(&f::ICMPV6_TYPE, start, 1, u64::from(ty), names::icmpv6_type(ty));
        t.uint(&f::ICMPV6_CODE, start + 1, 1, u64::from(code));
        t.hex(&f::ICMPV6_CHECKSUM, start + 2, 2, u64::from(checksum), 4);

        
        let info: String = match ty {
            128 | 129 => {
                let id = c.be_u16().map_err(m(P))?;
                let seq = c.be_u16().map_err(m(P))?;
                t.add(&f::ICMPV6_ECHO_ID, start + 4, 2, FieldValue::U64(u64::from(id)), || format!("0x{id:04x}"));
                t.uint(&f::ICMPV6_ECHO_SEQ, start + 6, 2, u64::from(seq));
                let data = c.rest();
                if !data.is_empty() {
                    t.bytes(&f::ICMPV6_DATA, start + 8, data);
                }
                format!(
                    "{} id=0x{id:04x}, seq={seq}{}",
                    names::icmpv6_type(ty),
                    hlim.map(|h| format!(", hop limit={h}")).unwrap_or_default()
                )
            }
            135..=137 => {
                let flags = c.be_u32().map_err(m(P))?;
                if ty == 136 {
                    t.add(&f::ICMPV6_ND_FLAGS, start + 4, 4, FieldValue::U64(u64::from(flags >> 29)), || {
                        let mut s = Vec::new();
                        if flags & 0x8000_0000 != 0 {
                            s.push("Router");
                        }
                        if flags & 0x4000_0000 != 0 {
                            s.push("Solicited");
                        }
                        if flags & 0x2000_0000 != 0 {
                            s.push("Override");
                        }
                        format!("0x{flags:08x}, {}", s.join(", "))
                    });
                }
                let target = c.array::<16>().map_err(m(P))?;
                t.ipv6(&f::ICMPV6_ND_TARGET, start + 8, target);
                if ty == 137 {
                    c.skip(16).map_err(m(P))?;
                }
                let ll = nd_options(t, &mut c)?;
                let target = Ipv6Addr::from(target);
                match (ty, ll) {
                    (135, Some(mac)) => format!("Neighbor Solicitation for {target} from {mac}"),
                    (135, None) => format!("Neighbor Solicitation for {target}"),
                    (136, Some(mac)) => format!("Neighbor Advertisement {target} is at {mac}"),
                    (136, None) => format!("Neighbor Advertisement {target}"),
                    _ => format!("Redirect {target}"),
                }
            }
            133 => {
                c.skip(4).map_err(m(P))?;
                let ll = nd_options(t, &mut c)?;
                match ll {
                    Some(mac) => format!("Router Solicitation from {mac}"),
                    None => "Router Solicitation".to_owned(),
                }
            }
            134 => {
                let cur = c.u8().map_err(m(P))?;
                let _flags = c.u8().map_err(m(P))?;
                let lifetime = c.be_u16().map_err(m(P))?;
                c.skip(8).map_err(m(P))?;
                t.uint(&f::ICMPV6_RA_HOP_LIMIT, start + 4, 1, u64::from(cur));
                t.uint(&f::ICMPV6_RA_LIFETIME, start + 6, 2, u64::from(lifetime));
                let ll = nd_options(t, &mut c)?;
                match ll {
                    Some(mac) => format!("Router Advertisement from {mac}"),
                    None => "Router Advertisement".to_owned(),
                }
            }
            1..=4 => {
                let word = c.be_u32().map_err(m(P))?;
                if ty == 2 {
                    t.uint(&f::ICMPV6_MTU, start + 4, 4, u64::from(word));
                }
                let body = c.rest();
                if let Some(desc) = describe_embedded(body) {
                    t.text(|| format!("Original datagram: {desc}"), start + 8, body.len());
                }
                t.bytes(&f::ICMPV6_DATA, start + 8, body);
                format!("{} (code {code})", names::icmpv6_type(ty))
            }
            _ => {
                let data = c.rest();
                if !data.is_empty() {
                    t.bytes(&f::ICMPV6_DATA, start + 4, data);
                }
                format!("{} (type {ty})", names::icmpv6_type(ty))
            }
        };
        t.close();
        ctx.info.set(P, || info);
        Ok(Handoff::Done)
    }
}
