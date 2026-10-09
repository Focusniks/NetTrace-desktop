use nettrace_model::{FieldValue, ProtocolId};
use nettrace_packet::Address;

use crate::context::{m, Ctx, Malformed};
use crate::fields as f;
use crate::format::bits;
use crate::names;
use crate::registry::{Dissector, Handoff, Layer};

pub struct Ipv6;
pub static IPV6: Ipv6 = Ipv6;

const P: ProtocolId = ProtocolId::Ipv6;
const MAX_EXT_HEADERS: usize = 8;

impl Dissector for Ipv6 {
    fn protocol(&self) -> ProtocolId {
        P
    }

    fn dissect(&self, ctx: &mut Ctx, layer: Layer) -> Result<Handoff, Malformed> {
        let mut c = layer.cursor();
        let start = c.offset();
        let vtf = c.be_u32().map_err(m(P))?;
        let plen = c.be_u16().map_err(m(P))?;
        let mut nxt = c.u8().map_err(m(P))?;
        let hlim = c.u8().map_err(m(P))?;
        let src = c.array::<16>().map_err(m(P))?;
        let dst = c.array::<16>().map_err(m(P))?;
        if vtf >> 28 != 6 {
            return Err(Malformed::at(P, start));
        }
        ctx.summary.net_src = Address::V6(src);
        ctx.summary.net_dst = Address::V6(dst);
        ctx.summary.hop_limit = Some(hlim);
        if plen != 0 {
            ctx.summary.ip_end = Some(start + 40 + usize::from(plen));
        }
        let end = if plen == 0 { layer.end } else { (start + 40 + usize::from(plen)).min(layer.end) };
        let tclass = (vtf >> 20) & 0xff;
        let flow = vtf & 0x000f_ffff;

        let t = &mut ctx.tree;
        t.open(&f::IPV6, start, 40);
        t.heading(|| format!("Internet Protocol Version 6, Src: {}, Dst: {}", Address::V6(src), Address::V6(dst)));
        let v = u64::from(vtf);
        t.add(&f::IPV6_VERSION, start, 1, FieldValue::U64(6), || format!("{} = Version: 6", bits(v >> 24, 0xf0, 8)));
        t.add(&f::IPV6_TCLASS, start, 2, FieldValue::U64(u64::from(tclass)), || format!("0x{tclass:02x}"));
        t.add(&f::IPV6_FLOW, start + 1, 3, FieldValue::U64(u64::from(flow)), || format!("0x{flow:05x}"));
        t.uint(&f::IPV6_PLEN, start + 4, 2, u64::from(plen));
        t.named(&f::IPV6_NXT, start + 6, 1, u64::from(nxt), names::ip_proto(nxt));
        t.uint(&f::IPV6_HLIM, start + 7, 1, u64::from(hlim));
        t.ipv6(&f::IPV6_SRC, start + 8, src);
        t.ipv6(&f::IPV6_DST, start + 24, dst);

        let mut pos = start + 40;
        let mut header_len = 40;
        let mut first_fragment = false;
        for _ in 0..MAX_EXT_HEADERS {
            if !matches!(nxt, 0 | 43 | 44 | 60) {
                break;
            }
            let ext = Layer::new(layer.frame, pos, end);
            let mut e = ext.cursor();
            let next = e.u8().map_err(m(P))?;
            let len_byte = e.u8().map_err(m(P))?;
            let size = if nxt == 44 { 8 } else { (usize::from(len_byte) + 1) * 8 };
            if ext.len() < size {
                return Err(Malformed::at(P, pos));
            }
            t.open(&f::IPV6_EXT, pos, size);
            let this = nxt;
            t.heading(|| names::ip_proto(this).to_owned());
            t.named(&f::IPV6_NXT, pos, 1, u64::from(next), names::ip_proto(next));
            if this == 44 {
                let off_flags = e.be_u16().map_err(m(P))?;
                let ident = e.be_u32().map_err(m(P))?;
                let offset = off_flags & 0xfff8;
                let more = off_flags & 1 != 0;
                t.uint(&f::IPV6_FRAG_OFFSET, pos + 2, 2, u64::from(offset));
                t.flag(&f::IPV6_FRAG_MORE, pos + 2, 2, more, || bits(u64::from(off_flags), 1, 16));
                t.add(&f::IPV6_FRAG_ID, pos + 4, 4, FieldValue::U64(u64::from(ident)), || format!("0x{ident:08x}"));
                if offset != 0 {
                    t.close();
                    t.set_len(header_len + size);
                    t.close();
                    let proto = next;
                    ctx.info.set(P, || {
                        format!("IPv6 fragment (nxt={} {proto}, off={offset}, ID=0x{ident:08x})", names::ip_proto(proto))
                    });
                    return Ok(Handoff::Data { start: pos + 8, end });
                }
                // First fragment: the upper layers see only part of the datagram.
                first_fragment = more;
            } else {
                t.uint(&f::IPV6_EXT_LEN, pos + 1, 1, u64::from(len_byte));
            }
            t.close();
            pos += size;
            header_len += size;
            nxt = next;
        }
        t.set_len(header_len);
        t.close();
        ctx.incomplete |= first_fragment;
        if nxt == 59 {
            ctx.info.set(P, || "IPv6 no next header".to_owned());
            return Ok(Handoff::Done);
        }
        let proto = nxt;
        ctx.info.set(P, || format!("IPv6 next header {} ({proto})", names::ip_proto(proto)));
        Ok(Handoff::IpProto { proto: nxt, start: pos, end })
    }
}
