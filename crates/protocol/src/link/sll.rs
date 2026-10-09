//! Linux "cooked" capture headers (SLL v1 and v2).

use nettrace_model::{FieldValue, ProtocolId};
use nettrace_packet::{Address, MacAddr};

use crate::context::{m, Ctx, Malformed};
use crate::fields as f;
use crate::names;
use crate::registry::{Dissector, Handoff, Layer};

pub struct Sll;
pub static SLL: Sll = Sll;
pub struct Sll2;
pub static SLL2: Sll2 = Sll2;

const P: ProtocolId = ProtocolId::Sll;

fn pkttype_name(t: u16) -> &'static str {
    match t {
        0 => "Unicast to us",
        1 => "Broadcast",
        2 => "Multicast",
        3 => "Unicast to another host",
        4 => "Sent by us",
        _ => "Unknown",
    }
}

fn finish(ctx: &mut Ctx, halen: u16, hatype: u16, addr: [u8; 8], addr_at: usize, proto: u16, proto_at: usize) {
    if hatype == 1 && halen == 6 {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&addr[..6]);
        ctx.summary.l2_src = Address::Mac(MacAddr(mac));
        ctx.tree.mac(&f::SLL_SRC, addr_at, mac);
    }
    ctx.tree.add(&f::SLL_ETYPE, proto_at, 2, FieldValue::U64(u64::from(proto)), || {
        format!("{} (0x{proto:04x})", names::ethertype(proto))
    });
    ctx.tree.close();
}

impl Dissector for Sll {
    fn protocol(&self) -> ProtocolId {
        P
    }

    fn dissect(&self, ctx: &mut Ctx, layer: Layer) -> Result<Handoff, Malformed> {
        let mut c = layer.cursor();
        let start = c.offset();
        let pkttype = c.be_u16().map_err(m(P))?;
        let hatype = c.be_u16().map_err(m(P))?;
        let halen = c.be_u16().map_err(m(P))?;
        let addr_at = c.offset();
        let addr = c.array::<8>().map_err(m(P))?;
        let proto = c.be_u16().map_err(m(P))?;
        let t = &mut ctx.tree;
        t.open(&f::SLL, start, 16);
        t.heading(|| "Linux cooked capture v1".to_owned());
        t.named(&f::SLL_PKTTYPE, start, 2, u64::from(pkttype), pkttype_name(pkttype));
        t.uint(&f::SLL_HATYPE, start + 2, 2, u64::from(hatype));
        t.uint(&f::SLL_HALEN, start + 4, 2, u64::from(halen));
        finish(ctx, halen, hatype, addr, addr_at, proto, start + 14);
        Ok(Handoff::Ethertype { ethertype: proto, start: start + 16, end: layer.end })
    }
}

impl Dissector for Sll2 {
    fn protocol(&self) -> ProtocolId {
        P
    }

    fn dissect(&self, ctx: &mut Ctx, layer: Layer) -> Result<Handoff, Malformed> {
        let mut c = layer.cursor();
        let start = c.offset();
        let proto = c.be_u16().map_err(m(P))?;
        c.skip(2).map_err(m(P))?;
        let ifindex = c.be_u32().map_err(m(P))?;
        let hatype = c.be_u16().map_err(m(P))?;
        let pkttype = c.u8().map_err(m(P))?;
        let halen = c.u8().map_err(m(P))?;
        let addr_at = c.offset();
        let addr = c.array::<8>().map_err(m(P))?;
        let t = &mut ctx.tree;
        t.open(&f::SLL, start, 20);
        t.heading(|| "Linux cooked capture v2".to_owned());
        t.uint(&f::SLL_IFINDEX, start + 4, 4, u64::from(ifindex));
        t.uint(&f::SLL_HATYPE, start + 8, 2, u64::from(hatype));
        t.named(&f::SLL_PKTTYPE, start + 10, 1, u64::from(pkttype), pkttype_name(u16::from(pkttype)));
        t.uint(&f::SLL_HALEN, start + 11, 1, u64::from(halen));
        finish(ctx, u16::from(halen), hatype, addr, addr_at, proto, start);
        Ok(Handoff::Ethertype { ethertype: proto, start: start + 20, end: layer.end })
    }
}
