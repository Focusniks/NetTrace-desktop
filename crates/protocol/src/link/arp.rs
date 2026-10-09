use std::net::Ipv4Addr;

use nettrace_model::{FieldValue, ProtocolId};
use nettrace_packet::MacAddr;

use crate::context::{m, Ctx, Malformed};
use crate::fields as f;
use crate::names;
use crate::registry::{Dissector, Handoff, Layer};

pub struct Arp;
pub static ARP: Arp = Arp;

const P: ProtocolId = ProtocolId::Arp;

impl Dissector for Arp {
    fn protocol(&self) -> ProtocolId {
        P
    }

    fn dissect(&self, ctx: &mut Ctx, layer: Layer) -> Result<Handoff, Malformed> {
        let mut c = layer.cursor();
        let start = c.offset();
        let htype = c.be_u16().map_err(m(P))?;
        let ptype = c.be_u16().map_err(m(P))?;
        let hlen = c.u8().map_err(m(P))?;
        let plen = c.u8().map_err(m(P))?;
        let op = c.be_u16().map_err(m(P))?;
        let total = 8 + 2 * (usize::from(hlen) + usize::from(plen));
        let sha_at = c.offset();
        let sha = c.take(usize::from(hlen)).map_err(m(P))?;
        let spa_at = c.offset();
        let spa = c.take(usize::from(plen)).map_err(m(P))?;
        let tha_at = c.offset();
        let tha = c.take(usize::from(hlen)).map_err(m(P))?;
        let tpa_at = c.offset();
        let tpa = c.take(usize::from(plen)).map_err(m(P))?;

        let ethernet_ipv4 = htype == 1 && ptype == 0x0800 && hlen == 6 && plen == 4;
        let gratuitous = ethernet_ipv4 && spa == tpa;
        let t = &mut ctx.tree;
        t.open(&f::ARP, start, total);
        t.heading(|| {
            let kind = if gratuitous { "gratuitous " } else { "" };
            format!("Address Resolution Protocol ({kind}{})", names::arp_opcode(op))
        });
        t.named(&f::ARP_HW_TYPE, start, 2, u64::from(htype), if htype == 1 { "Ethernet" } else { "Unknown" });
        t.add(&f::ARP_PROTO_TYPE, start + 2, 2, FieldValue::U64(u64::from(ptype)), || {
            format!("{} (0x{ptype:04x})", names::ethertype(ptype))
        });
        t.uint(&f::ARP_HW_SIZE, start + 4, 1, u64::from(hlen));
        t.uint(&f::ARP_PROTO_SIZE, start + 5, 1, u64::from(plen));
        t.named(&f::ARP_OPCODE, start + 6, 2, u64::from(op), names::arp_opcode(op));
        if ethernet_ipv4 {
            let (sha6, tha6) = (to6(sha), to6(tha));
            let (spa4, tpa4) = (to4(spa), to4(tpa));
            t.add(&f::ARP_GRATUITOUS, 0, 0, FieldValue::Bool(gratuitous), || gratuitous.to_string());
            t.mac(&f::ARP_SRC_HW, sha_at, sha6);
            t.ipv4(&f::ARP_SRC_IP, spa_at, spa4);
            t.mac(&f::ARP_DST_HW, tha_at, tha6);
            t.ipv4(&f::ARP_DST_IP, tpa_at, tpa4);
            t.close();
            let (s_ip, t_ip, s_mac) = (Ipv4Addr::from(spa4), Ipv4Addr::from(tpa4), MacAddr(sha6));
            ctx.info.set(P, || match op {
                1 if gratuitous => format!("Gratuitous ARP for {s_ip} (Request)"),
                1 => format!("Who has {t_ip}? Tell {s_ip}"),
                2 if gratuitous => format!("Gratuitous ARP for {s_ip} (Reply)"),
                2 => format!("{s_ip} is at {s_mac}"),
                _ => format!("ARP {}", names::arp_opcode(op)),
            });
        } else {
            t.bytes(&f::DATA_DATA, sha_at, sha);
            t.close();
            ctx.info.set(P, || format!("ARP {} (hardware type {htype})", names::arp_opcode(op)));
        }
        Ok(Handoff::Done)
    }
}

fn to6(b: &[u8]) -> [u8; 6] {
    let mut out = [0u8; 6];
    out.copy_from_slice(&b[..6]);
    out
}

fn to4(b: &[u8]) -> [u8; 4] {
    let mut out = [0u8; 4];
    out.copy_from_slice(&b[..4]);
    out
}
