//! BSD (`NULL`, host byte order) and OpenBSD (`LOOP`, network byte order) loopback.

use nettrace_model::{FieldValue, ProtocolId};

use crate::context::{m, Ctx, Malformed};
use crate::fields as f;
use crate::registry::{Dissector, Handoff, Layer};

pub struct Null {
    network_order: bool,
}
pub static NULL: Null = Null { network_order: false };
pub static LOOP: Null = Null { network_order: true };

const P: ProtocolId = ProtocolId::Loopback;

fn family_name(fam: u32) -> &'static str {
    match fam {
        2 => "IP",
        // 10: Linux AF_INET6, 23: Windows (Npcap loopback), 24/28/30: BSDs and macOS.
        10 | 23 | 24 | 28 | 30 => "IPv6",
        _ => "Unknown",
    }
}

impl Dissector for Null {
    fn protocol(&self) -> ProtocolId {
        P
    }

    fn dissect(&self, ctx: &mut Ctx, layer: Layer) -> Result<Handoff, Malformed> {
        let mut c = layer.cursor();
        let start = c.offset();
        let raw = c.array::<4>().map_err(m(P))?;
        // The writer's byte order is unknown for NULL: a small value in either order is the family.
        let fam = if self.network_order || (raw[0] == 0 && raw[1] == 0) {
            u32::from_be_bytes(raw)
        } else {
            u32::from_le_bytes(raw)
        };
        let t = &mut ctx.tree;
        t.open(&f::NULL, start, 4);
        t.heading(|| "Null/Loopback".to_owned());
        t.add(&f::NULL_FAMILY, start, 4, FieldValue::U64(u64::from(fam)), || {
            format!("{} ({fam})", family_name(fam))
        });
        t.close();
        let ethertype = match fam {
            2 => 0x0800,
            10 | 23 | 24 | 28 | 30 => 0x86dd,
            _ => return Ok(Handoff::Data { start: start + 4, end: layer.end }),
        };
        Ok(Handoff::Ethertype { ethertype, start: start + 4, end: layer.end })
    }
}
