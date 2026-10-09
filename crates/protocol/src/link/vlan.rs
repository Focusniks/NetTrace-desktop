use nettrace_model::{FieldValue, ProtocolId};

use crate::context::{m, Ctx, Malformed};
use crate::fields as f;
use crate::format::bits;
use crate::names;
use crate::registry::{Dissector, Handoff, Layer};

pub struct Vlan;
pub static VLAN: Vlan = Vlan;

const P: ProtocolId = ProtocolId::Vlan;

impl Dissector for Vlan {
    fn protocol(&self) -> ProtocolId {
        P
    }

    fn dissect(&self, ctx: &mut Ctx, layer: Layer) -> Result<Handoff, Malformed> {
        let mut c = layer.cursor();
        let start = c.offset();
        let tci = c.be_u16().map_err(m(P))?;
        let ty = c.be_u16().map_err(m(P))?;
        let (pri, dei, id) = (tci >> 13, tci & 0x1000 != 0, tci & 0x0fff);
        let t = &mut ctx.tree;
        t.open(&f::VLAN, start, 4);
        t.heading(|| format!("802.1Q Virtual LAN, PRI: {pri}, DEI: {}, ID: {id}", u8::from(dei)));
        let tci64 = u64::from(tci);
        t.add(&f::VLAN_PRIORITY, start, 2, FieldValue::U64(u64::from(pri)), || {
            format!("{} = Priority: {pri}", bits(tci64, 0xe000, 16))
        });
        t.add(&f::VLAN_DEI, start, 2, FieldValue::Bool(dei), || {
            format!("{} = DEI: {}", bits(tci64, 0x1000, 16), if dei { "Eligible" } else { "Ineligible" })
        });
        t.add(&f::VLAN_ID, start, 2, FieldValue::U64(u64::from(id)), || {
            format!("{} = ID: {id}", bits(tci64, 0x0fff, 16))
        });
        t.add(&f::VLAN_ETYPE, start + 2, 2, FieldValue::U64(u64::from(ty)), || {
            format!("{} (0x{ty:04x})", names::ethertype(ty))
        });
        t.close();
        ctx.info.set(P, || format!("802.1Q VLAN {id}"));
        Ok(Handoff::Ethertype { ethertype: ty, start: start + 4, end: layer.end })
    }
}
