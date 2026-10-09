use nettrace_model::ProtocolId;
use nettrace_packet::{Address, MacAddr};

use crate::context::{m, Ctx, Malformed};
use crate::fields as f;
use crate::format::bits;
use crate::names;
use crate::registry::{Dissector, Handoff, Layer};

pub struct Ethernet;
pub static ETHERNET: Ethernet = Ethernet;

const P: ProtocolId = ProtocolId::Eth;

impl Dissector for Ethernet {
    fn protocol(&self) -> ProtocolId {
        P
    }

    fn dissect(&self, ctx: &mut Ctx, layer: Layer) -> Result<Handoff, Malformed> {
        let mut c = layer.cursor();
        let start = c.offset();
        let dst = c.array::<6>().map_err(m(P))?;
        let src = c.array::<6>().map_err(m(P))?;
        let ty = c.be_u16().map_err(m(P))?;
        ctx.summary.l2_src = Address::Mac(MacAddr(src));
        ctx.summary.l2_dst = Address::Mac(MacAddr(dst));

        let t = &mut ctx.tree;
        t.open(&f::ETH, start, 14);
        t.heading(|| {
            let kind = if ty <= 1500 { "IEEE 802.3 Ethernet" } else { "Ethernet II" };
            format!("{kind}, Src: {}, Dst: {}", MacAddr(src), MacAddr(dst))
        });
        mac_subtree(t, &f::ETH_DST, start, dst);
        mac_subtree(t, &f::ETH_SRC, start + 6, src);

        if ty <= 1500 {
            t.uint(&f::ETH_LEN, start + 12, 2, u64::from(ty));
            t.close();
            let payload_end = (start + 14 + usize::from(ty)).min(layer.end);
            ctx.info.set(P, || "IEEE 802.3 frame".to_owned());
            return Ok(Handoff::Data { start: start + 14, end: payload_end });
        }
        t.add(&f::ETH_TYPE, start + 12, 2, nettrace_model::FieldValue::U64(u64::from(ty)), || {
            format!("{} (0x{ty:04x})", names::ethertype(ty))
        });
        t.close();
        ctx.info.set(P, || format!("Ethernet II, type {} (0x{ty:04x})", names::ethertype(ty)));
        Ok(Handoff::Ethertype { ethertype: ty, start: start + 14, end: layer.end })
    }
}

fn mac_subtree(t: &mut crate::tree::Tree, field: &'static crate::fields::Field, at: usize, mac: [u8; 6]) {
    let addr = MacAddr(mac);
    t.open_value(field, at, 6, nettrace_model::FieldValue::Mac(mac), || addr.to_string());
    let lg = mac[0] & 0x02 != 0;
    let ig = mac[0] & 0x01 != 0;
    t.add(&f::ETH_LG, at, 3, nettrace_model::FieldValue::Bool(lg), || {
        format!(
            "{} = LG bit: {}",
            bits(u64::from(mac[0]) << 16, 0x02_0000, 24),
            if lg { "Locally administered address (this is NOT the factory default)" } else { "Globally unique address (factory default)" }
        )
    });
    t.add(&f::ETH_IG, at, 3, nettrace_model::FieldValue::Bool(ig), || {
        format!(
            "{} = IG bit: {}",
            bits(u64::from(mac[0]) << 16, 0x01_0000, 24),
            if ig { "Group address (multicast/broadcast)" } else { "Individual address (unicast)" }
        )
    });
    t.close();
}
