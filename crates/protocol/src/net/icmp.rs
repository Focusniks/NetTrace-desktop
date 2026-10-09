use nettrace_model::{FieldValue, ProtocolId};

use crate::context::{m, Ctx, Malformed};
use crate::fields as f;
use crate::names;
use crate::net::describe_embedded;
use crate::net::ipv4::internet_checksum;
use crate::registry::{Dissector, Handoff, Layer};

pub struct Icmp;
pub static ICMP: Icmp = Icmp;

const P: ProtocolId = ProtocolId::Icmp;

impl Dissector for Icmp {
    fn protocol(&self) -> ProtocolId {
        P
    }

    fn dissect(&self, ctx: &mut Ctx, layer: Layer) -> Result<Handoff, Malformed> {
        let mut c = layer.cursor();
        let start = c.offset();
        let ty = c.u8().map_err(m(P))?;
        let code = c.u8().map_err(m(P))?;
        let checksum = c.be_u16().map_err(m(P))?;
        let rest = c.array::<4>().map_err(m(P))?;
        let body_at = c.offset();
        let body = c.rest();
        let ttl = ctx.summary.hop_limit;

        let t = &mut ctx.tree;
        t.open(&f::ICMP, start, layer.len());
        t.heading(|| "Internet Control Message Protocol".to_owned());
        t.named(&f::ICMP_TYPE, start, 1, u64::from(ty), names::icmp_type(ty));
        let code_name = if ty == 3 { names::icmp_unreach_code(code) } else { "" };
        if code_name.is_empty() {
            t.uint(&f::ICMP_CODE, start + 1, 1, u64::from(code));
        } else {
            t.named(&f::ICMP_CODE, start + 1, 1, u64::from(code), code_name);
        }
        let correct = internet_checksum(layer.bytes()) == 0;
        t.add(&f::ICMP_CHECKSUM, start + 2, 2, FieldValue::U64(u64::from(checksum)), || {
            format!("0x{checksum:04x} [{}]", if correct { "correct" } else { "incorrect" })
        });

        let ident = u16::from_be_bytes([rest[0], rest[1]]);
        let seq = u16::from_be_bytes([rest[2], rest[3]]);
        match ty {
            0 | 8 | 13 | 14 => {
                t.add(&f::ICMP_IDENT, start + 4, 2, FieldValue::U64(u64::from(ident)), || format!("{ident} (0x{ident:04x})"));
                t.add(&f::ICMP_SEQ, start + 6, 2, FieldValue::U64(u64::from(seq)), || format!("{seq} (0x{seq:04x})"));
                if !body.is_empty() {
                    t.bytes(&f::ICMP_DATA, body_at, body);
                }
            }
            3 | 11 | 12 | 5 => {
                if ty == 5 {
                    t.ipv4(&f::ICMP_GATEWAY, start + 4, rest);
                } else if ty == 3 && code == 4 {
                    t.uint(&f::ICMP_MTU, start + 6, 2, u64::from(seq));
                }
                if let Some(desc) = describe_embedded(body) {
                    t.text(|| format!("Original datagram: {desc}"), body_at, body.len());
                }
                t.bytes(&f::ICMP_DATA, body_at, body);
            }
            _ => {
                if !body.is_empty() {
                    t.bytes(&f::ICMP_DATA, body_at, body);
                }
            }
        }
        t.close();

        ctx.info.set(P, || match ty {
            0 | 8 => {
                let mut s = format!("{}  id=0x{ident:04x}, seq={seq}/{}", names::icmp_type(ty), seq.swap_bytes());
                if let Some(ttl) = ttl {
                    s.push_str(&format!(", ttl={ttl}"));
                }
                s
            }
            3 => format!("Destination unreachable ({})", names::icmp_unreach_code(code)),
            11 => format!("Time-to-live exceeded ({})", if code == 0 { "Time to live exceeded in transit" } else { "Fragment reassembly time exceeded" }),
            _ => format!("{} (type {ty}, code {code})", names::icmp_type(ty)),
        });
        Ok(Handoff::Done)
    }
}
