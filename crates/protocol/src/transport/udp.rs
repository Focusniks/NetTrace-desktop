use nettrace_model::{FieldValue, ProtocolId, Transport};

use crate::context::{m, Ctx, Malformed, TransportInfo};
use crate::fields as f;
use crate::format;
use crate::registry::{Dissector, Handoff, Layer};

pub struct Udp;
pub static UDP: Udp = Udp;

const P: ProtocolId = ProtocolId::Udp;

impl Dissector for Udp {
    fn protocol(&self) -> ProtocolId {
        P
    }

    fn dissect(&self, ctx: &mut Ctx, layer: Layer) -> Result<Handoff, Malformed> {
        let mut c = layer.cursor();
        let start = c.offset();
        let sport = c.be_u16().map_err(m(P))?;
        let dport = c.be_u16().map_err(m(P))?;
        let length = c.be_u16().map_err(m(P))?;
        let checksum = c.be_u16().map_err(m(P))?;
        ctx.summary.src_port = sport;
        ctx.summary.dst_port = dport;
        // Length 0 is legal only for IPv6 jumbograms; then use the captured payload.
        let end = match length {
            0 => layer.end,
            1..=7 => return Err(Malformed::at(P, start + 4)),
            l => (start + usize::from(l)).min(layer.end),
        };
        let payload_len = end.saturating_sub(start + 8);
        // Wire length from the header, independent of snaplen truncation.
        let wire_payload = if length >= 8 { u32::from(length) - 8 } else { payload_len as u32 };
        ctx.summary.transport = Some(TransportInfo::Udp { payload_len: wire_payload });

        let t = &mut ctx.tree;
        t.open(&f::UDP, start, 8);
        t.heading(|| format!("User Datagram Protocol, Src Port: {sport}, Dst Port: {dport}"));
        t.uint(&f::UDP_SRCPORT, start, 2, u64::from(sport));
        t.uint(&f::UDP_DSTPORT, start + 2, 2, u64::from(dport));
        t.uint(&f::UDP_LENGTH, start + 4, 2, u64::from(length));
        t.add(&f::UDP_CHECKSUM, start + 6, 2, FieldValue::U64(u64::from(checksum)), || {
            if checksum == 0 { "0x0000 [zero-value ignored]".to_owned() } else { format!("0x{checksum:04x} [unverified]") }
        });
        if let Some(stream) = ctx.frame.udp_stream {
            t.generated(&f::UDP_STREAM, FieldValue::U64(u64::from(stream)), || stream.to_string());
        }
        t.close();
        if payload_len > 0 {
            if t.full() {
                t.text(|| format!("UDP payload ({})", format::plural_bytes(payload_len)), start + 8, payload_len);
            } else {
                let payload = layer.frame.get(start + 8..end).unwrap_or(&[]);
                t.bytes(&f::UDP_PAYLOAD, start + 8, payload);
            }
        }
        ctx.info.set(P, || format!("{sport} → {dport} Len={payload_len}"));
        if payload_len == 0 {
            return Ok(Handoff::Done);
        }
        Ok(Handoff::Payload { transport: Transport::Udp, src_port: sport, dst_port: dport, start: start + 8, end })
    }
}
