use std::net::{Ipv4Addr, Ipv6Addr};

use nettrace_model::{FieldValue, ProtocolId, TimelineKind, Transport};
use nettrace_packet::Cursor;

use crate::context::{m, AppEvent, Ctx, Malformed};
use crate::fields::{self as f, Field};
use crate::format::bits;
use crate::names;
use crate::registry::{AppDissector, Layer};
use crate::transport::tcp::info_prefix;
use crate::tree::Tree;

pub struct Dns;
pub static DNS: Dns = Dns;

const P: ProtocolId = ProtocolId::Dns;
const MAX_JUMPS: usize = 16;
const MAX_NAME_LEN: usize = 255;
const MAX_RECORDS: usize = 512;
/// Total decoded name bytes allowed per message (bounds pointer amplification).
const NAME_BUDGET: usize = 32 * 1024;

/// Reads a (possibly compressed) domain name starting at `pos` of `msg`.
/// Returns the name and the number of bytes it occupies at `pos`.
pub(crate) fn read_name(msg: &[u8], pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut cur = pos;
    let mut consumed = None;
    let mut jumps = 0;
    let mut total = 0usize;
    loop {
        let len = *msg.get(cur)?;
        match len & 0xc0 {
            0x00 => {
                if len == 0 {
                    let used = consumed.unwrap_or_else(|| cur + 1 - pos);
                    if name.is_empty() {
                        name.push_str("<Root>");
                    }
                    return Some((name, used));
                }
                let label = msg.get(cur + 1..cur + 1 + usize::from(len))?;
                total += usize::from(len) + 1;
                if total > MAX_NAME_LEN {
                    return None;
                }
                if !name.is_empty() {
                    name.push('.');
                }
                for &b in label {
                    match b {
                        b'.' | b'\\' => {
                            name.push('\\');
                            name.push(b as char);
                        }
                        0x21..=0x7e => name.push(b as char),
                        _ => name.push_str(&format!("\\{b:03}")),
                    }
                }
                cur += 1 + usize::from(len);
            }
            0xc0 => {
                let lo = *msg.get(cur + 1)?;
                let target = (usize::from(len & 0x3f) << 8) | usize::from(lo);
                if consumed.is_none() {
                    consumed = Some(cur + 2 - pos);
                }
                jumps += 1;
                // Pointers must go backwards; together with the jump limit this rules out loops.
                if jumps > MAX_JUMPS || target >= cur {
                    return None;
                }
                cur = target;
            }
            _ => return None,
        }
    }
}

struct Message<'a> {
    msg: &'a [u8],
    /// Absolute frame offset of `msg[0]`.
    base: usize,
    budget: std::cell::Cell<usize>,
}

impl<'a> Message<'a> {
    fn name(&self, c: &mut Cursor) -> Result<String, Malformed> {
        let rel = c.offset() - self.base;
        let (name, used) = read_name(self.msg, rel).ok_or(Malformed::at(P, c.offset()))?;
        let left = self.budget.get().checked_sub(name.len()).ok_or(Malformed::at(P, c.offset()))?;
        self.budget.set(left);
        c.skip(used).map_err(m(P))?;
        Ok(name)
    }
}

struct Answer {
    rtype: u16,
    text: String,
}

impl AppDissector for Dns {
    fn protocol(&self) -> ProtocolId {
        P
    }

    fn tcp_ports(&self) -> &'static [u16] {
        &[53, 5353]
    }

    fn udp_ports(&self) -> &'static [u16] {
        &[53, 5353, 5355]
    }

    fn accepts(&self, payload: &[u8], transport: Transport) -> bool {
        payload.len() >= if transport == Transport::Tcp { 14 } else { 12 }
    }

    fn dissect(&self, ctx: &mut Ctx, layer: Layer, transport: Transport) -> Result<(), Malformed> {
        let prefix = info_prefix(ctx);
        let mut start = layer.start;
        let mut end = layer.end;
        let mut tcp_len = None;
        if transport == Transport::Tcp {
            let mut c = layer.cursor();
            let len = c.be_u16().map_err(m(P))?;
            tcp_len = Some(len);
            start += 2;
            end = end.min(start + usize::from(len));
        }
        let msg = layer.frame.get(start..end).unwrap_or(&[]);
        let message = Message { msg, base: start, budget: std::cell::Cell::new(NAME_BUDGET) };
        let mut c = Cursor::with_base(msg, start);
        let id = c.be_u16().map_err(m(P))?;
        let flags = c.be_u16().map_err(m(P))?;
        let qd = c.be_u16().map_err(m(P))?;
        let an = c.be_u16().map_err(m(P))?;
        let ns = c.be_u16().map_err(m(P))?;
        let ar = c.be_u16().map_err(m(P))?;
        let response = flags & 0x8000 != 0;
        let opcode = (flags >> 11) & 0x0f;
        let rcode = flags & 0x000f;

        let t = &mut ctx.tree;
        t.open(&f::DNS, layer.start, layer.len());
        t.heading(|| format!("Domain Name System ({})", if response { "response" } else { "query" }));
        if let Some(len) = tcp_len {
            t.uint(&f::DNS_LENGTH, layer.start, 2, u64::from(len));
        }
        t.add(&f::DNS_ID, start, 2, FieldValue::U64(u64::from(id)), || format!("0x{id:04x}"));
        flags_tree(t, start + 2, flags);
        t.uint(&f::DNS_COUNT_QUERIES, start + 4, 2, u64::from(qd));
        t.uint(&f::DNS_COUNT_ANSWERS, start + 6, 2, u64::from(an));
        t.uint(&f::DNS_COUNT_AUTH, start + 8, 2, u64::from(ns));
        t.uint(&f::DNS_COUNT_ADD, start + 10, 2, u64::from(ar));

        let mut first_query: Option<(String, u16)> = None;
        let mut answers: Vec<Answer> = Vec::new();
        let result = (|| -> Result<(), Malformed> {
            if qd > 0 {
                let at = c.offset();
                t.open(&f::DNS_QUERIES, at, 0);
                t.heading(|| "Queries".to_owned());
                for _ in 0..usize::from(qd).min(MAX_RECORDS) {
                    let q_at = c.offset();
                    let name = message.name(&mut c)?;
                    let name_end = c.offset();
                    let qtype = c.be_u16().map_err(m(P))?;
                    let qclass = c.be_u16().map_err(m(P))?;
                    t.open_text(|| {
                        format!("{name}: type {}, class {}", names::dns_type(qtype), names::dns_class(qclass))
                    }, q_at, c.offset() - q_at);
                    t.string(&f::DNS_QRY_NAME, q_at, name_end - q_at, &name);
                    t.named(&f::DNS_QRY_TYPE, name_end, 2, u64::from(qtype), names::dns_type(qtype));
                    t.add(&f::DNS_QRY_CLASS, name_end + 2, 2, FieldValue::U64(u64::from(qclass)), || {
                        format!("{} (0x{qclass:04x})", names::dns_class(qclass))
                    });
                    t.close();
                    if first_query.is_none() {
                        first_query = Some((name, qtype));
                    }
                }
                t.set_len(c.offset() - at);
                t.close();
            }
            for (count, section, heading) in [
                (an, &f::DNS_ANSWERS, "Answers"),
                (ns, &f::DNS_AUTHORITIES, "Authoritative nameservers"),
                (ar, &f::DNS_ADDITIONALS, "Additional records"),
            ] {
                if count == 0 {
                    continue;
                }
                let at = c.offset();
                t.open(section, at, 0);
                t.heading(|| heading.to_owned());
                for _ in 0..usize::from(count).min(MAX_RECORDS) {
                    let rec = resource_record(t, &message, &mut c)?;
                    if std::ptr::eq(section, &f::DNS_ANSWERS) {
                        answers.push(rec);
                    }
                }
                t.set_len(c.offset() - at);
                t.close();
            }
            Ok(())
        })();
        t.close();

        let (qname, qtype) = first_query.clone().unwrap_or_default();
        let opname = names::dns_opcode(opcode);
        ctx.info.set(P, || {
            let mut s = format!("{prefix}{opname}{} 0x{id:04x}", if response { " response" } else { "" });
            if response && rcode != 0 {
                s.push(' ');
                s.push_str(names::dns_rcode(rcode));
            }
            if first_query.is_some() {
                s.push_str(&format!(" {} {qname}", names::dns_type(qtype)));
            }
            for a in answers.iter().take(8) {
                s.push_str(&format!(" {} {}", names::dns_type(a.rtype), a.text));
            }
            s
        });
        if ctx.opts.events && first_query.is_some() {
            let (kind, label) = if response {
                let label = if rcode != 0 {
                    format!("{qname}: {}", names::dns_rcode(rcode))
                } else {
                    match answers.iter().find(|a| matches!(a.rtype, 1 | 28)).or(answers.first()) {
                        Some(a) => format!("{qname} → {}", a.text),
                        None => format!("{qname}: no answers"),
                    }
                };
                (TimelineKind::DnsResponse, label)
            } else {
                (TimelineKind::DnsQuery, format!("{} {qname}", names::dns_type(qtype)))
            };
            ctx.summary.event = Some(AppEvent { kind, label, name: Some(qname) });
        }
        result
    }
}

fn flags_tree(t: &mut Tree, at: usize, flags: u16) {
    let response = flags & 0x8000 != 0;
    let opcode = (flags >> 11) & 0x0f;
    let rcode = flags & 0x000f;
    let fv = u64::from(flags);
    t.open_value(&f::DNS_FLAGS, at, 2, FieldValue::U64(fv), || {
        let mut s = format!("0x{flags:04x} {}", names::dns_opcode(opcode));
        if response {
            s.push_str(" response, ");
            s.push_str(names::dns_rcode(rcode));
        }
        s
    });
    t.add(&f::DNS_FLAGS_RESPONSE, at, 2, FieldValue::Bool(response), || {
        format!("{} = Response: {}", bits(fv, 0x8000, 16), if response { "Message is a response" } else { "Message is a query" })
    });
    t.add(&f::DNS_FLAGS_OPCODE, at, 2, FieldValue::U64(u64::from(opcode)), || {
        format!("{} = Opcode: {} ({opcode})", bits(fv, 0x7800, 16), names::dns_opcode(opcode))
    });
    let bool_flags: [(&'static Field, u16, &str); 4] = [
        (&f::DNS_FLAGS_AA, 0x0400, "Authoritative"),
        (&f::DNS_FLAGS_TC, 0x0200, "Truncated"),
        (&f::DNS_FLAGS_RD, 0x0100, "Recursion desired"),
        (&f::DNS_FLAGS_RA, 0x0080, "Recursion available"),
    ];
    for (field, bit, name) in bool_flags {
        if !response && (bit == 0x0400 || bit == 0x0080) {
            continue;
        }
        t.flag(field, at, 2, flags & bit != 0, || format!("{} {name}", bits(fv, u64::from(bit), 16)));
    }
    if response {
        t.add(&f::DNS_FLAGS_RCODE, at, 2, FieldValue::U64(u64::from(rcode)), || {
            format!("{} = Reply code: {} ({rcode})", bits(fv, 0x000f, 16), names::dns_rcode(rcode))
        });
    }
    t.close();
}

fn resource_record(t: &mut Tree, message: &Message, c: &mut Cursor) -> Result<Answer, Malformed> {
    let at = c.offset();
    let name = message.name(c)?;
    let name_end = c.offset();
    let rtype = c.be_u16().map_err(m(P))?;
    let class = c.be_u16().map_err(m(P))?;
    let ttl = c.be_u32().map_err(m(P))?;
    let rdlen = c.be_u16().map_err(m(P))?;
    let rdata_at = c.offset();
    let mut rd = c.sub(usize::from(rdlen)).map_err(m(P))?;
    let total = c.offset() - at;

    let text = match rtype {
        1 if rdlen == 4 => Ipv4Addr::from(rd.array::<4>().map_err(m(P))?).to_string(),
        28 if rdlen == 16 => Ipv6Addr::from(rd.array::<16>().map_err(m(P))?).to_string(),
        2 | 5 | 12 => message.name(&mut rd)?,
        15 => {
            let _pref = rd.be_u16().map_err(m(P))?;
            message.name(&mut rd)?
        }
        16 => {
            let mut parts = Vec::new();
            while rd.remaining() > 0 {
                let l = usize::from(rd.u8().map_err(m(P))?);
                parts.push(crate::format::text(rd.take(l).map_err(m(P))?));
            }
            parts.join(" ")
        }
        33 => {
            rd.skip(4).map_err(m(P))?;
            let port = rd.be_u16().map_err(m(P))?;
            format!("{} port {port}", message.name(&mut rd)?)
        }
        6 => message.name(&mut rd)?,
        _ => String::new(),
    };

    let type_name = names::dns_type(rtype);
    t.open_text(|| {
        if rtype == 41 {
            format!("{name}: type OPT")
        } else if text.is_empty() {
            format!("{name}: type {type_name}, class {}", names::dns_class(class))
        } else {
            let what = match rtype {
                1 | 28 => "addr",
                5 => "cname",
                2 => "ns",
                12 => "ptr",
                15 => "mx",
                16 => "txt",
                33 => "srv",
                6 => "mname",
                _ => "data",
            };
            format!("{name}: type {type_name}, class {}, {what} {text}", names::dns_class(class))
        }
    }, at, total);
    t.string(&f::DNS_RESP_NAME, at, name_end - at, &name);
    t.named(&f::DNS_RESP_TYPE, name_end, 2, u64::from(rtype), type_name);
    if rtype == 41 {
        t.uint(&f::DNS_RESP_CLASS, name_end + 2, 2, u64::from(class));
    } else {
        t.add(&f::DNS_RESP_CLASS, name_end + 2, 2, FieldValue::U64(u64::from(class)), || {
            format!("{} (0x{class:04x})", names::dns_class(class))
        });
        t.add(&f::DNS_RESP_TTL, name_end + 4, 4, FieldValue::U64(u64::from(ttl)), || format!("{ttl} ({})", human_ttl(ttl)));
    }
    t.uint(&f::DNS_RESP_LEN, name_end + 8, 2, u64::from(rdlen));
    let rdata = message.msg.get(rdata_at - message.base..rdata_at - message.base + usize::from(rdlen)).unwrap_or(&[]);
    match rtype {
        1 if rdlen == 4 => {
            let mut b = [0u8; 4];
            b.copy_from_slice(rdata);
            t.ipv4(&f::DNS_A, rdata_at, b);
        }
        28 if rdlen == 16 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(rdata);
            t.ipv6(&f::DNS_AAAA, rdata_at, b);
        }
        5 => t.string(&f::DNS_CNAME, rdata_at, rdata.len(), &text),
        2 => t.string(&f::DNS_NS, rdata_at, rdata.len(), &text),
        12 => t.string(&f::DNS_PTR, rdata_at, rdata.len(), &text),
        15 => t.string(&f::DNS_MX, rdata_at, rdata.len(), &text),
        16 => t.string(&f::DNS_TXT, rdata_at, rdata.len(), &text),
        33 => t.string(&f::DNS_SRV_TARGET, rdata_at, rdata.len(), &text),
        6 => t.string(&f::DNS_SOA_MNAME, rdata_at, rdata.len(), &text),
        _ if !rdata.is_empty() => t.bytes(&f::DNS_RDATA, rdata_at, rdata),
        _ => {}
    }
    t.close();
    Ok(Answer { rtype, text })
}

fn human_ttl(ttl: u32) -> String {
    let (d, h, mi, s) = (ttl / 86_400, (ttl / 3600) % 24, (ttl / 60) % 60, ttl % 60);
    let mut parts = Vec::new();
    if d > 0 {
        parts.push(format!("{d} day{}", if d == 1 { "" } else { "s" }));
    }
    if h > 0 {
        parts.push(format!("{h} hour{}", if h == 1 { "" } else { "s" }));
    }
    if mi > 0 {
        parts.push(format!("{mi} minute{}", if mi == 1 { "" } else { "s" }));
    }
    if s > 0 || parts.is_empty() {
        parts.push(format!("{s} second{}", if s == 1 { "" } else { "s" }));
    }
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_and_compressed_names() {
        let mut msg = vec![0u8; 12];
        msg.extend_from_slice(b"\x03www\x07example\x03com\x00");
        let ptr_at = msg.len();
        msg.extend_from_slice(&[0xc0, 12]);
        msg.extend_from_slice(b"\x03api\xc0\x10");
        assert_eq!(read_name(&msg, 12), Some(("www.example.com".into(), 17)));
        assert_eq!(read_name(&msg, ptr_at), Some(("www.example.com".into(), 2)));
        assert_eq!(read_name(&msg, ptr_at + 2), Some(("api.example.com".into(), 6)));
    }

    #[test]
    fn pointer_loops_and_forward_pointers_are_rejected() {
        let msg = [0xc0u8, 0x00];
        assert_eq!(read_name(&msg, 0), None);
        let msg = [0xc0u8, 0x02, 0x00];
        assert_eq!(read_name(&msg, 0), None);
        let msg = [0x05u8, b'a'];
        assert_eq!(read_name(&msg, 0), None);
        let msg = [0x80u8, 0x00];
        assert_eq!(read_name(&msg, 0), None);
    }

    #[test]
    fn root_and_escaping() {
        assert_eq!(read_name(&[0], 0), Some(("<Root>".into(), 1)));
        assert_eq!(read_name(b"\x03a.b\x00", 0), Some(("a\\.b".into(), 5)));
        assert_eq!(read_name(b"\x01\x07\x00", 0), Some(("\\007".into(), 3)));
    }

    #[test]
    fn overlong_names_rejected() {
        let mut msg = Vec::new();
        for _ in 0..5 {
            msg.push(63);
            msg.extend_from_slice(&[b'a'; 63]);
        }
        msg.push(0);
        assert_eq!(read_name(&msg, 0), None);
    }

    #[test]
    fn ttl_text() {
        assert_eq!(human_ttl(0), "0 seconds");
        assert_eq!(human_ttl(3661), "1 hour, 1 minute, 1 second");
    }
}
