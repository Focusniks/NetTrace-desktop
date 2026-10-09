use std::net::Ipv4Addr;

use nettrace_model::{FieldValue, ProtocolId, Transport};
use nettrace_packet::MacAddr;

use crate::context::{m, Ctx, Malformed};
use crate::fields as f;
use crate::format;
use crate::names;
use crate::registry::{AppDissector, Layer};

pub struct Dhcp;
pub static DHCP: Dhcp = Dhcp;

const P: ProtocolId = ProtocolId::Dhcp;
const MAGIC: u32 = 0x6382_5363;
const MAX_OPTIONS: usize = 255;

impl AppDissector for Dhcp {
    fn protocol(&self) -> ProtocolId {
        P
    }

    fn udp_ports(&self) -> &'static [u16] {
        &[67, 68]
    }

    fn accepts(&self, payload: &[u8], transport: Transport) -> bool {
        transport == Transport::Udp && payload.len() >= 236 && matches!(payload[0], 1 | 2)
    }

    fn dissect(&self, ctx: &mut Ctx, layer: Layer, _transport: Transport) -> Result<(), Malformed> {
        let mut c = layer.cursor();
        let start = c.offset();
        let op = c.u8().map_err(m(P))?;
        let htype = c.u8().map_err(m(P))?;
        let hlen = c.u8().map_err(m(P))?;
        let hops = c.u8().map_err(m(P))?;
        let xid = c.be_u32().map_err(m(P))?;
        let secs = c.be_u16().map_err(m(P))?;
        let flags = c.be_u16().map_err(m(P))?;
        let ciaddr = c.array::<4>().map_err(m(P))?;
        let yiaddr = c.array::<4>().map_err(m(P))?;
        let siaddr = c.array::<4>().map_err(m(P))?;
        let giaddr = c.array::<4>().map_err(m(P))?;
        let chaddr = c.array::<16>().map_err(m(P))?;
        let sname = c.take(64).map_err(m(P))?;
        let file = c.take(128).map_err(m(P))?;

        let t = &mut ctx.tree;
        t.open(&f::DHCP, start, layer.len());
        t.heading(|| "Dynamic Host Configuration Protocol".to_owned());
        t.named(&f::DHCP_TYPE, start, 1, u64::from(op), if op == 1 { "Boot Request" } else { "Boot Reply" });
        t.named(&f::DHCP_HW_TYPE, start + 1, 1, u64::from(htype), if htype == 1 { "Ethernet" } else { "Unknown" });
        t.uint(&f::DHCP_HW_LEN, start + 2, 1, u64::from(hlen));
        t.uint(&f::DHCP_HOPS, start + 3, 1, u64::from(hops));
        t.hex(&f::DHCP_ID, start + 4, 4, u64::from(xid), 8);
        t.uint(&f::DHCP_SECS, start + 8, 2, u64::from(secs));
        t.add(&f::DHCP_FLAGS, start + 10, 2, FieldValue::U64(u64::from(flags)), || {
            format!("0x{flags:04x} ({})", if flags & 0x8000 != 0 { "Broadcast" } else { "Unicast" })
        });
        t.ipv4(&f::DHCP_CLIENT_IP, start + 12, ciaddr);
        t.ipv4(&f::DHCP_YOUR_IP, start + 16, yiaddr);
        t.ipv4(&f::DHCP_SERVER_IP, start + 20, siaddr);
        t.ipv4(&f::DHCP_RELAY_IP, start + 24, giaddr);
        if htype == 1 && hlen == 6 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&chaddr[..6]);
            t.mac(&f::DHCP_HW_MAC, start + 28, mac);
        }
        let sname_s = cstr(sname);
        if !sname_s.is_empty() {
            t.string(&f::DHCP_SERVER_NAME, start + 44, 64, &sname_s);
        } else {
            t.text(|| "Server host name not given".to_owned(), start + 44, 64);
        }
        let file_s = cstr(file);
        if !file_s.is_empty() {
            t.string(&f::DHCP_FILE, start + 108, 128, &file_s);
        } else {
            t.text(|| "Boot file name not given".to_owned(), start + 108, 128);
        }

        let mut msg_type = None;
        let mut hostname = None;
        if c.remaining() >= 4 {
            let cookie = c.be_u32().map_err(m(P))?;
            if cookie == MAGIC {
                t.add(&f::DHCP_COOKIE, start + 236, 4, FieldValue::U64(u64::from(cookie)), || "DHCP".to_owned());
                for _ in 0..MAX_OPTIONS {
                    if c.remaining() == 0 {
                        break;
                    }
                    let at = c.offset();
                    let code = c.u8().map_err(m(P))?;
                    if code == 0 {
                        continue;
                    }
                    if code == 255 {
                        t.open_text(|| "Option: (255) End".to_owned(), at, 1);
                        t.uint(&f::DHCP_OPTION, at, 1, 255);
                        t.close();
                        break;
                    }
                    let len = usize::from(c.u8().map_err(m(P))?);
                    let v = c.take(len).map_err(m(P))?;
                    let vat = at + 2;
                    t.open_text(|| format!("Option: ({code}) {}", names::dhcp_option(code)), at, len + 2);
                    t.uint(&f::DHCP_OPTION, at, 1, u64::from(code));
                    match code {
                        53 if len == 1 => {
                            msg_type = Some(v[0]);
                            t.named(&f::DHCP_MSG_TYPE, vat, 1, u64::from(v[0]), names::dhcp_message_type(v[0]));
                        }
                        1 if len == 4 => t.ipv4(&f::DHCP_SUBNET, vat, ip(v, 0)),
                        3 | 6 if len % 4 == 0 => {
                            let field = if code == 3 { &f::DHCP_ROUTER } else { &f::DHCP_DNS };
                            for i in 0..len / 4 {
                                t.ipv4(field, vat + i * 4, ip(v, i * 4));
                            }
                        }
                        50 if len == 4 => t.ipv4(&f::DHCP_REQUESTED_IP, vat, ip(v, 0)),
                        54 if len == 4 => t.ipv4(&f::DHCP_SERVER_ID, vat, ip(v, 0)),
                        51 if len == 4 => {
                            let lease = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
                            t.add(&f::DHCP_LEASE, vat, 4, FieldValue::U64(u64::from(lease)), || format!("{lease} s"));
                        }
                        12 => {
                            let s = format::text(v);
                            t.string(&f::DHCP_HOSTNAME, vat, len, &s);
                            hostname = Some(s);
                        }
                        15 => t.string(&f::DHCP_DOMAIN, vat, len, &format::text(v)),
                        60 => t.string(&f::DHCP_VENDOR, vat, len, &format::text(v)),
                        55 => {
                            for (i, p) in v.iter().enumerate() {
                                t.named(&f::DHCP_PARAM, vat + i, 1, u64::from(*p), names::dhcp_option(*p));
                            }
                        }
                        61 => t.bytes(&f::DHCP_CLIENT_ID, vat, v),
                        _ => t.bytes(&f::DATA_DATA, vat, v),
                    }
                    t.close();
                }
            }
        }
        t.close();

        let chaddr_mac = MacAddr([chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5]]);
        ctx.info.set(P, || {
            let kind = msg_type.map(names::dhcp_message_type).unwrap_or(if op == 1 { "Boot Request" } else { "Boot Reply" });
            let mut s = format!("DHCP {kind} - Transaction ID 0x{xid:08x}");
            if let Some(h) = &hostname {
                s.push_str(&format!(" ({h})"));
            } else if htype == 1 && op == 1 {
                s.push_str(&format!(" ({chaddr_mac})"));
            }
            if yiaddr != [0; 4] {
                s.push_str(&format!(", yiaddr {}", Ipv4Addr::from(yiaddr)));
            }
            s
        });
        Ok(())
    }
}

fn ip(v: &[u8], at: usize) -> [u8; 4] {
    [v[at], v[at + 1], v[at + 2], v[at + 3]]
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&x| x == 0).unwrap_or(b.len());
    format::text(&b[..end])
}
