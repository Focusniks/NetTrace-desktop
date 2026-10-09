//! TLS record layer and handshake metadata (ClientHello/ServerHello,
//! certificates, alerts). Encrypted content is shown as opaque data.
//! Records split across TCP segments are not reassembled in the MVP.

use nettrace_model::{FieldValue, ProtocolId, TimelineKind, Transport};
use nettrace_packet::Cursor;

use crate::app::x509;
use crate::context::{m, Ctx, Malformed};
use crate::fields as f;
use crate::format;
use crate::names;
use crate::registry::{AppDissector, Layer};
use crate::transport::tcp::info_prefix;
use crate::tree::Tree;

pub struct Tls;
pub static TLS: Tls = Tls;

const P: ProtocolId = ProtocolId::Tls;
const MAX_RECORD: usize = 16384 + 2048;
const MAX_RECORDS: usize = 128;
const MAX_HS_MESSAGES: usize = 32;
const MAX_LIST: usize = 512;

fn valid_header(ct: u8, ver: u16, len: usize) -> bool {
    (20..=24).contains(&ct) && (0x0300..=0x0304).contains(&ver) && len <= MAX_RECORD
}

fn looks_like_tls(p: &[u8]) -> bool {
    if p.len() < 5 {
        return false;
    }
    let ver = u16::from_be_bytes([p[1], p[2]]);
    let len = usize::from(u16::from_be_bytes([p[3], p[4]]));
    if !valid_header(p[0], ver, len) {
        return false;
    }
    // Require a plausible handshake for the heuristic to avoid false positives.
    p[0] != 22 || p.get(5).is_some_and(|t| matches!(t, 1 | 2 | 11 | 12 | 14 | 16 | 4))
}

#[derive(Default)]
struct Facts {
    messages: Vec<String>,
    sni: Option<String>,
    server_hello: Option<(u16, u16)>,
    client_hello: bool,
}

impl AppDissector for Tls {
    fn protocol(&self) -> ProtocolId {
        P
    }

    fn tcp_ports(&self) -> &'static [u16] {
        &[443, 465, 563, 636, 853, 989, 990, 992, 993, 995, 5061, 8443]
    }

    fn accepts(&self, _payload: &[u8], transport: Transport) -> bool {
        transport == Transport::Tcp
    }

    fn heuristic(&self, payload: &[u8], transport: Transport) -> bool {
        transport == Transport::Tcp && looks_like_tls(payload)
    }

    fn dissect(&self, ctx: &mut Ctx, layer: Layer, _transport: Transport) -> Result<(), Malformed> {
        let prefix = info_prefix(ctx);
        let data = layer.bytes();
        let start = layer.start;
        let mut facts = Facts::default();
        let t = &mut ctx.tree;
        t.open(&f::TLS, start, layer.len());
        t.heading(|| "Transport Layer Security".to_owned());
        let mut pos = 0usize;
        let mut result = Ok(());
        for _ in 0..MAX_RECORDS {
            if pos >= data.len() {
                break;
            }
            let rest = &data[pos..];
            let at = start + pos;
            if rest.len() < 5 {
                t.bytes(&f::TLS_SEGMENT, at, rest);
                facts.messages.push(if pos == 0 { "Continuation Data".into() } else { "[TLS segment data]".into() });
                break;
            }
            let ct = rest[0];
            let ver = u16::from_be_bytes([rest[1], rest[2]]);
            let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
            if !valid_header(ct, ver, len) {
                t.bytes(&f::TLS_SEGMENT, at, rest);
                facts.messages.push(if pos == 0 { "Continuation Data".into() } else { "Ignored Unknown Record".into() });
                break;
            }
            let available = len.min(rest.len() - 5);
            let fragment = &rest[5..5 + available];
            t.open(&f::TLS_RECORD, at, 5 + available);
            let heading_at = facts.messages.len();
            t.named(&f::TLS_RECORD_TYPE, at, 1, u64::from(ct), names::tls_content_type(ct));
            t.add(&f::TLS_RECORD_VERSION, at + 1, 2, FieldValue::U64(u64::from(ver)), || {
                format!("{} (0x{ver:04x})", names::tls_version(ver))
            });
            t.uint(&f::TLS_RECORD_LENGTH, at + 3, 2, len as u64);
            let frag_at = at + 5;
            match ct {
                20 => {
                    t.add(&f::TLS_CCS, frag_at, available, FieldValue::None, String::new);
                    facts.messages.push("Change Cipher Spec".into());
                }
                21 => {
                    if available == 2 {
                        let (level, desc) = (fragment[0], fragment[1]);
                        t.named(&f::TLS_ALERT_LEVEL, frag_at, 1, u64::from(level), if level == 1 { "Warning" } else { "Fatal" });
                        t.named(&f::TLS_ALERT_DESC, frag_at + 1, 1, u64::from(desc), names::tls_alert(desc));
                        facts.messages.push(format!("Alert (Level: {}, Description: {})", if level == 1 { "Warning" } else { "Fatal" }, names::tls_alert(desc)));
                    } else {
                        t.bytes(&f::TLS_APP_DATA, frag_at, fragment);
                        facts.messages.push("Encrypted Alert".into());
                    }
                }
                22 => {
                    if let Err(e) = handshake(t, fragment, frag_at, &mut facts) {
                        result = Err(e);
                    }
                }
                23 => {
                    t.bytes(&f::TLS_APP_DATA, frag_at, fragment);
                    facts.messages.push("Application Data".into());
                }
                _ => {
                    t.bytes(&f::DATA_DATA, frag_at, fragment);
                    facts.messages.push("Heartbeat".into());
                }
            }
            if available < len {
                t.text(
                    || format!("[Record continues in the next segment: {} of {len} bytes captured; reassembly is not supported]", available),
                    frag_at,
                    available,
                );
            }
            let summary = facts.messages.get(heading_at..).map(|m| m.join(", ")).unwrap_or_default();
            t.heading(|| {
                format!(
                    "{} Record Layer: {}{}",
                    names::tls_version(ver),
                    names::tls_content_type(ct),
                    if summary.is_empty() || ct != 22 { String::new() } else { format!(" Protocol: {summary}") }
                )
            });
            t.close();
            if result.is_err() {
                break;
            }
            pos += 5 + len;
        }
        t.close();

        let info = facts.messages.join(", ");
        ctx.info.set(P, || format!("{prefix}{info}"));
        if facts.client_hello {
            let sni = facts.sni.clone().unwrap_or_default();
            ctx.event(TimelineKind::TlsClientHello, || sni);
        } else if let Some((ver, suite)) = facts.server_hello {
            ctx.event(TimelineKind::TlsServerHello, || format!("{}, {}", names::tls_version(ver), names::cipher_suite(suite)));
        }
        result
    }
}

fn handshake(t: &mut Tree, fragment: &[u8], base: usize, facts: &mut Facts) -> Result<(), Malformed> {
    let mut c = Cursor::with_base(fragment, base);
    for _ in 0..MAX_HS_MESSAGES {
        if c.remaining() == 0 {
            break;
        }
        let at = c.offset();
        let rest = c.rest();
        let ty = rest[0];
        let len = if rest.len() >= 4 { u32::from_be_bytes([0, rest[1], rest[2], rest[3]]) as usize } else { usize::MAX };
        // Without decryption state, an unknown type or an implausible length
        // means the record carries an encrypted handshake message (e.g. Finished).
        if names::tls_handshake_type(ty) == "Unknown" || len > 0xffff {
            t.bytes(&f::TLS_ENCRYPTED_HS, at, rest);
            facts.messages.push("Encrypted Handshake Message".into());
            return Ok(());
        }
        c.skip(4).map_err(m(P))?;
        let body_len = len.min(c.remaining());
        let mut body = c.sub(body_len).map_err(m(P))?;
        let name = names::tls_handshake_type(ty);
        t.open(&f::TLS_HANDSHAKE, at, 4 + body_len);
        t.heading(|| format!("Handshake Protocol: {name}"));
        t.named(&f::TLS_HS_TYPE, at, 1, u64::from(ty), name);
        t.uint(&f::TLS_HS_LENGTH, at + 1, 3, len as u64);
        let r = match ty {
            1 => hello(t, &mut body, true, facts),
            2 => hello(t, &mut body, false, facts),
            11 => certificates(t, &mut body),
            _ => Ok(()),
        };
        if body_len < len {
            t.text(|| "[Handshake message continues in the next segment]".to_owned(), at, 0);
        }
        t.close();
        let label = match (ty, &facts.sni) {
            (1, Some(sni)) => format!("Client Hello (SNI={sni})"),
            _ => name.to_owned(),
        };
        facts.messages.push(label);
        r?;
        if body_len < len {
            break;
        }
    }
    Ok(())
}

fn hello(t: &mut Tree, c: &mut Cursor, client: bool, facts: &mut Facts) -> Result<(), Malformed> {
    let at = c.offset();
    let version = c.be_u16().map_err(m(P))?;
    t.add(&f::TLS_HS_VERSION, at, 2, FieldValue::U64(u64::from(version)), || {
        format!("{} (0x{version:04x})", names::tls_version(version))
    });
    let random_at = c.offset();
    let random = c.take(32).map_err(m(P))?;
    t.bytes(&f::TLS_HS_RANDOM, random_at, random);
    let sid_len = usize::from(c.u8().map_err(m(P))?);
    let sid_at = c.offset();
    let sid = c.take(sid_len).map_err(m(P))?;
    if !sid.is_empty() {
        t.bytes(&f::TLS_HS_SESSION_ID, sid_at, sid);
    }
    let mut selected_suite = 0u16;
    if client {
        facts.client_hello = true;
        let cs_len = usize::from(c.be_u16().map_err(m(P))?);
        let cs_at = c.offset();
        let mut cs = c.sub(cs_len).map_err(m(P))?;
        t.uint(&f::TLS_HS_CIPHERSUITES_LEN, cs_at - 2, 2, cs_len as u64);
        t.open_text(|| format!("Cipher Suites ({} suites)", cs_len / 2), cs_at, cs_len);
        for _ in 0..MAX_LIST {
            let Ok(s) = cs.be_u16() else { break };
            let o = cs.offset() - 2;
            t.add(&f::TLS_HS_CIPHERSUITE, o, 2, FieldValue::U64(u64::from(s)), || {
                format!("{} (0x{s:04x})", names::cipher_suite(s))
            });
        }
        t.close();
        let comp_len = usize::from(c.u8().map_err(m(P))?);
        c.skip(comp_len).map_err(m(P))?;
    } else {
        let s_at = c.offset();
        selected_suite = c.be_u16().map_err(m(P))?;
        let s = selected_suite;
        t.add(&f::TLS_HS_CIPHERSUITE, s_at, 2, FieldValue::U64(u64::from(s)), || {
            format!("{} (0x{s:04x})", names::cipher_suite(s))
        });
        let comp_at = c.offset();
        let comp = c.u8().map_err(m(P))?;
        t.uint(&f::TLS_HS_COMP, comp_at, 1, u64::from(comp));
    }
    let mut negotiated = version;
    if c.remaining() >= 2 {
        let ext_len = usize::from(c.be_u16().map_err(m(P))?);
        t.uint(&f::TLS_HS_EXT_LEN, c.offset() - 2, 2, ext_len as u64);
        let mut exts = c.sub(ext_len.min(c.remaining())).map_err(m(P))?;
        for _ in 0..MAX_LIST {
            if exts.remaining() < 4 {
                break;
            }
            let e_at = exts.offset();
            let ty = exts.be_u16().map_err(m(P))?;
            let len = usize::from(exts.be_u16().map_err(m(P))?);
            let mut v = exts.sub(len).map_err(m(P))?;
            let ename = names::tls_extension(ty);
            t.open_text(|| format!("Extension: {ename} (len={len})"), e_at, len + 4);
            t.named(&f::TLS_HS_EXT_TYPE, e_at, 2, u64::from(ty), ename);
            t.uint(&f::TLS_HS_EXT_LEN1, e_at + 2, 2, len as u64);
            match ty {
                0 if client && len >= 2 => {
                    let _list_len = v.be_u16().map_err(m(P))?;
                    while v.remaining() >= 3 {
                        let kind = v.u8().map_err(m(P))?;
                        let n = usize::from(v.be_u16().map_err(m(P))?);
                        let n_at = v.offset();
                        let name = v.take(n).map_err(m(P))?;
                        if kind == 0 {
                            let s = format::text(name);
                            t.string(&f::TLS_HS_SNI, n_at, n, &s);
                            facts.sni.get_or_insert(s);
                        }
                    }
                }
                16 if len >= 2 => {
                    let _list_len = v.be_u16().map_err(m(P))?;
                    while v.remaining() >= 1 {
                        let n = usize::from(v.u8().map_err(m(P))?);
                        let p_at = v.offset();
                        let p = v.take(n).map_err(m(P))?;
                        t.string(&f::TLS_HS_ALPN, p_at, n, &format::text(p));
                    }
                }
                43 => {
                    if client {
                        let n = usize::from(v.u8().map_err(m(P))?);
                        let mut list = v.sub(n).map_err(m(P))?;
                        while let Ok(sv) = list.be_u16() {
                            let o = list.offset() - 2;
                            t.add(&f::TLS_HS_SUPPORTED_VERSION, o, 2, FieldValue::U64(u64::from(sv)), || {
                                format!("{} (0x{sv:04x})", names::tls_version(sv))
                            });
                        }
                    } else if len == 2 {
                        let sv = v.be_u16().map_err(m(P))?;
                        negotiated = sv;
                        t.add(&f::TLS_HS_SUPPORTED_VERSION, e_at + 4, 2, FieldValue::U64(u64::from(sv)), || {
                            format!("{} (0x{sv:04x})", names::tls_version(sv))
                        });
                    }
                }
                10 if len >= 2 => {
                    let n = usize::from(v.be_u16().map_err(m(P))?);
                    let mut list = v.sub(n.min(v.remaining())).map_err(m(P))?;
                    while let Ok(g) = list.be_u16() {
                        let o = list.offset() - 2;
                        t.add(&f::TLS_HS_GROUP, o, 2, FieldValue::U64(u64::from(g)), || {
                            format!("{} (0x{g:04x})", names::tls_group(g))
                        });
                    }
                }
                13 if len >= 2 => {
                    let n = usize::from(v.be_u16().map_err(m(P))?);
                    let mut list = v.sub(n.min(v.remaining())).map_err(m(P))?;
                    while let Ok(a) = list.be_u16() {
                        let o = list.offset() - 2;
                        t.hex(&f::TLS_HS_SIG_ALG, o, 2, u64::from(a), 4);
                    }
                }
                _ => {}
            }
            t.close();
        }
    }
    if !client {
        facts.server_hello = Some((negotiated, selected_suite));
    }
    Ok(())
}

fn certificates(t: &mut Tree, c: &mut Cursor) -> Result<(), Malformed> {
    let at = c.offset();
    let total = c.be_u24().map_err(m(P))? as usize;
    t.uint(&f::TLS_HS_CERTS_LEN, at, 3, total as u64);
    let mut list = c.sub(total.min(c.remaining())).map_err(m(P))?;
    t.open_text(|| "Certificates".to_owned(), at + 3, total.min(list.len()));
    for _ in 0..MAX_LIST {
        if list.remaining() < 3 {
            break;
        }
        let len_at = list.offset();
        let len = list.be_u24().map_err(m(P))? as usize;
        let der_at = list.offset();
        let der = list.take(len.min(list.remaining())).map_err(m(P))?;
        t.uint(&f::TLS_HS_CERT_LEN, len_at, 3, len as u64);
        let facts = x509::parse(der);
        t.open_value(&f::TLS_HS_CERT, der_at, der.len(), FieldValue::Bytes(Vec::new()), || {
            match facts.as_ref().and_then(|f| f.subject_cn.clone()) {
                Some(cn) => format!("CN={cn} ({})", format::plural_bytes(len)),
                None => format::plural_bytes(len),
            }
        });
        if let Some(facts) = facts {
            if let Some(cn) = &facts.subject_cn {
                t.string(&f::X509_SUBJECT_CN, der_at, 0, cn);
            }
            if let Some(cn) = &facts.issuer_cn {
                t.string(&f::X509_ISSUER_CN, der_at, 0, cn);
            }
            if let Some(v) = &facts.not_before {
                t.string(&f::X509_NOT_BEFORE, der_at, 0, v);
            }
            if let Some(v) = &facts.not_after {
                t.string(&f::X509_NOT_AFTER, der_at, 0, v);
            }
            for name in &facts.dns_names {
                t.string(&f::X509_SAN, der_at, 0, name);
            }
        }
        t.close();
        if der.len() < len {
            break;
        }
    }
    t.close();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heuristic_requires_plausible_record() {
        assert!(looks_like_tls(&[22, 3, 1, 0, 5, 1, 0, 0, 1, 0]));
        assert!(!looks_like_tls(&[22, 3, 1, 0, 5, 99]));
        assert!(!looks_like_tls(&[25, 3, 3, 0, 1, 0]));
        assert!(!looks_like_tls(&[23, 3, 9, 0, 1, 0]));
        assert!(looks_like_tls(&[23, 3, 3, 0, 1, 0]));
    }
}
