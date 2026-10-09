//! HTTP/1.x request/response headers within a single TCP segment
//! (no stream reassembly in the MVP).

use nettrace_model::{FieldValue, ProtocolId, TimelineKind, Transport};

use crate::context::{Ctx, Malformed};
use crate::fields::{self as f, Field};
use crate::format;
use crate::registry::{AppDissector, Layer};
use crate::transport::tcp::info_prefix;

pub struct Http;
pub static HTTP: Http = Http;

const P: ProtocolId = ProtocolId::Http;
const METHODS: [&str; 9] = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"];
const MAX_LINES: usize = 256;

fn is_request(p: &[u8]) -> bool {
    METHODS.iter().any(|m| p.len() > m.len() && p.starts_with(m.as_bytes()) && p[m.len()] == b' ')
}

fn is_response(p: &[u8]) -> bool {
    p.len() >= 12 && p.starts_with(b"HTTP/1.") && p[8] == b' ' && p[9..12].iter().all(u8::is_ascii_digit)
}

fn header_field(name: &str) -> Option<&'static Field> {
    Some(match name.to_ascii_lowercase().as_str() {
        "host" => &f::HTTP_HOST,
        "user-agent" => &f::HTTP_USER_AGENT,
        "accept" => &f::HTTP_ACCEPT,
        "referer" => &f::HTTP_REFERER,
        "cookie" => &f::HTTP_COOKIE,
        "set-cookie" => &f::HTTP_SET_COOKIE,
        "content-type" => &f::HTTP_CONTENT_TYPE,
        "server" => &f::HTTP_SERVER,
        "location" => &f::HTTP_LOCATION,
        "connection" => &f::HTTP_CONNECTION,
        "authorization" => &f::HTTP_AUTHORIZATION,
        "transfer-encoding" => &f::HTTP_TRANSFER_ENCODING,
        _ => return None,
    })
}

/// Splits at the next line break; returns (line without CR/LF, bytes consumed).
fn next_line(data: &[u8]) -> Option<(&[u8], usize)> {
    let nl = data.iter().position(|&b| b == b'\n')?;
    let line = &data[..nl];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    Some((line, nl + 1))
}

impl AppDissector for Http {
    fn protocol(&self) -> ProtocolId {
        P
    }

    fn tcp_ports(&self) -> &'static [u16] {
        &[80, 3128, 8000, 8008, 8080, 8888]
    }

    fn accepts(&self, _payload: &[u8], transport: Transport) -> bool {
        transport == Transport::Tcp
    }

    fn heuristic(&self, payload: &[u8], transport: Transport) -> bool {
        transport == Transport::Tcp && (is_request(payload) || is_response(payload))
    }

    fn dissect(&self, ctx: &mut Ctx, layer: Layer, _transport: Transport) -> Result<(), Malformed> {
        let prefix = info_prefix(ctx);
        let data = layer.bytes();
        let start = layer.start;
        let request = is_request(data);
        let response = !request && is_response(data);
        let t = &mut ctx.tree;
        t.open(&f::HTTP, start, layer.len());
        t.heading(|| "Hypertext Transfer Protocol".to_owned());
        if !request && !response {
            t.bytes(&f::HTTP_CONTINUATION, start, data);
            t.close();
            ctx.info.set(P, || format!("{prefix}Continuation"));
            return Ok(());
        }

        let mut pos = 0usize;
        let mut first: Option<(String, String, String)> = None;
        let mut host: Option<String> = None;
        let mut content_type: Option<String> = None;
        let mut headers_complete = false;
        for i in 0..MAX_LINES {
            let Some((line, used)) = next_line(&data[pos..]) else { break };
            let at = start + pos;
            pos += used;
            if line.is_empty() {
                headers_complete = true;
                t.text(|| "\\r\\n".to_owned(), at, used);
                break;
            }
            let text = format::text(line);
            if i == 0 {
                // Split on raw bytes so field ranges point at the real bytes.
                let sp1 = line.iter().position(|&b| b == b' ').unwrap_or(line.len());
                let rest = line.get(sp1 + 1..).unwrap_or(&[]);
                let sp2 = rest.iter().position(|&b| b == b' ').map_or(line.len(), |p| sp1 + 1 + p);
                let (ra, rb, rc) = (
                    &line[..sp1],
                    line.get(sp1 + 1..sp2).unwrap_or(&[]),
                    line.get(sp2 + 1..).unwrap_or(&[]),
                );
                let (a_at, b_at, c_at) = (at, at + sp1 + 1, at + sp2 + 1);
                let (a, b, c) = (format::text(ra), format::text(rb), format::text(rc));
                let line_field = if request { &f::HTTP_REQUEST_LINE } else { &f::HTTP_RESPONSE_LINE };
                t.open_value(line_field, at, used, FieldValue::Str(text.clone()), || format!("{text}\\r\\n"));
                if request {
                    t.add(&f::HTTP_REQUEST, at, 0, FieldValue::Bool(true), || "True".to_owned());
                    t.string(&f::HTTP_METHOD, a_at, ra.len(), &a);
                    t.string(&f::HTTP_URI, b_at, rb.len(), &b);
                    t.string(&f::HTTP_REQ_VERSION, c_at, rc.len(), &c);
                } else {
                    t.add(&f::HTTP_RESPONSE, at, 0, FieldValue::Bool(true), || "True".to_owned());
                    t.string(&f::HTTP_RESP_VERSION, a_at, ra.len(), &a);
                    let code: u64 = b.parse().unwrap_or(0);
                    t.uint(&f::HTTP_CODE, b_at, rb.len(), code);
                    t.string(&f::HTTP_PHRASE, c_at, rc.len(), &c);
                }
                t.close();
                first = Some((a, b, c));
                continue;
            }
            let Some(colon) = text.find(':') else {
                t.text(|| text.clone(), at, used);
                continue;
            };
            let name = text[..colon].trim().to_owned();
            let value = text[colon + 1..].trim().to_owned();
            if name.eq_ignore_ascii_case("host") {
                host = Some(value.clone());
            }
            if name.eq_ignore_ascii_case("content-type") {
                content_type = Some(value.clone());
            }
            if name.eq_ignore_ascii_case("content-length") {
                if let Ok(n) = value.parse::<u64>() {
                    t.add(&f::HTTP_CONTENT_LENGTH, at, used, FieldValue::U64(n), || format!("{name}: {value}"));
                    continue;
                }
            }
            match header_field(&name) {
                Some(field) => t.add(field, at, used, FieldValue::Str(value.clone()), || format!("{name}: {value}")),
                None => t.text(|| format!("{name}: {value}"), at, used),
            }
        }
        if !headers_complete {
            t.text(|| "[Headers continue in the next segment; reassembly is not supported]".to_owned(), start + pos, 0);
        }
        let body = data.get(pos..).unwrap_or(&[]);
        if headers_complete && !body.is_empty() {
            let n = body.len();
            t.add(&f::HTTP_FILE_DATA, start + pos, n, FieldValue::Bytes(if t.full() { Vec::new() } else { body.to_vec() }), || {
                format::plural_bytes(n)
            });
        }
        t.close();

        let (a, b, c) = first.unwrap_or_default();
        if request {
            let (method, uri, version) = (a, b, c);
            ctx.info.set(P, || format!("{prefix}{method} {uri} {version}"));
            let host_s = host.unwrap_or_default();
            ctx.event(TimelineKind::HttpRequest, || format!("{method} {host_s}{uri}"));
        } else {
            let (version, code, phrase) = (a, b, c);
            ctx.info.set(P, || {
                let mut s = format!("{prefix}{version} {code} {phrase}");
                if let Some(ct) = &content_type {
                    s.push_str(&format!("  ({ct})"));
                }
                s
            });
            ctx.event(TimelineKind::HttpResponse, || format!("{code} {phrase}"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection() {
        assert!(is_request(b"GET / HTTP/1.1\r\n"));
        assert!(!is_request(b"GETX / HTTP/1.1\r\n"));
        assert!(is_response(b"HTTP/1.1 200 OK\r\n"));
        assert!(!is_response(b"HTTP/1.1 2x0 OK\r\n"));
        assert!(!is_response(b"HTTP/1.1"));
    }

    #[test]
    fn line_splitting() {
        assert_eq!(next_line(b"a\r\nb"), Some((&b"a"[..], 3)));
        assert_eq!(next_line(b"a\nb"), Some((&b"a"[..], 2)));
        assert_eq!(next_line(b"abc"), None);
    }
}
