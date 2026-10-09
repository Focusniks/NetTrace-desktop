//! Find the next/previous packet in a view matching a filter, a string or bytes.

use nettrace_model::{FieldValue, ProtocolId};
use nettrace_protocol::{dissect, DissectOptions};
use nettrace_query::Filter;
use nettrace_storage::CaptureFile;
use parking_lot::RwLock;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::error::{EngineError, Result};
use crate::fields::PacketFields;
use crate::frame::frame_context;
use crate::session::Shared;
use crate::view::{read_error, View};

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SearchQuery {
    /// Display filter expression (IP, port, protocol, domain … are expressed as filters by the UI).
    Filter { text: String },
    /// Text in packet bytes or in decoded field values (DNS names, HTTP host, TLS SNI).
    Text {
        text: String,
        #[serde(default)]
        case_sensitive: bool,
    },
    /// Byte sequence, e.g. `16 03 01` or `160301`.
    Hex { text: String },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchRequest {
    pub view_id: u64,
    /// Row to start after; `None` starts at the beginning (or end when backwards).
    pub from_row: Option<u32>,
    #[serde(default)]
    pub backwards: bool,
    pub query: SearchQuery,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchHit {
    pub row: u32,
    pub number: u32,
    pub wrapped: bool,
}

enum Matcher {
    Filter(Filter),
    Text { needle: Vec<u8>, case_sensitive: bool },
    Bytes(Vec<u8>),
}

fn find(hay: &[u8], needle: &[u8], case_sensitive: bool) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    if case_sensitive {
        hay.windows(needle.len()).any(|w| w == needle)
    } else {
        hay.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
    }
}

pub fn parse_hex(text: &str) -> Option<Vec<u8>> {
    let digits: String = text.chars().filter(|c| !c.is_whitespace() && !matches!(c, ':' | '-')).collect();
    let digits = digits.strip_prefix("0x").unwrap_or(&digits);
    if digits.is_empty() || !digits.len().is_multiple_of(2) {
        return None;
    }
    (0..digits.len()).step_by(2).map(|i| u8::from_str_radix(digits.get(i..i + 2)?, 16).ok()).collect()
}

const DECODED: [ProtocolId; 4] = [ProtocolId::Dns, ProtocolId::Http, ProtocolId::Tls, ProtocolId::Dhcp];

fn matches(sh: &Shared, file: &CaptureFile, index: u32, m: &Matcher) -> Result<bool> {
    let Some(meta) = sh.index.get(index) else { return Ok(false) };
    match m {
        Matcher::Filter(f) => {
            let mut fields = PacketFields::new(sh, file, index, meta);
            let hit = f.matches(&mut fields);
            match fields.take_read_error() {
                Some(e) => Err(read_error(index, &e)),
                None => Ok(hit),
            }
        }
        Matcher::Bytes(needle) => {
            let bytes = file.read(meta).map_err(|e| read_error(index, &e))?;
            Ok(find(&bytes, needle, true))
        }
        Matcher::Text { needle, case_sensitive } => {
            let bytes = file.read(meta).map_err(|e| read_error(index, &e))?;
            if find(&bytes, needle, *case_sensitive) {
                return Ok(true);
            }
            // DNS names are length-prefixed on the wire; check decoded values too.
            if !DECODED.iter().any(|p| meta.protocols & p.bit() != 0) {
                return Ok(false);
            }
            let fctx = frame_context(sh, index);
            Ok(dissect(&bytes, &fctx, DissectOptions::VALUES).values.iter().any(|(_, v)| match v {
                FieldValue::Str(s) => find(s.as_bytes(), needle, *case_sensitive),
                _ => false,
            }))
        }
    }
}

const CHUNK: usize = 4096;

pub fn search(
    data: &RwLock<Shared>,
    file: &CaptureFile,
    view: &View,
    req: &SearchRequest,
    compile: impl Fn(&str) -> Result<Filter>,
    keep_going: &(dyn Fn() -> bool + Sync),
) -> Result<Option<SearchHit>> {
    let matcher = match &req.query {
        SearchQuery::Filter { text } => Matcher::Filter(compile(text)?),
        SearchQuery::Text { text, case_sensitive } => {
            if text.is_empty() {
                return Err(EngineError::new("invalid_search", "empty search text"));
            }
            Matcher::Text { needle: text.as_bytes().to_vec(), case_sensitive: *case_sensitive }
        }
        SearchQuery::Hex { text } => {
            Matcher::Bytes(parse_hex(text).ok_or_else(|| EngineError::new("invalid_hex", "invalid hex byte sequence"))?)
        }
    };
    let len = view.len(&data.read());
    if len == 0 {
        return Ok(None);
    }
    // Rows in search order, wrapping around once.
    let order: Box<dyn Iterator<Item = (u32, bool)>> = if req.backwards {
        let start = req.from_row.map_or(len, |r| r.min(len));
        Box::new((0..start).rev().map(|r| (r, false)).chain((start..len).rev().map(|r| (r, true))))
    } else {
        let start = req.from_row.map_or(0, |r| r.saturating_add(1).min(len));
        Box::new((start..len).map(|r| (r, false)).chain((0..start).map(|r| (r, true))))
    };
    let mut chunk = Vec::with_capacity(CHUNK);
    let mut order = order.peekable();
    while order.peek().is_some() {
        if !keep_going() {
            return Err(EngineError::cancelled());
        }
        chunk.clear();
        chunk.extend(order.by_ref().take(CHUNK));
        // Lock per chunk so a long search does not stall indexing.
        let sh = data.read();
        let results: Vec<Result<bool>> = chunk
            .par_iter()
            .map(|(row, _)| match view.packet_at(&sh, *row) {
                Some(index) => matches(&sh, file, index, &matcher),
                None => Ok(false),
            })
            .collect();
        for (pos, r) in results.into_iter().enumerate() {
            if r? {
                let (row, wrapped) = chunk[pos];
                let number = view.packet_at(&sh, row).unwrap_or(0) + 1;
                return Ok(Some(SearchHit { row, number, wrapped }));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_parsing() {
        assert_eq!(parse_hex("16 03 01"), Some(vec![0x16, 3, 1]));
        assert_eq!(parse_hex("0x160301"), Some(vec![0x16, 3, 1]));
        assert_eq!(parse_hex("aa:bb"), Some(vec![0xaa, 0xbb]));
        assert_eq!(parse_hex("abc"), None);
        assert_eq!(parse_hex("zz"), None);
        assert_eq!(parse_hex(""), None);
    }

    #[test]
    fn substring_search() {
        assert!(find(b"Host: API.example.com", b"api.example", false));
        assert!(!find(b"Host: API.example.com", b"api.example", true));
        assert!(!find(b"ab", b"abc", false));
    }
}
