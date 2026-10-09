//! Packet list views: the result of a display filter and/or a sort.

use std::cmp::Ordering;
use std::ops::Range;

use nettrace_model::ProtocolId;
use nettrace_query::Filter;
use nettrace_storage::{CaptureFile, PacketMeta};
use parking_lot::RwLock;
use rayon::prelude::*;
use serde::Deserialize;

use crate::error::{EngineError, Result};
use crate::fields::PacketFields;
use crate::session::Shared;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SortKey {
    Number,
    Time,
    Source,
    Destination,
    Protocol,
    Length,
    SrcPort,
    DstPort,
    Stream,
    TcpFlags,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SortSpec {
    pub key: SortKey,
    #[serde(default)]
    pub desc: bool,
}

#[derive(Debug, Clone)]
pub struct View {
    pub id: u64,
    /// Packet indices in display order; `None` = all packets in capture order
    /// (grows while indexing is still running).
    pub rows: Option<Vec<u32>>,
    /// True if `rows` is in capture order (enables binary search).
    pub ordered: bool,
}

impl View {
    pub fn all() -> Self {
        View { id: 0, rows: None, ordered: true }
    }

    pub fn len(&self, sh: &Shared) -> u32 {
        match &self.rows {
            Some(r) => r.len() as u32,
            None => sh.index.len(),
        }
    }

    pub fn packet_at(&self, sh: &Shared, row: u32) -> Option<u32> {
        match &self.rows {
            Some(r) => r.get(row as usize).copied(),
            None => (row < sh.index.len()).then_some(row),
        }
    }

    /// Row of packet `index` in this view, if visible.
    pub fn row_of(&self, sh: &Shared, index: u32) -> Option<u32> {
        match &self.rows {
            None => (index < sh.index.len()).then_some(index),
            Some(r) => {
                if self.ordered {
                    r.binary_search(&index).ok().map(|p| p as u32)
                } else {
                    r.iter().position(|i| *i == index).map(|p| p as u32)
                }
            }
        }
    }
}

const CHUNK: u32 = 8192;

pub fn read_error(index: u32, e: &std::io::Error) -> EngineError {
    EngineError::new("io", format!("packet {} could not be read from the capture file: {e}", index + 1))
}

/// Indices in `range` matching `filter`, evaluated in parallel.
///
/// The read lock is taken per chunk, so a long deep-field scan never blocks
/// the indexer (and, through writer priority, every other reader) for long.
pub fn filter_indices(
    data: &RwLock<Shared>,
    file: &CaptureFile,
    filter: &Filter,
    range: Range<u32>,
    keep_going: &(dyn Fn() -> bool + Sync),
) -> Result<Vec<u32>> {
    let chunks: Vec<Range<u32>> = (range.start..range.end)
        .step_by(CHUNK as usize)
        .map(|s| s..(s + CHUNK).min(range.end))
        .collect();
    let parts: Vec<Result<Vec<u32>>> = chunks
        .into_par_iter()
        .map(|r| {
            if !keep_going() {
                return Err(EngineError::cancelled());
            }
            let sh = data.read();
            let metas = sh.index.all();
            let mut out = Vec::new();
            for i in r {
                let Some(meta) = metas.get(i as usize) else { break };
                let mut src = PacketFields::new(&sh, file, i, meta);
                let hit = filter.matches(&mut src);
                // A packet that cannot be read would silently (mis)match; report it instead.
                if let Some(e) = src.take_read_error() {
                    return Err(read_error(i, &e));
                }
                if hit {
                    out.push(i);
                }
            }
            Ok(out)
        })
        .collect();
    let mut out = Vec::new();
    for p in parts {
        out.extend(p?);
    }
    Ok(out)
}

fn protocol_name(m: &PacketMeta) -> &'static str {
    ProtocolId::from_u8(m.top).map(|p| p.short_name()).unwrap_or("")
}

pub fn sort_rows(sh: &Shared, rows: &mut [u32], spec: SortSpec) {
    let metas = sh.index.all();
    let addrs = &sh.index.addrs;
    let stream = |m: &PacketMeta| m.flow().and_then(|f| sh.flows.flow(f)).map(|f| (f.transport, f.stream_id));
    let cmp = |a: &u32, b: &u32| -> Ordering {
        let (ma, mb) = (&metas[*a as usize], &metas[*b as usize]);
        let ord = match spec.key {
            SortKey::Number => a.cmp(b),
            SortKey::Time => ma.ts_ns.cmp(&mb.ts_ns),
            SortKey::Source => addrs.get(ma.src).cmp(&addrs.get(mb.src)),
            SortKey::Destination => addrs.get(ma.dst).cmp(&addrs.get(mb.dst)),
            SortKey::Protocol => protocol_name(ma).cmp(protocol_name(mb)),
            SortKey::Length => ma.origlen.cmp(&mb.origlen),
            SortKey::SrcPort => ma.sport.cmp(&mb.sport),
            SortKey::DstPort => ma.dport.cmp(&mb.dport),
            SortKey::Stream => stream(ma).cmp(&stream(mb)),
            SortKey::TcpFlags => ma.tcp_flags.cmp(&mb.tcp_flags),
        };
        let ord = if spec.desc { ord.reverse() } else { ord };
        ord.then_with(|| a.cmp(b))
    };
    rows.par_sort_by(cmp);
}
