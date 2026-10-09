//! Packet list rows and packet details.

use nettrace_model::{PacketDetail, PacketRow, ProtocolId};
use nettrace_packet::CastType;
use nettrace_protocol::{dissect, tcp_flags_string, tree, DissectOptions};
use nettrace_query::Filter;
use nettrace_storage::{CaptureFile, PacketMeta};

use crate::fields::PacketFields;
use crate::frame::{frame_context, stream_ref};
use crate::session::Shared;

fn cast_name(c: CastType) -> &'static str {
    match c {
        CastType::Unicast => "unicast",
        CastType::Multicast => "multicast",
        CastType::Broadcast => "broadcast",
        CastType::Unknown => "unknown",
    }
}

fn has(m: &PacketMeta, p: ProtocolId) -> bool {
    m.protocols & p.bit() != 0
}

pub fn build_row(
    sh: &Shared,
    file: &CaptureFile,
    index: u32,
    prev_ts: Option<i64>,
    colors: &[Option<Filter>],
    buf: &mut Vec<u8>,
) -> Option<PacketRow> {
    let m = sh.index.get(index)?;
    let read_error = file.read_into(m.offset, m.caplen, buf).is_err();
    if read_error {
        buf.clear();
    }
    let fctx = frame_context(sh, index);
    let info = if read_error { String::new() } else { dissect(buf, &fctx, DissectOptions::ROW).info };
    let addrs = &sh.index.addrs;
    let base = sh.index.first_ts().unwrap_or(m.ts_ns);
    let transport = has(m, ProtocolId::Tcp) || has(m, ProtocolId::Udp);
    let color_rule = if read_error { None } else { colors.iter().position(|rule| {
        rule.as_ref().is_some_and(|f| f.matches(&mut PacketFields::new(sh, file, index, m).with_data(buf)))
    }) };
    Some(PacketRow {
        number: index + 1,
        time_rel: m.ts_ns.saturating_sub(base) as f64 / 1e9,
        time_delta: prev_ts.map(|p| m.ts_ns.saturating_sub(p) as f64 / 1e9).unwrap_or(0.0),
        ts_sec: m.ts_ns.div_euclid(1_000_000_000),
        ts_nsec: m.ts_ns.rem_euclid(1_000_000_000) as u32,
        src: addrs.get(m.src).to_string(),
        dst: addrs.get(m.dst).to_string(),
        protocol: ProtocolId::from_u8(m.top).map(|p| p.short_name()).unwrap_or("").to_owned(),
        length: m.origlen,
        info,
        src_port: transport.then_some(m.sport),
        dst_port: transport.then_some(m.dport),
        tcp_flags: has(m, ProtocolId::Tcp).then(|| tcp_flags_string(m.tcp_flags)),
        stream: stream_ref(sh, index),
        cast: cast_name(addrs.get(m.dst).cast()),
        color_rule: color_rule.map(|c| c as u16),
        analysis: m.analysis,
        malformed: m.malformed(),
        read_error,
    })
}

pub fn packet_detail(sh: &Shared, file: &CaptureFile, index: u32) -> Option<std::io::Result<PacketDetail>> {
    let m = sh.index.get(index)?;
    Some(file.read(m).map(|bytes| {
        let fctx = frame_context(sh, index);
        let d = dissect(&bytes, &fctx, DissectOptions::FULL);
        PacketDetail { number: index + 1, tree: tree::to_model(&d.nodes), bytes, stream: stream_ref(sh, index) }
    }))
}
