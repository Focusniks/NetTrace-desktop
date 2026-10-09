use nettrace_model::{tcp_analysis as ta, FieldValue, ProtocolId, Severity, Transport};
use nettrace_packet::Cursor;

use crate::context::{m, Ctx, Malformed, TcpInfo, TransportInfo};
use crate::fields::{self as f, Field};
use crate::format::{self, bits};
use crate::registry::{Dissector, Handoff, Layer};
use crate::tcp_flags as fl;
use crate::tree::Tree;

pub struct Tcp;
pub static TCP: Tcp = Tcp;

const P: ProtocolId = ProtocolId::Tcp;
const MAX_OPTIONS: usize = 40;

/// `SYN, ACK` style list of set flags (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, AE).
pub fn flags_string(flags: u16) -> String {
    const NAMES: [(u16, &str); 9] = [
        (fl::FIN, "FIN"),
        (fl::SYN, "SYN"),
        (fl::RST, "RST"),
        (fl::PSH, "PSH"),
        (fl::ACK, "ACK"),
        (fl::URG, "URG"),
        (fl::ECE, "ECE"),
        (fl::CWR, "CWR"),
        (fl::AE, "AE"),
    ];
    let set: Vec<&str> = NAMES.iter().filter(|(b, _)| flags & b != 0).map(|(_, n)| *n).collect();
    if set.is_empty() { "<None>".to_owned() } else { set.join(", ") }
}

/// Flag → (field, info prefix, severity). Fast retransmission is listed first
/// because it supersedes the plain retransmission label.
const ANALYSIS: [(u16, &Field, &str, Severity); 10] = [
    (ta::FAST_RETRANSMISSION, &f::TCP_ANALYSIS_FAST_RETRANS, "[TCP Fast Retransmission]", Severity::Note),
    (ta::RETRANSMISSION, &f::TCP_ANALYSIS_RETRANS, "[TCP Retransmission]", Severity::Note),
    (ta::OUT_OF_ORDER, &f::TCP_ANALYSIS_OOO, "[TCP Out-Of-Order]", Severity::Warning),
    (ta::LOST_SEGMENT, &f::TCP_ANALYSIS_LOST, "[TCP Previous segment not captured]", Severity::Warning),
    (ta::ACKED_UNSEEN, &f::TCP_ANALYSIS_ACKED_UNSEEN, "[TCP ACKed unseen segment]", Severity::Warning),
    (ta::DUPLICATE_ACK, &f::TCP_ANALYSIS_DUP_ACK, "[TCP Dup ACK]", Severity::Note),
    (ta::ZERO_WINDOW, &f::TCP_ANALYSIS_ZERO_WINDOW, "[TCP ZeroWindow]", Severity::Warning),
    (ta::KEEP_ALIVE, &f::TCP_ANALYSIS_KEEP_ALIVE, "[TCP Keep-Alive]", Severity::Note),
    (ta::WINDOW_UPDATE, &f::TCP_ANALYSIS_WINDOW_UPDATE, "[TCP Window Update]", Severity::Note),
    (ta::PORT_REUSE, &f::TCP_ANALYSIS_PORT_REUSE, "[TCP Port numbers reused]", Severity::Note),
];

fn analysis_prefix(flags: u16) -> String {
    let mut out = String::new();
    let mut flags = flags;
    if flags & ta::FAST_RETRANSMISSION != 0 {
        flags &= !ta::RETRANSMISSION;
    }
    for (bit, _, label, _) in ANALYSIS {
        if flags & bit != 0 {
            out.push_str(label);
            out.push(' ');
        }
    }
    out
}

#[derive(Default)]
struct Options {
    mss: Option<u16>,
    wscale: Option<u8>,
    sack_perm: bool,
    ts: Option<(u32, u32)>,
}

fn parse_options(t: &mut Tree, mut c: Cursor) -> Result<Options, Malformed> {
    let mut o = Options::default();
    for _ in 0..MAX_OPTIONS {
        if c.remaining() == 0 {
            break;
        }
        let at = c.offset();
        let kind = c.u8().map_err(m(P))?;
        match kind {
            0 => {
                t.text(|| "End of Option List (EOL)".to_owned(), at, 1);
                break;
            }
            1 => {
                t.text(|| "No-Operation (NOP)".to_owned(), at, 1);
                continue;
            }
            _ => {}
        }
        let len = usize::from(c.u8().map_err(m(P))?);
        if len < 2 {
            return Err(Malformed::at(P, at + 1));
        }
        let mut v = c.sub(len - 2).map_err(m(P))?;
        match (kind, len) {
            (2, 4) => {
                let mss = v.be_u16().map_err(m(P))?;
                o.mss = Some(mss);
                t.open(&f::TCP_OPT, at, len);
                t.heading(|| format!("Maximum segment size: {mss} bytes"));
                t.uint(&f::TCP_OPT_MSS, at + 2, 2, u64::from(mss));
                t.close();
            }
            (3, 3) => {
                let shift = v.u8().map_err(m(P))?;
                o.wscale = Some(shift.min(14));
                let mult = 1u32 << shift.min(14);
                t.open(&f::TCP_OPT, at, len);
                t.heading(|| format!("Window scale: {shift} (multiply by {mult})"));
                t.uint(&f::TCP_OPT_WSCALE, at + 2, 1, u64::from(shift));
                t.close();
            }
            (4, 2) => {
                o.sack_perm = true;
                t.add(&f::TCP_OPT_SACK_PERM, at, 2, FieldValue::None, String::new);
            }
            (5, _) => {
                let n = (len - 2) / 8;
                t.open(&f::TCP_OPT_SACK, at, len);
                let mut blocks = Vec::new();
                for _ in 0..n {
                    let l = v.be_u32().map_err(m(P))?;
                    let r = v.be_u32().map_err(m(P))?;
                    blocks.push((l, r));
                }
                t.heading(|| {
                    let list: Vec<String> = blocks.iter().map(|(l, r)| format!("{l}-{r}")).collect();
                    format!("SACK: {}", list.join(" "))
                });
                t.close();
            }
            (8, 10) => {
                let tsval = v.be_u32().map_err(m(P))?;
                let tsecr = v.be_u32().map_err(m(P))?;
                o.ts = Some((tsval, tsecr));
                t.open(&f::TCP_OPT, at, len);
                t.heading(|| format!("Timestamps: TSval {tsval}, TSecr {tsecr}"));
                t.uint(&f::TCP_OPT_TSVAL, at + 2, 4, u64::from(tsval));
                t.uint(&f::TCP_OPT_TSECR, at + 6, 4, u64::from(tsecr));
                t.close();
            }
            _ => {
                t.text(|| format!("Unknown option (kind {kind}, length {len})"), at, len);
            }
        }
    }
    Ok(o)
}

impl Dissector for Tcp {
    fn protocol(&self) -> ProtocolId {
        P
    }

    fn dissect(&self, ctx: &mut Ctx, layer: Layer) -> Result<Handoff, Malformed> {
        let mut c = layer.cursor();
        let start = c.offset();
        let sport = c.be_u16().map_err(m(P))?;
        let dport = c.be_u16().map_err(m(P))?;
        let seq = c.be_u32().map_err(m(P))?;
        let ack = c.be_u32().map_err(m(P))?;
        let off_flags = c.be_u16().map_err(m(P))?;
        let window = c.be_u16().map_err(m(P))?;
        let checksum = c.be_u16().map_err(m(P))?;
        let urgent = c.be_u16().map_err(m(P))?;
        let hdr_len = usize::from(off_flags >> 12) * 4;
        let flags = off_flags & 0x01ff;
        ctx.summary.src_port = sport;
        ctx.summary.dst_port = dport;
        if hdr_len < 20 {
            return Err(Malformed::at(P, start + 12));
        }
        // Options cut by the capture length are parsed as far as captured.
        let opts_wanted = hdr_len - 20;
        let opts_avail = opts_wanted.min(c.remaining());
        let opts_cursor = c.sub(opts_avail).map_err(m(P))?;
        let opts_truncated = opts_avail < opts_wanted;
        let payload_start = start + hdr_len;
        let captured_payload = layer.end.saturating_sub(payload_start);
        // Sequence analysis needs the length on the wire, not what snaplen kept.
        let payload_len = match ctx.summary.ip_end {
            Some(end) if end >= payload_start => end - payload_start,
            _ => captured_payload,
        };

        let ann = ctx.frame.tcp.clone();
        let analysis = ann.as_ref().map(|a| a.analysis).unwrap_or(0);
        let rel_seq = match ann.as_ref().and_then(|a| a.seq_base) {
            Some(base) => seq.wrapping_sub(base),
            None => seq,
        };
        let has_ack = flags & fl::ACK != 0;
        let rel_ack = match ann.as_ref().and_then(|a| a.ack_base) {
            Some(base) if has_ack => ack.wrapping_sub(base),
            _ => ack,
        };
        let seg_len = payload_len as u32 + u32::from(flags & fl::SYN != 0) + u32::from(flags & fl::FIN != 0);

        let t = &mut ctx.tree;
        t.open(&f::TCP, start, hdr_len);
        t.heading(|| {
            let mut s = format!("Transmission Control Protocol, Src Port: {sport}, Dst Port: {dport}, Seq: {rel_seq}");
            if has_ack {
                s.push_str(&format!(", Ack: {rel_ack}"));
            }
            s.push_str(&format!(", Len: {payload_len}"));
            s
        });
        t.uint(&f::TCP_SRCPORT, start, 2, u64::from(sport));
        t.uint(&f::TCP_DSTPORT, start + 2, 2, u64::from(dport));
        if let Some(a) = &ann {
            let stream = a.stream;
            t.generated(&f::TCP_STREAM, FieldValue::U64(u64::from(stream)), || stream.to_string());
        }
        t.generated(&f::TCP_LEN, FieldValue::U64(payload_len as u64), || payload_len.to_string());
        let relative = ann.as_ref().is_some_and(|a| a.seq_base.is_some());
        t.add(&f::TCP_SEQ, start + 4, 4, FieldValue::U64(u64::from(rel_seq)), || {
            if relative { format!("{rel_seq}    (relative sequence number)") } else { rel_seq.to_string() }
        });
        t.uint(&f::TCP_SEQ_RAW, start + 4, 4, u64::from(seq));
        if seg_len > 0 {
            let next = rel_seq.wrapping_add(seg_len);
            t.generated(&f::TCP_NXTSEQ, FieldValue::U64(u64::from(next)), || {
                if relative { format!("{next}    (relative sequence number)") } else { next.to_string() }
            });
        }
        if has_ack {
            let rel_a = ann.as_ref().is_some_and(|a| a.ack_base.is_some());
            t.add(&f::TCP_ACK, start + 8, 4, FieldValue::U64(u64::from(rel_ack)), || {
                if rel_a { format!("{rel_ack}    (relative ack number)") } else { rel_ack.to_string() }
            });
            t.uint(&f::TCP_ACK_RAW, start + 8, 4, u64::from(ack));
        }
        let of = u64::from(off_flags);
        t.add(&f::TCP_HDR_LEN, start + 12, 1, FieldValue::U64(hdr_len as u64), || {
            format!("{} = Header Length: {hdr_len} bytes ({})", bits(of >> 8, 0xf0, 8), hdr_len / 4)
        });
        t.open_value(&f::TCP_FLAGS, start + 12, 2, FieldValue::U64(u64::from(flags)), || {
            format!("0x{flags:03x} ({})", flags_string(flags))
        });
        if t.enabled() {
            let flag_bits: [(&'static Field, u16, &str); 9] = [
                (&f::TCP_FLAGS_AE, fl::AE, "Accurate ECN"),
                (&f::TCP_FLAGS_CWR, fl::CWR, "Congestion Window Reduced"),
                (&f::TCP_FLAGS_ECE, fl::ECE, "ECN-Echo"),
                (&f::TCP_FLAGS_URG, fl::URG, "Urgent"),
                (&f::TCP_FLAGS_ACK, fl::ACK, "Acknowledgment"),
                (&f::TCP_FLAGS_PSH, fl::PSH, "Push"),
                (&f::TCP_FLAGS_RST, fl::RST, "Reset"),
                (&f::TCP_FLAGS_SYN, fl::SYN, "Syn"),
                (&f::TCP_FLAGS_FIN, fl::FIN, "Fin"),
            ];
            t.flag(&f::TCP_FLAGS_RES, start + 12, 2, off_flags & 0x0e00 != 0, || {
                format!("{} Reserved", bits(of & 0x0fff, 0x0e00, 12))
            });
            for (field, bit, name) in flag_bits {
                t.flag(field, start + 12, 2, flags & bit != 0, || {
                    format!("{} {name}", bits(u64::from(flags), u64::from(bit), 12))
                });
            }
            let letters = flag_letters(flags);
            t.generated(&f::TCP_FLAGS_STR, FieldValue::Str(letters.clone()), || letters);
        }
        t.close();
        t.uint(&f::TCP_WINDOW_VALUE, start + 14, 2, u64::from(window));
        let shift = ann.as_ref().and_then(|a| a.window_shift);
        if let Some(shift) = shift.filter(|_| flags & fl::SYN == 0) {
            let calc = u64::from(window) << shift;
            t.generated(&f::TCP_WINDOW_SIZE, FieldValue::U64(calc), || calc.to_string());
            let factor = 1i64 << shift;
            t.generated(&f::TCP_WINDOW_SCALE, FieldValue::I64(factor), || factor.to_string());
        }
        t.add(&f::TCP_CHECKSUM, start + 16, 2, FieldValue::U64(u64::from(checksum)), || {
            format!("0x{checksum:04x} [unverified]")
        });
        t.uint(&f::TCP_URGENT, start + 18, 2, u64::from(urgent));

        let options = if hdr_len > 20 {
            t.open(&f::TCP_OPTIONS, start + 20, hdr_len - 20);
            let n = hdr_len - 20;
            t.heading(|| format!("Options: ({})", format::plural_bytes(n)));
            let parsed = parse_options(t, opts_cursor);
            if opts_truncated {
                t.expert(&f::TCP_OPTIONS, Severity::Warning, || "[Options truncated by the capture length]".to_owned());
            }
            if parsed.is_err() {
                t.expert(&f::TCP_OPTIONS, Severity::Warning, || "[Malformed TCP options]".to_owned());
            }
            t.close();
            parsed.unwrap_or_default()
        } else {
            Options::default()
        };

        if let Some(a) = &ann {
            if t.enabled() {
                let since = a.time_since_first_ns;
                t.open_text(|| "[Timestamps]".to_owned(), 0, 0);
                t.mark_generated();
                t.generated(&f::TCP_TIME_RELATIVE, FieldValue::F64(since as f64 / 1e9), || format::seconds(since));
                t.close();
                if a.analysis != 0 || a.ack_rtt_ns.is_some() || a.acked_frame.is_some() {
                    t.open(&f::TCP_ANALYSIS, 0, 0);
                    t.mark_generated();
                    t.heading(|| "[SEQ/ACK analysis]".to_owned());
                    if let Some(frame) = a.acked_frame {
                        t.text(|| format!("[This is an ACK to the segment in frame: {frame}]"), 0, 0);
                    }
                    if let Some(rtt) = a.ack_rtt_ns {
                        t.generated(&f::TCP_ANALYSIS_ACK_RTT, FieldValue::F64(rtt as f64 / 1e9), || format::seconds(rtt));
                    }
                    if a.analysis != 0 {
                        t.open(&f::TCP_ANALYSIS_FLAGS, 0, 0);
                        t.mark_generated();
                        t.heading(|| "[TCP Analysis Flags]".to_owned());
                        for (bit, field, label, sev) in ANALYSIS {
                            if a.analysis & bit != 0 {
                                t.expert(field, sev, || format!("{label} {}", field.name));
                            }
                        }
                        t.close();
                    }
                    t.close();
                }
            }
        }
        t.close();

        let retransmitted = analysis & ta::RETRANSMISSION != 0;
        if captured_payload > 0 {
            let payload = layer.frame.get(payload_start..layer.end).unwrap_or(&[]);
            if retransmitted {
                t.bytes(&f::TCP_SEGMENT_DATA, payload_start, payload);
            } else if t.full() {
                t.text(
                    || {
                        let mut s = format!("TCP payload ({})", format::plural_bytes(payload_len));
                        if captured_payload < payload_len {
                            s.push_str(&format!(" [{captured_payload} captured]"));
                        }
                        s
                    },
                    payload_start,
                    captured_payload,
                );
            } else {
                t.bytes(&f::TCP_PAYLOAD, payload_start, payload);
            }
        }

        ctx.summary.transport = Some(TransportInfo::Tcp(TcpInfo {
            seq,
            ack,
            flags,
            window,
            header_len: hdr_len as u8,
            payload_len: payload_len as u32,
            mss: options.mss,
            wscale: options.wscale,
            sack_perm: options.sack_perm,
        }));

        ctx.info.set(P, || {
            let mut s = analysis_prefix(analysis);
            s.push_str(&format!("{sport} → {dport} [{}] Seq={rel_seq}", flags_string(flags)));
            if has_ack {
                s.push_str(&format!(" Ack={rel_ack}"));
            }
            s.push_str(&format!(" Win={window} Len={payload_len}"));
            if let Some(mss) = options.mss {
                s.push_str(&format!(" MSS={mss}"));
            }
            if options.sack_perm {
                s.push_str(" SACK_PERM");
            }
            if let Some((tsval, tsecr)) = options.ts {
                s.push_str(&format!(" TSval={tsval} TSecr={tsecr}"));
            }
            if let Some(ws) = options.wscale {
                s.push_str(&format!(" WS={}", 1u32 << ws));
            }
            s
        });

        if captured_payload == 0 || retransmitted {
            return Ok(Handoff::Done);
        }
        Ok(Handoff::Payload { transport: Transport::Tcp, src_port: sport, dst_port: dport, start: payload_start, end: layer.end })
    }
}

/// `·······AP···` style string (`tcp.flags.str`).
fn flag_letters(flags: u16) -> String {
    const L: [(u16, char); 12] = [
        (0x800, 'R'),
        (0x400, 'R'),
        (0x200, 'R'),
        (fl::AE, 'A'),
        (fl::CWR, 'C'),
        (fl::ECE, 'E'),
        (fl::URG, 'U'),
        (fl::ACK, 'A'),
        (fl::PSH, 'P'),
        (fl::RST, 'R'),
        (fl::SYN, 'S'),
        (fl::FIN, 'F'),
    ];
    L.iter().map(|(b, ch)| if flags & b != 0 { *ch } else { '·' }).collect()
}

/// Helper for app dissectors: TCP analysis prefix is preserved when they set Info.
pub fn info_prefix(ctx: &Ctx) -> String {
    ctx.frame.tcp.as_ref().map(|a| analysis_prefix(a.analysis)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_text() {
        assert_eq!(flags_string(fl::SYN | fl::ACK), "SYN, ACK");
        assert_eq!(flags_string(fl::FIN | fl::PSH | fl::ACK), "FIN, PSH, ACK");
        assert_eq!(flags_string(0), "<None>");
        assert_eq!(flag_letters(fl::PSH | fl::ACK), "·······AP···");
    }

    #[test]
    fn fast_retransmission_label_supersedes() {
        let p = analysis_prefix(ta::RETRANSMISSION | ta::FAST_RETRANSMISSION);
        assert_eq!(p, "[TCP Fast Retransmission] ");
    }
}
