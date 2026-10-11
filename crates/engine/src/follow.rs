//! «Показать поток»: the application payload of a TCP or UDP stream, in
//! sequence order, page by page.
//!
//! TCP segments are put in order per direction ([`Reorder`]): duplicates and
//! retransmissions are dropped, overlaps cut, segments ahead of the expected
//! sequence number wait until the hole is filled; a hole that is not filled
//! in time is reported as a gap (lost segment). Only segment positions are
//! kept, the bytes are read from the capture file when emitted.

use base64::Engine as _;
use nettrace_flow::{seq_gt, seq_le, Flow};
use nettrace_model::{Direction, FollowChunk, FollowChunkKind, FollowDirection, FollowPage, StreamExport, Transport};
use nettrace_protocol::{dissect, tcp_flags, DissectOptions, FrameContext, TransportInfo};
use nettrace_storage::{CaptureFile, NONE};

use crate::error::Result;
use crate::session::Shared;
use crate::view::read_error;

/// Largest page (payload bytes) one request may ask for.
pub const MAX_PAGE: u32 = 1 << 20;
/// Segments waiting for an earlier hole before it is declared a gap.
const MAX_HELD: usize = 64;
/// Packets of a direction a held segment waits before its hole becomes a gap.
const HOLD_STEPS: u32 = 512;
/// Packets one request looks at (pure-ACK stretches cost time but no output).
const MAX_STEPS_PER_CALL: u32 = 100_000;
/// Output bytes between remembered positions, so a page far into the stream
/// does not replay it from the start.
const CHECKPOINT_EVERY: u64 = 1 << 20;
/// Packets between remembered positions: stretches without output (the other
/// direction, pure ACKs) still move the resume point forward.
const CHECKPOINT_STEPS: u64 = (MAX_STEPS_PER_CALL / 4) as u64;
const MAX_CHECKPOINTS: usize = 8192;
/// Tiny segments (keystrokes, crafted captures) are joined into one chunk up
/// to this size, so a page never carries one chunk per byte.
const SMALL_SEGMENT: usize = 128;
const JOINED_MAX: u32 = 4096;

/// A TCP segment with payload: where it is, not what it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Seg {
    pub packet: u32,
    pub seq: u32,
    /// Payload length on the wire.
    pub len: u32,
    /// Ordinal of the packet in its direction (for the hold timeout).
    pub step: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Event {
    /// Emit `seg`'s payload from byte `skip` on (bytes before it were already emitted).
    Emit { seg: Seg, skip: u32 },
    /// `len` bytes before the segment in `packet` were never seen.
    Gap { len: u32, packet: u32 },
}

/// Orders the segments of one direction.
#[derive(Debug, Clone, Default)]
pub(crate) struct Reorder {
    next: Option<u32>,
    held: Vec<Seg>,
}

impl Reorder {
    /// `start`: the sequence number of the first payload byte, when known (SYN + 1).
    pub fn new(start: Option<u32>) -> Self {
        Reorder { next: start, held: Vec::new() }
    }

    pub fn push(&mut self, seg: Seg, out: &mut Vec<Event>) {
        let next = *self.next.get_or_insert(seg.seq);
        if seg.len == 0 || seq_le(seg.seq.wrapping_add(seg.len), next) {
            return; // nothing new (retransmission, keep-alive)
        }
        if seq_gt(seg.seq, next) {
            // Ahead of a hole: wait for the missing bytes, keeping the longest copy.
            match self.held.iter_mut().find(|h| h.seq == seg.seq) {
                Some(h) if h.len >= seg.len => {}
                Some(h) => *h = seg,
                None => self.held.push(seg),
            }
            self.expire(seg.step, out);
            return;
        }
        out.push(Event::Emit { seg, skip: next.wrapping_sub(seg.seq) });
        self.next = Some(seg.seq.wrapping_add(seg.len));
        self.drain(out);
    }

    /// Emits held segments that now continue the stream.
    fn drain(&mut self, out: &mut Vec<Event>) {
        while let Some(next) = self.next {
            self.held.retain(|h| seq_gt(h.seq.wrapping_add(h.len), next));
            let Some(i) = self.held.iter().position(|h| seq_le(h.seq, next)) else { break };
            let h = self.held.swap_remove(i);
            out.push(Event::Emit { seg: h, skip: next.wrapping_sub(h.seq) });
            self.next = Some(h.seq.wrapping_add(h.len));
        }
    }

    /// Gives up on holes that waited too long or behind too many segments.
    fn expire(&mut self, step: u32, out: &mut Vec<Event>) {
        while self.held.len() > MAX_HELD || self.held.iter().any(|h| step.saturating_sub(h.step) > HOLD_STEPS) {
            self.skip_hole(out);
        }
    }

    /// Declares the hole before the lowest held segment a gap.
    fn skip_hole(&mut self, out: &mut Vec<Event>) {
        let Some(next) = self.next else { return };
        let Some(lowest) = self.held.iter().min_by_key(|h| h.seq.wrapping_sub(next)).copied() else { return };
        out.push(Event::Gap { len: lowest.seq.wrapping_sub(next), packet: lowest.packet });
        self.next = Some(lowest.seq);
        self.drain(out);
    }

    /// End of the stream: remaining holes are gaps.
    pub fn flush(&mut self, out: &mut Vec<Event>) {
        while !self.held.is_empty() {
            self.skip_hole(out);
        }
    }
}

/// State of one direction while following.
#[derive(Debug, Clone, Default)]
struct DirState {
    reorder: Reorder,
    /// Packets of this direction seen (hold timeout clock).
    steps: u32,
    /// Bytes of this direction emitted or skipped (relative position).
    pos: u64,
}

/// Position in a followed stream: resumable, cheap to clone.
#[derive(Debug, Clone)]
pub(crate) struct Cursor {
    /// Next packet of the flow chain to read, or the last one read when the
    /// chain had no successor yet (a live capture may extend it).
    packet: u32,
    read: bool,
    dirs: [DirState; 2],
    /// Payload bytes produced so far (the output offset).
    out: u64,
    /// Packets of the chain looked at.
    walked: u64,
    finished: bool,
}

impl Cursor {
    fn start(flow: &Flow) -> Self {
        let base = |d: usize| flow.tcp.as_deref().and_then(|t| t.dirs[d].base_seq).map(|b| b.wrapping_add(1));
        Cursor {
            packet: flow.first_packet(),
            read: false,
            dirs: [0, 1].map(|d| DirState { reorder: Reorder::new(base(d)), ..DirState::default() }),
            out: 0,
            walked: 0,
            finished: false,
        }
    }
}

/// Positions remembered for one (flow, direction filter).
#[derive(Debug, Default)]
pub(crate) struct FollowCache {
    key: Option<(u32, FollowDirection)>,
    checkpoints: Vec<Cursor>,
}

/// Why [`run`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// The sink asked to stop.
    Sink,
    /// The step budget of one call is used up; the cursor can continue.
    Budget,
    /// The end of the packets indexed so far; a live capture may add more.
    Waiting,
    /// The end of the stream.
    Finished,
}

/// A piece of output before paging; `offset` is its position in the output.
enum Piece<'a> {
    Data { dir: usize, packet: u32, pos: u64, offset: u64, bytes: &'a [u8] },
    Hole { kind: FollowChunkKind, dir: usize, packet: u32, pos: u64, offset: u64, len: u32 },
}

fn direction(dir: usize) -> Direction {
    if dir == 0 {
        Direction::C2s
    } else {
        Direction::S2c
    }
}

/// Payload of a packet: (sequence number, wire length, captured bytes).
fn payload<'b>(sh: &Shared, file: &CaptureFile, index: u32, buf: &'b mut Vec<u8>) -> Result<Option<(u32, u32, &'b [u8])>> {
    let Some(m) = sh.index.get(index) else { return Ok(None) };
    file.read_into(m.offset, m.caplen, buf).map_err(|e| read_error(index, &e))?;
    let fctx = FrameContext {
        number: index + 1,
        caplen: m.caplen,
        origlen: m.origlen,
        interface: m.interface,
        link_type: Some(sh.index.link_type(m.interface)),
        ..FrameContext::default()
    };
    let s = dissect(buf, &fctx, DissectOptions::TRANSPORT).summary;
    let (seq, wire) = match s.transport {
        Some(TransportInfo::Tcp(t)) => (t.seq.wrapping_add(u32::from(t.flags & tcp_flags::SYN != 0)), t.payload_len),
        Some(TransportInfo::Udp { payload_len }) => (0, payload_len),
        None => return Ok(None),
    };
    let data = s.payload.and_then(|(a, b)| buf.get(a..b)).unwrap_or(&[]);
    Ok(Some((seq, wire, data)))
}

/// Advances `cur`, calling `sink` for every piece, until `sink` returns false,
/// the chain ends, or the step budget is used.
#[allow(clippy::too_many_arguments)]
fn run(
    sh: &Shared,
    file: &CaptureFile,
    flow: &Flow,
    filter: FollowDirection,
    indexing: bool,
    cur: &mut Cursor,
    mut checkpoint: impl FnMut(&Cursor),
    sink: &mut dyn FnMut(Piece) -> bool,
) -> Result<Stop> {
    let wanted = |dir: usize| matches!((filter, dir), (FollowDirection::Both, _) | (FollowDirection::C2s, 0) | (FollowDirection::S2c, 1));
    let tcp = flow.transport == Transport::Tcp;
    let mut buf = Vec::new();
    let mut seg_buf = Vec::new();
    let mut events = Vec::new();
    let mut steps = 0;
    while !cur.finished {
        // The packet to read next (following the chain past the last one read).
        let packet = if cur.read {
            match sh.index.get(cur.packet).map(|m| m.next_in_flow) {
                Some(next) if next != NONE => next,
                _ => {
                    if indexing {
                        return Ok(Stop::Waiting); // more may arrive
                    }
                    // End of the stream: what is still held follows its gaps.
                    for (dir, d) in cur.dirs.iter_mut().enumerate() {
                        if !wanted(dir) {
                            continue;
                        }
                        d.reorder.flush(&mut events);
                        if !emit(sh, file, dir, d, &mut events, &mut seg_buf, &mut cur.out, sink)? {
                            return Ok(Stop::Sink);
                        }
                    }
                    cur.finished = true;
                    return Ok(Stop::Finished);
                }
            }
        } else {
            cur.packet
        };
        steps += 1;
        if steps > MAX_STEPS_PER_CALL {
            return Ok(Stop::Budget);
        }
        checkpoint(cur);
        cur.packet = packet;
        cur.read = true;
        cur.walked += 1;
        let Some(m) = sh.index.get(packet) else { continue };
        let dir = usize::from(m.reverse());
        if !wanted(dir) {
            continue;
        }
        let Some((seq, wire, data)) = payload(sh, file, packet, &mut buf)? else { continue };
        let d = &mut cur.dirs[dir];
        d.steps += 1;
        if tcp {
            d.reorder.push(Seg { packet, seq, len: wire, step: d.steps }, &mut events);
            if !emit(sh, file, dir, d, &mut events, &mut seg_buf, &mut cur.out, sink)? {
                return Ok(Stop::Sink);
            }
        } else if wire > 0 {
            // UDP: every datagram as it is.
            let (pos, offset) = (d.pos, cur.out);
            d.pos += u64::from(wire);
            cur.out += data.len() as u64;
            let mut more = sink(Piece::Data { dir, packet, pos, offset, bytes: data });
            if more && (data.len() as u32) < wire {
                let len = wire - data.len() as u32;
                let pos = pos + data.len() as u64;
                more = sink(Piece::Hole { kind: FollowChunkKind::NotCaptured, dir, packet, pos, offset: cur.out, len });
            }
            if !more {
                return Ok(Stop::Sink);
            }
        }
    }
    Ok(Stop::Finished)
}

/// Turns reorder events into pieces (reading the emitted segments' bytes).
#[allow(clippy::too_many_arguments)]
fn emit(
    sh: &Shared,
    file: &CaptureFile,
    dir: usize,
    d: &mut DirState,
    events: &mut Vec<Event>,
    buf: &mut Vec<u8>,
    out: &mut u64,
    sink: &mut dyn FnMut(Piece) -> bool,
) -> Result<bool> {
    // Stopping early leaves this cursor inconsistent; it is then discarded
    // (resumable state is only taken between packets).
    for e in events.drain(..) {
        let more = match e {
            Event::Gap { len, packet } => {
                let more = sink(Piece::Hole { kind: FollowChunkKind::Gap, dir, packet, pos: d.pos, offset: *out, len });
                d.pos += u64::from(len);
                more
            }
            Event::Emit { seg, skip } => {
                let data = payload(sh, file, seg.packet, buf)?.map_or(&[][..], |(_, _, data)| data);
                let captured = (data.len() as u32).min(seg.len);
                let bytes = data.get(skip as usize..captured as usize).unwrap_or(&[]);
                let mut more = true;
                if !bytes.is_empty() {
                    let offset = *out;
                    *out += bytes.len() as u64;
                    more = sink(Piece::Data { dir, packet: seg.packet, pos: d.pos, offset, bytes });
                }
                let missing = seg.len - skip.max(captured);
                if more && missing > 0 {
                    let pos = d.pos + bytes.len() as u64;
                    more = sink(Piece::Hole { kind: FollowChunkKind::NotCaptured, dir, packet: seg.packet, pos, offset: *out, len: missing });
                }
                d.pos += u64::from(seg.len - skip);
                more
            }
        };
        if !more {
            return Ok(false); // dropping the drain discards the remaining events
        }
    }
    Ok(true)
}

/// One page of the stream: up to `limit` payload bytes from output offset
/// `offset`, with the holes in between.
#[allow(clippy::too_many_arguments)]
pub(crate) fn page(
    sh: &Shared,
    file: &CaptureFile,
    flow_index: u32,
    flow: &Flow,
    filter: FollowDirection,
    offset: u64,
    limit: u32,
    indexing: bool,
    cache: &mut FollowCache,
) -> Result<FollowPage> {
    let limit = u64::from(limit.clamp(1, MAX_PAGE));
    if cache.key != Some((flow_index, filter)) {
        *cache = FollowCache { key: Some((flow_index, filter)), checkpoints: Vec::new() };
    }
    let mut cur = cache.checkpoints.iter().rev().find(|c| c.out <= offset).cloned().unwrap_or_else(|| Cursor::start(flow));
    let checkpoints = &mut cache.checkpoints;
    let remember = |c: &Cursor| {
        if checkpoints.last().is_none_or(|l| c.out >= l.out + CHECKPOINT_EVERY || c.walked >= l.walked + CHECKPOINT_STEPS) {
            checkpoints.push(c.clone());
            if checkpoints.len() > MAX_CHECKPOINTS {
                // Every other one: the spacing doubles, memory stays bounded.
                *checkpoints = checkpoints.iter().step_by(2).cloned().collect();
            }
        }
    };
    let mut chunks: Vec<(FollowChunk, Vec<u8>)> = Vec::new();
    // Holes wait for the data after them: a page that ends without more data
    // leaves them to the next page (which starts at their offset), so they
    // are never sent twice.
    let mut holes = Vec::new();
    let mut taken = 0u64;
    let mut sink = |piece: Piece| -> bool {
        match piece {
            Piece::Data { dir, packet, pos, offset: start, bytes } => {
                let end = start + bytes.len() as u64;
                if end <= offset {
                    return true; // before this page
                }
                chunks.extend(holes.drain(..).map(|h| (h, Vec::new())));
                let from = offset.saturating_sub(start) as usize;
                let to = bytes.len().min(from + (limit - taken) as usize);
                let part = &bytes[from..to];
                let at = start + from as u64;
                taken += part.len() as u64;
                if let Some((last, data)) = chunks.last_mut() {
                    let joins = last.kind == FollowChunkKind::Data && last.direction == direction(dir) && last.offset + u64::from(last.len) == at;
                    if joins && part.len() < SMALL_SEGMENT && last.len < JOINED_MAX {
                        data.extend_from_slice(part);
                        last.len += part.len() as u32;
                        return taken < limit;
                    }
                }
                let chunk = FollowChunk {
                    kind: FollowChunkKind::Data,
                    direction: direction(dir),
                    number: packet + 1,
                    offset: at,
                    stream_offset: pos + from as u64,
                    len: part.len() as u32,
                    data: None,
                };
                chunks.push((chunk, part.to_vec()));
            }
            Piece::Hole { kind, dir, packet, pos, offset: start, len } => {
                if start >= offset {
                    holes.push(FollowChunk { kind, direction: direction(dir), number: packet + 1, offset: start, stream_offset: pos, len, data: None });
                }
            }
        }
        taken < limit
    };
    let stop = run(sh, file, flow, filter, indexing, &mut cur, remember, &mut sink)?;
    if stop == Stop::Finished {
        chunks.extend(holes.drain(..).map(|h| (h, Vec::new())));
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let chunks = chunks
        .into_iter()
        .map(|(mut c, data)| {
            if c.kind == FollowChunkKind::Data {
                c.data = Some(b64.encode(data));
            }
            c
        })
        .collect();
    // `offset` comes from the UI: saturate rather than wrap.
    Ok(FollowPage { offset, next_offset: offset.saturating_add(taken), done: stop == Stop::Finished, waiting: stop == Stop::Waiting, chunks })
}

/// Writes the whole stream's payload (`Data` bytes only, holes skipped).
/// The caller makes sure indexing has finished.
pub(crate) fn write_all(sh: &Shared, file: &CaptureFile, flow: &Flow, filter: FollowDirection, w: &mut dyn std::io::Write) -> Result<StreamExport> {
    let mut cur = Cursor::start(flow);
    let (mut written, mut missing) = (0u64, 0u64);
    let mut failed = None;
    while !cur.finished {
        let mut sink = |piece: Piece| match piece {
            Piece::Data { bytes, .. } => match w.write_all(bytes) {
                Ok(()) => {
                    written += bytes.len() as u64;
                    true
                }
                Err(e) => {
                    failed = Some(e);
                    false
                }
            },
            Piece::Hole { len, .. } => {
                missing += u64::from(len);
                true
            }
        };
        run(sh, file, flow, filter, false, &mut cur, |_| {}, &mut sink)?;
        if let Some(e) = failed.take() {
            return Err(e.into());
        }
    }
    Ok(StreamExport { bytes: written, missing })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(packet: u32, seq: u32, len: u32) -> Seg {
        Seg { packet, seq, len, step: packet }
    }

    /// Pushes segments and returns (packet, skip) emitted and (len) gaps, in order.
    fn order(start: Option<u32>, segs: &[Seg], end: bool) -> Vec<String> {
        let mut r = Reorder::new(start);
        let mut out = Vec::new();
        for s in segs {
            r.push(*s, &mut out);
        }
        if end {
            r.flush(&mut out);
        }
        out.iter()
            .map(|e| match e {
                Event::Emit { seg, skip } => format!("#{}+{skip}", seg.packet),
                Event::Gap { len, packet } => format!("gap{len}@{packet}"),
            })
            .collect()
    }

    #[test]
    fn in_order_duplicates_and_overlaps() {
        assert_eq!(order(Some(100), &[seg(1, 100, 10), seg(2, 110, 10)], true), ["#1+0", "#2+0"]);
        // A retransmission of emitted bytes is dropped; an overlap emits only the new tail.
        assert_eq!(order(Some(100), &[seg(1, 100, 10), seg(2, 100, 10), seg(3, 105, 10)], true), ["#1+0", "#3+5"]);
    }

    #[test]
    fn out_of_order_segments_wait_for_the_hole() {
        assert_eq!(order(Some(100), &[seg(1, 110, 10), seg(2, 100, 10)], true), ["#2+0", "#1+0"]);
        // A hole never filled becomes a gap at the end.
        assert_eq!(order(Some(100), &[seg(1, 100, 10), seg(2, 130, 10)], true), ["#1+0", "gap20@2", "#2+0"]);
        // A stream that starts after the expected first byte (capture began late).
        assert_eq!(order(Some(100), &[seg(1, 150, 10)], true), ["gap50@1", "#1+0"]);
    }

    #[test]
    fn holes_are_given_up_after_the_hold_limits() {
        let mut segs = vec![seg(1, 100, 10)];
        // 2000 bytes missing, then a long run of later segments.
        segs.extend((0..70).map(|i| seg(2 + i, 2110 + i * 10, 10)));
        let out = order(Some(100), &segs, false);
        assert_eq!(out[0], "#1+0");
        assert_eq!(out[1], "gap2000@2");
        assert_eq!(out.len(), 2 + 70, "the gap is declared once, then everything flows: {out:?}");
    }

    #[test]
    fn sequence_numbers_wrap_around() {
        let start = u32::MAX - 4;
        assert_eq!(order(Some(start), &[seg(1, 5, 10), seg(2, start, 10)], true), ["#2+0", "#1+0"]);
    }

    #[test]
    fn any_order_of_duplicated_segments_gives_the_original_stream() {
        // Deterministic shuffles of 40 segments, some sent twice: no gaps, every byte once.
        for round in 0u32..50 {
            let mut segs: Vec<Seg> = (0..40).map(|i| seg(i, 1000 + i * 7, 7)).collect();
            let mut x = round.wrapping_mul(2_654_435_761).wrapping_add(1);
            for i in (1..segs.len()).rev() {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                segs.swap(i, x as usize % (i + 1));
            }
            let dup: Vec<Seg> = segs.iter().step_by(5).copied().collect();
            segs.extend(dup);
            for (step, s) in segs.iter_mut().enumerate() {
                s.step = step as u32;
            }
            let mut r = Reorder::new(Some(1000));
            let mut out = Vec::new();
            for s in &segs {
                r.push(*s, &mut out);
            }
            r.flush(&mut out);
            let mut covered = 1000u32;
            for e in &out {
                let Event::Emit { seg, skip } = e else { panic!("gap in round {round}: {out:?}") };
                assert_eq!(seg.seq + skip, covered);
                covered = seg.seq + seg.len;
            }
            assert_eq!(covered, 1000 + 40 * 7);
        }
    }
}
