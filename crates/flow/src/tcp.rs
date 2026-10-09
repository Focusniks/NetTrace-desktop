//! TCP sequence analysis (retransmissions, duplicate ACKs, out-of-order, RTT).

use std::collections::VecDeque;

use nettrace_model::{tcp_analysis as ta, TcpState};

use crate::seq::{seq_gt, seq_le, seq_lt};
use crate::table::TcpSegment;
use crate::{flags as fl, Dir};

/// Segments recently seen per direction, used to tell retransmissions from out-of-order data.
const RECENT: usize = 32;
/// Unacknowledged segments remembered for RTT measurement.
const OUTSTANDING: usize = 512;
/// A segment filling a gap within this time of the highest segment is out-of-order.
const OOO_THRESHOLD_NS: i64 = 3_000_000;

#[derive(Debug, Clone, Copy)]
struct Outstanding {
    end: u32,
    ts_ns: i64,
    packet: u32,
    retransmitted: bool,
}

/// Per-direction sequence state.
#[derive(Debug, Clone, Default)]
pub struct TcpDirection {
    /// Raw sequence number that maps to relative 0.
    pub base_seq: Option<u32>,
    /// Highest sequence number sent + 1.
    pub next_seq: Option<u32>,
    pub last_ack: Option<u32>,
    pub last_win: Option<u16>,
    /// Window scale shift advertised in this direction's SYN.
    pub wscale: Option<u8>,
    dup_acks: u32,
    highest_ts_ns: i64,
    recent: VecDeque<(u32, u32)>,
    outstanding: VecDeque<Outstanding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RttSample {
    /// Packet index of the ACK.
    pub packet: u32,
    /// Packet index of the acknowledged segment.
    pub acked: u32,
    pub rtt_ns: i64,
}

/// Results of analysing one segment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SegmentAnalysis {
    pub flags: u16,
    pub rtt: Option<RttSample>,
}

#[derive(Debug, Clone, Default)]
pub struct TcpFlow {
    pub dirs: [TcpDirection; 2],
    pub syn: Option<u32>,
    pub syn_ack: Option<u32>,
    pub handshake_ack: Option<u32>,
    syn_ts_ns: Option<i64>,
    pub irtt_ns: Option<i64>,
    pub fin: [Option<u32>; 2],
    pub first_rst: Option<u32>,
    pub refused: bool,
    pub rtt_min_ns: Option<i64>,
    pub rtt_max_ns: Option<i64>,
    pub rtt_sum_ns: i64,
    pub rtt_samples: Vec<RttSample>,
    pub retransmissions: u32,
    pub fast_retransmissions: u32,
    pub duplicate_acks: u32,
    pub out_of_order: u32,
    pub zero_window: u32,
    pub keep_alive: u32,
    pub lost_segments: u32,
    pub resets: u32,
    pub window_updates: u32,
}

impl TcpFlow {
    pub fn state(&self) -> TcpState {
        if self.first_rst.is_some() {
            return if self.refused { TcpState::Refused } else { TcpState::Reset };
        }
        match (self.fin[0].is_some(), self.fin[1].is_some()) {
            (true, true) => return TcpState::Closed,
            (true, false) | (false, true) => return TcpState::Closing,
            _ => {}
        }
        if self.handshake_ack.is_some() {
            TcpState::Established
        } else if self.syn_ack.is_some() {
            TcpState::SynReceived
        } else if self.syn.is_some() {
            TcpState::SynSent
        } else {
            TcpState::Midstream
        }
    }

    /// True once the connection can no longer carry data.
    pub fn is_finished(&self) -> bool {
        self.first_rst.is_some() || (self.fin[0].is_some() && self.fin[1].is_some())
    }

    /// Window scale shift applied to windows sent in `dir` (only if both sides negotiated it).
    pub fn window_shift(&self, dir: Dir) -> Option<u8> {
        match (self.dirs[0].wscale, self.dirs[1].wscale) {
            (Some(_), Some(_)) => self.dirs[dir.index()].wscale,
            _ => None,
        }
    }

    /// RTT sample recorded on the ACK with packet index `packet`.
    pub fn rtt_for(&self, packet: u32) -> Option<RttSample> {
        self.rtt_samples
            .binary_search_by_key(&packet, |s| s.packet)
            .ok()
            .map(|i| self.rtt_samples[i])
    }

    pub fn rtt_avg_ns(&self) -> Option<i64> {
        let n = self.rtt_samples.len() as i64;
        (n > 0).then(|| self.rtt_sum_ns / n)
    }

    /// Releases per-direction buffers once the connection is over.
    fn release_buffers(&mut self) {
        for d in &mut self.dirs {
            d.recent = VecDeque::new();
            d.outstanding = VecDeque::new();
        }
    }

    pub(crate) fn analyse(&mut self, index: u32, ts_ns: i64, dir: Dir, seg: &TcpSegment) -> SegmentAnalysis {
        let syn = seg.flags & fl::SYN != 0;
        let fin = seg.flags & fl::FIN != 0;
        let rst = seg.flags & fl::RST != 0;
        let has_ack = seg.flags & fl::ACK != 0;
        let control = syn || fin || rst;
        let seglen = seg.payload_len.wrapping_add(u32::from(syn)).wrapping_add(u32::from(fin));
        let (d_i, r_i) = (dir.index(), dir.reverse().index());
        let mut out = SegmentAnalysis::default();

        // Handshake bookkeeping.
        if syn && !has_ack {
            if self.syn.is_none() {
                self.syn = Some(index);
                self.syn_ts_ns = Some(ts_ns);
            }
            self.dirs[d_i].wscale = seg.wscale;
        } else if syn && has_ack {
            if self.syn_ack.is_none() {
                self.syn_ack = Some(index);
            }
            self.dirs[d_i].wscale = seg.wscale;
        } else if has_ack && self.syn_ack.is_some() && self.handshake_ack.is_none() && dir == Dir::ClientToServer {
            let server_isn_next = self.dirs[r_i].base_seq.map(|b| b.wrapping_add(1));
            if server_isn_next == Some(seg.ack) {
                self.handshake_ack = Some(index);
                self.irtt_ns = self.syn_ts_ns.map(|t| ts_ns.saturating_sub(t));
            }
        }

        let d = &self.dirs[d_i];
        if d.base_seq.is_none() {
            // Relative numbering: SYN maps to 0, a mid-stream first segment to 1.
            self.dirs[d_i].base_seq = Some(if syn { seg.seq } else { seg.seq.wrapping_sub(1) });
        }

        let d = &self.dirs[d_i];
        let r_next = self.dirs[r_i].next_seq;
        let keep_alive = !control
            && seg.payload_len <= 1
            && d.next_seq.is_some_and(|n| seg.seq == n.wrapping_sub(1));
        if keep_alive {
            out.flags |= ta::KEEP_ALIVE;
        }
        if seg.window == 0 && !control {
            out.flags |= ta::ZERO_WINDOW;
        }
        if let Some(next) = d.next_seq {
            if seq_gt(seg.seq, next) && !rst {
                out.flags |= ta::LOST_SEGMENT;
            }
            if seglen > 0 && seq_lt(seg.seq, next) && !keep_alive {
                let end = seg.seq.wrapping_add(seglen);
                let seen = d.recent.iter().any(|&(s, e)| seq_lt(seg.seq, e) && seq_lt(s, end));
                let recent_highest = ts_ns.saturating_sub(d.highest_ts_ns) < OOO_THRESHOLD_NS;
                if seen || !recent_highest {
                    out.flags |= ta::RETRANSMISSION;
                    let peer = &self.dirs[r_i];
                    if peer.dup_acks >= 2 && peer.last_ack == Some(seg.seq) {
                        out.flags |= ta::FAST_RETRANSMISSION;
                    }
                } else {
                    out.flags |= ta::OUT_OF_ORDER;
                }
            }
        }
        if has_ack && !control && seg.payload_len == 0 {
            let same_ack = d.last_ack == Some(seg.ack);
            let same_win = d.last_win == Some(seg.window);
            let outstanding = r_next.is_some_and(|n| n != seg.ack);
            if same_ack && same_win && outstanding && !keep_alive {
                out.flags |= ta::DUPLICATE_ACK;
            } else if same_ack && !same_win && d.next_seq == Some(seg.seq) {
                out.flags |= ta::WINDOW_UPDATE;
            }
        }
        if has_ack && r_next.is_some_and(|n| seq_gt(seg.ack, n)) {
            out.flags |= ta::ACKED_UNSEEN;
        }

        // RTT: this ACK acknowledges outstanding segments of the reverse direction.
        if has_ack {
            let peer = &mut self.dirs[r_i];
            let mut last = None;
            while let Some(front) = peer.outstanding.front() {
                if seq_le(front.end, seg.ack) {
                    last = peer.outstanding.pop_front();
                } else {
                    break;
                }
            }
            if let Some(o) = last.filter(|o| !o.retransmitted) {
                let sample = RttSample { packet: index, acked: o.packet, rtt_ns: ts_ns.saturating_sub(o.ts_ns) };
                out.rtt = Some(sample);
                self.rtt_samples.push(sample);
                self.rtt_sum_ns = self.rtt_sum_ns.saturating_add(sample.rtt_ns);
                self.rtt_min_ns = Some(self.rtt_min_ns.map_or(sample.rtt_ns, |m| m.min(sample.rtt_ns)));
                self.rtt_max_ns = Some(self.rtt_max_ns.map_or(sample.rtt_ns, |m| m.max(sample.rtt_ns)));
            }
        }

        // Update the sender's state.
        let retrans = out.flags & ta::RETRANSMISSION != 0;
        let d = &mut self.dirs[d_i];
        if has_ack {
            if out.flags & ta::DUPLICATE_ACK != 0 {
                d.dup_acks += 1;
            } else if d.last_ack != Some(seg.ack) {
                d.dup_acks = 0;
            }
            d.last_ack = Some(seg.ack);
        }
        d.last_win = Some(seg.window);
        if seglen > 0 {
            let end = seg.seq.wrapping_add(seglen);
            if d.next_seq.is_none_or(|n| seq_gt(end, n)) {
                d.next_seq = Some(end);
                d.highest_ts_ns = ts_ns;
            }
            if d.recent.len() >= RECENT {
                d.recent.pop_front();
            }
            d.recent.push_back((seg.seq, end));
            if retrans {
                for o in d.outstanding.iter_mut() {
                    if seq_lt(seg.seq, o.end) && seq_le(o.end, end) {
                        o.retransmitted = true;
                    }
                }
            } else {
                if d.outstanding.len() >= OUTSTANDING {
                    d.outstanding.pop_front();
                }
                d.outstanding.push_back(Outstanding { end, ts_ns, packet: index, retransmitted: false });
            }
        } else if d.next_seq.is_none() {
            d.next_seq = Some(seg.seq);
            d.highest_ts_ns = ts_ns;
        }

        if fin && self.fin[d_i].is_none() {
            self.fin[d_i] = Some(index);
        }
        if rst {
            self.resets += 1;
            if self.first_rst.is_none() {
                self.first_rst = Some(index);
                self.refused = self.syn.is_some() && self.handshake_ack.is_none() && dir == Dir::ServerToClient;
            }
        }

        let f = out.flags;
        self.retransmissions += u32::from(f & ta::RETRANSMISSION != 0);
        self.fast_retransmissions += u32::from(f & ta::FAST_RETRANSMISSION != 0);
        self.duplicate_acks += u32::from(f & ta::DUPLICATE_ACK != 0);
        self.out_of_order += u32::from(f & ta::OUT_OF_ORDER != 0);
        self.zero_window += u32::from(f & ta::ZERO_WINDOW != 0);
        self.keep_alive += u32::from(f & ta::KEEP_ALIVE != 0);
        self.lost_segments += u32::from(f & ta::LOST_SEGMENT != 0);
        self.window_updates += u32::from(f & ta::WINDOW_UPDATE != 0);

        if self.is_finished() {
            self.release_buffers();
        }
        out
    }
}
