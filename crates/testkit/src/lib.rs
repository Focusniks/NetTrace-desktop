//! Test support: packet builders, an in-memory capture builder and canned
//! scenarios used by unit/integration tests and the fixture generator.

pub mod build;
pub mod scenarios;

use std::io;
use std::path::Path;

use nettrace_capture::{PcapNgWriter, PcapWriter};
use nettrace_packet::{LinkType, Timestamp};

use build::{tcpf, TcpSegment};

/// Base timestamp of generated captures: 2023-11-14 22:13:20 UTC.
pub const BASE_SECS: i64 = 1_700_000_000;

/// Frames with timestamps, written as pcap or pcapng.
#[derive(Debug, Clone)]
pub struct Capture {
    pub link: LinkType,
    pub frames: Vec<(Timestamp, Vec<u8>)>,
    now_ns: i64,
}

impl Capture {
    pub fn new(link: LinkType) -> Self {
        Capture { link, frames: Vec::new(), now_ns: BASE_SECS * 1_000_000_000 }
    }

    pub fn ethernet() -> Self {
        Self::new(LinkType::Ethernet)
    }

    pub fn advance_us(&mut self, us: i64) {
        self.now_ns += us * 1000;
    }

    pub fn push(&mut self, frame: Vec<u8>) {
        self.frames.push((Timestamp::from_nanos(self.now_ns), frame));
    }

    pub fn push_after_us(&mut self, us: i64, frame: Vec<u8>) {
        self.advance_us(us);
        self.push(frame);
    }

    pub fn to_pcap(&self) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut w = PcapWriter::new(&mut out, self.link, true).expect("vec write");
            for (ts, f) in &self.frames {
                w.write(*ts, f, f.len() as u32).expect("vec write");
            }
        }
        out
    }

    pub fn to_pcapng(&self) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut w = PcapNgWriter::new(&mut out).expect("vec write");
            w.add_interface(self.link, 262_144, Some("test0"), Some(9)).expect("vec write");
            for (ts, f) in &self.frames {
                w.write_epb(0, *ts, f, f.len() as u32).expect("vec write");
            }
        }
        out
    }

    pub fn write_pcap(&self, path: &Path) -> io::Result<()> {
        std::fs::write(path, self.to_pcap())
    }

    pub fn write_pcapng(&self, path: &Path) -> io::Result<()> {
        std::fs::write(path, self.to_pcapng())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Host {
    pub mac: [u8; 6],
    pub ip: [u8; 4],
}

impl Host {
    pub const fn new(mac: [u8; 6], ip: [u8; 4]) -> Self {
        Host { mac, ip }
    }
}

/// Stateful TCP conversation over Ethernet/IPv4 that tracks sequence numbers.
#[derive(Debug, Clone)]
pub struct TcpConv {
    pub client: Host,
    pub server: Host,
    pub cport: u16,
    pub sport: u16,
    /// Next sequence number the client will send.
    pub cseq: u32,
    pub sseq: u32,
    pub window: u16,
    ip_id: u16,
}

impl TcpConv {
    pub fn new(client: Host, cport: u16, server: Host, sport: u16) -> Self {
        TcpConv {
            client,
            server,
            cport,
            sport,
            cseq: 0x1000_0000u32.wrapping_add(u32::from(cport) * 7919),
            sseq: 0x7000_0000u32.wrapping_add(u32::from(sport) * 104_729),
            window: 64240,
            ip_id: 1,
        }
    }

    pub fn segment(&mut self, from_client: bool, flags: u8, seq: u32, ack: u32, payload: &[u8], options: Vec<u8>) -> Vec<u8> {
        let (src, dst, sp, dp) = if from_client {
            (self.client, self.server, self.cport, self.sport)
        } else {
            (self.server, self.client, self.sport, self.cport)
        };
        let seg = TcpSegment {
            sport: sp,
            dport: dp,
            seq,
            ack,
            flags,
            window: self.window,
            options,
            payload: payload.to_vec(),
        };
        self.ip_id = self.ip_id.wrapping_add(1);
        let ip = build::ipv4(src.ip, dst.ip, 6, self.ip_id, 64, &build::tcp(&seg));
        build::ethernet(dst.mac, src.mac, build::ETH_IPV4, &ip)
    }

    /// SYN, SYN/ACK, ACK with the given one-way delay.
    pub fn handshake(&mut self, cap: &mut Capture, one_way_us: i64) {
        let syn = self.segment(true, tcpf::SYN, self.cseq, 0, &[], build::syn_options(1460, 7));
        cap.push_after_us(1, syn);
        self.cseq = self.cseq.wrapping_add(1);
        let syn_ack = self.segment(false, tcpf::SYN | tcpf::ACK, self.sseq, self.cseq, &[], build::syn_options(1460, 8));
        cap.push_after_us(one_way_us, syn_ack);
        self.sseq = self.sseq.wrapping_add(1);
        let ack = self.segment(true, tcpf::ACK, self.cseq, self.sseq, &[], vec![]);
        cap.push_after_us(one_way_us, ack);
    }

    /// Sends data (PSH/ACK) and advances the sender's sequence number.
    pub fn send(&mut self, cap: &mut Capture, from_client: bool, payload: &[u8], after_us: i64) -> u32 {
        let (seq, ack) = if from_client { (self.cseq, self.sseq) } else { (self.sseq, self.cseq) };
        let frame = self.segment(from_client, tcpf::PSH | tcpf::ACK, seq, ack, payload, vec![]);
        cap.push_after_us(after_us, frame);
        let next = seq.wrapping_add(payload.len() as u32);
        if from_client {
            self.cseq = next;
        } else {
            self.sseq = next;
        }
        seq
    }

    /// Re-sends `payload` at an explicit sequence number without advancing state.
    pub fn send_at(&mut self, cap: &mut Capture, from_client: bool, seq: u32, payload: &[u8], after_us: i64) {
        let ack = if from_client { self.sseq } else { self.cseq };
        let frame = self.segment(from_client, tcpf::PSH | tcpf::ACK, seq, ack, payload, vec![]);
        cap.push_after_us(after_us, frame);
    }

    /// Pure ACK of everything the peer sent so far.
    pub fn ack(&mut self, cap: &mut Capture, from_client: bool, after_us: i64) {
        let (seq, ack) = if from_client { (self.cseq, self.sseq) } else { (self.sseq, self.cseq) };
        let frame = self.segment(from_client, tcpf::ACK, seq, ack, &[], vec![]);
        cap.push_after_us(after_us, frame);
    }

    /// Pure ACK with an explicit acknowledgment number (dup ACKs, gaps).
    pub fn ack_at(&mut self, cap: &mut Capture, from_client: bool, ack: u32, after_us: i64) {
        let seq = if from_client { self.cseq } else { self.sseq };
        let frame = self.segment(from_client, tcpf::ACK, seq, ack, &[], vec![]);
        cap.push_after_us(after_us, frame);
    }

    pub fn fin(&mut self, cap: &mut Capture, from_client: bool, after_us: i64) {
        let (seq, ack) = if from_client { (self.cseq, self.sseq) } else { (self.sseq, self.cseq) };
        let frame = self.segment(from_client, tcpf::FIN | tcpf::ACK, seq, ack, &[], vec![]);
        cap.push_after_us(after_us, frame);
        if from_client {
            self.cseq = self.cseq.wrapping_add(1);
        } else {
            self.sseq = self.sseq.wrapping_add(1);
        }
    }

    /// Full FIN/ACK exchange initiated by `from_client`.
    pub fn close(&mut self, cap: &mut Capture, from_client: bool, after_us: i64) {
        self.fin(cap, from_client, after_us);
        self.fin(cap, !from_client, after_us);
        self.ack(cap, from_client, after_us);
    }

    pub fn rst(&mut self, cap: &mut Capture, from_client: bool, after_us: i64) {
        let (seq, ack) = if from_client { (self.cseq, self.sseq) } else { (self.sseq, self.cseq) };
        let frame = self.segment(from_client, tcpf::RST | tcpf::ACK, seq, ack, &[], vec![]);
        cap.push_after_us(after_us, frame);
    }

    pub fn set_window(&mut self, window: u16) {
        self.window = window;
    }
}

/// UDP datagram over Ethernet/IPv4.
pub fn udp_frame(src: Host, sport: u16, dst: Host, dport: u16, payload: &[u8]) -> Vec<u8> {
    let ip = build::ipv4(src.ip, dst.ip, 17, 0x100, 64, &build::udp(sport, dport, payload));
    build::ethernet(dst.mac, src.mac, build::ETH_IPV4, &ip)
}
