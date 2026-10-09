use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
}

/// Reference to a transport stream (`tcp.stream == id` / `udp.stream == id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamRef {
    pub kind: Transport,
    pub id: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub addr: String,
    pub port: u16,
}

/// Connection state derived from observed TCP flags (facts, not guesses).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpState {
    /// SYN seen, no SYN/ACK.
    SynSent,
    /// SYN/ACK seen, final ACK not seen.
    SynReceived,
    Established,
    /// Capture started mid-connection (no handshake observed).
    Midstream,
    /// FIN seen in one direction.
    Closing,
    /// FIN seen in both directions.
    Closed,
    /// Connection terminated by RST.
    Reset,
    /// SYN answered by RST.
    Refused,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Handshake {
    pub syn: Option<u32>,
    pub syn_ack: Option<u32>,
    pub ack: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpFlowStats {
    pub state: TcpState,
    pub handshake: Handshake,
    /// Handshake round-trip time (SYN → ACK), milliseconds.
    pub irtt_ms: Option<f64>,
    pub rtt_min_ms: Option<f64>,
    pub rtt_avg_ms: Option<f64>,
    pub rtt_max_ms: Option<f64>,
    pub rtt_samples: u32,
    pub retransmissions: u32,
    pub fast_retransmissions: u32,
    pub duplicate_acks: u32,
    pub out_of_order: u32,
    pub zero_window: u32,
    pub keep_alive: u32,
    pub lost_segments: u32,
    pub resets: u32,
    pub fin_client: Option<u32>,
    pub fin_server: Option<u32>,
    /// Payload bytes per second, client → server.
    pub throughput_c2s: f64,
    pub throughput_s2c: f64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowSummary {
    pub kind: Transport,
    pub id: u32,
    pub client: Endpoint,
    pub server: Endpoint,
    /// Highest-layer protocol seen in the flow (e.g. "TLS").
    pub protocol: String,
    pub packets: u64,
    pub bytes: u64,
    pub c2s_packets: u64,
    pub c2s_bytes: u64,
    pub c2s_payload: u64,
    pub s2c_packets: u64,
    pub s2c_bytes: u64,
    pub s2c_payload: u64,
    pub first_packet: u32,
    pub last_packet: u32,
    pub start: f64,
    pub duration: f64,
    pub tcp: Option<TcpFlowStats>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// client → server
    C2s,
    /// server → client
    S2c,
}

/// One arrow of the sequence (ladder) diagram.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SequenceEntry {
    pub number: u32,
    pub time_rel: f64,
    /// Seconds since the first packet of the stream.
    pub time_stream: f64,
    pub direction: Direction,
    pub label: String,
    pub tcp_flags: Option<String>,
    pub seq: Option<u32>,
    pub ack: Option<u32>,
    pub len: u32,
    pub window: Option<u32>,
    pub analysis: u16,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SequencePage {
    pub total: u32,
    pub offset: u32,
    pub entries: Vec<SequenceEntry>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowPage {
    pub total: u32,
    pub offset: u32,
    pub flows: Vec<FlowSummary>,
}

/// Bit flags produced by TCP sequence analysis (`PacketRow::analysis`).
pub mod tcp_analysis {
    pub const RETRANSMISSION: u16 = 1 << 0;
    pub const FAST_RETRANSMISSION: u16 = 1 << 1;
    pub const OUT_OF_ORDER: u16 = 1 << 2;
    pub const DUPLICATE_ACK: u16 = 1 << 3;
    pub const ZERO_WINDOW: u16 = 1 << 4;
    pub const KEEP_ALIVE: u16 = 1 << 5;
    pub const LOST_SEGMENT: u16 = 1 << 6;
    pub const WINDOW_UPDATE: u16 = 1 << 7;
    pub const PORT_REUSE: u16 = 1 << 8;
    pub const ACKED_UNSEEN: u16 = 1 << 9;

    /// Flags that indicate a problem (used by the "TCP problems" coloring rule).
    pub const PROBLEMS: u16 = RETRANSMISSION
        | FAST_RETRANSMISSION
        | OUT_OF_ORDER
        | DUPLICATE_ACK
        | ZERO_WINDOW
        | LOST_SEGMENT
        | ACKED_UNSEEN;
}
