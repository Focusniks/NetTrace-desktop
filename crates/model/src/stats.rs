use serde::{Deserialize, Serialize};

use crate::{Severity, StreamRef};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressKind {
    Mac,
    Ipv4,
    Ipv6,
}

/// Endpoint statistics («Узлы»).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostRow {
    pub address: String,
    pub kind: AddressKind,
    /// Link-layer source address observed for this host (IP hosts only).
    pub mac: Option<String>,
    pub packets: u64,
    pub bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub protocols: Vec<String>,
    pub first_seen: f64,
    pub last_seen: f64,
    /// Display filter selecting this host.
    pub filter: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConversationKind {
    Eth,
    Ip,
    Tcp,
    Udp,
}

/// Conversation between two endpoints («Соединения»).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationRow {
    pub kind: ConversationKind,
    pub a: String,
    pub a_port: Option<u16>,
    pub b: String,
    pub b_port: Option<u16>,
    pub packets: u64,
    pub bytes: u64,
    pub a_to_b_packets: u64,
    pub a_to_b_bytes: u64,
    pub b_to_a_packets: u64,
    pub b_to_a_bytes: u64,
    pub start: f64,
    pub duration: f64,
    /// TCP state code (see `TcpState`) for TCP conversations.
    pub state: Option<String>,
    pub stream: Option<StreamRef>,
    pub filter: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolNode {
    pub name: String,
    pub filter: String,
    pub packets: u64,
    pub bytes: u64,
    pub children: Vec<ProtocolNode>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IoGraph {
    /// Bucket width, seconds.
    pub interval: f64,
    /// Start of bucket 0, seconds relative to the first packet.
    pub start: f64,
    pub packets: Vec<u64>,
    pub bytes: Vec<u64>,
    pub matched_packets: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LengthBucket {
    pub min: u32,
    /// Inclusive upper bound; `None` for the last open-ended bucket.
    pub max: Option<u32>,
    pub count: u64,
    pub min_seen: Option<u32>,
    pub max_seen: Option<u32>,
    pub avg: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketLengths {
    pub buckets: Vec<LengthBucket>,
    pub total: u64,
    pub min: Option<u32>,
    pub max: Option<u32>,
    pub avg: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineKind {
    DnsQuery,
    DnsResponse,
    TlsClientHello,
    TlsServerHello,
    HttpRequest,
    HttpResponse,
    TcpOpen,
    TcpClose,
    TcpReset,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEvent {
    pub kind: TimelineKind,
    pub number: u32,
    pub time_rel: f64,
    pub label: String,
    pub stream: Option<StreamRef>,
}

/// Bucketed activity lanes for the timeline panel.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Timeline {
    pub start: f64,
    pub end: f64,
    pub bucket: f64,
    pub packets: Vec<u32>,
    pub bytes: Vec<u64>,
    pub tcp_open: Vec<u32>,
    /// TCP connections active in each bucket.
    pub tcp_active: Vec<u32>,
    pub dns: Vec<u32>,
    pub tls: Vec<u32>,
    pub http: Vec<u32>,
    /// Individual events, present when the range holds few enough of them.
    pub events: Vec<TimelineEvent>,
    pub events_truncated: bool,
}

/// Objective technical observation. Text is built by the UI from `kind`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Indicator {
    pub severity: Severity,
    #[serde(flatten)]
    pub kind: IndicatorKind,
    /// Filter that shows the packets behind the observation.
    pub filter: String,
    pub first_packet: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum IndicatorKind {
    #[serde(rename_all = "camelCase")]
    TcpRetransmissionRate { stream: u32, endpoints: String, retransmissions: u32, segments: u64, percent: f64 },
    #[serde(rename_all = "camelCase")]
    TcpResets { streams: u32, packets: u64 },
    #[serde(rename_all = "camelCase")]
    TcpZeroWindow { stream: u32, endpoints: String, count: u32 },
    #[serde(rename_all = "camelCase")]
    RepeatedFailedConnections { client: String, server: String, port: u16, attempts: u32, refused: u32 },
    #[serde(rename_all = "camelCase")]
    ManyConnections { host: String, connections: u32, distinct_peers: u32, distinct_ports: u32 },
    #[serde(rename_all = "camelCase")]
    ManyDnsQueries { host: String, queries: u32, distinct_names: u32 },
    #[serde(rename_all = "camelCase")]
    LargeFlow { stream: u32, kind: String, client: String, server: String, client_bytes: u64, server_bytes: u64 },
    #[serde(rename_all = "camelCase")]
    NonStandardPort { protocol: String, port: u16, streams: u32 },
    #[serde(rename_all = "camelCase")]
    MalformedPackets { count: u64 },
}
