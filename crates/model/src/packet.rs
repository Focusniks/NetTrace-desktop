use serde::Serialize;

use crate::{PacketField, StreamRef};

/// One row of the packet list.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketRow {
    /// 1-based frame number.
    pub number: u32,
    /// Seconds since the first packet of the capture.
    pub time_rel: f64,
    /// Seconds since the previous packet in the current view.
    pub time_delta: f64,
    pub ts_sec: i64,
    pub ts_nsec: u32,
    pub src: String,
    pub dst: String,
    pub protocol: String,
    pub length: u32,
    pub info: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<String>,
    pub stream: Option<StreamRef>,
    /// unicast / multicast / broadcast / unknown
    pub cast: &'static str,
    /// Index of the first matching coloring rule.
    pub color_rule: Option<u16>,
    /// Bitmask of TCP analysis flags (see `TcpAnalysisFlag` in the UI).
    pub analysis: u16,
    pub malformed: bool,
    /// The packet bytes could not be read from the file (info/colors are unavailable).
    pub read_error: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketDetail {
    pub number: u32,
    pub tree: Vec<PacketField>,
    pub bytes: Vec<u8>,
    pub stream: Option<StreamRef>,
}
