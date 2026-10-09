use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceInfo {
    pub link_type: String,
    pub name: Option<String>,
    pub snaplen: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureInfo {
    /// Matches `IndexProgress::capture_id` of this capture's events.
    pub capture_id: u64,
    pub path: String,
    pub file_name: String,
    pub file_size: u64,
    pub format: String,
    /// True for a live capture (packets are being recorded to a temporary file).
    pub live: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IndexState {
    Indexing,
    Done,
    Cancelled,
    Failed,
}

/// Incremental indexing progress, pushed to the UI as an event.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexProgress {
    pub capture_id: u64,
    pub state: IndexState,
    pub packets: u32,
    pub tcp_streams: u32,
    pub udp_streams: u32,
    pub bytes_read: u64,
    pub total_bytes: u64,
    pub elapsed_ms: u64,
    /// Non-fatal reading problem (e.g. truncated last record), stable code.
    pub warning: Option<String>,
    pub error: Option<String>,
    /// Live capture statistics (present only while capturing / after a live capture).
    pub capture: Option<LiveStats>,
}

/// Counters of a live capture as reported by the capture driver.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveStats {
    pub interface: String,
    /// Packets written to the capture file.
    pub captured: u64,
    /// Packets dropped by the driver/kernel buffer.
    pub dropped: u64,
    /// Packets dropped by the network interface.
    pub if_dropped: u64,
    /// True while the capture is still running.
    pub running: bool,
}

/// A network interface available for live capture.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureInterface {
    /// Device name passed to the driver (e.g. `\Device\NPF_{GUID}` or `eth0`).
    pub name: String,
    /// Human-readable description from the driver.
    pub description: Option<String>,
    pub addresses: Vec<String>,
    pub loopback: bool,
    pub up: bool,
    pub running: bool,
    pub wireless: bool,
}

/// Parameters of a live capture.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveOptions {
    pub interface: String,
    /// BPF capture filter (driver-side), e.g. `tcp port 443`.
    #[serde(default)]
    pub capture_filter: Option<String>,
    #[serde(default = "default_snaplen")]
    pub snaplen: u32,
    #[serde(default = "default_true")]
    pub promiscuous: bool,
}

fn default_snaplen() -> u32 {
    262_144
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureSummary {
    pub info: CaptureInfo,
    pub packets: u32,
    pub bytes: u64,
    pub first_ts_sec: Option<i64>,
    pub first_ts_nsec: Option<u32>,
    pub duration: f64,
    pub tcp_streams: u32,
    pub udp_streams: u32,
    pub hosts: u32,
    pub malformed: u64,
    pub interfaces: Vec<InterfaceInfo>,
    pub state: IndexState,
}

/// Result of applying a filter / sort.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewInfo {
    pub view_id: u64,
    pub total: u32,
    /// Number of packets that existed when the view was built.
    pub scanned: u32,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FilterError {
    pub code: String,
    pub start: u32,
    pub end: u32,
    pub detail: String,
}
