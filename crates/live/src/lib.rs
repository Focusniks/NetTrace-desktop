//! Live packet capture.
//!
//! The capture library (Npcap on Windows, libpcap elsewhere) is loaded at
//! runtime, so the application builds and runs without it; live capture is
//! simply reported as unavailable until the driver is installed.
//!
//! A [`LiveSource`] yields raw packets; the engine records them to a capture
//! file and indexes that file while it grows, exactly like an opened PCAP.

mod ffi;
mod replay;
mod sockaddr;

use std::time::Duration;

use nettrace_model::{CaptureInterface, LiveOptions};
use nettrace_packet::{LinkType, Timestamp};

pub use replay::ReplaySource;

#[derive(Debug, thiserror::Error)]
pub enum LiveError {
    /// Npcap/libpcap is not installed or could not be loaded.
    #[error("capture library is not available: {0}")]
    NotAvailable(String),
    #[error("cannot open interface: {0}")]
    Open(String),
    #[error("invalid capture filter: {0}")]
    Filter(String),
    #[error("capture error: {0}")]
    Read(String),
}

impl LiveError {
    /// Stable code for the UI.
    pub fn code(&self) -> &'static str {
        match self {
            LiveError::NotAvailable(_) => "capture_unavailable",
            LiveError::Open(_) => "capture_open",
            LiveError::Filter(_) => "capture_filter",
            LiveError::Read(_) => "capture_read",
        }
    }
}

/// One captured packet's metadata; the bytes are in the caller's buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LivePacket {
    pub ts: Timestamp,
    /// Length on the wire (the buffer may be shorter: snaplen).
    pub origlen: u32,
}

/// Driver counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DriverStats {
    pub received: u64,
    pub dropped: u64,
    pub if_dropped: u64,
}

/// A running capture on one interface.
pub trait LiveSource: Send {
    fn link_type(&self) -> LinkType;

    /// Waits up to roughly `timeout` for the next packet. `Ok(None)` means no
    /// packet arrived in time (the caller checks for stop requests and retries).
    fn next_packet(&mut self, buf: &mut Vec<u8>, timeout: Duration) -> Result<Option<LivePacket>, LiveError>;

    fn stats(&mut self) -> Option<DriverStats>;

    /// True when the source has no more packets (replays); live interfaces never end.
    fn finished(&self) -> bool {
        false
    }
}

/// Version string of the loaded capture library, or why it is unavailable.
pub fn library_version() -> Result<String, LiveError> {
    ffi::api().map(|api| api.version())
}

/// Interfaces the capture driver can open.
pub fn list_interfaces() -> Result<Vec<CaptureInterface>, LiveError> {
    ffi::api()?.interfaces()
}

/// Starts capturing on `opts.interface`.
pub fn open(opts: &LiveOptions) -> Result<Box<dyn LiveSource>, LiveError> {
    let api = ffi::api()?;
    Ok(Box::new(api.open(opts)?))
}
