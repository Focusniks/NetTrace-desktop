//! Capture sources.
//!
//! The MVP reads existing PCAP/PCAPNG files. Live capture (libpcap/Npcap) is
//! expected to plug in later as another [`PacketSource`] implementation; the
//! engine only depends on this trait.

mod error;
mod pcap;
mod pcapng;
mod reader;
mod writer;

use nettrace_packet::{LinkType, Timestamp};

pub use error::CaptureError;
pub use pcap::PcapReader;
pub use pcapng::PcapNgReader;
pub use reader::{detect_format, CaptureReader};
pub use writer::{PcapNgWriter, PcapWriter};

/// Upper bound for a single captured packet. Larger values mean a corrupt file.
pub const MAX_RECORD_LEN: u32 = 256 * 1024;

/// Location and timing of one packet record inside the capture file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordMeta {
    /// Absolute file offset of the first byte of packet data.
    pub offset: u64,
    pub ts: Timestamp,
    /// Number of bytes actually stored in the file.
    pub caplen: u32,
    /// Original length on the wire.
    pub origlen: u32,
    /// Index into [`PacketSource::interfaces`].
    pub interface: u16,
}

/// Capture interface description (one per pcap file, many per pcapng).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub link_type: LinkType,
    pub snaplen: u32,
    pub name: Option<String>,
    pub description: Option<String>,
    /// Timestamp ticks per second (pcapng `if_tsresol`, default 10^6).
    pub ticks_per_sec: u64,
    /// Seconds added to every timestamp (pcapng `if_tsoffset`).
    pub ts_offset_secs: i64,
}

impl Interface {
    pub fn new(link_type: LinkType, snaplen: u32) -> Self {
        Self {
            link_type,
            snaplen,
            name: None,
            description: None,
            ticks_per_sec: 1_000_000,
            ts_offset_secs: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureFormat {
    Pcap { nanosecond: bool },
    PcapNg,
}

impl CaptureFormat {
    pub fn name(self) -> &'static str {
        match self {
            CaptureFormat::Pcap { nanosecond: false } => "PCAP",
            CaptureFormat::Pcap { nanosecond: true } => "PCAP (ns)",
            CaptureFormat::PcapNg => "PCAPNG",
        }
    }
}

/// A sequential source of packet records.
pub trait PacketSource {
    /// Reads the next record, replacing the contents of `buf` with packet data.
    /// Returns `Ok(None)` at a clean end of input.
    fn next_record(&mut self, buf: &mut Vec<u8>) -> Result<Option<RecordMeta>, CaptureError>;

    /// Interfaces discovered so far (pcapng may add interfaces mid-file).
    fn interfaces(&self) -> &[Interface];

    fn format(&self) -> CaptureFormat;

    /// Bytes consumed from the underlying input; used for progress reporting.
    fn bytes_consumed(&self) -> u64;
}
