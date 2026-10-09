//! Capture-wide statistics. Everything here reports measured facts; nothing
//! classifies traffic as malicious.

mod accum;
mod indicators;
mod series;

pub use accum::{
    conversation_row, host_row, protocol_names, Accumulators, ConvStats, ConvTable, DnsActivity, Event, HostStats, HostTable, PacketFacts,
};
pub use indicators::{addr_filter, indicators, IndicatorConfig};
pub use series::{io_graph, packet_lengths, timeline, MAX_BUCKETS};
