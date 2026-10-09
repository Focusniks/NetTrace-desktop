//! Capture-wide statistics. Everything here reports measured facts; nothing
//! classifies traffic as malicious.

mod accum;
mod indicators;
mod series;

pub use accum::{protocol_names, Accumulators, ConvStats, DnsActivity, Event, HostStats, PacketFacts};
pub use indicators::{addr_filter, indicators, IndicatorConfig};
pub use series::{io_graph, packet_lengths, timeline, MAX_BUCKETS};
