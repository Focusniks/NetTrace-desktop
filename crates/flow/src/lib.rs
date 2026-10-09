//! Flow tracking.
//!
//! [`FlowTable::process`] is fed packets in capture order and assigns each
//! TCP/UDP packet to a stream, computing TCP analysis flags (retransmission,
//! duplicate ACK, out-of-order, zero window, …) and RTT samples. The table is
//! a plain data structure; the engine guards it with a lock for concurrent
//! readers.

mod ring;
mod seq;
mod table;
mod tcp;

pub use seq::{seq_gt, seq_le, seq_lt};
pub use table::{Flow, FlowAssignment, FlowKind, FlowPacket, FlowTable, TcpSegment};
pub use tcp::{RttSample, TcpDirection, TcpFlow};

/// Packet direction within a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dir {
    ClientToServer = 0,
    ServerToClient = 1,
}

impl Dir {
    pub fn index(self) -> usize {
        self as usize
    }

    pub fn reverse(self) -> Dir {
        match self {
            Dir::ClientToServer => Dir::ServerToClient,
            Dir::ServerToClient => Dir::ClientToServer,
        }
    }
}

/// TCP flag bits (same layout as the TCP header, plus AE at bit 8).
pub mod flags {
    pub const FIN: u16 = 0x001;
    pub const SYN: u16 = 0x002;
    pub const RST: u16 = 0x004;
    pub const PSH: u16 = 0x008;
    pub const ACK: u16 = 0x010;
}
