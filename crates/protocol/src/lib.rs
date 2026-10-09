//! Protocol dissectors.
//!
//! [`dissect`] turns raw frame bytes into a [`Summary`] (always), an Info
//! string and a protocol tree (on request). Every dissector reads through a
//! bounds-checked cursor; malformed input yields a `[Malformed]` marker
//! instead of an error for the whole capture.

mod app;
mod context;
pub mod fields;
pub mod format;
mod link;
mod names;
mod net;
mod registry;
mod transport;
pub mod tree;

pub use context::{
    AppEvent, Ctx, DissectOptions, FrameContext, Info, Malformed, Summary, TcpAnnotations, TcpInfo,
    TransportInfo,
};
pub use registry::{dissect, dissect_with, registry, AppDissector, Dissection, Dissector, Handoff, Layer, Registry};
pub use transport::tcp::flags_string as tcp_flags_string;
pub use tree::{Node, TreeMode};

/// TCP flag bits as carried in [`TcpInfo::flags`].
pub mod tcp_flags {
    pub const FIN: u16 = 0x001;
    pub const SYN: u16 = 0x002;
    pub const RST: u16 = 0x004;
    pub const PSH: u16 = 0x008;
    pub const ACK: u16 = 0x010;
    pub const URG: u16 = 0x020;
    pub const ECE: u16 = 0x040;
    pub const CWR: u16 = 0x080;
    pub const AE: u16 = 0x100;
}
