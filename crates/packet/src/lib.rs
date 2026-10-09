//! Low-level packet primitives shared by every other layer.
//!
//! Everything that touches untrusted capture bytes goes through [`Cursor`],
//! which never panics on short input.

mod address;
mod cursor;
mod link;
mod time;

pub use address::{Address, CastType, MacAddr};
pub use cursor::{be_u16_at, Cursor, Truncated};
pub use link::LinkType;
pub use time::Timestamp;
