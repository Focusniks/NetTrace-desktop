//! Packet storage.
//!
//! The capture is never loaded into memory. Indexing keeps one fixed-size
//! [`PacketMeta`] per packet (64 bytes) plus an interned address table; packet
//! bytes are read back from the file on demand through [`CaptureFile`].
//! A persistent (e.g. SQLite) index can later replace [`PacketIndex`] without
//! touching other layers.

use std::fs::File;
use std::hash::BuildHasher;
use std::io;
use std::path::{Path, PathBuf};

use hashbrown::{DefaultHashBuilder, HashTable};
use nettrace_packet::{Address, LinkType};

/// Sentinel for "no value" in u32 id fields.
pub const NONE: u32 = u32::MAX;

pub mod status {
    pub const MALFORMED: u8 = 1 << 0;
    /// Packet travels server → client within its flow.
    pub const REVERSE: u8 = 1 << 1;
}

/// Per-packet metadata kept in memory. Everything the packet list, the fast
/// filter path and statistics need without touching the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketMeta {
    /// File offset of the packet data.
    pub offset: u64,
    pub ts_ns: i64,
    pub caplen: u32,
    pub origlen: u32,
    /// `ProtocolSet` bitmask.
    pub protocols: u32,
    /// Interned network-layer (or link-layer fallback) addresses.
    pub src: u32,
    pub dst: u32,
    pub l2_src: u32,
    pub l2_dst: u32,
    /// Index into the flow table, or [`NONE`].
    pub flow: u32,
    /// Next packet of the same flow, or [`NONE`] (fits in padding: the
    /// struct stays 64 bytes).
    pub next_in_flow: u32,
    pub sport: u16,
    pub dport: u16,
    pub analysis: u16,
    pub tcp_flags: u16,
    pub interface: u16,
    /// `ProtocolId` of the highest layer.
    pub top: u8,
    pub status: u8,
}

impl PacketMeta {
    pub fn malformed(&self) -> bool {
        self.status & status::MALFORMED != 0
    }

    pub fn reverse(&self) -> bool {
        self.status & status::REVERSE != 0
    }

    pub fn flow(&self) -> Option<u32> {
        (self.flow != NONE).then_some(self.flow)
    }
}

/// Interns addresses so each packet stores two u32 ids instead of 2×17 bytes.
#[derive(Debug, Default)]
pub struct AddressTable {
    list: Vec<Address>,
    /// Ids by address; the address is read back from `list` (4 bytes per entry).
    map: HashTable<u32>,
    hasher: DefaultHashBuilder,
}

impl AddressTable {
    pub fn intern(&mut self, addr: Address) -> u32 {
        if addr.is_none() {
            return NONE;
        }
        let hash = self.hasher.hash_one(addr);
        let list = &self.list;
        if let Some(&id) = self.map.find(hash, |&i| list[i as usize] == addr) {
            return id;
        }
        let id = self.list.len() as u32;
        self.list.push(addr);
        let (list, hasher) = (&self.list, &self.hasher);
        self.map.insert_unique(hash, id, |&i| hasher.hash_one(list[i as usize]));
        id
    }

    fn shrink_to_fit(&mut self) {
        self.list.shrink_to_fit();
        let (list, hasher) = (&self.list, &self.hasher);
        self.map.shrink_to_fit(|&i| hasher.hash_one(list[i as usize]));
    }

    pub fn get(&self, id: u32) -> Address {
        self.list.get(id as usize).copied().unwrap_or(Address::None)
    }

    pub fn id_of(&self, addr: &Address) -> Option<u32> {
        let list = &self.list;
        self.map.find(self.hasher.hash_one(addr), |&i| list[i as usize] == *addr).copied()
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (u32, &Address)> {
        self.list.iter().enumerate().map(|(i, a)| (i as u32, a))
    }
}

/// Growing index of all packets seen so far.
#[derive(Debug, Default)]
pub struct PacketIndex {
    packets: Vec<PacketMeta>,
    pub addrs: AddressTable,
    pub link_types: Vec<LinkType>,
}

impl PacketIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, meta: PacketMeta) -> u32 {
        let id = self.packets.len() as u32;
        self.packets.push(meta);
        id
    }

    pub fn len(&self) -> u32 {
        self.packets.len() as u32
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn get(&self, index: u32) -> Option<&PacketMeta> {
        self.packets.get(index as usize)
    }

    /// Packets of a flow in capture order, following `next_in_flow` from `first`.
    pub fn flow_packets(&self, first: u32) -> impl Iterator<Item = u32> + '_ {
        std::iter::successors(self.get(first).map(|_| first), move |&i| {
            self.get(i).map(|m| m.next_in_flow).filter(|&n| n != NONE)
        })
    }

    /// Drops spare capacity once the capture is fully indexed.
    pub fn shrink_to_fit(&mut self) {
        self.packets.shrink_to_fit();
        self.addrs.shrink_to_fit();
    }

    pub fn get_mut(&mut self, index: u32) -> Option<&mut PacketMeta> {
        self.packets.get_mut(index as usize)
    }

    pub fn all(&self) -> &[PacketMeta] {
        &self.packets
    }

    pub fn first_ts(&self) -> Option<i64> {
        self.packets.first().map(|p| p.ts_ns)
    }

    pub fn link_type(&self, interface: u16) -> LinkType {
        self.link_types.get(usize::from(interface)).copied().unwrap_or(LinkType::Other(u32::MAX))
    }

    pub fn reserve(&mut self, additional: usize) {
        self.packets.reserve(additional);
    }

    /// Approximate heap usage in bytes (for diagnostics).
    pub fn memory_bytes(&self) -> usize {
        self.packets.capacity() * std::mem::size_of::<PacketMeta>()
            + self.addrs.list.capacity() * std::mem::size_of::<Address>()
            + self.addrs.map.capacity() * (std::mem::size_of::<u32>() + 1)
    }
}

/// Random-access reader for packet bytes. Safe to share between threads:
/// positioned reads do not depend on a shared cursor.
#[derive(Debug)]
pub struct CaptureFile {
    path: PathBuf,
    file: File,
    size: u64,
}

impl CaptureFile {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        Ok(CaptureFile { path: path.to_path_buf(), file, size })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Size when the file was opened.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Current size (differs from [`CaptureFile::size`] while a live capture writes to it).
    pub fn current_size(&self) -> u64 {
        self.file.metadata().map(|m| m.len()).unwrap_or(self.size)
    }

    /// Reads `len` bytes at `offset` into `buf` (replacing its contents).
    pub fn read_into(&self, offset: u64, len: u32, buf: &mut Vec<u8>) -> io::Result<()> {
        // The file may still be growing (live capture), so EOF is detected by the read itself.
        offset.checked_add(u64::from(len)).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        buf.clear();
        buf.resize(len as usize, 0);
        read_exact_at(&self.file, buf, offset)
    }

    pub fn read(&self, meta: &PacketMeta) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.read_into(meta.offset, meta.caplen, &mut buf)?;
        Ok(buf)
    }
}

#[cfg(unix)]
fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match file.seek_read(buf, offset) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(n) => {
                buf = &mut buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn meta_is_compact() {
        assert!(std::mem::size_of::<PacketMeta>() <= 64);
    }

    #[test]
    fn address_interning() {
        let mut t = AddressTable::default();
        let a = t.intern(Address::V4([1, 2, 3, 4]));
        let b = t.intern(Address::V4([5, 6, 7, 8]));
        assert_eq!(t.intern(Address::V4([1, 2, 3, 4])), a);
        assert_ne!(a, b);
        assert_eq!(t.intern(Address::None), NONE);
        assert_eq!(t.get(b), Address::V4([5, 6, 7, 8]));
        assert_eq!(t.get(NONE), Address::None);
        assert_eq!(t.id_of(&Address::V4([1, 2, 3, 4])), Some(a));
    }

    #[test]
    fn positioned_reads() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"0123456789").unwrap();
        let cf = CaptureFile::open(f.path()).unwrap();
        let mut buf = Vec::new();
        cf.read_into(3, 4, &mut buf).unwrap();
        assert_eq!(buf, b"3456");
        assert!(cf.read_into(8, 4, &mut buf).is_err());
        assert!(cf.read_into(u64::MAX, 4, &mut buf).is_err());
        // Concurrent readers share the handle.
        std::thread::scope(|s| {
            for i in 0..4u64 {
                let cf = &cf;
                s.spawn(move || {
                    let mut b = Vec::new();
                    cf.read_into(i, 2, &mut b).unwrap();
                    assert_eq!(b[0], b'0' + i as u8);
                });
            }
        });
    }

    #[test]
    fn flow_packets_follow_the_chain() {
        let mut idx = PacketIndex::new();
        let m = |next| PacketMeta {
            offset: 0, ts_ns: 0, caplen: 0, origlen: 0, protocols: 0, src: NONE, dst: NONE, l2_src: NONE, l2_dst: NONE,
            flow: 0, next_in_flow: next, sport: 0, dport: 0, analysis: 0, tcp_flags: 0, interface: 0, top: 0, status: 0,
        };
        for next in [2, NONE, 3, NONE] {
            idx.push(m(next));
        }
        assert_eq!(idx.flow_packets(0).collect::<Vec<_>>(), [0, 2, 3]);
        assert_eq!(idx.flow_packets(1).collect::<Vec<_>>(), [1]);
        assert_eq!(idx.flow_packets(9).count(), 0);
    }

    #[test]
    fn index_basics() {
        let mut idx = PacketIndex::new();
        let meta = PacketMeta {
            offset: 40,
            ts_ns: 5,
            caplen: 60,
            origlen: 60,
            protocols: 0,
            src: NONE,
            dst: NONE,
            l2_src: NONE,
            l2_dst: NONE,
            flow: NONE,
            next_in_flow: NONE,
            sport: 0,
            dport: 0,
            analysis: 0,
            tcp_flags: 0,
            interface: 0,
            top: 0,
            status: status::MALFORMED,
        };
        assert_eq!(idx.push(meta), 0);
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.first_ts(), Some(5));
        assert!(idx.get(0).unwrap().malformed());
        assert_eq!(idx.get(0).unwrap().flow(), None);
    }
}
