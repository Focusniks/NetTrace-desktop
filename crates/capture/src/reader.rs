use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::pcap::is_pcap_magic;
use crate::pcapng::SHB_TYPE;
use crate::{CaptureError, CaptureFormat, Interface, PacketSource, PcapNgReader, PcapReader, RecordMeta};

const READ_BUFFER: usize = 4 * 1024 * 1024;

/// Detects the capture format from the first four bytes.
pub fn detect_format(magic: [u8; 4]) -> Option<CaptureFormat> {
    if u32::from_le_bytes(magic) == SHB_TYPE {
        Some(CaptureFormat::PcapNg)
    } else if is_pcap_magic(magic) {
        let nanosecond = matches!(magic, [0x4d, 0x3c, 0xb2, 0xa1] | [0xa1, 0xb2, 0x3c, 0x4d]);
        Some(CaptureFormat::Pcap { nanosecond })
    } else {
        None
    }
}

/// Format-agnostic file reader.
pub enum CaptureReader<R> {
    Pcap(PcapReader<R>),
    PcapNg(PcapNgReader<R>),
}

impl CaptureReader<BufReader<File>> {
    pub fn open(path: &Path) -> Result<Self, CaptureError> {
        let mut file = File::open(path)?;
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic).map_err(|e| crate::error::eof_as_truncated(e, 0))?;
        let format = detect_format(magic).ok_or(CaptureError::UnknownFormat)?;
        file.seek(SeekFrom::Start(0))?;
        let buffered = BufReader::with_capacity(READ_BUFFER, file);
        Ok(match format {
            CaptureFormat::PcapNg => CaptureReader::PcapNg(PcapNgReader::new(buffered)?),
            CaptureFormat::Pcap { .. } => CaptureReader::Pcap(PcapReader::new(buffered)?),
        })
    }
}

impl<R: Read> CaptureReader<R> {
    pub fn from_reader(mut inner: R) -> Result<CaptureReader<Prefixed<R>>, CaptureError> {
        let mut magic = [0u8; 4];
        inner.read_exact(&mut magic).map_err(|e| crate::error::eof_as_truncated(e, 0))?;
        let format = detect_format(magic).ok_or(CaptureError::UnknownFormat)?;
        let prefixed = Prefixed { prefix: magic, pos: 0, inner };
        Ok(match format {
            CaptureFormat::PcapNg => CaptureReader::PcapNg(PcapNgReader::new(prefixed)?),
            CaptureFormat::Pcap { .. } => CaptureReader::Pcap(PcapReader::new(prefixed)?),
        })
    }
}

impl<R: Read> PacketSource for CaptureReader<R> {
    fn next_record(&mut self, buf: &mut Vec<u8>) -> Result<Option<RecordMeta>, CaptureError> {
        match self {
            CaptureReader::Pcap(r) => r.next_record(buf),
            CaptureReader::PcapNg(r) => r.next_record(buf),
        }
    }

    fn interfaces(&self) -> &[Interface] {
        match self {
            CaptureReader::Pcap(r) => r.interfaces(),
            CaptureReader::PcapNg(r) => r.interfaces(),
        }
    }

    fn format(&self) -> CaptureFormat {
        match self {
            CaptureReader::Pcap(r) => r.format(),
            CaptureReader::PcapNg(r) => r.format(),
        }
    }

    fn bytes_consumed(&self) -> u64 {
        match self {
            CaptureReader::Pcap(r) => r.bytes_consumed(),
            CaptureReader::PcapNg(r) => r.bytes_consumed(),
        }
    }
}

/// Reader that replays already-consumed magic bytes before the inner reader.
pub struct Prefixed<R> {
    prefix: [u8; 4],
    pos: usize,
    inner: R,
}

impl<R: Read> Read for Prefixed<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.inner.read(buf)
    }
}

/// Reads until `buf` is full or EOF; returns the number of bytes read.
pub(crate) fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, CaptureError> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(CaptureError::Io(e)),
        }
    }
    Ok(filled)
}

/// Replaces the contents of `buf` with exactly `len` bytes from `reader`.
pub(crate) fn read_into_vec<R: Read>(reader: &mut R, buf: &mut Vec<u8>, len: usize) -> io::Result<()> {
    buf.clear();
    buf.resize(len, 0);
    reader.read_exact(buf)
}

pub(crate) fn skip_bytes<R: Read>(reader: &mut R, n: u64) -> io::Result<()> {
    let copied = io::copy(&mut reader.by_ref().take(n), &mut io::sink())?;
    if copied < n {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PcapNgWriter, PcapWriter};
    use nettrace_packet::{LinkType, Timestamp};
    use std::io::Write;

    #[test]
    fn detects_formats() {
        assert_eq!(detect_format([0x0a, 0x0d, 0x0d, 0x0a]), Some(CaptureFormat::PcapNg));
        assert_eq!(detect_format([0xd4, 0xc3, 0xb2, 0xa1]), Some(CaptureFormat::Pcap { nanosecond: false }));
        assert_eq!(detect_format([0x4d, 0x3c, 0xb2, 0xa1]), Some(CaptureFormat::Pcap { nanosecond: true }));
        assert_eq!(detect_format([0, 0, 0, 0]), None);
    }

    #[test]
    fn opens_files_of_both_formats() {
        let dir = tempfile::tempdir().unwrap();
        let pcap = dir.path().join("a.pcap");
        let mut bytes = Vec::new();
        {
            let mut w = PcapWriter::new(&mut bytes, LinkType::Ethernet, false).unwrap();
            w.write(Timestamp::from_parts(1, 0), &[1, 2], 2).unwrap();
        }
        File::create(&pcap).unwrap().write_all(&bytes).unwrap();
        let mut r = CaptureReader::open(&pcap).unwrap();
        assert!(matches!(r, CaptureReader::Pcap(_)));
        let mut buf = Vec::new();
        assert!(r.next_record(&mut buf).unwrap().is_some());

        let ng = dir.path().join("b.pcapng");
        let mut bytes = Vec::new();
        {
            let mut w = PcapNgWriter::new(&mut bytes).unwrap();
            w.add_interface(LinkType::Ethernet, 0, None, None).unwrap();
            w.write_epb(0, Timestamp::from_parts(1, 0), &[3], 1).unwrap();
        }
        File::create(&ng).unwrap().write_all(&bytes).unwrap();
        let mut r = CaptureReader::open(&ng).unwrap();
        assert_eq!(r.format(), CaptureFormat::PcapNg);
        assert!(r.next_record(&mut buf).unwrap().is_some());
        assert!(r.next_record(&mut buf).unwrap().is_none());

        let junk = dir.path().join("c.bin");
        File::create(&junk).unwrap().write_all(b"hello world").unwrap();
        assert!(matches!(CaptureReader::open(&junk), Err(CaptureError::UnknownFormat)));
    }

    #[test]
    fn from_reader_replays_magic() {
        let mut bytes = Vec::new();
        {
            let mut w = PcapWriter::new(&mut bytes, LinkType::Raw, false).unwrap();
            w.write(Timestamp::from_parts(5, 0), &[0x45], 1).unwrap();
        }
        let mut r = CaptureReader::from_reader(&bytes[..]).unwrap();
        assert_eq!(r.interfaces()[0].link_type, LinkType::Raw);
        let mut buf = Vec::new();
        let m = r.next_record(&mut buf).unwrap().unwrap();
        assert_eq!(m.offset, 40);
    }
}
