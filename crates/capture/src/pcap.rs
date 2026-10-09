use std::io::Read;

use nettrace_packet::{LinkType, Timestamp};

use crate::error::eof_as_truncated;
use crate::reader::{read_full, read_into_vec};
use crate::{CaptureError, CaptureFormat, Interface, PacketSource, RecordMeta, MAX_RECORD_LEN};

const GLOBAL_HEADER_LEN: u64 = 24;

#[derive(Debug, Clone, Copy)]
struct Variant {
    big_endian: bool,
    nanosecond: bool,
    /// Kuznetzov "modified pcap" adds 8 bytes to every record header.
    modified: bool,
}

fn variant_from_magic(magic: [u8; 4]) -> Option<Variant> {
    let v = |big_endian, nanosecond, modified| Some(Variant { big_endian, nanosecond, modified });
    match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => v(false, false, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => v(true, false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => v(false, true, false),
        [0xa1, 0xb2, 0x3c, 0x4d] => v(true, true, false),
        [0x34, 0xcd, 0xb2, 0xa1] => v(false, false, true),
        [0xa1, 0xb2, 0xcd, 0x34] => v(true, false, true),
        _ => None,
    }
}

pub(crate) fn is_pcap_magic(magic: [u8; 4]) -> bool {
    variant_from_magic(magic).is_some()
}

/// Streaming reader for classic libpcap files.
pub struct PcapReader<R> {
    inner: R,
    variant: Variant,
    interfaces: Vec<Interface>,
    consumed: u64,
}

impl<R: Read> PcapReader<R> {
    pub fn new(mut inner: R) -> Result<Self, CaptureError> {
        let mut hdr = [0u8; GLOBAL_HEADER_LEN as usize];
        inner.read_exact(&mut hdr).map_err(|e| eof_as_truncated(e, 0))?;
        let variant = variant_from_magic([hdr[0], hdr[1], hdr[2], hdr[3]])
            .ok_or(CaptureError::UnknownFormat)?;
        let u16_at = |at: usize| {
            let b = [hdr[at], hdr[at + 1]];
            if variant.big_endian { u16::from_be_bytes(b) } else { u16::from_le_bytes(b) }
        };
        let u32_at = |at: usize| {
            let b = [hdr[at], hdr[at + 1], hdr[at + 2], hdr[at + 3]];
            if variant.big_endian { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) }
        };
        let (major, minor) = (u16_at(4), u16_at(6));
        if major != 2 {
            return Err(CaptureError::UnsupportedVersion { major, minor });
        }
        let snaplen = u32_at(16);
        // The upper bits of the link type field carry FCS information.
        let link_type = LinkType::from_raw(u32_at(20) & 0x0fff_ffff);
        Ok(Self {
            inner,
            variant,
            interfaces: vec![Interface::new(link_type, snaplen)],
            consumed: GLOBAL_HEADER_LEN,
        })
    }

    fn u32(&self, b: &[u8]) -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if self.variant.big_endian { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) }
    }
}

impl<R: Read> PacketSource for PcapReader<R> {
    fn next_record(&mut self, buf: &mut Vec<u8>) -> Result<Option<RecordMeta>, CaptureError> {
        let header_len = if self.variant.modified { 24 } else { 16 };
        let mut hdr = [0u8; 24];
        let record_start = self.consumed;
        let got = read_full(&mut self.inner, &mut hdr[..header_len])?;
        if got == 0 {
            return Ok(None);
        }
        if got < header_len {
            return Err(CaptureError::Truncated { offset: record_start });
        }
        let secs = self.u32(&hdr[0..4]);
        let frac = self.u32(&hdr[4..8]);
        let caplen = self.u32(&hdr[8..12]);
        let origlen = self.u32(&hdr[12..16]);
        if caplen > MAX_RECORD_LEN {
            return Err(CaptureError::Corrupt { offset: record_start, reason: "record length too large" });
        }
        // Some writers emit a fraction of a full second or more; normalize instead of rejecting.
        let frac_ns = u64::from(frac) * if self.variant.nanosecond { 1 } else { 1000 };
        let secs = i64::from(secs) + (frac_ns / 1_000_000_000) as i64;
        let frac_nanos = (frac_ns % 1_000_000_000) as u32;
        let data_offset = record_start + header_len as u64;
        read_into_vec(&mut self.inner, buf, caplen as usize)
            .map_err(|e| eof_as_truncated(e, record_start))?;
        self.consumed = data_offset + u64::from(caplen);
        Ok(Some(RecordMeta {
            offset: data_offset,
            ts: Timestamp::from_parts(secs, frac_nanos),
            caplen,
            origlen,
            interface: 0,
        }))
    }

    fn interfaces(&self) -> &[Interface] {
        &self.interfaces
    }

    fn format(&self) -> CaptureFormat {
        CaptureFormat::Pcap { nanosecond: self.variant.nanosecond }
    }

    fn bytes_consumed(&self) -> u64 {
        self.consumed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PcapWriter;

    fn sample(nanos: bool) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut w = PcapWriter::new(&mut out, LinkType::Ethernet, nanos).unwrap();
            w.write(Timestamp::from_parts(10, 500_000_000), &[1, 2, 3, 4], 60).unwrap();
            w.write(Timestamp::from_parts(11, 1_000), &[5; 10], 10).unwrap();
        }
        out
    }

    #[test]
    fn reads_records_with_offsets() {
        let data = sample(false);
        let mut r = PcapReader::new(&data[..]).unwrap();
        assert_eq!(r.interfaces()[0].link_type, LinkType::Ethernet);
        let mut buf = Vec::new();
        let m = r.next_record(&mut buf).unwrap().unwrap();
        assert_eq!(m.offset, 24 + 16);
        assert_eq!((m.caplen, m.origlen), (4, 60));
        assert_eq!(m.ts, Timestamp::from_parts(10, 500_000_000));
        assert_eq!(buf, [1, 2, 3, 4]);
        assert_eq!(&data[m.offset as usize..m.offset as usize + 4], &buf[..]);
        let m2 = r.next_record(&mut buf).unwrap().unwrap();
        assert_eq!(m2.offset, 24 + 16 + 4 + 16);
        assert_eq!(m2.ts, Timestamp::from_parts(11, 1_000));
        assert!(r.next_record(&mut buf).unwrap().is_none());
        assert_eq!(r.bytes_consumed(), data.len() as u64);
    }

    #[test]
    fn nanosecond_variant() {
        let data = sample(true);
        let mut r = PcapReader::new(&data[..]).unwrap();
        assert_eq!(r.format(), CaptureFormat::Pcap { nanosecond: true });
        let mut buf = Vec::new();
        r.next_record(&mut buf).unwrap();
        let m = r.next_record(&mut buf).unwrap().unwrap();
        assert_eq!(m.ts, Timestamp::from_parts(11, 1_000));
    }

    #[test]
    fn big_endian_header() {
        let mut data = vec![0xa1, 0xb2, 0xc3, 0xd4, 0, 2, 0, 4];
        data.extend_from_slice(&[0; 8]);
        data.extend_from_slice(&65535u32.to_be_bytes());
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&7u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&2u32.to_be_bytes());
        data.extend_from_slice(&2u32.to_be_bytes());
        data.extend_from_slice(&[0xaa, 0xbb]);
        let mut r = PcapReader::new(&data[..]).unwrap();
        let mut buf = Vec::new();
        let m = r.next_record(&mut buf).unwrap().unwrap();
        assert_eq!(m.ts.secs(), 7);
        assert_eq!(buf, [0xaa, 0xbb]);
    }

    #[test]
    fn truncated_record_is_reported() {
        let mut data = sample(false);
        data.truncate(data.len() - 3);
        let mut r = PcapReader::new(&data[..]).unwrap();
        let mut buf = Vec::new();
        assert!(r.next_record(&mut buf).unwrap().is_some());
        assert!(matches!(r.next_record(&mut buf), Err(CaptureError::Truncated { .. })));
    }

    #[test]
    fn truncated_record_header() {
        let mut data = sample(false);
        data.truncate(24 + 16 + 4 + 5);
        let mut r = PcapReader::new(&data[..]).unwrap();
        let mut buf = Vec::new();
        r.next_record(&mut buf).unwrap();
        assert!(matches!(r.next_record(&mut buf), Err(CaptureError::Truncated { offset: 44 })));
    }

    #[test]
    fn oversized_record_is_corrupt() {
        let mut data = sample(false);
        data[24 + 8..24 + 12].copy_from_slice(&(MAX_RECORD_LEN + 1).to_le_bytes());
        let mut r = PcapReader::new(&data[..]).unwrap();
        let mut buf = Vec::new();
        assert!(matches!(r.next_record(&mut buf), Err(CaptureError::Corrupt { .. })));
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(PcapReader::new(&[0u8; 24][..]), Err(CaptureError::UnknownFormat)));
        assert!(matches!(PcapReader::new(&[0xd4u8, 0xc3][..]), Err(CaptureError::Truncated { .. })));
    }
}
