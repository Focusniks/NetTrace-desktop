use std::io::Read;

use nettrace_packet::{LinkType, Timestamp};

use crate::error::eof_as_truncated;
use crate::reader::{read_full, read_into_vec, skip_bytes};
use crate::{CaptureError, CaptureFormat, Interface, PacketSource, RecordMeta, MAX_RECORD_LEN};

pub(crate) const SHB_TYPE: u32 = 0x0A0D_0D0A;
const IDB_TYPE: u32 = 1;
const PB_TYPE: u32 = 2;
const SPB_TYPE: u32 = 3;
const EPB_TYPE: u32 = 6;
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

/// Blocks larger than this are treated as corruption (protects against huge allocations).
const MAX_BLOCK_LEN: u32 = 16 * 1024 * 1024;
const MAX_INTERFACES: usize = 4096;

/// Streaming reader for pcapng files (SHB, IDB, EPB, SPB and obsolete PB).
/// Unknown block types are skipped.
pub struct PcapNgReader<R> {
    inner: R,
    big_endian: bool,
    interfaces: Vec<Interface>,
    /// Global index of interface 0 of the current section.
    section_base: usize,
    consumed: u64,
    last_ts: Timestamp,
    scratch: Vec<u8>,
}

impl<R: Read> PcapNgReader<R> {
    pub fn new(inner: R) -> Result<Self, CaptureError> {
        let mut reader = Self {
            inner,
            big_endian: false,
            interfaces: Vec::new(),
            section_base: 0,
            consumed: 0,
            last_ts: Timestamp::ZERO,
            scratch: Vec::new(),
        };
        let mut head = [0u8; 8];
        reader.inner.read_exact(&mut head).map_err(|e| eof_as_truncated(e, 0))?;
        if u32::from_le_bytes([head[0], head[1], head[2], head[3]]) != SHB_TYPE {
            return Err(CaptureError::UnknownFormat);
        }
        reader.consumed = 8;
        reader.read_section_header(head[4..8].try_into().unwrap_or([0; 4]), 0)?;
        Ok(reader)
    }

    fn u16(&self, b: &[u8]) -> u16 {
        let a = [b[0], b[1]];
        if self.big_endian { u16::from_be_bytes(a) } else { u16::from_le_bytes(a) }
    }

    fn u32(&self, b: &[u8]) -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if self.big_endian { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) }
    }

    fn read_exact_tracked(&mut self, buf: &mut [u8], block_start: u64) -> Result<(), CaptureError> {
        self.inner.read_exact(buf).map_err(|e| eof_as_truncated(e, block_start))?;
        self.consumed += buf.len() as u64;
        Ok(())
    }

    fn skip_tracked(&mut self, n: u64, block_start: u64) -> Result<(), CaptureError> {
        skip_bytes(&mut self.inner, n).map_err(|e| eof_as_truncated(e, block_start))?;
        self.consumed += n;
        Ok(())
    }

    /// Called after the 8-byte block header of an SHB has been consumed.
    fn read_section_header(&mut self, raw_len: [u8; 4], block_start: u64) -> Result<(), CaptureError> {
        let mut bom = [0u8; 4];
        self.read_exact_tracked(&mut bom, block_start)?;
        self.big_endian = match u32::from_le_bytes(bom) {
            BYTE_ORDER_MAGIC => false,
            m if m.swap_bytes() == BYTE_ORDER_MAGIC => true,
            _ => return Err(CaptureError::Corrupt { offset: block_start, reason: "bad byte-order magic" }),
        };
        let total_len = self.u32(&raw_len);
        if total_len < 28 || !total_len.is_multiple_of(4) || total_len > MAX_BLOCK_LEN {
            return Err(CaptureError::Corrupt { offset: block_start, reason: "bad section header length" });
        }
        let mut ver = [0u8; 4];
        self.read_exact_tracked(&mut ver, block_start)?;
        let major = self.u16(&ver[0..2]);
        if major != 1 {
            return Err(CaptureError::UnsupportedVersion { major, minor: self.u16(&ver[2..4]) });
        }
        // section length (8) + options + trailing length (4)
        self.skip_tracked(u64::from(total_len) - 16, block_start)?;
        self.section_base = self.interfaces.len();
        Ok(())
    }

    fn read_body(&mut self, len: usize, block_start: u64) -> Result<(), CaptureError> {
        read_into_vec(&mut self.inner, &mut self.scratch, len).map_err(|e| eof_as_truncated(e, block_start))?;
        self.consumed += len as u64;
        Ok(())
    }

    fn parse_interface(&mut self, block_start: u64) -> Result<(), CaptureError> {
        let body = std::mem::take(&mut self.scratch);
        let result = self.parse_interface_body(&body, block_start);
        self.scratch = body;
        result
    }

    fn parse_interface_body(&mut self, body: &[u8], block_start: u64) -> Result<(), CaptureError> {
        if body.len() < 8 {
            return Err(CaptureError::Corrupt { offset: block_start, reason: "short interface block" });
        }
        if self.interfaces.len() >= MAX_INTERFACES {
            return Err(CaptureError::Corrupt { offset: block_start, reason: "too many interfaces" });
        }
        let link_type = LinkType::from_raw(u32::from(self.u16(&body[0..2])));
        let snaplen = self.u32(&body[4..8]);
        let mut iface = Interface::new(link_type, snaplen);
        let mut opts = &body[8..];
        while opts.len() >= 4 {
            let code = self.u16(&opts[0..2]);
            let len = usize::from(self.u16(&opts[2..4]));
            let padded = (len + 3) & !3;
            let Some(value) = opts.get(4..4 + len) else { break };
            match code {
                0 => break,
                2 => iface.name = Some(String::from_utf8_lossy(value).into_owned()),
                3 => iface.description = Some(String::from_utf8_lossy(value).into_owned()),
                9 if len == 1 => {
                    let r = value[0];
                    let exp = u32::from(r & 0x7f);
                    let tps = if r & 0x80 != 0 { 2u64.checked_pow(exp) } else { 10u64.checked_pow(exp) };
                    // Resolutions finer than 10^-18 cannot be represented; keep default.
                    if let Some(tps) = tps.filter(|t| *t > 0) {
                        iface.ticks_per_sec = tps;
                    }
                }
                14 if len == 8 => {
                    let raw: [u8; 8] = value.try_into().unwrap_or([0; 8]);
                    iface.ts_offset_secs =
                        if self.big_endian { i64::from_be_bytes(raw) } else { i64::from_le_bytes(raw) };
                }
                _ => {}
            }
            opts = opts.get(4 + padded..).unwrap_or(&[]);
        }
        self.interfaces.push(iface);
        Ok(())
    }

    fn timestamp(&self, iface: usize, hi: u32, lo: u32) -> Timestamp {
        let ticks = (u64::from(hi) << 32) | u64::from(lo);
        let Some(info) = self.interfaces.get(iface) else { return Timestamp::ZERO };
        let base = Timestamp::from_ticks(ticks, info.ticks_per_sec);
        Timestamp::from_nanos(base.nanos().saturating_add(info.ts_offset_secs.saturating_mul(1_000_000_000)))
    }

    fn global_interface(&self, local: u32, block_start: u64) -> Result<usize, CaptureError> {
        let idx = self.section_base.saturating_add(local as usize);
        if idx >= self.interfaces.len() || idx > u16::MAX as usize {
            return Err(CaptureError::Corrupt { offset: block_start, reason: "packet references unknown interface" });
        }
        Ok(idx)
    }
}

impl<R: Read> PacketSource for PcapNgReader<R> {
    fn next_record(&mut self, buf: &mut Vec<u8>) -> Result<Option<RecordMeta>, CaptureError> {
        loop {
            let block_start = self.consumed;
            let mut head = [0u8; 8];
            let got = read_full(&mut self.inner, &mut head)?;
            if got == 0 {
                return Ok(None);
            }
            if got < 8 {
                return Err(CaptureError::Truncated { offset: block_start });
            }
            self.consumed += 8;
            let block_type = self.u32(&head[0..4]);
            // The SHB type value is a byte palindrome, so it is recognised in either byte order.
            if block_type == SHB_TYPE {
                self.read_section_header([head[4], head[5], head[6], head[7]], block_start)?;
                continue;
            }
            let total_len = self.u32(&head[4..8]);
            if total_len < 12 || !total_len.is_multiple_of(4) || total_len > MAX_BLOCK_LEN {
                return Err(CaptureError::Corrupt { offset: block_start, reason: "bad block length" });
            }
            // Body without the 8-byte header and 4-byte trailing length.
            let body_len = (total_len - 12) as usize;
            match block_type {
                EPB_TYPE | PB_TYPE => {
                    if body_len < 20 {
                        return Err(CaptureError::Corrupt { offset: block_start, reason: "short packet block" });
                    }
                    let mut fixed = [0u8; 20];
                    self.read_exact_tracked(&mut fixed, block_start)?;
                    let local_if = if block_type == EPB_TYPE {
                        self.u32(&fixed[0..4])
                    } else {
                        u32::from(self.u16(&fixed[0..2]))
                    };
                    let hi = self.u32(&fixed[4..8]);
                    let lo = self.u32(&fixed[8..12]);
                    let caplen = self.u32(&fixed[12..16]);
                    let origlen = self.u32(&fixed[16..20]);
                    if caplen > MAX_RECORD_LEN || caplen as usize > body_len - 20 {
                        return Err(CaptureError::Corrupt { offset: block_start, reason: "bad captured length" });
                    }
                    let iface = self.global_interface(local_if, block_start)?;
                    let data_offset = self.consumed;
                    read_into_vec(&mut self.inner, buf, caplen as usize)
                        .map_err(|e| eof_as_truncated(e, block_start))?;
                    self.consumed += u64::from(caplen);
                    // padding + options + trailing length
                    let rest = (body_len - 20 - caplen as usize) as u64 + 4;
                    self.skip_tracked(rest, block_start)?;
                    let ts = self.timestamp(iface, hi, lo);
                    self.last_ts = ts;
                    return Ok(Some(RecordMeta { offset: data_offset, ts, caplen, origlen, interface: iface as u16 }));
                }
                SPB_TYPE => {
                    if body_len < 4 {
                        return Err(CaptureError::Corrupt { offset: block_start, reason: "short simple packet block" });
                    }
                    let mut fixed = [0u8; 4];
                    self.read_exact_tracked(&mut fixed, block_start)?;
                    let origlen = self.u32(&fixed);
                    let iface = self.global_interface(0, block_start)?;
                    let snaplen = self.interfaces[iface].snaplen;
                    let mut caplen = origlen.min((body_len - 4) as u32);
                    if snaplen > 0 {
                        caplen = caplen.min(snaplen);
                    }
                    if caplen > MAX_RECORD_LEN {
                        return Err(CaptureError::Corrupt { offset: block_start, reason: "bad captured length" });
                    }
                    let data_offset = self.consumed;
                    read_into_vec(&mut self.inner, buf, caplen as usize)
                        .map_err(|e| eof_as_truncated(e, block_start))?;
                    self.consumed += u64::from(caplen);
                    self.skip_tracked((body_len - 4 - caplen as usize) as u64 + 4, block_start)?;
                    return Ok(Some(RecordMeta {
                        offset: data_offset,
                        ts: self.last_ts,
                        caplen,
                        origlen,
                        interface: iface as u16,
                    }));
                }
                IDB_TYPE => {
                    self.read_body(body_len, block_start)?;
                    self.skip_tracked(4, block_start)?;
                    self.parse_interface(block_start)?;
                }
                _ => {
                    self.skip_tracked(body_len as u64 + 4, block_start)?;
                }
            }
        }
    }

    fn interfaces(&self) -> &[Interface] {
        &self.interfaces
    }

    fn format(&self) -> CaptureFormat {
        CaptureFormat::PcapNg
    }

    fn bytes_consumed(&self) -> u64 {
        self.consumed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PcapNgWriter;

    fn sample() -> Vec<u8> {
        let mut out = Vec::new();
        let mut w = PcapNgWriter::new(&mut out).unwrap();
        let eth = w.add_interface(LinkType::Ethernet, 65535, Some("eth0"), None).unwrap();
        let raw = w.add_interface(LinkType::Raw, 65535, None, Some(9)).unwrap();
        w.write_epb(eth, Timestamp::from_parts(100, 250_000_000), &[1, 2, 3], 3).unwrap();
        w.write_custom_block(0x0000_0BAD, &[9; 7]).unwrap();
        w.write_epb(raw, Timestamp::from_parts(101, 123_456_789), &[4; 5], 9).unwrap();
        w.write_spb(&[7, 7, 7, 7], 4).unwrap();
        drop(w);
        out
    }

    #[test]
    fn reads_interfaces_packets_and_skips_unknown_blocks() {
        let data = sample();
        let mut r = PcapNgReader::new(&data[..]).unwrap();
        let mut buf = Vec::new();
        let m1 = r.next_record(&mut buf).unwrap().unwrap();
        assert_eq!(buf, [1, 2, 3]);
        assert_eq!(&data[m1.offset as usize..m1.offset as usize + 3], &[1, 2, 3]);
        assert_eq!(m1.interface, 0);
        assert_eq!(m1.ts, Timestamp::from_parts(100, 250_000_000));
        assert_eq!(r.interfaces()[0].name.as_deref(), Some("eth0"));

        let m2 = r.next_record(&mut buf).unwrap().unwrap();
        assert_eq!(m2.interface, 1);
        assert_eq!((m2.caplen, m2.origlen), (5, 9));
        assert_eq!(r.interfaces()[1].ticks_per_sec, 1_000_000_000);
        assert_eq!(m2.ts, Timestamp::from_parts(101, 123_456_789));

        let m3 = r.next_record(&mut buf).unwrap().unwrap();
        assert_eq!(buf, [7, 7, 7, 7]);
        assert_eq!(m3.ts, m2.ts);
        assert!(r.next_record(&mut buf).unwrap().is_none());
        assert_eq!(r.bytes_consumed(), data.len() as u64);
    }

    #[test]
    fn truncated_block_is_reported() {
        let mut data = sample();
        data.truncate(data.len() - 2);
        let mut r = PcapNgReader::new(&data[..]).unwrap();
        let mut buf = Vec::new();
        let mut last = Ok(None);
        for _ in 0..10 {
            last = r.next_record(&mut buf);
            if !matches!(last, Ok(Some(_))) {
                break;
            }
        }
        assert!(matches!(last, Err(CaptureError::Truncated { .. })));
    }

    #[test]
    fn packet_referencing_unknown_interface_is_corrupt() {
        let mut out = Vec::new();
        let mut w = PcapNgWriter::new(&mut out).unwrap();
        w.write_epb(3, Timestamp::ZERO, &[1], 1).unwrap();
        drop(w);
        let mut r = PcapNgReader::new(&out[..]).unwrap();
        assert!(matches!(r.next_record(&mut Vec::new()), Err(CaptureError::Corrupt { .. })));
    }

    #[test]
    fn bad_block_length_is_corrupt() {
        let mut data = sample();
        // First block after SHB (28 bytes) is the IDB; break its length.
        data[28 + 4..28 + 8].copy_from_slice(&7u32.to_le_bytes());
        let mut r = PcapNgReader::new(&data[..]).unwrap();
        assert!(matches!(r.next_record(&mut Vec::new()), Err(CaptureError::Corrupt { .. })));
    }

    #[test]
    fn caplen_larger_than_block_is_corrupt() {
        let mut out = Vec::new();
        let mut w = PcapNgWriter::new(&mut out).unwrap();
        w.add_interface(LinkType::Ethernet, 0, None, None).unwrap();
        w.write_epb(0, Timestamp::ZERO, &[1, 2, 3, 4], 4).unwrap();
        drop(w);
        let epb = out.len() - 36;
        out[epb + 20..epb + 24].copy_from_slice(&1000u32.to_le_bytes());
        let mut r = PcapNgReader::new(&out[..]).unwrap();
        assert!(matches!(r.next_record(&mut Vec::new()), Err(CaptureError::Corrupt { .. })));
    }
}
