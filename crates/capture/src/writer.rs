use std::io::{self, Write};

use nettrace_packet::{LinkType, Timestamp};

/// Writes little-endian classic pcap files.
pub struct PcapWriter<W: Write> {
    out: W,
    nanosecond: bool,
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut out: W, link_type: LinkType, nanosecond: bool) -> io::Result<Self> {
        let magic: u32 = if nanosecond { 0xa1b2_3c4d } else { 0xa1b2_c3d4 };
        out.write_all(&magic.to_le_bytes())?;
        out.write_all(&2u16.to_le_bytes())?;
        out.write_all(&4u16.to_le_bytes())?;
        out.write_all(&0i32.to_le_bytes())?;
        out.write_all(&0u32.to_le_bytes())?;
        out.write_all(&262_144u32.to_le_bytes())?;
        out.write_all(&link_type.to_raw().to_le_bytes())?;
        Ok(Self { out, nanosecond })
    }

    pub fn write(&mut self, ts: Timestamp, data: &[u8], origlen: u32) -> io::Result<()> {
        let caplen = u32::try_from(data.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let secs = u32::try_from(ts.secs().max(0)).unwrap_or(u32::MAX);
        let frac = if self.nanosecond { ts.subsec_nanos() } else { ts.subsec_nanos() / 1000 };
        self.out.write_all(&secs.to_le_bytes())?;
        self.out.write_all(&frac.to_le_bytes())?;
        self.out.write_all(&caplen.to_le_bytes())?;
        self.out.write_all(&origlen.max(caplen).to_le_bytes())?;
        self.out.write_all(data)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    /// Flushes and returns the underlying writer.
    pub fn into_inner(mut self) -> W {
        let _ = self.out.flush();
        self.out
    }
}

/// Minimal little-endian pcapng writer (used by tests and fixtures).
pub struct PcapNgWriter<W: Write> {
    out: W,
    interfaces: u32,
    /// Timestamp resolution exponent (10^-n) per interface.
    resolutions: Vec<u8>,
}

impl<W: Write> PcapNgWriter<W> {
    pub fn new(mut out: W) -> io::Result<Self> {
        // SHB: type, len, BOM, version 1.0, section length -1, len.
        let len: u32 = 28;
        out.write_all(&0x0A0D_0D0Au32.to_le_bytes())?;
        out.write_all(&len.to_le_bytes())?;
        out.write_all(&0x1A2B_3C4Du32.to_le_bytes())?;
        out.write_all(&1u16.to_le_bytes())?;
        out.write_all(&0u16.to_le_bytes())?;
        out.write_all(&(-1i64).to_le_bytes())?;
        out.write_all(&len.to_le_bytes())?;
        Ok(Self { out, interfaces: 0, resolutions: Vec::new() })
    }

    /// Adds an interface; `tsresol` is the decimal exponent (6 = µs, 9 = ns).
    pub fn add_interface(
        &mut self,
        link_type: LinkType,
        snaplen: u32,
        name: Option<&str>,
        tsresol: Option<u8>,
    ) -> io::Result<u32> {
        let mut opts = Vec::new();
        if let Some(name) = name {
            push_option(&mut opts, 2, name.as_bytes());
        }
        if let Some(r) = tsresol {
            push_option(&mut opts, 9, &[r]);
        }
        if !opts.is_empty() {
            push_option(&mut opts, 0, &[]);
        }
        let link = u16::try_from(link_type.to_raw()).unwrap_or(u16::MAX);
        let mut body = Vec::new();
        body.extend_from_slice(&link.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&snaplen.to_le_bytes());
        body.extend_from_slice(&opts);
        self.write_block(1, &body)?;
        self.resolutions.push(tsresol.unwrap_or(6));
        self.interfaces += 1;
        Ok(self.interfaces - 1)
    }

    pub fn write_epb(&mut self, interface: u32, ts: Timestamp, data: &[u8], origlen: u32) -> io::Result<()> {
        let exp = self.resolutions.get(interface as usize).copied().unwrap_or(6);
        let ticks_per_sec = 10u64.pow(u32::from(exp));
        let secs = u64::try_from(ts.secs().max(0)).unwrap_or(0);
        let frac = u64::from(ts.subsec_nanos()) * ticks_per_sec / 1_000_000_000;
        let ticks = secs * ticks_per_sec + frac;
        let caplen = u32::try_from(data.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let mut body = Vec::with_capacity(20 + data.len() + 3);
        body.extend_from_slice(&interface.to_le_bytes());
        body.extend_from_slice(&((ticks >> 32) as u32).to_le_bytes());
        body.extend_from_slice(&(ticks as u32).to_le_bytes());
        body.extend_from_slice(&caplen.to_le_bytes());
        body.extend_from_slice(&origlen.max(caplen).to_le_bytes());
        body.extend_from_slice(data);
        pad4(&mut body);
        self.write_block(6, &body)
    }

    pub fn write_spb(&mut self, data: &[u8], origlen: u32) -> io::Result<()> {
        let mut body = Vec::with_capacity(4 + data.len() + 3);
        body.extend_from_slice(&origlen.to_le_bytes());
        body.extend_from_slice(data);
        pad4(&mut body);
        self.write_block(3, &body)
    }

    pub fn write_custom_block(&mut self, block_type: u32, payload: &[u8]) -> io::Result<()> {
        let mut body = payload.to_vec();
        pad4(&mut body);
        self.write_block(block_type, &body)
    }

    /// Returns the underlying writer (callers flush it themselves).
    pub fn into_inner(self) -> W {
        self.out
    }

    fn write_block(&mut self, block_type: u32, body: &[u8]) -> io::Result<()> {
        let len = u32::try_from(body.len() + 12).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        self.out.write_all(&block_type.to_le_bytes())?;
        self.out.write_all(&len.to_le_bytes())?;
        self.out.write_all(body)?;
        self.out.write_all(&len.to_le_bytes())
    }
}

fn pad4(buf: &mut Vec<u8>) {
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

fn push_option(buf: &mut Vec<u8>, code: u16, value: &[u8]) {
    buf.extend_from_slice(&code.to_le_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_le_bytes());
    buf.extend_from_slice(value);
    pad4(buf);
}
