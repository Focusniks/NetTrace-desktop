//! "Save displayed packets": writes the packets of a view to a new file.
//! PCAP is used when all packets share one link type, PCAPNG otherwise
//! (or when the target path ends in `.pcapng`).

use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

use nettrace_capture::{PcapNgWriter, PcapWriter};
use nettrace_packet::Timestamp;
use nettrace_storage::CaptureFile;

use crate::error::{EngineError, Result};
use crate::session::Shared;
use crate::view::View;

/// Writes to a temporary file next to `path` and renames it on success, so a
/// failure never leaves a truncated capture behind or clobbers an existing file.
pub fn write(sh: &Shared, file: &CaptureFile, view: &View, path: &Path) -> Result<u32> {
    let tmp = path.with_extension(format!(
        "{}.part",
        path.extension().map(|e| e.to_string_lossy().into_owned()).unwrap_or_default()
    ));
    let result = write_to(sh, file, view, path, &tmp);
    match result {
        Ok(n) => {
            std::fs::rename(&tmp, path)?;
            Ok(n)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn write_to(sh: &Shared, file: &CaptureFile, view: &View, path: &Path, tmp: &Path) -> Result<u32> {
    let len = view.len(sh);
    let indices: Vec<u32> = (0..len).filter_map(|r| view.packet_at(sh, r)).collect();
    let mut interfaces: Vec<u16> = indices.iter().filter_map(|i| sh.index.get(*i)).map(|m| m.interface).collect();
    interfaces.sort_unstable();
    interfaces.dedup();
    let link_types: Vec<_> = interfaces.iter().map(|i| sh.index.link_type(*i)).collect();
    let uniform = link_types.windows(2).all(|w| w[0] == w[1]);
    let want_ng = path.extension().is_some_and(|e| e.eq_ignore_ascii_case("pcapng"));
    let out = BufWriter::new(File::create(tmp)?);
    let mut buf = Vec::new();
    let mut count = 0u32;
    if want_ng || !uniform {
        let mut w = PcapNgWriter::new(out)?;
        let mut map = std::collections::HashMap::new();
        for (iface, link) in interfaces.iter().zip(&link_types) {
            map.insert(*iface, w.add_interface(*link, 262_144, None, Some(9))?);
        }
        for i in &indices {
            let Some(m) = sh.index.get(*i) else { continue };
            file.read_into(m.offset, m.caplen, &mut buf)?;
            let iface = map.get(&m.interface).copied().ok_or_else(|| EngineError::new("export", "interface missing"))?;
            w.write_epb(iface, Timestamp::from_nanos(m.ts_ns), &buf, m.origlen)?;
            count += 1;
        }
        finish(w.into_inner())?;
    } else {
        let link = link_types.first().copied().unwrap_or(nettrace_packet::LinkType::Ethernet);
        let mut w = PcapWriter::new(out, link, true)?;
        for i in &indices {
            let Some(m) = sh.index.get(*i) else { continue };
            file.read_into(m.offset, m.caplen, &mut buf)?;
            w.write(Timestamp::from_nanos(m.ts_ns), &buf, m.origlen)?;
            count += 1;
        }
        finish(w.into_inner())?;
    }
    Ok(count)
}

/// Flushes the buffer and syncs to disk; `BufWriter`'s drop would swallow errors.
fn finish(out: BufWriter<File>) -> Result<()> {
    let f = out.into_inner().map_err(|e| e.into_error())?;
    f.sync_all()?;
    Ok(())
}
