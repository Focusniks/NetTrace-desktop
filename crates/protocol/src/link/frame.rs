//! Generated "Frame" subtree (capture metadata, not packet bytes).

use nettrace_model::FieldValue;

use crate::context::{FrameContext, Summary};
use crate::fields as f;
use crate::format;
use crate::tree::Tree;

pub fn frame_tree(t: &mut Tree, fctx: &FrameContext, summary: &Summary, frame_len: usize) {
    t.open(&f::FRAME, 0, frame_len);
    t.heading(|| {
        let mut s = format!(
            "Frame {}: {} bytes on wire ({} bits), {} bytes captured ({} bits)",
            fctx.number,
            fctx.origlen,
            u64::from(fctx.origlen) * 8,
            fctx.caplen,
            u64::from(fctx.caplen) * 8
        );
        s.push_str(&format!(" on interface {}", fctx.interface));
        s
    });
    let link = fctx.link_type;
    t.add(&f::FRAME_ENCAP, 0, 0, FieldValue::Str(link.map(|l| l.name()).unwrap_or("Unknown").into()), || {
        match link {
            Some(l) => format!("{} ({})", l.name(), l.to_raw()),
            None => "Unknown".to_owned(),
        }
    });
    t.uint(&f::FRAME_INTERFACE, 0, 0, u64::from(fctx.interface));
    let (secs, nanos) = (fctx.ts.secs(), fctx.ts.subsec_nanos());
    t.add(&f::FRAME_TIME, 0, 0, FieldValue::Str(format::utc(secs, nanos)), || format::utc(secs, nanos));
    let epoch = secs as f64 + f64::from(nanos) / 1e9;
    t.add(&f::FRAME_TIME_EPOCH, 0, 0, FieldValue::F64(epoch), || format!("{secs}.{nanos:09} seconds"));
    let delta = fctx.time_delta_ns;
    t.add(&f::FRAME_TIME_DELTA, 0, 0, FieldValue::F64(delta as f64 / 1e9), || format::seconds(delta));
    let rel = fctx.time_rel_ns;
    t.add(&f::FRAME_TIME_RELATIVE, 0, 0, FieldValue::F64(rel as f64 / 1e9), || format::seconds(rel));
    t.uint(&f::FRAME_NUMBER, 0, 0, u64::from(fctx.number));
    let (orig, cap) = (fctx.origlen, fctx.caplen);
    t.add(&f::FRAME_LEN, 0, 0, FieldValue::U64(u64::from(orig)), || {
        format!("{orig} bytes ({} bits)", u64::from(orig) * 8)
    });
    t.add(&f::FRAME_CAP_LEN, 0, 0, FieldValue::U64(u64::from(cap)), || {
        format!("{cap} bytes ({} bits)", u64::from(cap) * 8)
    });
    // Also emitted in Values mode so `frame.protocols contains "..."` works in filters.
    let protocols: Vec<&str> = summary.path().skip(1).map(|p| p.filter_name()).collect();
    let joined = protocols.join(":");
    t.add(&f::FRAME_PROTOCOLS, 0, 0, FieldValue::Str(joined.clone()), || joined);
    t.close();
}
