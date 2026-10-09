use nettrace_model::{FieldValue, ProtocolId, Transport};

use crate::context::{m, Ctx, Malformed};
use crate::fields as f;
use crate::format::{self, bits};
use crate::names;
use crate::registry::{AppDissector, Layer};

pub struct Ntp;
pub static NTP: Ntp = Ntp;

const P: ProtocolId = ProtocolId::Ntp;
/// Seconds between 1900-01-01 (NTP era 0) and the Unix epoch.
const NTP_UNIX_OFFSET: i64 = 2_208_988_800;

pub(crate) fn ntp_timestamp(raw: u64) -> String {
    if raw == 0 {
        return "NULL".to_owned();
    }
    let secs = (raw >> 32) as i64 - NTP_UNIX_OFFSET;
    let frac = raw & 0xffff_ffff;
    let nanos = ((frac * 1_000_000_000) >> 32) as u32;
    format::utc(secs, nanos)
}

fn short_format(v: u32) -> f64 {
    f64::from(v >> 16) + f64::from(v & 0xffff) / 65536.0
}

impl AppDissector for Ntp {
    fn protocol(&self) -> ProtocolId {
        P
    }

    fn udp_ports(&self) -> &'static [u16] {
        &[123]
    }

    fn accepts(&self, payload: &[u8], transport: Transport) -> bool {
        transport == Transport::Udp && payload.len() >= 48
    }

    fn dissect(&self, ctx: &mut Ctx, layer: Layer, _transport: Transport) -> Result<(), Malformed> {
        let mut c = layer.cursor();
        let start = c.offset();
        let flags = c.u8().map_err(m(P))?;
        let stratum = c.u8().map_err(m(P))?;
        let poll = c.u8().map_err(m(P))? as i8;
        let precision = c.u8().map_err(m(P))? as i8;
        let root_delay = c.be_u32().map_err(m(P))?;
        let root_disp = c.be_u32().map_err(m(P))?;
        let refid = c.array::<4>().map_err(m(P))?;
        let reft = c.be_u64().map_err(m(P))?;
        let org = c.be_u64().map_err(m(P))?;
        let rec = c.be_u64().map_err(m(P))?;
        let xmt = c.be_u64().map_err(m(P))?;
        let (li, vn, mode) = (flags >> 6, (flags >> 3) & 0x07, flags & 0x07);

        let t = &mut ctx.tree;
        t.open(&f::NTP, start, layer.len());
        t.heading(|| "Network Time Protocol (NTP Version ".to_owned() + &format!("{vn}, {})", names::ntp_mode(mode)));
        let fv = u64::from(flags);
        t.open_value(&f::NTP_FLAGS, start, 1, FieldValue::U64(fv), || format!("0x{flags:02x}"));
        t.add(&f::NTP_LI, start, 1, FieldValue::U64(u64::from(li)), || format!("{} = Leap Indicator: {li}", bits(fv, 0xc0, 8)));
        t.add(&f::NTP_VN, start, 1, FieldValue::U64(u64::from(vn)), || format!("{} = Version number: NTP Version {vn}", bits(fv, 0x38, 8)));
        t.add(&f::NTP_MODE, start, 1, FieldValue::U64(u64::from(mode)), || format!("{} = Mode: {} ({mode})", bits(fv, 0x07, 8), names::ntp_mode(mode)));
        t.close();
        t.uint(&f::NTP_STRATUM, start + 1, 1, u64::from(stratum));
        t.add(&f::NTP_POLL, start + 2, 1, FieldValue::I64(i64::from(poll)), || {
            format!("{poll} ({} seconds)", 2f64.powi(i32::from(poll)))
        });
        t.add(&f::NTP_PRECISION, start + 3, 1, FieldValue::I64(i64::from(precision)), || {
            format!("{precision} ({:.9} seconds)", 2f64.powi(i32::from(precision)))
        });
        let rd = short_format(root_delay);
        t.add(&f::NTP_ROOT_DELAY, start + 4, 4, FieldValue::F64(rd), || format!("{rd:.6} seconds"));
        let rdisp = short_format(root_disp);
        t.add(&f::NTP_ROOT_DISPERSION, start + 8, 4, FieldValue::F64(rdisp), || format!("{rdisp:.6} seconds"));
        t.add(&f::NTP_REFID, start + 12, 4, FieldValue::Bytes(refid.to_vec()), || {
            if stratum <= 1 && refid.iter().all(|b| b.is_ascii_graphic() || *b == 0) {
                format::text(&refid).trim_end_matches("\\x00").to_owned()
            } else {
                format!("{}.{}.{}.{}", refid[0], refid[1], refid[2], refid[3])
            }
        });
        for (field, at, v) in [
            (&f::NTP_REF_TS, 16, reft),
            (&f::NTP_ORG_TS, 24, org),
            (&f::NTP_REC_TS, 32, rec),
            (&f::NTP_XMT_TS, 40, xmt),
        ] {
            let s = ntp_timestamp(v);
            t.add(field, start + at, 8, FieldValue::Str(s.clone()), || s);
        }
        t.close();
        ctx.info.set(P, || format!("NTP Version {vn}, {}", names::ntp_mode(mode)));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps() {
        assert_eq!(ntp_timestamp(0), "NULL");
        let raw = ((NTP_UNIX_OFFSET as u64 + 1_700_000_000) << 32) | 0x8000_0000;
        assert_eq!(ntp_timestamp(raw), "2023-11-14 22:13:20.500000000 UTC");
        assert!((short_format(0x0001_8000) - 1.5).abs() < 1e-9);
    }
}
