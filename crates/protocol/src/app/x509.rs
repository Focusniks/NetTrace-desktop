//! Minimal, bounds-checked DER walker extracting display facts from an X.509
//! certificate: subject/issuer CommonName, validity and DNS SANs.

use nettrace_packet::Cursor;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct CertFacts {
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub dns_names: Vec<String>,
}

const MAX_DEPTH: usize = 8;

struct Tlv<'a> {
    tag: u8,
    value: Cursor<'a>,
}

fn read_tlv<'a>(c: &mut Cursor<'a>) -> Option<Tlv<'a>> {
    let tag = c.u8().ok()?;
    let first = c.u8().ok()?;
    let len = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | usize::from(c.u8().ok()?);
        }
        len
    };
    let value = c.sub(len).ok()?;
    Some(Tlv { tag, value })
}

const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];

fn string_value(tlv: &Tlv) -> Option<String> {
    match tlv.tag {
        0x0c | 0x13 | 0x14 | 0x16 | 0x1a => Some(crate::format::text(tlv.value.data())),
        0x1e => {
            // BMPString (UTF-16BE)
            let units: Vec<u16> =
                tlv.value.data().as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            Some(String::from_utf16_lossy(&units))
        }
        _ => None,
    }
}

fn common_name(mut name: Cursor) -> Option<String> {
    let mut found = None;
    for _ in 0..64 {
        let set = read_tlv(&mut name)?;
        let mut set_c = set.value;
        while let Some(atv) = read_tlv(&mut set_c) {
            let mut atv_c = atv.value;
            let oid = read_tlv(&mut atv_c)?;
            let value = read_tlv(&mut atv_c)?;
            if oid.tag == 0x06 && oid.value.data() == OID_CN {
                found = string_value(&value);
            }
        }
        if name.remaining() == 0 {
            break;
        }
    }
    found
}

fn time_value(tlv: &Tlv) -> Option<String> {
    let s = std::str::from_utf8(tlv.value.data()).ok()?;
    let digits = s.trim_end_matches('Z');
    let (year, rest) = match tlv.tag {
        0x17 if digits.len() >= 10 => {
            let yy: u32 = digits.get(0..2)?.parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, digits.get(2..)?)
        }
        0x18 if digits.len() >= 12 => (digits.get(0..4)?.parse().ok()?, digits.get(4..)?),
        _ => return None,
    };
    let part = |i: usize| rest.get(i..i + 2).unwrap_or("00");
    Some(format!("{year:04}-{}-{} {}:{}:{} UTC", part(0), part(2), part(4), part(6), part(8)))
}

fn san_names(ext_value: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut c = Cursor::new(ext_value);
    let Some(seq) = read_tlv(&mut c) else { return out };
    let mut s = seq.value;
    while let Some(gn) = read_tlv(&mut s) {
        if gn.tag == 0x82 && out.len() < 64 {
            out.push(crate::format::text(gn.value.data()));
        }
    }
    out
}

fn extensions(mut c: Cursor, facts: &mut CertFacts, depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    let Some(seq) = read_tlv(&mut c) else { return };
    let mut exts = seq.value;
    while let Some(ext) = read_tlv(&mut exts) {
        let mut e = ext.value;
        let Some(oid) = read_tlv(&mut e) else { continue };
        let mut next = read_tlv(&mut e);
        if next.as_ref().is_some_and(|t| t.tag == 0x01) {
            next = read_tlv(&mut e);
        }
        if oid.value.data() == OID_SAN {
            if let Some(v) = next.filter(|t| t.tag == 0x04) {
                facts.dns_names = san_names(v.value.data());
            }
        }
    }
}

/// Parses a DER certificate. Returns `None` if the structure is not a certificate.
pub fn parse(der: &[u8]) -> Option<CertFacts> {
    let mut c = Cursor::new(der);
    let cert = read_tlv(&mut c)?;
    if cert.tag != 0x30 {
        return None;
    }
    let mut cert_c = cert.value;
    let tbs = read_tlv(&mut cert_c)?;
    if tbs.tag != 0x30 {
        return None;
    }
    let mut tbs_c = tbs.value;
    let mut item = read_tlv(&mut tbs_c)?;
    if item.tag == 0xa0 {
        item = read_tlv(&mut tbs_c)?; // serial
    }
    let _ = item;
    let _signature = read_tlv(&mut tbs_c)?;
    let issuer = read_tlv(&mut tbs_c)?;
    let validity = read_tlv(&mut tbs_c)?;
    let subject = read_tlv(&mut tbs_c)?;
    let mut facts = CertFacts {
        issuer_cn: common_name(issuer.value),
        subject_cn: common_name(subject.value),
        ..CertFacts::default()
    };
    let mut v = validity.value;
    if let Some(nb) = read_tlv(&mut v) {
        facts.not_before = time_value(&nb);
    }
    if let Some(na) = read_tlv(&mut v) {
        facts.not_after = time_value(&na);
    }
    let _spki = read_tlv(&mut tbs_c);
    while let Some(opt) = read_tlv(&mut tbs_c) {
        if opt.tag == 0xa3 {
            extensions(opt.value, &mut facts, 1);
        }
    }
    Some(facts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if value.len() < 128 {
            out.push(value.len() as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(value);
        out
    }

    fn name(cn: &str) -> Vec<u8> {
        let atv = [tlv(0x06, OID_CN), tlv(0x0c, cn.as_bytes())].concat();
        tlv(0x30, &tlv(0x31, &tlv(0x30, &atv)))
    }

    /// Builds a structurally valid (unsigned) certificate for tests.
    pub fn fake_cert(subject: &str, issuer: &str, san: &str) -> Vec<u8> {
        let validity = tlv(0x30, &[tlv(0x17, b"240101000000Z"), tlv(0x17, b"250101000000Z")].concat());
        let san_ext = tlv(
            0x30,
            &[tlv(0x06, OID_SAN), tlv(0x04, &tlv(0x30, &tlv(0x82, san.as_bytes())))].concat(),
        );
        let exts = tlv(0xa3, &tlv(0x30, &san_ext));
        let tbs = tlv(
            0x30,
            &[
                tlv(0xa0, &tlv(0x02, &[2])),
                tlv(0x02, &[1]),
                tlv(0x30, &tlv(0x06, &[0x2a])),
                name(issuer),
                validity,
                name(subject),
                tlv(0x30, &[0u8; 4]),
                exts,
            ]
            .concat(),
        );
        tlv(0x30, &[tbs, tlv(0x30, &tlv(0x06, &[0x2a])), tlv(0x03, &[0, 1, 2])].concat())
    }

    #[test]
    fn extracts_names_validity_and_san() {
        let der = fake_cert("api.example.com", "Example CA", "www.example.com");
        let facts = parse(&der).unwrap();
        assert_eq!(facts.subject_cn.as_deref(), Some("api.example.com"));
        assert_eq!(facts.issuer_cn.as_deref(), Some("Example CA"));
        assert_eq!(facts.not_before.as_deref(), Some("2024-01-01 00:00:00 UTC"));
        assert_eq!(facts.dns_names, vec!["www.example.com".to_owned()]);
    }

    #[test]
    fn garbage_does_not_panic() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_none());
        let der = fake_cert("a", "b", "c");
        for cut in 0..der.len() {
            let _ = parse(&der[..cut]);
        }
    }
}
