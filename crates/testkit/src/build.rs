//! Byte-level builders for protocol headers. They produce well-formed packets
//! (correct lengths and IPv4 checksums) so tests exercise real parsing paths.

pub const MAC_A: [u8; 6] = [0x00, 0x1f, 0x1a, 0x2b, 0x3c, 0x01];
pub const MAC_B: [u8; 6] = [0x48, 0x8f, 0x5a, 0xdb, 0x11, 0x22];
pub const MAC_BCAST: [u8; 6] = [0xff; 6];

pub const ETH_IPV4: u16 = 0x0800;
pub const ETH_IPV6: u16 = 0x86dd;
pub const ETH_ARP: u16 = 0x0806;
pub const ETH_VLAN: u16 = 0x8100;

pub mod tcpf {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for c in data.chunks(2) {
        let w = if c.len() == 2 { u16::from_be_bytes([c[0], c[1]]) } else { u16::from(c[0]) << 8 };
        sum += u32::from(w);
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn ethernet(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(14 + payload.len());
    out.extend_from_slice(&dst);
    out.extend_from_slice(&src);
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(payload);
    // Pad to the 60-byte Ethernet minimum like real NICs do.
    while out.len() < 60 {
        out.push(0);
    }
    out
}

pub fn vlan_tag(id: u16, priority: u8, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let tci = (u16::from(priority & 0x07) << 13) | (id & 0x0fff);
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&tci.to_be_bytes());
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, id: u16, ttl: u8, payload: &[u8]) -> Vec<u8> {
    let total = (20 + payload.len()) as u16;
    let mut h = vec![0x45, 0x00];
    h.extend_from_slice(&total.to_be_bytes());
    h.extend_from_slice(&id.to_be_bytes());
    h.extend_from_slice(&0x4000u16.to_be_bytes());
    h.push(ttl);
    h.push(proto);
    h.extend_from_slice(&[0, 0]);
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let c = checksum(&h);
    h[10..12].copy_from_slice(&c.to_be_bytes());
    h.extend_from_slice(payload);
    h
}

pub fn ipv6(src: [u8; 16], dst: [u8; 16], next: u8, hop_limit: u8, payload: &[u8]) -> Vec<u8> {
    let mut h = vec![0x60, 0, 0, 0];
    h.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    h.push(next);
    h.push(hop_limit);
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    h.extend_from_slice(payload);
    h
}

#[derive(Debug, Clone, Default)]
pub struct TcpSegment {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub options: Vec<u8>,
    pub payload: Vec<u8>,
}

pub fn tcp(seg: &TcpSegment) -> Vec<u8> {
    let mut opts = seg.options.clone();
    while !opts.len().is_multiple_of(4) {
        opts.push(1);
    }
    let hdr_len = 20 + opts.len();
    let mut out = Vec::with_capacity(hdr_len + seg.payload.len());
    out.extend_from_slice(&seg.sport.to_be_bytes());
    out.extend_from_slice(&seg.dport.to_be_bytes());
    out.extend_from_slice(&seg.seq.to_be_bytes());
    out.extend_from_slice(&seg.ack.to_be_bytes());
    out.push(((hdr_len / 4) as u8) << 4);
    out.push(seg.flags);
    out.extend_from_slice(&seg.window.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&opts);
    out.extend_from_slice(&seg.payload);
    out
}

/// MSS + SACK_PERM + window scale options as sent in a SYN.
pub fn syn_options(mss: u16, wscale: u8) -> Vec<u8> {
    let mut o = vec![2, 4];
    o.extend_from_slice(&mss.to_be_bytes());
    o.extend_from_slice(&[4, 2, 1, 3, 3, wscale]);
    o
}

pub fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&sport.to_be_bytes());
    out.extend_from_slice(&dport.to_be_bytes());
    out.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);
    out
}

pub fn icmp_echo(request: bool, ident: u16, seq: u16, data: &[u8]) -> Vec<u8> {
    let mut out = vec![if request { 8 } else { 0 }, 0, 0, 0];
    out.extend_from_slice(&ident.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(data);
    let c = checksum(&out);
    out[2..4].copy_from_slice(&c.to_be_bytes());
    out
}

pub fn icmp_port_unreachable(original_ip_packet: &[u8]) -> Vec<u8> {
    let mut out = vec![3, 3, 0, 0, 0, 0, 0, 0];
    out.extend_from_slice(&original_ip_packet[..original_ip_packet.len().min(28)]);
    let c = checksum(&out);
    out[2..4].copy_from_slice(&c.to_be_bytes());
    out
}

pub fn icmpv6_echo(request: bool, ident: u16, seq: u16) -> Vec<u8> {
    let mut out = vec![if request { 128 } else { 129 }, 0, 0, 0];
    out.extend_from_slice(&ident.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(b"abcdefgh");
    out
}

pub fn icmpv6_neighbor_solicitation(target: [u8; 16], mac: [u8; 6]) -> Vec<u8> {
    let mut out = vec![135, 0, 0, 0, 0, 0, 0, 0];
    out.extend_from_slice(&target);
    out.extend_from_slice(&[1, 1]);
    out.extend_from_slice(&mac);
    out
}

pub fn arp(op: u16, sha: [u8; 6], spa: [u8; 4], tha: [u8; 6], tpa: [u8; 4]) -> Vec<u8> {
    let mut out = vec![0, 1, 0x08, 0x00, 6, 4];
    out.extend_from_slice(&op.to_be_bytes());
    out.extend_from_slice(&sha);
    out.extend_from_slice(&spa);
    out.extend_from_slice(&tha);
    out.extend_from_slice(&tpa);
    out
}

fn dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

pub fn dns_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(&dns_name(name));
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

/// Response with one A record (compressed name) and optionally a CNAME first.
pub fn dns_response_a(id: u16, name: &str, cname: Option<&str>, addr: [u8; 4]) -> Vec<u8> {
    let answers: u16 = if cname.is_some() { 2 } else { 1 };
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x8180u16.to_be_bytes());
    out.extend_from_slice(&[0, 1]);
    out.extend_from_slice(&answers.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&dns_name(name));
    out.extend_from_slice(&[0, 1, 0, 1]);
    let mut owner = vec![0xc0, 12];
    if let Some(c) = cname {
        let target = dns_name(c);
        out.extend_from_slice(&owner);
        out.extend_from_slice(&[0, 5, 0, 1]);
        out.extend_from_slice(&300u32.to_be_bytes());
        out.extend_from_slice(&(target.len() as u16).to_be_bytes());
        let target_at = out.len();
        out.extend_from_slice(&target);
        owner = vec![0xc0 | ((target_at >> 8) as u8), target_at as u8];
    }
    out.extend_from_slice(&owner);
    out.extend_from_slice(&[0, 1, 0, 1]);
    out.extend_from_slice(&60u32.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&addr);
    out
}

pub fn dns_response_nxdomain(id: u16, name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x8183u16.to_be_bytes());
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(&dns_name(name));
    out.extend_from_slice(&[0, 1, 0, 1]);
    out
}

pub fn dhcp(msg_type: u8, xid: u32, mac: [u8; 6], yiaddr: [u8; 4], hostname: Option<&str>) -> Vec<u8> {
    let op = if matches!(msg_type, 2 | 5 | 6) { 2 } else { 1 };
    let mut out = vec![op, 1, 6, 0];
    out.extend_from_slice(&xid.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0x80, 0]);
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&yiaddr);
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&mac);
    out.extend_from_slice(&[0; 10]);
    out.extend_from_slice(&[0; 192]);
    out.extend_from_slice(&0x6382_5363u32.to_be_bytes());
    out.extend_from_slice(&[53, 1, msg_type]);
    if let Some(h) = hostname {
        out.push(12);
        out.push(h.len() as u8);
        out.extend_from_slice(h.as_bytes());
    }
    if op == 2 {
        out.extend_from_slice(&[1, 4, 255, 255, 255, 0, 3, 4, 192, 168, 1, 1, 51, 4, 0, 0, 0x0e, 0x10]);
        out.extend_from_slice(&[54, 4, 192, 168, 1, 1]);
    } else {
        out.extend_from_slice(&[55, 4, 1, 3, 6, 15]);
    }
    out.push(255);
    out
}

pub fn ntp_client(transmit_unix_secs: u32) -> Vec<u8> {
    let mut out = vec![0x23, 0, 6, 0xec];
    out.extend_from_slice(&[0; 12]);
    out.extend_from_slice(&[0; 24]);
    let ntp_secs = u64::from(transmit_unix_secs) + 2_208_988_800;
    out.extend_from_slice(&((ntp_secs << 32) | 0x4000_0000).to_be_bytes());
    out
}

pub fn ntp_server(transmit_unix_secs: u32) -> Vec<u8> {
    let mut out = ntp_client(transmit_unix_secs);
    out[0] = 0x24;
    out[1] = 2;
    out[12..16].copy_from_slice(&[192, 168, 1, 1]);
    out
}

pub fn http_request(method: &str, host: &str, uri: &str) -> Vec<u8> {
    format!("{method} {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: nettrace-test/1.0\r\nAccept: */*\r\n\r\n").into_bytes()
}

pub fn http_response(code: u16, phrase: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {code} {phrase}\r\nServer: test\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn tls_record(content_type: u8, version: u16, body: &[u8]) -> Vec<u8> {
    let mut out = vec![content_type];
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn tls_handshake(ty: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![ty];
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(body);
    out
}

fn ext(ty: u16, data: &[u8]) -> Vec<u8> {
    let mut out = ty.to_be_bytes().to_vec();
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

pub fn tls_client_hello(sni: &str) -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x11; 32]);
    body.push(0);
    let suites: [u16; 3] = [0x1301, 0x1302, 0xc02f];
    body.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    for s in suites {
        body.extend_from_slice(&s.to_be_bytes());
    }
    body.extend_from_slice(&[1, 0]);
    let mut sni_data = Vec::new();
    sni_data.extend_from_slice(&((sni.len() + 3) as u16).to_be_bytes());
    sni_data.push(0);
    sni_data.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    sni_data.extend_from_slice(sni.as_bytes());
    let mut alpn = vec![0, 12, 2, b'h', b'2', 8];
    alpn.extend_from_slice(b"http/1.1");
    let mut exts = Vec::new();
    exts.extend(ext(0, &sni_data));
    exts.extend(ext(10, &[0, 4, 0, 29, 0, 23]));
    exts.extend(ext(16, &alpn));
    exts.extend(ext(43, &[4, 3, 4, 3, 3]));
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    tls_record(22, 0x0301, &tls_handshake(1, &body))
}

pub fn tls_server_hello_tls13() -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x22; 32]);
    body.push(0);
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.push(0);
    let exts = ext(43, &[3, 4]);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    let mut out = tls_record(22, 0x0303, &tls_handshake(2, &body));
    out.extend(tls_record(20, 0x0303, &[1]));
    out.extend(tls_record(23, 0x0303, &[0xab; 48]));
    out
}

/// TLS 1.2 ServerHello + Certificate + ServerHelloDone in one segment.
pub fn tls12_server_flight(cert_cn: &str) -> Vec<u8> {
    let mut hello = vec![0x03, 0x03];
    hello.extend_from_slice(&[0x33; 32]);
    hello.push(0);
    hello.extend_from_slice(&0xc02fu16.to_be_bytes());
    hello.push(0);
    let cert = fake_certificate(cert_cn, "NetTrace Test CA");
    let mut certs = Vec::new();
    certs.extend_from_slice(&(cert.len() as u32).to_be_bytes()[1..]);
    certs.extend_from_slice(&cert);
    let mut cert_msg = Vec::new();
    cert_msg.extend_from_slice(&(certs.len() as u32).to_be_bytes()[1..]);
    cert_msg.extend_from_slice(&certs);
    let mut hs = tls_handshake(2, &hello);
    hs.extend(tls_handshake(11, &cert_msg));
    hs.extend(tls_handshake(14, &[]));
    tls_record(22, 0x0303, &hs)
}

pub fn tls_application_data(len: usize) -> Vec<u8> {
    tls_record(23, 0x0303, &vec![0x5a; len])
}

fn der(tag: u8, value: &[u8]) -> Vec<u8> {
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

/// Structurally valid (unsigned) DER certificate carrying CNs and validity.
pub fn fake_certificate(subject_cn: &str, issuer_cn: &str) -> Vec<u8> {
    let name = |cn: &str| {
        let atv = [der(0x06, &[0x55, 0x04, 0x03]), der(0x0c, cn.as_bytes())].concat();
        der(0x30, &der(0x31, &der(0x30, &atv)))
    };
    let validity = der(0x30, &[der(0x17, b"250101000000Z"), der(0x17, b"270101000000Z")].concat());
    let tbs = der(
        0x30,
        &[
            der(0xa0, &der(0x02, &[2])),
            der(0x02, &[0x01, 0x23]),
            der(0x30, &der(0x06, &[0x2a, 0x86, 0x48])),
            name(issuer_cn),
            validity,
            name(subject_cn),
            der(0x30, &[0u8; 16]),
        ]
        .concat(),
    );
    der(0x30, &[tbs, der(0x30, &der(0x06, &[0x2a])), der(0x03, &[0, 9, 9])].concat())
}
