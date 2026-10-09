//! Symbolic names for protocol constants.

pub fn ethertype(t: u16) -> &'static str {
    match t {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86dd => "IPv6",
        0x8100 => "802.1Q Virtual LAN",
        0x88a8 => "802.1ad Provider Bridge",
        0x9100 => "802.1Q (QinQ)",
        0x8847 => "MPLS unicast",
        0x8848 => "MPLS multicast",
        0x8863 => "PPPoE Discovery",
        0x8864 => "PPPoE Session",
        0x888e => "802.1X Authentication",
        0x88cc => "802.1 Link Layer Discovery Protocol (LLDP)",
        0x8035 => "RARP",
        0x88e5 => "802.1AE (MACsec)",
        0x88f7 => "PTPv2",
        _ => "Unknown",
    }
}

pub fn ip_proto(p: u8) -> &'static str {
    match p {
        0 => "IPv6 Hop-by-Hop Option",
        1 => "ICMP",
        2 => "IGMP",
        4 => "IPIP",
        6 => "TCP",
        17 => "UDP",
        41 => "IPv6",
        43 => "IPv6 Routing",
        44 => "IPv6 Fragment",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        59 => "IPv6 No Next Header",
        60 => "IPv6 Destination Options",
        89 => "OSPF",
        103 => "PIM",
        112 => "VRRP",
        132 => "SCTP",
        _ => "Unknown",
    }
}

pub fn icmp_type(t: u8) -> &'static str {
    match t {
        0 => "Echo (ping) reply",
        3 => "Destination unreachable",
        4 => "Source quench",
        5 => "Redirect",
        8 => "Echo (ping) request",
        9 => "Router advertisement",
        10 => "Router solicitation",
        11 => "Time-to-live exceeded",
        12 => "Parameter problem",
        13 => "Timestamp request",
        14 => "Timestamp reply",
        _ => "Unknown",
    }
}

pub fn icmp_unreach_code(c: u8) -> &'static str {
    match c {
        0 => "Network unreachable",
        1 => "Host unreachable",
        2 => "Protocol unreachable",
        3 => "Port unreachable",
        4 => "Fragmentation needed",
        5 => "Source route failed",
        6 => "Destination network unknown",
        7 => "Destination host unknown",
        9 => "Network administratively prohibited",
        10 => "Host administratively prohibited",
        13 => "Communication administratively filtered",
        _ => "Unknown code",
    }
}

pub fn icmpv6_type(t: u8) -> &'static str {
    match t {
        1 => "Destination Unreachable",
        2 => "Packet Too Big",
        3 => "Time Exceeded",
        4 => "Parameter Problem",
        128 => "Echo (ping) request",
        129 => "Echo (ping) reply",
        130 => "Multicast Listener Query",
        131 => "Multicast Listener Report",
        132 => "Multicast Listener Done",
        133 => "Router Solicitation",
        134 => "Router Advertisement",
        135 => "Neighbor Solicitation",
        136 => "Neighbor Advertisement",
        137 => "Redirect",
        143 => "Multicast Listener Report Message v2",
        _ => "Unknown",
    }
}

pub fn dns_type(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        13 => "HINFO",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        35 => "NAPTR",
        41 => "OPT",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        64 => "SVCB",
        65 => "HTTPS",
        99 => "SPF",
        252 => "AXFR",
        255 => "ANY",
        257 => "CAA",
        _ => "Unknown",
    }
}

pub fn dns_class(c: u16) -> &'static str {
    match c & 0x7fff {
        1 => "IN",
        3 => "CH",
        4 => "HS",
        254 => "NONE",
        255 => "ANY",
        _ => "Unknown",
    }
}

pub fn dns_rcode(r: u16) -> &'static str {
    match r {
        0 => "No error",
        1 => "Format error",
        2 => "Server failure",
        3 => "No such name",
        4 => "Not implemented",
        5 => "Refused",
        6 => "Name exists",
        7 => "RRset exists",
        8 => "RRset does not exist",
        9 => "Not authoritative",
        10 => "Name out of zone",
        _ => "Unknown",
    }
}

pub fn dns_opcode(o: u16) -> &'static str {
    match o {
        0 => "Standard query",
        1 => "Inverse query",
        2 => "Server status request",
        4 => "Zone change notification",
        5 => "Dynamic update",
        _ => "Unknown operation",
    }
}

pub fn dhcp_message_type(t: u8) -> &'static str {
    match t {
        1 => "Discover",
        2 => "Offer",
        3 => "Request",
        4 => "Decline",
        5 => "ACK",
        6 => "NAK",
        7 => "Release",
        8 => "Inform",
        9 => "Force Renew",
        10 => "Lease query",
        _ => "Unknown",
    }
}

pub fn dhcp_option(code: u8) -> &'static str {
    match code {
        0 => "Padding",
        1 => "Subnet Mask",
        2 => "Time Offset",
        3 => "Router",
        4 => "Time Server",
        6 => "Domain Name Server",
        12 => "Host Name",
        15 => "Domain Name",
        28 => "Broadcast Address",
        42 => "Network Time Protocol Servers",
        43 => "Vendor-Specific Information",
        44 => "NetBIOS over TCP/IP Name Server",
        50 => "Requested IP Address",
        51 => "IP Address Lease Time",
        53 => "DHCP Message Type",
        54 => "DHCP Server Identifier",
        55 => "Parameter Request List",
        56 => "Message",
        57 => "Maximum DHCP Message Size",
        58 => "Renewal Time Value",
        59 => "Rebinding Time Value",
        60 => "Vendor class identifier",
        61 => "Client identifier",
        66 => "TFTP Server Name",
        67 => "Bootfile name",
        81 => "Client Fully Qualified Domain Name",
        82 => "Agent Information Option",
        119 => "Domain Search",
        121 => "Classless Static Route",
        255 => "End",
        _ => "Unknown",
    }
}

pub fn tls_version(v: u16) -> &'static str {
    match v {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        v if v & 0x0f0f == 0x0a0a => "Reserved (GREASE)",
        _ => "Unknown",
    }
}

pub fn tls_content_type(t: u8) -> &'static str {
    match t {
        20 => "Change Cipher Spec",
        21 => "Alert",
        22 => "Handshake",
        23 => "Application Data",
        24 => "Heartbeat",
        _ => "Unknown",
    }
}

pub fn tls_handshake_type(t: u8) -> &'static str {
    match t {
        0 => "Hello Request",
        1 => "Client Hello",
        2 => "Server Hello",
        4 => "New Session Ticket",
        5 => "End Of Early Data",
        8 => "Encrypted Extensions",
        11 => "Certificate",
        12 => "Server Key Exchange",
        13 => "Certificate Request",
        14 => "Server Hello Done",
        15 => "Certificate Verify",
        16 => "Client Key Exchange",
        20 => "Finished",
        24 => "Key Update",
        _ => "Unknown",
    }
}

pub fn tls_extension(t: u16) -> &'static str {
    match t {
        0 => "server_name",
        1 => "max_fragment_length",
        5 => "status_request",
        10 => "supported_groups",
        11 => "ec_point_formats",
        13 => "signature_algorithms",
        16 => "application_layer_protocol_negotiation",
        18 => "signed_certificate_timestamp",
        21 => "padding",
        22 => "encrypt_then_mac",
        23 => "extended_master_secret",
        27 => "compress_certificate",
        28 => "record_size_limit",
        35 => "session_ticket",
        41 => "pre_shared_key",
        42 => "early_data",
        43 => "supported_versions",
        44 => "cookie",
        45 => "psk_key_exchange_modes",
        49 => "post_handshake_auth",
        50 => "signature_algorithms_cert",
        51 => "key_share",
        57 => "quic_transport_parameters",
        17513 => "application_settings",
        65037 => "encrypted_client_hello",
        65281 => "renegotiation_info",
        t if t & 0x0f0f == 0x0a0a => "Reserved (GREASE)",
        _ => "Unknown",
    }
}

pub fn tls_group(g: u16) -> &'static str {
    match g {
        23 => "secp256r1",
        24 => "secp384r1",
        25 => "secp521r1",
        29 => "x25519",
        30 => "x448",
        256 => "ffdhe2048",
        257 => "ffdhe3072",
        4588 => "X25519MLKEM768",
        g if g & 0x0f0f == 0x0a0a => "Reserved (GREASE)",
        _ => "Unknown",
    }
}

pub fn tls_alert(d: u8) -> &'static str {
    match d {
        0 => "Close Notify",
        10 => "Unexpected Message",
        20 => "Bad Record MAC",
        22 => "Record Overflow",
        40 => "Handshake Failure",
        42 => "Bad Certificate",
        43 => "Unsupported Certificate",
        44 => "Certificate Revoked",
        45 => "Certificate Expired",
        46 => "Certificate Unknown",
        47 => "Illegal Parameter",
        48 => "Unknown CA",
        49 => "Access Denied",
        50 => "Decode Error",
        51 => "Decrypt Error",
        70 => "Protocol Version",
        71 => "Insufficient Security",
        80 => "Internal Error",
        86 => "Inappropriate Fallback",
        90 => "User Canceled",
        109 => "Missing Extension",
        110 => "Unsupported Extension",
        112 => "Unrecognized Name",
        116 => "Certificate Required",
        120 => "No Application Protocol",
        _ => "Unknown",
    }
}

pub fn cipher_suite(c: u16) -> &'static str {
    match c {
        0x0000 => "TLS_NULL_WITH_NULL_NULL",
        0x0004 => "TLS_RSA_WITH_RC4_128_MD5",
        0x0005 => "TLS_RSA_WITH_RC4_128_SHA",
        0x000a => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0033 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x0039 => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        0x003c => "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003d => "TLS_RSA_WITH_AES_256_CBC_SHA256",
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x009e => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        0x009f => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        0x00ff => "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x1304 => "TLS_AES_128_CCM_SHA256",
        0x5600 => "TLS_FALLBACK_SCSV",
        0xc009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        0xc00a => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        0xc013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0xc023 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        0xc024 => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        0xc027 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xc028 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0xccaa => "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        c if c & 0x0f0f == 0x0a0a => "Reserved (GREASE)",
        _ => "Unknown",
    }
}

pub fn ntp_mode(m: u8) -> &'static str {
    match m {
        0 => "reserved",
        1 => "symmetric active",
        2 => "symmetric passive",
        3 => "client",
        4 => "server",
        5 => "broadcast",
        6 => "reserved for NTP control message",
        _ => "reserved for private use",
    }
}

pub fn arp_opcode(o: u16) -> &'static str {
    match o {
        1 => "request",
        2 => "reply",
        3 => "reverse request",
        4 => "reverse reply",
        _ => "unknown",
    }
}
