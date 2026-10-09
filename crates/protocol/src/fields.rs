//! Field registry: the single source of truth for field abbreviations used by
//! the protocol tree, the display filter and the UI autocompletion.

use nettrace_model::{FieldKind, ProtocolId};

#[derive(Debug, PartialEq, Eq)]
pub struct Field {
    pub abbrev: &'static str,
    pub name: &'static str,
    pub kind: FieldKind,
}

macro_rules! fields {
    ($( $ident:ident = $abbrev:literal, $name:literal, $kind:ident; )*) => {
        $( pub static $ident: Field = Field { abbrev: $abbrev, name: $name, kind: FieldKind::$kind }; )*
        /// Every registered field (excluding aliases).
        pub static ALL: &[&Field] = &[ $( &$ident ),* ];
    };
}

fields! {
    // Protocols (presence)
    FRAME = "frame", "Frame", Protocol;
    ETH = "eth", "Ethernet II", Protocol;
    VLAN = "vlan", "802.1Q Virtual LAN", Protocol;
    ARP = "arp", "Address Resolution Protocol", Protocol;
    IP = "ip", "Internet Protocol Version 4", Protocol;
    IPV6 = "ipv6", "Internet Protocol Version 6", Protocol;
    ICMP = "icmp", "Internet Control Message Protocol", Protocol;
    ICMPV6 = "icmpv6", "Internet Control Message Protocol v6", Protocol;
    TCP = "tcp", "Transmission Control Protocol", Protocol;
    UDP = "udp", "User Datagram Protocol", Protocol;
    DNS = "dns", "Domain Name System", Protocol;
    DHCP = "dhcp", "Dynamic Host Configuration Protocol", Protocol;
    HTTP = "http", "Hypertext Transfer Protocol", Protocol;
    TLS = "tls", "Transport Layer Security", Protocol;
    NTP = "ntp", "Network Time Protocol", Protocol;
    SLL = "sll", "Linux cooked capture", Protocol;
    NULL = "null", "Null/Loopback", Protocol;
    DATA = "data", "Data", Protocol;
    MALFORMED = "_ws.malformed", "Malformed Packet", Protocol;
    EXPERT = "_ws.expert", "Expert Info", None;

    // Frame (generated)
    FRAME_NUMBER = "frame.number", "Frame Number", Uint;
    FRAME_TIME = "frame.time", "Arrival Time", String;
    FRAME_TIME_EPOCH = "frame.time_epoch", "Epoch Arrival Time", Float;
    FRAME_TIME_RELATIVE = "frame.time_relative", "Time since reference or first frame", Float;
    FRAME_TIME_DELTA = "frame.time_delta", "Time delta from previous captured frame", Float;
    FRAME_LEN = "frame.len", "Frame Length", Uint;
    FRAME_CAP_LEN = "frame.cap_len", "Capture Length", Uint;
    FRAME_INTERFACE = "frame.interface_id", "Interface id", Uint;
    FRAME_ENCAP = "frame.encap_type", "Encapsulation type", String;
    FRAME_PROTOCOLS = "frame.protocols", "Protocols in frame", String;

    // Ethernet
    ETH_DST = "eth.dst", "Destination", Mac;
    ETH_SRC = "eth.src", "Source", Mac;
    ETH_TYPE = "eth.type", "Type", Uint;
    ETH_LEN = "eth.len", "Length", Uint;
    ETH_PADDING = "eth.padding", "Padding", Bytes;
    ETH_IG = "eth.ig", "IG bit", Bool;
    ETH_LG = "eth.lg", "LG bit", Bool;

    // 802.1Q
    VLAN_PRIORITY = "vlan.priority", "Priority", Uint;
    VLAN_DEI = "vlan.dei", "DEI", Bool;
    VLAN_ID = "vlan.id", "ID", Uint;
    VLAN_ETYPE = "vlan.etype", "Type", Uint;

    // Linux cooked / loopback
    SLL_PKTTYPE = "sll.pkttype", "Packet type", Uint;
    SLL_HATYPE = "sll.hatype", "Link-layer address type", Uint;
    SLL_HALEN = "sll.halen", "Link-layer address length", Uint;
    SLL_SRC = "sll.src.eth", "Source", Mac;
    SLL_ETYPE = "sll.etype", "Protocol", Uint;
    SLL_IFINDEX = "sll.ifindex", "Interface index", Uint;
    NULL_FAMILY = "null.family", "Family", Uint;

    // ARP
    ARP_HW_TYPE = "arp.hw.type", "Hardware type", Uint;
    ARP_PROTO_TYPE = "arp.proto.type", "Protocol type", Uint;
    ARP_HW_SIZE = "arp.hw.size", "Hardware size", Uint;
    ARP_PROTO_SIZE = "arp.proto.size", "Protocol size", Uint;
    ARP_OPCODE = "arp.opcode", "Opcode", Uint;
    ARP_SRC_HW = "arp.src.hw_mac", "Sender MAC address", Mac;
    ARP_SRC_IP = "arp.src.proto_ipv4", "Sender IP address", Ipv4;
    ARP_DST_HW = "arp.dst.hw_mac", "Target MAC address", Mac;
    ARP_DST_IP = "arp.dst.proto_ipv4", "Target IP address", Ipv4;
    ARP_GRATUITOUS = "arp.isgratuitous", "Is gratuitous", Bool;

    // IPv4
    IP_VERSION = "ip.version", "Version", Uint;
    IP_HDR_LEN = "ip.hdr_len", "Header Length", Uint;
    IP_DSFIELD = "ip.dsfield", "Differentiated Services Field", Uint;
    IP_DSCP = "ip.dsfield.dscp", "Differentiated Services Codepoint", Uint;
    IP_ECN = "ip.dsfield.ecn", "Explicit Congestion Notification", Uint;
    IP_LEN = "ip.len", "Total Length", Uint;
    IP_ID = "ip.id", "Identification", Uint;
    IP_FLAGS = "ip.flags", "Flags", Uint;
    IP_FLAGS_RB = "ip.flags.rb", "Reserved bit", Bool;
    IP_FLAGS_DF = "ip.flags.df", "Don't fragment", Bool;
    IP_FLAGS_MF = "ip.flags.mf", "More fragments", Bool;
    IP_FRAG_OFFSET = "ip.frag_offset", "Fragment Offset", Uint;
    IP_TTL = "ip.ttl", "Time to Live", Uint;
    IP_PROTO = "ip.proto", "Protocol", Uint;
    IP_CHECKSUM = "ip.checksum", "Header Checksum", Uint;
    IP_CHECKSUM_STATUS = "ip.checksum.status", "Header checksum status", String;
    IP_SRC = "ip.src", "Source Address", Ipv4;
    IP_DST = "ip.dst", "Destination Address", Ipv4;
    IP_OPTIONS = "ip.options", "Options", Bytes;

    // IPv6
    IPV6_VERSION = "ipv6.version", "Version", Uint;
    IPV6_TCLASS = "ipv6.tclass", "Traffic Class", Uint;
    IPV6_FLOW = "ipv6.flow", "Flow Label", Uint;
    IPV6_PLEN = "ipv6.plen", "Payload Length", Uint;
    IPV6_NXT = "ipv6.nxt", "Next Header", Uint;
    IPV6_HLIM = "ipv6.hlim", "Hop Limit", Uint;
    IPV6_SRC = "ipv6.src", "Source Address", Ipv6;
    IPV6_DST = "ipv6.dst", "Destination Address", Ipv6;
    IPV6_EXT = "ipv6.ext", "Extension Header", None;
    IPV6_EXT_LEN = "ipv6.ext.len", "Length", Uint;
    IPV6_FRAG_OFFSET = "ipv6.fragment.offset", "Offset", Uint;
    IPV6_FRAG_MORE = "ipv6.fragment.more", "More Fragments", Bool;
    IPV6_FRAG_ID = "ipv6.fragment.id", "Identification", Uint;

    // ICMP
    ICMP_TYPE = "icmp.type", "Type", Uint;
    ICMP_CODE = "icmp.code", "Code", Uint;
    ICMP_CHECKSUM = "icmp.checksum", "Checksum", Uint;
    ICMP_IDENT = "icmp.ident", "Identifier", Uint;
    ICMP_SEQ = "icmp.seq", "Sequence Number", Uint;
    ICMP_GATEWAY = "icmp.redir_gw", "Gateway Address", Ipv4;
    ICMP_MTU = "icmp.mtu", "MTU of next hop", Uint;
    ICMP_DATA = "icmp.data", "Data", Bytes;

    // ICMPv6
    ICMPV6_TYPE = "icmpv6.type", "Type", Uint;
    ICMPV6_CODE = "icmpv6.code", "Code", Uint;
    ICMPV6_CHECKSUM = "icmpv6.checksum", "Checksum", Uint;
    ICMPV6_ECHO_ID = "icmpv6.echo.identifier", "Identifier", Uint;
    ICMPV6_ECHO_SEQ = "icmpv6.echo.sequence_number", "Sequence", Uint;
    ICMPV6_ND_TARGET = "icmpv6.nd.ns.target_address", "Target Address", Ipv6;
    ICMPV6_ND_FLAGS = "icmpv6.nd.na.flag", "Flags", Uint;
    ICMPV6_RA_HOP_LIMIT = "icmpv6.nd.ra.cur_hop_limit", "Cur hop limit", Uint;
    ICMPV6_RA_LIFETIME = "icmpv6.nd.ra.router_lifetime", "Router lifetime (s)", Uint;
    ICMPV6_OPT = "icmpv6.opt", "ICMPv6 Option", None;
    ICMPV6_OPT_LINKADDR = "icmpv6.opt.linkaddr", "Link-layer address", Mac;
    ICMPV6_MTU = "icmpv6.mtu", "MTU", Uint;
    ICMPV6_DATA = "icmpv6.data", "Data", Bytes;

    // TCP
    TCP_SRCPORT = "tcp.srcport", "Source Port", Uint;
    TCP_DSTPORT = "tcp.dstport", "Destination Port", Uint;
    TCP_STREAM = "tcp.stream", "Stream index", Uint;
    TCP_LEN = "tcp.len", "TCP Segment Len", Uint;
    TCP_SEQ = "tcp.seq", "Sequence Number", Uint;
    TCP_SEQ_RAW = "tcp.seq_raw", "Sequence Number (raw)", Uint;
    TCP_NXTSEQ = "tcp.nxtseq", "Next Sequence Number", Uint;
    TCP_ACK = "tcp.ack", "Acknowledgment Number", Uint;
    TCP_ACK_RAW = "tcp.ack_raw", "Acknowledgment number (raw)", Uint;
    TCP_HDR_LEN = "tcp.hdr_len", "Header Length", Uint;
    TCP_FLAGS = "tcp.flags", "Flags", Uint;
    TCP_FLAGS_RES = "tcp.flags.res", "Reserved", Bool;
    TCP_FLAGS_AE = "tcp.flags.ae", "Accurate ECN", Bool;
    TCP_FLAGS_CWR = "tcp.flags.cwr", "Congestion Window Reduced", Bool;
    TCP_FLAGS_ECE = "tcp.flags.ece", "ECN-Echo", Bool;
    TCP_FLAGS_URG = "tcp.flags.urg", "Urgent", Bool;
    TCP_FLAGS_ACK = "tcp.flags.ack", "Acknowledgment", Bool;
    TCP_FLAGS_PSH = "tcp.flags.push", "Push", Bool;
    TCP_FLAGS_RST = "tcp.flags.reset", "Reset", Bool;
    TCP_FLAGS_SYN = "tcp.flags.syn", "Syn", Bool;
    TCP_FLAGS_FIN = "tcp.flags.fin", "Fin", Bool;
    TCP_FLAGS_STR = "tcp.flags.str", "TCP Flags", String;
    TCP_WINDOW_VALUE = "tcp.window_size_value", "Window", Uint;
    TCP_WINDOW_SIZE = "tcp.window_size", "Calculated window size", Uint;
    TCP_WINDOW_SCALE = "tcp.window_size_scalefactor", "Window size scaling factor", Int;
    TCP_CHECKSUM = "tcp.checksum", "Checksum", Uint;
    TCP_URGENT = "tcp.urgent_pointer", "Urgent Pointer", Uint;
    TCP_OPTIONS = "tcp.options", "Options", Bytes;
    TCP_OPT_MSS = "tcp.options.mss_val", "MSS Value", Uint;
    TCP_OPT_WSCALE = "tcp.options.wscale.shift", "Shift count", Uint;
    TCP_OPT_SACK_PERM = "tcp.options.sack_perm", "SACK Permitted", None;
    TCP_OPT_SACK = "tcp.options.sack", "SACK", None;
    TCP_OPT_TSVAL = "tcp.options.timestamp.tsval", "Timestamp value", Uint;
    TCP_OPT_TSECR = "tcp.options.timestamp.tsecr", "Timestamp echo reply", Uint;
    TCP_OPT = "tcp.option", "Option", None;
    TCP_PAYLOAD = "tcp.payload", "TCP payload", Bytes;
    TCP_SEGMENT_DATA = "tcp.segment_data", "TCP segment data", Bytes;
    TCP_TIME_RELATIVE = "tcp.time_relative", "Time since first frame in this TCP stream", Float;
    TCP_ANALYSIS = "tcp.analysis", "SEQ/ACK analysis", None;
    TCP_ANALYSIS_FLAGS = "tcp.analysis.flags", "TCP Analysis Flags", None;
    TCP_ANALYSIS_ACK_RTT = "tcp.analysis.ack_rtt", "The RTT to ACK the segment was", Float;
    TCP_ANALYSIS_RETRANS = "tcp.analysis.retransmission", "This frame is a (suspected) retransmission", None;
    TCP_ANALYSIS_FAST_RETRANS = "tcp.analysis.fast_retransmission", "This frame is a (suspected) fast retransmission", None;
    TCP_ANALYSIS_OOO = "tcp.analysis.out_of_order", "This frame is a (suspected) out-of-order segment", None;
    TCP_ANALYSIS_DUP_ACK = "tcp.analysis.duplicate_ack", "Duplicate ACK", None;
    TCP_ANALYSIS_ZERO_WINDOW = "tcp.analysis.zero_window", "TCP Zero Window segment", None;
    TCP_ANALYSIS_KEEP_ALIVE = "tcp.analysis.keep_alive", "TCP keep-alive segment", None;
    TCP_ANALYSIS_LOST = "tcp.analysis.lost_segment", "Previous segment(s) not captured", None;
    TCP_ANALYSIS_WINDOW_UPDATE = "tcp.analysis.window_update", "TCP window update", None;
    TCP_ANALYSIS_PORT_REUSE = "tcp.analysis.reused_ports", "A new tcp session is started with the same ports", None;
    TCP_ANALYSIS_ACKED_UNSEEN = "tcp.analysis.ack_lost_segment", "ACKed segment that wasn't captured", None;

    // UDP
    UDP_SRCPORT = "udp.srcport", "Source Port", Uint;
    UDP_DSTPORT = "udp.dstport", "Destination Port", Uint;
    UDP_LENGTH = "udp.length", "Length", Uint;
    UDP_CHECKSUM = "udp.checksum", "Checksum", Uint;
    UDP_STREAM = "udp.stream", "Stream index", Uint;
    UDP_PAYLOAD = "udp.payload", "UDP payload", Bytes;

    // DNS
    DNS_ID = "dns.id", "Transaction ID", Uint;
    DNS_LENGTH = "dns.length", "Length", Uint;
    DNS_FLAGS = "dns.flags", "Flags", Uint;
    DNS_FLAGS_RESPONSE = "dns.flags.response", "Response", Bool;
    DNS_FLAGS_OPCODE = "dns.flags.opcode", "Opcode", Uint;
    DNS_FLAGS_AA = "dns.flags.authoritative", "Authoritative", Bool;
    DNS_FLAGS_TC = "dns.flags.truncated", "Truncated", Bool;
    DNS_FLAGS_RD = "dns.flags.recdesired", "Recursion desired", Bool;
    DNS_FLAGS_RA = "dns.flags.recavail", "Recursion available", Bool;
    DNS_FLAGS_RCODE = "dns.flags.rcode", "Reply code", Uint;
    DNS_COUNT_QUERIES = "dns.count.queries", "Questions", Uint;
    DNS_COUNT_ANSWERS = "dns.count.answers", "Answer RRs", Uint;
    DNS_COUNT_AUTH = "dns.count.auth_rr", "Authority RRs", Uint;
    DNS_COUNT_ADD = "dns.count.add_rr", "Additional RRs", Uint;
    DNS_QRY_NAME = "dns.qry.name", "Name", String;
    DNS_QRY_TYPE = "dns.qry.type", "Type", Uint;
    DNS_QRY_CLASS = "dns.qry.class", "Class", Uint;
    DNS_RESP_NAME = "dns.resp.name", "Name", String;
    DNS_RESP_TYPE = "dns.resp.type", "Type", Uint;
    DNS_RESP_CLASS = "dns.resp.class", "Class", Uint;
    DNS_RESP_TTL = "dns.resp.ttl", "Time to live", Uint;
    DNS_RESP_LEN = "dns.resp.len", "Data length", Uint;
    DNS_A = "dns.a", "Address", Ipv4;
    DNS_AAAA = "dns.aaaa", "AAAA Address", Ipv6;
    DNS_CNAME = "dns.cname", "CNAME", String;
    DNS_NS = "dns.ns", "Name Server", String;
    DNS_PTR = "dns.ptr.domain_name", "Domain Name", String;
    DNS_MX = "dns.mx.mail_exchange", "Mail Exchange", String;
    DNS_MX_PREF = "dns.mx.preference", "Preference", Uint;
    DNS_TXT = "dns.txt", "TXT", String;
    DNS_SRV_TARGET = "dns.srv.target", "Target", String;
    DNS_SRV_PORT = "dns.srv.port", "Port", Uint;
    DNS_SOA_MNAME = "dns.soa.mname", "Primary name server", String;
    DNS_RDATA = "dns.rdata", "Data", Bytes;
    DNS_QUERIES = "dns.queries", "Queries", None;
    DNS_ANSWERS = "dns.answers", "Answers", None;
    DNS_AUTHORITIES = "dns.authorities", "Authoritative nameservers", None;
    DNS_ADDITIONALS = "dns.additionals", "Additional records", None;

    // DHCP
    DHCP_TYPE = "dhcp.type", "Message type", Uint;
    DHCP_HW_TYPE = "dhcp.hw.type", "Hardware type", Uint;
    DHCP_HW_LEN = "dhcp.hw.len", "Hardware address length", Uint;
    DHCP_HOPS = "dhcp.hops", "Hops", Uint;
    DHCP_ID = "dhcp.id", "Transaction ID", Uint;
    DHCP_SECS = "dhcp.secs", "Seconds elapsed", Uint;
    DHCP_FLAGS = "dhcp.flags", "Bootp flags", Uint;
    DHCP_CLIENT_IP = "dhcp.ip.client", "Client IP address", Ipv4;
    DHCP_YOUR_IP = "dhcp.ip.your", "Your (client) IP address", Ipv4;
    DHCP_SERVER_IP = "dhcp.ip.server", "Next server IP address", Ipv4;
    DHCP_RELAY_IP = "dhcp.ip.relay", "Relay agent IP address", Ipv4;
    DHCP_HW_MAC = "dhcp.hw.mac_addr", "Client MAC address", Mac;
    DHCP_SERVER_NAME = "dhcp.server", "Server host name", String;
    DHCP_FILE = "dhcp.file", "Boot file name", String;
    DHCP_COOKIE = "dhcp.cookie", "Magic cookie", Uint;
    DHCP_OPTION = "dhcp.option.type", "Option", Uint;
    DHCP_MSG_TYPE = "dhcp.option.dhcp", "DHCP", Uint;
    DHCP_SUBNET = "dhcp.option.subnet_mask", "Subnet Mask", Ipv4;
    DHCP_ROUTER = "dhcp.option.router", "Router", Ipv4;
    DHCP_DNS = "dhcp.option.domain_name_server", "Domain Name Server", Ipv4;
    DHCP_HOSTNAME = "dhcp.option.hostname", "Host Name", String;
    DHCP_DOMAIN = "dhcp.option.domain_name", "Domain Name", String;
    DHCP_REQUESTED_IP = "dhcp.option.requested_ip_address", "Requested IP Address", Ipv4;
    DHCP_LEASE = "dhcp.option.ip_address_lease_time", "IP Address Lease Time", Uint;
    DHCP_SERVER_ID = "dhcp.option.dhcp_server_id", "DHCP Server Identifier", Ipv4;
    DHCP_VENDOR = "dhcp.option.vendor_class_id", "Vendor class identifier", String;
    DHCP_PARAM = "dhcp.option.request_list_item", "Parameter Request List Item", Uint;
    DHCP_CLIENT_ID = "dhcp.option.client_id", "Client identifier", Bytes;

    // HTTP
    HTTP_REQUEST = "http.request", "Request", Bool;
    HTTP_RESPONSE = "http.response", "Response", Bool;
    HTTP_REQUEST_LINE = "http.request.line", "Request line", String;
    HTTP_RESPONSE_LINE = "http.response.line", "Response line", String;
    HTTP_METHOD = "http.request.method", "Request Method", String;
    HTTP_URI = "http.request.uri", "Request URI", String;
    HTTP_REQ_VERSION = "http.request.version", "Request Version", String;
    HTTP_RESP_VERSION = "http.response.version", "Response Version", String;
    HTTP_CODE = "http.response.code", "Status Code", Uint;
    HTTP_PHRASE = "http.response.phrase", "Response Phrase", String;
    HTTP_HOST = "http.host", "Host", String;
    HTTP_USER_AGENT = "http.user_agent", "User-Agent", String;
    HTTP_ACCEPT = "http.accept", "Accept", String;
    HTTP_REFERER = "http.referer", "Referer", String;
    HTTP_COOKIE = "http.cookie", "Cookie", String;
    HTTP_SET_COOKIE = "http.set_cookie", "Set-Cookie", String;
    HTTP_CONTENT_TYPE = "http.content_type", "Content-Type", String;
    HTTP_CONTENT_LENGTH = "http.content_length", "Content length", Uint;
    HTTP_SERVER = "http.server", "Server", String;
    HTTP_LOCATION = "http.location", "Location", String;
    HTTP_CONNECTION = "http.connection", "Connection", String;
    HTTP_AUTHORIZATION = "http.authorization", "Authorization", String;
    HTTP_TRANSFER_ENCODING = "http.transfer_encoding", "Transfer-Encoding", String;
    HTTP_FILE_DATA = "http.file_data", "File Data", Bytes;
    HTTP_CONTINUATION = "http.continuation", "Continuation", Bytes;

    // TLS
    TLS_RECORD = "tls.record", "TLS Record Layer", None;
    TLS_RECORD_TYPE = "tls.record.content_type", "Content Type", Uint;
    TLS_RECORD_VERSION = "tls.record.version", "Version", Uint;
    TLS_RECORD_LENGTH = "tls.record.length", "Length", Uint;
    TLS_HANDSHAKE = "tls.handshake", "Handshake Protocol", None;
    TLS_HS_TYPE = "tls.handshake.type", "Handshake Type", Uint;
    TLS_HS_LENGTH = "tls.handshake.length", "Length", Uint;
    TLS_HS_VERSION = "tls.handshake.version", "Version", Uint;
    TLS_HS_RANDOM = "tls.handshake.random", "Random", Bytes;
    TLS_HS_SESSION_ID = "tls.handshake.session_id", "Session ID", Bytes;
    TLS_HS_CIPHERSUITES_LEN = "tls.handshake.cipher_suites_length", "Cipher Suites Length", Uint;
    TLS_HS_CIPHERSUITE = "tls.handshake.ciphersuite", "Cipher Suite", Uint;
    TLS_HS_COMP = "tls.handshake.comp_method", "Compression Method", Uint;
    TLS_HS_EXT_LEN = "tls.handshake.extensions_length", "Extensions Length", Uint;
    TLS_HS_EXT_TYPE = "tls.handshake.extension.type", "Type", Uint;
    TLS_HS_EXT_LEN1 = "tls.handshake.extension.len", "Length", Uint;
    TLS_HS_SNI = "tls.handshake.extensions_server_name", "Server Name", String;
    TLS_HS_ALPN = "tls.handshake.extensions_alpn_str", "ALPN Next Protocol", String;
    TLS_HS_SUPPORTED_VERSION = "tls.handshake.extensions.supported_version", "Supported Version", Uint;
    TLS_HS_GROUP = "tls.handshake.extensions_supported_group", "Supported Group", Uint;
    TLS_HS_SIG_ALG = "tls.handshake.sig_hash_alg", "Signature Algorithm", Uint;
    TLS_HS_CERTS_LEN = "tls.handshake.certificates_length", "Certificates Length", Uint;
    TLS_HS_CERT_LEN = "tls.handshake.certificate_length", "Certificate Length", Uint;
    TLS_HS_CERT = "tls.handshake.certificate", "Certificate", Bytes;
    TLS_ALERT_LEVEL = "tls.alert_message.level", "Level", Uint;
    TLS_ALERT_DESC = "tls.alert_message.desc", "Description", Uint;
    TLS_CCS = "tls.change_cipher_spec", "Change Cipher Spec Message", None;
    TLS_APP_DATA = "tls.app_data", "Encrypted Application Data", Bytes;
    TLS_ENCRYPTED_HS = "tls.handshake.encrypted", "Encrypted Handshake Message", Bytes;
    TLS_SEGMENT = "tls.segment.data", "TLS segment data", Bytes;
    X509_SUBJECT_CN = "x509sat.subject.cn", "Subject CommonName", String;
    X509_ISSUER_CN = "x509sat.issuer.cn", "Issuer CommonName", String;
    X509_NOT_BEFORE = "x509af.notBefore", "Not Before", String;
    X509_NOT_AFTER = "x509af.notAfter", "Not After", String;
    X509_SAN = "x509ce.dNSName", "Subject Alternative Name", String;

    // NTP
    NTP_LI = "ntp.flags.li", "Leap Indicator", Uint;
    NTP_VN = "ntp.flags.vn", "Version number", Uint;
    NTP_MODE = "ntp.flags.mode", "Mode", Uint;
    NTP_FLAGS = "ntp.flags", "Flags", Uint;
    NTP_STRATUM = "ntp.stratum", "Peer Clock Stratum", Uint;
    NTP_POLL = "ntp.ppoll", "Peer Polling Interval", Int;
    NTP_PRECISION = "ntp.precision", "Peer Clock Precision", Int;
    NTP_ROOT_DELAY = "ntp.rootdelay", "Root Delay", Float;
    NTP_ROOT_DISPERSION = "ntp.rootdispersion", "Root Dispersion", Float;
    NTP_REFID = "ntp.refid", "Reference ID", Bytes;
    NTP_REF_TS = "ntp.reftime", "Reference Timestamp", String;
    NTP_ORG_TS = "ntp.org", "Origin Timestamp", String;
    NTP_REC_TS = "ntp.rec", "Receive Timestamp", String;
    NTP_XMT_TS = "ntp.xmt", "Transmit Timestamp", String;

    // Generic payload
    DATA_DATA = "data.data", "Data", Bytes;
    DATA_LEN = "data.len", "Length", Uint;
}

/// Virtual fields that match any of their members (`ip.addr` = `ip.src` or `ip.dst`).
pub static ALIASES: &[(&str, &str, FieldKind, &[&Field])] = &[
    ("eth.addr", "Address", FieldKind::Mac, &[&ETH_SRC, &ETH_DST]),
    ("ip.addr", "Source or Destination Address", FieldKind::Ipv4, &[&IP_SRC, &IP_DST]),
    ("ipv6.addr", "Source or Destination Address", FieldKind::Ipv6, &[&IPV6_SRC, &IPV6_DST]),
    ("tcp.port", "Source or Destination Port", FieldKind::Uint, &[&TCP_SRCPORT, &TCP_DSTPORT]),
    ("udp.port", "Source or Destination Port", FieldKind::Uint, &[&UDP_SRCPORT, &UDP_DSTPORT]),
];

/// Field used as the tree heading for a protocol.
pub fn protocol_field(p: ProtocolId) -> &'static Field {
    match p {
        ProtocolId::Frame => &FRAME,
        ProtocolId::Eth => &ETH,
        ProtocolId::Vlan => &VLAN,
        ProtocolId::Arp => &ARP,
        ProtocolId::Ipv4 => &IP,
        ProtocolId::Ipv6 => &IPV6,
        ProtocolId::Icmp => &ICMP,
        ProtocolId::Icmpv6 => &ICMPV6,
        ProtocolId::Tcp => &TCP,
        ProtocolId::Udp => &UDP,
        ProtocolId::Dns => &DNS,
        ProtocolId::Dhcp => &DHCP,
        ProtocolId::Http => &HTTP,
        ProtocolId::Tls => &TLS,
        ProtocolId::Ntp => &NTP,
        ProtocolId::Sll => &SLL,
        ProtocolId::Loopback => &NULL,
        ProtocolId::Data => &DATA,
        ProtocolId::Malformed => &MALFORMED,
    }
}

/// Protocol id for a protocol-presence field abbreviation.
pub fn protocol_by_abbrev(abbrev: &str) -> Option<ProtocolId> {
    ProtocolId::ALL.into_iter().find(|p| protocol_field(*p).abbrev == abbrev)
}

pub fn lookup(abbrev: &str) -> Option<&'static Field> {
    ALL.iter().copied().find(|f| f.abbrev == abbrev)
}

pub fn alias(abbrev: &str) -> Option<(FieldKind, &'static [&'static Field])> {
    ALIASES.iter().find(|(a, ..)| *a == abbrev).map(|(_, _, k, members)| (*k, *members))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn abbreviations_are_unique() {
        let mut seen = HashSet::new();
        for f in ALL {
            assert!(seen.insert(f.abbrev), "duplicate field {}", f.abbrev);
        }
        for (a, ..) in ALIASES {
            assert!(seen.insert(a), "alias collides with field {a}");
        }
    }

    #[test]
    fn every_protocol_has_a_field() {
        for p in ProtocolId::ALL {
            let f = protocol_field(p);
            assert_eq!(f.kind, FieldKind::Protocol);
            assert_eq!(f.abbrev, p.filter_name());
            assert_eq!(protocol_by_abbrev(f.abbrev), Some(p));
        }
    }

    #[test]
    fn lookup_and_alias() {
        assert_eq!(lookup("ip.src").unwrap().kind, FieldKind::Ipv4);
        assert!(lookup("ip.addr").is_none());
        let (kind, members) = alias("tcp.port").unwrap();
        assert_eq!(kind, FieldKind::Uint);
        assert_eq!(members.len(), 2);
    }
}
