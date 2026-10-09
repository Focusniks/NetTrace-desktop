// UI-facing model. Mirrors `crates/model` (serde camelCase). The UI depends
// only on these types — never on dissector internals.

export type Transport = "tcp" | "udp";

export interface StreamRef {
  kind: Transport;
  id: number;
}

export type Severity = "note" | "warning" | "error";

export interface PacketField {
  field: string;
  name: string;
  display: string;
  start: number;
  len: number;
  generated: boolean;
  severity?: Severity;
  filter?: string;
  children: PacketField[];
}

export interface PacketRow {
  number: number;
  timeRel: number;
  timeDelta: number;
  tsSec: number;
  tsNsec: number;
  src: string;
  dst: string;
  protocol: string;
  length: number;
  info: string;
  srcPort: number | null;
  dstPort: number | null;
  tcpFlags: string | null;
  stream: StreamRef | null;
  cast: "unicast" | "multicast" | "broadcast" | "unknown";
  colorRule: number | null;
  analysis: number;
  malformed: boolean;
  readError: boolean;
}

export interface PacketDetail {
  number: number;
  tree: PacketField[];
  bytes: number[];
  stream: StreamRef | null;
}

export type TcpState =
  | "syn_sent"
  | "syn_received"
  | "established"
  | "midstream"
  | "closing"
  | "closed"
  | "reset"
  | "refused";

export interface Endpoint {
  addr: string;
  port: number;
}

export interface TcpFlowStats {
  state: TcpState;
  handshake: { syn: number | null; synAck: number | null; ack: number | null };
  irttMs: number | null;
  rttMinMs: number | null;
  rttAvgMs: number | null;
  rttMaxMs: number | null;
  rttSamples: number;
  retransmissions: number;
  fastRetransmissions: number;
  duplicateAcks: number;
  outOfOrder: number;
  zeroWindow: number;
  keepAlive: number;
  lostSegments: number;
  resets: number;
  finClient: number | null;
  finServer: number | null;
  throughputC2s: number;
  throughputS2c: number;
}

export interface FlowSummary {
  kind: Transport;
  id: number;
  client: Endpoint;
  server: Endpoint;
  protocol: string;
  packets: number;
  bytes: number;
  c2sPackets: number;
  c2sBytes: number;
  c2sPayload: number;
  s2cPackets: number;
  s2cBytes: number;
  s2cPayload: number;
  firstPacket: number;
  lastPacket: number;
  start: number;
  duration: number;
  tcp: TcpFlowStats | null;
}

export interface FlowPage {
  total: number;
  offset: number;
  flows: FlowSummary[];
}

export type FlowSort = "id" | "packets" | "bytes" | "start" | "duration" | "retransmissions" | "rtt";

export interface FlowQuery {
  kind: Transport | null;
  sort: FlowSort;
  desc: boolean;
  offset: number;
  limit: number;
  search?: string | null;
}

export type HostSort = "address" | "mac" | "packets" | "bytes" | "tx" | "rx" | "first" | "last";

export interface HostQuery {
  sort: HostSort;
  desc: boolean;
  offset: number;
  limit: number;
  search?: string | null;
}

export interface HostPage {
  total: number;
  offset: number;
  rows: HostRow[];
}

export type ConversationSort = "a" | "b" | "packets" | "bytes" | "ab" | "ba" | "start" | "duration" | "state";

export interface ConversationQuery {
  kind: ConversationKind;
  sort: ConversationSort;
  desc: boolean;
  offset: number;
  limit: number;
  search?: string | null;
}

export interface ConversationPage {
  total: number;
  offset: number;
  rows: ConversationRow[];
}

export interface SequenceEntry {
  number: number;
  timeRel: number;
  timeStream: number;
  direction: "c2s" | "s2c";
  label: string;
  tcpFlags: string | null;
  seq: number | null;
  ack: number | null;
  len: number;
  window: number | null;
  analysis: number;
}

export interface SequencePage {
  total: number;
  offset: number;
  entries: SequenceEntry[];
}

export type AddressKind = "mac" | "ipv4" | "ipv6";

export interface HostRow {
  address: string;
  kind: AddressKind;
  mac: string | null;
  packets: number;
  bytes: number;
  txPackets: number;
  txBytes: number;
  rxPackets: number;
  rxBytes: number;
  protocols: string[];
  firstSeen: number;
  lastSeen: number;
  filter: string;
}

export type ConversationKind = "eth" | "ip" | "tcp" | "udp";

export interface ConversationRow {
  kind: ConversationKind;
  a: string;
  aPort: number | null;
  b: string;
  bPort: number | null;
  packets: number;
  bytes: number;
  aToBPackets: number;
  aToBBytes: number;
  bToAPackets: number;
  bToABytes: number;
  start: number;
  duration: number;
  state: TcpState | null;
  stream: StreamRef | null;
  filter: string;
}

export interface ProtocolNode {
  name: string;
  filter: string;
  packets: number;
  bytes: number;
  children: ProtocolNode[];
}

export interface IoGraph {
  interval: number;
  start: number;
  packets: number[];
  bytes: number[];
  matchedPackets: number;
}

export interface LengthBucket {
  min: number;
  max: number | null;
  count: number;
  minSeen: number | null;
  maxSeen: number | null;
  avg: number | null;
}

export interface PacketLengths {
  buckets: LengthBucket[];
  total: number;
  min: number | null;
  max: number | null;
  avg: number | null;
}

export type TimelineKind =
  | "dns_query"
  | "dns_response"
  | "tls_client_hello"
  | "tls_server_hello"
  | "http_request"
  | "http_response"
  | "tcp_open"
  | "tcp_close"
  | "tcp_reset";

export interface TimelineEvent {
  kind: TimelineKind;
  number: number;
  timeRel: number;
  label: string;
  stream: StreamRef | null;
}

export interface Timeline {
  start: number;
  end: number;
  bucket: number;
  packets: number[];
  bytes: number[];
  tcpOpen: number[];
  tcpActive: number[];
  dns: number[];
  tls: number[];
  http: number[];
  events: TimelineEvent[];
  eventsTruncated: boolean;
}

export type IndicatorKind =
  | { code: "tcp_retransmission_rate"; stream: number; endpoints: string; retransmissions: number; segments: number; percent: number }
  | { code: "tcp_resets"; streams: number; packets: number }
  | { code: "tcp_zero_window"; stream: number; endpoints: string; count: number }
  | { code: "repeated_failed_connections"; client: string; server: string; port: number; attempts: number; refused: number }
  | { code: "many_connections"; host: string; connections: number; distinctPeers: number; distinctPorts: number }
  | { code: "many_dns_queries"; host: string; queries: number; distinctNames: number }
  | { code: "large_flow"; stream: number; kind: Transport; client: string; server: string; clientBytes: number; serverBytes: number }
  | { code: "non_standard_port"; protocol: string; port: number; streams: number }
  | { code: "malformed_packets"; count: number };

export type Indicator = IndicatorKind & {
  severity: Severity;
  filter: string;
  firstPacket: number | null;
};

export interface CaptureInfo {
  captureId: number;
  live: boolean;
  path: string;
  fileName: string;
  fileSize: number;
  format: string;
}

export type IndexState = "indexing" | "done" | "cancelled" | "failed";

export interface IndexProgress {
  captureId: number;
  state: IndexState;
  packets: number;
  tcpStreams: number;
  udpStreams: number;
  bytesRead: number;
  totalBytes: number;
  elapsedMs: number;
  warning: string | null;
  error: string | null;
  capture: LiveStats | null;
}

export interface LiveStats {
  interface: string;
  captured: number;
  dropped: number;
  ifDropped: number;
  running: boolean;
}

export interface CaptureInterface {
  name: string;
  description: string | null;
  addresses: string[];
  loopback: boolean;
  up: boolean;
  running: boolean;
  wireless: boolean;
}

export interface LiveOptions {
  interface: string;
  captureFilter: string | null;
  snaplen: number;
  promiscuous: boolean;
}

export interface CaptureSummary {
  info: CaptureInfo;
  packets: number;
  bytes: number;
  firstTsSec: number | null;
  firstTsNsec: number | null;
  duration: number;
  tcpStreams: number;
  udpStreams: number;
  hosts: number;
  malformed: number;
  interfaces: { linkType: string; name: string | null; snaplen: number }[];
  state: IndexState;
}

export interface ViewInfo {
  viewId: number;
  total: number;
  scanned: number;
  elapsedMs: number;
}

export interface FilterError {
  code: string;
  start: number;
  end: number;
  detail: string;
}

export interface EngineError {
  code: string;
  message: string;
  filter?: FilterError;
}

export type FieldKind = "protocol" | "bool" | "uint" | "int" | "float" | "string" | "bytes" | "ipv4" | "ipv6" | "mac" | "none";

export interface FieldInfo {
  abbrev: string;
  name: string;
  kind: FieldKind;
  indexed: boolean;
}

export type SortKey =
  | "number"
  | "time"
  | "source"
  | "destination"
  | "protocol"
  | "length"
  | "srcPort"
  | "dstPort"
  | "stream"
  | "tcpFlags";

export interface SortSpec {
  key: SortKey;
  desc: boolean;
}

export type SearchQuery =
  | { kind: "filter"; text: string }
  | { kind: "text"; text: string; caseSensitive: boolean }
  | { kind: "hex"; text: string };

export interface SearchHit {
  row: number;
  number: number;
  wrapped: boolean;
}

/** TCP analysis bit flags (crates/model `tcp_analysis`). */
export const TcpAnalysis = {
  RETRANSMISSION: 1 << 0,
  FAST_RETRANSMISSION: 1 << 1,
  OUT_OF_ORDER: 1 << 2,
  DUPLICATE_ACK: 1 << 3,
  ZERO_WINDOW: 1 << 4,
  KEEP_ALIVE: 1 << 5,
  LOST_SEGMENT: 1 << 6,
  WINDOW_UPDATE: 1 << 7,
  PORT_REUSE: 1 << 8,
  ACKED_UNSEEN: 1 << 9,
} as const;
