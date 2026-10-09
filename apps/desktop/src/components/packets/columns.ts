import type { PacketRow, SortKey } from "../../api/types";
import { t, type MessageKey } from "../../i18n";
import { fmtPacketTime, type TimeFormat } from "../../lib/format";
import type { ColumnId } from "../../state/settings";

export interface ColumnDef {
  id: ColumnId;
  title: MessageKey;
  sortKey: SortKey | null;
  align?: "right";
  mono?: boolean;
  text: (row: PacketRow, timeFormat: TimeFormat) => string;
  /** Filter expression for "apply as filter" on this cell. */
  filter?: (row: PacketRow) => string | null;
}

function addrField(addr: string, dir: "src" | "dst"): string {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(addr)) return `ip.${dir} == ${addr}`;
  if (/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(addr)) return `eth.${dir} == ${addr}`;
  if (addr.includes(":")) return `ipv6.${dir} == ${addr}`;
  return "";
}

const PROTOCOL_FILTER: Record<string, string> = {
  Ethernet: "eth", "802.1Q": "vlan", IPv4: "ip", IPv6: "ipv6", SLL: "sll", Loopback: "null", Malformed: "_ws.malformed",
};

export function protocolFilter(name: string): string | null {
  if (!name || name === "Frame") return null;
  return PROTOCOL_FILTER[name] ?? name.toLowerCase();
}

function portFilter(row: PacketRow, dir: "src" | "dst"): string | null {
  const port = dir === "src" ? row.srcPort : row.dstPort;
  if (port == null) return null;
  const proto = row.stream?.kind ?? (row.protocol === "UDP" ? "udp" : "tcp");
  return `${proto}.${dir}port == ${port}`;
}

export const COLUMN_DEFS: Record<ColumnId, ColumnDef> = {
  number: { id: "number", title: "col.number", sortKey: "number", align: "right", mono: true, text: (r) => String(r.number), filter: (r) => `frame.number == ${r.number}` },
  time: { id: "time", title: "col.time", sortKey: "time", align: "right", mono: true, text: (r, f) => fmtPacketTime(f, r) },
  source: { id: "source", title: "col.source", sortKey: "source", mono: true, text: (r) => r.src, filter: (r) => addrField(r.src, "src") || null },
  destination: { id: "destination", title: "col.destination", sortKey: "destination", mono: true, text: (r) => r.dst, filter: (r) => addrField(r.dst, "dst") || null },
  protocol: { id: "protocol", title: "col.protocol", sortKey: "protocol", text: (r) => r.protocol, filter: (r) => protocolFilter(r.protocol) },
  length: { id: "length", title: "col.length", sortKey: "length", align: "right", mono: true, text: (r) => String(r.length), filter: (r) => `frame.len == ${r.length}` },
  info: { id: "info", title: "col.info", sortKey: null, text: (r) => r.info },
  srcPort: { id: "srcPort", title: "col.srcPort", sortKey: "srcPort", align: "right", mono: true, text: (r) => (r.srcPort == null ? "" : String(r.srcPort)), filter: (r) => portFilter(r, "src") },
  dstPort: { id: "dstPort", title: "col.dstPort", sortKey: "dstPort", align: "right", mono: true, text: (r) => (r.dstPort == null ? "" : String(r.dstPort)), filter: (r) => portFilter(r, "dst") },
  tcpFlags: { id: "tcpFlags", title: "col.tcpFlags", sortKey: "tcpFlags", text: (r) => r.tcpFlags ?? "" },
  stream: { id: "stream", title: "col.stream", sortKey: "stream", align: "right", mono: true, text: (r) => (r.stream ? `${r.stream.kind} ${r.stream.id}` : ""), filter: (r) => (r.stream ? `${r.stream.kind}.stream == ${r.stream.id}` : null) },
  cast: { id: "cast", title: "col.cast", sortKey: null, text: (r) => t(`cast.${r.cast}` as MessageKey) },
};

export function rowSummary(row: PacketRow, timeFormat: TimeFormat): string {
  return [row.number, fmtPacketTime(timeFormat, row), row.src, row.dst, row.protocol, row.length, row.info].join("\t");
}

export function conversationFilter(row: PacketRow): string | null {
  const a = addrField(row.src, "src").replace(".src ==", ".addr ==");
  const b = addrField(row.dst, "dst").replace(".dst ==", ".addr ==");
  if (!a || !b) return null;
  if (row.stream) return `${row.stream.kind}.stream == ${row.stream.id}`;
  return `${a} && ${b}`;
}
