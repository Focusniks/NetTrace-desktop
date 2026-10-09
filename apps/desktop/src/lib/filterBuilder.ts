// Visual filter builder → ordinary display filter text.

export type BuilderField =
  | "src"
  | "dst"
  | "ip"
  | "port"
  | "srcport"
  | "dstport"
  | "protocol"
  | "stream"
  | "frame"
  | "mac"
  | "dns"
  | "host"
  | "sni"
  | "len"
  | "flags";

export type BuilderOp = "eq" | "ne" | "contains" | "gt" | "lt" | "present" | "absent";

export interface BuilderCondition {
  field: BuilderField;
  op: BuilderOp;
  value: string;
  /** Joiner with the previous condition. */
  join: "and" | "or";
}

export const BUILDER_FIELDS: BuilderField[] = [
  "src", "dst", "ip", "protocol", "port", "srcport", "dstport", "stream", "frame", "mac", "dns", "host", "sni", "len", "flags",
];

export const PROTOCOLS = ["tcp", "udp", "icmp", "icmpv6", "arp", "dns", "dhcp", "http", "tls", "ntp", "ip", "ipv6", "vlan", "eth"];

export const TCP_FLAGS = ["syn", "ack", "fin", "reset", "push", "urg"];

/** Operators available for a field. */
export function opsFor(field: BuilderField): BuilderOp[] {
  switch (field) {
    case "protocol":
    case "flags":
      return ["present", "absent"];
    case "dns":
    case "host":
    case "sni":
      return ["contains", "eq", "ne"];
    case "port":
    case "srcport":
    case "dstport":
    case "frame":
    case "len":
    case "stream":
      return ["eq", "ne", "gt", "lt"];
    default:
      return ["eq", "ne"];
  }
}

function isIpv6(v: string): boolean {
  return v.includes(":") && !/^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i.test(v);
}

function quote(v: string): string {
  return `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

const OP: Record<BuilderOp, string> = { eq: "==", ne: "!=", contains: "contains", gt: ">", lt: "<", present: "", absent: "" };

/** One condition → filter fragment, or null when incomplete. */
export function conditionToFilter(c: BuilderCondition): string | null {
  const v = c.value.trim();
  const op = OP[c.op];
  const needsValue = c.op !== "present" && c.op !== "absent";
  if (needsValue && !v) return null;
  const cmp = (field: string, value: string) => `${field} ${op} ${value}`;
  switch (c.field) {
    case "src":
      return cmp(isIpv6(v) ? "ipv6.src" : "ip.src", v);
    case "dst":
      return cmp(isIpv6(v) ? "ipv6.dst" : "ip.dst", v);
    case "ip":
      return cmp(isIpv6(v) ? "ipv6.addr" : "ip.addr", v);
    case "port":
      return c.op === "ne"
        ? `!(tcp.port == ${v} || udp.port == ${v})`
        : `(${cmp("tcp.port", v)} || ${cmp("udp.port", v)})`;
    case "srcport":
      return `(${cmp("tcp.srcport", v)} || ${cmp("udp.srcport", v)})`;
    case "dstport":
      return `(${cmp("tcp.dstport", v)} || ${cmp("udp.dstport", v)})`;
    case "stream":
      return cmp("tcp.stream", v);
    case "frame":
      return cmp("frame.number", v);
    case "len":
      return cmp("frame.len", v);
    case "mac":
      return cmp("eth.addr", v);
    case "dns":
      return cmp("dns.qry.name", quote(v));
    case "host":
      return cmp("http.host", quote(v));
    case "sni":
      return cmp("tls.handshake.extensions_server_name", quote(v));
    case "protocol": {
      if (!v) return null;
      return c.op === "absent" ? `!${v}` : v;
    }
    case "flags": {
      if (!v) return null;
      return `tcp.flags.${v} == ${c.op === "absent" ? 0 : 1}`;
    }
  }
}

/** All complete conditions joined; `and` binds tighter than `or` like the filter language. */
export function buildFilter(conditions: BuilderCondition[]): string {
  let out = "";
  for (const c of conditions) {
    const part = conditionToFilter(c);
    if (!part) continue;
    out = out ? `${out} ${c.join === "or" ? "||" : "&&"} ${part}` : part;
  }
  return out;
}

/** Combines an existing filter with a new term ("Apply as filter … and/or selected"). */
export function combineFilters(current: string, term: string, mode: "replace" | "and" | "or" | "not"): string {
  const cur = current.trim();
  const wrap = (s: string) => (/\|\||\bor\b|&&|\band\b/.test(s) ? `(${s})` : s);
  switch (mode) {
    case "replace":
      return term;
    case "not":
      return cur ? `${wrap(cur)} && !(${term})` : `!(${term})`;
    case "and":
      return cur ? `${wrap(cur)} && ${wrap(term)}` : term;
    case "or":
      return cur ? `${wrap(cur)} || ${wrap(term)}` : term;
  }
}
