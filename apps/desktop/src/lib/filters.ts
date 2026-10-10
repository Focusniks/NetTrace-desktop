/** Filter for an address of any family: ip / ipv6 / eth, field `src`, `dst` or `addr`. */
export function addrFilter(addr: string, dir: "src" | "dst" | "addr"): string {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(addr)) return `ip.${dir} == ${addr}`;
  if (/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(addr)) return `eth.${dir} == ${addr}`;
  return `ipv6.${dir} == ${addr}`;
}

export type IoSource = "all" | "displayed" | "protocol" | "stream" | "custom";

/** Display filter of an I/O graph series (null: the series is not drawn). */
export function ioSourceFilter(
  source: IoSource,
  o: { applied: string; protocol: string; streamKind: "tcp" | "udp"; stream: string; custom: string },
): string | null {
  switch (source) {
    case "all":
      return null;
    case "displayed":
      return o.applied || null;
    case "protocol":
      return o.protocol;
    case "stream":
      return `${o.streamKind}.stream == ${Number.parseInt(o.stream, 10) || 0}`;
    case "custom":
      return o.custom.trim() || null;
  }
}
