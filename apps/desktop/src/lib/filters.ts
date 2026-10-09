/** Filter for an address of any family: ip / ipv6 / eth, field `src`, `dst` or `addr`. */
export function addrFilter(addr: string, dir: "src" | "dst" | "addr"): string {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(addr)) return `ip.${dir} == ${addr}`;
  if (/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(addr)) return `eth.${dir} == ${addr}`;
  return `ipv6.${dir} == ${addr}`;
}
