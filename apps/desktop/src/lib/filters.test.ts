import { describe, expect, it } from "vitest";

import { addrFilter, ioSourceFilter } from "./filters";

describe("addrFilter", () => {
  it("picks the address family", () => {
    expect(addrFilter("10.0.0.1", "src")).toBe("ip.src == 10.0.0.1");
    expect(addrFilter("00:11:22:33:44:55", "addr")).toBe("eth.addr == 00:11:22:33:44:55");
    expect(addrFilter("fe80::1", "dst")).toBe("ipv6.dst == fe80::1");
  });
});

describe("ioSourceFilter", () => {
  const o = { applied: "dns", protocol: "tls", streamKind: "tcp" as const, stream: "7", custom: "  " };
  it("builds the filter of each source", () => {
    expect(ioSourceFilter("all", o)).toBeNull();
    expect(ioSourceFilter("displayed", o)).toBe("dns");
    expect(ioSourceFilter("protocol", o)).toBe("tls");
    expect(ioSourceFilter("stream", o)).toBe("tcp.stream == 7");
    expect(ioSourceFilter("stream", { ...o, streamKind: "udp", stream: "x" })).toBe("udp.stream == 0");
    expect(ioSourceFilter("custom", o)).toBeNull();
  });
});
