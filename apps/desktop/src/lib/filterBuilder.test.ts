import { describe, expect, it } from "vitest";
import { buildFilter, combineFilters, conditionToFilter, withField } from "./filterBuilder";

describe("conditionToFilter", () => {
  it("maps fields to display filter syntax", () => {
    expect(conditionToFilter({ field: "src", op: "eq", value: "10.10.1.15", join: "and" })).toBe("ip.src == 10.10.1.15");
    expect(conditionToFilter({ field: "ip", op: "eq", value: "fe80::1", join: "and" })).toBe("ipv6.addr == fe80::1");
    expect(conditionToFilter({ field: "mac", op: "eq", value: "00:11:22:33:44:55", join: "and" })).toBe("eth.addr == 00:11:22:33:44:55");
    expect(conditionToFilter({ field: "protocol", op: "present", value: "tcp", join: "and" })).toBe("tcp");
    expect(conditionToFilter({ field: "protocol", op: "absent", value: "arp", join: "and" })).toBe("!arp");
    expect(conditionToFilter({ field: "dstport", op: "eq", value: "443", join: "and" })).toBe("(tcp.dstport == 443 || udp.dstport == 443)");
    expect(conditionToFilter({ field: "srcport", op: "ne", value: "53", join: "and" })).toBe("!(tcp.srcport == 53 || udp.srcport == 53)");
    expect(conditionToFilter({ field: "port", op: "ne", value: "53", join: "and" })).toBe("!(tcp.port == 53 || udp.port == 53)");
    expect(conditionToFilter({ field: "sni", op: "contains", value: 'a"b', join: "and" })).toBe('tls.handshake.extensions_server_name contains "a\\"b"');
    expect(conditionToFilter({ field: "flags", op: "present", value: "syn", join: "and" })).toBe("tcp.flags.syn == 1");
  });

  it("skips incomplete conditions", () => {
    expect(conditionToFilter({ field: "src", op: "eq", value: " ", join: "and" })).toBeNull();
  });
});

describe("buildFilter", () => {
  it("joins conditions", () => {
    expect(
      buildFilter([
        { field: "src", op: "eq", value: "10.10.1.15", join: "and" },
        { field: "protocol", op: "present", value: "tcp", join: "and" },
        { field: "dstport", op: "eq", value: "443", join: "and" },
      ]),
    ).toBe("ip.src == 10.10.1.15 && tcp && (tcp.dstport == 443 || udp.dstport == 443)");
    expect(buildFilter([])).toBe("");
  });
});

describe("combineFilters", () => {
  it("wraps compound expressions", () => {
    expect(combineFilters("", "tcp", "and")).toBe("tcp");
    expect(combineFilters("dns || arp", "ip.src == 1.1.1.1", "and")).toBe("(dns || arp) && ip.src == 1.1.1.1");
    expect(combineFilters("tcp", "udp", "or")).toBe("tcp || udp");
    expect(combineFilters("tcp", "tcp.port == 22", "not")).toBe("tcp && !(tcp.port == 22)");
    expect(combineFilters("tcp", "udp", "replace")).toBe("udp");
  });
});

describe("withField", () => {
  const c = (field: Parameters<typeof withField>[1], value: string, op: "eq" | "present" | "contains" = "eq") =>
    ({ field, op, value, join: "and" }) as const;

  it("keeps the value only between fields of the same kind", () => {
    expect(withField(c("src", "10.0.0.1"), "dst").value).toBe("10.0.0.1");
    expect(withField(c("port", "443"), "dstport").value).toBe("443");
    expect(withField(c("host", "a.example", "contains"), "sni")).toMatchObject({ value: "a.example", op: "contains" });
    expect(withField(c("protocol", "tcp", "present"), "src")).toMatchObject({ value: "", op: "eq" });
    expect(withField(c("src", "10.0.0.1"), "port").value).toBe("");
  });

  it("starts protocol and flag conditions with a valid choice", () => {
    expect(withField(c("src", "10.0.0.1"), "protocol")).toMatchObject({ value: "tcp", op: "present" });
    expect(withField(c("port", "80"), "flags")).toMatchObject({ value: "syn", op: "present" });
  });
});

describe("stream fields", () => {
  it("names the transport of the stream", () => {
    expect(conditionToFilter({ field: "stream", op: "eq", value: "3", join: "and" })).toBe("tcp.stream == 3");
    expect(conditionToFilter({ field: "udpstream", op: "eq", value: "3", join: "and" })).toBe("udp.stream == 3");
  });
});
