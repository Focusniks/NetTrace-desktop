import { describe, expect, it } from "vitest";

import type { PacketField } from "../api/types";
import { ancestorKeys, deepestAt, flatten, nodeAt } from "./tree";

const f = (field: string, start: number, len: number, children: PacketField[] = []): PacketField => ({
  field,
  name: field,
  display: "",
  start,
  len,
  generated: false,
  children,
});

const tree: PacketField[] = [
  f("frame", 0, 60),
  f("eth", 0, 14, [f("eth.dst", 0, 6), f("eth.src", 6, 6)]),
  f("ip", 14, 20, [f("ip.flags", 20, 2, [f("ip.flags.df", 20, 1)]), f("ip.src", 26, 4)]),
];

describe("tree helpers", () => {
  it("flattens only expanded branches", () => {
    expect(flatten(tree, new Set()).map((n) => n.path)).toEqual(["0", "1", "2"]);
    const open = flatten(tree, new Set(["ip", "ip/ip.flags"]));
    expect(open.map((n) => n.node.field)).toEqual(["frame", "eth", "ip", "ip.flags", "ip.flags.df", "ip.src"]);
    expect(open[4].depth).toBe(2);
  });

  it("finds the deepest node for a byte", () => {
    expect(deepestAt(tree, 20)).toBe("2/0/0");
    expect(deepestAt(tree, 27)).toBe("2/1");
    expect(deepestAt(tree, 7)).toBe("1/1");
    expect(deepestAt(tree, 50)).toBeNull();
  });

  it("resolves paths and ancestors", () => {
    expect(nodeAt(tree, "2/0/0")?.field).toBe("ip.flags.df");
    expect(nodeAt(tree, "9")).toBeNull();
    expect(ancestorKeys(tree, "2/0/0")).toEqual(["ip", "ip/ip.flags"]);
  });
});
