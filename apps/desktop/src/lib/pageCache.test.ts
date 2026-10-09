import { describe, expect, it } from "vitest";

import { PageCache } from "./pageCache";

const rows = (from: number, n: number) => Array.from({ length: n }, (_, i) => from + i);

describe("PageCache", () => {
  it("requests the pages of a window once", () => {
    const c = new PageCache<number>(10, 3);
    expect(c.missing(0, 1)).toEqual([0]);
    const g = c.begin(0);
    expect(c.missing(0, 1)).toEqual([]);
    expect(c.done(0, g, { total: 35, rows: rows(0, 10) })).toBe(true);
    expect(c.get(7)).toBe(7);
    expect(c.missing(5, 20)).toEqual([1, 2]);
    // Never past the end.
    expect(c.missing(30, 50)).toEqual([3]);
  });

  it("evicts least recently used pages", () => {
    const c = new PageCache<number>(10, 2);
    for (const p of [0, 1]) c.done(p, c.begin(p), { total: 100, rows: rows(p * 10, 10) });
    expect(c.get(5)).toBe(5); // page 0 is now the most recently used
    c.done(2, c.begin(2), { total: 100, rows: rows(20, 10) });
    expect(c.get(15)).toBeUndefined();
    expect(c.get(5)).toBe(5);
    expect(c.get(25)).toBe(25);
  });

  it("keeps showing rows while a refresh is loading and drops answers to an old query", () => {
    const c = new PageCache<number>(10, 5);
    c.done(0, c.begin(0), { total: 20, rows: rows(0, 10) });
    const slow = c.begin(1);
    c.refresh();
    expect(c.get(3)).toBe(3);
    // A request still under way at a refresh lands.
    expect(c.done(1, slow, { total: 20, rows: rows(10, 10) })).toBe(true);
    const old = c.begin(0);
    c.reset();
    expect(c.done(0, old, { total: 10, rows: rows(100, 10) })).toBe(false);
    expect(c.missing(0, 5)).toEqual([0]);
    c.done(0, c.begin(0), { total: 12, rows: rows(50, 10) });
    expect(c.total).toBe(12);
    expect(c.get(3)).toBe(53);
  });

  it("forgets everything on reset and retries failed pages on request", () => {
    const c = new PageCache<number>(10, 5);
    c.done(0, c.begin(0), { total: 10, rows: rows(0, 10) });
    c.reset();
    expect(c.total).toBeNull();
    expect(c.get(0)).toBeUndefined();
    const g = c.begin(0);
    expect(c.fail(0, g)).toBe(true);
    expect(c.missing(0, 1)).toEqual([]);
    c.retry();
    expect(c.missing(0, 1)).toEqual([0]);
  });
});
