import { describe, expect, it } from "vitest";
import { computeWindow, MAX_SCROLL_PX, scrollTopForRow } from "./virtual";

describe("computeWindow", () => {
  it("renders the visible slice for small lists", () => {
    const w = computeWindow(1000, 20, 400, 2000, 2);
    expect(w.contentHeight).toBe(20_000);
    expect(w.first).toBe(98);
    expect(w.offsetY).toBe(98 * 20);
    expect(w.count).toBeLessThanOrEqual(26);
  });

  it("never renders past the end", () => {
    const w = computeWindow(10, 20, 400, 0);
    expect(w.first).toBe(0);
    expect(w.count).toBe(10);
    expect(computeWindow(0, 20, 400, 0).count).toBe(0);
  });

  it("compresses huge lists and reaches the last row", () => {
    const total = 5_000_000;
    const top = computeWindow(total, 20, 400, 0);
    expect(top.contentHeight).toBe(MAX_SCROLL_PX);
    expect(top.first).toBe(0);
    const bottom = computeWindow(total, 20, 400, MAX_SCROLL_PX - 400);
    expect(bottom.first + bottom.count).toBe(total);
  });
});

describe("scrollTopForRow", () => {
  it("keeps visible rows in place", () => {
    expect(scrollTopForRow(5, 1000, 20, 400, 0, true)).toBe(0);
    expect(scrollTopForRow(30, 1000, 20, 400, 0, true)).toBe(31 * 20 - 400);
    expect(scrollTopForRow(2, 1000, 20, 400, 200, true)).toBe(40);
  });

  it("maps rows into compressed space", () => {
    const total = 5_000_000;
    const y = scrollTopForRow(total - 1, total, 20, 400, 0, false);
    const w = computeWindow(total, 20, 400, y);
    expect(w.first + w.count).toBeGreaterThanOrEqual(total - 1);
  });
});
