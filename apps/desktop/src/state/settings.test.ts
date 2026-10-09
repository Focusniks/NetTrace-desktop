import { describe, expect, it } from "vitest";

import { DEFAULT_SETTINGS, sanitizeSettings } from "./settings";

describe("sanitizeSettings", () => {
  it("falls back to defaults for missing or ill-typed values", () => {
    const s = sanitizeSettings({
      timeFormat: "bogus",
      dockWidth: "wide",
      listFraction: 7,
      coloringRules: [{ name: "x" }, { name: "ok", filter: "tcp", bg: "red", fg: "#ffffff" }],
      recentFiles: ["a.pcap", 5, null],
      lastCapture: { interface: 3 },
    });
    expect(s.timeFormat).toBe(DEFAULT_SETTINGS.timeFormat);
    expect(s.dockWidth).toBe(DEFAULT_SETTINGS.dockWidth);
    expect(s.listFraction).toBe(0.9);
    expect(s.coloringRules).toEqual([{ name: "ok", filter: "tcp", bg: "#2a3140", fg: "#ffffff", enabled: true }]);
    expect(s.recentFiles).toEqual(["a.pcap"]);
    expect(s.lastCapture).toBeNull();
  });

  it("keeps valid values", () => {
    const s = sanitizeSettings({ ...DEFAULT_SETTINGS, timeFormat: "utc", autoScroll: false, skippedVersion: "1.2.0" });
    expect(s).toEqual({ ...DEFAULT_SETTINGS, timeFormat: "utc", autoScroll: false, skippedVersion: "1.2.0" });
    expect(sanitizeSettings("garbage")).toBe(DEFAULT_SETTINGS);
  });
});
