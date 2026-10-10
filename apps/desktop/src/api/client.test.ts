import { describe, expect, it } from "vitest";

import { dragOverlayState } from "./client";

describe("dragOverlayState", () => {
  it("shows the drop hint while files are over the window", () => {
    expect(dragOverlayState("enter")).toBe(true);
    expect(dragOverlayState("over")).toBe(true);
    expect(dragOverlayState("leave")).toBe(false);
    expect(dragOverlayState("drop")).toBe(false);
    expect(dragOverlayState("something")).toBeNull();
  });
});
