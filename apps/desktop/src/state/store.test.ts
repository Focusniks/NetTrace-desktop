import { beforeEach, describe, expect, it, vi } from "vitest";

import type { CaptureInfo, IndexProgress } from "../api/types";

const openCapture = vi.fn();
const summary = vi.fn(async () => ({}));
vi.mock("../api/client", async (orig) => {
  const real = await orig<typeof import("../api/client")>();
  return {
    ...real,
    setWindowTitle: vi.fn(async () => undefined),
    api: { ...real.api, openCapture, summary },
  };
});

const { useStore } = await import("./store");

const info = (captureId: number): CaptureInfo => ({
  captureId,
  path: `C:\\c${captureId}.pcap`,
  fileName: `c${captureId}.pcap`,
  fileSize: 100,
  format: "PCAP",
  live: false,
});

const done = (captureId: number, packets: number): IndexProgress => ({
  captureId,
  state: "done",
  packets,
  tcpStreams: 0,
  udpStreams: 0,
  bytesRead: 100,
  totalBytes: 100,
  elapsedMs: 2,
  warning: null,
  error: null,
  capture: null,
});

beforeEach(() => {
  openCapture.mockReset();
  useStore.setState({ capture: null, progress: null, viewTotal: 0, filterText: "" });
});

describe("opening a capture", () => {
  it("keeps a progress event that arrives before openCapture returns", async () => {
    // A small file is indexed before the command's response reaches the UI.
    openCapture.mockImplementation(async () => {
      useStore.getState().onProgress(done(7, 137));
      return info(7);
    });
    await useStore.getState().openFile("C:\\c7.pcap");
    const s = useStore.getState();
    expect(s.progress?.state).toBe("done");
    expect(s.viewTotal).toBe(137);
    expect(summary).toHaveBeenCalled();
  });

  it("ignores late events of the previous capture", async () => {
    openCapture.mockResolvedValue(info(9));
    await useStore.getState().openFile("C:\\c9.pcap");
    useStore.getState().onProgress(done(8, 5));
    expect(useStore.getState().progress).toBeNull();
    useStore.getState().onProgress(done(9, 42));
    expect(useStore.getState().viewTotal).toBe(42);
  });
});
