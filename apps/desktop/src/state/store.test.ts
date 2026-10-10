import { beforeEach, describe, expect, it, vi } from "vitest";

import type { CaptureInfo, IndexProgress, PacketField } from "../api/types";

const openCapture = vi.fn();
const summary = vi.fn(async () => ({}));
const findRow = vi.fn(async () => 0);
const packetDetail = vi.fn(async (n: number) => ({ number: n, tree: [] as PacketField[], bytes: [] as number[] }));
const applyView = vi.fn(async () => ({ viewId: 1, total: 1, elapsedMs: 0 }));
vi.mock("../api/client", async (orig) => {
  const real = await orig<typeof import("../api/client")>();
  return {
    ...real,
    setWindowTitle: vi.fn(async () => undefined),
    api: { ...real.api, openCapture, summary, findRow, packetDetail, applyView },
  };
});

const { describeError, progressErrorText, useStore } = await import("./store");

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
  errorCode: null,
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

describe("navigating to packets", () => {
  it("brings the packet list back from behind a maximized tool panel", async () => {
    const { applyFilterText } = await import("./actions");
    useStore.setState({ capture: info(1), dockOpen: true, dockMaximized: true });
    await useStore.getState().selectPacket(5);
    expect(useStore.getState().dockMaximized).toBe(false);

    useStore.setState({ dockMaximized: true });
    applyFilterText("dns");
    expect(useStore.getState().dockMaximized).toBe(false);

    // A live refresh of the same filter is not a navigation.
    useStore.setState({ dockMaximized: true });
    await useStore.getState().applyFilter("dns", { refresh: true });
    expect(useStore.getState().dockMaximized).toBe(true);
  });
});

describe("error texts", () => {
  it("are Russian, with the OS detail only where it helps", () => {
    expect(describeError("corrupt", "pcapng block too large")).toBe("Файл захвата повреждён");
    expect(describeError("io", "Не удается найти указанный файл")).toBe("Ошибка ввода-вывода: Не удается найти указанный файл");
    expect(describeError("weird_code", "boom")).toBe("Ошибка weird_code: boom");
    const p = { ...done(1, 0), state: "failed" as const, error: "corrupt: bad block", errorCode: "corrupt" };
    expect(progressErrorText(p)).toBe("Файл захвата повреждён");
  });
});

describe("search matches", () => {
  it("highlight the matched field once the details arrive", async () => {
    const field = { field: "dns.qry.name", name: "Name", display: "a.example", start: 54, len: 11, generated: false, children: [] };
    packetDetail.mockResolvedValueOnce({ number: 7, tree: [field], bytes: [] });
    useStore.setState({ capture: info(1) });
    await useStore.getState().selectPacket(7, { match: { path: [0], start: 54, len: 11 } });
    expect(useStore.getState()).toMatchObject({ highlight: { start: 54, len: 11 }, selectedFieldKey: "0" });
    // A plain selection clears it.
    await useStore.getState().selectPacket(8);
    expect(useStore.getState().highlight).toBeNull();
  });
});
