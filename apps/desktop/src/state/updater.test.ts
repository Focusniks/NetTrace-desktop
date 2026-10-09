import { beforeEach, describe, expect, it, vi } from "vitest";

const check = vi.fn();
const relaunch = vi.fn();
vi.mock("@tauri-apps/plugin-updater", () => ({ check }));
vi.mock("@tauri-apps/plugin-process", () => ({ relaunch }));
vi.mock("../api/client", async (orig) => {
  const real = await orig<typeof import("../api/client")>();
  return {
    ...real,
    inTauri: true,
    setWindowTitle: vi.fn(async () => undefined),
    api: { ...real.api, closeCapture: vi.fn(async () => undefined) },
  };
});

const { checkForUpdates, dismiss, installUpdate, resetUpdater, shouldOffer, skipVersion, useUpdate } = await import("./updater");
const { useStore } = await import("./store");

function fakeUpdate(version = "1.2.0") {
  return {
    version,
    currentVersion: "1.0.0",
    body: "### Добавлено\n- новая функция",
    date: "2026-10-01",
    close: vi.fn(async () => undefined),
    download: vi.fn(async (cb: (e: unknown) => void) => {
      cb({ event: "Started", data: { contentLength: 100 } });
      cb({ event: "Progress", data: { chunkLength: 60 } });
      cb({ event: "Progress", data: { chunkLength: 40 } });
      cb({ event: "Finished" });
    }),
    install: vi.fn(async () => undefined),
  };
}

beforeEach(() => {
  check.mockReset();
  relaunch.mockReset();
  resetUpdater();
  useStore.setState({ dialog: null, capture: null, progress: null, pendingAction: null, liveSaved: false });
  useStore.getState().updateSettings({ skippedVersion: null });
});

describe("shouldOffer", () => {
  it("hides a skipped version only from the silent check", () => {
    expect(shouldOffer("1.2.0", false, "1.2.0")).toBe(false);
    expect(shouldOffer("1.2.0", true, "1.2.0")).toBe(true);
    expect(shouldOffer("1.3.0", false, "1.2.0")).toBe(true);
  });
});

describe("checkForUpdates", () => {
  it("silent check without an update stays quiet", async () => {
    check.mockResolvedValue(null);
    await checkForUpdates(false);
    expect(useUpdate.getState().status).toBe("idle");
    expect(useStore.getState().dialog).toBeNull();
  });

  it("manual check reports that the app is up to date", async () => {
    check.mockResolvedValue(null);
    await checkForUpdates(true);
    expect(useUpdate.getState().status).toBe("latest");
    expect(useStore.getState().dialog).toBe("update");
  });

  it("offers a found update with its notes", async () => {
    check.mockResolvedValue(fakeUpdate());
    await checkForUpdates(false);
    const u = useUpdate.getState();
    expect(u).toMatchObject({ status: "available", version: "1.2.0", currentVersion: "1.0.0" });
    expect(u.notes).toContain("новая функция");
    expect(useStore.getState().dialog).toBe("update");
  });

  it("does not replace another open dialog", async () => {
    check.mockResolvedValue(fakeUpdate());
    useStore.setState({ dialog: "capture" });
    await checkForUpdates(false);
    expect(useStore.getState().dialog).toBe("capture");
    expect(useUpdate.getState().status).toBe("available");
  });

  it("silent check skips the version the user skipped", async () => {
    check.mockResolvedValue(fakeUpdate());
    await checkForUpdates(false);
    skipVersion();
    expect(useStore.getState().settings.skippedVersion).toBe("1.2.0");
    expect(useStore.getState().dialog).toBeNull();

    const again = fakeUpdate();
    check.mockResolvedValue(again);
    await checkForUpdates(false);
    expect(useUpdate.getState().status).toBe("idle");
    expect(again.close).toHaveBeenCalled();
  });

  it("a manual check joining a quiet startup check still reports the result", async () => {
    let resolve: (v: null) => void = () => undefined;
    check.mockReturnValueOnce(new Promise((r) => (resolve = r)));
    const silent = checkForUpdates(false);
    check.mockResolvedValueOnce(null);
    const manual = checkForUpdates(true);
    resolve(null);
    await Promise.all([silent, manual]);
    expect(useUpdate.getState().status).toBe("latest");
    expect(useUpdate.getState().currentVersion).toBeTruthy();
    expect(useStore.getState().dialog).toBe("update");
  });

  it("a startup offer during a live capture only flashes", async () => {
    check.mockResolvedValue(fakeUpdate());
    useStore.setState({
      capture: { captureId: 1, path: "x", fileName: "x", fileSize: 0, format: "pcap", live: true },
      progress: { state: "indexing", packets: 5, capture: { running: true } } as never,
    });
    await checkForUpdates(false);
    expect(useUpdate.getState().status).toBe("available");
    expect(useStore.getState().dialog).toBeNull();
  });

  it("silent check swallows network errors; manual check shows them", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    check.mockRejectedValue(new Error("offline"));
    await checkForUpdates(false);
    expect(useUpdate.getState().status).toBe("idle");
    expect(warn).toHaveBeenCalled();
    await checkForUpdates(true);
    expect(useUpdate.getState()).toMatchObject({ status: "error", error: "offline" });
    warn.mockRestore();
  });
});

describe("installUpdate", () => {
  it("downloads with progress, installs and relaunches", async () => {
    const update = fakeUpdate();
    check.mockResolvedValue(update);
    await checkForUpdates(true);
    await installUpdate();
    expect(update.download).toHaveBeenCalled();
    expect(useUpdate.getState().downloaded).toBe(100);
    expect(useUpdate.getState().total).toBe(100);
    expect(update.install).toHaveBeenCalled();
    expect(relaunch).toHaveBeenCalled();
  });

  it("asks about unsaved live packets before installing", async () => {
    const update = fakeUpdate();
    check.mockResolvedValue(update);
    await checkForUpdates(true);
    useStore.setState({
      capture: { captureId: 1, path: "x", fileName: "x", fileSize: 0, format: "pcap", live: true },
      progress: { state: "done", packets: 5 } as never,
      liveSaved: false,
    });
    await installUpdate();
    expect(useStore.getState().dialog).toBe("unsaved");
    expect(update.install).not.toHaveBeenCalled();
    // "Не сохранять" runs the pending action.
    await useStore.getState().pendingAction?.();
    expect(update.install).toHaveBeenCalled();
  });

  it("a failed download can be retried", async () => {
    const update = fakeUpdate();
    update.download.mockRejectedValueOnce(new Error("signature mismatch"));
    check.mockResolvedValue(update);
    await checkForUpdates(true);
    await installUpdate();
    expect(useUpdate.getState()).toMatchObject({ status: "error", error: "signature mismatch" });
    expect(update.install).not.toHaveBeenCalled();
    await installUpdate();
    expect(update.install).toHaveBeenCalled();
  });

  it("never installs unasked when the dialog was closed during the download", async () => {
    const update = fakeUpdate();
    update.download.mockImplementationOnce(async () => {
      dismiss();
    });
    check.mockResolvedValue(update);
    await checkForUpdates(true);
    await installUpdate();
    expect(useUpdate.getState().status).toBe("ready");
    expect(update.install).not.toHaveBeenCalled();
    // Installing later from the dialog skips the download.
    useStore.getState().setDialog("update");
    await installUpdate();
    expect(update.download).toHaveBeenCalledTimes(1);
    expect(update.install).toHaveBeenCalled();
  });

  it("a double click starts one download and one install", async () => {
    const update = fakeUpdate();
    check.mockResolvedValue(update);
    await checkForUpdates(true);
    await Promise.all([installUpdate(), installUpdate()]);
    expect(update.download).toHaveBeenCalledTimes(1);
    expect(update.install).toHaveBeenCalledTimes(1);
  });

  it("the dialog cannot be dismissed while installing", async () => {
    useStore.getState().setDialog("update");
    useUpdate.setState({ status: "installing" });
    dismiss();
    expect(useStore.getState().dialog).toBe("update");
  });

  it("closing the dialog forgets a finished check", async () => {
    check.mockResolvedValue(null);
    await checkForUpdates(true);
    dismiss();
    expect(useUpdate.getState().status).toBe("idle");
    expect(useStore.getState().dialog).toBeNull();
  });
});
