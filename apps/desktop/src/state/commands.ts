// User commands shared by the menu bar, toolbar and keyboard shortcuts.

import { api, BackendError, pickCaptureFile } from "../api/client";
import { t, type MessageKey } from "../i18n";
import { useStore, type DockTab } from "./store";

const s = () => useStore.getState();

function message(e: unknown): string {
  if (e instanceof BackendError) {
    const key = `err.${e.code}` as MessageKey;
    const known = t(key);
    return known === key ? e.message : known;
  }
  return (e as Error).message ?? String(e);
}

/** True while a live capture is still recording packets. */
export function isCapturing(): boolean {
  const st = s();
  return !!st.capture?.live && st.progress?.capture?.running !== false && st.progress?.state !== "done" && st.progress?.state !== "failed";
}

/** Stops a running capture and waits until its last packets are indexed. */
export async function stopAndWait(timeoutMs = 15000): Promise<void> {
  if (!isCapturing()) return;
  await s().stopCapture();
  const until = Date.now() + timeoutMs;
  while (s().progress?.state === "indexing" && Date.now() < until) {
    await new Promise((r) => setTimeout(r, 50));
  }
}

export const commands = {
  async open() {
    await s().guardUnsaved(async () => {
      const path = await pickCaptureFile(t("action.open"));
      if (path) await s().openFile(path);
    });
  },
  async openPath(path: string) {
    await s().guardUnsaved(() => s().openFile(path));
  },
  async close() {
    await s().guardUnsaved(() => s().closeFile());
  },
  /**
   * Saves the displayed packets (`all`: every packet, ignoring the display
   * filter); resolves to true when a file was written.
   */
  async exportView(all = false): Promise<boolean> {
    const st = s();
    if (!st.capture) return false;
    try {
      await stopAndWait();
      const cur = s();
      const base = cur.capture?.live
        ? `capture-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}`
        : (cur.capture?.fileName ?? "capture").replace(/\.(pcapng|pcap|cap)$/i, "") + "-filtered";
      // View 0 is the whole capture.
      const whole = all || !cur.appliedFilter;
      const n = await api.exportView(whole ? 0 : cur.viewId, `${base}.pcap`, t("action.export"));
      if (n == null) return false;
      // Saving the whole live capture means nothing is lost on close.
      if (cur.capture?.live && whole) useStore.setState({ liveSaved: true });
      // Only indexed packets are written: say so when reading stopped early.
      const p = cur.progress;
      const partial = p != null && (p.state === "failed" || p.state === "cancelled" || p.warning === "too_many_packets");
      cur.flash(t(partial ? "status.exportedPartial" : "status.exported", { n }));
      return true;
    } catch (e) {
      s().flash(t("common.error", { message: message(e) }));
      return false;
    }
  },
  /** Opens the interface dialog (Ctrl+E when nothing is capturing). */
  captureDialog() {
    s().setDialog("capture");
  },
  async startOrStop() {
    if (isCapturing()) await s().stopCapture();
    else s().setDialog("capture");
  },
  async stopCapture() {
    await s().stopCapture();
  },
  /** Restarts the capture with the last options. */
  async restartCapture() {
    const opts = s().settings.lastCapture;
    if (!opts) {
      s().setDialog("capture");
      return;
    }
    try {
      await stopAndWait();
      // Restarting discards the current packets: ask to save them first.
      await s().guardUnsaved(() => s().startCapture(opts));
    } catch (e) {
      s().flash(t("common.error", { message: message(e) }));
    }
  },
  toggleAutoScroll() {
    s().updateSettings({ autoScroll: !s().settings.autoScroll });
  },
  find() {
    // Ctrl+F on an open search bar goes back to its input rather than closing it.
    const input = document.getElementById("packet-search") as HTMLInputElement | null;
    if (input) {
      input.focus();
      input.select();
    } else {
      s().setSearchOpen(true);
    }
  },
  goto() {
    s().setDialog("goto");
  },
  first() {
    void s().moveSelection("first");
  },
  last() {
    void s().moveSelection("last");
  },
  next() {
    void s().moveSelection(1);
  },
  prev() {
    void s().moveSelection(-1);
  },
  back() {
    s().back();
  },
  forward() {
    s().forward();
  },
  focusFilter() {
    document.getElementById("display-filter")?.focus();
  },
  toggleColorize() {
    s().updateSettings({ colorize: !s().settings.colorize });
  },
  dock(tab: DockTab) {
    const st = s();
    if (st.dockOpen && st.dockTab === tab) st.setDock({ dockOpen: false });
    else st.openDock(tab);
  },
  followSelected(tab: "streams" | "sequence" = "streams") {
    const stream = s().detail?.stream;
    if (stream) s().focusOnStream(stream, tab);
  },
};
