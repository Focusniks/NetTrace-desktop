// Application updates (Tauri only): signed releases published on GitHub.
// The updater plugin verifies every package against the public key built into
// the app, so a tampered download is rejected before anything is installed.

import type { Update } from "@tauri-apps/plugin-updater";
import { create } from "zustand";

import { inTauri } from "../api/client";
import { t } from "../i18n";
import { APP_VERSION } from "../version";
import { isCapturing, stopAndWait } from "./commands";
import { useStore } from "./store";

export type UpdateStatus =
  | "idle"
  | "checking"
  /** Manual check found nothing newer. */
  | "latest"
  | "available"
  | "downloading"
  /** Downloaded; waiting for the unsaved-capture prompt or the installer. */
  | "ready"
  | "installing"
  | "error";

export interface UpdateState {
  status: UpdateStatus;
  /** The user asked for this check (menu), as opposed to the startup check. */
  manual: boolean;
  version: string | null;
  currentVersion: string;
  notes: string;
  date: string | null;
  downloaded: number;
  total: number | null;
  error: string | null;
}

const IDLE: UpdateState = {
  status: "idle",
  manual: false,
  version: null,
  currentVersion: APP_VERSION,
  notes: "",
  date: null,
  downloaded: 0,
  total: null,
  error: null,
};

export const useUpdate = create<UpdateState>(() => IDLE);

/** The update found by the last check (kept outside React state: it owns a native resource). */
let pending: Update | null = null;
/** The check in flight, so a manual check can wait for a running startup check. */
let inflight: Promise<void> | null = null;
/** Set synchronously so a double click cannot start two downloads or installs. */
let installing = false;

const PROGRESS_INTERVAL_MS = 100;

function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** Silent checks never prompt for a version the user chose to skip. */
export function shouldOffer(version: string, manual: boolean, skipped: string | null): boolean {
  return manual || version !== skipped;
}

const dialogOpen = () => useStore.getState().dialog === "update";

/** Opens the update dialog unless another dialog is open; then `fallback` goes to the status bar. */
function showDialog(fallback: string): void {
  const st = useStore.getState();
  if (st.dialog === null || st.dialog === "update") st.setDialog("update");
  else st.flash(fallback);
}

/** Reports an outcome: in the dialog when it is open, otherwise in the status bar. */
function report(message: string): void {
  if (!dialogOpen()) useStore.getState().flash(message);
}

/**
 * Checks GitHub for a newer release. A manual check always reports the outcome;
 * the silent startup check only speaks up when there is something to install.
 */
export async function checkForUpdates(manual: boolean): Promise<void> {
  if (!inTauri) return;
  const { status } = useUpdate.getState();
  if (status === "checking" && inflight) {
    if (!manual) return;
    // Join the running startup check; repeat it as a manual one if it stayed quiet.
    useUpdate.setState({ manual: true });
    useStore.getState().setDialog("update");
    await inflight;
    if (useUpdate.getState().status === "idle") await checkForUpdates(true);
    return;
  }
  if (status === "downloading" || status === "ready" || status === "installing") {
    if (manual) useStore.getState().setDialog("update");
    return;
  }
  useUpdate.setState({ ...IDLE, status: "checking", manual });
  if (manual) useStore.getState().setDialog("update");
  inflight = runCheck();
  try {
    await inflight;
  } finally {
    inflight = null;
  }
}

async function runCheck(): Promise<void> {
  try {
    const { check } = await import("@tauri-apps/plugin-updater");
    const update = await check({ timeout: 30_000 });
    // A manual check may have joined while this one was running.
    const manual = useUpdate.getState().manual;
    if (!update) {
      if (manual) {
        useUpdate.setState({ status: "latest" });
        report(t("update.latest", { version: APP_VERSION }));
      } else {
        useUpdate.setState({ status: "idle" });
      }
      return;
    }
    if (!shouldOffer(update.version, manual, useStore.getState().settings.skippedVersion)) {
      await update.close().catch(() => undefined);
      useUpdate.setState({ status: "idle" });
      return;
    }
    await pending?.close().catch(() => undefined);
    pending = update;
    useUpdate.setState({
      status: "available",
      version: update.version,
      currentVersion: update.currentVersion,
      notes: update.body ?? "",
      date: update.date ?? null,
    });
    const flash = t("update.availableFlash", { version: update.version });
    // Never interrupt a live capture with a popup: mention it in the status bar.
    if (!manual && isCapturing()) useStore.getState().flash(flash);
    else showDialog(flash);
  } catch (e) {
    if (useUpdate.getState().manual) {
      const message = errorText(e);
      useUpdate.setState({ status: "error", error: message });
      report(t("update.error", { message }));
    } else {
      // Offline or GitHub unreachable: the startup check stays quiet.
      console.warn("update check failed:", e);
      useUpdate.setState({ status: "idle" });
    }
  }
}

/** Downloads the update, then installs it and restarts the app. */
export async function installUpdate(): Promise<void> {
  const update = pending;
  if (!update || installing) return;
  installing = true;
  try {
    const status = useUpdate.getState().status;
    if (status === "available" || status === "error") {
      useUpdate.setState({ status: "downloading", downloaded: 0, total: null, error: null });
      let downloaded = 0;
      let last = 0;
      await update.download((ev) => {
        if (ev.event === "Started") {
          useUpdate.setState({ total: ev.data.contentLength ?? null });
        } else if (ev.event === "Progress") {
          downloaded += ev.data.chunkLength;
          // Throttled: one render per interval, not per network chunk.
          const now = Date.now();
          if (now - last >= PROGRESS_INTERVAL_MS) {
            last = now;
            useUpdate.setState({ downloaded });
          }
        }
      });
      useUpdate.setState({ status: "ready", downloaded });
      // The dialog was closed during the download: never restart unasked.
      if (!dialogOpen()) {
        useStore.getState().flash(t("update.readyFlash", { version: useUpdate.getState().version ?? "" }));
        return;
      }
    } else if (status !== "ready") {
      return;
    }
    // A running capture is stopped first; unsaved packets are offered for saving.
    await stopAndWait();
    // The action may run later from the "save packets?" dialog, outside this
    // try block, so it reports its own failures.
    await useStore.getState().guardUnsaved(async () => {
      try {
        useUpdate.setState({ status: "installing" });
        useStore.getState().setDialog("update");
        // Close a live capture so its temporary file is removed before the app
        // exits; an opened file stays open in case the install fails.
        if (useStore.getState().capture?.live) await useStore.getState().closeFile();
        // On Windows the installer takes over and the app exits here; the
        // installer starts the new version itself.
        await update.install();
        const { relaunch } = await import("@tauri-apps/plugin-process");
        await relaunch();
      } catch (e) {
        const message = errorText(e);
        useUpdate.setState({ status: "error", error: message });
        report(t("update.error", { message }));
      }
    });
  } catch (e) {
    const message = errorText(e);
    useUpdate.setState({ status: "error", error: message });
    report(t("update.error", { message }));
  } finally {
    installing = false;
  }
}

/** "Skip this version": the startup check stays quiet until a newer release appears. */
export function skipVersion(): void {
  const version = useUpdate.getState().version;
  if (version) useStore.getState().updateSettings({ skippedVersion: version });
  dismiss();
}

/**
 * Closes the dialog. A check or download in progress continues (its outcome is
 * reported in the status bar); finished checks are forgotten. The dialog stays
 * while the installer takes over.
 */
export function dismiss(): void {
  const status = useUpdate.getState().status;
  if (status === "installing") return;
  useStore.getState().setDialog(null);
  if (status === "latest" || status === "error" || status === "available") useUpdate.setState({ status: "idle" });
}

/** Test hook: forget the pending update. */
export function resetUpdater(): void {
  pending = null;
  inflight = null;
  installing = false;
  useUpdate.setState(IDLE);
}
