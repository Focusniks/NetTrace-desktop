import { useEffect, useState } from "react";

import { api, inTauri, onFileDrop, onProgress } from "./api/client";
import { ContextMenuHost } from "./components/common/ContextMenu";
import { ErrorBoundary } from "./components/common/ErrorBoundary";
import { Dialogs } from "./components/dialogs/Dialogs";
import { FilterBar } from "./components/filter/FilterBar";
import { SearchBar } from "./components/filter/SearchBar";
import { Analyzer } from "./components/layout/Analyzer";
import { Dock } from "./components/layout/Dock";
import { EmptyState } from "./components/layout/EmptyState";
import { MenuBar } from "./components/layout/MenuBar";
import { StatusBar } from "./components/layout/StatusBar";
import { Toolbar } from "./components/layout/Toolbar";
import { t } from "./i18n";
import { commands } from "./state/commands";
import { syncColoringRules, useStore } from "./state/store";
import { checkForUpdates } from "./state/updater";

function useGlobalShortcuts() {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const typing = target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.tagName === "SELECT");
      const ctrl = e.ctrlKey || e.metaKey;
      const key = e.key.toLowerCase();
      if (ctrl && key === "o") {
        e.preventDefault();
        void commands.open();
      } else if (ctrl && key === "s") {
        e.preventDefault();
        void commands.exportView();
      } else if (ctrl && key === "w") {
        e.preventDefault();
        void commands.close();
      } else if (ctrl && key === "f") {
        e.preventDefault();
        commands.find();
      } else if (ctrl && key === "g") {
        e.preventDefault();
        commands.goto();
      } else if (ctrl && key === "e") {
        e.preventDefault();
        void commands.startOrStop();
      } else if (ctrl && key === "k") {
        e.preventDefault();
        commands.captureDialog();
      } else if (ctrl && key === "r") {
        e.preventDefault();
        void commands.restartCapture();
      } else if (ctrl && key === "t") {
        e.preventDefault();
        commands.dock("timeline");
      } else if (ctrl && (key === "/" || key === "k")) {
        e.preventDefault();
        commands.focusFilter();
      } else if (e.altKey && e.key === "ArrowLeft") {
        e.preventDefault();
        commands.back();
      } else if (e.altKey && e.key === "ArrowRight") {
        e.preventDefault();
        commands.forward();
      } else if (e.key === "F1") {
        e.preventDefault();
        useStore.getState().setDialog("shortcuts");
      } else if (!typing && ctrl && e.key === "Home") {
        commands.first();
      } else if (!typing && ctrl && e.key === "End") {
        commands.last();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
}

let startupDone = false;

export function App() {
  const capture = useStore((s) => s.capture);
  const dockOpen = useStore((s) => s.dockOpen);
  const dockTab = useStore((s) => s.dockTab);
  const searchOpen = useStore((s) => s.searchOpen);
  const [dragging, setDragging] = useState(false);
  useGlobalShortcuts();

  useEffect(() => {
    // Listeners resolve asynchronously; if the effect is torn down first
    // (StrictMode double mount), unsubscribe as soon as they arrive.
    let disposed = false;
    const unsubs: (() => void)[] = [];
    const keep = (u: () => void) => (disposed ? u() : unsubs.push(u));
    void onProgress((p) => useStore.getState().onProgress(p)).then(keep);
    void onFileDrop((paths) => {
      setDragging(false);
      if (paths[0]) void commands.openPath(paths[0]);
    }).then(keep);
    return () => {
      disposed = true;
      unsubs.forEach((u) => u());
    };
  }, []);

  useEffect(() => {
    // One-time startup work (must not run twice under StrictMode).
    if (startupDone) return;
    startupDone = true;
    const fail = (e: unknown) => useStore.getState().flash(t("common.error", { message: (e as Error).message ?? String(e) }));
    void api.fields().then((fields) => useStore.setState({ fields })).catch(fail);
    void syncColoringRules();
    // Dev bridge only: `?open=<path>` opens a capture without a native dialog.
    const devOpen = !inTauri && import.meta.env.DEV ? new URLSearchParams(window.location.search).get("open") : null;
    if (devOpen) void commands.openPath(devOpen);
    // Dev bridge only: expose the store for manual testing in the browser console.
    if (!inTauri && import.meta.env.DEV) (window as unknown as { __nettrace: unknown }).__nettrace = { store: useStore };
    // Quiet update check shortly after start, so it never delays opening a file.
    if (inTauri && useStore.getState().settings.autoUpdateCheck) {
      window.setTimeout(() => void checkForUpdates(false), 5000);
    }
    void api
      .initialFile()
      .then((p) => {
        if (p) void commands.openPath(p);
      })
      .catch(fail);
  }, []);

  return (
    <div
      className="app"
      onContextMenu={(e) => {
        // Suppress the webview's native menu; components show their own.
        if (!(e.target as HTMLElement).closest("input, textarea")) e.preventDefault();
      }}
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
      }}
    >
      <MenuBar />
      <Toolbar />
      <FilterBar />
      {searchOpen && capture ? <SearchBar /> : null}
      <div className="workspace" style={{ position: "relative" }}>
        {capture ? (
          <>
            <ErrorBoundary resetKey={capture.captureId}>
              <Analyzer />
            </ErrorBoundary>
            {dockOpen ? (
              <ErrorBoundary resetKey={`${capture.captureId}:${dockTab}`}>
                <Dock />
              </ErrorBoundary>
            ) : null}
          </>
        ) : (
          <EmptyState />
        )}
      </div>
      <StatusBar />
      <ContextMenuHost />
      <Dialogs />
      {dragging ? <div className="drop-overlay">{t("empty.hint")}</div> : null}
    </div>
  );
}
