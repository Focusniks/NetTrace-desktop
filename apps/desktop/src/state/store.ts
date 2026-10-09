import { create } from "zustand";

import { api, BackendError, setWindowTitle } from "../api/client";
import type {
  LiveOptions,
  CaptureInfo,
  CaptureSummary,
  FieldInfo,
  FilterError,
  IndexProgress,
  PacketDetail,
  SortSpec,
  StreamRef,
} from "../api/types";
import { t, type MessageKey } from "../i18n";
import type { ColorRule } from "../lib/coloring";
import type { TimeFormat } from "../lib/format";
import { loadSettings, saveSettings, type ColumnConfig, type Settings } from "./settings";

export type DockTab = "streams" | "sequence" | "hosts" | "conversations" | "statistics" | "timeline" | "indicators";
export type DialogId = "goto" | "coloring" | "properties" | "about" | "shortcuts" | "fields" | "capture" | "unsaved" | "update" | null;

export interface Highlight {
  start: number;
  len: number;
}

interface State {
  // capture
  capture: CaptureInfo | null;
  progress: IndexProgress | null;
  summary: CaptureSummary | null;
  openError: string | null;
  // view
  viewId: number;
  viewTotal: number;
  /** Bumped whenever cached rows must be refetched. */
  viewVersion: number;
  filterText: string;
  appliedFilter: string;
  filterError: FilterError | null;
  filterBusy: boolean;
  filterElapsed: number | null;
  sort: SortSpec | null;
  // selection
  selectedNumber: number | null;
  selectedRow: number | null;
  /** Row to scroll into view (one-shot request for the packet list). */
  scrollRequest: { row: number; seq: number } | null;
  /** Bumped when the packet list should jump back to the top (new view/file). */
  scrollReset: number;
  history: number[];
  historyPos: number;
  detail: PacketDetail | null;
  detailLoading: boolean;
  highlight: Highlight | null;
  selectedFieldKey: string | null;
  // layout & tools
  dockOpen: boolean;
  dockTab: DockTab;
  dockMaximized: boolean;
  searchOpen: boolean;
  builderOpen: boolean;
  dialog: DialogId;
  focusStream: StreamRef | null;
  status: { text: string; seq: number } | null;
  fields: FieldInfo[];
  settings: Settings;
  /** A finished live capture whose packets were saved (or that the user chose to discard). */
  liveSaved: boolean;
  /** Action waiting for the "save captured packets?" answer. */
  pendingAction: (() => Promise<void>) | null;

  // actions
  openFile: (path: string) => Promise<void>;
  closeFile: () => Promise<void>;
  onProgress: (p: IndexProgress) => void;
  setFilterText: (text: string) => void;
  applyFilter: (text?: string, opts?: { refresh?: boolean }) => Promise<boolean>;
  startCapture: (options: LiveOptions) => Promise<void>;
  stopCapture: () => Promise<void>;
  /** Runs `action` now, or after asking to save an unsaved live capture. */
  guardUnsaved: (action: () => Promise<void>) => Promise<void>;
  setSort: (sort: SortSpec | null) => Promise<void>;
  selectPacket: (number: number, opts?: { history?: boolean; scroll?: boolean; row?: number }) => Promise<void>;
  selectRow: (row: number, number: number) => void;
  moveSelection: (delta: number | "first" | "last") => Promise<void>;
  back: () => void;
  forward: () => void;
  setHighlight: (h: Highlight | null, key?: string | null) => void;
  openDock: (tab: DockTab) => void;
  setDock: (patch: Partial<Pick<State, "dockOpen" | "dockMaximized" | "dockTab">>) => void;
  focusOnStream: (s: StreamRef, tab?: DockTab) => void;
  setDialog: (d: DialogId) => void;
  setSearchOpen: (open: boolean) => void;
  setBuilderOpen: (open: boolean) => void;
  flash: (text: string) => void;
  updateSettings: (patch: Partial<Settings>) => void;
  setColumns: (cols: ColumnConfig[]) => void;
  setColoringRules: (rules: ColorRule[]) => Promise<(FilterError | null)[]>;
  setTimeFormat: (f: TimeFormat) => void;
}

/** How often a filtered view is recomputed during a live capture. */
const LIVE_REFRESH_MS = 1000;
let lastLiveRefresh = 0;

/** Placeholder filter for disabled coloring rules (keeps rule indices stable). */
const NEVER = "frame.number == 0";

let statusSeq = 0;
let scrollSeq = 0;
let detailSeq = 0;
/** Tokens that let a newer filter/selection request win over a slower older one. */
let applySeq = 0;
let selectSeq = 0;

function errorText(e: unknown): string {
  if (!(e instanceof BackendError)) return String(e);
  // Known codes get a Russian explanation; the backend detail is kept for the specialist.
  const key = `err.${e.code}` as MessageKey;
  const known = t(key);
  return known === key ? `${e.code}: ${e.message}` : `${known} (${e.message})`;
}

export const useStore = create<State>((set, get) => ({
  capture: null,
  progress: null,
  summary: null,
  openError: null,
  viewId: 0,
  viewTotal: 0,
  viewVersion: 0,
  filterText: "",
  appliedFilter: "",
  filterError: null,
  filterBusy: false,
  filterElapsed: null,
  sort: null,
  selectedNumber: null,
  selectedRow: null,
  scrollRequest: null,
  scrollReset: 0,
  history: [],
  historyPos: -1,
  detail: null,
  detailLoading: false,
  highlight: null,
  selectedFieldKey: null,
  dockOpen: false,
  dockTab: "streams",
  dockMaximized: false,
  searchOpen: false,
  builderOpen: false,
  dialog: null,
  focusStream: null,
  status: null,
  fields: [],
  settings: loadSettings(),
  liveSaved: false,
  pendingAction: null,

  async openFile(path) {
    set({ openError: null });
    try {
      const info = await api.openCapture(path);
      const recent = [path, ...get().settings.recentFiles.filter((p) => p !== path)].slice(0, 10);
      get().updateSettings({ recentFiles: recent });
      set({
        capture: info,
        liveSaved: false,
        progress: null,
        summary: null,
        viewId: 0,
        viewTotal: 0,
        viewVersion: get().viewVersion + 1,
        appliedFilter: "",
        filterError: null,
        filterElapsed: null,
        sort: null,
        selectedNumber: null,
        selectedRow: null,
        history: [],
        historyPos: -1,
        detail: null,
        highlight: null,
        focusStream: null,
        scrollRequest: null,
        scrollReset: get().scrollReset + 1,
      });
      // A filter typed before opening is applied once indexing completes (see onProgress).
      void setWindowTitle(`${info.fileName} — ${t("app.title")}`);
    } catch (e) {
      set({ openError: errorText(e) });
      get().flash(t("common.error", { message: errorText(e) }));
    }
  },

  async startCapture(options) {
    set({ openError: null });
    try {
      const info = await api.startCapture(options);
      get().updateSettings({ lastCapture: options });
      set({
        capture: info,
        liveSaved: false,
        progress: null,
        summary: null,
        viewId: 0,
        viewTotal: 0,
        viewVersion: get().viewVersion + 1,
        appliedFilter: "",
        filterError: null,
        filterElapsed: null,
        sort: null,
        selectedNumber: null,
        selectedRow: null,
        history: [],
        historyPos: -1,
        detail: null,
        highlight: null,
        focusStream: null,
        scrollRequest: null,
        scrollReset: get().scrollReset + 1,
        dialog: null,
      });
      void setWindowTitle(`${t("capture.title", { iface: info.fileName })} — ${t("app.title")}`);
      // Keep a typed display filter: it is applied to live data right away.
      if (get().filterText.trim()) void get().applyFilter(get().filterText);
    } catch (e) {
      set({ openError: errorText(e) });
      get().flash(t("common.error", { message: errorText(e) }));
      throw e;
    }
  },

  async stopCapture() {
    try {
      await api.stopCapture();
    } catch (e) {
      get().flash(t("common.error", { message: errorText(e) }));
    }
  },

  async guardUnsaved(action) {
    const s = get();
    const unsaved = s.capture?.live && !s.liveSaved && (s.progress?.packets ?? 0) > 0;
    if (!unsaved) {
      await action();
      return;
    }
    set({ pendingAction: action, dialog: "unsaved" });
  },

  async closeFile() {
    try {
      await api.closeCapture();
    } catch (e) {
      get().flash(t("common.error", { message: errorText(e) }));
    }
    set({
      capture: null,
      progress: null,
      summary: null,
      viewId: 0,
      viewTotal: 0,
      viewVersion: get().viewVersion + 1,
      selectedNumber: null,
      selectedRow: null,
      detail: null,
      highlight: null,
      focusStream: null,
      appliedFilter: "",
      scrollRequest: null,
    });
    void setWindowTitle(t("app.title"));
  },

  onProgress(p) {
    const s = get();
    // Ignore late events from a previously opened capture.
    if (!s.capture || p.captureId !== s.capture.captureId) return;
    const wasIndexing = s.progress?.state === "indexing" || s.progress == null;
    set({ progress: p });
    if (s.viewId === 0 && !s.sort) {
      set({ viewTotal: p.packets });
    } else if (s.capture.live && p.state === "indexing" && !s.filterBusy && Date.now() - lastLiveRefresh > LIVE_REFRESH_MS) {
      // Filtered/sorted views are snapshots: refresh them while packets keep arriving.
      lastLiveRefresh = Date.now();
      void get().applyFilter(s.appliedFilter, { refresh: true });
    }
    if (p.state !== "indexing" && wasIndexing) {
      void api
        .summary()
        .then((summary) => set({ summary }))
        .catch((e) => get().flash(t("common.error", { message: errorText(e) })));
      // Re-run the active filter/sort over the complete capture.
      if (s.appliedFilter || s.sort || s.filterText.trim()) void get().applyFilter(s.filterText);
      else set({ viewVersion: get().viewVersion + 1 });
      if (p.warning) get().flash(t(`status.warning.${p.warning}` as never));
      if (p.error) get().flash(t("status.failed", { error: p.error }));
    }
  },

  setFilterText(text) {
    set({ filterText: text });
  },

  async applyFilter(text, opts) {
    const refresh = opts?.refresh === true;
    const filter = (text ?? get().filterText).trim();
    if (!get().capture) {
      set({ filterText: filter });
      return false;
    }
    const my = ++applySeq;
    set(refresh ? { filterBusy: true } : { filterBusy: true, filterText: filter });
    try {
      const v = await api.applyView(filter || null, get().sort);
      if (my !== applySeq) return false;
      if (!refresh && filter) {
        get().updateSettings({ filterHistory: [filter, ...get().settings.filterHistory.filter((f) => f !== filter)].slice(0, 30) });
      }
      set({
        viewId: v.viewId,
        viewTotal: v.total,
        viewVersion: get().viewVersion + 1,
        appliedFilter: filter,
        filterError: null,
        filterElapsed: filter ? v.elapsedMs : null,
        filterBusy: false,
        // A live refresh keeps the user's scroll position.
        ...(refresh ? {} : { scrollRequest: null, scrollReset: get().scrollReset + 1 }),
      });
      if (refresh) return true;
      // Keep the selected packet visible if it survived the filter.
      const sel = get().selectedNumber;
      if (sel != null) {
        const row = await api.findRow(v.viewId, sel);
        if (my !== applySeq) return true;
        set({ selectedRow: row });
        if (row != null) set({ scrollRequest: { row, seq: ++scrollSeq } });
      }
      return true;
    } catch (e) {
      if (my !== applySeq) return false;
      set({ filterBusy: false });
      if (e instanceof BackendError && e.filter) {
        set({ filterError: e.filter });
      } else if (!(e instanceof BackendError && e.code === "cancelled")) {
        get().flash(t("common.error", { message: errorText(e) }));
      }
      return false;
    }
  },

  async setSort(sort) {
    set({ sort });
    await get().applyFilter(get().appliedFilter);
  },

  async selectPacket(number, opts) {
    const s = get();
    if (!s.capture) return;
    const my = ++selectSeq;
    const fail = (e: unknown) => {
      if (my === selectSeq) get().flash(t("common.error", { message: errorText(e) }));
    };
    let row: number | null;
    try {
      row = opts?.row ?? (await api.findRow(s.viewId, number));
    } catch (e) {
      fail(e);
      return;
    }
    if (my !== selectSeq) return;
    if (row == null) {
      if (number < 1 || number > (s.progress?.packets ?? s.viewTotal)) {
        get().flash(t("dialog.goto.notFound", { n: number }));
        return;
      }
      // Hidden by the filter: show all packets so the target can be selected.
      get().flash(t("status.hiddenByFilter", { n: number }));
      set({ filterText: "" });
      await get().applyFilter("");
      if (my !== selectSeq) return;
      try {
        row = await api.findRow(get().viewId, number);
      } catch (e) {
        fail(e);
        return;
      }
      if (my !== selectSeq) return;
    }
    if (opts?.history !== false) {
      const { history, historyPos } = get();
      const trimmed = history.slice(0, historyPos + 1);
      if (trimmed[trimmed.length - 1] !== number) trimmed.push(number);
      set({ history: trimmed.slice(-200), historyPos: Math.min(trimmed.length, 200) - 1 });
    }
    set({ selectedNumber: number, selectedRow: row });
    if (row != null && opts?.scroll !== false) set({ scrollRequest: { row, seq: ++scrollSeq } });
    const seq = ++detailSeq;
    set({ detailLoading: true });
    try {
      const detail = await api.packetDetail(number);
      if (seq === detailSeq) set({ detail, detailLoading: false, highlight: null, selectedFieldKey: null });
    } catch (e) {
      if (seq === detailSeq) {
        set({ detail: null, detailLoading: false });
        get().flash(t("common.error", { message: errorText(e) }));
      }
    }
  },

  selectRow(row, number) {
    if (get().selectedNumber === number) {
      set({ selectedRow: row });
      return;
    }
    set({ selectedRow: row });
    void get().selectPacket(number, { scroll: false });
  },

  async moveSelection(delta) {
    const s = get();
    if (!s.capture || s.viewTotal === 0) return;
    let row: number;
    if (delta === "first") row = 0;
    else if (delta === "last") row = s.viewTotal - 1;
    else row = Math.min(s.viewTotal - 1, Math.max(0, (s.selectedRow ?? -1) + delta));
    // Update the row immediately so key repeat moves from here, not from a stale row.
    set({ selectedRow: row, scrollRequest: { row, seq: ++scrollSeq } });
    let rows;
    try {
      rows = await api.rows(s.viewId, row, 1);
    } catch (e) {
      get().flash(t("common.error", { message: errorText(e) }));
      return;
    }
    if (rows[0] && get().selectedRow === row && get().viewId === s.viewId) {
      await get().selectPacket(rows[0].number, { scroll: false, row });
    }
  },

  back() {
    const { history, historyPos } = get();
    if (historyPos > 0) {
      set({ historyPos: historyPos - 1 });
      void get().selectPacket(history[historyPos - 1], { history: false });
    }
  },

  forward() {
    const { history, historyPos } = get();
    if (historyPos < history.length - 1) {
      set({ historyPos: historyPos + 1 });
      void get().selectPacket(history[historyPos + 1], { history: false });
    }
  },

  setHighlight(h, key = null) {
    set({ highlight: h, selectedFieldKey: key });
  },

  openDock(tab) {
    set({ dockOpen: true, dockTab: tab });
  },

  setDock(patch) {
    set(patch);
  },

  focusOnStream(s, tab = "streams") {
    set({ focusStream: s, dockOpen: true, dockTab: tab });
  },

  setDialog(d) {
    set({ dialog: d });
  },

  setSearchOpen(open) {
    set({ searchOpen: open });
  },

  setBuilderOpen(open) {
    set({ builderOpen: open });
  },

  flash(text) {
    set({ status: { text, seq: ++statusSeq } });
  },

  updateSettings(patch) {
    const settings = { ...get().settings, ...patch };
    set({ settings });
    saveSettings(settings);
  },

  setColumns(cols) {
    get().updateSettings({ columns: cols });
  },

  async setColoringRules(rules) {
    get().updateSettings({ coloringRules: rules });
    const errors = await api.setColoringRules(rules.map((r) => (r.enabled ? r.filter : NEVER)));
    set({ viewVersion: get().viewVersion + 1 });
    return errors.map((e, i) => (rules[i].enabled ? e : null));
  },

  setTimeFormat(f) {
    get().updateSettings({ timeFormat: f });
  },
}));

/** Pushes coloring rules to the backend; disabled rules compile to a filter that never matches. */
export async function syncColoringRules(): Promise<void> {
  const rules = useStore.getState().settings.coloringRules;
  try {
    const errors = await api.setColoringRules(rules.map((r) => (r.enabled ? r.filter : NEVER)));
    const bad = errors.findIndex((e, i) => e && rules[i].enabled);
    if (bad >= 0) useStore.getState().flash(t("status.badColorRule", { name: rules[bad].name }));
  } catch (e) {
    useStore.getState().flash(t("common.error", { message: errorText(e) }));
  }
}
