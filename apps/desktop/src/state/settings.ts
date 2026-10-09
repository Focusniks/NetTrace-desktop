// Persisted per-user UI settings (localStorage, best effort).

import { DEFAULT_RULES, type ColorRule } from "../lib/coloring";
import type { LiveOptions } from "../api/types";
import type { TimeFormat } from "../lib/format";

export type ColumnId =
  | "number"
  | "time"
  | "source"
  | "destination"
  | "protocol"
  | "length"
  | "info"
  | "srcPort"
  | "dstPort"
  | "tcpFlags"
  | "stream"
  | "cast";

export interface ColumnConfig {
  id: ColumnId;
  width: number;
  visible: boolean;
}

export const DEFAULT_COLUMNS: ColumnConfig[] = [
  { id: "number", width: 72, visible: true },
  { id: "time", width: 108, visible: true },
  { id: "source", width: 168, visible: true },
  { id: "destination", width: 168, visible: true },
  { id: "protocol", width: 76, visible: true },
  { id: "length", width: 64, visible: true },
  { id: "srcPort", width: 72, visible: false },
  { id: "dstPort", width: 72, visible: false },
  { id: "tcpFlags", width: 110, visible: false },
  { id: "stream", width: 64, visible: false },
  { id: "cast", width: 84, visible: false },
  { id: "info", width: 640, visible: true },
];

export interface Settings {
  columns: ColumnConfig[];
  timeFormat: TimeFormat;
  colorize: boolean;
  coloringRules: ColorRule[];
  recentFiles: string[];
  filterHistory: string[];
  dockWidth: number;
  listFraction: number;
  detailFraction: number;
  /** Keep the newest packet in view during a live capture. */
  autoScroll: boolean;
  /** Parameters of the last live capture (for restart and as dialog defaults). */
  lastCapture: LiveOptions | null;
}

const KEY = "nettrace.settings.v1";

export const DEFAULT_SETTINGS: Settings = {
  columns: DEFAULT_COLUMNS,
  timeFormat: "relative",
  colorize: true,
  coloringRules: DEFAULT_RULES,
  recentFiles: [],
  filterHistory: [],
  dockWidth: 640,
  listFraction: 0.5,
  detailFraction: 0.58,
  autoScroll: true,
  lastCapture: null,
};

function sanitizeColumns(cols: unknown): ColumnConfig[] {
  if (!Array.isArray(cols)) return DEFAULT_COLUMNS;
  const known = new Map(DEFAULT_COLUMNS.map((c) => [c.id, c]));
  const out: ColumnConfig[] = [];
  for (const c of cols) {
    if (c && typeof c === "object" && known.has(c.id)) {
      out.push({ id: c.id, width: Math.max(32, Math.min(2000, Number(c.width) || 80)), visible: Boolean(c.visible) });
      known.delete(c.id);
    }
  }
  return [...out, ...known.values()];
}

export function loadSettings(): Settings {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return DEFAULT_SETTINGS;
    const s = JSON.parse(raw) as Partial<Settings>;
    return {
      ...DEFAULT_SETTINGS,
      ...s,
      columns: sanitizeColumns(s.columns),
      coloringRules: Array.isArray(s.coloringRules) ? s.coloringRules : DEFAULT_RULES,
      recentFiles: Array.isArray(s.recentFiles) ? s.recentFiles.slice(0, 10) : [],
      filterHistory: Array.isArray(s.filterHistory) ? s.filterHistory.slice(0, 30) : [],
    };
  } catch {
    return DEFAULT_SETTINGS;
  }
}

export function saveSettings(s: Settings): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(s));
  } catch {
    /* storage unavailable: settings stay in memory */
  }
}
