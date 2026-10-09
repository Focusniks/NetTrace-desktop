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
  /** Look for a new release on startup. */
  autoUpdateCheck: boolean;
  /** Release the user chose to skip ("Пропустить эту версию"). */
  skippedVersion: string | null;
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
  autoUpdateCheck: true,
  skippedVersion: null,
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

const TIME_FORMATS: TimeFormat[] = ["relative", "delta", "local", "utc"];

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null;
const strings = (v: unknown, max: number): string[] => (Array.isArray(v) ? v.filter((x) => typeof x === "string").slice(0, max) : []);
const number = (v: unknown, min: number, max: number, fallback: number): number =>
  typeof v === "number" && Number.isFinite(v) ? Math.min(max, Math.max(min, v)) : fallback;
const color = (v: unknown, fallback: string): string => (typeof v === "string" && /^#[0-9a-f]{6}$/i.test(v) ? v : fallback);

function sanitizeRules(v: unknown): ColorRule[] {
  if (!Array.isArray(v)) return DEFAULT_RULES;
  const rules = v
    .filter((r): r is Record<string, unknown> => isObj(r) && typeof r.filter === "string")
    .map((r) => ({
      name: typeof r.name === "string" ? r.name : "",
      filter: r.filter as string,
      bg: color(r.bg, "#2a3140"),
      fg: color(r.fg, "#d5dae2"),
      enabled: r.enabled !== false,
    }));
  // An empty list is a choice; a list with nothing usable is damage.
  return rules.length === 0 && v.length > 0 ? DEFAULT_RULES : rules;
}

function sanitizeCapture(v: unknown): LiveOptions | null {
  if (!isObj(v) || typeof v.interface !== "string") return null;
  return {
    interface: v.interface,
    captureFilter: typeof v.captureFilter === "string" ? v.captureFilter : null,
    snaplen: number(v.snaplen, 64, 262144, 262144),
    promiscuous: v.promiscuous !== false,
  };
}

/** Settings from stored JSON: unknown, missing or ill-typed values fall back to defaults. */
export function sanitizeSettings(raw: unknown): Settings {
  if (!isObj(raw)) return DEFAULT_SETTINGS;
  const d = DEFAULT_SETTINGS;
  return {
    columns: sanitizeColumns(raw.columns),
    timeFormat: TIME_FORMATS.includes(raw.timeFormat as TimeFormat) ? (raw.timeFormat as TimeFormat) : d.timeFormat,
    colorize: raw.colorize !== false,
    coloringRules: sanitizeRules(raw.coloringRules),
    recentFiles: strings(raw.recentFiles, 10),
    filterHistory: strings(raw.filterHistory, 30),
    dockWidth: number(raw.dockWidth, 200, 4000, d.dockWidth),
    listFraction: number(raw.listFraction, 0.1, 0.9, d.listFraction),
    detailFraction: number(raw.detailFraction, 0.1, 0.9, d.detailFraction),
    autoScroll: raw.autoScroll !== false,
    lastCapture: sanitizeCapture(raw.lastCapture),
    autoUpdateCheck: raw.autoUpdateCheck !== false,
    skippedVersion: typeof raw.skippedVersion === "string" ? raw.skippedVersion : null,
  };
}

export function loadSettings(): Settings {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? sanitizeSettings(JSON.parse(raw)) : DEFAULT_SETTINGS;
  } catch (e) {
    // Corrupt JSON or no storage: start from defaults. The next save replaces
    // the stored value, so keep a copy for recovery.
    console.warn("settings could not be loaded:", e);
    try {
      const raw = localStorage.getItem(KEY);
      if (raw) localStorage.setItem(`${KEY}.corrupt`, raw);
    } catch {
      /* storage unavailable */
    }
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
