// Backend client. Inside Tauri it uses IPC; in a plain browser during
// development (`npm run dev` + `cargo run -p nettrace-devbridge`) it talks to
// the same engine through a localhost bridge proxied by Vite. There is no
// mock backend.

import { t } from "../i18n";
import type {
  CaptureInfo,
  CaptureInterface,
  LiveOptions,
  CaptureSummary,
  ConversationPage,
  ConversationQuery,
  EngineError,
  FieldInfo,
  FilterError,
  FlowPage,
  FlowQuery,
  FlowSummary,
  HostPage,
  HostQuery,
  IndexProgress,
  Indicator,
  IoGraph,
  PacketDetail,
  PacketLengths,
  PacketRow,
  ProtocolNode,
  SearchHit,
  SearchQuery,
  SequencePage,
  SortSpec,
  StreamRef,
  Timeline,
  ViewInfo,
} from "./types";

export const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export class BackendError extends Error {
  readonly code: string;
  readonly filter?: FilterError;
  constructor(e: EngineError) {
    super(e.message);
    this.code = e.code;
    this.filter = e.filter;
  }
}

function toError(e: unknown): BackendError {
  if (e instanceof BackendError) return e;
  if (e && typeof e === "object" && "code" in e && "message" in e) return new BackendError(e as EngineError);
  return new BackendError({ code: "internal", message: String(e) });
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    if (inTauri) {
      const { invoke } = await import("@tauri-apps/api/core");
      return await invoke<T>(cmd, args);
    }
    if (import.meta.env.DEV) {
      const res = await fetch(`/__bridge/invoke/${cmd}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(args ?? {}),
      });
      const body = (await res.json()) as { ok?: T; err?: EngineError };
      if (body.err) throw new BackendError(body.err);
      return body.ok as T;
    }
    throw new BackendError({ code: "no_backend", message: "backend is not available" });
  } catch (e) {
    throw toError(e);
  }
}

export const api = {
  openCapture: (path: string) => call<CaptureInfo>("open_capture", { path }),
  closeCapture: () => call<void>("close_capture"),
  captureLibrary: () => call<string>("capture_library"),
  captureInterfaces: () => call<CaptureInterface[]>("capture_interfaces"),
  startCapture: (options: LiveOptions) => call<CaptureInfo>("start_capture", { options }),
  stopCapture: () => call<void>("stop_capture"),
  initialFile: () => call<string | null>("initial_file"),
  summary: () => call<CaptureSummary>("capture_summary"),
  progress: () => call<IndexProgress>("index_progress"),
  applyView: (filter: string | null, sort: SortSpec | null) => call<ViewInfo>("apply_view", { filter, sort }),
  rows: (viewId: number, offset: number, limit: number) => call<PacketRow[]>("get_rows", { viewId, offset, limit }),
  findRow: (viewId: number, number: number) => call<number | null>("find_row", { viewId, number }),
  packetDetail: (number: number) => call<PacketDetail>("packet_detail", { number }),
  validateFilter: (text: string) => call<FilterError | null>("validate_filter", { text }),
  fields: () => call<FieldInfo[]>("list_fields"),
  setColoringRules: (rules: string[]) => call<(FilterError | null)[]>("set_coloring_rules", { rules }),
  flows: (query: FlowQuery) => call<FlowPage>("list_flows", { query }),
  flow: (stream: StreamRef) => call<FlowSummary>("get_flow", { stream }),
  sequence: (stream: StreamRef, offset: number, limit: number) =>
    call<SequencePage>("get_sequence", { stream, offset, limit }),
  hostsPage: (query: HostQuery) => call<HostPage>("get_hosts_page", { query }),
  conversationsPage: (query: ConversationQuery) => call<ConversationPage>("get_conversations_page", { query }),
  protocolHierarchy: () => call<ProtocolNode[]>("get_protocol_hierarchy"),
  ioGraph: (interval: number, filter: string | null) => call<IoGraph>("get_io_graph", { request: { interval, filter } }),
  packetLengths: (filter: string | null) => call<PacketLengths>("get_packet_lengths", { filter }),
  timeline: (start: number | null, end: number | null, buckets: number, maxEvents = 2000) =>
    call<Timeline>("get_timeline", { request: { start, end, buckets, maxEvents } }),
  indicators: () => call<Indicator[]>("get_indicators"),
  search: (viewId: number, fromRow: number | null, backwards: boolean, query: SearchQuery) =>
    call<SearchHit | null>("search", { request: { viewId, fromRow, backwards, query } }),
  /** Backend shows the save dialog itself; resolves to null when cancelled. */
  exportView: (viewId: number, defaultName: string, title: string) =>
    call<number | null>("export_view", { viewId, defaultName, title }),
};

/** Subscribes to indexing progress (IPC events in Tauri, polling via the dev bridge). */
export async function onProgress(cb: (p: IndexProgress) => void): Promise<() => void> {
  if (inTauri) {
    const { listen } = await import("@tauri-apps/api/event");
    return listen<IndexProgress>("index-progress", (e) => cb(e.payload));
  }
  let stopped = false;
  const tick = async () => {
    if (stopped) return;
    try {
      cb(await api.progress());
    } catch {
      /* no capture yet */
    }
    setTimeout(tick, 250);
  };
  void tick();
  return () => {
    stopped = true;
  };
}

/** Native file dialogs (Tauri); a path prompt when running through the dev bridge. */
export async function pickCaptureFile(title: string): Promise<string | null> {
  if (inTauri) {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const r = await open({
      title,
      multiple: false,
      directory: false,
      filters: [
        { name: t("file.captures"), extensions: ["pcap", "pcapng", "cap"] },
        { name: t("file.all"), extensions: ["*"] },
      ],
    });
    return typeof r === "string" ? r : null;
  }
  return window.prompt(title);
}

export async function setWindowTitle(title: string): Promise<void> {
  document.title = title;
  if (inTauri) {
    const { getCurrentWindow } = await import("@tauri-apps/api/window");
    await getCurrentWindow().setTitle(title);
  }
}

/** Calls `cb` with paths of files dropped onto the window. */
export async function onFileDrop(cb: (paths: string[]) => void): Promise<() => void> {
  if (!inTauri) return () => {};
  const { getCurrentWebview } = await import("@tauri-apps/api/webview");
  return getCurrentWebview().onDragDropEvent((e) => {
    if (e.payload.type === "drop") cb(e.payload.paths);
  });
}
