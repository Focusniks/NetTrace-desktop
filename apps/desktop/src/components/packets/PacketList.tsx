import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";

import { TcpAnalysis, type PacketRow } from "../../api/types";
import { t } from "../../i18n";
import type { ColorRule } from "../../lib/coloring";
import { fmtInt, type TimeFormat } from "../../lib/format";
import { computeWindow, scrollTopForRow } from "../../lib/virtual";
import { copy, filterByTerm, openStream } from "../../state/actions";
import { DEFAULT_COLUMNS, type ColumnConfig } from "../../state/settings";
import { useStore } from "../../state/store";
import { showContextMenuAt, type MenuEntry } from "../common/ContextMenu";
import { COLUMN_DEFS, conversationFilter, rowSummary } from "./columns";
import { useRowCache } from "./useRowCache";

const ROW_H = 20;
const PROBLEM_FLAGS =
  TcpAnalysis.RETRANSMISSION | TcpAnalysis.OUT_OF_ORDER | TcpAnalysis.LOST_SEGMENT | TcpAnalysis.ZERO_WINDOW | TcpAnalysis.DUPLICATE_ACK;

function filterMenu(term: string | null, label: string): MenuEntry[] {
  if (!term) return [];
  return [
    { kind: "label", label },
    { label: t("ctx.applyFilter"), onSelect: () => filterByTerm(term, "replace", true) },
    { label: t("ctx.prepareFilter"), onSelect: () => filterByTerm(term, "replace", false) },
    { label: t("ctx.andFilter"), onSelect: () => filterByTerm(term, "and", true) },
    { label: t("ctx.orFilter"), onSelect: () => filterByTerm(term, "or", true) },
    { label: t("ctx.notFilter"), onSelect: () => filterByTerm(term, "not", true) },
  ];
}

function rowMenuItems(row: PacketRow, colId: string, timeFormat: TimeFormat): MenuEntry[] {
  const def = COLUMN_DEFS[colId as keyof typeof COLUMN_DEFS];
  const cellText = def?.text(row, timeFormat) ?? "";
  const items: MenuEntry[] = [
    { label: t("ctx.copyCell"), onSelect: () => void copy(cellText) },
    { label: t("ctx.copyRow"), onSelect: () => void copy(rowSummary(row, timeFormat)) },
    { kind: "separator" },
    ...filterMenu(def?.filter?.(row) ?? null, `${t(def?.title ?? "col.info")}: ${cellText.slice(0, 48)}`),
    { kind: "separator" },
  ];
  const srcF = COLUMN_DEFS.source.filter?.(row);
  const dstF = COLUMN_DEFS.destination.filter?.(row);
  const convF = conversationFilter(row);
  if (srcF) items.push({ label: t("ctx.filterSrc"), onSelect: () => filterByTerm(srcF, "replace", true) });
  if (dstF) items.push({ label: t("ctx.filterDst"), onSelect: () => filterByTerm(dstF, "replace", true) });
  if (convF) items.push({ label: t("ctx.filterConv"), onSelect: () => filterByTerm(convF, "replace", true) });
  if (row.stream) {
    const stream = row.stream;
    items.push(
      { kind: "separator" },
      { label: t("ctx.followStream", { kind: stream.kind.toUpperCase(), id: stream.id }), onSelect: () => openStream(stream) },
      { label: t("ctx.sequence"), onSelect: () => openStream(stream, "sequence") },
    );
  }
  return items;
}

interface RowProps {
  row: PacketRow;
  index: number;
  cols: ColumnConfig[];
  width: number;
  rule: ColorRule | undefined;
  selected: boolean;
  timeFormat: TimeFormat;
  onMenu: (x: number, y: number, row: PacketRow, colId: string) => void;
}

/** One packet row; memoized so scrolling and selection re-render only changed rows. */
const PacketRowView = memo(function PacketRowView({ row, index, cols, width, rule, selected, timeFormat, onMenu }: RowProps) {
  const style: React.CSSProperties = { width };
  if (rule) {
    style.background = rule.bg;
    style.color = rule.fg;
  }
  return (
    <div
      className={`plist-row${selected ? " is-selected" : ""}`}
      style={style}
      role="row"
      aria-selected={selected}
      onMouseDown={(e) => {
        if (e.button === 0) useStore.getState().selectRow(index, row.number);
      }}
      onDoubleClick={() => {
        const s = useStore.getState();
        if (row.stream) openStream(row.stream);
        else s.openDock(s.dockTab);
      }}
    >
      {cols.map((c) => {
        const def = COLUMN_DEFS[c.id];
        let content: React.ReactNode = def.text(row, timeFormat);
        if (c.id === "info") {
          if (row.readError) {
            content = <span style={{ color: "var(--error)" }}>[{t("status.readError")}]</span>;
          } else if (row.analysis & PROBLEM_FLAGS || row.malformed) {
            content = (
              <>
                <span className={`analysis-mark${row.malformed ? " is-error" : ""}`} />
                {content}
              </>
            );
          }
        }
        return (
          <div
            key={c.id}
            role="gridcell"
            className={`plist-cell${def.align ? " num" : ""}${def.mono ? " mono" : ""}`}
            style={{ width: c.width }}
            onContextMenu={(e) => {
              e.preventDefault();
              e.stopPropagation();
              onMenu(e.clientX, e.clientY, row, c.id);
            }}
          >
            {content}
          </div>
        );
      })}
    </div>
  );
});

/** Indexing progress overlay; subscribes on its own so progress ticks do not re-render the list. */
function IndexingOverlay() {
  const progress = useStore((s) => (s.progress?.state === "indexing" && !s.capture?.live ? s.progress : null));
  if (!progress) return null;
  const pct = progress.totalBytes > 0 ? Math.min(100, (progress.bytesRead * 100) / progress.totalBytes) : 0;
  return (
    <div className="plist-indexing" role="status">
      <div className="row">
        <span className="muted">{t("indexing.title")}</span>
        <span className="grow" />
        <span className="pct">{pct.toFixed(0)}%</span>
      </div>
      <div className="progress">
        <div style={{ width: `${pct}%` }} />
      </div>
      <div className="muted">
        {t("indexing.found", { packets: fmtInt(progress.packets), flows: fmtInt(progress.tcpStreams + progress.udpStreams) })}
      </div>
    </div>
  );
}

export function PacketList() {
  const captureId = useStore((s) => s.capture?.captureId ?? 0);
  const viewId = useStore((s) => s.viewId);
  const viewVersion = useStore((s) => s.viewVersion);
  const total = useStore((s) => s.viewTotal);
  const selectedNumber = useStore((s) => s.selectedNumber);
  const scrollRequest = useStore((s) => s.scrollRequest);
  const scrollReset = useStore((s) => s.scrollReset);
  const indexing = useStore((s) => s.progress?.state === "indexing");
  const sort = useStore((s) => s.sort);
  const appliedFilter = useStore((s) => s.appliedFilter);
  const columns = useStore((s) => s.settings.columns);
  const timeFormat = useStore((s) => s.settings.timeFormat);
  const colorize = useStore((s) => s.settings.colorize);
  const coloringRules = useStore((s) => s.settings.coloringRules);

  const bodyRef = useRef<HTMLDivElement>(null);
  const headerRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewport, setViewport] = useState(400);
  const { get, ensure, error, retry } = useRowCache(captureId, viewId, viewVersion, total);
  const totalRef = useRef(total);
  totalRef.current = total;

  const visibleCols = useMemo(() => columns.filter((c) => c.visible), [columns]);
  const totalWidth = visibleCols.reduce((s, c) => s + c.width, 0);

  useEffect(() => {
    const el = bodyRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setViewport(el.clientHeight));
    ro.observe(el);
    setViewport(el.clientHeight);
    return () => ro.disconnect();
  }, []);

  // New file or new filter/sort: back to the top.
  useEffect(() => {
    if (bodyRef.current) bodyRef.current.scrollTop = 0;
    setScrollTop(0);
  }, [scrollReset]);

  // Explicit requests only (selection, search); indexing progress never pulls the list back.
  useEffect(() => {
    const el = bodyRef.current;
    if (!scrollRequest || !el) return;
    el.scrollTop = scrollTopForRow(scrollRequest.row, totalRef.current, ROW_H, el.clientHeight, el.scrollTop, true);
    setScrollTop(el.scrollTop);
  }, [scrollRequest]);

  // Live capture: follow new packets while the user stays at the bottom (auto-scroll).
  const autoScroll = useStore((s) => s.settings.autoScroll && !!s.capture?.live && s.progress?.capture?.running === true);
  const atBottom = useRef(true);
  useEffect(() => {
    const el = bodyRef.current;
    if (!el || !autoScroll || !atBottom.current) return;
    el.scrollTop = el.scrollHeight;
    setScrollTop(el.scrollTop);
  }, [total, autoScroll]);

  const win = computeWindow(total, ROW_H, viewport, scrollTop);
  useEffect(() => {
    ensure(win.first, win.count);
  });

  const onMenu = useCallback(
    (x: number, y: number, row: PacketRow, colId: string) => {
      void useStore.getState().selectPacket(row.number, { scroll: false });
      showContextMenuAt(x, y, rowMenuItems(row, colId, timeFormat));
    },
    [timeFormat],
  );

  const visibleRows = Math.max(1, Math.floor(viewport / ROW_H) - 1);
  const onKeyDown = (e: React.KeyboardEvent) => {
    const s = useStore.getState();
    const map: Record<string, number | "first" | "last"> = {
      ArrowDown: 1,
      ArrowUp: -1,
      PageDown: visibleRows,
      PageUp: -visibleRows,
      Home: "first",
      End: "last",
    };
    const d = map[e.key];
    if (d !== undefined) {
      e.preventDefault();
      void s.moveSelection(d);
      return;
    }
    if (e.key === "Enter") {
      if (s.detail?.stream) openStream(s.detail.stream);
      else s.openDock(s.dockTab);
      return;
    }
    // Keyboard access to the row context menu (Shift+F10 / Menu key).
    if (e.key === "ContextMenu" || (e.shiftKey && e.key === "F10")) {
      e.preventDefault();
      const row = s.selectedRow != null ? get(s.selectedRow) : undefined;
      const el = bodyRef.current?.querySelector<HTMLElement>(".plist-row.is-selected");
      if (row) {
        const r = el?.getBoundingClientRect() ?? bodyRef.current?.getBoundingClientRect();
        showContextMenuAt((r?.left ?? 0) + 40, (r?.bottom ?? 0) - 2, rowMenuItems(row, "info", timeFormat));
      }
    }
  };

  // ----- column resizing -----
  const resize = useRef<{ id: string; startX: number; startW: number } | null>(null);
  const [liveCols, setLiveCols] = useState<ColumnConfig[] | null>(null);
  const cols = useMemo(() => (liveCols ? liveCols.filter((c) => c.visible) : visibleCols), [liveCols, visibleCols]);
  const colsWidth = cols.reduce((s, c) => s + c.width, 0);

  const onResizeDown = (e: React.PointerEvent, c: ColumnConfig) => {
    e.stopPropagation();
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
    resize.current = { id: c.id, startX: e.clientX, startW: c.width };
    setLiveCols(columns);
  };
  const onResizeMove = (e: React.PointerEvent) => {
    const r = resize.current;
    if (!r) return;
    const width = Math.max(32, r.startW + e.clientX - r.startX);
    setLiveCols((prev) => (prev ?? columns).map((c) => (c.id === r.id ? { ...c, width } : c)));
  };
  const onResizeUp = () => {
    if (resize.current && liveCols) useStore.getState().setColumns(liveCols);
    resize.current = null;
    setLiveCols(null);
  };

  const headerMenu = (e: React.MouseEvent, colId?: string) => {
    e.preventDefault();
    e.stopPropagation();
    const items: MenuEntry[] = [];
    if (colId) {
      items.push({
        label: t("ctx.hideColumn"),
        disabled: visibleCols.length <= 1,
        onSelect: () => useStore.getState().setColumns(columns.map((c) => (c.id === colId ? { ...c, visible: false } : c))),
      });
      items.push({ kind: "separator" });
    }
    items.push({ kind: "label", label: t("ctx.columns") });
    for (const c of columns) {
      items.push({
        label: t(COLUMN_DEFS[c.id].title),
        checked: c.visible,
        onSelect: () => useStore.getState().setColumns(columns.map((x) => (x.id === c.id ? { ...x, visible: !x.visible } : x))),
      });
    }
    items.push({ kind: "separator" }, { label: t("ctx.resetColumns"), onSelect: () => useStore.getState().setColumns(DEFAULT_COLUMNS) });
    showContextMenuAt(e.clientX, e.clientY, items);
  };

  const clickHeader = (c: ColumnConfig) => {
    const key = COLUMN_DEFS[c.id].sortKey;
    if (!key) return;
    const s = useStore.getState();
    let next = s.sort;
    if (!next || next.key !== key) next = { key, desc: false };
    else if (!next.desc) next = { key, desc: true };
    else next = null;
    void s.setSort(next);
  };

  const rows: React.ReactNode[] = [];
  for (let i = win.first; i < win.first + win.count; i++) {
    const row = get(i);
    if (!row) {
      rows.push(
        <div key={`p${i}`} className="plist-row is-placeholder" style={{ width: colsWidth }}>
          <div className="plist-cell num mono" style={{ width: cols[0]?.width }}>
            …
          </div>
        </div>,
      );
      continue;
    }
    rows.push(
      <PacketRowView
        key={row.number}
        row={row}
        index={i}
        cols={cols}
        width={colsWidth}
        rule={colorize && row.colorRule != null ? coloringRules[row.colorRule] : undefined}
        selected={row.number === selectedNumber}
        timeFormat={timeFormat}
        onMenu={onMenu}
      />,
    );
  }

  return (
    <div className="plist" tabIndex={0} onKeyDown={onKeyDown} aria-label={t("plist.title")} role="grid" aria-rowcount={total}>
      <div ref={headerRef} className="plist-header" onContextMenu={(e) => headerMenu(e)} role="row">
        <div style={{ display: "flex", minWidth: colsWidth }}>
          {cols.map((c) => {
            const def = COLUMN_DEFS[c.id];
            const sorted = sort && def.sortKey === sort.key;
            return (
              <div
                key={c.id}
                className={`plist-hcell${sorted ? " is-sorted" : ""}`}
                style={{ width: c.width, justifyContent: def.align ? "flex-end" : undefined }}
                onClick={() => clickHeader(c)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    e.stopPropagation();
                    clickHeader(c);
                  }
                }}
                onContextMenu={(e) => headerMenu(e, c.id)}
                role="columnheader"
                tabIndex={def.sortKey ? 0 : -1}
                aria-sort={sorted ? (sort.desc ? "descending" : "ascending") : undefined}
              >
                {t(def.title)}
                {sorted ? <span className="sort-arrow">{sort.desc ? "▼" : "▲"}</span> : null}
                <span
                  className="resizer"
                  onPointerDown={(e) => onResizeDown(e, c)}
                  onPointerMove={onResizeMove}
                  onPointerUp={onResizeUp}
                  onClick={(e) => e.stopPropagation()}
                />
              </div>
            );
          })}
        </div>
      </div>
      <div
        ref={bodyRef}
        className="plist-body"
        onScroll={(e) => {
          const el = e.currentTarget;
          setScrollTop(el.scrollTop);
          atBottom.current = el.scrollTop + el.clientHeight >= el.scrollHeight - ROW_H * 2;
          if (headerRef.current) headerRef.current.scrollLeft = el.scrollLeft;
        }}
      >
        <div style={{ height: win.contentHeight, width: Math.max(totalWidth, colsWidth), position: "relative" }}>
          <div className="plist-rows" style={{ transform: `translateY(${win.offsetY}px)` }}>
            {rows}
          </div>
        </div>
      </div>
      {error ? (
        <div className="plist-error" role="alert">
          <span>{t("status.rowsError", { message: error })}</span>
          <button className="btn btn-small" onClick={retry}>
            {t("status.retry")}
          </button>
        </div>
      ) : null}
      {total === 0 && !indexing ? <div className="plist-empty">{appliedFilter ? t("search.notFound") : t("hex.empty")}</div> : null}
      <IndexingOverlay />
    </div>
  );
}
