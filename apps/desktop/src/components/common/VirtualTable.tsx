import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { computeWindow, scrollTopForRow } from "../../lib/virtual";

export interface VColumn<T> {
  id: string;
  title: string;
  width: number;
  align?: "left" | "right";
  mono?: boolean;
  render: (row: T) => ReactNode;
  /** Enables client-side sorting by this value. */
  sortValue?: (row: T) => number | string;
  /** With server-side sorting (`onSortChange`): the backend can sort by this column. */
  sortable?: boolean;
  title_attr?: (row: T) => string;
}

/** Rows loaded on demand (backend paging): `get` returns undefined until loaded. */
export interface RowSource<T> {
  /** Identity of the query: a new one restarts keyboard navigation. */
  key: string;
  total: number;
  get: (index: number) => T | undefined;
  ensure: (first: number, count: number) => void;
}

interface Props<T> {
  columns: VColumn<T>[];
  /** All rows (sorted here unless `onSortChange` is given)… */
  rows?: T[];
  /** …or rows paged from the backend (sorting is then the backend's). */
  source?: RowSource<T>;
  rowKey: (row: T) => string;
  selectedKey?: string | null;
  onSelect?: (row: T) => void;
  onActivate?: (row: T) => void;
  onContextMenu?: (e: React.MouseEvent, row: T) => void;
  initialSort?: { id: string; desc: boolean };
  /** Server-side sorting: when given, the table does not sort itself. */
  onSortChange?: (id: string, desc: boolean) => void;
  sort?: { id: string; desc: boolean } | null;
  emptyText?: string;
  rowHeight?: number;
}

/** Virtualized, sortable read-only table for tool panels. */
export function VirtualTable<T>(p: Props<T>) {
  const rowHeight = p.rowHeight ?? 20;
  const bodyRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewport, setViewport] = useState(400);
  const [localSort, setLocalSort] = useState(p.initialSort ?? null);
  const sort = p.onSortChange ? (p.sort ?? null) : localSort;
  /** Keyboard position in paged mode (rows there are not all known). */
  const [cursor, setCursor] = useState(-1);
  /** Row moved to with the keyboard before it was loaded; selected on arrival. */
  const pendingSelect = useRef<number | null>(null);

  useEffect(() => {
    const el = bodyRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setViewport(el.clientHeight));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const sorted = useMemo(() => {
    const rows = p.rows ?? [];
    if (p.onSortChange || !sort) return rows;
    const col = p.columns.find((c) => c.id === sort.id);
    if (!col?.sortValue) return rows;
    const val = col.sortValue;
    const out = [...rows].sort((a, b) => {
      const x = val(a);
      const y = val(b);
      const c = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y), "ru");
      return sort.desc ? -c : c;
    });
    return out;
  }, [p.rows, p.columns, sort, p.onSortChange]);

  const source = p.source;
  const count = source ? source.total : sorted.length;
  const rowAt = (i: number): T | undefined => (source ? source.get(i) : sorted[i]);
  const w = computeWindow(count, rowHeight, viewport, scrollTop);
  useEffect(() => {
    if (w.count > 0) source?.ensure(w.first, w.count);
    const pending = pendingSelect.current;
    const row = pending == null ? undefined : rowAt(pending);
    if (row !== undefined) {
      pendingSelect.current = null;
      p.onSelect?.(row);
    }
  });
  // Another order or filter: positions no longer mean the same rows.
  const sourceKey = source?.key;
  useEffect(() => {
    setCursor(-1);
    pendingSelect.current = null;
  }, [sourceKey]);
  /** Index of the selected row: the cursor if it still shows it, else found among loaded rows. */
  const selectedIndex = (): number => {
    if (!source) return p.selectedKey == null ? -1 : sorted.findIndex((r) => p.rowKey(r) === p.selectedKey);
    const at = (i: number) => {
      const r = rowAt(i);
      return r !== undefined && p.rowKey(r) === p.selectedKey;
    };
    if (p.selectedKey == null) return cursor;
    if (cursor >= 0 && at(cursor)) return cursor;
    for (let i = w.first; i < w.first + w.count; i++) if (at(i)) return i;
    return cursor;
  };
  const sortable = (c: VColumn<T>) => (p.onSortChange ? !!c.sortable : !!c.sortValue);
  const select = (row: T, index: number) => {
    pendingSelect.current = null;
    setCursor(index);
    p.onSelect?.(row);
  };
  const totalWidth = p.columns.reduce((s, c) => s + c.width, 0);

  const clickHeader = (c: VColumn<T>) => {
    if (!sortable(c)) return;
    const desc = sort?.id === c.id ? !sort.desc : c.align === "right";
    if (p.onSortChange) p.onSortChange(c.id, desc);
    else setLocalSort({ id: c.id, desc });
  };

  return (
    <div className="plist">
      <div className="plist-header" style={{ minWidth: totalWidth }}>
        {p.columns.map((c) => (
          <div
            key={c.id}
            className={`plist-hcell${sort?.id === c.id ? " is-sorted" : ""}`}
            style={{ width: c.width, justifyContent: c.align === "right" ? "flex-end" : undefined }}
            onClick={() => clickHeader(c)}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                clickHeader(c);
              }
            }}
            role="columnheader"
            tabIndex={sortable(c) ? 0 : -1}
            aria-sort={sort?.id === c.id ? (sort.desc ? "descending" : "ascending") : undefined}
            title={c.title}
          >
            {c.title}
            {sort?.id === c.id ? <span className="sort-arrow">{sort.desc ? "▼" : "▲"}</span> : null}
          </div>
        ))}
      </div>
      <div
        ref={bodyRef}
        className="plist-body"
        tabIndex={0}
        role="grid"
        aria-rowcount={count}
        onKeyDown={(e) => {
          if (!count) return;
          const idx = selectedIndex();
          const page = Math.max(1, Math.floor(viewport / rowHeight) - 1);
          const moves: Record<string, number> = { ArrowDown: 1, ArrowUp: -1, PageDown: page, PageUp: -page };
          let next: number | null = null;
          if (e.key in moves) next = Math.min(count - 1, Math.max(0, idx + moves[e.key]));
          else if (e.key === "Home") next = 0;
          else if (e.key === "End") next = count - 1;
          else if (e.key === "Enter" && idx >= 0) {
            e.preventDefault();
            const row = rowAt(idx);
            if (row) p.onActivate?.(row);
            return;
          }
          if (next == null) return;
          e.preventDefault();
          setCursor(next);
          const row = rowAt(next);
          pendingSelect.current = row === undefined ? next : null;
          if (row !== undefined) p.onSelect?.(row);
          const el = bodyRef.current;
          if (el) el.scrollTop = scrollTopForRow(next, count, rowHeight, el.clientHeight, el.scrollTop, true);
        }}
        onScroll={(e) => {
          setScrollTop(e.currentTarget.scrollTop);
          const header = e.currentTarget.previousElementSibling as HTMLElement | null;
          if (header) header.scrollLeft = e.currentTarget.scrollLeft;
        }}
      >
        <div style={{ height: w.contentHeight, width: totalWidth, position: "relative" }}>
          <div className="plist-rows" style={{ transform: `translateY(${w.offsetY}px)` }}>
            {Array.from({ length: w.count }, (_, k) => w.first + k).map((index) => {
              const row = rowAt(index);
              if (row === undefined) {
                return (
                  <div key={`loading-${index}`} role="row" className="plist-row is-loading">
                    <div className="plist-cell faint">…</div>
                  </div>
                );
              }
              const key = p.rowKey(row);
              return (
                <div
                  key={key}
                  role="row"
                  aria-selected={p.selectedKey === key}
                  className={`plist-row${p.selectedKey === key ? " is-selected" : ""}`}
                  onClick={() => select(row, index)}
                  onDoubleClick={() => p.onActivate?.(row)}
                  onContextMenu={(e) => p.onContextMenu?.(e, row)}
                >
                  {p.columns.map((c) => (
                    <div
                      key={c.id}
                      className={`plist-cell${c.align === "right" ? " num" : ""}${c.mono ? " mono" : ""}`}
                      style={{ width: c.width }}
                      title={c.title_attr?.(row)}
                    >
                      {c.render(row)}
                    </div>
                  ))}
                </div>
              );
            })}
          </div>
        </div>
        {count === 0 && p.emptyText ? <div className="plist-empty">{p.emptyText}</div> : null}
      </div>
    </div>
  );
}
