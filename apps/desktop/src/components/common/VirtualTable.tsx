import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { computeWindow } from "../../lib/virtual";

export interface VColumn<T> {
  id: string;
  title: string;
  width: number;
  align?: "left" | "right";
  mono?: boolean;
  render: (row: T) => ReactNode;
  /** Enables client-side sorting by this value. */
  sortValue?: (row: T) => number | string;
  title_attr?: (row: T) => string;
}

interface Props<T> {
  columns: VColumn<T>[];
  rows: T[];
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

  useEffect(() => {
    const el = bodyRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setViewport(el.clientHeight));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const sorted = useMemo(() => {
    if (p.onSortChange || !sort) return p.rows;
    const col = p.columns.find((c) => c.id === sort.id);
    if (!col?.sortValue) return p.rows;
    const val = col.sortValue;
    const out = [...p.rows].sort((a, b) => {
      const x = val(a);
      const y = val(b);
      const c = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y), "ru");
      return sort.desc ? -c : c;
    });
    return out;
  }, [p.rows, p.columns, sort, p.onSortChange]);

  const w = computeWindow(sorted.length, rowHeight, viewport, scrollTop);
  const totalWidth = p.columns.reduce((s, c) => s + c.width, 0);

  const clickHeader = (c: VColumn<T>) => {
    if (!c.sortValue && !p.onSortChange) return;
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
            tabIndex={c.sortValue || p.onSortChange ? 0 : -1}
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
        aria-rowcount={sorted.length}
        onKeyDown={(e) => {
          if (!sorted.length) return;
          const idx = p.selectedKey == null ? -1 : sorted.findIndex((r) => p.rowKey(r) === p.selectedKey);
          const page = Math.max(1, Math.floor(viewport / rowHeight) - 1);
          const moves: Record<string, number> = { ArrowDown: 1, ArrowUp: -1, PageDown: page, PageUp: -page };
          let next: number | null = null;
          if (e.key in moves) next = Math.min(sorted.length - 1, Math.max(0, idx + moves[e.key]));
          else if (e.key === "Home") next = 0;
          else if (e.key === "End") next = sorted.length - 1;
          else if (e.key === "Enter" && idx >= 0) {
            e.preventDefault();
            p.onActivate?.(sorted[idx]);
            return;
          }
          if (next == null) return;
          e.preventDefault();
          p.onSelect?.(sorted[next]);
          const el = bodyRef.current;
          if (el) {
            const y = next * rowHeight;
            if (y < el.scrollTop) el.scrollTop = y;
            else if (y + rowHeight > el.scrollTop + el.clientHeight) el.scrollTop = y + rowHeight - el.clientHeight;
          }
        }}
        onScroll={(e) => {
          setScrollTop(e.currentTarget.scrollTop);
          const header = e.currentTarget.previousElementSibling as HTMLElement | null;
          if (header) header.scrollLeft = e.currentTarget.scrollLeft;
        }}
      >
        <div style={{ height: w.contentHeight, width: totalWidth, position: "relative" }}>
          <div className="plist-rows" style={{ transform: `translateY(${w.offsetY}px)` }}>
            {sorted.slice(w.first, w.first + w.count).map((row) => {
              const key = p.rowKey(row);
              return (
                <div
                  key={key}
                  role="row"
                  aria-selected={p.selectedKey === key}
                  className={`plist-row${p.selectedKey === key ? " is-selected" : ""}`}
                  onClick={() => p.onSelect?.(row)}
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
        {sorted.length === 0 && p.emptyText ? <div className="plist-empty">{p.emptyText}</div> : null}
      </div>
    </div>
  );
}
