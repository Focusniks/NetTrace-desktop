import { useEffect, useMemo, useRef, useState } from "react";

import { api } from "../../api/client";
import type { Timeline, TimelineEvent } from "../../api/types";
import { t, type MessageKey } from "../../i18n";
import { filterByTerm } from "../../state/actions";
import { useStore } from "../../state/store";
import { VirtualTable, type VColumn } from "../common/VirtualTable";
import { QueryError, useBackend } from "./useBackend";

const LABEL_W = 118;
const LANE_H = 30;
const AXIS_H = 18;

interface Lane {
  key: MessageKey;
  values: (tl: Timeline) => number[];
  color: string;
  kind: "bars" | "line";
}

const LANES: Lane[] = [
  { key: "timeline.packets", values: (tl) => tl.packets, color: "#5aa2ff", kind: "bars" },
  { key: "timeline.bytes", values: (tl) => tl.bytes, color: "#3f7fcf", kind: "bars" },
  { key: "timeline.tcp", values: (tl) => tl.tcpActive, color: "#4fb57c", kind: "line" },
  { key: "timeline.dns", values: (tl) => tl.dns, color: "#7aa7d9", kind: "bars" },
  { key: "timeline.tls", values: (tl) => tl.tls, color: "#b08cf0", kind: "bars" },
  { key: "timeline.http", values: (tl) => tl.http, color: "#e8a33d", kind: "bars" },
];

const EVENT_COLS: VColumn<TimelineEvent>[] = [
  { id: "time", title: t("col.time"), width: 96, align: "right", mono: true, render: (e) => e.timeRel.toFixed(6) },
  { id: "kind", title: t("timeline.col.kind"), width: 130, render: (e) => t(`ev.${e.kind}` as MessageKey) },
  { id: "label", title: t("col.info"), width: 340, render: (e) => e.label, title_attr: (e) => e.label },
  { id: "n", title: t("col.number"), width: 64, align: "right", mono: true, render: (e) => e.number },
  { id: "stream", title: t("col.stream"), width: 70, align: "right", mono: true, render: (e) => (e.stream ? `${e.stream.kind} ${e.stream.id}` : "") },
];

export function TimelinePanel() {
  const wrapRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [width, setWidth] = useState(600);
  const [range, setRange] = useState<{ start: number; end: number } | null>(null);
  const [sel, setSel] = useState<{ a: number; b: number } | null>(null);
  const drag = useRef<{ x0: number } | null>(null);
  const selectedNumber = useStore((s) => s.selectedNumber);
  const buckets = Math.max(20, Math.floor((width - LABEL_W) / 3));

  const { data, error } = useBackend(() => api.timeline(range?.start ?? null, range?.end ?? null, buckets, 3000), [range?.start, range?.end, buckets]);

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setWidth(el.clientWidth));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const height = AXIS_H + LANES.length * LANE_H;
  const plotW = Math.max(1, width - LABEL_W);
  const xToTime = (x: number) => (data ? data.start + ((x - LABEL_W) / plotW) * (data.end - data.start) : 0);
  const timeToX = (s: number) => (data ? LABEL_W + ((s - data.start) / Math.max(1e-9, data.end - data.start)) * plotW : 0);

  useEffect(() => {
    const c = canvasRef.current;
    if (!c || !data) return;
    const dpr = window.devicePixelRatio || 1;
    c.width = width * dpr;
    c.height = height * dpr;
    c.style.width = `${width}px`;
    c.style.height = `${height}px`;
    const g = c.getContext("2d");
    if (!g) return;
    g.scale(dpr, dpr);
    g.clearRect(0, 0, width, height);
    g.font = "11px Segoe UI, system-ui, sans-serif";
    g.textBaseline = "middle";
    const n = data.packets.length;
    const bw = plotW / Math.max(1, n);
    LANES.forEach((lane, li) => {
      const y0 = AXIS_H + li * LANE_H;
      g.fillStyle = li % 2 ? "#181c22" : "#1b1f26";
      g.fillRect(0, y0, width, LANE_H);
      g.fillStyle = "#8a93a2";
      g.fillText(t(lane.key), 8, y0 + LANE_H / 2);
      const values = lane.values(data);
      const max = Math.max(1, ...values);
      g.fillStyle = lane.color;
      g.strokeStyle = lane.color;
      if (lane.kind === "bars") {
        values.forEach((v, i) => {
          if (!v) return;
          const h = Math.max(1, (v / max) * (LANE_H - 6));
          g.fillRect(LABEL_W + i * bw, y0 + LANE_H - 3 - h, Math.max(1, bw - 0.5), h);
        });
      } else {
        g.beginPath();
        values.forEach((v, i) => {
          const x = LABEL_W + i * bw + bw / 2;
          const y = y0 + LANE_H - 3 - (v / max) * (LANE_H - 6);
          if (i === 0) g.moveTo(x, y);
          else g.lineTo(x, y);
        });
        g.lineWidth = 1.25;
        g.stroke();
      }
      g.fillStyle = "#646c79";
      g.textAlign = "right";
      g.fillText(String(max), width - 4, y0 + 8);
      g.textAlign = "left";
    });
    // Axis
    g.fillStyle = "#20252e";
    g.fillRect(0, 0, width, AXIS_H);
    g.fillStyle = "#8a93a2";
    const ticks = 6;
    for (let i = 0; i <= ticks; i++) {
      const x = LABEL_W + (plotW * i) / ticks;
      const s = data.start + ((data.end - data.start) * i) / ticks;
      g.fillRect(x, AXIS_H - 4, 1, 4);
      g.textAlign = i === ticks ? "right" : i === 0 ? "left" : "center";
      g.fillText(`${s.toFixed(s < 10 ? 3 : 1)} с`, x, AXIS_H / 2);
    }
    g.textAlign = "left";
    if (sel) {
      const x1 = timeToX(Math.min(sel.a, sel.b));
      const x2 = timeToX(Math.max(sel.a, sel.b));
      g.fillStyle = "rgba(90,162,255,0.18)";
      g.fillRect(x1, AXIS_H, Math.max(1, x2 - x1), height - AXIS_H);
      g.fillStyle = "#5aa2ff";
      g.fillRect(x1, AXIS_H, 1, height - AXIS_H);
      g.fillRect(x2, AXIS_H, 1, height - AXIS_H);
    }
  }, [data, width, height, sel, plotW]);

  const onDown = (e: React.PointerEvent) => {
    const x = e.nativeEvent.offsetX;
    if (x < LABEL_W) return;
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
    drag.current = { x0: x };
    setSel({ a: xToTime(x), b: xToTime(x) });
  };
  const onMove = (e: React.PointerEvent) => {
    if (!drag.current) return;
    const x = Math.max(LABEL_W, Math.min(width, e.nativeEvent.offsetX));
    setSel((s) => (s ? { a: s.a, b: xToTime(x) } : s));
  };
  const onUp = async (e: React.PointerEvent) => {
    const d = drag.current;
    drag.current = null;
    if (!d) return;
    if (Math.abs(e.nativeEvent.offsetX - d.x0) < 3) {
      // Click: jump to the first packet at this moment.
      setSel(null);
      const at = xToTime(d.x0);
      const hit = await api.search(0, null, false, { kind: "filter", text: `frame.time_relative >= ${at.toFixed(6)}` }).catch(() => null);
      if (hit) void useStore.getState().selectPacket(hit.number);
    }
  };

  const selRange = sel && Math.abs(sel.b - sel.a) > 0 ? { a: Math.min(sel.a, sel.b), b: Math.max(sel.a, sel.b) } : null;
  const events = useMemo(() => {
    const list = data?.events ?? [];
    return selRange ? list.filter((e) => e.timeRel >= selRange.a && e.timeRel <= selRange.b) : list;
  }, [data, selRange?.a, selRange?.b]);

  return (
    <div className="timeline">
      <QueryError error={error} />
      <div className="tool-bar">
        <span className="muted">{t("timeline.hint")}</span>
        <span className="grow" />
        {selRange ? <span className="mono">{t("timeline.range", { a: selRange.a.toFixed(3), b: selRange.b.toFixed(3) })}</span> : null}
        <button
          className="btn btn-small btn-primary"
          disabled={!selRange}
          onClick={() =>
            selRange && filterByTerm(`frame.time_relative >= ${selRange.a.toFixed(6)} && frame.time_relative <= ${selRange.b.toFixed(6)}`, "and", true)
          }
        >
          {t("timeline.applyRange")}
        </button>
        <button
          className="btn btn-small"
          disabled={!selRange}
          onClick={() => {
            if (selRange) setRange({ start: selRange.a, end: selRange.b });
            setSel(null);
          }}
        >
          {t("timeline.zoomIn")}
        </button>
        <button className="btn btn-small" disabled={!range} onClick={() => setRange(null)}>
          {t("timeline.zoomOut")}
        </button>
      </div>
      <div ref={wrapRef} className="timeline-canvas-wrap">
        <canvas ref={canvasRef} onPointerDown={onDown} onPointerMove={onMove} onPointerUp={onUp} />
      </div>
      <div className="pane-header">
        <span className="pane-title">{t("timeline.events")}</span>
        <span>{events.length}</span>
        {data?.eventsTruncated ? <span className="badge badge-warn">{t("timeline.truncated")}</span> : null}
      </div>
      <div className="timeline-events">
        <VirtualTable
          columns={EVENT_COLS}
          rows={events}
          rowKey={(e) => `${e.number}:${e.kind}`}
          selectedKey={events.find((e) => e.number === selectedNumber) ? `${selectedNumber}:${events.find((e) => e.number === selectedNumber)?.kind}` : null}
          onSelect={(e) => void useStore.getState().selectPacket(e.number)}
          onActivate={(e) => e.stream && useStore.getState().focusOnStream(e.stream, "streams")}
        />
      </div>
    </div>
  );
}
