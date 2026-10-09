import { useEffect, useRef, useState } from "react";

import { api } from "../../api/client";
import { TcpAnalysis, type FlowSummary, type SequenceEntry, type StreamRef } from "../../api/types";
import { t } from "../../i18n";
import { fmtEndpoint } from "../../lib/format";
import { computeWindow } from "../../lib/virtual";
import { useStore } from "../../state/store";

const ROW_H = 30;
const PAGE = 500;
const MAX_PAGES = 40;
const GRID = "48px 82px minmax(200px, 1fr) 176px";

const FLAG_BADGES: [number, string, "warn" | "error" | "note"][] = [
  [TcpAnalysis.FAST_RETRANSMISSION, "Fast Retr.", "warn"],
  [TcpAnalysis.RETRANSMISSION, "Retr.", "warn"],
  [TcpAnalysis.OUT_OF_ORDER, "OOO", "warn"],
  [TcpAnalysis.DUPLICATE_ACK, "Dup ACK", "note"],
  [TcpAnalysis.LOST_SEGMENT, "Lost", "error"],
  [TcpAnalysis.ZERO_WINDOW, "Zero win", "error"],
  [TcpAnalysis.KEEP_ALIVE, "Keep-alive", "note"],
  [TcpAnalysis.WINDOW_UPDATE, "Win upd", "note"],
];

function badges(flags: number) {
  const out = [];
  let f = flags;
  if (f & TcpAnalysis.FAST_RETRANSMISSION) f &= ~TcpAnalysis.RETRANSMISSION;
  for (const [bit, label, kind] of FLAG_BADGES) {
    if (f & bit) out.push(<span key={label} className={`badge badge-${kind}`}>{label}</span>);
  }
  return out;
}

/** Ladder diagram of a stream: every arrow is a packet, click jumps to it. */
export function SequencePanel() {
  const stream = useStore((s) => s.focusStream);
  if (!stream) return <div className="tool-note">{t("seq.pick")}</div>;
  return <Sequence key={`${stream.kind}:${stream.id}`} stream={stream} />;
}

function Sequence({ stream }: { stream: StreamRef }) {
  const selected = useStore((s) => s.selectedNumber);
  const indexState = useStore((s) => s.progress?.state);
  const [flow, setFlow] = useState<FlowSummary | null>(null);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState<Map<number, SequenceEntry[]>>(new Map());
  const pending = useRef(new Set<number>());
  const [streamTime, setStreamTime] = useState(true);
  const bodyRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewport, setViewport] = useState(400);

  const [error, setError] = useState<string | null>(null);
  /** Incremented on reload; responses from an older generation are ignored. */
  const gen = useRef(0);

  useEffect(() => {
    const my = ++gen.current;
    pending.current.clear();
    setPages(new Map());
    setError(null);
    const fail = (e: Error) => {
      if (my === gen.current) setError(e.message);
    };
    api
      .flow(stream)
      .then((f) => my === gen.current && setFlow(f))
      .catch(fail);
    api
      .sequence(stream, 0, PAGE)
      .then((p) => {
        if (my !== gen.current) return;
        setTotal(p.total);
        setPages(new Map([[0, p.entries]]));
      })
      .catch(fail);
  }, [stream, indexState]);

  useEffect(() => {
    const el = bodyRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setViewport(el.clientHeight));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const win = computeWindow(total, ROW_H, viewport, scrollTop);
  useEffect(() => {
    const from = Math.floor(win.first / PAGE);
    const to = Math.floor((win.first + Math.max(win.count, 1) - 1) / PAGE);
    const my = gen.current;
    for (let p = from; p <= to; p++) {
      if (pages.has(p) || pending.current.has(p)) continue;
      pending.current.add(p);
      api
        .sequence(stream, p * PAGE, PAGE)
        .then((page) => {
          if (my !== gen.current) return;
          setPages((prev) => {
            const next = new Map(prev).set(p, page.entries);
            // Keep memory bounded on very long streams: drop the pages farthest away.
            while (next.size > MAX_PAGES) {
              const far = [...next.keys()].sort((x, y) => Math.abs(y - p) - Math.abs(x - p))[0];
              next.delete(far);
            }
            return next;
          });
        })
        .catch((e: Error) => my === gen.current && setError(e.message))
        .finally(() => {
          if (my === gen.current) pending.current.delete(p);
        });
    }
  }, [win.first, win.count, pages, stream]);

  const rows = [];
  for (let i = win.first; i < win.first + win.count; i++) {
    const e = pages.get(Math.floor(i / PAGE))?.[i % PAGE];
    if (!e) {
      rows.push(<div key={`p${i}`} className="seq-row" style={{ gridTemplateColumns: GRID }} />);
      continue;
    }
    const meta = [
      e.seq != null ? `Seq=${e.seq}` : null,
      e.ack != null ? `Ack=${e.ack}` : null,
      `Len=${e.len}`,
      e.window != null ? `Win=${e.window}` : null,
    ]
      .filter(Boolean)
      .join(" ");
    rows.push(
      <div
        key={e.number}
        className={`seq-row${e.number === selected ? " is-selected" : ""}`}
        style={{ gridTemplateColumns: GRID }}
        onClick={() => void useStore.getState().selectPacket(e.number)}
        title={`№${e.number} · ${e.label}`}
      >
        <span className="seq-num num">{e.number}</span>
        <span className="seq-time">{(streamTime ? e.timeStream : e.timeRel).toFixed(6)}</span>
        <span className="seq-lane">
          <span className="seq-label">
            {e.label}
            {badges(e.analysis)}
          </span>
          <span className={`seq-arrow ${e.direction}`} />
        </span>
        <span className="seq-meta">{meta}</span>
      </div>,
    );
  }

  return (
    <div className="col" style={{ flex: 1, minHeight: 0 }}>
      <div className="tool-bar">
        <strong>{t("stream.title", { kind: stream.kind.toUpperCase(), id: stream.id })}</strong>
        {flow ? <span className="badge">{flow.protocol}</span> : null}
        <span className="muted">{t("seq.packets", { n: total })}</span>
        <span className="grow" />
        <label className="checkbox">
          <input type="checkbox" checked={streamTime} onChange={(e) => setStreamTime(e.target.checked)} />
          {t("seq.timeMode")}
        </label>
      </div>
      {error ? (
        <div className="tool-note" role="alert" style={{ color: "var(--error)" }}>
          {t("common.error", { message: error })}
        </div>
      ) : null}
      <div className="tool-body" style={{ overflow: "hidden" }}>
        <div className="seq">
          <div className="seq-head" style={{ gridTemplateColumns: GRID }}>
            <span className="seq-num">№</span>
            <span className="seq-time">{t("seq.col.time")}</span>
            <span className="seq-eps">
              <span className="seq-ep is-client" title={flow ? fmtEndpoint(flow.client.addr, flow.client.port) : ""}>
                <span className="who">{t("seq.client")}</span>
                {flow ? fmtEndpoint(flow.client.addr, flow.client.port) : ""}
              </span>
              <span className="seq-ep is-server" title={flow ? fmtEndpoint(flow.server.addr, flow.server.port) : ""}>
                <span className="who">{t("seq.server")}</span>
                {flow ? fmtEndpoint(flow.server.addr, flow.server.port) : ""}
              </span>
            </span>
            <span className="seq-meta">Seq / Ack / Len / Win</span>
          </div>
          <div ref={bodyRef} className="seq-body" onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}>
            <div style={{ height: win.contentHeight, position: "relative" }}>
              <div style={{ position: "absolute", left: 0, right: 0, top: 0, transform: `translateY(${win.offsetY}px)` }}>{rows}</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
