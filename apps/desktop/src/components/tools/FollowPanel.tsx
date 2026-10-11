import { useEffect, useRef, useState } from "react";

import { api } from "../../api/client";
import type { FollowChunk, FollowDirection, StreamRef } from "../../api/types";
import { t, type MessageKey } from "../../i18n";
import { LineBuilder, type FollowLine, type FollowMode } from "../../lib/follow";
import { fmtBytes } from "../../lib/format";
import { computeWindow } from "../../lib/virtual";
import { copy } from "../../state/actions";
import { errorText, useStore } from "../../state/store";
import { Icon } from "../common/Icon";

const ROW_H = 18;
const PAGE_BYTES = 256 * 1024;
/** Held in the panel at once; the rest is reached with "next part" or saved to a file. */
const MAX_LOADED = 8 * 1024 * 1024;
const MAX_LINES = 200_000;
const MAX_CHUNKS = 200_000;
/** Load the next page when the view is this close to the end of the lines. */
const PREFETCH_ROWS = 400;
/** A running capture has no new data yet: ask again after this delay. */
const POLL_MS = 2000;

/** Payload of a stream as text or hex, reassembled by the engine. */
export function FollowPanel() {
  const stream = useStore((s) => s.focusStream);
  if (!stream) return <div className="tool-note">{t("seq.pick")}</div>;
  return <Follow key={`${stream.kind}:${stream.id}`} stream={stream} />;
}

/** The loaded part of the stream: the only copy of the data (lines are derived from it). */
interface Loaded {
  /** Offset the panel starts at (non-zero after "next part"). */
  start: number;
  chunks: FollowChunk[];
  bytes: number;
  next: number;
  done: boolean;
  /** The end of the captured data was reached while a capture runs. */
  waiting: boolean;
}

const emptyLoaded = (start: number): Loaded => ({ start, chunks: [], bytes: 0, next: start, done: false, waiting: false });

/** Lines built from `Loaded`, extended as chunks arrive and rebuilt when the mode or the data set changes. */
interface Built {
  source: Loaded;
  builder: LineBuilder;
  consumed: number;
  closed: boolean;
}

function lineText(l: FollowLine): string {
  return l.kind === "data" ? l.text : t(l.kind === "gap" ? "follow.gap" : "follow.notCaptured", { size: fmtBytes(l.len ?? 0) });
}

function Follow({ stream }: { stream: StreamRef }) {
  const indexState = useStore((s) => s.progress?.state);
  const [direction, setDirection] = useState<FollowDirection>("both");
  const [mode, setMode] = useState<FollowMode>("text");
  const loaded = useRef<Loaded>(emptyLoaded(0));
  const built = useRef<Built | null>(null);
  /** Bumped whenever `loaded` changes, to render. */
  const [, setVersion] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const bodyRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewport, setViewport] = useState(400);
  /** Incremented on reload and unmount; responses from an older generation are ignored. */
  const gen = useRef(0);

  // Bring the lines up to date with the loaded chunks. Idempotent, so safe
  // during render: only chunks not consumed yet are added.
  const d = loaded.current;
  let b = built.current;
  if (!b || b.source !== d || b.builder.mode !== mode) {
    b = built.current = { source: d, builder: new LineBuilder(mode), consumed: 0, closed: false };
  }
  for (; b.consumed < d.chunks.length; b.consumed++) b.builder.push(d.chunks[b.consumed]);
  const lines = b.builder.lines;
  const full = !d.done && (d.bytes >= MAX_LOADED || lines.length >= MAX_LINES || d.chunks.length >= MAX_CHUNKS);
  if ((d.done || full) && !b.closed) {
    b.builder.close();
    b.closed = true;
  }

  const reset = (start: number) => {
    gen.current++;
    loaded.current = emptyLoaded(start);
    setVersion((v) => v + 1);
    setError(null);
    setLoading(false);
    setScrollTop(0);
    if (bodyRef.current) bodyRef.current.scrollTop = 0;
  };

  useEffect(
    () => () => {
      gen.current++;
    },
    [],
  );

  useEffect(() => {
    const el = bodyRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setViewport(el.clientHeight));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const win = computeWindow(lines.length, ROW_H, viewport, scrollTop);
  const wantMore = !d.done && !full && win.first + win.count + PREFETCH_ROWS >= lines.length;

  useEffect(() => {
    if (!wantMore || loading || error) return;
    const my = gen.current;
    const target = loaded.current;
    setLoading(true);
    api
      .followStream(stream, direction, target.next, Math.min(PAGE_BYTES, MAX_LOADED - target.bytes))
      .then((p) => {
        if (my !== gen.current) return;
        for (const c of p.chunks) target.chunks.push(c);
        target.bytes += p.nextOffset - p.offset;
        target.next = p.nextOffset;
        target.done = p.done;
        target.waiting = p.waiting && p.chunks.length === 0;
        setVersion((v) => v + 1);
        // Waiting for a running capture: stay "loading" for a moment before asking
        // again. Otherwise (an empty page after a long stretch without payload) go on.
        if (target.waiting) setTimeout(() => my === gen.current && setLoading(false), POLL_MS);
        else setLoading(false);
      })
      .catch((e: Error) => {
        if (my !== gen.current) return;
        setError(errorText(e));
        setLoading(false);
      });
  }, [wantMore, loading, error, stream, direction]);

  const changeDirection = (next: FollowDirection) => {
    if (next === direction) return;
    setDirection(next);
    reset(0);
  };

  const save = async () => {
    if (saving) return;
    setSaving(true);
    try {
      const name = `${stream.kind}-stream-${stream.id}${direction === "both" ? "" : `-${direction}`}.bin`;
      const r = await api.exportStream(stream, direction, name, t("follow.save"));
      if (r) {
        const size = fmtBytes(r.bytes);
        useStore.getState().flash(r.missing > 0 ? t("follow.savedMissing", { size, missing: fmtBytes(r.missing) }) : t("follow.saved", { size }));
      }
    } catch (e) {
      useStore.getState().flash(t("common.error", { message: errorText(e as Error) }));
    } finally {
      setSaving(false);
    }
  };

  const dirLabel = (dir: FollowDirection) => t(`follow.dir.${dir}` as MessageKey);
  const rows = [];
  for (let i = win.first; i < win.first + win.count; i++) {
    const l = lines[i];
    if (!l) continue;
    const select = () => {
      // Releasing the mouse after selecting text is not a click on the line.
      if (window.getSelection()?.toString()) return;
      void useStore.getState().selectPacket(l.number, { reveal: false });
    };
    rows.push(
      <div
        key={i}
        className={l.kind === "data" ? `follow-line ${l.direction}` : "follow-line follow-hole"}
        onClick={select}
        title={`№${l.number} · ${dirLabel(l.direction)}`}
      >
        {l.kind === "data" ? l.text || " " : lineText(l)}
      </div>,
    );
  }

  const status = d.waiting ? t("follow.waiting") : loading && lines.length === 0 ? t("follow.loading") : null;

  return (
    <div className="col" style={{ flex: 1, minHeight: 0 }}>
      <div className="tool-bar">
        <strong>{t("stream.title", { kind: stream.kind.toUpperCase(), id: stream.id })}</strong>
        <div className="segmented" role="group" aria-label={t("follow.direction")}>
          {(["both", "c2s", "s2c"] as const).map((x) => (
            <button key={x} className={direction === x ? "is-active" : ""} aria-pressed={direction === x} onClick={() => changeDirection(x)}>
              {dirLabel(x)}
            </button>
          ))}
        </div>
        <div className="segmented" role="group" aria-label={t("follow.mode")}>
          {(["text", "hex"] as const).map((m) => (
            <button key={m} className={mode === m ? "is-active" : ""} aria-pressed={mode === m} onClick={() => setMode(m)}>
              {t(`follow.mode.${m}` as MessageKey)}
            </button>
          ))}
        </div>
        <span className="grow" />
        <span className="muted">{fmtBytes(d.bytes)}</span>
        <button
          className="icon-btn"
          title={t("follow.copy")}
          aria-label={t("follow.copy")}
          disabled={lines.length === 0}
          onClick={() => void copy(lines.map(lineText).join("\n"))}
        >
          <Icon name="copy" />
        </button>
        <button className="btn btn-small" disabled={indexState === "indexing" || saving} title={t("follow.saveHint")} onClick={() => void save()}>
          <Icon name="save" />
          {t("follow.save")}
        </button>
      </div>
      {error ? (
        <div className="tool-note tool-error" role="alert">
          {t("common.error", { message: error })}{" "}
          <button className="btn btn-small" onClick={() => setError(null)}>
            {t("follow.retry")}
          </button>
        </div>
      ) : null}
      <div
        ref={bodyRef}
        className="tool-body follow-body"
        role="region"
        aria-label={t("dock.follow")}
        aria-busy={loading}
        tabIndex={0}
        onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
      >
        {lines.length === 0 && d.done ? <div className="tool-note">{t("follow.empty")}</div> : null}
        <div style={{ height: win.contentHeight, position: "relative" }}>
          <div style={{ position: "absolute", left: 0, right: 0, top: 0, transform: `translateY(${win.offsetY}px)` }}>{rows}</div>
        </div>
      </div>
      {status || d.start > 0 || full ? (
        <div className="tool-bar" aria-live="polite">
          {status ? <span className="muted">{status}</span> : null}
          {d.start > 0 ? (
            <button className="btn btn-small" onClick={() => reset(0)}>
              <Icon name="first" />
              {t("follow.fromStart")}
            </button>
          ) : null}
          {full ? (
            <>
              <span className="muted">{t("follow.limit", { size: fmtBytes(d.bytes) })}</span>
              <button className="btn btn-small" onClick={() => reset(d.next)}>
                <Icon name="forward" />
                {t("follow.nextPart")}
              </button>
            </>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
