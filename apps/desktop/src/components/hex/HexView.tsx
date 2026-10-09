import { useEffect, useRef, useState } from "react";

import { t } from "../../i18n";
import { deepestAt, nodeAt } from "../../lib/tree";
import { computeWindow } from "../../lib/virtual";
import { copy } from "../../state/actions";
import { useStore } from "../../state/store";
import { showContextMenu } from "../common/ContextMenu";

const LINE_H = 18;
const PER_LINE = 16;
const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));

function printable(b: number): string {
  return b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".";
}

/** OFFSET | HEX | ASCII with field highlighting; only visible lines are rendered. */
export function HexView() {
  const detail = useStore((s) => s.detail);
  const highlight = useStore((s) => s.highlight);
  const hasDetail = useStore((s) => s.detail != null);
  const loadError = useStore((s) => s.detailError);
  const setHighlight = useStore((s) => s.setHighlight);
  const ref = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewport, setViewport] = useState(200);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setViewport(el.clientHeight));
    ro.observe(el);
    setViewport(el.clientHeight);
    // A new scroll element starts at the top: drop the old element's position.
    setScrollTop(el.scrollTop);
    return () => ro.disconnect();
    // The scroll element only exists once a packet is shown.
  }, [hasDetail]);

  // Scroll the highlighted range into view.
  useEffect(() => {
    const el = ref.current;
    if (!el || !highlight) return;
    const line = Math.floor(highlight.start / PER_LINE);
    const y = line * LINE_H;
    if (y < el.scrollTop || y + LINE_H > el.scrollTop + el.clientHeight) el.scrollTop = Math.max(0, y - LINE_H);
  }, [highlight]);

  if (!detail) return <div className="tool-note">{loadError ? t("hex.unavailable") : t("hex.empty")}</div>;
  const bytes = detail.bytes;
  const lines = Math.ceil(bytes.length / PER_LINE);
  const offDigits = bytes.length > 0xffff ? 8 : 4;
  const win = computeWindow(lines, LINE_H, viewport, scrollTop, 2);
  const hlStart = highlight?.start ?? -1;
  const hlEnd = highlight ? highlight.start + highlight.len : -1;

  const pick = (offset: number) => {
    const path = deepestAt(detail.tree, offset);
    const node = path ? nodeAt(detail.tree, path) : null;
    if (node && path) setHighlight({ start: node.start, len: node.len }, path);
    else setHighlight({ start: offset, len: 1 }, null);
  };

  const rendered = [];
  for (let line = win.first; line < win.first + win.count; line++) {
    const base = line * PER_LINE;
    const hex = [];
    const ascii = [];
    for (let i = 0; i < PER_LINE; i++) {
      const off = base + i;
      if (off >= bytes.length) break;
      const b = bytes[off];
      const hl = off >= hlStart && off < hlEnd;
      hex.push(
        <span key={off} className={`hex-b${hl ? " hl" : ""}`} onMouseDown={() => pick(off)}>
          {HEX[b]}
        </span>,
      );
      hex.push(i === 7 ? <span key={`g${off}`}>{"  "}</span> : " ");
      ascii.push(
        <span key={off} className={`hex-b${hl ? " hl" : ""}${b < 0x20 || b >= 0x7f ? " np" : ""}`} onMouseDown={() => pick(off)}>
          {printable(b)}
        </span>,
      );
    }
    rendered.push(
      <div className="hex-line" key={line}>
        <span className="hex-off">{base.toString(16).padStart(offDigits, "0")}</span>
        <span className="hex-bytes">{hex}</span>
        <span className="hex-ascii">{ascii}</span>
      </div>,
    );
  }

  const onContext = (e: React.MouseEvent) => {
    const range = highlight ? bytes.slice(highlight.start, highlight.start + highlight.len) : bytes;
    showContextMenu(e, [
      { label: t("ctx.copyHex"), onSelect: () => void copy(range.map((b) => HEX[b]).join(" ")) },
      { label: "ASCII", onSelect: () => void copy(range.map(printable).join("")) },
      {
        label: "Hex dump",
        onSelect: () => {
          const out: string[] = [];
          for (let i = 0; i < bytes.length; i += PER_LINE) {
            const chunk = bytes.slice(i, i + PER_LINE);
            out.push(`${i.toString(16).padStart(offDigits, "0")}  ${chunk.map((b) => HEX[b]).join(" ").padEnd(47)}  ${chunk.map(printable).join("")}`);
          }
          void copy(out.join("\n"));
        },
      },
    ]);
  };

  return (
    <div ref={ref} className="hex" tabIndex={0} onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)} onContextMenu={onContext}>
      <div style={{ height: win.contentHeight, position: "relative" }}>
        <div style={{ position: "absolute", top: 0, left: 0, transform: `translateY(${win.offsetY}px)` }}>{rendered}</div>
      </div>
    </div>
  );
}
