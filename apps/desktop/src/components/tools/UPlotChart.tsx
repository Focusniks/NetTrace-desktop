import { useEffect, useRef } from "react";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";

interface Props {
  data: uPlot.AlignedData;
  series: { label: string; stroke: string; fill?: string }[];
  yLabel: string;
  height: number;
  /** Called with a selected x range (seconds). */
  onSelectRange?: (from: number, to: number) => void;
  /** Called on a plain click with the x value. */
  onClickX?: (x: number) => void;
}

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888";
}

/** Thin React wrapper around uPlot (fast canvas time series). */
export function UPlotChart({ data, series, yLabel, height, onSelectRange, onClickX }: Props) {
  const wrap = useRef<HTMLDivElement>(null);
  const plot = useRef<uPlot | null>(null);
  const handlers = useRef({ onSelectRange, onClickX });
  handlers.current = { onSelectRange, onClickX };

  useEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const grid = { stroke: cssVar("--chart-grid"), width: 1 };
    const axis = { stroke: cssVar("--text-muted"), grid, ticks: { stroke: cssVar("--chart-grid") }, font: "11px Segoe UI, system-ui" };
    const opts: uPlot.Options = {
      width: el.clientWidth || 400,
      height,
      cursor: { drag: { x: true, y: false, setScale: false } },
      select: { show: true, left: 0, top: 0, width: 0, height: 0 },
      legend: { show: true, live: true },
      scales: { x: { time: false } },
      axes: [
        { ...axis, label: "с", labelSize: 14, values: (_u, vals) => vals.map((v) => v.toFixed(v < 10 ? 2 : 0)) },
        { ...axis, label: yLabel, labelSize: 14, size: 60 },
      ],
      series: [
        { label: "t, с", value: (_u, v) => (v == null ? "—" : v.toFixed(3)) },
        ...series.map((s) => ({ label: s.label, stroke: s.stroke, fill: s.fill, width: 1.25, points: { show: false } })),
      ],
      hooks: {
        setSelect: [
          (u) => {
            const { left, width } = u.select;
            if (width > 2) {
              const a = u.posToVal(left, "x");
              const b = u.posToVal(left + width, "x");
              handlers.current.onSelectRange?.(a, b);
            }
            u.setSelect({ left: 0, top: 0, width: 0, height: 0 }, false);
          },
        ],
      },
    };
    const p = new uPlot(opts, data, el);
    plot.current = p;
    const onClick = (e: MouseEvent) => {
      if (!handlers.current.onClickX || p.select.width > 2) return;
      const rect = p.over.getBoundingClientRect();
      handlers.current.onClickX(p.posToVal(e.clientX - rect.left, "x"));
    };
    p.over.addEventListener("dblclick", onClick);
    const ro = new ResizeObserver(() => p.setSize({ width: el.clientWidth, height }));
    ro.observe(el);
    return () => {
      ro.disconnect();
      p.over.removeEventListener("dblclick", onClick);
      p.destroy();
      plot.current = null;
    };
    // Recreate on series/label changes; data updates go through setData below.
  }, [series.map((s) => s.label + s.stroke).join("|"), yLabel, height]);

  useEffect(() => {
    plot.current?.setData(data);
  }, [data]);

  return <div ref={wrap} className="chart-wrap" />;
}
