import { useMemo, useState } from "react";
import type uPlot from "uplot";

import { api } from "../../api/client";
import type { ProtocolNode } from "../../api/types";
import { t, type MessageKey } from "../../i18n";
import { fmtBytes, fmtInt, fmtPercent } from "../../lib/format";
import { applyFilterText, filterByTerm } from "../../state/actions";
import { useStore } from "../../state/store";
import { showContextMenu } from "../common/ContextMenu";
import { Icon } from "../common/Icon";
import { Select } from "../common/Select";
import { UPlotChart } from "./UPlotChart";
import { QueryError, useBackend } from "./useBackend";

type Sub = "hierarchy" | "io" | "lengths";

export function StatisticsPanel() {
  const [sub, setSub] = useState<Sub>("hierarchy");
  return (
    <div className="col" style={{ flex: 1, minHeight: 0 }}>
      <div className="tool-bar">
        <div className="segmented">
          {(["hierarchy", "io", "lengths"] as Sub[]).map((s) => (
            <button key={s} className={sub === s ? "is-active" : ""} onClick={() => setSub(s)}>
              {t(`stats.${s}` as MessageKey)}
            </button>
          ))}
        </div>
      </div>
      <div className="tool-body">{sub === "hierarchy" ? <Hierarchy /> : sub === "io" ? <IoGraphView /> : <Lengths />}</div>
    </div>
  );
}

function Hierarchy() {
  const { data, error } = useBackend(() => api.protocolHierarchy(), []);
  const root = data?.[0];
  const totalPackets = root?.packets ?? 0;
  const totalBytes = root?.bytes ?? 0;
  const rows: { node: ProtocolNode; depth: number }[] = [];
  const walk = (nodes: ProtocolNode[], depth: number) => {
    for (const n of nodes) {
      rows.push({ node: n, depth });
      walk(n.children, depth + 1);
    }
  };
  walk(data ?? [], 0);

  if (error) return <QueryError error={error} />;
  return (
    <table className="dtable">
      <thead>
        <tr>
          <th>{t("stats.col.protocol")}</th>
          <th className="num">{t("stats.col.pctPackets")}</th>
          <th className="num">{t("stats.col.packets")}</th>
          <th className="num">{t("stats.col.pctBytes")}</th>
          <th className="num">{t("stats.col.bytes")}</th>
          <th style={{ width: 90 }} />
        </tr>
      </thead>
      <tbody>
        {rows.map(({ node, depth }, i) => {
          const pct = Number(fmtPercent(node.packets, totalPackets));
          return (
            <tr
              key={i}
              onDoubleClick={() => applyFilterText(node.filter)}
              onContextMenu={(e) =>
                showContextMenu(e, [
                  { label: t("ctx.applyFilter"), onSelect: () => applyFilterText(node.filter) },
                  { label: t("ctx.andFilter"), onSelect: () => filterByTerm(node.filter, "and", true) },
                  { label: t("ctx.notFilter"), onSelect: () => filterByTerm(node.filter, "not", true) },
                ])
              }
              title={node.filter}
            >
              <td style={{ paddingLeft: 6 + depth * 14 }}>{node.name}</td>
              <td className="num">{pct.toFixed(1)}</td>
              <td className="num">{fmtInt(node.packets)}</td>
              <td className="num">{fmtPercent(node.bytes, totalBytes)}</td>
              <td className="num">{fmtBytes(node.bytes)}</td>
              <td>
                <span className="bar" style={{ width: `${Math.max(1, pct * 0.8)}px` }} />
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

const INTERVALS = [0.001, 0.01, 0.1, 1, 10, 60];
type Source = "all" | "displayed" | "protocol" | "stream" | "custom";
const PROTOCOLS = ["tcp", "udp", "dns", "tls", "http", "icmp", "arp", "ipv6"];

function IoGraphView() {
  const appliedFilter = useStore((s) => s.appliedFilter);
  const duration = useStore((s) => s.summary?.duration ?? 0);
  const [interval, setInterval_] = useState<number | null>(null);
  const [metric, setMetric] = useState<"pps" | "bps">("pps");
  const [source, setSource] = useState<Source>("all");
  const [protocol, setProtocol] = useState("tcp");
  const [stream, setStream] = useState("0");
  const [custom, setCustom] = useState("");
  const auto = duration > 0 ? INTERVALS.find((i) => duration / i <= 1500) ?? 60 : 1;
  const step = interval ?? auto;

  const filter = useMemo(() => {
    switch (source) {
      case "all":
        return null;
      case "displayed":
        return appliedFilter || null;
      case "protocol":
        return protocol;
      case "stream":
        return `tcp.stream == ${Number.parseInt(stream, 10) || 0}`;
      case "custom":
        return custom.trim() || null;
    }
  }, [source, appliedFilter, protocol, stream, custom]);

  const all = useBackend(() => api.ioGraph(step, null), [step]);
  const sel = useBackend(() => (filter ? api.ioGraph(step, filter) : Promise.resolve(null)), [step, filter]);

  const data = useMemo<uPlot.AlignedData | null>(() => {
    const base = all.data;
    if (!base) return null;
    const xs = base.packets.map((_, i) => base.start + i * base.interval);
    const scale = (v: number) => v / base.interval;
    const pick = (g: typeof base) => (metric === "pps" ? g.packets : g.bytes).map(scale);
    const out: (number | null)[][] = [xs, pick(base)];
    if (sel.data) out.push(pick(sel.data).slice(0, xs.length));
    return out as uPlot.AlignedData;
  }, [all.data, sel.data, metric]);

  const series = [{ label: t("stats.io.all"), stroke: "#5aa2ff", fill: "rgba(90,162,255,0.10)" }];
  if (filter && sel.data) series.push({ label: filter.length > 40 ? `${filter.slice(0, 40)}…` : filter, stroke: "#e8a33d", fill: "rgba(232,163,61,0.10)" });

  const applyRange = (a: number, b: number) => {
    const from = Math.max(0, Math.min(a, b));
    const to = Math.max(a, b);
    filterByTerm(`frame.time_relative >= ${from.toFixed(6)} && frame.time_relative <= ${to.toFixed(6)}`, "and", true);
  };

  return (
    <div>
      <div className="tool-bar" style={{ borderBottom: 0 }}>
        <span className="muted">{t("stats.io.interval")}</span>
        <Select
          value={interval ?? "auto"}
          options={[
            { value: "auto" as string | number, label: t("stats.io.auto", { s: auto }) },
            ...INTERVALS.map((i) => ({ value: i as string | number, label: `${i} ${t("unit.s")}` })),
          ]}
          onChange={(v) => setInterval_(v === "auto" ? null : Number(v))}
          ariaLabel={t("stats.io.interval")}
        />
        <span className="muted">{t("stats.io.metric")}</span>
        <div className="segmented">
          <button className={metric === "pps" ? "is-active" : ""} onClick={() => setMetric("pps")}>
            {t("stats.io.pps")}
          </button>
          <button className={metric === "bps" ? "is-active" : ""} onClick={() => setMetric("bps")}>
            {t("stats.io.bps")}
          </button>
        </div>
        <span className="muted">{t("stats.io.source")}</span>
        <Select
          value={source}
          options={[
            { value: "all" as Source, label: t("stats.io.all") },
            { value: "displayed" as Source, label: t("stats.io.displayed"), disabled: !appliedFilter },
            { value: "protocol" as Source, label: t("stats.io.protocol") },
            { value: "stream" as Source, label: t("stats.io.stream") },
            { value: "custom" as Source, label: t("stats.io.custom") },
          ]}
          onChange={setSource}
          ariaLabel={t("stats.io.source")}
        />
        {source === "protocol" ? (
          <Select value={protocol} options={PROTOCOLS.map((p) => ({ value: p, label: p.toUpperCase() }))} onChange={setProtocol} />
        ) : null}
        {source === "stream" ? (
          <input className="input mono" style={{ width: 70 }} autoComplete="off" spellCheck={false} value={stream} onChange={(e) => setStream(e.target.value)} />
        ) : null}
        {source === "custom" ? (
          <input className="input mono grow" autoComplete="off" spellCheck={false} placeholder="dns || tls" value={custom} onChange={(e) => setCustom(e.target.value)} />
        ) : null}
        <button className="icon-btn" title={t("stats.io.refresh")} onClick={() => { all.reload(); sel.reload(); }}>
          <Icon name="refresh" />
        </button>
      </div>
      <QueryError error={all.error ?? sel.error} />
      {data ? (
        <UPlotChart
          data={data}
          series={series}
          yLabel={metric === "pps" ? t("stats.io.pps") : t("stats.io.bps")}
          height={260}
          onSelectRange={applyRange}
          onClickX={(x) => applyRange(x, x + step)}
        />
      ) : null}
      <div className="tool-note" style={{ paddingTop: 0 }}>{t("stats.io.hint")}</div>
    </div>
  );
}

function Lengths() {
  const appliedFilter = useStore((s) => s.appliedFilter);
  const [useFilter, setUseFilter] = useState(false);
  const { data, error } = useBackend(() => api.packetLengths(useFilter ? appliedFilter || null : null), [useFilter, appliedFilter]);
  const max = Math.max(1, ...(data?.buckets.map((b) => b.count) ?? [1]));
  return (
    <div>
      <QueryError error={error} />
      <div className="tool-bar" style={{ borderBottom: 0 }}>
        <label className="checkbox">
          <input type="checkbox" checked={useFilter} disabled={!appliedFilter} onChange={(e) => setUseFilter(e.target.checked)} />
          {t("stats.io.displayed")}
        </label>
        {data ? (
          <span className="muted">
            {fmtInt(data.total)} · {t("stats.col.avg")} {data.avg?.toFixed(1) ?? "—"} · {t("stats.col.minmax")} {data.min ?? "—"} / {data.max ?? "—"}
          </span>
        ) : null}
      </div>
      <table className="dtable">
        <thead>
          <tr>
            <th>{t("stats.col.range")}</th>
            <th className="num">{t("stats.col.count")}</th>
            <th className="num">%</th>
            <th className="num">{t("stats.col.avg")}</th>
            <th className="num">{t("stats.col.minmax")}</th>
            <th style={{ width: 130 }} />
          </tr>
        </thead>
        <tbody>
          {data?.buckets.map((b) => {
            const range = b.max == null ? `${b.min}+` : `${b.min}–${b.max}`;
            const f = b.max == null ? `frame.len >= ${b.min}` : `frame.len >= ${b.min} && frame.len <= ${b.max}`;
            return (
              <tr key={b.min} onDoubleClick={() => applyFilterText(f)} title={f}>
                <td className="mono">{range}</td>
                <td className="num">{fmtInt(b.count)}</td>
                <td className="num">{fmtPercent(b.count, data.total)}</td>
                <td className="num">{b.avg?.toFixed(1) ?? "—"}</td>
                <td className="num">{b.minSeen != null ? `${b.minSeen} / ${b.maxSeen}` : "—"}</td>
                <td>
                  <span className="bar alt" style={{ width: `${(b.count / max) * 120}px` }} />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
