import { useState } from "react";

import { api } from "../../api/client";
import type { FlowSort, FlowSummary, Transport } from "../../api/types";
import { t, type MessageKey } from "../../i18n";
import { fmtBytes, fmtDuration, fmtEndpoint, fmtInt, fmtMs, fmtRate } from "../../lib/format";
import { applyFilterText, copy, streamFilter } from "../../state/actions";
import { useStore } from "../../state/store";
import { showContextMenu } from "../common/ContextMenu";
import { Icon } from "../common/Icon";
import { VirtualTable, type VColumn } from "../common/VirtualTable";
import { useBackend } from "./useBackend";

const COLS: (VColumn<FlowSummary> & { sort?: FlowSort })[] = [
  { id: "id", sort: "id", title: t("streams.col.id"), width: 70, align: "right", mono: true, render: (f) => `${f.kind} ${f.id}` },
  { id: "client", title: t("streams.col.client"), width: 170, mono: true, render: (f) => fmtEndpoint(f.client.addr, f.client.port) },
  { id: "server", title: t("streams.col.server"), width: 170, mono: true, render: (f) => fmtEndpoint(f.server.addr, f.server.port) },
  { id: "proto", title: t("streams.col.protocol"), width: 64, render: (f) => f.protocol },
  { id: "packets", sort: "packets", title: t("streams.col.packets"), width: 70, align: "right", render: (f) => fmtInt(f.packets) },
  { id: "bytes", sort: "bytes", title: t("streams.col.bytes"), width: 84, align: "right", render: (f) => fmtBytes(f.bytes) },
  { id: "start", sort: "start", title: t("streams.col.start"), width: 84, align: "right", mono: true, render: (f) => f.start.toFixed(3) },
  { id: "duration", sort: "duration", title: t("streams.col.duration"), width: 90, align: "right", render: (f) => fmtDuration(f.duration) },
  {
    id: "retrans",
    sort: "retransmissions",
    title: t("streams.col.retrans"),
    width: 56,
    align: "right",
    render: (f) => (f.tcp && f.tcp.retransmissions > 0 ? <span style={{ color: "var(--warn)" }}>{f.tcp.retransmissions}</span> : f.tcp ? "0" : ""),
  },
  { id: "rtt", sort: "rtt", title: t("streams.col.rtt"), width: 76, align: "right", render: (f) => (f.tcp ? fmtMs(f.tcp.rttAvgMs ?? f.tcp.irttMs) : "") },
  { id: "state", title: t("streams.col.state"), width: 150, render: (f) => (f.tcp ? t(`state.${f.tcp.state}` as MessageKey) : "") },
];

export function StreamsPanel() {
  const [kind, setKind] = useState<Transport | null>("tcp");
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<{ id: string; desc: boolean }>({ id: "id", desc: false });
  const focus = useStore((s) => s.focusStream);
  const flowSort = (COLS.find((c) => c.id === sort.id)?.sort ?? "id") as FlowSort;

  const { data, reload } = useBackend(
    () => api.flows({ kind, sort: flowSort, desc: sort.desc, offset: 0, limit: 5000, search: search || null }),
    [kind, flowSort, sort.desc, search],
  );

  const selectedKey = focus ? `${focus.kind}:${focus.id}` : null;

  return (
    <div className="col" style={{ flex: 1, minHeight: 0 }}>
      <div className="tool-bar">
        <div className="segmented">
          {([["tcp", "TCP"], ["udp", "UDP"], [null, t("streams.all")]] as [Transport | null, string][]).map(([k, label]) => (
            <button key={label} className={kind === k ? "is-active" : ""} onClick={() => setKind(k)}>
              {label}
            </button>
          ))}
        </div>
        <input spellCheck={false} autoComplete="off" className="input grow" placeholder={t("streams.search")} value={search} onChange={(e) => setSearch(e.target.value)} />
        <span className="muted">{data ? `${fmtInt(data.flows.length)} / ${fmtInt(data.total)}` : ""}</span>
        <button className="icon-btn" title={t("common.refresh")} onClick={reload}>
          <Icon name="refresh" />
        </button>
      </div>
      <div className="tool-body" style={{ overflow: "hidden" }}>
        <VirtualTable
          columns={COLS}
          rows={data?.flows ?? []}
          rowKey={(f) => `${f.kind}:${f.id}`}
          selectedKey={selectedKey}
          onSelect={(f) => useStore.getState().focusOnStream({ kind: f.kind, id: f.id }, "streams")}
          onActivate={(f) => applyFilterText(streamFilter(f))}
          onContextMenu={(e, f) =>
            showContextMenu(e, [
              { label: t("stream.filter"), onSelect: () => applyFilterText(streamFilter(f)) },
              { label: t("stream.sequence"), onSelect: () => useStore.getState().focusOnStream({ kind: f.kind, id: f.id }, "sequence") },
              { label: t("stream.first"), onSelect: () => void useStore.getState().selectPacket(f.firstPacket) },
              { label: t("stream.last"), onSelect: () => void useStore.getState().selectPacket(f.lastPacket) },
              { kind: "separator" },
              { label: t("ctx.copyFilter"), onSelect: () => void copy(streamFilter(f)) },
            ])
          }
          sort={sort}
          onSortChange={(id, desc) => {
            if (COLS.find((c) => c.id === id)?.sort) setSort({ id, desc });
          }}
          emptyText={t("streams.empty")}
        />
      </div>
      {focus ? <StreamDetail /> : null}
    </div>
  );
}

function Fact({ label, children }: { label: MessageKey; children: React.ReactNode }) {
  return (
    <>
      <dt>{t(label)}</dt>
      <dd>{children}</dd>
    </>
  );
}

function PacketLink({ n }: { n: number | null | undefined }) {
  if (n == null) return <span className="faint">—</span>;
  return (
    <button className="link" onClick={() => void useStore.getState().selectPacket(n)}>
      №{n}
    </button>
  );
}

/** Objective facts about the focused stream. */
export function StreamDetail() {
  const focus = useStore((s) => s.focusStream);
  const { data: f } = useBackend(() => (focus ? api.flow(focus) : Promise.reject(new Error("no stream"))), [focus?.kind, focus?.id]);
  // Never show (and act on) the previous stream while the new one loads.
  if (!focus || !f || f.id !== focus.id || f.kind !== focus.kind) return null;
  const tcp = f.tcp;
  const warn = (n: number) => (n > 0 ? <span className="warn">{fmtInt(n)}</span> : "0");
  return (
    <div className="stream-detail">
      <div className="stream-detail-head">
        <h3>{t("stream.title", { kind: f.kind.toUpperCase(), id: f.id })}</h3>
        <span className="badge">{f.protocol}</span>
        {tcp ? <span className={`badge ${tcp.state === "reset" || tcp.state === "refused" ? "badge-error" : tcp.state === "closed" ? "" : "badge-ok"}`}>{t(`state.${tcp.state}` as MessageKey)}</span> : null}
      </div>
      <dl className="facts">
        <Fact label="stream.client">{fmtEndpoint(f.client.addr, f.client.port)}</Fact>
        <Fact label="stream.server">{fmtEndpoint(f.server.addr, f.server.port)}</Fact>
        <Fact label="stream.packets">
          {fmtInt(f.packets)} <span className="muted">({fmtInt(f.c2sPackets)} → / ← {fmtInt(f.s2cPackets)})</span>
        </Fact>
        <Fact label="stream.c2s">
          {fmtBytes(f.c2sBytes)} <span className="muted">· {t("stream.payload")} {fmtBytes(f.c2sPayload)}</span>
        </Fact>
        <Fact label="stream.s2c">
          {fmtBytes(f.s2cBytes)} <span className="muted">· {t("stream.payload")} {fmtBytes(f.s2cPayload)}</span>
        </Fact>
        <Fact label="stream.start">{f.start.toFixed(6)} {t("unit.s")}</Fact>
        <Fact label="stream.duration">{fmtDuration(f.duration)}</Fact>
        {tcp ? (
          <>
            <Fact label="stream.handshake">
              SYN <PacketLink n={tcp.handshake.syn} /> · SYN/ACK <PacketLink n={tcp.handshake.synAck} /> · ACK <PacketLink n={tcp.handshake.ack} />
            </Fact>
            <Fact label="stream.irtt">{fmtMs(tcp.irttMs)}</Fact>
            <Fact label="stream.rtt">
              {fmtMs(tcp.rttMinMs)} / {fmtMs(tcp.rttAvgMs)} / {fmtMs(tcp.rttMaxMs)} <span className="muted">({t("stream.rttSamples")}: {fmtInt(tcp.rttSamples)})</span>
            </Fact>
            <Fact label="stream.retrans">
              {warn(tcp.retransmissions)} <span className="muted">({t("stream.fastRetrans")}: {fmtInt(tcp.fastRetransmissions)})</span>
            </Fact>
            <Fact label="stream.dupAck">{warn(tcp.duplicateAcks)}</Fact>
            <Fact label="stream.ooo">{warn(tcp.outOfOrder)}</Fact>
            <Fact label="stream.lost">{warn(tcp.lostSegments)}</Fact>
            <Fact label="stream.zeroWin">{warn(tcp.zeroWindow)}</Fact>
            <Fact label="stream.keepAlive">{fmtInt(tcp.keepAlive)}</Fact>
            <Fact label="stream.rst">{warn(tcp.resets)}</Fact>
            <Fact label="stream.fin">
              <PacketLink n={tcp.finClient} /> / <PacketLink n={tcp.finServer} />
            </Fact>
            <Fact label="stream.throughput">
              → {fmtRate(tcp.throughputC2s)} · ← {fmtRate(tcp.throughputS2c)}
            </Fact>
          </>
        ) : null}
      </dl>
      <div className="stream-actions">
        <button className="btn btn-small btn-primary" onClick={() => applyFilterText(streamFilter(f))}>
          <Icon name="filter" />
          {t("stream.filter")}
        </button>
        <button className="btn btn-small" onClick={() => useStore.getState().focusOnStream({ kind: f.kind, id: f.id }, "sequence")}>
          <Icon name="sequence" />
          {t("stream.sequence")}
        </button>
        <button className="btn btn-small" onClick={() => void useStore.getState().selectPacket(f.firstPacket)}>
          <Icon name="first" />
          {t("stream.first")}
        </button>
        <button className="btn btn-small" onClick={() => void useStore.getState().selectPacket(f.lastPacket)}>
          <Icon name="last" />
          {t("stream.last")}
        </button>
      </div>
    </div>
  );
}
