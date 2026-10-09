import { useMemo, useState } from "react";

import { api } from "../../api/client";
import type { ConversationKind, ConversationRow } from "../../api/types";
import { t, type MessageKey } from "../../i18n";
import { fmtBytes, fmtDuration, fmtEndpoint, fmtInt } from "../../lib/format";
import { applyFilterText, copy, filterByTerm } from "../../state/actions";
import { useStore } from "../../state/store";
import { showContextMenu } from "../common/ContextMenu";
import { Icon } from "../common/Icon";
import { VirtualTable, type VColumn } from "../common/VirtualTable";
import { QueryError, useBackend } from "./useBackend";

const KINDS: ConversationKind[] = ["eth", "ip", "tcp", "udp"];

function columns(kind: ConversationKind): VColumn<ConversationRow>[] {
  const ports = kind === "tcp" || kind === "udp";
  const cols: VColumn<ConversationRow>[] = [
    { id: "a", title: t("conv.col.a"), width: ports ? 180 : 150, mono: true, render: (c) => fmtEndpoint(c.a, c.aPort), sortValue: (c) => c.a },
    { id: "b", title: t("conv.col.b"), width: ports ? 180 : 150, mono: true, render: (c) => fmtEndpoint(c.b, c.bPort), sortValue: (c) => c.b },
    { id: "packets", title: t("conv.col.packets"), width: 70, align: "right", render: (c) => fmtInt(c.packets), sortValue: (c) => c.packets },
    { id: "bytes", title: t("conv.col.bytes"), width: 84, align: "right", render: (c) => fmtBytes(c.bytes), sortValue: (c) => c.bytes },
    { id: "ab", title: t("conv.col.ab"), width: 84, align: "right", render: (c) => fmtBytes(c.aToBBytes), sortValue: (c) => c.aToBBytes },
    { id: "ba", title: t("conv.col.ba"), width: 84, align: "right", render: (c) => fmtBytes(c.bToABytes), sortValue: (c) => c.bToABytes },
    { id: "start", title: t("conv.col.start"), width: 80, align: "right", mono: true, render: (c) => c.start.toFixed(3), sortValue: (c) => c.start },
    { id: "duration", title: t("conv.col.duration"), width: 90, align: "right", render: (c) => fmtDuration(c.duration), sortValue: (c) => c.duration },
  ];
  if (kind === "tcp") {
    cols.push({ id: "state", title: t("conv.col.state"), width: 150, render: (c) => (c.state ? t(`state.${c.state}` as MessageKey) : ""), sortValue: (c) => c.state ?? "" });
  }
  return cols;
}

export function ConversationsPanel() {
  const [kind, setKind] = useState<ConversationKind>("tcp");
  const [selected, setSelected] = useState<string | null>(null);
  const { data, error, reload } = useBackend(() => api.conversations(kind), [kind]);
  const cols = useMemo(() => columns(kind), [kind]);
  const key = (c: ConversationRow) => `${c.a}|${c.aPort}|${c.b}|${c.bPort}|${c.stream?.id ?? ""}`;

  return (
    <div className="col" style={{ flex: 1, minHeight: 0 }}>
      <div className="tool-bar">
        <div className="segmented">
          {KINDS.map((k) => (
            <button key={k} className={kind === k ? "is-active" : ""} onClick={() => setKind(k)}>
              {t(`conv.${k}` as MessageKey)}
            </button>
          ))}
        </div>
        <span className="muted">{data ? fmtInt(data.length) : ""}</span>
        <span className="grow" />
        <button className="icon-btn" title={t("common.refresh")} onClick={reload}>
          <Icon name="refresh" />
        </button>
      </div>
      <QueryError error={error} />
      <div className="tool-body" style={{ overflow: "hidden" }}>
        <VirtualTable
          key={kind}
          columns={cols}
          rows={data ?? []}
          rowKey={key}
          selectedKey={selected}
          initialSort={{ id: "bytes", desc: true }}
          onSelect={(c) => {
            setSelected(key(c));
            if (c.stream) useStore.getState().focusOnStream(c.stream, useStore.getState().dockTab);
          }}
          onActivate={(c) => applyFilterText(c.filter)}
          onContextMenu={(e, c) => {
            setSelected(key(c));
            const stream = c.stream;
            showContextMenu(e, [
              { label: t("ctx.applyFilter"), onSelect: () => applyFilterText(c.filter) },
              { label: t("ctx.andFilter"), onSelect: () => filterByTerm(c.filter, "and", true) },
              { label: t("ctx.notFilter"), onSelect: () => filterByTerm(c.filter, "not", true) },
              ...(stream
                ? [
                    { kind: "separator" as const },
                    { label: t("conv.open"), onSelect: () => useStore.getState().focusOnStream(stream, "streams") },
                    { label: t("ctx.sequence"), onSelect: () => useStore.getState().focusOnStream(stream, "sequence") },
                  ]
                : []),
              { kind: "separator" },
              { label: t("ctx.copyFilter"), onSelect: () => void copy(c.filter) },
            ]);
          }}
        />
      </div>
    </div>
  );
}
