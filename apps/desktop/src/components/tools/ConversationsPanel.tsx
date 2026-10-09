import { useMemo, useState } from "react";

import { api } from "../../api/client";
import type { ConversationKind, ConversationRow, ConversationSort } from "../../api/types";
import { t, type MessageKey } from "../../i18n";
import { fmtBytes, fmtDuration, fmtEndpoint, fmtInt } from "../../lib/format";
import { applyFilterText, copy, filterByTerm } from "../../state/actions";
import { useStore } from "../../state/store";
import { showContextMenu } from "../common/ContextMenu";
import { Icon } from "../common/Icon";
import { VirtualTable, type VColumn } from "../common/VirtualTable";
import { QueryError } from "./useBackend";
import { useDebounced, usePagedTable } from "./usePagedTable";

const KINDS: ConversationKind[] = ["eth", "ip", "tcp", "udp"];
/** Columns the backend can sort by (column id = sort key). */
const SORTS: ConversationSort[] = ["a", "b", "packets", "bytes", "ab", "ba", "start", "duration", "state"];

function columns(kind: ConversationKind): VColumn<ConversationRow>[] {
  const ports = kind === "tcp" || kind === "udp";
  const cols: VColumn<ConversationRow>[] = [
    { id: "a", sortable: true, title: t("conv.col.a"), width: ports ? 180 : 150, mono: true, render: (c) => fmtEndpoint(c.a, c.aPort) },
    { id: "b", sortable: true, title: t("conv.col.b"), width: ports ? 180 : 150, mono: true, render: (c) => fmtEndpoint(c.b, c.bPort) },
    { id: "packets", sortable: true, title: t("conv.col.packets"), width: 70, align: "right", render: (c) => fmtInt(c.packets) },
    { id: "bytes", sortable: true, title: t("conv.col.bytes"), width: 84, align: "right", render: (c) => fmtBytes(c.bytes) },
    { id: "ab", sortable: true, title: t("conv.col.ab"), width: 84, align: "right", render: (c) => fmtBytes(c.aToBBytes) },
    { id: "ba", sortable: true, title: t("conv.col.ba"), width: 84, align: "right", render: (c) => fmtBytes(c.bToABytes) },
    { id: "start", sortable: true, title: t("conv.col.start"), width: 80, align: "right", mono: true, render: (c) => c.start.toFixed(3) },
    { id: "duration", sortable: true, title: t("conv.col.duration"), width: 90, align: "right", render: (c) => fmtDuration(c.duration) },
  ];
  if (kind === "tcp") {
    cols.push({ id: "state", sortable: true, title: t("conv.col.state"), width: 150, render: (c) => (c.state ? t(`state.${c.state}` as MessageKey) : "") });
  }
  return cols;
}

export function ConversationsPanel() {
  const [kind, setKind] = useState<ConversationKind>("tcp");
  const [selected, setSelected] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<{ id: ConversationSort; desc: boolean }>({ id: "bytes", desc: true });
  const query = useDebounced(search.trim());
  // "State" exists only for TCP: other kinds fall back to bytes.
  const sortId = sort.id === "state" && kind !== "tcp" ? "bytes" : sort.id;
  const table = usePagedTable(`${kind}|${sortId}|${sort.desc}|${query}`, (offset, limit) =>
    api.conversationsPage({ kind, sort: sortId, desc: sort.desc, offset, limit, search: query || null }),
  );
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
        <input spellCheck={false} autoComplete="off" className="input grow" placeholder={t("conv.search")} value={search} onChange={(e) => setSearch(e.target.value)} />
        <span className="muted">{table.loaded ? fmtInt(table.total) : ""}</span>
        <button className="icon-btn" title={t("common.refresh")} onClick={table.reload}>
          <Icon name="refresh" />
        </button>
      </div>
      <QueryError error={table.error} />
      <div className="tool-body" style={{ overflow: "hidden" }}>
        <VirtualTable
          key={kind}
          columns={cols}
          source={table}
          rowKey={key}
          selectedKey={selected}
          sort={{ id: sortId, desc: sort.desc }}
          onSortChange={(id, desc) => {
            const s = SORTS.find((x) => x === id);
            if (s) setSort({ id: s, desc });
          }}
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
