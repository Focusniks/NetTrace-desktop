import { useState } from "react";

import { api } from "../../api/client";
import type { HostRow, HostSort } from "../../api/types";
import { t } from "../../i18n";
import { fmtBytes, fmtInt } from "../../lib/format";
import { addrFilter } from "../../lib/filters";
import { applyFilterText, copy, filterByTerm } from "../../state/actions";
import { showContextMenu } from "../common/ContextMenu";
import { Icon } from "../common/Icon";
import { VirtualTable, type VColumn } from "../common/VirtualTable";
import { useDebounced, usePagedTable } from "./usePagedTable";
import { QueryError } from "./useBackend";

/** Columns the backend can sort by (column id = sort key). */
const SORTS: HostSort[] = ["address", "mac", "packets", "bytes", "tx", "rx", "first", "last"];

const COLS: VColumn<HostRow>[] = [
  { id: "address", sortable: true, title: t("hosts.col.address"), width: 200, mono: true, render: (h) => h.address },
  { id: "mac", sortable: true, title: t("hosts.col.mac"), width: 130, mono: true, render: (h) => h.mac ?? "" },
  { id: "packets", sortable: true, title: t("hosts.col.packets"), width: 74, align: "right", render: (h) => fmtInt(h.packets) },
  { id: "bytes", sortable: true, title: t("hosts.col.bytes"), width: 84, align: "right", render: (h) => fmtBytes(h.bytes) },
  { id: "tx", sortable: true, title: t("hosts.col.tx"), width: 84, align: "right", render: (h) => fmtBytes(h.txBytes) },
  { id: "rx", sortable: true, title: t("hosts.col.rx"), width: 84, align: "right", render: (h) => fmtBytes(h.rxBytes) },
  { id: "first", sortable: true, title: t("hosts.col.first"), width: 84, align: "right", mono: true, render: (h) => h.firstSeen.toFixed(3) },
  { id: "last", sortable: true, title: t("hosts.col.last"), width: 84, align: "right", mono: true, render: (h) => h.lastSeen.toFixed(3) },
  { id: "protocols", title: t("hosts.col.protocols"), width: 260, render: (h) => h.protocols.join(", "), title_attr: (h) => h.protocols.join(", ") },
];

export function HostsPanel() {
  const [selected, setSelected] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<{ id: HostSort; desc: boolean }>({ id: "bytes", desc: true });
  const query = useDebounced(search.trim());
  const table = usePagedTable(`${sort.id}|${sort.desc}|${query}`, (offset, limit) =>
    api.hostsPage({ sort: sort.id, desc: sort.desc, offset, limit, search: query || null }),
  );

  return (
    <div className="col" style={{ flex: 1, minHeight: 0 }}>
      <div className="tool-bar">
        <input spellCheck={false} autoComplete="off" className="input grow" placeholder={t("hosts.search")} value={search} onChange={(e) => setSearch(e.target.value)} />
        <span className="muted">{table.loaded ? fmtInt(table.total) : ""}</span>
        <button className="icon-btn" title={t("common.refresh")} onClick={table.reload}>
          <Icon name="refresh" />
        </button>
      </div>
      <QueryError error={table.error} />
      <div className="tool-body" style={{ overflow: "hidden" }}>
        <VirtualTable
          columns={COLS}
          source={table}
          rowKey={(h) => h.address}
          selectedKey={selected}
          sort={sort}
          onSortChange={(id, desc) => {
            const key = SORTS.find((s) => s === id);
            if (key) setSort({ id: key, desc });
          }}
          onSelect={(h) => setSelected(h.address)}
          onActivate={(h) => applyFilterText(h.filter)}
          onContextMenu={(e, h) => {
            setSelected(h.address);
            showContextMenu(e, [
              { label: t("hosts.filter"), onSelect: () => applyFilterText(h.filter) },
              { label: t("ctx.filterSrc"), onSelect: () => applyFilterText(addrFilter(h.address, "src")) },
              { label: t("ctx.filterDst"), onSelect: () => applyFilterText(addrFilter(h.address, "dst")) },
              { label: t("ctx.andFilter"), onSelect: () => filterByTerm(h.filter, "and", true) },
              { label: t("ctx.notFilter"), onSelect: () => filterByTerm(h.filter, "not", true) },
              { kind: "separator" },
              { label: t("ctx.copyCell"), onSelect: () => void copy(h.address) },
              { label: t("ctx.copyFilter"), onSelect: () => void copy(h.filter) },
            ]);
          }}
        />
      </div>
    </div>
  );
}
