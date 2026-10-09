import { useMemo, useState } from "react";

import { api } from "../../api/client";
import type { HostRow } from "../../api/types";
import { t } from "../../i18n";
import { fmtBytes, fmtInt } from "../../lib/format";
import { addrFilter } from "../../lib/filters";
import { applyFilterText, copy, filterByTerm } from "../../state/actions";
import { showContextMenu } from "../common/ContextMenu";
import { Icon } from "../common/Icon";
import { VirtualTable, type VColumn } from "../common/VirtualTable";
import { useBackend } from "./useBackend";

const COLS: VColumn<HostRow>[] = [
  { id: "address", title: t("hosts.col.address"), width: 200, mono: true, render: (h) => h.address, sortValue: (h) => h.address },
  { id: "mac", title: t("hosts.col.mac"), width: 130, mono: true, render: (h) => h.mac ?? "", sortValue: (h) => h.mac ?? "" },
  { id: "packets", title: t("hosts.col.packets"), width: 74, align: "right", render: (h) => fmtInt(h.packets), sortValue: (h) => h.packets },
  { id: "bytes", title: t("hosts.col.bytes"), width: 84, align: "right", render: (h) => fmtBytes(h.bytes), sortValue: (h) => h.bytes },
  { id: "tx", title: t("hosts.col.tx"), width: 84, align: "right", render: (h) => fmtBytes(h.txBytes), sortValue: (h) => h.txBytes },
  { id: "rx", title: t("hosts.col.rx"), width: 84, align: "right", render: (h) => fmtBytes(h.rxBytes), sortValue: (h) => h.rxBytes },
  { id: "first", title: t("hosts.col.first"), width: 84, align: "right", mono: true, render: (h) => h.firstSeen.toFixed(3), sortValue: (h) => h.firstSeen },
  { id: "last", title: t("hosts.col.last"), width: 84, align: "right", mono: true, render: (h) => h.lastSeen.toFixed(3), sortValue: (h) => h.lastSeen },
  { id: "protocols", title: t("hosts.col.protocols"), width: 260, render: (h) => h.protocols.join(", "), title_attr: (h) => h.protocols.join(", ") },
];

export function HostsPanel() {
  const { data, reload } = useBackend(() => api.hosts(), []);
  const [selected, setSelected] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const rows = useMemo(() => {
    const q = search.trim().toLowerCase();
    const all = data ?? [];
    return q ? all.filter((h) => h.address.toLowerCase().includes(q) || (h.mac ?? "").includes(q)) : all;
  }, [data, search]);

  return (
    <div className="col" style={{ flex: 1, minHeight: 0 }}>
      <div className="tool-bar">
        <input spellCheck={false} autoComplete="off" className="input grow" placeholder={t("hosts.search")} value={search} onChange={(e) => setSearch(e.target.value)} />
        <span className="muted">{fmtInt(rows.length)}</span>
        <button className="icon-btn" title={t("common.refresh")} onClick={reload}>
          <Icon name="refresh" />
        </button>
      </div>
      <div className="tool-body" style={{ overflow: "hidden" }}>
        <VirtualTable
          columns={COLS}
          rows={rows}
          rowKey={(h) => h.address}
          selectedKey={selected}
          initialSort={{ id: "bytes", desc: true }}
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
