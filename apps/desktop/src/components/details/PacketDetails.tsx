import { useEffect, useMemo, useRef, useState } from "react";

import type { PacketField } from "../../api/types";
import { fieldLabel, t } from "../../i18n";
import { allExpansionKeys, ancestorKeys, flatten, type FlatNode } from "../../lib/tree";
import { copy, filterByTerm, openStream } from "../../state/actions";
import { useStore } from "../../state/store";
import { showContextMenu, type MenuEntry } from "../common/ContextMenu";
import { Icon } from "../common/Icon";

/** Russian rendering of the Frame heading; other headings keep protocol wording. */
function frameHeading(name: string): string {
  const m = /^Frame (\d+): (\d+) bytes on wire \((\d+) bits\), (\d+) bytes captured \((\d+) bits\)(?: on interface (\d+))?/.exec(name);
  if (!m) return name;
  return `Кадр ${m[1]}: ${m[2]} байт в канале (${m[3]} бит), захвачено ${m[4]} байт (${m[5]} бит)${m[6] ? `, интерфейс ${m[6]}` : ""}`;
}

export function nodeLabel(n: PacketField): string {
  let text: string;
  if (n.field === "frame") text = frameHeading(n.name);
  else if (n.display) text = `${fieldLabel(n.field, n.name)}: ${n.display}`;
  else text = n.name || n.field;
  if (n.generated && !text.startsWith("[")) text = `[${text}]`;
  return text;
}

function isProtocolNode(fn: FlatNode): boolean {
  return fn.depth === 0 && !!fn.node.field;
}

const DEFAULT_EXPANDED = new Set<string>();

export function PacketDetails() {
  const detail = useStore((s) => s.detail);
  const loading = useStore((s) => s.detailLoading);
  const selectedKey = useStore((s) => s.selectedFieldKey);
  const setHighlight = useStore((s) => s.setHighlight);
  const [expanded, setExpanded] = useState<Set<string>>(DEFAULT_EXPANDED);
  const [showAbbrev, setShowAbbrev] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const tree = detail?.tree;

  // Reveal the node selected from the hex view.
  useEffect(() => {
    if (!tree || !selectedKey) return;
    const need = ancestorKeys(tree, selectedKey).filter((k) => !expanded.has(k));
    if (need.length) setExpanded((prev) => new Set([...prev, ...need]));
  }, [tree, selectedKey, expanded]);

  const flat = useMemo(() => (tree ? flatten(tree, expanded) : []), [tree, expanded]);

  useEffect(() => {
    if (!selectedKey || !ref.current) return;
    const el = ref.current.querySelector<HTMLElement>(`[data-path="${selectedKey}"]`);
    el?.scrollIntoView({ block: "nearest" });
  }, [selectedKey, flat]);

  const toggle = (k: string, open?: boolean) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      const want = open ?? !next.has(k);
      if (want) next.add(k);
      else next.delete(k);
      return next;
    });

  const select = (fn: FlatNode) => {
    const n = fn.node;
    setHighlight(n.len > 0 ? { start: n.start, len: n.len } : null, fn.path);
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (!flat.length) return;
    const idx = Math.max(0, flat.findIndex((f) => f.path === selectedKey));
    const cur = flat[idx];
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        select(flat[Math.min(flat.length - 1, selectedKey ? idx + 1 : 0)]);
        break;
      case "ArrowUp":
        e.preventDefault();
        select(flat[Math.max(0, idx - 1)]);
        break;
      case "ArrowRight":
        e.preventDefault();
        if (cur?.hasChildren && !cur.expanded) toggle(cur.expKey, true);
        else if (cur?.expanded && flat[idx + 1]) select(flat[idx + 1]);
        break;
      case "ArrowLeft": {
        e.preventDefault();
        if (cur?.expanded) toggle(cur.expKey, false);
        else if (cur?.parentPath) {
          const parent = flat.find((f) => f.path === cur.parentPath);
          if (parent) select(parent);
        }
        break;
      }
      case "Enter":
      case " ":
        if (cur?.hasChildren) {
          e.preventDefault();
          toggle(cur.expKey);
        }
        break;
    }
  };

  const menu = (e: React.MouseEvent, fn: FlatNode) => {
    select(fn);
    const n = fn.node;
    const label = nodeLabel(n);
    const items: MenuEntry[] = [
      { label: t("ctx.copyFieldValue"), onSelect: () => void copy(label) },
      { label: t("ctx.copyCell"), disabled: !n.display, onSelect: () => void copy(n.display) },
      { label: t("ctx.copyField"), disabled: !n.field, onSelect: () => void copy(n.field) },
    ];
    if (n.len > 0 && detail) {
      const bytes = detail.bytes.slice(n.start, n.start + n.len);
      items.push({ label: t("ctx.copyHex"), onSelect: () => void copy(bytes.map((b) => b.toString(16).padStart(2, "0")).join(" ")) });
    }
    if (n.filter) {
      const term = n.filter;
      items.push(
        { kind: "separator" },
        { label: t("ctx.applyFilter"), onSelect: () => filterByTerm(term, "replace", true) },
        { label: t("ctx.prepareFilter"), onSelect: () => filterByTerm(term, "replace", false) },
        { label: t("ctx.andFilter"), onSelect: () => filterByTerm(term, "and", true) },
        { label: t("ctx.orFilter"), onSelect: () => filterByTerm(term, "or", true) },
        { label: t("ctx.notFilter"), onSelect: () => filterByTerm(term, "not", true) },
      );
    }
    if (detail?.stream) {
      const stream = detail.stream;
      items.push(
        { kind: "separator" },
        { label: t("ctx.followStream", { kind: stream.kind.toUpperCase(), id: stream.id }), onSelect: () => openStream(stream) },
        { label: t("ctx.sequence"), onSelect: () => openStream(stream, "sequence") },
      );
    }
    items.push(
      { kind: "separator" },
      {
        label: t("ctx.expandSubtree"),
        disabled: !fn.hasChildren,
        onSelect: () => {
          const keys = allExpansionKeys([n]).map((k) => (fn.expKey.includes("/") ? `${fn.expKey.slice(0, fn.expKey.lastIndexOf("/"))}/${k}` : k));
          setExpanded((prev) => new Set([...prev, ...keys]));
        },
      },
      { label: t("ctx.expandAll"), onSelect: () => tree && setExpanded(new Set(allExpansionKeys(tree))) },
      { label: t("ctx.collapseAll"), onSelect: () => setExpanded(new Set()) },
      { kind: "separator" },
      { label: t("ctx.showAbbrev"), checked: showAbbrev, onSelect: () => setShowAbbrev((v) => !v) },
    );
    showContextMenu(e, items);
  };

  if (!detail) {
    return <div className="tool-note">{loading ? t("details.loading") : t("details.empty")}</div>;
  }

  return (
    <div ref={ref} className="tree" tabIndex={0} onKeyDown={onKeyDown} role="tree" aria-label={t("details.title")}>
      {flat.map((fn) => {
        const n = fn.node;
        const sev = n.severity ? ` sev-${n.severity}` : "";
        const streamLink = n.field === "tcp.stream" || n.field === "udp.stream";
        return (
          <div
            key={fn.path}
            data-path={fn.path}
            role="treeitem"
            aria-expanded={fn.hasChildren ? fn.expanded : undefined}
            aria-level={fn.depth + 1}
            aria-selected={selectedKey === fn.path}
            className={`tree-row${selectedKey === fn.path ? " is-selected" : ""}${isProtocolNode(fn) ? " is-protocol" : ""}${n.generated ? " is-generated" : ""}${sev}`}
            style={{ paddingLeft: 4 + fn.depth * 16 }}
            onMouseDown={() => select(fn)}
            onDoubleClick={() => {
              if (fn.hasChildren) toggle(fn.expKey);
              else if (streamLink && detail.stream) openStream(detail.stream);
            }}
            onContextMenu={(e) => menu(e, fn)}
            title={n.field ? `${n.field}${n.len ? ` · ${n.start}–${n.start + n.len - 1}` : ""}` : undefined}
          >
            <span
              className="tree-toggle"
              onMouseDown={(e) => {
                e.stopPropagation();
                if (fn.hasChildren) toggle(fn.expKey);
              }}
            >
              {fn.hasChildren ? <Icon name={fn.expanded ? "chevronDown" : "chevronRight"} /> : null}
            </span>
            <span className="tree-label selectable">{nodeLabel(n)}</span>
            {showAbbrev && n.field ? <span className="field-abbrev">{n.field}</span> : null}
          </div>
        );
      })}
    </div>
  );
}
