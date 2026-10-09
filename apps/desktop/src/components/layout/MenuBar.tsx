import { useEffect, useRef, useState } from "react";

import { t, type MessageKey } from "../../i18n";
import type { TimeFormat } from "../../lib/format";
import { commands } from "../../state/commands";
import { useStore } from "../../state/store";
import { MenuItems, type MenuEntry } from "../common/ContextMenu";
import { Logo } from "../common/Icon";

function useMenus(): { id: MessageKey; items: MenuEntry[] }[] {
  const capture = useStore((s) => s.capture);
  const settings = useStore((s) => s.settings);
  const dockOpen = useStore((s) => s.dockOpen);
  const dockTab = useStore((s) => s.dockTab);
  const hasStream = useStore((s) => !!s.detail?.stream);
  const capturing = useStore((s) => !!s.capture?.live && s.progress?.state !== "done" && s.progress?.state !== "failed" && s.progress?.capture?.running !== false);
  const st = useStore.getState();
  const none = !capture;
  const tf = (f: TimeFormat, key: MessageKey): MenuEntry => ({
    label: t(key),
    checked: settings.timeFormat === f,
    onSelect: () => st.setTimeFormat(f),
  });
  const dock = (tab: Parameters<typeof commands.dock>[0], key: MessageKey, shortcut?: string): MenuEntry => ({
    label: t(key),
    checked: dockOpen && dockTab === tab,
    disabled: none,
    shortcut,
    onSelect: () => commands.dock(tab),
  });
  const recent: MenuEntry[] = settings.recentFiles.length
    ? settings.recentFiles.map((p) => ({ label: p, onSelect: () => void commands.openPath(p) }))
    : [{ label: t("action.noRecent"), disabled: true, onSelect: () => undefined }];

  return [
    {
      id: "menu.file",
      items: [
        { label: t("action.open"), shortcut: "Ctrl+O", onSelect: () => void commands.open() },
        { kind: "label", label: t("action.openRecent") },
        ...recent,
        { kind: "separator" },
        { label: t("action.export"), shortcut: "Ctrl+S", disabled: none, onSelect: () => void commands.exportView() },
        { label: t("action.properties"), disabled: none, onSelect: () => st.setDialog("properties") },
        { kind: "separator" },
        { label: t("action.close"), shortcut: "Ctrl+W", disabled: none, onSelect: () => void commands.close() },
      ],
    },
    {
      id: "menu.edit",
      items: [
        { label: t("action.find"), shortcut: "Ctrl+F", disabled: none, onSelect: commands.find },
        { label: t("action.goto"), shortcut: "Ctrl+G", disabled: none, onSelect: commands.goto },
        { kind: "separator" },
        { label: t("action.coloringRules"), onSelect: () => st.setDialog("coloring") },
      ],
    },
    {
      id: "menu.view",
      items: [
        { kind: "label", label: t("action.timeFormat") },
        tf("relative", "time.relative"),
        tf("delta", "time.delta"),
        tf("local", "time.local"),
        tf("utc", "time.utc"),
        { kind: "separator" },
        { label: t("action.colorize"), checked: settings.colorize, onSelect: commands.toggleColorize },
        { label: t("action.coloringRules"), onSelect: () => st.setDialog("coloring") },
        { kind: "separator" },
        dock("timeline", "dock.timeline", "Ctrl+T"),
        dock("indicators", "dock.indicators"),
      ],
    },
    {
      id: "menu.capture",
      items: [
        { label: t("action.captureInterfaces"), shortcut: "Ctrl+K", onSelect: commands.captureDialog },
        { label: t("action.captureStart"), shortcut: "Ctrl+E", disabled: capturing, onSelect: commands.captureDialog },
        { label: t("action.captureStop"), shortcut: "Ctrl+E", disabled: !capturing, onSelect: () => void commands.stopCapture() },
        { label: t("action.captureRestart"), shortcut: "Ctrl+R", disabled: !settings.lastCapture, onSelect: () => void commands.restartCapture() },
        { kind: "separator" },
        { label: t("toolbar.autoScroll"), checked: settings.autoScroll, onSelect: commands.toggleAutoScroll },
      ],
    },
    {
      id: "menu.analyze",
      items: [
        { label: t("action.applyFilter"), shortcut: "Enter", disabled: none, onSelect: () => void st.applyFilter() },
        { label: t("action.filterBuilder"), onSelect: () => st.setBuilderOpen(true) },
        { label: t("action.clearFilter"), disabled: none, onSelect: () => void st.applyFilter("") },
        { kind: "separator" },
        { label: t("action.followStream"), shortcut: "Enter", disabled: !hasStream, onSelect: () => commands.followSelected("streams") },
        { label: t("action.sequence"), disabled: !hasStream, onSelect: () => commands.followSelected("sequence") },
        { kind: "separator" },
        dock("indicators", "dock.indicators"),
      ],
    },
    {
      id: "menu.statistics",
      items: [
        { label: t("action.properties"), disabled: none, onSelect: () => st.setDialog("properties") },
        { kind: "separator" },
        dock("statistics", "stats.hierarchy"),
        dock("conversations", "dock.conversations"),
        dock("hosts", "dock.hosts"),
        dock("streams", "dock.streams"),
        dock("timeline", "dock.timeline"),
      ],
    },
    {
      id: "menu.tools",
      items: [
        { label: t("action.coloringRules"), onSelect: () => st.setDialog("coloring") },
        { label: t("action.fieldReference"), onSelect: () => st.setDialog("fields") },
      ],
    },
    {
      id: "menu.help",
      items: [
        { label: t("action.shortcuts"), shortcut: "F1", onSelect: () => st.setDialog("shortcuts") },
        { label: t("action.fieldReference"), onSelect: () => st.setDialog("fields") },
        { kind: "separator" },
        { label: t("action.about"), onSelect: () => st.setDialog("about") },
      ],
    },
  ];
}

export function MenuBar() {
  const menus = useMenus();
  const [open, setOpen] = useState<MessageKey | null>(null);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(null);
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(null);
    window.addEventListener("mousedown", onDown);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onDown);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div className="menubar" ref={ref} role="menubar">
      <div className="menubar-brand">
        <Logo />
        {t("app.short")}
      </div>
      {menus.map((m) => (
        <div key={m.id} className={`menubar-item${open === m.id ? " is-open" : ""}`}>
          <button
            role="menuitem"
            aria-haspopup="true"
            aria-expanded={open === m.id}
            onClick={() => setOpen(open === m.id ? null : m.id)}
            onMouseEnter={() => open && setOpen(m.id)}
            onKeyDown={(e) => {
              const i = menus.findIndex((x) => x.id === m.id);
              if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
                e.preventDefault();
                const next = menus[(i + (e.key === "ArrowRight" ? 1 : -1) + menus.length) % menus.length];
                const buttons = ref.current?.querySelectorAll<HTMLButtonElement>(".menubar-item > button");
                buttons?.[menus.indexOf(next)]?.focus();
                if (open) setOpen(next.id);
              } else if (e.key === "ArrowDown") {
                e.preventDefault();
                setOpen(m.id);
                requestAnimationFrame(() =>
                  ref.current?.querySelector<HTMLElement>(".menubar-item.is-open .menu-item:not(:disabled)")?.focus(),
                );
              }
            }}
          >
            {t(m.id)}
          </button>
          {open === m.id ? (
            <div
              className="menu"
              role="menu"
              onKeyDown={(e) => {
                if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
                e.preventDefault();
                const items = [...e.currentTarget.querySelectorAll<HTMLElement>(".menu-item:not(:disabled)")];
                const i = items.indexOf(document.activeElement as HTMLElement);
                items[(i + (e.key === "ArrowDown" ? 1 : -1) + items.length) % items.length]?.focus();
              }}
            >
              <MenuItems items={m.items} onDone={() => setOpen(null)} />
            </div>
          ) : null}
        </div>
      ))}
    </div>
  );
}
