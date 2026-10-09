import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { create } from "zustand";

export type MenuEntry =
  | { kind?: "item"; label: string; onSelect: () => void; disabled?: boolean; shortcut?: string; checked?: boolean }
  | { kind: "separator" }
  | { kind: "label"; label: string };

interface CtxState {
  open: { x: number; y: number; items: MenuEntry[] } | null;
  show: (x: number, y: number, items: MenuEntry[]) => void;
  hide: () => void;
}

export const useContextMenu = create<CtxState>((set) => ({
  open: null,
  show: (x, y, items) => set({ open: { x, y, items } }),
  hide: () => set({ open: null }),
}));

/** Opens the shared context menu at the mouse position. */
export function showContextMenu(e: React.MouseEvent, items: MenuEntry[]) {
  e.preventDefault();
  e.stopPropagation();
  useContextMenu.getState().show(e.clientX, e.clientY, items);
}

/** Opens the shared context menu at viewport coordinates (keyboard invocation). */
export function showContextMenuAt(x: number, y: number, items: MenuEntry[]) {
  useContextMenu.getState().show(x, y, items);
}

export function MenuItems({ items, onDone }: { items: MenuEntry[]; onDone: () => void }) {
  return (
    <>
      {items.map((it, i) => {
        if (it.kind === "separator") return <div key={i} className="menu-sep" />;
        if (it.kind === "label") return <div key={i} className="menu-label">{it.label}</div>;
        return (
          <button
            key={i}
            className="menu-item"
            role="menuitem"
            disabled={it.disabled}
            onClick={() => {
              onDone();
              it.onSelect();
            }}
          >
            {it.checked ? <span className="check">✓</span> : null}
            <span>{it.label}</span>
            {it.shortcut ? <span className="shortcut">{it.shortcut}</span> : null}
          </button>
        );
      })}
    </>
  );
}

export function ContextMenuHost() {
  const { open, hide } = useContextMenu();
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ x: 0, y: 0 });

  useLayoutEffect(() => {
    if (!open || !ref.current) return;
    // Keyboard users land on the first item.
    ref.current.querySelector<HTMLElement>(".menu-item:not(:disabled)")?.focus();
    const r = ref.current.getBoundingClientRect();
    setPos({
      x: Math.min(open.x, window.innerWidth - r.width - 4),
      y: Math.min(open.y, window.innerHeight - r.height - 4),
    });
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const close = (e: Event) => {
      if (e instanceof KeyboardEvent && e.key !== "Escape") return;
      if (e instanceof MouseEvent && ref.current?.contains(e.target as Node)) return;
      hide();
    };
    window.addEventListener("mousedown", close, true);
    window.addEventListener("keydown", close, true);
    window.addEventListener("blur", hide);
    window.addEventListener("resize", hide);
    return () => {
      window.removeEventListener("mousedown", close, true);
      window.removeEventListener("keydown", close, true);
      window.removeEventListener("blur", hide);
      window.removeEventListener("resize", hide);
    };
  }, [open, hide]);

  if (!open) return null;
  return (
    <div
      ref={ref}
      className="ctx-menu"
      role="menu"
      style={{ left: pos.x || open.x, top: pos.y || open.y }}
      onKeyDown={(e) => {
        if (e.key !== "ArrowDown" && e.key !== "ArrowUp" && e.key !== "Home" && e.key !== "End") return;
        e.preventDefault();
        const items = [...(ref.current?.querySelectorAll<HTMLElement>(".menu-item:not(:disabled)") ?? [])];
        if (!items.length) return;
        const i = items.indexOf(document.activeElement as HTMLElement);
        const next =
          e.key === "Home" ? 0 : e.key === "End" ? items.length - 1 : (i + (e.key === "ArrowDown" ? 1 : -1) + items.length) % items.length;
        items[next].focus();
      }}
    >
      <MenuItems items={open.items} onDone={hide} />
    </div>
  );
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
