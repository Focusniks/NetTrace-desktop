import { useEffect, useLayoutEffect, useRef, useState } from "react";

import { Icon } from "./Icon";

export interface SelectOption<T extends string | number> {
  value: T;
  label: string;
  disabled?: boolean;
}

interface Props<T extends string | number> {
  value: T;
  options: SelectOption<T>[];
  onChange: (value: T) => void;
  ariaLabel?: string;
  className?: string;
  /** Minimum width of the closed control in px. */
  minWidth?: number;
}

/**
 * Dark dropdown rendered by the app itself. The native `<select>` popup is
 * drawn by the OS/WebView (light, unstyleable) and flashes white over the UI.
 */
export function Select<T extends string | number>({ value, options, onChange, ariaLabel, className, minWidth }: Props<T>) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [pos, setPos] = useState<{ left: number; top: number; width: number; maxHeight: number } | null>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const current = options.find((o) => o.value === value);

  const openList = () => {
    const idx = Math.max(0, options.findIndex((o) => o.value === value));
    setActive(idx);
    setOpen(true);
  };

  useLayoutEffect(() => {
    if (!open || !buttonRef.current) return;
    const r = buttonRef.current.getBoundingClientRect();
    const below = window.innerHeight - r.bottom - 8;
    const above = r.top - 8;
    const wanted = Math.min(320, options.length * 22 + 8);
    const maxHeight = Math.max(80, below >= wanted || below >= above ? below : above);
    const top = below >= wanted || below >= above ? r.bottom + 2 : Math.max(4, r.top - 2 - Math.min(wanted, maxHeight));
    setPos({ left: r.left, top, width: r.width, maxHeight: Math.min(320, maxHeight) });
  }, [open, options.length]);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (!listRef.current?.contains(t) && !buttonRef.current?.contains(t)) setOpen(false);
    };
    const close = () => setOpen(false);
    window.addEventListener("mousedown", onDown, true);
    window.addEventListener("resize", close);
    window.addEventListener("blur", close);
    return () => {
      window.removeEventListener("mousedown", onDown, true);
      window.removeEventListener("resize", close);
      window.removeEventListener("blur", close);
    };
  }, [open]);

  useEffect(() => {
    if (open) listRef.current?.querySelector<HTMLElement>(`[data-index="${active}"]`)?.scrollIntoView({ block: "nearest" });
  }, [open, active]);

  const pick = (o: SelectOption<T> | undefined) => {
    if (!o || o.disabled) return;
    onChange(o.value);
    setOpen(false);
    buttonRef.current?.focus();
  };

  const step = (dir: 1 | -1) => {
    let i = active;
    for (let n = 0; n < options.length; n++) {
      i = (i + dir + options.length) % options.length;
      if (!options[i].disabled) break;
    }
    setActive(i);
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (!open) {
      if (e.key === "ArrowDown" || e.key === "ArrowUp" || e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        openList();
      }
      return;
    }
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        step(1);
        break;
      case "ArrowUp":
        e.preventDefault();
        step(-1);
        break;
      case "Home":
        e.preventDefault();
        setActive(0);
        break;
      case "End":
        e.preventDefault();
        setActive(options.length - 1);
        break;
      case "Enter":
      case " ":
        e.preventDefault();
        pick(options[active]);
        break;
      case "Escape":
      case "Tab":
        if (e.key === "Escape") {
          e.preventDefault();
          e.stopPropagation();
        }
        setOpen(false);
        break;
    }
  };

  return (
    <>
      <button
        ref={buttonRef}
        type="button"
        className={`select dd-button${className ? ` ${className}` : ""}`}
        style={minWidth ? { minWidth } : undefined}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={ariaLabel}
        onClick={() => (open ? setOpen(false) : openList())}
        onKeyDown={onKeyDown}
      >
        <span className="dd-label">{current?.label ?? ""}</span>
        <Icon name="chevronDown" />
      </button>
      {open && pos ? (
        <div
          ref={listRef}
          className="dd-list"
          role="listbox"
          aria-label={ariaLabel}
          style={{ left: pos.left, top: pos.top, minWidth: pos.width, maxHeight: pos.maxHeight }}
        >
          {options.map((o, i) => (
            <div
              key={String(o.value)}
              data-index={i}
              role="option"
              aria-selected={o.value === value}
              aria-disabled={o.disabled || undefined}
              className={`dd-option${i === active ? " is-active" : ""}${o.value === value ? " is-selected" : ""}${o.disabled ? " is-disabled" : ""}`}
              onMouseEnter={() => setActive(i)}
              onMouseDown={(e) => {
                e.preventDefault();
                pick(o);
              }}
            >
              {o.label}
            </div>
          ))}
        </div>
      ) : null}
    </>
  );
}
