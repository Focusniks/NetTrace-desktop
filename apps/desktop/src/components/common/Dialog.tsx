import { useEffect, useRef, type ReactNode } from "react";

import { t } from "../../i18n";
import { Icon } from "./Icon";

interface Props {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  width?: number;
  /** False for dialogs with edits a stray click outside must not discard. */
  dismissOnBackdrop?: boolean;
}

const FOCUSABLE = 'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function Dialog({ title, onClose, children, footer, width, dismissOnBackdrop = true }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    // Focus an element marked data-autofocus, else the first field, else the
    // primary action (so Enter never triggers a secondary button such as
    // "skip"), else the dialog itself so keys never reach the page behind it.
    const root = ref.current;
    const first =
      root?.querySelector<HTMLElement>("[data-autofocus]") ??
      root?.querySelector<HTMLElement>("input, select, textarea") ??
      root?.querySelector<HTMLElement>("button.btn-primary") ??
      root?.querySelector<HTMLElement>("button:not(.icon-btn)") ??
      root;
    first?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        closeRef.current();
      } else if (e.key === "Tab" && root) {
        // Keep focus inside the dialog (it is modal).
        const items = [...root.querySelectorAll<HTMLElement>(FOCUSABLE)];
        const active = document.activeElement as HTMLElement | null;
        const inside = active != null && root.contains(active);
        if (items.length === 0) {
          e.preventDefault();
        } else if (e.shiftKey && (!inside || active === items[0] || active === root)) {
          e.preventDefault();
          items[items.length - 1].focus();
        } else if (!e.shiftKey && (!inside || active === items[items.length - 1])) {
          e.preventDefault();
          items[0].focus();
        }
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => {
      window.removeEventListener("keydown", onKey, true);
      prev?.focus?.();
    };
  }, []);

  return (
    <div className="dialog-backdrop" onMouseDown={(e) => dismissOnBackdrop && e.target === e.currentTarget && onClose()}>
      <div ref={ref} className="dialog" tabIndex={-1} role="dialog" aria-modal="true" aria-label={title} style={width ? { width } : undefined}>
        <div className="dialog-title">
          <span>{title}</span>
          <button className="icon-btn" onClick={onClose} aria-label={t("dialog.close")}>
            <Icon name="close" />
          </button>
        </div>
        <div className="dialog-body">{children}</div>
        {footer ? <div className="dialog-footer">{footer}</div> : null}
      </div>
    </div>
  );
}
