import { useEffect, useMemo, useRef, useState } from "react";

import { api } from "../../api/client";
import type { FieldInfo, FilterError } from "../../api/types";
import { t, type MessageKey } from "../../i18n";
import { useStore } from "../../state/store";
import { showContextMenu } from "../common/ContextMenu";
import { Icon } from "../common/Icon";
import { FilterBuilder } from "./FilterBuilder";

type Validity = "neutral" | "valid" | "invalid";

export function filterErrorText(e: FilterError): string {
  const key = `filter.err.${e.code}` as MessageKey;
  const text = t(key, { detail: e.detail });
  return text === key ? e.code : text;
}

/** Token being typed at the caret (a field-name prefix), with its span. */
function tokenAt(text: string, caret: number): { start: number; word: string } | null {
  let start = caret;
  while (start > 0 && /[A-Za-z0-9_.]/.test(text[start - 1])) start--;
  const word = text.slice(start, caret);
  if (!word || /^[0-9]/.test(word)) return null;
  // Only suggest in field position: not right after a comparison operator.
  const before = text.slice(0, start).trimEnd();
  if (/(==|!=|<=|>=|<|>|\bcontains|\beq|\bne|\blt|\bgt|\ble|\bge)$/.test(before)) return null;
  return { start, word };
}

export function FilterBar() {
  const filterText = useStore((s) => s.filterText);
  const appliedFilter = useStore((s) => s.appliedFilter);
  const filterError = useStore((s) => s.filterError);
  const busy = useStore((s) => s.filterBusy);
  const fields = useStore((s) => s.fields);
  const history = useStore((s) => s.settings.filterHistory);
  const builderOpen = useStore((s) => s.builderOpen);
  const capture = useStore((s) => s.capture);
  const { setFilterText, applyFilter, setBuilderOpen } = useStore.getState();

  const inputRef = useRef<HTMLInputElement>(null);
  const [validity, setValidity] = useState<Validity>("neutral");
  const [error, setError] = useState<FilterError | null>(null);
  const [caret, setCaret] = useState(0);
  const [acIndex, setAcIndex] = useState(0);
  const [acOpen, setAcOpen] = useState(false);
  /** True once the user navigated the suggestions with arrows; only then Enter accepts one. */
  const [acTouched, setAcTouched] = useState(false);

  // Live validation (debounced) — same parser as the backend filter engine.
  useEffect(() => {
    const text = filterText.trim();
    if (!text) {
      setValidity("neutral");
      setError(null);
      return;
    }
    let cancelled = false;
    const id = setTimeout(() => {
      api
        .validateFilter(text)
        .then((err) => {
          if (cancelled) return;
          setValidity(err ? "invalid" : "valid");
          setError(err);
        })
        .catch(() => {
          if (cancelled) return;
          setValidity("neutral");
          setError(null);
        });
    }, 150);
    return () => {
      cancelled = true;
      clearTimeout(id);
    };
  }, [filterText]);

  useEffect(() => {
    if (filterError) {
      setValidity("invalid");
      setError(filterError);
    }
  }, [filterError]);

  const token = tokenAt(filterText, caret);
  const suggestions = useMemo<FieldInfo[]>(() => {
    if (!token || token.word.length < 1) return [];
    const w = token.word.toLowerCase();
    const starts = fields.filter((f) => f.abbrev.startsWith(w) && f.abbrev !== w);
    return starts.slice(0, 40);
  }, [fields, token?.word]);
  const showAc = acOpen && suggestions.length > 0;

  const accept = (f: FieldInfo) => {
    if (!token) return;
    const next = filterText.slice(0, token.start) + f.abbrev + filterText.slice(caret);
    setFilterText(next);
    const pos = token.start + f.abbrev.length;
    requestAnimationFrame(() => {
      inputRef.current?.setSelectionRange(pos, pos);
      setCaret(pos);
    });
    setAcOpen(false);
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (showAc) {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setAcTouched(true);
        setAcIndex((i) => Math.min(suggestions.length - 1, i + 1));
        return;
      }
      if (e.key === "ArrowUp") {
        e.preventDefault();
        setAcTouched(true);
        setAcIndex((i) => Math.max(0, i - 1));
        return;
      }
      if (e.key === "Tab" || (e.key === "Enter" && acTouched && suggestions[acIndex])) {
        e.preventDefault();
        accept(suggestions[acIndex]);
        return;
      }
      if (e.key === "Escape") {
        setAcOpen(false);
        return;
      }
    }
    if (e.key === "Enter") {
      e.preventDefault();
      setAcOpen(false);
      void applyFilter();
    } else if (e.key === "Escape") {
      setFilterText(appliedFilter);
    }
  };

  const historyMenu = (e: React.MouseEvent) => {
    showContextMenu(
      e,
      history.length
        ? history.map((h) => ({
            label: h.length > 90 ? `${h.slice(0, 90)}…` : h,
            onSelect: () => {
              setFilterText(h);
              void applyFilter(h);
            },
          }))
        : [{ kind: "label" as const, label: t("common.none") }],
    );
  };

  const cls = `filter-input${validity === "valid" ? " is-valid" : validity === "invalid" ? " is-invalid" : ""}${appliedFilter && appliedFilter === filterText.trim() ? " is-applied" : ""}`;

  return (
    <div className="filterbar">
      <div className="filter-field">
        <span className="filter-icon">
          <Icon name="filter" />
        </span>
        <input
          ref={inputRef}
          id="display-filter"
          className={cls}
          value={filterText}
          placeholder={t("filter.placeholder")}
          spellCheck={false}
          autoComplete="off"
          aria-label={t("action.applyFilter")}
          aria-invalid={validity === "invalid"}
          onChange={(e) => {
            setFilterText(e.target.value);
            setCaret(e.target.selectionStart ?? e.target.value.length);
            setAcOpen(true);
            setAcIndex(0);
            setAcTouched(false);
          }}
          onKeyDown={onKeyDown}
          onKeyUp={(e) => setCaret(e.currentTarget.selectionStart ?? 0)}
          onClick={(e) => setCaret(e.currentTarget.selectionStart ?? 0)}
          onBlur={() => setTimeout(() => setAcOpen(false), 120)}
        />
        {showAc ? (
          <div className="autocomplete" role="listbox">
            {suggestions.map((f, i) => (
              <div
                key={f.abbrev}
                role="option"
                aria-selected={i === acIndex}
                className={`ac-item${i === acIndex ? " is-active" : ""}`}
                onMouseDown={(e) => {
                  e.preventDefault();
                  accept(f);
                }}
              >
                <span className="ac-abbrev">{f.abbrev}</span>
                <span className="ac-name">{f.name}</span>
                <span className="ac-kind">
                  {f.kind}
                  {f.indexed ? " ⚡" : ""}
                </span>
              </div>
            ))}
          </div>
        ) : null}
        {validity === "invalid" && error ? <div className="filter-error">{filterErrorText(error)}</div> : null}
      </div>
      <button className="tb-btn" title={t("filter.history")} onClick={historyMenu} aria-label={t("filter.history")}>
        <Icon name="chevronDown" />
      </button>
      <button className="btn btn-primary" disabled={!capture || busy} onClick={() => void applyFilter()}>
        {busy ? t("filter.applying") : t("filter.apply")}
      </button>
      <button
        className="btn"
        disabled={!filterText && !appliedFilter}
        onClick={() => {
          setFilterText("");
          void applyFilter("");
        }}
      >
        {t("filter.clear")}
      </button>
      <button className={`btn${builderOpen ? " btn-primary" : ""}`} onClick={() => setBuilderOpen(!builderOpen)}>
        <Icon name="sliders" />
        {t("filter.builder")}
      </button>
      {builderOpen ? <FilterBuilder onClose={() => setBuilderOpen(false)} /> : null}
    </div>
  );
}
