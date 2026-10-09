// Cross-component actions built on the store.

import type { StreamRef } from "../api/types";
import { copyText } from "../components/common/ContextMenu";
import { t } from "../i18n";
import { combineFilters } from "../lib/filterBuilder";
import { useStore } from "./store";

export type FilterMode = "replace" | "and" | "or" | "not";

/** "Apply as filter" / "Prepare as filter" semantics. */
export function filterByTerm(term: string, mode: FilterMode, apply: boolean): void {
  const s = useStore.getState();
  const next = combineFilters(s.appliedFilter || s.filterText, term, mode);
  s.setFilterText(next);
  if (apply) void s.applyFilter(next);
}

export function applyFilterText(text: string): void {
  const s = useStore.getState();
  s.setFilterText(text);
  void s.applyFilter(text);
}

export async function copy(text: string): Promise<void> {
  if (await copyText(text)) useStore.getState().flash(t("status.copied"));
}

export function openStream(stream: StreamRef, tab: "streams" | "sequence" = "streams"): void {
  useStore.getState().focusOnStream(stream, tab);
}

export function streamFilter(stream: StreamRef): string {
  return `${stream.kind}.stream == ${stream.id}`;
}
