import { useCallback, useEffect, useRef, useState } from "react";

import { BackendError } from "../../api/client";
import { PageCache, type Page } from "../../lib/pageCache";
import { errorText, useStore } from "../../state/store";
import { filterErrorText } from "../filter/FilterBar";

const PAGE = 200;

/**
 * Rows of a backend-sorted table, fetched page by page for the visible window.
 * `query` identifies the order/filter: a new value starts over. While the
 * capture is still indexing, pages are refreshed every `liveMs`.
 */
export function usePagedTable<T>(query: string, fetchPage: (offset: number, limit: number) => Promise<Page<T>>, liveMs = 2000) {
  const capture = useStore((s) => s.capture);
  const captureId = useStore((s) => s.progress?.captureId ?? 0);
  const state = useStore((s) => s.progress?.state);
  const [cache] = useState(() => ({ current: new PageCache<T>(PAGE) }));
  const scope = useRef("");
  const fetchRef = useRef(fetchPage);
  fetchRef.current = fetchPage;
  const [, setTick] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const rerender = useCallback(() => setTick((n) => n + 1), []);

  const key = `${captureId}|${query}`;
  if (scope.current !== key) {
    scope.current = key;
    cache.current.reset();
  }
  useEffect(() => setError(null), [key]);

  const ensure = useCallback(
    (first: number, count: number) => {
      if (!useStore.getState().capture) return;
      const c = cache.current;
      for (const p of c.missing(first, count)) {
        const generation = c.begin(p);
        fetchRef
          .current(p * PAGE, PAGE)
          .then((page) => {
            // An error stays shown until reload or a new query: its page is still missing.
            if (c.done(p, generation, page)) rerender();
          })
          .catch((e: unknown) => {
            if ((e as { code?: string }).code === "cancelled") {
              c.cancel(p, generation);
              return;
            }
            if (!c.fail(p, generation)) return;
            setError(e instanceof BackendError && e.filter ? filterErrorText(e.filter) : errorText(e));
            rerender();
          });
      }
    },
    [cache, rerender],
  );

  // New data for the same query: when indexing ends, and periodically while it
  // runs (skipping ticks while pages are still loading, or slow sorts would
  // never finish).
  const lastState = useRef(state);
  useEffect(() => {
    if (lastState.current === state) return;
    lastState.current = state;
    cache.current.refresh();
    rerender();
  }, [state, cache, rerender]);
  useEffect(() => {
    if (state !== "indexing" || liveMs <= 0) return;
    const id = setInterval(() => {
      if (cache.current.hasPending()) return;
      cache.current.refresh();
      rerender();
    }, liveMs);
    return () => clearInterval(id);
  }, [state, liveMs, cache, rerender]);

  // The first page tells how many rows there are.
  useEffect(() => ensure(0, 1));

  const reload = useCallback(() => {
    cache.current.retry();
    cache.current.refresh();
    setError(null);
    rerender();
  }, [cache, rerender]);

  const get = useCallback((i: number) => cache.current.get(i), [cache]);
  const total = capture ? (cache.current.total ?? 0) : 0;
  return { key, total, loaded: cache.current.total != null, get, ensure, error, reload };
}

/** `value` after it stopped changing for `ms` (for search boxes that query the backend). */
export function useDebounced<T>(value: T, ms = 250): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setV(value), ms);
    return () => clearTimeout(id);
  }, [value, ms]);
  return v;
}
