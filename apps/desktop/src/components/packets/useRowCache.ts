import { useCallback, useEffect, useRef, useState } from "react";

import { api } from "../../api/client";
import type { PacketRow } from "../../api/types";

const PAGE = 200;
const MAX_PAGES = 120;

interface Cache {
  key: string;
  /** Capture + view identity; stale rows are reused only within the same scope. */
  scope: string;
  pages: Map<number, PacketRow[]>;
  /** `total` at the time each page was fetched (an incomplete page is refetched only when it grows). */
  fetchedAt: Map<number, number>;
  /** Pages of the previous version of the same view, shown until fresh rows arrive (no flicker). */
  stale: Map<number, PacketRow[]>;
  pending: Set<number>;
  /** Pages whose request failed; not retried until `retry()`. */
  failed: Set<number>;
  used: number[];
}

function emptyCache(key: string, scope: string, stale: Map<number, PacketRow[]> = new Map()): Cache {
  return { key, scope, pages: new Map(), fetchedAt: new Map(), stale, pending: new Set(), failed: new Set(), used: [] };
}

/**
 * Lazily loads packet list rows in pages. Rows are fetched only for the
 * visible window; far-away pages are evicted (LRU) to bound memory.
 */
export function useRowCache(captureId: number, viewId: number, version: number, total: number) {
  const scope = `${captureId}:${viewId}`;
  const key = `${scope}:${version}`;
  const cache = useRef<Cache>(emptyCache(key, scope));
  const [, setTick] = useState(0);
  const [error, setError] = useState<string | null>(null);
  if (cache.current.key !== key) {
    const prev = cache.current;
    cache.current = emptyCache(key, scope, prev.scope === scope ? new Map(prev.pages) : new Map());
  }
  const totalRef = useRef(total);
  totalRef.current = total;

  useEffect(() => setError(null), [key]);

  const touch = (c: Cache, page: number) => {
    c.used = c.used.filter((p) => p !== page);
    c.used.push(page);
    while (c.used.length > MAX_PAGES) {
      const evict = c.used.shift();
      if (evict !== undefined) {
        c.pages.delete(evict);
        c.fetchedAt.delete(evict);
      }
    }
  };

  const ensure = useCallback(
    (first: number, count: number) => {
      const c = cache.current;
      if (count <= 0) return;
      const from = Math.floor(first / PAGE);
      const to = Math.floor((first + count - 1) / PAGE);
      for (let p = from; p <= to; p++) {
        const have = c.pages.get(p);
        const tot = totalRef.current;
        const complete =
          have && (have.length === PAGE || p * PAGE + have.length >= tot || c.fetchedAt.get(p) === tot);
        if (complete || c.pending.has(p) || c.failed.has(p)) continue;
        c.pending.add(p);
        const requestKey = c.key;
        const askedAt = tot;
        api
          .rows(viewId, p * PAGE, PAGE)
          .then((rows) => {
            if (cache.current.key !== requestKey) return;
            cache.current.pages.set(p, rows);
            cache.current.fetchedAt.set(p, askedAt);
            cache.current.stale.delete(p);
            touch(cache.current, p);
          })
          .catch((e: Error) => {
            if (cache.current.key !== requestKey) return;
            cache.current.failed.add(p);
            setError(e.message);
          })
          .finally(() => {
            if (cache.current.key === requestKey) {
              cache.current.pending.delete(p);
              setTick((x) => x + 1);
            }
          });
      }
    },
    [viewId],
  );

  const get = useCallback((i: number): PacketRow | undefined => {
    const p = Math.floor(i / PAGE);
    const c = cache.current;
    return c.pages.get(p)?.[i % PAGE] ?? c.stale.get(p)?.[i % PAGE];
  }, []);

  const retry = useCallback(() => {
    cache.current.failed.clear();
    setError(null);
    setTick((x) => x + 1);
  }, []);

  // Rows of the last page may still be arriving while indexing; re-check on growth.
  useEffect(() => {
    setTick((x) => x + 1);
  }, [total]);

  return { get, ensure, error, retry };
}
