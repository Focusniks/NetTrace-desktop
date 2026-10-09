import { useCallback, useEffect, useRef, useState } from "react";

import { t } from "../../i18n";
import { useStore } from "../../state/store";

/**
 * Loads data from the backend for a tool panel. Reloads when the capture
 * changes, when indexing finishes, periodically while indexing is running,
 * and on demand (`reload`).
 *
 * Data from a previous query (other stream, other filter) is dropped as soon
 * as the query changes, and failures are reported instead of leaving stale
 * numbers on screen.
 */
export function useBackend<T>(fetcher: () => Promise<T>, deps: unknown[], liveMs = 2000) {
  const captureId = useStore((s) => s.progress?.captureId ?? 0);
  const state = useStore((s) => s.progress?.state);
  const capture = useStore((s) => s.capture);
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const seq = useRef(0);
  const inFlight = useRef(false);

  const reload = useCallback(() => {
    if (!capture) {
      setData(null);
      return;
    }
    const my = ++seq.current;
    inFlight.current = true;
    setLoading(true);
    fetcher()
      .then((d) => {
        if (my === seq.current) {
          setData(d);
          setError(null);
        }
      })
      .catch((e: Error) => {
        if (my !== seq.current || (e as { code?: string }).code === "cancelled") return;
        setData(null);
        setError(e.message);
        useStore.getState().flash(t("common.error", { message: e.message }));
      })
      .finally(() => {
        if (my === seq.current) {
          inFlight.current = false;
          setLoading(false);
        }
      });
    // `deps` are the caller's query parameters.
  }, [capture, ...deps]);

  // A different query must not show the previous query's result.
  useEffect(() => {
    setData(null);
  }, [reload]);

  useEffect(() => {
    reload();
  }, [reload, captureId, state]);

  useEffect(() => {
    if (state !== "indexing" || liveMs <= 0) return;
    // Skip ticks while a slow request is still running, or it would never finish.
    const id = setInterval(() => {
      if (!inFlight.current) reload();
    }, liveMs);
    return () => clearInterval(id);
  }, [state, reload, liveMs]);

  return { data, error, loading, reload };
}
