import { useCallback, useEffect, useRef, useState } from "react";

import { BackendError } from "../../api/client";
import { t } from "../../i18n";
import { errorText, useStore } from "../../state/store";
import { filterErrorText } from "../filter/FilterBar";

/** A failed panel query, shown in place of an empty ("nothing found") result. */
export function QueryError({ error }: { error: string | null }) {
  return error ? (
    <div className="tool-note tool-error" role="alert">
      {t("common.error", { message: error })}
    </div>
  ) : null;
}

/**
 * Loads data from the backend for a tool panel. Reloads when the capture
 * changes, when indexing finishes, periodically while indexing is running,
 * and on demand (`reload`).
 *
 * Data from a previous query (other stream, other filter) is dropped as soon
 * as the query changes, and failures are returned as `error` (render it with
 * `QueryError`) instead of leaving stale numbers on screen.
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
        setError(e instanceof BackendError && e.filter ? filterErrorText(e.filter) : errorText(e));
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
    setError(null);
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
