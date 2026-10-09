import { api } from "../../api/client";
import type { Indicator } from "../../api/types";
import { t, type MessageKey } from "../../i18n";
import { fmtBytes, fmtInt } from "../../lib/format";
import { applyFilterText, copy } from "../../state/actions";
import { useStore } from "../../state/store";
import { Icon } from "../common/Icon";
import { QueryError, useBackend } from "./useBackend";

/** Indicator → localized title + factual sentence. */
export function describeIndicator(ind: Indicator): { title: string; facts: string } {
  const params: Record<string, string | number> = {};
  for (const [k, v] of Object.entries(ind)) {
    if (typeof v === "number") {
      params[k] = k.endsWith("Bytes") ? fmtBytes(v) : k === "percent" ? v.toFixed(1) : k === "port" || k === "stream" ? String(v) : fmtInt(v);
    }
    else if (typeof v === "string") params[k] = k === "kind" ? v.toUpperCase() : v;
  }
  return {
    title: t(`ind.${ind.code}` as MessageKey),
    facts: t(`ind.${ind.code}.facts` as MessageKey, params),
  };
}

export function IndicatorsPanel() {
  const { data, error, loading, reload } = useBackend(() => api.indicators(), [], 0);
  const list = data ?? [];
  return (
    <div className="col" style={{ flex: 1, minHeight: 0 }}>
      <div className="tool-bar">
        <span className="muted">{t("ind.hint")}</span>
        <span className="grow" />
        <button className="icon-btn" title={t("common.refresh")} onClick={reload}>
          <Icon name="refresh" />
        </button>
      </div>
      <div className="tool-body">
        <QueryError error={error} />
        {data == null && loading ? <div className="tool-note">{t("common.loading")}</div> : null}
        {data?.length === 0 ? <div className="tool-note">{t("ind.none")}</div> : null}
        <div className="ind-list">
          {list.map((ind, i) => {
            const d = describeIndicator(ind);
            return (
              <div key={i} className={`ind sev-${ind.severity}`}>
                <div className="ind-title">
                  <span className={`badge badge-${ind.severity === "warning" ? "warn" : ind.severity === "error" ? "error" : "note"}`}>
                    {t(`ind.severity.${ind.severity}` as MessageKey)}
                  </span>
                  {d.title}
                </div>
                <div className="ind-facts">{d.facts}</div>
                <div className="row">
                  <button className="btn btn-small btn-primary" onClick={() => applyFilterText(ind.filter)}>
                    <Icon name="filter" />
                    {t("ind.show")}
                  </button>
                  {ind.firstPacket ? (
                    <button className="btn btn-small" onClick={() => void useStore.getState().selectPacket(ind.firstPacket as number)}>
                      {t("ind.goto")}
                    </button>
                  ) : null}
                  <span className="ind-filter ellipsis grow" title={ind.filter} onDoubleClick={() => void copy(ind.filter)}>
                    {ind.filter}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
