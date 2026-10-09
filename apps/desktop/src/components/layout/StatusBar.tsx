import { useEffect, useState } from "react";

import { t, type MessageKey } from "../../i18n";
import { fmtBytes, fmtDuration, fmtInt, fmtPercent } from "../../lib/format";
import { useStore } from "../../state/store";

export function StatusBar() {
  const capture = useStore((s) => s.capture);
  const progress = useStore((s) => s.progress);
  const viewTotal = useStore((s) => s.viewTotal);
  const appliedFilter = useStore((s) => s.appliedFilter);
  const filterElapsed = useStore((s) => s.filterElapsed);
  const selected = useStore((s) => s.selectedNumber);
  const highlight = useStore((s) => s.highlight);
  const status = useStore((s) => s.status);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!status) return;
    setMessage(status.text);
    const id = setTimeout(() => setMessage(null), 6000);
    return () => clearTimeout(id);
  }, [status]);

  if (!capture) {
    return (
      <div className="statusbar">
        <span className="sb-item">{t("status.noCapture")}</span>
        {message ? <span className="sb-msg">{message}</span> : null}
      </div>
    );
  }

  const total = progress?.packets ?? 0;
  const indexing = progress?.state === "indexing";
  const pct = progress && progress.totalBytes > 0 ? (progress.bytesRead * 100) / progress.totalBytes : 0;

  return (
    <div className="statusbar" role="status">
      <span className="sb-item sb-strong ellipsis" title={capture.path} style={{ maxWidth: 280 }}>
        {capture.fileName}
      </span>
      {capture.live ? null : (
        <span className="sb-item">
          {capture.format} · {fmtBytes(capture.fileSize)}
        </span>
      )}
      <span className="sb-item">{t("status.packets", { n: fmtInt(total) })}</span>
      {appliedFilter ? (
        <span className="sb-item sb-strong">{t("status.displayed", { n: fmtInt(viewTotal), pct: fmtPercent(viewTotal, total) })}</span>
      ) : null}
      {selected != null ? <span className="sb-item">{t("status.selected", { n: selected })}</span> : null}
      {highlight && highlight.len > 0 ? (
        <span className="sb-item">{t("hex.selected", { start: highlight.start, end: highlight.start + highlight.len - 1, len: highlight.len })}</span>
      ) : null}
      {filterElapsed != null ? <span className="sb-item">{t("status.filterTime", { ms: filterElapsed })}</span> : null}
      {capture.live && progress?.capture ? (
        <span className={`sb-item${progress.capture.running ? " sb-live" : ""}`}>
          {progress.capture.running
            ? t("capture.running", { iface: capture.fileName })
            : t("capture.stopped", { iface: capture.fileName })}
          <span className="muted" style={{ fontWeight: "normal" }}>
            {t("capture.stats", { captured: fmtInt(progress.capture.captured), dropped: fmtInt(progress.capture.dropped + progress.capture.ifDropped) })}
          </span>
        </span>
      ) : null}
      {indexing && !capture.live ? (
        <span className="sb-item">
          {t("status.indexing", { pct: pct.toFixed(0) })}
          <span className="progress">
            <div style={{ width: `${pct}%` }} />
          </span>
          {t("status.found", { packets: fmtInt(progress.packets), flows: fmtInt(progress.tcpStreams + progress.udpStreams) })}
        </span>
      ) : progress?.state === "done" ? (
        <span className="sb-item">{t("status.indexed", { time: fmtDuration(progress.elapsedMs / 1000) })}</span>
      ) : progress?.state === "failed" ? (
        <span className="sb-item sb-error">{t("status.failed", { error: progress.error ?? "" })}</span>
      ) : null}
      {progress?.warning ? <span className="sb-item sb-warn">{t(`status.warning.${progress.warning}` as MessageKey)}</span> : null}
      <span className="grow" />
      {message ? <span className="sb-msg">{message}</span> : null}
    </div>
  );
}
