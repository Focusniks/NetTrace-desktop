import { useEffect } from "react";

import { t } from "../../i18n";
import { fmtBytes } from "../../lib/format";
import { checkForUpdates, dismiss, installUpdate, skipVersion, useUpdate } from "../../state/updater";
import { Dialog } from "../common/Dialog";

/** Release notes come from CHANGELOG.md (Markdown); shown as plain text, never as HTML. */
function Notes({ text }: { text: string }) {
  const lines = text.split(/\r?\n/).filter((l) => l.trim() !== "");
  if (!lines.length) return <p className="muted">{t("update.noNotes")}</p>;
  return (
    <div className="update-notes">
      {lines.map((line, i) => {
        const heading = /^#{1,6}\s+(.*)$/.exec(line);
        if (heading) return <div key={i} className="update-notes-h">{heading[1]}</div>;
        const item = /^\s*[-*]\s+(.*)$/.exec(line);
        return <div key={i} className={item ? "update-notes-li" : undefined}>{item ? `• ${item[1]}` : line}</div>;
      })}
    </div>
  );
}

const noop = () => {};

export function UpdateDialog() {
  const u = useUpdate();
  const offer = u.status === "available" || (u.status === "error" && !!u.version);
  const percent = u.total ? Math.min(100, Math.round((u.downloaded / u.total) * 100)) : null;
  const progress = percent != null ? `${percent}% (${fmtBytes(u.downloaded)} / ${fmtBytes(u.total ?? 0)})` : fmtBytes(u.downloaded);
  // The footer changes with the status: move focus to its marked button so
  // keys never fall through to the page. The startup offer focuses "Later",
  // so a key pressed while typing elsewhere never starts an install.
  const phase = offer ? `offer-${u.manual}` : u.status;
  useEffect(() => {
    // Only one dialog is open at a time.
    document.querySelector<HTMLElement>(".dialog [data-autofocus]")?.focus();
  }, [phase]);

  const primary = (label: string, onClick: () => void, focus = true) => (
    <button className="btn btn-primary" data-autofocus={focus ? "" : undefined} onClick={onClick}>
      {label}
    </button>
  );

  const footer = offer ? (
    <>
      <button className="btn" onClick={skipVersion}>
        {t("update.skip")}
      </button>
      <button className="btn" data-autofocus={u.manual ? undefined : ""} onClick={dismiss}>
        {t("update.later")}
      </button>
      {primary(u.status === "error" ? t("update.retry") : t("update.install"), () => void installUpdate(), u.manual)}
    </>
  ) : u.status === "ready" ? (
    <>
      <button className="btn" onClick={dismiss}>
        {t("update.later")}
      </button>
      {primary(t("update.install"), () => void installUpdate())}
    </>
  ) : u.status === "error" ? (
    <>
      <button className="btn" onClick={dismiss}>
        {t("dialog.close")}
      </button>
      {primary(t("update.retry"), () => void checkForUpdates(true))}
    </>
  ) : u.status === "latest" || u.status === "idle" ? (
    primary(t("dialog.close"), dismiss)
  ) : null;

  return (
    <Dialog
      title={t("update.title")}
      onClose={u.status === "installing" ? noop : dismiss}
      width={520}
      footer={footer}
    >
      <div role="status" aria-live="polite">
        {u.status === "checking" ? <p className="muted">{t("update.checking")}</p> : null}
        {u.status === "latest" ? <p>{t("update.latest", { version: u.currentVersion })}</p> : null}
        {u.status === "ready" ? <p>{t("update.ready")}</p> : null}
        {u.status === "installing" ? <p>{t("update.installing")}</p> : null}
      </div>
      {u.version && u.status !== "latest" && u.status !== "checking" ? (
        <>
          <p style={{ marginTop: 0 }}>
            <strong>{t("update.available", { version: u.version })}</strong>
            <span className="muted"> · {t("update.current", { version: u.currentVersion })}</span>
          </p>
          <h4 className="update-notes-title">{t("update.notes")}</h4>
          <Notes text={u.notes} />
        </>
      ) : null}
      {u.status === "downloading" ? (
        <div className="update-progress">
          <div
            className="update-progress-bar"
            role="progressbar"
            aria-label={t("update.title")}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={percent ?? undefined}
            aria-valuetext={progress}
            style={{ width: percent != null ? `${percent}%` : "30%" }}
          />
          <span aria-hidden="true">{t("update.downloading", { progress })}</span>
        </div>
      ) : null}
      {u.status === "error" ? (
        <p role="alert" style={{ color: "var(--error)" }}>
          {t("update.error", { message: u.error ?? "" })}
        </p>
      ) : null}
      {offer ? <p className="faint" style={{ fontSize: 11, marginBottom: 0 }}>{t("update.hint")}</p> : null}
    </Dialog>
  );
}
