import { useState } from "react";

import { t } from "../../i18n";
import { commands } from "../../state/commands";
import { useStore } from "../../state/store";
import { InterfaceList, useInterfaces } from "../capture/InterfaceList";
import { Icon } from "../common/Icon";

/** Start page: open a file or start a live capture. */
export function EmptyState() {
  const recent = useStore((s) => s.settings.recentFiles);
  const openError = useStore((s) => s.openError);
  const last = useStore((s) => s.settings.lastCapture);
  const ifaces = useInterfaces();
  const [selected, setSelected] = useState<string | null>(last?.interface ?? null);

  const start = (name: string) => {
    const base = last ?? { captureFilter: null, snaplen: 262144, promiscuous: true };
    void useStore
      .getState()
      .startCapture({ ...base, interface: name })
      .catch(() => undefined);
  };

  return (
    <div className="empty">
      <div className="empty-box" style={{ width: 620 }}>
        <h2>{t("empty.title")}</h2>
        <p>{t("empty.hint")}</p>
        <button className="btn btn-primary" onClick={() => void commands.open()}>
          <Icon name="open" />
          {t("empty.open")}
        </button>
        {openError ? <p style={{ marginTop: 10, color: "var(--error)" }}>{openError}</p> : null}
        <p className="faint" style={{ marginTop: 14, marginBottom: 0, fontSize: 11 }}>
          {t("empty.formats")}
        </p>

        <div className="empty-recent">
          <h4>{t("capture.section")}</h4>
          <InterfaceList state={ifaces} selected={selected} onSelect={setSelected} onStart={start} maxHeight={220} />
          {!ifaces.unavailable && ifaces.interfaces.length ? (
            <div className="row" style={{ marginTop: 8 }}>
              <button className="btn btn-primary" disabled={!selected} onClick={() => selected && start(selected)}>
                <Icon name="play" />
                {t("capture.start")}
              </button>
              <button className="btn" onClick={commands.captureDialog}>
                {t("action.captureInterfaces")}
              </button>
            </div>
          ) : null}
        </div>

        {recent.length ? (
          <div className="empty-recent">
            <h4>{t("empty.recent")}</h4>
            {recent.map((p) => (
              <button key={p} className="recent" title={p} onClick={() => void commands.openPath(p)}>
                {p}
              </button>
            ))}
          </div>
        ) : null}
      </div>
    </div>
  );
}
