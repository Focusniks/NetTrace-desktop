import { useState } from "react";

import { t } from "../../i18n";
import { errorText, useStore } from "../../state/store";
import { Dialog } from "../common/Dialog";
import { Icon } from "../common/Icon";
import { InterfaceList, useInterfaces } from "./InterfaceList";

/** Interface selection + capture options ("Захват → Интерфейсы…"). */
export function CaptureDialog({ onClose, initial }: { onClose: () => void; initial?: string | null }) {
  const last = useStore((s) => s.settings.lastCapture);
  const ifaces = useInterfaces();
  const [selected, setSelected] = useState<string | null>(initial ?? last?.interface ?? null);
  const [filter, setFilter] = useState(last?.captureFilter ?? "");
  const [promiscuous, setPromiscuous] = useState(last?.promiscuous ?? true);
  const [snaplen, setSnaplen] = useState(String(last?.snaplen ?? 262144));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const known = selected != null && ifaces.interfaces.some((i) => i.name === selected);

  const start = async (name = selected) => {
    if (!name) return;
    setBusy(true);
    setError(null);
    const options = {
      interface: name,
      captureFilter: filter.trim() || null,
      snaplen: Math.min(262144, Math.max(64, Number.parseInt(snaplen, 10) || 262144)),
      promiscuous,
    };
    try {
      await useStore.getState().guardUnsaved(() => useStore.getState().startCapture(options));
      // guardUnsaved may have replaced this dialog with the "save packets?" question.
      if (useStore.getState().dialog === "capture") onClose();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      title={t("capture.dialog.title")}
      onClose={onClose}
      width={720}
      footer={
        <>
          <span className="muted grow">{ifaces.library ? t("capture.library", { version: ifaces.library }) : null}</span>
          <button className="btn" onClick={onClose}>
            {t("dialog.cancel")}
          </button>
          <button className="btn btn-primary" disabled={!known || busy || !!ifaces.unavailable} onClick={() => void start()}>
            <Icon name="play" />
            {t("capture.start")}
          </button>
        </>
      }
    >
      <InterfaceList state={ifaces} selected={selected} onSelect={setSelected} onStart={(n) => void start(n)} maxHeight={300} />
      {!ifaces.unavailable ? (
        <div className="capture-options">
          <label className="field">
            {t("capture.filter")}
            <input
              className="input mono"
              autoComplete="off"
              spellCheck={false}
              value={filter}
              placeholder={t("capture.filter.placeholder")}
              onChange={(e) => setFilter(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && void start()}
            />
            <span className="faint" style={{ fontSize: 11 }}>
              {t("capture.filter.hint")}
            </span>
          </label>
          <div className="row" style={{ gap: 18 }}>
            <label className="checkbox">
              <input type="checkbox" checked={promiscuous} onChange={(e) => setPromiscuous(e.target.checked)} />
              {t("capture.promisc")}
            </label>
            <label className="checkbox">
              {t("capture.snaplen")}
              <input
                className="input mono"
                style={{ width: 90 }}
                autoComplete="off"
                inputMode="numeric"
                value={snaplen}
                onChange={(e) => setSnaplen(e.target.value.replace(/\D/g, ""))}
              />
            </label>
          </div>
        </div>
      ) : null}
      {error ? (
        <div role="alert" style={{ color: "var(--error)", marginTop: 8 }}>
          {error}
        </div>
      ) : null}
    </Dialog>
  );
}

/** Asked before closing/replacing a live capture that was not saved. */
export function UnsavedDialog({ onClose }: { onClose: () => void }) {
  const pending = useStore((s) => s.pendingAction);
  const proceed = async (saved: boolean) => {
    const before = useStore.getState().capture?.captureId;
    // The action must not ask again; it usually replaces or closes the capture.
    useStore.setState({ liveSaved: true, pendingAction: null, dialog: null });
    try {
      if (pending) await pending();
    } catch (e) {
      useStore.getState().flash(t("common.error", { message: errorText(e) }));
    } finally {
      // Still the same unsaved capture (action failed or was cancelled): keep asking next time.
      if (!saved && useStore.getState().capture?.captureId === before) useStore.setState({ liveSaved: false });
    }
  };
  const save = async () => {
    const { commands } = await import("../../state/commands");
    // The question is about the whole capture, not just the filtered view.
    const saved = await commands.exportView(true);
    if (saved) await proceed(true);
  };
  return (
    <Dialog
      title={t("unsaved.title")}
      onClose={() => {
        useStore.setState({ pendingAction: null });
        onClose();
      }}
      width={460}
      footer={
        <>
          <button className="btn" onClick={() => useStore.setState({ pendingAction: null, dialog: null })}>
            {t("dialog.cancel")}
          </button>
          <button className="btn" onClick={() => void proceed(false)}>
            {t("unsaved.discard")}
          </button>
          <button className="btn btn-primary" onClick={() => void save()}>
            {t("unsaved.save")}
          </button>
        </>
      }
    >
      <p style={{ margin: 0 }}>{t("unsaved.text")}</p>
    </Dialog>
  );
}
