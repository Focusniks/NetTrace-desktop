import { useEffect, useState } from "react";

import { api, BackendError } from "../../api/client";
import type { CaptureInterface } from "../../api/types";
import { t } from "../../i18n";

export interface InterfacesState {
  loading: boolean;
  /** Driver version when available. */
  library: string | null;
  /** Set when live capture is unavailable (e.g. Npcap missing). */
  unavailable: string | null;
  error: string | null;
  interfaces: CaptureInterface[];
}

/** Loads the capture driver status and the interface list once per mount. */
export function useInterfaces(): InterfacesState & { reload: () => void } {
  const [state, setState] = useState<InterfacesState>({ loading: true, library: null, unavailable: null, error: null, interfaces: [] });
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let cancelled = false;
    setState((s) => ({ ...s, loading: true, error: null }));
    (async () => {
      try {
        const library = await api.captureLibrary();
        const interfaces = await api.captureInterfaces();
        if (!cancelled) setState({ loading: false, library, unavailable: null, error: null, interfaces });
      } catch (e) {
        if (cancelled) return;
        const err = e as BackendError;
        if (err.code === "capture_unavailable") {
          setState({ loading: false, library: null, unavailable: err.message, error: null, interfaces: [] });
        } else {
          setState({ loading: false, library: null, unavailable: null, error: err.message, interfaces: [] });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [tick]);
  return { ...state, reload: () => setTick((x) => x + 1) };
}

/** Friendly name: the driver description when present, otherwise the device name. */
export function interfaceLabel(i: CaptureInterface): string {
  return i.description || i.name;
}

interface Props {
  state: InterfacesState;
  selected: string | null;
  onSelect: (name: string) => void;
  onStart: (name: string) => void;
  maxHeight?: number;
}

export function InterfaceList({ state, selected, onSelect, onStart, maxHeight }: Props) {
  if (state.loading) return <div className="muted">{t("capture.loading")}</div>;
  if (state.unavailable) {
    return (
      <div className="capture-unavailable" role="alert">
        <strong>{t("capture.unavailable")}</strong>
        <p>{t("capture.install")}</p>
        <p className="faint mono" style={{ fontSize: 10.5 }}>
          {state.unavailable}
        </p>
      </div>
    );
  }
  if (state.error) return <div style={{ color: "var(--error)" }}>{t("common.error", { message: state.error })}</div>;
  if (!state.interfaces.length) return <div className="muted">{t("capture.none")}</div>;
  // Active interfaces with addresses first.
  const list = [...state.interfaces].sort((a, b) => Number(b.up && b.running) - Number(a.up && a.running) || b.addresses.length - a.addresses.length);
  return (
    <div className="iface-list" style={{ maxHeight }} role="listbox" aria-label={t("capture.col.name")}>
      {list.map((i) => (
        <div
          key={i.name}
          role="option"
          aria-selected={selected === i.name}
          tabIndex={0}
          className={`iface${selected === i.name ? " is-selected" : ""}${i.up && i.running ? "" : " is-down"}`}
          onClick={() => onSelect(i.name)}
          onDoubleClick={() => onStart(i.name)}
          onKeyDown={(e) => {
            if (e.key === "Enter") onStart(i.name);
            if (e.key === " ") {
              e.preventDefault();
              onSelect(i.name);
            }
          }}
          title={i.name}
        >
          <div className="iface-name">
            {interfaceLabel(i)}
            {i.loopback ? <span className="badge">{t("capture.loopback")}</span> : null}
            {i.wireless ? <span className="badge">{t("capture.wireless")}</span> : null}
            {!(i.up && i.running) ? <span className="badge">{t("capture.down")}</span> : null}
          </div>
          <div className="iface-addr mono">{i.addresses.join("  ·  ") || i.name}</div>
        </div>
      ))}
    </div>
  );
}
