import { useRef, useState } from "react";

import { t } from "../../i18n";
import { useStore } from "../../state/store";
import { Splitter } from "../common/Splitter";
import { PacketDetails } from "../details/PacketDetails";
import { HexView } from "../hex/HexView";
import { PacketList } from "../packets/PacketList";

const MIN = 0.12;

/** Main working surface: packet list / protocol details / bytes. */
export function Analyzer() {
  const listFraction = useStore((s) => s.settings.listFraction);
  const detailFraction = useStore((s) => s.settings.detailFraction);
  const detailNumber = useStore((s) => s.detail?.number);
  const ref = useRef<HTMLDivElement>(null);
  const [live, setLive] = useState<{ list: number; detail: number } | null>(null);
  const start = useRef({ list: listFraction, detail: detailFraction });
  const list = live?.list ?? listFraction;
  const detail = live?.detail ?? detailFraction;

  const height = () => ref.current?.clientHeight ?? 800;
  const commit = () => {
    if (live) useStore.getState().updateSettings({ listFraction: live.list, detailFraction: live.detail });
    setLive(null);
  };

  return (
    <div className="analyzer" ref={ref}>
      <section className="pane" style={{ flex: `${list} 1 0` }}>
        <div className="pane-body">
          <PacketList />
        </div>
      </section>
      <Splitter
        direction="horizontal"
        onDrag={(d) => {
          if (!live) start.current = { list, detail };
          const l = Math.min(1 - MIN * 2, Math.max(MIN, start.current.list + d / height()));
          setLive({ list: l, detail: start.current.detail });
        }}
        onEnd={commit}
      />
      <section className="pane" style={{ flex: `${(1 - list) * detail} 1 0` }}>
        <div className="pane-header">
          <span className="pane-title">{t("details.title")}</span>
          {detailNumber ? <span>№ {detailNumber}</span> : null}
        </div>
        <div className="pane-body">
          <PacketDetails />
        </div>
      </section>
      <Splitter
        direction="horizontal"
        onDrag={(d) => {
          if (!live) start.current = { list, detail };
          const rest = (1 - start.current.list) * height();
          const dd = Math.min(0.9, Math.max(0.1, start.current.detail + d / Math.max(1, rest)));
          setLive({ list: start.current.list, detail: dd });
        }}
        onEnd={commit}
      />
      <section className="pane" style={{ flex: `${(1 - list) * (1 - detail)} 1 0` }}>
        <div className="pane-header">
          <span className="pane-title">{t("hex.title")}</span>
        </div>
        <div className="pane-body">
          <HexView />
        </div>
      </section>
    </div>
  );
}
