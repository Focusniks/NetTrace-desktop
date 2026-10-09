import { useRef, useState } from "react";

import { t, type MessageKey } from "../../i18n";
import { useStore, type DockTab } from "../../state/store";
import { Icon } from "../common/Icon";
import { Splitter } from "../common/Splitter";
import { ConversationsPanel } from "../tools/ConversationsPanel";
import { HostsPanel } from "../tools/HostsPanel";
import { IndicatorsPanel } from "../tools/IndicatorsPanel";
import { SequencePanel } from "../tools/SequencePanel";
import { StatisticsPanel } from "../tools/StatisticsPanel";
import { StreamsPanel } from "../tools/StreamsPanel";
import { TimelinePanel } from "../tools/TimelinePanel";

const TABS: { id: DockTab; label: MessageKey }[] = [
  { id: "streams", label: "dock.streams" },
  { id: "sequence", label: "dock.sequence" },
  { id: "hosts", label: "dock.hosts" },
  { id: "conversations", label: "dock.conversations" },
  { id: "statistics", label: "dock.statistics" },
  { id: "timeline", label: "dock.timeline" },
  { id: "indicators", label: "dock.indicators" },
];

function Body({ tab }: { tab: DockTab }) {
  switch (tab) {
    case "streams":
      return <StreamsPanel />;
    case "sequence":
      return <SequencePanel />;
    case "hosts":
      return <HostsPanel />;
    case "conversations":
      return <ConversationsPanel />;
    case "statistics":
      return <StatisticsPanel />;
    case "timeline":
      return <TimelinePanel />;
    case "indicators":
      return <IndicatorsPanel />;
  }
}

/** Splitter + right-hand tool panel ("windows" of the analyzer). */
export function Dock() {
  const tab = useStore((s) => s.dockTab);
  const maximized = useStore((s) => s.dockMaximized);
  const savedWidth = useStore((s) => s.settings.dockWidth);
  const setDock = useStore((s) => s.setDock);
  const [live, setLive] = useState<number | null>(null);
  const start = useRef(savedWidth);
  const width = live ?? savedWidth;

  return (
    <>
      {!maximized ? (
        <Splitter
          direction="vertical"
          onDrag={(d) => {
            if (live == null) start.current = width;
            setLive(Math.min(window.innerWidth - 360, Math.max(300, start.current - d)));
          }}
          onEnd={() => {
            if (live != null) useStore.getState().updateSettings({ dockWidth: live });
            setLive(null);
          }}
        />
      ) : null}
      <aside className={`dock${maximized ? " is-maximized" : ""}`} style={maximized ? undefined : { width }} aria-label={t(TABS.find((x) => x.id === tab)?.label ?? "dock.streams")}>
        <div className="dock-tabs">
          <div
            className="dock-tabs-scroll"
            role="tablist"
            onWheel={(e) => {
              // Vertical wheel scrolls the tab strip horizontally (no visible scrollbar).
              if (e.deltaY !== 0) e.currentTarget.scrollLeft += e.deltaY;
            }}
          >
            {TABS.map((x) => (
              <button
                key={x.id}
                role="tab"
                aria-selected={tab === x.id}
                className={`dock-tab${tab === x.id ? " is-active" : ""}`}
                onClick={(e) => {
                  setDock({ dockTab: x.id });
                  e.currentTarget.scrollIntoView({ block: "nearest", inline: "nearest" });
                }}
              >
                {t(x.label)}
              </button>
            ))}
          </div>
          <button
            className="icon-btn"
            title={maximized ? t("dock.restore") : t("dock.maximize")}
            onClick={() => setDock({ dockMaximized: !maximized })}
          >
            <Icon name={maximized ? "restore" : "maximize"} />
          </button>
          <button className="icon-btn" title={t("dock.close")} onClick={() => setDock({ dockOpen: false, dockMaximized: false })}>
            <Icon name="close" />
          </button>
        </div>
        <div className="dock-body" role="tabpanel">
          <Body tab={tab} />
        </div>
      </aside>
    </>
  );
}
