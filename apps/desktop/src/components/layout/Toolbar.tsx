import { t, type MessageKey } from "../../i18n";
import { commands } from "../../state/commands";
import { useStore } from "../../state/store";
import { Icon } from "../common/Icon";

function Btn(p: { icon: string; title: MessageKey; onClick: () => void; disabled?: boolean; active?: boolean; label?: string }) {
  return (
    <button className={`tb-btn${p.active ? " is-active" : ""}`} title={t(p.title)} aria-label={t(p.title)} disabled={p.disabled} onClick={p.onClick}>
      <Icon name={p.icon} />
      {p.label ? <span className="label">{p.label}</span> : null}
    </button>
  );
}

export function Toolbar() {
  const capture = useStore((s) => s.capture);
  const historyPos = useStore((s) => s.historyPos);
  const historyLen = useStore((s) => s.history.length);
  const colorize = useStore((s) => s.settings.colorize);
  const searchOpen = useStore((s) => s.searchOpen);
  const none = !capture;
  const capturing = useStore((s) => !!s.capture?.live && s.progress?.state !== "done" && s.progress?.state !== "failed" && s.progress?.capture?.running !== false);
  const hasLast = useStore((s) => s.settings.lastCapture != null);
  const autoScroll = useStore((s) => s.settings.autoScroll);

  return (
    <div className="toolbar" role="toolbar">
      <Btn icon="open" title="toolbar.open" label={t("empty.open")} onClick={() => void commands.open()} />
      <span className="tb-sep" />
      <Btn icon="play" title="toolbar.captureStart" disabled={capturing} onClick={commands.captureDialog} />
      <Btn icon="stop" title="toolbar.captureStop" disabled={!capturing} onClick={() => void commands.stopCapture()} />
      <Btn icon="restart" title="toolbar.captureRestart" disabled={!hasLast} onClick={() => void commands.restartCapture()} />
      <Btn icon="autoscroll" title="toolbar.autoScroll" active={autoScroll} onClick={commands.toggleAutoScroll} />
      <span className="tb-sep" />
      <Btn icon="save" title="toolbar.save" disabled={none} onClick={() => void commands.exportView()} />
      <Btn icon="close" title="toolbar.close" disabled={none} onClick={() => void commands.close()} />
      <span className="tb-sep" />
      <Btn icon="back" title="toolbar.back" disabled={historyPos <= 0} onClick={commands.back} />
      <Btn icon="forward" title="toolbar.forward" disabled={historyPos >= historyLen - 1} onClick={commands.forward} />
      <Btn icon="goto" title="toolbar.goto" disabled={none} onClick={commands.goto} />
      <span className="tb-sep" />
      <Btn icon="first" title="toolbar.first" disabled={none} onClick={commands.first} />
      <Btn icon="up" title="toolbar.prev" disabled={none} onClick={commands.prev} />
      <Btn icon="down" title="toolbar.next" disabled={none} onClick={commands.next} />
      <Btn icon="last" title="toolbar.last" disabled={none} onClick={commands.last} />
      <span className="tb-sep" />
      <Btn icon="search" title="toolbar.find" disabled={none} active={searchOpen} onClick={commands.find} />
      <Btn icon="palette" title="toolbar.colorize" active={colorize} onClick={commands.toggleColorize} />
    </div>
  );
}
