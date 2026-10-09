import { useMemo, useState } from "react";

import { t } from "../../i18n";
import { DEFAULT_RULES, type ColorRule } from "../../lib/coloring";
import { fmtAbsolute, fmtBytes, fmtDuration, fmtInt, fmtRate } from "../../lib/format";
import { useStore } from "../../state/store";
import { CaptureDialog, UnsavedDialog } from "../capture/CaptureDialog";
import { Dialog } from "../common/Dialog";
import { Icon } from "../common/Icon";
import { filterErrorText } from "../filter/FilterBar";

export function Dialogs() {
  const dialog = useStore((s) => s.dialog);
  const close = () => useStore.getState().setDialog(null);
  switch (dialog) {
    case "goto":
      return <GotoDialog onClose={close} />;
    case "coloring":
      return <ColoringDialog onClose={close} />;
    case "properties":
      return <PropertiesDialog onClose={close} />;
    case "about":
      return (
        <Dialog title={t("dialog.about.title")} onClose={close} width={460}>
          <p style={{ marginTop: 0 }}>
            <strong>{t("app.title")}</strong> · 0.1.0
          </p>
          <p className="muted">{t("dialog.about.text")}</p>
        </Dialog>
      );
    case "shortcuts":
      return <ShortcutsDialog onClose={close} />;
    case "fields":
      return <FieldsDialog onClose={close} />;
    case "capture":
      return <CaptureDialog onClose={close} />;
    case "unsaved":
      return <UnsavedDialog onClose={close} />;
    default:
      return null;
  }
}

function GotoDialog({ onClose }: { onClose: () => void }) {
  const [value, setValue] = useState("");
  const go = () => {
    const n = Number.parseInt(value, 10);
    if (Number.isFinite(n) && n > 0) {
      void useStore.getState().selectPacket(n);
      onClose();
    }
  };
  return (
    <Dialog
      title={t("dialog.goto.title")}
      onClose={onClose}
      width={320}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            {t("dialog.cancel")}
          </button>
          <button className="btn btn-primary" onClick={go}>
            {t("dialog.goto.go")}
          </button>
        </>
      }
    >
      <label className="field">
        {t("dialog.goto.label")}
        <input spellCheck={false} autoComplete="off"
          className="input mono"
          inputMode="numeric"
          value={value}
          onChange={(e) => setValue(e.target.value.replace(/\D/g, ""))}
          onKeyDown={(e) => e.key === "Enter" && go()}
        />
      </label>
    </Dialog>
  );
}

function ColoringDialog({ onClose }: { onClose: () => void }) {
  const saved = useStore((s) => s.settings.coloringRules);
  const [rules, setRules] = useState<ColorRule[]>(saved);
  const [errors, setErrors] = useState<(string | null)[]>([]);
  const update = (i: number, patch: Partial<ColorRule>) => setRules((rs) => rs.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const move = (i: number, d: number) =>
    setRules((rs) => {
      const j = i + d;
      if (j < 0 || j >= rs.length) return rs;
      const next = [...rs];
      [next[i], next[j]] = [next[j], next[i]];
      return next;
    });
  const save = async () => {
    const errs = await useStore.getState().setColoringRules(rules);
    const texts = errs.map((e) => (e ? filterErrorText(e) : null));
    setErrors(texts);
    if (texts.every((e) => !e)) onClose();
  };
  return (
    <Dialog
      title={t("dialog.coloring.title")}
      onClose={onClose}
      width={880}
      footer={
        <>
          <button className="btn" onClick={() => setRules(DEFAULT_RULES)}>
            {t("dialog.reset")}
          </button>
          <span className="grow" />
          <button className="btn" onClick={onClose}>
            {t("dialog.cancel")}
          </button>
          <button className="btn btn-primary" onClick={() => void save()}>
            {t("dialog.save")}
          </button>
        </>
      }
    >
      <p className="muted" style={{ marginTop: 0 }}>
        {t("dialog.coloring.hint")}
      </p>
      <table className="dtable rules-table">
        <thead>
          <tr>
            <th>{t("dialog.coloring.enabled")}</th>
            <th>{t("dialog.coloring.name")}</th>
            <th>{t("dialog.coloring.filter")}</th>
            <th>{t("dialog.coloring.colors")}</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {rules.map((r, i) => (
            <tr key={i}>
              <td>
                <input type="checkbox" checked={r.enabled} onChange={(e) => update(i, { enabled: e.target.checked })} />
              </td>
              <td style={{ width: 170 }}>
                <input spellCheck={false} autoComplete="off" className="input" value={r.name} onChange={(e) => update(i, { name: e.target.value })} />
              </td>
              <td>
                <input spellCheck={false} autoComplete="off"
                  className="input mono"
                  value={r.filter}
                  onChange={(e) => update(i, { filter: e.target.value })}
                  style={errors[i] ? { borderColor: "var(--error)" } : undefined}
                  title={errors[i] ?? undefined}
                />
              </td>
              <td style={{ width: 170 }}>
                <span className="row">
                  <input type="color" className="swatch" value={r.bg} onChange={(e) => update(i, { bg: e.target.value })} aria-label="bg" />
                  <input type="color" className="swatch" value={r.fg} onChange={(e) => update(i, { fg: e.target.value })} aria-label="fg" />
                  <span className="rule-preview" style={{ background: r.bg, color: r.fg }}>
                    10.0.0.1
                  </span>
                </span>
              </td>
              <td style={{ width: 80 }}>
                <button className="icon-btn" title={t("dialog.coloring.up")} onClick={() => move(i, -1)}>
                  <Icon name="up" />
                </button>
                <button className="icon-btn" title={t("dialog.coloring.down")} onClick={() => move(i, 1)}>
                  <Icon name="down" />
                </button>
                <button className="icon-btn" title={t("builder.remove")} onClick={() => setRules((rs) => rs.filter((_, j) => j !== i))}>
                  <Icon name="trash" />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <button
        className="btn btn-small"
        style={{ marginTop: 8 }}
        onClick={() => setRules((rs) => [...rs, { name: "Правило", filter: "", bg: "#2a3140", fg: "#d5dae2", enabled: true }])}
      >
        <Icon name="plus" />
        {t("dialog.coloring.add")}
      </button>
    </Dialog>
  );
}

function PropertiesDialog({ onClose }: { onClose: () => void }) {
  const summary = useStore((s) => s.summary);
  const capture = useStore((s) => s.capture);
  const progress = useStore((s) => s.progress);
  if (!capture) return null;
  const s = summary;
  return (
    <Dialog title={t("dialog.properties.title")} onClose={onClose} width={560}>
      <dl className="facts" style={{ padding: 0 }}>
        <dt>{t("dialog.properties.file")}</dt>
        <dd className="mono">{capture.path}</dd>
        <dt>{t("dialog.properties.format")}</dt>
        <dd>{capture.format}</dd>
        <dt>{t("dialog.properties.size")}</dt>
        <dd>{fmtBytes(capture.fileSize)}</dd>
        <dt>{t("dialog.properties.packets")}</dt>
        <dd>{fmtInt(s?.packets ?? progress?.packets ?? 0)}</dd>
        {s ? (
          <>
            <dt>{t("dialog.properties.bytes")}</dt>
            <dd>{fmtBytes(s.bytes)}</dd>
            <dt>{t("dialog.properties.first")}</dt>
            <dd>{s.firstTsSec != null ? fmtAbsolute(s.firstTsSec, s.firstTsNsec ?? 0) : "—"}</dd>
            <dt>{t("dialog.properties.duration")}</dt>
            <dd>{fmtDuration(s.duration)}</dd>
            <dt>{t("dialog.properties.avgRate")}</dt>
            <dd>{s.duration > 0 ? fmtRate(s.bytes / s.duration) : "—"}</dd>
            <dt>{t("dialog.properties.tcp")}</dt>
            <dd>{fmtInt(s.tcpStreams)}</dd>
            <dt>{t("dialog.properties.udp")}</dt>
            <dd>{fmtInt(s.udpStreams)}</dd>
            <dt>{t("dialog.properties.hosts")}</dt>
            <dd>{fmtInt(s.hosts)}</dd>
            <dt>{t("dialog.properties.malformed")}</dt>
            <dd>{fmtInt(s.malformed)}</dd>
            <dt>{t("dialog.properties.links")}</dt>
            <dd>{[...new Set(s.interfaces.map((i) => i.linkType))].join(", ")}</dd>
          </>
        ) : null}
      </dl>
    </Dialog>
  );
}

const SHORTCUTS: [string, Parameters<typeof t>[0]][] = [
  ["Ctrl+O", "sc.open"],
  ["Ctrl+S", "sc.save"],
  ["Ctrl+F", "sc.find"],
  ["Ctrl+G", "sc.goto"],
  ["Ctrl+/", "sc.filter"],
  ["↑ / ↓", "sc.nav"],
  ["PgUp / PgDn", "sc.page"],
  ["Home / End", "sc.firstLast"],
  ["Alt+← / Alt+→", "sc.history"],
  ["← / →", "sc.tree"],
  ["Enter", "sc.stream"],
  ["Esc", "sc.escape"],
];

function ShortcutsDialog({ onClose }: { onClose: () => void }) {
  return (
    <Dialog title={t("dialog.shortcuts.title")} onClose={onClose} width={460}>
      <dl className="facts" style={{ padding: 0 }}>
        {SHORTCUTS.map(([k, label]) => (
          <span key={k} style={{ display: "contents" }}>
            <dt>
              <span className="kbd">{k}</span>
            </dt>
            <dd>{t(label)}</dd>
          </span>
        ))}
      </dl>
    </Dialog>
  );
}

function FieldsDialog({ onClose }: { onClose: () => void }) {
  const fields = useStore((s) => s.fields);
  const [q, setQ] = useState("");
  const list = useMemo(() => {
    const s = q.trim().toLowerCase();
    return s ? fields.filter((f) => f.abbrev.includes(s) || f.name.toLowerCase().includes(s)) : fields;
  }, [fields, q]);
  return (
    <Dialog title={t("dialog.fields.title")} onClose={onClose} width={720}>
      <input spellCheck={false} autoComplete="off" className="input" style={{ width: "100%", marginBottom: 8 }} placeholder={t("dialog.fields.search")} value={q} onChange={(e) => setQ(e.target.value)} />
      <div style={{ maxHeight: "60vh", overflow: "auto" }}>
        <table className="dtable">
          <tbody>
            {list.map((f) => (
              <tr
                key={f.abbrev}
                onDoubleClick={() => {
                  const st = useStore.getState();
                  st.setFilterText(st.filterText ? `${st.filterText} ${f.abbrev}` : f.abbrev);
                  onClose();
                }}
              >
                <td className="mono selectable">{f.abbrev}</td>
                <td>{f.name}</td>
                <td className="faint">{f.kind}</td>
                <td className={f.indexed ? "" : "faint"}>{f.indexed ? t("dialog.fields.indexed") : t("dialog.fields.deep")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Dialog>
  );
}
