import { useEffect, useState } from "react";

import { t, type MessageKey } from "../../i18n";
import {
  BUILDER_FIELDS,
  buildFilter,
  opsFor,
  PROTOCOLS,
  TCP_FLAGS,
  type BuilderCondition,
  type BuilderField,
} from "../../lib/filterBuilder";
import { useStore } from "../../state/store";
import { Icon } from "../common/Icon";
import { Select } from "../common/Select";

const blank = (join: "and" | "or" = "and"): BuilderCondition => ({ field: "ip", op: "eq", value: "", join });

export function FilterBuilder({ onClose }: { onClose: () => void }) {
  const [conds, setConds] = useState<BuilderCondition[]>([
    { field: "src", op: "eq", value: "", join: "and" },
    { field: "protocol", op: "present", value: "tcp", join: "and" },
    { field: "dstport", op: "eq", value: "", join: "and" },
  ]);
  const expr = buildFilter(conds);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const update = (i: number, patch: Partial<BuilderCondition>) =>
    setConds((cs) =>
      cs.map((c, j) => {
        if (j !== i) return c;
        const next = { ...c, ...patch };
        if (patch.field && !opsFor(patch.field).includes(next.op)) next.op = opsFor(patch.field)[0];
        if (patch.field === "protocol") next.value = next.value && PROTOCOLS.includes(next.value) ? next.value : "tcp";
        if (patch.field === "flags") next.value = "syn";
        return next;
      }),
    );

  const apply = (run: boolean) => {
    const s = useStore.getState();
    s.setFilterText(expr);
    if (run) void s.applyFilter(expr);
    onClose();
  };

  return (
    <div className="builder" role="dialog" aria-label={t("builder.title")}>
      <div className="dialog-title">
        <span>{t("builder.title")}</span>
        <button className="icon-btn" onClick={onClose} aria-label={t("dialog.close")}>
          <Icon name="close" />
        </button>
      </div>
      <div className="builder-rows">
        {conds.map((c, i) => (
          <div className="builder-row" key={i}>
            {i === 0 ? (
              <span className="muted">{t("builder.field")}</span>
            ) : (
              <Select
                value={c.join}
                options={[
                  { value: "and", label: t("builder.and") },
                  { value: "or", label: t("builder.or") },
                ]}
                onChange={(join) => update(i, { join })}
              />
            )}
            <Select
              value={c.field}
              options={BUILDER_FIELDS.map((f) => ({ value: f, label: t(`builder.f.${f}` as MessageKey) }))}
              onChange={(field: BuilderField) => update(i, { field })}
            />
            <Select
              value={c.op}
              options={opsFor(c.field).map((o) => ({ value: o, label: t(`builder.op.${o}` as MessageKey) }))}
              onChange={(op: BuilderCondition["op"]) => update(i, { op })}
            />
            {c.field === "protocol" || c.field === "flags" ? (
              <Select
                value={c.value}
                options={(c.field === "protocol" ? PROTOCOLS : TCP_FLAGS).map((p) => ({ value: p, label: p.toUpperCase() }))}
                onChange={(value: string) => update(i, { value })}
              />
            ) : (
              <input spellCheck={false} autoComplete="off"
                className="input mono"
                value={c.value}
                placeholder={c.field === "src" || c.field === "dst" || c.field === "ip" ? "10.10.1.15 / 10.0.0.0/8" : ""}
                onChange={(e) => update(i, { value: e.target.value })}
                onKeyDown={(e) => e.key === "Enter" && apply(true)}
              />
            )}
            <button className="icon-btn" title={t("builder.remove")} onClick={() => setConds((cs) => cs.filter((_, j) => j !== i))}>
              <Icon name="trash" />
            </button>
          </div>
        ))}
        <div>
          <button className="btn btn-small" onClick={() => setConds((cs) => [...cs, blank()])}>
            <Icon name="plus" />
            {t("builder.add")}
          </button>
        </div>
      </div>
      <div className="builder-preview" aria-label={t("builder.result")}>
        {expr || <span className="faint">{t("builder.result")}</span>}
      </div>
      <div className="builder-foot">
        <button className="btn" disabled={!expr} onClick={() => apply(false)}>
          {t("builder.insert")}
        </button>
        <button className="btn btn-primary" disabled={!expr} onClick={() => apply(true)}>
          {t("builder.apply")}
        </button>
      </div>
    </div>
  );
}
