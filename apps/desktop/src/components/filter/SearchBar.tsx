import { useEffect, useRef, useState } from "react";

import { api, BackendError } from "../../api/client";
import type { SearchQuery } from "../../api/types";
import { t, type MessageKey } from "../../i18n";
import { errorText, useStore } from "../../state/store";
import { Icon } from "../common/Icon";
import { Select } from "../common/Select";
import { filterErrorText } from "./FilterBar";

type Kind = "text" | "hex" | "filter" | "ip" | "mac" | "port" | "protocol" | "number" | "domain" | "httpHost" | "sni";
const KINDS: Kind[] = ["text", "domain", "ip", "mac", "port", "protocol", "httpHost", "sni", "hex", "filter", "number"];

function quote(v: string): string {
  return `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** Converts a typed search into a backend query (most kinds are display filters). */
export function toQuery(kind: Kind, text: string, caseSensitive: boolean): SearchQuery | null {
  const v = text.trim();
  if (!v) return null;
  switch (kind) {
    case "text":
      return { kind: "text", text: v, caseSensitive };
    case "hex":
      return { kind: "hex", text: v };
    case "filter":
      return { kind: "filter", text: v };
    case "ip":
      return { kind: "filter", text: v.includes(":") ? `ipv6.addr == ${v}` : `ip.addr == ${v}` };
    case "mac":
      return { kind: "filter", text: `eth.addr == ${v}` };
    case "port":
      return { kind: "filter", text: `tcp.port == ${v} || udp.port == ${v}` };
    case "protocol":
      return { kind: "filter", text: v.toLowerCase() };
    case "domain": {
      const q = quote(v);
      return { kind: "filter", text: `dns.qry.name contains ${q} || tls.handshake.extensions_server_name contains ${q} || http.host contains ${q}` };
    }
    case "httpHost":
      return { kind: "filter", text: `http.host contains ${quote(v)}` };
    case "sni":
      return { kind: "filter", text: `tls.handshake.extensions_server_name contains ${quote(v)}` };
    case "number":
      return null;
  }
}

export function SearchBar() {
  const [kind, setKind] = useState<Kind>("text");
  const [text, setText] = useState("");
  const [caseSensitive, setCaseSensitive] = useState(false);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const busyRef = useRef(false);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const run = async (backwards: boolean) => {
    const s = useStore.getState();
    setNote(null);
    if (kind === "number") {
      const n = Number.parseInt(text, 10);
      if (Number.isFinite(n)) void s.selectPacket(n);
      return;
    }
    const q = toQuery(kind, text, caseSensitive);
    // One search at a time: repeated Enter would start every run from the same row.
    if (!q || !s.capture || busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    try {
      const hit = await api.search(s.viewId, s.selectedRow, backwards, q);
      if (!hit) setNote(t("search.notFound"));
      else {
        if (hit.wrapped) setNote(t("search.wrapped"));
        await s.selectPacket(hit.number);
      }
    } catch (e) {
      setNote(e instanceof BackendError && e.filter ? filterErrorText(e.filter) : errorText(e));
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  };

  return (
    <div className="searchbar" role="search">
      <Icon name="search" />
      <Select
        value={kind}
        options={KINDS.map((k) => ({ value: k, label: t(`search.kind.${k}` as MessageKey) }))}
        onChange={setKind}
        ariaLabel={t("search.title")}
        minWidth={200}
      />
      <input autoComplete="off"
        id="packet-search"
        ref={inputRef}
        className="input mono"
        value={text}
        placeholder={t("search.placeholder")}
        spellCheck={false}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") void run(e.shiftKey);
          if (e.key === "Escape") useStore.getState().setSearchOpen(false);
        }}
      />
      {kind === "text" ? (
        <label className="checkbox">
          <input type="checkbox" checked={caseSensitive} onChange={(e) => setCaseSensitive(e.target.checked)} />
          {t("search.case")}
        </label>
      ) : null}
      <button className="btn" disabled={busy} onClick={() => void run(true)} title="Shift+Enter">
        <Icon name="up" />
        {t("search.prev")}
      </button>
      <button className="btn btn-primary" disabled={busy} onClick={() => void run(false)} title="Enter">
        <Icon name="down" />
        {t("search.next")}
      </button>
      <span className="muted">{busy ? t("search.searching") : note}</span>
      <span className="grow" />
      <button className="icon-btn" onClick={() => useStore.getState().setSearchOpen(false)} aria-label={t("dialog.close")}>
        <Icon name="close" />
      </button>
    </div>
  );
}
