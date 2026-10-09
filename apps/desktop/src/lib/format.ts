import { locale, t } from "../i18n";

const intFmt = new Intl.NumberFormat(locale, { maximumFractionDigits: 0 });

export function fmtInt(n: number): string {
  return intFmt.format(n);
}

export function fmtBytes(n: number): string {
  if (!Number.isFinite(n)) return "—";
  const units = [t("unit.bytes"), t("unit.kb"), t("unit.mb"), t("unit.gb")];
  let v = n;
  let u = 0;
  while (Math.abs(v) >= 1024 && u < units.length - 1) {
    v /= 1024;
    u += 1;
  }
  const digits = u === 0 ? 0 : v < 10 ? 2 : v < 100 ? 1 : 0;
  return `${v.toLocaleString(locale, { minimumFractionDigits: digits, maximumFractionDigits: digits })} ${units[u]}`;
}

export function fmtRate(bytesPerSec: number): string {
  return `${fmtBytes(bytesPerSec)}/${t("unit.s")}`;
}

/** Seconds with fixed fractional digits, e.g. `12.345678`. */
export function fmtSeconds(s: number, digits = 6): string {
  return s.toFixed(digits);
}

export function fmtDuration(s: number): string {
  if (s < 1) return `${(s * 1000).toFixed(3)} ${t("unit.ms")}`;
  if (s < 120) return `${s.toFixed(3)} ${t("unit.s")}`;
  const m = Math.floor(s / 60);
  const rest = s - m * 60;
  if (m < 120) return `${m} мин ${rest.toFixed(0)} ${t("unit.s")}`;
  const h = Math.floor(m / 60);
  return `${h} ч ${m % 60} мин`;
}

export function fmtMs(ms: number | null | undefined): string {
  if (ms == null) return "—";
  return ms < 10 ? `${ms.toFixed(3)} ${t("unit.ms")}` : `${ms.toFixed(1)} ${t("unit.ms")}`;
}

export type TimeFormat = "relative" | "delta" | "local" | "utc";

function pad(n: number, w = 2): string {
  return String(n).padStart(w, "0");
}

/** Formats a packet timestamp for the Time column. */
export function fmtPacketTime(
  fmt: TimeFormat,
  row: { timeRel: number; timeDelta: number; tsSec: number; tsNsec: number },
): string {
  switch (fmt) {
    case "relative":
      return row.timeRel.toFixed(6);
    case "delta":
      return row.timeDelta.toFixed(6);
    case "local": {
      const d = new Date(row.tsSec * 1000);
      return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(Math.floor(row.tsNsec / 1000), 6)}`;
    }
    case "utc": {
      const d = new Date(row.tsSec * 1000);
      return (
        `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ` +
        `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}.${pad(Math.floor(row.tsNsec / 1000), 6)}`
      );
    }
  }
}

export function fmtAbsolute(sec: number, nsec: number): string {
  const d = new Date(sec * 1000);
  return `${d.toLocaleString(locale)}.${pad(Math.floor(nsec / 1000), 6)}`;
}

export function fmtPercent(part: number, total: number): string {
  if (total <= 0) return "0.0";
  return ((part * 100) / total).toFixed(1);
}

/** Endpoint for display; IPv6 addresses are bracketed before the port. */
export function fmtEndpoint(addr: string, port: number | null | undefined): string {
  if (port == null) return addr;
  return addr.includes(":") ? `[${addr}]:${port}` : `${addr}:${port}`;
}
