// Small stroke icon set (16×16 grid) — no icon font, no external assets.

const paths: Record<string, string> = {
  open: "M2 4.5h4l1.5 1.5H14v6.5a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1z M2 6.5h12",
  save: "M3 2.5h8l2.5 2.5v8a.5.5 0 0 1-.5.5H3a.5.5 0 0 1-.5-.5V3a.5.5 0 0 1 .5-.5z M5 2.5v3.5h5V2.5 M5 13.5V9h6v4.5",
  close: "M4 4l8 8M12 4l-8 8",
  back: "M10 3L5 8l5 5",
  forward: "M6 3l5 5-5 5",
  goto: "M2.5 8h8M8 4.5L11.5 8 8 11.5M13.5 3v10",
  first: "M4 3v10M12 3L7 8l5 5",
  last: "M12 3v10M4 3l5 5-5 5",
  up: "M3.5 10L8 5.5l4.5 4.5",
  down: "M3.5 6L8 10.5 12.5 6",
  search: "M7 12A5 5 0 1 0 7 2a5 5 0 0 0 0 10zM10.6 10.6L14 14",
  palette: "M8 2a6 6 0 1 0 0 12c.9 0 1.2-.6 1-1.3-.3-.9.3-1.7 1.2-1.7H12a2 2 0 0 0 2-2A6 6 0 0 0 8 2z M5 7.5h.01M7 5h.01M10 5.5h.01",
  panel: "M2.5 3h11v10h-11zM9.5 3v10",
  timeline: "M2 12.5h12M3.5 10V8M6 10V5M8.5 10V7M11 10V3.5M13.5 10V8",
  filter: "M2.5 3.5h11l-4.3 5v4l-2.4 1.5V8.5z",
  sliders: "M3 4h10M3 8h10M3 12h10 M6 2.5v3M10 6.5v3M5 10.5v3",
  chevronRight: "M6 3.5L10.5 8 6 12.5",
  chevronDown: "M3.5 6L8 10.5 12.5 6",
  maximize: "M3 3h10v10H3z",
  restore: "M5 3h8v8 M3 5h8v8H3z",
  stream: "M2 5h9l-2-2M14 11H5l2 2",
  hosts: "M3 3h4v4H3zM9 9h4v4H9zM7 5h3v4",
  stats: "M3 13V8M6.5 13V4M10 13v-6M13.5 13V2.5",
  warn: "M8 2.5l6 11H2zM8 7v3M8 12h.01",
  info: "M8 14A6 6 0 1 0 8 2a6 6 0 0 0 0 12zM8 7.5v4M8 5h.01",
  copy: "M5.5 5.5h7v8h-7zM3.5 10.5v-8h7",
  plus: "M8 3v10M3 8h10",
  trash: "M3 4.5h10M6 4.5V3h4v1.5M4.5 4.5l.6 9h5.8l.6-9",
  sequence: "M3 2v12M13 2v12M3 5h10l-2-1.5M13 10H3l2 1.5",
  refresh: "M13 8a5 5 0 1 1-1.5-3.6M13 2.5v3h-3",
  play: "M5 3.2v9.6L12.8 8z",
  stop: "M4 4h8v8H4z",
  restart: "M3 8a5 5 0 1 0 1.5-3.6M3 2.5v3h3 M7 6v4l3-2z",
  autoscroll: "M8 2.5v9M4.5 8L8 11.5 11.5 8M3.5 13.5h9",
};

export function Icon({ name, title }: { name: keyof typeof paths | string; title?: string }) {
  const d = paths[name] ?? paths.info;
  return (
    // Explicit size: an unsized inline SVG stretches to its container.
    <svg width={16} height={16} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth={1.4} strokeLinecap="round" strokeLinejoin="round" aria-hidden={title ? undefined : true} role={title ? "img" : undefined}>
      {title ? <title>{title}</title> : null}
      <path d={d} />
    </svg>
  );
}

export function Logo() {
  return (
    <svg width={16} height={16} viewBox="0 0 16 16" fill="none" aria-hidden>
      <path d="M1.5 9h2.6l1-3 1.4 5.5L8.1 4l1.3 5.3.9-1.8h4.2" stroke="#5aa2ff" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="14.5" cy="7.5" r="1" fill="#e8a33d" />
    </svg>
  );
}
