// Builds the GitHub wiki from the documentation in docs/.
//
//   node scripts/wiki-sync.mjs <output-dir>
//
// The site (GitHub Pages) and the wiki share one source: docs/*.md and the
// menu in docs/_data/nav.yml. Every wiki page is generated, so edit docs/,
// never the wiki. .github/workflows/wiki.yml runs this on every push to main.

import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** Sections and pages of docs/_data/nav.yml (the small subset of YAML it uses). */
export function parseNav(text) {
  const nav = [];
  for (const line of text.split(/\r?\n/)) {
    const section = line.match(/^- title:\s*(.+?)\s*$/);
    const item = line.match(/^\s+- \{\s*title:\s*(.+?),\s*url:\s*(\S+)\s*\}\s*$/);
    if (section) nav.push({ title: section[1], items: [] });
    else if (item) {
      if (!nav.length) throw new Error(`nav.yml: page before the first section: ${line}`);
      const url = item[2];
      nav.at(-1).items.push({ title: item[1], url, file: url === "/" ? "index.md" : url.replace(/^\//, "").replace(/\.html$/, ".md") });
    }
  }
  return nav;
}

/** Wiki page name (its file name without .md, and its link target). */
export function pageName(page) {
  return page.file === "index.md" ? "Home" : page.title.replace(/[\\/:*?"<>|#]/g, "").trim().replace(/\s+/g, "-");
}

/** A page of docs/ as a wiki page. */
export function convert(markdown, page, pages, siteUrl) {
  let body = markdown.replace(/\r\n/g, "\n");
  let lead = "";
  const front = body.match(/^---\n([\s\S]*?)\n---\n/);
  if (front) {
    lead = front[1].match(/^lead:\s*(.+)$/m)?.[1].trim() ?? "";
    body = body.slice(front[0].length);
  } else {
    // The wiki shows the page name as the title.
    body = body.replace(/^\s*# .*\n/, "");
  }
  const byFile = new Map(pages.map((p) => [p.file, p]));
  body = body.replace(/(!?)\[([^\]]*)\]\(([^)\s]+)\)/g, (all, bang, text, target) => {
    if (/^([a-z][a-z0-9+.-]*:|#|\/\/)/i.test(target)) return all;
    if (bang) return `![${text}](${siteUrl}/${target})`;
    const [file, anchor] = target.split("#");
    if (!file.endsWith(".md")) return all;
    const to = byFile.get(file);
    if (!to) throw new Error(`${page.file}: link to a page that is not in nav.yml: ${target}`);
    return `[${text}](${pageName(to)}${anchor ? `#${anchor}` : ""})`;
  });
  const onSite = `${siteUrl}${page.url === "/" ? "/" : page.url}`;
  return `${lead ? `_${lead}_\n\n` : ""}${body.trim()}\n\n---\n\nЭта страница создана из документации проекта. Удобнее читать [на сайте](${onSite}).\n`;
}

export function sidebar(nav) {
  return nav.map((s) => `**${s.title}**\n\n${s.items.map((p) => `- [${p.title}](${pageName(p)})`).join("\n")}`).join("\n\n") + "\n";
}

function main() {
  const out = process.argv[2];
  if (!out) {
    console.error("usage: node scripts/wiki-sync.mjs <output-dir>");
    process.exit(2);
  }
  const docs = join(dirname(fileURLToPath(import.meta.url)), "..", "docs");
  const config = readFileSync(join(docs, "_config.yml"), "utf8");
  const siteUrl = config.match(/^url:\s*(\S+)/m)[1] + config.match(/^baseurl:\s*(\S+)/m)[1];
  const nav = parseNav(readFileSync(join(docs, "_data", "nav.yml"), "utf8"));
  const pages = nav.flatMap((s) => s.items);

  mkdirSync(out, { recursive: true });
  // Pages removed from docs/ disappear from the wiki too (.git stays).
  for (const f of readdirSync(out)) if (f.endsWith(".md")) rmSync(join(out, f));
  for (const page of pages) {
    writeFileSync(join(out, `${pageName(page)}.md`), convert(readFileSync(join(docs, page.file), "utf8"), page, pages, siteUrl));
  }
  writeFileSync(join(out, "_Sidebar.md"), sidebar(nav));
  writeFileSync(join(out, "_Footer.md"), `[Сайт документации](${siteUrl}/) · [Скачать NetTrace](https://github.com/Focusniks/NetTrace-desktop/releases/latest)\n`);
  console.log(`${pages.length} pages written to ${out}`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
