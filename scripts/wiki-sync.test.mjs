import assert from "node:assert/strict";
import { test } from "node:test";

import { convert, pageName, parseNav, sidebar } from "./wiki-sync.mjs";

const NAV = `
# comment
- title: Начало
  items:
    - { title: Обзор, url: / }
    - { title: Установка и обновление, url: /install.html }

- title: Разработчикам
  items:
    - { title: Архитектура, url: /ARCHITECTURE.html }
`;

test("parseNav reads sections and items", () => {
  const nav = parseNav(NAV);
  assert.deepEqual(
    nav.map((s) => [s.title, s.items.map((i) => `${i.title}|${i.file}`)]),
    [
      ["Начало", ["Обзор|index.md", "Установка и обновление|install.md"]],
      ["Разработчикам", ["Архитектура|ARCHITECTURE.md"]],
    ],
  );
});

test("pageName: the index is Home, other pages are named by their title", () => {
  assert.equal(pageName({ title: "Обзор", file: "index.md" }), "Home");
  assert.equal(pageName({ title: "Установка и обновление", file: "install.md" }), "Установка-и-обновление");
  assert.equal(pageName({ title: "Потоки и TCP-анализ", file: "streams.md" }), "Потоки-и-TCP-анализ");
});

const pages = parseNav(NAV).flatMap((s) => s.items);
const SITE = "https://example.test/docs";

test("convert strips front matter and puts the lead first", () => {
  const out = convert("---\ntitle: Установка\nlead: Коротко о главном.\n---\n\n## Раздел\n\nТекст.\n", pages[1], pages, SITE);
  assert.ok(out.startsWith("_Коротко о главном._\n\n## Раздел"), out);
  assert.ok(!out.includes("title:"));
});

test("convert rewrites page links and images, leaves external links alone", () => {
  const md = "---\ntitle: X\n---\n[установка](install.md), [раздел](install.md#req), [арх](ARCHITECTURE.md), [сайт](https://a.b/c.md)\n\n![Окно](img/main.png)\n";
  const out = convert(md, pages[0], pages, SITE);
  assert.ok(out.includes("[установка](Установка-и-обновление)"), out);
  assert.ok(out.includes("[раздел](Установка-и-обновление#req)"), out);
  assert.ok(out.includes("[арх](Архитектура)"), out);
  assert.ok(out.includes("[сайт](https://a.b/c.md)"), out);
  assert.ok(out.includes("![Окно](https://example.test/docs/img/main.png)"), out);
});

test("convert drops the first heading of pages without front matter", () => {
  const out = convert("# NetTrace — архитектура\n\nТекст.\n", pages[2], pages, SITE);
  assert.ok(!out.includes("# NetTrace"), out);
  assert.ok(out.includes("Текст."));
});

test("convert ends with a link to the same page of the site", () => {
  assert.ok(convert("---\ntitle: X\n---\nТекст\n", pages[1], pages, SITE).trimEnd().endsWith("(https://example.test/docs/install.html)."));
  assert.ok(convert("---\ntitle: X\n---\nТекст\n", pages[0], pages, SITE).trimEnd().endsWith("(https://example.test/docs/)."));
});

test("a link to an unknown page fails loudly", () => {
  assert.throws(() => convert("---\ntitle: X\n---\n[x](missing.md)\n", pages[0], pages, SITE), /missing\.md/);
});

test("sidebar lists every page under its section", () => {
  const s = sidebar(parseNav(NAV));
  assert.ok(s.includes("**Начало**"));
  assert.ok(s.includes("- [Обзор](Home)"));
  assert.ok(s.includes("- [Архитектура](Архитектура)"));
});
