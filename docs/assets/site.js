// NetTrace documentation: table of contents, search, theme, small conveniences.
(function () {
  "use strict";
  var NT = window.NT || { base: "", current: "/", pages: [] };
  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };
  var doc = $(".doc");

  // ---- Theme ---------------------------------------------------------------
  var themeBtn = $("#theme-btn");
  if (themeBtn) {
    themeBtn.addEventListener("click", function () {
      var root = document.documentElement;
      var dark = root.dataset.theme ? root.dataset.theme === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
      root.dataset.theme = dark ? "light" : "dark";
      try { localStorage.setItem("nt-theme", root.dataset.theme); } catch (e) { /* private mode */ }
    });
  }

  // ---- Mobile menu ---------------------------------------------------------
  var menuBtn = $("#menu-btn");
  function setNav(open) {
    document.body.classList.toggle("nav-open", open);
    if (menuBtn) menuBtn.setAttribute("aria-expanded", String(open));
  }
  if (menuBtn) menuBtn.addEventListener("click", function () { setNav(!document.body.classList.contains("nav-open")); });
  document.addEventListener("click", function (e) {
    if (document.body.classList.contains("nav-open") && !e.target.closest("#side") && !e.target.closest("#menu-btn")) setNav(false);
  });
  var current = $(".side a.is-current");
  if (current && current.scrollIntoView) current.scrollIntoView({ block: "center" });

  if (doc) {
    // ---- Tables: scroll inside their own box ------------------------------
    $$("table", doc).forEach(function (t) {
      var wrap = document.createElement("div");
      wrap.className = "table-wrap";
      t.parentNode.insertBefore(wrap, t);
      wrap.appendChild(t);
    });

    // ---- A list of bold links with descriptions becomes a grid of cards ------
    $$("ul", doc).forEach(function (ul) {
      var items = $$("li", ul);
      var ok = items.length >= 3 && items.every(function (li) {
        var a = li.firstElementChild;
        return a && a.tagName === "A" && a.firstElementChild && a.firstElementChild.tagName === "STRONG" && li.parentNode === ul;
      });
      if (!ok) return;
      ul.className = "cards";
      items.forEach(function (li) {
        var a = li.firstElementChild;
        var text = li.textContent.slice(a.textContent.length).replace(/^\s*[—-]\s*/, "");
        var span = document.createElement("span");
        span.textContent = text.charAt(0).toUpperCase() + text.slice(1);
        while (a.nextSibling) li.removeChild(a.nextSibling);
        a.appendChild(span);
      });
    });

    // ---- Notes: warnings get their own colour ------------------------------
    $$("blockquote", doc).forEach(function (b) {
      var s = $("strong", b);
      if (s && /^(Важно|Внимание|Осторожно)/.test(s.textContent)) b.classList.add("warn");
    });

    // ---- Screenshots: click to enlarge -------------------------------------
    $$("img", doc).forEach(function (img) {
      img.classList.add("shot");
      img.setAttribute("loading", "lazy");
      img.setAttribute("tabindex", "0");
      img.setAttribute("role", "button");
      var open = function () {
        var box = document.createElement("div");
        box.className = "lightbox";
        var big = document.createElement("img");
        big.src = img.src;
        big.alt = img.alt;
        box.appendChild(big);
        var close = function () { box.remove(); document.removeEventListener("keydown", onKey); img.focus(); };
        var onKey = function (e) { if (e.key === "Escape") close(); };
        box.addEventListener("click", close);
        document.addEventListener("keydown", onKey);
        document.body.appendChild(box);
      };
      img.addEventListener("click", open);
      img.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } });
    });

    // ---- Code blocks: copy button ------------------------------------------
    $$("pre", doc).forEach(function (pre) {
      var btn = document.createElement("button");
      btn.className = "copy-btn";
      btn.type = "button";
      btn.textContent = "Копировать";
      btn.addEventListener("click", function () {
        var text = ($("code", pre) || pre).textContent.replace(/\n$/, "");
        (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject()).then(
          function () { btn.textContent = "Скопировано"; setTimeout(function () { btn.textContent = "Копировать"; }, 1500); },
          function () { btn.textContent = "Не удалось"; }
        );
      });
      pre.appendChild(btn);
    });

    // ---- Headings: anchors and the table of contents ------------------------
    var heads = $$("h2[id], h3[id]", doc);
    var toc = $("#toc");
    var links = [];
    heads.forEach(function (h) {
      var a = document.createElement("a");
      a.className = "anchor";
      a.href = "#" + h.id;
      a.textContent = "#";
      a.setAttribute("aria-label", "Ссылка на раздел «" + h.textContent + "»");
      h.appendChild(a);
    });
    if (toc && heads.length > 1) {
      var title = document.createElement("div");
      title.className = "toc-title";
      title.textContent = "На этой странице";
      toc.appendChild(title);
      heads.forEach(function (h) {
        var a = document.createElement("a");
        a.href = "#" + h.id;
        a.className = h.tagName.toLowerCase();
        a.textContent = h.firstChild ? h.firstChild.textContent : h.textContent;
        toc.appendChild(a);
        links.push(a);
      });
      var spy = function () {
        var top = window.scrollY + 90;
        var active = 0;
        for (var i = 0; i < heads.length; i++) if (heads[i].offsetTop <= top) active = i;
        links.forEach(function (a, i) { a.classList.toggle("is-active", i === active); });
      };
      window.addEventListener("scroll", spy, { passive: true });
      spy();
    }
  }

  // ---- Previous / next -----------------------------------------------------
  var pager = $("#pager");
  var idx = -1;
  NT.pages.forEach(function (p, i) { if (p.u === NT.current) idx = i; });
  if (pager && idx >= 0) {
    var link = function (p, cls, label) {
      var a = document.createElement("a");
      a.className = cls;
      a.href = NT.base + p.u;
      a.innerHTML = "<small></small><b></b>";
      a.firstChild.textContent = label;
      a.lastChild.textContent = p.t;
      return a;
    };
    if (idx > 0) pager.appendChild(link(NT.pages[idx - 1], "prev", "← Назад"));
    else pager.appendChild(document.createElement("span"));
    if (idx < NT.pages.length - 1) pager.appendChild(link(NT.pages[idx + 1], "next", "Далее →"));
  }

  // ---- Search --------------------------------------------------------------
  // The index is built in the browser on first use: every page is fetched once
  // and split into sections by its headings, so results link straight to them.
  var input = $("#search");
  var box = $("#search-results");
  var index = null;
  var loading = null;
  var active = -1;

  function norm(s) { return s.toLowerCase().replace(/ё/g, "е"); }

  function buildIndex() {
    if (index) return Promise.resolve(index);
    if (loading) return loading;
    loading = Promise.all(NT.pages.map(function (p) {
      return fetch(NT.base + p.u).then(function (r) { return r.ok ? r.text() : ""; }).then(function (html) {
        var out = [];
        var d = new DOMParser().parseFromString(html, "text/html").querySelector(".doc");
        if (!d) return out;
        var cur = { page: p.t, title: p.t, url: NT.base + p.u, text: "" };
        Array.prototype.forEach.call(d.children, function (el) {
          if (/^H[23]$/.test(el.tagName) && el.id) {
            out.push(cur);
            cur = { page: p.t, title: el.textContent.trim(), url: NT.base + p.u + "#" + el.id, text: "" };
          } else if (el.tagName !== "H1") {
            cur.text += " " + el.textContent.replace(/\s+/g, " ").trim();
          }
        });
        out.push(cur);
        return out;
      }).catch(function () { return []; });
    })).then(function (lists) {
      index = [];
      lists.forEach(function (l) { l.forEach(function (s) { s.nTitle = norm(s.title); s.nPage = norm(s.page); s.nText = norm(s.text); index.push(s); }); });
      return index;
    });
    return loading;
  }

  function escapeHtml(s) { return s.replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }

  function snippet(s, words) {
    var pos = -1;
    for (var i = 0; i < words.length && pos < 0; i++) pos = s.nText.indexOf(words[i]);
    var start = Math.max(0, pos - 60);
    var text = (start > 0 ? "…" : "") + s.text.slice(start, start + 180);
    var html = escapeHtml(text);
    words.forEach(function (w) {
      if (w.length < 2) return;
      var re = new RegExp(w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/е/g, "[её]"), "gi");
      html = html.replace(re, function (m) { return "<mark>" + m + "</mark>"; });
    });
    return html;
  }

  // Russian words are matched by their stem, so any grammatical form is found.
  function terms(q) {
    return norm(q).split(/\s+/).filter(Boolean).map(function (w) {
      if (/^[а-я]{7,}$/.test(w)) return w.slice(0, -2);
      if (/^[а-я]{5,6}$/.test(w)) return w.slice(0, -1);
      return w;
    });
  }

  function count(text, w) {
    var n = 0;
    for (var i = text.indexOf(w); i >= 0 && n < 5; i = text.indexOf(w, i + w.length)) n++;
    return n;
  }

  function search(q) {
    var words = terms(q);
    if (!words.length) return [];
    var phrase = norm(q).trim();
    var res = [];
    index.forEach(function (s) {
      var score = 0;
      for (var i = 0; i < words.length; i++) {
        var w = words[i];
        var inTitle = s.nTitle.indexOf(w) >= 0;
        var inPage = s.nPage.indexOf(w) >= 0;
        var inText = count(s.nText, w);
        if (!inTitle && !inPage && !inText) return;
        score += (inTitle ? 12 : 0) + (inPage ? 3 : 0) + inText;
      }
      // The words next to each other count for more than the words apart.
      if (words.length > 1) score += (s.nTitle.indexOf(phrase) >= 0 ? 20 : 0) + (s.nText.indexOf(phrase) >= 0 ? 6 : 0);
      res.push({ s: s, score: score });
    });
    res.sort(function (a, b) { return b.score - a.score; });
    return res.slice(0, 12).map(function (r) { return r.s; });
  }

  function render(q) {
    var words = terms(q);
    var res = search(q);
    active = -1;
    if (!words.length) { box.hidden = true; return; }
    box.hidden = false;
    if (!res.length) { box.innerHTML = '<div class="sr-empty">Ничего не найдено</div>'; return; }
    box.innerHTML = res.map(function (s) {
      var page = s.title === s.page ? "" : ' <span class="sr-page">· ' + escapeHtml(s.page) + "</span>";
      return '<a href="' + escapeHtml(s.url) + '"><div class="sr-title">' + escapeHtml(s.title) + page + '</div><div class="sr-text">' + snippet(s, words) + "</div></a>";
    }).join("");
  }

  if (input && box) {
    input.addEventListener("focus", function () { buildIndex(); });
    input.addEventListener("input", function () {
      var q = input.value;
      if (!index) { box.hidden = false; box.innerHTML = '<div class="sr-empty">Загрузка…</div>'; }
      buildIndex().then(function () { if (input.value === q) render(q); });
    });
    input.addEventListener("keydown", function (e) {
      var items = $$("a", box);
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        if (!items.length) return;
        e.preventDefault();
        active = (active + (e.key === "ArrowDown" ? 1 : -1) + items.length) % items.length;
        items.forEach(function (a, i) { a.classList.toggle("is-active", i === active); });
        items[active].scrollIntoView({ block: "nearest" });
      } else if (e.key === "Enter") {
        var go = items[active] || items[0];
        if (go) location.href = go.href;
      } else if (e.key === "Escape") {
        box.hidden = true;
        input.blur();
      }
    });
    document.addEventListener("click", function (e) { if (!e.target.closest(".search")) box.hidden = true; });
    document.addEventListener("keydown", function (e) {
      if (e.key === "/" && !/^(INPUT|TEXTAREA)$/.test(document.activeElement.tagName)) { e.preventDefault(); input.focus(); }
    });
  }
})();
