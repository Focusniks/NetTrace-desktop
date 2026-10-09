// Pure helpers for scripts/release.mjs and scripts/release-ci.mjs (tested by
// release-lib.test.mjs with `node --test scripts/`).

const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

/** Validates "X.Y.Z" (a leading "v" is accepted) and returns it without the "v". */
export function parseVersion(input) {
  const v = String(input ?? "").trim().replace(/^v/, "");
  if (!SEMVER.test(v)) throw new Error(`invalid version "${input}": expected X.Y.Z`);
  return v;
}

/** Negative, zero or positive like a sort comparator. */
export function compareVersions(a, b) {
  const pa = parseVersion(a).split(".").map(Number);
  const pb = parseVersion(b).split(".").map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
}

const eolOf = (text) => (text.includes("\r\n") ? "\r\n" : "\n");
const toEol = (text, eol) => text.replace(/\r?\n/g, eol);

/** Index of the `version` line in the [workspace.package] table, or -1. */
function workspaceVersionLine(lines) {
  let inTable = false;
  for (let i = 0; i < lines.length; i++) {
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(lines[i]);
    if (header) inTable = header[1].trim() === "workspace.package";
    else if (inTable && /^\s*version\s*=/.test(lines[i])) return i;
  }
  return -1;
}

/** The version in the [workspace.package] table of the root Cargo.toml. */
export function readCargoVersion(text) {
  const lines = text.split(/\r?\n/);
  const i = workspaceVersionLine(lines);
  const v = i < 0 ? undefined : /=\s*"([^"]*)"/.exec(lines[i])?.[1];
  if (v === undefined) throw new Error("Cargo.toml: no version in [workspace.package]");
  return v;
}

/** Sets `version` in the [workspace.package] table of the root Cargo.toml. */
export function bumpCargoToml(text, version) {
  const lines = text.split(/\r?\n/);
  const i = workspaceVersionLine(lines);
  if (i < 0) throw new Error("Cargo.toml: no version in [workspace.package]");
  lines[i] = `version = "${version}"`;
  return lines.join(eolOf(text));
}

/** Sets the version of the local (source-less) Cargo.lock packages named in `names`. */
export function bumpCargoLock(text, names, version) {
  const eol = eolOf(text);
  const wanted = new Set(names);
  const blocks = text.split(/(?=^\[\[package\]\]\s*$)/m);
  const bumped = new Set();
  const out = blocks.map((block) => {
    const name = /^name = "([^"]+)"\s*$/m.exec(block)?.[1];
    if (!name || !wanted.has(name) || /^source = /m.test(block)) return block;
    if (/^version = "[^"]*"\r?$/m.test(block)) bumped.add(name);
    return block.replace(/^version = "[^"]*"(\r?)$/m, `version = "${version}"$1`);
  });
  const missing = names.filter((n) => !bumped.has(n));
  if (missing.length) throw new Error(`Cargo.lock: workspace packages not found: ${missing.join(", ")}`);
  return toEol(out.join(""), eol);
}

/** Sets the top-level "version" of a JSON document (and the root package of a package-lock). */
export function bumpJson(text, version) {
  const eol = eolOf(text);
  const doc = JSON.parse(text);
  if (typeof doc.version !== "string") throw new Error("JSON: no top-level version");
  doc.version = version;
  if (doc.packages && doc.packages[""]) doc.packages[""].version = version;
  return toEol(JSON.stringify(doc, null, 2) + "\n", eol);
}

const escapeDots = (version) => version.replace(/\./g, "\\.");

const UNRELEASED = /^## \[Unreleased\][^\n]*$/im;
const ANY_SECTION = /^## \[/m;

function sectionBody(text, headingMatch) {
  const start = headingMatch.index + headingMatch[0].length;
  const rest = text.slice(start);
  const next = ANY_SECTION.exec(rest);
  return { start, end: next ? start + next.index : text.length };
}

/** Moves the "Unreleased" notes under a new "## [version] - date" heading. */
export function releaseChangelog(text, version, date) {
  const eol = eolOf(text);
  const src = text.replace(/\r\n/g, "\n");
  const heading = UNRELEASED.exec(src);
  if (!heading) throw new Error('CHANGELOG.md: no "## [Unreleased]" section');
  if (new RegExp(`^## \\[${escapeDots(version)}\\]`, "m").test(src)) {
    throw new Error(`CHANGELOG.md: version ${version} already exists`);
  }
  const { start, end } = sectionBody(src, heading);
  const body = src.slice(start, end).trim();
  if (!body) throw new Error('CHANGELOG.md: the "Unreleased" section is empty — describe the changes first');
  const out = `${src.slice(0, start)}\n\n## [${version}] - ${date}\n\n${body}\n\n${src.slice(end).replace(/^\n+/, "")}`;
  return toEol(out.replace(/\n{3,}/g, "\n\n").replace(/\n*$/, "\n"), eol);
}

/** The notes of one released version (used as GitHub release text and in-app "what's new"). */
export function extractNotes(text, version) {
  const src = text.replace(/\r\n/g, "\n");
  const heading = new RegExp(`^## \\[${escapeDots(version)}\\][^\\n]*$`, "m").exec(src);
  if (!heading) throw new Error(`CHANGELOG.md: no section for ${version}`);
  const { start, end } = sectionBody(src, heading);
  const body = src.slice(start, end).trim();
  if (!body) throw new Error(`CHANGELOG.md: section ${version} is empty`);
  return body;
}

/** The 8-byte key id of a Tauri/minisign public key or signature (both base64-wrapped text files). */
export function minisignKeyId(wrapped) {
  const text = Buffer.from(String(wrapped).trim(), "base64").toString("utf8");
  const line = text.split(/\r?\n/).find((l) => l && !/^(untrusted|trusted) comment:/.test(l));
  const raw = line ? Buffer.from(line.trim(), "base64") : Buffer.alloc(0);
  if (raw.length < 10) throw new Error("malformed minisign key or signature");
  return raw.subarray(2, 10).toString("hex");
}

/** The trusted comment of a Tauri update signature (contains "version:X.Y.Z"). */
export function signatureComment(wrapped) {
  const text = Buffer.from(String(wrapped).trim(), "base64").toString("utf8");
  return /^trusted comment: (.*)$/m.exec(text)?.[1] ?? "";
}

/**
 * Checks a release's latest.json before it is published: it must announce
 * `version`, point to an installer of this release in `repoUrl`, carry the
 * uploaded signature, and that signature must be made with the key the app
 * trusts and bind the version (the app sets requireSignedVersion).
 */
export function checkManifest(manifest, sigText, pubkey, version, repoUrl) {
  const errors = [];
  if (manifest.version !== version) errors.push(`latest.json version is ${manifest.version}, expected ${version}`);
  const win = manifest.platforms?.["windows-x86_64"];
  if (!win) {
    errors.push("latest.json has no windows-x86_64 platform");
    return errors;
  }
  const prefix = `${repoUrl}/releases/download/v${version}/`;
  if (typeof win.url !== "string" || !win.url.startsWith(prefix)) errors.push(`installer URL ${win.url} is not under ${prefix}`);
  if (String(win.signature).trim() !== String(sigText).trim()) errors.push("latest.json signature differs from the uploaded .sig");
  try {
    if (minisignKeyId(win.signature) !== minisignKeyId(pubkey)) errors.push("the package is signed with a key the app does not trust (pubkey mismatch)");
  } catch (e) {
    errors.push(e.message);
  }
  if (!signatureComment(win.signature).split("\t").includes(`version:${version}`)) errors.push(`the signature does not bind version ${version}`);
  return errors;
}
