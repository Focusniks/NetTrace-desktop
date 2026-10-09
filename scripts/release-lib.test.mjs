import assert from "node:assert/strict";
import { test } from "node:test";

import {
  bumpCargoLock,
  bumpCargoToml,
  bumpJson,
  checkManifest,
  compareVersions,
  extractNotes,
  minisignKeyId,
  parseVersion,
  readCargoVersion,
  releaseChangelog,
  signatureComment,
} from "./release-lib.mjs";

test("parseVersion accepts X.Y.Z with optional v", () => {
  assert.equal(parseVersion("1.2.3"), "1.2.3");
  assert.equal(parseVersion("v1.0.0"), "1.0.0");
  for (const bad of ["1.2", "1.2.3-beta", "01.2.3", "", "x"]) assert.throws(() => parseVersion(bad));
});

test("compareVersions orders numerically", () => {
  assert.ok(compareVersions("1.10.0", "1.9.9") > 0);
  assert.ok(compareVersions("1.0.0", "1.0.1") < 0);
  assert.equal(compareVersions("v2.0.0", "2.0.0"), 0);
});

test("bumpCargoToml only touches [workspace.package]", () => {
  const src = '[workspace]\nmembers = []\n\n[workspace.package]\nversion = "0.1.0"\nedition = "2021"\n\n[workspace.dependencies]\nserde = { version = "1" }\n';
  const out = bumpCargoToml(src, "1.0.0");
  assert.match(out, /\[workspace\.package\]\nversion = "1\.0\.0"/);
  assert.match(out, /serde = \{ version = "1" \}/);
  assert.throws(() => bumpCargoToml("[package]\nversion = \"1\"\n", "1.0.0"));
});

test("bumpCargoLock changes only local workspace packages and keeps CRLF", () => {
  const src = [
    "version = 4",
    "",
    "[[package]]",
    'name = "nettrace-engine"',
    'version = "0.1.0"',
    "dependencies = [",
    ' "serde",',
    "]",
    "",
    "[[package]]",
    'name = "serde"',
    'version = "0.1.0"',
    'source = "registry+https://github.com/rust-lang/crates.io-index"',
    "",
  ].join("\r\n");
  const out = bumpCargoLock(src, ["nettrace-engine"], "1.0.0");
  assert.match(out, /name = "nettrace-engine"\r\nversion = "1\.0\.0"/);
  assert.match(out, /name = "serde"\r\nversion = "0\.1\.0"/);
  assert.ok(!/[^\r]\n/.test(out));
  // Every named crate must be found as a local package (serde is a registry one).
  assert.throws(() => bumpCargoLock(src, ["nettrace-engine", "serde"], "1.0.0"), /serde/);
  assert.throws(() => bumpCargoLock(src, ["missing"], "1.0.0"), /missing/);
});

test("readCargoVersion reads the table even after array fields", () => {
  const src = '[workspace.package]\nauthors = ["a"]\nkeywords = [\n  "x",\n]\nversion = "2.3.4"\n\n[dependencies]\nversion = "9"\n';
  assert.equal(readCargoVersion(src), "2.3.4");
  assert.throws(() => readCargoVersion('[package]\nversion = "1"\n'));
});

test("bumpJson updates version and package-lock root", () => {
  const lock = JSON.stringify({ name: "a", version: "0.1.0", packages: { "": { name: "a", version: "0.1.0" }, "node_modules/x": { version: "0.1.0" } } }, null, 2) + "\n";
  const out = JSON.parse(bumpJson(lock, "1.0.0"));
  assert.equal(out.version, "1.0.0");
  assert.equal(out.packages[""].version, "1.0.0");
  assert.equal(out.packages["node_modules/x"].version, "0.1.0");
});

const CHANGELOG = "# Changelog\n\n## [Unreleased]\n\n### Added\n- Updates\n\n## [0.9.0] - 2026-01-01\n\n- Old\n";

test("releaseChangelog moves Unreleased notes under the version", () => {
  const out = releaseChangelog(CHANGELOG, "1.0.0", "2026-10-09");
  assert.equal(out, "# Changelog\n\n## [Unreleased]\n\n## [1.0.0] - 2026-10-09\n\n### Added\n- Updates\n\n## [0.9.0] - 2026-01-01\n\n- Old\n");
  assert.equal(extractNotes(out, "1.0.0"), "### Added\n- Updates");
  assert.equal(extractNotes(out, "0.9.0"), "- Old");
});

test("releaseChangelog refuses empty notes and duplicate versions", () => {
  const released = releaseChangelog(CHANGELOG, "1.0.0", "2026-10-09");
  assert.throws(() => releaseChangelog(released, "1.0.1", "2026-10-09"), /empty/);
  assert.throws(() => releaseChangelog(CHANGELOG, "0.9.0", "2026-10-09"), /already exists/);
  assert.throws(() => extractNotes(CHANGELOG, "2.0.0"), /no section/);
});

test("releaseChangelog keeps CRLF files CRLF", () => {
  const out = releaseChangelog(CHANGELOG.replace(/\n/g, "\r\n"), "1.0.0", "2026-10-09");
  assert.ok(!/[^\r]\n/.test(out));
});

// A real update signature (public data) from a test build, and the app's public key.
const SIG_002 =
  "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVRd1ZidDQ1S1lqbmN3VHRXUEVUT1JWb05mT1BUTFMwNUU3ekZOUjF2R2tVRFlIZTE4d0VqNnlTa2lwYnU4ZlVKTmJwVStQcmxnYXI1NzFIbmFBU1d0MllmWHVlMVQyTndvPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzkxNTEyMTAwCWZpbGU6TmV0VHJhY2VfMC4wLjJfeDY0LXNldHVwLmV4ZQl2ZXJzaW9uOjAuMC4yCkU5OUxXWVNMSXdMQzdtV1FISVJtOHB5UkFNaXJURlJlWGpSRlNJYjdVcUl0a2g1MkZXaW9sOUVqaEIwREdrSnJNcjNzQ0NoaGZiNGtyY2FyajJoOENRPT0K";
const PUBKEY =
  "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDlEMjNBNkU0NzhCQjU1MzAKUldRd1ZidDQ1S1lqbmQ3WWFPUTRLdW9VSzRXcWhYK2ZTWWJiQnBVaUtpKy9GYUVWS2lWY0o5cGwK";
const REPO = "https://github.com/Focusniks/NetTrace-desktop";
const manifest = (over = {}) => ({
  version: "0.0.2",
  platforms: {
    "windows-x86_64": { signature: SIG_002, url: `${REPO}/releases/download/v0.0.2/NetTrace_0.0.2_x64-setup.exe`, ...over },
  },
});

test("minisign key ids of the signature and the app key match", () => {
  assert.equal(minisignKeyId(SIG_002), minisignKeyId(PUBKEY));
  assert.match(signatureComment(SIG_002), /\tversion:0\.0\.2$/);
});

test("checkManifest accepts a consistent release", () => {
  assert.deepEqual(checkManifest(manifest(), SIG_002, PUBKEY, "0.0.2", REPO), []);
});

test("checkManifest rejects wrong version, foreign URL, other key and missing sig", () => {
  assert.ok(checkManifest(manifest(), SIG_002, PUBKEY, "0.0.3", REPO).some((e) => /does not bind/.test(e)));
  assert.ok(checkManifest(manifest({ url: "https://evil.example/x.exe" }), SIG_002, PUBKEY, "0.0.2", REPO).some((e) => /not under/.test(e)));
  const otherKey = Buffer.from("untrusted comment: k\nRWQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n").toString("base64");
  assert.ok(checkManifest(manifest(), SIG_002, otherKey, "0.0.2", REPO).some((e) => /does not trust/.test(e)));
  assert.ok(checkManifest(manifest(), "", PUBKEY, "0.0.2", REPO).some((e) => /differs/.test(e)));
  assert.deepEqual(checkManifest({ version: "0.0.2", platforms: {} }, SIG_002, PUBKEY, "0.0.2", REPO), ["latest.json has no windows-x86_64 platform"]);
});
