#!/usr/bin/env node
// Helpers for .github/workflows/release.yml.
//
//   node scripts/release-ci.mjs check v1.0.1         tag must match every version field
//   node scripts/release-ci.mjs notes v1.0.1 <file>  write the CHANGELOG section to <file>
//   node scripts/release-ci.mjs manifest v1.0.1 <dir> check latest.json + .sig downloaded to <dir>

import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { checkManifest, extractNotes, parseVersion, readCargoVersion } from "./release-lib.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (rel) => readFileSync(join(ROOT, rel), "utf8");

function fail(message) {
  console.error(`release-ci: ${message}`);
  process.exit(1);
}

const [command, tag, out] = process.argv.slice(2);
let version;
try {
  version = parseVersion(tag);
} catch (e) {
  fail(e.message);
}

if (command === "check") {
  const found = {
    "apps/desktop/src-tauri/tauri.conf.json": JSON.parse(read("apps/desktop/src-tauri/tauri.conf.json")).version,
    "apps/desktop/package.json": JSON.parse(read("apps/desktop/package.json")).version,
    "Cargo.toml [workspace.package]": readCargoVersion(read("Cargo.toml")),
  };
  const wrong = Object.entries(found).filter(([, v]) => v !== version);
  if (wrong.length) fail(`tag ${tag} does not match: ${wrong.map(([f, v]) => `${f}=${v}`).join(", ")}`);
  console.log(`release-ci: all versions are ${version}`);
} else if (command === "notes") {
  if (!out) fail("usage: release-ci.mjs notes <tag> <file>");
  try {
    writeFileSync(out, extractNotes(read("CHANGELOG.md"), version) + "\n", "utf8");
  } catch (e) {
    fail(e.message);
  }
} else if (command === "manifest") {
  if (!out) fail("usage: release-ci.mjs manifest <tag> <dir>");
  const sigs = readdirSync(out).filter((f) => f.endsWith(".sig"));
  if (sigs.length !== 1) fail(`expected one .sig in ${out}, found ${sigs.length}`);
  const manifest = JSON.parse(readFileSync(join(out, "latest.json"), "utf8"));
  const pubkey = JSON.parse(read("apps/desktop/src-tauri/tauri.conf.json")).plugins.updater.pubkey;
  const errors = checkManifest(manifest, readFileSync(join(out, sigs[0]), "utf8"), pubkey, version, "https://github.com/Focusniks/NetTrace-desktop");
  if (errors.length) fail(`latest.json is not publishable:\n  ${errors.join("\n  ")}`);
  console.log(`release-ci: latest.json announces ${version}, signed with the trusted key`);
} else {
  fail("usage: release-ci.mjs <check|notes|manifest> <tag> [file|dir]");
}
