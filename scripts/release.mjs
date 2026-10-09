#!/usr/bin/env node
// Cuts a release: bumps the version everywhere, dates the CHANGELOG section,
// commits, tags vX.Y.Z and pushes. GitHub Actions (.github/workflows/release.yml)
// then builds, signs and publishes the installer and the update manifest.
//
//   node scripts/release.mjs 1.0.1            (or: npm run release -- 1.0.1 in apps/desktop)
//   node scripts/release.mjs 1.0.1 --no-push  commit and tag locally only
//   node scripts/release.mjs 1.0.1 --no-git   only edit files (local test builds)
//
// Every step is checked before anything is published; on failure the files,
// the release commit and the tag are rolled back.

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { bumpCargoLock, bumpCargoToml, bumpJson, compareVersions, parseVersion, readCargoVersion, releaseChangelog } from "./release-lib.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FILES = {
  cargoToml: "Cargo.toml",
  cargoLock: "Cargo.lock",
  packageJson: "apps/desktop/package.json",
  packageLock: "apps/desktop/package-lock.json",
  tauriConf: "apps/desktop/src-tauri/tauri.conf.json",
  changelog: "CHANGELOG.md",
};

const read = (rel) => readFileSync(join(ROOT, rel), "utf8");
const write = (rel, text) => writeFileSync(join(ROOT, rel), text, "utf8");
const run = (cmd, args) => execFileSync(cmd, args, { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
const git = (...args) => run("git", args);

class ReleaseError extends Error {}

function fail(message) {
  throw new ReleaseError(message);
}

/** Names of workspace crates that inherit the workspace version. */
function workspaceCrates() {
  const toml = read(FILES.cargoToml);
  const members = /^members\s*=\s*\[([\s\S]*?)\]/m.exec(toml)?.[1] ?? "";
  const names = [];
  for (const [, dir] of members.matchAll(/"([^"]+)"/g)) {
    const crate = read(`${dir}/Cargo.toml`);
    const name = /^name\s*=\s*"([^"]+)"/m.exec(crate)?.[1];
    if (name && /^version\.workspace\s*=\s*true/m.test(crate)) names.push(name);
  }
  if (!names.length) fail("no workspace crates found in Cargo.toml");
  return names;
}

function today() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

function parseArgs(argv) {
  const flags = new Set(argv.filter((a) => a.startsWith("--")));
  const positional = argv.filter((a) => !a.startsWith("--"));
  for (const f of flags) if (!["--no-git", "--no-push"].includes(f)) fail(`unknown option ${f}`);
  if (flags.has("--no-git") && flags.has("--no-push")) fail("--no-git and --no-push cannot be combined");
  if (positional.length !== 1) fail("usage: release.mjs <X.Y.Z> [--no-push | --no-git]");
  return { version: parseVersion(positional[0]), useGit: !flags.has("--no-git"), push: !flags.has("--no-git") && !flags.has("--no-push") };
}

/** Local main must contain origin/main, and the tag must not exist anywhere yet. */
function checkGit(tag, push) {
  if (git("status", "--porcelain")) fail("the working tree has uncommitted changes — commit or stash them first");
  const branch = git("rev-parse", "--abbrev-ref", "HEAD");
  if (branch !== "main") fail(`releases are cut from main (current branch: ${branch})`);
  if (git("tag", "--list", tag)) fail(`tag ${tag} already exists locally`);
  if (!push) return;
  try {
    git("fetch", "--quiet", "origin", "main");
  } catch (e) {
    fail(`cannot reach GitHub (git fetch failed): ${e.stderr || e.message}`);
  }
  const behind = Number(git("rev-list", "--count", "HEAD..origin/main"));
  if (behind > 0) fail(`main is ${behind} commit(s) behind origin/main — run git pull first`);
  if (git("ls-remote", "--tags", "origin", `refs/tags/${tag}`)) fail(`tag ${tag} already exists on GitHub`);
}

/** Cargo.lock must match the manifests, or the CI build (--locked) fails after the tag is public. */
function checkCargoLock() {
  try {
    run("cargo", ["metadata", "--locked", "--offline", "--no-deps", "--format-version", "1"]);
  } catch (e) {
    if (e.code === "ENOENT") fail("cargo not found in PATH (needed to verify Cargo.lock)");
    fail(`Cargo.lock does not match the bumped manifests:\n${e.stderr || e.message}`);
  }
}

function main() {
  const { version, useGit, push } = parseArgs(process.argv.slice(2));
  const tag = `v${version}`;
  const current = JSON.parse(read(FILES.tauriConf)).version;
  if (compareVersions(version, current) <= 0) fail(`${version} must be greater than the current version ${current}`);
  if (useGit) checkGit(tag, push);

  // All new texts are computed (and validated) before anything is written.
  const originals = Object.fromEntries(Object.values(FILES).map((f) => [f, read(f)]));
  const edits = {
    [FILES.cargoToml]: bumpCargoToml(originals[FILES.cargoToml], version),
    [FILES.cargoLock]: bumpCargoLock(originals[FILES.cargoLock], workspaceCrates(), version),
    [FILES.packageJson]: bumpJson(originals[FILES.packageJson], version),
    [FILES.packageLock]: bumpJson(originals[FILES.packageLock], version),
    [FILES.tauriConf]: bumpJson(originals[FILES.tauriConf], version),
    [FILES.changelog]: releaseChangelog(originals[FILES.changelog], version, today()),
  };
  if (readCargoVersion(edits[FILES.cargoToml]) !== version) fail("Cargo.toml bump did not apply");

  const startSha = useGit ? git("rev-parse", "HEAD") : null;
  let committed = false;
  let tagged = false;
  const rollback = () => {
    if (tagged) git("tag", "-d", tag);
    // The tree was verified clean before the release started.
    if (committed) git("reset", "--hard", startSha);
    else for (const [file, text] of Object.entries(originals)) write(file, text);
  };

  try {
    for (const [file, text] of Object.entries(edits)) write(file, text);
    checkCargoLock();
    console.log(`release: version ${current} → ${version}`);
    for (const file of Object.keys(edits)) console.log(`  updated ${file}`);
    if (!useGit) return;

    git("add", ...Object.keys(edits));
    git("commit", "-m", `Release ${tag}`);
    committed = true;
    git("tag", "-a", tag, "-m", `NetTrace ${tag}`);
    tagged = true;
    console.log(`release: committed and tagged ${tag}`);
    if (!push) {
      console.log(`release: not pushed. Publish with: git push --atomic origin main ${tag}`);
      return;
    }
  } catch (e) {
    rollback();
    throw e;
  }

  try {
    git("push", "--atomic", "origin", "main", tag);
  } catch (e) {
    // --atomic: either both refs were updated or neither. Roll back only when
    // GitHub surely has no tag; otherwise leave everything for a manual check.
    let remoteTag = "";
    try {
      remoteTag = git("ls-remote", "--tags", "origin", `refs/tags/${tag}`);
    } catch {
      remoteTag = "unknown";
    }
    if (!remoteTag) {
      rollback();
      fail(`git push failed, the release was rolled back:\n${e.stderr || e.message}`);
    }
    fail(
      `git push failed and the state of GitHub is unclear:\n${e.stderr || e.message}\n` +
        `Check https://github.com/Focusniks/NetTrace-desktop/tags, then either retry:\n` +
        `  git push --atomic origin main ${tag}\n` +
        `or undo locally:\n  git tag -d ${tag} && git reset --hard ${startSha}`,
    );
  }
  console.log("release: pushed. GitHub Actions is building the release:");
  console.log("  https://github.com/Focusniks/NetTrace-desktop/actions");
}

try {
  main();
} catch (e) {
  if (e instanceof ReleaseError) console.error(`release: ${e.message}`);
  else if (e instanceof Error && !e.stack?.includes("release-lib.mjs")) console.error("release: unexpected error\n", e);
  else console.error(`release: ${e instanceof Error ? e.message : e}`);
  process.exit(1);
}
