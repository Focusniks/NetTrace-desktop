// Application version, injected at build time from package.json (kept in sync
// with tauri.conf.json and Cargo.toml by scripts/release.mjs).

declare const __APP_VERSION__: string;

export const APP_VERSION: string = __APP_VERSION__;
