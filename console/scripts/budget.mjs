#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
// The size budget (#333), enforced after every build.
//
// Reads Vite's build manifest, follows each entry's static imports and stylesheets, and gzips
// every file it reaches. The shell with Home may load at most 220 KB; an approval link opened
// cold at most 160 KB, because that route is its own chunk and pulls nothing from Home; every
// other route chunk stays under 60 KB beyond what the shell already loaded; and the command
// palette and Base UI's dialog may only ever be reached by a dynamic import. Compressed means
// gzip, which is what a reverse proxy in front of the gateway typically serves. Exits non-zero
// over any budget, so `pnpm build` fails. A hosted edition's route files (`src/hosted/routes/`)
// are routes like core's, except its workspace approval link, which is an approval link opened
// cold like core's (#496).

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

import { editionFor, outDir } from "./editions.ts";

export const BUDGETS = {
  shellWithHome: 220 * 1024,
  approval: 160 * 1024,
  route: 60 * 1024,
};
export const HOME = "src/routes/index.tsx";
export const APPROVAL = "src/routes/approvals.$approvalId.tsx";
// The address a hosted notification opens (#496): an approval link opened cold as well,
// so it is held to the same budget as core's.
export const SCOPED_APPROVAL = "src/hosted/routes/workspaces.$tenantId.approvals.$approvalId.tsx";
export const PALETTE = "src/components/ui/CommandPalette.tsx";
export const DIALOG = "src/components/ui/DialogPanel.tsx";
export const SHEET = "src/shell/NavigationSheet.tsx";
export const WORKSPACE_MENU = "src/shell/WorkspaceMenu.tsx";
export const SPACE_MENU = "src/shell/SpaceMenu.tsx";
// What the shell does after its first frame, the navigation sheet and the keyboard among it (#678).
export const AFTER_PAINT = "src/shell/AfterPaint.tsx";
const ROUTES = ["src/routes/", "src/hosted/routes/"];
const ROOT_ROUTE = "src/routes/__root.tsx";

/** What may only ever be reached by a dynamic import, and what a finding calls it. */
const LAZY = [
  [PALETTE, "the command palette"],
  [DIALOG, "Base UI's dialog"],
  [SHEET, "the navigation sheet"],
  [WORKSPACE_MENU, "the workspace menu"],
  [SPACE_MENU, "the space menu"],
  [AFTER_PAINT, "the shell's after-paint layer"],
];

/**
 * @typedef {{ file: string, isEntry?: boolean, imports?: string[], css?: string[] }} Chunk
 * @typedef {Record<string, Chunk>} Manifest
 * @typedef {(file: string) => number} SizeOf
 * @typedef {[string, number, number]} Row
 */

/**
 * The manifest key without the query TanStack Router adds when it splits a route.
 * @param {string} key
 * @returns {string}
 */
export function source(key) {
  return key.split("?")[0];
}

/**
 * Every output file an entry loads statically: its own, its stylesheets, its imports.
 * @param {Manifest} manifest
 * @param {string} key
 * @returns {Set<string>}
 */
export function closure(manifest, key) {
  /** @type {Set<string>} */
  const seen = new Set();
  /** @type {Set<string>} */
  const found = new Set();
  /** @param {string} name */
  const visit = (name) => {
    if (seen.has(name)) return;
    seen.add(name);
    const chunk = manifest[name];
    if (chunk === undefined) return;
    found.add(chunk.file);
    for (const css of chunk.css ?? []) found.add(css);
    for (const imported of chunk.imports ?? []) visit(imported);
  };
  visit(key);
  return found;
}

/**
 * Rows of [label, bytes, budget] and the findings, over a manifest and a size function.
 * @param {Manifest} manifest
 * @param {SizeOf} sizeOf
 * @returns {{ rows: Row[], findings: string[] }}
 */
export function evaluate(manifest, sizeOf) {
  const keys = Object.keys(manifest);
  const entry = keys.find((key) => manifest[key].isEntry === true);
  if (entry === undefined) return { rows: [], findings: ["the manifest has no entry"] };
  const shell = closure(manifest, entry);
  /** @param {Iterable<string>} files */
  const sum = (files) => [...files].reduce((total, file) => total + sizeOf(file), 0);
  /** @param {string} key */
  const beyondShell = (key) => sum([...closure(manifest, key)].filter((file) => !shell.has(file)));
  const routeKeys = keys.filter((key) => {
    const name = source(key);
    return ROUTES.some((prefix) => name.startsWith(prefix)) && name !== ROOT_ROUTE;
  });
  /** @param {string} file */
  const chunksOf = (file) => routeKeys.filter((key) => source(key) === file);
  /** @type {Row[]} */
  const rows = [];
  /** @type {string[]} */
  const findings = [];
  /** @param {number} bytes */
  const kb = (bytes) => `${(bytes / 1024).toFixed(1)} KB`;

  const shellSize = sum(shell);
  const home = chunksOf(HOME).reduce((total, key) => total + beyondShell(key), 0);
  rows.push(["shell with Home", shellSize + home, BUDGETS.shellWithHome]);
  if (shellSize + home > BUDGETS.shellWithHome) {
    findings.push(`the shell with Home loads ${kb(shellSize + home)}, over ${kb(BUDGETS.shellWithHome)}`);
  }

  for (const [file, label, finding] of [
    [APPROVAL, "approval link, cold", "an approval link"],
    [SCOPED_APPROVAL, "workspace approval link, cold", "a workspace approval link"],
  ]) {
    const approvalChunks = chunksOf(file);
    if (approvalChunks.length === 0) continue;
    const approval = shellSize + approvalChunks.reduce((total, key) => total + beyondShell(key), 0);
    rows.push([label, approval, BUDGETS.approval]);
    if (approval > BUDGETS.approval) {
      findings.push(`${finding} loads ${kb(approval)}, over ${kb(BUDGETS.approval)}`);
    }
  }

  for (const key of routeKeys) {
    const name = source(key);
    if (name === HOME || name === APPROVAL || name === SCOPED_APPROVAL) continue;
    const size = beyondShell(key);
    rows.push([key, size, BUDGETS.route]);
    if (size >= BUDGETS.route) {
      findings.push(`route chunk ${key} is ${kb(size)}, not under ${kb(BUDGETS.route)}`);
    }
  }

  for (const [module, what] of LAZY) {
    for (const key of keys.filter((key) => source(key) === module)) {
      const file = manifest[key].file;
      if (shell.has(file)) findings.push(`${what} is imported statically by the shell`);
      for (const routeKey of routeKeys) {
        if (closure(manifest, routeKey).has(file)) {
          findings.push(`${what} is imported statically by ${routeKey}`);
        }
      }
    }
  }
  return { rows, findings };
}

function main() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  // The edition is the first argument (`node scripts/budget.mjs hosted`), as `vite build --mode`
  // names it; the directory is the one vite.config.ts wrote for that edition.
  const dir = path.resolve(here, "..", outDir(editionFor(process.argv[2] ?? ""), process.env));
  const manifest = JSON.parse(readFileSync(path.join(dir, ".vite/manifest.json"), "utf8"));
  const sizeOf = (file) => gzipSync(readFileSync(path.join(dir, file))).length;
  const { rows, findings } = evaluate(manifest, sizeOf);
  for (const [label, bytes, budget] of rows) {
    const mark = bytes > budget ? "OVER" : "ok";
    console.log(`${mark.padEnd(5)} ${(bytes / 1024).toFixed(1).padStart(7)} KB of ${(budget / 1024).toFixed(0).padStart(4)} KB  ${label}`);
  }
  if (findings.length > 0) {
    for (const finding of findings) console.error(`budget: ${finding}`);
    process.exit(1);
  }
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
