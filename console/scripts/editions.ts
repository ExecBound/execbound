// SPDX-License-Identifier: AGPL-3.0-only
// The console's editions (#496): the core edition, which `vite build` makes and the
// package, the self-hosted image and the export carry, and the hosted one, which
// `vite build --mode hosted` makes. This module holds the build's own parts of that split: which
// edition a mode builds and where it is written, the edition's name in the document it writes,
// the core build's refusal of any module under src/hosted/, and the hosted build's return of
// src/hosted/'s classes to Tailwind.

import { existsSync, realpathSync } from "node:fs";
import path from "node:path";

import { normalizePath, type Plugin } from "vite";

/** console/, by its real path, from which the build's relative directories are resolved. */
const CONSOLE = realpathSync.native(path.dirname(import.meta.dirname));

export type EditionName = "core" | "hosted";

/** The edition a Vite mode builds: only the `hosted` mode builds the hosted edition. */
export function editionFor(mode: string): EditionName {
  return mode === "hosted" ? "hosted" : "core";
}

/**
 * Where each edition's build is written, relative to console/. Core's is the package's own
 * directory, which `uv build`, the wheel and the image carry; the hosted edition's stays beside
 * the sources, so building it never replaces what the package carries. A build of another
 * edition that the package must carry, such as an image's, names the package's directory
 * through CONSOLE_OUT_DIR.
 */
export const OUT_DIRS: Readonly<Record<EditionName, string>> = {
  core: "../src/execbound/surfaces/console_dist",
  hosted: "dist/hosted",
};

/**
 * The directory an edition's build is written to: CONSOLE_OUT_DIR where it is set and not
 * blank, and the edition's own otherwise.
 *
 * The build empties its directory before it writes, so CONSOLE_OUT_DIR may name only the
 * package's build directory or a directory inside console/dist/, and anything else is refused
 * here, before Vite resolves it. Unguarded, an empty value names console/ itself, whose emptying
 * takes the sources and node_modules with it, and `..` empties the repository.
 */
export function outDir(edition: EditionName, env: Readonly<Record<string, string | undefined>>): string {
  const named = env.CONSOLE_OUT_DIR;
  if (named === undefined || named.trim() === "") return OUT_DIRS[edition];
  const dir = path.resolve(CONSOLE, named);
  const pkg = path.resolve(CONSOLE, OUT_DIRS.core);
  const dist = path.join(CONSOLE, "dist");
  if (dir !== pkg && !dir.startsWith(dist + path.sep)) {
    throw new Error(
      `CONSOLE_OUT_DIR="${named}" names ${dir}, which the build would empty before writing. ` +
        `It may name only the package's build directory (${pkg}) or a directory inside ${dist}.`,
    );
  }
  return named;
}

/** The document's empty edition tag (index.html), which every build fills. */
export const EDITION_TAG = '<meta name="execbound-edition" content="" />';

/** The document with its edition named, which the server reads and `/health/ready` reports. */
export function nameEdition(html: string, edition: EditionName): string {
  if (!html.includes(EDITION_TAG)) throw new Error("The console document has no edition tag to fill");
  return html.replace(EDITION_TAG, `<meta name="execbound-edition" content="${edition}" />`);
}

/** The build's plugin that names the edition in the document. */
export function editionMeta(edition: EditionName): Plugin {
  return { name: "execbound-edition", transformIndexHtml: (html) => nameEdition(html, edition) };
}

/**
 * The license each edition's generated route tree names. Every other file carries its line from
 * `scripts/licence_headers.py --write`, but the router rewrites this one whole on every build, so
 * its line comes from the router's own header option, the same identifier the script's map gives
 * the tree's directory.
 */
export const ROUTE_TREE_LICENCES: Readonly<Record<EditionName, string>> = {
  core: "AGPL-3.0-only",
  hosted: "LicenseRef-ExecBound-Proprietary",
};

/**
 * The lines the router writes at the top of an edition's route tree: the license line first, then
 * the router's three defaults, which the option replaces rather than extends.
 */
export function routeTreeFileHeader(edition: EditionName): string[] {
  return [
    `// SPDX-License-Identifier: ${ROUTE_TREE_LICENCES[edition]}`,
    "/* eslint-disable */",
    "// @ts-nocheck",
    "// noinspection JSUnusedGlobalSymbols",
  ];
}

/** The name of the plugin that holds the core build free of hosted code. */
export const CORE_ONLY = "execbound-core-only";

/** What that plugin tells anything that reads the build's plugins, as Vite's plugin `api`. */
export interface CoreOnlyApi {
  /** The directory it refuses, as `hostedDirOf` names it. */
  readonly hostedDir: string;
}

/** A path as the build's module ids name it: its real path, with forward slashes. */
function real(file: string): string {
  return normalizePath(existsSync(file) ? realpathSync.native(file) : file);
}

/**
 * The directory under `root` whose modules the core build refuses, `src/hosted/`, ending in "/".
 * The build names a module by its real path, so this names the directory by its own: a root
 * reached through a link, or a src/hosted that is itself a link, cannot put a hosted module
 * outside it.
 */
export function hostedDirOf(root: string): string {
  return real(path.join(realpathSync.native(root), "src", "hosted")) + "/";
}

/** The module ids under `hostedDir` (an absolute path ending in "/"), sorted. */
export function hostedModules(ids: Iterable<string>, hostedDir: string): string[] {
  return [...ids].filter((id) => id.startsWith(hostedDir)).sort();
}

/** What the core build says when it reached hosted code, or null when it did not. */
export function refusal(ids: Iterable<string>, hostedDir: string): string | null {
  const found = hostedModules(ids, hostedDir);
  return found.length === 0 ? null : `The core build reached hosted code: ${found.join(", ")}`;
}

/**
 * Refuse a core build that reached a file under `hostedDir`. Vite's configuration runs it in the
 * build and, through `worker.plugins`, in every worker bundle the build makes.
 *
 * - **Modules.** Once the build ends it lists every module it loaded, so a static or lazy
 *   import, a glob, a `?raw` or `?url` import, or a worker's entry fails here, directly or
 *   through an alias or a link.
 * - **Assets.** Before anything is written it reads the source of every emitted asset, so a file
 *   that `new URL(..., import.meta.url)` or a stylesheet's `url()` would copy into the build
 *   fails too, though no module names it.
 * - **Not a stylesheet's `@import`.** The CSS pipeline inlines an imported stylesheet, so neither
 *   list names it; `scripts/editions.test.ts` reads core's stylesheets for a hosted path instead.
 */
export function coreOnly(hostedDir: string): Plugin<CoreOnlyApi> {
  // An asset's source is named relative to the root; the configuration says which, and the
  // working directory is Vite's own default.
  let root = process.cwd();
  const refuse = (ids: Iterable<string>, error: (message: string) => never) => {
    const message = refusal(ids, hostedDir);
    if (message !== null) error(message);
  };
  return {
    name: CORE_ONLY,
    apply: "build",
    api: { hostedDir },
    configResolved(config) {
      root = config.root;
    },
    buildEnd() {
      refuse(this.getModuleIds(), (message) => this.error(message));
    },
    generateBundle(_options, bundle) {
      const sources = Object.values(bundle).flatMap((file) =>
        file.type === "asset" ? file.originalFileNames.map((name) => real(path.resolve(root, name))) : [],
      );
      refuse(sources, (message) => this.error(message));
    },
  };
}

/** The name of the plugin that gives the hosted build's stylesheet src/hosted/'s classes back. */
export const HOSTED_STYLES = "execbound-hosted-styles";

/** What that plugin tells anything that reads the build's plugins, as Vite's plugin `api`. */
export interface HostedStylesApi {
  /** The stylesheet it rewrites, as the build's module ids name it. */
  readonly stylesheet: string;
}

/** The line in core's stylesheet that leaves the hosted sources out of Tailwind's scan, alone on its line. */
const LEAVE_HOSTED_OUT = /^@source not "\.\.\/hosted";$/m;

/**
 * The module ids Tailwind never compiles, whatever their extension: the dependency cache, and a
 * stylesheet imported as a worker, a raw string, a URL or a CommonJS proxy. The same patterns as
 * `@tailwindcss/vite`'s own, so this plugin reads exactly the stylesheets Tailwind does.
 */
const NOT_COMPILED = [/\/\.vite\//, /[?&](?:worker|sharedworker|raw|url)\b/, /\?commonjs-proxy/];

/**
 * Give Tailwind the hosted sources back in the hosted build. Core's stylesheet (`stylesheet`,
 * src/styles/app.css by its real path with forward slashes) leaves src/hosted/ out of the scan,
 * so core's CSS carries no class only a hosted module uses, and a later `@source` naming the
 * directory does not undo that, in the same stylesheet or in one that imports it. So this plugin
 * takes the line out before Tailwind reads the stylesheet.
 *
 * - **Only the hosted build** lists it; core's build compiles the stylesheet as it is written.
 * - **Before Tailwind.** Both are `enforce: "pre"`, so the order of the build's plugin list
 *   decides. After Tailwind, this plugin would see the stylesheet Tailwind already compiled.
 * - **Loudly, both ways.** A stylesheet without the line fails the build, which is what either
 *   mistake looks like from here: the line was taken out of core's stylesheet, or this plugin
 *   runs after Tailwind, whose output has no `@source`. And a build that never compiled the
 *   stylesheet this plugin names fails when it ends, so a wrong path cannot drop the hosted
 *   classes with nothing said.
 */
export function hostedStyles(stylesheet: string): Plugin<HostedStylesApi> {
  // A development server compiles a stylesheet only when a page asks for it, so only a build
  // is held to having compiled it.
  let building = false;
  let seen = false;
  return {
    name: HOSTED_STYLES,
    enforce: "pre",
    api: { stylesheet },
    configResolved(config) {
      building = config.command === "build";
    },
    transform(code, id) {
      if (NOT_COMPILED.some((pattern) => pattern.test(id))) return null;
      if (normalizePath(id.split("?")[0] ?? "") !== stylesheet) return null;
      seen = true;
      if (!LEAVE_HOSTED_OUT.test(code)) {
        this.error(
          `${stylesheet} has no line @source not "../hosted"; to take out, so the hosted build ` +
            "cannot give Tailwind the hosted sources back: either the line is gone from core's " +
            "stylesheet, or this plugin runs after Tailwind, which has already compiled it.",
        );
      }
      return code.replace(LEAVE_HOSTED_OUT, "");
    },
    buildEnd(error) {
      // A build that already failed says why itself.
      if (!building || seen || error !== undefined) return;
      this.error(
        `The hosted build never compiled ${stylesheet}, so it gave Tailwind no hosted sources: ` +
          "the path names no stylesheet the build reached.",
      );
    },
  };
}
