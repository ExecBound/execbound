// SPDX-License-Identifier: AGPL-3.0-only
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { loadConfigFromFile, normalizePath, type Alias, type Plugin, type PluginOption, type UserConfig } from "vite";
import { describe, expect, it, vi } from "vitest";

import {
  CORE_ONLY,
  coreOnly,
  EDITION_TAG,
  editionFor,
  HOSTED_STYLES,
  hostedDirOf,
  hostedModules,
  hostedStyles,
  nameEdition,
  OUT_DIRS,
  outDir,
  refusal,
  ROUTE_TREE_LICENCES,
  routeTreeFileHeader,
  type CoreOnlyApi,
  type HostedStylesApi,
} from "./editions";

const HOSTED = "/work/console/src/hosted/";
const CONSOLE = path.dirname(import.meta.dirname);

describe("the core build's refusal of hosted code (#496)", () => {
  it("names every hosted module a build reached, and nothing that merely looks alike", () => {
    const ids = [
      "/work/console/src/main.tsx",
      "/work/console/src/hosted/metrics.ts",
      "/work/console/src/hostedness.ts",
      "/work/console/src/hosted/edition.tsx",
      "\0vite/modulepreload-polyfill",
    ];
    expect(hostedModules(ids, HOSTED)).toEqual([
      "/work/console/src/hosted/edition.tsx",
      "/work/console/src/hosted/metrics.ts",
    ]);
  });

  it("refuses a core build that reached one, and passes one that did not", () => {
    expect(refusal(["/work/console/src/main.tsx", "/work/console/src/hosted/metrics.ts"], HOSTED)).toBe(
      "The core build reached hosted code: /work/console/src/hosted/metrics.ts",
    );
    expect(refusal(["/work/console/src/main.tsx"], HOSTED)).toBeNull();
  });
});

/** The plugin's hooks as the build calls them, with the context each one uses. */
interface Hooks {
  configResolved(config: { root: string }): void;
  buildEnd(this: { getModuleIds(): string[]; error(message: string): never }): void;
  generateBundle(this: { error(message: string): never }, options: unknown, bundle: Record<string, unknown>): void;
}

function hooks(plugin: Plugin): Hooks {
  return plugin as unknown as Hooks;
}

function error(message: string): never {
  throw new Error(message);
}

describe("the core-only plugin (#496)", () => {
  it("refuses a hosted module the build loaded", () => {
    const plugin = hooks(coreOnly(HOSTED));
    const loaded = (ids: string[]) => () => {
      plugin.buildEnd.call({ getModuleIds: () => ids, error });
    };
    expect(loaded(["/work/console/src/main.tsx", "/work/console/src/hosted/leak.ts?raw"])).toThrow(
      "The core build reached hosted code: /work/console/src/hosted/leak.ts?raw",
    );
    expect(loaded(["/work/console/src/main.tsx", "/work/console/src/hostedness.ts"])).not.toThrow();
  });

  it("refuses an asset emitted from a hosted file, which it names from the configured root", () => {
    const plugin = hooks(coreOnly(HOSTED));
    plugin.configResolved({ root: "/work/console" });
    const emitted = (bundle: Record<string, unknown>) => () => {
      plugin.generateBundle.call({ error }, {}, bundle);
    };
    const asset = (...originalFileNames: string[]) => ({ type: "asset", originalFileNames });
    expect(
      emitted({
        "assets/index-a.js": { type: "chunk" },
        "assets/logo-b.svg": asset("src/shell/logo.svg"),
        "assets/leak-c.ts": asset("src/hosted/leak.ts"),
      }),
    ).toThrow("The core build reached hosted code: /work/console/src/hosted/leak.ts");
    expect(emitted({ "assets/logo-b.svg": asset("src/shell/logo.svg"), "index.html": asset("index.html") })).not.toThrow();
  });

  it("names src/hosted by its real path, where it or the root is a link", () => {
    const work = realpathSync.native(mkdtempSync(path.join(tmpdir(), "editions-")));
    try {
      const root = path.join(work, "console");
      mkdirSync(path.join(root, "src"), { recursive: true });
      expect(hostedDirOf(root)).toBe(`${normalizePath(path.join(root, "src", "hosted"))}/`);

      mkdirSync(path.join(work, "elsewhere"));
      symlinkSync(path.join(work, "elsewhere"), path.join(root, "src", "hosted"), "junction");
      symlinkSync(root, path.join(work, "link"), "junction");
      const elsewhere = `${normalizePath(path.join(work, "elsewhere"))}/`;
      expect(hostedDirOf(root)).toBe(elsewhere);
      expect(hostedDirOf(path.join(work, "link"))).toBe(elsewhere);
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  });
});

async function pluginsOf(options: PluginOption[] | undefined): Promise<Plugin[]> {
  const found: Plugin[] = [];
  for (const option of options ?? []) {
    const value = await option;
    if (Array.isArray(value)) found.push(...(await pluginsOf(value)));
    else if (value) found.push(value);
  }
  return found;
}

/**
 * The configuration `vite build` runs in a mode, loaded as the build loads it, with no
 * CONSOLE_OUT_DIR, as a developer's and CI's builds have.
 */
async function buildConfig(mode: string): Promise<{ config: UserConfig; plugins: Plugin[]; workerPlugins: Plugin[] }> {
  vi.stubEnv("CONSOLE_OUT_DIR", undefined);
  try {
    const loaded = await loadConfigFromFile({ command: "build", mode }, path.join(CONSOLE, "vite.config.ts"));
    const config = loaded?.config ?? {};
    return { config, plugins: await pluginsOf(config.plugins), workerPlugins: await pluginsOf(config.worker?.plugins?.()) };
  } finally {
    vi.unstubAllEnvs();
  }
}

const names = (plugins: Plugin[]) => plugins.map((plugin) => plugin.name);
const isTailwind = (name: string) => name.startsWith("@tailwindcss/");

/** What the configuration resolves an import of `name` to: the first alias that matches it. */
function aliasOf(config: UserConfig, name: string): string | undefined {
  const aliases = config.resolve?.alias ?? [];
  expect(Array.isArray(aliases)).toBe(true);
  return (aliases as readonly Alias[]).find(({ find }) => (typeof find === "string" ? find === name : find.test(name)))
    ?.replacement;
}

/** A file under console/, as the configuration names it: by its real path. */
const real = (...parts: string[]) => path.join(realpathSync.native(CONSOLE), ...parts);

describe("the core build's configuration (#496)", () => {
  // Loaded as `vite build` loads it, so what is held is the configuration the build runs.
  it("refuses hosted code in its own bundle and in every worker's", async () => {
    const { plugins, workerPlugins } = await buildConfig("production");
    const refusing = (found: Plugin[]) =>
      found.filter((plugin) => plugin.name === CORE_ONLY).map((plugin) => (plugin.api as CoreOnlyApi).hostedDir);
    const expected = [hostedDirOf(CONSOLE)];
    expect(refusing(plugins)).toEqual(expected);
    expect(refusing(workerPlugins)).toEqual(expected);
  });

  it("leaves the hosted sources out of Tailwind's scan", async () => {
    const { plugins, workerPlugins } = await buildConfig("production");
    expect(names(plugins).some(isTailwind)).toBe(true);
    expect([...names(plugins), ...names(workerPlugins)]).not.toContain(HOSTED_STYLES);
  });

  it("resolves the edition's slots and routes to core's, and writes into the package", async () => {
    const { config } = await buildConfig("production");
    expect(aliasOf(config, "@edition")).toBe(real("src", "edition", "core.ts"));
    expect(aliasOf(config, "@route-tree")).toBe(real("src", "routeTree.gen.ts"));
    expect(aliasOf(config, "@editions")).toBeUndefined();
    expect(config.build?.outDir).toBe("../src/execbound/surfaces/console_dist");
  });
});

describe("the hosted build's configuration (#496)", () => {
  it("refuses nothing, in its own bundle or in any worker's", async () => {
    const { plugins, workerPlugins } = await buildConfig("hosted");
    expect(names(plugins)).not.toContain(CORE_ONLY);
    expect(names(workerPlugins)).not.toContain(CORE_ONLY);
  });

  it("gives core's stylesheet the hosted sources back before Tailwind reads it", async () => {
    // Both are `enforce: "pre"`, so the order of the list decides. After Tailwind, the plugin
    // finds a compiled stylesheet with no `@source` in it and fails the build, which is loud but
    // late; this says so before any build.
    const { plugins, workerPlugins } = await buildConfig("hosted");
    const sheet = normalizePath(path.join(realpathSync.native(CONSOLE), "src", "styles", "app.css"));
    for (const found of [plugins, workerPlugins]) {
      const tailwind = names(found).findIndex(isTailwind);
      if (tailwind === -1) continue;
      const styles = names(found).indexOf(HOSTED_STYLES);
      expect(styles).toBeGreaterThanOrEqual(0);
      expect(styles).toBeLessThan(tailwind);
      expect((found[styles]?.api as HostedStylesApi | undefined)?.stylesheet).toBe(sheet);
    }
    expect(names(plugins).some(isTailwind)).toBe(true);
  });

  it("resolves the edition's slots and routes to the hosted edition's, and writes beside the sources", async () => {
    const { config } = await buildConfig("hosted");
    expect(aliasOf(config, "@edition")).toBe(real("src", "hosted", "edition.tsx"));
    expect(aliasOf(config, "@route-tree")).toBe(real("src", "hosted", "routeTree.gen.ts"));
    expect(aliasOf(config, "@editions")).toBeUndefined();
    expect(config.build?.outDir).toBe("dist/hosted");
  });
});

/** The hosted-styles plugin's hooks as the build calls them, with the context each one uses. */
interface StyleHooks {
  configResolved(config: { command: "build" | "serve" }): void;
  transform(this: { error(message: string): never }, code: string, id: string): string | null;
  buildEnd(this: { error(message: string): never }, error?: Error): void;
}

describe("the hosted build's stylesheet (#496)", () => {
  const SHEET = "/work/console/src/styles/app.css";
  const LINE = '@source not "../hosted";';
  const CSS = `@import "tailwindcss";\n${LINE}\n.a { color: red; }\n`;
  const WITHOUT = '@import "tailwindcss";\n\n.a { color: red; }\n';
  const MISSING =
    `${SHEET} has no line @source not "../hosted"; to take out, so the hosted build cannot give Tailwind the ` +
    "hosted sources back: either the line is gone from core's stylesheet, or this plugin runs after Tailwind, " +
    "which has already compiled it.";
  const NEVER = `The hosted build never compiled ${SHEET}, so it gave Tailwind no hosted sources: the path names no stylesheet the build reached.`;

  function plugin(command: "build" | "serve" = "build") {
    const hooks = hostedStyles(SHEET) as unknown as StyleHooks;
    hooks.configResolved({ command });
    return {
      transform: (code: string, id: string) => hooks.transform.call({ error }, code, id),
      buildEnd: (failure?: Error) => () => {
        hooks.buildEnd.call({ error }, failure);
      },
    };
  }

  it("takes out the line that leaves the hosted sources out, in core's stylesheet alone", () => {
    const { transform } = plugin();
    expect(transform(CSS, SHEET)).toBe(WITHOUT);
    expect(transform(CSS, `${SHEET}?direct`)).toBe(WITHOUT);
    expect(transform(CSS, "/work/console/src/styles/other.css")).toBeNull();
    expect(transform(CSS, "/work/console/src/styles/app.css.ts")).toBeNull();
  });

  it("leaves alone the imports of core's stylesheet that Tailwind never compiles, with the line or without it", () => {
    const { transform } = plugin();
    for (const query of ["?url", "?raw", "?worker", "?sharedworker", "?inline&url", "?commonjs-proxy"]) {
      expect(transform(CSS, `${SHEET}${query}`), query).toBeNull();
      expect(transform('@import "tailwindcss";\n', `${SHEET}${query}`), query).toBeNull();
    }
  });

  it("refuses core's stylesheet without the line on a line of its own, naming both ways that happens", () => {
    const { transform } = plugin();
    expect(() => transform('@import "tailwindcss";\n', SHEET)).toThrow(MISSING);
    // Compiled CSS, as the plugin sees the stylesheet when it runs after Tailwind.
    expect(() => transform(".a{color:red}", SHEET)).toThrow(MISSING);
    expect(() => transform(`@import "tailwindcss";\n/* ${LINE} */\n`, SHEET)).toThrow(MISSING);
    expect(() => transform(`@import "tailwindcss";\n  ${LINE}\n`, SHEET)).toThrow(MISSING);
  });

  it("fails a build that never compiled core's stylesheet, and nothing else", () => {
    const unseen = plugin();
    unseen.transform(CSS, `${SHEET}?url`);
    unseen.transform(CSS, "/work/console/src/styles/App.css");
    expect(unseen.buildEnd()).toThrow(NEVER);
    // A build that already failed says why itself.
    expect(unseen.buildEnd(new Error("an earlier failure"))).not.toThrow();

    const seen = plugin();
    seen.transform(CSS, SHEET);
    expect(seen.buildEnd()).not.toThrow();

    // A development server compiles a stylesheet only when a page asks for it.
    expect(plugin("serve").buildEnd()).not.toThrow();
  });
});

/** The paths a stylesheet names, in quotes or a bare `url()`, other than the sources it leaves out. */
function cssPaths(css: string): string[] {
  const named = css.replace(/@source\s+not\s+(["']).*?\1\s*;/g, "");
  return [...named.matchAll(/(["'])(.*?)\1|url\(\s*([^)"'\s]+)\s*\)/g)].map((m) => m[2] ?? m[3] ?? "");
}

const hostedPath = (file: string) => /(^|\/)hosted(\/|$)/.test(file);

describe("core's stylesheets (#496)", () => {
  // The build cannot see a stylesheet's `@import`, because the CSS pipeline inlines it (coreOnly),
  // so core's stylesheets are read here instead.
  it("find a hosted path wherever a stylesheet names one", () => {
    const css = [
      '@import "../hosted/cards.css";',
      "@import url(../hosted/more.css);",
      '@source "../hosted";',
      '@source not "../hosted";',
      '@import "./hostedness.css";',
      ".a { background: url('../hosted/a.svg'); }",
    ].join("\n");
    expect(cssPaths(css).filter(hostedPath)).toEqual(["../hosted/cards.css", "../hosted/more.css", "../hosted", "../hosted/a.svg"]);
  });

  it("name no hosted file", () => {
    const src = path.join(CONSOLE, "src");
    const sheets = readdirSync(src, { recursive: true, encoding: "utf8" })
      .map((file) => normalizePath(file))
      .filter((file) => file.endsWith(".css") && !file.startsWith("hosted/"));
    expect(sheets).toContain("styles/app.css");
    for (const sheet of sheets) {
      expect({ sheet, hosted: cssPaths(readFileSync(path.join(src, sheet), "utf8")).filter(hostedPath) }).toEqual({ sheet, hosted: [] });
    }
  });

  it("leave hosted modules out of the classes Tailwind finds for core", () => {
    expect(readFileSync(path.join(CONSOLE, "src", "styles", "app.css"), "utf8")).toMatch(/^@source not "\.\.\/hosted";$/m);
  });
});

describe("the two editions' builds (#496)", () => {
  it("builds the hosted edition only in the hosted mode", () => {
    expect(editionFor("hosted")).toBe("hosted");
    for (const mode of ["production", "development", "test", "Hosted", "hosted-preview", ""]) {
      expect(editionFor(mode)).toBe("core");
    }
  });

  it("writes core's build into the package and the hosted one beside the sources, unless told otherwise", () => {
    expect(OUT_DIRS).toEqual({ core: "../src/execbound/surfaces/console_dist", hosted: "dist/hosted" });
    expect(outDir("core", {})).toBe("../src/execbound/surfaces/console_dist");
    expect(outDir("hosted", {})).toBe("dist/hosted");
    expect(outDir("hosted", { CONSOLE_OUT_DIR: "../src/execbound/surfaces/console_dist" })).toBe(
      "../src/execbound/surfaces/console_dist",
    );
  });

  it("reads a blank CONSOLE_OUT_DIR as unset", () => {
    expect(outDir("hosted", { CONSOLE_OUT_DIR: "" })).toBe("dist/hosted");
    expect(outDir("core", { CONSOLE_OUT_DIR: "" })).toBe("../src/execbound/surfaces/console_dist");
    expect(outDir("hosted", { CONSOLE_OUT_DIR: "  " })).toBe("dist/hosted");
  });

  it("writes where CONSOLE_OUT_DIR says when it names the package's build directory or one inside dist/", () => {
    for (const named of [
      "../src/execbound/surfaces/console_dist",
      real("..", "src", "execbound", "surfaces", "console_dist"),
      "dist/preview",
      "dist/hosted",
      real("dist", "core"),
    ]) {
      expect(outDir("hosted", { CONSOLE_OUT_DIR: named })).toBe(named);
      expect(outDir("core", { CONSOLE_OUT_DIR: named })).toBe(named);
    }
  });

  it("refuses a CONSOLE_OUT_DIR anywhere else, before the build empties it", () => {
    // The build empties its directory before it writes. Unguarded, an empty value names the
    // console itself, and `..` the repository.
    const root = realpathSync.native(CONSOLE);
    const pkg = path.resolve(root, "../src/execbound/surfaces/console_dist");
    expect(() => outDir("hosted", { CONSOLE_OUT_DIR: ".." })).toThrow(
      `CONSOLE_OUT_DIR=".." names ${path.dirname(root)}, which the build would empty before writing. ` +
        `It may name only the package's build directory (${pkg}) or a directory inside ${path.join(root, "dist")}.`,
    );
    for (const named of [
      // The console, and every directory that holds it: the repository, and above.
      ".",
      root,
      `${root}/`,
      "..",
      "../..",
      path.parse(root).root,
      // The console's own sources and dependencies, or a directory inside one.
      "src",
      "src/hosted/build",
      "scripts",
      "public",
      "openapi",
      "node_modules/.cache/build",
      // Every edition's builds at once, a directory that holds the package's, or one inside it.
      "dist",
      "../src",
      "../src/execbound",
      "../src/execbound/surfaces",
      "../src/execbound/surfaces/console_dist/nested",
      // The rest of the repository, and beyond it.
      "../docs",
      "../tests",
      "dist/../src",
      path.join(path.dirname(root), "..", "elsewhere"),
    ]) {
      for (const edition of ["core", "hosted"] as const) {
        expect(() => outDir(edition, { CONSOLE_OUT_DIR: named }), named).toThrow(/^CONSOLE_OUT_DIR=".*" names .*, which the build would empty before writing\./);
      }
    }
  });
});

describe("the document's edition tag", () => {
  it("names the edition in the document the build writes", () => {
    const html = `<head>${EDITION_TAG}</head>`;
    expect(nameEdition(html, "hosted")).toBe('<head><meta name="execbound-edition" content="hosted" /></head>');
    expect(nameEdition(html, "core")).toBe('<head><meta name="execbound-edition" content="core" /></head>');
  });

  it("refuses a document with no tag to fill", () => {
    expect(() => nameEdition("<head></head>", "core")).toThrow("The console document has no edition tag to fill");
  });
});

describe("the route trees' license line (#496)", () => {
  it("opens each edition's route tree with its license, then the router's own three lines", () => {
    const defaults = ["/* eslint-disable */", "// @ts-nocheck", "// noinspection JSUnusedGlobalSymbols"];
    expect(routeTreeFileHeader("core")).toEqual(["// SPDX-License-Identifier: AGPL-3.0-only", ...defaults]);
    expect(routeTreeFileHeader("hosted")).toEqual([
      "// SPDX-License-Identifier: LicenseRef-ExecBound-Proprietary",
      ...defaults,
    ]);
    expect(ROUTE_TREE_LICENCES).toEqual({ core: "AGPL-3.0-only", hosted: "LicenseRef-ExecBound-Proprietary" });
  });

  it("is how core's committed route tree opens, as the router joins it", () => {
    // The router writes each header line as its own paragraph. The hosted edition's tree is held
    // by scripts/licence_headers.py, since a core test does not read src/hosted/.
    const tree = readFileSync(path.join(CONSOLE, "src", "routeTree.gen.ts"), "utf8");
    expect(tree.startsWith(`${routeTreeFileHeader("core").join("\n\n")}\n\n`)).toBe(true);
  });
});
