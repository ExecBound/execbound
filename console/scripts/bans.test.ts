// SPDX-License-Identifier: AGPL-3.0-only
// Each of the console's security bans (#333) is held to a lint error by one fixture, using the
// rules the project configuration exports, so a quiet edit to eslint.config.js fails here.

import path from "node:path";

import { ESLint, type Linter } from "eslint";
import tseslint from "typescript-eslint";
import { describe, expect, it } from "vitest";

import {
  bans,
  coreBans,
  deviceZoneBan,
  draftKeepers,
  draftsImport,
  draftsLazy,
  nameBans,
  timeBans,
} from "../eslint.config.js";

const linter = new ESLint({
  overrideConfigFile: true,
  overrideConfig: [
    {
      files: ["**/*.tsx"],
      languageOptions: {
        parser: tseslint.parser,
        parserOptions: { ecmaFeatures: { jsx: true }, ecmaVersion: 2022, sourceType: "module" },
      },
      rules: bans,
    },
  ],
});

async function errorsIn(code: string): Promise<string[]> {
  const [result] = await linter.lintText(code, { filePath: "src/fixture.tsx" });
  return (result?.messages ?? []).filter((m) => m.severity === 2).map((m) => m.ruleId ?? "?");
}

const fixtures: [string, string][] = [
  ["dangerouslySetInnerHTML", "export const a = (v: string) => <div dangerouslySetInnerHTML={{ __html: v }} />;"],
  ["innerHTML assignment", "export const b = (e: HTMLElement, v: string) => { e.innerHTML = v; };"],
  ["outerHTML assignment", "export const c = (e: HTMLElement, v: string) => { e.outerHTML = v; };"],
  ["insertAdjacentHTML", 'export const d = (e: HTMLElement, v: string) => e.insertAdjacentHTML("beforeend", v);'],
  ["setHTMLUnsafe", "export const e = (el: HTMLElement, v: string) => el.setHTMLUnsafe(v);"],
  ["document.write", "export const f = (v: string) => document.write(v);"],
  ["string timer", 'export const g = () => setTimeout("go()", 1);'],
  ["template timer", "export const h = (n: string) => setInterval(`go(${n})`, 1);"],
  ["new Function", 'export const i = new Function("return 1");'],
  ["eval", "export const j = (v: string) => eval(v);"],
];

describe("the lint bans", () => {
  it.each(fixtures)("refuse %s", async (_name, code) => {
    expect(await errorsIn(code)).not.toHaveLength(0);
  });

  it("leave text rendering and function timers alone", async () => {
    const clean = [
      "export const k = (e: HTMLElement, v: string) => { e.textContent = v; };",
      "export const l = () => setTimeout(() => undefined, 1);",
      "export const m = (v: string) => <p>{v}</p>;",
    ].join("\n");
    expect(await errorsIn(clean)).toHaveLength(0);
  });
});

const coreLinter = new ESLint({
  overrideConfigFile: true,
  overrideConfig: [
    {
      files: ["**/*.tsx"],
      languageOptions: {
        parser: tseslint.parser,
        parserOptions: { ecmaFeatures: { jsx: true }, ecmaVersion: 2022, sourceType: "module" },
      },
      rules: coreBans,
    },
  ],
});

async function coreErrorsIn(code: string): Promise<string[]> {
  const [result] = await coreLinter.lintText(code, { filePath: "src/fixture.tsx" });
  return (result?.messages ?? []).filter((m) => m.severity === 2).map((m) => m.ruleId ?? "?");
}

// Core never reaches hosted code, and only src/main.tsx chooses the edition (#496).
const coreFixtures: [string, string][] = [
  ["a static import of a hosted module", 'import { edition } from "../hosted/edition";\nexport const e = edition;'],
  ["a hosted re-export", 'export { edition } from "./hosted/edition";'],
  ["a lazy import of a hosted module", 'export const load = () => import("./hosted/welcome/Welcome");'],
  ["a lazy import from a sibling's hosted module", 'export const load = () => import("../hosted/x");'],
  ["a lazy import of a bare hosted", 'export const load = () => import("hosted");'],
  ["the edition alias outside main.tsx", 'import { edition } from "@edition";\nexport const e = edition;'],
  ["the route tree alias outside main.tsx", 'import { routeTree } from "@route-tree";\nexport const r = routeTree;'],
];

describe("core's edition bans", () => {
  it.each(coreFixtures)("refuse %s", async (_name, code) => {
    expect(await coreErrorsIn(code)).not.toHaveLength(0);
  });

  it("keep every security ban", async () => {
    for (const [, code] of fixtures) {
      expect(await coreErrorsIn(code)).not.toHaveLength(0);
    }
  });

  it("leave core imports, a directory named alike and a lazy core chunk alone", async () => {
    const clean = [
      'import { Card } from "./components/ui/Card";',
      'import { x } from "./hostedness/x";',
      'import { g } from "../ghosted/g";',
      'import { u } from "./unhosted";',
      "export const c = Card;",
      "export const y = x;",
      "export const h = [g, u];",
      'export const load = () => import("./components/ui/CommandPalette");',
      'export const alike = () => import("./hostedness/x");',
      'export const ghost = () => import("../ghosted/x");',
      'export const unhosted = () => import("./unhosted");',
    ].join("\n");
    expect(await coreErrorsIn(clean)).toHaveLength(0);
  });
});

// The fixtures above hold the rules; this holds where the project's own configuration applies
// them, so narrowing a block's files or dropping main.tsx's exception fails here (#496).
const project = new ESLint({ cwd: path.dirname(import.meta.dirname) });

const HOSTED_PATH = "(^|/)hosted(/|$)";
const EDITION_ALIASES = "^@(edition|route-tree)$";
const DRAFTS = "(^|/)drafts$";

/** The import patterns and the `import()` selectors that refuse a path, as configured for `file`. */
async function restrictionsFor(file: string): Promise<{ imports: string[]; lazy: string[] }> {
  const config = (await project.calculateConfigForFile(file)) as Linter.Config;
  const imports = config.rules?.["no-restricted-imports"];
  const syntax = config.rules?.["no-restricted-syntax"];
  const options = (rule: Linter.RuleEntry | undefined): unknown[] => (Array.isArray(rule) && rule[0] !== 0 && rule[0] !== "off" ? rule.slice(1) : []);
  return {
    imports: options(imports).flatMap((option) => ((option as { patterns?: { regex?: string }[] }).patterns ?? []).map((p) => p.regex ?? "")),
    lazy: options(syntax)
      .map((option) => (option as { selector: string }).selector)
      .filter((selector) => selector.startsWith("ImportExpression")),
  };
}

describe("the project's edition bans", () => {
  const LAZY = [String.raw`ImportExpression[source.value=/(^|\/)hosted(\/|$)/]`];
  const DRAFTS_LAZY = String.raw`ImportExpression[source.value=/(^|\/)drafts$/]`;

  it.each(["src/shell/Mark.tsx", "src/lib/session.ts", "scripts/editions.ts", "scripts/budget.mjs"])(
    "refuse hosted code, the edition aliases and the draft store in %s",
    async (file) => {
      expect(await restrictionsFor(file)).toEqual({ imports: [HOSTED_PATH, EDITION_ALIASES, DRAFTS], lazy: [DRAFTS_LAZY, ...LAZY] });
    },
  );

  it.each(["src/edition/core.test.tsx", ...draftKeepers])(
    "let %s import the draft store, and still refuse it hosted code and the aliases",
    async (file) => {
      expect(await restrictionsFor(file)).toEqual({ imports: [HOSTED_PATH, EDITION_ALIASES], lazy: LAZY });
    },
  );

  it("let src/main.tsx name the aliases, and still refuse it hosted code and the draft store", async () => {
    expect(await restrictionsFor("src/main.tsx")).toEqual({ imports: [HOSTED_PATH, DRAFTS], lazy: [DRAFTS_LAZY, ...LAZY] });
  });

  it("leave the hosted edition's own modules to import each other, and refuse them the draft store", async () => {
    expect(await restrictionsFor("src/hosted/edition.tsx")).toEqual({ imports: [DRAFTS], lazy: [DRAFTS_LAZY] });
    expect(await restrictionsFor("src/hosted/edition.test.tsx")).toEqual({ imports: [DRAFTS], lazy: [DRAFTS_LAZY] });
  });
});

// The draft store's allowlist (#678): a show-once holder, core or hosted, can never import it.
describe("the draft store's import allowlist", () => {
  const store = 'import { clearDrafts } from "../../lib/drafts";\nexport const c = clearDrafts;';
  const lazy = 'export const load = () => import("../../lib/drafts");';
  const hosted = 'import { edition } from "../../hosted/edition";\nexport const e = edition;';

  /** Every error the project's configuration finds in `code` linted as `file`, by rule. */
  async function projectErrors(file: string, code: string): Promise<string[]> {
    const config = (await project.calculateConfigForFile(file)) as Linter.Config;
    const one = new ESLint({
      overrideConfigFile: true,
      overrideConfig: [
        {
          files: ["**/*.{ts,tsx}"],
          languageOptions: {
            parser: tseslint.parser,
            parserOptions: { ecmaFeatures: { jsx: true }, ecmaVersion: 2022, sourceType: "module" },
          },
          rules: {
            "no-restricted-imports": config.rules?.["no-restricted-imports"] ?? "off",
            "no-restricted-syntax": config.rules?.["no-restricted-syntax"] ?? "off",
          },
        },
      ],
    });
    const [result] = await one.lintText(code, { filePath: file });
    return (result?.messages ?? []).filter((m) => m.severity === 2).map((m) => m.ruleId ?? "?");
  }

  it("refuses the store to a show-once holder, statically and lazily", async () => {
    expect(await projectErrors("src/components/directory/SecretDialog.tsx", store)).toContain("no-restricted-imports");
    expect(await projectErrors("src/components/directory/SecretDialog.tsx", lazy)).toContain("no-restricted-syntax");
  });

  it("refuses the store to a hosted show-once holder", async () => {
    expect(await projectErrors("src/hosted/invitations/MintInvitation.tsx", store)).toContain("no-restricted-imports");
    expect(await projectErrors("src/hosted/invitations/MintInvitation.tsx", lazy)).toContain("no-restricted-syntax");
  });

  it("lets a keeping file import it, and still refuses that file hosted code", async () => {
    expect(await projectErrors("src/components/policy/BundleList.tsx", store)).toHaveLength(0);
    expect(await projectErrors("src/components/policy/BundleList.tsx", lazy)).toHaveLength(0);
    expect(await projectErrors("src/components/policy/BundleList.tsx", hosted)).toContain("no-restricted-imports");
  });

  it("names the four keeping files and no more", () => {
    expect(draftKeepers).toEqual([
      "src/approvals/DetailView.tsx",
      "src/components/policy/BundleList.tsx",
      "src/lib/client-config.ts",
      "src/shell/SignOut.tsx",
    ]);
    expect(coreBans["no-restricted-syntax"]).toContainEqual(draftsLazy);
    expect(bans["no-restricted-imports"]).toEqual(["error", { patterns: [draftsImport] }]);
  });
});

// The time rule (#678): one module formats instants, so every printed time names its zone.
const timeFixtures: [string, string][] = [
  ["toLocaleTimeString", "export const a = (d: Date) => d.toLocaleTimeString();"],
  ["toLocaleDateString", "export const b = (d: Date) => d.toLocaleDateString();"],
  ["toDateString", 'export const c = (iso: string) => new Date(iso).toDateString();'],
  ["toTimeString", "export const d = (d: Date) => d.toTimeString();"],
  ["toUTCString", "export const e = (d: Date) => d.toUTCString();"],
  ["toLocaleString on a new Date", 'export const f = (iso: string) => new Date(iso).toLocaleString(undefined, { timeZoneName: "short" });'],
  ["new Intl.DateTimeFormat", 'export const g = new Intl.DateTimeFormat(undefined, { hour: "2-digit" });'],
  ["Intl.DateTimeFormat called", "export const h = Intl.DateTimeFormat();"],
  ["the device-zone test seam", 'import { setDeviceZoneForTests } from "./lib/time";\nsetDeviceZoneForTests("UTC");'],
];

describe("the time bans", () => {
  it.each(timeFixtures)("refuse %s in both editions", async (_name, code) => {
    expect(await errorsIn(code)).toContain("no-restricted-syntax");
    expect(await coreErrorsIn(code)).toContain("no-restricted-syntax");
  });

  it("leave numbers, ISO strings and the one formatter alone", async () => {
    const clean = [
      "export const n = (count: number) => count.toLocaleString();",
      "export const iso = (d: Date) => d.toISOString();",
      'import { instant } from "./lib/time";',
      'export const t = instant("2026-10-08T17:34:24Z");',
    ].join("\n");
    expect(await errorsIn(clean)).toHaveLength(0);
    expect(await coreErrorsIn(clean)).toHaveLength(0);
  });

  it("hold every time ban in the shared list", () => {
    const selectors = (bans["no-restricted-syntax"] as unknown[]).slice(1).map((entry) => (entry as { selector: string }).selector);
    for (const ban of timeBans) expect(selectors).toContain(ban.selector);
  });
});

/** Lint `code` as the project's configuration lints `file`, with that file's syntax bans alone. */
async function asProjectLints(file: string, code: string): Promise<string[]> {
  const config = (await project.calculateConfigForFile(file)) as Linter.Config;
  const rule = config.rules?.["no-restricted-syntax"] as Linter.RuleEntry;
  const one = new ESLint({
    overrideConfigFile: true,
    overrideConfig: [
      {
        files: ["**/*.{ts,tsx}"],
        languageOptions: {
          parser: tseslint.parser,
          parserOptions: { ecmaFeatures: { jsx: true }, ecmaVersion: 2022, sourceType: "module" },
        },
        rules: { "no-restricted-syntax": rule },
      },
    ],
  });
  const [result] = await one.lintText(code, { filePath: file });
  return (result?.messages ?? []).filter((m) => m.severity === 2).map((m) => m.ruleId ?? "?");
}

describe("the project's time exemptions", () => {
  const formatter = 'export const f = new Intl.DateTimeFormat("en-US", { timeZone: "UTC" });';
  const seam = 'import { setDeviceZoneForTests } from "./time";\nsetDeviceZoneForTests("America/New_York");';

  it("let src/lib/time.ts format times, and nothing else", async () => {
    expect(await asProjectLints("src/lib/time.ts", formatter)).toHaveLength(0);
    expect(await asProjectLints("src/lib/when.ts", formatter)).toContain("no-restricted-syntax");
    expect(await asProjectLints("src/components/ui/Time.tsx", formatter)).toContain("no-restricted-syntax");
  });

  it("let a test file call the device-zone seam, and still refuse it a Date formatter", async () => {
    expect(await asProjectLints("src/lib/time.test.ts", seam)).toHaveLength(0);
    expect(await asProjectLints("src/hosted/x.test.tsx", seam)).toHaveLength(0);
    expect(await asProjectLints("src/lib/time.test.ts", formatter)).toContain("no-restricted-syntax");
    expect(await asProjectLints("src/lib/clock.ts", seam)).toContain("no-restricted-syntax");
  });

  it("keep the seam's ban in the list a test file is exempt from", () => {
    expect(timeBans).toContain(deviceZoneBan);
  });
});

// The name rule (#678): one helper names an agent or a person, never a handle built from an id.
const nameFixtures: [string, string][] = [
  ["a template starting Agent", "export const a = (id: string) => `Agent ${id.slice(0, 8)}`;"],
  ["a template starting agent", "export const b = (id: string) => `agent ${id}`;"],
  ["a template starting User", "export const c = (n: number) => `User ${String(n)}`;"],
  ["Agent joined with +", 'export const d = (id: string) => "Agent " + id;'],
  ["User joined with +", 'export const e = (id: string) => "User " + id;'],
  [
    "the Activity chip's former shape",
    'declare function shortId(id: string): string;\nexport const f = (key: string, id: string) => `${key === "agent" ? "Agent" : "Target"} ${shortId(id)}`;',
  ],
  ["a handle from a prefix", 'declare function prefix(id: string): string;\nexport const g = (id: string) => `${"User"} ${prefix(id)}`;'],
];

describe("the name bans", () => {
  it.each(nameFixtures)("refuse %s in both editions", async (_name, code) => {
    expect(await errorsIn(code)).toContain("no-restricted-syntax");
    expect(await coreErrorsIn(code)).toContain("no-restricted-syntax");
  });

  it("leave other words and the helpers alone", async () => {
    const clean = [
      'import { handle, principalName } from "./components/directory/format";',
      'export const a = (n: number) => handle("Agent", n);',
      'export const b = (l: string | null, n: number) => principalName("User", l, n);',
      "export const c = (id: string) => `Request ${id}`;",
      "export const d = (n: number) => `Key ${String(n)}`;",
      'export const e = "Agents";',
    ].join("\n");
    expect(await errorsIn(clean)).toHaveLength(0);
  });

  it("hold every name ban in the shared list", () => {
    const selectors = (bans["no-restricted-syntax"] as unknown[]).slice(1).map((entry) => (entry as { selector: string }).selector);
    for (const ban of nameBans) expect(selectors).toContain(ban.selector);
  });
});

describe("the project's name exemption", () => {
  const built = "export const handle = (id: string) => `Agent ${id.slice(0, 8)}`;";

  it("lets src/components/directory/handles.ts and format.ts build a handle, and nothing else", async () => {
    expect(await asProjectLints("src/components/directory/handles.ts", built)).toHaveLength(0);
    expect(await asProjectLints("src/components/directory/format.ts", built)).toHaveLength(0);
    expect(await asProjectLints("src/components/PrincipalName.tsx", built)).toContain("no-restricted-syntax");
    expect(await asProjectLints("src/components/directory/format.test.ts", built)).toContain("no-restricted-syntax");
    // format.ts is still held to the time rule.
    expect(await asProjectLints("src/components/directory/format.ts", 'export const f = new Intl.DateTimeFormat("en-US");')).toContain("no-restricted-syntax");
  });
});
