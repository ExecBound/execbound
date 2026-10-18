// SPDX-License-Identifier: AGPL-3.0-only
// Lint for the console: typescript-eslint's strictest type-checked sets, the hooks rules, and
// the console's security bans (#333). A raw string may never reach a DOM sink, nothing may
// evaluate a string, and links are built by the router from identifiers. scripts/bans.test.ts
// holds one fixture per ban to a lint error, so this file cannot go quiet without a test
// noticing.
//
// Core never imports hosted code (#496): a module outside src/hosted/ may not import one
// inside it, statically or lazily, and only src/main.tsx may name the two aliases that choose an
// edition. The core build refuses a hosted module too (scripts/editions.ts); this is the same
// rule, told to its author at the line that breaks it.

import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

const sink = (what) =>
  `${what} puts a raw string into a DOM sink; render untrusted strings as text (#333).`;

const zone = (what) =>
  `${what} formats a time outside src/lib/time.ts; print it with <Time> or lib/time.ts so it names its zone (#678).`;

/**
 * The time rule (#678): one module turns an instant into text, so every printed time names its
 * zone and follows the viewer's choice. A bare `toLocaleString` is left alone because it
 * formats numbers too; only its call on `new Date(...)` is refused.
 */
export const deviceZoneBan = {
  selector: 'CallExpression[callee.name="setDeviceZoneForTests"]',
  message: "setDeviceZoneForTests is a test seam; production code reads the device's zone (#678).",
};

export const timeBans = [
  {
    selector:
      "CallExpression[callee.property.name=/^(toLocaleTimeString|toLocaleDateString|toDateString|toTimeString|toUTCString)$/]",
    message: zone("A Date method"),
  },
  {
    selector:
      'CallExpression[callee.property.name="toLocaleString"][callee.object.type="NewExpression"][callee.object.callee.name="Date"]',
    message: zone("new Date(...).toLocaleString()"),
  },
  {
    selector: ':matches(NewExpression, CallExpression)[callee.object.name="Intl"][callee.property.name="DateTimeFormat"]',
    message: zone("Intl.DateTimeFormat"),
  },
  deviceZoneBan,
];

const handleMessage =
  "A principal's name is built from an id here; render it with <PrincipalName> or refName() from components/directory/format.ts, which names it \"Agent 3\" or \"User 3\" (#678).";

/**
 * The name rule (#678): one helper names an agent or a person. A handle built by hand from an id
 * is the shape every page used before, so these three shapes are refused outside format.ts.
 * They name one literal shape and two functions, never a word.
 */
export const nameBans = [
  {
    // `Agent ${…}`, `agent ${…}`, `User ${…}`
    selector: "TemplateLiteral[quasis.0.value.raw=/^(Agent|agent|User) $/]",
    message: handleMessage,
  },
  {
    // "Agent " + …, "User " + …
    selector: 'BinaryExpression[operator="+"] > Literal.left[value=/^(Agent|User) $/]',
    message: handleMessage,
  },
  {
    // `${kind === "agent" ? "Agent" : "Target"} ${shortId(…)}`: the Activity chip's shape.
    selector:
      'TemplateLiteral:has(Literal[value=/^(Agent|User)$/]):has(CallExpression[callee.name=/^(shortId|prefix)$/])',
    message: handleMessage,
  },
  {
    selector:
      'TemplateLiteral:has(Literal[value=/^(Agent|User)$/]):has(CallExpression[callee.property.name="slice"])',
    message: handleMessage,
  },
];

// The draft store keeps what a person typed in this tab's storage (#678). A show-once value must
// never reach it, and the holders of one are many and growing, so the rule is an allowlist: only
// the files `draftKeepers` names may import the store, statically or lazily, and every other file,
// hosted files included, is refused. A new kind of draft adds its one file there, in a change a
// reviewer sees.
export const draftsImport = {
  regex: "(^|/)drafts$",
  message: "Only the files that keep drafts may import the draft store; a show-once value never reaches storage (#678).",
};
export const draftsLazy = {
  selector: String.raw`ImportExpression[source.value=/(^|\/)drafts$/]`,
  message: draftsImport.message,
};
export const draftKeepers = [
  "src/approvals/DetailView.tsx",
  "src/components/policy/BundleList.tsx",
  "src/lib/client-config.ts",
  "src/shell/SignOut.tsx",
];

/** @type {import("eslint").Linter.RulesRecord} */
export const bans = {
  "no-eval": "error",
  "no-implied-eval": "error",
  "no-new-func": "error",
  "no-restricted-syntax": [
    "error",
    {
      selector: 'JSXAttribute[name.name="dangerouslySetInnerHTML"]',
      message: sink("dangerouslySetInnerHTML"),
    },
    {
      selector: "AssignmentExpression > MemberExpression.left[property.name=/^(innerHTML|outerHTML)$/]",
      message: sink("innerHTML"),
    },
    {
      selector: "CallExpression[callee.property.name=/^(insertAdjacentHTML|setHTMLUnsafe|write|writeln)$/]",
      message: sink("insertAdjacentHTML"),
    },
    {
      selector: "CallExpression[callee.name=/^(setTimeout|setInterval)$/] > :matches(Literal, TemplateLiteral).arguments:first-child",
      message: "A string timer evaluates code; pass a function (#333).",
    },
    {
      selector: 'NewExpression[callee.name="Function"], CallExpression[callee.name="Function"]',
      message: "Function() evaluates a string (#333).",
    },
    ...timeBans,
    ...nameBans,
    draftsLazy,
  ],
  "no-restricted-imports": ["error", { patterns: [draftsImport] }],
};

const hostedImport = {
  regex: "(^|/)hosted(/|$)",
  message: "Core never imports hosted code; the hosted edition fills core's slots (#496).",
};

/**
 * Every ban above, and core's own: no hosted module, and no edition alias outside main.tsx.
 * @type {import("eslint").Linter.RulesRecord}
 */
export const coreBans = {
  ...bans,
  "no-restricted-imports": [
    "error",
    {
      patterns: [
        hostedImport,
        {
          regex: "^@(edition|route-tree)$",
          message: "Only src/main.tsx chooses the edition; read a slot with useEdition() (#496).",
        },
        draftsImport,
      ],
    },
  ],
  "no-restricted-syntax": [
    ...bans["no-restricted-syntax"],
    {
      // The same path as a static import's; esquery reads a regex between slashes, so its own
      // slashes are escaped.
      selector: `ImportExpression[source.value=/${hostedImport.regex.replaceAll("/", "\\/")}/]`,
      message: "Core never imports hosted code, not even lazily (#496).",
    },
  ],
};

/**
 * A rule's whole option list without some of its entries. ESLint replaces a rule's options per
 * matching block rather than merging them, so an exemption rebuilds the list it narrows.
 */
export function without(rules, lifted) {
  const [level, ...entries] = rules["no-restricted-syntax"];
  return [level, ...entries.filter((entry) => !lifted.includes(entry))];
}

/** `no-restricted-imports` without some of its path patterns, rebuilt as `without` rebuilds. */
export function importsWithout(rules, lifted) {
  const [level, { patterns }] = rules["no-restricted-imports"];
  return [level, { patterns: patterns.filter((pattern) => !lifted.includes(pattern)) }];
}

export default tseslint.config(
  { ignores: ["dist/", "node_modules/", "src/routeTree.gen.ts", "src/api/", "src/hosted/routeTree.gen.ts", "src/hosted/api/"] },
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  reactHooks.configs.flat.recommended,
  {
    languageOptions: {
      parserOptions: {
        projectService: { allowDefaultProject: ["*.config.ts"] },
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: bans,
  },
  {
    files: ["src/**/*.{ts,tsx}", "scripts/**/*.{ts,mjs}"],
    ignores: ["src/hosted/**"],
    rules: coreBans,
  },
  {
    // The one module that formats times (#678).
    files: ["src/lib/time.ts"],
    rules: { "no-restricted-syntax": without(coreBans, timeBans) },
  },
  {
    // The modules that build a principal's handle (#678): handles.ts, and format.ts beside it.
    files: ["src/components/directory/handles.ts", "src/components/directory/format.ts"],
    rules: { "no-restricted-syntax": without(coreBans, nameBans) },
  },
  {
    // Tests may read the console as a viewer in another zone would; nothing else may.
    files: ["**/*.test.{ts,tsx}"],
    ignores: ["src/hosted/**"],
    rules: { "no-restricted-syntax": without(coreBans, [deviceZoneBan]) },
  },
  {
    files: ["src/hosted/**/*.test.{ts,tsx}"],
    rules: { "no-restricted-syntax": without(bans, [deviceZoneBan]) },
  },
  {
    // The one module that chooses the edition: it imports both aliases, and still no hosted path.
    files: ["src/main.tsx"],
    rules: { "no-restricted-imports": ["error", { patterns: [hostedImport, draftsImport] }] },
  },
  {
    // The files that keep drafts may import the store (#678); every other ban still holds.
    files: draftKeepers,
    rules: {
      "no-restricted-imports": importsWithout(coreBans, [draftsImport]),
      "no-restricted-syntax": without(coreBans, [draftsLazy]),
    },
  },
  {
    // Core's tests may too, keeping their exemption from the device-zone seam's ban.
    files: ["**/*.test.{ts,tsx}"],
    ignores: ["src/hosted/**"],
    rules: {
      "no-restricted-imports": importsWithout(coreBans, [draftsImport]),
      "no-restricted-syntax": without(coreBans, [deviceZoneBan, draftsLazy]),
    },
  },
  {
    files: ["**/*.js", "**/*.mjs"],
    ...tseslint.configs.disableTypeChecked,
  },
);
