// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from "vitest";

import { APPROVAL, BUDGETS, closure, DIALOG, evaluate, HOME, PALETTE, SCOPED_APPROVAL, SHEET } from "./budget.mjs";

const manifest = {
  "index.html": { file: "assets/index-a.js", isEntry: true, imports: ["_vendor-b.js"], css: ["assets/index-c.css"] },
  "_vendor-b.js": { file: "assets/vendor-b.js" },
  [`${HOME}?tsr-split=component`]: { file: "assets/index-d.js", imports: ["_vendor-b.js", "_charts-e.js"] },
  "_charts-e.js": { file: "assets/charts-e.js" },
  [`${APPROVAL}?tsr-split=component`]: { file: "assets/approval-f.js", imports: ["_vendor-b.js"] },
  "src/routes/activity.tsx?tsr-split=component": {
    file: "assets/activity-g.js",
    imports: ["_vendor-b.js", PALETTE, DIALOG],
  },
  [PALETTE]: { file: "assets/palette-h.js" },
  [DIALOG]: { file: "assets/dialog-j.js" },
  "src/routes/__root.tsx": { file: "assets/root-i.js" },
};

const sizes: Record<string, number> = {
  "assets/index-a.js": 10 * 1024,
  "assets/vendor-b.js": 100 * 1024,
  "assets/index-c.css": 5 * 1024,
  "assets/index-d.js": 20 * 1024,
  "assets/charts-e.js": 8 * 1024,
  "assets/approval-f.js": 30 * 1024,
  "assets/activity-g.js": 70 * 1024,
  "assets/palette-h.js": 12 * 1024,
  "assets/dialog-j.js": 19 * 1024,
  "assets/root-i.js": 1024,
};
const sizeOf = (file: string) => sizes[file] ?? 0;

describe("the size budget", () => {
  it("follows static imports and stylesheets from an entry", () => {
    expect([...closure(manifest, "index.html")].sort()).toEqual(
      ["assets/index-a.js", "assets/index-c.css", "assets/vendor-b.js"].sort(),
    );
  });

  it("charges each route only for what the shell did not already load", () => {
    const { rows } = evaluate(manifest, sizeOf);
    const byLabel = Object.fromEntries(rows.map(([label, bytes]) => [label, bytes]));
    expect(byLabel["shell with Home"]).toBe((10 + 100 + 5 + 20 + 8) * 1024);
    expect(byLabel["approval link, cold"]).toBe((10 + 100 + 5 + 30) * 1024);
    expect(byLabel["src/routes/activity.tsx?tsr-split=component"]).toBe((70 + 12 + 19) * 1024);
  });

  it("names every budget that is over, and a palette or a dialog imported statically", () => {
    const { findings } = evaluate(manifest, sizeOf);
    expect(findings).toEqual([
      "route chunk src/routes/activity.tsx?tsr-split=component is 101.0 KB, not under 60.0 KB",
      "the command palette is imported statically by src/routes/activity.tsx?tsr-split=component",
      "Base UI's dialog is imported statically by src/routes/activity.tsx?tsr-split=component",
    ]);
    expect(BUDGETS.shellWithHome).toBe(220 * 1024);
  });

  it("refuses the navigation sheet imported statically by the shell (#678)", () => {
    const sheet = {
      ...manifest,
      "index.html": { ...manifest["index.html"], imports: ["_vendor-b.js", SHEET] },
      [SHEET]: { file: "assets/sheet-m.js" },
    };
    expect(evaluate(sheet, sizeOf).findings).toContain("the navigation sheet is imported statically by the shell");
  });

  it("charges a hosted edition's route like any other route (#496)", () => {
    const hosted = {
      ...manifest,
      "src/hosted/routes/invitations.tsx?tsr-split=component": { file: "assets/invitations-k.js", imports: ["_vendor-b.js"] },
    };
    const { rows, findings } = evaluate(hosted, (file) => (file === "assets/invitations-k.js" ? 61 * 1024 : sizeOf(file)));
    const byLabel = Object.fromEntries(rows.map(([label, bytes]) => [label, bytes]));
    expect(byLabel["src/hosted/routes/invitations.tsx?tsr-split=component"]).toBe(61 * 1024);
    expect(findings).toContain("route chunk src/hosted/routes/invitations.tsx?tsr-split=component is 61.0 KB, not under 60.0 KB");
  });

  it("holds a workspace approval link, opened cold, to the approval budget (#496)", () => {
    const hosted = {
      ...manifest,
      [`${SCOPED_APPROVAL}?tsr-split=component`]: { file: "assets/scoped-l.js", imports: ["_vendor-b.js"] },
    };
    const { rows, findings } = evaluate(hosted, (file) => (file === "assets/scoped-l.js" ? 60 * 1024 : sizeOf(file)));
    const byLabel = Object.fromEntries(rows.map(([label, bytes]) => [label, bytes]));
    expect(byLabel["workspace approval link, cold"]).toBe((10 + 100 + 5 + 60) * 1024);
    expect(byLabel[`${SCOPED_APPROVAL}?tsr-split=component`]).toBeUndefined();
    expect(findings).toContain("a workspace approval link loads 175.0 KB, over 160.0 KB");
  });

  it("passes a build inside every budget", () => {
    const small = (file: string) => (file === "assets/vendor-b.js" ? 60 * 1024 : 1024);
    const trimmed = { ...manifest };
    trimmed["src/routes/activity.tsx?tsr-split=component"] = { file: "assets/activity-g.js", imports: ["_vendor-b.js"] };
    expect(evaluate(trimmed, small).findings).toEqual([]);
  });
});
