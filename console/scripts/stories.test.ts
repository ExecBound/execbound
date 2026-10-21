// SPDX-License-Identifier: AGPL-3.0-only
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { testEvent } from "../src/components/welcome/TinesTestEvent";
import { tinesStories } from "./stories";

const CONSOLE = path.resolve(import.meta.dirname, "..");

interface Emitted {
  type: string;
  fileName: string;
  source: Buffer;
}

function run(root: string): Emitted[] {
  const emitted: Emitted[] = [];
  const plugin = tinesStories(root);
  const hook = plugin.generateBundle as unknown as (this: { emitFile: (file: Emitted) => string }) => void;
  hook.call({
    emitFile: (file) => {
      emitted.push(file);
      return file.fileName;
    },
  });
  return emitted;
}

describe("the Tines stories in the console build (UX14, #678)", () => {
  it("emits both committed stories and the directory's license, byte for byte", () => {
    const emitted = run(CONSOLE);
    expect(emitted.map((file) => file.fileName)).toEqual([
      "stories/tines/execbound-governed-action.json",
      "stories/tines/execbound-gate.json",
      "stories/tines/LICENSE",
    ]);
    for (const file of emitted) expect(file.type).toBe("asset");
    const committed = (...parts: string[]) => readFileSync(path.join(CONSOLE, "..", "integrations", ...parts));
    expect(emitted[0]?.source.equals(committed("tines", "execbound-governed-action.json"))).toBe(true);
    expect(emitted[1]?.source.equals(committed("tines", "execbound-gate.json"))).toBe(true);
    expect(emitted[2]?.source.equals(committed("LICENSE"))).toBe(true);
  });

  it("is applied to builds only", () => {
    expect(tinesStories(CONSOLE).apply).toBe("build");
  });

  it("fails the build naming the path of a missing file, the license included", () => {
    const root = mkdtempSync(path.join(tmpdir(), "stories-"));
    const consoleRoot = path.join(root, "console");
    mkdirSync(path.join(root, "integrations", "tines"), { recursive: true });
    mkdirSync(consoleRoot);
    expect(() => run(consoleRoot)).toThrow(/execbound-governed-action\.json/);
    writeFileSync(path.join(root, "integrations", "tines", "execbound-governed-action.json"), "{}");
    writeFileSync(path.join(root, "integrations", "tines", "execbound-gate.json"), "{}");
    expect(() => run(consoleRoot)).toThrow(/integrations\/LICENSE/);
  });
});

describe("the test event Getting started gives for a sample target (#178)", () => {
  it("names only fields the committed Execute story reads", () => {
    const story = readFileSync(path.resolve(CONSOLE, "../integrations/tines/execbound-governed-action.json"), "utf8");
    const host = { hostname: "ws-dev-01.sample.invalid", effect: "allow", incident_id: "x", criticality: 1, environment: "dev", provider_id: "p", role: "r", rules: [] };
    const fields = Object.keys(JSON.parse(testEvent(host, "22222222-0000-4000-8000-000000000001", "op.x", "tines-test-1")) as object);
    expect(fields).toEqual(["operation_ref", "target_kind", "target_value", "incident_id", "reference"]);
    for (const field of fields) expect(story).toContain(`entry.body.${field}`);
  });
});
