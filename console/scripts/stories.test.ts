// SPDX-License-Identifier: AGPL-3.0-only
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

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
