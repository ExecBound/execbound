// SPDX-License-Identifier: AGPL-3.0-only
// The committed Tines stories, offered as downloads by Getting started (#678). The build copies
// the two story files from ../integrations/tines/ into the console's output unchanged, byte for
// byte, as unhashed assets at `stories/tines/<name>`: nothing is rendered, templated or given
// an origin, a token or a tenant id. integrations/ is Apache-2.0 and the console build ships
// inside the AGPL package, so the directory's LICENSE travels beside the stories, where the
// wheel's license check holds it. A file that is missing fails the build.

import { readFileSync } from "node:fs";
import path from "node:path";

import type { Plugin } from "vite";

export const STORIES = ["execbound-governed-action.json", "execbound-gate.json"] as const;
export const STORY_DIR = "stories/tines";

/** What the build emits: the published path and the committed file it is a copy of. */
export function storyFiles(consoleRoot: string): [string, string][] {
  const integrations = path.join(consoleRoot, "..", "integrations");
  return [
    ...STORIES.map((name): [string, string] => [`${STORY_DIR}/${name}`, path.join(integrations, "tines", name)]),
    [`${STORY_DIR}/LICENSE`, path.join(integrations, "LICENSE")],
  ];
}

export function tinesStories(consoleRoot: string): Plugin {
  return {
    name: "execbound-tines-stories",
    apply: "build",
    generateBundle() {
      for (const [fileName, source] of storyFiles(consoleRoot)) {
        let body: Buffer;
        try {
          body = readFileSync(source);
        } catch {
          throw new Error(`The committed Tines story file is missing: ${source}`);
        }
        this.emitFile({ type: "asset", fileName, source: body });
      }
    },
  };
}
