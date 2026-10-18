// SPDX-License-Identifier: AGPL-3.0-only
import { configDefaults, defineConfig } from "vitest/config";

import { editionFor } from "./scripts/editions.ts";

// Two runs (#496). `vitest run` is core's and leaves src/hosted/ out, as the core edition
// does; `vitest run --mode hosted` runs every test, core's too, with the hosted client pointed at
// the test origin. A core test is the same in both: a component rendered without an edition's
// provider is core.
export default defineConfig(({ mode }) => {
  const hosted = editionFor(mode) === "hosted";
  return {
    test: {
      environment: "jsdom",
      setupFiles: hosted ? ["./src/test/setup.ts", "./src/hosted/test/setup.ts"] : ["./src/test/setup.ts"],
      include: ["src/**/*.test.{ts,tsx}", "scripts/**/*.test.ts"],
      exclude: hosted ? configDefaults.exclude : [...configDefaults.exclude, "src/hosted/**"],
      css: false,
      // Times print in the viewer's own time zone; the tests read them in UTC so an assertion
      // means the same on every machine. A test of another zone passes it explicitly.
      env: { TZ: "UTC" },
      // Above the five seconds a single wait may take (src/test/setup.ts), so a wait that fails
      // reports what it could not find rather than a bare timeout, with room for a test that
      // makes several waits on a loaded machine. The default is five seconds.
      testTimeout: 20_000,
    },
  };
});
