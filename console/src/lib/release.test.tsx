// SPDX-License-Identifier: AGPL-3.0-only
import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { builtRelease, forgetRelease, noteRelease, RELEASE_HEADER, useNewerRelease } from "./release";

function withMeta(content: string): Document {
  const document = new Document();
  const html = document.createElement("html");
  const head = document.createElement("head");
  const meta = document.createElement("meta");
  meta.setAttribute("name", "execbound-release");
  meta.setAttribute("content", content);
  head.append(meta);
  html.append(head);
  document.append(html);
  return document;
}

describe("the release check", () => {
  afterEach(() => {
    forgetRelease();
  });

  it("reads the built release from the meta tag", () => {
    expect(builtRelease(withMeta("abc1234"))).toBe("abc1234");
    expect(builtRelease(new Document())).toBe("");
  });

  it("notes a newer release only when the server's release differs", () => {
    const root = withMeta("abc1234");
    const { result } = renderHook(() => useNewerRelease());
    act(() => {
      noteRelease(new Headers({ [RELEASE_HEADER]: "abc1234" }), root);
    });
    expect(result.current).toBe(false);
    act(() => {
      noteRelease(new Headers({ [RELEASE_HEADER]: "def5678" }), root);
    });
    expect(result.current).toBe(true);
  });

  it("notes nothing when either side has no release", () => {
    noteRelease(new Headers(), withMeta("abc1234"));
    noteRelease(new Headers({ [RELEASE_HEADER]: "def5678" }), withMeta(""));
    const { result } = renderHook(() => useNewerRelease());
    expect(result.current).toBe(false);
  });
});
