// SPDX-License-Identifier: AGPL-3.0-only
import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { cookieName, readAppearance, useAppearance } from "./appearance";

function forget() {
  for (const part of document.cookie.split(";")) {
    const name = part.trim().split("=")[0];
    if (name) document.cookie = `${name}=; Path=/; Max-Age=0`;
  }
  document.documentElement.removeAttribute("data-eb-scheme");
}

beforeEach(forget);
afterEach(forget);

describe("the appearance choice", () => {
  it("is System until somebody chooses, and is then remembered for this browser", () => {
    expect(readAppearance()).toBe("system");
    const { result } = renderHook(() => useAppearance());
    expect(result.current[0]).toBe("system");

    act(() => {
      result.current[1]("dark");
    });
    expect(result.current[0]).toBe("dark");
    expect(document.cookie).toContain("eb_appearance=dark");
    expect(readAppearance()).toBe("dark");
    // The document the server serves next will carry the attribute; this page moves now, or
    // the choice would only show after a reload.
    expect(document.documentElement.getAttribute("data-eb-scheme")).toBe("dark");

    act(() => {
      result.current[1]("light");
    });
    expect(readAppearance()).toBe("light");
    expect(document.documentElement.getAttribute("data-eb-scheme")).toBe("light");
  });

  it("forgets the cookie and the attribute again when System is chosen", () => {
    const { result } = renderHook(() => useAppearance());
    act(() => {
      result.current[1]("dark");
    });
    act(() => {
      result.current[1]("system");
    });
    expect(result.current[0]).toBe("system");
    expect(document.cookie).not.toContain("eb_appearance=dark");
    expect(readAppearance()).toBe("system");
    expect(document.documentElement.hasAttribute("data-eb-scheme")).toBe(false);
  });

  it("reads anything but the two forced words as System, exactly as the server does", () => {
    document.cookie = "eb_appearance=sepia; Path=/";
    expect(readAppearance()).toBe("system");
    document.cookie = "eb_appearance=; Path=/";
    expect(readAppearance()).toBe("system");
    // A cookie whose name merely contains the appearance cookie's is a different cookie.
    forget();
    document.cookie = "other_eb_appearance=dark; Path=/";
    expect(readAppearance()).toBe("system");
  });

  it("takes the __Host- prefix over HTTPS, which is the name the server reads", () => {
    expect(cookieName("http:")).toBe("eb_appearance");
    expect(cookieName("https:")).toBe("__Host-eb_appearance");
  });
});
