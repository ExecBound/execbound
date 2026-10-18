// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from "vitest";

import { allEntries } from "../shell/navigation";
import { SECTIONS, isSection, sectionRoot } from "./sections";

const ID = "abcdef01-0000-4000-8000-000000000001";
const UUID = /[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}/;

describe("the sections a switch may land on", () => {
  it("are every core page root but Ask, and nothing else", () => {
    const roots = allEntries().map((entry) => entry.to).filter((to) => to !== "/ask");
    expect([...SECTIONS].sort()).toEqual([...roots].sort());
    for (const root of roots) expect(isSection(root)).toBe(true);
    for (const value of ["/ask", `/policy/${ID}`, "/activity?open=x", "//x", "", "constructor", "toString"]) {
      expect(isSection(value)).toBe(false);
    }
  });
});

describe("the section root of a page", () => {
  it("is the root, never anything carrying an identifier, under every root", () => {
    for (const entry of allEntries()) {
      for (const suffix of ["", "/x", `/${ID}`, `/${ID}/rules`]) {
        if (entry.to === "/" && suffix !== "") continue;
        const root = sectionRoot(entry.to === "/" ? "/" : entry.to + suffix);
        expect(root).toEqual({ to: entry.to, label: entry.label });
        expect(root.to).not.toMatch(UUID);
      }
    }
  });

  it("names Approvals for a workspace's own approval address", () => {
    expect(sectionRoot(`/workspaces/${ID}/approvals/${ID}`)).toEqual({ to: "/approvals", label: "Approvals" });
    expect(sectionRoot(`/workspaces/${ID}/approvals/${ID}/classic`)).toEqual({ to: "/approvals", label: "Approvals" });
  });

  it("is Home for an address no entry holds", () => {
    expect(sectionRoot("/invitations")).toEqual({ to: "/", label: "Home" });
    expect(sectionRoot("/somewhere/else")).toEqual({ to: "/", label: "Home" });
    expect(sectionRoot("/policyx")).toEqual({ to: "/", label: "Home" });
  });

  it("does not depend on who could see the entry", () => {
    expect(sectionRoot(`/agents/${ID}`)).toEqual({ to: "/agents", label: "Agent connections" });
  });
});
