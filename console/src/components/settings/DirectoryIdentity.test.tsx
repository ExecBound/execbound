// SPDX-License-Identifier: AGPL-3.0-only
import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { PersonalSettingsView } from "../../api/types.gen";
import { PLACEHOLDER, type Role } from "../../lib/session";
import { renderPage } from "../../test/page";
import { DirectoryIdentity } from "./DirectoryIdentity";

const PROVIDER = "5e1f0c2d-3333-4333-8333-333333333333";
const enabled = { provider_id: PROVIDER, name: "Contoso", state: "enabled" as const };
const linked = {
  provider_id: PROVIDER,
  provider_name: "Contoso",
  subject: "77777777-0000-4000-8000-0000000000cc",
  via: "admin" as const,
  display_name: null,
  display_username: null,
  created_at: "2026-09-19T05:00:00+00:00",
  last_sign_in_at: null,
};

const UNLINKED_BY_AN_ADMINISTRATOR = "Unlinking is an administrator action, on your page under Users.";
const NOT_FROM_THE_CONSOLE = "An administrator's link is not removed from the console.";

const STATES: [string, PersonalSettingsView["directory"]][] = [
  ["linked", { provider: enabled, link: linked }],
  ["offered a provider", { provider: enabled, link: null }],
  ["offered nothing", { provider: null, link: null }],
];

async function card() {
  const heading = await screen.findByRole("heading", { name: "Directory identity" });
  return within(heading.closest("section") ?? document.body);
}

/**
 * Who removes a link (#253, #241). `directory_unlink` takes an approver's link alone: its target
 * check refuses a principal whose kind or effective kind is an administrator's, so no console
 * page unlinks an administrator, and no command does either. The card tells each viewer what is
 * true for them, by the session's role, which is the effective kind the server resolved.
 */
describe("the directory identity card's unlinking sentence", () => {
  it.each(STATES)("tells an administrator, %s, that their link is not removed from the console", async (_, directory) => {
    renderPage(<DirectoryIdentity directory={directory} />, { ...PLACEHOLDER, role: "ADMIN" });
    const section = await card();
    expect(section.getByText(NOT_FROM_THE_CONSOLE)).toBeInTheDocument();
    expect(section.queryByText(UNLINKED_BY_AN_ADMINISTRATOR)).toBeNull();
    expect(section.queryByText(/under Users/)).toBeNull();
  });

  it.each<Role>(["APPROVER", "POLICY_MANAGER", "VIEWER"])(
    "tells a person whose role is %s that an administrator unlinks them on their page",
    async (role) => {
      renderPage(<DirectoryIdentity directory={{ provider: enabled, link: linked }} />, { ...PLACEHOLDER, role });
      const section = await card();
      expect(section.getByText(UNLINKED_BY_AN_ADMINISTRATOR)).toBeInTheDocument();
      expect(section.queryByText(NOT_FROM_THE_CONSOLE)).toBeNull();
    },
  );
});
