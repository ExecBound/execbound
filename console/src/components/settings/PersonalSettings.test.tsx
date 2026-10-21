// SPDX-License-Identifier: AGPL-3.0-only
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { PersonalSettingsView } from "../../api/types.gen";
import { NO_SERVICE, PLACEHOLDER } from "../../lib/session";
import { setDeviceZoneForTests, setTimeZone, utcOffsetMinutes } from "../../lib/time";
import { clearToasts } from "../../lib/toast";
import { withEdition } from "../../test/edition";
import { answerWith, renderPage } from "../../test/page";
import { resetSingleKeysForTest, setSingleKeys } from "../../lib/keys";
import Shortcuts from "../ui/Shortcuts";
import { PersonalSettings } from "./PersonalSettings";

const ME = "6d2c1f0a-0000-4000-8000-000000000001";
const THIS = "aaaaaaaa-1111-4111-8111-111111111111";
const OTHER = "bbbbbbbb-2222-4222-8222-222222222222";

function view(sessions: PersonalSettingsView["sessions"]): PersonalSettingsView {
  return {
    identity: { principal_id: ME, kind: "HUMAN_APPROVER", credential_id: "c0ffee00-0000-4000-8000-000000000002" },
    tenant_name: "Synthetic <b>SOC</b>",
    email: "dana@example.com",
    has_password: true,
    credential: { issued_at: "2026-09-19T04:00:00+00:00", expires_at: "2026-09-19T12:00:00+00:00" },
    sessions,
    others: sessions.filter((row) => !row.current).length,
    directory: { provider: null, link: null },
    weekly_summary: { available: false, subscribed: false, address: null },
  };
}

const mine = { session_id: THIS, created_at: "2026-09-19T05:00:00+00:00", expires_at: "2026-09-19T13:00:00+00:00", label: "Other", current: true };
const theirs = { session_id: OTHER, created_at: "2026-09-19T04:30:00+00:00", expires_at: "2026-09-19T12:30:00+00:00", label: "Chrome on Windows", current: false };

afterEach(() => {
  vi.unstubAllGlobals();
  setTimeZone("local");
  window.localStorage.clear();
  setDeviceZoneForTests(undefined);
  clearToasts();
  for (const part of document.cookie.split(";")) {
    const name = part.trim().split("=")[0];
    if (name) document.cookie = `${name}=; Path=/; Max-Age=0`;
  }
  document.documentElement.removeAttribute("data-eb-scheme");
});

describe("the single-key switch in Appearance (NV6, #678)", () => {
  it("is the same preference the keyboard list shows", async () => {
    window.localStorage.clear();
    resetSingleKeysForTest();
    answerWith({ "GET /api/console/v1/account": { body: { name: "Dana", requests: [], notifications: [] } },
      "GET /api/console/v1/settings": { body: view([mine]) } });
    renderPage(<PersonalSettings />);
    const appearance = (await screen.findByRole("heading", { name: "Appearance" })).closest("section") ?? document.body;
    const box = within(appearance).getByRole("checkbox", { name: "Use single-key shortcuts (?, g, j and k)" });
    expect(box).toBeChecked();
    await userEvent.click(box);
    expect(box).not.toBeChecked();
    expect(window.localStorage.getItem("eb.single-keys")).toBe("off");
    renderPage(<Shortcuts open onClose={() => undefined} />);
    const list = await screen.findByRole("dialog", { name: "Keyboard" });
    expect(within(list).getByRole("checkbox", { name: "Use single-key shortcuts (?, g, j and k)" })).not.toBeChecked();
    setSingleKeys(true);
  });
});

describe("the personal settings page", () => {
  it("puts the edition's panels between the profile and the data requests, and asks for no preference (#496)", async () => {
    const seen = answerWith({ "GET /api/console/v1/account": { body: { name: "Dana", requests: [], notifications: [] } },
      "GET /api/console/v1/settings": { body: view([mine]) } });
    renderPage(withEdition(<PersonalSettings />, { AccountPanels: () => <p>Edition account panel</p> }));
    const panel = await screen.findByText("Edition account panel");
    const profile = screen.getByRole("heading", { name: "Your profile" });
    const requests = screen.getByRole("heading", { name: "Your data and account" });
    expect(profile.compareDocumentPosition(panel) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(panel.compareDocumentPosition(requests) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(seen.some((request) => request.path.endsWith("/account/preferences"))).toBe(false);
  });

  it("shows who I am, my credential, this device and the other one as text", async () => {
    answerWith({ "GET /api/console/v1/account": { body: {name: "Dana", requests: [], notifications: []} },
      "GET /api/console/v1/settings": { body: view([mine, theirs]) } });
    renderPage(<PersonalSettings />);
    expect(await screen.findByText("Chrome on Windows")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("My account");
    expect(screen.getByText("This device")).toBeInTheDocument();
    expect(screen.getByText("6d2c1f0a")).toBeInTheDocument();
    expect(await screen.findByText(/\bMember\b/)).toBeInTheDocument();
    expect(screen.getByText("Advanced sign-in details").closest("details")).not.toHaveAttribute("open");
    expect(screen.queryByText(/issues another from the Credentials page/)).toBeNull();
    expect(screen.getByText("Synthetic <b>SOC</b>")).toBeInTheDocument();
    expect(document.querySelector("b")).toBeNull();
    expect(screen.getByText("2026-09-19 04:00 UTC")).toBeInTheDocument();
    expect(screen.getByText("2 active sessions")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign out other devices" })).toBeInTheDocument();
  });

  it("points a person with no password to Account security to add one (#593)", async () => {
    answerWith({ "GET /api/console/v1/account": { body: {name: "Dana", requests: [], notifications: []} },
      "GET /api/console/v1/settings": { body: { ...view([mine]), has_password: false } } });
    renderPage(<PersonalSettings />);
    const link = await screen.findByRole("link", { name: "Account security" });
    expect(link).toHaveAttribute("href", "/account/security");
    expect(screen.queryByRole("button", { name: "Change the password" })).toBeNull();
  });

  it("offers no sign-out when this is the only device", async () => {
    answerWith({ "GET /api/console/v1/account": { body: {name: "Dana", requests: [], notifications: []} },
      "GET /api/console/v1/settings": { body: view([mine]) } });
    renderPage(<PersonalSettings />);
    expect(await screen.findByText("No other device is signed in as you.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Sign out other devices" })).toBeNull();
  });

  it("ends the other sessions only after the confirmation, with the token, and shows the server's answer", async () => {
    const seen = answerWith({ "GET /api/console/v1/account": { body: {name: "Dana", requests: [], notifications: []} },
      "GET /api/console/v1/settings": { body: view([mine, theirs]) },
      "POST /api/console/v1/settings/sessions/revoke-others": { body: view([mine]) },
    });
    renderPage(<PersonalSettings />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Sign out other devices" }));
    const dialog = await screen.findByRole("dialog", { name: "Sign out other devices?" });
    expect(seen.filter((request) => request.method === "POST")).toHaveLength(0);
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(seen.filter((request) => request.method === "POST")).toHaveLength(0);

    await user.click(screen.getByRole("button", { name: "Sign out other devices" }));
    const again = await screen.findByRole("dialog", { name: "Sign out other devices?" });
    await user.click(within(again).getByRole("button", { name: "Sign out other devices" }));
    expect(await screen.findByText("No other device is signed in as you.")).toBeInTheDocument();
    const posted = seen.filter((request) => request.method === "POST");
    expect(posted).toHaveLength(1);
    expect(posted[0]?.path).toBe("/api/console/v1/settings/sessions/revoke-others");
    expect(posted[0]?.headers.get("x-csrf-token")).toBe("token-under-test");
    expect(posted[0]?.headers.get("content-type")).toBe("application/json");
    expect(posted[0]?.body).toEqual({});
    expect(screen.getByRole("status")).toHaveTextContent("Signed out 1 other device.");
  });

  it("keeps the dialog open and names the refusal when the server says no", async () => {
    answerWith({ "GET /api/console/v1/account": { body: {name: "Dana", requests: [], notifications: []} },
      "GET /api/console/v1/settings": { body: view([mine, theirs]) },
      "POST /api/console/v1/settings/sessions/revoke-others": {
        status: 503,
        body: { code: "UNAVAILABLE", detail: "<script>server text</script>" },
      },
    });
    renderPage(<PersonalSettings />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Sign out other devices" }));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Sign out other devices" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("ExecBound is unavailable");
    expect(screen.queryByText(/server text/)).toBeNull();
    expect(screen.getByText("Chrome on Windows")).toBeInTheDocument();
  });

  it("chooses the appearance for this browser without asking the server anything", async () => {
    const seen = answerWith({ "GET /api/console/v1/account": { body: {name: "Dana", requests: [], notifications: []} },
      "GET /api/console/v1/settings": { body: view([mine]) } });
    renderPage(<PersonalSettings />);
    const user = userEvent.setup();
    const group = await screen.findByRole("group", { name: "Appearance" });
    const pressed = () =>
      within(group)
        .getAllByRole("button")
        .filter((button) => button.getAttribute("aria-pressed") === "true")
        .map((button) => button.textContent);

    expect(pressed()).toEqual(["System"]);
    await user.click(within(group).getByRole("button", { name: "Dark" }));
    expect(pressed()).toEqual(["Dark"]);
    expect(document.cookie).toContain("eb_appearance=dark");
    expect(document.documentElement.getAttribute("data-eb-scheme")).toBe("dark");
    expect(
      screen.getByText("Always the dark scheme on this browser, whatever the device is set to."),
    ).toBeInTheDocument();

    await user.click(within(group).getByRole("button", { name: "System" }));
    expect(pressed()).toEqual(["System"]);
    expect(document.documentElement.hasAttribute("data-eb-scheme")).toBe(false);
    // The choice is this browser's: no request carries it, and nothing was written anywhere
    // the server could read it back as a fact about the person.
    expect(seen.filter((request) => request.method !== "GET")).toHaveLength(0);
  });

  it("chooses the zone times are shown in, for this browser alone", async () => {
    setDeviceZoneForTests("America/New_York");
    const seen = answerWith({ "GET /api/console/v1/account": { body: {name: "Dana", requests: [], notifications: []} },
      "GET /api/console/v1/settings": { body: view([mine]) } });
    const first = renderPage(<PersonalSettings />);
    const user = userEvent.setup();
    const group = await screen.findByRole("group", { name: "Show times in" });
    const pressed = () =>
      within(screen.getByRole("group", { name: "Show times in" }))
        .getAllByRole("button")
        .filter((button) => button.getAttribute("aria-pressed") === "true")
        .map((button) => button.textContent);
    expect(within(group).getAllByRole("button").map((button) => button.textContent)).toEqual([
      expect.stringMatching(/^My time zone \(E[DS]T\)$/),
      "UTC",
    ]);
    expect(pressed()).toEqual([expect.stringMatching(/^My time zone/)]);
    expect(utcOffsetMinutes()).not.toBe(0);

    await user.click(within(group).getByRole("button", { name: "UTC" }));
    expect(pressed()).toEqual(["UTC"]);
    expect(window.localStorage.getItem("eb.times")).toBe("utc");
    // The offset Home and the board send with their reads is now UTC's.
    expect(utcOffsetMinutes()).toBe(0);
    expect(screen.getByText(/Today on Home and the Live board starts at midnight/)).toBeInTheDocument();

    first.unmount();
    renderPage(<PersonalSettings />);
    await screen.findByRole("group", { name: "Show times in" });
    expect(pressed()).toEqual(["UTC"]);
    expect(seen.filter((request) => request.method !== "GET")).toHaveLength(0);
  });

  it("offers personal access tokens to an administrator and to nobody else", async () => {
    const account = { body: { name: "Dana", analytics_consent: false, requests: [], notifications: [] } };
    const admin = view([mine]);
    const seen = answerWith({
      "GET /api/console/v1/account": account,
      "GET /api/console/v1/settings": { body: { ...admin, identity: { ...admin.identity, kind: "ADMIN" } } },
      "GET /api/console/v1/settings/tokens": { body: { tokens: [] } },
    });
    const { unmount } = renderPage(<PersonalSettings />);
    expect(await screen.findByRole("heading", { name: "Personal access tokens" })).toBeInTheDocument();
    expect(await screen.findByText("No tokens yet.")).toBeInTheDocument();
    expect(seen.some((request) => request.path === "/api/console/v1/settings/tokens")).toBe(true);
    unmount();

    const approver = answerWith({
      "GET /api/console/v1/account": account,
      "GET /api/console/v1/settings": { body: view([mine]) },
      "GET /api/console/v1/settings/tokens": { body: { tokens: [] } },
    });
    renderPage(<PersonalSettings />);
    expect(await screen.findByRole("heading", { name: "Your password" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Personal access tokens" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Create token" })).toBeNull();
    expect(approver.some((request) => request.path === "/api/console/v1/settings/tokens")).toBe(false);
  });
});

describe("the data requests card's support line (#496)", () => {
  const answers = {
    "GET /api/console/v1/account": { body: { name: "Dana", requests: [], notifications: [] } },
    "GET /api/console/v1/settings": { body: view([mine]) },
  };

  it("offers the deployment's support address where it names one", async () => {
    answerWith(answers);
    renderPage(<PersonalSettings />, { ...PLACEHOLDER, service: { ...NO_SERVICE, support_email: "support@example.com" } });
    const card = within((await screen.findByRole("heading", { name: "Your data and account" })).closest("section") ?? document.body);
    expect(card.getByRole("link", { name: "contact support" })).toHaveAttribute(
      "href",
      "mailto:support@example.com?subject=ExecBound%20privacy%20request",
    );
  });

  it("names no address where the deployment names none", async () => {
    answerWith(answers);
    renderPage(<PersonalSettings />);
    expect(await screen.findByRole("heading", { name: "Your data and account" })).toBeInTheDocument();
    expect(screen.getByText(/Your workspace administrators handle these requests and post a response here\.$/)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "contact support" })).toBeNull();
    expect(document.querySelector('a[href^="mailto:"]')).toBeNull();
  });
});

describe("the directory identity card (#253, #241)", () => {
  const PROVIDER = "5e1f0c2d-3333-4333-8333-333333333333";
  const enabled = { provider_id: PROVIDER, name: "Contoso <i>SSO</i>", state: "enabled" as const };
  const linked = {
    provider_id: PROVIDER,
    provider_name: "Contoso <i>SSO</i>",
    subject: "77777777-0000-4000-8000-0000000000cc",
    via: "self" as const,
    display_name: "Sam <b>Lee</b>",
    display_username: "sam@contoso.example",
    created_at: "2026-09-19T05:00:00+00:00",
    last_sign_in_at: "2026-09-19T06:00:00+00:00",
  };

  function answer(directory: PersonalSettingsView["directory"]) {
    return answerWith({
      "GET /api/console/v1/account": { body: { name: "Dana", requests: [], notifications: [] } },
      "GET /api/console/v1/settings": { body: { ...view([mine]), directory } },
    });
  }

  async function card() {
    const heading = await screen.findByRole("heading", { name: "Directory identity" });
    return within(heading.closest("section") ?? document.body);
  }

  it("offers Link my identity when an enabled provider exists and nothing is linked", async () => {
    const assign = vi.fn();
    vi.stubGlobal("location", { assign });
    const seen = answer({ provider: enabled, link: null });
    renderPage(<PersonalSettings />);
    const section = await card();
    expect(section.getByText("Contoso <i>SSO</i>")).toBeInTheDocument();
    expect(document.querySelector("i")).toBeNull();
    expect(section.getByText("Unlinking is an administrator action, on your page under Users.")).toBeInTheDocument();
    await userEvent.setup().click(section.getByRole("button", { name: "Link my identity" }));
    // A navigation, not a request: the flow leaves for the directory and comes back.
    expect(assign).toHaveBeenCalledWith(`/login/directory/${PROVIDER}/link`);
    expect(seen.filter((request) => request.method !== "GET")).toHaveLength(0);
  });

  it("says there is nothing to link when no provider is offered", async () => {
    answer({ provider: null, link: null });
    renderPage(<PersonalSettings />);
    const section = await card();
    expect(section.getByText(/no directory sign-in enabled/)).toBeInTheDocument();
    expect(section.queryByRole("button", { name: "Link my identity" })).toBeNull();
    expect(section.getByText("Unlinking is an administrator action, on your page under Users.")).toBeInTheDocument();
  });

  it("shows my link, how it was made and the directory's hints as text, and offers no button", async () => {
    answer({ provider: enabled, link: linked });
    renderPage(<PersonalSettings />);
    const section = await card();
    expect(section.getByText("Linked")).toBeInTheDocument();
    expect(section.getByText("77777777-0000-4000-8000-0000000000cc")).toBeInTheDocument();
    expect(section.getByText("Sam <b>Lee</b>")).toBeInTheDocument();
    expect(section.getByText("sam@contoso.example")).toBeInTheDocument();
    expect(document.querySelector("b")).toBeNull();
    expect(section.getByText("You linked it yourself")).toBeInTheDocument();
    expect(section.getByText("2026-09-19 06:00 UTC")).toBeInTheDocument();
    expect(section.queryByRole("button", { name: "Link my identity" })).toBeNull();
    expect(section.queryByText(/not enabled in this workspace/)).toBeNull();
    expect(section.getByText("Unlinking is an administrator action, on your page under Users.")).toBeInTheDocument();
  });

  it("says who made a link an administrator made, and when sign-in through it is not enabled", async () => {
    answer({
      provider: null,
      link: { ...linked, via: "admin", display_name: null, display_username: null, last_sign_in_at: null },
    });
    renderPage(<PersonalSettings />);
    const section = await card();
    expect(section.getByText("An administrator linked it")).toBeInTheDocument();
    expect(section.getByText("None yet")).toBeInTheDocument();
    expect(section.queryByText("Name")).toBeNull();
    expect(section.getByText("Signing in through this directory is not enabled in this workspace right now.")).toBeInTheDocument();
    expect(section.queryByRole("button", { name: "Link my identity" })).toBeNull();
  });
});

describe("the second-factor card (AK10)", () => {
  function secured(security: NonNullable<PersonalSettingsView["security"]>): PersonalSettingsView {
    return { ...view([mine]), security };
  }

  it("states each figure and offers Manage where a factor is on", async () => {
    answerWith({ "GET /api/console/v1/settings": { body: secured({ authenticator: true, passkeys: 2, recovery_remaining: 7, requirement: "admins", available: true }) } });
    renderPage(<PersonalSettings />, { ...PLACEHOLDER, role: "APPROVER" });
    const card = (await screen.findByRole("heading", { level: 2, name: "Multi-factor authentication" })).closest("section");
    if (card === null) throw new Error("No card");
    expect(within(card).getByText("Authenticator app").nextSibling).toHaveTextContent("On");
    expect(within(card).getByText("Passkeys").nextSibling).toHaveTextContent("2 saved");
    expect(within(card).getByText("Recovery codes").nextSibling).toHaveTextContent("7 left");
    expect(card).toHaveTextContent("This workspace requires a second factor for administrators.");
    expect(within(card).getByRole("link", { name: "Manage" })).toHaveAttribute("href", "/account/security");
  });

  it("offers Add a second factor with none, and says where account security is not configured", async () => {
    answerWith({ "GET /api/console/v1/settings": { body: secured({ authenticator: false, passkeys: 0, recovery_remaining: 0, requirement: "optional", available: true }) } });
    const first = renderPage(<PersonalSettings />, { ...PLACEHOLDER, role: "APPROVER" });
    const card = (await screen.findByRole("heading", { level: 2, name: "Multi-factor authentication" })).closest("section");
    if (card === null) throw new Error("No card");
    expect(within(card).getByText("Authenticator app").nextSibling).toHaveTextContent("Off");
    expect(within(card).queryByText("Recovery codes")).toBeNull();
    expect(card).not.toHaveTextContent("requires a second factor");
    expect(within(card).getByRole("link", { name: "Add a second factor" })).toHaveAttribute("href", "/account/security");
    first.unmount();
    answerWith({ "GET /api/console/v1/settings": { body: secured({ authenticator: false, passkeys: 0, recovery_remaining: 0, requirement: "optional", available: false }) } });
    renderPage(<PersonalSettings />, { ...PLACEHOLDER, role: "APPROVER" });
    expect(await screen.findByText("Account security is not configured on this deployment.")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Add a second factor" })).toBeNull();
  });
});

describe("the trusted browsers card (#859)", () => {
  const HERE = "cccccccc-3333-4333-8333-333333333333";
  const THERE = "dddddddd-4444-4444-8444-444444444444";
  const base = { authenticator: true, passkeys: 0, recovery_remaining: 10, requirement: "optional" as const, available: true };
  const here = { browser_id: HERE, label: "Chrome on Windows", created_at: "2026-10-01T09:00:00+00:00", last_used_at: "2026-10-18T09:00:00+00:00", expires_at: "2026-10-31T09:00:00+00:00", this_browser: true };
  const there = { browser_id: THERE, label: null, created_at: "2026-09-25T09:00:00+00:00", last_used_at: null, expires_at: "2026-10-25T09:00:00+00:00", this_browser: false };

  function trusting(trusted: (typeof here | typeof there)[], trust_allowed = true): PersonalSettingsView {
    return { ...view([mine]), security: { ...base, trusted, trust_allowed } };
  }

  async function card() {
    const heading = await screen.findByRole("heading", { level: 2, name: "Trusted browsers" });
    const section = heading.closest("section");
    if (section === null) throw new Error("No card");
    return within(section);
  }

  it("says how a browser comes to be trusted when none is, and what a workspace that forbids it does", async () => {
    answerWith({ "GET /api/console/v1/settings": { body: trusting([]) } });
    const first = renderPage(<PersonalSettings />, { ...PLACEHOLDER, role: "APPROVER" });
    const section = await card();
    expect(section.getByText(/No browser is trusted\./)).toBeInTheDocument();
    expect(section.queryByRole("table")).toBeNull();
    expect(section.queryByRole("button", { name: /Remove/ })).toBeNull();
    first.unmount();
    answerWith({ "GET /api/console/v1/settings": { body: trusting([], false) } });
    renderPage(<PersonalSettings />, { ...PLACEHOLDER, role: "APPROVER" });
    expect((await card()).getByText(/This workspace does not allow trusted browsers/)).toBeInTheDocument();
  });

  it("is not shown where this deployment has no account security", async () => {
    answerWith({ "GET /api/console/v1/settings": { body: view([mine]) } });
    renderPage(<PersonalSettings />, { ...PLACEHOLDER, role: "APPROVER" });
    await screen.findByRole("heading", { level: 2, name: "Multi-factor authentication" });
    expect(screen.queryByRole("heading", { level: 2, name: "Trusted browsers" })).toBeNull();
  });

  it("lists each trust, marks this browser, and offers Remove and Remove all", async () => {
    answerWith({ "GET /api/console/v1/settings": { body: trusting([here, there]) } });
    renderPage(<PersonalSettings />, { ...PLACEHOLDER, role: "APPROVER" });
    const section = await card();
    const rows = section.getAllByRole("row").slice(1);
    expect(rows).toHaveLength(2);
    const [first, second] = rows;
    if (first === undefined || second === undefined) throw new Error("No rows");
    expect(first).toHaveTextContent("Chrome on Windows");
    expect(within(first).getByText("This browser")).toBeInTheDocument();
    expect(first).toHaveTextContent("2026-10-31 09:00 UTC");
    expect(second).toHaveTextContent("Unknown browser");
    expect(second).toHaveTextContent("Not yet");
    expect(within(second).queryByText("This browser")).toBeNull();
    expect(section.getByRole("button", { name: "Remove Chrome on Windows" })).toBeInTheDocument();
    expect(section.getByRole("button", { name: "Remove Unknown browser" })).toBeInTheDocument();
    expect(section.getByRole("button", { name: "Remove all" })).toBeInTheDocument();
  });

  it("removes one only after the confirmation, naming it, and shows the server's answer", async () => {
    const seen = answerWith({
      "GET /api/console/v1/settings": { body: trusting([here, there]) },
      "POST /api/console/v1/settings/trusted-browsers/remove": { body: trusting([here]) },
    });
    renderPage(<PersonalSettings />, { ...PLACEHOLDER, role: "APPROVER" });
    const user = userEvent.setup();
    const section = await card();
    await user.click(section.getByRole("button", { name: "Remove Unknown browser" }));
    const dialog = await screen.findByRole("dialog", { name: "Remove this trusted browser?" });
    expect(seen.filter((request) => request.method === "POST")).toHaveLength(0);
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(seen.filter((request) => request.method === "POST")).toHaveLength(0);

    await user.click(section.getByRole("button", { name: "Remove Unknown browser" }));
    const again = await screen.findByRole("dialog", { name: "Remove this trusted browser?" });
    await user.click(within(again).getByRole("button", { name: "Remove" }));
    await screen.findByText("Trusted browser removed.");
    const posted = seen.filter((request) => request.method === "POST");
    expect(posted).toHaveLength(1);
    expect(posted[0]?.path).toBe("/api/console/v1/settings/trusted-browsers/remove");
    expect(posted[0]?.headers.get("x-csrf-token")).toBe("token-under-test");
    expect(posted[0]?.body).toEqual({ browser_id: THERE });
    expect((await card()).getAllByRole("row")).toHaveLength(2);
  });

  it("removes every trust after its own confirmation", async () => {
    const seen = answerWith({
      "GET /api/console/v1/settings": { body: trusting([here, there]) },
      "POST /api/console/v1/settings/trusted-browsers/remove-all": { body: trusting([]) },
    });
    renderPage(<PersonalSettings />, { ...PLACEHOLDER, role: "APPROVER" });
    const user = userEvent.setup();
    await user.click((await card()).getByRole("button", { name: "Remove all" }));
    const dialog = await screen.findByRole("dialog", { name: "Remove every trusted browser?" });
    expect(dialog).toHaveTextContent("this one included");
    await user.click(within(dialog).getByRole("button", { name: "Remove all" }));
    expect(await screen.findByText(/No browser is trusted\./)).toBeInTheDocument();
    const posted = seen.filter((request) => request.method === "POST");
    expect(posted.map((request) => request.path)).toEqual(["/api/console/v1/settings/trusted-browsers/remove-all"]);
    expect(posted[0]?.body).toEqual({});
    expect(screen.getByRole("status")).toHaveTextContent("Removed 2 trusted browsers.");
  });

  it("does not say this browser is included when it holds none of the trusts", async () => {
    answerWith({ "GET /api/console/v1/settings": { body: trusting([there]) } });
    renderPage(<PersonalSettings />, { ...PLACEHOLDER, role: "APPROVER" });
    const user = userEvent.setup();
    await user.click((await card()).getByRole("button", { name: "Remove all" }));
    const dialog = await screen.findByRole("dialog", { name: "Remove every trusted browser?" });
    expect(dialog).toHaveTextContent("Every browser listed here will ask for your second factor at its next sign-in.");
    expect(dialog).not.toHaveTextContent("this one included");
  });
});
