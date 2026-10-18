// SPDX-License-Identifier: AGPL-3.0-only
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { PersonDetail, SignInView } from "../../api/types.gen";
import { PLACEHOLDER } from "../../lib/session";
import { clearToasts } from "../../lib/toast";
import { answerWith, renderPage } from "../../test/page";
import { DirectoryCard } from "./DirectoryCard";

const SIGN_IN = "/api/console/v1/tenant/sign-in";
const PROVIDER = "5b1c2d3e-0000-4000-8000-00000000000a";
const HUMAN = "1a2b3c4d-0000-4000-8000-000000000001";
const ADMIN = "0a1b2c3d-0000-4000-8000-000000000009";
const INVITATION = "9e8d7c6b-0000-4000-8000-00000000000b";
const PEOPLE = `/api/console/v1/people/${HUMAN}`;

function tenant(state: "enabled" | "draft" = "enabled"): SignInView {
  return {
    configured: true,
    redirect_uri: "https://app.example/login/directory/callback",
    sign_in_url: `https://app.example/login/directory/${PROVIDER}`,
    invite_url: "https://app.example/invite",
    subject_claims: ["sub", "oid"],
    provider: {
      provider_id: PROVIDER,
      name: "Contoso",
      issuer: "https://dev-1.okta.com/oauth2/default",
      client_id: "0oa123",
      subject_claim: "oid",
      state,
      created_at: "2026-09-20T09:00:00Z",
      verified_at: "2026-09-20T10:00:00Z",
      enabled_at: state === "enabled" ? "2026-09-20T10:05:00Z" : null,
      linked: 1,
      last_sign_in_at: null,
      self_linked: true,
    },
  };
}

function person(changes: Partial<PersonDetail["sign_in"]> = {}, kind: "HUMAN_APPROVER" | "ADMIN" = "HUMAN_APPROVER"): PersonDetail {
  return {
    person: {
      principal_id: kind === "ADMIN" ? ADMIN : HUMAN,
      kind,
      active: true,
      label: "Dana Reyes",
      number: kind === "ADMIN" ? 1 : 2,
      created_at: "2026-09-10T08:00:00Z",
      deactivated_at: null,
      replaced_by: null,
    },
    sign_in: {
      email: "dana@example.com",
      has_password: true,
      pending_until: null,
      identities: [],
      link: null,
      invitation: null,
      ...changes,
    },
    credentials: [],
    scopes: [],
    targets: [],
    actions: [],
    sessions: [],
    history: { decisions: [], sign_ins: [], events: [] },
    history_limit: 20,
    is_self: false,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  clearToasts();
});

describe("a person's directory account", () => {
  it("says the tenant has no enabled provider and points at where to register one", async () => {
    answerWith({ [`GET ${SIGN_IN}`]: { body: tenant("draft") } });
    renderPage(<DirectoryCard protection="standard" detail={person()} />, {
      ...PLACEHOLDER,
      role: "ADMIN",
      permissions: ["console.read", "access.manage", "workspace.manage"],
    });
    expect(await screen.findByText(/no enabled identity provider/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Register one in Workspace settings." })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Invite to/ })).not.toBeInTheDocument();
  });

  it("tells an administrator narrowed to spaces that a workspace administrator registers one", async () => {
    answerWith({ [`GET ${SIGN_IN}`]: { body: tenant("draft") } });
    renderPage(<DirectoryCard protection="standard" detail={person()} />, {
      ...PLACEHOLDER,
      role: "ADMIN",
      permissions: ["console.read", "policy.manage", "approvals.decide"],
    });
    expect(await screen.findByText(/A workspace administrator registers and enables one/)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Register one in Workspace settings." })).not.toBeInTheDocument();
  });

  it("invites a person and shows the code once, beside the page to open", async () => {
    const seen = answerWith({
      [`GET ${SIGN_IN}`]: { body: tenant() },
      [`POST ${PEOPLE}/directory-invite`]: {
        body: {
          code: "ebv1.7f8e9d0c-0000-4000-8000-000000000003.9e8d7c6b-0000-4000-8000-00000000000b.zzz",
          address: "https://app.example/invite",
          reset_id: INVITATION,
          principal_id: HUMAN,
          expires_at: "2026-09-27T10:00:00Z",
        },
      },
    });
    renderPage(<DirectoryCard protection="standard" detail={person()} />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Invite to Contoso" }));
    expect(await screen.findByText("Copy the code now")).toBeInTheDocument();
    expect(screen.getByLabelText(/Page to open/)).toHaveValue("https://app.example/invite");
    const posted = seen.filter((request) => request.method === "POST");
    expect(posted[0]?.body).toEqual({ provider_id: PROVIDER, lifetime: "168" });
  });

  it("shows a pending invitation with the day it stops working, and never its code", async () => {
    answerWith({ [`GET ${SIGN_IN}`]: { body: tenant() } });
    renderPage(
      <DirectoryCard protection="standard"
        detail={person({
          invitation: { invitation_id: INVITATION, provider_id: PROVIDER, expires_at: "2026-09-27T10:00:00Z" },
        })}
      />,
    );
    expect(await screen.findByText(/Pending until/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Revoke the invitation" })).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("ebv1.");
  });

  it("shows a linked account by its subject and how it was bound", async () => {
    answerWith({ [`GET ${SIGN_IN}`]: { body: tenant() } });
    renderPage(
      <DirectoryCard protection="standard"
        detail={person({
          link: {
            provider_id: PROVIDER,
            provider_name: "Contoso",
            subject: "00u1a2b3c4",
            via: "invitation",
            display_name: "Dana Reyes",
            display_username: "dana@contoso.example",
            last_sign_in_at: "2026-09-21T08:00:00Z",
          },
        })}
      />,
    );
    expect(await screen.findByText("00u1a2b3c4")).toBeInTheDocument();
    expect(screen.getByText("redeemed an invitation")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Unlink" })).toBeInTheDocument();
  });

  it("says unlinking ends every session before it does it", async () => {
    const seen = answerWith({
      [`GET ${SIGN_IN}`]: { body: tenant() },
      [`POST ${PEOPLE}/directory-unlink`]: { body: person() },
    });
    renderPage(
      <DirectoryCard protection="standard"
        detail={person({
          link: {
            provider_id: PROVIDER,
            provider_name: "Contoso",
            subject: "00u1a2b3c4",
            via: "admin",
            display_name: null,
            display_username: null,
            last_sign_in_at: null,
          },
        })}
      />,
    );
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Unlink" }));
    expect(await screen.findByText(/Every session of this person ends at once/)).toBeInTheDocument();
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Unlink" }));
    const posted = seen.filter((request) => request.method === "POST");
    expect(posted).toHaveLength(1);
    expect(posted[0]?.path).toBe(`${PEOPLE}/directory-unlink`);
  });

  it("offers an administrator nothing, because they link themselves", async () => {
    answerWith({ [`GET ${SIGN_IN}`]: { body: tenant() } });
    renderPage(<DirectoryCard protection="standard" detail={person({}, "ADMIN")} />);
    expect(await screen.findByText(/links their own account from Workspace settings/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Invite to/ })).not.toBeInTheDocument();
  });
});
