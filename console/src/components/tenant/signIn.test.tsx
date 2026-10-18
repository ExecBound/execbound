// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { act, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { readSignInOptions, readSignInQueryKey } from "../../api/@tanstack/react-query.gen";
import type { Provider, SignInView } from "../../api/types.gen";
import { PLACEHOLDER, type SessionSummary } from "../../lib/session";
import { clearToasts } from "../../lib/toast";
import { answerWith, renderPage, UNAVAILABLE } from "../../test/page";
import { SignInCard } from "./SignInCard";

const SIGN_IN = "/api/console/v1/tenant/sign-in";
const PROVIDER = "5b1c2d3e-0000-4000-8000-00000000000a";
const REDIRECT = "https://app.example/login/directory/callback";

function provider(changes: Partial<Provider> = {}): Provider {
  return {
    provider_id: PROVIDER,
    name: "Contoso",
    issuer: "https://login.microsoftonline.com/9f11b4a0-0000-4000-8000-00000000abcd/v2.0",
    client_id: "8a0d1f5c-1111-4000-8000-0000000000aa",
    subject_claim: "oid",
    state: "draft",
    created_at: "2026-09-20T09:00:00Z",
    verified_at: null,
    enabled_at: null,
    linked: 0,
    last_sign_in_at: null,
    self_linked: false,
    ...changes,
  };
}

function view(changes: Partial<SignInView> = {}): SignInView {
  return {
    configured: true,
    redirect_uri: REDIRECT,
    sign_in_url: null,
    invite_url: "https://app.example/invite",
    subject_claims: ["sub", "oid"],
    provider: null,
    ...changes,
  };
}

/** A workspace administrator: the one who configures the tenant's provider. */
const WORKSPACE_ADMINISTRATOR: SessionSummary = {
  ...PLACEHOLDER,
  role: "ADMIN",
  permissions: ["console.read", "policy.manage", "approvals.decide", "access.manage", "workspace.manage"],
};

/**
 * An administrator seated as `ADMIN` in one space: an administrator, without the workspace-wide
 * `access.manage` that configuring the tenant's provider takes.
 */
const SPACE_ADMINISTRATOR: SessionSummary = {
  ...PLACEHOLDER,
  role: "ADMIN",
  permissions: ["console.read", "policy.manage", "approvals.decide"],
};

/** Renders from the same read as the card, once a read of it has failed. */
function SignInReadFailed() {
  const query = useQuery({ ...readSignInOptions(), throwOnError: false });
  return query.isError ? <p>Sign-in read failed</p> : null;
}

afterEach(() => {
  vi.unstubAllGlobals();
  clearToasts();
});

describe("the tenant's own identity provider", () => {
  it("offers nothing when the deployment holds no key ring, and says why", async () => {
    answerWith({
      [`GET ${SIGN_IN}`]: {
        body: view({ configured: false, redirect_uri: null, invite_url: null }),
      },
    });
    renderPage(<SignInCard />, WORKSPACE_ADMINISTRATOR);
    expect(await screen.findByText(/was not given a key ring/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Register a provider" })).not.toBeInTheDocument();
  });

  it("shows the one redirect URI to paste before anything is registered", async () => {
    answerWith({ [`GET ${SIGN_IN}`]: { body: view() } });
    renderPage(<SignInCard />, WORKSPACE_ADMINISTRATOR);
    const field = await screen.findByLabelText(/Redirect URI/);
    expect(field).toHaveValue(REDIRECT);
    expect(screen.getByRole("button", { name: "Register a provider" })).toBeInTheDocument();
  });

  it("registers a provider with the issuer, the client and the subject claim", async () => {
    const seen = answerWith({
      [`GET ${SIGN_IN}`]: { body: view() },
      [`POST ${SIGN_IN}`]: { body: view({ provider: provider() }) },
    });
    renderPage(<SignInCard />, WORKSPACE_ADMINISTRATOR);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Register a provider" }));
    await user.type(await screen.findByLabelText("Name"), "Contoso");
    await user.type(screen.getByLabelText("Issuer"), "https://dev-1.okta.com/oauth2/default");
    await user.type(screen.getByLabelText("Client id"), "0oa123");
    await user.type(screen.getByLabelText("Client secret"), "the-secret");
    await user.click(screen.getByRole("button", { name: "Register" }));
    await screen.findByText("Not verified");
    const posted = seen.filter((request) => request.method === "POST");
    expect(posted).toHaveLength(1);
    expect(posted[0]?.body).toEqual({
      name: "Contoso",
      issuer: "https://dev-1.okta.com/oauth2/default",
      client_id: "0oa123",
      client_secret: "the-secret",
      subject_claim: "oid",
    });
    expect(posted[0]?.headers.get("x-csrf-token")).toBe("token-under-test");
  });

  it("explains an issuer the server refused rather than echoing what the server said", async () => {
    answerWith({
      [`GET ${SIGN_IN}`]: { body: view() },
      [`POST ${SIGN_IN}`]: {
        status: 400,
        body: { code: "INVALID_BODY", detail: "Invalid body", fields: ["issuer"] },
      },
    });
    renderPage(<SignInCard />, WORKSPACE_ADMINISTRATOR);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Register a provider" }));
    await user.type(await screen.findByLabelText("Name"), "Contoso");
    await user.type(screen.getByLabelText("Issuer"), "https://login.microsoftonline.com/common/v2.0");
    await user.type(screen.getByLabelText("Client id"), "0oa123");
    await user.type(screen.getByLabelText("Client secret"), "the-secret");
    await user.click(screen.getByRole("button", { name: "Register" }));
    expect(await screen.findByText(/must name one directory/)).toBeInTheDocument();
  });

  it("offers a test sign-in on a draft and no way to enable it", async () => {
    answerWith({ [`GET ${SIGN_IN}`]: { body: view({ provider: provider() }) } });
    renderPage(<SignInCard />, WORKSPACE_ADMINISTRATOR);
    expect(await screen.findByRole("button", { name: "Test sign-in" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Enable" })).not.toBeInTheDocument();
    expect(screen.getByText(/Nobody has signed in through this provider yet/)).toBeInTheDocument();
  });

  it("offers Enable once a sign-in verified it", async () => {
    answerWith({
      [`GET ${SIGN_IN}`]: {
        body: view({
          provider: provider({ state: "verified", verified_at: "2026-09-20T10:00:00Z", linked: 1, self_linked: true }),
        }),
      },
    });
    renderPage(<SignInCard />, WORKSPACE_ADMINISTRATOR);
    expect(await screen.findByRole("button", { name: "Enable" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Test sign-in" })).not.toBeInTheDocument();
  });

  it("says what disabling ends before it does it", async () => {
    const seen = answerWith({
      [`GET ${SIGN_IN}`]: {
        body: view({
          sign_in_url: `https://app.example/login/directory/${PROVIDER}`,
          provider: provider({ state: "enabled", linked: 3, self_linked: true }),
        }),
      },
      [`POST ${SIGN_IN}/${PROVIDER}/state`]: {
        body: view({ provider: provider({ state: "disabled", linked: 3, self_linked: true }) }),
      },
    });
    renderPage(<SignInCard />, WORKSPACE_ADMINISTRATOR);
    const user = userEvent.setup();
    expect(await screen.findByLabelText(/sign-in address/)).toHaveValue(
      `https://app.example/login/directory/${PROVIDER}`,
    );
    await user.click(screen.getByRole("button", { name: "Disable" }));
    expect(await screen.findByText(/for 3 linked users/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Disable it" }));
    await screen.findByText("Disabled");
    const posted = seen.filter((request) => request.method === "POST");
    expect(posted[0]?.body).toEqual({ state: "disabled" });
  });

  it("never shows a client secret or a ciphertext", async () => {
    answerWith({
      [`GET ${SIGN_IN}`]: { body: view({ provider: provider({ state: "enabled", self_linked: true }) }) },
    });
    renderPage(<SignInCard />, WORKSPACE_ADMINISTRATOR);
    await screen.findByText("Enabled");
    expect(document.body.textContent).not.toContain("secret");
    expect(document.body.textContent).not.toContain("ciphertext");
  });

  it("keeps the provider it read through a read that fails", async () => {
    let reads = 0;
    answerWith({
      [`GET ${SIGN_IN}`]: () => (++reads === 1 ? { body: view({ provider: provider({ state: "enabled" }) }) } : UNAVAILABLE),
    });
    const { queryClient } = renderPage(<><SignInCard /><SignInReadFailed /></>, WORKSPACE_ADMINISTRATOR);
    expect(await screen.findByText("Enabled")).toBeInTheDocument();
    // What returning to the tab does to a stale card: it reads it again, and here that read fails.
    await act(async () => {
      await queryClient.refetchQueries({ queryKey: readSignInQueryKey() });
    });
    // The sentinel renders from the same failed read as the card, so the card has had it too.
    expect(await screen.findByText("Sign-in read failed")).toBeInTheDocument();
    expect(reads).toBe(2);
    expect(screen.getByRole("heading", { name: "Sign-in provider" })).toBeInTheDocument();
    expect(screen.getByText("Enabled")).toBeInTheDocument();
    expect(screen.getByText("Contoso")).toBeInTheDocument();
  });
});

describe("the provider, read by an administrator narrowed to spaces", () => {
  it("offers no registration, and says who registers one", async () => {
    answerWith({ [`GET ${SIGN_IN}`]: { body: view() } });
    renderPage(<SignInCard />, SPACE_ADMINISTRATOR);
    expect(await screen.findByText(/Only a workspace administrator/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Register a provider" })).not.toBeInTheDocument();
  });

  it.each(["draft", "verified", "disabled"] as const)(
    "offers no test sign-in, link or state change on a %s provider",
    async (state) => {
      answerWith({ [`GET ${SIGN_IN}`]: { body: view({ provider: provider({ state }) }) } });
      renderPage(<SignInCard />, SPACE_ADMINISTRATOR);
      expect(await screen.findByText("Contoso")).toBeInTheDocument();
      expect(screen.getByText(/Only a workspace administrator/)).toBeInTheDocument();
      for (const name of ["Test sign-in", "Link my account", "Enable", "Disable"]) {
        expect(screen.queryByRole("button", { name })).not.toBeInTheDocument();
      }
      expect(screen.queryByText(/Nobody has signed in through this provider yet/)).not.toBeInTheDocument();
    },
  );

  it("still links their own account through the enabled provider, and cannot disable it", async () => {
    answerWith({
      [`GET ${SIGN_IN}`]: {
        body: view({
          sign_in_url: `https://app.example/login/directory/${PROVIDER}`,
          provider: provider({ state: "enabled", linked: 2 }),
        }),
      },
    });
    renderPage(<SignInCard />, SPACE_ADMINISTRATOR);
    expect(await screen.findByRole("button", { name: "Link my account" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Disable" })).not.toBeInTheDocument();
    expect(screen.getByLabelText(/sign-in address/)).toHaveValue(`https://app.example/login/directory/${PROVIDER}`);
  });
});
