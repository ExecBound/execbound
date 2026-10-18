// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { client } from "../../api/client.gen";
import { issueAgentCredential } from "../../api/sdk.gen";
import { ConfirmDialog } from "./ConfirmDialog";
import { explain, refusalOf } from "./errors";
import cases from "../../test/principal-names.json";
import { day, discoveredName, expiry, plural, prefix, refHandle, refName, when, words } from "./format";
import { SecretDialog } from "./SecretDialog";
import { useShowOnce } from "./showOnce";

const TOKEN = "eb1.00000000-0000-0000-0000-000000000000.11111111-1111-1111-1111-111111111111.secretsecretsecret";
const ISSUED = {
  token: TOKEN,
  credential_id: "11111111-1111-1111-1111-111111111111",
  principal_id: "22222222-2222-2222-2222-222222222222",
  kind: "AGENT",
  expires_at: "2026-09-19T22:00:00Z",
};

afterEach(() => {
  client.setConfig({ baseUrl: "/", fetch: undefined });
});

/** The generated client under a stubbed fetch; Node's Request needs an absolute address. */
function stub(fetch: (request: Request) => Promise<Response>) {
  client.setConfig({ baseUrl: "http://console.test/", fetch: fetch as typeof globalThis.fetch });
}

describe("one name per principal (#678)", () => {
  it.each(cases)("names $case as the server does", (row) => {
    expect(refName({ principal_id: row.principal_id, label: row.label, number: row.number, kind: row.kind })).toBe(row.name);
  });

  it("gives a handle beside a label, and the kind a reference carries wins over the default", () => {
    const person = { principal_id: "7d1e7b4a-0000-4000-8000-000000000002", label: "Dana", number: 2, kind: "HUMAN_APPROVER" };
    expect(refHandle(person)).toBe("User 2");
    expect(refName({ ...person, label: null, kind: undefined }, "ADMIN")).toBe("User 2");
    expect(refName({ ...person, label: null, kind: undefined })).toBe("Agent 2");
  });

  it("names a discovered agent no principal backs by its display name, never by a number", () => {
    expect(discoveredName("Synthetic agent 1", "3f2504e0-0000-4000-8000-000000000001")).toBe("Synthetic agent 1");
    expect(discoveredName(null, "3f2504e0-0000-4000-8000-000000000001")).toBe("Discovered agent 3f2504e0");
    expect(discoveredName("", "3f2504e0-0000-4000-8000-000000000001")).toBe("Discovered agent 3f2504e0");
  });
});

describe("the directory's words", () => {
  it("print a prefix, a UTC minute, a kind and a count", () => {
    expect(prefix("22222222-2222-2222-2222-222222222222")).toBe("22222222");
    expect(prefix(null)).toBe("");
    expect(when("2026-09-19T14:02:11.123Z")).toBe("2026-09-19 14:02 UTC");
    expect(when("2026-09-19T16:02:11+02:00")).toBe("2026-09-19 14:02 UTC");
    expect(when(null)).toBe("never");
    expect(when("not a time", "before labels")).toBe("before labels");
    expect(expiry("9999-12-31T00:00:00Z")).toBe("Never");
    expect(expiry("9999-12-30T19:00:00-05:00")).toBe("Never");
    expect(expiry("2026-09-19T14:02:11Z")).toBe("2026-09-19 14:02 UTC");
    expect(day("2026-09-01T00:00:00Z")).toBe("2026-09-01");
    expect(words("HUMAN_APPROVER")).toBe("human approver");
    expect(plural(1, "target")).toBe("1 target");
    expect(plural(2, "target")).toBe("2 targets");
  });

  it("explain a refusal by its code and name the fields of a body fault", () => {
    expect(refusalOf({ code: "CONFLICT", detail: "x" })).toEqual({ code: "CONFLICT", fields: [] });
    expect(refusalOf(new Error("boom"))).toEqual({ code: "UNAVAILABLE", fields: [] });
    expect(explain({ code: "INVALID_BODY", fields: ["label"] })).toBe(
      "A label of 1 to 80 characters is required, with nothing in it that looks like a password, key or token.",
    );
    expect(explain({ code: "INVALID_BODY", fields: ["reason", "lifetime"] })).toBe(
      "A reason of 1 to 500 characters is required, with nothing in it that looks like a password, key or token. " +
        "Choose a lifetime from the list.",
    );
    expect(explain({ code: "INVALID_BODY", fields: [] })).toBe("Something in the form is missing or out of bounds.");
    expect(explain({ code: "INVALID_PRINCIPAL" })).toBe("That principal cannot be changed from here.");
    expect(explain({ code: "NO_SUCH_CODE" })).toBe("ExecBound is unavailable; try again shortly.");
    expect(explain("string")).toBe("ExecBound is unavailable; try again shortly.");
  });

  it("names a field it has no copy for instead of the generic line, such as a bundle location", () => {
    expect(explain({ code: "INVALID_BODY", fields: ["ruleset.rules.0.note"] })).toBe(
      "Check ruleset.rules.0.note: something there is missing, out of bounds, or looks like a password, key or token.",
    );
    expect(explain({ code: "INVALID_BODY", fields: ["ruleset.rules.0.note", "ruleset.rules.1.note"] })).toBe(
      "Check ruleset.rules.0.note, ruleset.rules.1.note: something there is missing, out of bounds, or looks like a password, key or token.",
    );
  });

  it("falls back to the generic line for a field that does not read like a schema path", () => {
    expect(explain({ code: "INVALID_BODY", fields: ["<script>alert(1)</script>"] })).toBe(
      "Something in the form is missing or out of bounds.",
    );
    expect(explain({ code: "INVALID_BODY", fields: ["a b"] })).toBe(
      "Something in the form is missing or out of bounds.",
    );
  });

  it("falls back to the generic line for a field name longer than a schema path ever is", () => {
    const long = "a".repeat(121);
    expect(explain({ code: "INVALID_BODY", fields: [long] })).toBe(
      "Something in the form is missing or out of bounds.",
    );
    const atTheBound = "a".repeat(120);
    expect(explain({ code: "INVALID_BODY", fields: [atTheBound] })).toBe(
      `Check ${atTheBound}: something there is missing, out of bounds, or looks like a password, key or token.`,
    );
  });

  it("extends the email sentence with the secret-shaped domain rule", () => {
    expect(explain({ code: "INVALID_BODY", fields: ["email"] })).toBe(
      "Enter a valid email address whose domain does not look like a password, key or token.",
    );
  });

  it("states the name bound and the secret-shaped rule, and never the taken-name case CONFLICT answers instead", () => {
    expect(explain({ code: "INVALID_BODY", fields: ["name"] })).toBe(
      "A name of 1 to 80 characters is required, with nothing in it that looks like a password, key or token.",
    );
  });

  it("states the description bound and the secret-shaped rule", () => {
    expect(explain({ code: "INVALID_BODY", fields: ["description"] })).toBe(
      "A description of at most 240 characters is allowed, with nothing in it that looks like a password, key or token.",
    );
  });
});

describe("the confirm dialog", () => {
  it("waits for a reason, disables while pending, and closes on Escape", async () => {
    const onConfirm = vi.fn();
    const onClose = vi.fn();
    const { rerender } = render(
      <ConfirmDialog
        open
        title="Deactivate this agent?"
        confirm="Deactivate"
        danger
        reason="Reason (required)"
        pending={false}
        error={null}
        onConfirm={onConfirm}
        onClose={onClose}
      >
        <p>Every credential ends now.</p>
      </ConfirmDialog>,
    );
    const dialog = await screen.findByRole("dialog", { name: "Deactivate this agent?" });
    const confirm = screen.getByRole("button", { name: "Deactivate" });
    expect(confirm).toBeDisabled();
    expect(confirm).toHaveClass("btn-danger");
    await userEvent.type(screen.getByLabelText("Reason (required)"), "  left the team ");
    expect(confirm).toBeEnabled();
    await userEvent.click(confirm);
    expect(onConfirm).toHaveBeenCalledWith("left the team");
    rerender(
      <ConfirmDialog
        open
        title="Deactivate this agent?"
        confirm="Deactivate"
        danger
        reason="Reason (required)"
        pending
        error={{ code: "CONFLICT" }}
        onConfirm={onConfirm}
        onClose={onClose}
      />,
    );
    expect(screen.getByRole("button", { name: "Deactivate" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();
    expect(screen.getByRole("alert")).toHaveTextContent("Something changed first");
    expect(dialog).toBeInTheDocument();
    rerender(
      <ConfirmDialog
        open
        title="Deactivate this agent?"
        confirm="Deactivate"
        reason="Reason (required)"
        pending={false}
        error={null}
        onConfirm={onConfirm}
        onClose={onClose}
      />,
    );
    await userEvent.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalled();
  });
});

describe("the show-once dialog", () => {
  it("shows the secret once in a read-only field and closes on its own button only", async () => {
    const onClose = vi.fn();
    render(
      <SecretDialog
        secret={{ ...ISSUED, next_steps: { install: "pipx install execbound-client", mcp: "claude mcp add execbound" } }}
        onClose={onClose}
      />,
    );
    const dialog = await screen.findByRole("dialog", { name: "Copy the API key now" });
    const field = screen.getByLabelText("API key (copy it now)");
    expect(field).toHaveValue(TOKEN);
    expect(field).toHaveAttribute("readonly");
    expect(dialog).toHaveTextContent("agent 22222222");
    expect(dialog).toHaveTextContent("Authorization: Bearer <API key>");
    expect(dialog).toHaveTextContent("EXECBOUND_CREDENTIAL");
    expect(dialog).toHaveTextContent("expires 2026-09-19 22:00 UTC");
    const recipes = dialog.querySelectorAll("pre");
    expect(recipes).toHaveLength(2);
    for (const recipe of recipes) expect(recipe.textContent).not.toContain(TOKEN);
    await userEvent.keyboard("{Escape}");
    expect(onClose).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "I have copied it" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("says a key issued to never expire never expires, and holds until it is revoked", async () => {
    render(<SecretDialog secret={{ ...ISSUED, expires_at: "9999-12-31T00:00:00Z" }} onClose={vi.fn()} />);
    const dialog = await screen.findByRole("dialog", { name: "Copy the API key now" });
    expect(dialog).toHaveTextContent("API key 11111111 never expires.");
    expect(dialog).toHaveTextContent("until it is revoked");
  });

  it("calls a person's secret a credential and gives no agent header", async () => {
    render(<SecretDialog secret={{ ...ISSUED, kind: "HUMAN_APPROVER" }} onClose={vi.fn()} />);
    const dialog = await screen.findByRole("dialog", { name: "Copy the credential now" });
    expect(screen.getByLabelText("Credential (copy it now)")).toHaveValue(TOKEN);
    expect(dialog).not.toHaveTextContent("Authorization: Bearer");
  });

  it("names a personal access token by its name, with its bearer line and no credential", async () => {
    const onClose = vi.fn();
    render(
      <SecretDialog
        secret={{ kind: "TOKEN", token: "ebp1.secret", name: "CI <b>runner</b>", expires_at: "9999-12-31T00:00:00Z" }}
        onClose={onClose}
      />,
    );
    const dialog = await screen.findByRole("dialog", { name: "Copy the token now" });
    expect(screen.getByLabelText("Token (copy it now)")).toHaveValue("ebp1.secret");
    expect(dialog).toHaveTextContent("The token CI <b>runner</b> is shown once.");
    expect(dialog.querySelector("b")).toBeNull();
    expect(dialog).toHaveTextContent("Authorization: Bearer <token>");
    expect(dialog).toHaveTextContent("It never expires.");
    expect(dialog).toHaveTextContent("until it is revoked");
    expect(dialog).not.toHaveTextContent(/credential/i);
    expect(dialog).not.toHaveTextContent("EXECBOUND_CREDENTIAL");
    await userEvent.click(screen.getByRole("button", { name: "I have copied it" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

function answer(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

function Issuer() {
  const shown = useShowOnce({
    mutationFn: async () => {
      const { data } = await issueAgentCredential({
        path: { principal_id: ISSUED.principal_id },
        body: { lifetime: "8" },
        throwOnError: true,
      });
      return data;
    },
  });
  return (
    <>
      <button
        type="button"
        onClick={() => {
          void shown.issue(undefined);
        }}
      >
        Issue
      </button>
      <output>{shown.error === null ? (shown.pending ? "waiting" : "idle") : explain(shown.error)}</output>
      <SecretDialog secret={shown.secret} onClose={shown.close} />
    </>
  );
}

describe("a credential issued through the show-once hook", () => {
  it("is in no query, no mutation record and nowhere in the document once the dialog closes", async () => {
    stub(() => Promise.resolve(answer(ISSUED)));
    const queryClient = new QueryClient();
    render(
      <QueryClientProvider client={queryClient}>
        <Issuer />
      </QueryClientProvider>,
    );
    await userEvent.click(screen.getByRole("button", { name: "Issue" }));
    const field = await screen.findByLabelText("API key (copy it now)");
    expect(field).toHaveValue(TOKEN);
    await userEvent.click(screen.getByRole("button", { name: "I have copied it" }));
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    expect(document.body.innerHTML).not.toContain(TOKEN);
    expect(JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.state))).not.toContain(TOKEN);
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 5));
    });
    const records = queryClient.getMutationCache().getAll();
    expect(JSON.stringify(records.map((mutation) => mutation.state))).not.toContain(TOKEN);
    expect(records).toHaveLength(0);
    expect(window.location.href).not.toContain(TOKEN);
    expect(JSON.stringify(localStorage) + JSON.stringify(sessionStorage)).not.toContain("eb1.");
  });

  it("explains a refusal and shows no dialog", async () => {
    stub(() => Promise.resolve(answer({ code: "INVALID_PRINCIPAL", detail: "x" }, 400)));
    render(
      <QueryClientProvider client={new QueryClient()}>
        <Issuer />
      </QueryClientProvider>,
    );
    await userEvent.click(screen.getByRole("button", { name: "Issue" }));
    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent("That principal cannot be changed from here.");
    });
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});
