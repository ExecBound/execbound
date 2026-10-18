// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";

import type { PeoplePage, SpaceDetail, SpacePage, SpaceRow } from "../../api/types.gen";
import { PLACEHOLDER, SessionContext, type SessionSummary } from "../../lib/session";
import { Toaster } from "../ui/Toast";
import { called, json, serve } from "../../test/api";
import { SpacePanel } from "./SpacePanel";
import { DEFAULT_SPACES_SEARCH, parseSpacesSearch, SpacesList } from "./SpacesList";

const LIST = "/api/console/v1/spaces";
const NORTH = "11111111-1111-4111-8111-111111111111";
const OLD = "33333333-3333-4333-8333-333333333333";
const APPROVER = "aaaaaaaa-1111-4111-8111-111111111111";
const ADMIN_PERSON = "bbbbbbbb-1111-4111-8111-111111111111";
const DETAIL = `${LIST}/${NORTH}`;

const NORTHWIND: SpaceRow = {
  space_id: NORTH,
  name: "Northwind",
  detail: "The first customer",
  created_at: "2026-09-01T00:00:00Z",
  archived_at: null,
  members: 1,
  agents: 3,
  pending: 2,
  findings: 0,
};
const RETIRED: SpaceRow = {
  ...NORTHWIND,
  space_id: OLD,
  name: "Retired <b>customer</b>",
  detail: null,
  archived_at: "2026-09-10T00:00:00Z",
};

function detail(changes: Partial<SpaceDetail> = {}): SpaceDetail {
  return {
    space: NORTHWIND,
    members: [
      {
        principal_id: APPROVER,
        label: "Dana Reyes",
        email: "dana@example.com",
        number: 2,
        kind: "HUMAN_APPROVER",
        role: "HUMAN_APPROVER",
        assigned_at: "2026-09-02T00:00:00Z",
      },
    ],
    selection: null,
    offered: [],
    administrator: true,
    ...changes,
  };
}

const PEOPLE: PeoplePage = {
  people: [
    {
      principal_id: APPROVER,
      kind: "HUMAN_APPROVER",
      label: "Dana Reyes",
      email: "dana@example.com",
      number: 2,
      active: true,
      created_at: null,
      deactivated_at: null,
      last_sign_in: null,
    },
    {
      principal_id: ADMIN_PERSON,
      kind: "ADMIN",
      label: null,
      email: null,
      number: 1,
      active: true,
      created_at: null,
      deactivated_at: null,
      last_sign_in: null,
    },
  ] as PeoplePage["people"],
};

const ADMIN: SessionSummary = {
  ...PLACEHOLDER,
  role: "ADMIN",
  tenant: { name: "Acme SOC", detail: "" },
  space: { id: NORTH, name: "Northwind", archived: false },
  spaces: 2,
  allSpaces: true,
};

function mount(node: ReactNode, answers: Record<string, unknown>, session: SessionSummary = ADMIN) {
  const calls = serve(answers);
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <SessionContext.Provider value={session}>
      <QueryClientProvider client={queryClient}>
        {node}
        <Toaster />
      </QueryClientProvider>
    </SessionContext.Provider>,
  );
  return { calls, queryClient };
}

function listing(items: SpaceRow[]): SpacePage {
  return { items, next_cursor: null, administrator: true, all_spaces: true, current_space_id: NORTH };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the spaces list", () => {
  it("reads its state from the URL and never names a space in a parameter", () => {
    expect(parseSpacesSearch({})).toEqual(DEFAULT_SPACES_SEARCH);
    expect(parseSpacesSearch({ state: "elsewhere", q: 7 })).toEqual(DEFAULT_SPACES_SEARCH);
    expect(parseSpacesSearch({ open: NORTH, state: "archived", q: "north" })).toEqual({
      open: NORTH,
      state: "archived",
      q: "north",
    });
    // Nothing but the session names the space a person is looking at.
    expect(Object.keys(parseSpacesSearch({ space: NORTH }))).not.toContain("space");
  });

  it("shows each space with its state and counts, and renders a name as text", async () => {
    mount(<SpacesList search={{ ...DEFAULT_SPACES_SEARCH, state: "all" }} onSearch={() => undefined} />, {
      [LIST]: (request: Request) => {
        const state = new URL(request.url).searchParams.get("state");
        return json(listing(state === "active" ? [NORTHWIND] : [NORTHWIND, RETIRED]));
      },
    });
    const row = (await screen.findByText("Northwind")).closest("tr");
    expect(row).not.toBeNull();
    expect(within(row as HTMLElement).getByText("Active")).toBeInTheDocument();
    expect(within(row as HTMLElement).getByText("3")).toBeInTheDocument();
    const retired = screen.getByText("Retired <b>customer</b>").closest("tr");
    expect(within(retired as HTMLElement).getByText("Archived")).toBeInTheDocument();
    expect(document.querySelector("b")).toBeNull();
  });

  it("asks the server for the state the chips choose", async () => {
    const changes: unknown[] = [];
    mount(
      <SpacesList
        search={DEFAULT_SPACES_SEARCH}
        onSearch={(next) => {
          changes.push(next);
        }}
      />,
      { [LIST]: listing([NORTHWIND]) },
    );
    await screen.findByText("Northwind");
    await userEvent.click(screen.getByRole("button", { name: "Archived" }));
    expect(changes).toEqual([{ state: "archived" }]);
  });
});

describe("one space", () => {
  it("shows its counts, its members and the sentence that a space is not isolation", async () => {
    mount(<SpacePanel spaceId={NORTH} onGone={() => undefined} />, { [DETAIL]: detail() });
    expect(await screen.findByText("Dana Reyes")).toBeInTheDocument();
    // A space is ownership and view inside a tenant, and the page says so rather than
    // letting a reader take it for a boundary.
    expect(screen.getByText(/A space divides ownership and view inside one tenant/)).toBeInTheDocument();
    expect(screen.getByText("This space selects no policy bundle.")).toBeInTheDocument();
    expect(screen.getByText("This space offers nothing tenant-wide.")).toBeInTheDocument();
  });

  it("archives with a reason and never offers to delete", async () => {
    const { calls } = mount(<SpacePanel spaceId={NORTH} onGone={() => undefined} />, {
      [DETAIL]: detail(),
      [`${DETAIL}/archive`]: detail({ space: { ...NORTHWIND, archived_at: "2026-09-20T00:00:00Z" } }),
    });
    await userEvent.click(await screen.findByRole("button", { name: "Archive Northwind" }));
    const dialog = await screen.findByRole("dialog", { name: "Archive Northwind?" });
    expect(dialog).toHaveTextContent("Nothing is deleted");
    expect(screen.queryByRole("button", { name: /Delete/ })).toBeNull();
    await userEvent.type(within(dialog).getByRole("textbox"), "Customer left");
    await userEvent.click(within(dialog).getByRole("button", { name: "Archive" }));
    await waitFor(() => {
      expect(called(calls, "POST", `${DETAIL}/archive`)).toBe(true);
    });
    expect(calls.find((call) => call.path === `${DETAIL}/archive`)?.body).toEqual({
      reason: "Customer left",
    });
  });

  it("says in its own words that the tenant's last space stays", async () => {
    mount(<SpacePanel spaceId={NORTH} onGone={() => undefined} />, {
      [DETAIL]: detail(),
      [`${DETAIL}/archive`]: () => json({ code: "CONFLICT", detail: "no" }, 409),
    });
    await userEvent.click(await screen.findByRole("button", { name: "Archive Northwind" }));
    const dialog = await screen.findByRole("dialog", { name: "Archive Northwind?" });
    await userEvent.type(within(dialog).getByRole("textbox"), "Customer left");
    await userEvent.click(within(dialog).getByRole("button", { name: "Archive" }));
    expect(await screen.findByText(/last space that is not archived/)).toBeInTheDocument();
  });
});

describe("the members table", () => {
  it("says what a first membership does and refuses to offer an approver the administrator role", async () => {
    mount(<SpacePanel spaceId={NORTH} onGone={() => undefined} />, {
      [DETAIL]: detail({ members: [] }),
      "/api/console/v1/people": PEOPLE,
    });
    await userEvent.click(await screen.findByRole("button", { name: "Assign a person" }));
    const dialog = await screen.findByRole("dialog", { name: "Assign a person to Northwind" });
    expect(dialog).toHaveTextContent("Giving a tenant administrator their first space narrows them to it.");
    const role = within(dialog).getByLabelText(/Role in this space/);
    // A space role narrows and never raises: the approver principal is offered one role.
    expect(within(role as HTMLSelectElement).queryByRole("option", { name: "Space administrator" })).toBeNull();
    await userEvent.selectOptions(within(dialog).getByLabelText("Person"), ADMIN_PERSON);
    await waitFor(() => {
      expect(within(role as HTMLSelectElement).getByRole("option", { name: "Space administrator" })).toBeInTheDocument();
    });
  });

  it("shows the last tenant administrator refusal as its own sentence", async () => {
    mount(<SpacePanel spaceId={NORTH} onGone={() => undefined} />, {
      [DETAIL]: detail({ members: [] }),
      "/api/console/v1/people": PEOPLE,
      [`${DETAIL}/members/assign`]: () => json({ code: "CONFLICT", detail: "no" }, 409),
    });
    await userEvent.click(await screen.findByRole("button", { name: "Assign a person" }));
    const dialog = await screen.findByRole("dialog", { name: "Assign a person to Northwind" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Assign" }));
    expect(await screen.findByText(/no tenant administrator/)).toBeInTheDocument();
  });

  it("names a member without a label by their email, else by their number, where the id prefix was", async () => {
    const [dana] = detail().members;
    if (dana === undefined) throw new Error("fixture");
    mount(<SpacePanel spaceId={NORTH} onGone={() => undefined} />, {
      [DETAIL]: detail({
        members: [
          { ...dana, label: null },
          { ...dana, principal_id: ADMIN_PERSON, label: null, email: null, number: 1, kind: "ADMIN", role: "ADMIN" },
        ],
      }),
      "/api/console/v1/people": PEOPLE,
    });
    const table = await screen.findByRole("table", { name: /people who belong to this space/ });
    const [emailed, bare] = within(table).getAllByRole("row").slice(1);
    if (emailed === undefined || bare === undefined) throw new Error("The rows are missing");
    expect(within(emailed).getAllByRole("cell")[0]).toHaveTextContent(/^dana@example\.com User 2$/);
    expect(within(bare).getAllByRole("cell")[0]).toHaveTextContent(/^User 1$/);
    expect(table).not.toHaveTextContent(/unlabelled/i);
    expect(table).not.toHaveTextContent(APPROVER.slice(0, 8));
    expect(within(table).getByRole("button", { name: "Remove dana@example.com from Northwind" })).toBeInTheDocument();
    expect(within(table).getByRole("button", { name: "Remove User 1 from Northwind" })).toBeInTheDocument();
  });

  it("offers a person without a label by their number when assigning", async () => {
    mount(<SpacePanel spaceId={NORTH} onGone={() => undefined} />, {
      [DETAIL]: detail({ members: [] }),
      "/api/console/v1/people": PEOPLE,
    });
    await userEvent.click(await screen.findByRole("button", { name: "Assign a person" }));
    const dialog = await screen.findByRole("dialog", { name: "Assign a person to Northwind" });
    const options = within(within(dialog).getByLabelText("Person"))
      .getAllByRole("option")
      .map((option) => option.textContent);
    expect(options).toEqual(["Dana Reyes · Approver", "User 1 · Space administrator"]);
  });

  it("confirms a removal and says what a person is left with", async () => {
    const { calls } = mount(<SpacePanel spaceId={NORTH} onGone={() => undefined} />, {
      [DETAIL]: detail(),
      [`${DETAIL}/members/unassign`]: detail({ members: [] }),
    });
    await userEvent.click(await screen.findByRole("button", { name: /^Remove Dana Reyes from Northwind$/ }));
    const dialog = await screen.findByRole("dialog", { name: "Remove Dana Reyes from Northwind?" });
    expect(dialog).toHaveTextContent("They keep every other space they belong to.");
    await userEvent.click(within(dialog).getByRole("button", { name: "Remove" }));
    await waitFor(() => {
      expect(called(calls, "POST", `${DETAIL}/members/unassign`)).toBe(true);
    });
    expect(calls.find((call) => call.path === `${DETAIL}/members/unassign`)?.body).toEqual({
      principal_id: APPROVER,
    });
  });
});
