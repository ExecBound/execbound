// SPDX-License-Identifier: AGPL-3.0-only
import { useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useState } from "react";

import { createApproverMutation, setPersonEmailMutation } from "../../api/@tanstack/react-query.gen";
import type { AccessPage, AccessUser, PeoplePage, PersonRow } from "../../api/types.gen";
import { useServerMutation } from "../../lib/mutation";
import { toast } from "../../lib/toast";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { EmptyState } from "../ui/EmptyState";
import { Table, Td, Th } from "../ui/Table";
import { ConfirmDialog } from "./ConfirmDialog";
import { principalName, when } from "./format";
import { Field, Problem } from "./forms";
import { PersonName } from "./PersonName";
import { PersonStateBadge } from "./PersonState";
import { UserRoleEditor } from "./AccessManagement";
import { UserAccessLinks, UserRoleSummary, useUserAccess } from "./UserAccess";

import { PEOPLE_FILTERS, parsePeopleSearch, type PeopleSearch } from "./people-search";
import { useCommand } from "../../lib/commands";
export { DEFAULT_PEOPLE_SEARCH, parsePeopleSearch, type PeopleSearch } from "./people-search";

const LABELS: Record<keyof typeof PEOPLE_FILTERS, [string, Record<string, string>]> = {
  state: ["State", { active: "Active", deactivated: "Deactivated", all: "All" }],
  kind: ["Sign-in management", { any: "All accounts", HUMAN_APPROVER: "Console managed", ADMIN: "Installation owner managed" }],
};

export function PeopleList({
  data,
  search,
  onSearch,
}: {
  data: PeoplePage;
  search: PeopleSearch;
  onSearch: (next: Partial<PeopleSearch>) => void;
}) {
  const access = useUserAccess();
  const [editing, setEditing] = useState<AccessUser | null>(null);
  const users = new Map(access.data?.users.map((user) => [user.principal_id, user]));
  return (
    <div className="stack">
      <p className="note">Add users, set up sign-in, and assign access roles. Reviewers also need approval rules for the relevant actions and resources.</p>
      <UserAccessLinks />
      <form
        className="filters"
        aria-label="Filters"
        onSubmit={(event) => {
          event.preventDefault();
        }}
      >
        {(Object.keys(LABELS) as (keyof typeof PEOPLE_FILTERS)[]).map((key) => {
          const [label, names] = LABELS[key];
          return (
            <Field key={key} label={label}>
              <select
                name={key}
                value={search[key]}
                onChange={(event) => {
                  onSearch({ [key]: parsePeopleSearch({ ...search, [key]: event.target.value })[key] });
                }}
              >
                {PEOPLE_FILTERS[key].map((option) => (
                  <option key={option} value={option}>
                    {names[option] ?? option}
                  </option>
                ))}
              </select>
            </Field>
          );
        })}
      </form>
      <Card>
        <Table caption="Users matching the filters, with access as of this page load." density="compact">
          <thead>
            <tr>
              <Th>User</Th>
              <Th>Roles and scope</Th>
              <Th>State</Th>
              <Th>Second factor</Th>
              <Th>Active sessions</Th>
              <Th>Last sign-in</Th>
              <Th>Review assignments</Th>
              <Th>Manage</Th>
            </tr>
          </thead>
          <tbody>
            {data.people.map((row) => (
              <Row key={row.principal_id} row={row} access={access.data} user={users.get(row.principal_id)} loading={access.isPending} onEdit={setEditing} />
            ))}
          </tbody>
        </Table>
        {data.people.length === 0 ? <EmptyState title="No one matches these filters." /> : null}
      </Card>
      <Problem error={access.error} />
      {editing !== null && access.data !== undefined ? <UserRoleEditor key={editing.principal_id} data={access.data} user={editing} onClose={() => { setEditing(null); }} /> : null}
    </div>
  );
}

function Row({ row, access, user, loading, onEdit }: {
  row: PersonRow; access: AccessPage | undefined; user: AccessUser | undefined;
  loading: boolean; onEdit: (user: AccessUser) => void;
}) {
  return (
    <tr>
      <Td>
        <PersonName id={row.principal_id} label={row.label} email={row.email} number={row.number} kind={row.kind} link />
      </Td>
      <Td>{access !== undefined && user !== undefined ? <UserRoleSummary data={access} user={user} /> : loading ? "Loading…" : "Unavailable"}</Td>
      <Td><PersonStateBadge person={row} /></Td>
      <Td>{row.second_factor === true ? "Enrolled" : "None"}</Td>
      <Td>{row.sessions}</Td>
      <Td mono>{when(row.last_sign_in)}</Td>
      <Td>{String(row.scopes)}</Td>
      <Td>{user !== undefined ? <Button size="small" disabled={!user.active} onClick={() => { onEdit(user); }}>Edit roles for {principalName("User", user.label, user.number, user.principal_id, user.email)}</Button> : null}</Td>
    </tr>
  );
}

/** Existing protected operations create an account and save its sign-in address. */
export function NewApprover() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [label, setLabel] = useState("");
  const [email, setEmail] = useState("");
  const [createdId, setCreatedId] = useState<string | null>(null);
  const [invalid, setInvalid] = useState(false);
  const address = useServerMutation({
    ...setPersonEmailMutation(),
    onSuccess: (detail) => {
      setOpen(false);
      setLabel("");
      setEmail("");
      setCreatedId(null);
      toast("User created. Complete sign-in setup, then assign roles and approval rules.");
      void queryClient.invalidateQueries({ queryKey: [{ _id: "listPeople" }] });
      void queryClient.invalidateQueries({ queryKey: [{ _id: "readAccess" }] });
      void navigate({ to: "/people/$personId", params: { personId: detail.person.principal_id } });
    },
  });
  const create = useServerMutation({
    ...createApproverMutation(),
    onSuccess: (made) => {
      setCreatedId(made.principal_id);
      void queryClient.invalidateQueries({ queryKey: [{ _id: "listPeople" }] });
      address.mutate({ path: { principal_id: made.principal_id }, body: { email: email.trim() } });
    },
  });
  const begin = () => {
    create.reset();
    address.reset();
    setInvalid(false);
    setOpen(true);
  };
  // The palette's Add user opens this dialog as the button would (#678).
  useCommand("add-user", begin);
  return (
    <>
      <Button
        variant="primary"
        onClick={begin}
      >
        Add user
      </Button>
      <ConfirmDialog
        open={open}
        title="Add a user"
        confirm={createdId === null ? "Create account" : "Save sign-in address"}
        pending={create.isPending || address.isPending}
        error={address.error ?? create.error}
        onConfirm={() => {
          if (label.trim() === "" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) { setInvalid(true); return; }
          setInvalid(false);
          if (createdId === null) create.mutate({ body: { label: label.trim() } });
          else address.mutate({ path: { principal_id: createdId }, body: { email: email.trim() } });
        }}
        onClose={() => {
          setOpen(false);
        }}
      >
        <p>
          Create a user with their name and sign-in email. Next, help them set a password
          or use your configured directory, then assign roles and approval rules. No email is sent automatically.
        </p>
        {createdId !== null ? <p role="status">The account exists. Save its sign-in address to continue; this will not create another account.</p> : null}
        {invalid ? <p role="alert">Enter a name and a valid sign-in email.</p> : null}
        <Field label="Name (required)">
          <input
            value={label}
            disabled={createdId !== null || create.isPending || address.isPending}
            maxLength={80}
            autoComplete="off"
            required
            onChange={(event) => {
              setLabel(event.target.value);
            }}
          />
        </Field>
        <Field label="Sign-in email (required)">
          <input type="email" value={email} required maxLength={254} autoComplete="off" disabled={create.isPending || address.isPending}
            onChange={(event) => { setEmail(event.target.value); }} />
        </Field>
      </ConfirmDialog>
    </>
  );
}
