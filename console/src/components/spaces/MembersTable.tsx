// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import {
  assignSpaceMemberMutation,
  listPeopleOptions,
  unassignSpaceMemberMutation,
} from "../../api/@tanstack/react-query.gen";
import type { MemberRow, SpaceDetail } from "../../api/types.gen";
import { useServerMutation } from "../../lib/mutation";
import { toast } from "../../lib/toast";
import { ConfirmDialog } from "../directory/ConfirmDialog";
import { noun, principalName } from "../directory/format";
import { PersonName } from "../directory/PersonName";
import { Field } from "../directory/forms";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { DialogClose, DialogSurface, DialogTitle } from "../ui/dialog";
import { EmptyState } from "../ui/EmptyState";
import { Icon } from "../../shell/icons";
import { Table, Td, Th } from "../ui/Table";
import { LAST_TENANT_ADMIN, NARROWING, refusal, ROLES } from "./words";

type Role = "ADMIN" | "HUMAN_APPROVER";

/** A member as this table names them: label, else email, else "User 3". */
function memberName(row: MemberRow): string {
  return principalName(noun(row.kind), row.label, row.number, row.principal_id, row.email);
}

/**
 * Who belongs to one space, and the two changes that make and unmake a membership.
 *
 * Membership is the authority: a person with no membership of a space reads nothing of it,
 * and a space role **narrows and never raises**, so the administrator role is
 * offered only for a principal who is an administrator of the tenant already. The server
 * refuses the rest, and every sentence here is this page's own.
 */
export function MembersTable({ data, spaceId }: { data: SpaceDetail; spaceId: string }) {
  const queryClient = useQueryClient();
  const [assigning, setAssigning] = useState(false);
  const [removing, setRemoving] = useState<MemberRow | null>(null);
  const archived = data.space.archived_at !== null;
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: [{ _id: "readSpace" }] });
    void queryClient.invalidateQueries({ queryKey: [{ _id: "listSpaces" }] });
  };
  const unassign = useServerMutation({
    ...unassignSpaceMemberMutation(),
    onSuccess: () => {
      toast("Member removed from the space.");
      refresh();
      setRemoving(null);
    },
  });
  return (
    <Card
      title="Members"
      aside={
        data.administrator ? (
          <Button
            size="small"
            disabled={archived}
            title={archived ? "An archived space takes no new member." : undefined}
            onClick={() => {
              setAssigning(true);
            }}
          >
            Assign a person
          </Button>
        ) : undefined
      }
    >
      <Table caption="The people who belong to this space, with their kind and their role." density="compact">
        <thead>
          <tr>
            <Th>Person</Th>
            <Th>Kind</Th>
            <Th>Role in this space</Th>
            {data.administrator ? <Th>Remove</Th> : null}
          </tr>
        </thead>
        <tbody>
          {data.members.map((row) => (
            <tr key={row.principal_id}>
              <Td>
                <PersonName id={row.principal_id} label={row.label} email={row.email} number={row.number} kind={row.kind} />
              </Td>
              <Td>{ROLES[row.kind] ?? row.kind}</Td>
              <Td>{ROLES[row.role] ?? row.role}</Td>
              {data.administrator ? (
                <Td>
                  <Button
                    size="small"
                    aria-label={`Remove ${memberName(row)} from ${data.space.name}`}
                    onClick={() => {
                      unassign.reset();
                      setRemoving(row);
                    }}
                  >
                    Remove
                  </Button>
                </Td>
              ) : null}
            </tr>
          ))}
        </tbody>
      </Table>
      {data.members.length === 0 ? (
        <EmptyState title="Nobody belongs to this space yet.">
          A tenant administrator — an administrator with no space of their own — acts in every space.
          Assigning somebody here limits them to the spaces they are assigned.
        </EmptyState>
      ) : null}
      <AssignDialog
        open={assigning}
        spaceId={spaceId}
        spaceName={data.space.name}
        seated={data.members.map((row) => row.principal_id)}
        onClose={() => {
          setAssigning(false);
        }}
        onDone={refresh}
      />
      <ConfirmDialog
        open={removing !== null}
        title={
          removing === null
            ? "Remove this member?"
            : `Remove ${memberName(removing)} from ${data.space.name}?`
        }
        confirm="Remove"
        danger
        pending={unassign.isPending}
        error={unassign.error}
        onConfirm={() => {
          if (removing === null) return;
          unassign.mutate({
            path: { space_id: spaceId },
            body: { principal_id: removing.principal_id },
          });
        }}
        onClose={() => {
          setRemoving(null);
        }}
      >
        <p>
          They keep every other space they belong to. A person left with no membership at all is a
          tenant administrator again and acts in every space.
        </p>
      </ConfirmDialog>
    </Card>
  );
}

/** Pick a person and a role. The dialog says in words what a first membership does. */
function AssignDialog({
  open,
  spaceId,
  spaceName,
  seated,
  onClose,
  onDone,
}: {
  open: boolean;
  spaceId: string;
  spaceName: string;
  seated: string[];
  onClose: () => void;
  onDone: () => void;
}) {
  const people = useQuery({ ...listPeopleOptions({ query: { state: "active" } }), enabled: open });
  const candidates = (people.data?.people ?? []).filter(
    (person) => !seated.includes(person.principal_id),
  );
  const [principal, setPrincipal] = useState("");
  const [role, setRole] = useState<Role>("HUMAN_APPROVER");
  const chosen = candidates.find((person) => person.principal_id === principal) ?? candidates[0];
  const assign = useServerMutation({
    ...assignSpaceMemberMutation(),
    onSuccess: () => {
      toast("Person assigned to the space.");
      onDone();
      onClose();
    },
  });
  // A space role narrows and never raises: only a principal who is an administrator of the
  // tenant may hold the administrator role in a space, and the server refuses the rest.
  const mayAdminister = chosen?.kind === "ADMIN";
  const wanted: Role = mayAdminister ? role : "HUMAN_APPROVER";
  const problem = refusal(assign.error, { CONFLICT: LAST_TENANT_ADMIN });
  return (
    <DialogSurface
      open={open}
      className="dialog"
      onOpenChange={(next) => {
        if (!next && !assign.isPending) onClose();
      }}
    >
      <header className="drawer-head">
        <DialogTitle className="drawer-title">Assign a person to {spaceName}</DialogTitle>
        <DialogClose className="btn btn-icon btn-ghost" aria-label="Close" disabled={assign.isPending}>
          <Icon name="close" />
        </DialogClose>
      </header>
      <div className="dialog-body">
        <p>{NARROWING}</p>
        <Field label="Person">
          <select
            value={chosen?.principal_id ?? ""}
            onChange={(event) => {
              setPrincipal(event.target.value);
            }}
          >
            {candidates.map((person) => (
              <option key={person.principal_id} value={person.principal_id}>
                {principalName("User", person.label, person.number, person.principal_id, person.email)} · {ROLES[person.kind] ?? person.kind}
              </option>
            ))}
          </select>
        </Field>
        <Field
          label="Role in this space"
          hint={
            mayAdminister
              ? "A space administrator administers this space and nothing outside it."
              : "An approver principal may only hold the approver role: a space role narrows and never raises."
          }
        >
          <select
            value={wanted}
            disabled={!mayAdminister}
            onChange={(event) => {
              setRole(event.target.value === "ADMIN" ? "ADMIN" : "HUMAN_APPROVER");
            }}
          >
            <option value="HUMAN_APPROVER">{ROLES.HUMAN_APPROVER}</option>
            {mayAdminister ? <option value="ADMIN">{ROLES.ADMIN}</option> : null}
          </select>
        </Field>
        {candidates.length === 0 ? <p>Everybody active already belongs to this space.</p> : null}
        {problem !== "" ? (
          <p className="problem" role="alert">
            {problem}
          </p>
        ) : null}
      </div>
      <footer className="dialog-foot">
        <DialogClose className="btn" disabled={assign.isPending}>
          Cancel
        </DialogClose>
        <Button
          variant="primary"
          disabled={assign.isPending || chosen === undefined}
          aria-busy={assign.isPending}
          onClick={() => {
            if (chosen === undefined) return;
            assign.mutate({
              path: { space_id: spaceId },
              body: { principal_id: chosen.principal_id, role: wanted },
            });
          }}
        >
          Assign
        </Button>
      </footer>
    </DialogSurface>
  );
}
