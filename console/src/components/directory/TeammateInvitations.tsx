// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import {
  createTeammateInvitationMutation,
  listTeammateInvitationsOptions,
  resendTeammateInvitationMutation,
  revokeTeammateInvitationMutation,
} from "../../api/@tanstack/react-query.gen";
import type { TeammateInvitationRow } from "../../api/types.gen";
import { useServerMutation } from "../../lib/mutation";
import { toast } from "../../lib/toast";
import { Badge, type Tone } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { EmptyState } from "../ui/EmptyState";
import { Table, Td, Th } from "../ui/Table";
import { grantName } from "./AccessManagement";
import { ConfirmDialog } from "./ConfirmDialog";
import { explain } from "./errors";
import { when } from "./format";
import { Problem } from "./forms";
import { useUserAccess } from "./UserAccess";

/** Whether an invitation is still open: `PENDING`, expired or not. The list the server answers
 * is every invitation of the last thirty days (TI26). An accepted one is a person on the People
 * list now and a revoked one was ended on purpose, so both are left out here; an expired one
 * stays, so the administrator learns it lapsed and can send it again. */
function open(row: TeammateInvitationRow): boolean {
  return row.state === "PENDING";
}

function expired(row: TeammateInvitationRow): boolean {
  return new Date(row.expires_at).getTime() <= Date.now();
}

/** Where an open invitation stands. */
function status(row: TeammateInvitationRow): [Tone, string] {
  if (expired(row)) return ["stale", "Expired"];
  if (row.delivered_at !== null) return ["allow", "Sent"];
  if (row.last_error !== null) return ["deny", "Failed"];
  return ["hold", "Sending"];
}

/** The reviewer group an invitation names, in words; nothing when it names none. */
function groupWords(row: TeammateInvitationRow): string | null {
  if (row.reviewer_group_id == null) return null;
  return row.reviewer_group_name == null
    ? "Reviewer group: deleted since"
    : `Reviewer group: ${row.reviewer_group_name}`;
}

function invalidateInvitations(cache: ReturnType<typeof useQueryClient>) {
  void cache.invalidateQueries({ queryKey: [{ _id: "listTeammateInvitations" }] });
}

/** The People page's invitations section: address, role, delivery state and expiry, with Resend
 * and Revoke for an invitation that can still be accepted and Invite again for one that expired.
 * Nothing here ever shows a token: the service mints and holds the link's secret, and the
 * console only ever learns that a send happened. */
export function TeammateInvitations() {
  const query = useQuery({ ...listTeammateInvitationsOptions(), refetchInterval: 30_000 });
  const access = useUserAccess();
  const cache = useQueryClient();
  const [revoking, setRevoking] = useState<TeammateInvitationRow | null>(null);
  const resend = useServerMutation({
    ...resendTeammateInvitationMutation(),
    onSuccess: () => {
      toast("Invitation resent.");
      invalidateInvitations(cache);
    },
  });
  const revoke = useServerMutation({
    ...revokeTeammateInvitationMutation(),
    onSuccess: () => {
      toast("Invitation revoked.");
      setRevoking(null);
      invalidateInvitations(cache);
    },
  });
  // Creating the same invitation again revokes the expired one and makes a new one, in one
  // transaction on the server; the list shows the server's answer, never a guess.
  const again = useServerMutation({
    ...createTeammateInvitationMutation(),
    onSuccess: () => {
      toast("Invitation sent again. The new link works for seven days.");
      invalidateInvitations(cache);
    },
  });
  if (query.data === undefined) {
    return query.error !== null ? (
      <EmptyState title="Invitations could not be loaded.">{explain(query.error)}</EmptyState>
    ) : (
      <p role="status">Loading invitations.</p>
    );
  }
  const rows = query.data.invitations.filter(open);
  return (
    <Card title="Invitations">
      <p>They will get an email with a link. The link works for seven days.</p>
      <Table caption="Teammate invitations sent from this workspace." density="compact">
        <thead>
          <tr>
            <Th>Address</Th>
            <Th>Role</Th>
            <Th>State</Th>
            <Th>Expires</Th>
            <Th>Manage</Th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const [tone, word] = status(row);
            const group = groupWords(row);
            return (
              <tr key={row.invitation_id}>
                <Td>{row.email}</Td>
                <Td>
                  {row.grants
                    .map((grant) => (access.data !== undefined ? grantName(grant, access.data) : grant.role))
                    .join("; ")}
                  {group !== null ? <div className="faint">{group}</div> : null}
                </Td>
                <Td>
                  <Badge tone={tone}>{word}</Badge>
                </Td>
                <Td mono>{when(row.expires_at)}</Td>
                <Td>
                  {expired(row) ? (
                    <Button
                      size="small"
                      disabled={again.isPending}
                      onClick={() => {
                        again.mutate({
                          body: {
                            email: row.email,
                            grants: row.grants,
                            ...(row.reviewer_group_id != null ? { reviewer_group_id: row.reviewer_group_id } : {}),
                          },
                        });
                      }}
                    >
                      Invite again
                    </Button>
                  ) : (
                    <>
                      <Button
                        size="small"
                        disabled={resend.isPending}
                        onClick={() => {
                          resend.mutate({ path: { id: row.invitation_id }, body: {} });
                        }}
                      >
                        Resend
                      </Button>{" "}
                      <Button
                        size="small"
                        onClick={() => {
                          revoke.reset();
                          setRevoking(row);
                        }}
                      >
                        Revoke
                      </Button>
                    </>
                  )}
                </Td>
              </tr>
            );
          })}
        </tbody>
      </Table>
      {rows.length === 0 ? <EmptyState title="No open invitations." /> : null}
      <Problem error={resend.error} />
      <Problem error={again.error} />
      {revoking !== null ? (
        <ConfirmDialog
          open
          title={`Revoke the invitation to ${revoking.email}?`}
          confirm="Revoke"
          danger
          pending={revoke.isPending}
          error={revoke.error}
          onClose={() => {
            setRevoking(null);
          }}
          onConfirm={() => {
            revoke.mutate({ path: { id: revoking.invitation_id }, body: {} });
          }}
        >
          <p>Their invitation link will stop working. This cannot be undone.</p>
        </ConfirmDialog>
      ) : null}
    </Card>
  );
}
