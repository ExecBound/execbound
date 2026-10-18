// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useRef, useState } from "react";

import {
  listOwnTokensQueryKey,
  listWorkspaceTokensOptions,
  listWorkspaceTokensQueryKey,
  revokeWorkspaceTokenMutation,
} from "../../api/@tanstack/react-query.gen";
import type { TokenRow, TokensPage } from "../../api/types.gen";
import { useServerMutation } from "../../lib/mutation";
import { useRetry } from "../../lib/retry";
import { toast } from "../../lib/toast";
import { ConfirmDialog } from "../directory/ConfirmDialog";
import { explain } from "../directory/errors";
import { expiry, when } from "../directory/format";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { EmptyState } from "../ui/EmptyState";
import { Table, Td, Th } from "../ui/Table";
import { TryAgain } from "../ui/TryAgain";

/**
 * Every administrator's personal access tokens in this workspace (design 2026-09-25), so an
 * administrator with the standing-only authority a token cannot carry can see and revoke
 * anyone's. Issuing one stays on the owner's own My account page.
 */
export function WorkspaceTokens() {
  const queryClient = useQueryClient();
  const tokens = useQuery(listWorkspaceTokensOptions());
  const retry = useRetry(tokens);
  const [revoking, setRevoking] = useState<TokenRow | null>(null);
  const table = useId();
  // Set when a revoke succeeds: the row's Revoke button, which opened the dialog, is gone.
  const revoked = useRef(false);
  // The owner's own card may show the same token, so a change here reads that list again. A
  // success answers with this card's fresh list, which is written in place; a refusal reads
  // both again: its copy promises the page shows what is there now.
  const refresh = (fresh?: TokensPage) => {
    if (fresh !== undefined) queryClient.setQueryData(listWorkspaceTokensQueryKey(), fresh);
    else void queryClient.invalidateQueries({ queryKey: listWorkspaceTokensQueryKey() });
    void queryClient.invalidateQueries({ queryKey: listOwnTokensQueryKey() });
  };
  const revoke = useServerMutation({
    ...revokeWorkspaceTokenMutation(),
    onSuccess: (fresh) => {
      revoked.current = true;
      refresh(fresh);
      toast("Token revoked.");
      setRevoking(null);
    },
    onError: () => {
      refresh();
    },
  });
  const rows = tokens.data?.tokens ?? [];
  return (
    <Card title="Personal access tokens in this workspace">
      <p>Every administrator&apos;s tokens. Revoke one to stop it at its next request.</p>
      {/* Only a first read that failed stands in for the list; a later one is said above the
          list it read. */}
      {retry.failure !== null ? (
        <p className="problem" role="alert">
          Personal access tokens could not be loaded. {explain(retry.failure)}{" "}
          <TryAgain retry={retry} />
        </p>
      ) : null}
      {tokens.data === undefined ? (
        retry.failure !== null ? null : (
          <p className="muted" role="status">
            Loading tokens…
          </p>
        )
      ) : rows.length === 0 ? (
        <EmptyState title="No personal access tokens in this workspace." />
      ) : (
        <Table caption="Personal access tokens in this workspace, newest first." density="compact" id={table}>
          <thead>
            <tr>
              <Th>Name</Th>
              <Th>Owner</Th>
              <Th>Created</Th>
              <Th>Expires</Th>
              <Th>Last used</Th>
              <Th>State</Th>
              <Th>Action</Th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.token_id}>
                <Td>{row.name}</Td>
                <Td>{row.owner_label ?? "Administrator"}</Td>
                <Td mono>{when(row.created_at)}</Td>
                <Td mono>{expiry(row.expires_at)}</Td>
                <Td mono>{row.last_used_at ? when(row.last_used_at) : "Never used"}</Td>
                <Td>
                  <Badge tone={row.state === "live" ? "allow" : "stale"}>{row.state}</Badge>
                </Td>
                <Td>
                  {row.state === "live" ? (
                    <Button
                      size="small"
                      aria-label={`Revoke ${row.name}, ${row.owner_label ?? "Administrator"}`}
                      onClick={() => {
                        revoke.reset();
                        revoked.current = false;
                        setRevoking(row);
                      }}
                    >
                      Revoke
                    </Button>
                  ) : null}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      <ConfirmDialog
        open={revoking !== null}
        title={`Revoke ${revoking?.name ?? "this token"}?`}
        confirm="Revoke"
        danger
        pending={revoke.isPending}
        error={revoke.error}
        finalFocus={() =>
          revoked.current ? (document.getElementById(table)?.closest<HTMLElement>("[role=region]") ?? true) : true
        }
        onConfirm={() => {
          if (revoking) revoke.mutate({ path: { token_id: revoking.token_id }, body: {} });
        }}
        onClose={() => {
          setRevoking(null);
        }}
      >
        <p>Anything using it stops working at its next request.</p>
      </ConfirmDialog>
    </Card>
  );
}
