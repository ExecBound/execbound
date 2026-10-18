// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import {
  archiveSpaceMutation,
  readSpaceOptions,
  renameSpaceMutation,
  unarchiveSpaceMutation,
} from "../../api/@tanstack/react-query.gen";
import { useSession } from "../../lib/session";
import { useServerMutation } from "../../lib/mutation";
import { useSpaceSwitch } from "../../lib/spaces";
import { toast } from "../../lib/toast";
import { ConfirmDialog } from "../directory/ConfirmDialog";
import { explain } from "../directory/errors";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { EmptyState } from "../ui/EmptyState";
import { Table, Td, Th } from "../ui/Table";
import { MembersTable } from "./MembersTable";
import { SpaceFormDialog } from "./SpaceFormDialog";
import { LAST_SPACE, prefix, refusal, state } from "./words";

const OFFERED: Record<string, string> = {
  connector_account: "Connector account",
  policy_bundle: "Policy bundle",
};

/**
 * One space: its counts, its members, the objects it offers to the rest of the tenant, and
 * the three changes a tenant administrator makes to it — rename, archive and unarchive.
 *
 * **A space is never deleted.** Archiving is the per-space "takes no new work" control: an
 * archived space is still fully readable, keeps every row it ever owned, and stays in every
 * "All spaces" view. Nothing here describes a space as isolation, because it
 * is not one: the tenant is the boundary and a space is ownership and view inside it.
 */
export function SpacePanel({ spaceId, onGone }: { spaceId: string; onGone: () => void }) {
  const session = useSession();
  const queryClient = useQueryClient();
  const [renaming, setRenaming] = useState(false);
  const [changing, setChanging] = useState<"archive" | "unarchive" | null>(null);
  const detail = useQuery({ ...readSpaceOptions({ path: { space_id: spaceId } }), retry: false });
  const switcher = useSpaceSwitch();
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: [{ _id: "readSpace" }] });
    void queryClient.invalidateQueries({ queryKey: [{ _id: "listSpaces" }] });
  };
  const rename = useServerMutation({
    ...renameSpaceMutation(),
    onSuccess: () => {
      toast("Space renamed.");
      refresh();
      setRenaming(false);
    },
  });
  const archive = useServerMutation({
    ...archiveSpaceMutation(),
    onSuccess: () => {
      toast("Space archived; it takes no new work and keeps its history.");
      refresh();
      setChanging(null);
    },
  });
  const unarchive = useServerMutation({
    ...unarchiveSpaceMutation(),
    onSuccess: () => {
      toast("Space unarchived.");
      refresh();
      setChanging(null);
    },
  });

  if (detail.error !== null) {
    return (
      <EmptyState title="This space could not be read.">
        {explain(detail.error)}{" "}
        <Button size="small" onClick={onGone}>
          Back to the list
        </Button>
      </EmptyState>
    );
  }
  if (detail.data === undefined) return <p role="status">Loading the space.</p>;

  const data = detail.data;
  const space = data.space;
  const archived = space.archived_at !== null;
  const looking = session.space?.id === space.space_id;
  return (
    <div className="stack space-detail">
      <Card
        title={space.name}
        aside={
          <div className="page-actions">
            {!looking ? (
              <Button
                size="small"
                disabled={switcher.isPending}
                aria-label={`Look at ${space.name}`}
                onClick={() => {
                  switcher.mutate({ space: space.space_id, name: space.name });
                }}
              >
                Look at this space
              </Button>
            ) : null}
            {data.administrator ? (
              <>
                <Button
                  size="small"
                  aria-label={`Rename ${space.name}`}
                  onClick={() => {
                    rename.reset();
                    setRenaming(true);
                  }}
                >
                  Rename
                </Button>
                <Button
                  size="small"
                  variant={archived ? "default" : "danger"}
                  aria-label={archived ? `Unarchive ${space.name}` : `Archive ${space.name}`}
                  onClick={() => {
                    archive.reset();
                    unarchive.reset();
                    setChanging(archived ? "unarchive" : "archive");
                  }}
                >
                  {archived ? "Unarchive" : "Archive"}
                </Button>
              </>
            ) : null}
          </div>
        }
      >
        <p className="muted">{space.detail ?? "No detail line."}</p>
        <p>
          <Badge tone={archived ? "stale" : "allow"}>{state(space.archived_at)}</Badge>{" "}
          {archived
            ? "It takes no new work: an agent of this space is refused before any dispatch, and a decision in it is refused. Everything it owns stays readable."
            : "It takes work as usual."}
        </p>
        <div className="figures">
          <Figure label="Members" value={space.members} note="Users who belong to this space" />
          <Figure label="Agents" value={space.agents} note="Active agents this space owns" />
          <Figure label="Waiting" value={space.pending} note="Approvals pending in this space" />
          <Figure label="Findings" value={space.findings} note="Open monitoring findings" />
        </div>
        <p className="muted">
          A space divides ownership and view inside one tenant. The tenant stays the security
          boundary: a space is <strong>not</strong> isolation.
        </p>
      </Card>

      <MembersTable data={data} spaceId={spaceId} />

      <Card title="Policy">
        {data.selection === null ? (
          <EmptyState title="This space selects no policy bundle.">
            Admission fails closed for its agents until one is activated for it.
          </EmptyState>
        ) : (
          <p>
            This space runs under bundle <span className="mono">{prefix(data.selection.bundle_id)}</span>,
            selected {data.selection.changed_at.slice(0, 10)}.
          </p>
        )}
      </Card>

      <Card title="Offered to the whole tenant">
        {data.offered.length === 0 ? (
          <EmptyState title="This space offers nothing tenant-wide.">
            An object it owns is usable by this space alone until it is offered.
          </EmptyState>
        ) : (
          <Table caption="The objects this space owns and has offered to every space of the tenant." density="compact">
            <thead>
              <tr>
                <Th>Kind</Th>
                <Th>Object</Th>
                <Th>Label</Th>
              </tr>
            </thead>
            <tbody>
              {data.offered.map((row) => (
                <tr key={`${row.kind}:${row.object_id}`}>
                  <Td>{OFFERED[row.kind] ?? row.kind}</Td>
                  <Td mono>{prefix(row.object_id)}</Td>
                  <Td>{row.label ?? "unlabelled"}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <SpaceFormDialog
        open={renaming}
        title={`Rename ${space.name}`}
        confirm="Rename"
        lead="The name and the detail line are what every reader of this tenant sees in the switcher."
        name={space.name}
        detail={space.detail ?? ""}
        pending={rename.isPending}
        error={rename.error}
        onSubmit={(name, line) => {
          rename.mutate({ path: { space_id: spaceId }, body: { name, detail: line } });
        }}
        onClose={() => {
          setRenaming(false);
        }}
      />

      <ConfirmDialog
        open={changing !== null}
        title={changing === "unarchive" ? `Unarchive ${space.name}?` : `Archive ${space.name}?`}
        confirm={changing === "unarchive" ? "Unarchive" : "Archive"}
        danger={changing === "archive"}
        reason="Why"
        pending={archive.isPending || unarchive.isPending}
        error={null}
        onConfirm={(reason) => {
          const change = changing === "unarchive" ? unarchive : archive;
          change.mutate({ path: { space_id: spaceId }, body: { reason } });
        }}
        onClose={() => {
          setChanging(null);
        }}
      >
        {changing === "unarchive" ? (
          <p>It takes work again at once. Nothing was lost while it was archived.</p>
        ) : (
          <p>
            It takes no new work: its agents are refused before any dispatch and its approvals
            cannot be decided. Nothing is deleted, every row it owns stays readable, and it can be
            unarchived.
          </p>
        )}
        {refusal(archive.error, { CONFLICT: LAST_SPACE }) !== "" ? (
          <p className="problem" role="alert">
            {refusal(archive.error, { CONFLICT: LAST_SPACE })}
          </p>
        ) : null}
        {refusal(unarchive.error) !== "" ? (
          <p className="problem" role="alert">
            {refusal(unarchive.error)}
          </p>
        ) : null}
      </ConfirmDialog>
    </div>
  );
}

function Figure({ label, value, note }: { label: string; value: number; note: string }) {
  return (
    <div className="figure">
      <span className="figure-label">{label}</span>
      <span className="figure-value">{value}</span>
      <span className="figure-note">{note}</span>
    </div>
  );
}
