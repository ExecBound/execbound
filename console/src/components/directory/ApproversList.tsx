// SPDX-License-Identifier: AGPL-3.0-only
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { assignApproverScopeMutation, unassignApproverScopeMutation } from "../../api/@tanstack/react-query.gen";
import type { ApproversPage, Assignment } from "../../api/types.gen";
import { useServerMutation } from "../../lib/mutation";
import { toast } from "../../lib/toast";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { EmptyState } from "../ui/EmptyState";
import { Table, Td, Th } from "../ui/Table";
import { ConfirmDialog } from "./ConfirmDialog";
import { handle, plural, prefix, principalName, withHandle } from "./format";
import { Field, Problem } from "./forms";
import { PersonName } from "./PersonName";

/** The confirmation's title: the approver by their handle, the target by its prefix. */
function unassignTitle(row: Assignment): string {
  const approver = handle("User", row.number, row.approver_id);
  return `Unassign ${approver} from ${row.action} on ${prefix(row.canonical_target_id)}?`;
}

export function ApproversList({ data }: { data: ApproversPage }) {
  const queryClient = useQueryClient();
  const [withdrawing, setWithdrawing] = useState<Assignment | null>(null);
  const unassign = useServerMutation({
    ...unassignApproverScopeMutation(),
    onSuccess: () => {
      toast("Scope unassigned.");
      for (const id of COVERAGE_READS) void queryClient.invalidateQueries({ queryKey: [{ _id: id }] });
      setWithdrawing(null);
    },
  });
  return (
    <div className="stack">
      <p className="note">Reviewers use their own account and normal sign-in. Assign permission for each action and target in the selected space. Administrators need these assignments too.</p>
      <div className="figures">
        <div className="figure">
          <span className="figure-label">Active assignments</span>
          <span className="figure-value">{data.assignments.length}</span>
          <span className="figure-note">
            {plural(data.approvers.length, "approver")} · {plural(data.targets.length, "target")}
          </span>
        </div>
      </div>
      <Card>
        <Table caption="Active assignments by approver, canonical target and action." density="compact">
          <thead>
            <tr>
              <Th>Approver</Th>
              <Th>Canonical target</Th>
              <Th>Action</Th>
              <Th>Unassign</Th>
            </tr>
          </thead>
          <tbody>
            {data.assignments.map((row) => (
              <tr key={`${row.approver_id}-${row.canonical_target_id}-${row.action}`}>
                <Td>
                  <PersonName id={row.approver_id} label={row.label} email={row.email} number={row.number} link />
                </Td>
                <Td>
                  <span className="mono">{prefix(row.canonical_target_id)}</span>
                  {row.labels !== null ? ` · ${row.labels}` : ""}
                </Td>
                <Td mono>{row.action}</Td>
                <Td>
                  <Button
                    size="small"
                    onClick={() => {
                      unassign.reset();
                      setWithdrawing(row);
                    }}
                  >
                    Unassign {handle("User", row.number, row.approver_id)} from {row.action} on {prefix(row.canonical_target_id)}
                  </Button>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
        {data.assignments.length === 0 ? (
          <EmptyState title="No active assignments.">
            Approvals cannot be decided until an approver is assigned.
          </EmptyState>
        ) : null}
      </Card>
      <ConfirmDialog
        open={withdrawing !== null}
        title={
          withdrawing === null
            ? "Unassign?"
            : unassignTitle(withdrawing)
        }
        confirm="Unassign"
        danger
        pending={unassign.isPending}
        error={unassign.error}
        onConfirm={() => {
          if (withdrawing === null) return;
          unassign.mutate({
            body: {
              approver: withdrawing.approver_id,
              target: withdrawing.canonical_target_id,
              action: withdrawing.action,
            },
          });
        }}
        onClose={() => {
          setWithdrawing(null);
        }}
      >
        <p>Pending decisions under this scope will be refused.</p>
      </ConfirmDialog>
    </div>
  );
}

/** What a change to assignments makes stale: the matrix and both decision coverage reads. */
const COVERAGE_READS = ["listApproverScopes", "readApprovalCoverage", "readUnroutedApprovals"];

/**
 * What the coverage card asks the assignment dialog to start from: a gap's target, with its
 * labels, and its action. A target the approvers page's list does not hold is added to the
 * options, so it is shown, selected and sent.
 */
export interface AssignPreset {
  target?: { id: string; labels: string | null };
  action?: string;
}

/** `Assign an approver`: this tenant's approvers, its canonical targets, the catalog's actions. */
export function AssignScope({
  data,
  preset,
  open: controlled,
  onOpenChange,
}: {
  data: ApproversPage;
  preset?: AssignPreset;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const [own, setOwn] = useState(false);
  const open = controlled ?? own;
  const setOpen = (value: boolean) => {
    if (controlled === undefined) setOwn(value);
    onOpenChange?.(value);
  };
  const extra = preset?.target;
  const targets =
    extra !== undefined && !data.targets.some((row) => row.canonical_target_id === extra.id)
      ? [{ canonical_target_id: extra.id, labels: extra.labels }, ...data.targets]
      : data.targets;
  const [approver, setApprover] = useState(data.approvers[0]?.principal_id ?? "");
  const [target, setTarget] = useState(extra?.id ?? data.targets[0]?.canonical_target_id ?? "");
  const [action, setAction] = useState(preset?.action ?? data.actions[0] ?? "");
  const assign = useServerMutation({
    ...assignApproverScopeMutation(),
    onSuccess: () => {
      toast("Scope assigned.");
      for (const id of COVERAGE_READS) void queryClient.invalidateQueries({ queryKey: [{ _id: id }] });
      setOpen(false);
    },
  });
  const ready = approver !== "" && target !== "" && action !== "";
  return (
    <>
      {controlled === undefined ? (
        <Button
          variant="primary"
          onClick={() => {
            assign.reset();
            setOpen(true);
          }}
        >
          Assign an approver
        </Button>
      ) : null}
      <ConfirmDialog
        open={open}
        title="Assign an approver"
        confirm="Assign"
        pending={assign.isPending}
        confirmDisabled={!ready}
        error={assign.error}
        onConfirm={() => {
          if (!ready) return;
          assign.mutate({ body: { approver, target, action } });
        }}
        onClose={() => {
          setOpen(false);
        }}
      >
        <p>
          Choose an existing member or administrator account, then the target and action they may review.
          This assignment does not create an account or change their sign-in.
        </p>
        {data.approvers.length === 0 ? <p>Add a person in Team &amp; access and complete their sign-in setup first.</p> : null}
        <Field label="Approver">
          <select
            value={approver}
            required
            onChange={(event) => {
              setApprover(event.target.value);
            }}
          >
            {data.approvers.map((row) => (
              <option key={row.principal_id} value={row.principal_id}>
                {withHandle(principalName("User", row.label, row.number, row.principal_id, row.email), handle("User", row.number, row.principal_id))}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Canonical target">
          <select
            value={target}
            required
            onChange={(event) => {
              setTarget(event.target.value);
            }}
          >
            {targets.map((row) => (
              <option key={row.canonical_target_id} value={row.canonical_target_id}>
                {prefix(row.canonical_target_id)}
                {row.labels !== null ? ` · ${row.labels}` : ""}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Action">
          <select
            value={action}
            required
            onChange={(event) => {
              setAction(event.target.value);
            }}
          >
            {data.actions.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </Field>
        {!ready ? <Problem error={{ code: "INVALID_BODY", fields: ["approver"] }} /> : null}
      </ConfirmDialog>
    </>
  );
}
