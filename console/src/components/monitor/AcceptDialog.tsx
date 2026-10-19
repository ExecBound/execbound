// SPDX-License-Identifier: AGPL-3.0-only
// Accepting an actor's ungoverned paths (#355, step 4): the open paths, all chosen, one reason
// from a fixed list and how long it lasts. Accepting a path already accepted renews it. The
// change asks for a recent second factor, which the fetch wrapper asks for in place, and the
// page shows the actor as the server returns it: nothing is optimistic. Loaded the first time it
// opens.

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import {
  acceptMonitorReachMutation,
  readMonitorAgentOptions,
  readMonitorAgentQueryKey,
  readMonitorAgentsQueryKey,
  withdrawMonitorReachMutation,
} from "../../api/@tanstack/react-query.gen";
import type { AcceptedPath, MonitorReach } from "../../api/types.gen";
import { useServerMutation } from "../../lib/mutation";
import { copyFor } from "../../lib/refusal";
import { Field } from "../ui/Field";
import { FormDialog } from "../ui/FormDialog";
import { DEFAULT_PERIOD, PERIODS, type Period, type Reason, REASON_CODES, REASONS } from "./accept";

function key(row: Pick<MonitorReach, "action" | "path_kind" | "path_ref">): string {
  return `${row.action} ${row.path_kind} ${row.path_ref}`;
}

function acceptCopy(error: unknown): string {
  return copyFor(error, {
    paths: "A path chosen is no longer open: it lapsed, was accepted meanwhile or is not one this actor holds now. Reload to see its paths as they are.",
    path_ref: "That path is not one this actor holds.",
    reason_code: "Choose one of the reasons offered.",
    days: "Choose one of the periods offered.",
  });
}

/** Accept one actor's open paths. `name` is the directory's display name, shown as text. */
export function AcceptDialog({ agentId, name, onClose }: { agentId: string; name: string; onClose: () => void }) {
  const queryClient = useQueryClient();
  const detail = useQuery(readMonitorAgentOptions({ path: { agent_id: agentId } }));
  const open = (detail.data?.reach ?? []).filter((row) => row.open);
  // Every open path is chosen until the administrator leaves one out.
  const [left, setLeft] = useState<ReadonlySet<string>>(new Set());
  const [reason, setReason] = useState<Reason | "">("");
  const [days, setDays] = useState<Period>(DEFAULT_PERIOD);
  const [problem, setProblem] = useState<string | undefined>(undefined);
  const chosen = open.filter((row) => !left.has(key(row)));
  const accepting = useServerMutation({
    ...acceptMonitorReachMutation(),
    onSuccess: (fresh) => {
      queryClient.setQueryData(readMonitorAgentQueryKey({ path: { agent_id: agentId } }), fresh);
      void queryClient.invalidateQueries({ queryKey: readMonitorAgentsQueryKey() });
      onClose();
    },
    onError: (error) => {
      setProblem(acceptCopy(error));
    },
  });
  return (
    <FormDialog
      open
      onClose={onClose}
      title={`Accept the open paths of ${name}`}
      description="Accepting says the organization lives with a path for now. The path stays exactly where it is and is still shown; it stops counting as open until the acceptance expires or is withdrawn."
      confirm={chosen.length === 1 ? "Accept 1 path" : `Accept ${String(chosen.length)} paths`}
      pending={accepting.isPending}
      error={problem}
      onSubmit={() => {
        if (reason === "") {
          setProblem("Choose a reason.");
          return;
        }
        if (chosen.length === 0) {
          setProblem("Choose at least one path.");
          return;
        }
        setProblem(undefined);
        accepting.mutate({
          path: { agent_id: agentId },
          body: {
            paths: chosen.map((row) => ({
              action: row.action,
              path_kind: row.path_kind as "grant" | "role" | "inherited",
              path_ref: row.path_ref,
            })),
            reason_code: reason,
            days,
          },
        });
      }}
    >
      {detail.data === undefined ? (
        <p className="muted" role="status">
          Loading the paths
        </p>
      ) : open.length === 0 ? (
        <p>This actor has no open path to accept now.</p>
      ) : (
        <fieldset className="field">
          <legend>Open paths</legend>
          {open.map((row) => (
            <label key={key(row)} className="check-row">
              <input
                type="checkbox"
                checked={!left.has(key(row))}
                onChange={(event) => {
                  const next = new Set(left);
                  if (event.target.checked) next.delete(key(row));
                  else next.add(key(row));
                  setLeft(next);
                }}
              />
              <span className="mono">{row.action}</span> through {row.path_kind}{" "}
              <span className="mono">{row.path_ref}</span>
            </label>
          ))}
        </fieldset>
      )}
      <Field id="accept-reason" label="Reason">
        <select
          id="accept-reason"
          value={reason}
          onChange={(event) => {
            setReason(event.target.value as Reason | "");
          }}
        >
          <option value="">Choose a reason</option>
          {REASON_CODES.map((code) => (
            <option key={code} value={code}>
              {REASONS[code]}
            </option>
          ))}
        </select>
      </Field>
      <Field id="accept-days" label="Accept for" hint="It expires then, and the path is open again.">
        <select
          id="accept-days"
          value={days}
          onChange={(event) => {
            setDays(Number(event.target.value) as Period);
          }}
        >
          {PERIODS.map((period) => (
            <option key={period} value={period}>
              {period} days
            </option>
          ))}
        </select>
      </Field>
    </FormDialog>
  );
}

/** Withdraw one path's acceptance: it is open again at once. */
export function WithdrawDialog({ agentId, row, onClose }: { agentId: string; row: MonitorReach; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [problem, setProblem] = useState<string | undefined>(undefined);
  const withdrawing = useServerMutation({
    ...withdrawMonitorReachMutation(),
    onSuccess: (fresh) => {
      queryClient.setQueryData(readMonitorAgentQueryKey({ path: { agent_id: agentId } }), fresh);
      void queryClient.invalidateQueries({ queryKey: readMonitorAgentsQueryKey() });
      onClose();
    },
    onError: (error) => {
      setProblem(
        copyFor(error, { path_ref: "That path is not one this actor holds." }).replace(
          "That is already the current state; nothing was changed.",
          "This acceptance was already withdrawn; nothing was changed.",
        ),
      );
    },
  });
  return (
    <FormDialog
      open
      onClose={onClose}
      title="Withdraw this acceptance?"
      description="The path counts as open again at once, and the next collection reopens its finding."
      confirm="Withdraw acceptance"
      variant="danger"
      pending={withdrawing.isPending}
      error={problem}
      onSubmit={() => {
        setProblem(undefined);
        withdrawing.mutate({
          path: { agent_id: agentId },
          // Any kind an acceptance is recorded for, `accept-reach`'s observed paths included; the
          // server refuses one it never records.
          body: { action: row.action, path_kind: row.path_kind as AcceptedPath["path_kind"], path_ref: row.path_ref },
        });
      }}
    >
      <p>
        <span className="mono">{row.action}</span> through {row.path_kind} <span className="mono">{row.path_ref}</span>
      </p>
    </FormDialog>
  );
}
