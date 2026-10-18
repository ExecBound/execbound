// SPDX-License-Identifier: AGPL-3.0-only
import { useQueryClient } from "@tanstack/react-query";
import { useState, type SyntheticEvent } from "react";

import { reconcileExecution } from "../api/sdk.gen";
import type { ExecutionDetail, ReconcileExecutionData, ReconcileResult } from "../api/types.gen";
import { copyFor } from "../lib/errors";
import { useServerMutation } from "../lib/mutation";
import { Icon } from "../shell/icons";
import { FIELDS, refusalOf } from "./directory/errors";
import { DialogClose, DialogSurface, DialogTitle } from "./ui/dialog";

/**
 * The reconcile and settle-grant routes now refuse a credential-shaped reason as `INVALID_BODY`
 * naming it (the people's-text screen). That is the same rule every other screened field
 * states, so its sentence is read from the shared `FIELDS.reason` rather than this dialog's own
 * generic "check the reason and the record" line. Any other refusal keeps `copyFor`'s sentence,
 * which already distinguishes `INVALID_CONTINUATION`, `STOPPED` and the rest for this dialog.
 */
function reconcileErrorText(error: unknown): string {
  const refusal = refusalOf(error);
  if (refusal.code === "INVALID_BODY" && refusal.fields.includes("reason")) return FIELDS.reason ?? copyFor(error);
  return copyFor(error);
}

const WORDS = {
  provider: {
    title: "Reconcile with provider evidence",
    text:
      "ExecBound asks the provider's journal for a terminal entry for this dispatch and settles " +
      "the record from it. Without one the record stays unsettled, unless you cancel it.",
    button: "Reconcile with provider evidence",
  },
  record: {
    title: "Settle from the executor's signed record",
    text:
      "Settling from the executor's own signed record closes ExecBound's settlement route for " +
      "this grant. ExecBound dispatched nothing here and cannot undo what the executor does at " +
      "the vendor.",
    button: "Settle from the executor's signed record",
  },
  correction: {
    title: "Correct this settlement",
    text:
      "This record was settled on the platform's own word that its call failed, which ExecBound " +
      "could check nothing about, and the impact was charged for it. A signed record stating that " +
      "the call was not executed replaces that settlement with evidence ExecBound verifies against " +
      "a key this tenant registered: the impact becomes a non-execution, the target claim is " +
      "released, and the statement being corrected stays in this record's history. A record " +
      "stating that the executor acted is refused, and a corrected record is refused a second " +
      "correction.",
    button: "Correct this settlement with a signed non-execution",
  },
} as const;

/**
 * An administrator settles one uncertain record (#333): the page's reconcile form as a
 * dialog. The continuation the drawer's detail carries binds the record; the server decides
 * what the evidence allows, the button waits for its answer, and a refusal is shown as copy.
 */
export function ReconcileDialog({
  detail,
  onClose,
  onSettled,
}: {
  detail: ExecutionDetail;
  onClose: () => void;
  onSettled: (result: ReconcileResult) => void;
}) {
  const queryClient = useQueryClient();
  const kind = detail.reconcile.kind ?? "provider";
  const continuation = detail.reconcile.continuation;
  const words = WORDS[kind];
  const [reason, setReason] = useState("");
  const [cancel, setCancel] = useState(false);
  const [record, setRecord] = useState("");
  const settle = useServerMutation<ReconcileResult, ReconcileExecutionData["body"]>({
    mutationFn: async (body) => {
      const { data } = await reconcileExecution({
        path: { execution_id: detail.execution_id },
        body,
        throwOnError: true,
      });
      return data;
    },
    onSuccess: async (result) => {
      await queryClient.invalidateQueries();
      onSettled(result);
    },
  });
  const ready =
    continuation !== null &&
    reason.trim() !== "" &&
    (kind === "provider" || record.trim() !== "") &&
    !settle.isPending;
  const submit = (event: SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!ready) return;
    settle.mutate({
      continuation,
      reason: reason.trim(),
      cancel_if_missing: kind === "provider" ? cancel : false,
      record: kind === "provider" ? null : record,
    });
  };
  return (
    <DialogSurface
      open
      className="dialog"
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
    >
      <header className="drawer-head">
        <DialogTitle className="drawer-title">{words.title}</DialogTitle>
        <DialogClose className="btn btn-icon btn-ghost" aria-label="Close">
          <Icon name="close" />
        </DialogClose>
      </header>
      <form className="dialog-form" onSubmit={submit}>
        <p className="muted">{words.text}</p>
        {continuation === null ? (
          <p role="alert">Your session is about to end; sign in again and open the record.</p>
        ) : null}
        <label className="field">
          Reason
          <input
            name="reason"
            required
            maxLength={500}
            autoComplete="off"
            value={reason}
            onChange={(event) => {
              setReason(event.target.value);
            }}
          />
        </label>
        {kind === "provider" ? (
          <label className="field field-check">
            <input
              type="checkbox"
              name="cancel"
              checked={cancel}
              onChange={(event) => {
                setCancel(event.target.checked);
              }}
            />
            Cancel if no terminal evidence exists
          </label>
        ) : (
          <label className="field">
            Executor record
            <textarea
              name="record"
              required
              rows={4}
              maxLength={8000}
              spellCheck={false}
              value={record}
              onChange={(event) => {
                setRecord(event.target.value);
              }}
            />
          </label>
        )}
        {settle.isError ? (
          <p role="alert" className="form-error">
            {reconcileErrorText(settle.error)}
          </p>
        ) : null}
    <div className="dialog-actions">
      <DialogClose className="btn">Keep it as it is</DialogClose>
      <button type="submit" className="btn btn-primary" disabled={!ready}>
        {settle.isPending ? "Waiting for the server" : words.button}
      </button>
    </div>
      </form>
    </DialogSurface>
  );
}
