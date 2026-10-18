// SPDX-License-Identifier: AGPL-3.0-only
import { useId, useState } from "react";

import { changeDeadlineMutation } from "../../api/@tanstack/react-query.gen";
import type { NotificationDelivery, NotificationDestination, TenantDeadline } from "../../api/types.gen";
import { copyFor, refusal } from "../../lib/refusal";
import { toast } from "../../lib/toast";
import { describedBy, Field } from "../ui/Field";
import { FormDialog } from "../ui/FormDialog";
import { DEADLINE_BOUNDS, reasonOf, REASON_REQUIRED, useTenantChange } from "./change";
import { deadlineHint, lapseWarning } from "./delivery";
import { ReasonField } from "./ReasonField";

/**
 * The approval deadline, changed with a reason through `set_approval_deadline`. The field is
 * sent as typed, `off` or seconds, and the server refuses 119, 3601 and a word before any store
 * function sees them; the form shows the bound it answers with and never a value of its own.
 *
 * As the administrator types, a hint warns when the deadline is short against how fast this
 * workspace's notifications have arrived, or else when a deadline under ten minutes can lapse before
 * a message reaches a reviewer (#678). Either is a description, not an error:
 * it never blocks the change, and the body sent is still exactly `{deadline, reason}`. Both props
 * are required, so every mount passes the destinations and the measurement it is read against.
 */
export function DeadlineDialog({
  open,
  onClose,
  current,
  destinations,
  delivery,
}: {
  open: boolean;
  onClose: () => void;
  current: TenantDeadline;
  destinations: NotificationDestination[];
  delivery: NotificationDelivery;
}) {
  const id = useId();
  const [deadline, setDeadline] = useState(current.seconds === null ? "off" : String(current.seconds));
  const [reason, setReason] = useState("");
  const [missing, setMissing] = useState(false);
  const change = useTenantChange(changeDeadlineMutation(), (view) => {
    toast(
      view.deadline.seconds === null
        ? "Approval deadline turned off for new approvals."
        : `Approval deadline set to ${String(view.deadline.seconds)} seconds for new approvals.`,
    );
    onClose();
  });
  const faults = change.isError ? refusal(change.error).fields : [];
  // At most one warning: the delivery hint where it applies, else the warning that a short
  // deadline can lapse before its message arrives, in the hold tone (#678).
  const measured = deadlineHint(deadline, destinations, delivery, current.bounds);
  const hint = measured ?? lapseWarning(deadline, destinations, delivery, current.bounds);
  const hintId = `${id}-deadline-delivery`;
  return (
    <FormDialog
      open={open}
      onClose={onClose}
      title="Change the approval deadline?"
      description="New approvals wait this long for a person. Approvals already pending keep the expiry they were created with."
      confirm="Change deadline"
      pending={change.isPending}
      error={change.isError && faults.length === 0 ? copyFor(change.error) : undefined}
      onSubmit={() => {
        const given = reasonOf(reason);
        setMissing(given === undefined);
        if (given === undefined) return;
        change.mutate({ body: { deadline: deadline.trim().slice(0, 8), reason: given } });
      }}
    >
      <Field
        id={`${id}-deadline`}
        label={`Seconds (${String(current.bounds.min)} to ${String(current.bounds.max)}), or off`}
        hint="An approval never outlives the frozen plan, so off means the plan's own validity is the only deadline."
        error={faults.includes("deadline") ? DEADLINE_BOUNDS : undefined}
      >
        <input
          id={`${id}-deadline`}
          name="deadline"
          className="mono"
          value={deadline}
          maxLength={8}
          autoComplete="off"
          inputMode="numeric"
          aria-describedby={hint === null ? describedBy(`${id}-deadline`) : `${describedBy(`${id}-deadline`)} ${hintId}`}
          aria-invalid={faults.includes("deadline") ? true : undefined}
          onChange={(event) => {
            setDeadline(event.target.value);
          }}
        />
        {hint !== null ? (
          <p className={measured !== null ? "muted" : "tone-hold"} id={hintId}>
            {hint}
          </p>
        ) : null}
      </Field>
      <ReasonField
        id={`${id}-reason`}
        label="Reason for the deadline change"
        value={reason}
        onChange={(value) => {
          setReason(value);
          setMissing(false);
        }}
        error={missing || faults.includes("reason") ? REASON_REQUIRED : undefined}
      />
    </FormDialog>
  );
}
