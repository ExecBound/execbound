// SPDX-License-Identifier: AGPL-3.0-only
import { useId, useState } from "react";

import { activateStopMutation, releaseStopMutation } from "../../api/@tanstack/react-query.gen";
import { copyFor, refusal } from "../../lib/refusal";
import { toast } from "../../lib/toast";
import { FormDialog } from "../ui/FormDialog";
import { reasonOf, REASON_REQUIRED, useTenantChange } from "./change";
import { ReasonField } from "./ReasonField";

/**
 * The emergency stop, activated or released with a reason through `activate_stop` and
 * `release_stop`, the functions `execbound tenant-stop` and `tenant-resume` call. The same
 * dialog opens from the tenant page and from the top bar.
 */
export function StopDialog({
  open,
  onClose,
  active,
}: {
  open: boolean;
  onClose: () => void;
  /** Whether a stop is active now, which decides between activating and resuming. */
  active: boolean;
}) {
  const id = useId();
  const [reason, setReason] = useState("");
  const [missing, setMissing] = useState(false);
  const change = useTenantChange(active ? releaseStopMutation() : activateStopMutation(), (view) => {
    toast(
      view.stop === null
        ? "The tenant resumed. New actions and decisions are accepted again."
        : "Emergency stop active. Every new action and decision is refused until an administrator resumes this tenant.",
    );
    onClose();
  });
  const faults = change.isError ? refusal(change.error).fields : [];
  return (
    <FormDialog
      open={open}
      onClose={onClose}
      title={active ? "Resume this tenant?" : "Activate the emergency stop?"}
      description={
        active
          ? "New actions and decisions are accepted again. Nothing halted by the stop is retried or resumed on its own."
          : "Every new action, approval decision and dispatch attempt is refused until an administrator resumes this tenant. Operations already committed stay committed and wait in the uncertain queue."
      }
      confirm={active ? "Resume the tenant" : "Activate the emergency stop"}
      variant={active ? "primary" : "danger"}
      pending={change.isPending}
      error={change.isError && faults.length === 0 ? copyFor(change.error) : undefined}
      onSubmit={() => {
        const given = reasonOf(reason);
        setMissing(given === undefined);
        if (given === undefined) return;
        change.mutate({ body: { reason: given } });
      }}
    >
      <ReasonField
        id={`${id}-reason`}
        label={active ? "Reason for resuming" : "Reason for stopping"}
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
