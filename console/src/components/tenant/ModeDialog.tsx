// SPDX-License-Identifier: AGPL-3.0-only
import { useId, useState } from "react";

import { changeModeMutation } from "../../api/@tanstack/react-query.gen";
import type { TenantMode } from "../../api/types.gen";
import { copyFor, refusal } from "../../lib/refusal";
import { toast } from "../../lib/toast";
import { Field } from "../ui/Field";
import { FormDialog } from "../ui/FormDialog";
import { reasonOf, REASON_REQUIRED, TENANT_FIELDS, useTenantChange } from "./change";
import { ReasonField } from "./ReasonField";

export const MODE_WORDS: Record<TenantMode["value"], string> = {
  ENFORCE: "Enforcing",
  OBSERVE: "Observe only",
};

/** The enforcement mode, changed with a reason through `set_enforcement_mode`. */
export function ModeDialog({
  open,
  onClose,
  current,
}: {
  open: boolean;
  onClose: () => void;
  current: TenantMode["value"];
}) {
  const id = useId();
  const [mode, setMode] = useState<TenantMode["value"]>(current === "ENFORCE" ? "OBSERVE" : "ENFORCE");
  const [reason, setReason] = useState("");
  const [missing, setMissing] = useState(false);
  const change = useTenantChange(changeModeMutation(), (view) => {
    toast(`Mode changed to ${MODE_WORDS[view.mode.value]}.`);
    onClose();
  });
  const faults = change.isError ? refusal(change.error).fields : [];
  return (
    <FormDialog
      open={open}
      onClose={onClose}
      title="Change the enforcement mode?"
      description="Every new request is admitted under the new mode. Approvals already pending keep their state."
      confirm="Change mode"
      pending={change.isPending}
      error={change.isError && faults.length === 0 ? copyFor(change.error) : undefined}
      onSubmit={() => {
        const given = reasonOf(reason);
        setMissing(given === undefined);
        if (given === undefined) return;
        change.mutate({ body: { mode, reason: given } });
      }}
    >
      <Field
        id={`${id}-mode`}
        label="Mode"
        hint={
          mode === "OBSERVE"
            ? "In Observe only, decisions are recorded with their would-be effect and nothing is dispatched, approved, reserved or claimed."
            : "In Enforcing, a permitted action is dispatched and a held one waits for a person."
        }
        error={faults.includes("mode") ? TENANT_FIELDS.mode : undefined}
      >
        <select
          id={`${id}-mode`}
          name="mode"
          value={mode}
          aria-describedby={`${id}-mode-hint`}
          onChange={(event) => {
            setMode(event.target.value === "OBSERVE" ? "OBSERVE" : "ENFORCE");
          }}
        >
          <option value="ENFORCE">Enforcing</option>
          <option value="OBSERVE">Observe only</option>
        </select>
      </Field>
      <ReasonField
        id={`${id}-reason`}
        label="Reason for the mode change"
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
