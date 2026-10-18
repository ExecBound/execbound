// SPDX-License-Identifier: AGPL-3.0-only
import { useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";

import {
  readAssistantSettingsQueryKey,
  setAssistantSettingsMutation,
} from "../../api/@tanstack/react-query.gen";
import type { Settings } from "../../api/types.gen";
import { useServerMutation } from "../../lib/mutation";
import { copyFor, refusal } from "../../lib/refusal";
import { toast } from "../../lib/toast";
import { FormDialog } from "../ui/FormDialog";
import { REASON_REQUIRED, reasonOf, TENANT_FIELDS } from "./change";
import { ReasonField } from "./ReasonField";

/**
 * The tenant's assistant switch (#330), with the provider's retention stated in
 * the dialog rather than in a document, so the administrator reads it at the moment they turn
 * it on. Turning it off is the same form and the same audited reason.
 */
export function AssistantDialog({
  open,
  onClose,
  enabled,
  retention,
  model,
}: {
  open: boolean;
  onClose: () => void;
  enabled: boolean;
  retention: string;
  model: string;
}) {
  const id = useId();
  const [reason, setReason] = useState("");
  const [missing, setMissing] = useState(false);
  const queryClient = useQueryClient();
  const change = useServerMutation({
    ...setAssistantSettingsMutation(),
    onSuccess: (view: Settings) => {
      queryClient.setQueryData(readAssistantSettingsQueryKey(), view);
      toast(view.enabled ? "The assistant is on for this tenant." : "The assistant is off.");
      onClose();
    },
  });
  const faults = change.isError ? refusal(change.error).fields : [];
  return (
    <FormDialog
      open={open}
      onClose={onClose}
      title={enabled ? "Turn the assistant off?" : "Turn the assistant on?"}
      description={
        enabled
          ? "No further question reaches the model provider. Questions already asked keep their answers until they are erased at thirty days."
          : `Questions people ask, and the records the assistant reads to answer them, are sent to the model provider. ${retention}`
      }
      confirm={enabled ? "Turn it off" : "Turn it on"}
      pending={change.isPending}
      error={change.isError && faults.length === 0 ? copyFor(change.error, TENANT_FIELDS) : undefined}
      onSubmit={() => {
        const given = reasonOf(reason);
        setMissing(given === undefined);
        if (given === undefined) return;
        change.mutate({ body: { enabled: !enabled, reason: given } });
      }}
    >
      {enabled ? null : (
        <ul className="dialog-notes">
          <li>It reads only what the person asking can read, and it changes nothing.</li>
          <li>It never says whether to approve or refuse a request.</li>
          <li>No credential, key or code is ever sent; a turn that finds one is stopped.</li>
          <li>A person&apos;s questions are readable only by that person, you included.</li>
          <li>Answered by {model}.</li>
        </ul>
      )}
      <ReasonField
        id={`${id}-reason`}
        label={enabled ? "Reason for turning it off" : "Reason for turning it on"}
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
