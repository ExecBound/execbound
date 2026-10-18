// SPDX-License-Identifier: AGPL-3.0-only
import type { Target } from "../../api/types.gen";
import { RequestToRelay } from "./RequestToRelay";

/**
 * The example request "Connect this agent" suggests: one synthetic target and its open incident,
 * with the operation to name where the server gives one (#545). Core names its sample
 * workstation this way, and an edition may name its own (#496), whose sentence stays as
 * it was until the edition passes an operation; `label` says which one it is.
 */
export function ExampleRequest({ label, target, operationRef = null }: { label: string; target: Target; operationRef?: string | null }) {
  return (
    <p className="note">
      {label}: ask your agent to <RequestToRelay operationRef={operationRef} kind={target.kind} value={target.value} incident={target.incident_id} />. This can change the protected mock endpoint.
    </p>
  );
}
