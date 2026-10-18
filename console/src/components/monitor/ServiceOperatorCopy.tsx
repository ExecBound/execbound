// SPDX-License-Identifier: AGPL-3.0-only
// Who connects a monitoring provider where the console cannot, and how to ask (#678, MC18). An
// edition without operator commands (a hosted service) shows this in place of the host steps:
// the deployment's operator and support address come from its `ServiceLinks`, so core names no
// hosted service, and a deployment that configures neither still says who connects a provider.

import { useService } from "../../lib/session";

export function ServiceOperatorCopy({ subject = "this provider" }: { subject?: string }) {
  const service = useService();
  const who = service.operator ?? "Your service operator";
  const address = service.support_email;
  return (
    <div className="stack service-operator">
      <p>
        {who} connects {subject} for this workspace for now.
        {address !== null ? (
          <>
            {" "}Email <a href={`mailto:${address}`}>{address}</a> with the connection name and the Space it belongs in.
          </>
        ) : null}
      </p>
      <p>Never send an API key, client secret or token by email.</p>
    </div>
  );
}
