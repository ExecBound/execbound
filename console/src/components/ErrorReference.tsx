// SPDX-License-Identifier: AGPL-3.0-only
// The reference a failed page shows (#678), once its report is sent: "Reference 3fa2c1d0", and
// where the deployment names a support address, a mail link whose subject carries it.

import { useEffect, useState } from "react";

import { send } from "../lib/client-errors";
import { builtRelease } from "../lib/release";
import { useService } from "../lib/session";

export default function ErrorReference({
  error,
  routeId,
  componentStack,
}: {
  error: unknown;
  routeId: string | undefined;
  componentStack: string | undefined;
}) {
  const service = useService();
  const [reference, setReference] = useState<string | undefined>(undefined);
  useEffect(() => {
    let current = true;
    void send({ error, routeId, componentStack, release: builtRelease() }).then((found) => {
      if (current) setReference(found);
    });
    return () => {
      current = false;
    };
  }, [error, routeId, componentStack]);
  if (reference === undefined) return null;
  return (
    <p className="muted">
      Reference <span className="mono">{reference}</span>
      {service.support_email !== null ? (
        <>
          {". If this keeps happening, "}
          <a href={`mailto:${service.support_email}?subject=${encodeURIComponent(`ExecBound support: reference ${reference}`)}`}>
            email support with this reference
          </a>
          .
        </>
      ) : null}
    </p>
  );
}
