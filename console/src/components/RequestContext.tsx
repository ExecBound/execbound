// SPDX-License-Identifier: AGPL-3.0-only
import { Link } from "@tanstack/react-router";

import type { DeliveryView, ExternalCase, RelatedRequest } from "../api/types.gen";

/** Each delivery row named by its message (#678): the announcement, a reminder or a close-out. */
export const DELIVERY_LABELS: Record<DeliveryView["kind"], string> = {
  "approval.pending": "Delivery",
  "approval.reminder": "Reminder delivery",
  "approval.closed": "Outcome delivery",
};

/** Case metadata is inert text and an explicit external link, never a review signal. */
export function RequestContext({ externalCase, related, executionId, approvalId, deliveries }: {
  externalCase: ExternalCase | null;
  related: RelatedRequest[];
  executionId: string;
  approvalId?: string | null;
  deliveries: DeliveryView[];
}) {
  return (
    <section className="drawer-section" aria-label="Request context">
      {externalCase !== null ? (
        <>
          <h3 className="eyebrow">Source case</h3>
          <p><span className="mono">{externalCase.case_id}</span> · {externalCase.source}</p>
          <p className="muted">Reported by the caller; not verified incident context.</p>
          {externalCase.url ? (
            <p><a href={externalCase.url} target="_blank" rel="noopener noreferrer">
              Open case at {new URL(externalCase.url).hostname} ↗
            </a></p>
          ) : null}
          {related.length > 0 ? (
            <>
              <h3 className="eyebrow">Other requests in this case</h3>
              <ul>
                {related.map((request) => (
                  <li key={request.execution_id}>
                    <Link to="/activity" search={{ open: request.execution_id }}>{request.request_ref}</Link>
                    {" · "}{request.action}{" · "}{request.state.toLowerCase().replaceAll("_", " ")}
                  </li>
                ))}
              </ul>
              <p className="muted">Up to 20 recent requests you can access.</p>
            </>
          ) : null}
        </>
      ) : null}
      <details>
        <summary>Technical details</summary>
        <dl className="kv">
          <div><dt>Execution ID</dt><dd className="mono">{executionId}</dd></div>
          {approvalId ? <div><dt>Approval ID</dt><dd className="mono">{approvalId}</dd></div> : null}
          {deliveries.map((delivery) => (
            <div key={delivery.delivery_id}>
              <dt>{DELIVERY_LABELS[delivery.kind]} · {delivery.state.toLowerCase()} · {String(delivery.attempts)} attempts</dt>
              <dd className="mono">{delivery.delivery_id}</dd>
            </div>
          ))}
        </dl>
      </details>
    </section>
  );
}
