// SPDX-License-Identifier: AGPL-3.0-only
import type { ReactNode } from "react";

/** Every page has one h1, which takes focus on arrival (#333). */
export function PageHeading({
  title,
  lead,
  actions,
}: {
  title: string;
  lead?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="page-head">
      <div>
        <h1 tabIndex={-1}>{title}</h1>
        {lead !== undefined ? <p className="lead">{lead}</p> : null}
      </div>
      {actions !== undefined ? <div className="page-actions">{actions}</div> : null}
    </div>
  );
}
