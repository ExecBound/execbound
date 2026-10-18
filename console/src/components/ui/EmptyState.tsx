// SPDX-License-Identifier: AGPL-3.0-only
import type { ReactNode } from "react";

/** An empty state names the next action; it never leaves a blank region. */
export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty" role="status">
      <p className="empty-title">{title}</p>
      {children !== undefined ? <div className="empty-body">{children}</div> : null}
    </div>
  );
}
