// SPDX-License-Identifier: AGPL-3.0-only
import type { ReactNode } from "react";

/** A definition list in two columns: an eyebrow term, then its value. */
export function Definitions({ children, ...rest }: { children: ReactNode; "aria-label"?: string }) {
  return (
    <dl className="defs" {...rest}>
      {children}
    </dl>
  );
}

export function Definition({ term, mono = false, children }: { term: string; mono?: boolean; children: ReactNode }) {
  return (
    <>
      <dt>{term}</dt>
      <dd className={mono ? "mono" : undefined}>{children}</dd>
    </>
  );
}
