// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useRef } from "react";

import { sectionRoot } from "./sections";
import type { StaleReason } from "./workspace-context";

/**
 * What a tab left behind by a switch or a new sign-in says: which workspace it showed, where the
 * browser is now when that is known, and one link. The link reloads the page, so nothing of this
 * tab's memory survives: its own address when the workspace is the same, else its section's root,
 * never a record of the workspace it showed.
 */
export default function StalePage({ reason }: { reason: StaleReason }) {
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { heading.current?.focus(); }, []);
  const { pathname, search } = window.location;
  const from = reason.from;
  const section = sectionRoot(pathname);
  const showing = from === null ? "" : `This tab was showing ${from.name}. `;
  if (reason.kind === "same") {
    return (
      <main id="main">
        <h1 ref={heading} tabIndex={-1}>You signed in again</h1>
        <p>{from === null ? "This tab belongs to an earlier sign-in." : `This tab belongs to an earlier sign-in to ${from.name}.`} Reload it to carry on where you were.</p>
        <a className="btn" href={pathname + search}>Reload this page</a>
      </main>
    );
  }
  const elsewhere = reason.kind === "elsewhere";
  return (
    <main id="main">
      <h1 ref={heading} tabIndex={-1}>Workspace changed</h1>
      <p>{showing}{elsewhere ? `This browser is now in ${reason.to.name}.` : "This browser has since moved to another workspace or signed in again."}</p>
      <a className="btn" href={section.to}>{elsewhere ? `Open ${section.label} in ${reason.to.name}` : `Open ${section.label}`}</a>
    </main>
  );
}
