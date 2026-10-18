// SPDX-License-Identifier: AGPL-3.0-only
import { Link } from "@tanstack/react-router";

import { can, useSession } from "../lib/session";
import { refHandle, refName, type PrincipalLike } from "./directory/handles";

/**
 * A principal as every page names it (#678): its label, else "Agent 3" or "User 3", with the
 * handle beside a label in faint text so two principals with one label stay apart. With
 * `link`, a router link built from the id, offered only to a reader who can open the page the
 * navigation would: an agent's to an administrator, a person's to who manages access, and the
 * scheduler's to nobody. Inside a clickable row the link does not also open the row. Every
 * label renders as text. The prop is `principal`, never `ref`, which React reserves.
 */
export function PrincipalName({ principal, kind = "AGENT", link = false }: { principal: PrincipalLike; kind?: string; link?: boolean }) {
  const session = useSession();
  const of = principal.kind ?? kind;
  const name = refName(principal, kind);
  const tag = refHandle(principal, kind);
  const person = of === "ADMIN" || of === "HUMAN_APPROVER";
  const linked = link && (of === "AGENT" ? session.role === "ADMIN" : person && can(session, "access.manage"));
  const stop = (event: { stopPropagation: () => void }) => {
    event.stopPropagation();
  };
  return (
    <>
      {linked ? (
        of === "AGENT" ? (
          <Link to="/agents/$agentId" params={{ agentId: principal.principal_id }} onClick={stop}>
            {name}
          </Link>
        ) : (
          <Link to="/people/$personId" params={{ personId: principal.principal_id }} onClick={stop}>
            {name}
          </Link>
        )
      ) : (
        name
      )}
      {name !== tag && of !== "SYSTEM" ? (
        <>
          {" "}
          <span className="faint">{tag}</span>
        </>
      ) : null}
    </>
  );
}
