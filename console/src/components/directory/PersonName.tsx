// SPDX-License-Identifier: AGPL-3.0-only
import { Link } from "@tanstack/react-router";

import { handle, noun, principalName } from "./format";

/**
 * A person where a list names one: their label, else their email, else "User 3", linked to
 * their page when `link` is set, with their handle beside the name where the id prefix used
 * to be. A person named by the handle itself shows it once. Every value is text.
 */
export function PersonName({
  id,
  label,
  email,
  number,
  kind = "HUMAN_APPROVER",
  link = false,
}: {
  id: string;
  label: string | null;
  email?: string | null;
  number: number | null | undefined;
  kind?: string;
  link?: boolean;
}) {
  const of = noun(kind);
  const name = principalName(of, label, number, id, email);
  const tag = handle(of, number, id);
  return (
    <>
      {link ? (
        <Link to="/people/$personId" params={{ personId: id }}>
          {name}
        </Link>
      ) : (
        name
      )}
      {name !== tag ? (
        <>
          {" "}
          <span className="faint">{tag}</span>
        </>
      ) : null}
    </>
  );
}
