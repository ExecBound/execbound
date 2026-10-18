// SPDX-License-Identifier: AGPL-3.0-only
// One name per principal (#678): its label, else "Agent 3" or "User 3", the workspace's own
// counting number. The one module that builds a handle, so the shell and the approval route load
// these few functions without the rest of the directory's formatting; `format.ts` re-exports
// them under the names the directory pages and other pages use. Every value is text.

/** The first eight characters of an identifier, as the pages show them. */
export function prefix(id: string | null | undefined): string {
  return id === null || id === undefined ? "" : id.slice(0, 8);
}

/** What a principal's handle calls it: agents and people count separately in a workspace. */
export type Noun = "Agent" | "User";

/** The noun of a principal's kind: `AGENT` reads "Agent", an administrator, an approver and the
 * scheduler "User" (the scheduler is named by `refName` before its noun is ever needed). */
export function noun(kind: string): Noun {
  return kind === "AGENT" ? "Agent" : "User";
}

/** The scheduler principal's own name, when it carries no label (migration 0064). */
export const SCHEDULER = "ExecBound scheduler";

/** A principal as the console API references it: its id, label and counting number, and its
 * kind where the reference carries one. */
export interface PrincipalLike {
  principal_id: string;
  label: string | null;
  number: number | null;
  kind?: string | null;
}

/** A reference's name: its label; else the scheduler's own name; else "Agent 3" or "User 3"
 * (`console/src/test/principal-names.json` holds the cases, which the server's rule reads too).
 * Outside the directory a person is never named by their sign-in address. */
export function refName(principal: PrincipalLike, kind = "AGENT"): string {
  const of = principal.kind ?? kind;
  if (principal.label !== null && principal.label !== "") return principal.label;
  if (of === "SYSTEM") return SCHEDULER;
  return handle(noun(of), principal.number, principal.principal_id);
}

/** A reference's handle alone, "Agent 3" or "User 3". */
export function refHandle(principal: PrincipalLike, kind = "AGENT"): string {
  return handle(noun(principal.kind ?? kind), principal.number, principal.principal_id);
}

/** A principal's counting handle in its workspace, "Agent 3" or "User 3"; a row that carries
 * no number shows its id prefix after the noun. */
export function handle(of: Noun, number: number | null | undefined, id?: string | null): string {
  return number !== null && number !== undefined ? `${of} ${String(number)}` : `${of} ${prefix(id)}`;
}
