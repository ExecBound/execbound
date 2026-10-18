// SPDX-License-Identifier: AGPL-3.0-only
// The address to copy for an approval (#678): the deployment's own path for it, which the server
// builds from identifiers only, accepted only when it is an approval path ending in this
// approval's id; anything else is replaced by the core address the router builds. The origin is
// always this page's own, so a copied link can never point anywhere else.

const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const GRAMMAR = new RegExp(`^(?:/workspaces/${UUID})?/approvals/(${UUID})$`);

/** The server's path when it matches the approval grammar and names this approval, else `fallback`. */
export function approvalPath(linkPath: string | null | undefined, approvalId: string, fallback: string): string {
  const match = typeof linkPath === "string" ? GRAMMAR.exec(linkPath) : null;
  return match !== null && match[1] === approvalId ? linkPath ?? fallback : fallback;
}

/** The full link: this page's origin and a validated path. */
export function approvalLink(linkPath: string | null | undefined, approvalId: string, fallback: string, origin: string): string {
  return origin + approvalPath(linkPath, approvalId, fallback);
}
