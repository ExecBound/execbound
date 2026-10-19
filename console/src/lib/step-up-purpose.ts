// SPDX-License-Identifier: AGPL-3.0-only
// What a refused change was, in words, for the step-up's first line (#678): "To revoke key 2 for
// Agent 3, confirm it is you." One table keyed by method and the API's path template, with a
// phrase per route. A phrase names an agent, a key or a person by handle alone ("Agent 3",
// "key 2", "User 4"), read from what the page already holds, and never by a label, a name, an
// email or any agent or provider string, so a hostile label cannot make the question describe a
// different change. The line is informational: one verification covers every protected change
// for thirty minutes, as it always has.
//
// Every core route the server's step-up matches has an entry; a test holds the table to the
// served document (`tests/test_console_step_up_purposes.py`), so a route added to the step-up
// adds its phrase here in the same change. A route with no entry, such as a hosted plugin's own,
// keeps the generic sentence. Only `StepUpDialog` imports this, so it loads with the dialog.

import type { QueryClient } from "@tanstack/react-query";

import { handle, keyName } from "../components/directory/format";
import { policyName } from "../components/policy/format";
import type { RefusedChange } from "./step-up";

interface Names {
  agent: (id: string | undefined) => string;
  key: (id: string | undefined) => string;
  user: (id: string | undefined) => string;
  policy: (id: string | undefined) => string;
}

type Phrase = (params: Record<string, string>, names: Names) => string;

const V = "/api/console/v1";

/** Exported for its test; keyed `"METHOD /api/console/v1/..."` exactly as the document serves. */
export const PURPOSES: Readonly<Record<string, Phrase>> = {
  [`POST ${V}/access/groups`]: () => "Create a group",
  [`POST ${V}/access/groups/{group_id}`]: () => "Change a group",
  [`POST ${V}/access/groups/{group_id}/delete`]: () => "Delete a group",
  [`POST ${V}/access/groups/{group_id}/members`]: () => "Change a group's members",
  [`POST ${V}/access/groups/{group_id}/roles`]: () => "Change a group's roles",
  [`POST ${V}/access/users/{principal_id}/roles`]: (p, n) => `Change the roles of ${n.user(p.principal_id)}`,
  [`POST ${V}/account/requests`]: () => "Make a request about your account's data",
  [`POST ${V}/account/requests/resolve`]: () => "Resolve a request about an account's data",
  [`POST ${V}/agents/{principal_id}/credentials/issue`]: (p, n) => `Issue an API key for ${n.agent(p.principal_id)}`,
  [`POST ${V}/agents/{principal_id}/credentials/{credential_id}/delete`]: (p, n) =>
    `Delete ${n.key(p.credential_id)} for ${n.agent(p.principal_id)}`,
  [`POST ${V}/agents/{principal_id}/credentials/{credential_id}/revoke`]: (p, n) =>
    `Revoke ${n.key(p.credential_id)} for ${n.agent(p.principal_id)}`,
  [`POST ${V}/approval-rules`]: () => "Create an approval rule",
  [`POST ${V}/approval-rules/{rule_id}`]: () => "Change an approval rule",
  [`POST ${V}/approval-rules/{rule_id}/disable`]: () => "Turn off an approval rule",
  [`POST ${V}/approvers/assign`]: () => "Assign an approver",
  [`POST ${V}/approvers/unassign`]: () => "Unassign an approver",
  [`POST ${V}/credentials/issue`]: () => "Issue an API key",
  [`POST ${V}/credentials/{credential_id}/delete`]: (p, n) => `Delete ${n.key(p.credential_id)}`,
  [`POST ${V}/credentials/{credential_id}/revoke`]: (p, n) => `Revoke ${n.key(p.credential_id)}`,
  [`POST ${V}/people/{principal_id}/credentials/issue`]: (p, n) => `Issue a credential for ${n.user(p.principal_id)}`,
  [`POST ${V}/people/{principal_id}/credentials/{credential_id}/revoke`]: (p, n) =>
    `Revoke a credential of ${n.user(p.principal_id)}`,
  [`POST ${V}/people/{principal_id}/deactivate`]: (p, n) => `Deactivate ${n.user(p.principal_id)}`,
  [`POST ${V}/people/{principal_id}/directory-invite`]: (p, n) =>
    `Invite ${n.user(p.principal_id)} to sign in through the directory`,
  [`POST ${V}/people/{principal_id}/directory-invite/revoke`]: (p, n) =>
    `Withdraw the directory invitation of ${n.user(p.principal_id)}`,
  [`POST ${V}/people/{principal_id}/directory-link`]: (p, n) => `Link ${n.user(p.principal_id)} to the directory`,
  [`POST ${V}/people/{principal_id}/directory-unlink`]: (p, n) => `Unlink ${n.user(p.principal_id)} from the directory`,
  [`POST ${V}/people/{principal_id}/email`]: (p, n) => `Change the email address of ${n.user(p.principal_id)}`,
  [`POST ${V}/people/{principal_id}/label`]: (p, n) => `Rename ${n.user(p.principal_id)}`,
  [`POST ${V}/people/{principal_id}/password-link`]: (p, n) => `Issue a set-password code for ${n.user(p.principal_id)}`,
  [`POST ${V}/people/{principal_id}/reactivate`]: (p, n) => `Reactivate ${n.user(p.principal_id)}`,
  [`POST ${V}/people/{principal_id}/scopes/assign`]: (p, n) => `Assign an approval scope to ${n.user(p.principal_id)}`,
  [`POST ${V}/people/{principal_id}/scopes/unassign`]: (p, n) =>
    `Remove an approval scope from ${n.user(p.principal_id)}`,
  [`POST ${V}/people/{principal_id}/sessions/end`]: (p, n) => `End the sessions of ${n.user(p.principal_id)}`,
  [`POST ${V}/policy/{bundle_id}/activate`]: (p, n) => `Activate ${n.policy(p.bundle_id)}`,
  [`POST ${V}/samples`]: () => "Add the sample targets and activate the starter policy",
  [`POST ${V}/samples/refresh`]: () => "Refresh the sample targets and activate the starter policy again",
  [`POST ${V}/settings/password`]: () => "Change your password",
  [`POST ${V}/settings/tokens/issue`]: () => "Create a personal access token",
  [`POST ${V}/settings/tokens/{token_id}/delete`]: () => "Delete a personal access token",
  [`POST ${V}/settings/tokens/{token_id}/revoke`]: () => "Revoke a personal access token",
  [`POST ${V}/spaces/{space_id}/members/assign`]: () => "Add a member to a space",
  [`POST ${V}/spaces/{space_id}/members/unassign`]: () => "Remove a member from a space",
  [`POST ${V}/teammate-invitations`]: () => "Invite a teammate",
  [`POST ${V}/teammate-invitations/{id}/resend`]: () => "Send a teammate invitation again",
  [`POST ${V}/teammate-invitations/{id}/revoke`]: () => "Revoke a teammate invitation",
  [`POST ${V}/tenant/mode`]: () => "Change the workspace's enforcement mode",
  [`POST ${V}/tenant/sign-in`]: () => "Add a sign-in provider",
  [`POST ${V}/tenant/sign-in/{provider_id}/state`]: () => "Turn a sign-in provider on or off",
  // Monitoring connections and reporting sources (#678). A connection or a source is never
  // named by its label: a provider string never reaches this line.
  [`POST ${V}/monitor/agents/{agent_id}/accept`]: () => "Accept an actor's ungoverned paths",
  [`POST ${V}/monitor/agents/{agent_id}/withdraw`]: () => "Withdraw an acceptance of a path",
  [`POST ${V}/monitor/connections/tines`]: () => "Connect Tines",
  [`POST ${V}/monitor/connections/{connection_id}/key`]: () => "Replace a monitoring connection's key",
  [`POST ${V}/monitor/connections/{connection_id}/revoke`]: () => "Revoke a monitoring connection",
  [`POST ${V}/monitor/connections/{connection_id}/egress`]: () => "Record a Tines connection's egress addresses",
  [`POST ${V}/monitor/connections/entra/start`]: () => "Connect Microsoft Entra",
  // A reporting source holds a token, not a key.
  [`POST ${V}/monitor/sources`]: () => "Create a reporting source",
  [`POST ${V}/monitor/sources/{source_id}/rotate`]: () => "Rotate a reporting source's token",
  [`POST ${V}/monitor/sources/{source_id}/revoke`]: () => "Revoke a reporting source",
};

interface Template {
  method: string;
  pattern: RegExp;
  params: string[];
  phrase: Phrase;
}

const SEGMENT = /\{([a-z_]+)\}/g;

function compile(key: string, phrase: Phrase): Template {
  const space = key.indexOf(" ");
  const method = key.slice(0, space);
  const path = key.slice(space + 1);
  const params = [...path.matchAll(SEGMENT)].map((match) => match[1] ?? "");
  const source = path
    .split(SEGMENT)
    .map((part, index) => (index % 2 === 1 ? "([^/]+)" : part.replace(/[.*+?^$()|[\]\\]/g, "\\$&")))
    .join("");
  return { method, pattern: new RegExp(`^${source}$`), params, phrase };
}

// Exact paths first, so `/approval-rules/{rule_id}` never reads `/approval-rules/x/disable`.
const TEMPLATES: Template[] = Object.entries(PURPOSES)
  .map(([key, phrase]) => compile(key, phrase))
  .sort((a, b) => a.params.length - b.params.length);

interface Numbered {
  principal_id?: string | null;
  credential_id?: string | null;
  number?: number | null;
}

/** Where a page's cached answer keeps numbered rows: a query's id and the fields of its answer
 * that hold one row or a list of them. */
type Source = readonly [string, readonly string[]];

const AGENTS: readonly Source[] = [
  ["readAgent", ["agent"]],
  ["listAgents", ["agents"]],
  ["listCredentials", ["principals"]],
];
const KEYS: readonly Source[] = [
  ["readAgent", ["credentials"]],
  ["listCredentials", ["credentials"]],
];
const PEOPLE: readonly Source[] = [
  ["readPerson", ["person"]],
  ["listPeople", ["people"]],
  ["listCredentials", ["principals"]],
];

/** The number a cached row names this id by, or null where nothing the page holds says. */
function cachedNumber(
  queryClient: QueryClient,
  sources: readonly Source[],
  field: "principal_id" | "credential_id",
  id: string,
): number | null {
  for (const [queryId, fields] of sources) {
    for (const [, data] of queryClient.getQueriesData({ queryKey: [{ _id: queryId }] })) {
      if (typeof data !== "object" || data === null) continue;
      const record = data as Record<string, unknown>;
      for (const name of fields) {
        const value = record[name];
        const found = Array.isArray(value) ? (value as Numbered[]) : value !== null && typeof value === "object" ? [value as Numbered] : [];
        for (const row of found) {
          if (row[field] === id && typeof row.number === "number") return row.number;
        }
      }
    }
  }
  return null;
}

function names(queryClient: QueryClient): Names {
  return {
    agent: (id) => {
      if (id === undefined) return "an agent";
      const number = cachedNumber(queryClient, AGENTS, "principal_id", id);
      return number === null ? "an agent" : handle("Agent", number);
    },
    key: (id) => {
      if (id === undefined) return "an API key";
      const number = cachedNumber(queryClient, KEYS, "credential_id", id);
      return number === null ? "an API key" : keyName(number, id).toLowerCase();
    },
    user: (id) => {
      if (id === undefined) return "a user";
      const number = cachedNumber(queryClient, PEOPLE, "principal_id", id);
      return number === null ? "a user" : handle("User", number);
    },
    policy: (id) => (id === undefined ? "a policy" : policyName(id)),
  };
}

/** The change in words, "Revoke key 2 for Agent 3", or null for a change the table does not name. */
export function describe(change: RefusedChange, queryClient: QueryClient): string | null {
  const method = change.method.toUpperCase();
  for (const template of TEMPLATES) {
    if (template.method !== method) continue;
    const match = template.pattern.exec(change.path);
    if (match === null) continue;
    const params: Record<string, string> = {};
    template.params.forEach((name, index) => {
      params[name] = decodeURIComponent(match[index + 1] ?? "");
    });
    return template.phrase(params, names(queryClient));
  }
  return null;
}
