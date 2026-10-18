// SPDX-License-Identifier: AGPL-3.0-only
// The console's terms (#678), in a module of their own so only Help's chunk carries them; every
// other word in `./words` loads with the shell. `./words` re-exports this list unchanged.

/**
 * The console's short list of terms, as the console guide prints it (#678). Help's glossary
 * renders this list as it is; a page that needs a term adds it here rather than defining it
 * again. Credentials, invitations and tokens expire; only approvals lapse.
 */
export const TERMS: readonly { term: string; meaning: string }[] = [
  {
    term: "Workspace",
    meaning:
      "One customer's or team's ExecBound: its people, agents, policies and records. The console calls this a workspace; some older pages still say tenant.",
  },
  {
    term: "Space",
    meaning: "A part of a workspace with its own agents, policy and members. A view and a permission boundary, not isolation.",
  },
  { term: "Policy version", meaning: "One immutable version of a space's policy." },
  { term: "Approval rule", meaning: "Which people may decide which held actions." },
  { term: "Impact limit", meaning: "A cap on how many targets a set of actions may reach in a window, shared across agents." },
  {
    term: "Enforcing, Observe only",
    meaning: "The workspace's mode: decisions are applied, or only recorded with what they would have been.",
  },
  { term: "Request", meaning: "What an agent asks ExecBound to do, referenced as EB-12." },
  {
    term: "Held",
    meaning: "A request waiting for a person's approval. Its approval is Waiting for a person, or Waiting for you to someone who can decide it.",
  },
  { term: "Approve, Refuse", meaning: "A person's answer to an approval; recorded as Approved or Refused." },
  { term: "Denied", meaning: "The outcome of a request the policy or a person refused; its reason line says which." },
  {
    term: "Lapsed",
    meaning: "An approval whose deadline passed before anyone decided it. It cannot be used; the agent must send a new request.",
  },
  {
    term: "Stale",
    meaning: "A request whose authority no longer held when it came to run, such as an approval that lapsed or facts that expired.",
  },
  { term: "Observed", meaning: "Decided in observe-only mode; nothing ran." },
  {
    term: "Uncertain outcome (Unsettled, Effect unknown)",
    meaning:
      "Dispatched, with the provider's outcome not yet established. An administrator settles it from evidence; it is never retried without that evidence.",
  },
  {
    term: "Agent 3, User 3",
    meaning: "The workspace's own number for an agent or a person without a name. It means nothing in another workspace.",
  },
  {
    term: "Times",
    meaning: 'Every time names its zone: yours unless you chose UTC under My account. "Today" starts at your midnight in that zone.',
  },
];
