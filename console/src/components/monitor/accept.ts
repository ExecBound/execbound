// SPDX-License-Identifier: AGPL-3.0-only
// The words of Scout's to-do list (#355, step 4): why an administrator accepts an ungoverned
// path, for how long, who drives an actor, and where its access is removed. Every value the
// server sends here is one of its fixed codes; a code the command line recorded outside the
// console's list is shown as it was written.

import type { MonitorAgentRow, MonitorDriverSummary } from "../../api/types.gen";

export const REASONS = {
  COMPENSATING_CONTROL: "Another control covers this path",
  VENDOR_MANAGED: "The vendor manages this application",
  BUSINESS_REQUIRED: "The business needs this access as it is",
  GOVERNANCE_PLANNED: "Governing it is planned",
  BREAK_GLASS: "Emergency access",
} as const;

export type Reason = keyof typeof REASONS;

export const REASON_CODES = Object.keys(REASONS) as Reason[];

/** The periods an acceptance made here lasts, in days; it always expires. */
export const PERIODS = [30, 90, 180, 365] as const;

export type Period = (typeof PERIODS)[number];

export const DEFAULT_PERIOD: Period = 90;

/** A reason code in words, or the code itself where the console's list does not hold it. */
export function reasonWords(code: string): string {
  return code in REASONS ? REASONS[code as Reason] : code;
}

// A joined row names every story in the Tines tenant that uses a credential allowed to call
// Microsoft Graph or Microsoft sign-in, never one story and never a credential for this
// directory (T6.40), and is worded as the threat model words it.
const EVIDENCE: Record<MonitorDriverSummary["evidence"], string> = {
  declared: "declared by the directory",
  network: "seen in its sign-ins",
  joined: "stories that use a credential allowed to call Microsoft Graph or Microsoft sign-in",
};

/** One driver row in words: its platform's name and how it is known. */
export function driverWords(driver: MonitorDriverSummary): string {
  return `${driver.label}, ${EVIDENCE[driver.evidence]}`;
}

/** Where an actor came from, as the page names a source. */
export function sourceWords(source: MonitorAgentRow["source"]): string {
  switch (source) {
    case "entra_agent_id":
      return "Microsoft Entra";
    case "tines":
      return "Tines";
    case "fixture":
      return "Synthetic directory";
  }
}

/** Whether a row is driven from Tines: a Tines story, or a directory actor a Tines tenant's
 * egress or credentials attribute by any live row the reader may see, its strongest or not. */
export function tinesDriven(agent: Pick<MonitorAgentRow, "identity_class" | "tines_driven">): boolean {
  return agent.identity_class === "tines_story" || agent.tines_driven;
}

/** Why Accept and Withdraw are not offered: the list and an actor's page are the workspace's, an
 * acceptance its connection's Space's, made by an administrator of that Space. */
export const ACCEPTED_ELSEWHERE = "Its paths are accepted or withdrawn by an administrator of its Space.";

/** The pointer the Inventory view gives too: no external address. */
export const TINES_RECIPE =
  "To put this story's action behind ExecBound, follow the Tines Gate recipe in integrations/tines/README.md of your ExecBound release.";
