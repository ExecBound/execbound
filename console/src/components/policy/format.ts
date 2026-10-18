// SPDX-License-Identifier: AGPL-3.0-only
// How the Policy pages print a bundle's parts (#333). Every value here is text: a
// state becomes a word and a tone, a window becomes a phrase, a rule's effect becomes the word
// the badge leads with. Nothing builds a link or a query from data.

import type { ActivationNote, BundlePreviewView } from "../../api/types.gen";
import { refName } from "../directory/handles";
import type { Tone } from "../ui/Badge";

export type BundleState = "DRAFT" | "VALIDATED" | "ACTIVE" | "RETIRED";

/** The word and the colour for a lifecycle state. Colour is reserved for decisions, so a
 *  bundle's state borrows the decision tones: active is allowed, retired is stale. */
export const STATE: Record<BundleState, { word: string; tone: Tone }> = {
  DRAFT: { word: "Draft", tone: "obs" },
  VALIDATED: { word: "Validated", tone: "hold" },
  ACTIVE: { word: "Active", tone: "allow" },
  RETIRED: { word: "Retired", tone: "stale" },
};

/**
 * The word a version's state reads as where the reader is looking (#678): an active version that
 * is not the selection of the Space being read is active in another Space, and under All spaces,
 * where no Space is selected, it is simply active.
 */
export function stateWord(state: BundleState, active: boolean, allSpaces: boolean): string {
  return state === "ACTIVE" && !active && !allSpaces ? "Active in another Space" : STATE[state].word;
}

/** The word and the colour for what a rule does. The word leads; the dot repeats it. */
export const EFFECT: Record<string, { word: string; tone: Tone }> = {
  ALLOW: { word: "Allow", tone: "allow" },
  DENY: { word: "Deny", tone: "deny" },
  REVIEW: { word: "Review", tone: "hold" },
};

/** The word and the colour for a decision effect, as the preview and the drawer print them. */
export const DECISION: Record<string, { word: string; tone: Tone }> = {
  ALLOW: { word: "Allowed", tone: "allow" },
  DENY: { word: "Denied", tone: "deny" },
  REQUIRE_APPROVAL: { word: "Held for a person", tone: "hold" },
  OBSERVE: { word: "Observed", tone: "obs" },
};

export type Window = "1h" | "24h" | "7d" | "30d";

export const WINDOWS: readonly [Window, string][] = [
  ["1h", "the last hour"],
  ["24h", "the last 24 hours"],
  ["7d", "the last 7 days"],
  ["30d", "the last 30 days"],
];

export function isWindow(value: string): value is Window {
  return WINDOWS.some(([key]) => key === value);
}

export type Direction = "wider" | "narrower" | "unclear" | "none";

/** The word and the colour for what a change does, as the rules read. The word leads; the
 *  colour repeats it. A change to a note alone carries no badge. */
export const DIRECTION: Record<Direction, { word: string; tone: Tone } | null> = {
  wider: { word: "Allows more", tone: "allow" },
  narrower: { word: "Allows less", tone: "deny" },
  unclear: { word: "Check", tone: "hold" },
  none: null,
};

/** The short words a preview summary uses for each effect, as in "2 allowed to held". */
export const SHORT_EFFECT: Record<string, string> = {
  ALLOW: "allowed",
  DENY: "denied",
  REQUIRE_APPROVAL: "held",
  OBSERVE: "observed",
};

function shortEffect(effect: string): string {
  return SHORT_EFFECT[effect] ?? decisionWord(effect).toLowerCase();
}

function windowPhrase(window: string): string {
  return WINDOWS.find(([key]) => key === window)?.[1] ?? window;
}

/**
 * One line for what a preview found, which the activation step and its dialog quote. Changes
 * are grouped by the effect they move from and to, most first; a change that keeps its effect
 * but not its approval requirement is counted on its own. Plain text, built from fixed words.
 */
export function changeSummary(preview: BundlePreviewView): string {
  if (!preview.available) {
    return "The preview could not be computed, so what would change is not known here.";
  }
  const over = `Previewed over ${windowPhrase(preview.window)}`;
  if (preview.considered === 0) {
    return `${over}: no recorded decision in that window, so nothing here shows what would change.`;
  }
  const recorded = `recorded decision${preview.considered === 1 ? "" : "s"}`;
  if (preview.changed.length === 0) {
    return `${over}: none of ${String(preview.considered)} ${recorded} would change.`;
  }
  const groups = new Map<string, number>();
  let requirement = 0;
  for (const change of preview.changed) {
    if (change.baseline_effect === change.candidate_effect) {
      requirement += 1;
      continue;
    }
    const key = `${shortEffect(change.baseline_effect)} to ${shortEffect(change.candidate_effect)}`;
    groups.set(key, (groups.get(key) ?? 0) + 1);
  }
  const parts = [...groups.entries()]
    .sort((left, right) => right[1] - left[1])
    .map(([words, count]) => `${String(count)} ${words}`);
  if (requirement > 0) parts.push(`${String(requirement)} with a different approval requirement`);
  return `${over}: ${String(preview.changed.length)} of ${String(preview.considered)} ${recorded} would change (${parts.join(", ")}).`;
}

/** A decision effect as a word, falling back to the code itself lowercased and spaced. */
export function decisionWord(effect: string): string {
  return DECISION[effect]?.word ?? effect.replaceAll("_", " ").toLowerCase();
}

/** `endpoint.isolate, identity.disable` from a rule's action list. */
export function actionList(actions: readonly string[]): string {
  return actions.join(", ");
}

/** The catalog action a mapping serves: its ref, unless the ref is another name for one. */
export function servedAction(mapping: { operation_ref: string; action?: string | null }): string {
  return mapping.action ?? mapping.operation_ref;
}

/** A mapping's operation as the Mappings table names it: `isolate.corroborated
 *  (endpoint.isolate)` when its ref is another name for an action, else the ref alone. */
export function mappingName(mapping: { operation_ref: string; action?: string | null }): string {
  return mapping.action ? `${mapping.operation_ref} (${mapping.action})` : mapping.operation_ref;
}

/** Who activated a policy, named the way every page names a person (#678): their label,
 *  else "User N", else "User" and their id's first eight characters. Every part is text the
 *  page renders as text. */
export function activatedBy(note: Pick<ActivationNote, "by_id" | "by_label" | "by_number">): string {
  return refName({ principal_id: note.by_id, label: note.by_label, number: note.by_number }, "ADMIN");
}

/** The button that shows the retired versions the list folds away. */
export function retiredToggle(count: number): string {
  return `Show ${String(count)} retired version${count === 1 ? "" : "s"}`;
}

/** Stable without mutable metadata: the full identity remains in Advanced. */
export function policyName(bundleId: string): string {
  return `Policy version ${bundleId.slice(0, 8)}`;
}

export function duration(seconds: number): string {
  for (const [unit, size] of [["day", 86400], ["hour", 3600], ["minute", 60]] as const) {
    if (seconds >= size && seconds % size === 0) {
      const count = seconds / size;
      return `${String(count)} ${unit}${count === 1 ? "" : "s"}`;
    }
  }
  return `${String(seconds)} second${seconds === 1 ? "" : "s"}`;
}

/** A vocabulary for the typed rule model only. This never parses or translates Cedar. */
export function ruleSentence(sentence: string): string {
  const words: [string, string][] = [
    ["endpoint.lift_isolation", "lifting endpoint isolation"],
    ["endpoint.isolate", "isolating an endpoint"],
    ["identity.revoke_sessions", "revoking identity sessions"],
    ["identity.reset_password", "resetting an identity password"],
    ["identity.disable", "disabling an identity"],
    ["identity.enable", "enabling an identity"],
    ["is_production is true", "the target is in production"],
    ["is_production is false", "the target is outside production"],
    ["role is domain_controller", "the target is a domain controller"],
    ["role is workstation", "the target is a workstation"],
    ["privilege_class", "privilege class"],
    ["incident_status", "incident status"],
    ["incident_severity", "incident severity"],
    ["require_change_at_next_sign_in", "password change at next sign-in"],
    ["domain_controller", "domain controller"],
    ["false_positive", "false positive"],
    ["tier0", "Tier 0"],
  ];
  return words.reduce((text, [from, to]) => text.replaceAll(from, to), sentence)
    .replace(/^Review /, "Require approval for ");
}
