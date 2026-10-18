// SPDX-License-Identifier: AGPL-3.0-only
// Whether this deployment has an assistant, and whether this tenant turned it on. They are
// different answers and the console must not conflate them.
//
// **Whether it exists** comes with the session the shell already reads: the operator either
// configured a model or did not, and without one there are no assistant addresses at all
// (#330). Reading it from the session means the sidebar, the top bar and the palette ask
// nothing of their own, and a console built for a deployment without an assistant shows no
// door to it, not even for a frame.
//
// **Whether the tenant turned it on** is `GET /assistant/settings`, which is the
// administrator's route. An approver cannot read it and is not asked to: they see the Ask
// page, and a tenant with the switch off refuses their question with `ASSISTANT_OFF`, which
// is the same answer said once rather than guessed at twice.

import { useQuery } from "@tanstack/react-query";

import { readAssistantSettingsOptions } from "../api/@tanstack/react-query.gen";
import type { Settings } from "../api/types.gen";
import { useSession } from "./session";

export interface Assistant {
  /** The operator configured a model. Without this nothing about the assistant is shown. */
  exists: boolean;
  /** The tenant's switch, as an administrator reads it; false for anyone who cannot. */
  enabled: boolean;
  /** Whether the switch is knowable here at all, which only an administrator's session is. */
  known: boolean;
  settings?: Settings;
}

export function useAssistant(): Assistant {
  const session = useSession();
  const exists = session.assistant;
  const admin = session.role === "ADMIN";
  const query = useQuery({
    ...readAssistantSettingsOptions(),
    enabled: exists && admin,
    retry: false,
    staleTime: Number.POSITIVE_INFINITY,
    throwOnError: false,
  });
  if (!exists) return { exists: false, enabled: false, known: true };
  if (!admin) return { exists: true, enabled: false, known: false };
  if (query.data === undefined) return { exists: true, enabled: false, known: false };
  return { exists: true, enabled: query.data.enabled, known: true, settings: query.data };
}

/** The label a turn is listed and titled by; a contextual turn has no question of its own. */
export const CONTEXT_WORDS: Record<string, string> = {
  question: "Question",
  execution: "Decision",
  approval: "Approval",
  finding: "Finding",
  agent: "Agent",
  policy_change: "Policy change",
};

export function turnTitle(turn: { context_kind: string; question: string | null }): string {
  if (turn.question !== null && turn.question !== "") return turn.question;
  const word = CONTEXT_WORDS[turn.context_kind] ?? "Record";
  return `${word} explained`;
}

/**
 * What a turn that ended without an answer says, written here rather than by the model. The
 * recommendation case says what it says on purpose: the explanation is withheld, and the
 * facts on the page are still the record.
 */
export const REFUSALS: Record<string, string> = {
  TOOL_LIMIT: "The assistant read as much as it may for one question and stopped.",
  TIME_LIMIT: "The assistant took too long and stopped.",
  TOKEN_LIMIT: "The answer grew past what one turn allows and stopped.",
  REFUSED_SECRET:
    "Something that looked like a credential was found while reading, so nothing was sent and " +
    "the turn was stopped.",
  RECOMMENDATION: "The explanation could not be shown.",
  MODEL_ERROR: "The assistant could not answer.",
  ABANDONED: "The assistant stopped before it answered.",
};
