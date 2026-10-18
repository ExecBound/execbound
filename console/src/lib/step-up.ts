// SPDX-License-Identifier: AGPL-3.0-only
// The step-up asked for in place (decided 28 September 2026). A console change behind the
// server's step-up answers MFA_REQUIRED once the session's factor was verified more than thirty
// minutes ago. The console used to send the person to Account security for a code, and whatever
// they had open on the page was lost; now the fetch wrapper asks for a code over the page and
// sends the refused change again, once.
//
// This module is only the meeting point: the dialog registers the question it asks, and the
// fetch wrapper asks it. It imports nothing, so the wrapper can reach it without a cycle through
// the generated client.

/** Ask for a code; true once one was accepted and the session's new CSRF token is held. */
export type StepUpPrompt = () => Promise<boolean>;

let prompt: StepUpPrompt | null = null;
let asking: Promise<boolean> | null = null;

/** The dialog registers its question while it is mounted; the returned function withdraws it. */
export function registerStepUp(next: StepUpPrompt): () => void {
  prompt = next;
  return () => {
    if (prompt === next) prompt = null;
  };
}

/** Whether anything can ask here; where nothing can, a refusal goes to the security page. */
export function canStepUp(): boolean {
  return prompt !== null;
}

/** A change the step-up refused, as the fetch wrapper sent it: its method and its path. The
 * dialog turns it into words through a fixed table (`step-up-purpose.ts`); nothing of the
 * request's body or of any agent, provider or person string is kept. */
export interface RefusedChange {
  method: string;
  path: string;
}

const NONE: readonly RefusedChange[] = [];
let refused: readonly RefusedChange[] = NONE;
const listeners = new Set<() => void>();

function notify(): void {
  for (const listener of listeners) listener();
}

/** For `useSyncExternalStore`: the changes the open question covers, the same array until one
 * more is refused or the question settles. */
export function refusedChanges(): readonly RefusedChange[] {
  return refused;
}

export function subscribeRefused(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/**
 * Ask once, however many changes were refused together: two refused at the same moment share
 * one question and both are sent again after one code. False when nothing can ask, or when the
 * person cancelled. `change` names what was refused, for the question's first line.
 */
export function stepUp(change?: RefusedChange): Promise<boolean> {
  if (prompt === null) return Promise.resolve(false);
  if (change !== undefined) {
    refused = [...refused, change];
    notify();
  }
  asking ??= prompt().finally(() => {
    asking = null;
    refused = NONE;
    notify();
  });
  return asking;
}
