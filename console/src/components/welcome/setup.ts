// SPDX-License-Identifier: AGPL-3.0-only
// Getting started's steps and what the setup read says of them (#678). Every tick is a record
// the server read (`GET /setup`); nothing here writes setup state. The one thing kept in the
// browser is whether this person hid the sidebar's progress card, a display preference only.

import { useSyncExternalStore } from "react";

import type { SampleStatusView, SetupMilestone, SetupView } from "../../api/types.gen";

import type { Step } from "./steps";

export { parseStep, STEPS, type Step } from "./steps";

export const STEP_LABELS: Record<Step, string> = {
  example: "Try an example",
  connect: "Connect an agent",
  verify: "Verify protection",
  controls: "Set your controls",
};

export type SetupKey = SetupMilestone["key"];

/** What the card and Home call the step a Space has left, in the console's words. */
export const NEXT_WORDS: Record<SetupKey, string> = {
  policy: "Activate a policy",
  agent_key: "Connect an agent",
  first_request: "Send a first request",
  reviewer: "Choose a reviewer",
  first_decision: "Decide a held request",
};

export function milestone(setup: SetupView | undefined, key: SetupKey): SetupMilestone | undefined {
  return setup?.milestones.find((item) => item.key === key);
}

function done(setup: SetupView | undefined, key: SetupKey): boolean {
  return milestone(setup, key)?.state === "done";
}

function settled(setup: SetupView | undefined, key: SetupKey): boolean {
  const state = milestone(setup, key)?.state;
  return state === "done" || state === "not_applicable";
}

/**
 * Where Getting started opens with no step in the address. Trying an example comes first only
 * where it can reach a governed decision in this Space: no connection of its own, samples
 * offered, and this Space the one they install into. Without either read it opens as it always
 * did, on the example.
 */
export function openingStep(setup: SetupView | undefined, samples: SampleStatusView | undefined): Step {
  if (samples === undefined || setup?.state !== "ready") return "example";
  if (!setup.connected && samples.offered && setup.samples_here) return "example";
  if (!done(setup, "agent_key")) return "connect";
  if (!done(setup, "first_request")) return "verify";
  return "controls";
}

/** Whether a step's milestones all hold. Trying an example is learning, not setup, so never. */
export function stepDone(step: Step, setup: SetupView | undefined): boolean {
  if (setup?.state !== "ready") return false;
  switch (step) {
    case "example":
      return false;
    case "connect":
      return done(setup, "agent_key");
    case "verify":
      return done(setup, "first_request");
    case "controls":
      return done(setup, "policy") && settled(setup, "reviewer") && settled(setup, "first_decision");
  }
}

// The hidden card is per browser and per workspace; storage that throws reads as not hidden.
const HIDDEN = "execbound.setup-card.hidden.";
const CHANGED = "execbound:setup-card";

export function setupCardHidden(tenant: string | undefined): boolean {
  if (tenant === undefined) return false;
  try {
    return localStorage.getItem(HIDDEN + tenant) === "1";
  } catch {
    return false;
  }
}

export function setSetupCardHidden(tenant: string | undefined, hidden: boolean): void {
  if (tenant === undefined) return;
  try {
    if (hidden) localStorage.setItem(HIDDEN + tenant, "1");
    else localStorage.removeItem(HIDDEN + tenant);
  } catch {
    // The card stays as it was where browser storage is unavailable.
  }
  window.dispatchEvent(new Event(CHANGED));
}

export function hideSetupCard(tenant: string | undefined): void {
  setSetupCardHidden(tenant, true);
}

export function showSetupCard(tenant: string | undefined): void {
  setSetupCardHidden(tenant, false);
}

function subscribe(changed: () => void): () => void {
  window.addEventListener(CHANGED, changed);
  window.addEventListener("storage", changed);
  return () => {
    window.removeEventListener(CHANGED, changed);
    window.removeEventListener("storage", changed);
  };
}

/** Whether the card is hidden in this browser, kept current wherever it changes. */
export function useSetupCardHidden(tenant: string | undefined): boolean {
  return useSyncExternalStore(subscribe, () => setupCardHidden(tenant), () => false);
}
