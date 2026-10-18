// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useState } from "react";

import { registerStepUp } from "../lib/step-up";

type Dialog = typeof import("./StepUpDialog")["StepUpDialog"];

/**
 * The step-up asked for in place (decided 28 September 2026). Mounted once under the shell, it
 * registers the question the fetch wrapper asks when a change is refused MFA_REQUIRED, and
 * loads the dialog that asks it the first time it is needed, so no page pays for it before
 * then, an approval link opened cold least of all. A dialog that cannot be loaded answers
 * "not verified", and the page says the change was not made.
 */
export function StepUpHost() {
  const [StepUpDialog, setStepUpDialog] = useState<Dialog | null>(null);
  const [answer, setAnswer] = useState<((verified: boolean) => void) | null>(null);
  // Each question is a fresh dialog, so nothing typed into the last one is still there.
  const [round, setRound] = useState(0);

  useEffect(() => {
    let settle: ((verified: boolean) => void) | null = null;
    const withdraw = registerStepUp(async () => {
      let loaded: Dialog;
      try {
        loaded = (await import("./StepUpDialog")).StepUpDialog;
      } catch {
        return false;
      }
      setStepUpDialog(() => loaded);
      return new Promise<boolean>((resolve) => {
        settle = resolve;
        setRound((value) => value + 1);
        setAnswer(() => resolve);
      });
    });
    return () => {
      withdraw();
      settle?.(false);
    };
  }, []);

  if (StepUpDialog === null) return null;
  return (
    <StepUpDialog
      key={round}
      open={answer !== null}
      onSettled={(verified) => {
        answer?.(verified);
        setAnswer(null);
      }}
    />
  );
}
