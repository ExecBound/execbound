// SPDX-License-Identifier: AGPL-3.0-only
// Hiding and showing the sidebar's setup progress (#678): a display preference in this browser
// for this workspace, which ticks nothing and hides nothing for good. The footer's plain
// "Getting started" row stays whichever way it is set.

import { Button } from "../ui/Button";
import { hideSetupCard, showSetupCard, useSetupCardHidden } from "./setup";

/** Getting started's own control, both ways. */
export function SetupCardToggle({ tenant }: { tenant: string | undefined }) {
  const hidden = useSetupCardHidden(tenant);
  return <p className="setup-foot">
    <Button onClick={() => { if (hidden) showSetupCard(tenant); else hideSetupCard(tenant); }}>
      {hidden ? "Show setup progress in the sidebar" : "Hide setup progress in the sidebar"}
    </Button>
  </p>;
}

/** Help's control, shown only while the card is hidden in this browser. */
export function ShowSetupProgress({ tenant }: { tenant: string | undefined }) {
  const hidden = useSetupCardHidden(tenant);
  if (!hidden) return null;
  return <p className="setup-foot"><Button onClick={() => { showSetupCard(tenant); }}>Show setup progress in the sidebar</Button></p>;
}
