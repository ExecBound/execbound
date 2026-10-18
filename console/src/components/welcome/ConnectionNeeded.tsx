// SPDX-License-Identifier: AGPL-3.0-only
// What an empty Space needs before an agent's request can be decided (#678): the sample targets
// where they can tick something here, the default-Space sentence where they would go elsewhere,
// and otherwise who connects a provider. Getting started's Connect step and the Policies page
// say it the same way, from the same two reads.

import { Link } from "@tanstack/react-router";

import type { SampleStatusView, SetupView } from "../../api/types.gen";
import { OperatorSteps } from "./OperatorSteps";

export const DEFAULT_SPACE_SAMPLES =
  "Sample targets are added to the workspace's default Space, not this one. Switch to it in the sidebar to try them.";

export function ConnectionNeeded({ setup, samples }: { setup: SetupView; samples: SampleStatusView | undefined }) {
  const offered = samples?.offered === true;
  if (offered && setup.samples_here) {
    return <p>Try an example adds sample targets and an active starter policy to this Space. <Link to="/welcome" search={{ step: "example" }}>Try an example</Link></p>;
  }
  return <>
    {offered && setup.default_space_id !== null ? <p>{DEFAULT_SPACE_SAMPLES}</p> : null}
    <OperatorSteps />
  </>;
}
