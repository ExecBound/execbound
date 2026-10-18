// SPDX-License-Identifier: AGPL-3.0-only
import { createFileRoute } from "@tanstack/react-router";

import { PersonalSettings } from "../components/settings/PersonalSettings";

export const Route = createFileRoute("/settings")({
  component: PersonalSettings,
});
