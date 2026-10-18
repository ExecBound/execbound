// SPDX-License-Identifier: AGPL-3.0-only
import { createFileRoute } from "@tanstack/react-router";

import { TenantSettings } from "../components/tenant/TenantSettings";

export const Route = createFileRoute("/tenant")({
  component: TenantSettings,
});
