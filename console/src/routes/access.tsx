// SPDX-License-Identifier: AGPL-3.0-only
import { createFileRoute } from "@tanstack/react-router";
import { AccessManagement } from "../components/directory/AccessManagement";
import { PageHeading } from "../components/ui/PageHeading";

export const Route = createFileRoute("/access")({ component: AccessRoute });
function AccessRoute() {
  return <><PageHeading title="Groups & roles" lead="Give teams the access they need, and see where each user's permissions come from." /><AccessManagement /></>;
}
