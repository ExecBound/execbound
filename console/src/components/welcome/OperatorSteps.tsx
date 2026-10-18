// SPDX-License-Identifier: AGPL-3.0-only
// Who connects a provider, and how (#678). On a self-hosted console the people who administer it
// also run its server, so the block names the commands with this workspace's and this Space's
// identifiers; on a service the console cannot run them, so it names the service operator. Core
// copy names no hosted address: support and documentation come from the deployment's own links.

import { useEdition } from "../../edition/context";
import { useService, useSession } from "../../lib/session";
import { CopyRecipe } from "./CopyRecipe";

/** The operator's instructions, with the two identifiers filled where the session knows them. */
export function operatorInstructions(tenant: string | undefined, space: string | undefined): string {
  const t = tenant ?? "<tenant id>";
  const s = space ?? "<space id>";
  return [
    "# Register a provider account and its action mappings for this Space.",
    "# Run each command on the server with a tenant administrator principal as --actor;",
    "# a Space administrator's principal is refused as the actor.",
    `execbound account-create --tenant ${t} --space ${s} --provider <provider> --actor <admin principal>`,
    `execbound mapping-create --tenant ${t} --account <account id> --action <action> --actor <admin principal>`,
    "# Then register the account's resources and their trusted context:",
    '# Install, "The long way, one command at a time", and Operations, "Provision trusted context".',
    "# To offer sample targets instead: add a sample_providers block to the gateway configuration",
    '# and set EXECBOUND_MOCK_SAMPLE_KEY on the endpoint mock (Operations, "Configuration inventory").',
  ].join("\n");
}

/** "Your service operator connects providers", with the support address where one is set; inline. */
export function ServiceOperatorWords({ children = "Your service operator connects providers for this workspace" }: { children?: string }) {
  const service = useService();
  return <>{children}{service.support_email !== null ? <>: <a href={`mailto:${service.support_email}`}>{service.support_email}</a>.</> : "."}</>;
}

export function ServiceOperatorLine({ children }: { children?: string }) {
  return <p><ServiceOperatorWords>{children}</ServiceOperatorWords></p>;
}

export function OperatorSteps() {
  const { operatorCommands } = useEdition();
  const session = useSession();
  const service = useService();
  if (!operatorCommands) return <ServiceOperatorLine />;
  return <div className="stack operator-steps">
    <p>Your deployment&apos;s operator registers a provider account and its action mappings on the server.</p>
    <CopyRecipe label="Copy instructions for your operator" text={operatorInstructions(session.tenant.id, session.space?.id)} />
    {service.help_url !== null ? <p><a href={service.help_url}>Open the documentation</a></p> : null}
  </div>;
}
