// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";

import { readTenantOptions } from "../../api/@tanstack/react-query.gen";
import type { TenantSettingsView } from "../../api/types.gen";
import { useEdition } from "../../edition/context";
import { useAssistant } from "../../lib/assistant";
import { can, useSession } from "../../lib/session";
import { count, prefix, when } from "../../lib/when";
import { PrincipalName } from "../PrincipalName";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { WorkspaceService } from "../settings/WorkspaceService";
import { Card } from "../ui/Card";
import { Definition, Definitions } from "../ui/Definitions";
import { PageHeading } from "../ui/PageHeading";
import { AssistantDialog } from "./AssistantDialog";
import { ApprovalReadiness } from "./ApprovalReadiness";
import { Changed, WorkspaceOnly } from "./ChangeNotes";
import { MODE_WORDS, ModeDialog } from "./ModeDialog";
import { SignInCard } from "./SignInCard";
import { StopDialog } from "./StopDialog";
import { WorkspaceTokens } from "./WorkspaceTokens";

/**
 * The tenant page (#253): the mode, the deadline and the stop, each changed with a reason and a
 * confirmation through the functions the command line calls, and the read-only block. An
 * administrator's page; the server refuses anyone else, and the sidebar never shows it to them.
 *
 * The mode, the deadline, the stop and the assistant switch are each one value for every space,
 * so only a workspace administrator changes them (0074): an administrator narrowed to spaces
 * reads every card, because their own work depends on knowing that a stop is in force or that
 * the workspace only observes, and is offered no control to change one.
 */
export function TenantSettings() {
  const query = useQuery({
    ...readTenantOptions(),
    throwOnError: (_error, failed) => failed.state.data === undefined,
  });
  return (
    <>
      <PageHeading
        title="Workspace settings"
        lead="Set enforcement mode, approval deadlines and sign-in options for this workspace. Security changes require a reason and are recorded in the audit history."
      />
      {query.data !== undefined ? (
        <Sections view={query.data} />
      ) : (
        <p className="muted" role="status">
          Loading the tenant
        </p>
      )}
    </>
  );
}

function Sections({ view }: { view: TenantSettingsView }) {
  // Workspace-wide `access.manage`, which an administrator narrowed to spaces does not hold.
  const workspace = can(useSession(), "access.manage");
  return (
    <>
      <div className="cards">
        <ModeCard view={view} workspace={workspace} />
        <ApprovalReadiness view={view} workspace={workspace} />
        <StopCard view={view} workspace={workspace} />
        <WorkspaceTokens />
        <AssistantCard workspace={workspace} />
        <SignInCard />
        <WorkspaceService />
      </div>
      <About view={view} />
    </>
  );
}

function ModeCard({ view, workspace }: { view: TenantSettingsView; workspace: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <Card title="Enforcement mode">
      <p>
        <Badge tone={view.mode.value === "OBSERVE" ? "obs" : "allow"}>{MODE_WORDS[view.mode.value]}</Badge>
      </p>
      <Changed change={view.mode.changed} never="Never changed from the default." />
      <p className="muted">
        In Observe only, decisions are recorded with their would-be effect and nothing is dispatched, approved,
        reserved or claimed.
      </p>
      {workspace ? (
        <div className="row">
          <Button
            onClick={() => {
              setOpen(true);
            }}
          >
            Change mode
          </Button>
        </div>
      ) : (
        <WorkspaceOnly what="changes the enforcement mode" />
      )}
      {open ? (
        <ModeDialog
          open
          onClose={() => {
            setOpen(false);
          }}
          current={view.mode.value}
        />
      ) : null}
    </Card>
  );
}

function StopCard({ view, workspace }: { view: TenantSettingsView; workspace: boolean }) {
  const [open, setOpen] = useState(false);
  const stop = view.stop;
  return (
    <Card title="Emergency stop">
      {stop !== null ? (
        <>
          <p>
            <Badge tone="deny">Stop active</Badge>
          </p>
          <p className="muted">
            Since <span className="mono">{when(stop.stopped_at)}</span> by{" "}
            {stop.stopped_by_ref !== null ? <PrincipalName principal={stop.stopped_by_ref} /> : "an administrator"}
            {stop.committed !== null ? ` · ${count(stop.committed, "committed dispatch", "committed dispatches")} recorded at activation` : ""}.
          </p>
          <p className="muted">Reason: {stop.reason}</p>
          <p className="muted">
            A stop can leave committed operations to settle; the uncertain queue on <Link to="/activity">Activity</Link>{" "}
            lists them.
          </p>
        </>
      ) : (
        <>
          <p>
            <Badge tone="stale">Not active</Badge>
          </p>
          <p className="muted">
            Activating the stop refuses every new action, approval decision and dispatch attempt for this tenant
            until an administrator resumes it. Operations already committed stay committed and wait in the uncertain
            queue on <Link to="/activity">Activity</Link>.
          </p>
        </>
      )}
      {workspace ? (
        <div className="row">
          <Button
            variant={stop !== null ? "primary" : "danger"}
            onClick={() => {
              setOpen(true);
            }}
          >
            {stop !== null ? "Resume the tenant" : "Activate the emergency stop"}
          </Button>
        </div>
      ) : (
        <WorkspaceOnly what="activates or lifts the emergency stop" />
      )}
      {open ? (
        <StopDialog
          open
          onClose={() => {
            setOpen(false);
          }}
          active={stop !== null}
        />
      ) : null}
    </Card>
  );
}

function AssistantCard({ workspace }: { workspace: boolean }) {
  const assistant = useAssistant();
  const [open, setOpen] = useState(false);
  // Absent means the feature does not exist (#330): a deployment whose operator configured no
  // model shows no card at all, rather than a switch that could never be turned on.
  if (!assistant.exists || assistant.settings === undefined) return null;
  const { enabled, model, provider_retention: retention } = assistant.settings;
  return (
    <Card title="Assistant">
      <p>
        <Badge tone={enabled ? "allow" : "stale"}>{enabled ? "On" : "Off"}</Badge>
      </p>
      <p className="muted">
        Users of this tenant can ask questions about its records in plain words. The assistant
        reads only what the person asking can read, changes nothing, and never says whether to
        approve or refuse.
      </p>
      <p className="muted">{retention}</p>
      {workspace ? (
        <div className="row">
          <Button
            onClick={() => {
              setOpen(true);
            }}
          >
            {enabled ? "Turn the assistant off" : "Turn the assistant on"}
          </Button>
        </div>
      ) : (
        <WorkspaceOnly what="turns the assistant on or off" />
      )}
      {open ? (
        <AssistantDialog
          open
          onClose={() => {
            setOpen(false);
          }}
          enabled={enabled}
          retention={retention}
          model={model}
        />
      ) : null}
    </Card>
  );
}

function About({ view }: { view: TenantSettingsView }) {
  const monitoring = view.monitoring;
  const { TenantDefinitions } = useEdition();
  return (
    <Card title="What this tenant is">
      <Definitions aria-label="What this tenant is">
        <Definition term="Tenant">{view.tenant_name}</Definition>
        <Definition term="Tenant id" mono>
          {view.tenant_id}
        </Definition>
        <Definition term="Active bundle">
          {view.bundle_id !== null ? (
            <Link to="/policy" className="mono">
              {prefix(view.bundle_id)}
            </Link>
          ) : (
            "None: admission fails closed"
          )}
        </Definition>
        <TenantDefinitions />
        <Definition term="Monitoring">
          {count(monitoring.sources, "source")}: {monitoring.reporting} reporting, {monitoring.stale} stale ·{" "}
          {count(monitoring.open_findings, "open finding")} · <Link to="/monitor">Monitoring</Link>
        </Definition>
      </Definitions>
    </Card>
  );
}

