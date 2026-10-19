// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { lazy, Suspense, useState } from "react";

import { readMonitorAgentOptions } from "../../api/@tanstack/react-query.gen";
import type { MonitorAgentDetail, MonitorDriver, MonitorReach } from "../../api/types.gen";
import { useEdition } from "../../edition/context";
import { count, when } from "../../lib/when";
import { PrincipalName } from "../PrincipalName";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { Definition, Definitions } from "../ui/Definitions";
import { PageHeading } from "../ui/PageHeading";
import { Table, Td, Th } from "../ui/Table";
import { Time } from "../ui/Time";
import { ACCEPTED_ELSEWHERE, reasonWords, sourceWords, TINES_RECIPE } from "./accept";
import { classWord, Removal } from "./Agents";

// Loaded the first time one opens, so the page does not carry the forms.
const AcceptDialog = lazy(async () => ({ default: (await import("./AcceptDialog")).AcceptDialog }));
const WithdrawDialog = lazy(async () => ({ default: (await import("./AcceptDialog")).WithdrawDialog }));

function capital(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

const LEVELS: Record<MonitorDriver["evidence"], string> = {
  declared: "Declared by the directory",
  network: "Seen in its sign-ins",
  joined: "Joined to a Tines tenant",
};

/** One agent: its identity, who drives it, every path it reaches, its grants, its findings and
 * observations. */
export function AgentDetailPage({ agentId }: { agentId: string }) {
  const query = useQuery({
    ...readMonitorAgentOptions({ path: { agent_id: agentId } }),
    throwOnError: (_error, failed) => failed.state.data === undefined,
  });
  const data = query.data;
  if (data === undefined) {
    return (
      <>
        <PageHeading title="Agent" lead="What this agent can reach, through which path, and whether anything governs that path." />
        <p className="muted" role="status">
          Loading the agent
        </p>
      </>
    );
  }
  return <Detail data={data} />;
}

function Detail({ data }: { data: MonitorAgentDetail }) {
  const agent = data.agent;
  const warning = agent.sponsor_state !== "present" && agent.identity_class === "agent_identity";
  const [accepting, setAccepting] = useState(false);
  const [withdrawing, setWithdrawing] = useState<MonitorReach | null>(null);
  const open = data.reach.filter((row) => row.open).length;
  return (
    <>
      <PageHeading
        title={agent.display_name}
        lead="What this agent can reach, through which path, and whether anything governs that path."
        actions={
          <Link to="/monitor" search={{ view: "agents" }} className="btn">
            Back to monitored agents
          </Link>
        }
      />
      {agent.synthetic ? (
        <p className="monitor-note" role="note">
          <Badge tone="accent">Synthetic directory</Badge> This actor comes from the synthetic directory, which exists only in
          ExecBound. It is not real, what it raised is never sent anywhere, and it cannot be governed.
        </p>
      ) : null}
      <Card title="Identity" aside={<Badge tone={warning ? "hold" : "stale"}>{classWord(agent.identity_class)}</Badge>}>
        <Definitions aria-label="Identity">
          <Definition term="Source">{sourceWords(agent.source)}</Definition>
          <Definition term="Directory object" mono>
            {agent.platform_ref}
          </Definition>
          {agent.app_ref !== null ? (
            <Definition term="Application ID" mono>
              {agent.app_ref}
            </Definition>
          ) : null}
          <Definition term="Enabled">{agent.enabled === null ? "Not recorded" : agent.enabled ? "Yes" : "No"}</Definition>
          <Definition term="Accountable">
            {agent.sponsor_state === "present"
              ? agent.sponsors.map((sponsor) => `${sponsor.kind} ${sponsor.ref}`).join(", ")
              : agent.sponsor_state === "absent"
                ? "Nobody is recorded as accountable"
                : agent.sponsor_state === "unreadable"
                  ? "The directory refused the read; this is not the same as nobody"
                  : "Not read yet"}
          </Definition>
          <Definition term="Owners">{agent.owner_count === null ? "Could not read" : String(agent.owner_count)}</Definition>
          <Definition term="Blueprint" mono>
            {agent.blueprint_ref ?? "None; this principal holds its own credentials"}
          </Definition>
          <Definition term="Credential kinds on the blueprint">
            {agent.credential_kinds.length > 0 ? agent.credential_kinds.join(", ") : "None recorded"}
          </Definition>
          <Definition term="Linked ExecBound principal">
            {agent.linked_principal_ref !== null ? (
              <PrincipalName principal={agent.linked_principal_ref} link />
            ) : agent.linked_principal_id !== null ? (
              <span className="mono">{agent.linked_principal_id}</span>
            ) : (
              "None; nothing attributes an execution to this agent"
            )}
          </Definition>
          <Definition term="First seen / last seen" mono>
            {when(agent.first_seen_at)} / {when(agent.observed_at)}
          </Definition>
        </Definitions>
        {agent.tags.length > 0 ? (
          <p className="muted">
            The directory tags this principal {agent.tags.join(", ")}. A tag is evidence and is shown; the class above
            comes from the directory&apos;s own object type and its consents, never from a tag.
          </p>
        ) : null}
        <Removal agent={agent} />
      </Card>
      <Drivers data={data} />
      <Card
        title="Reach"
        aside={
          open > 0 && agent.administered ? (
            <Button
              onClick={() => {
                setAccepting(true);
              }}
            >
              Accept the open paths
            </Button>
          ) : null
        }
      >
        <Table caption="Every path this agent has to a catalog action." density="compact">
          <thead>
            <tr>
              <Th>Action</Th>
              <Th>Path</Th>
              <Th>Certainty</Th>
              <Th>Enforcement</Th>
              <Th>Freshness</Th>
              <Th>Acceptance</Th>
            </tr>
          </thead>
          <tbody>
            {data.reach.length === 0 ? (
              <tr>
                <Td colSpan={6}>No reach established. This does not establish that the agent reaches nothing.</Td>
              </tr>
            ) : (
              data.reach.map((row) => (
                <tr key={`${row.action} ${row.path_kind} ${row.path_ref}`}>
                  <Td mono>{row.action}</Td>
                  <Td>
                    {capital(row.path_kind)}
                    <small className="mono">{row.path_ref}</small>
                  </Td>
                  <Td>
                    {capital(row.effective)}
                    {row.effective !== row.certainty ? <small>Was {row.certainty} until the proof lapsed</small> : null}
                  </Td>
                  <Td>{capital(row.enforcement_mode)}</Td>
                  <Td>
                    {row.gone_at !== null ? `Gone since ${when(row.gone_at)}` : `Valid until ${when(row.valid_until)}`}
                    <small className="mono">Catalog {row.catalog_version}</small>
                  </Td>
                  <Td>
                    <Acceptance
                      row={row}
                      administered={agent.administered}
                      onWithdraw={() => {
                        setWithdrawing(row);
                      }}
                    />
                  </Td>
                </tr>
              ))
            )}
          </tbody>
        </Table>
        <p className="muted">
          A grant path can never claim an enforced mode: nothing ExecBound operates stands between this agent and its
          own credential. Registering a mapping, a policy and an executor adds a governed path beside the ones above; it
          does not remove them, and the finding stays open until the grant is gone or an administrator accepts it. An open
          path is a live grant, role or inherited path to a consequential action that nothing governs and no acceptance
          covers.
          {data.assessed ? "" : " No detection profile names a consequential action, so no path is counted as open."}
          {agent.administered ? "" : ` ${ACCEPTED_ELSEWHERE}`}
        </p>
      </Card>
      <History data={data} />
      <Card title="Grants">
        <Table caption="Directory grants this agent holds, and what each reaches." density="compact">
          <thead>
            <tr>
              <Th>Grant</Th>
              <Th>Held on</Th>
              <Th>Reaches</Th>
              <Th>State</Th>
            </tr>
          </thead>
          <tbody>
            {data.grants.length === 0 ? (
              <tr>
                <Td colSpan={4}>No grants collected for this agent.</Td>
              </tr>
            ) : (
              data.grants.map((grant) => (
                <tr key={`${grant.grant_kind} ${grant.resource_ref} ${grant.value} ${grant.path_ref}`}>
                  <Td>
                    <span className="mono">{grant.value}</span>
                    <small>
                      {grant.grant_kind.replaceAll("_", " ")}
                      {grant.resource_ref !== "" ? ` on ${grant.resource_ref}` : ""}
                    </small>
                  </Td>
                  <Td>
                    {grant.inherited ? "The blueprint" : "This agent"}
                    <small className="mono">{grant.path_ref}</small>
                  </Td>
                  <Td>
                    {grant.actions.length > 0 ? (
                      <>
                        <span className="mono">{grant.actions.join(", ")}</span>
                        {grant.breadth !== null ? <small>{capital(grant.breadth)}</small> : null}
                      </>
                    ) : (
                      "Not established"
                    )}
                  </Td>
                  <Td>{grant.gone_at === null ? "Held" : `Gone since ${when(grant.gone_at)}`}</Td>
                </tr>
              ))
            )}
          </tbody>
        </Table>
        {data.unresolved > 0 ? (
          <p className="muted monitor-note">
            {count(data.unresolved, "grant")} the reviewed catalog cannot explain. Those produce no reach row, because a
            row has to name an action and naming one we cannot establish would be a guess. They are shown here so the
            gap is visible rather than counted as nothing.
          </p>
        ) : null}
      </Card>
      <Card title="Findings about this agent">
        <Table caption="Findings about this agent." density="compact">
          <thead>
            <tr>
              <Th>Recorded</Th>
              <Th>Rule</Th>
              <Th>Title</Th>
              <Th>State</Th>
            </tr>
          </thead>
          <tbody>
            {data.findings.length === 0 ? (
              <tr>
                <Td colSpan={4}>No findings about this agent.</Td>
              </tr>
            ) : (
              data.findings.map((finding) => (
                <tr key={finding.finding_id}>
                  <Td mono>{when(finding.created_at)}</Td>
                  <Td mono>{finding.rule_version}</Td>
                  <Td>
                    <Link to="/monitor" search={{ view: "findings", state: "all", open: finding.finding_id }}>
                      {finding.title}
                    </Link>
                  </Td>
                  <Td>{finding.acknowledged_at === null ? "Open" : `Acknowledged ${when(finding.acknowledged_at)}`}</Td>
                </tr>
              ))
            )}
          </tbody>
        </Table>
      </Card>
      <Card title="Observations">
        <Table caption="Observations attributed to this agent by its directory object identifier." density="compact">
          <thead>
            <tr>
              <Th>Occurred</Th>
              <Th>Kind</Th>
              <Th>Action</Th>
              <Th>Outcome</Th>
            </tr>
          </thead>
          <tbody>
            {data.observations.length === 0 ? (
              <tr>
                <Td colSpan={4}>No observations attributed to this agent.</Td>
              </tr>
            ) : (
              data.observations.map((item, index) => (
                <tr key={`${item.occurred_at} ${String(index)}`}>
                  <Td mono>{when(item.occurred_at)}</Td>
                  <Td>{item.kind.replaceAll("_", " ")}</Td>
                  <Td>{item.action ?? item.operation_name ?? "Not applicable"}</Td>
                  <Td>{item.outcome ?? "Not applicable"}</Td>
                </tr>
              ))
            )}
          </tbody>
        </Table>
      </Card>
      {agent.synthetic ? null : <Govern data={data} />}
      <Suspense fallback={null}>
        {accepting ? (
          <AcceptDialog
            agentId={agent.agent_id}
            name={agent.display_name}
            onClose={() => {
              setAccepting(false);
            }}
          />
        ) : null}
        {withdrawing !== null ? (
          <WithdrawDialog
            agentId={agent.agent_id}
            row={withdrawing}
            onClose={() => {
              setWithdrawing(null);
            }}
          />
        ) : null}
      </Suspense>
    </>
  );
}

/** A path's acceptance: in force with its reason and expiry, expired, or none; and Withdraw for
 * one that stands, where the reader may withdraw it. */
function Acceptance({
  row,
  administered,
  onWithdraw,
}: {
  row: MonitorReach;
  administered: boolean;
  onWithdraw: () => void;
}) {
  if (row.reason_code === null) return <>{row.open ? "Open" : "None"}</>;
  return (
    <>
      {row.accepted ? "Accepted" : "Acceptance expired"}
      <small>{reasonWords(row.reason_code)}</small>
      {row.expires_at !== null ? (
        <small>
          {row.accepted ? "Until" : "Expired"} <Time at={row.expires_at} />
        </small>
      ) : (
        <small>No expiry</small>
      )}
      {row.accepted_by_ref !== null ? (
        <small>
          By <PrincipalName principal={row.accepted_by_ref} kind="ADMIN" />
        </small>
      ) : null}
      {administered ? <Button onClick={onWithdraw}>Withdraw</Button> : null}
    </>
  );
}

/** Who drives the actor and how that is known (#355), kept apart from what it can reach. */
function Drivers({ data }: { data: MonitorAgentDetail }) {
  const agent = data.agent;
  const live = data.drivers.filter((row) => row.gone_at === null);
  const tines = data.drivers.some((row) => row.platform_kind === "tines" && row.gone_at === null);
  return (
    <Card title="Driver">
      {live.length === 0 ? (
        <p>
          Unattributed: nothing in the directory, its sign-ins or a Tines tenant names what drives this actor. This is not
          the same as nothing driving it.
        </p>
      ) : null}
      {data.drivers.length > 0 ? (
        <Table caption="Evidence of what drives this actor, strongest first." density="compact">
          <thead>
            <tr>
              <Th>Driver</Th>
              <Th>Evidence</Th>
              <Th>Seen</Th>
            </tr>
          </thead>
          <tbody>
            {data.drivers.map((row) => (
              <tr key={`${row.evidence} ${row.platform_ref}`}>
                <Td>
                  {row.label}
                  {row.source !== null ? (
                    <small>
                      From the catalog
                      {row.retrieved !== null ? `, read ${row.retrieved}` : ""}
                    </small>
                  ) : null}
                  {row.story_ids.length > 0 ? (
                    <small>
                      Stories in your Tines tenant that use a credential allowed to call Microsoft Graph or Microsoft sign-in:{" "}
                      <span className="mono">{row.story_ids.join(", ")}</span>
                      {row.stories_capped ? " (at least)" : ""}
                    </small>
                  ) : null}
                  {row.unrestricted_credentials !== null && row.unrestricted_credentials > 0 ? (
                    <small>{count(row.unrestricted_credentials, "credential")} with no host restriction, never joined</small>
                  ) : null}
                </Td>
                <Td>{LEVELS[row.evidence]}</Td>
                <Td>
                  {row.gone_at !== null ? (
                    <>
                      Gone since <Time at={row.gone_at} />
                    </>
                  ) : (
                    <>
                      <Time at={row.first_seen_at} /> to <Time at={row.last_seen_at} />
                    </>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : null}
      {agent.user_agent_hint !== null ? (
        <p className="muted">
          Its newest sign-in said its client was <span className="mono">{agent.user_agent_hint}</span>. A client chooses
          what it says, so this is a hint and not evidence.
        </p>
      ) : null}
      {tines ? <p className="muted">{TINES_RECIPE} The egress address may be shared with other Tines tenants.</p> : null}
      <p className="muted">
        {data.driver_gaps.unattributable.length > 0
          ? `${data.driver_gaps.unattributable.join(" and ")} publish no stable egress, so their actors cannot be attributed by network. `
          : ""}
        {data.driver_gaps.pending.length > 0
          ? `${data.driver_gaps.pending.join(" and ")} are not in the egress catalog yet (version ${data.driver_gaps.catalog_version}).`
          : ""}
      </p>
    </Card>
  );
}

/** Every acceptance of this actor's paths and its withdrawal, newest first. */
function History({ data }: { data: MonitorAgentDetail }) {
  if (data.acceptances.length === 0) return null;
  return (
    <Card title="Acceptance history">
      <Table caption="Every acceptance of this actor's paths and every withdrawal, newest first." density="compact">
        <thead>
          <tr>
            <Th>When</Th>
            <Th>Change</Th>
            <Th>Path</Th>
            <Th>Reason</Th>
            <Th>By</Th>
          </tr>
        </thead>
        <tbody>
          {data.acceptances.map((row, index) => (
            <tr key={`${row.recorded_at} ${String(index)}`}>
              <Td>
                <Time at={row.recorded_at} />
              </Td>
              <Td>
                {row.change === "accepted" ? "Accepted" : "Withdrawn"}
                {row.expires_at !== null ? (
                  <small>
                    Until <Time at={row.expires_at} />
                  </small>
                ) : null}
              </Td>
              <Td>
                <span className="mono">{row.action}</span>
                <small>
                  {row.path_kind} <span className="mono">{row.path_ref}</span>
                </small>
              </Td>
              <Td>{row.reason_code !== null ? reasonWords(row.reason_code) : "Not applicable"}</Td>
              <Td>{row.recorded_by_ref !== null ? <PrincipalName principal={row.recorded_by_ref} kind="ADMIN" /> : "An administrator"}</Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </Card>
  );
}

/**
 * Governing happens on the agent's own page, which resolves a discovered agent by this id and
 * offers to govern it or bind it, and keeps the show-once key there (#678). An agent already
 * linked opens the agent that governs it. The operator commands are offered only where the
 * reader can run them.
 */
function Govern({ data }: { data: MonitorAgentDetail }) {
  const agent = data.agent;
  const { operatorCommands } = useEdition();
  const linked = agent.linked_principal_id;
  return (
    <Card title="Govern this agent">
      {linked === null ? (
        <>
          <p>
            Governing creates an ExecBound agent for this directory agent, binds the two and issues its first API key, on
            the agent&apos;s page. A governed path is added beside the paths above; it does not close them.
          </p>
          <div className="row">
            <Link to="/agents/$agentId" params={{ agentId: agent.agent_id }} className="btn btn-primary">
              Govern this agent
            </Link>
            <Link to="/agents/$agentId" params={{ agentId: agent.agent_id }}>
              Bind to an existing agent
            </Link>
            <Link to="/policy">Govern this action</Link>
          </div>
        </>
      ) : (
        <div className="row">
          <Link to="/agents/$agentId" params={{ agentId: linked }} className="btn">
            Open the governed agent
          </Link>
          <Link to="/policy">Govern this action</Link>
        </div>
      )}
      <p className="muted">
        Adding a governed path does not close an ungoverned one. Until the directory grant is gone, this agent can
        still reach the action without asking ExecBound anything. Accepting a path, above, records that the organization
        lives with it.
      </p>
      {operatorCommands ? (
        <details>
          <summary>Operator commands</summary>
          <Definitions aria-label="Operator commands">
            <Definition term="Link this agent">
              <code>
                monitor link-agent --connection {agent.connection_id} --agent {agent.platform_ref} --principal
                &lt;principal&gt;
              </code>
            </Definition>
            <Definition term="Accept a path instead">
              <code>
                monitor accept-reach --connection {agent.connection_id} --agent {agent.platform_ref} --action
                &lt;action&gt; --path-kind &lt;kind&gt; --path &lt;path&gt; --reason &lt;CODE&gt;
              </code>
            </Definition>
            <Definition term="Withdraw an acceptance">
              <code>
                monitor withdraw-reach --connection {agent.connection_id} --agent {agent.platform_ref} --action
                &lt;action&gt; --path-kind &lt;kind&gt; --path &lt;path&gt;
              </code>
            </Definition>
          </Definitions>
          <p className="muted">
            Governing an action for this agent also takes an operation mapping in the active policy bundle (
            <Link to="/policy">Policy bundles</Link>) and an executor registration where that mapping hands the act to an
            external executor.
          </p>
        </details>
      ) : null}
    </Card>
  );
}
