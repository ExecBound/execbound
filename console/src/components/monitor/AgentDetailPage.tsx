// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";

import { readMonitorAgentOptions } from "../../api/@tanstack/react-query.gen";
import type { MonitorAgentDetail } from "../../api/types.gen";
import { useEdition } from "../../edition/context";
import { count, when } from "../../lib/when";
import { PrincipalName } from "../PrincipalName";
import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";
import { Definition, Definitions } from "../ui/Definitions";
import { PageHeading } from "../ui/PageHeading";
import { Table, Td, Th } from "../ui/Table";
import { classWord } from "./Agents";

function capital(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

/** One agent: its identity, every path it reaches, its grants, its findings and observations. */
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
      <Card title="Identity" aside={<Badge tone={warning ? "hold" : "stale"}>{classWord(agent.identity_class)}</Badge>}>
        <Definitions aria-label="Identity">
          <Definition term="Directory object" mono>
            {agent.platform_ref}
          </Definition>
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
            comes from the directory's own object type, never from a tag.
          </p>
        ) : null}
      </Card>
      <Card title="Reach">
        <Table caption="Every path this agent has to a catalog action." density="compact">
          <thead>
            <tr>
              <Th>Action</Th>
              <Th>Path</Th>
              <Th>Certainty</Th>
              <Th>Enforcement</Th>
              <Th>Freshness</Th>
            </tr>
          </thead>
          <tbody>
            {data.reach.length === 0 ? (
              <tr>
                <Td colSpan={5}>No reach established. This does not establish that the agent reaches nothing.</Td>
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
                  <Td>
                    {capital(row.enforcement_mode)}
                    {row.reason_code !== null ? (
                      <small>
                        Accepted {row.accepted_at === null ? "" : when(row.accepted_at)}: {row.reason_code}
                      </small>
                    ) : null}
                  </Td>
                  <Td>
                    {row.gone_at !== null ? `Gone since ${when(row.gone_at)}` : `Valid until ${when(row.valid_until)}`}
                    <small className="mono">Catalog {row.catalog_version}</small>
                  </Td>
                </tr>
              ))
            )}
          </tbody>
        </Table>
        <p className="muted">
          A grant path can never claim an enforced mode: nothing ExecBound operates stands between this agent and its
          own credential. Registering a mapping, a policy and an executor adds a governed path beside the ones above; it
          does not remove them, and the finding stays open until the grant is gone or an administrator accepts it.
        </p>
      </Card>
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
      <Govern data={data} />
    </>
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
          </div>
        </>
      ) : (
        <div className="row">
          <Link to="/agents/$agentId" params={{ agentId: linked }} className="btn">
            Open the governed agent
          </Link>
        </div>
      )}
      <p className="muted">
        Adding a governed path does not close an ungoverned one. Until the directory grant is gone, this agent can
        still reach the action without asking ExecBound anything.
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
          </Definitions>
          <p className="muted">
            Governing an action for this agent also takes an operation mapping in the active policy bundle (
            <Link to="/policy">Policy bundles</Link>) and an executor registration where that mapping hands the act to an
            external executor.
          </p>
        </details>
      ) : (
        <p className="muted">Accepting an ungoverned path is not available in the console yet.</p>
      )}
    </Card>
  );
}
