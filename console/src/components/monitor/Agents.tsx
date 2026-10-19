// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { lazy, Suspense, useState } from "react";

import { readMonitorAgentsOptions } from "../../api/@tanstack/react-query.gen";
import type { MonitorAgentRow, MonitorAgents } from "../../api/types.gen";
import { count } from "../../lib/when";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { Table, Td, Th } from "../ui/Table";
import { Time } from "../ui/Time";
import { ACCEPTED_ELSEWHERE, driverWords, sourceWords, TINES_RECIPE, tinesDriven } from "./accept";
import { ENTRA_ENTERPRISE_APPS } from "./connect";

// Loaded the first time it opens, so the list does not carry the form.
const AcceptDialog = lazy(async () => ({ default: (await import("./AcceptDialog")).AcceptDialog }));

export function classWord(identityClass: string): string {
  const lower = identityClass.replaceAll("_", " ");
  return lower.charAt(0).toUpperCase() + lower.slice(1);
}

/** Who is accountable for an agent, in the words the page uses; never "nobody" for a refused read.
 * It takes the number of sponsors, which a finding carries without the sponsors themselves. */
export function accountable(
  agent: Pick<MonitorAgentRow, "sponsor_state" | "identity_class" | "owner_count"> & { sponsor_count: number },
): string {
  switch (agent.sponsor_state) {
    case "present":
      return count(agent.sponsor_count, "sponsor");
    case "absent":
      if (agent.identity_class === "agent_identity") return "Nobody";
      return agent.owner_count !== null && agent.owner_count > 0 ? count(agent.owner_count, "owner") : "Nobody";
    case "unreadable":
      return "Could not read";
    default:
      return "Not read yet";
  }
}

/** What an actor did outside ExecBound in the last thirty days, in the page's words. */
export function didWords(agent: Pick<MonitorAgentRow, "did" | "did_at_least">, assessed: boolean): string {
  if (!assessed) return "Not assessed";
  return agent.did_at_least ? `At least ${String(agent.did)}` : String(agent.did);
}

/** Where an actor's access is removed: Scout never writes to the directory, so the page says where. */
export function Removal({ agent }: { agent: Pick<MonitorAgentRow, "removal" | "app_ref"> }) {
  switch (agent.removal) {
    case "entra":
      return (
        <small>
          <a href={ENTRA_ENTERPRISE_APPS} target="_blank" rel="noopener noreferrer">
            Remove in Entra
          </a>
          {agent.app_ref !== null ? (
            <>
              {" "}
              (Application ID starts with <span className="mono">{agent.app_ref}</span>, then Permissions)
            </>
          ) : (
            " (search for its name, then Permissions)"
          )}
        </small>
      );
    case "azure_resource":
      return <small>Its access is removed on the Azure resource it belongs to.</small>;
    case "blueprint":
      return <small>Its access is removed through its agent identity blueprint.</small>;
    default:
      return null;
  }
}

/** The Agents view, the to-do list (#355): the tenant line that states its own denominator, then
 * every actor in the order the server gives it, what needs attention first. */
export function Agents() {
  const query = useQuery({
    ...readMonitorAgentsOptions(),
    refetchInterval: 30_000,
    throwOnError: (_error, failed) => failed.state.data === undefined,
  });
  const data = query.data;
  if (data === undefined) {
    return (
      <p className="muted" role="status">
        Loading agents
      </p>
    );
  }
  return <AgentsTable data={data} />;
}

function Governed({ agent }: { agent: MonitorAgentRow }) {
  return (
    <Td>
      {count(agent.governed, "governed path")}
      {agent.open_paths > 0 ? <small>{count(agent.open_paths, "open path")}</small> : null}
      {agent.accepted > 0 ? (
        <small>
          {count(agent.accepted, "accepted path")}
          {agent.accepted_until !== null ? (
            <>
              {" "}
              until <Time at={agent.accepted_until} />
            </>
          ) : null}
        </small>
      ) : null}
    </Td>
  );
}

function AgentsTable({ data }: { data: MonitorAgents }) {
  const [accepting, setAccepting] = useState<MonitorAgentRow | null>(null);
  const assessed = data.tenant.assessed;
  const figures: [string, number][] = [
    ["Actors enumerated", data.tenant.enumerated],
    ["With consequential reach", data.tenant.with_reach],
    ["With a governed path", data.tenant.governed],
    ["Unattributed", data.tenant.unattributed],
    ["Reach not established", data.tenant.unestablished],
  ];
  const sources = data.tenant.per_source;
  const synthetic = sources.synthetic > 0;
  return (
    <>
      <p>
        Anything non-human that can act here: agent identities, service principals, managed identities, consented apps
        and Tines stories. What did something consequential outside ExecBound in the last 30 days comes first, then what
        has an open path nothing governs and nobody accepted.
      </p>
      {synthetic ? (
        <p className="monitor-note" role="note">
          <Badge tone="accent">Synthetic directory</Badge> Actors marked so come from the synthetic directory, which exists
          only in ExecBound: none of them is real, what it finds is never sent anywhere, and none can be governed.
          {data.tenant.built_in
            ? ` No detection profile is set, so they are assessed against the built-in sensitive actions: ${data.consequential.join(", ")}. A profile, once set, decides instead, and a real directory is never assessed without one.`
            : ""}
        </p>
      ) : null}
      <dl className="figures" aria-label="Actors the connections could enumerate">
        {figures.map(([label, value]) => (
          <div key={label} className="figure">
            <dt className="figure-label">{label}</dt>
            <dd className="figure-value">{value}</dd>
          </div>
        ))}
      </dl>
      <p className="muted">
        By source: Microsoft Entra {sources.entra}, Tines {sources.tines}
        {synthetic ? `, Synthetic directory ${String(sources.synthetic)}` : ""}. Every number above counts actors the
        connections could enumerate, not the actors that exist; unattributed counts the directory actors with no driver
        evidence, which is not the same as nothing driving them. Microsoft's own endpoint sweep reports agents with no
        identity at all; Graph does not serve them and ExecBound never counts them. Azure RBAC assignments are not served
        by Graph either, so reach into Azure resources is a hole rather than a zero.
        {assessed
          ? ""
          : " No detection profile names a consequential action, so no actor is counted as having consequential reach, and what each did is not assessed."}
      </p>
      <Card title="Actors to work through">
        <Table caption="Actors the connections list, what needs attention first." density="compact">
          <thead>
            <tr>
              <Th>Actor</Th>
              <Th>Class</Th>
              <Th>Driver</Th>
              <Th>Did (30 days)</Th>
              <Th>Consequential reach</Th>
              <Th>Governed</Th>
              <Th>Accountable</Th>
              <Th>Open findings</Th>
              <Th>Act</Th>
            </tr>
          </thead>
          <tbody>
            {data.agents.length === 0 ? (
              <tr>
                <Td colSpan={9}>
                  No actors collected. Register an identity provider connection and run a collection. No actors here does
                  not establish that the directory holds none.
                </Td>
              </tr>
            ) : (
              data.agents.map((agent) => (
                <tr key={agent.agent_id}>
                  <Td>
                    <Link to="/monitor/agents/$agentId" params={{ agentId: agent.agent_id }}>
                      {agent.display_name}
                    </Link>
                    <small className="mono">{agent.platform_ref}</small>
                    {agent.synthetic ? <small>Synthetic directory</small> : <small>{sourceWords(agent.source)}</small>}
                  </Td>
                  <Td>
                    {classWord(agent.identity_class)}
                    {agent.tags.length > 0 ? <small>Tagged {agent.tags.join(", ")}</small> : null}
                  </Td>
                  <Td>
                    {agent.driver !== null ? driverWords(agent.driver) : agent.identity_class === "tines_story" ? "Tines" : "Unattributed"}
                    {agent.drivers_more > 0 ? <small>and {count(agent.drivers_more, "more")}</small> : null}
                  </Td>
                  <Td>{didWords(agent, assessed)}</Td>
                  <Td>
                    {agent.consequential}
                    {agent.unresolved > 0 ? (
                      <small>{count(agent.unresolved, "grant")} we cannot explain</small>
                    ) : agent.lapsed > 0 ? (
                      <small>{count(agent.lapsed, "lapsed claim")}</small>
                    ) : null}
                  </Td>
                  <Governed agent={agent} />
                  <Td>{accountable({ ...agent, sponsor_count: agent.sponsors.length })}</Td>
                  <Td>{agent.open_findings}</Td>
                  <Td>
                    <div className="monitor-row-actions">
                      {agent.synthetic ? null : agent.linked_principal_id !== null ? (
                        <Link to="/agents/$agentId" params={{ agentId: agent.linked_principal_id }}>
                          Open the governed agent
                        </Link>
                      ) : agent.consequential > 0 || agent.open_paths > 0 ? (
                        <Link to="/agents/$agentId" params={{ agentId: agent.agent_id }}>
                          Govern this agent
                        </Link>
                      ) : (
                        <small>No principal linked</small>
                      )}
                      <Link to="/policy">Govern this action</Link>
                      {agent.open_paths > 0 && agent.administered ? (
                        <Button
                          onClick={() => {
                            setAccepting(agent);
                          }}
                        >
                          Accept
                        </Button>
                      ) : agent.open_paths > 0 ? (
                        <small>{ACCEPTED_ELSEWHERE}</small>
                      ) : null}
                      <Removal agent={agent} />
                      {tinesDriven(agent) ? <small>{TINES_RECIPE}</small> : null}
                    </div>
                  </Td>
                </tr>
              ))
            )}
          </tbody>
        </Table>
        <p className="muted">
          First {data.tenant.shown} of {data.tenant.enumerated} shown, in the order above. An actor&apos;s class comes from
          the directory&apos;s own type and its consents, never from a tag; a tag is shown as evidence. A driver is evidence
          of what makes an actor act, kept apart from what it can reach. Every capability is fixture-verified until a live
          probe records it.
        </p>
      </Card>
      {accepting !== null ? (
        <Suspense fallback={null}>
          <AcceptDialog
            agentId={accepting.agent_id}
            name={accepting.display_name}
            onClose={() => {
              setAccepting(null);
            }}
          />
        </Suspense>
      ) : null}
    </>
  );
}
