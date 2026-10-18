// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";

import { readMonitorAgentsOptions } from "../../api/@tanstack/react-query.gen";
import type { MonitorAgentRow, MonitorAgents } from "../../api/types.gen";
import { count } from "../../lib/when";
import { Card } from "../ui/Card";
import { Table, Td, Th } from "../ui/Table";

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

/** The Agents view: the tenant line that states its own denominator, then every agent listed. */
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

function AgentsTable({ data }: { data: MonitorAgents }) {
  const figures: [string, number][] = [
    ["Agents enumerated", data.tenant.enumerated],
    ["With consequential reach", data.tenant.with_reach],
    ["With a governed path", data.tenant.governed],
    ["Reach not established", data.tenant.unestablished],
  ];
  return (
    <>
      <dl className="figures" aria-label="Agents this connection could enumerate">
        {figures.map(([label, value]) => (
          <div key={label} className="figure">
            <dt className="figure-label">{label}</dt>
            <dd className="figure-value">{value}</dd>
          </div>
        ))}
      </dl>
      <p className="muted">
        Every number above counts agents this connection could enumerate, not the agents that exist. Microsoft's own
        endpoint sweep reports agents with no identity at all; Graph does not serve them and ExecBound never counts
        them. Azure RBAC assignments are not served by Graph either, so reach into Azure resources is a hole rather than
        a zero.
        {data.consequential.length === 0
          ? " No detection profile names a consequential action, so no agent is counted as having consequential reach."
          : ""}
      </p>
      <Card title="Agents the directory lists">
        <Table caption="Agents the directory lists, with what each reaches." density="compact">
          <thead>
            <tr>
              <Th>Agent</Th>
              <Th>Class</Th>
              <Th>Accountable</Th>
              <Th>Consequential reach</Th>
              <Th>Governed</Th>
              <Th>Open findings</Th>
            </tr>
          </thead>
          <tbody>
            {data.agents.length === 0 ? (
              <tr>
                <Td colSpan={6}>
                  No agents collected. Register an identity provider connection and run a collection. No agents here
                  does not establish that the directory holds none.
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
                  </Td>
                  <Td>
                    {classWord(agent.identity_class)}
                    {agent.tags.length > 0 ? <small>Tagged {agent.tags.join(", ")}</small> : null}
                  </Td>
                  <Td>{accountable({ ...agent, sponsor_count: agent.sponsors.length })}</Td>
                  <Td>
                    {agent.consequential}
                    {agent.unresolved > 0 ? (
                      <small>{count(agent.unresolved, "grant")} we cannot explain</small>
                    ) : agent.lapsed > 0 ? (
                      <small>{count(agent.lapsed, "lapsed claim")}</small>
                    ) : null}
                  </Td>
                  <Td>
                    {agent.governed}
                    <small>
                      {agent.linked_principal_id !== null ? (
                        <Link to="/agents/$agentId" params={{ agentId: agent.linked_principal_id }}>
                          Linked
                        </Link>
                      ) : agent.consequential > 0 ? (
                        <Link to="/agents/$agentId" params={{ agentId: agent.agent_id }}>
                          Govern
                        </Link>
                      ) : (
                        "No principal linked"
                      )}
                    </small>
                  </Td>
                  <Td>{agent.open_findings}</Td>
                </tr>
              ))
            )}
          </tbody>
        </Table>
        <p className="muted">
          Latest {data.tenant.shown} of {data.tenant.enumerated} shown. An agent's class comes from the directory's own
          type, never from a tag; a tag is shown as evidence. Every capability is fixture-verified until a live probe
          records it.
        </p>
      </Card>
    </>
  );
}
