// SPDX-License-Identifier: AGPL-3.0-only
import { Link } from "@tanstack/react-router";
import { useState } from "react";

import type { AgentRow, AgentsPage, TenantLine } from "../../api/types.gen";
import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";
import { EmptyState } from "../ui/EmptyState";
import { Table, Td, Th } from "../ui/Table";
import { PLAN_LIMIT_SENTENCE } from "./errors";
import { day, plural, principalName, when } from "./format";
import { Field } from "./forms";
import { NewAgent } from "./NewAgent";

import { DEFAULT_SEARCH, FILTERS, parseAgentsSearch, type AgentsSearch } from "./agent-search";
export { FILTERS, parseAgentsSearch, DEFAULT_SEARCH, type AgentsSearch } from "./agent-search";
const LABELS: Record<keyof typeof FILTERS, [string, Record<string, string>]> = {
  state: [
    "State",
    { active: "Active", deactivated: "Deactivated", gone: "Gone from the source", all: "All" },
  ],
  population: [
    "Population",
    { all: "All", registered: "Registered agents", bound: "Bound", governed: "Governed only", discovered: "Discovered only" },
  ],
  source: ["Source", { all: "All", entra_agent_id: "Entra", tines: "Tines" }],
  ungoverned: ["Reach", { any: "Any", yes: "Consequential, not governed" }],
  active: ["This month", { any: "Any", yes: "Made a request", no: "Made no request" }],
};
const POPULATIONS: Record<AgentRow["population"], string> = {
  bound: "bound",
  governed: "governed only",
  discovered: "discovered only",
};

export function AgentsList({
  data,
  search,
  onSearch,
}: {
  data: AgentsPage;
  search: AgentsSearch;
  onSearch: (next: Partial<AgentsSearch>) => void;
}) {
  const [discovery, setDiscovery] = useState(false);
  // Nothing in this Space at all, rather than nothing these filters match: say so and name the
  // next action, with no filters or empty table to read as "filtered out" (#678). Asleep agents
  // are not active, so the default State hides them; a Space they are in is not empty, and
  // keeps the filters that list them (#439). `space_dormant` counts the listed Space's own,
  // where the tenant line's `agents_dormant` is the whole workspace's.
  const pristine =
    data.agents.length === 0 &&
    data.space_dormant === 0 &&
    search.cursor === undefined &&
    (Object.keys(DEFAULT_SEARCH) as (keyof typeof FILTERS)[]).every((key) => search[key] === DEFAULT_SEARCH[key]);
  if (pristine) {
    return (
      <Card>
        <EmptyState title="No agents in this Space yet.">
          <p>Add an agent to give a coding agent or a Tines story its own API key.</p>
          <p><NewAgent /></p>
          <p className="muted">
            Deactivated agents are listed under{" "}
            <Link to="/agents" search={{ ...DEFAULT_SEARCH, state: "all" }}>State</Link>.
          </p>
        </EmptyState>
      </Card>
    );
  }
  return (
    <div className="stack">
      <details className="setup-details"><summary>Discovery coverage and agent capacity</summary>
        <TenantLineView line={data.line} activeMonth={data.active_month} month={data.month} />
      </details>
      <form
        className="filters"
        aria-label="Filters"
        onSubmit={(event) => {
          event.preventDefault();
        }}
      >
        {(Object.keys(LABELS) as (keyof typeof FILTERS)[]).map((key) => {
          const [label, names] = LABELS[key];
          return (
            <Field key={key} label={label}>
              <select
                name={key}
                value={search[key]}
                onChange={(event) => {
                  onSearch({ [key]: parseAgentsSearch({ [key]: event.target.value })[key], cursor: undefined });
                }}
              >
                {FILTERS[key].map((option) => (
                  <option key={option} value={option}>
                    {names[option] ?? option}
                  </option>
                ))}
              </select>
            </Field>
          );
        })}
      </form>
      <label className="check"><input type="checkbox" checked={discovery} onChange={(event) => { setDiscovery(event.target.checked); }} /> Show discovery details</label>
      <Card>
        <Table
          caption="Agents matching the filters, with counts as of this page load. Reach counts consequential actions a grant reaches while its proof is current."
          density="compact"
        >
          <thead>
            <tr>
              <Th>Agent</Th>
              <Th>Connection</Th>
              {discovery ? <><Th>Source</Th><Th>Sponsor</Th><Th>Consequential reach</Th><Th>Governed paths</Th></> : null}
              <Th>Requests this month</Th>
              <Th>Last activity</Th>
              {discovery ? <Th>Open findings</Th> : null}
              <Th>State</Th>
            </tr>
          </thead>
          <tbody>
            {data.agents.map((row) => (
              <Row key={row.row_id} row={row} discovery={discovery} />
            ))}
          </tbody>
        </Table>
        {data.agents.length === 0 ? <EmptyState title="No agent matches these filters." /> : null}
        {data.next !== null ? (
          <div className="pager">
            <Link to="/agents" search={{ ...search, cursor: data.next }} rel="next" className="btn">
              Next page
            </Link>
          </div>
        ) : null}
      </Card>
    </div>
  );
}

function Row({ row, discovery }: { row: AgentRow; discovery: boolean }) {
  const inventoried = row.agent_id !== null;
  return (
    <tr>
      <Td>
        <Link to="/agents/$agentId" params={{ agentId: row.row_id }}>
          {principalName("Agent", row.name, row.number, row.row_id)}
        </Link>
      </Td>
      <Td>{POPULATIONS[row.population]}</Td>
      {discovery ? <>
      <Td>{inventoried ? `${row.source_label} · ${row.class_label}` : "ExecBound only"}</Td>
      <Td>
        {!inventoried ? (
          "not inventoried"
        ) : row.sponsors.length > 0 ? (
          <>
            <span className="mono">{row.sponsors[0]?.ref}</span>
            {row.sponsors.length > 1 ? ` and ${plural(row.sponsors.length - 1, "more", "more")}` : null}
          </>
        ) : (
          (row.sponsor_state ?? "").replaceAll("_", " ")
        )}
      </Td>
      <Td>
        {inventoried
          ? `${String(row.consequential)}${row.lapsed > 0 ? ` · ${String(row.lapsed)} unknown` : ""}`
          : "not inventoried"}
      </Td>
      <Td>{inventoried ? String(row.governed_paths) : "not inventoried"}</Td>
      </> : null}
      <Td>{row.principal_id !== null ? String(row.requests) : "not governed"}</Td>
      <Td mono>
        {row.last_request !== null
          ? `request ${when(row.last_request)}`
          : row.last_seen !== null
            ? `seen ${when(row.last_seen)}`
            : "never"}
      </Td>
      {discovery ? <Td>{inventoried ? String(row.findings) : "none"}</Td> : null}
      <Td>
        <StateCell row={row} />
      </Td>
    </tr>
  );
}

function StateCell({ row }: { row: AgentRow }) {
  return (
    <span className="badges">
      {row.principal_id !== null ? (
        row.active === true ? (
          <Badge tone="allow">Active</Badge>
        ) : row.dormant === true ? (
          <Badge tone="obs">Asleep</Badge>
        ) : (
          <Badge tone="stale">Deactivated</Badge>
        )
      ) : null}
      {row.agent_id !== null ? (
        row.gone_at !== null ? (
          <Badge tone="stale">Gone from the source</Badge>
        ) : row.enabled === false ? (
          <Badge tone="stale">Disabled at the source</Badge>
        ) : row.principal_id === null ? (
          "listed by the source"
        ) : null
      ) : null}
    </span>
  );
}

/** The one line: how many agents the workspace holds against its limit (`tenants.max_agents`,
 * #257), with no "of N" when it has none; the over-limit sentence -- `PLAN_LIMIT_SENTENCE`, the
 * same words the refusal toast shows for `PLAN_LIMIT`, imported rather than retyped -- when it
 * is at or over the limit; and how many agents are asleep when any are, pointing at the
 * "Asleep" badge `StateCell`/`AgentDetail` render rather than a control this page lacks. */
export function capacityLineText(line: TenantLine): string {
  const base =
    line.agent_limit === null
      ? `Agents: ${String(line.agents_held)}.`
      : `Agents: ${String(line.agents_held)} of ${String(line.agent_limit)}.`;
  const overCap =
    line.agent_limit !== null && line.agents_held >= line.agent_limit ? ` ${PLAN_LIMIT_SENTENCE}` : "";
  const dormant =
    line.agents_dormant > 0
      ? ` ${plural(line.agents_dormant, "agent")} ${line.agents_dormant === 1 ? "is" : "are"} asleep after ninety` +
        ` days without a governed request. Open an agent marked Asleep to reactivate it.`
      : "";
  return base + overCap + dormant;
}

function CapacityLine({ line }: { line: TenantLine }) {
  return <p className="note">{capacityLineText(line)}</p>;
}

function TenantLineView({ line, activeMonth, month }: { line: TenantLine; activeMonth: number; month: string }) {
  return (
    <>
      <CapacityLine line={line} />
      <div className="figures">
        <div className="figure">
          <span className="figure-label">Active agent principals</span>
          <span className="figure-value">{line.principals}</span>
          <span className="figure-note">
            {String(line.bound)} bound to a discovered agent
          </span>
        </div>
        <div className="figure">
          <span className="figure-label">Active governed this month</span>
          <span className="figure-value">{activeMonth}</span>
          <span className="figure-note">
            made at least one request since {day(month)}, the start of the calendar month in UTC
          </span>
        </div>
        <div className="figure">
          <span className="figure-label">Agents the sources list</span>
          <span className="figure-value">{line.totals.listed}</span>
          <span className="figure-note">
            {line.sources.length === 0
              ? "no monitoring connection lists agents"
              : `${String(line.totals.consequential)} with consequential reach · ${String(line.totals.unestablished)} not established`}
          </span>
        </div>
      </div>
      <Card title="What this tenant can see">
        {line.sources.length === 0 ? (
          <p>
            No monitoring connection lists agents for this tenant, so only the agents ExecBound governs are
            counted. A <Link to="/monitor">monitoring connection</Link> adds the ones a directory or platform
            knows about.
          </p>
        ) : (
          <>
            <Table
              caption="Agents each monitoring connection lists, as of its last collection. Every count is of agents a connection could enumerate, not of the agents that exist."
              density="compact"
            >
              <thead>
                <tr>
                  <Th>Source</Th>
                  <Th>Last collected</Th>
                  <Th>Listed</Th>
                  <Th>Consequential reach</Th>
                  <Th>Bound</Th>
                  <Th>Reach not established</Th>
                </tr>
              </thead>
              <tbody>
                {line.sources.map((row) => (
                  <tr key={row.connection_id}>
                    <Td>
                      {row.label} · {row.source_label}
                      {!row.active ? " · revoked" : ""}
                    </Td>
                    <Td mono>
                      {when(row.last_sync_at)}
                      {row.health_state !== null && !["COLLECTING", "NEVER_COLLECTED"].includes(row.health_state)
                        ? ` · ${row.health_state.replaceAll("_", " ").toLowerCase()}`
                        : ""}
                    </Td>
                    <Td>{row.listed}</Td>
                    <Td>
                      {row.consequential} of {row.listed}
                    </Td>
                    <Td>
                      {row.bound} of {row.listed}
                    </Td>
                    <Td>
                      {row.unestablished} of {row.listed}
                    </Td>
                  </tr>
                ))}
                {line.sources.length > 1 ? (
                  <tr>
                    <Td>All sources</Td>
                    <Td />
                    <Td>{line.totals.listed}</Td>
                    <Td>
                      {line.totals.consequential} of {line.totals.listed}
                    </Td>
                    <Td>
                      {line.totals.bound} of {line.totals.listed}
                    </Td>
                    <Td>
                      {line.totals.unestablished} of {line.totals.listed}
                    </Td>
                  </tr>
                ) : null}
              </tbody>
            </Table>
            <p className="note">
              Agents with no identity cannot be read by any connection, so no number here counts them, and a
              source that lists none has not shown that it holds none.
              {!line.profiled
                ? " No detection profile names a consequential action, so no agent is counted as having consequential reach."
                : ""}{" "}
              Reach not established means a grant the catalog cannot explain, a lapsed claim, or accountability
              the source would not let us read. Bound means tied to an agent principal here.
            </p>
          </>
        )}
      </Card>
    </>
  );
}

export { NewAgent };
