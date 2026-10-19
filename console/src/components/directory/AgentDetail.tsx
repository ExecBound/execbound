// SPDX-License-Identifier: AGPL-3.0-only
import { useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useState, type ReactNode } from "react";

import {
  bindAgentMutation,
  deactivateAgentMutation,
  governAgentMutation,
  issueAgentCredentialMutation,
  labelAgentMutation,
  reactivateAgentMutation,
  readAgentQueryKey,
  deleteAgentCredentialMutation,
  revokeAgentCredentialMutation,
  unbindAgentMutation,
} from "../../api/@tanstack/react-query.gen";
import type { AgentDetail, CredentialRow, LimitRow, ReachRow } from "../../api/types.gen";
import { useServerMutation, type ServerMutationOptions } from "../../lib/mutation";
import { toast } from "../../lib/toast";
import { Explain } from "../assistant/Explain";
import { Meter } from "../charts";
import { CopyLink } from "../CopyLink";
import { Badge, type Tone } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { PageHeading } from "../ui/PageHeading";
import { Time } from "../ui/Time";
import { Table, Td, Th } from "../ui/Table";
import { ConfirmDialog } from "./ConfirmDialog";
import { day, discoveredName, expiry, keyName, plural, prefix, principalName, when, words } from "./format";
import { EFFECT, ruleSentence } from "../policy/format";
import { PrincipalName } from "../PrincipalName";
import { NamePrompt } from "./NamePrompt";
import { Field, KeyLifetimeSelect, Problem, type KeyLifetime } from "./forms";
import { KeyExpires, KeyLastUsed, keyState } from "./KeyCells";
import { KeyNotice } from "./KeyNotice";
import { RotateKey } from "./RotateKey";
import { SecretDialog } from "./SecretDialog";
import { useShowOnce } from "./showOnce";
import { AgentConnection } from "../welcome/AgentConnection";
import "../ui/table-stack.css";

const STATES: Record<string, Tone> = {
  EXECUTED: "allow",
  DENIED: "deny",
  PENDING_APPROVAL: "hold",
  OBSERVED: "obs",
  STALE_AUTHORIZATION: "stale",
  FAILED_NOT_EXECUTED: "deny",
};
const CREDENTIAL_TONES: Record<CredentialRow["state"], Tone> = {
  live: "allow",
  expired: "stale",
  revoked: "stale",
};

/**
 * A change to one agent: the server's answer is the agent as it is afterwards, which
 * replaces the page's copy; the list is refreshed; nothing is assumed before the answer.
 */
function useAgentChange<TVariables>(
  rowId: string,
  options: ServerMutationOptions<AgentDetail, TVariables>,
  done: string,
) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  return useServerMutation<AgentDetail, TVariables>({
    ...options,
    onSuccess: (data, variables, context, mutation) => {
      toast(done);
      void queryClient.invalidateQueries({ queryKey: [{ _id: "listAgents" }] });
      if (data.row_id === rowId) {
        queryClient.setQueryData(readAgentQueryKey({ path: { row_id: rowId } }), data);
      } else {
        void navigate({ to: "/agents/$agentId", params: { agentId: data.row_id }, search: (previous) => previous, replace: true });
      }
      void options.onSuccess?.(data, variables, context, mutation);
    },
  });
}

/** The agent page's sections, one at a time, from `?section=` (#678). */
export const AGENT_SECTIONS = ["overview", "connection", "permissions", "activity", "advanced"] as const;
export type AgentSection = (typeof AGENT_SECTIONS)[number];

const SECTION_LABELS: Record<AgentSection, string> = {
  overview: "Overview",
  connection: "Connection",
  permissions: "Permissions",
  activity: "Activity",
  advanced: "Advanced",
};

/** A section the address names, or nothing for any other value. */
export function parseAgentSection(search: unknown): AgentSection | undefined {
  if (typeof search !== "object" || search === null) return undefined;
  const value = (search as { section?: unknown }).section;
  return AGENT_SECTIONS.find((section) => section === value);
}

/** The sections this agent has: Connection needs an active governed agent this reader may
 * change, Activity a governed agent or what a source lists, Advanced a governed agent. */
export function agentSections(detail: AgentDetail): AgentSection[] {
  const agent = detail.agent;
  const administered = detail.administered !== false;
  return AGENT_SECTIONS.filter((section) => {
    if (section === "connection") return agent?.active === true && administered;
    if (section === "activity") return agent !== null || detail.discovered !== null;
    if (section === "advanced") return agent !== null;
    return true;
  });
}

/** The section shown: the one asked for where it applies, else a new active agent's
 * Connection, where its key and connection steps are, else Overview. */
export function shownSection(detail: AgentDetail, asked: AgentSection | undefined): AgentSection {
  const sections = agentSections(detail);
  if (asked !== undefined && sections.includes(asked)) return asked;
  return sections.includes("connection") && detail.recent.length === 0 ? "connection" : "overview";
}

export function AgentDetailView({ detail, section }: { detail: AgentDetail; section?: AgentSection }) {
  const agent = detail.agent;
  const facts = detail.discovered?.agent ?? null;
  const administered = detail.administered !== false;
  const title = agent !== null ? principalName("Agent", agent.label, agent.number, detail.row_id) : discoveredName(facts?.display_name, detail.row_id);
  // The default is chosen as the page opens and kept while it stays open: an agent that makes
  // its first request while the person watches Connection stays on Connection.
  const [opened, setOpened] = useState(() => ({ row: detail.row_id, section: shownSection(detail, undefined) }));
  if (opened.row !== detail.row_id) setOpened({ row: detail.row_id, section: shownSection(detail, undefined) });
  const shown = section !== undefined || !agentSections(detail).includes(opened.section) ? shownSection(detail, section) : opened.section;
  return (
    <>
      <PageHeading
        title={title}
        lead={
          agent !== null
            ? "Connect this agent, inspect its requests, and understand the actions it can take."
            : "An agent a monitoring connection lists and nothing here governs yet. Bind it to an agent principal that already exists, or govern it: one step creates the principal, binds it and issues its first API key."
        }
        actions={<>
          <CopyLink to="/agents/$agentId" params={{ agentId: detail.row_id }} />
          {agent !== null ? (
            agent.active ? (
              <Badge tone="allow">Active</Badge>
            ) : agent.dormant ? (
              <Badge tone="obs">Asleep</Badge>
            ) : (
              <Badge tone="stale">Deactivated</Badge>
            )
          ) : facts?.gone_at !== null && facts?.gone_at !== undefined ? (
            <Badge tone="stale">Gone from the source</Badge>
          ) : (
            <Badge tone="obs">Not governed</Badge>
          )}
        </>}
      />
      {agent !== null && agent.label === null && administered ? <AgentNamePrompt detail={detail} /> : null}
      <p className="meta">
        <Link to="/agents">Back to Agent connections</Link>
        {agent !== null ? (
          <>
            {" · "}Principal <span className="mono">{prefix(agent.principal_id)}</span> · created{" "}
            {agent.created_at !== null ? when(agent.created_at) : "before labels"}
            {agent.deactivated_at !== null ? ` · deactivated ${when(agent.deactivated_at)}` : ""}
          </>
        ) : facts !== null ? (
          <>
            {" · "}Agent <span className="mono">{prefix(facts.agent_id)}</span> · first seen {when(facts.first_seen_at)}
          </>
        ) : null}
      </p>
      <nav className="tabs" aria-label="Agent sections">
        <ul>
          {agentSections(detail).map((entry) => (
            <li key={entry}>
              <Link
                to="/agents/$agentId"
                params={{ agentId: detail.row_id }}
                search={{ section: entry }}
                className="tab-link"
                activeOptions={{ exact: true, includeSearch: true }}
                aria-current={entry === shown ? "page" : undefined}
              >
                {SECTION_LABELS[entry]}
              </Link>
            </li>
          ))}
        </ul>
      </nav>
      <div className="stack">
        {shown === "overview" ? <OverviewSection detail={detail} /> : null}
        {shown === "connection" ? <ConnectionSection detail={detail} /> : null}
        {shown === "permissions" ? (
          <>
            <ReachCard detail={detail} />
            {agent !== null ? <LimitsCard detail={detail} /> : null}
          </>
        ) : null}
        {shown === "activity" ? (
          <>
            {agent !== null ? <ActivityCard detail={detail} /> : null}
            {facts !== null ? <FindingsCard detail={detail} /> : null}
          </>
        ) : null}
        {shown === "advanced" && agent !== null ? (
          <>
            {administered ? <BindingCard detail={detail} /> : null}
            {facts !== null ? <SourceCard detail={detail} /> : null}
            {!administered ? <CredentialsCard detail={detail} /> : null}
            {administered ? <LifecycleCard detail={detail} /> : null}
            <Explain kind="agent" id={agent.principal_id} what="this agent" />
          </>
        ) : null}
      </div>
    </>
  );
}

function OverviewSection({ detail }: { detail: AgentDetail }) {
  const agent = detail.agent;
  const administered = detail.administered !== false;
  if (agent === null) {
    return (
      <>
        <SourceCard detail={detail} />
        <BindingCard detail={detail} />
      </>
    );
  }
  return (
    <>
      {!administered ? (
        <p className="note" role="note">
          You can see this agent because you belong to its Space; it is changed by that Space&apos;s administrators.
        </p>
      ) : null}
      <SummaryCard detail={detail} />
      {detail.expiring_key !== null && detail.expiring_key !== undefined ? <KeyNotice notice={detail.expiring_key} /> : null}
      <div className="grid-2">
        {/* Keyed by the label: the card's field is set on mount, so a name saved from the
            prompt above remounts it with that name (#678). */}
        <IdentityCard key={agent.label ?? ""} detail={detail} />
        <MonthCard detail={detail} />
      </div>
    </>
  );
}

/** The closest limit, in words: the one nearest its maximum, if it is at least half used. */
export function closestLimit(limits: readonly LimitRow[]): string {
  if (limits.length === 0) return "No impact limit applies";
  let best: LimitRow | null = null;
  for (const row of limits) {
    if (row.count === null || row.max_targets <= 0) continue;
    if (best?.count === null || best === null || row.count / row.max_targets > best.count / best.max_targets) best = row;
  }
  if (best?.count === null || best === null || best.count / best.max_targets < 0.5) return "No limit is close";
  return `${String(best.count)} of ${String(best.max_targets)} ${best.labels} targets in ${best.window}`;
}

function SummaryCard({ detail }: { detail: AgentDetail }) {
  const agent = detail.agent;
  if (agent === null) return null;
  const last = detail.recent[0]?.created_at;
  const live = detail.credentials.filter((row) => row.state === "live");
  const next = [...live]
    .filter((row) => expiry(row.expires_at) !== "Never")
    .sort((a, b) => a.expires_at.localeCompare(b.expires_at))[0];
  return (
    <Card title="Summary">
      <dl className="facts">
        <dt>State</dt>
        <dd>
          {agent.active ? (
            <Badge tone="allow">Active</Badge>
          ) : agent.dormant ? (
            <Badge tone="obs">Asleep</Badge>
          ) : (
            <Badge tone="stale">Deactivated</Badge>
          )}
        </dd>
        <dt>Last request</dt>
        <dd>{last !== undefined ? <Time at={last} /> : "No request yet"}</dd>
        <dt>Live API keys</dt>
        <dd>
          {String(live.length)}
          {next !== undefined ? (
            <>
              {", the next expires "}
              <Time at={next.expires_at} form="relative" />
            </>
          ) : null}
        </dd>
        <dt>Closest limit</dt>
        <dd>{closestLimit(detail.limits)}</dd>
        <dt>Mode</dt>
        <dd>{detail.observe ? "Observe only" : "Enforcing"}</dd>
      </dl>
    </Card>
  );
}

/** Connect this agent and its API keys. An agent that has made requests opens with the steps
 * folded into one line; one that makes its first while the page is open keeps them, so the
 * first request's panel stays where the person is watching. */
function ConnectionSection({ detail }: { detail: AgentDetail }) {
  const [folded] = useState(detail.recent.length > 0);
  const last = detail.recent[0]?.created_at;
  return (
    <>
      {folded && last !== undefined ? (
        <>
          <p>
            Connected: requests received, the last at <Time at={last} />.
          </p>
          <details className="setup-details">
            <summary>Show the connection steps</summary>
            <AgentConnection key={detail.row_id} detail={detail} />
          </details>
        </>
      ) : (
        <AgentConnection key={detail.row_id} detail={detail} />
      )}
      <CredentialsCard detail={detail} />
    </>
  );
}

function AgentNamePrompt({ detail }: { detail: AgentDetail }) {
  const relabel = useAgentChange(detail.row_id, labelAgentMutation(), "Label saved.");
  const principal = detail.agent?.principal_id;
  if (principal === undefined) return null;
  return (
    <NamePrompt
      noun="Agent"
      pending={relabel.isPending}
      error={relabel.error}
      onSave={(label) => {
        relabel.mutate({ path: { principal_id: principal }, body: { label } });
      }}
    />
  );
}

function IdentityCard({ detail }: { detail: AgentDetail }) {
  const agent = detail.agent;
  const [label, setLabel] = useState(agent?.label ?? "");
  const relabel = useAgentChange(detail.row_id, labelAgentMutation(), "Label saved.");
  if (agent === null) return null;
  return (
    <Card title="Identity">
      <dl className="facts">
        <dt>Principal</dt>
        <dd className="mono">{agent.principal_id}</dd>
        <dt>State</dt>
        <dd>
          {agent.active ? (
            <Badge tone="allow">Active</Badge>
          ) : agent.dormant ? (
            <Badge tone="obs">Asleep</Badge>
          ) : (
            <Badge tone="stale">Deactivated</Badge>
          )}
        </dd>
        <dt>Groups</dt>
        <dd>{detail.groups.length > 0 ? detail.groups.map((group) => group.name).join(", ") : "none"}</dd>
      </dl>
      {detail.administered !== false ? <>
      <form
        className="form-row"
        onSubmit={(event) => {
          event.preventDefault();
          relabel.mutate({ path: { principal_id: agent.principal_id }, body: { label: label.trim() } });
        }}
      >
        <Field label="Label (1 to 80 characters)">
          <input
            value={label}
            maxLength={80}
            required
            autoComplete="off"
            onChange={(event) => {
              setLabel(event.target.value);
            }}
          />
        </Field>
        <Button type="submit" disabled={relabel.isPending}>
          Save the label
        </Button>
      </form>
      <Problem error={relabel.error} />
      </> : null}
      <p className="note">Group membership is provisioned by owner tooling and read here only.</p>
    </Card>
  );
}

function MonthCard({ detail }: { detail: AgentDetail }) {
  return (
    <Card title="This month">
      <dl className="facts">
        <dt>Requests since {day(detail.month)}</dt>
        <dd>{detail.requests}</dd>
        <dt>Active governed this month</dt>
        <dd>{detail.requests > 0 ? "yes" : "no"}</dd>
      </dl>
      <Table caption="Runs issued to this agent that have not expired." density="compact">
        <thead>
          <tr>
            <Th>Run</Th>
            <Th>Issued</Th>
            <Th>Expires</Th>
          </tr>
        </thead>
        <tbody>
          {detail.runs.map((row) => (
            <tr key={row.run_id}>
              <Td mono>{prefix(row.run_id)}</Td>
              <Td mono>{when(row.issued_at)}</Td>
              <Td mono>{when(row.expires_at)}</Td>
            </tr>
          ))}
          {detail.runs.length === 0 ? (
            <tr>
              <Td colSpan={3}>No active run.</Td>
            </tr>
          ) : null}
        </tbody>
      </Table>
      {detail.more_runs ? <p className="note">Showing the latest {String(detail.runs.length)} active runs.</p> : null}
    </Card>
  );
}

function BindingCard({ detail }: { detail: AgentDetail }) {
  const agent = detail.agent;
  const facts = detail.discovered?.agent ?? null;
  const binding = detail.binding;
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [target, setTarget] = useState(detail.options[0]?.id ?? "");
  const [lifetime, setLifetime] = useState<KeyLifetime | "">("");
  const [unbinding, setUnbinding] = useState(false);
  const bind = useAgentChange(detail.row_id, bindAgentMutation(), "Bound.");
  const unbind = useAgentChange(detail.row_id, unbindAgentMutation(), "Unbound.");
  const govern = useShowOnce(governAgentMutation());
  let body: ReactNode;
  if (binding !== null && facts !== null) {
    body = (
      <>
        <p>
          Bound to the discovered agent <strong>{facts.display_name}</strong>{" "}
          <span className="mono">{prefix(binding.agent_id)}</span>, {facts.source_label} {facts.class_label}, since{" "}
          {when(binding.bound_at)}
          {binding.bound_by !== null ? (
            <>
              {" "}
              by{" "}
              {binding.bound_by_ref !== null ? (
                <PrincipalName principal={binding.bound_by_ref} />
              ) : (
                "an administrator"
              )}
            </>
          ) : (
            ", bound before bindings were recorded"
          )}
          . Binding <span className="mono">{prefix(binding.binding_id)}</span>.
        </p>
        <div className="row">
          <Button
            onClick={() => {
              unbind.reset();
              setUnbinding(true);
            }}
          >
            Unbind
          </Button>
        </div>
        <ConfirmDialog
          open={unbinding}
          title="Unbind this agent?"
          confirm="Unbind"
          danger
          reason="Reason for unbinding (required, up to 500 characters)"
          pending={unbind.isPending}
          error={unbind.error}
          onConfirm={(reason) => {
            unbind.mutate(
              { path: { principal_id: binding.principal_id }, body: { reason } },
              {
                onSuccess: () => {
                  setUnbinding(false);
                },
              },
            );
          }}
          onClose={() => {
            setUnbinding(false);
          }}
        >
          <p>Its reach through ExecBound stops being attributed to the discovered agent now.</p>
        </ConfirmDialog>
      </>
    );
  } else if (agent !== null) {
    body = !agent.active ? (
      <p>
        {agent.dormant
          ? "Not bound. This agent is asleep after ninety days without a governed request; reactivate it first."
          : "Not bound. A deactivated agent cannot be bound; reactivate it first."}
      </p>
    ) : detail.options.length > 0 ? (
      <>
        <p>
          Not bound to any agent a monitoring connection lists. Binding says that this principal is that agent,
          so its executions count as that agent&apos;s verified reach.
        </p>
        <form
          className="form-row"
          onSubmit={(event) => {
            event.preventDefault();
            bind.mutate({ path: { row_id: agent.principal_id }, body: { target } });
          }}
        >
          <Field label="Discovered agent">
            <select
              value={target}
              required
              onChange={(event) => {
                setTarget(event.target.value);
              }}
            >
              {detail.options.map((option) => (
                <option key={option.id} value={option.id}>
                  {option.name ?? "unnamed"} · {option.detail} · {prefix(option.id)}
                </option>
              ))}
            </select>
          </Field>
          <Button type="submit" variant="primary" disabled={bind.isPending || target === ""}>
            Bind
          </Button>
        </form>
        <Problem error={bind.error} />
      </>
    ) : (
      <p>Not bound. No monitoring connection lists an agent that is not already bound.</p>
    );
  } else if (facts !== null) {
    body =
      facts.gone_at !== null ? (
        <p>This agent is gone from its source, so it cannot be bound or governed.</p>
      ) : (
        <>
          <form
            className="form-row"
            onSubmit={(event) => {
              event.preventDefault();
              if (lifetime === "") return;
              void govern.issue({ path: { row_id: facts.agent_id }, body: { lifetime } });
            }}
          >
            <KeyLifetimeSelect
              label="Govern this agent: create its principal, bind it and issue an API key with a lifetime of"
              value={lifetime}
              onChange={setLifetime}
            />
            <Button type="submit" variant="primary" disabled={govern.pending || lifetime === ""}>
              Govern this agent
            </Button>
          </form>
          <Problem error={govern.error} />
          <p className="note">
            The principal is labelled with the agent&apos;s display name. The API key appears once with what
            to do next; only identifiers are audited.
          </p>
          {detail.options.length > 0 ? (
            <form
              className="form-row"
              onSubmit={(event) => {
                event.preventDefault();
                bind.mutate({ path: { row_id: facts.agent_id }, body: { target } });
              }}
            >
              <Field label="Or bind it to an agent principal that already exists">
                <select
                  value={target}
                  required
                  onChange={(event) => {
                    setTarget(event.target.value);
                  }}
                >
                  {detail.options.map((option) => (
                    <option key={option.id} value={option.id}>
                      {option.name ?? "unlabelled"} · {prefix(option.id)}
                    </option>
                  ))}
                </select>
              </Field>
              <Button type="submit" disabled={bind.isPending || target === ""}>
                Bind
              </Button>
            </form>
          ) : null}
          <Problem error={bind.error} />
          <SecretDialog
            secret={govern.secret}
            onClose={() => {
              const principal = govern.secret?.principal_id;
              govern.close();
              void queryClient.invalidateQueries({ queryKey: [{ _id: "listAgents" }] });
              if (principal !== undefined) {
                void navigate({ to: "/agents/$agentId", params: { agentId: principal }, search: (previous) => previous, replace: true });
              }
            }}
          />
        </>
      );
  }
  return <Card title="Binding">{body}</Card>;
}

function SourceCard({ detail }: { detail: AgentDetail }) {
  const found = detail.discovered;
  if (found === null) return null;
  const facts = found.agent;
  return (
    <Card title="What the source lists">
      {detail.agent !== null && !detail.agent.active ? (
        <p className="problem" role="note">
          {detail.agent.dormant
            ? "The governed principal of this agent is asleep after ninety days without a governed request; the source still lists the agent."
            : "The governed principal of this agent is deactivated; the source still lists the agent."}
        </p>
      ) : null}
      <dl className="facts">
        <dt>Source</dt>
        <dd>
          {facts.source_label} · {facts.class_label}
        </dd>
        <dt>Platform id</dt>
        <dd className="mono">{facts.platform_ref}</dd>
        {facts.blueprint_ref !== null ? (
          <>
            <dt>Blueprint</dt>
            <dd className="mono">{facts.blueprint_ref}</dd>
          </>
        ) : null}
        <dt>Sponsors</dt>
        <dd>
          <Sponsors facts={facts} />
        </dd>
        <dt>Credential kinds</dt>
        <dd>{facts.credential_kinds.length > 0 ? facts.credential_kinds.join(", ") : "none read"}</dd>
        <dt>First seen</dt>
        <dd className="mono">{when(facts.first_seen_at)}</dd>
        <dt>Last seen</dt>
        <dd className="mono">{when(facts.observed_at)}</dd>
        <dt>At the source</dt>
        <dd>{facts.gone_at !== null ? `gone since ${when(facts.gone_at)}` : facts.enabled ? "enabled" : "disabled"}</dd>
      </dl>
      <p className="note">
        Sponsors are shown as object id prefixes, never names.{" "}
        <Link to="/monitor/agents/$agentId" params={{ agentId: facts.agent_id }}>
          This agent&apos;s Monitoring page
        </Link>{" "}
        carries its grants and path exceptions.
      </p>
    </Card>
  );
}

function Sponsors({ facts }: { facts: NonNullable<AgentDetail["discovered"]>["agent"] }) {
  if (facts.sponsors.length === 0) return <>{facts.sponsor_state.replaceAll("_", " ")}</>;
  return (
    <>
      {facts.sponsors.map((sponsor, index) => (
        <span key={`${sponsor.kind}-${sponsor.ref}`}>
          {index > 0 ? ", " : ""}
          {sponsor.kind} <span className="mono">{sponsor.ref}</span>
        </span>
      ))}
    </>
  );
}

function CredentialsCard({ detail }: { detail: AgentDetail }) {
  const agent = detail.agent;
  const queryClient = useQueryClient();
  const [lifetime, setLifetime] = useState<KeyLifetime | "">("");
  const [revoking, setRevoking] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const issue = useShowOnce(issueAgentCredentialMutation());
  const revoke = useAgentChange(detail.row_id, revokeAgentCredentialMutation(), "API key revoked.");
  const remove = useAgentChange(detail.row_id, deleteAgentCredentialMutation(), "API key deleted.");
  const named = (id: string | null) => {
    const row = detail.credentials.find((item) => item.credential_id === id);
    if (row === undefined) return "";
    return `API key ${row.number !== null && row.number !== undefined ? String(row.number) : prefix(row.credential_id)}`;
  };
  if (agent === null) return null;
  const agentName = principalName("Agent", agent.label, agent.number, agent.principal_id);
  // A reader who sees this agent without administering it is offered no change (0072).
  const administered = detail.administered !== false;
  return (
    <Card title="API keys">
      <Table caption="Every API key of this agent, newest first." density="compact">
        <thead>
          <tr>
            <Th>API key</Th>
            <Th>Issued</Th>
            <Th>Expires</Th>
            <Th>Last used</Th>
            <Th>State</Th>
            <Th>Failures (24 h)</Th>
            <Th>Action</Th>
          </tr>
        </thead>
        <tbody>
          {detail.credentials.map((row) => (
            <tr key={row.credential_id}>
              <Td mono>{keyName(row.number, row.credential_id)}</Td>
              <Td mono>{when(row.issued_at)}</Td>
              <Td>
                <KeyExpires row={row} />
              </Td>
              <Td>
                <KeyLastUsed at={row.last_used_at} />
              </Td>
              <Td>
                <Badge tone={CREDENTIAL_TONES[row.state]}>{keyState(row)}</Badge>
              </Td>
              <Td>{row.failures}</Td>
              <Td>
                {!administered ? null : row.state === "live" ? (
                  <span className="key-actions">
                    {agent.active ? (
                      <RotateKey principalId={agent.principal_id} agentName={agentName} replaced={row} />
                    ) : null}
                    <Button
                      size="small"
                      onClick={() => {
                        revoke.reset();
                        setRevoking(row.credential_id);
                      }}
                    >
                      Revoke {keyName(row.number, row.credential_id).toLowerCase()}
                    </Button>
                  </span>
                ) : (
                  <Button
                    size="small"
                    onClick={() => {
                      remove.reset();
                      setDeleting(row.credential_id);
                    }}
                  >
                    Delete {keyName(row.number, row.credential_id).toLowerCase()}
                  </Button>
                )}
              </Td>
            </tr>
          ))}
          {detail.credentials.length === 0 ? (
            <tr>
              <Td colSpan={7}>No API key yet.</Td>
            </tr>
          ) : null}
        </tbody>
      </Table>
      {agent.active && administered ? (
        <>
          <form
            className="form-row"
            onSubmit={(event) => {
              event.preventDefault();
              if (lifetime === "") return;
              void issue.issue({ path: { principal_id: agent.principal_id }, body: { lifetime } }).then((done) => {
                if (done) void queryClient.invalidateQueries({ queryKey: [{ _id: "readAgent" }] });
              });
            }}
          >
            <KeyLifetimeSelect label="Issue an API key with a lifetime of" value={lifetime} onChange={setLifetime} />
            <Button type="submit" variant="primary" disabled={issue.pending || lifetime === ""}>
              Issue API key
            </Button>
          </form>
          <Problem error={issue.error} />
          <p className="note">The key appears once and is never stored; only identifiers are audited.</p>
        </>
      ) : null}
      <SecretDialog secret={issue.secret} onClose={issue.close} />
      <ConfirmDialog
        open={revoking !== null}
        title={`Revoke ${named(revoking)}?`}
        confirm="Revoke"
        danger
        pending={revoke.isPending}
        error={revoke.error}
        onConfirm={() => {
          if (revoking === null) return;
          revoke.mutate(
            { path: { principal_id: agent.principal_id, credential_id: revoking }, body: {} },
            {
              onSuccess: () => {
                setRevoking(null);
              },
            },
          );
        }}
        onClose={() => {
          setRevoking(null);
        }}
      >
        <p>Requests that use it are refused from now on.</p>
      </ConfirmDialog>
      <ConfirmDialog
        open={deleting !== null}
        title={`Delete ${named(deleting)}?`}
        confirm="Delete"
        danger
        pending={remove.isPending}
        error={remove.error}
        onConfirm={() => {
          if (deleting === null) return;
          remove.mutate(
            { path: { principal_id: agent.principal_id, credential_id: deleting }, body: {} },
            {
              onSuccess: () => {
                setDeleting(null);
              },
            },
          );
        }}
        onClose={() => {
          setDeleting(null);
        }}
      >
        <p>It disappears from every list. The audit history keeps when it was issued and revoked.</p>
      </ConfirmDialog>
    </Card>
  );
}

function certainty(row: ReachRow): ReactNode {
  if (row.certainty === "verified") return <Badge tone="allow">verified</Badge>;
  if (row.certainty === "unknown") return <Badge tone="stale">unknown</Badge>;
  return row.certainty;
}

/** An instant as Python's `isoformat` writes it, inside a server's sentence. */
const INSTANT = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})/g;

/**
 * A path's freshness, a server's sentence, with each instant in it printed as the console prints
 * every time (#678), in the viewer's zone and broken at its spaces rather than kept whole as
 * `2026-10-11T19:20:42.599403+00:00`, which held the column wide. The rest is text.
 */
function Freshness({ text }: { text: string }) {
  const parts: ReactNode[] = [];
  let last = 0;
  for (const found of text.matchAll(INSTANT)) {
    parts.push(text.slice(last, found.index), <Time key={found.index} at={found[0]} />);
    last = found.index + found[0].length;
  }
  parts.push(text.slice(last));
  return <>{parts}</>;
}

/**
 * An identifier that may break after a dot or an underscore, and nowhere else (#678), so
 * `identity.revoke_sessions` or `mock_crowdstrike` does not hold its column wide.
 */
function Breakable({ text }: { text: string }) {
  return (
    <>
      {text.split(/(?<=[._])/).map((piece, index) => (
        <span key={index}>
          {index > 0 ? <wbr /> : null}
          {piece}
        </span>
      ))}
    </>
  );
}

/**
 * The rules the active bundle holds for one path, each named and linked to where it is read: a
 * seed written as Cedar on its bundle's page, a ruleset on its rules form (#273). A governed path
 * the rules never name says so, because an action with no allow rule is refused; a grant or
 * observation row has nothing to say here at all.
 */
function Rules({ row, bundleId, seed }: { row: ReachRow; bundleId: string; seed: boolean }) {
  if (row.rules.length === 0) {
    return row.path_kind === "execbound" ? <>no rule names this action</> : null;
  }
  return (
    <>
      {row.rules.map((rule) => {
        const effect = EFFECT[rule.effect.toUpperCase()];
        return (
          <div key={rule.id}>
            {effect !== undefined ? <Badge tone={effect.tone}>{effect.word}</Badge> : null}{" "}
            {rule.description ? <span>{ruleSentence(rule.description)}</span> : <span>{rule.effect} rule · conditions unavailable </span>}{" "}
            {/* A seed written as Cedar is read on its bundle's page; a ruleset on its form. */}
            {seed ? (
              <Link to="/policy/$bundleId" params={{ bundleId }} className="mono">
                {rule.id}
              </Link>
            ) : (
              <Link to="/policy/$bundleId/rules" params={{ bundleId }} className="mono">
                {rule.id}
              </Link>
            )}
          </div>
        );
      })}
    </>
  );
}

function ReachCard({ detail }: { detail: AgentDetail }) {
  const found = detail.discovered !== null;
  const bundleId = detail.rules_bundle_id;
  const selectedBundle = detail.permissions_bundle_id ?? bundleId;
  const governed = detail.reach.filter((row) => row.path_kind === "execbound");
  const external = detail.reach.filter((row) => row.path_kind !== "execbound");
  return (
    <Card title="Permissions" id="agent-permissions" aria-label="Permissions">
      {detail.agent !== null ? <>
        <dl className="facts">
          <dt>Space</dt><dd>{detail.space?.name ?? "Space unavailable"}</dd>
          <dt>Policy source</dt><dd className="links">{selectedBundle ? <>
            {detail.permissions_inherited ? "Shared policy selected by this Space" : "Selected policy for this Space"}{" · "}
            <Link to="/policy/$bundleId" params={{ bundleId: selectedBundle }}>Bundle {prefix(selectedBundle)}</Link>
          </> : detail.bundle ? "Policy document selected; source details unavailable" : "No policy selected"}</dd>
          <dt>Mode</dt><dd>{detail.observe ? "Observe only — requests do not enforce policy" : "Enforce participating requests"}</dd>
        </dl>
        <p>Each request is evaluated against its exact target, trusted context, arguments, and current limits. A listed action is not permission to execute. In enforce mode, hard denials win and requests without a matching permit are denied.</p>
        <h3>Paths through ExecBound</h3>
      </> : <p>This discovered agent has no registered ExecBound principal. Its vendor authority is not governed here.</p>}
      {detail.agent !== null ? <>
      <Table
        caption={
          "Actions the active bundle governs for this agent’s Space, and actions this agent executed in the last 30 days. Verified describes historical execution through ExecBound; inferred means a configured path without execution evidence. " +
          (bundleId !== null
            ? "Rules are as they read for the action; the decision is the kernel's, from the compiled bundle. "
            : "")
        }
        density="compact"
        className="table-stack reach-table"
      >
        <thead>
          <tr>
            <Th>Action</Th>
            <Th>Certainty</Th>
            <Th>Placement</Th>
            <Th>Path</Th>
            <Th>Resource scope</Th>
            <Th>Freshness</Th>
            {bundleId !== null ? <Th>Rules</Th> : null}
          </tr>
        </thead>
        <tbody>
          {governed.map((row) => (
            <tr key={`${row.action}-${row.path_kind}-${row.path}`}>
              <Td>
                {row.label}{" "}
                <span className="mono faint">
                  <Breakable text={row.action} />
                </span>
              </Td>
              <Td data-label="Certainty">{certainty(row)}</Td>
              <Td data-label="Placement">{row.mode.startsWith("native") ? `Execute${row.mode.includes("no longer mapped") ? " · no longer mapped" : ""}` : row.mode.startsWith("integrated") ? `Gate · external executor${row.mode.includes("no longer mapped") ? " · no longer mapped" : ""}` : row.mode}</Td>
              <Td data-label="Path">
                {row.path}
                {row.govern ? (
                  <>
                    {" · "}
                    <Link to="/policy">Govern this action</Link>
                  </>
                ) : null}
              </Td>
              <Td data-label="Resource scope">{row.resource_scope?.length ? row.resource_scope.map((scope) => <div key={scope}><Breakable text={scope} /></div>) : "Not established for this path"}</Td>
              <Td data-label="Freshness">
                <Freshness text={row.freshness} />
              </Td>
              {bundleId !== null ? (
                <Td data-label="Rules" className="reach-rules">
                  <Rules row={row} bundleId={bundleId} seed={detail.rules_origin === "recognized-seed"} />
                </Td>
              ) : null}
            </tr>
          ))}
          {governed.length === 0 ? (
            <tr>
              <Td colSpan={bundleId !== null ? 7 : 6}>
                No configured enforcement path or recent executed action is known for this agent.
              </Td>
            </tr>
          ) : null}
        </tbody>
      </Table>
      <p className="note">Resource scope names configured provider accounts. Policy conditions narrow the eligible targets; target eligibility is resolved for each request.</p>
      {bundleId !== null && detail.rules_origin === "recognized-seed" && detail.policy_document ? (
        // `policy-reading` wraps the documents' long lines, as it does below; without it they
        // ran to 691 px at 390 and panned inside `main`.
        <details className="policy-reading">
          <summary>Exact policy documents</summary>
          <h4>Authorization</h4>
          <pre>{detail.policy_document.authorization_policies || "No authorization statements."}</pre>
          <h4>Approval requirements</h4>
          <pre>{detail.policy_document.approval_policies || "No policy-based approval requirements. Impact limits can still require approval."}</pre>
        </details>
      ) : null}
      {bundleId === null && detail.bundle ? <section className="policy-reading" aria-label="Policy conditions">
        <h3>Policy conditions</h3>
        <p>These conditions describe the selected policy across its agents and actions. They do not predict a request's decision. Deny takes precedence; approval conditions only apply to otherwise permitted requests. Current context and impact limits still apply.</p>
        {detail.policy_document ? <>
          {!detail.policy_document.complete ? <p className="note">Some policy syntax cannot be summarized. Read the exact documents below for all conditions.</p> : null}
          <ul>{detail.policy_document.rules.map((rule) => <li key={rule.id}><strong>{rule.effect}</strong>: {rule.description ?? "Read the exact document for this condition."} <small className="mono faint">{rule.id}</small></li>)}</ul>
          {detail.policy_document.rules.length === 0 && detail.policy_document.complete ? <p>No policy statements. Without a matching permit, enforce mode denies the request.</p> : null}
          <details><summary>Exact policy documents</summary>
            <h4>Authorization</h4><pre>{detail.policy_document.authorization_policies || "No authorization statements."}</pre>
            <h4>Approval requirements</h4><pre>{detail.policy_document.approval_policies || "No policy-based approval requirements. Impact limits can still require approval."}</pre>
          </details>
        </> : <p>Policy conditions could not be summarized. Open the selected bundle to read the exact documents.</p>}
      </section> : null}
      <p className="note">Execute protects the path when provider credentials remain behind ExecBound. Gate covers requests submitted by the external executor. Calls using separate credentials or routes remain outside these controls.</p>
      </> : null}
      <h3>Observed vendor reach</h3>
      <p className="note">Source-reported grants, roles, inherited access, and activity describe vendor authority. This evidence does not establish an enforced path or an ExecBound authorization decision. A lapsed claim reads unknown.</p>
      {external.length > 0 ? <Table caption="External vendor authority and observations; enforcement and target scope may be unknown." density="compact">
        <thead><tr><Th>Action</Th><Th>Source / inheritance</Th><Th>Certainty</Th><Th>Freshness</Th><Th>Resource scope</Th></tr></thead>
        <tbody>{external.map((row) => <tr key={`${row.action}-${row.path_kind}-${row.path}`}>
          <Td>{row.label} <span className="mono faint">{row.action}</span></Td>
          <Td>{row.path}{row.govern ? <> · <Link to="/policy">Govern this action</Link></> : null}</Td><Td>{certainty(row)}</Td><Td><Freshness text={row.freshness} /></Td>
          <Td>{row.resource_scope?.length ? row.resource_scope.join("; ") : "Not established by this source"}</Td>
        </tr>)}</tbody>
      </Table> : <p>{found ? "No current vendor reach is established by this source." : "Vendor reach is unknown. Bind a discovered agent to see its source-reported permissions and activity."}</p>}
    </Card>
  );
}

function ActivityCard({ detail }: { detail: AgentDetail }) {
  return (
    <Card title="Recent activity" id="agent-activity">
      <Table caption={`The last ${String(detail.recent.length)} requests of this agent, newest first.`} density="compact">
        <thead>
          <tr>
            <Th>Action</Th>
            <Th>Target</Th>
            <Th>State</Th>
            <Th>Requested</Th>
          </tr>
        </thead>
        <tbody>
          {detail.recent.map((row) => (
            <tr key={row.execution_id}>
              <Td>
                <Link to="/activity" search={{ open: row.execution_id }}>{row.label}</Link>
              </Td>
              {/* The target's provider identifier, agent text shown as text; else its prefix. */}
              <Td mono>
                {row.target_label ?? (row.canonical_target_id !== null ? prefix(row.canonical_target_id) : "none")}
              </Td>
              <Td>
                <Badge tone={STATES[row.state] ?? "stale"}>{words(row.state)}</Badge>
              </Td>
              <Td mono>{when(row.created_at)}</Td>
            </tr>
          ))}
          {detail.recent.length === 0 ? (
            <tr>
              <Td colSpan={4}>This agent has made no request.</Td>
            </tr>
          ) : null}
        </tbody>
      </Table>
      <p className="note">
        <Link to="/activity" search={{ agent: detail.agent?.principal_id }}>All activity for this agent</Link>
      </p>
    </Card>
  );
}

function LimitsCard({ detail }: { detail: AgentDetail }) {
  return (
    <Card title="Limits">
      {!detail.bundle ? (
        <p>No bundle is active, so every request from this agent is refused.</p>
      ) : (
        <>
          <div className="meters">
            {detail.limits.map((row) => (
              <LimitView key={`${row.scope}-${row.budget}-${row.actions}`} row={row} />
            ))}
            {detail.limits.length === 0 ? <p>No applicable impact limit is configured in this policy.</p> : null}
          </div>
          <p className="note">
            Used counts confirmed targets inside the rolling window and every target still unresolved
            {detail.observe ? ", plus observed decisions inside the window, because the tenant is in observe mode" : ""}
            ; an autonomous budget counts only what was not approved. The next request counts as one more against
            each figure. Rules scoped to an account or a fact depend on the request&apos;s target and are counted
            when it is made.
          </p>
        </>
      )}
    </Card>
  );
}

function LimitView({ row }: { row: LimitRow }) {
  const heading = `${row.scope} · ${row.budget} · ${row.labels}`;
  const exceeded = row.on_exceed === "REQUIRE_APPROVAL" ? "needs approval" : "denied";
  if (row.count === null) {
    return (
      <div>
        <div className="meter-row">
          <span className="meter-label">{heading}</span>
          <span className="meter-value mono">counted per request</span>
        </div>
        <small>
          {String(row.max_targets)} in {row.window}; when exceeded, {exceeded}
        </small>
      </div>
    );
  }
  return (
    <div>
      <Meter label={heading} value={row.count} max={row.max_targets} />
      <small>
        {plural(row.count, "target")} of {String(row.max_targets)} in the rolling window of {row.window}; when exceeded,{" "}
        {exceeded}
      </small>
    </div>
  );
}

function FindingsCard({ detail }: { detail: AgentDetail }) {
  const found = detail.discovered;
  if (found === null) return null;
  return (
    <Card title="Observations and findings">
      <p className="note">
        Findings name the agent&apos;s sponsor as their owner:{" "}
        {found.agent.sponsors.length > 0 ? <Sponsors facts={found.agent} /> : "no sponsor was read"}.
      </p>
      <Table caption="Findings about this agent, newest first." density="compact">
        <thead>
          <tr>
            <Th>Rule</Th>
            <Th>Finding</Th>
            <Th>Raised</Th>
            <Th>State</Th>
          </tr>
        </thead>
        <tbody>
          {found.findings.map((row) => (
            <tr key={row.finding_id}>
              <Td mono>{row.rule_version}</Td>
              <Td>{row.title}</Td>
              <Td mono>{when(row.created_at)}</Td>
              <Td>{row.acknowledged_at !== null ? "acknowledged" : "open"}</Td>
            </tr>
          ))}
          {found.findings.length === 0 ? (
            <tr>
              <Td colSpan={4}>No finding.</Td>
            </tr>
          ) : null}
        </tbody>
      </Table>
      <Table caption="What platforms reported this agent doing, newest first." density="compact">
        <thead>
          <tr>
            <Th>Occurred</Th>
            <Th>Kind</Th>
            <Th>Action</Th>
            <Th>Outcome</Th>
          </tr>
        </thead>
        <tbody>
          {found.observations.map((row, index) => (
            <tr key={`${row.occurred_at}-${String(index)}`}>
              <Td mono>{when(row.occurred_at)}</Td>
              <Td>{row.kind}</Td>
              <Td mono>{row.action ?? "none"}</Td>
              <Td>{row.outcome ?? "not reported"}</Td>
            </tr>
          ))}
          {found.observations.length === 0 ? (
            <tr>
              <Td colSpan={4}>No observation.</Td>
            </tr>
          ) : null}
        </tbody>
      </Table>
    </Card>
  );
}

function LifecycleCard({ detail }: { detail: AgentDetail }) {
  const agent = detail.agent;
  const [asking, setAsking] = useState(false);
  const deactivate = useAgentChange(detail.row_id, deactivateAgentMutation(), "Agent deactivated.");
  const reactivate = useAgentChange(detail.row_id, reactivateAgentMutation(), "Agent reactivated.");
  if (agent === null) return null;
  if (agent.active) {
    return (
      <Card title="Deactivate">
        <p className="note">
          Ends this agent&apos;s access in one step: every live credential is revoked and no credential can be
          issued to it. Nothing is deleted; the audit chain keeps referring to this principal
          {detail.binding !== null ? ", and the binding stays" : ""}.
        </p>
        <div className="row">
          <Button
            variant="danger"
            onClick={() => {
              deactivate.reset();
              setAsking(true);
            }}
          >
            Deactivate this agent
          </Button>
        </div>
        <ConfirmDialog
          open={asking}
          title="Deactivate this agent?"
          confirm="Deactivate"
          danger
          reason="Reason (required, up to 500 characters)"
          pending={deactivate.isPending}
          error={deactivate.error}
          onConfirm={(reason) => {
            deactivate.mutate(
              { path: { principal_id: agent.principal_id }, body: { reason } },
              {
                onSuccess: () => {
                  setAsking(false);
                },
              },
            );
          }}
          onClose={() => {
            setAsking(false);
          }}
        >
          <p>Every API key ends now.</p>
        </ConfirmDialog>
      </Card>
    );
  }
  return (
    <Card title="Reactivate">
      <p className="note">Restores this agent with its groups as they were. No API key is issued; issue one above afterwards.</p>
      <div className="row">
        <Button
          variant="primary"
          onClick={() => {
            reactivate.reset();
            setAsking(true);
          }}
        >
          Reactivate this agent
        </Button>
      </div>
      <ConfirmDialog
        open={asking}
        title="Reactivate this agent?"
        confirm="Reactivate"
        pending={reactivate.isPending}
        error={reactivate.error}
        onConfirm={() => {
          reactivate.mutate(
            { path: { principal_id: agent.principal_id }, body: {} },
            {
              onSuccess: () => {
                setAsking(false);
              },
            },
          );
        }}
        onClose={() => {
          setAsking(false);
        }}
      >
        <p>Its API keys stay revoked; issue a new one afterwards.</p>
      </ConfirmDialog>
    </Card>
  );
}
