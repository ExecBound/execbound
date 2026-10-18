// SPDX-License-Identifier: AGPL-3.0-only
import { useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";

import {
  deleteCredentialMutation,
  issueCredentialMutation,
  revokeCredentialMutation,
} from "../../api/@tanstack/react-query.gen";
import type { CredentialListRow, CredentialsPage } from "../../api/types.gen";
import { useServerMutation } from "../../lib/mutation";
import { toast } from "../../lib/toast";
import { Badge, type Tone } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { EmptyState } from "../ui/EmptyState";
import { Table, Td, Th } from "../ui/Table";
import { ConfirmDialog } from "./ConfirmDialog";
import { keyName, plural, prefix, principalName, when, words } from "./format";
import { KeyExpires, KeyLastUsed, keyState } from "./KeyCells";
import { RotateKey } from "./RotateKey";
import { PersonName } from "./PersonName";
import { Field, KeyLifetimeSelect, Problem, type KeyLifetime } from "./forms";
import { SecretDialog } from "./SecretDialog";
import { useShowOnce } from "./showOnce";
import { useCommand } from "../../lib/commands";

const TONES: Record<CredentialListRow["state"], Tone> = { live: "allow", expired: "stale", revoked: "stale" };
const NEW_AGENT = "new:AGENT";

/** How a dialog names a row: "API key 12" for an agent's key, "credential 1a2b3c4d" for a
 * person's older bearer credential, which has no number. */
function named(row: CredentialListRow | undefined): string {
  if (row === undefined) return "";
  return row.kind === "AGENT" && row.number !== null ? `API key ${String(row.number)}` : `credential ${prefix(row.credential_id)}`;
}

/** The principal's own page: an agent's on Agents, a person's on People. */
function Principal({ row }: { row: CredentialListRow }) {
  if (row.kind === "AGENT") {
    return (
      <Link to="/agents/$agentId" params={{ agentId: row.principal_id }}>
        {principalName("Agent", row.label, row.principal_number, row.principal_id)}
      </Link>
    );
  }
  return <PersonName id={row.principal_id} label={row.label} email={row.email} number={row.principal_number} kind={row.kind} link />;
}

export function CredentialsList({ data }: { data: CredentialsPage }) {
  const queryClient = useQueryClient();
  const [revoking, setRevoking] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const find = (id: string | null) => data.credentials.find((row) => row.credential_id === id);
  const refresh = (page: CredentialsPage) => {
    queryClient.setQueryData([{ _id: "listCredentials", baseUrl: "/" }], page);
    void queryClient.invalidateQueries({ queryKey: [{ _id: "listCredentials" }] });
  };
  const revokingRow = find(revoking);
  const revoke = useServerMutation({
    ...revokeCredentialMutation(),
    onSuccess: (page) => {
      toast(revokingRow?.kind === "AGENT" ? "API key revoked." : "Credential revoked.");
      refresh(page);
      setRevoking(null);
    },
  });
  const remove = useServerMutation({
    ...deleteCredentialMutation(),
    onSuccess: (page) => {
      toast("API key deleted.");
      refresh(page);
      setDeleting(null);
    },
  });
  const agents = data.credentials.filter((row) => row.kind === "AGENT");
  const legacy = data.credentials.filter((row) => row.kind !== "AGENT");
  const requestRevoke = (id: string) => {
    revoke.reset();
    setRevoking(id);
  };
  const requestDelete = (id: string) => {
    remove.reset();
    setDeleting(id);
  };
  return (
    <div className="stack">
      <div className="figures">
        <div className="figure">
          <span className="figure-label">Live API keys</span>
          <span className="figure-value">{agents.filter((row) => row.state === "live").length}</span>
          <span className="figure-note">in this view; failures counted over the last 24 hours</span>
        </div>
      </div>
      <CredentialTable
        rows={agents}
        caption="API keys in this tenant, grouped by agent."
        column="API key"
        empty="No API keys yet."
        onRevoke={requestRevoke}
        onDelete={requestDelete}
      />
      <Card title="Using an API key">
        <p>
          An agent sends its key on every call as <code>Authorization: Bearer &lt;API key&gt;</code>, to the
          gateway&apos;s <code>/v1/execute</code> or to MCP at <code>/mcp/</code>. The Python client and the host
          recipes read it from <code>EXECBOUND_CREDENTIAL</code>. The key is shown once, when it is issued.
        </p>
        <p>
          Give each tool that calls ExecBound its own agent and key, such as a coding agent, an MCP server or a
          Tines story. Activity then shows which one acted, and you can revoke one without the others.
        </p>
        <p className="note">
          To replace a key, issue a new one, update the agent, then revoke the old one. Issuing a key never revokes
          another. A revoked or expired key can be deleted; the audit history keeps it. Each agent&apos;s own page
          shows the setup for its host.
        </p>
      </Card>
      <details className="setup-details">
        <summary>Advanced: legacy human and administrator credentials</summary>
        <p>Use <Link to="/people">Team &amp; access</Link> to set up a person's sign-in. Existing setup credentials can be inspected here; a legacy member credential can still be revoked.</p>
        <CredentialTable
          rows={legacy}
          caption="Legacy human and administrator credentials, grouped by principal."
          column="Credential"
          empty="No credentials in this group."
          onRevoke={requestRevoke}
        />
      </details>
      <ConfirmDialog
        open={revoking !== null}
        title={`Revoke ${named(revokingRow)}?`}
        confirm="Revoke"
        danger
        pending={revoke.isPending}
        error={revoke.error}
        onConfirm={() => {
          if (revoking !== null) revoke.mutate({ path: { credential_id: revoking }, body: {} });
        }}
        onClose={() => {
          setRevoking(null);
        }}
      >
        <p>Sessions and requests that use it stop at their next check.</p>
      </ConfirmDialog>
      <ConfirmDialog
        open={deleting !== null}
        title={`Delete ${named(find(deleting))}?`}
        confirm="Delete"
        danger
        pending={remove.isPending}
        error={remove.error}
        onConfirm={() => {
          if (deleting !== null) remove.mutate({ path: { credential_id: deleting }, body: {} });
        }}
        onClose={() => {
          setDeleting(null);
        }}
      >
        <p>It disappears from every list. The audit history keeps when it was issued and revoked.</p>
      </ConfirmDialog>
    </div>
  );
}

function CredentialTable({ rows, caption, column, empty, onRevoke, onDelete }: {
  rows: CredentialListRow[];
  caption: string;
  column: string;
  empty: string;
  onRevoke: (id: string) => void;
  onDelete?: (id: string) => void;
}) {
  return <Card>
        <Table caption={caption} density="compact">
          <thead>
            <tr>
              <Th>{column}</Th>
              <Th>Principal</Th>
              <Th>Kind</Th>
              <Th>Issued</Th>
              <Th>Expires</Th>
              <Th>Last used</Th>
              <Th>State</Th>
              <Th>Failures</Th>
              <Th>Action</Th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const name = keyName(row.number, row.credential_id);
              return (
                <tr key={row.credential_id}>
                  <Td mono>{name}</Td>
                  <Td>
                    <Principal row={row} />
                  </Td>
                  <Td>{words(row.kind)}</Td>
                  <Td mono>{when(row.issued_at)}</Td>
                  <Td>
                    <KeyExpires row={row} />
                  </Td>
                  <Td>
                    <KeyLastUsed at={row.last_used_at} />
                  </Td>
                  <Td>
                    <Badge tone={TONES[row.state]}>{keyState(row)}</Badge>
                  </Td>
                  <Td>{row.failures_24h}</Td>
                  <Td>
                    {row.kind === "ADMIN" ? (
                      <span className="muted">owner tooling</span>
                    ) : row.state === "live" ? (
                      <span className="key-actions">
                        {row.kind === "AGENT" && row.number !== null ? (
                          <RotateKey
                            principalId={row.principal_id}
                            agentName={principalName("Agent", row.label, row.principal_number, row.principal_id)}
                            replaced={row}
                          />
                        ) : null}
                        <Button
                          size="small"
                          onClick={() => {
                            onRevoke(row.credential_id);
                          }}
                        >
                          Revoke {name.toLowerCase()}
                        </Button>
                      </span>
                    ) : onDelete !== undefined ? (
                      <Button
                        size="small"
                        onClick={() => {
                          onDelete(row.credential_id);
                        }}
                      >
                        Delete {name.toLowerCase()}
                      </Button>
                    ) : null}
                  </Td>
                </tr>
              );
            })}
          </tbody>
        </Table>
        {rows.length === 0 ? <EmptyState title={empty} /> : null}
      </Card>;
}

/** API keys are issued for agents, an existing one or one created for the key; people use the
 * account setup flow. */
export function IssueCredential({ data }: { data: CredentialsPage }) {
  const queryClient = useQueryClient();
  const eligible = data.principals.filter((row) => row.kind === "AGENT" && row.active);
  const first = eligible[0]?.principal_id ?? NEW_AGENT;
  const [open, setOpen] = useState(false);
  const [principal, setPrincipal] = useState(first);
  const [name, setName] = useState("");
  const [lifetime, setLifetime] = useState<KeyLifetime | "">("");
  const issue = useShowOnce(issueCredentialMutation());
  const creating = principal === NEW_AGENT;
  const chosen = creating ? name.trim() !== "" : eligible.some((row) => row.principal_id === principal);
  const ready = chosen && lifetime !== "";
  const begin = () => {
    if (!creating && !chosen) setPrincipal(first);
    setLifetime("");
    issue.clear();
    setOpen(true);
  };
  // The palette's Issue API key opens this dialog as the button would; its step-up is its own (#678).
  useCommand("issue-key", begin);
  return (
    <>
      <Button
        variant="primary"
        onClick={begin}
      >
        Issue an API key
      </Button>
      <ConfirmDialog
        open={open}
        title="Issue an API key"
        confirm="Issue API key"
        pending={issue.pending}
        confirmDisabled={!ready}
        error={issue.error}
        onConfirm={() => {
          if (!chosen || lifetime === "") return;
          const body = creating ? { principal, lifetime, label: name.trim() } : { principal, lifetime };
          void issue.issue({ body }).then((done) => {
            if (done) {
              setOpen(false);
              setName("");
              void queryClient.invalidateQueries({ queryKey: [{ _id: "listCredentials" }] });
              void queryClient.invalidateQueries({ queryKey: [{ _id: "listAgents" }] });
            }
          });
        }}
        onClose={() => {
          setOpen(false);
        }}
      >
        <p>
          Choose the agent the key is for, or create one for the tool that will use it, and a lifetime of up to
          90 days, or Never. The key appears once and is never stored; only identifiers are audited.
        </p>
        <Field label="Agent">
          <select
            value={principal}
            onChange={(event) => {
              setPrincipal(event.target.value);
            }}
          >
            {eligible.map((row) => (
              <option key={row.principal_id} value={row.principal_id}>
                {principalName("Agent", row.label, row.number, row.principal_id)} · {plural(row.live, "live key", "live keys")}
              </option>
            ))}
            <option value={NEW_AGENT}>New agent…</option>
          </select>
        </Field>
        {creating ? (
          <Field label="Name">
            <input
              value={name}
              maxLength={80}
              placeholder="Coding agent on my laptop"
              onChange={(event) => {
                setName(event.target.value);
              }}
            />
          </Field>
        ) : null}
        <KeyLifetimeSelect value={lifetime} onChange={setLifetime} />
        <Problem error={null} />
      </ConfirmDialog>
      <SecretDialog secret={issue.secret} onClose={issue.close} />
    </>
  );
}
