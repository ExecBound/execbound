// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";

import { issueAgentCredentialMutation, readConnectionOptions } from "../../api/@tanstack/react-query.gen";
import type { AgentDetail } from "../../api/types.gen";
import { useEdition } from "../../edition/context";
import { useSession } from "../../lib/session";
import { Field, KeyLifetimeSelect, Problem, type KeyLifetime } from "../directory/forms";
import { SecretDialog } from "../directory/SecretDialog";
import { useShowOnce } from "../directory/showOnce";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { CopyRecipe } from "./CopyRecipe";
import { ExampleRequest } from "./ExampleRequest";
import { FirstRequest } from "./FirstRequest";
import { TinesStory } from "./TinesStory";
import { AGENT_HOSTS, isAgentHost, savedAgentHost, saveAgentHost, type AgentHost } from "./agent-host";

export function AgentConnection({ detail }: { detail: AgentDetail }) {
  const [host, setHost] = useState<AgentHost | "">(() => savedAgentHost(detail.row_id));
  const [lifetime, setLifetime] = useState<KeyLifetime | "">("");
  const [checking, setChecking] = useState(false);
  const [checked, setChecked] = useState(false);
  const [checkError, setCheckError] = useState<unknown>(null);
  const cache = useQueryClient();
  const session = useSession();
  const { FixtureHint } = useEdition();
  const connection = useQuery({ ...readConnectionOptions(), staleTime: 30_000 });
  const issue = useShowOnce(issueAgentCredentialMutation());
  const agent = detail.agent;
  if (!agent?.active) return null;
  const live = detail.credentials.some((credential) => credential.state === "live");
  const received = detail.recent.length > 0;
  const executed = detail.recent.some((request) => request.state === "EXECUTED");
  const origin = connection.data?.origin;
  const recipe = host === "mcp"
    ? `Server URL: ${origin ?? ""}/mcp/\nTransport: Streamable HTTP\nAuthorization: Bearer <API key>`
    : connection.data?.recipes[host] ?? "";
  // The sample development workstation's hint, which core names once samples are installed with
  // an open incident, with the operation the samples answer to (#545). Where core's answer is in
  // and names none, the edition may name its own (#496), which on the hosted service is a
  // claimed sandbox's fixture workstation.
  const workstation = connection.data?.workstation;
  return (
    <Card title="Connect this agent" id="agent-connection" aside={<Badge tone={received ? "allow" : "hold"}>{received ? "Requests received" : "Setup needed"}</Badge>}>
      <ol className="connection-steps">
        <li>
          <h3>1. Create its API key</h3>
          <p>{live ? "An active API key exists. Use the saved key, or issue another if you no longer have it. Revoke a lost key in API keys below; issuing another does not revoke existing keys." : "Issue an API key for this agent. It is shown once; save it in your client's secret configuration."}</p>
          <form className="form-row" onSubmit={(event) => {
            event.preventDefault();
            if (lifetime === "") return;
            void issue.issue({ path: { principal_id: agent.principal_id }, body: { lifetime } }).then((done) => {
              if (done) void cache.invalidateQueries({ queryKey: [{ _id: "readAgent" }] });
            });
          }}>
            <KeyLifetimeSelect value={lifetime} onChange={setLifetime} label="API key expires after" />
            <Button type="submit" disabled={issue.pending || lifetime === ""}>{live ? "Issue another API key" : "Issue API key"}</Button>
          </form>
          <Problem error={issue.error} />
        </li>
        <li>
          <h3>2. Configure your agent host</h3>
          <Field label="Agent host">
            <select value={host} onChange={(event) => { const value = event.target.value; if (isAgentHost(value)) { setHost(value); saveAgentHost(agent.principal_id, value); } }}>
              <option value="" disabled>Choose a supported host</option>
              {AGENT_HOSTS.map(([value, label]) => <option value={value} key={value}>{label}</option>)}
            </select>
          </Field>
          {host === "tines" ? <TinesStory /> : connection.error !== null ? <Problem error={connection.error} /> : origin === undefined ? <p role="status">Loading gateway configuration…</p> : host === "" ? <p>Select a host to see its connection instructions.</p> : recipe === "" ? <p role="alert">Instructions for this host are unavailable. Choose Generic MCP client for the server connection details.</p> : <CopyRecipe label="Agent configuration" text={recipe} />}
          <p className="muted">Replace <code>&lt;API key&gt;</code> with the key you issued, or set EXECBOUND_CREDENTIAL in the client environment. Provider credentials stay with the gateway or approved executor.</p>
          <details className="setup-details"><summary>About hosts</summary>
            <p className="muted">Host preference is saved only in this browser. It does not grant access or identify the agent.</p>
            <p className="muted">Claude Desktop and claude.ai require OAuth; that connection method is not available here yet.</p>
          </details>
        </li>
        <li>
          <h3>3. Review permissions</h3>
          <p><Link to="/agents/$agentId" params={{ agentId: agent.principal_id }} search={{ section: "permissions" }}>Review this agent’s Permissions</Link> for conditional rules, resource scope, and shared limits before submitting a test request.</p>
        </li>
        <li>
          <h3>4. Verify a governed request</h3>
          {!detail.bundle ? <p className="problem">No policy is selected. <Link to="/policy">Choose and activate a policy</Link> before testing.</p> : <p>A policy is selected. Ask the host to list its tools, then submit an intended request for a test resource you control. A tool list alone does not prove enforcement.</p>}
          {workstation !== null && workstation !== undefined ? (
            <ExampleRequest label="Sample target test" target={workstation} operationRef={connection.data?.operation_ref ?? null} />
          ) : connection.data !== undefined ? <FixtureHint /> : null}
          <Button variant="primary" disabled={checking} onClick={() => {
            setChecking(true); setChecked(false); setCheckError(null);
            void cache.refetchQueries({ queryKey: [{ _id: "readAgent" }], type: "active" }, { throwOnError: true })
              .then(() => { setChecked(true); }).catch((error: unknown) => { setCheckError(error); })
              .finally(() => { setChecking(false); });
          }}>{checking ? "Checking…" : "Check connection"}</Button>
          <Problem error={checkError} />
          <FirstRequest detail={detail} />
          <div role="status">
            {checked || received ? <p>{received ? "Authenticated requests from this agent appear in Activity." : "No governed request is recorded yet. Check the server URL and API key in your host, then submit a request."}</p> : null}
            {received ? <p>{executed ? "A recorded request executed. Open its details for the provider evidence and enforcement path." : "No confirmed execution appears in these recent requests. Open Activity to inspect the policy decision and execution result."}</p> : null}
          </div>
          <p><Link to="/activity" search={{ agent: agent.principal_id }} className="btn">View this agent’s activity</Link></p>
          <p className="muted">Mode: {session.mode === "ENFORCE" ? "Enforcing participating requests" : session.mode === "OBSERVE" ? "Observe only" : "Unknown"}. Calls made outside ExecBound remain outside this protection. Discovered reach is shown separately below.</p>
        </li>
      </ol>
      <SecretDialog secret={issue.secret} onClose={issue.close} />
    </Card>
  );
}
