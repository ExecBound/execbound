// SPDX-License-Identifier: AGPL-3.0-only
import { useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState, type ReactNode } from "react";

import { readMonitorQueryKey, verifyMonitorSetupMutation } from "../../api/@tanstack/react-query.gen";
import type { MonitorSetupVerification } from "../../api/types.gen";
import { useEdition } from "../../edition/context";
import { useServerMutation } from "../../lib/mutation";
import { copyFor } from "../../lib/refusal";
import { useSession } from "../../lib/session";
import { when } from "../../lib/when";
import { Button } from "../ui/Button";
import { Definition, Definitions } from "../ui/Definitions";
import { DialogClose, DialogSurface, DialogTitle } from "../ui/dialog";
import { Field } from "../ui/Field";
import { Time } from "../ui/Time";
import { useListening } from "./listening";
import { ServiceOperatorCopy } from "./ServiceOperatorCopy";
import { PROVIDERS, setupInstructions, UUID, validConfiguration, type MonitorProvider } from "./setup";
import { Snippet } from "./Snippet";

function Verification({ result, children }: { result: MonitorSetupVerification; children?: ReactNode }) {
  const { operatorCommands } = useEdition();
  const titles = {
    awaiting_sync: "Registered — awaiting first sync",
    reporting: "Reporting — first sync verified",
    attention: "Collection needs attention",
    inactive: "Connection is inactive",
  };
  return (
    <section aria-label="Connection verification" aria-live="polite">
      <h3>{titles[result.state]}</h3>
      <p>{result.label}</p>
      {result.state === "awaiting_sync" ? (
        operatorCommands
          ? <p>Registration saved the connection metadata. Run the collection command on your trusted host, then check again. No completed sync has been verified.</p>
          : <p>Registration saved the connection metadata. No completed sync has been verified. Check again once the first collection has run.</p>
      ) : null}
      {children}
      {result.state === "reporting" ? <p>ExecBound recorded a successful collection run within the last 24 hours. This confirms that collection ran; it does not prove complete coverage or that a schedule is running.</p> : null}
      {result.state === "attention" ? (
        <p>
          {operatorCommands ? "Run the collector again after correcting its reported error or permissions." : "The collection reported an error or a missing permission, which whoever connected this provider corrects before it collects again."}
          {" "}An older sync, a partial run, or unavailable capabilities does not establish current coverage.
        </p>
      ) : null}
      {result.state === "inactive" ? <p>A revoked connection cannot collect. Ask your operator to register a new connection and use its new identifier.</p> : null}
      <Definitions aria-label="Persisted collection evidence">
        <Definition term="Checked">{when(result.checked_at)}</Definition>
        <Definition term="Last collection run">{result.last_run_at === null ? "No run recorded" : when(result.last_run_at)}</Definition>
        <Definition term="Last inventory sync">{result.last_sync_at === null ? "No sync recorded" : when(result.last_sync_at)}</Definition>
        <Definition term="Last outcome">{result.last_outcome ?? "Not run"}</Definition>
        {result.last_error_code !== null ? <Definition term="Collection error">{result.last_error_code}</Definition> : null}
        <Definition term="Recent events shown">{result.recent_observations} from this connection in the latest 200 visible observations</Definition>
        <Definition term="Latest event received">{result.latest_observation_at === null ? "No event in this view; inventory collection may still work" : when(result.latest_observation_at)}</Definition>
      </Definitions>
      <h3>Permissions and capabilities observed</h3>
      {Object.keys(result.capabilities).length === 0 ? <p>No provider probe recorded yet.</p> : (
        <ul>{Object.entries(result.capabilities).map(([name, capability]) => <li key={name}>{name.replaceAll("_", " ")}: {capability.state}</li>)}</ul>
      )}
      <p>Unavailable or forbidden capabilities leave gaps. An empty event list does not establish that no activity occurred.</p>
      <Link to="/monitor" search={{ view: result.provider === "entra_agent_id" ? "agents" : "inventory" }}>View collected {result.provider === "entra_agent_id" ? "agents" : "inventory"}</Link>
      {result.state === "reporting" ? (
        <p className="monitor-next">
          Next:{" "}
          {result.provider === "entra_agent_id" ? (
            <Link to="/agents" search={{ ungoverned: "yes" }}>Review agents with consequential reach that nothing governs</Link>
          ) : (
            <Link to="/agents">Govern a story: add an agent for it and choose Tines story as its host</Link>
          )}
        </p>
      ) : null}
    </section>
  );
}

/** An operator completes provisioning on the trusted host; the console verifies evidence.
 * No provider credential, arbitrary endpoint, or browser-side connection test is accepted.
 * Where the edition offers no operator commands (a hosted service), the host steps give way to
 * who connects a provider and how to ask, and the guide goes from the provider to verification.
 */
interface MonitorSetupProps {
  onClose: () => void;
  provider?: MonitorProvider;
  connectionId?: string;
  /** Where this deployment connects Tines from the console (#678): opens Connect Tines. */
  onConnectTines?: () => void;
  /** Where it connects Microsoft Entra by consent from the console: opens Connect Microsoft Entra. */
  onConnectEntra?: () => void;
}

export function MonitorSetup(props: MonitorSetupProps) {
  const session = useSession();
  return <SetupForSpace key={session.space?.id ?? "all"} {...props} />;
}

function SetupForSpace({
  onClose,
  provider: initialProvider = "tines",
  connectionId = "",
  onConnectTines,
  onConnectEntra,
}: MonitorSetupProps) {
  const session = useSession();
  const { operatorCommands } = useEdition();
  const queryClient = useQueryClient();
  const [step, setStep] = useState(connectionId === "" ? 1 : 4);
  const [provider, setProvider] = useState<MonitorProvider>(initialProvider);
  const [label, setLabel] = useState("Monitoring source");
  const [team, setTeam] = useState("");
  const [connection, setConnection] = useState(connectionId);
  const [checkedConnection, setCheckedConnection] = useState<string | null>(null);
  // The last answer stays on screen while the listener checks again, so it does not blink.
  const [answer, setAnswer] = useState<MonitorSetupVerification | undefined>(undefined);
  const verification = useServerMutation({
    ...verifyMonitorSetupMutation(),
    onSuccess: (fresh) => {
      setAnswer(fresh);
      void queryClient.invalidateQueries({ queryKey: readMonitorQueryKey() });
    },
    onError: () => {
      setAnswer(undefined);
    },
  });
  const forget = () => {
    setAnswer(undefined);
    verification.reset();
  };
  const listener = useListening(
    () => {
      verification.mutate({ body: { provider, connection_id: connection } });
    },
    {
      // Only while the last answer for this very connection asked to wait, and nothing failed.
      active:
        answer?.state === "awaiting_sync" &&
        answer.connection_id === connection &&
        checkedConnection === connection &&
        verification.error === null,
      pending: verification.isPending,
    },
  );
  const config = { provider, label, team, space: session.space?.id ?? null };
  const instructions = setupInstructions(config, UUID.test(connection) ? connection : "");
  const needsSpace = session.space === null && session.spaces > 1;
  const archived = session.space?.archived === true;
  const configured = validConfiguration(config) && !needsSpace && !archived;
  const result = answer;
  const names = ["Choose a provider", "Configure access", "Register and collect", "Verify evidence"];
  // The steps this edition walks through: the host steps only where its reader can run them.
  const flow = operatorCommands ? [1, 2, 3, 4] : [1, 4];
  const position = flow.indexOf(step);
  const previous = flow[position - 1];
  const next = flow[position + 1];
  return (
    <DialogSurface open onOpenChange={(open) => { if (!open) onClose(); }} className="dialog dialog-wide">
      <header className="drawer-head">
        <DialogTitle className="drawer-title">Connect a source</DialogTitle>
        <DialogClose className="btn btn-ghost">Close</DialogClose>
      </header>
      <div className="dialog-body">
        <p className="muted">Step {position + 1} of {flow.length} · {names[step - 1]}</p>
        <p>Monitoring gives visibility into external activity and authority. It does not prevent actions or move vendor credentials behind ExecBound.</p>
        <p><strong>Placement:</strong> {session.space?.name ?? (needsSpace ? "Choose a Space in the space switcher first" : "This tenant's default Space")}.</p>
        {step === 1 ? <>
          <Field id="monitor-provider" label="Provider">
            <select id="monitor-provider" value={provider} onChange={(event) => {
              setProvider(event.target.value as MonitorProvider);
              setConnection("");
              setCheckedConnection(null);
              forget();
            }}>
              <option value="tines">Tines — stories and audit metadata</option>
              <option value="entra_agent_id">Microsoft Entra — agent identities and grants</option>
              <option disabled>Other providers — unavailable</option>
            </select>
          </Field>
          {provider === "tines" && onConnectTines !== undefined ? <>
            <h3>Connect Tines from here</h3>
            <p>Paste a read-only Tines API key. It is sealed for ExecBound&apos;s collector, which collects on a schedule, and this web service cannot read it back.</p>
            <Button variant="primary" onClick={onConnectTines}>Connect Tines</Button>
          </> : null}
          {provider === "entra_agent_id" && onConnectEntra !== undefined ? <>
            <h3>Connect Microsoft Entra from here</h3>
            <p>A directory administrator signs in with Microsoft and approves read-only access for this deployment&apos;s app, which collects on a schedule. Nothing is created until they approve.</p>
            <Button variant="primary" onClick={onConnectEntra}>Connect Microsoft Entra</Button>
          </> : null}
          {operatorCommands ? <>
            <h3>Customer-operated collector</h3>
            <p>An administrator runs the supported collector on a trusted ExecBound host with access to this deployment's database. This console generates its configuration and verifies the resulting records; clicking through does not run a collector.</p>
            <p>If you only have console access, your deployment operator must complete the host steps. An ExecBound sign-in session is not a collector credential.</p>
          </> : (provider === "tines" && onConnectTines !== undefined) || (provider === "entra_agent_id" && onConnectEntra !== undefined) ? null : <>
            <h3>Who connects a provider</h3>
            <ServiceOperatorCopy />
            <p>Once it is connected, verify its first collection here with the connection ID shown in Connections.</p>
          </>}
        </> : null}
        {step === 2 ? <>
          <h3>{PROVIDERS[provider]} minimum access</h3>
          {provider === "tines" ? <>
            <p>Use a service or team API key restricted to the teams being monitored, with read access to stories, actions and credential metadata. Audit and AI-audit access require the relevant Tines plan and permissions; the collector probes and reports availability.</p>
            <p>Ordinary connector execution is not established by management audit records. Selected story events need separate instrumentation; audit and AI-audit collection remain fixture-tested.</p>
          </> : <>
            <p>Create a dedicated collection app registration with the Microsoft Graph application permissions AgentIdentity.Read.All, Application.Read.All, AuditLog.Read.All and Directory.Read.All, and have a directory administrator grant consent. Keep it separate from any app that executes actions.</p>
            <p>Graph enumerates directory identities and grants. Azure RBAC, identities absent from the directory, and group-mediated role paths are not covered.</p>
          </>}
          <Field id="monitor-label" label="Connection name" hint="Letters, numbers, spaces, dots, underscores and hyphens; start with a letter or number.">
            <input id="monitor-label" value={label} maxLength={96} aria-describedby="monitor-label-hint" onChange={(event) => { setLabel(event.target.value); }} />
          </Field>
          {provider === "tines" ? <Field id="monitor-team" label="Tines team ID (optional)" hint="Leave blank to collect every team the key can read. The key's permissions still bound access.">
            <input id="monitor-team" value={team} maxLength={64} aria-describedby="monitor-team-hint" onChange={(event) => { setTeam(event.target.value); }} />
          </Field> : null}
          <p>Provider secrets stay in a private file on the collector host. ExecBound registers only a fingerprint. Never paste a provider secret into the connection name, this console, or a command argument.</p>
          {needsSpace ? <p role="alert">Close this guide and choose a Space before generating a registration command.</p> : null}
          {archived ? <p role="alert">This Space is archived. Choose an active Space before registering a source.</p> : null}
        </> : null}
        {step === 3 && instructions !== null ? <>
          <h3>1. Prepare the trusted host</h3>
          <p>Run from the deployed ExecBound repository with its locked Python dependencies. Set DATABASE_URL to this deployment's runtime database, using the existing private runtime configuration. The operator must have authorized database access; the browser cannot supply it.</p>
          <p>Save a current ExecBound ADMIN credential for this tenant in <code>local-data/admin-token.txt</code>. Save the following template as <code>{instructions.keyFile}</code>, replace every placeholder locally, and restrict both files to the operator account. Keep them outside version control.</p>
          <Snippet label="Environment template" value={instructions.environment} />
          <h3>2. Register once</h3>
          <p>This stores a connection in the Space shown above and prints its connection_id. One active connection per provider per Space is supported. If one already exists, use its identifier instead of registering again.</p>
          <Snippet label="Registration command" value={instructions.register} />
          <Field id="monitor-registered-id" label="Connection ID returned by registration">
            <input id="monitor-registered-id" value={connection} maxLength={36} placeholder="00000000-0000-0000-0000-000000000000" onChange={(event) => { setConnection(event.target.value.trim().toLowerCase()); forget(); }} />
          </Field>
          <h3>3. Run the first collection</h3>
          <p>{UUID.test(connection) ? "The command now uses the connection ID above." : "Replace CONNECTION_ID_FROM_REGISTRATION with the identifier printed by registration, or paste it above."} Run this command on the same host, then verify here.</p>
          <Snippet label="Collection command" value={instructions.collect} />
          <p>A run is bounded and ends. Configure your operator's scheduler for recurring collection and keep its ADMIN credential current. No schedule is created here.</p>
        </> : null}
        {step === 4 ? <>
          <h3>Check the registered {PROVIDERS[provider]} connection</h3>
          <Field id="monitor-verify-id" label="Connection ID" hint={`Use the ID ${operatorCommands ? "printed by create-connection or " : ""}shown in Connections. Only a connection visible in your current Space can be verified.`}>
            <input id="monitor-verify-id" value={connection} maxLength={36} aria-describedby="monitor-verify-id-hint" onChange={(event) => { setConnection(event.target.value.trim().toLowerCase()); forget(); }} />
          </Field>
          <Button variant="primary" disabled={!UUID.test(connection) || verification.isPending} aria-busy={verification.isPending} onClick={() => {
            setCheckedConnection(connection);
            listener.start();
            verification.mutate({ body: { provider, connection_id: connection } });
          }}>{verification.isPending && !listener.listening ? "Checking recorded evidence…" : "Check connection"}</Button>
          {verification.error !== null ? <p role="alert" className="problem">{copyFor(verification.error)} Confirm the connection ID, provider and current Space, and that registration finished on this deployment.</p> : null}
          {result !== undefined && checkedConnection === connection ? (
            <Verification result={result}>
              {listener.listening ? (
                <>
                  <p>
                    Listening for the first completed collection run. Last checked at <Time at={result.checked_at} />;
                    checks again every 10 seconds while this tab is open, for up to 10 minutes.
                  </p>
                  <Button onClick={listener.stop}>Stop listening</Button>
                </>
              ) : listener.stoppedAtCap ? (
                <p>Stopped listening after 10 minutes. Check again once the collector has run.</p>
              ) : null}
            </Verification>
          ) : null}
          {result === undefined && verification.error === null ? <p className="muted">No setup success is assumed. This check reads registration, collection outcomes and event receipts already stored by the server.</p> : null}
        </> : null}
      </div>
      <footer className="dialog-foot">
        {previous !== undefined ? <Button onClick={() => { setStep(previous); }}>Back</Button> : null}
        {next !== undefined ? <Button variant="primary" disabled={step === 2 && !configured} onClick={() => { setStep(next); }}>{next === 4 ? "Verify connection" : "Continue"}</Button> : <DialogClose className="btn">Done</DialogClose>}
      </footer>
    </DialogSurface>
  );
}
