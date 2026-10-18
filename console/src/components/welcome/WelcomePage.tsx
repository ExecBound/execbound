// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useEffect, useRef, useState, type ReactNode } from "react";

import { listAgentsOptions, readSamplesOptions, readSetupOptions } from "../../api/@tanstack/react-query.gen";
import type { SampleStatusView, SetupView } from "../../api/types.gen";
import { useEdition } from "../../edition/context";
import { useSession } from "../../lib/session";
import { Icon } from "../../shell/icons";
import { NewAgent } from "../directory/AgentsList";
import { handle, principalName } from "../directory/format";
import { Problem } from "../directory/forms";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { PageHeading } from "../ui/PageHeading";
import { Time } from "../ui/Time";
import { useWatchFirst } from "../monitor/connect";
import { ConnectionNeeded } from "./ConnectionNeeded";
import { LearningExample } from "./LearningExample";
import { ServiceOperatorWords } from "./OperatorSteps";
import { PilotCard } from "./PilotCard";
import { ReviewCoverage } from "./ReviewCoverage";
import { SampleChecks } from "./SampleChecks";
import { SampleTargets } from "./SampleTargets";
import { SetupCardToggle } from "./SetupCardToggle";
import { milestone, openingStep, STEP_LABELS, stepDone, STEPS, type Step } from "./setup";
import { WatchFirstLine } from "./WatchFirstLine";
import "./welcome.css";

export interface StepChange {
  replace?: boolean;
}

/**
 * Getting started (#678). The step lives in the address: the route passes `step` and `onStep`,
 * and a test may render the page without them, when it keeps its own. With no step named, the
 * page reads the Space's setup (`GET /setup`) and its samples together and opens on the first
 * step left, once both have answered, so it never shows one step and then jumps to another.
 */
export function WelcomePage({ step: named, onStep }: { step?: Step; onStep?: (next: Step, options?: StepChange) => void } = {}) {
  const [own, setOwn] = useState<Step | undefined>(undefined);
  const step = onStep === undefined ? own : named;
  const go = (next: Step, options?: StepChange) => {
    if (onStep === undefined) setOwn(next);
    else onStep(next, options);
  };
  // An edition's own part follows the steps (#496); core's page stands on core's reads.
  const { Welcome } = useEdition();
  const session = useSession();
  // The workspace's sample targets (#420), core's own read (#496).
  const query = useQuery({ ...readSamplesOptions(), throwOnError: (_error, failed) => failed.state.data === undefined });
  // What is already set up in this Space, from records; arriving here always reads it afresh.
  const setup = useQuery({ ...readSetupOptions(), staleTime: 30_000, refetchOnMount: "always" });
  const ready = query.data !== undefined && (step !== undefined || !setup.isPending);
  const opening = ready && step === undefined ? openingStep(setup.data, query.data) : undefined;
  const written = useRef(false);
  useEffect(() => {
    // The opening step goes into the address once, as a replacement, so a later read cannot
    // move the page and Back gains no entry.
    if (opening === undefined || written.current) return;
    written.current = true;
    go(opening, { replace: true });
  });
  if (query.data === undefined || !ready) return <><PageHeading title="Getting started" /><p role="status">Loading setup…</p></>;
  const current: Step = step ?? opening ?? "example";
  const index = STEPS.indexOf(current);
  const view = setup.data;
  return <>
    <PageHeading title="Getting started" lead="Try a safe example, connect your agent, and see why each action is allowed, denied or sent for review." />
    {view?.state === "choose_space" ? <p role="status" className="muted">Choose a Space in the sidebar to see what is left to set up in it.</p> : null}
    <nav className="setup-steps" aria-label="Setup steps">
      {STEPS.map((key, position) => {
        const finished = stepDone(key, view);
        return <button type="button" key={key} className="setup-step" aria-current={current === key ? "step" : undefined} onClick={() => { go(key); }}>
          <span>{finished ? <Icon name="check" /> : position + 1}</span>{STEP_LABELS[key]}{finished ? <span className="sr-only">, done</span> : null}
        </button>;
      })}
    </nav>
    {current === "example" ? <>{view?.state === "ready" && !view.samples_here ? <p className="notice">Sample targets are added to the workspace&apos;s default Space, not the Space selected in the sidebar.</p> : null}<SampleTargets samples={query.data} /><LearningExample /></> : null}
    {current === "connect" ? <ConnectStep setup={view} samples={query.data} /> : null}
    {current === "verify" ? <VerifyStep setup={view} /> : null}
    {current === "controls" ? <ControlsStep setup={view} /> : null}
    <div className="setup-actions">
      <Button disabled={index === 0} onClick={() => { const previous = STEPS[index - 1]; if (previous !== undefined) go(previous); }}>Back</Button>
      {index < STEPS.length - 1 ? <Button onClick={() => { const next = STEPS[index + 1]; if (next !== undefined) go(next); }}>{`Next: ${STEP_LABELS[STEPS[index + 1] ?? "controls"]}`}</Button> : <Link to="/">Go to Home</Link>}
    </div>
    <SetupCardToggle tenant={session.tenant.id} />
    <Welcome />
  </>;
}

/** One done step's record: what holds, when, and a link to the record by its identifier. */
function DoneNote({ children }: { children: ReactNode }) {
  return <p className="setup-done"><Icon name="check" /> {children}</p>;
}

function AgentKeyNote({ setup }: { setup: SetupView | undefined }) {
  const item = milestone(setup, "agent_key");
  if (item?.state !== "done" || item.record === null) return null;
  return <DoneNote>API key issued {item.at !== null ? <Time at={item.at} /> : null}. <Link to="/agents/$agentId" params={{ agentId: item.record.id }}>Open the agent</Link></DoneNote>;
}

function FirstRequestNote({ setup }: { setup: SetupView | undefined }) {
  const item = milestone(setup, "first_request");
  if (item?.state !== "done" || item.record === null) return null;
  return <DoneNote>First request <Link to="/activity" search={{ open: item.record.id }}>{item.record.request_ref}</Link> {item.at !== null ? <Time at={item.at} /> : null}</DoneNote>;
}

function PolicyNote({ setup }: { setup: SetupView | undefined }) {
  const item = milestone(setup, "policy");
  if (item?.state !== "done" || item.record === null) return null;
  return <DoneNote>Policy active since {item.at !== null ? <Time at={item.at} /> : null}. <Link to="/policy/$bundleId" params={{ bundleId: item.record.id }}>Open the policy</Link></DoneNote>;
}

function DecisionNote({ setup }: { setup: SetupView | undefined }) {
  const item = milestone(setup, "first_decision");
  if (item?.state !== "done" || item.record === null) return null;
  return <DoneNote>First approval decided {item.at !== null ? <Time at={item.at} /> : null}, <Link to="/activity" search={{ open: item.record.id }}>{item.record.request_ref}</Link></DoneNote>;
}

/** A registered agent by its one name, "Agent 1" or its label with the handle beside it (#678),
 * linked by its row as before. */
function AgentEntry({ agent }: { agent: { row_id: string; name: string | null; number: number | null } }) {
  const name = principalName("Agent", agent.name, agent.number, agent.row_id);
  const tag = handle("Agent", agent.number, agent.row_id);
  return <span>
    <Link to="/agents/$agentId" params={{ agentId: agent.row_id }} search={{ section: "connection" }}>{name}</Link>
    {name !== tag ? <> <span className="faint">{tag}</span></> : null}
  </span>;
}

function ConnectStep({ setup, samples }: { setup: SetupView | undefined; samples: SampleStatusView }) {
  const agents = useQuery(listAgentsOptions({ query: { population: "registered" } }));
  const ready = setup?.state === "ready" ? setup : undefined;
  return <Card title="Connect an agent" aside={<NewAgent />}>
    <AgentKeyNote setup={setup} />
    {ready !== undefined && !ready.connected ? <div className="setup-readiness">
      <p><strong>Requests from agents are refused until this Space has a registered connection and an active policy.</strong></p>
      <ConnectionNeeded setup={ready} samples={samples} />
    </div> : null}
    {ready !== undefined && ready.connected && milestone(ready, "policy")?.state === "todo" ? <p className="setup-readiness"><strong>Requests from agents are refused until a policy is active in this Space.</strong> <Link to="/policy">Choose a policy</Link></p> : null}
    <p>Give your agent a name, issue its API key, then choose its host. The connection page guides you through all three steps.</p>
    <Problem error={agents.error} />
    {agents.data === undefined ? agents.error === null ? <p role="status">Loading agents…</p> : null : <>
      <ul className="setup-links">{agents.data.agents.map((agent) => <li key={agent.row_id}>
        <AgentEntry agent={agent} />
        <span className="muted">{agent.live > 0 ? "API key issued" : "Needs an API key"} · {agent.last_request !== null ? "Request received" : "Waiting for first request"}</span>
      </li>)}</ul>
      {agents.data.agents.length === 0 ? <p>No active agent is configured in this Space yet. Start with Add agent above.</p> : null}
      <RegisteredAgentPages next={agents.data.next} />
    </>}
    {ready !== undefined && milestone(ready, "first_request")?.state === "todo" ? <WatchFirstLine /> : null}
    <p className="muted">Only participating requests are governed. Remove direct access to protected provider credentials from the agent to prevent bypass.</p>
  </Card>;
}

function VerifyStep({ setup }: { setup: SetupView | undefined }) {
  const agents = useQuery({ ...listAgentsOptions({ query: { population: "registered" } }), refetchInterval: 10_000 });
  // The samples, polled like the agents, so a sample request appears without a reload.
  const samples = useQuery({ ...readSamplesOptions(), refetchInterval: 10_000 }).data;
  return <Card title="Verify protection">
    <FirstRequestNote setup={setup} />
    <p>After configuring your host, submit a request for a test resource you control. Open the agent connection to check the recorded result.</p>
    {samples !== undefined && samples.state !== "absent" ? <SampleChecks samples={samples} /> : null}
    <Problem error={agents.error} />
    {agents.data === undefined ? agents.error === null ? <p role="status">Checking recorded requests…</p> : null : <>
      <ul className="setup-links">{agents.data.agents.map((agent) => <li key={agent.row_id}>
        <AgentEntry agent={agent} />
        <Badge tone={agent.last_request !== null ? "allow" : "hold"}>{agent.last_request !== null ? "Request received" : "No request yet"}</Badge>
        {agent.last_execution_id !== null && agent.last_request_ref !== null ? <Link to="/activity" search={{ open: agent.last_execution_id }}>{agent.last_request_ref}</Link> : null}
      </li>)}</ul>
      {agents.data.agents.length === 0 ? <p>No active agent is configured in this Space yet. Connect an agent before verifying its requests.</p> : null}
      <RegisteredAgentPages next={agents.data.next} />
    </>}
    <ol className="steps">
      <li><strong>Authentication:</strong> a request appears under the correct agent name.</li>
      <li><strong>Decision:</strong> open Why to see the policy and trusted facts used.</li>
      <li><strong>Execution:</strong> check whether a provider actually acted, the request was denied, or a person still needs to approve it.</li>
      <li><strong>Coverage:</strong> confirm the action uses the expected gateway or external executor. Monitoring alone does not prevent actions.</li>
    </ol>
    <p><Link to="/activity">Open Activity</Link> · <Link to="/agents" search={{ population: "registered" }}>Configure an agent</Link></p>
    <details className="setup-details"><summary>What a connection does not prove</summary><p className="muted">An unknown provider outcome needs investigation before another attempt. A successful connection or tool list alone does not verify the execution path.</p></details>
  </Card>;
}

function RegisteredAgentPages({ next }: { next: string | null }) {
  return <>
    {next !== null ? <p className="muted">This is the first page of registered agents in this Space. More agents are available.</p> : null}
    <p><Link to="/agents" search={{ population: "registered" }}>View all registered agents</Link>{next !== null ? <> · <Link to="/agents" search={{ population: "registered", cursor: next }}>Next registered agents</Link></> : null}</p>
  </>;
}

function ControlsStep({ setup }: { setup: SetupView | undefined }) {
  const watching = useWatchFirst();
  const reviewer = milestone(setup, "reviewer");
  return <div className="cards">
    <Card title="Choose your policy"><PolicyNote setup={setup} /><p>Start with a named template or copy your active policy. Edit rules and limits, validate the draft, then preview its effect on recent requests before activation.</p><p><Link to="/policy" className="btn btn-primary">Open policies</Link></p></Card>
    <Card title="Choose who can review"><DecisionNote setup={setup} />{setup?.state === "ready" && reviewer?.state === "todo" ? <p><strong>Nobody in this Space can review the actions your policy holds yet.</strong></p> : null}{setup?.state === "ready" && setup.space_id !== null ? <ReviewCoverage spaceId={setup.space_id} /> : null}<p>Use a normal account. Add a teammate or open your own account in Users, set up sign-in, and assign the actions and resources they can review.</p><p>Administrators also need explicit review permissions. There is no separate reviewer login credential.</p><p><Link to="/people">Set up reviewers</Link> · <Link to="/approvals">Open approvals</Link></p></Card>
    <PilotCard />
    <Card title="Discover other activity"><p>Connect a monitoring source to find agents, tools and gaps in coverage. Collection gives visibility; execution controls apply only on governed paths.</p>{watching !== null ? <p><Link to="/monitor" search={{ setup: watching }}>Connect a monitoring source</Link></p> : <p><ServiceOperatorWords>Monitoring setup in the console comes later here. Ask your service operator to connect a source</ServiceOperatorWords></p>}</Card>
  </div>;
}
