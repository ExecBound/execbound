// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";

import { readSamplesOptions, readSetupOptions } from "../../api/@tanstack/react-query.gen";
import type { SetupView } from "../../api/types.gen";
import { useEdition } from "../../edition/context";
import { useSession } from "../../lib/session";
import { plural } from "../../lib/words";
import { Card } from "../ui/Card";
import { ServiceOperatorWords } from "./OperatorSteps";
import { milestone } from "./setup";
import { WatchFirstLine } from "./WatchFirstLine";

const DEFAULT_SPACE =
  "Sample targets are added to the workspace's default Space; switch to it in the sidebar to try them.";

interface Words {
  text: ReactNode;
  link: ReactNode;
  /** The next step is the mode, not a record: approvals need Enforcing. */
  enforcing?: boolean;
  /** Nothing is left to set up in this Space. */
  final?: boolean;
}

/** Home's one next step, from the Space's setup read and its samples (#678). */
export function NextStep() {
  const setup = useQuery({ ...readSetupOptions(), staleTime: 30_000 });
  const samples = useQuery({ ...readSamplesOptions(), staleTime: 30_000 });
  const session = useSession();
  const { operatorCommands } = useEdition();
  const view = setup.data;
  const words = view === undefined || samples.isPending ? waiting() : wordsFor(view, samples.data?.offered === true, operatorCommands);
  const observed = view?.observed ?? null;
  const counted = observed === null ? 0 : observed.eligible + observed.held + observed.denied;
  const enforcing = words.enforcing === true;
  return <Card title={words.final === true ? "Your workspace" : "Your next step"} className="next-step">
    <p>{words.text}</p>
    {session.mode === "OBSERVE" && observed !== null && counted > 0 ? <p>
      Observe only: in the last 7 days, {plural(observed.eligible, "request")} would have run, {String(observed.held)} would have waited for a person and {String(observed.denied)} would have been denied.{" "}
      <Link to="/activity" search={{ state: "OBSERVED", since: "7d" }}>Review before enforcing</Link>
      {enforcing ? null : <> · <Link to="/tenant">Change the mode</Link></>}
    </p> : null}
    {view?.state === "ready" && milestone(view, "first_request")?.state === "todo" ? <WatchFirstLine /> : null}
    {words.link !== null ? <div className="links">{words.link}</div> : null}
  </Card>;
}

function waiting(): Words {
  return { text: "Open guided setup to try an example or connect your agent.", link: <Link to="/welcome" className="btn btn-primary">Open guided setup</Link> };
}

function wordsFor(view: SetupView, offered: boolean, operatorCommands: boolean): Words {
  if (view.state === "choose_space") return { text: "Choose a Space to see what is left to set up in it.", link: null };
  if (!view.connected) {
    if (offered && view.samples_here) {
      return {
        text: "Try ExecBound on sample targets, or ask your operator to connect a provider. Requests from agents are refused until this Space has a connection and an active policy.",
        link: <Link to="/welcome" search={{ step: "example" }} className="btn btn-primary">Add sample targets</Link>,
      };
    }
    const elsewhere = offered && view.default_space_id !== null ? <> {DEFAULT_SPACE}</> : null;
    if (operatorCommands) {
      return {
        text: <>Connect a provider to this Space first: requests from agents are refused until it has a connection and an active policy.{elsewhere}</>,
        link: <Link to="/welcome" search={{ step: "connect" }} className="btn btn-primary">See the operator steps</Link>,
      };
    }
    return { text: <><ServiceOperatorWords />{elsewhere}</>, link: null };
  }
  switch (view.next) {
    case "policy":
      return { text: "Activate a policy in this Space. Until then every request is refused.", link: <Link to="/policy" className="btn btn-primary">Open policies</Link> };
    case "agent_key":
      return { text: "Connect your first agent in this Space to see how ExecBound controls its actions.", link: <Link to="/welcome" search={{ step: "connect" }} className="btn btn-primary">Open guided setup</Link> };
    case "first_request": {
      const agent = milestone(view, "agent_key")?.record;
      return {
        text: "Finish connecting your agent and send it a first request.",
        link: agent != null
          ? <Link to="/agents/$agentId" params={{ agentId: agent.id }} className="btn btn-primary">Finish agent setup</Link>
          : <Link to="/welcome" search={{ step: "verify" }} className="btn btn-primary">Finish agent setup</Link>,
      };
    }
    case "reviewer":
      return { text: "Choose who can review the requests your policy holds.", link: <Link to="/welcome" search={{ step: "controls" }} className="btn btn-primary">Choose a reviewer</Link> };
    case "first_decision":
      return { text: "Decide a held request in Approvals to see the whole loop.", link: <Link to="/approvals" className="btn btn-primary">Open approvals</Link> };
    case null:
      break;
  }
  if (view.milestones.some((item) => item.state === "needs_enforcing")) {
    return {
      text: "Approvals need Enforcing. While this workspace observes, nothing waits for a person.",
      link: <Link to="/tenant" className="btn btn-primary">Change the mode</Link>,
      enforcing: true,
    };
  }
  return {
    text: "Review your controls, connect another agent, or add teammates who can review requests.",
    link: <><Link to="/welcome" className="btn btn-primary">Open guided setup</Link><Link to="/policy">Review policies</Link><Link to="/people">Users</Link></>,
    final: true,
  };
}
