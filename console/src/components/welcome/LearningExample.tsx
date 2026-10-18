// SPDX-License-Identifier: AGPL-3.0-only
import { Fragment, useState } from "react";

import { runLearningExampleMutation } from "../../api/@tanstack/react-query.gen";
import { useServerMutation } from "../../lib/mutation";
import { Field, Problem } from "../directory/forms";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";

type Scenario = "workstation" | "domain_controller" | "production";

export function LearningExample() {
  const [scenario, setScenario] = useState<Scenario>("workstation");
  const run = useServerMutation(runLearningExampleMutation());
  return (
    <Card title="Try a safe example" aside={<Badge tone="obs">Simulation</Badge>}>
      <p>Ask an example agent to isolate an endpoint. See how trusted facts change the policy decision.</p>
      <p className="muted">This uses a synthetic example policy. It never calls a provider, changes your policy, or counts as a connected agent.</p>
      <form className="form-row" onSubmit={(event) => {
        event.preventDefault(); run.mutate({ body: { scenario } });
      }}>
        <Field label="Example target">
          <select value={scenario} onChange={(event) => {
            setScenario(event.target.value as Scenario); run.reset();
          }}>
            <option value="workstation">Workstation · development</option>
            <option value="domain_controller">Domain controller · protected</option>
            <option value="production">Workstation · production</option>
          </select>
        </Field>
        <Button type="submit" variant="primary" disabled={run.isPending}>{run.isPending ? "Evaluating…" : "Run safe example"}</Button>
      </form>
      <Problem error={run.error} />
      {run.data !== undefined ? (
        <div className="learning-result" role="status">
          <h3><Badge tone={run.data.decision === "ALLOW" ? "allow" : run.data.decision === "DENY" ? "deny" : "hold"}>
            {run.data.decision === "REQUIRE_APPROVAL" ? "Approval required" : run.data.decision === "ALLOW" ? "Allowed by example policy" : "Denied by example policy"}
          </Badge></h3>
          <p>{run.data.reason}</p>
          <p><strong>Execution: none.</strong> This is a simulation.</p>
          <dl className="facts">
            {Object.entries(run.data.facts).map(([name, value]) => <Fragment key={name}><dt>{name.replaceAll("_", " ")}</dt><dd>{value.replaceAll("_", " ")}</dd></Fragment>)}
          </dl>
          <p className="muted">Try the other targets to compare allow, deny and approval. Your connected agent will be evaluated against your workspace policy and current trusted context.</p>
        </div>
      ) : null}
    </Card>
  );
}
