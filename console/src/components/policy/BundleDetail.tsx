// SPDX-License-Identifier: AGPL-3.0-only
import { Link } from "@tanstack/react-router";

import type { BundleDetail, LimitMeter } from "../../api/types.gen";
import { Meter } from "../charts/Meter";
import { CoverageLine } from "../directory/CoverageLine";
import { when } from "../directory/format";
import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";
import { PageHeading } from "../ui/PageHeading";
import { Table, Td, Th } from "../ui/Table";
import { duration, EFFECT, mappingName, policyName, ruleSentence, servedAction, STATE, stateWord } from "./format";
import { CopyDraft } from "./BundleList";
import { Changes, compareSummary, useComparison } from "./Compare";
import { Lifecycle } from "./Lifecycle";
import { DownloadRules } from "./RulesFile";
import { inAllSpaces, useSession } from "../../lib/session";

const PREFIX = 8;

export function BundleDetailView({
  detail,
  active,
}: {
  detail: BundleDetail;
  active: { bundle_id: string } | null;
}) {
  const state = STATE[detail.state];
  const comparison = useComparison(detail);
  // Under All spaces no Space is selected, so this bundle is no Space's selection here (#678).
  const allSpaces = inAllSpaces(useSession());
  return (
    <>
      <PageHeading
        title={policyName(detail.bundle_id)}
        lead={
          detail.active
            ? "The active selection: admission decides new requests in this Space with this bundle."
            : allSpaces
              ? "Choose a Space to see whether this policy decides its requests."
              : "This bundle is not the active selection in this Space."
        }
      />
      <p className="meta">
        <Link to="/policy">Back to Policies</Link>
      </p>
      <div className="badges" style={{ marginBottom: 14 }}>
        <Badge tone={state.tone}>{stateWord(detail.state, detail.active, allSpaces)}</Badge>
        {detail.written_as_rules ? <Badge tone="accent">Written as rules</Badge> : null}
        {detail.sample === true ? <Badge tone="accent">Sample</Badge> : null}
      </div>

      <Card title="What this policy does">
        <p>Controls {[...new Set(detail.mappings.map(servedAction))].map((action) => action.replaceAll(".", " ").replaceAll("_", " ")).join(", ")}. An action needs an allow rule; a denial always wins.</p>
        {detail.rules_origin === "recognized-seed" ? <p className="note">Recognized demonstration policy. The rules below match a reviewed shipped policy; create an editable draft to customize them.</p> : !detail.written_as_rules ? <p className="note">Custom Cedar policy. Its authorization cannot be safely translated into this form. Review the policy text under Advanced; copying preserves its complete configuration.</p> : null}
        {detail.sample === true ? <p className="note">Added with the sample targets. Removing them retires this policy while it is still active and unchanged.</p> : null}
        {/* Validate, preview and activate are the stepper's to say for a draft or a validated
            version, so the "Next" line stays only where the stepper does not lead. */}
        {detail.state === "ACTIVE" ? <p className="muted">{detail.active ? "Next: create an editable draft to change the active policy." : allSpaces ? "Next: choose a Space to activate this policy there, or copy it to a draft to customize and preview." : "Next: activate this policy for the selected Space, or copy it to a draft to customize and preview."}</p> : detail.state === "RETIRED" ? <p className="muted">This version is retired. Copy it to start a new draft.</p> : null}
        {detail.state !== "DRAFT" || !detail.written_as_rules ? <CopyDraft bundleId={detail.bundle_id} formAvailable={detail.form_available ?? detail.written_as_rules} /> : null}
        <DownloadRules bundleId={detail.bundle_id} summary={detail.rules_file} origin={detail.rules_origin} />
      </Card>

      <Lifecycle detail={detail} active={active} comparison={compareSummary(comparison.data)} />
      <Changes detail={detail} comparison={comparison.data} error={comparison.error} />

      {detail.rules.length > 0 ? <Rules detail={detail} /> : null}

      <Card title="Limits">
        {detail.limits.length === 0 ? (
          <p className="muted">This bundle sets no limit.</p>
        ) : (
          <div className="meters">
            {detail.limits.map((rule) => (
              <LimitRow key={rule.rule_id} rule={rule} />
            ))}
          </div>
        )}
      </Card>

      <div className="grid-2">
        <Card title="Quorum">
          {detail.quorum.length === 0 ? (
            <p className="muted">None: one approver decides.</p>
          ) : (
            <ul className="plain">
              {detail.quorum.map((rule) => (
                <li key={rule.rule_id}>
                  <span className="mono">{String(rule.required)} approvers</span> for{" "}
                  {rule.rule === null ? (
                    <span className="mono">{rule.obligation}</span>
                  ) : (
                    <>
                      rule <span className="mono">{rule.rule}</span>
                    </>
                  )}
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Context settings">
          {detail.context_settings.length === 0 ? (
            <p className="muted">The contracts&rsquo; own defaults.</p>
          ) : (
            <ul className="plain">
              {detail.context_settings.map((setting) => (
                <li key={`${setting.context_contract_version}:${setting.source_kind}`}>
                  <span className="mono">{setting.context_contract_version}</span>{" "}
                  {setting.source_kind}, at most {duration(setting.max_age_seconds)} old,
                  written by {setting.permitted_writers.join(", ")}
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <details>
        <summary>Advanced: version identity and operation mappings</summary>
      <Card title="This bundle">
        <dl className="facts">
          <dt>Identity</dt>
          <dd className="mono">{detail.bundle_id}</dd>
          <dt>Content hash</dt>
          <dd className="mono">{detail.content_hash}</dd>
          <dt>Changed</dt>
          <dd>{when(detail.changed_at)}</dd>
        </dl>
      </Card>

      <Card title="Mappings">
        <Table caption="The operation mappings this bundle binds.">
          <thead>
            <tr>
              <Th>Operation</Th>
              <Th>Account</Th>
              <Th>Mapping</Th>
              <Th>Contract</Th>
              <Th>Placement</Th>
            </tr>
          </thead>
          <tbody>
            {detail.mappings.map((row) => (
              <tr key={row.operation_ref}>
                <th scope="row" className="mono">
                  {mappingName(row)}
                </th>
                <Td mono>{row.account_id.slice(0, PREFIX)}</Td>
                <Td mono>{row.mapping_version}</Td>
                <Td mono>{row.context_contract_version}</Td>
                <Td>
                  {row.observe_only
                    ? "observed only"
                    : row.external_executor
                      ? "external executor"
                      : "dispatched by ExecBound"}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>
      </details>

      <details>
      <summary>Advanced: Cedar policy language</summary>
      <Card title="As policy language">
        <p className="muted">
          The compiled bundle, read-only. This is what the kernel executes
          {detail.written_as_rules ? ", and the rules above are its source." : "."}
        </p>
        <PolicyText label="Cedar schema" text={detail.compiled.cedar_schema} />
        <PolicyText label="Authorization policies" text={detail.compiled.authorization_policies} />
        <PolicyText label="Approval policies" text={detail.compiled.approval_policies} />
      </Card>
      </details>
    </>
  );
}

function Rules({ detail }: { detail: BundleDetail }) {
  return (
    <Card title="Rules">
      <p className="muted">
        As the rules read. The decision is the kernel&rsquo;s, made from the compiled policy
        below.
      </p>
      {detail.written_as_rules ? <p className="note">
        <Link to="/policy/$bundleId/rules" params={{ bundleId: detail.bundle_id }}>
          {detail.state === "DRAFT" ? "Change the rules" : "Read the rules as a form"}
        </Link>
      </p> : null}
      <ul className="policy-rules">
        {detail.rules.map((rule) => {
          const effect = EFFECT[rule.effect];
          return (
            <li key={rule.id}>
              <span className="badges">
                {effect === undefined ? null : <Badge tone={effect.tone}>{effect.word}</Badge>}
                <span className="mono faint">{rule.id}</span>
              </span>
              <p>{ruleSentence(rule.sentence)}</p>
              {rule.note === null ? null : <p className="muted">Note: {rule.note}</p>}
              {detail.active && rule.effect === "REVIEW" ? <CoverageLine bundleId={detail.bundle_id} action={rule.action} /> : null}
            </li>
          );
        })}
      </ul>
    </Card>
  );
}

function LimitRow({ rule }: { rule: LimitMeter }) {
  const label = `${rule.rule_id}: ${rule.labels.join(", ")}, ${rule.scope_label}`;
  const ceiling = `${String(rule.max_targets)} ${rule.budget} targets per ${rule.window}`;
  return (
    <div>
      {rule.used === null ? (
        <>
          <p className="meter-row">
            <span className="meter-label">{label}</span>
            <span className="meter-value mono">{ceiling}</span>
          </p>
          <small className="faint">Counted {rule.counted}, so there is no one figure here.</small>
        </>
      ) : (
        <>
          <Meter label={label} value={rule.used} max={rule.max_targets} />
          <small className="faint">
            {ceiling}, counted {rule.counted}.
          </small>
        </>
      )}
      <small className="faint">
        {" "}
        Over the ceiling:{" "}
        {rule.on_exceed === "DENY" ? "denied" : "held for a person"}.
      </small>
    </div>
  );
}

function PolicyText({ label, text }: { label: string; text: string }) {
  return (
    <>
      <h3>{label}</h3>
      {text.trim() === "" ? (
        <p className="muted">None.</p>
      ) : (
        <pre className="policy-text">{text}</pre>
      )}
    </>
  );
}
