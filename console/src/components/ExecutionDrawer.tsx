// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";

import { readExecutionOptions } from "../api/@tanstack/react-query.gen";
import type { ExecutionDetail, NoteView, ReasonView, SignalRecordView } from "../api/types.gen";
import { canAnywhere, useSession } from "../lib/session";
import { useServerNow } from "../lib/clock";
import { useTimeZone, zoneName } from "../lib/time";
import { age, APPROVAL_WORDS, shortId } from "../lib/words";
import { reasonSentence, timelineSentence } from "../lib/decision-presentation";
import { decisionPresentation, recordBadge } from "../lib/decision-summary";
import { Explain } from "./assistant/Explain";
import { policyName } from "./policy/format";
import { FactSource } from "./FactSource";
import { PrincipalName } from "./PrincipalName";
import { CopyLink, CopyText } from "./CopyLink";
import { Badge } from "./ui/Badge";
import { Drawer } from "./ui/Drawer";
import { Deadline, Time } from "./ui/Time";
import { RequestContext } from "./RequestContext";
import { RequestRef } from "./RequestRef";
import "./rule-links.css";

/**
 * One record in the detail drawer (#333): why it was decided, the facts used with
 * their source and age, the timeline, and the approval. The page keeps the open record's id
 * in its URL and hands it here; every string is the server's, rendered as text.
 */
export function ExecutionDrawer({
  executionId,
  onClose,
  actions,
  after,
}: {
  executionId: string | undefined;
  onClose: () => void;
  actions?: (detail: ExecutionDetail) => ReactNode;
  /** Rendered with the loaded record, for a dialog its actions open. */
  after?: (detail: ExecutionDetail) => ReactNode;
}) {
  const query = useQuery({
    ...readExecutionOptions({ path: { execution_id: executionId ?? "" } }),
    enabled: executionId !== undefined,
    refetchInterval: 10_000,
    // A record a row prefetched within five seconds is shown as read, not read again at once.
    staleTime: 5_000,
  });
  const detail = query.data;
  return (
    <Drawer
      open={executionId !== undefined}
      onClose={onClose}
      title={detail === undefined ? "Record" : `${detail.action_label} ${detail.target.provider_id}`}
      eyebrow={
        detail === undefined ? undefined : (
          <>
            {/* The row's badge, so the drawer and its row in Activity never disagree (#678). */}
            <RecordBadge detail={detail} />
            <RequestRef prefix="Request " value={detail.request_ref} />
            <CopyText value={detail.request_ref} />
            <CopyLink to="/activity" search={{ open: detail.execution_id }} />
          </>
        )
      }
      actions={detail !== undefined && actions !== undefined ? actions(detail) : undefined}
    >
      {query.isError ? <p role="alert">This record could not load.</p> : null}
      {detail === undefined ? (
        query.isError ? null : (
          <p role="status" className="muted">
            Loading
          </p>
        )
      ) : (
        <>
          <Body detail={detail} />
          {after !== undefined ? after(detail) : null}
        </>
      )}
    </Drawer>
  );
}

function RecordBadge({ detail }: { detail: ExecutionDetail }) {
  const badge = recordBadge(detail);
  return <Badge tone={badge.tone}>{badge.text}</Badge>;
}

/**
 * The rules a reason names, each a link to that rule in the policy version that decided the
 * request (#678). Offered only where the server says this reader may open that version's
 * rules (`policy_readable`): holding the permission in some space is not enough, since the
 * version may belong to another. A rule id is a value in a search key and text on the page,
 * never an id, a class or a fragment.
 */
function RuleLinks({ rules, detail }: { rules: readonly string[]; detail: ExecutionDetail }) {
  if (rules.length === 0) return null;
  return (
    <ul className="rule-links">
      {rules.map((rule) => (
        <li key={rule}>
          {detail.policy_readable ? (
            <Link to="/policy/$bundleId/rules" params={{ bundleId: detail.bundle_id }} search={{ rule }}>
              Rule <code>{rule}</code> in {policyName(detail.bundle_id)}
            </Link>
          ) : (
            <>
              Rule <code>{rule}</code>
            </>
          )}
        </li>
      ))}
    </ul>
  );
}

function Reasons({ items, detail }: { items: ReasonView[]; detail: ExecutionDetail }) {
  return (
    <>
      {items.map((reason) => (
        <div className="why" key={reason.code}>
          <p>
            <strong>{reasonSentence(reason)}</strong>
          </p>
          <RuleLinks rules={reason.rules ?? []} detail={detail} />
          <details><summary>Recorded reason</summary><code>{reason.code}</code>{reason.rule_id !== null ? <p>Rule: <code>{reason.rule_id}</code></p> : null}</details>
        </div>
      ))}
    </>
  );
}

/**
 * The records a signal fact was mapped from, every field the plan froze; the server
 * sends them to an administrator alone. The verdict, the event id and the producer's name and
 * version are a producer's words about a host whoever controls that host may have chosen: each
 * renders as text in its own isolate, so its direction cannot reorder the words beside it, and
 * never as a link.
 */
function SignalRecords({ records }: { records: SignalRecordView[] }) {
  return (
    <details>
      <summary>Signal records</summary>
      {records.map((record) => (
        <div key={record.source_id}>
          <p>
            Verdict <code><bdi>{record.verdict}</bdi></code>, confidence {String(record.confidence)} of 1000.
          </p>
          <p>
            Observed <Time at={record.observed_at} precision="second" />, received{" "}
            <Time at={record.received_at} precision="second" />;{" "}
            {record.expires_at ? (
              <>
                the producer set its expiry to <Time at={record.expires_at} precision="second" />.
              </>
            ) : (
              "the producer set no expiry."
            )}
          </p>
          <p>
            Event <code><bdi>{record.source_event_id}</bdi></code> from <code><bdi>{record.producer_name}</bdi></code>{" "}
            version <code><bdi>{record.producer_version}</bdi></code>.
          </p>
          <p>
            Source <code>{shortId(record.source_id)}</code>, registration version {String(record.registration_version)},{" "}
            {record.attests_liveness ? "attests liveness" : "does not attest liveness"}.
          </p>
          <p>
            Record <code>{record.record_digest}</code>
          </p>
        </div>
      ))}
    </details>
  );
}

function Notes({ items }: { items: NoteView[] }) {
  return (
    <dl className="kv">
      {items.map((note) => (
        <div key={note.label}>
          <dt>{note.label}</dt>
          <dd>{note.text}</dd>
        </div>
      ))}
    </dl>
  );
}

/** A pending approval's deadline, against the server's clock, ticking while it is shown. */
function ApprovalDeadline({ at }: { at: string }) {
  return <Deadline at={at} now={useServerNow()} />;
}

function Body({ detail }: { detail: ExecutionDetail }) {
  const reviews = canAnywhere(useSession(), "approvals.decide");
  const target = detail.target;
  const explanation = decisionPresentation(detail);
  const [choice] = useTimeZone();
  const where = target.environment === null ? target.resource_class : `${target.resource_class} · ${target.environment}`;
  return (
    <>
      <p className="drawer-sub">
        {where} · by <PrincipalName principal={detail.agent} /> at{" "}
        <Time at={detail.created_at} precision="second" />
      </p>
      <section className="drawer-section" aria-labelledby="drawer-outcome">
        <h3 className="eyebrow" id="drawer-outcome">Decision and execution</h3>
        <dl className="kv">
          <div><dt>Decision</dt><dd>{explanation.decision}</dd></div>
          <div><dt>Execution</dt><dd>{explanation.execution}</dd></div>
          <div><dt>Next step</dt><dd>{explanation.next}</dd></div>
        </dl>
      </section>
      <section className="drawer-section" aria-labelledby="drawer-why">
        <h3 className="eyebrow" id="drawer-why">
          Why
        </h3>
        <p>{explanation.cause}</p>
        {detail.reasons.length > 1 ? (
          <Reasons items={detail.reasons} detail={detail} />
        ) : (
          <RuleLinks rules={detail.reasons[0]?.rules ?? []} detail={detail} />
        )}
        {/* A denial no rule names, under a version written as policy text, still reaches the
            policy that decided it. */}
        {detail.state === "DENIED" && detail.policy_readable && !detail.reasons.some((reason) => (reason.rules ?? []).length > 0) ? (
          <ul className="rule-links">
            <li>
              <Link to="/policy/$bundleId" params={{ bundleId: detail.bundle_id }}>
                Open {policyName(detail.bundle_id)}
              </Link>
            </li>
          </ul>
        ) : null}
        <details>
          <summary>Decision evidence</summary>
          <p>Recorded state: <code>{detail.state}</code></p>
          {detail.reasons.map((reason) => <div key={reason.code}><p>Reason: <code>{reason.code}</code>{reason.rule_id !== null ? <> · rule <code>{reason.rule_id}</code></> : null}</p>{reason.sentence !== "" && reason.sentence !== reasonSentence(reason) ? <p>{reason.sentence}</p> : null}</div>)}
        </details>
      </section>
      {detail.obligations.length > 0 ? (
        <section className="drawer-section" aria-labelledby="drawer-obligations">
          <h3 className="eyebrow" id="drawer-obligations">
            A person decides
          </h3>
          <Reasons items={detail.obligations} detail={detail} />
        </section>
      ) : null}
      <section className="drawer-section" aria-labelledby="drawer-facts">
        <h3 className="eyebrow" id="drawer-facts">
          Facts used
        </h3>
        {detail.facts.length === 0 ? (
          <p className="muted">No trusted facts were needed.</p>
        ) : (
          <dl className="kv">
            {detail.facts.map((fact) => (
              <div key={fact.name}>
                <dt>{fact.name.replaceAll("_", " ")}</dt>
                <dd>
                  <span className="mono">{fact.value}</span>
                  <small>
                    <FactSource fact={fact} /> · {age(fact.observed_at)}
                  </small>
                  {fact.records ? <SignalRecords records={fact.records} /> : null}
                </dd>
              </div>
            ))}
          </dl>
        )}
      </section>
      {detail.arguments.length > 0 ? (
        <section className="drawer-section" aria-labelledby="drawer-arguments">
          <h3 className="eyebrow" id="drawer-arguments">
            Arguments
          </h3>
          <dl className="kv">
            {detail.arguments.map((argument) => (
              <div key={argument.name}>
                <dt>{argument.name.replaceAll("_", " ")}</dt>
                <dd>
                  <span className="mono">{argument.value}</span>
                </dd>
              </div>
            ))}
          </dl>
        </section>
      ) : null}
      <section className="drawer-section" aria-labelledby="drawer-timeline">
        <h3 className="eyebrow" id="drawer-timeline">
          Timeline · {zoneName(choice)}
        </h3>
        <ol className="timeline">
          {detail.timeline.map((entry, index) => (
            <li key={`${entry.at}-${String(index)}`}>
              <Time at={entry.at} form="clock" />
              <span>{timelineSentence(entry)}</span>
            </li>
          ))}
        </ol>
        <details>
          <summary>Timeline evidence</summary>
          {detail.timeline.map((entry, index) => <p key={`${entry.at}-${String(index)}`}><code>{entry.at} · {entry.state ?? entry.kind}</code> {entry.sentence}</p>)}
        </details>
      </section>
      {detail.approval !== null ? (
        <section className="drawer-section" aria-labelledby="drawer-approval">
          <h3 className="eyebrow" id="drawer-approval">
            Approval
          </h3>
          {/* The server classifies a lapse on its own clock; the page never decides one. */}
          {detail.approval.lapsed === true ? (
            <p>
              Lapsed at <Time at={detail.approval.expires_at} precision="second" /> before a decision. Nothing ran.
            </p>
          ) : detail.approval.unused === true ? (
            <p>
              Approved, but not used before <Time at={detail.approval.expires_at} precision="second" />. Nothing ran.
            </p>
          ) : (
          <p>
            {detail.approval.state === "PENDING"
              ? APPROVAL_WORDS.PENDING
              : `Approval: ${APPROVAL_WORDS[detail.approval.state] ?? detail.approval.state}`}
            {detail.approval.required_approvers > 1
              ? `; ${String(detail.approval.recorded)} of ${String(detail.approval.required_approvers)} approvals recorded`
              : ""}
            {detail.approval.state === "PENDING" ? (
              <>
                ; <ApprovalDeadline at={detail.approval.expires_at} />.
              </>
            ) : (
              <>
                ; expires <Time at={detail.approval.expires_at} precision="second" />.
              </>
            )}
          </p>
          )}
          {/* The approval itself, which names the space that owns it, so the page follows it
              there (#330). Offered only to someone who decides approvals in some space; for
              anyone else the approval page has nothing but a refusal. */}
          {reviews ? (
            <p>
              <Link to="/approvals/$approvalId" params={{ approvalId: detail.approval.approval_id }}>
                Open in Approvals
              </Link>
            </p>
          ) : null}
        </section>
      ) : null}
      {detail.limits.length > 0 ? (
        <section className="drawer-section" aria-labelledby="drawer-limits">
          <h3 className="eyebrow" id="drawer-limits">
            Shared limits that apply
          </h3>
          <Reasons items={detail.limits} detail={detail} />
        </section>
      ) : null}
      {detail.checkpoint.length > 0 ? (
        <section className="drawer-section" aria-labelledby="drawer-checkpoint">
          <h3 className="eyebrow" id="drawer-checkpoint">
            Executed outside ExecBound
          </h3>
          <Notes items={detail.checkpoint} />
        </section>
      ) : null}
      {detail.dispatch === null ? null : (
        <section className="drawer-section" aria-labelledby="drawer-dispatch">
          <h3 className="eyebrow" id="drawer-dispatch">
            What this dispatch carried
          </h3>
          <p className="muted">{detail.dispatch}</p>
        </section>
      )}
      {detail.carriers.map((carrier, index) => (
        <section className="drawer-section" key={String(index)} aria-labelledby={`drawer-carrier-${String(index)}`}>
          <h3 className="eyebrow" id={`drawer-carrier-${String(index)}`}>
            Carried by a control point
          </h3>
          <Notes items={carrier} />
        </section>
      ))}
      <p className="drawer-sub">
        Frozen plan <span className="mono">{shortId(detail.plan_hash)}</span>; context valid until{" "}
        <Time at={detail.valid_until} precision="second" />.
      </p>
      {/* Below the record, collapsed, and labelled: the facts above are the record (#330). */}
      <RequestContext externalCase={detail.external_case} related={detail.related_requests}
        executionId={detail.execution_id} approvalId={detail.approval?.approval_id} deliveries={detail.deliveries} />
      <Explain kind="execution" id={detail.execution_id} what="this decision" />
    </>
  );
}
