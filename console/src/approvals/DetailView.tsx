// SPDX-License-Identifier: AGPL-3.0-only
import { lazy, Suspense, useEffect, useRef, useState } from "react";

import type { ApprovalDetail, ApprovalItem } from "../api/types.gen";
import { CountdownRing, clock } from "../components/charts/CountdownRing";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { Table, Td, Th } from "../components/ui/Table";
import { Time } from "../components/ui/Time";
import { FactSource } from "../components/FactSource";
import { duration, humanizeDurations, timelineSentence } from "../lib/decision-presentation";
import { useSession } from "../lib/session";
import { useSpaceSwitch } from "../lib/spaces";
import { useTimeZone, zoneName } from "../lib/time";
import { toast } from "../lib/toast";
import { DECIDED_WORDS } from "../lib/words";
import { refHandle, refName } from "../components/directory/handles";
import { executionLine, lapsed, stateBadge, statusNotice } from "./copy";
import { DecisionBar, type Decision } from "./DecisionBar";
import { takeDetailFocus } from "./focus";
import { age, secondsSince, secondsUntil } from "./time";

export type { Decision };

const WaitingPanel = lazy(() => import("./WaitingPanel"));
// When the message arrived, under the quorum: below the fold, so a cold link fetches it after.
const DeliveryLine = lazy(() => import("./DeliveryLine").then((module) => ({ default: module.DeliveryLine })));
// The draft store is only ever needed after the page is on screen, to restore a comment kept
// across signing in again and to keep the next keystroke, so a cold link never fetches it
// unless this tab kept something for this approval.
const drafts = () => import("../lib/drafts");
// Below the decision: the caller's case, related requests and deliveries.
const RequestContext = lazy(() => import("../components/RequestContext").then((module) => ({ default: module.RequestContext })));
// The assistant's disclosure, fetched only by a deployment that has one.
const Explain = lazy(() => import("../components/assistant/Explain").then((module) => ({ default: module.Explain })));

/** Whether this tab kept a comment for one approval, without loading the store to ask. */
function keptFor(approvalId: string): boolean {
  try {
    return window.sessionStorage.getItem(`eb:draft:approval:${approvalId}`) !== null;
  } catch {
    return false;
  }
}

/** The agent that asked, as a sentence names it: "triage-bot (Agent 3)", or "Agent 3" (#678). */
export function requester(agent: ApprovalItem["agent"]): string {
  const name = refName(agent);
  const tag = refHandle(agent);
  return name === tag ? name : `${name} (${tag})`;
}

/**
 * One approval in words, and the decision bar. Everything shown came from the server's
 * answer; the buttons disable while a decision is on its way and nothing here assumes the
 * answer (#333). Strings from an agent, a provider or a label render as text.
 *
 * Rendered once per approval (`key={approval_id}`), so the comment field belongs to one
 * approval: text typed on one is never kept under, or sent with, another's decision. The
 * comment is kept in this tab while it is typed and comes back after signing in again (#678).
 * An administrator reading an approval they are not assigned to decide gets the Waiting panel
 * in place of the bar.
 */
export function DetailView({
  detail,
  now,
  phone,
  deciding,
  onDecide,
}: {
  detail: ApprovalDetail;
  now: number;
  phone: boolean;
  deciding: boolean;
  onDecide: (decision: Decision, comment: string) => Promise<unknown> | undefined;
}) {
  const session = useSession();
  const principal = session.person.id;
  const item = detail.item;
  const approvalId = item.approval_id;
  const [comment, setComment] = useState("");
  const restoredAt = useRef(now);
  // After the kernel refused the comment as secret-shaped, nothing is kept again for this
  // approval until the field is emptied: the next keystroke must not write it straight back.
  const refused = useRef(false);
  const [choice] = useTimeZone();
  const title = useRef<HTMLHeadingElement>(null);
  const left = secondsUntil(item.expires_at, now);
  const reviewing = detail.reviewing;
  // "Waiting for you" is for someone who can decide it, at every width, and never for an
  // administrator reading it (#678).
  const badge = stateBadge(item, reviewing && detail.continuation !== null);
  const notice = statusNotice(detail, session.role === "ADMIN");
  const expiredHere = detail.status === "pending" && left <= 0;
  // Read as the queue reads its rows, so a lapsed approval never says it is waiting (#678).
  const lapse = lapsed(detail, left);
  const canDecide = detail.status === "pending" && !expiredHere && detail.continuation !== null;
  const waiting = !reviewing && detail.status === "pending" && !expiredHere;
  const workspace = session.tenant.name;
  const space = detail.space !== null && session.spaces > 1 ? detail.space.name : null;
  useEffect(() => {
    if (takeDetailFocus()) title.current?.focus();
  }, [approvalId]);
  useEffect(() => {
    if (!keptFor(approvalId)) return;
    let live = true;
    void drafts().then((store) => {
      const kept = store.restoreApprovalDraft(approvalId, principal, restoredAt.current);
      if (!live || kept === null) return;
      // Never over what was typed while the store was on its way.
      setComment((typed) => (typed === "" ? kept : typed));
      toast("Your comment was kept.");
    });
    return () => {
      live = false;
    };
  }, [approvalId, principal]);

  const onComment = (text: string) => {
    setComment(text);
    if (text === "") refused.current = false;
    if (refused.current) return;
    void drafts().then((store) => {
      store.saveApprovalDraft(approvalId, principal, item.expires_at, text);
    });
  };
  // What the decision's answer means for the kept comment is the store's to say.
  const settle = (error?: unknown) => {
    void drafts().then((store) => {
      if (store.settleApprovalDraft(approvalId, error)) refused.current = true;
    });
  };
  const decide = (decision: Decision) => {
    if (!canDecide || deciding) return;
    const answer = onDecide(decision, comment);
    if (answer === undefined) return;
    answer.then(() => {
      settle();
      refused.current = false;
      setComment("");
    }, settle);
  };

  return (
    // Marked while its comment field is on the page, which the store keeps (`lib/kept.ts`).
    <article className="detail" aria-labelledby="detail-title" data-eb-kept={canDecide ? "" : undefined}>
      <header className="detail-head">
        <div className="detail-head-main">
          <div className="detail-eyebrow">
            <Badge tone={lapse ? "stale" : badge.tone}>{lapse ? "Lapsed" : badge.text}</Badge>
            <span className="detail-workspace" title={space === null ? workspace : `${workspace} · ${space}`}>
              <bdi>{workspace}</bdi>
              {space !== null ? (
                <>
                  {" · "}
                  <bdi>{space}</bdi>
                </>
              ) : null}
            </span>
            <span className="detail-ref">
              Request <span className="mono">{item.request_ref}</span>
            </span>
            {phone && detail.status === "pending" && !expiredHere ? (
              <span className="detail-left mono tone-hold">{clock(left)} left</span>
            ) : null}
          </div>
          <h2 id="detail-title" className="detail-title" tabIndex={-1} ref={title}>
            {item.target}
          </h2>
          <p className="detail-sentence">
            <strong>{item.action_label}</strong>
            {item.environment !== null ? ` on a ${String(item.environment)} ` : " on a "}
            {String(item.resource_class)}, requested by {requester(item.agent)} at{" "}
            <Time at={item.created_at} precision="second" />
          </p>
        </div>
        {!phone && detail.status === "pending" && !expiredHere ? (
          <div className="detail-ring">
            <CountdownRing remainingSeconds={left} totalSeconds={item.total_seconds} size={72} />
            <span className="sr-only">{clock(left)} left</span>
          </div>
        ) : null}
      </header>

      <section className="drawer-section" aria-label="Decision and execution">
        <p><strong>Execution:</strong> {executionLine(detail, lapse)}</p>
        {expiredHere ? <p role="status">The approval deadline has passed. Refresh this record to see its current status; this approval cannot be used.</p> : null}
      </section>

      {notice !== null ? (
        <p className={`notice notice-${notice.tone}`} role="status">
          {notice.text}
          {detail.stop !== null && detail.status === "paused" ? (
            <>
              {" "}
              Stopped at <Time at={detail.stop.stopped_at} precision="second" />: {detail.stop.reason}
            </>
          ) : null}
        </p>
      ) : null}

      <div className="detail-cards">
        <Card title="Why a person decides">
          {detail.obligations.length === 0 ? (
            <p className="muted">No obligation is recorded for this approval.</p>
          ) : (
            <ul className="rules">
              {detail.obligations.map((obligation) => (
                <li key={obligation.id}>
                  <p className="rule-sentence">{humanizeDurations(obligation.sentence)}</p>
                  <details><summary>Policy evidence</summary><span className="rule-id">{obligation.rule_id ?? obligation.id}</span></details>
                </li>
              ))}
            </ul>
          )}
          <p className="muted quorum">
            Quorum: {String(detail.quorum.required)} approval{detail.quorum.required === 1 ? "" : "s"} needed,{" "}
            {detail.quorum.recorded === 0 ? "none recorded yet" : `${String(detail.quorum.recorded)} recorded`}
            {detail.quorum.decisions.length > 0 ? (
              <>
                {" ("}
                {detail.quorum.decisions.map((decision, index) => (
                  <span key={decision.principal_id}>
                    {index > 0 ? ", " : ""}
                    {refName(decision, decision.kind ?? "HUMAN_APPROVER")}: {DECIDED_WORDS[decision.decision]} at{" "}
                    <Time at={decision.decided_at} precision="second" />
                  </span>
                ))}
                {")"}
              </>
            ) : null}
            .
          </p>
          <Suspense fallback={null}>
            <DeliveryLine item={item} />
          </Suspense>
        </Card>
        <Card title="If approved">
          <p className="effect">{detail.effect.sentence}</p>
          <p className="muted">
            Reversible: {detail.effect.reversible ? `yes, by ${detail.effect.reversed_by ?? ""}` : "no"}.
            {detail.effect.precondition !== null ? ` Precondition: ${detail.effect.precondition}` : ""}
          </p>
          {detail.arguments.length > 0 ? (
            <p className="muted">
              Requested arguments:{" "}
              {detail.arguments.map((argument, index) => (
                <span key={argument.name} className="mono">
                  {index > 0 ? ", " : ""}
                  {argument.name}: {String(argument.value)}
                </span>
              ))}
            </p>
          ) : null}
        </Card>
      </div>

      <Card title="Trusted facts" aside={<span className="muted">Read from their sources, never from the agent</span>} className="facts-card">
        <Table caption="The trusted facts frozen into the plan, each with its source and its age" density="compact">
          <thead>
            <tr>
              <Th>Fact</Th>
              <Th>Value</Th>
              <Th>Source</Th>
              <Th>Age</Th>
            </tr>
          </thead>
          <tbody>
            {detail.facts.map((fact) => (
              <tr key={fact.name}>
                <th scope="row">{fact.name.replaceAll("_", " ")}</th>
                <Td mono>{String(fact.value)}</Td>
                <Td>
                  <span className="fact-source">
                    <span>
                      <FactSource fact={fact} />
                    </span>
                    {/* The object id is data from outside ExecBound: text, isolated. */}
                    <small>
                      <bdi>{fact.source_object_id}</bdi> · {fact.source_version}
                    </small>
                  </span>
                </Td>
                <Td>
                  <span className="fact-age">{age(secondsSince(fact.observed_at, now))}</span>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
        {detail.limits.length > 0 ? (
          <p className="muted limits">
            Impact limits:{" "}
            {detail.limits.map((limit, index) => (
              <span key={limit.rule_id}>
                {index > 0 ? "; " : ""}
                {limit.scope}: {String(limit.max_targets)} {limit.budget} targets per {duration(limit.window_seconds)},{" "}
                {limit.on_exceed.toLowerCase().replaceAll("_", " ")}
              </span>
            ))}
            .
          </p>
        ) : null}
      </Card>

      {detail.notices.length > 0 ? (
        <Card title="What ExecBound can and cannot prove">
          <ul className="notices">
            {detail.notices.map((line, index) => (
              <li key={index}>{line}</li>
            ))}
          </ul>
        </Card>
      ) : null}

      {/* Below the frozen facts, collapsed, and never a recommendation: the answer schema
          has no field for one, the instructions forbid one, and the renderer refuses one in
          an approval context, showing "the explanation could not be shown" instead (#330). */}
      {session.assistant ? (
        <Suspense fallback={null}>
          <Explain kind="approval" id={item.approval_id} what="this request" />
        </Suspense>
      ) : null}

      <Suspense fallback={null}>
        <RequestContext externalCase={item.external_case} related={detail.related_requests}
          executionId={item.execution_id} approvalId={item.approval_id} deliveries={detail.deliveries} />
      </Suspense>
      <section className="drawer-section" aria-label="Request timeline">
        <h3 className="eyebrow">Timeline · {zoneName(choice)}</h3>
        <ol className="timeline">
          {detail.timeline.map((entry, index) => (
            <li key={`${entry.at}-${String(index)}`}>
              <Time at={entry.at} form="clock" /><span>{timelineSentence(entry)}</span>
            </li>
          ))}
        </ol>
        <details>
          <summary>Timeline evidence</summary>
          {detail.timeline.map((entry, index) => <p key={`${entry.at}-${String(index)}`}><code>{entry.at} · {entry.state ?? entry.kind}</code> {entry.sentence}</p>)}
        </details>
      </section>
      {canDecide ? (
        <DecisionBar
          detail={detail}
          now={now}
          phone={phone}
          deciding={deciding}
          comment={comment}
          onComment={onComment}
          onDecide={decide}
        />
      ) : waiting ? (
        <Waiting detail={detail} />
      ) : (
        <p className="detail-recheck muted">
          Your authority, the frozen plan, the selected bundle and the expiry are checked again on the server when you decide.
        </p>
      )}
    </article>
  );
}

/** The Waiting panel, with the page's own space switch, for an administrator who is not assigned. */
function Waiting({ detail }: { detail: ApprovalDetail }) {
  const switcher = useSpaceSwitch();
  return (
    <Suspense fallback={null}>
      <WaitingPanel
        detail={detail}
        switching={switcher.isPending}
        onSwitch={(target) => {
          switcher.mutate({ space: target.space_id, name: target.name });
        }}
      />
    </Suspense>
  );
}
