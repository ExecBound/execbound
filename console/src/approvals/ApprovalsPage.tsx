// SPDX-License-Identifier: AGPL-3.0-only
import { useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { lazy, Suspense, useEffect, useSyncExternalStore } from "react";

import { decideApproval, listApprovalsOptions, readApprovalOptions } from "../lib/shell-api";
import type { ApprovalItem, DecisionResult } from "../api/types.gen";
import { EmptyState } from "../components/ui/EmptyState";
import { PageHeading } from "../components/ui/PageHeading";
import { useEdition } from "../edition/context";
import { useServerMutation } from "../lib/mutation";
import { POLL_MS, usePolledQuery } from "../lib/poll";
import { useSession } from "../lib/session";
import { useFollowSpace } from "../lib/spaces";
import { useTimeZone, utcOffsetMinutes } from "../lib/time";
import { toast } from "../lib/toast";
import { refusalCode, refusalText } from "./copy";
import { DetailView, type Decision } from "./DetailView";
import { Queue, type View } from "./Queue";
import { useServerNow } from "./time";

const NotAssigned = lazy(() => import("./Others").then((module) => ({ default: module.NotAssigned })));
const LateLapses = lazy(() => import("./Others").then((module) => ({ default: module.LateLapses })));
const UnroutedNotice = lazy(() => import("./Others").then((module) => ({ default: module.UnroutedNotice })));

export const LIST_INTERVAL_MS = POLL_MS;
export const DETAIL_INTERVAL_MS = POLL_MS;
const EMPTY: Record<View, string> = {
  pending: "Nothing is waiting for you.",
  others: "Nothing is waiting on anyone else.",
  // Every view but Lapsed and Waiting on others reads the approvals this person is assigned to
  // review, an administrator included, so an empty Decided today says so (#678).
  decided: "Nothing assigned to you was decided today.",
  lapsed: "Nothing has lapsed undecided.",
};
const LABELS: Record<View, string> = {
  pending: "Pending",
  others: "Waiting on others",
  decided: "Decided today",
  lapsed: "Lapsed",
};

/** What Decided today counts, said where it is empty (#678). */
function decidedCounts(admin: boolean): string {
  return admin
    ? "Decided today lists only the approvals you are assigned to review; Activity lists the others."
    : "Decided today lists the approvals you are assigned to review, whoever decided them.";
}

/**
 * The queue beside the detail on a desktop; on a phone the card, then what else is in the same
 * view, with the decision buttons pinned above the tab bar (#333). `selected` is the route's
 * approval, so a link and the back button restore the same view.
 *
 * Four views: what is still decidable, what waits on other people (an administrator's alone),
 * what was decided today, and what lapsed undecided. The view is the route's search (#678),
 * so Back, a reload and a shared link return to it; `onView` changes it. A view this session
 * cannot use reads as Pending and leaves the address. The hosted workspace route passes no
 * view and gets Pending; its chips go to `/approvals`. The pending query is the one the
 * sidebar's count already watches, so the two share it rather than asking twice
 * (#427).
 */
export function ApprovalsPage({
  selected,
  view: asked,
  onView,
}: {
  selected?: string;
  view?: View;
  onView?: (view: View | undefined, replace?: boolean) => void;
}) {
  const phone = usePhone();
  const now = useServerNow();
  const session = useSession();
  const navigate = useNavigate();
  const admin = session.role === "ADMIN";
  const refused = asked === "others" && !admin;
  const view: View = refused ? "pending" : (asked ?? "pending");
  useEffect(() => {
    // The address drops a view this session cannot use, without a new history entry.
    if (refused) onView?.(undefined, true);
  }, [refused, onView]);
  const choose = (next: View) => {
    if (onView !== undefined) {
      onView(next);
    } else {
      void navigate({ to: "/approvals", search: next === "pending" ? {} : { view: next } });
    }
  };
  const pending = usePolledQuery({ ...listApprovalsOptions({ query: { view: "pending" } }) });
  // Polled for an administrator alone: nobody else may read it, and the server refuses it.
  const others = usePolledQuery({
    ...listApprovalsOptions({ query: { view: "others" } }),
    enabled: admin,
  });
  const [choice] = useTimeZone();
  // Decided today starts at the viewer's midnight in the zone they chose.
  const decided = usePolledQuery({
    ...listApprovalsOptions({ query: { view: "decided", utc_offset: String(utcOffsetMinutes(choice)) } }),
    enabled: view === "decided",
  });
  const lapsed = usePolledQuery({
    ...listApprovalsOptions({ query: { view: "lapsed" } }),
    enabled: view === "lapsed",
  });

  const current = view === "pending" ? pending : view === "others" ? others : view === "decided" ? decided : lapsed;
  const shown = current.data;
  const items = shown?.items ?? [];
  const rest = items.filter((item) => item.approval_id !== selected);
  const waitingOnOthers = others.data?.items.length ?? 0;
  const also = view === "pending" || view === "others" ? "Also waiting" : `Also in ${LABELS[view]}`;
  const count = (data: { items: ApprovalItem[] } | undefined) => (data !== undefined ? ` ${String(data.items.length)}` : "");
  const chip = (option: View, data: { items: ApprovalItem[] } | undefined) => (
    <button
      type="button"
      className="chip"
      aria-pressed={view === option}
      onClick={() => {
        choose(option);
      }}
    >
      {LABELS[option]}
      {count(data)}
    </button>
  );
  // On the queue alone, never an open approval; the line itself asks only with workspace-wide
  // `access.manage`, so a narrowed administrator loads it and makes no call (#678).
  const unrouted =
    admin && selected === undefined ? (
      <Suspense fallback={null}>
        <UnroutedNotice />
      </Suspense>
    ) : null;
  const chips = (
    <div className="chips" role="group" aria-label="Which approvals">
      {chip("pending", pending.data)}
      {admin ? chip("others", others.data) : null}
      {chip("decided", decided.data)}
      {chip("lapsed", lapsed.data)}
    </div>
  );
  // An administrator's empty queue says why (#678): they review only what they are assigned
  // to, and these requests wait on other people. Exact by construction, since Waiting on others
  // is precisely the pending approvals here that the administrator does not review.
  const notAssigned = admin && view === "pending" && pending.data?.items.length === 0 && waitingOnOthers > 0;
  const queue = current.isPending ? <p className="muted" role="status">Loading approvals</p> : current.isError ? (
    <EmptyState title="Approvals could not be loaded.">{refusalText(current.error, admin)}</EmptyState>
  ) : notAssigned ? (
    <Suspense fallback={<p className="muted" role="status">Loading approvals</p>}>
      <NotAssigned
        waiting={waitingOnOthers}
        onShow={() => {
          choose("others");
        }}
      />
    </Suspense>
  ) : (
    <>
      {admin && view === "lapsed" ? (
        <Suspense fallback={null}>
          <LateLapses items={items} />
        </Suspense>
      ) : null}
      <Queue
        items={items}
        view={view}
        now={now}
        emptyTitle={EMPTY[view]}
        emptyBody={view === "decided" ? decidedCounts(admin) : undefined}
        flagLate={admin && view === "lapsed"}
      />
    </>
  );
  // An administrator can read the execution history; anyone else may have come from a message
  // and can only know that the agent must ask again (#678).
  const note = (
    <p className="queue-note">
      Review each request before its deadline. Approvals that lapse cannot be used; they appear under Lapsed.
      {admin
        ? " Check the request's execution history before asking for a fresh plan."
        : " If the agent still needs one, it must send the request again."}
    </p>
  );

  if (phone) {
    return (
      <div className={selected === undefined ? "approvals approvals-phone" : "approvals approvals-phone approvals-open"}>
        <PageHeading title="Approvals" />
        {selected === undefined ? (
          <section className="queue" aria-label="Queue">
            {unrouted}
            {chips}
            {queue}
            {note}
          </section>
        ) : (
          <>
            <section className="detail-pane">
              <Detail id={selected} now={now} phone view={view} next={rest[0]?.approval_id} />
            </section>
            <section className="queue" aria-labelledby="also-waiting">
              <h2 id="also-waiting" className="eyebrow also-waiting">
                {also}
              </h2>
              <Queue
                items={rest}
                view={view}
                now={now}
                title={also}
                emptyTitle={view === "pending" || view === "others" ? "Nothing else is waiting." : "Nothing else is here."}
                emptyBody={view === "pending" ? "This is the only approval in your scope right now." : "This is the only approval in this view."}
              />
            </section>
          </>
        )}
      </div>
    );
  }

  return (
    <div className={selected !== undefined ? "approvals approvals-open" : items.length > 0 ? "approvals" : "approvals approvals-empty"}>
      <section className="queue" aria-label="Queue">
        <PageHeading title="Approvals" />
        {unrouted}
        {chips}
        {queue}
        {note}
      </section>
      {(selected !== undefined || items.length > 0) && <section className="detail-pane" aria-label="Detail">
        {selected === undefined ? (
          <EmptyState title="Choose an approval to read it.">
            The frozen plan, its facts and the rule that held it are shown beside the queue.
          </EmptyState>
        ) : (
          <Detail id={selected} now={now} phone={false} view={view} next={rest[0]?.approval_id} />
        )}
      </section>}
    </div>
  );
}

/** One approval read through the generated client, and its decision, never optimistic. */
function Detail({ id, now, phone, view, next }: { id: string; now: number; phone: boolean; view: View; next: string | undefined }) {
  const navigate = useNavigate();
  const admin = useSession().role === "ADMIN";
  const queryClient = useQueryClient();
  const { event } = useEdition();
  const detail = usePolledQuery({
    ...readApprovalOptions({ path: { approval_id: id } }),
    retry: false,
  });
  // An approval link opens in the space that owns it: membership is the
  // authority, so the record is answered whatever the session's current space is, and its
  // answer names its space. The shell then moves the session there and says so, rather than
  // showing one space's approval while every count on the screen belongs to another.
  useFollowSpace(detail.data?.space);
  const search = view === "pending" ? {} : { view };
  const decide = useServerMutation<DecisionResult, DecisionBody>({
    mutationFn: async (body) => {
      const { data } = await decideApproval({ path: { approval_id: id }, body, throwOnError: true });
      return data;
    },
    onSuccess: (result, variables) => {
      if (result.approval_state !== "PENDING") event("approval_completed");
      const decided = variables.decision === "APPROVE" ? "Approved" : "Refused";
      const target = detail.data?.item.target ?? "";
      toast(
        result.approval_state === "PENDING"
          ? `${decided} ${target}; recorded, ${String(result.recorded)} of ${String(result.required)} needed.`
          : `${decided} ${target}.`,
      );
      void queryClient.invalidateQueries({ queryKey: [{ _id: "listApprovals" }] });
      void queryClient.invalidateQueries({ queryKey: [{ _id: "readApproval" }] });
      // The next item in the same view, with the view kept in the address.
      if (next !== undefined) {
        void navigate({ to: "/approvals/$approvalId", params: { approvalId: next }, search });
      } else {
        void navigate({ to: "/approvals", search });
      }
    },
    onError: (error) => {
      toast(refusalText(error, admin));
      // The server said why; the detail's status says the same in the page.
      void detail.refetch();
      void queryClient.invalidateQueries({ queryKey: [{ _id: "listApprovals" }] });
    },
  });

  if (detail.isPending) {
    return (
      <p className="muted" role="status">
        Loading the approval
      </p>
    );
  }
  if (detail.isError) {
    const code = refusalCode(detail.error);
    return (
      <EmptyState title={code === "NOT_FOUND" ? "This approval is not in your scope." : "This approval could not be read."}>
        {refusalText(detail.error, admin)} <Link to="/approvals">Back to the queue</Link>
        {" or "}
        <a href={`/approvals/${id}/classic`}>use the basic page</a>.
      </EmptyState>
    );
  }
  const data = detail.data;
  const onDecide = (decision: Decision, comment: string) => {
    if (data.continuation === null) return;
    return decide.mutateAsync({ decision, comment, continuation: data.continuation });
  };
  // One field per approval: moving to another mounts a fresh one (#678).
  return (
    <DetailView
      key={data.item.approval_id}
      detail={data}
      now={now}
      phone={phone}
      deciding={decide.isPending}
      onDecide={onDecide}
    />
  );
}

interface DecisionBody {
  decision: Decision;
  comment: string;
  continuation: string;
}

const PHONE = "(max-width: 767px)";

function subscribePhone(listener: () => void): () => void {
  const query = window.matchMedia(PHONE);
  query.addEventListener("change", listener);
  return () => {
    query.removeEventListener("change", listener);
  };
}

/** Whether the phone layout applies; the same breakpoint the stylesheet turns the shell at. */
export function usePhone(): boolean {
  return useSyncExternalStore(
    subscribePhone,
    () => window.matchMedia(PHONE).matches,
    () => false,
  );
}

export type { ApprovalItem };
