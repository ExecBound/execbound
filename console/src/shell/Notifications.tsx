// SPDX-License-Identifier: AGPL-3.0-only
// The bell's panel (#678): first what is waiting on this person, each a count with the reason it
// is theirs and a link to the filtered page, then the sign-in security log. Nothing here decides
// anything: every row is a link. The counts are the server's, already scoped to the viewer.
//
// The waiting count is the shell's own pending queue, on the page's one timer, and the open
// findings are the shell's own count, passed in. An administrator's
// two further rows each read once, while the panel is open, and are on no timer: the approvals
// held for other approvers (the Approvals page's own `view=others` read, so they share an entry)
// and the dispatches awaiting provider evidence (Home's overview on its default range, so they
// share an entry too). Neither figure is windowed, so no row names a period.

import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";

import { listApprovalsOptions, readOverviewOptions } from "../api/@tanstack/react-query.gen";
import { clock } from "../components/charts/CountdownRing";
import { SecurityChanges } from "../components/settings/SecurityNotifications";
import { Drawer } from "../components/ui/Drawer";
import { useServerNow } from "../lib/clock";
import { useSession } from "../lib/session";
import { useTimeZone, utcOffsetMinutes } from "../lib/time";
import { usePending } from "./pending";
import "./surfaces.css";

const plural = (count: number, one: string, many: string) => `${String(count)} ${count === 1 ? one : many}`;

function Row({ title, detail, reason, link }: { title: string; detail?: string; reason: string; link: ReactNode }) {
  return (
    <li className="waiting-row">
      <strong>{title}</strong>
      {detail !== undefined ? <span>{detail}</span> : null}
      <small className="muted">{reason}</small>
      {link}
    </li>
  );
}

export default function Notifications({ onClose, findings = 0 }: { onClose: () => void; findings?: number }) {
  const session = useSession();
  const admin = session.role === "ADMIN";
  const pending = usePending();
  const now = useServerNow();
  const [choice] = useTimeZone();
  const others = useQuery({ ...listApprovalsOptions({ query: { view: "others" } }), enabled: admin });
  const overview = useQuery({
    ...readOverviewOptions({ query: { range: "7d", utc_offset: String(utcOffsetMinutes(choice)) } }),
    enabled: admin,
  });
  const rows: ReactNode[] = [];
  const mine = pending.count ?? 0;
  if (mine > 0) {
    const left = pending.soonest === undefined ? undefined : (Date.parse(pending.soonest) - now) / 1000;
    rows.push(
      <Row
        key="mine"
        title={`${pending.more ? "50+ approvals" : plural(mine, "approval", "approvals")} waiting for your decision`}
        detail={left === undefined ? undefined : `The soonest lapses in ${clock(left)}`}
        reason="You are an assigned approver."
        link={<Link to="/approvals" onClick={onClose}>Open Approvals</Link>}
      />,
    );
  }
  if (admin && findings > 0) {
    rows.push(
      <Row
        key="findings"
        title={plural(findings, "open monitoring finding", "open monitoring findings")}
        reason="You administer this workspace's monitoring."
        link={<Link to="/monitor" search={{ view: "findings" }} onClick={onClose}>Review findings</Link>}
      />,
    );
  }
  const held = others.data?.items.length ?? 0;
  if (admin && held > 0) {
    const more = (others.data?.next_cursor ?? null) !== null;
    rows.push(
      <Row
        key="others"
        title={`${more ? "50+ approvals" : plural(held, "approval", "approvals")} waiting on other approvers`}
        reason="Held for approvers in the spaces you are looking at. You are not assigned to decide these."
        link={<Link to="/approvals" search={{ view: "others" }} onClick={onClose}>Show waiting on others</Link>}
      />,
    );
  }
  const unsettled = admin ? (overview.data?.unsettled ?? 0) : 0;
  if (unsettled > 0) {
    rows.push(
      <Row
        key="unsettled"
        title={`${plural(unsettled, "dispatch", "dispatches")} awaiting provider evidence`}
        reason="An administrator settles these from the record."
        link={<Link to="/activity" search={{ state: "UNCERTAIN" }} onClick={onClose}>See uncertain requests</Link>}
      />,
    );
  }
  return (
    <Drawer open onClose={onClose} title="Notifications">
      <section aria-labelledby="waiting-on-you">
        <h3 id="waiting-on-you" className="notifications-heading">Waiting on you</h3>
        {rows.length > 0 ? <ul className="waiting-list">{rows}</ul> : <p>Nothing is waiting on you.</p>}
      </section>
      <section aria-labelledby="sign-in-security">
        <h3 id="sign-in-security" className="notifications-heading">Sign-in security</h3>
        <SecurityChanges />
      </section>
    </Drawer>
  );
}
