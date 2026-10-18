// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";

import { readAccountOptions } from "../../api/@tanstack/react-query.gen";
import { useRetry } from "../../lib/retry";
import { when } from "../../lib/when";
import { TryAgain } from "../ui/TryAgain";

/**
 * The account's recent sign-in security changes, as the bell's panel shows them below what is
 * waiting on the person (#678).
 */
export function SecurityChanges() {
  const query = useQuery({ ...readAccountOptions(), refetchInterval: 30_000 });
  const retry = useRetry(query);
  return <>
    <p>Recent changes to your sign-in security, shown in the app. If you do not recognize a change, secure your account and contact your administrator.</p>
    <a href="/account/security" className="btn">Manage account security</a>
    {/* Only a first read that failed stands in for the list; a poll that fails is said above
        the notifications it read. */}
    {retry.failure !== null ? <p role="alert">Notifications could not be loaded. <TryAgain retry={retry} /></p> : null}
    {query.data === undefined ? retry.failure !== null ? null : <p role="status">Loading notifications…</p>
      : query.data.notifications.length ? <ul>{query.data.notifications.map((item) => <li key={item.sequence}><strong>{item.message}</strong><p className="muted">{when(item.at)}</p></li>)}</ul>
      : <p>No security changes in the last 90 days.</p>}
    <p className="muted">Shows the 30 most recent changes for your account.</p>
  </>;
}
