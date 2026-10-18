// SPDX-License-Identifier: AGPL-3.0-only
// What an administrator's account should act on, on Home (#678): agent keys in use that expire
// within seven days, at most five agents, with the rest counted and linked to API keys; and,
// once, that their own account has no second factor while the deployment offers one. Both read
// once a minute at most and never poll, and neither shows when there is nothing to do.

import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";

import { listExpiringKeysOptions, readSettingsOptions } from "../../api/@tanstack/react-query.gen";
import { useSession } from "../../lib/session";
import { KeyNotice } from "../directory/KeyNotice";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";

export function AccountNotices() {
  const session = useSession();
  const admin = session.role === "ADMIN";
  if (!admin) return null;
  return (
    <>
      <SecondFactorNotice />
      <ExpiringKeys />
    </>
  );
}

function ExpiringKeys() {
  const expiring = useQuery({ ...listExpiringKeysOptions(), staleTime: 60_000 });
  const data = expiring.data;
  if (data === undefined || data.keys.length === 0) return null;
  return (
    <Card title="API keys expiring soon">
      <ul className="notice-list">
        {data.keys.map((notice) => (
          <li key={notice.credential_id}>
            <KeyNotice notice={notice} />
          </li>
        ))}
      </ul>
      {data.more > 0 ? (
        <p>
          <Link to="/credentials">and {String(data.more)} more</Link>
        </p>
      ) : null}
    </Card>
  );
}

/** Where a dismissal is remembered: this browser only, per person. */
export function dismissalKey(principalId: string): string {
  return `eb.notice.second-factor.${principalId}`;
}

function dismissed(key: string): boolean {
  try {
    return window.localStorage.getItem(key) === "dismissed";
  } catch {
    return false;
  }
}

function remember(key: string): void {
  try {
    window.localStorage.setItem(key, "dismissed");
  } catch {
    // Nothing to remember it in; the card stays gone until the page is left.
  }
}

/** Shown once, until dismissed in this browser: an administrator whose own account has no
 * second factor where the deployment offers one. Where the workspace requires a factor,
 * sign-in already enrols one, so this can only appear under an optional requirement. */
function SecondFactorNotice() {
  const settings = useQuery({ ...readSettingsOptions(), staleTime: 60_000 });
  const [closed, setClosed] = useState<string | null>(null);
  const view = settings.data;
  const security = view?.security;
  if (view === undefined || !security?.available || security.authenticator) return null;
  const key = dismissalKey(view.identity.principal_id);
  if (closed === key || dismissed(key)) return null;
  return (
    <Card title="Your account has no second factor">
      <p>Changes to people, keys and approval rules are not protected by a second factor for your account.</p>
      <div className="row">
        <a className="btn btn-primary" href="/account/security">
          Add a second factor
        </a>
        <Button
          onClick={() => {
            remember(key);
            setClosed(key);
          }}
        >
          Dismiss
        </Button>
      </div>
    </Card>
  );
}
