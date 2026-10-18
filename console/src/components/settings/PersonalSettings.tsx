// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import {
  changePasswordMutation,
  readSettingsOptions,
  readSettingsQueryKey,
  revokeOtherSessionsMutation,
} from "../../api/@tanstack/react-query.gen";
import type { PersonalSettingsView } from "../../api/types.gen";
import {
  APPEARANCE_LEAD,
  APPEARANCE_WORDS,
  APPEARANCES,
  useAppearance,
} from "../../lib/appearance";
import { useServerMutation } from "../../lib/mutation";
import { copyFor } from "../../lib/refusal";
import { type TimeZoneChoice, useTimeZone, zoneName } from "../../lib/time";
import { toast } from "../../lib/toast";
import { count, prefix, when } from "../../lib/when";
import { AccountDetails } from "./AccountDetails";
import { DirectoryIdentity } from "./DirectoryIdentity";
import { PersonalTokens } from "./PersonalTokens";
import { WeeklySummary } from "./WeeklySummary";
import { SignOut } from "../../shell/SignOut";
import { Badge } from "../ui/Badge";
import { SingleKeysSwitch } from "../ui/SingleKeysSwitch";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { Definition, Definitions } from "../ui/Definitions";
import { FormDialog } from "../ui/FormDialog";
import { PageHeading } from "../ui/PageHeading";
import { Table, Td, Th } from "../ui/Table";


/**
 * The personal page (#253): who I am, the credential I signed in with, my directory identity,
 * and every session signed in as me, of which I can end all but this one. Nothing here changes
 * the tenant, and every row is the acting principal's own.
 */
export function PersonalSettings() {
  const query = useQuery({
    ...readSettingsOptions(),
    throwOnError: (_error, failed) => failed.state.data === undefined,
  });
  return (
    <>
      <PageHeading
        title="My account"
        lead="Manage your sign-in, devices and appearance. Review permissions are assigned by an administrator."
      />
      {query.data !== undefined ? (
        <Sections view={query.data} />
      ) : (
        <p className="muted" role="status">
          Loading your settings
        </p>
      )}
    </>
  );
}

function Sections({ view }: { view: PersonalSettingsView }) {
  return (
    <>
      <div className="cards">
        <AccountDetails identity={view} />
        <details>
          <summary>Advanced sign-in details</summary>
          <Card title="Session access record">
          <Definitions aria-label="Session access record">
            <Definition term="Account ID" mono>{prefix(view.identity.principal_id)}</Definition>
            <Definition term="Credential" mono>
              {prefix(view.identity.credential_id)}
            </Definition>
            <Definition term="Issued" mono>
              {when(view.credential.issued_at)}
            </Definition>
            <Definition term="Expires" mono>
              {when(view.credential.expires_at)}
            </Definition>
          </Definitions>
          <p className="muted">
            This internal access record supports your signed-in session. Use your normal sign-in method
            when returning to ExecBound.
          </p>
          </Card>
        </details>
        <Password view={view} />
        <DirectoryIdentity directory={view.directory} />
        {view.identity.kind === "ADMIN" ? <PersonalTokens /> : null}
        <SecondFactor view={view} />
        <Appearance />
        <WeeklySummary view={view} />
        <Card title="This session">
          <p className="muted">
            Signing out ends the session you are using now and sends you to the sign-in page. Every other
            session signed in as you stays open; the list below ends those.
          </p>
          <div className="row">
            <SignOut />
          </div>
        </Card>
      </div>
      <Sessions view={view} />
    </>
  );
}

/**
 * Light, Dark, or whatever this device is set to. The choice belongs to this browser and
 * nothing else: it is a cookie of one word, no request carries it as data and no row records
 * it, so the same person on another machine gets that machine's setting.
 *
 * It is a cookie rather than the browser storage the sidebar rail uses because the server has
 * to apply it. The console document carries no inline script and paints a plain frame from
 * the tokens before the bundle runs, so a scheme this page applied on its own would arrive a
 * paint late every time the console is opened — the wrong scheme, briefly, on every visit.
 */
function Appearance() {
  const [appearance, choose] = useAppearance();
  const [times, chooseTimes] = useTimeZone();
  return (
    <Card title="Appearance">
      <div className="segments" role="group" aria-label="Appearance">
        {APPEARANCES.map((option) => (
          <button
            key={option}
            type="button"
            className="btn"
            aria-pressed={option === appearance}
            onClick={() => {
              choose(option);
            }}
          >
            {APPEARANCE_WORDS[option]}
          </button>
        ))}
      </div>
      <p className="muted">{APPEARANCE_LEAD[appearance]}</p>
      <p className="muted">
        This is remembered for this browser alone, the way the sidebar and a table&apos;s density
        are. Nothing about it is sent to the server as data or kept against your account, and the
        live board stays dark in every appearance because it is built to be read across a room.
      </p>
      <div className="segments" role="group" aria-label="Show times in">
        {TIME_ZONE_CHOICES.map((option) => (
          <button
            key={option}
            type="button"
            className="btn"
            aria-pressed={option === times}
            onClick={() => {
              chooseTimes(option);
            }}
          >
            {option === "utc" ? "UTC" : `My time zone (${zoneName("local")})`}
          </button>
        ))}
      </div>
      <p className="muted">
        Remembered for this browser alone. Today on Home and the Live board starts at midnight in
        this zone.
      </p>
      <SingleKeysSwitch />
    </Card>
  );
}

const TIME_ZONE_CHOICES: readonly TimeZoneChoice[] = ["local", "utc"];

const MIN_PASSWORD = 12;
const MAX_PASSWORD = 200;

/**
 * Your own password, changed by presenting the current one. Nobody else can change it: the
 * server takes the principal from the session, so this request names no person at all, and
 * an administrator's route mints a one-time code instead of setting a password for somebody.
 */
function Password({ view }: { view: PersonalSettingsView }) {
  const queryClient = useQueryClient();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [mismatch, setMismatch] = useState(false);
  const change = useServerMutation({
    ...changePasswordMutation(),
    onSuccess: (fresh) => {
      queryClient.setQueryData(readSettingsQueryKey(), fresh);
      setCurrent("");
      setNext("");
      setAgain("");
      toast("Password changed.");
    },
  });
  return (
    <Card title="Your password">
      {view.has_password ? (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            if (next !== again) {
              setMismatch(true);
              return;
            }
            setMismatch(false);
            change.mutate({ body: { current, new: next } });
          }}
        >
          <label className="field">
            <span className="field-label">Current password</span>
            <input
              type="password"
              value={current}
              required
              maxLength={MAX_PASSWORD}
              autoComplete="current-password"
              onChange={(event) => {
                setCurrent(event.target.value);
              }}
            />
          </label>
          <label className="field">
            <span className="field-label">New password</span>
            <input
              type="password"
              value={next}
              required
              minLength={MIN_PASSWORD}
              maxLength={MAX_PASSWORD}
              autoComplete="new-password"
              onChange={(event) => {
                setNext(event.target.value);
              }}
            />
          </label>
          <label className="field">
            <span className="field-label">New password again</span>
            <input
              type="password"
              value={again}
              required
              minLength={MIN_PASSWORD}
              maxLength={MAX_PASSWORD}
              autoComplete="new-password"
              onChange={(event) => {
                setAgain(event.target.value);
              }}
            />
          </label>
          <div className="row">
            <Button type="submit" disabled={change.isPending}>
              Change the password
            </Button>
          </div>
          {mismatch ? (
            <p className="problem" role="alert">
              The two new passwords are not the same.
            </p>
          ) : null}
          {change.isError ? (
            <p className="problem" role="alert">
              {copyFor(change.error)}
            </p>
          ) : null}
          <p className="muted">
            At least {MIN_PASSWORD} characters. Your sessions stay open; an administrator&apos;s
            one-time code is what ends them, because that is a recovery rather than a change.
          </p>
        </form>
      ) : (
        <p className="muted">
          You have no password set. You can add one from{" "}
          <a href="/account/security">Account security</a> after signing in again. Otherwise continue
          with your configured sign-in provider, or ask
          {view.identity.kind === "ADMIN" ? " the installation owner" : " an administrator"} for password setup.
        </p>
      )}
      <p className="muted">
        {view.email !== null
          ? `You sign in as ${view.email}.`
          : view.identity.kind === "ADMIN"
            ? "Ask the installation owner to configure your sign-in address."
            : "Ask an administrator to save your sign-in email in Team & access."}
      </p>
    </Card>
  );
}

function Sessions({ view }: { view: PersonalSettingsView }) {
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const signOut = useServerMutation({
    ...revokeOtherSessionsMutation(),
    onSuccess: (fresh) => {
      queryClient.setQueryData(readSettingsQueryKey(), fresh);
      setConfirming(false);
      toast(`Signed out ${count(view.others, "other device")}.`);
    },
  });
  return (
    <Card title="Sessions" aside={<span className="muted">{count(view.sessions.length, "active session")}</span>}>
      <Table caption="Every active session signed in as you, newest first." density="compact">
        <thead>
          <tr>
            <Th>Session</Th>
            <Th>Device</Th>
            <Th>Signed in</Th>
            <Th>Expires</Th>
          </tr>
        </thead>
        <tbody>
          {view.sessions.map((row) => (
            <tr key={row.session_id}>
              <Td mono>
                {prefix(row.session_id)}{" "}
                {row.current ? <Badge tone="accent">This device</Badge> : null}
              </Td>
              <Td>{row.label}</Td>
              <Td mono>{when(row.created_at)}</Td>
              <Td mono>{when(row.expires_at)}</Td>
            </tr>
          ))}
        </tbody>
      </Table>
      {view.others > 0 ? (
        <>
          <div className="row">
            <Button
              variant="danger"
              onClick={() => {
                signOut.reset();
                setConfirming(true);
              }}
            >
              Sign out other devices
            </Button>
          </div>
          <p className="muted">
            Ends the {count(view.others, "other session")} above and keeps this one. Their next request is
            refused and the audit chain records each one as ended from here.
          </p>
          <FormDialog
            open={confirming}
            onClose={() => {
              setConfirming(false);
            }}
            title="Sign out other devices?"
            description="Every other session signed in as you ends now. This device stays signed in."
            confirm="Sign out other devices"
            variant="danger"
            pending={signOut.isPending}
            error={signOut.isError ? copyFor(signOut.error) : undefined}
            onSubmit={() => {
              signOut.mutate({ body: {} });
            }}
          />
        </>
      ) : (
        <p className="muted">No other device is signed in as you.</p>
      )}
      <p className="muted">
        Ending other sessions asks for no password: this session is at most eight hours old, the request carries
        your session's token, and the button confirms first. The device name comes from a fixed list; the
        browser's own string is never stored.
      </p>
    </Card>
  );
}

const REQUIREMENT_WORDS: Record<"admins" | "all", string> = {
  admins: "This workspace requires a second factor for administrators.",
  all: "This workspace requires a second factor for everyone.",
};

/** The person's own second factor (#678): what is on, as counts, and the way to change it on
 * Account security, which is a server-rendered page, so the link is a plain one. */
function SecondFactor({ view }: { view: PersonalSettingsView }) {
  const security = view.security;
  if (!security?.available) {
    return (
      <Card title="Multi-factor authentication">
        <p>Account security is not configured on this deployment.</p>
      </Card>
    );
  }
  const any = security.authenticator || security.passkeys > 0;
  return (
    <Card title="Multi-factor authentication">
      <dl className="facts">
        <dt>Authenticator app</dt>
        <dd>{security.authenticator ? "On" : "Off"}</dd>
        <dt>Passkeys</dt>
        <dd>{String(security.passkeys)} saved</dd>
        {security.authenticator ? (
          <>
            <dt>Recovery codes</dt>
            <dd>{String(security.recovery_remaining)} left</dd>
          </>
        ) : null}
      </dl>
      {security.requirement !== "optional" ? <p className="note">{REQUIREMENT_WORDS[security.requirement]}</p> : null}
      <a className="btn" href="/account/security">
        {any ? "Manage" : "Add a second factor"}
      </a>
    </Card>
  );
}
