// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import {
  changeProfileMutation, readAccountOptions, readAccountQueryKey, requestAccountDataMutation,
} from "../../api/@tanstack/react-query.gen";
import type { AccountView, PersonalSettingsView, PrivacyRequest } from "../../api/types.gen";
import { useEdition } from "../../edition/context";
import { useServerMutation } from "../../lib/mutation";
import { copyFor } from "../../lib/refusal";
import { useRetry } from "../../lib/retry";
import { useService } from "../../lib/session";
import { toast } from "../../lib/toast";
import { when } from "../../lib/when";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { FormDialog } from "../ui/FormDialog";
import { TryAgain } from "../ui/TryAgain";

export const REQUEST_LABELS = {
  data_access: "Access my data", close_account: "Close my account", close_workspace: "Close this workspace",
};

export function AccountDetails({ identity }: { identity: PersonalSettingsView }) {
  const query = useQuery(readAccountOptions());
  const retry = useRetry(query);
  // An edition's cards between the profile and the requests (#496); core has none.
  const { AccountPanels } = useEdition();
  // Only a first read that failed takes the profile's place; a later one, the bell's poll or a
  // return to the tab, is said above the profile it read, so a name being typed survives it.
  const failed = retry.failure !== null ? <p role="alert">Your profile could not be loaded. <TryAgain retry={retry} /></p> : null;
  if (query.data === undefined) return failed ?? <p role="status">Loading your profile…</p>;
  return <>{failed}<Profile key={query.data.name} view={query.data} identity={identity} /><AccountPanels />
    <PrivacyRequests view={query.data} admin={identity.identity.kind === "ADMIN"} /></>;
}

function Profile({ view, identity }: { view: AccountView; identity: PersonalSettingsView }) {
  const cache = useQueryClient();
  const [name, setName] = useState(view.name ?? "");
  const change = useServerMutation({ ...changeProfileMutation(), onSuccess: (fresh) => {
    cache.setQueryData(readAccountQueryKey(), fresh); void cache.invalidateQueries(); toast("Profile saved.");
  } });
  return <Card title="Your profile"><form onSubmit={(event) => { event.preventDefault(); change.mutate({ body: { name: name.trim() } }); }}>
    <label className="field"><span className="field-label">Display name</span><input autoComplete="name" required maxLength={80} value={name} onChange={(event) => { setName(event.target.value); }} /></label>
    <p><strong>Email:</strong> {identity.email ?? "Ask your administrator to add a sign-in email."}</p>
    <p><strong>Workspace:</strong> {identity.tenant_name}</p>
    <p><strong>Access:</strong> {identity.identity.kind === "ADMIN" ? "Administrator" : "Member"}</p>
    <Button type="submit" disabled={change.isPending || !name.trim()}>Save profile</Button>
    {change.isError ? <p role="alert">{copyFor(change.error)}</p> : null}
  </form></Card>;
}

function PrivacyRequests({ view, admin }: { view: AccountView; admin: boolean }) {
  const cache = useQueryClient();
  // The deployment's own support address (#496), where it names one.
  const { support_email: support } = useService();
  const [kind, setKind] = useState<PrivacyRequest["kind"] | null>(null);
  const change = useServerMutation({ ...requestAccountDataMutation(), onSuccess: (fresh) => {
    cache.setQueryData(readAccountQueryKey(), fresh); setKind(null); toast("Request sent to your workspace administrators.");
  } });
  return <Card title="Your data and account">
    <p>Request a copy of your data or account closure. Your workspace administrators handle these requests and post a response here.{support !== null ? <> For help beyond your workspace administrators, <a href={`mailto:${support}?subject=ExecBound%20privacy%20request`}>contact support</a>.</> : null}</p>
    <div className="row">{(Object.keys(REQUEST_LABELS) as PrivacyRequest["kind"][]).filter((item) => admin || item !== "close_workspace").map((item) => <Button key={item} disabled={view.requests.some((row) => row.kind === item && row.state === "pending")} onClick={() => { change.reset(); setKind(item); }}>{REQUEST_LABELS[item]}</Button>)}</div>
    <p className="muted">Requesting closure starts a review. It does not immediately delete data or stop agents. Administrators must coordinate access, retention, backups and any security-audit obligations before confirming completion.</p>
    {view.requests.length ? <ul>{view.requests.map((row) => <li key={row.request_id}><strong>{REQUEST_LABELS[row.kind]}</strong> — {row.state} · {when(row.requested_at)}{row.response ? <p>{row.response}</p> : null}</li>)}</ul> : <p className="muted">No data or closure requests yet.</p>}
    <FormDialog open={kind !== null} onClose={() => { setKind(null); }} title={kind ? REQUEST_LABELS[kind] : "Account request"}
      description="Send this request to your workspace administrators? You can follow its status here."
      confirm="Send request" pending={change.isPending} error={change.isError ? copyFor(change.error) : undefined}
      onSubmit={() => { if (kind) change.mutate({ body: { kind } }); }} />
  </Card>;
}
