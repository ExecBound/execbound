// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";

import {
  assignPersonScopeMutation,
  deactivatePersonMutation,
  endPersonSessionsMutation,
  issuePasswordCodeMutation,
  labelPersonMutation,
  reactivatePersonMutation,
  readSignInOptions,
  revokePersonCredentialMutation,
  setPersonEmailMutation,
  unassignPersonScopeMutation,
} from "../../api/@tanstack/react-query.gen";
import type { AccessUser, CredentialRow, EventRow, PersonDetail } from "../../api/types.gen";
import { Badge, type Tone } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { PageHeading } from "../ui/PageHeading";
import { Table, Td, Th } from "../ui/Table";
import { CodeDialog } from "./CodeDialog";
import { DirectoryCard } from "./DirectoryCard";
import { ConfirmDialog } from "./ConfirmDialog";
import { NamePrompt } from "./NamePrompt";
import { PRINCIPAL_REPLACED_SENTENCE } from "./errors";
import { handle, prefix, principalName, when, words } from "./format";
import { policyName } from "../policy/format";
import { scopeChange, usePersonChange } from "./personChange";
import { PersonStateBadge } from "./PersonState";
import { CODE_LIFETIMES, Field, LifetimeSelect, Problem, type Lifetime } from "./forms";
import { useShowOnce } from "./showOnce";
import { UserAccessCard, useUserAccess, type AccountProtection } from "./UserAccess";

const CREDENTIAL_TONES: Record<CredentialRow["state"], Tone> = {
  live: "allow",
  expired: "stale",
  revoked: "stale",
};

export function PersonDetailView({ detail }: { detail: PersonDetail }) {
  const person = detail.person;
  const access = useUserAccess();
  const user = access.data?.users.find((item) => item.principal_id === person.principal_id);
  const administrator = person.kind === "ADMIN" || [...(user?.direct_roles ?? []), ...(user?.inherited_roles ?? [])].some((grant) => grant.role === "administrator");
  const protection: AccountProtection = administrator ? "protected" : user === undefined ? "unknown" : "standard";
  return (
    <>
      <PageHeading
        title={principalName("User", person.label, person.number, person.principal_id, detail.sign_in.email)}
        lead="Manage this user’s sign-in, access roles and review assignments."
        actions={<PersonStateBadge person={person} />}
      />
      {person.label === null ? <PersonNamePrompt principalId={person.principal_id} /> : null}
      <p className="meta">
        <Link to="/people">Back to Users</Link>
        {" · "}
        {handle("User", person.number, person.principal_id)} · created{" "}
        {person.created_at !== null ? when(person.created_at) : "before labels"}
        {person.deactivated_at !== null ? ` · deactivated ${when(person.deactivated_at)}` : ""}
      </p>
      <div className="stack">
        <SetupCard detail={detail} user={user} protection={protection} />
        <UserAccessCard key={person.principal_id} principalId={person.principal_id} query={access} />
        <div className="grid-2">
          {/* Keyed by the label, so a name saved from the prompt above remounts it (#678). */}
          <IdentityCard key={person.label ?? ""} detail={detail} />
          <SessionsCard detail={detail} />
        </div>
        <SignInCard detail={detail} protection={protection} />
        <DirectoryCard detail={detail} protection={protection} />
        <ScopesCard detail={detail} />
        <HistoryCard detail={detail} />
        <details>
          <summary>Advanced access details</summary>
          <CredentialsCard detail={detail} protection={protection} />
        </details>
        {person.replaced_by !== null ? (
          <ReplacedCard replacedBy={person.replaced_by} />
        ) : protection === "standard" && !detail.is_self ? (
          <LifecycleCard detail={detail} />
        ) : null}
      </div>
    </>
  );
}

function SetupCard({ detail, user, protection }: { detail: PersonDetail; user: AccessUser | undefined; protection: AccountProtection }) {
  const signIn = detail.sign_in;
  const tenant = useQuery({ ...readSignInOptions(), enabled: signIn.link !== null, throwOnError: false });
  const provider = tenant.data?.provider;
  const directoryReady = tenant.isSuccess && provider?.state === "enabled" && provider.provider_id === signIn.link?.provider_id;
  const canSignIn = signIn.has_password || signIn.identities.length > 0 || directoryReady;
  const grants = [...(user?.direct_roles ?? []), ...(user?.inherited_roles ?? [])];
  const reviewer = grants.some((grant) => grant.role === "approver");
  const reviewerGroups = [...new Set(user?.inherited_roles.filter((grant) => grant.role === "approver").map((grant) => grant.group_name) ?? [])];
  let signInState = canSignIn ? "configured" : signIn.pending_until !== null || signIn.invitation !== null ? "invitation pending" : "needs setup";
  let next = detail.person.replaced_by !== null
    ? PRINCIPAL_REPLACED_SENTENCE
    : !detail.person.active
    ? "This account is deactivated. Restore access before completing setup."
    : !canSignIn
      ? protection === "unknown"
        ? "Load access roles before choosing a sign-in setup method for this account."
        : protection === "protected"
        ? "Ask the installation owner to configure this account's sign-in or password recovery."
        : signIn.email === null
        ? "Save a sign-in email below, then choose password or directory sign-in."
        : "Create a one-time password setup code below, or invite this account to your configured directory."
      : user === undefined
        ? "Access roles are unavailable. Check Roles and access before changing this account."
        : grants.length === 0
          ? "Choose access roles below for this user's work."
          : reviewer
            ? "Review Approval rules for the groups, actions, resources and Spaces this user may review. Individual assignments are listed separately below."
            : "Sign-in and access roles are configured. Review access is optional and is not needed for this user's current roles.";
  if (!canSignIn && signIn.link !== null) {
    signInState = tenant.isError ? "directory availability unknown" : tenant.isPending ? "checking directory availability" : "directory unavailable";
    if (detail.person.active) {
      next = tenant.isError
        ? "Could not check directory sign-in. Check again before treating this account as ready to review."
        : tenant.isPending
          ? "Checking whether the linked directory is enabled before confirming sign-in setup."
          : "Enable the linked directory in Workspace settings, or configure another sign-in method for this account.";
    }
  }
  return (
    <Card title="Account setup">
      <ol>
        <li>Named account: {detail.person.label ?? "not yet; name them above"}</li>
        <li>Sign-in: {signInState}</li>
        <li>Review role: {reviewerGroups.length > 0 ? `Approver via ${reviewerGroups.join(", ")}` : reviewer ? "Approver assigned" : user === undefined ? "not established" : "not assigned; only needed for reviewers"}</li>
        <li>Individual review assignments: {detail.scopes.length > 0 ? `${String(detail.scopes.length)} assigned` : "none assigned"}</li>
      </ol>
      <p><strong>Next step:</strong> {next}</p>
      {reviewer ? <p><Link to="/approvers">Open Approval rules</Link> to check current group routing and reviewer eligibility.</p> : null}
      {!canSignIn && signIn.link !== null && tenant.isError ? <Button disabled={tenant.isFetching} onClick={() => { void tenant.refetch(); }}>Check directory sign-in again</Button> : null}
      <p className="note">Signing in does not grant review permission. Reviewers need an eligible assignment, and access is checked again when they decide.</p>
    </Card>
  );
}

function PersonNamePrompt({ principalId }: { principalId: string }) {
  const relabel = usePersonChange(principalId, labelPersonMutation(), "Label saved.");
  return (
    <NamePrompt
      noun="User"
      pending={relabel.isPending}
      error={relabel.error}
      onSave={(label) => {
        relabel.mutate({ path: { principal_id: principalId }, body: { label } });
      }}
    />
  );
}

function IdentityCard({ detail }: { detail: PersonDetail }) {
  const person = detail.person;
  const [label, setLabel] = useState(person.label ?? "");
  const relabel = usePersonChange(person.principal_id, labelPersonMutation(), "Label saved.");
  return (
    <Card title="Identity">
      <dl className="facts">
        <dt>Principal</dt>
        <dd className="mono">{person.principal_id}</dd>
        <dt>State</dt>
        <dd><PersonStateBadge person={person} /></dd>
      </dl>
      <form
        className="form-row"
        onSubmit={(event) => {
          event.preventDefault();
          relabel.mutate({ path: { principal_id: person.principal_id }, body: { label: label.trim() } });
        }}
      >
        <Field label="Label (1 to 80 characters)">
          <input
            value={label}
            maxLength={80}
            required
            autoComplete="off"
            onChange={(event) => {
              setLabel(event.target.value);
            }}
          />
        </Field>
        <Button type="submit" disabled={relabel.isPending}>
          Save the label
        </Button>
      </form>
      <Problem error={relabel.error} />
    </Card>
  );
}

/**
 * How this user signs in: the address they use, whether they hold a password, whether a
 * set-password code is waiting, and any directory account bound to them.
 *
 * An administrator's sign-in address stays with owner tooling.
 */
function SignInCard({ detail, protection }: { detail: PersonDetail; protection: AccountProtection }) {
  const person = detail.person;
  const signIn = detail.sign_in;
  const [email, setEmail] = useState(signIn.email ?? "");
  const [lifetime, setLifetime] = useState<Lifetime>("24");
  const queryClient = useQueryClient();
  const setAddress = usePersonChange(person.principal_id, setPersonEmailMutation(), "Sign-in address saved.");
  const code = useShowOnce({
    ...issuePasswordCodeMutation(),
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: [{ _id: "readPerson" }] }); },
  });
  return (
    <Card title="Sign-in">
      <dl className="facts">
        <dt>Address</dt>
        <dd>{signIn.email ?? "Not set"}</dd>
        <dt>Password</dt>
        <dd>{signIn.has_password ? <Badge tone="allow">Set</Badge> : <Badge tone="stale">Not set</Badge>}</dd>
        <dt>Second factor</dt>
        <dd>{person.second_factor === true ? "Enrolled" : "None"}</dd>
        <dt>Pending code</dt>
        <dd>{signIn.pending_until !== null ? `Valid until ${when(signIn.pending_until)}` : "None"}</dd>
        <dt>Directory account</dt>
        <dd>
          {signIn.identities.length === 0
            ? "None linked"
            : signIn.identities.map((row) => (
                <span key={`${row.provider}:${row.subject}`}>
                  {words(row.provider)}
                  {row.display_name !== null ? ` · ${row.display_name}` : ""}
                  {row.last_sign_in_at !== null ? ` · last signed in ${when(row.last_sign_in_at)}` : ""}
                </span>
              ))}
        </dd>
      </dl>
      {signIn.account_owned ? <p className="note">This member manages their own account sign-in and recovery. Workspace administrators manage membership and workspace permissions.</p> : protection === "protected" ? (
        <p className="note">
          {detail.is_self ? <>Manage your password in <Link to="/settings">My account</Link>. </> : null}
          The installation owner manages this account’s sign-in address and password recovery.
        </p>
      ) : protection === "unknown" ? <p className="note">Access roles are unavailable. Sign-in changes are hidden until account protection can be checked.</p> : person.active ? (
        <>
          <form
            className="form-row"
            onSubmit={(event) => {
              event.preventDefault();
              setAddress.mutate({
                path: { principal_id: person.principal_id },
                body: { email: email.trim() },
              });
            }}
          >
            <Field label="Sign-in address" hint="One address belongs to one user.">
              <input
                type="email"
                value={email}
                maxLength={254}
                required
                autoComplete="off"
                spellCheck={false}
                onChange={(event) => {
                  setEmail(event.target.value);
                }}
              />
            </Field>
            <Button type="submit" disabled={setAddress.isPending}>
              Save the address
            </Button>
          </form>
          <Problem error={setAddress.error} />
          {signIn.email !== null ? (
            <form
              className="form-row"
              onSubmit={(event) => {
                event.preventDefault();
                void code.issue({ path: { principal_id: person.principal_id }, body: { lifetime } });
              }}
            >
              <LifetimeSelect
                value={lifetime}
                onChange={setLifetime}
                label="Code lifetime"
                options={CODE_LIFETIMES}
              />
              <Button type="submit" disabled={code.pending}>
                Create password setup code
              </Button>
            </form>
          ) : (
            <p className="note">Give this user an address before issuing a code.</p>
          )}
          <Problem error={code.error} />
          <p className="note">
            Share the setup page and one-time code through your approved channel. No email is sent
            automatically. The user chooses their password, then signs in normally to review requests.
            A new code replaces the previous one; setting a password ends existing sessions.
          </p>
        </>
      ) : person.replaced_by !== null ? (
        <p className="note">This person signs in as their new entry in this workspace.</p>
      ) : <p className="note">Reactivate this account before changing sign-in.</p>}
      <CodeDialog code={code.secret} onClose={code.close} />
    </Card>
  );
}

function SessionsCard({ detail }: { detail: PersonDetail }) {
  const person = detail.person;
  const [asking, setAsking] = useState(false);
  const end = usePersonChange(person.principal_id, endPersonSessionsMutation(), "Every session of this user ended.");
  return (
    <Card title="Sessions">
      <Table caption="Active sessions of this user." density="compact">
        <thead>
          <tr>
            <Th>Session</Th>
            <Th>Device</Th>
            <Th>Signed in</Th>
            <Th>Expires</Th>
          </tr>
        </thead>
        <tbody>
          {detail.sessions.map((row) => (
            <tr key={row.session_id}>
              <Td mono>{prefix(row.session_id)}</Td>
              <Td>{row.label ?? "Other"}</Td>
              <Td mono>{when(row.created_at)}</Td>
              <Td mono>{when(row.expires_at)}</Td>
            </tr>
          ))}
          {detail.sessions.length === 0 ? (
            <tr>
              <Td colSpan={4}>No active session.</Td>
            </tr>
          ) : null}
        </tbody>
      </Table>
      {detail.is_self ? (
        <p className="note">
          Manage your own sessions in <Link to="/settings">My account</Link>.
        </p>
      ) : detail.sessions.length > 0 ? (
        <>
          <div className="row">
            <Button
              onClick={() => {
                end.reset();
                setAsking(true);
              }}
            >
              End all sessions
            </Button>
          </div>
          <ConfirmDialog
            open={asking}
            title="End every session of this user?"
            confirm="End all sessions"
            danger
            pending={end.isPending}
            error={end.error}
            onConfirm={() => {
              end.mutate(
                { path: { principal_id: person.principal_id }, body: {} },
                {
                  onSuccess: () => {
                    setAsking(false);
                  },
                },
              );
            }}
            onClose={() => {
              setAsking(false);
            }}
          >
            <p>The user will need to sign in again on each device.</p>
          </ConfirmDialog>
        </>
      ) : null}
    </Card>
  );
}

function CredentialsCard({ detail, protection }: { detail: PersonDetail; protection: AccountProtection }) {
  const person = detail.person;
  const [revoking, setRevoking] = useState<string | null>(null);
  const revoke = usePersonChange(person.principal_id, revokePersonCredentialMutation(), "Credential revoked.");
  return (
    <Card title="Legacy and session credentials">
      <p className="note">These records support access auditing and revocation. Reviewer setup uses the Sign-in section above.</p>
      {protection === "protected" ? (
        <p className="note">
          This account’s credentials are managed by the installation owner and cannot be issued or revoked here.
        </p>
      ) : null}
      <Table caption="Every credential of this user, newest first." density="compact">
        <thead>
          <tr>
            <Th>Credential</Th>
            <Th>Issued</Th>
            <Th>Expires</Th>
            <Th>State</Th>
            <Th>Failures (24 h)</Th>
            <Th>Revoke</Th>
          </tr>
        </thead>
        <tbody>
          {detail.credentials.map((row) => (
            <tr key={row.credential_id}>
              <Td mono>{prefix(row.credential_id)}</Td>
              <Td mono>{when(row.issued_at)}</Td>
              <Td mono>{when(row.expires_at)}</Td>
              <Td>
                <Badge tone={CREDENTIAL_TONES[row.state]}>{row.state}</Badge>
              </Td>
              <Td>{row.failures}</Td>
              <Td>
                {protection === "protected" ? (
                  <span className="muted">owner tooling</span>
                ) : protection === "unknown" ? <span className="muted">Access unavailable</span> : row.state === "live" ? (
                  <Button
                    size="small"
                    onClick={() => {
                      revoke.reset();
                      setRevoking(row.credential_id);
                    }}
                  >
                    Revoke {prefix(row.credential_id)}
                  </Button>
                ) : null}
              </Td>
            </tr>
          ))}
          {detail.credentials.length === 0 ? (
            <tr>
              <Td colSpan={6}>No credential yet.</Td>
            </tr>
          ) : null}
        </tbody>
      </Table>
      <ConfirmDialog
        open={revoking !== null}
        title={`Revoke credential ${prefix(revoking)}?`}
        confirm="Revoke"
        danger
        pending={revoke.isPending}
        error={revoke.error}
        onConfirm={() => {
          if (revoking === null) return;
          revoke.mutate(
            { path: { principal_id: person.principal_id, credential_id: revoking }, body: {} },
            {
              onSuccess: () => {
                setRevoking(null);
              },
            },
          );
        }}
        onClose={() => {
          setRevoking(null);
        }}
      >
        <p>Sessions and requests that use it stop at their next check.</p>
      </ConfirmDialog>
    </Card>
  );
}

function ScopesCard({ detail }: { detail: PersonDetail }) {
  const person = detail.person;
  const [target, setTarget] = useState(detail.targets[0]?.canonical_target_id ?? "");
  const [action, setAction] = useState(detail.actions[0] ?? "");
  const [unassigning, setUnassigning] = useState<{ target: string; action: string } | null>(null);
  const assign = usePersonChange(person.principal_id, scopeChange(assignPersonScopeMutation()), "Scope assigned.");
  const unassign = usePersonChange(person.principal_id, scopeChange(unassignPersonScopeMutation()), "Scope unassigned.");
  return (
    <Card title="Review permissions">
      <p className="note">Each assignment allows this account to review one action on one target in the selected space. Administrator access does not grant review permission automatically.</p>
      <Table caption="Canonical targets and actions this approver may decide." density="compact">
        <thead>
          <tr>
            <Th>Canonical target</Th>
            <Th>Action</Th>
            <Th>Unassign</Th>
          </tr>
        </thead>
        <tbody>
          {detail.scopes.map((row) => (
            <tr key={`${row.canonical_target_id}-${row.action}`}>
              <Td>
                <span className="mono">{prefix(row.canonical_target_id)}</span>
                {row.labels !== null ? ` · ${row.labels}` : ""}
              </Td>
              <Td mono>{row.action}</Td>
              <Td>
                {person.active ? (
                  <Button
                    size="small"
                    onClick={() => {
                      unassign.reset();
                      setUnassigning({ target: row.canonical_target_id, action: row.action });
                    }}
                  >
                    Unassign {row.action} on {prefix(row.canonical_target_id)}
                  </Button>
                ) : null}
              </Td>
            </tr>
          ))}
          {detail.scopes.length === 0 ? (
            <tr>
              <Td colSpan={3}>No review permissions. Assign an action and target before this user can decide requests.</Td>
            </tr>
          ) : null}
        </tbody>
      </Table>
      {person.active ? (
        <>
          <form
            className="form-row"
            onSubmit={(event) => {
              event.preventDefault();
              assign.mutate({ path: { principal_id: person.principal_id }, body: { target, action } });
            }}
          >
            <Field label="Canonical target">
              <select
                value={target}
                required
                onChange={(event) => {
                  setTarget(event.target.value);
                }}
              >
                {detail.targets.map((option) => (
                  <option key={option.canonical_target_id} value={option.canonical_target_id}>
                    {prefix(option.canonical_target_id)}
                    {option.labels !== null ? ` · ${option.labels}` : ""}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Action">
              <select
                value={action}
                required
                onChange={(event) => {
                  setAction(event.target.value);
                }}
              >
                {detail.actions.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </select>
            </Field>
            <Button type="submit" variant="primary" disabled={assign.isPending || target === "" || action === ""}>
              Assign
            </Button>
          </form>
          <Problem error={assign.error} />
        </>
      ) : null}
      <ConfirmDialog
        open={unassigning !== null}
        title={unassigning === null ? "Unassign?" : `Unassign ${unassigning.action} on ${prefix(unassigning.target)}?`}
        confirm="Unassign"
        danger
        pending={unassign.isPending}
        error={unassign.error}
        onConfirm={() => {
          if (unassigning === null) return;
          unassign.mutate(
            { path: { principal_id: person.principal_id }, body: unassigning },
            {
              onSuccess: () => {
                setUnassigning(null);
              },
            },
          );
        }}
        onClose={() => {
          setUnassigning(null);
        }}
      >
        <p>Pending decisions under this scope will be refused.</p>
      </ConfirmDialog>
    </Card>
  );
}

function HistoryCard({ detail }: { detail: PersonDetail }) {
  const history = detail.history;
  const limit = String(detail.history_limit);
  return (
    <Card title="History">
      <h3>Decisions</h3>
      <Table
        caption={`The last ${limit} decisions of this user, newest first. A decision stays here after its scope is unassigned.`}
        density="compact"
      >
        <thead>
          <tr>
            <Th>Decided</Th>
            <Th>Approval</Th>
            <Th>Action</Th>
            <Th>Target</Th>
            <Th>Decision</Th>
          </tr>
        </thead>
        <tbody>
          {history.decisions.map((row) => (
            <tr key={`${row.approval}-${row.decided_at}`}>
              <Td mono>{when(row.decided_at)}</Td>
              <Td mono>
                {/* The record opens only where the reader may see its execution; elsewhere the
                    server names none, and the prefix stays text. */}
                {row.execution_id !== null && row.execution_id !== undefined ? (
                  <Link to="/activity" search={{ open: row.execution_id }}>
                    {row.approval}
                  </Link>
                ) : (
                  row.approval
                )}
              </Td>
              <Td>{row.action}</Td>
              <Td mono>{row.target}</Td>
              <Td>
                <Badge tone={row.decision === "approved" ? "allow" : "deny"}>{row.decision}</Badge>
              </Td>
            </tr>
          ))}
          {history.decisions.length === 0 ? (
            <tr>
              <Td colSpan={5}>No decision yet.</Td>
            </tr>
          ) : null}
        </tbody>
      </Table>
      <h3>Sign-ins</h3>
      <Table
        caption={`The last ${limit} sign-ins of this user, newest first, with each session's state now.`}
        density="compact"
      >
        <thead>
          <tr>
            <Th>Signed in</Th>
            <Th>Session</Th>
            <Th>Credential</Th>
            <Th>Device</Th>
            <Th>State</Th>
          </tr>
        </thead>
        <tbody>
          {history.sign_ins.map((row) => (
            <tr key={`${row.session}-${row.occurred_at}`}>
              <Td mono>{when(row.occurred_at)}</Td>
              <Td mono>{row.session}</Td>
              <Td mono>{row.credential}</Td>
              <Td>{row.device}</Td>
              <Td>
                <Badge tone={row.state === "active" ? "allow" : "stale"}>{row.state}</Badge>
              </Td>
            </tr>
          ))}
          {history.sign_ins.length === 0 ? (
            <tr>
              <Td colSpan={5}>No sign-in yet.</Td>
            </tr>
          ) : null}
        </tbody>
      </Table>
      {detail.person.kind === "ADMIN" ? <h3>Administrative changes</h3> : null}
      {detail.person.kind === "ADMIN" ? (
        <Table
          caption={`The last ${limit} administrative events of this user, newest first: policy, credentials, scopes, users, agent bindings and the tenant's settings.`}
          density="compact"
        >
          <thead>
            <tr>
              <Th>When</Th>
              <Th>What</Th>
              <Th>Subject</Th>
            </tr>
          </thead>
          <tbody>
            {history.events.map((row, index) => (
              <tr key={`${row.occurred_at}-${String(index)}`}>
                <Td mono>{when(row.occurred_at)}</Td>
                <Td>{row.words}</Td>
                <Td>
                  <EventSubject row={row} />
                </Td>
              </tr>
            ))}
            {history.events.length === 0 ? (
              <tr>
                <Td colSpan={3}>No administrative event yet.</Td>
              </tr>
            ) : null}
          </tbody>
        </Table>
      ) : null}
    </Card>
  );
}

/** An event's subject: a policy, an agent or a person links to its page by the identifier the
 * server returned, named as the console names it; a space or a credential stays text. The
 * label is the subject's own text and renders as text. */
function EventSubject({ row }: { row: EventRow }) {
  const id = row.subject_id ?? null;
  if (row.subject === "") return <>this tenant</>;
  if (id !== null && row.subject_kind === "bundle") {
    return (
      <Link to="/policy/$bundleId" params={{ bundleId: id }}>
        {policyName(id)}
      </Link>
    );
  }
  if (id !== null && row.subject_kind === "principal" && row.subject_principal_kind === "AGENT") {
    return (
      <Link to="/agents/$agentId" params={{ agentId: id }}>
        {principalName("Agent", row.label, row.subject_number, id)}
      </Link>
    );
  }
  if (
    id !== null &&
    row.subject_kind === "principal" &&
    (row.subject_principal_kind === "HUMAN_APPROVER" || row.subject_principal_kind === "ADMIN")
  ) {
    return (
      <Link to="/people/$personId" params={{ personId: id }}>
        {principalName("User", row.label, row.subject_number, id)}
      </Link>
    );
  }
  return (
    <>
      <span className="mono">{row.subject}</span>
      {row.label !== null ? ` · ${row.label}` : ""}
    </>
  );
}

/** An entry a re-invitation replaced (migration 0061) is retired for good, so there is no
 * Reactivate here: the person's access lives on the entry that replaced this one. */
function ReplacedCard({ replacedBy }: { replacedBy: string }) {
  return (
    <Card title="Rejoined">
      <p className="note">{PRINCIPAL_REPLACED_SENTENCE}</p>
      <p>
        <Link to="/people/$personId" params={{ personId: replacedBy }}>
          Open their new entry
        </Link>
      </p>
    </Card>
  );
}

function LifecycleCard({ detail }: { detail: PersonDetail }) {
  const person = detail.person;
  const [asking, setAsking] = useState(false);
  const deactivate = usePersonChange(person.principal_id, deactivatePersonMutation(), "User deactivated.");
  const reactivate = usePersonChange(person.principal_id, reactivatePersonMutation(), "User reactivated.");
  if (person.active) {
    return (
      <Card title="Deactivate">
        <p className="note">
          Ends this user&apos;s access in one step: every live credential and every session is revoked and the
          user can no longer sign in or be issued a credential. Scopes are kept, so reactivation restores them
          exactly. Nothing is deleted; the audit chain keeps referring to this principal.
        </p>
        <div className="row">
          <Button
            variant="danger"
            onClick={() => {
              deactivate.reset();
              setAsking(true);
            }}
          >
            Deactivate this user
          </Button>
        </div>
        <ConfirmDialog
          open={asking}
          title="Deactivate this user?"
          confirm="Deactivate"
          danger
          reason="Reason (required, up to 500 characters)"
          pending={deactivate.isPending}
          error={deactivate.error}
          onConfirm={(reason) => {
            deactivate.mutate(
              { path: { principal_id: person.principal_id }, body: { reason } },
              {
                onSuccess: () => {
                  setAsking(false);
                },
              },
            );
          }}
          onClose={() => {
            setAsking(false);
          }}
        >
          <p>Every credential and session ends now.</p>
        </ConfirmDialog>
      </Card>
    );
  }
  return (
    <Card title="Reactivate">
      <p className="note">
        Restores this account and its existing review permissions. The user signs in again using their configured sign-in method.
      </p>
      <div className="row">
        <Button
          variant="primary"
          onClick={() => {
            reactivate.reset();
            setAsking(true);
          }}
        >
          Reactivate this user
        </Button>
      </div>
      <ConfirmDialog
        open={asking}
        title="Reactivate this user?"
        confirm="Reactivate"
        pending={reactivate.isPending}
        error={reactivate.error}
        onConfirm={() => {
          reactivate.mutate(
            { path: { principal_id: person.principal_id }, body: {} },
            {
              onSuccess: () => {
                setAsking(false);
              },
            },
          );
        }}
        onClose={() => {
          setAsking(false);
        }}
      >
        <p>Existing sessions stay closed. Check their sign-in setup after restoring access.</p>
      </ConfirmDialog>
    </Card>
  );
}
