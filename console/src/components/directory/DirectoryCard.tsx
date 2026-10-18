// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";

import {
  inviteToDirectoryMutation,
  linkPersonToDirectoryMutation,
  readSignInOptions,
  revokeDirectoryInvitationMutation,
  unlinkPersonFromDirectoryMutation,
} from "../../api/@tanstack/react-query.gen";
import type { PersonDetail } from "../../api/types.gen";
import { can, useSession } from "../../lib/session";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { CodeDialog } from "./CodeDialog";
import { ConfirmDialog } from "./ConfirmDialog";
import { when } from "./format";
import { CODE_LIFETIMES, Field, LifetimeSelect, Problem, type Lifetime } from "./forms";
import { usePersonChange } from "./personChange";
import { useShowOnce } from "./showOnce";
import type { AccountProtection } from "./UserAccess";

const VIA_WORDS: Record<string, string> = {
  invitation: "redeemed an invitation",
  self: "linked their own account",
  admin: "linked by an administrator",
};

/**
 * One person's account at the tenant's own directory (#177, #241): the link, the invitation
 * that will make one, or neither.
 *
 * An invitation is a code, not an address match. The code is shown once and handed over by
 * whatever channel the tenant uses; the sign-in that follows binds the subject to this person
 * in the same function call that consumes it, so two browsers holding one code produce one
 * link. An administrator is never a target here, exactly as they are never a target for a
 * set-password code.
 */
export function DirectoryCard({ detail, protection }: { detail: PersonDetail; protection: AccountProtection }) {
  const person = detail.person;
  const administrator = person.kind === "ADMIN" || protection === "protected";
  const signIn = detail.sign_in;
  const tenant = useQuery({ ...readSignInOptions(), throwOnError: false });
  const provider = tenant.data?.provider ?? null;
  const enabled = provider !== null && provider.state === "enabled";
  // Only a workspace administrator registers a provider (0073), so only they are sent to do it.
  const configures = can(useSession(), "access.manage");
  const [lifetime, setLifetime] = useState<Lifetime>("168");
  const [subject, setSubject] = useState("");
  const [unlinking, setUnlinking] = useState(false);
  const code = useShowOnce(inviteToDirectoryMutation());
  const revoke = usePersonChange(
    person.principal_id,
    revokeDirectoryInvitationMutation(),
    "The invitation is revoked.",
  );
  const link = usePersonChange(
    person.principal_id,
    linkPersonToDirectoryMutation(),
    "The directory account is linked.",
  );
  const unlink = usePersonChange(
    person.principal_id,
    unlinkPersonFromDirectoryMutation(),
    "The directory account is unlinked.",
  );
  return (
    <Card title="Directory account">
      {tenant.data !== undefined && !enabled ? (
        <p className="muted">
          This tenant has no enabled identity provider, so nobody can be invited or linked yet.{" "}
          {configures ? (
            <Link to="/tenant">Register one in Workspace settings.</Link>
          ) : (
            "A workspace administrator registers and enables one."
          )}
        </p>
      ) : null}
      <dl className="facts">
        <dt>Account</dt>
        <dd>
          {signIn.link !== null ? (
            <>
              <Badge tone="allow">Linked</Badge> {signIn.link.provider_name}
              {signIn.link.display_username !== null ? ` · ${signIn.link.display_username}` : ""}
            </>
          ) : signIn.invitation !== null ? (
            <Badge tone="hold">Invited</Badge>
          ) : (
            <Badge tone="stale">Not linked</Badge>
          )}
        </dd>
        {signIn.link !== null ? (
          <>
            <dt>Subject</dt>
            <dd className="mono">{signIn.link.subject}</dd>
            <dt>How</dt>
            <dd>{VIA_WORDS[signIn.link.via] ?? signIn.link.via}</dd>
            <dt>Last sign-in</dt>
            <dd>
              {signIn.link.last_sign_in_at !== null ? when(signIn.link.last_sign_in_at) : "None yet"}
            </dd>
          </>
        ) : null}
        {signIn.invitation !== null ? (
          <>
            <dt>Invitation</dt>
            <dd>Pending until {when(signIn.invitation.expires_at)}</dd>
          </>
        ) : null}
      </dl>
      {administrator ? (
        <p className="note">
          The installation owner manages this account’s directory. An administrator links their own account from Workspace settings and is never linked by anybody else.
        </p>
      ) : protection === "unknown" ? <p className="note">Access roles are unavailable. Directory changes are hidden until account protection can be checked.</p> : signIn.link !== null ? (
        <>
          <div className="row">
            <Button
              variant="danger"
              disabled={unlink.isPending}
              onClick={() => {
                setUnlinking(true);
              }}
            >
              Unlink
            </Button>
          </div>
          <Problem error={unlink.error} />
        </>
      ) : signIn.invitation !== null ? (
        <>
          <div className="row">
            <Button
              disabled={revoke.isPending}
              onClick={() => {
                if (signIn.invitation !== null) {
                  revoke.mutate({
                    path: { principal_id: person.principal_id },
                    body: { invitation_id: signIn.invitation.invitation_id },
                  });
                }
              }}
            >
              Revoke the invitation
            </Button>
          </div>
          <Problem error={revoke.error} />
          <p className="note">
            Issuing another revokes this one, so exactly one code ever works. Five wrong attempts
            revoke it too.
          </p>
        </>
      ) : enabled ? (
        <>
          <form
            className="form-row"
            onSubmit={(event) => {
              event.preventDefault();
              void code.issue({
                path: { principal_id: person.principal_id },
                body: { provider_id: provider.provider_id, lifetime },
              });
            }}
          >
            <LifetimeSelect
              value={lifetime}
              onChange={setLifetime}
              label="Invitation lifetime"
              options={CODE_LIFETIMES}
            />
            <Button type="submit" disabled={code.pending}>
              Invite to {provider.name}
            </Button>
          </form>
          <Problem error={code.error} />
          <form
            className="form-row"
            onSubmit={(event) => {
              event.preventDefault();
              link.mutate({
                path: { principal_id: person.principal_id },
                body: { provider_id: provider.provider_id, subject: subject.trim() },
              });
            }}
          >
            <Field
              label="Or link an account you already know"
              hint={`The value of the ${provider.subject_claim} claim at ${provider.name}. An address is never an identifier.`}
            >
              <input
                type="text"
                className="mono"
                value={subject}
                maxLength={255}
                required
                autoComplete="off"
                spellCheck={false}
                onChange={(event) => {
                  setSubject(event.target.value);
                }}
              />
            </Field>
            <Button type="submit" disabled={link.isPending}>
              Link
            </Button>
          </form>
          <Problem error={link.error} />
        </>
      ) : null}
      <CodeDialog code={code.secret} onClose={code.close} />
      <ConfirmDialog
        open={unlinking}
        title="Unlink this directory account?"
        confirm="Unlink"
        danger
        pending={unlink.isPending}
        error={unlink.error}
        onConfirm={() => {
          unlink.mutate({ path: { principal_id: person.principal_id }, body: {} });
          setUnlinking(false);
        }}
        onClose={() => {
          setUnlinking(false);
        }}
      >
        <p>
          Every session of this person ends at once. Their scopes and credentials are untouched,
          and they can be invited or linked again.
        </p>
      </ConfirmDialog>
    </Card>
  );
}
