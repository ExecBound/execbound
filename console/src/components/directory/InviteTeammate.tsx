// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";

import {
  createTeammateInvitationMutation,
  listApprovalRulesOptions,
} from "../../api/@tanstack/react-query.gen";
import type { AccessGrant, AccessPage, ApprovalRule } from "../../api/types.gen";
import { useServerMutation } from "../../lib/mutation";
import { toast } from "../../lib/toast";
import { Button } from "../ui/Button";
import { eligibleReviewers } from "./ApprovalRules";
import { ConfirmDialog } from "./ConfirmDialog";
import { refusalOf } from "./errors";
import { Field } from "./forms";
import { useUserAccess } from "./UserAccess";

type RoleId = AccessPage["roles"][number]["id"];
type Group = AccessPage["groups"][number];

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Roles a reviewer group may never carry into an invitation: they are more than review. */
const MORE_THAN_REVIEW = new Set(["administrator", "policy_manager"]);

/** A group grant in words: "Approver in Default", "Viewer everywhere". */
export function groupGrantWords(grant: AccessGrant, access: AccessPage): string {
  const role = access.roles.find((item) => item.id === grant.role)?.name ?? grant.role;
  if (grant.space_id == null) return `${role} everywhere`;
  const space = access.spaces.find((item) => item.space_id === grant.space_id)?.name ?? "an archived Space";
  return `${role} in ${space}`;
}

/** Why the server would refuse this group for an invitation carrying `grant`, or `null` when it
 * would not. The server applies the same rule at creation and again at acceptance and stays the
 * authority; this only says so before the administrator asks. A group grant is covered by an
 * invitation grant of the same role that is workspace-wide or names the same Space. */
export function groupRefusal(group: Group, grant: AccessGrant): "review" | "invitation" | null {
  if (group.roles.some((item) => MORE_THAN_REVIEW.has(item.role))) return "review";
  const covered = (item: AccessGrant) =>
    item.role === grant.role && (grant.space_id == null || grant.space_id === item.space_id);
  return group.roles.every(covered) ? null : "invitation";
}

/**
 * The People page's "Invite teammate" button and its dialog: one address, one role, one Space
 * scope, and for an Approver the reviewer group they join once they accept. Unlike
 * `UserRoleEditor`'s `GrantPicker`, an invitation carries exactly one grant (there is nobody yet
 * to hold a second one), so this is its own small form rather than a reuse of that array editor.
 */
export function InviteTeammate() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button
        variant="primary"
        onClick={() => {
          setOpen(true);
        }}
      >
        Invite teammate
      </Button>
      {open ? (
        <InviteTeammateDialog
          onClose={() => {
            setOpen(false);
          }}
        />
      ) : null}
    </>
  );
}

function InviteTeammateDialog({ onClose }: { onClose: () => void }) {
  const access = useUserAccess();
  const roles = access.data?.roles ?? [];
  const spaces = access.data?.spaces ?? [];
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<RoleId>("viewer");
  const [spaceId, setSpaceId] = useState("");
  const [groupId, setGroupId] = useState("");
  const queryClient = useQueryClient();
  const invite = useServerMutation({
    ...createTeammateInvitationMutation(),
    onSuccess: () => {
      toast("Invitation queued. They will get an email with a link that works for seven days.");
      void queryClient.invalidateQueries({ queryKey: [{ _id: "listTeammateInvitations" }] });
      onClose();
    },
  });
  const trimmed = email.trim();
  const invalid = trimmed === "" || !EMAIL_PATTERN.test(trimmed);
  const grant: AccessGrant = { role, space_id: role === "administrator" ? null : spaceId || null };
  const reviewing = role === "approver";
  const groupRefused = invite.isError && refusalOf(invite.error).fields.includes("reviewer_group_id");
  return (
    <ConfirmDialog
      open
      title="Invite a teammate"
      confirm="Invite"
      pending={invite.isPending}
      confirmDisabled={invalid}
      error={invite.error}
      onClose={onClose}
      onConfirm={() => {
        if (invalid) return;
        invite.mutate({
          body: {
            email: trimmed,
            grants: [grant],
            ...(reviewing && groupId !== "" ? { reviewer_group_id: groupId } : {}),
          },
        });
      }}
    >
      <p>They will get an email with a link. The link works for seven days.</p>
      <Field label="Email">
        <input
          type="email"
          value={email}
          required
          maxLength={254}
          autoComplete="off"
          disabled={invite.isPending}
          onChange={(event) => {
            setEmail(event.target.value);
          }}
        />
      </Field>
      <Field label="Role">
        <select
          value={role}
          disabled={invite.isPending}
          onChange={(event) => {
            const next = event.target.value as RoleId;
            setRole(next);
            setGroupId("");
            if (next === "administrator") setSpaceId("");
          }}
        >
          {roles.length > 0
            ? roles.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name}
                </option>
              ))
            : <option value="viewer">Viewer</option>}
        </select>
      </Field>
      <Field label="Space">
        <select
          value={spaceId}
          disabled={invite.isPending || role === "administrator"}
          onChange={(event) => {
            const next = event.target.value;
            setSpaceId(next);
            const chosen = access.data?.groups.find((item) => item.group_id === groupId);
            if (chosen !== undefined && groupRefusal(chosen, { role, space_id: next || null }) !== null) {
              setGroupId("");
            }
          }}
        >
          <option value="">All Spaces</option>
          {spaces.map((space) => (
            <option key={space.space_id} value={space.space_id}>
              {space.name}
            </option>
          ))}
        </select>
      </Field>
      {reviewing && access.data !== undefined ? (
        <ReviewerGroup
          access={access.data}
          grant={grant}
          groupId={groupId}
          refused={groupRefused}
          disabled={invite.isPending}
          onChange={setGroupId}
        />
      ) : null}
    </ConfirmDialog>
  );
}

const REFUSAL_WORDS = {
  review: "grants more than review",
  invitation: "grants more than this invitation",
} as const;

function ReviewerGroup({
  access,
  grant,
  groupId,
  refused,
  disabled,
  onChange,
}: {
  access: AccessPage;
  grant: AccessGrant;
  groupId: string;
  refused: boolean;
  disabled: boolean;
  onChange: (groupId: string) => void;
}) {
  if (access.groups.length === 0) {
    return (
      <p className="note">
        No reviewer groups yet. Create one under <Link to="/access">Team &amp; access</Link>, then
        invite.
      </p>
    );
  }
  const chosen = access.groups.find((item) => item.group_id === groupId);
  return (
    <>
      <Field label="Reviewer group">
        <select
          value={groupId}
          disabled={disabled}
          aria-invalid={refused ? true : undefined}
          onChange={(event) => {
            onChange(event.target.value);
          }}
        >
          <option value="">None: add them to a group later</option>
          {access.groups.map((group) => {
            const refusal = groupRefusal(group, grant);
            const grants =
              group.roles.length === 0
                ? "No roles"
                : group.roles.map((item) => groupGrantWords(item, access)).join(", ");
            return (
              <option key={group.group_id} value={group.group_id} disabled={refusal !== null}>
                {`${group.name} · ${grants}${refusal !== null ? ` (${REFUSAL_WORDS[refusal]})` : ""}`}
              </option>
            );
          })}
        </select>
      </Field>
      <p className="note">They join it once they accept, and only while it grants no more than this invitation.</p>
      {chosen !== undefined ? <GroupRules access={access} group={chosen} /> : null}
    </>
  );
}

/** What choosing this group means: the rules that route work to it, and who could decide that
 * work now. A preview from the current directory; eligibility is checked again on every review. */
function GroupRules({ access, group }: { access: AccessPage; group: Group }) {
  const rules = useQuery(listApprovalRulesOptions());
  if (rules.data === undefined) {
    return rules.isError ? (
      <p className="note">The approval rules for this group could not be loaded.</p>
    ) : (
      <p role="status">Loading the approval rules for this group.</p>
    );
  }
  const naming = rules.data.rules.filter((rule) => rule.active && rule.group_id === group.group_id);
  if (naming.length === 0) {
    return (
      <p className="note" role="status">
        No approval rule names this group yet, so they will not be able to decide anything until
        one does. <Link to="/approvers">Approval rules</Link>
      </p>
    );
  }
  const actionName = (id: string) => rules.data.actions.find((item) => item.id === id)?.name ?? id;
  const spaces = [...new Map(naming.map((rule) => [rule.space_id, rule.space_name])).entries()];
  return (
    <div role="status">
      <p>Rules for this group:</p>
      <ul>
        {naming.map((rule) => (
          <li key={rule.rule_id}>{ruleWords(rule, actionName)}</li>
        ))}
      </ul>
      {spaces.map(([spaceId, spaceName]) => {
        const eligible = eligibleReviewers(access, group.group_id, spaceId);
        return (
          <p key={spaceId} className="note">
            {`${String(eligible)} eligible ${eligible === 1 ? "reviewer" : "reviewers"} in ${spaceName} now; they join once they accept, if their Approver role covers that Space.`}
          </p>
        );
      })}
    </div>
  );
}

function ruleWords(rule: ApprovalRule, actionName: (id: string) => string): string {
  const count = rule.targets.length;
  return `${rule.name}: ${rule.actions.map(actionName).join(", ")} on ${String(count)} ${
    count === 1 ? "resource" : "resources"
  } in ${rule.space_name}.`;
}
