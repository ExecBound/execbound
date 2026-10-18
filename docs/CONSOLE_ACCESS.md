# Users, groups and approval rules

## Connect an agent

Open **Agent connections → Add agent**. Choose a supported host or connection method, give
the agent a recognizable name, and select its Space. Continue through credential creation,
the host-specific connection instructions, Permissions and verification. A host name is setup
metadata, not proof of identity. Keep the agent's API key separate from provider credentials.

The agent's **Permissions** section shows the selected policy and its conditions, resource
scope and applicable limits. Configured mappings describe the controlled path; they do not
guarantee an action will be allowed. Current context, policy, approval, limits and emergency
state still decide each request. Externally reported vendor reach is shown separately and may
include paths outside ExecBound's enforcement.

## Manage human access

Open **Users** to create accounts and configure sign-in. Use **Edit roles** on the user or
open **Groups & roles** to manage teams and inherited access.

| Role | What it permits | Scope |
| --- | --- | --- |
| Administrator | Manage users, groups, credentials, settings and policies | Workspace |
| Policy manager | Create, validate, preview and activate policies | Workspace or selected Spaces |
| Approver | Review requests covered by an approval rule or individual assignment | Workspace or selected Spaces |
| Viewer | Read activity | Workspace or selected Spaces |

A Policy manager previews a policy over the decisions recorded in the Spaces they manage, and a
workspace Administrator over the whole workspace; the replay export itself still needs a
workspace Administrator. Roles are built-in; an arbitrary custom-permission editor is
not included. Administrator does not automatically grant approval authority.
Configure an account's ordinary sign-in before promoting it to Administrator. Administrator
sign-in bindings and password recovery are protected and remain installation-owner operations.
Promotion ends previous sessions and setup credentials; the user signs in again with their
ordinary password or directory account. Outstanding setup and recovery links do not gain
Administrator authority.

Direct and inherited roles add together. Removing a direct role does not remove a role
inherited from a group. Change group roles or remove membership at the source. At least one
active workspace Administrator must remain; the backend checks this even when administrators
make changes concurrently. Changes require a reason and are audited.

Existing accounts retain their original access until an explicit user-role save. Their
current equivalent roles are shown as **Existing access**. Saving replaces that compatibility
access with the selected direct roles; group roles remain additive. Removing all managed
roles never restores the account's old authority. Current database permissions govern every
request; a role change may require the affected user to sign in again.

## Route approvals

1. Create a reviewer group, add users and assign Approver access for the appropriate Space.
2. Open **Approval rules → Create approval rule**.
3. Name the rule and choose its group, Space, actions and resources.
4. Check the eligible-reviewer count. A rule with no eligible reviewers grants nobody access.

Only selected resources are included; new resources need an explicit rule update. Policy
determines when review is required. Approval rules determine which humans may review it.
Existing per-user assignments remain under **Advanced: individual review assignments**.

To bring a new reviewer in, invite them as an **Approver** from **Users → Invite teammate** and
choose the **Reviewer group** they join. The dialog shows the rules that name the group and how
many people could decide that work now. A group that grants more than the invitation (an
Administrator or Policy manager role, or a role the invitation does not give in that Space) is
listed but cannot be chosen, and the server refuses it too. The person joins the group only when
they accept, and only if the group still grants no more than the invitation did; otherwise they
join without it and the audit record says why. An invitation that expired stays on the list with
**Invite again**, which sends a new one with the same address, role and group.

**Decision coverage**, at the top of Approval rules, shows for each Space and each action its
active policy can hold how many people can decide it, and which resources held, requested or
only just covered in the last 30 days too few people can decide: "Nobody can decide this" or
"Needs 2 people; 1 can decide". **Add to a rule** opens the rule dialog with the resource, the
action and the Space already chosen, and **Assign a person** opens the assignment dialog the
same way when you are looking at that Space; nothing changes until you save the rule with a
reason or confirm the assignment. A custom policy that may hold an action says so rather than
guessing which requests it holds. When a held request has fewer people who can decide it than
it needs, Home and Approvals say so, with a link to the request and to this card, and a request
that lapsed that way is marked on the Lapsed list. These counts are a preview of current rules,
groups, roles and assignments; who can decide is checked again when a request is reviewed and
before execution. Only an administrator of the whole workspace sees them.

Disabling a rule or removing membership takes effect for pending requests and for approved
requests that have not executed. Other applicable rules and individual assignments still
apply. Quorum counts distinct people, even if someone belongs to multiple reviewer groups.
No approval overrides a policy denial or the execution safety checks.

## Use the Live board

**Activity** is the primary history. The **Live board** under Visibility shows the live
15-minute window or a clearly labeled one-hour/24-hour historical snapshot. Historical
windows do not stream or animate as new activity. An idle view shows the last visible request
and useful next steps. Limits on displayed results are reported instead of implying complete
history. Follow a request to its Activity detail to inspect the decision and result.

## Self-hosted deployments

Roles and approval rules need the database at migration `0048_approval_rules` or later.
Those migrations refuse to downgrade while access or approval-rule records remain, so
rolling back a populated installation needs a plan for keeping that data.
