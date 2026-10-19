# SPDX-License-Identifier: AGPL-3.0-only
"""Every column that names a principal, and whether the scheduler principal may appear in it.

The scheduler principal (kind `SYSTEM`, #503) is an attribution and never an identity: it is
the actor of the events a scheduled pass writes in a workspace, and nothing else. Migration
`0064_scheduled_jobs` attaches `principal_guard` to every column in `GUARDED`, which refuses it
wherever a principal authenticates or gains authority. Every other column that names a
principal is in `UNGUARDED` with the reason it needs no guard.
`tests/test_scheduled_jobs_schema.py` enumerates the catalog (every foreign key to
`principals`, every column whose name says it holds one, and the columns it lists whose names
do not) and fails on a column in neither, so a new column fails closed until someone decides
which it is. Each migration that attaches the guard keeps its own copy of what it guards (a
migration never imports application code): 0064's `GUARDED`, and a later migration's
`GUARDED_ADDED`. The same test holds `GUARDED` equal to all of them together.
"""

GUARDED: frozenset[tuple[str, str]] = frozenset(
    {
        # Authentication: a credential, session, token, password, factor or sign-in link.
        ("credentials", "principal_id"),
        ("human_sessions", "principal_id"),
        ("personal_access_tokens", "principal_id"),
        ("principal_passwords", "principal_id"),
        ("password_resets", "principal_id"),
        ("principal_identities", "principal_id"),
        ("identity_links", "principal_id"),
        ("identity_invitations", "principal_id"),
        ("federated_sign_ins", "principal_id"),
        ("account_factors", "principal_id"),
        ("account_passkeys", "principal_id"),
        ("account_requests", "principal_id"),
        ("user_factors", "principal_id"),
        ("user_factors", "pending_principal_id"),
        ("user_passkeys", "principal_id"),
        # Authority: a membership, role, group, binding, review scope or decision.
        ("workspace_memberships", "principal_id"),
        ("workspace_invitations", "accepted_principal_id"),
        ("space_members", "principal_id"),
        ("access_principals", "principal_id"),
        ("access_group_members", "principal_id"),
        ("access_role_grants", "principal_id"),
        ("principal_group_members", "principal_id"),
        ("agent_bindings", "principal_id"),
        ("arcade_hooks", "principal_id"),
        ("monitor_agents", "linked_principal_id"),
        # Entra admin consent (0088): the attempt's principal is the authority that creates a
        # connection at the callback, and a consenter granted a directory-wide read.
        ("monitor_connect_attempts", "principal_id"),
        ("monitor_connections", "consented_by"),
        ("approval_scopes", "approver_id"),
        ("approval_decisions", "principal_id"),
        ("approvals", "decided_by"),
        ("principals", "replaced_by"),
    }
)

_OWN = "The scheduled pass's own attribution: one of the two columns it writes."
_AGENT = (
    "The requesting agent, taken from an authenticated identity, "
    "which the scheduler principal can never be."
)
_ACT = "Who performed an administrative act, taken from an authenticated session."
_OWNER = (
    "An owner command's --actor, checked by provisioning._actor to be an active ADMIN; "
    "it attributes and grants nothing."
)

UNGUARDED: dict[tuple[str, str], str] = {
    ("audit_events", "actor_id"): _OWN,
    ("execution_events", "actor_id"): _OWN,
    ("executions", "principal_id"): _AGENT,
    ("execution_impact", "principal_id"): _AGENT,
    ("execution_keys", "principal_id"): _AGENT,
    ("agent_runs", "principal_id"): _AGENT,
    ("approvals", "principal_id"): _AGENT,
    ("assistant_turns", "principal_id"): "The asking person, taken from a signed-in session.",
    ("account_preferences", "principal_id"): "A signed-in person's own display preferences.",
    ("authentication_failures", "subject_id"): (
        "The subject of a refused authentication, a principal when `subject_kind` is "
        "'principal': it records a refusal and grants nothing."
    ),
    ("community_allocations", "claimant_principal_id"): (
        "The workspace's first administrator, set by community_provision."
    ),
    ("account_requests", "closed_by"): _ACT,
    ("account_security_policy", "changed_by"): _ACT,
    ("agent_bindings", "bound_by"): _ACT,
    ("agent_bindings", "unbound_by"): _ACT,
    ("identity_invitations", "created_by"): _ACT,
    ("identity_links", "created_by"): _ACT,
    ("identity_providers", "created_by"): _ACT,
    ("identity_providers", "verified_by"): _ACT,
    ("monitor_connections", "collect_requested_by"): _ACT,
    # The administrator who recorded a Tines tenant's egress addresses (0098): an attribution.
    ("monitor_connections", "egress_recorded_by"): _ACT,
    ("monitor_connections", "created_by"): _ACT,
    ("monitor_findings", "acknowledged_by"): _ACT,
    ("monitor_profiles", "created_by"): _ACT,
    ("monitor_reach_exceptions", "accepted_by"): _ACT,
    # Who accepted an ungoverned path or withdrew the acceptance (0099): an attribution.
    ("monitor_reach_acceptances", "recorded_by"): _ACT,
    ("monitor_sources", "created_by"): _ACT,
    ("monitor_sources", "revoked_by"): _ACT,
    ("monitor_sources", "rotated_by"): _ACT,
    ("password_resets", "created_by"): _ACT,
    ("personal_access_tokens", "revoked_by"): _ACT,
    ("policy_bundle_contents", "created_by"): _ACT,
    ("space_policy_selection", "changed_by"): _ACT,
    ("spaces", "created_by"): _ACT,
    ("tenant_policy_control", "stopped_by"): _ACT,
    ("workspace_invitations", "inviter_id"): _ACT,
    ("workspace_invitations", "revoked_by"): _ACT,
    # Signal sources (0068) are registered, rotated and revoked only by owner commands.
    # `signal_sources.principal_ids` is deliberately in neither list: it is a `uuid[]` scope of
    # the agents a record applies to, which the catalog's query (one `uuid` column named for a
    # principal, or a foreign key to `principals`) does not see, and it attributes nothing.
    # The weekly summary (0078): a person's own opt-in, made from a signed-in session, and the
    # outbox row queued for it. Neither authenticates or grants anything, and a message goes
    # only to an active ADMIN or HUMAN_APPROVER, which the scheduler principal never is.
    ("weekly_summary_subscriptions", "principal_id"): (
        "A signed-in person's own opt-in to the weekly summary; it grants nothing."
    ),
    ("weekly_summary_messages", "principal_id"): (
        "The recipient of one queued summary, an active ADMIN or HUMAN_APPROVER; it grants nothing."
    ),
    # The advance dormancy warning (0092): the recipient of one queued warning, an active person
    # holding `access.manage`, which the scheduler principal never is. It grants nothing.
    ("dormancy_warnings", "principal_id"): (
        "The recipient of one queued dormancy warning, a live administrator; it grants nothing."
    ),
    # Approval emails (0096): a person's own opt-in, made from a signed-in session, and the
    # recipient of one queued message, an active ADMIN or HUMAN_APPROVER the approval routing
    # join names, which the scheduler principal never is. Neither grants anything.
    ("approval_email_subscriptions", "principal_id"): (
        "A signed-in person's own opt-in to approval emails; it grants nothing."
    ),
    ("approval_emails", "principal_id"): (
        "The recipient of one queued approval email, an assigned reviewer; it grants nothing."
    ),
    ("signal_sources", "created_by"): _OWNER,
    ("signal_sources", "rotated_by"): _OWNER,
    ("signal_sources", "revoked_by"): _OWNER,
}
