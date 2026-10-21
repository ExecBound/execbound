# SPDX-License-Identifier: AGPL-3.0-only
"""Transaction-scoped tenant context; runtime credentials never own migrations."""

import re
import threading
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from types import MappingProxyType
from typing import Any
from uuid import UUID

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, Connection, RowMapping

from execbound.connection import connect_args, database_url

SCHEMA_REVISION = "0102_directory_recheck_claim"
# SECURITY DEFINER functions: owned by the schema owner, executable by the runtime role unless
# dormant (below), and the only way the runtime writes principals, credentials, scopes, a
# session's expiry, a sandbox claim or a sandbox's fact observation times.
FUNCTIONS = (
    ("account_adopt", "p_principal uuid"),
    ("account_lock", "p_account uuid"),
    (
        "account_switch",
        "p_previous uuid, p_destination uuid, p_next uuid, p_credential uuid, "
        "p_token_hash text, p_csrf_hash text, p_credential_hash text, "
        "p_now timestamp with time zone",
    ),
    (
        "user_security_change",
        "p_session uuid, p_now timestamp with time zone, p_operation text, p_data jsonb",
    ),
    (
        "account_login_credential",
        "p_account uuid, p_version bigint, p_principal uuid, "
        "p_credential uuid, p_hash text, p_method text, p_now timestamp with time zone, "
        "p_expires timestamp with time zone",
    ),
    (
        "account_session_open",
        "p_credential uuid, p_session uuid, p_hash text, p_now timestamp with time zone",
    ),
    ("account_session_touch", "p_session uuid, p_now timestamp with time zone"),
    ("account_session_revoke", "p_session uuid, p_now timestamp with time zone, p_others boolean"),
    (
        "account_change",
        "p_session uuid, p_now timestamp with time zone, p_operation text, p_data jsonb",
    ),
    ("product_count", "p_event text, p_page text"),
    (
        "account_security_change",
        "p_session uuid, p_now timestamp with time zone, p_operation text, p_data jsonb",
    ),
    ("approval_rule_change", "p_actor uuid, p_rule uuid, p_body jsonb"),
    ("access_has_permission", "p_principal uuid, p_permission text, p_space uuid, p_any boolean"),
    ("access_effective_kind", "p_principal uuid"),
    ("access_change", "p_actor uuid, p_operation text, p_subject uuid, p_body jsonb"),
    ("admin_create_principal", "p_actor uuid, p_kind text, p_space uuid"),
    (
        "admin_issue_credential",
        "p_actor uuid, p_principal uuid, p_credential uuid, p_token_hash text, "
        "p_issued_at timestamp with time zone, p_expires_at timestamp with time zone",
    ),
    (
        "admin_revoke_credential",
        "p_actor uuid, p_credential uuid, p_revoked_at timestamp with time zone",
    ),
    (
        "admin_delete_credential",
        "p_actor uuid, p_credential uuid, p_deleted_at timestamp with time zone",
    ),
    (
        "admin_assign_approver",
        "p_actor uuid, p_approver uuid, p_target uuid, p_action text, p_space uuid",
    ),
    ("admin_unassign_approver", "p_actor uuid, p_approver uuid, p_target uuid, p_action text"),
    ("admin_label_principal", "p_actor uuid, p_principal uuid, p_label text"),
    ("admin_deactivate_principal", "p_actor uuid, p_principal uuid, p_reason text"),
    ("admin_reactivate_principal", "p_actor uuid, p_principal uuid"),
    ("admin_bind_agent", "p_actor uuid, p_agent uuid, p_principal uuid"),
    ("admin_unbind_agent", "p_actor uuid, p_binding uuid, p_reason text"),
    (
        "renew_human_session",
        "p_session uuid, p_token_hash text, p_now timestamp with time zone, "
        "p_lifetime interval, p_absolute interval",
    ),
    (
        "onboarding_claim",
        "p_invitation uuid, p_token_hash text, p_name text, p_admin uuid, p_credential uuid, "
        "p_credential_hash text, p_issued_at timestamp with time zone, "
        "p_expires_at timestamp with time zone",
    ),
    ("sandbox_reattest", "p_actor uuid"),
    (
        "assistant_turn_create",
        "p_actor uuid, p_turn uuid, p_context_kind text, p_context_id uuid, p_question text, "
        "p_model text, p_now timestamp with time zone",
    ),
    ("assistant_turn_step", "p_actor uuid, p_turn uuid, p_step text"),
    (
        "assistant_turn_complete",
        "p_actor uuid, p_turn uuid, p_state text, p_reason text, p_answer jsonb, "
        "p_cited jsonb, p_tools jsonb, p_input integer, p_cached integer, p_output integer, "
        "p_now timestamp with time zone",
    ),
    ("assistant_turn_retire", "p_actor uuid, p_now timestamp with time zone"),
    ("onboarding_invite", "p_note text, p_token_hash text, p_expires_at timestamp with time zone"),
    ("onboarding_invitation_rekey", "p_invitation uuid, p_token_hash text"),
    ("onboarding_invitation_revoke", "p_invitation uuid"),
    ("sandbox_expire", "p_reason text, p_now timestamp with time zone"),
    ("sandbox_notice", "p_now timestamp with time zone"),
    ("sandbox_fallback", "p_now timestamp with time zone"),
    ("agents_sleep", "p_now timestamp with time zone"),
    (
        "signup_request",
        "p_request uuid, p_email text, p_domain text, p_free_mail boolean, p_consent text, "
        "p_now timestamp with time zone, p_refusal text, p_per_hour integer, p_per_day integer, "
        "p_per_domain integer, p_free_mail_daily integer, p_cooldown_days integer",
    ),
    (
        "signup_allocate",
        "p_request uuid, p_slot_tenant uuid, p_invitation uuid, p_message uuid, p_class text, "
        "p_now timestamp with time zone",
    ),
    (
        "signup_mark",
        "p_request uuid, p_state text, p_at timestamp with time zone, "
        "p_purge_after timestamp with time zone",
    ),
    ("signup_verify_queue", "p_request uuid, p_message uuid, p_now timestamp with time zone"),
    (
        "signup_verify_rekey",
        "p_request uuid, p_token_hash text, p_now timestamp with time zone",
    ),
    (
        "signup_verify_check",
        "p_request uuid, p_token_hash text, p_now timestamp with time zone",
    ),
    (
        "community_provision",
        "p_request uuid, p_token_hash text, p_tenant uuid, p_principal uuid, p_account uuid, "
        "p_name text, p_slug text, p_password jsonb, p_capacity integer, "
        "p_now timestamp with time zone",
    ),
    # Provider signup (0069, #504): a provider's verified address admits or attaches to the
    # same Community signup request an emailed link completes, and creates the account and
    # its binding with no password, handing the workspace to `community_provision` itself.
    (
        "signup_provider_attach",
        "p_request uuid, p_provider text, p_subject text, p_token_hash text, p_admit boolean, "
        "p_capacity integer, p_now timestamp with time zone",
    ),
    (
        "community_provision_provider",
        "p_request uuid, p_token_hash text, p_tenant uuid, p_principal uuid, p_account uuid, "
        "p_name text, p_slug text, p_capacity integer, p_now timestamp with time zone",
    ),
    # Password reset by email (0085, #678): a hosted account holder's emailed link, held
    # dormant for the hosted plugin like the signup functions above.
    (
        "account_recovery_request",
        "p_recovery uuid, p_message uuid, p_email text, p_refusal text, p_ceiling integer, "
        "p_per_hour integer, p_per_account_hour integer, p_per_account_day integer, "
        "p_now timestamp with time zone",
    ),
    (
        "account_recovery_rekey",
        "p_recovery uuid, p_token_hash text, p_now timestamp with time zone",
    ),
    (
        "account_recovery_check",
        "p_recovery uuid, p_token_hash text, p_now timestamp with time zone",
    ),
    (
        "account_password_recover",
        "p_recovery uuid, p_token_hash text, p_account uuid, p_factor jsonb, "
        "p_password jsonb, p_notice uuid, p_now timestamp with time zone",
    ),
    ("account_recovery_lapse", "p_now timestamp with time zone"),
    # The advance dormancy warning (0092, #439): the one writer of a warning, fenced to the
    # caller's tenant, and a list of identifiers and a count across tenants, held dormant for
    # the hosted plugin like the functions above.
    ("dormancy_warn", "p_now timestamp with time zone"),
    ("dormancy_warnings_due", "p_now timestamp with time zone, p_limit integer"),
    (
        "dormancy_warnings_sent",
        "p_since timestamp with time zone, p_now timestamp with time zone",
    ),
    # Approval emails (0096, #179): the one writer of a person's setting and the one writer
    # of a message, each fenced to the caller's tenant, two lists of identifiers and a count
    # across tenants, and the fenced one-click stop, dormant for the hosted plugin.
    (
        "approval_email_change",
        "p_session uuid, p_on boolean, p_now timestamp with time zone",
    ),
    ("approval_email_queue", "p_now timestamp with time zone"),
    ("approval_email_tenants", "p_now timestamp with time zone"),
    ("approval_email_due", "p_now timestamp with time zone, p_limit integer"),
    (
        "approval_email_sent",
        "p_since timestamp with time zone, p_now timestamp with time zone",
    ),
    (
        "approval_email_unsubscribe",
        "p_email uuid, p_hash text, p_now timestamp with time zone",
    ),
    # Sample targets (#420): the only writers of `connector_accounts.sample`.
    (
        "samples_install",
        "p_actor uuid, p_account uuid, p_space uuid, p_targets jsonb, "
        "p_now timestamp with time zone",
    ),
    (
        "samples_remove",
        "p_actor uuid, p_account uuid, p_bundle uuid, p_now timestamp with time zone",
    ),
    (
        "workspace_invitation_create",
        "p_actor uuid, p_invitation uuid, p_email text, p_grants jsonb, p_message uuid, "
        "p_now timestamp with time zone",
    ),
    (
        "workspace_invitation_revoke",
        "p_actor uuid, p_invitation uuid, p_now timestamp with time zone",
    ),
    (
        "workspace_invitation_resend",
        "p_actor uuid, p_invitation uuid, p_now timestamp with time zone",
    ),
    ("workspace_invitation_due", "p_now timestamp with time zone, p_limit integer"),
    (
        "workspace_invitation_rekey",
        "p_invitation uuid, p_token_hash text, p_now timestamp with time zone",
    ),
    (
        "workspace_invitation_check",
        "p_invitation uuid, p_token_hash text, p_now timestamp with time zone",
    ),
    (
        "workspace_invitation_accept",
        "p_invitation uuid, p_token_hash text, p_principal uuid, p_account uuid, "
        "p_password jsonb, p_now timestamp with time zone",
    ),
    # The reviewer group an invitation names (0083), set once in the creating transaction and
    # applied only by the acceptance.
    (
        "workspace_invitation_set_group",
        "p_actor uuid, p_invitation uuid, p_group uuid, p_now timestamp with time zone",
    ),
    # The weekly summary (#678): two lists of identifiers and a count across tenants, and two
    # writers fenced to the caller's own tenant.
    ("weekly_summary_tenants", "p_now timestamp with time zone"),
    ("weekly_summary_enqueue", "p_week date, p_now timestamp with time zone"),
    ("weekly_summary_due", "p_now timestamp with time zone, p_limit integer"),
    ("weekly_summary_sent", "p_since timestamp with time zone"),
    (
        "weekly_summary_unsubscribe",
        "p_message uuid, p_hash text, p_now timestamp with time zone",
    ),
    (
        "sign_in_credential",
        "p_principal uuid, p_credential uuid, p_token_hash text, p_method text, "
        "p_issued_at timestamp with time zone, p_expires_at timestamp with time zone",
    ),
    (
        "identity_sign_in",
        "p_principal uuid, p_provider text, p_subject text, p_email text, "
        "p_display_name text, p_now timestamp with time zone",
    ),
    ("admin_set_email", "p_actor uuid, p_principal uuid, p_email text"),
    (
        "admin_reset_password",
        "p_actor uuid, p_principal uuid, p_reset uuid, p_token_hash text, "
        "p_expires_at timestamp with time zone",
    ),
    ("password_reset_check", "p_reset uuid, p_token_hash text"),
    (
        "password_redeem",
        "p_reset uuid, p_token_hash text, p_algorithm text, p_n integer, p_r integer, "
        "p_p integer, p_dklen integer, p_salt text, p_hash text, "
        "p_now timestamp with time zone",
    ),
    (
        "password_replace",
        "p_principal uuid, p_algorithm text, p_n integer, p_r integer, p_p integer, "
        "p_dklen integer, p_salt text, p_hash text, p_now timestamp with time zone",
    ),
    ("space_create", "p_name text, p_detail text, p_actor uuid"),
    ("space_rename", "p_space uuid, p_name text, p_detail text, p_actor uuid"),
    ("space_archive", "p_space uuid, p_actor uuid"),
    ("space_unarchive", "p_space uuid, p_actor uuid"),
    ("space_assign", "p_space uuid, p_principal uuid, p_role text, p_actor uuid"),
    ("space_unassign", "p_space uuid, p_principal uuid, p_actor uuid"),
    ("session_set_space", "p_session uuid, p_space uuid"),
    # The customer's own identity provider (#177, #241). None of these gives the runtime a
    # table write: a provider, a link, an invitation and a directory sign-in are written only
    # inside the database, by the definer functions of migration 0042.
    (
        "directory_register",
        "p_actor uuid, p_provider uuid, p_name text, p_issuer text, p_client_id text, "
        "p_secret_ciphertext text, p_secret_key_id text, p_subject_claim text, "
        "p_issuer_tenant text, p_authorization_endpoint text, p_token_endpoint text, "
        "p_jwks_uri text, p_now timestamp with time zone",
    ),
    (
        "directory_set_state",
        "p_actor uuid, p_provider uuid, p_state text, p_now timestamp with time zone",
    ),
    (
        "directory_link_self",
        "p_actor uuid, p_provider uuid, p_subject text, p_display_name text, "
        "p_display_username text, p_now timestamp with time zone",
    ),
    (
        "directory_link",
        "p_actor uuid, p_principal uuid, p_provider uuid, p_subject text, "
        "p_now timestamp with time zone",
    ),
    ("directory_unlink", "p_actor uuid, p_principal uuid, p_now timestamp with time zone"),
    (
        "directory_invite",
        "p_actor uuid, p_principal uuid, p_provider uuid, p_invitation uuid, p_token_hash text, "
        "p_expires_at timestamp with time zone",
    ),
    (
        "directory_invitation_revoke",
        "p_actor uuid, p_invitation uuid, p_now timestamp with time zone",
    ),
    ("directory_invitation_check", "p_invitation uuid, p_token_hash text"),
    (
        "directory_sign_in",
        "p_provider uuid, p_subject text, p_invitation uuid, p_credential uuid, "
        "p_token_hash text, p_refresh_ciphertext text, p_refresh_key_id text, "
        "p_display_name text, p_display_username text, p_issued_at timestamp with time zone, "
        "p_expires_at timestamp with time zone",
    ),
    (
        "directory_recheck",
        "p_credential uuid, p_refresh_ciphertext text, p_refresh_key_id text, "
        "p_now timestamp with time zone, p_claimed timestamp with time zone",
    ),
    ("directory_revoke", "p_credential uuid, p_reason text, p_now timestamp with time zone"),
    # Claiming a directory recheck (0100, 0102): one of several simultaneous requests calls the
    # directory, by setting `recheck_claimed_at` only while `verified_at` reads the value it saw
    # and no other claim stands. The claim never moves `verified_at`; only the directory's yes
    # does (`directory_recheck`).
    (
        "directory_recheck_claim",
        "p_credential uuid, p_seen timestamp with time zone, p_now timestamp with time zone",
    ),
    ("directory_recheck_release", "p_credential uuid, p_claimed timestamp with time zone"),
    # Trusted browsers (0101): an account's trusts are written only through these. The runtime
    # reads its own account's rows of `trusted_browsers` and writes none.
    (
        "trusted_browser_add",
        "p_tenant uuid, p_session uuid, p_browser uuid, p_hash text, p_label text, "
        "p_method text, p_verified_at timestamp with time zone, "
        "p_now timestamp with time zone",
    ),
    (
        "trusted_browser_use",
        "p_tenant uuid, p_session uuid, p_browser uuid, p_hash text, p_token_hash text, "
        "p_csrf_hash text, p_now timestamp with time zone",
    ),
    (
        "trusted_browser_remove",
        "p_account uuid, p_browser uuid, p_now timestamp with time zone",
    ),
    ("trusted_browser_remove_all", "p_account uuid, p_now timestamp with time zone"),
    (
        "trusted_browser_policy",
        "p_tenant uuid, p_principal uuid, p_allow boolean, p_now timestamp with time zone",
    ),
    # "Sign out other devices" for a session with no account sign-in (0101): it moves the
    # linked account's version, as the account path does, which ends every trust.
    (
        "account_sign_out_others",
        "p_tenant uuid, p_session uuid, p_now timestamp with time zone",
    ),
    # Personal access tokens (0063): an administrator's own bearer token for the console
    # API, minted with a discarded secret alongside its backing credential in `credentials`.
    (
        "admin_issue_personal_token",
        "p_actor uuid, p_token uuid, p_credential uuid, p_name text, p_token_hash text, "
        "p_credential_hash text, p_issued_at timestamp with time zone, "
        "p_expires_at timestamp with time zone",
    ),
    (
        "admin_revoke_personal_token",
        "p_actor uuid, p_token uuid, p_revoked_at timestamp with time zone",
    ),
    (
        "admin_delete_personal_token",
        "p_actor uuid, p_token uuid, p_deleted_at timestamp with time zone",
    ),
    ("personal_token_used", "p_token uuid, p_used_at timestamp with time zone"),
    # Agent keys (0079): the throttled last-use stamp authentication makes, the recorded
    # rotation an issue with `replaces` makes, and one boolean per person telling an
    # administrator who has a second factor, read as step-up enforcement reads it.
    ("credential_used", "p_credential uuid, p_used_at timestamp with time zone"),
    ("admin_credential_replaces", "p_actor uuid, p_credential uuid, p_replaces uuid"),
    ("admin_member_factors", "p_actor uuid, p_principals uuid[]"),
    ("job_tenants_page", "p_after uuid, p_limit integer"),
    ("scheduler_actor", ""),
    ("assistant_turn_retire_due", ""),
    # Security signals (0068): the one writer of `security_signals` and of a source's health
    # columns. It authenticates the producer's token inside the fence and returns a refusal
    # rather than raising, so the counters commit with it.
    (
        "signal_admit",
        "p_source uuid, p_token_hash text, p_now timestamp with time zone, p_event_id text, "
        "p_record_digest text, p_producer_name text, p_producer_version text, "
        "p_capability text, p_verdict text, p_confidence integer, p_severity text, "
        "p_subject_kind text, p_subject_account uuid, p_subject_provider text, "
        "p_subject_resource_type text, p_subject_provider_id text, p_action text, "
        "p_request_reference text, p_observed_at timestamp with time zone, "
        "p_expires_at timestamp with time zone, p_attributes jsonb, p_evidence_ref text, "
        "p_evidence_digest text",
    ),
    # Scheduled monitoring collection (0086): the only writers of a connection's request,
    # schedule and lease. A claim takes a duration of at most fifteen minutes from the
    # database's own clock and no time from its caller.
    ("admin_request_collection", "p_actor uuid, p_connection uuid"),
    (
        "admin_set_collection_schedule",
        "p_actor uuid, p_connection uuid, p_collect integer, p_activity integer",
    ),
    ("collector_claim", "p_connection uuid, p_lease uuid, p_seconds integer"),
    ("collector_release", "p_connection uuid, p_lease uuid"),
    # A delta pass's claim (0093): the same lease, marked as a delta pass's, taken only while
    # no collection request waits, and never answering one.
    ("collector_claim_delta", "p_connection uuid, p_lease uuid, p_seconds integer"),
    # Sealed collection keys (0087): the only writers of a connection's ciphertext and the
    # collector key it is sealed to. The gateway seals; only the collector's key opens.
    (
        "admin_create_sealed_connection",
        "p_actor uuid, p_space uuid, p_connection uuid, p_label text, p_base_url text, "
        "p_team text, p_fingerprint text, p_sealed_ct bytea, p_key_id text",
    ),
    (
        "admin_replace_sealed_key",
        "p_actor uuid, p_connection uuid, p_fingerprint text, p_sealed_ct bytea, p_key_id text",
    ),
    (
        "collector_reseal",
        "p_connection uuid, p_old_key_id text, p_old_ct bytea, p_sealed_ct bytea, p_key_id text",
    ),
    # Entra admin consent (0088): the only writers of a connect attempt, and of a connection a
    # directory administrator consented to. A sign-in and a consent are decided against the
    # attempt the callback's state names; a refusal decided outside the database ends it.
    (
        "admin_start_connect",
        "p_actor uuid, p_space uuid, p_attempt uuid, p_connection uuid, p_label text, "
        "p_state_hash text, p_binding_hash text, p_nonce_hash text",
    ),
    (
        "admin_record_signin",
        "p_attempt uuid, p_state_hash text, p_binding_hash text, p_nonce_hash text, "
        "p_directory text",
    ),
    (
        "admin_complete_consent",
        "p_attempt uuid, p_state_hash text, p_binding_hash text, p_directory text, "
        "p_client_ref text",
    ),
    ("admin_refuse_connect", "p_attempt uuid, p_state_hash text, p_step text, p_code text"),
    # The retention of a directory's audit observations (0095): the one way the runtime removes
    # an observation, fenced to the caller's tenant and an Entra connection of it, and only one
    # evaluated, uncited and a month old by the database's own clock.
    ("monitor_audit_purge", "p_connection uuid, p_observations uuid[]"),
    # A Tines tenant's egress addresses (0098): the one writer of what an administrator of the
    # connection's Space recorded, at most eight single public addresses.
    ("admin_set_egress_addresses", "p_actor uuid, p_connection uuid, p_addresses inet[]"),
    # The synthetic directory (0099): the one writer of a connection of kind `fixture`, which
    # holds no credential, one per workspace and never beside a Microsoft Entra connection.
    ("admin_add_synthetic_directory", "p_actor uuid, p_space uuid, p_connection uuid"),
    # Accepting an ungoverned path and withdrawing the acceptance (0099): the only writers of
    # `monitor_reach_exceptions` and of its append-only history.
    (
        "admin_accept_reach",
        "p_actor uuid, p_agent uuid, p_action text, p_kind text, p_path text, p_reason text, "
        "p_expires timestamp with time zone",
    ),
    (
        "admin_withdraw_reach",
        "p_actor uuid, p_agent uuid, p_action text, p_kind text, p_path text",
    ),
)
# Trigger functions that run as their owner. A trigger function is fired, never called, so
# each is held to this list by name rather than to an EXECUTE grant: 0088's keeps the
# deployment-wide directory claims, on which the runtime that fires it holds nothing.
TRIGGER_DEFINERS = frozenset({"monitor_directory_claim_sync"})
TABLES = (
    "workspace_invitations",
    "workspace_invitation_messages",
    "user_accounts",
    "user_passwords",
    "workspace_memberships",
    "user_identities",
    "user_factors",
    "user_passkeys",
    "trusted_browsers",
    "community_allocations",
    "account_login_proofs",
    "account_sessions",
    "account_provider_links",
    "user_security_events",
    "account_passkeys",
    "passkey_challenges",
    "account_preferences",
    "account_requests",
    "product_counts",
    "account_factors",
    "session_assurance",
    "account_security_policy",
    "approval_rules",
    "approval_rule_actions",
    "approval_rule_targets",
    "access_principals",
    "access_groups",
    "access_group_members",
    "access_role_grants",
    "tenants",
    "principals",
    "credentials",
    "audit_heads",
    "audit_events",
    "connector_accounts",
    "context_sources",
    "operation_mappings",
    "resources",
    "resource_aliases",
    "incidents",
    "resource_facts",
    "agent_runs",
    "policy_bundle_contents",
    "policy_bundle_lifecycle",
    "tenant_policy_control",
    "canonical_targets",
    "resource_identities",
    "approval_scopes",
    "executions",
    "execution_keys",
    "execution_events",
    "approvals",
    "execution_impact",
    "resource_claims",
    "human_sessions",
    "monitor_sources",
    "monitor_observations",
    "monitor_findings",
    "monitor_deliveries",
    "authentication_failures",
    "monitor_profiles",
    "approval_notifications",
    "export_cursors",
    "approval_decisions",
    "principal_groups",
    "principal_group_members",
    "monitor_connections",
    "monitor_inventory",
    "executor_keys",
    "onboarding_slots",
    "onboarding_invitations",
    "monitor_agents",
    "monitor_agent_grants",
    "monitor_agent_reach",
    "monitor_reach_exceptions",
    # Who drives a directory actor, and how that is known (0098).
    "monitor_actor_drivers",
    # Every acceptance of an ungoverned path and its withdrawal, append-only (0099). SELECT only;
    # `admin_accept_reach` and `admin_withdraw_reach` are its writers.
    "monitor_reach_acceptances",
    "arcade_hooks",
    "agent_bindings",
    "assistant_turns",
    "signup_requests",
    "signup_messages",
    "account_recoveries",
    "account_messages",
    "dormancy_warnings",
    "principal_passwords",
    "password_resets",
    "principal_identities",
    "spaces",
    "space_members",
    "space_policy_selection",
    "identity_providers",
    "identity_links",
    "identity_invitations",
    "federated_sign_ins",
    "personal_access_tokens",
    "job_tenants",
    # Security signals (#478): authority data and the records producers attest. SELECT only;
    # `signal_admit` is the one writer.
    "signal_sources",
    "security_signals",
    # The weekly summary (#678): a person's opt-in, and its outbox.
    "weekly_summary_subscriptions",
    "weekly_summary_messages",
    # Approval emails (0096, #179): a person's opt-in in a Community workspace, and its
    # outbox; dormant, for the hosted plugin.
    "approval_email_subscriptions",
    "approval_emails",
    # Entra admin consent (0088): every attempt to connect a directory, which the runtime only
    # reads, and the deployment-wide directory claims, on which it holds nothing.
    "monitor_connect_attempts",
    "monitor_directory_claims",
)

# Tables the runtime holds no privilege on at all, of any kind or on any column. The directory
# claims name no tenant and so carry no tenant fence: only definer functions and their trigger,
# running as the owner, read or write them (0088).
PRIVILEGELESS_TABLES = frozenset({"monitor_directory_claims"})

UPDATE_COLUMNS = {
    "policy_bundle_lifecycle": {"state", "changed_at"},
    # The active bundle moved to `space_policy_selection` in migration 0041, so the
    # control row no longer carries it and the runtime no longer writes it here.
    "tenant_policy_control": {
        "changed_at",
        "stop_id",
        "stopped_at",
        "stopped_by",
        "stop_reason",
        "enforcement_mode",
        "approval_deadline_seconds",
        "assistant_enabled",
    },
    # report_expires_at is written once at admission and is deliberately not updatable.
    "executions": {
        "state",
        "changed_at",
        "owner_hash",
        "dispatch_attempted_at",
        "result",
        "settlement_tier",
        "precondition_class",
        "precondition_window_ms",
    },
    "approvals": {"state", "decided_by", "decided_credential_id", "decided_at"},
    "execution_impact": {"state", "confirmed_at"},
    "resource_claims": {"released_at"},
    "human_sessions": {"revoked_at"},
    "monitor_sources": {
        "active",
        "revoked_at",
        "revoked_by",
        "current_token_hash",
        "expires_at",
        "previous_token_hash",
        "previous_valid_until",
        "rotated_at",
        "rotated_by",
        "health_state",
        "health_changed_at",
        "health_checked_at",
        "last_event_at",
        "last_heartbeat_at",
        "last_refusal_code",
        "last_refusal_at",
        "rate_window_at",
        "rate_count",
        "accepted_count",
    },
    "monitor_observations": {
        "evaluation_state",
        "evaluation_result",
        "evaluated_at",
        "integrity_conflict_at",
    },
    "monitor_findings": {"acknowledged_at", "acknowledged_by", "acknowledgement_note"},
    "monitor_connections": {
        "active",
        "revoked_at",
        "capabilities",
        "capabilities_at",
        "health_state",
        "health_changed_at",
        "audit_cursor",
        "platform_tenant_ref",
        "last_run_at",
        "last_run_id",
        "last_outcome",
        "last_error_code",
        "last_sync_at",
        "retry_after_seconds",
        "consecutive_rate_limited",
        "consecutive_backlog",
        # A delta pass's link and the moment it advanced, and the connection's baseline (0093);
        # the runtime inserts none of the three, so `INSERT_COLUMNS` does not name them.
        "delta_link",
        "delta_at",
        "baseline_at",
        # When the connection's first directory audit read that caught up stored what it found,
        # and since when its reads have not caught up (0094); the runtime inserts neither.
        "audit_baseline_at",
        "audit_behind_since",
        # Since when its audit reads have met the connection's observation bound (0095); the
        # runtime does not insert it.
        "audit_bound_since",
        # Where the next read of the directory's service principal sign-ins starts (0098); the
        # runtime does not insert it, and writes none of a Tines tenant's egress addresses.
        "sign_in_cursor",
    },
    "monitor_inventory": {
        "name",
        "name_truncated",
        "item_type",
        "disabled",
        "outbound",
        "last_seen_at",
        "gone_at",
        "source_updated_at",
        "gap_opened_at",
        "coverage_class",
        # A credential's host scope and the stories that reference it (0098).
        "host_scope",
        "story_refs",
        "references_capped",
    },
    "monitor_agents": {
        "display_name",
        "display_name_truncated",
        "enabled",
        "blueprint_ref",
        "blueprint_object_ref",
        "credential_kinds",
        "sponsors",
        "sponsor_state",
        "sponsor_group_count",
        "owner_count",
        "tags",
        "observed_at",
        "gone_at",
        "reach_gap_opened_at",
        "sponsor_gap_opened_at",
        "owner_org_ref",
        # The AI publisher catalog's key and the three new-actor episode markers (0093).
        "ai_publisher",
        "new_actor_opened_at",
        "first_action_opened_at",
        "ai_consent_opened_at",
        # The leading product token of the newest sign-in's user agent, a hint (0098).
        "user_agent_hint",
        "user_agent_seen_at",
        # The class within the classic family, which moves with a principal's type and its
        # consents, and its application id (0099).
        "identity_class",
        "app_ref",
    },
    "monitor_agent_grants": {"path_ref", "observed_at", "gone_at"},
    "monitor_agent_reach": {
        "certainty",
        "enforcement_mode",
        "catalog_version",
        "computed_at",
        "valid_until",
        "gone_at",
    },
    "monitor_actor_drivers": {
        "first_seen_at",
        "last_seen_at",
        "gone_at",
        "detail_refs",
        "detail_capped",
        "catalog_version",
    },
    "monitor_deliveries": {
        "state",
        "attempts",
        "next_attempt_at",
        "lease_until",
        "lease_token",
        "delivered_at",
        "last_error",
    },
    "authentication_failures": {"count", "last_at"},
    # The invitation outbox is moved by the runtime for itself, and only its lease and its
    # outcome: the runtime leases and settles a message, and never writes which invitation,
    # tenant or time a message belongs to.
    "workspace_invitation_messages": {
        "state",
        "attempts",
        "next_attempt_at",
        "lease_until",
        "lease_token",
        "delivered_at",
        "last_error",
    },
    "monitor_profiles": {"retired_at"},
    # A person's own opt-in, turned on, off and on again; the row is never deleted.
    "weekly_summary_subscriptions": {"subscribed_at", "ended_at", "ended_via"},
    # The summary outbox, as the invitation outbox: its lease, its outcome and the hash of the
    # unsubscribe secret minted for each attempt, never whose message or which week it is.
    "weekly_summary_messages": {
        "state",
        "attempts",
        "next_attempt_at",
        "lease_until",
        "lease_token",
        "delivered_at",
        "last_error",
        "unsubscribe_hash",
    },
    # `kind`, `outcome` and `closed_at` (0080) are insert-only on purpose: a message's kind and
    # a close-out's report are fixed when the row is queued, so a retry says the same thing.
    "approval_notifications": {
        "state",
        "attempts",
        "next_attempt_at",
        "lease_until",
        "lease_token",
        "delivered_at",
        "last_error",
    },
    "export_cursors": {
        "last_sequence",
        "last_event_hash",
        "last_failure_window",
        "attempts",
        "next_attempt_at",
        "lease_until",
        "lease_token",
        "state",
        "last_error",
    },
    # The correlation row is inserted before the kernel call with what the hook body
    # already carries and completed afterwards, so what the runtime may move is the
    # kernel's answer, what the platform reported, the two contradiction marks and the
    # report secret the settlement and the opportunistic clearing null. The tenant, the
    # principal, the Arcade execution id, the derived key, the tool identity, the reported
    # metadata and user id and the creation time are written once.
    # A space selects one bundle. The runtime writes this under the same fence and the
    # same audited ADMIN check activation has today; who owns the space is not writable.
    "space_policy_selection": {"bundle_id", "changed_at", "changed_by"},
    "arcade_hooks": {
        "decision",
        "execution_id",
        "operation_id",
        "report_secret",
        "reported_success",
        "reported_code",
        "reported_error",
        "denial_contradiction_at",
        "inputs_contradiction_at",
        "settled_at",
    },
}

# Tables the runtime may insert into only by naming some columns: exactly these, and every one
# of them. Since 0086 a monitoring connection's mode, schedule, request and lease are written by
# definer functions alone, so the runtime inserts only the columns that existed before them.
INSERT_COLUMNS = {
    "monitor_connections": {
        "tenant_id",
        "connection_id",
        "label",
        "base_url",
        "team_id",
        "key_fingerprint",
        "created_at",
        "created_by",
        "active",
        "revoked_at",
        "capabilities",
        "capabilities_at",
        "health_state",
        "health_changed_at",
        "audit_cursor",
        "platform_tenant_ref",
        "last_run_at",
        "last_run_id",
        "last_outcome",
        "last_error_code",
        "last_sync_at",
        "retry_after_seconds",
        "consecutive_rate_limited",
        "consecutive_backlog",
        "kind",
        "directory_ref",
        "client_ref",
        "space_id",
    },
}

# Columns the runtime must never read. A producer token's digest is the credential at the
# database layer, since `signal_admit` takes a digest, so 0068 grants the runtime SELECT on
# every other `signal_sources` column and on neither of these (0042's precedent).
UNREADABLE_COLUMNS = frozenset({"signal_sources.token_hash", "signal_sources.previous_token_hash"})

# The objects only a plugin uses (#496). Every one exists in every database, because
# every migration ships in the one shared chain, and no migration grants anyone but the owner
# anything on them: `0065_dormant_grants` took away what earlier revisions granted, and a later
# such object is created without a grant. `check_runtime` requires each to hold exactly the
# privileges a loaded plugin claims (`plugins.Registry.claim`), and nothing where none does,
# so a runtime with no plugin can neither read these tables nor call these functions. They
# stay in `TABLES` and `FUNCTIONS`, which list every object the schema must hold; these say
# which of them are asleep.
DORMANT_TABLES: tuple[str, ...] = (
    "community_allocations",
    "product_counts",
    "onboarding_slots",
    "onboarding_invitations",
    "signup_requests",
    "signup_messages",
    "account_preferences",
    "account_recoveries",
    "account_messages",
    "dormancy_warnings",
    "approval_email_subscriptions",
    "approval_emails",
)
_DORMANT_FUNCTION_NAMES = frozenset(
    {
        "product_count",
        "onboarding_claim",
        "sandbox_reattest",
        "onboarding_invite",
        "onboarding_invitation_rekey",
        "onboarding_invitation_revoke",
        "sandbox_expire",
        "sandbox_notice",
        "sandbox_fallback",
        "agents_sleep",
        "signup_request",
        "signup_allocate",
        "signup_mark",
        "signup_verify_queue",
        "signup_verify_rekey",
        "signup_verify_check",
        "community_provision",
        "signup_provider_attach",
        "community_provision_provider",
        "account_recovery_request",
        "account_recovery_rekey",
        "account_recovery_check",
        "account_password_recover",
        "account_recovery_lapse",
        "dormancy_warn",
        "dormancy_warnings_due",
        "dormancy_warnings_sent",
        "approval_email_change",
        "approval_email_queue",
        "approval_email_tenants",
        "approval_email_due",
        "approval_email_sent",
        "approval_email_unsubscribe",
    }
)
DORMANT_FUNCTIONS: tuple[tuple[str, str], ...] = tuple(
    entry for entry in FUNCTIONS if entry[0] in _DORMANT_FUNCTION_NAMES
)
DORMANT: frozenset[str] = frozenset(DORMANT_TABLES) | _DORMANT_FUNCTION_NAMES
# Each dormant function with its catalogued signature: another function of the same name is
# not the dormant object.
_DORMANT_SIGNATURES: frozenset[tuple[str, str]] = frozenset(DORMANT_FUNCTIONS)

# What a loaded plugin says the runtime holds on each dormant object it uses.
Claims = Mapping[str, frozenset[str]]
EMPTY_CLAIMS: Claims = MappingProxyType({})
# A table takes SELECT, INSERT or UPDATE, whole or on one column each; a function takes
# EXECUTE. The runtime never deletes or truncates, on a plugin's tables as on core's.
_TABLE_PRIVILEGE = re.compile(
    r"(?P<privilege>SELECT|INSERT|UPDATE)(?:\((?P<column>[a-z_][a-z0-9_]{0,62})\))?"
)
# The claims of every plugin this process loaded; see `honour_claims`.
_honoured: Claims = EMPTY_CLAIMS
_honour_lock = threading.Lock()


class ClaimConflict(ValueError):
    """A claim that differs from the one this process already honours for the same object."""


def _privilege_parts(privilege: str) -> tuple[str, str | None]:
    """One table claim's privilege and column: ``("UPDATE", "state")`` for ``UPDATE(state)``,
    ``("SELECT", None)`` for ``SELECT``. The one reading of the grammar; anything outside it,
    or anything but an exact ``str``, raises ``ValueError``."""
    found = _TABLE_PRIVILEGE.fullmatch(privilege) if type(privilege) is str else None
    if found is None:
        raise ValueError("Invalid table privilege")
    return found["privilege"], found["column"]


def claim_is_valid(name: object, privileges: object) -> bool:
    """Whether ``privileges`` is something a plugin may claim on the dormant object ``name``,
    and something a database could ever hold exactly.

    Exact types only: a ``str`` subclass can compare equal to anything or render as another
    name, and these names end up in the owner's grant statements. Whether a claimed column
    exists is left to the database check, which fails closed on a claim the database does not
    match exactly.
    """
    if type(name) is not str or type(privileges) is not frozenset or not privileges:
        return False
    if any(type(privilege) is not str for privilege in privileges):
        return False
    if name in DORMANT_TABLES:
        try:
            parts = [_privilege_parts(privilege) for privilege in privileges]
        except ValueError:
            return False
        # A privilege held on a whole table reads as the whole table and never as its
        # columns, so claiming both for one privilege could never be met.
        whole = {privilege for privilege, column in parts if column is None}
        on_columns = {privilege for privilege, column in parts if column is not None}
        return not whole & on_columns
    return name in _DORMANT_FUNCTION_NAMES and privileges == {"EXECUTE"}


def honour_claims(claims: Claims) -> None:
    """Have `check_runtime`, in this process, expect what the plugins it loaded claim.

    The plugin loader calls this once every named plugin has loaded and passed its checks,
    and this is the one check-and-set, under a lock: it only adds. A command that loads
    `EXECBOUND_PLUGINS` and then a runtime configuration naming the same plugin honours the
    same claims twice, and a claim that differs from one already honoured raises
    `ClaimConflict`, so a later load can never narrow or widen what an earlier one recorded.
    An invalid claim raises ``ValueError``. Either way nothing is recorded.
    """
    global _honoured
    with _honour_lock:
        merged = dict(_honoured)
        for name, privileges in claims.items():
            if not claim_is_valid(name, privileges):
                raise ValueError("Invalid dormant claim")
            if merged.get(name, privileges) != privileges:
                raise ClaimConflict("Conflicting dormant claim")
            merged[name] = privileges
        _honoured = MappingProxyType(merged)


def honoured_claims() -> Claims:
    """The dormant grants this process's loaded plugins claim; empty with none loaded."""
    return _honoured


# What the runtime role holds on the dormant tables: whole-table privileges, then those held on
# columns only. Every check names the runtime role rather than the current user, so the
# owner's connection reads exactly what a runtime process will find, and PUBLIC's grants
# count, because the runtime role holds them too. MAINTAIN exists from PostgreSQL 17 and is
# asked about only there. A column grant lives only in its column's ACL, so the column branch
# reads only columns that have one. The schema is named by its oid rather than joined by name:
# the runtime's checks run unprepared (the pooler), so every call parses and plans this text.
_DORMANT_TABLE_GRANTS = """
SELECT c.relname AS name, p.privilege, CAST(NULL AS name) AS column_name,
       CAST(NULL AS text) AS arguments
  FROM pg_class c
 CROSS JOIN unnest(
       CASE WHEN current_setting('server_version_num')::integer >= 170000
            THEN ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES',
                       'TRIGGER', 'MAINTAIN']
            ELSE ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES',
                       'TRIGGER']
       END) AS p(privilege)
 WHERE c.relnamespace = 'execbound'::regnamespace AND c.relkind = 'r'
   AND c.relname = ANY(:dormant_tables)
   AND has_table_privilege('execbound_app', c.oid, p.privilege)
UNION ALL
SELECT c.relname, p.privilege, a.attname, NULL
  FROM pg_class c
  JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
                     AND a.attacl IS NOT NULL
 CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']) AS p(privilege)
 WHERE c.relnamespace = 'execbound'::regnamespace AND c.relkind = 'r'
   AND c.relname = ANY(:dormant_tables)
   AND NOT has_table_privilege('execbound_app', c.oid, p.privilege)
   AND has_column_privilege('execbound_app', c.oid, a.attnum, p.privilege)
"""
# The same table grants, then EXECUTE on each dormant function with its signature, for
# `dormant_grants`. `check_runtime` reads the table grants beside its own function rows
# (`_FUNCTIONS_AND_DORMANT`) and each function's EXECUTE from those rows (`_runtime_grants`),
# rather than reading the functions twice; DC3's parity test holds the two readings equal.
_DORMANT_GRANTS = (
    _DORMANT_TABLE_GRANTS  # nosec B608 - constants only
    + """UNION ALL
SELECT p.proname, 'EXECUTE', NULL, pg_get_function_identity_arguments(p.oid)
  FROM pg_proc p
 WHERE p.pronamespace = 'execbound'::regnamespace AND p.proname = ANY(:dormant_functions)
   AND has_function_privilege('execbound_app', p.oid, 'EXECUTE')
"""
)
# Lists inside, because the driver sends a list, not a tuple, as an array.
_DORMANT_PARAMETERS: Mapping[str, list[str]] = MappingProxyType(
    {
        "dormant_tables": list(DORMANT_TABLES),
        "dormant_functions": sorted(_DORMANT_FUNCTION_NAMES),
    }
)


def _grants_of(rows: Iterable[Sequence[Any]]) -> dict[str, frozenset[str]]:
    """``_DORMANT_GRANTS``' rows in a claim's own terms, one key per dormant object.

    A privilege on a whole table reads ``SELECT``; one held on columns only reads one token per
    column, ``UPDATE(state)``. A function counts only with its catalogued signature: another
    function of the same name is not the dormant object. On the runtime's path,
    `check_runtime`'s functions check refuses it: outright when it is a definer, which
    `FUNCTIONS` does not list, and otherwise whenever the runtime could call it. On the owner's,
    `check_dormant` reads the ACLs by name and refuses any grant on it.
    """
    held: dict[str, set[str]] = {name: set() for name in DORMANT}
    for name, privilege, column, arguments in rows:
        if arguments is not None and (name, arguments) not in _DORMANT_SIGNATURES:
            continue
        held[name].add(privilege if column is None else f"{privilege}({column})")
    return {name: frozenset(privileges) for name, privileges in held.items()}


def dormant_grants(conn: Connection) -> dict[str, frozenset[str]]:
    """What the runtime role can do on every dormant object, read on its own.

    Over the runtime's connection or the owner's: the query names the runtime role, so both
    read the same thing.
    """
    return _grants_of(conn.execute(text(_DORMANT_GRANTS), _DORMANT_PARAMETERS).all())


class UnsafeDatabaseRole(RuntimeError):
    pass


class DormantGrantsRefused(UnsafeDatabaseRole):
    """The dormant objects' grants are not what this process's loaded plugins claim: most
    often a process run against a plugin's database without that plugin named."""


# Every function in the schema, then every dormant table grant as a row of its own: `kind`
# tells them apart, and a grant row's function-only columns are null. One round trip, and no
# aggregate repeated on every row.
_FUNCTIONS_AND_DORMANT = (
    "WITH dormant AS ("  # nosec B608 - constants only
    + _DORMANT_TABLE_GRANTS
    + """)
        SELECT 'function' AS kind, p.proname AS name,
               pg_get_function_identity_arguments(p.oid) AS arguments, p.prosecdef,
               p.proowner = :role AS owned,
               has_function_privilege(current_user, p.oid, 'EXECUTE') AS can_execute,
               p.prorettype = 'trigger'::regtype AS trigger,
               CAST(NULL AS text) AS privilege, CAST(NULL AS name) AS column_name
          FROM pg_proc p
         WHERE p.pronamespace = 'execbound'::regnamespace
        UNION ALL
        SELECT 'dormant' AS kind, d.name, d.arguments,
               NULL AS prosecdef, NULL AS owned, NULL AS can_execute, NULL AS trigger,
               d.privilege, d.column_name
          FROM dormant d
    """
)


def _runtime_rows(conn: Connection, role: int) -> Sequence[RowMapping]:
    """``_FUNCTIONS_AND_DORMANT``'s rows, for the runtime role whose oid is ``role``."""
    return (
        conn.execute(
            text(_FUNCTIONS_AND_DORMANT),
            {"role": role, "dormant_tables": _DORMANT_PARAMETERS["dormant_tables"]},
        )
        .mappings()
        .all()
    )


def _runtime_grants(rows: Sequence[RowMapping]) -> dict[str, frozenset[str]]:
    """What ``_FUNCTIONS_AND_DORMANT``'s rows say the runtime role holds on every dormant
    object, in `dormant_grants`' terms.

    The table grants are the dormant rows. A dormant function's EXECUTE is its own function
    row's ``can_execute``, which asks about the current user: `check_runtime` has already
    verified that the current user is the runtime role, so this is the same question
    `dormant_grants` asks by name, and the functions are not read a second time.
    """
    tables = [
        (row["name"], row["privilege"], row["column_name"], None)
        for row in rows
        if row["kind"] == "dormant"
    ]
    functions = [
        (row["name"], "EXECUTE", None, row["arguments"])
        for row in rows
        if row["kind"] == "function"
        and row["name"] in _DORMANT_FUNCTION_NAMES
        and row["can_execute"]
    ]
    return _grants_of(tables + functions)


def check_runtime(conn: Connection) -> None:
    role = (
        conn.execute(
            text("""
        SELECT r.oid, r.rolname, r.rolsuper, r.rolbypassrls, r.rolcreaterole,
               r.rolcreatedb, r.rolreplication,
               EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = r.oid) AS member,
               has_schema_privilege(current_user, 'execbound', 'CREATE') AS can_create
        FROM pg_roles r WHERE r.rolname = current_user
    """)
        )
        .mappings()
        .one()
    )
    if role["rolname"] != "execbound_app" or any(
        role[key]
        for key in (
            "rolsuper",
            "rolbypassrls",
            "rolcreaterole",
            "rolcreatedb",
            "rolreplication",
            "member",
            "can_create",
        )
    ):
        raise UnsafeDatabaseRole("Unsafe runtime database role")
    tables = (
        conn.execute(
            text("""
        SELECT c.relname, c.relowner, c.relrowsecurity, c.relforcerowsecurity,
               has_any_column_privilege(current_user, c.oid, 'UPDATE') AS can_update,
               has_table_privilege(current_user, c.oid, 'DELETE') AS can_delete,
               has_table_privilege(current_user, c.oid, 'TRUNCATE') AS can_truncate,
               has_any_column_privilege(current_user, c.oid, 'INSERT') AS can_insert,
               has_table_privilege(current_user, c.oid,
                                   'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                   OR has_any_column_privilege(current_user, c.oid,
                                               'SELECT,INSERT,UPDATE,REFERENCES')
                   AS can_any
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'execbound' AND c.relkind = 'r'
          AND c.relname != 'alembic_version'
    """)
        )
        .mappings()
        .all()
    )
    if {row["relname"] for row in tables} != set(TABLES):
        raise UnsafeDatabaseRole("Incomplete database schema")
    views = (
        conn.execute(
            text("""
        SELECT c.relname,c.relowner,c.reloptions,
            has_table_privilege(current_user,c.oid,'SELECT') AS can_read,
            has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE') AS can_write
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='execbound' AND c.relkind IN ('v','m')
    """)
        )
        .mappings()
        .all()
    )
    if len(views) != 1 or any(
        view["relname"] != "effective_approval_scopes"
        or view["relowner"] == role["oid"]
        or "security_invoker=true" not in (view["reloptions"] or [])
        or not view["can_read"]
        or view["can_write"]
        for view in views
    ):
        raise UnsafeDatabaseRole("Unsafe review scope view")
    for row in tables:
        if (
            row["relowner"] == role["oid"]
            or not row["relrowsecurity"]
            or not row["relforcerowsecurity"]
            or row["can_delete"]
            or row["can_truncate"]
            or (row["can_any"] and row["relname"] in PRIVILEGELESS_TABLES)
            # A dormant table's inserts and updates are exactly what a loaded plugin claims,
            # which the dormant check below holds it to; deletes and truncates never are.
            or (
                row["can_update"]
                and row["relname"] not in {"audit_heads", *UPDATE_COLUMNS, *DORMANT_TABLES}
            )
            or (
                row["can_insert"]
                and row["relname"]
                not in {
                    "audit_events",
                    "audit_heads",
                    "agent_runs",
                    "policy_bundle_contents",
                    "policy_bundle_lifecycle",
                    "tenant_policy_control",
                    "executions",
                    "execution_keys",
                    "execution_events",
                    "approvals",
                    "execution_impact",
                    "resource_claims",
                    "human_sessions",
                    "monitor_sources",
                    "monitor_observations",
                    "monitor_findings",
                    "monitor_deliveries",
                    "authentication_failures",
                    "monitor_profiles",
                    "approval_notifications",
                    "export_cursors",
                    "approval_decisions",
                    "monitor_connections",
                    "monitor_inventory",
                    "monitor_agents",
                    "monitor_agent_grants",
                    "monitor_agent_reach",
                    "monitor_actor_drivers",
                    "arcade_hooks",
                    "space_policy_selection",
                    "weekly_summary_subscriptions",
                    *DORMANT_TABLES,
                }
            )
        ):
            raise UnsafeDatabaseRole("Unsafe runtime table privileges")
    # One round trip for the three column rules: every column of an `UPDATE_COLUMNS` table the
    # runtime may update, every `UNREADABLE_COLUMNS` column it may read, and every column of an
    # `INSERT_COLUMNS` table with whether it may insert it (a table-level grant included, which
    # `has_column_privilege` also reports).
    columns = (
        conn.execute(
            text("""
        SELECT c.relname, a.attname,
               c.relname = ANY(:tables)
                   AND has_column_privilege(current_user, c.oid, a.attnum, 'UPDATE')
                   AS can_update,
               c.relname || '.' || a.attname = ANY(:unreadable)
                   AND has_column_privilege(current_user, c.oid, a.attnum, 'SELECT')
                   AS can_read,
               c.relname = ANY(:inserts)
                   AND has_column_privilege(current_user, c.oid, a.attnum, 'INSERT')
                   AS can_insert
        FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'execbound' AND a.attnum > 0 AND NOT a.attisdropped
          AND ((c.relname = ANY(:tables)
                AND has_column_privilege(current_user, c.oid, a.attnum, 'UPDATE'))
            OR (c.relname || '.' || a.attname = ANY(:unreadable)
                AND has_column_privilege(current_user, c.oid, a.attnum, 'SELECT'))
            OR c.relname = ANY(:inserts))
    """),
            {
                "tables": list(UPDATE_COLUMNS),
                "unreadable": sorted(UNREADABLE_COLUMNS),
                "inserts": list(INSERT_COLUMNS),
            },
        )
        .mappings()
        .all()
    )
    if any(
        row["can_read"]
        or (row["can_update"] and row["attname"] not in UPDATE_COLUMNS[row["relname"]])
        for row in columns
    ):
        raise UnsafeDatabaseRole("Unsafe runtime column privileges")
    if any(
        {row["attname"] for row in columns if row["relname"] == table and row["can_insert"]}
        != allowed
        for table, allowed in INSERT_COLUMNS.items()
    ):
        raise UnsafeDatabaseRole("Unsafe runtime column privileges")
    # The dormant table grants come back as rows of their own in the same round trip; the
    # dormant functions' EXECUTE is read from the function rows (`_runtime_grants`).
    rows = _runtime_rows(conn, role["oid"])
    functions = [row for row in rows if row["kind"] == "function"]
    # Exactly the administration functions run as definer, owned elsewhere and executable
    # here, apart from a dormant one, whose EXECUTE is exactly what a loaded plugin claims;
    # nothing else the runtime could call may exist (trigger functions are not callable).
    # Exactly the listed trigger functions run as definer, owned elsewhere.
    definers = {
        (row["name"], row["arguments"])
        for row in functions
        if row["prosecdef"] and not row["trigger"]
    }
    trigger_definers = {row["name"] for row in functions if row["prosecdef"] and row["trigger"]}
    if (
        definers != set(FUNCTIONS)
        or trigger_definers != TRIGGER_DEFINERS
        or any(
            (
                row["owned"]
                or (
                    not row["can_execute"]
                    and not row["trigger"]
                    and (row["name"], row["arguments"]) not in _DORMANT_SIGNATURES
                )
            )
            if row["prosecdef"]
            else (row["can_execute"] and not row["trigger"])
            for row in functions
        )
    ):
        raise UnsafeDatabaseRole("Unsafe administration functions")
    if (
        conn.execute(text("SELECT version_num FROM execbound.alembic_version")).scalar_one()
        != SCHEMA_REVISION
    ):
        raise UnsafeDatabaseRole("Database revision mismatch")
    # After the revision, so a database at another revision says so first.
    _refuse_unless_claimed(_runtime_grants(rows), honoured_claims())


def _refuse_unless_claimed(held: dict[str, frozenset[str]], claims: Claims) -> None:
    if held != {name: claims.get(name, frozenset()) for name in DORMANT}:
        raise DormantGrantsRefused("Unsafe dormant grants")


# Every ACL entry on every dormant object, whoever holds it and whoever granted it: tables
# and their columns by name, and functions by name, so another function of a dormant name is
# read too. A table with no ACL of its own holds the owner's default; a function with none
# holds the default that lets PUBLIC execute it. PUBLIC is grantee 0, which matches no role.
_DORMANT_ACL = """
SELECT c.relname AS name, CAST(NULL AS text) AS arguments,
       a.grantor = c.relowner AS by_owner, a.grantee = c.relowner AS to_owner,
       a.grantee = CAST(to_regrole('execbound_app') AS oid) AS to_runtime, a.is_grantable
  FROM pg_class c
 CROSS JOIN aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) AS a
 WHERE c.relnamespace = 'execbound'::regnamespace AND c.relname = ANY(:dormant_tables)
UNION ALL
SELECT c.relname, NULL, a.grantor = c.relowner, a.grantee = c.relowner,
       a.grantee = CAST(to_regrole('execbound_app') AS oid), a.is_grantable
  FROM pg_attribute t
  JOIN pg_class c ON c.oid = t.attrelid
 CROSS JOIN aclexplode(t.attacl) AS a
 WHERE c.relnamespace = 'execbound'::regnamespace AND c.relname = ANY(:dormant_tables)
   AND t.attacl IS NOT NULL
UNION ALL
SELECT p.proname, pg_get_function_identity_arguments(p.oid), a.grantor = p.proowner,
       a.grantee = p.proowner, a.grantee = CAST(to_regrole('execbound_app') AS oid),
       a.is_grantable
  FROM pg_proc p
 CROSS JOIN aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) AS a
 WHERE p.pronamespace = 'execbound'::regnamespace AND p.proname = ANY(:dormant_functions)
"""


def _acl_is_safe(rows: Iterable[Sequence[Any]]) -> bool:
    """Whether every entry of ``_DORMANT_ACL`` is one the dormant rule allows: the owner's own,
    or the runtime role's on a catalogued object, granted by the owner without a grant option.

    Anything else is refused: a grant by any grantor but the owner, which the owner's revoke
    cannot take away; a grant to PUBLIC or to any other role, which the runtime's own reading
    either folds into its reach or cannot see; a grant option; and any grant on another
    function of a dormant name. A null comparison (no runtime role) counts as not allowed.
    """
    for name, arguments, by_owner, to_owner, to_runtime, grantable in rows:
        if by_owner is not True:
            return False
        if to_owner is True:
            continue
        if to_runtime is not True or grantable is not False:
            return False
        if arguments is not None and (name, arguments) not in _DORMANT_SIGNATURES:
            return False
    return True


def check_dormant(conn: Connection, claims: Claims) -> None:
    """Refuse unless every dormant object holds exactly what ``claims`` gives the runtime role,
    nothing where ``claims`` does not name it, and nothing for anyone but the owner.

    For the owner's connection, where a plugin's owner command verifies its grants before it
    commits. Beyond `check_runtime`'s comparison of what the runtime role can do, this reads
    the ACLs themselves (``_acl_is_safe``), because what the runtime can do folds PUBLIC's
    grants into its own and cannot see a platform role's at all.
    """
    _refuse_unless_claimed(dormant_grants(conn), claims)
    if not _acl_is_safe(conn.execute(text(_DORMANT_ACL), _DORMANT_PARAMETERS).all()):
        raise DormantGrantsRefused("Unsafe dormant grants")


# Roles a hosting platform adds that might have been granted something (Supabase's).
_PLATFORM_ROLES = ("anon", "authenticated", "service_role")


def grant_dormant(conn: Connection, claims: Claims) -> None:
    """Set the privileges on every dormant object to exactly ``claims`` for the runtime role, and
    revoke what the owner granted PUBLIC and the platform roles.

    For the owner's connection: a plugin's owner command runs it inside the migration
    transaction, and the suite runs it around a plugin directory's tests. Everything the
    owner granted the runtime role, PUBLIC and a platform role on every dormant object is
    revoked first, so the result is the claim whatever the owner granted before, and an object
    no claim names ends with nothing. An owner's revoke takes away only the owner's own grants:
    one made by another grantor, one to a role this does not name, and one on another function
    of a dormant name all survive, and `check_dormant`, which reads the ACLs themselves,
    refuses each of them. Every name in these statements comes from this module's catalog or
    from a claim `claim_is_valid` accepted; a claim it refuses raises ``ValueError``.
    """
    if any(not claim_is_valid(name, privileges) for name, privileges in claims.items()):
        raise ValueError("Invalid dormant claim")
    present = set(
        conn.execute(
            text("SELECT rolname FROM pg_roles WHERE rolname = ANY(:roles)"),
            {"roles": list(_PLATFORM_ROLES)},
        ).scalars()
    )
    grantees = ", ".join(
        ["PUBLIC", "execbound_app", *(role for role in _PLATFORM_ROLES if role in present)]
    )
    # Revoking a table's privileges revokes its column privileges too.
    for table in DORMANT_TABLES:
        conn.execute(text(f"REVOKE ALL ON execbound.{table} FROM {grantees}"))
    for name, arguments in DORMANT_FUNCTIONS:
        conn.execute(text(f"REVOKE ALL ON FUNCTION execbound.{name}({arguments}) FROM {grantees}"))
    for table in DORMANT_TABLES:
        parts = [_privilege_parts(privilege) for privilege in claims.get(table, ())]
        whole = sorted(kind for kind, column in parts if column is None)
        if whole:
            conn.execute(text(f"GRANT {', '.join(whole)} ON execbound.{table} TO execbound_app"))
        columns: dict[str, list[str]] = {}
        for kind, column in parts:
            if column is not None:
                columns.setdefault(kind, []).append(f'"{column}"')
        for kind, names in sorted(columns.items()):
            conn.execute(
                text(
                    f"GRANT {kind} ({', '.join(sorted(names))}) "
                    f"ON execbound.{table} TO execbound_app"
                )
            )
    for name, arguments in DORMANT_FUNCTIONS:
        if name in claims:
            conn.execute(
                text(f"GRANT EXECUTE ON FUNCTION execbound.{name}({arguments}) TO execbound_app")
            )


class Database:
    def __init__(self, url: str | URL, *, pool_size: int = 5, max_overflow: int = 8) -> None:
        if (
            type(pool_size) is not int
            or type(max_overflow) is not int
            or not 1 <= pool_size <= 64
            or not 0 <= max_overflow <= 64
        ):
            raise ValueError("Invalid database pool size")
        parsed = database_url(url)
        # Every concurrent runtime call needs one connection; the runtime caps itself here.
        self.capacity = pool_size + max_overflow
        self.engine = create_engine(
            parsed,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_timeout=5,
            pool_pre_ping=True,
            hide_parameters=True,
            connect_args=connect_args(parsed),
        )

    @contextmanager
    def transaction(self, tenant_id: UUID, *, snapshot: bool = False) -> Iterator[Connection]:
        with self.engine.connect() as connection:
            conn = connection.execution_options(
                isolation_level="REPEATABLE READ" if snapshot else "READ COMMITTED"
            )
            with conn.begin():
                conn.execute(text("SELECT set_config('statement_timeout', '10000', true)"))
                conn.execute(text("SELECT set_config('lock_timeout', '5000', true)"))
                conn.execute(
                    text("SELECT set_config('execbound.tenant_id', :tenant, true)"),
                    {"tenant": str(tenant_id)},
                )
                yield conn

    def close(self) -> None:
        self.engine.dispose()
