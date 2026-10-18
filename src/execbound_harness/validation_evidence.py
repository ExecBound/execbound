# SPDX-License-Identifier: AGPL-3.0-only
"""Allowlisted validation manifest; no private fixture or workspace archiving."""

import argparse
import hashlib
import json

# git on this checkout and pytest's own JUnit output are the only external inputs.
import subprocess  # nosec B404 - git on this checkout, fixed argv, no shell
from importlib.metadata import distributions
from pathlib import Path
from typing import Any
from xml.etree import ElementTree  # nosec B405 - pytest's own output; entities refused

from execbound.replay.runner import read_bounded
from execbound.replay.verify import ReplayValidationError, reject_secrets

ACCEPTANCE_PREFIXES: dict[str, tuple[str, ...]] = {
    "A": (
        "tests/test_protected_path.py::test_production_approval_then_exactly_one_real_provider_mutation",
    ),
    "B": (
        "tests/test_protected_path.py::test_authorization_forbid_produces_no_provider_invocation",
        "tests/test_identity_reconciliation.py::test_existing_privileged_identity_is_denied_without_provider_effect",
    ),
    "C": ("tests/test_replay_integration.py::test_actual_",),
    "D": ("tests/test_execution.py::test_autonomous_ten_then_approval_and_shared_total_twenty",),
    "E": (
        "tests/test_policy_evaluation.py::test_caller_claim_changes_cannot_change_cedar_entities",
        "tests/test_resolution.py::test_claims_cannot_replace_missing_incident",
    ),
    "F": (
        "tests/test_resolution.py::test_unknown_operation_fails_without_foreign_disclosure",
        "tests/test_requests.py::test_requires_an_explicit_arguments_object",
        "tests/test_requests.py::test_rejects_non_scalar_or_unbounded_arguments",
        "tests/test_resolution.py::test_arguments_outside_the_action_spec_fail_before_facts",
    ),
    "G": ("tests/test_execution.py::test_pending_authority_changes_invalidate_approval",),
    "H": (
        "tests/test_execution.py::test_confirmed_retries_retain_status_and_new_key_charges_again",
    ),
    "I": (
        "tests/test_protected_path.py::test_effect_then_lost_response_reconciles_from_retained_journal",
        "tests/test_execution.py::test_uncertainty_keeps_capacity_and_target_guard_without_resend",
    ),
    "J": (
        "tests/test_replay_integration.py::test_actual_",
        "tests/test_replay_scenarios.py::test_",
    ),
    "K": (
        "tests/test_human_surface.py::test_agent_bearer_cannot_use_human_routes",
        "tests/test_protected_path.py::test_agent_reconciliation_rejected_before_provider_network",
    ),
    "L": (
        "tests/test_execution.py::test_concurrent_principals_cannot_exceed_shared_first_capacity",
    ),
    "M": ("tests/test_identity_surfaces.py::test_", "tests/test_mcp_surface.py::test_"),
    "N": (
        "tests/test_policy_evaluation.py::test_policy_errors_cannot_be_waived_by_matching_approval",
        "tests/test_policy_evaluation.py::test_approval_evaluation_error_also_denies",
        "tests/test_policy_evaluation.py::test_invalid_inventory_facts_fail_closed",
        "tests/test_cedar.py::test_",
    ),
    "O": (
        "tests/test_protected_path.py::test_provider_version_changes_after_gateway_commit_fail_atomically",
    ),
    "P": ("tests/test_identity_reconciliation.py::test_",),
    "Q": ("tests/test_requests.py::test_q_rejects_mixed_targets_and_embedded_target_arguments",),
    "R": (
        "tests/test_execution.py::test_hard_denial_after_human_approval_never_consumes",
        "tests/test_policy_evaluation.py::test_hard_limit_wins_over_policy_and_soft_approvals",
    ),
    "S": (
        "tests/test_replay_export.py::test_foreign_tenant_bundle_id_collision_cannot_enter_export",
        "tests/test_execution_database.py::test_all_execution_tables_isolate_colliding_tenant_objects",
        "tests/test_resolution.py::test_colliding_tenant_aliases_do_not_cross",
    ),
    "T": (
        "tests/test_resolution.py::test_required_context_and_mapping_fail_closed",
        "tests/test_resolution.py::test_claims_cannot_replace_missing_incident",
        "tests/test_resolution.py::test_revalidation_detects_changed_bound_evidence",
    ),
    "U": (
        "tests/test_protected_path.py::test_provider_version_changes_after_gateway_commit_fail_atomically",
        "tests/test_execution.py::test_authority_is_rechecked_after_lock_wait",
    ),
    "V": (
        "tests/test_execution.py::test_precommit_failures_roll_back_every_claim",
        "tests/test_execution.py::test_racing_first_intent_creates_one_pending_approval",
        "tests/test_execution.py::test_same_key_changed_intent_conflicts_under_race",
        "tests/test_execution.py::test_crash_before_send_has_no_ticket_takeover_and_admin_requires_proof",
    ),
    "W": (
        "tests/test_identity_reconciliation.py::test_later_signed_operation_cannot_settle_or_refund_original_effect",
        "tests/test_identity_reconciliation.py::test_current_identity_state_with_absent_journal_preserves_original_impact",
        "tests/test_protected_path.py::test_missing_journal_does_not_refund_and_cancel_fences_delayed_dispatch",
    ),
    "X": ("tests/test_browser_surfaces.py::test_", "tests/test_human_surface.py::test_"),
    "SA": (
        "tests/test_action_catalog.py::test_",
        "tests/test_domains.py::test_",
        "tests/test_identity_compatibility.py::test_",
        "tests/test_requests.py::test_requires_an_explicit_arguments_object",
        "tests/test_requests.py::test_rejects_non_scalar_or_unbounded_arguments",
        "tests/test_resolution.py::test_arguments_outside_the_action_spec_fail_before_facts",
        "tests/test_resolution.py::test_synthetic_long_argument_resolves_only_with_its_catalog",
        "tests/test_policy_evaluation.py::test_soc_pack_reads_arguments_from_the_cedar_context",
        "tests/test_context_bundle_validation.py::test_action_context_must_match_the_catalog_exactly",
        "tests/test_soc_pack.py::test_",
        "tests/test_soc_provider.py::test_",
        "tests/test_soc_execution.py::test_",
        "tests/test_soc_schema.py::test_",
        "tests/test_replay_scenarios.py::test_candidate_can_forbid_lift_isolation_by_argument",
        "tests/test_replay_verify.py::test_",
    ),
    "SL": (
        "tests/test_limit_scopes.py::test_",
        "tests/test_limit_scopes_schema.py::test_",
        "tests/test_policy_models.py::test_applies_to_covers_every_scope",
        "tests/test_policy_evaluation.py::test_group_rule_applies_only_to_members",
        "tests/test_context_bundle_validation.py::test_selector_",
        "tests/test_policy_store.py::test_scoped_rules_",
        "tests/test_admin_cli.py::test_group_",
        "tests/test_replay_history.py::test_",
        "tests/test_replay_scenarios.py::test_sl9_",
        "tests/test_human_surface.py::test_record_page_",
        "tests/test_browser_surfaces.py::test_sl11_",
    ),
    "GC": (
        "tests/test_checkpoint.py::test_gc",
        "tests/test_checkpoint_workflow.py::test_gc",
        "tests/test_checkpoint_schema.py::test_gc",
        "tests/test_browser_surfaces.py::test_gc18",
    ),
    "AL": (
        "tests/test_arcade.py::test_al",
        "tests/test_arcade_schema.py::test_al",
        "tests/test_arcade_workflow.py::test_al",
        "tests/test_browser_surfaces.py::test_al",
    ),
    # Spaces (SP1 to SP22). The isolation file is named first because it is the whole of
    # the mitigation for a forgotten space predicate: forced row-level security does not
    # catch one, so a run that did not execute it proves nothing about SP1.
    "SP": (
        "tests/test_spaces_isolation.py::test_",
        "tests/test_spaces.py::test_",
        "tests/test_spaces_schema.py::test_",
        "tests/test_spaces_kernel.py::test_",
        "tests/test_console_api_spaces.py::test_",
        "tests/test_browser_console_spaces.py::test_",
        "tests/test_spaces_credentials.py::test_sp15",
        "tests/test_spaces_principals.py::test_sp1",
        "tests/test_spaces_directory.py::test_sp20",
        "tests/test_spaces_workspace_settings.py::test_sp21",
        "tests/test_spaces_workspace_requests.py::test_sp22",
    ),
    # Sample targets (SM1 to SM11). A sample account is the one connection the dispatch path
    # resolves without a configured connector, so its evidence travels with the kernel's. The
    # connection view's `operation_ref` tests are SM10's and carry no `test_sm` in their names,
    # and a token's download of the demo configuration is SM11's, beside the demo run on it.
    "SM": (
        "tests/test_sample_accounts.py::test_sm3",
        "tests/test_samples_schema.py::test_sm",
        "tests/test_samples.py::test_sm",
        "tests/test_sample_runtime.py::test_sm_runtime",
        "tests/test_sample_mock.py::test_sm4",
        "tests/test_samples_end_to_end.py::test_sm5",
        "tests/test_console_api_samples.py::test_sm",
        "tests/test_console_api_connection.py::test_the_operation_ref",
        "tests/test_console_api_tokens.py::test_a_token_downloads_the_samples_demo_configuration",
        "tests/test_demo_command.py::test_sm11",
        "tests/test_browser_console_samples.py::test_sm7",
    ),
    # Denial notice (DN1 to DN10). What a denied agent is told, over HTTP and MCP, and what a
    # refusal before any plan records for people, are part of the enforcement contract
    # (THREAT_MODEL.md T1.16), so their evidence travels with the kernel's.
    "DN": ("tests/test_denial_notice.py::test_dn", "tests/test_denial_categories.py::test_dn"),
    # Action listing (LA1 to LA8). What an agent's own space offers it, and admission refusing
    # every other operation exactly as an unknown one (THREAT_MODEL.md T1.17).
    "LA": ("tests/test_action_listing.py::test_la",),
    # Scheduled audit-chain verification (AV1 to AV7). Every workspace's chain read again on the
    # live database, and each retained checkpoint placed on it (THREAT_MODEL.md T2.4).
    "AV": ("tests/test_audit_verify.py::test_av",),
    # Self-hosted export (EX1 to EX10). Only the rows whose tests the export carries: EX5's
    # stage list, the service links (EX8), a plugin's token routes (EX9) and the release's
    # preflight and provenance (EX10). EX1 to EX4, EX6, EX7 and the release workflow's shape
    # are tested under `tests/internal/`, which the exported tree does not hold, and this
    # module runs there too.
    "EX": (
        "tests/test_ci_stages.py::test_",
        "tests/test_release_preflight.py::test_",
        "tests/test_release_provenance.py::test_",
        "tests/test_service_links.py::test_",
        "tests/test_plugins.py::test_the_service_links_come_from_the_configuration_or_a_plugin_never_both",
        "tests/test_plugins.py::test_a_plugin_cannot_allow_any_method_of_a_core_path",
        "tests/test_plugins.py::test_token_routes_are_the_plugins_own_console_routes_and_methods",
        "tests/test_plugin_surfaces.py::test_a_token_calls_the_route_a_plugin_allows_and_no_other",
    ),
    # Security signals (SG1 to SG17). Every signal test file, each named as every group names
    # its files, so `tests/test_validation_evidence.py` refuses a signal test file left out;
    # and the two route-inventory tests that hold SG3 across every route.
    "SG": (
        "tests/test_signal_admit.py::test_",
        "tests/test_signal_bundle_validation.py::test_",
        "tests/test_signal_capabilities.py::test_",
        "tests/test_signal_conformance.py::test_",
        "tests/test_signal_contract.py::test_",
        "tests/test_signal_envelope.py::test_",
        "tests/test_signal_evaluation.py::test_",
        "tests/test_signal_evidence.py::test_",
        "tests/test_signal_execution.py::test_",
        "tests/test_signal_intake.py::test_",
        "tests/test_signal_mapping_create.py::test_",
        "tests/test_signal_mapping_model.py::test_",
        "tests/test_signal_mapping.py::test_",
        "tests/test_signal_registration.py::test_",
        "tests/test_signal_replay.py::test_",
        "tests/test_signal_resolution.py::test_",
        "tests/test_signal_ruleset_compile.py::test_",
        "tests/test_signal_schema.py::test_",
        "tests/test_signal_tokens.py::test_",
        "tests/test_signal_views.py::test_",
        "tests/test_route_authority.py::test_the_signal_intake_refuses_an_agent_credential",
        "tests/test_route_authority.py::test_a_producer_token_reaches_nothing_but_the_signal_intake",
    ),
    # Protocol and connector packages (PK1 to PK10, #496): the import boundary, one
    # definition of everything that moved, the frozen journals re-signed byte for byte, and
    # evidence settling only through the verifier the runtime built.
    "PK": (
        "tests/test_connector_packages.py::test_",
        "tests/test_protected_path.py::test_a_connector_receives_the_frozen_provider_command",
        "tests/test_protected_path.py::test_the_verifier_comes_from_the_server_not_the_connector",
        "tests/test_protected_path.py::test_reconciliation_settles_with_the_server_verifier_too",
        "tests/test_protected_path.py::"
        "test_the_runtime_verifies_with_the_config_it_was_given_not_what_a_connector_reports",
        "tests/test_protected_path.py::"
        "test_a_rotation_reaches_the_runtimes_verifier_whatever_the_connector_does",
    ),
    # Console foundation (CF1 to CF14, #678): one time format, one name per principal, one
    # vocabulary. CF3 (the lint bans) and CF10 (strings as text) are held by the console's own
    # tests, `console/scripts/bans.test.ts` and the component tests, and named in
    # ACCEPTANCE_TESTS.md rather than here.
    "CF": (
        "tests/test_console_foundation.py::test_cf",
        "tests/test_browser_console_foundation.py::test_cf",
        "tests/test_principal_names.py::test_cf",
        "tests/test_console_api_board.py::test_cf",
        "tests/test_console_api_monitoring.py::test_cf",
        "tests/test_console_api_agents.py::test_cf",
        "tests/test_account_api.py::test_cf",
    ),
    # Approval delivery (AY, #678): a notification is never sent, retried or deferred once it
    # could not arrive with time to act, and the jobs service drains every fifteen seconds
    # beside its other jobs; each message has a kind, a destination chooses its kinds, and an
    # outcome follows an announcement once.
    "AY": (
        "tests/test_approval_delivery.py::test_ay",
        "tests/test_jobs_schedule.py::test_ay",
        "tests/test_notification_transports.py::test_ay",
        "tests/test_notification_email.py::test_ay",
        "tests/test_notification_chat.py::test_ay",
        "tests/test_approval_delivery_config.py::test_ay",
        "tests/test_notification_kinds_migration.py::test_ay",
        "tests/test_console_api_settings.py::test_ay",
        "tests/test_browser_console_tenant.py::test_ay",
        "tests/test_browser_console_samples.py::test_ay",
        "tests/test_request_references.py::test_ay",
    ),
    # Monitoring queue (MQ, #678): acknowledgement held to the spaces the caller sees and
    # audited with the credential that acted.
    "MQ": (
        "tests/test_monitoring_acknowledgement.py::test_mq",
        "tests/test_console_api_monitoring.py::test_mq",
        "tests/test_replay_informational_kinds.py::"
        "test_an_acknowledged_finding_leaves_every_later_decision_replayable",
        "tests/test_monitoring_freshness.py::test_mq",
        "tests/test_browser_console_monitor.py::test_mq",
        "tests/test_finding_acknowledgement_migration.py::test_mq",
    ),
    # Home, value reporting and the board (#678).
    "HV": (
        "tests/test_home_value.py::test_hv",
        "tests/test_console_api_report.py::test_hv",
        "tests/test_weekly_summary_schema.py::test_hv",
        "tests/test_weekly_summary.py::test_hv",
        "tests/test_jobs_schedule.py::test_hv",
        "tests/test_console_api_weekly_summary.py::test_hv",
        "tests/test_summary_pages.py::test_hv",
        "tests/test_browser_console_home_value.py::test_hv",
    ),
    # Approval pages (#678): Waiting on others, the decision bar, assigning yourself and the
    # kept comment.
    "AQ": (
        "tests/test_console_api_approvals.py::"
        "test_records_refuses_others_to_anyone_but_an_administrator_reading_outside_review",
        "tests/test_console_api_approvals.py::test_others_is_the_complement_of_the_administrators_own_scope",
        "tests/test_console_api_approvals.py::"
        "test_an_administrator_sees_approvals_waiting_on_others_and_cannot_decide_them",
        "tests/test_console_api_approvals.py::test_waiting_on_others_is_an_administrators_view",
        "tests/test_console_api_approvals.py::"
        "test_an_approval_the_administrator_reviews_is_not_waiting_on_others",
        "tests/test_console_api_approvals.py::test_waiting_on_others_stays_inside_the_administrators_spaces",
        "tests/test_console_api_approvals.py::test_the_reviewer_count_is_people_who_can_open_the_record",
        "tests/test_console_api_approvals.py::test_an_administrators_lapsed_view_covers_every_reviewer",
        "tests/test_console_api_approvals.py::test_assigning_yourself_moves_a_review_from_another_space",
        "tests/test_console_api_approvals.py::test_the_detail_carries_the_cores_approval_link",
        "tests/test_browser_console_approvals.py::"
        "test_an_administrator_chases_an_approval_waiting_on_someone_else",
        "tests/test_browser_console_approvals.py::"
        "test_the_phone_bar_names_the_effect_the_time_and_the_workspace",
        "tests/test_browser_console_approvals.py::"
        "test_assigning_yourself_asks_for_the_factor_and_then_the_decision_lands",
        "tests/test_browser_console_approvals.py::test_a_typed_comment_survives_signing_in_again",
        "tests/test_browser_console_approvals.py::"
        "test_waiting_on_others_lapsed_and_the_waiting_panel_are_clean",
        "tests/test_approval_notifications.py::test_a_message_the_sweep_beat_",
        "tests/test_approval_notifications.py::test_a_message_a_decision_beat_reads_as_closed",
        "tests/test_approval_notifications.py::"
        "test_an_approved_approval_that_lapsed_unused_reads_as_closed",
        "tests/test_approval_notifications.py::"
        "test_a_message_for_an_invalidated_approval_reads_as_withdrawn",
        "tests/test_approval_notifications.py::"
        "test_the_records_row_carries_the_delivery_times_only_when_asked",
        "tests/test_console_api_approvals.py::test_the_delivery_view_says_when_the_message_arrived",
        "tests/test_console_api_approvals.py::"
        "test_a_delivery_after_the_deadline_has_a_negative_margin_and_is_late",
        "tests/test_console_api_approvals.py::test_nobody_notified_reads_no_delivery",
        "tests/test_console_api_approvals.py::"
        "test_waiting_on_others_and_the_administrators_detail_carry_delivery",
        "tests/test_console_api_approvals.py::test_an_expired_detail_carries_the_quorum_it_reached",
        "tests/test_console_api_approvals.py::"
        "test_an_approved_detail_that_lapsed_unused_reads_its_quorum_met",
        "tests/test_browser_console_approvals.py::test_an_approver_reads_what_happened_after_a_lapse",
        "tests/test_browser_console_approvals.py::"
        "test_an_approver_who_approved_is_not_told_nobody_decided",
    ),
    # Agents, keys and account security (#678): a key's last use, a recorded rotation, the keys
    # that expire soon, and who has a second factor.
    "AK": (
        "tests/test_key_last_used.py::test_ak",
        "tests/test_member_factors_without_bypass.py::test_ak",
        "tests/test_console_api_expiring_keys.py::test_ak",
        "tests/test_console_api_agents.py::test_ak5_ak6",
        "tests/test_browser_console_agents_account.py::test_ak",
        "tests/test_console_api_people.py::test_ak",
        "tests/test_console_api_settings.py::test_ak",
    ),
    "MC": (
        "tests/test_monitor_connect_schema.py::test_mc1",
        "tests/test_monitor_sealing.py::test_mc",
        "tests/test_surface_configuration.py::test_mc2",
        "tests/test_monitor_connect_store.py::test_mc",
        "tests/test_console_api_monitoring_connect.py::test_mc",
        "tests/test_boot.py::test_mc3",
        "tests/test_boot.py::test_mc4",
        "tests/test_jobs_schedule.py::test_mc3",
        "tests/test_monitor_lease.py::test_mc5",
        "tests/test_monitor_lease.py::test_mc6",
        "tests/test_console_api_monitoring.py::test_mc5",
        "tests/test_monitor_collect_due.py::test_mc7",
        "tests/test_jobs_schedule.py::test_mc7",
        "tests/test_boot.py::test_mc7",
        "tests/test_replay_informational_kinds.py::"
        "test_monitoring_connection_changes_leave_every_later_decision_replayable",
        "tests/test_route_authority.py::test_a_scout_block_serves_exactly_the_same_routes",
        "tests/test_community_bundle.py::"
        "test_the_collectors_key_is_mounted_into_the_jobs_container_alone",
        "tests/test_browser_monitoring_connect.py::"
        "test_mc17_connect_tines_collect_and_verify_reporting",
        "tests/test_browser_monitoring_connect.py::"
        "test_mc18_with_operator_commands_the_console_keeps_the_operator_steps",
        "tests/test_monitor_process_all.py::test_mc21",
        "tests/test_monitor_consent.py::test_mc",
        "tests/test_monitor_platform_app.py::test_mc3",
        "tests/test_monitor_collect_due.py::test_mc3",
        "tests/test_surface_configuration.py::test_mc3",
        "tests/test_browser_monitoring_connect.py::"
        "test_mc17_connect_microsoft_entra_to_microsofts_sign_in_and_back",
        "tests/test_console_api_monitoring_sources.py::test_mc",
        "tests/test_monitoring_lifecycle.py::test_mc14",
        "tests/test_monitoring_lifecycle.py::test_mc15",
        "tests/test_browser_monitoring_connect.py::"
        "test_mc16_mc17_add_a_reporting_source_and_see_its_first_heartbeat",
        "tests/test_browser_monitoring_connect.py::"
        "test_mc19_report_a_story_with_an_open_gap_from_inventory",
        "tests/test_browser_monitoring_connect.py::"
        "test_mc22_without_console_connect_nothing_is_minted_and_a_source_is_still_revoked",
    ),
    # Working across workspaces (#678): what each of an account's workspaces makes of it, a
    # count of its own waiting approvals elsewhere, the section a switch keeps, and a tab left
    # behind.
    "XW": (
        "tests/test_workspace_sections.py::test_xw",
        "tests/test_workspace_waiting.py::test_xw",
        "tests/test_browser_workspaces.py::test_xw",
    ),
    # Sign-in, sessions and returning (#678): the signed hint's closed grammar, a return to any
    # console page through sign-in and the second factor, and the session's hard end; the
    # workspace a sign-in opens, a code just used, and the challenge that names a workspace; a
    # recent verification carried across a switch, and its record.
    "SN": (
        "tests/test_login_return.py::test_sn",
        "tests/test_sign_in_surface.py::test_sn",
        "tests/test_sign_in_surface.py::"
        "test_an_invalid_navigation_cookie_never_controls_the_login_destination",
        "tests/test_mfa_surface.py::test_sn",
        "tests/test_session_end.py::test_sn",
        "tests/test_browser_console_return.py::test_sn",
        "tests/test_workspace_entry_migration.py::test_sn",
        "tests/test_assurance_carry_migration.py::test_sn",
        "tests/test_workspace_switching.py::test_sn",
        "tests/test_workspace_waiting.py::test_sn",
        "tests/test_mfa_sessions.py::test_sn",
        "tests/test_mfa_sessions.py::test_totp_is_single_use_across_concurrent_sessions",
        "tests/test_browser_accessibility.py::"
        "test_the_challenge_after_a_switch_passes_the_audit_in_both_schemes",
    ),
    # Approval routing (#678): an invitation that puts an Approver into a reviewer group.
    "AR": (
        "tests/test_invitation_reviewer_group_migration.py::test_ar",
        "tests/test_invitation_reviewer_group.py::test_ar",
        "tests/test_browser_invitations.py::test_ar",
        "tests/test_approval_windows.py::test_",
        "tests/test_console_api_settings.py::test_ar9",
        "tests/test_browser_console_tenant.py::test_ar13",
        "tests/test_reviewers_at_hold_migration.py::test_ar",
        "tests/test_approval_routing.py::test_",
        "tests/test_console_api_approval_routing.py::test_",
        "tests/test_browser_console_routing.py::test_ar",
    ),
    # Microsoft sign-in (#678): the provider's claim checks, its configuration and routes, a
    # sign-in and a link by subject only, the migration that widens the provider lists, replay
    # and the sign-in page with three providers.
    "MI": (
        "tests/test_microsoft_sign_in.py::test_mi",
        "tests/test_sign_in_surface.py::test_mi3",
        "tests/test_microsoft_migration.py::test_mi4",
        "tests/test_browser_accessibility.py::test_mi6",
    ),
    # Replay regression fixtures (#132): the format and its check, the sanitizer's refusals and
    # its survival proof, both commands offline, a fixture from the signal-replay world on real
    # PostgreSQL, the committed fixtures, and the validation demonstration, which builds and
    # checks both tenants' fixtures on real PostgreSQL.
    "RF": (
        "tests/test_replay_fixture.py::test_rf",
        "tests/test_replay_fixture_cli.py::test_rf8",
        "tests/test_replay_fixture_worlds.py::test_rf9",
        "tests/test_validation_harness.py::test_fresh_validation_package_runs_all_boundaries",
    ),
}


def artifact_names() -> tuple[str, ...]:
    names = ["validation.json"]
    for index in range(2):
        names.extend(
            (
                f"tenant-{index}.json",
                f"tenant-{index}.head.json",
                f"tenant-{index}.fixture.json",
                f"candidate-{index}.json",
                f"uncertain-{index}.json",
                f"uncertain-{index}.head.json",
            )
        )
        for directory in (f"baseline-{index}", f"comparison-{index}", f"uncertain-replay-{index}"):
            names.extend(f"{directory}/{name}" for name in ("report.json", "report.md"))
        for label in ("workstation-25", "identity-enable"):
            names.extend(
                f"tenant-{index}-{label}-approval-{size}.png" for size in ("desktop", "mobile")
            )
    return tuple(names)


# The one selection a run may make (#747): `-m "not timed"`, which leaves out the tests that take
# the machine's timing lock. Any other selection is refused, so a run cannot leave out tests it
# chose for itself, and the manifest records the one it made, so a partial run's evidence says it
# is partial.
SELECTIONS = ("not timed",)


def manifest(
    junit: Path,
    collected: Path,
    evidence: Path,
    repository: Path,
    selection: str | None = None,
) -> dict[str, Any]:
    if selection is not None and selection not in SELECTIONS:
        raise ValueError("Unsupported test selection")
    raw = read_bounded(junit, 16 * 1024 * 1024)
    if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise ValueError("Unsupported XML declaration")
    # DOCTYPE and ENTITY declarations are rejected above; the XML is pytest's own output.
    cases = ElementTree.fromstring(raw).findall(".//testcase")  # nosec B314 - entities refused above
    nodes: list[str] = []
    for case in cases:
        if any(case.find(name) is not None for name in ("failure", "error", "skipped")):
            raise ValueError("Validation suite is not fully passing")
        nodes.append(case.attrib["classname"].replace(".", "/") + ".py::" + case.attrib["name"])
    expected = {
        line.strip()
        for line in read_bounded(collected, 4 * 1024 * 1024).decode().splitlines()
        if line.startswith("tests/") and "::" in line
    }
    if not nodes or len(nodes) != len(set(nodes)) or set(nodes) != expected:
        raise ValueError("Test evidence does not match collection")
    mapping = {
        letter: sorted(node for node in nodes if node.startswith(prefixes))
        for letter, prefixes in ACCEPTANCE_PREFIXES.items()
    }
    if any(
        not any(node.startswith(prefix) for node in nodes)
        for prefixes in ACCEPTANCE_PREFIXES.values()
        for prefix in prefixes
    ):
        raise ValueError("Acceptance evidence is missing")
    artifacts = []
    validation: dict[str, Any] = {}
    for name in artifact_names():
        path = evidence / name
        if path.is_symlink() or not path.resolve().is_relative_to(evidence.resolve()):
            raise ValueError("Invalid artifact path")
        content = read_bounded(path, 64 * 1024 * 1024)
        if path.suffix == ".json":
            parsed = json.loads(content)
            reject_secrets(parsed)
            if name == "validation.json":
                validation = parsed
        artifacts.append(
            {"path": name, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        )
    if (
        not validation["providers_stopped_before_replay"]
        or not validation["live_fingerprints_unchanged"]
    ):
        raise ValueError("Isolation evidence is missing")

    # Fixed argv without a shell; git resolves from PATH like the rest of the tooling.
    def git(*arguments: str) -> str:
        return subprocess.check_output(  # nosec B603 B607 - fixed argv, no shell
            ["git", "-C", str(repository), *arguments], text=True
        ).strip()

    maintained = {
        item.metadata["Name"]: item.version
        for item in distributions(path=[str(repository / ".tools" / "mcp-legacy")])
    }
    if "mcp" not in maintained:
        raise ValueError("Maintained client environment is missing")
    result: dict[str, Any] = {
        "version": 1,
        "source_commit": git("rev-parse", "HEAD"),
        "worktree_dirty": bool(git("status", "--porcelain")),
        "lock_sha256": hashlib.sha256((repository / "uv.lock").read_bytes()).hexdigest(),
        "maintained_mcp_version": maintained["mcp"],
        "maintained_client_lock_sha256": hashlib.sha256(
            (repository / "tests" / "mcp-legacy.txt").read_bytes()
        ).hexdigest(),
        "junit_sha256": hashlib.sha256(raw).hexdigest(),
        "test_count": len(nodes),
        "test_nodes": sorted(nodes),
        "acceptance_evidence": mapping,
        "artifacts": artifacts,
        "validation": validation,
        "coverage_scope": "Controlled mock contracts and local HTTP/MCP/browser/replay",
        "named_practitioner_host_trial": "NOT_PERFORMED",
        "real_vendor_trial": "NOT_PERFORMED",
    }
    if selection is not None:
        result["selection"] = selection
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build an allowlisted validation evidence manifest"
    )
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--collected", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--selection", choices=SELECTIONS)
    args = parser.parse_args()
    try:
        result = manifest(
            args.junit, args.collected, args.evidence, args.repository, args.selection
        )
        with args.output.open("x", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print("Validation evidence manifest created; private fixtures excluded.")
    except json.JSONDecodeError as error:
        # Offsets and json's own vocabulary, not a reason; the type is all worth saying.
        parser.exit(2, f"Validation evidence unavailable: {type(error).__name__}\n")
    except ReplayValidationError as error:
        # Its str() is a generic sentence about replay input; the code is the reason.
        parser.exit(2, f"Validation evidence unavailable: {error.code}\n")
    except ValueError as error:
        # Every remaining ValueError reachable here was raised with an author-written
        # literal, so its text discloses nothing that is not already in the repository.
        parser.exit(2, f"Validation evidence unavailable: {error}\n")
    except Exception as error:
        # OSError carries a path and CalledProcessError the full argv, --repository
        # included; name the class only, which is what the blanket catch protected.
        parser.exit(2, f"Validation evidence unavailable: {type(error).__name__}\n")


if __name__ == "__main__":
    main()
