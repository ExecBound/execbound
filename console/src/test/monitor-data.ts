// SPDX-License-Identifier: AGPL-3.0-only
// Monitoring answers for the console's tests (#678): one of each kind of finding, connection and
// story, with markup in every string an external platform supplied.

import type {
  MonitorAgentDetail,
  MonitorAgents,
  MonitorConnection,
  MonitorFinding,
  MonitorFindings,
  MonitorSnapshot,
  MonitorStory,
} from "../api/types.gen";

export const FINDING = "f1f1f1f1-0000-4000-8000-000000000001";
export const AGENT = "aaaaaaaa-0000-4000-8000-000000000001";
export const PRINCIPAL = "0a1b2c3d-0000-4000-8000-000000000003";
export const CONNECTION = "c0c0c0c0-0000-4000-8000-000000000002";

export const OBSERVED: MonitorFinding = {
  finding_id: FINDING,
  title: "Sensitive action <img src=x> reported",
  rule_version: "sensitive-action.v1",
  profile_version: null,
  created_at: "2026-09-19T05:02:00+00:00",
  source_id: "5a5a5a5a-0000-4000-8000-000000000003",
  connection_id: null,
  observation_id: "0b0b0b0b-0000-4000-8000-000000000004",
  story_id: "4001",
  action: "identity.disable",
  target_ref: "u-2231",
  outcome: "success",
  acknowledged_at: null,
  acknowledged_by: null,
  acknowledged_by_ref: null,
  acknowledgement_note: null,
  agent: null,
  connection_label: null,
  source_label: "Triage source",
  synthetic: false,
};

export const REACH: MonitorFinding = {
  ...OBSERVED,
  finding_id: "f1f1f1f1-0000-4000-8000-000000000002",
  title: "Ungoverned reach",
  rule_version: "ungoverned-reach.v1",
  source_id: null,
  connection_id: CONNECTION,
  observation_id: null,
  story_id: null,
  action: null,
  target_ref: null,
  outcome: null,
  agent: {
    agent_id: AGENT,
    display_name: "<img src=x> payroll",
    identity_class: "agent_identity",
    sponsor_state: "absent",
    sponsor_count: 0,
    owner_count: null,
    linked_principal_id: null,
  },
  connection_label: "Synthetic directory",
  source_label: null,
};

export const HEALTH: MonitorFinding = {
  ...REACH,
  finding_id: "f1f1f1f1-0000-4000-8000-000000000003",
  title: "Collection failed",
  rule_version: "collection-health.v1",
  agent: null,
  connection_label: "Synthetic <b>Tines</b> tenant",
};

export const GAP: MonitorFinding = {
  ...HEALTH,
  finding_id: "f1f1f1f1-0000-4000-8000-000000000004",
  title: "Story without a reporting source",
  rule_version: "instrumentation-gap.v1",
};

export function findings(changes: Partial<MonitorFindings> = {}): MonitorFindings {
  return {
    state: "open",
    findings: [OBSERVED],
    counts: { open: 2, acknowledged: 1 },
    profile: null,
    ...changes,
  };
}

export function connection(changes: Partial<MonitorConnection> = {}): MonitorConnection {
  return {
    connection_id: CONNECTION,
    label: "Synthetic <b>Tines</b> tenant",
    base_url: "https://fixture.tines.com",
    team_id: "7",
    health_state: "COLLECTING",
    health_changed_at: null,
    audit_cursor: "2026-09-19T05:00:00+00:00",
    last_run_at: "2026-09-19T05:01:00+00:00",
    last_outcome: "COMPLETE",
    last_error_code: null,
    last_sync_at: "2026-09-19T05:01:00+00:00",
    retry_after_seconds: null,
    revoked_at: null,
    platform_tenant_ref: null,
    capabilities: { stories: { state: "available", at: "2026-09-19T05:01:00+00:00" }, audit: { state: "unsupported", at: null } },
    overdue_since: null,
    reporting: true,
    kind: "tines",
    credential_mode: "key_file",
    collect_interval_seconds: 86400,
    activity_interval_seconds: 900,
    collect_requested_at: null,
    collect_requested_by: null,
    collecting: false,
    next_due_at: "2026-09-19T05:16:00+00:00",
    consented_at: null,
    consented_by: null,
    consent_needs_update: false,
    sign_in_cursor: null,
    egress_addresses: [],
    egress_recorded_at: null,
    egress_recorded_by: null,
    ...changes,
  };
}

export function story(changes: Partial<MonitorStory> = {}): MonitorStory {
  return {
    external_id: "4001",
    name: "Phishing triage",
    coverage_class: "instrumented",
    coverage: "Instrumented",
    gap_opened_at: null,
    action_count: 3,
    any_outbound: true,
    any_unknown: false,
    source_id: "s1",
    source_expired: false,
    source_visible: true,
    connection_revoked: false,
    disabled: false,
    ...changes,
  };
}

export function snapshot(changes: Partial<MonitorSnapshot> = {}): MonitorSnapshot {
  // Unless a case says otherwise, the workspace is the one Space shown: its synthetic directory is
  // present where these connections hold an active one, and can be added where they hold none and
  // no Microsoft Entra connection.
  const connections = changes.connections ?? [connection()];
  const present = connections.some((item) => item.kind === "fixture" && item.revoked_at === null);
  return {
    connections,
    synthetic_directory: {
      present,
      addable: !present && !connections.some((item) => item.kind === "entra_agent_id"),
    },
    sources: [],
    stories: [story()],
    credentials: [{ external_id: "9", name: "okta_api", item_type: "TEXT", source_updated_at: null, gone_at: null }],
    observations: [],
    findings: [OBSERVED],
    deliveries: [],
    destinations: [],
    profile: null,
    open_findings: 1,
    ...changes,
  };
}

export const agents: MonitorAgents = {
  agents: [
    {
      agent_id: AGENT,
      platform_ref: AGENT,
      identity_class: "agent_identity",
      display_name: '<script>alert("x")</script> payroll',
      enabled: true,
      sponsor_state: "unreadable",
      sponsors: [],
      owner_count: null,
      tags: ["agent"],
      linked_principal_id: null,
      linked_principal_ref: null,
      consequential: 1,
      governed: 0,
      lapsed: 0,
      unresolved: 1,
      open_findings: 1,
      did: 0,
      did_at_least: false,
      open_paths: 1,
      accepted: 0,
      accepted_until: null,
      driver: null,
      drivers_more: 0,
      tines_driven: false,
      source: "entra_agent_id",
      synthetic: false,
      app_ref: null,
      removal: "blueprint",
      administered: true,
    },
  ],
  consequential: ["identity.disable"],
  tenant: {
    enumerated: 1,
    shown: 1,
    with_reach: 1,
    governed: 0,
    unestablished: 1,
    assessed: true,
    built_in: false,
    per_source: { entra: 1, tines: 0, synthetic: 0 },
    unattributed: 1,
  },
};

export function agentDetail(changes: Partial<MonitorAgentDetail["agent"]> = {}): MonitorAgentDetail {
  return {
    agent: {
      agent_id: AGENT,
      connection_id: CONNECTION,
      platform_ref: "obj-1",
      identity_class: "agent_identity",
      display_name: "Payroll agent",
      enabled: true,
      sponsor_state: "absent",
      sponsors: [],
      owner_count: 0,
      tags: [],
      blueprint_ref: null,
      credential_kinds: [],
      linked_principal_id: null,
      linked_principal_ref: null,
      first_seen_at: "2026-09-19T05:00:00+00:00",
      observed_at: "2026-09-19T05:00:00+00:00",
      user_agent_hint: null,
      user_agent_seen_at: null,
      source: "entra_agent_id",
      synthetic: false,
      app_ref: null,
      removal: "blueprint",
      administered: true,
      ...changes,
    },
    grants: [],
    reach: [],
    findings: [
      { finding_id: FINDING, rule_version: "ungoverned-reach.v1", title: "Ungoverned reach", created_at: "2026-09-19T05:02:00+00:00", acknowledged_at: null },
    ],
    observations: [],
    unresolved: 0,
    drivers: [],
    driver_gaps: { catalog_version: "egress.2026-10-18", unattributable: ["Zapier", "n8n Cloud"], pending: ["OpenAI"] },
    acceptances: [],
    assessed: true,
  };
}
