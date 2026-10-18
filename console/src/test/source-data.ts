// SPDX-License-Identifier: AGPL-3.0-only
// Reporting sources as the console API answers them (#678), for the source dialogs' tests.

import type { MintedSource, MonitorConnectOptions, MonitorSource } from "../api/types.gen";

export const SOURCE = "5e5e5e5e-0000-4000-8000-000000000001";
// A token no page, cache or storage may keep once its dialog closes.
export const TOKEN = "mo1.SENTINEL-source-token-7d14.SENTINEL";
export const INTAKE = "https://console.example/v1/monitor/events";
// The Spaces the monitoring tests place things in: the sessions' own, and another.
export const SPACE_A = "aaaaaaaa-0000-4000-8000-000000000002";
export const SPACE_B = "bbbbbbbb-0000-4000-8000-000000000003";

export function source(changes: Partial<MonitorSource> = {}): MonitorSource {
  return {
    source_id: SOURCE,
    label: "Disable a user",
    story_id: "4001",
    coverage: "No heartbeat",
    health_state: "UNKNOWN",
    health_changed_at: null,
    last_event_at: null,
    last_heartbeat_at: null,
    heartbeat_seconds: 300,
    expires_at: "2026-11-11T12:00:00+00:00",
    previous_valid_until: null,
    revoked_at: null,
    last_refusal_code: null,
    accepted_count: 0,
    administered: true,
    ...changes,
  };
}

export function minted(changes: Partial<MintedSource> = {}): MintedSource {
  return {
    source_id: SOURCE,
    story_id: "4001",
    label: "Disable a user",
    token: TOKEN,
    expires_at: "2026-11-11T12:00:00+00:00",
    heartbeat_seconds: 300,
    previous_valid_until: null,
    intake_url: INTAKE,
    ...changes,
  };
}

export function options(changes: Partial<MonitorConnectOptions> = {}): MonitorConnectOptions {
  return {
    tines: "available",
    entra: "unconfigured",
    sources: "available",
    intake_url: INTAKE,
    entra_display_name: null,
    entra_client_id: null,
    last_attempt: null,
    placement: { space_id: SPACE_A, name: "Customer A", archived: false, administered: true },
    ...changes,
  };
}
