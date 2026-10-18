# Protected identity mock

Mock Entra supports four narrow identity actions through the shared FastAPI, HTTP/MCP, human approval and durable execution path. It runs as a separate authenticated provider process with private state. It does not call Microsoft Graph or claim production identity-provider atomicity or token invalidation.

## Action contracts

| Canonical action | Provider path | Atomic mock transition | Required human approval |
|---|---|---|---|
| `identity.disable` | `/v1/disable` | Set account enabled to false; preserve session generation | Production identities |
| `identity.enable` | `/v1/enable` | Set account enabled to true; preserve session generation | Every identity |
| `identity.revoke_sessions` | `/v1/revoke_sessions` | Increment session generation; preserve enabled state | Production identities |
| `identity.reset_password` | `/v1/reset_password` | Increment password generation and set must-change from the argument; preserve enabled state and session generation | Production identities or resets that do not force a change |

Each action accepts one canonical or provider-ID selector. The [action catalog](ACTION_CATALOG.md) binds `mock_entra` (`identity.disable` also binds to `graph`, the real Microsoft Graph connector), resource type `identity`, canonical action, provider operation and `action.v1`; the first three actions take no arguments and use `identity-control.v1`, while `identity.reset_password` takes the boolean `require_change_at_next_sign_in` and uses `identity-credential.v1`. Hostname/email selectors, filters, bulk input, alternate URLs and arbitrary provider arguments are unavailable: an argument outside the action's spec is rejected during resolution, before any fact is read. Runtime configuration must match the trusted resolved account and provider before any reservation.

Required facts are environment, criticality and privilege class from trusted inventory, independently linked incident status/severity, and a derived production flag. By default, `identity-control.v1` permits inventory writer `inventory_sync` and incident writer `soc_analyst` and bounds evidence to a 300-second max age. A bundle's `context_settings` may change the permitted writers and max age for each source kind, with max age capped at the contract's 3,600-second ceiling. A longer max age never extends an already frozen plan. See [Context contracts](CONTEXT_CONTRACTS.md). Evidence retains source versions, provenance and original expiry. Missing, stale, agent-writable or unrelated evidence fails closed. Pending approval cannot survive a privilege/version change.

The synthetic Cedar policy permits standard identities with an open, critical linked incident. It forbids privileged and tier-0 identities and criticality 4. Hard denial takes precedence over approval. The approval column above states each action's rule in the pack that covers it: the first three come from `identity_demo.identity_bundle`, which does not mention `identity.reset_password`, so the reset is authorized and reviewed only under the [SOC pack](ACTION_CATALOG.md#soc-policy-pack), which additionally requires an open high or critical incident for it. Every action declares separate principal autonomous and tenant total limits; mixed bundles apply the matching action's rules while validating the complete usage snapshot. Enabling does not refund an earlier disable, and an unresolved action holds the shared canonical target against conflicting actions.

Human assignments are exact canonical-target/action pairs. The same current scope is used by the SQL list filter, decision verification and dispatch-time recheck. Review pages show the action's name, its requested arguments, privilege facts, frozen plan and applicable limits. Identity pages use no endpoint-only role field.

## Protected state and proof

The identity store tracks enabled state, session generation, password generation, the must-change-password flag, security version and mutation count. `password_generation` and `must_change_password` are added to a store created before credential evidence existed with `ALTER TABLE ... ADD COLUMN` when `PRAGMA table_info` shows them absent, so existing rows and journals are preserved. `reset_password` never generates, stores, returns or logs a password: it advances the password generation counter, which is the only evidence that the secret changed. Every new accepted operation advances its version once, even if the requested enabled state already holds. Repeated delivery of the exact operation returns its immutable journal without another mutation. Concurrent requests, expected-version checks, journal insertion and cancellation share the provider's SQLite transaction.

Provider kind is bound to private account configuration and the physical store. An identity service cannot open an endpoint store or accept endpoint commands; an endpoint service cannot accept identity commands. The service exposes one dispatch path per catalog binding of its provider, and refuses to start when the catalog binds an identity action its store cannot execute; beyond those four fixed mutation paths it exposes only the authenticated journal and control-only cancellation paths. Provisioning has no HTTP route.

The signed journal binds the complete command, expected/resulting versions and exact before/after identity transition. Enable/disable cannot alter session generation; revoke must increment it exactly once without changing enabled state. An executed reset additionally carries `credential_transition`, with `before` and `after` `CredentialState(password_generation, must_change_password)`: the generation must advance by exactly one and the flag must equal the command's `require_change_at_next_sign_in` argument, while the identity transition must show enabled state and session generation unchanged. That field is excluded from serialization when absent and must be absent for every other action, so existing identity journals serialize and verify byte for byte. A correctly signed but mismatched operation or malformed transition is insufficient evidence. Nonexecution outcomes carry no transition of either kind.

Timeout, lost response or failed settlement audit keeps impact and target ownership unresolved. ADMIN reconciliation uses the original operation's signed terminal journal. Current enabled state, a later inverse operation or another revocation cannot settle that earlier request. Missing lookup retains uncertainty; authenticated cancellation can create a tombstone that fences delayed arrival. The existing human session, role and control-authority rechecks still apply.

Endpoint serialization defaults are unchanged. Golden fixtures preserve original intent/plan/bundle/command bytes, hashes and journal MACs. Upgrade tests seed unresolved endpoint executions on schema 0006, apply 0007 and reconcile with their original evidence without another provider send.

## Running the mock on its own

[The install](INSTALL.md) already runs this mock beside the gateway and the endpoint mock, and its long way creates the `mock_entra` account. What follows is for running it outside that install.

Migrate the database to head through the owner connection. Downgrading below `0007_identity_context` is refused while any identity inventory, mapping, assignment or history remains, inactive records and other tenants' data included, and below `0018_soc_actions` while any tenant keeps a row naming one of the newer actions.

Use a distinct private provider database and account file. Account JSON follows [PROVIDER.md](PROVIDER.md) and adds `"provider": "mock_entra"`. Gateway [runtime configuration](SURFACES.md) also sets that provider explicitly. Generate separate random dispatch/control secrets and an independent evidence key; preserve historical verification keys for retained operations. Keep all credentials, keys, state and configuration outside protected-agent authority.

```sh
export EXECBOUND_MOCK_PROVIDER=mock_entra
export EXECBOUND_MOCK_DATABASE_PATH=/path/to/private/identity-provider.sqlite3
export EXECBOUND_MOCK_ACCOUNTS_PATH=/path/to/private/identity-accounts.json
uv run uvicorn execbound_connectors.mock_app:create_mock_app --factory --host 127.0.0.1 --port 8011 --no-access-log
```

Provision matching synthetic gateway accounts, all four mappings, inventory and incident sources, identity resources, canonical representations and exact-action approver assignments. `execbound_harness.identity_demo.identity_bundle` provides a valid synthetic Cedar bundle to create, validate and activate through the normal ADMIN lifecycle. The mock holds its targets from `EXECBOUND_MOCK_RESOURCES_JSON` when it starts through `python -m execbound.boot` ([Providers](PROVIDER.md#local-service-configuration)), or from `IdentityStore.provision_resource` and `provision_representation` in a test harness; neither has an HTTP route.

## Verification

`tests/identity_fixtures.py` builds synthetic inventory and starts a separate authenticated identity process. Identity contract/policy/provider/schema tests cover action confusion, provenance, hard exclusions, atomic races, retained evidence and migration restrictions. Execution and surface tests cover all four actions, scoped approvals, per-action impact, current and maintained older MCP clients, Chromium review pages and uncertain-effect recovery. Startup refuses a configuration that reuses one provider's credential or key for another, and a regression test covers it.

The repository's checks are listed in `CONTRIBUTING.md` at its root. Only one PostgreSQL suite may own the guarded loopback `execbound_test` database at a time. Browser screenshots are synthetic temporary artifacts; credentials and browser storage are not captured.

This page describes the mock. The real Microsoft Graph binding for `identity.disable` is in [Providers and the credential boundary](PROVIDER.md#a-vendor-that-co-signs-nothing); the connector checks its precondition itself, not atomically at the provider. [Replay](REPLAY.md) reproduces identity decisions offline.
