# Community and hosting

Community is the complete control plane for one organization. It runs in two ways: self-hosted, where you install and operate it, and Hosted Community, which ExecBound operates for you. Both draw the same authority boundary. The hosted service adds resource limits; it does not add authority.

The matrix below is as of 15 October 2026.

| | Hosted Community | Self-hosted Community |
| --- | --- | --- |
| Who operates it | ExecBound | You |
| Getting started | Sign up on the hosted service | [Install on one host](INSTALL.md), or [deploy it in your cloud](CLOUD_DEPLOYMENT.md) |
| Workspace lifetime | Persistent | Yours to manage |
| Agents | Three per workspace; a sleeping agent still holds a place | Not capped by the software |
| Sign-in | Accounts and the sign-in providers the service configures | Accounts and the sign-in providers you configure |
| Connectors | The ones the hosted deployment configures | The ones you configure |
| Capacity, retention and data lifecycle | The hosted service's limits, dormancy and retention apply | Yours |

An agent above the hosted cap is never cut off mid-request: the cap applies when an agent is created or woken, never to a governed request.

## Authority and integrations

Policy, shared impact limits across agents and platforms, scoped human approval, audit and replay, ordinary OIDC sign-in, the open connector and executor interfaces, security event export and replicas that share one database are all part of Community. Which adapters and distributions have actually shipped is recorded in [Integrations](INTEGRATIONS.md) and [Releases](RELEASE.md), not here.

- **Execute** dispatches through a connector ExecBound holds.
- **Gate** lets an external executor act while the customer keeps its own connectors and credentials. It is Advisory: a workflow that holds the vendor credential can still act without asking. An importable Tines Gate recipe has been qualified in a live trial ([Integrations](INTEGRATIONS.md)).
- **Monitor** supplies visibility and alerts, never execution authority. A credential used directly, outside a governed path, bypasses it.

Community onboarding needs neither managed credential custody nor custom actions. Supported operation across independent estates, SAML and SCIM, managed custody and contractual services are Enterprise. Community replicas sharing one PostgreSQL are a different thing from that.

## Persistence

Workspace access does not expire. Invitations, credentials, sessions and approvals still expire on their own clocks.

On the hosted service, an agent that governs nothing for ninety days goes to sleep, and any governed request in the meantime starts the ninety days again. Fourteen days before a workspace's agents would sleep, the service tries to send each of its workspace administrators one email giving the date. That email is best effort, not a promise: sleep never waits for it, a workspace that reaches that point late is told with less notice, and an administrator can go without one, for example on a day the service's outgoing mail is at its limit or when no address is on file. Administrators keep their access, a sleeping agent still counts toward the allowance, and it can be woken. Dormancy deletes no history, and contact retention and audit retention are separate.

The optional seeded examples use synthetic data and the protected mock providers. They add no real connector and grant no permission to act on an organization's systems.

## Licences and releases

- **AGPL-3.0-only:** the server, the console and the tests, under the root `LICENSE`. The console's fonts are OFL-1.1.
- **CC BY 4.0:** the documentation (`docs/LICENSE`).
- **Apache-2.0:** what runs in your own code or is copied into your configuration, each directory with its own `LICENSE`:
  - the Python client (`clients/python/`), the provider protocol (`protocol/`) and the connectors (`connectors/`);
  - `examples/`, `integrations/` and `deploy/`;
  - the install bundle (`src/execbound/data/community/`), the starter policy packs (`src/execbound/data/starters/`) and the MCP recipes (`src/execbound/surfaces/templates/recipes/`).
- **The internal-use licence:** an organization whose policies do not allow AGPL software can ask ExecBound LLC for the server and console under the PolyForm Internal Use License 1.0.0, free (`INTERNAL_USE_LICENSE.md` at the repository's root).
- **Trademarks:** "ExecBound" and its mark are trademarks of ExecBound LLC, with a policy for their use in `TRADEMARK.md`; contributions are made under `CONTRIBUTOR_AGREEMENT.md`.

Each release is a signed image with its SBOM, provenance and release record. [Releases](RELEASE.md) describes what a release publishes and how to verify it.
