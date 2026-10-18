# Glossary

The words the console, the API and these pages use, in plain terms.

| Term | Meaning |
| --- | --- |
| Action | One consequential thing an agent can ask for, such as `endpoint.isolate` or `identity.disable`. The [action catalog](ACTION_CATALOG.md) lists them. |
| Admin consent | How a Microsoft Entra directory is connected from the console: a Global Administrator or Privileged Role Administrator of the directory signs in with Microsoft and approves read-only access for the deployment's own app (the platform app). Only the directory withdraws it, by removing the app's enterprise application; revoking the connection here stops collection. |
| Agent | A tool that calls ExecBound: a coding agent, an MCP server, a workflow. Each has its own identity, API keys and activity. |
| API key | An agent's credential, sent as `Authorization: Bearer <API key>`. Shown once when issued; revocable; expires unless issued to never expire. |
| Approval | A person's decision on one pending request. It authorizes that exact plan once, before its deadline, and nothing else. |
| Approval deadline | How long a pending request waits for a decision: 120 seconds unless an administrator sets it between 120 and 3,600 seconds or turns it off. |
| Audit history | The append-only record of every request, decision, approval and change. [Replay](REPLAY.md) checks it offline. |
| Budget | A policy limit on how many distinct targets an action may touch in a window, before it asks a person or refuses. |
| Bundle | A compiled policy: the Cedar ExecBound decides with, its budgets and its settings. Written once and never changed. |
| Checkpoint grant | The answer when an external executor, not ExecBound, performs the action: what it may do once, and the secret that settles it. Neither an execution nor an approval. See [the external execution checkpoint](CHECKPOINT.md). |
| Collector | The process that collects monitoring connections on their schedule. It alone holds what opens a connection's credential: operator key files, the private key that opens a key pasted in the console, and the platform app's certificate. The web service holds only the collector's public key and the platform app's public values. |
| Connector account | A provider account ExecBound acts through, holding the credential the agent never sees. |
| Continuation | A short-lived signed token a pending approval's answer carries, for reading its status. Not an approval. |
| Emergency stop | An administrator's switch that stops a workspace admitting, deciding or dispatching anything new. Requests answer 423 `TENANT_STOPPED` until it is lifted. |
| Enforcement mode | How much a path's decision can actually prevent: native, integrated, embedded, advisory, observed or unknown. See [the enforcement modes](INTEGRATIONS.md#enforcement-modes). |
| Execute, Gate, Monitor | The three placements. Execute: ExecBound performs the action. Gate: ExecBound decides and an external executor performs it. Monitor: ExecBound observes and alerts, and prevents nothing. |
| Decision coverage | For each Space and each action its active policy can hold, how many people can decide it now, and which recently requested resources nobody, or too few, can. Shown to a workspace administrator on Approval rules; a preview, checked again when a request is reviewed. |
| Effect unknown | An outcome whose effect nobody has established, such as an executor reporting failure after the call went out. It stays open on Home until an administrator settles it from evidence. |
| Execution | One proposed action and everything that happened to it, from the request to its outcome. |
| Fact | Something ExecBound knows about a target from a trusted source, such as its environment or its incident's severity. Never taken from the agent's request. |
| Idempotency key | The key that makes a repeated request return the same execution instead of acting twice. Derived from `reference` when the agent sends one. |
| Incident | The case an action responds to. The agent names it; ExecBound reads its status and severity from its own sources. |
| Lapsed | An approval whose deadline passed before anybody decided it. The console says so as soon as the deadline passes; nothing ran, and the agent must send a new request. An approval a person approved and the agent did not use in time reads "Approved, but not used". |
| Mapping | The link from an action a workspace offers to the provider operation that performs it. |
| Observe-only | A mode in which nothing is executed and each request records what would have been decided. |
| Overdue (collection) | A monitoring connection no collection run has been recorded for in a day (one the collector opens itself, such as a sealed key's, in twice its own interval if that is sooner), or no inventory sync in two days. Monitoring says so in place of "Collecting"; what it shows may be out of date. |
| Plan hash | A fingerprint of the frozen plan: the action, target, facts and settings a decision was made on. An approval is bound to it. |
| Policy | What agents may do on their own, what needs a person, and what never happens. Written as a ruleset. See [Write a policy](POLICY_GUIDE.md). |
| Platform app | The deployment's own Microsoft Entra app registration, which every directory that gives admin consent consents to. It holds read-only permissions only, and its certificate, which reads every consenting directory, is the collector's alone. |
| Quorum | How many different people must approve a request a rule sends for review, from 2 to 5. |
| Quiet (monitoring) | A reporting source whose heartbeat went stale, or a collection that is overdue. The count beside Monitoring shows quiet items when no finding is open. Quiet is not evidence that nothing happened. |
| Reference | The ticket, case or run an action answers, sent with the request. ExecBound derives the idempotency key from it. |
| Reporting source | One Tines story registered to send events about itself to ExecBound's intake, with its own token. The token authorizes intake for that story only: it cannot run actions, approve requests or read anything. It is minted from the console where the deployment connects Tines there, for 1, 7 or 30 days, or from the command line for up to 24 hours, and is shown once. See [Tines monitoring](TINES_MONITORING.md#add-a-reporting-source-from-the-console). |
| Request reference | The short workspace-unique name of an execution, such as `EB-1042`. See [request references](REQUEST_REFERENCES.md). |
| Reviewer | A person with review permissions for an action and target, who may approve or deny it. |
| Rule | One line of a policy: an action, an effect (`ALLOW`, `DENY` or `REVIEW`) and the conditions it applies under. |
| Sealed key | A monitoring key pasted in the console, encrypted to the collector's public key before it is stored, bound to its workspace and connection. This web service cannot read it back; only the collector opens it. |
| Space | A partition of a workspace with its own agents, active policy and budgets. |
| Target | The thing an action acts on: an endpoint, an identity. |
| Trusted context | The facts a decision is made on, each from a source ExecBound trusts and no older than the policy allows. See [trusted context](CONTEXT_CONTRACTS.md). |
| Unrouted request | A held request fewer people can decide than it needs, so it cannot be approved as things stand. A workspace administrator is told on Home and Approvals, with a link to the request and to decision coverage. |
| Workspace | One organization's ExecBound, with its own users, agents, policies and data. The API and data model call it a tenant. |
