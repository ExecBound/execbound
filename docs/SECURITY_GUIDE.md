# Security and the trust center

This page is for the people who run ExecBound: what to set up so it protects what it should, and where to read what ExecBound claims about itself. The claims, the threat model and the evidence for each one are on the [trust center](https://trust.execbound.ai).

## What ExecBound protects, and what it cannot

ExecBound decides before an action runs, and it performs the action with a provider credential the agent never holds. That protection holds only on a path the agent cannot go around. An agent that also holds the provider's own credential, or a host that can call the provider directly, can skip ExecBound entirely, and a decision on that path is a recommendation rather than a control. Each integration records which kind of path it is, and [the enforcement modes](INTEGRATIONS.md#enforcement-modes) say what each kind can claim.

So check the agent's own reach first. Remove every provider credential from its environment, and send its calls for protected actions through ExecBound.

## API keys

- Give each tool that calls ExecBound its own agent and key: a coding agent, an MCP server, a workflow. Activity then shows which one acted, and you can revoke one without the others. [Authentication](https://docs.execbound.ai/api/agent#description/authentication) in the API reference says how.
- Keep the key in the tool's secret store, not in a file the agent can read or a prompt it can repeat. ExecBound shows the key once and keeps only its hash.
- Choose the shortest lifetime the tool can live with. A key that never expires stays valid until you revoke it.
- To replace a key, issue a new one, update the tool, then revoke the old one. Issuing a key never revokes another. A revoked or expired key can be deleted from the list; the audit history keeps it.
- For a script or a coding agent that calls the console API itself, an administrator creates their own personal access token from **My account → Personal access tokens** instead of sharing a sign-in; if they have enrolled a second factor, it must have been verified in the last thirty minutes, and an administrator with none enrolled is not asked for one. Lifetimes are the same choices, one hour to 90 days or Never; the token acts as its owner except that it can never decide an approval, loosen enforcement, change people, access or sign-in, or manage tokens or its owner's own account. Any administrator can revoke a token from **Workspace settings**, effective on its next request; a revoked or expired one can then be deleted. [Authentication](https://docs.execbound.ai/api/console#description/authentication) in the console API reference says what a token can and cannot do.

## People and sign-in

- Give administrator access only to the people who manage the workspace. A reviewer needs review permissions for the actions and targets they approve, and nothing more.
- Require MFA. A workspace administrator can require it for administrators or for everyone, from Account security. Enroll your own factor and save your recovery codes first. Passkeys are a second factor, not a replacement for the password.
- Sensitive account and access changes ask anyone with a factor enrolled for MFA verified within the last thirty minutes; someone with none enrolled is never asked, which is why requiring MFA matters. When it is older, the console asks for a code in a dialog over the page and then finishes the change; nothing you had open is lost.

## Approvals and evidence

- An approval authorizes one specific plan. It expires, and it is used by one execution at most.
- Every decision and execution is recorded in the audit history. Export it and check it offline with [replay](REPLAY.md), which never executes anything or changes live state.

## Running it yourself

On your own host or cloud account, you hold what the hosted service holds for you.

- Keep provider credentials, runtime configuration and signing material where the agent cannot read or write them. [Where credentials live](CREDENTIALS.md) lists each one.
- Terminate TLS in front of the gateway and keep the database reachable only by ExecBound. [The image and its processes](DEPLOYMENT.md) covers placement, and [retention, backup and recovery](RECOVERY.md) covers backups.

## The trust center

[trust.execbound.ai](https://trust.execbound.ai) publishes:

- [The threat model](THREAT_MODEL.md): who can act on ExecBound, what each trust boundary must hold, and the residual risks.
- [Architecture and data flow](ARCHITECTURE.md).
- [Where credentials live](CREDENTIALS.md).
- [The acceptance inventory](ACCEPTANCE_TESTS.md): every required behavior, and the test that shows it holds. The hosted service's own rows are kept with the service, and a row whose test is not published says so.

To report a vulnerability, follow [the security policy](../SECURITY.md), which the [disclosure page](https://execbound.ai/security.html) repeats.
