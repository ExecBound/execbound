# Where credentials live

ExecBound's central promise is that an agent can ask for an action but never hold the credential that performs it. This page lists every credential ExecBound keeps, the form it is kept in, where it is kept and who can read it, and it says plainly where that protection ends. It was checked against the source on 2 October 2026. The [threat model](THREAT_MODEL.md) carries the threats behind it, with evidence and status.

## What an agent holds

An agent holds one credential: its own ExecBound token, in the form `eb1.<tenant>.<credential>.<secret>`, which the console calls its API key. An administrator issues it ([Get an API key](https://docs.execbound.ai/api/agent#description/authentication)), for up to 90 days or to never expire; a key that never expires stays valid until it is revoked. The console chooses no lifetime for an agent's key: the person picks one, and a Tines story or another long-running integration usually needs 30 or 90 days. The key records when it last authenticated (`last_used_at`), at most once a minute and only after every check has passed, for display; nothing authorises by it. A key issued with **Rotate** names the live key of the same agent it replaces (`replaces` on the issue route, recorded in `replaces_credential_id`), and the old key keeps working until it is revoked. It opens only the agent routes: proposing an action, reading the status of its own requests, listing the actions its own space offers, and reading back its own identity. Over MCP those are three tools, `execute`, `execution_status` and `list_actions`. Two more routes accept it in narrower cases: an external executor reports what it did with a grant through `POST /v1/executions/{id}/outcome`, which also requires that grant's own report secret, and where an `arcade` block is configured, a control point's two hook routes take it ([Arcade logic extension](ARCADE.md)).

An agent **never receives a vendor credential, in any form.** The connector adds it to the request on the gateway's side, and sends the request to a destination the operator configured, which the agent cannot choose. There is no route that returns configuration, a vendor credential, a signing key or a control store, and no generic passthrough tool.

The one signed thing an agent can receive is a continuation, handed back while a request waits for approval. It is a capability rather than a credential: bound to the tenant, the agent, its credential, the one execution and approval, the plan and a nonce, and expiring within two minutes at most. Its signing key never leaves the gateway.

## What an administrator's own token holds

An administrator can also create their own bearer token for the console API: `ebp1.<tenant>.<token>.<secret>`, from **My account → Personal access tokens**. If they have enrolled a second factor, it must have been verified in the last thirty minutes, and the console asks for a code over the page when it was not; an administrator with none enrolled is not asked for one. It lives in its own table, `personal_access_tokens`, held only as the SHA-256 digest of the whole token and shown once. Minted alongside it, in the same statement, is an ordinary **backing credential** in the `credentials` table an agent's key also lives in, held only as its own digest. The console's own credential lists leave it out, so a token is never mistaken for one more agent key, though the CLI's `credential-list` reads the `credentials` table directly and still shows it; its id is what an audit event names as `actor_credential_id` when a token causes it. Revoking or deleting the token does the same to its backing credential, and losing the credential (a password reset, a change of role, a deactivation) ends the token too, even though nothing in `personal_access_tokens` was touched.

Its lifetime is the agent-key choices, one hour to 90 days or Never, 30 days by default, and it stops working the moment its owner leaves the workspace, is deactivated, or is no longer an administrator, whether or not anyone revoked it. Its owner or any other administrator of the workspace can revoke it from Workspace settings, taking effect on the token's own next request; a revoked or expired token can then be deleted, and the audit chain keeps its issue, revoke and delete events. It carries its owner's authority with named exceptions it can never reach: deciding an approval, loosening enforcement, changing people, access or sign-in, changing a monitoring credential or acknowledging findings in bulk, or managing tokens or its own owner's account, all detailed in the threat model's [human browser](THREAT_MODEL.md#b4-human-browser-to-human-surface) and [owner tooling](THREAT_MODEL.md#b5-owner-tooling-admin-and-policy) boundaries and the [API reference](https://docs.execbound.ai/api/console)'s Authentication section.

## Four forms, from the least useful to an attacker

1. **Not kept at all, only a digest.** A copy of the database yields nothing that can be turned back into the credential.
2. **Only a public key.** The private half never reaches ExecBound.
3. **Encrypted in the database.** AES-256-GCM under a key ring kept in the deployment's private configuration, so the database alone yields ciphertext.
4. **In the deployment's private configuration or environment, never in the database.** Protected by the host and file permissions, not by encryption.

## Every credential

| Credential | Form | Where | Who can read it |
| --- | --- | --- | --- |
| Agent token | SHA-256 digest; the token is shown once, when issued | Database | Nobody: only the digest exists |
| An administrator's personal access token, and its backing credential | SHA-256 digests of each; the token is shown once, when issued | Database (`personal_access_tokens`, and `credentials` for the backing credential) | Nobody: only the digests exist |
| Session and form-protection tokens for people | SHA-256 digests | Database | Nobody |
| Invitation and sign-up codes | Digests | Database | Nobody |
| Recovery codes | A domain-separated SHA-256 digest of 96 random bits; shown once | Database | Nobody |
| Passwords | scrypt; the database refuses any other algorithm | Database | Nobody can reverse one. A stolen hash can only be attacked by guessing, which scrypt makes slow, so a weak password is still a weak password |
| Monitoring source tokens | SHA-256 digest; the token is written once to a file the operator creates, or shown once in the console where the deployment connects Tines from it (`Cache-Control: no-store`, held in the dialog's state alone), and lives at most 30 days | Database, and the operator's file or the Tines credential the administrator puts it in | Whoever holds that file or credential. The token authorizes intake for one story only: it cannot run actions, approve requests or read anything |
| Security signal producer tokens | A SHA-256 digest the gateway's own role cannot read; the token is written once to a file the operator creates | Database, and the operator's file | Whoever holds the operator's file |
| Gate report secrets | SHA-256 digest; the secret is returned once, with the grant | Database | Nobody: only the digest exists |
| Arcade report secrets | The secret itself, while its grant is live, cleared when the grant settles | Database, in the Arcade correlation table | A reader of that row can settle that one grant's execution, and nothing else (the threat model's R17) |
| Passkeys | The public key and a signature counter | Database | The private key never leaves the person's authenticator |
| Executor signing keys | Ed25519 public keys only | Database | The private key never leaves the executor, so nothing on ExecBound's side can forge an executor's report |
| Authenticator seeds for multi-factor sign-in | AES-256-GCM | Database, key in the private configuration | A process that can read the deployment's private configuration |
| A customer's identity provider: client secret and refresh token | AES-256-GCM, bound to the tenant, the provider and the purpose, so ciphertext moved to another row does not open | Database, key in the private configuration | A process that can read the deployment's private configuration |
| A monitoring collection's vendor management key | The key in a file the operator keeps; only its SHA-256 fingerprint in the database | The operator's file | The operator |
| Vendor credentials for connectors, and their evidence keys | Plain values in the private configuration file | Never the database | A process that can read the private configuration. The connector sends them; the agent cannot. Reusing one across vendor families is refused at startup |
| Continuation signing keys | Private configuration | Never the database | Same |
| Provider journal keys for checkpoints, which verify a provider's journal and sign nothing | Private configuration | Never the database | Same |
| The sample key, one secret behind every workspace's sample connection to the endpoint mock | Private configuration | Never the database | Same. It reaches synthetic targets only (the threat model's R28) |
| Slack and Teams webhook addresses, where the address is itself the secret, and the shared secrets of signed webhooks | Private configuration | Never the database | Same |
| Google and GitHub sign-in client secrets, the mail relay password, the assistant's model key, the multi-factor key ring | The private configuration file, or the environment: started through `python -m execbound.boot`, a value from the environment is merged into the owner-only configuration file the module writes and removed from the environment | Never the database | A process that can read the private configuration |
| Scout's directory read credential | A file the operator keeps, for a read-only registration held separate from any registration that performs actions | Never the database | The operator |
| Database role passwords | The deployment's environment | Never the database | The operator |

**No vendor credential is stored in the database.** The database holds digests, public keys, the two kinds of ciphertext above, and one usable secret: an Arcade report secret while its grant is live.

## What protects them

- **Against the agent:** the gateway's routes and the database's permissions. The role the gateway runs as cannot write to principals, credentials or approval scopes, and reaches them only through a small set of audited database functions, which is also how the console's administration pages act. The owner connection that migrations and owner commands use has no web route at all.
- **Against a copy of the database:** a backup, a replica or a query that reaches the tables yields digests, public keys and ciphertext, none of which performs an action on its own, and any Arcade report secret still live, each of which can settle its own grant's execution and nothing else.

## Where the protection stops

These limits matter as much as the table.

- **Anything that can read the deployment's private configuration can open every encrypted secret and use every vendor credential.** The key ring and the vendor credentials live there, so the configuration file and the environment are the custody. There is no managed key service or secret manager yet.
- **Never run an agent where it can read the gateway's configuration.** Put it on another host, in another container, or at the least under another operating system account with no read access to the configuration file. On one machine under one account, an agent that can read files can read the configuration, and the only protection left is the gateway's routes. The enforcement is only native where this holds, which is why the first step of the demonstration calls the provider directly with the agent's own credential and is refused.
- **Make the configuration files owner-only.** The files ExecBound writes itself, such as those `execbound init` and the boot module create, are written owner-only on Linux and macOS, but the gateway does not check the mode of a file you supply. On Windows a file takes the permissions of its folder, so the folder's permissions are its protection.
- **ExecBound protects what an agent can do, not the host it runs on.** A compromised operator account, host or database owner is outside what these controls address.

## Hosted and self-hosted

- **Self-hosted:** you hold the configuration, the environment and the database. None of these credentials is sent to ExecBound.
- **Hosted Community:** ExecBound LLC operates the configuration and the database, and so can open the encrypted secrets it holds for you: your people's authenticator seeds and, if you connect one, your identity provider's client secret and refresh token. Passwords, recovery codes and tokens are hashed there too, and cannot be read back. **Hosted Community holds no vendor credentials:** its providers are ExecBound's protected mocks, and real vendor connections wait on managed key custody.

## What will change this page

- **Managed key custody** moves the key ring out of the configuration file.
- **The hybrid executor** keeps vendor credentials inside the customer's own network while using the hosted service.
- **The credential store** lets the gateway hold agents' own service credentials under that custody.

All three are designed and none is built. This page changes when one ships, not before.
