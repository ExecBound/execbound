# Audit event reference

Every change ExecBound makes inside a workspace appends one event to that workspace's audit chain, in the same transaction as the change, so a change whose event cannot be appended does not happen. Some refusals of an authenticated principal's request, or of a scheduled job's reconciliation, are recorded too, on a best-effort basis, as `execution.rejected`; that kind's row below says which, and no other refusal appends one. This page names every kind of event the chain can carry, when each is written and which fields its payload holds. A test holds it to the code: a kind written by a module or known to [replay](REPLAY.md) and missing here fails the build, as does a kind listed here that nothing knows, and so does a payload field a writer names that its row leaves out, or a field a row names that no writer of its kind is seen to write, apart from a reviewed few the test lists because they reach the payload through a helper it cannot read.

## Reading an event

Each event is one row of `audit_events`, and the replay export and the security event export carry exactly these fields:

| Field | What it is |
| --- | --- |
| `tenant_id` | The workspace the event belongs to. Each workspace has one chain. |
| `sequence` | The event's position in that chain, from 1 with no gaps. |
| `event_id` | The event's own identifier. |
| `actor_id` | The principal that acted (see below). |
| `kind` | One of the kinds on this page. |
| `occurred_at` | The database's clock when the event was appended, in UTC. |
| `payload` | A JSON object, at most 16 KiB, whose fields depend on the kind. |
| `previous_hash` | The `event_hash` of the event before it, or 64 zeros for the first. |
| `event_hash` | SHA-256 of the canonical JSON of the event's envelope, which links the chain. |

**The actor** is the principal on whose authority the change was made: an agent for its own requests, a person for what they do in the console, the administrator an owner command names with `--actor`, and the workspace's scheduler principal (kind `SYSTEM`) for what a scheduled job does. A person who signs in to several workspaces is a different principal in each. Many kinds also carry `actor_credential_id`, the credential that acted: a console session's, an API key's, or a personal access token's own, so a token's actions map to the token that took them. An owner command acting without a credential adds nothing.

**Withheld values.** An identity provider's subject and a directory's issuer are never refused for looking like a secret, because the provider has already vouched for them. Where one does look like a secret, the payload carries the literal `WITHHELD` in that field and the value's unkeyed SHA-256 beside it under `subject_digest` or `issuer_digest`. Tell a withheld value by the digest field, not by the literal, which a plain value may spell. Other text that people, agents and platforms write is screened before it reaches the chain, and refused where it is written if it is shaped like a password, key or token; the [threat model](THREAT_MODEL.md#residual-risks) lists what those screens do not reach.

**Payloads only grow.** A field is added to a kind as the product grows, which changes the bytes of events appended afterwards and of none already in the chain. New kinds are added too. A consumer should tolerate a field or a kind it does not know.

**What replay reads.** Five kinds carry decisions replay reconstructs: `execution.evaluated`, `execution.transition`, `approval.transition`, `tenant.stop_activated` and `tenant.stop_released`. Every other kind on this page is informational to replay: it explains a later fact and decides nothing a replay recomputes. A kind replay does not know makes a workspace's export `UNSUPPORTED`, because the chain is append-only, so a new kind is registered with replay in the same change that first appends one.

**Where you see them.** `execbound audit-export` writes a workspace's chain for [replay](REPLAY.md), and `execbound export-events` posts it to a security event destination in sequence order ([operations](OPERATIONS.md#structured-logs-and-security-event-export)). Both read the chain and never write it. The application's own JSON logs are a separate, closed catalogue of operational events and carry none of these payloads.

The hosted service appends a few kinds of its own for its plan and signup lifecycle; they are documented with the hosted service.

## Requests and executions

| Kind | Written when | Payload |
| --- | --- | --- |
| `execution.evaluated` | Policy evaluated an agent's request at admission, or again when a person reviewed it. The payload is the decision capture replay reconstructs the decision from: the frozen request, the identity and bundle it was decided under and the evaluation itself. `mode` is present only for an observed decision. The actor is the agent at admission and the reviewer at review. | `version`, `stage`, `execution_id`, `operation_id`, `canonical_target_id`, `semantic_time`, `usage_time`, `finished_time`, `identity`, `frozen`, `bundle_id`, `decision`, `approval`, `reviewer`, `human_decision`, `mode` |
| `execution.transition` | An execution moved from one state to another: admitted, denied, held for approval, reserved, committed to dispatch, settled, or corrected by an administrator. `from_state` is null for the first transition. `request_ref` is the request's human reference when it has one, `external_case` appears on the first transition when the request named a case, and the transition adds its own detail, such as a `reason` or a settlement's evidence and tier. | `execution_id`, `from_state`, `to_state`, `intent_hash`, `plan_hash`, `operation_id`, `replay`, `request_ref`, `external_case`, `reason` |
| `execution.rejected` | A request from an authenticated principal, or a scheduled job's reconciliation, was refused. An operation records its own refusal: an admission, an outcome report, a reconciliation, an approval decision, an emergency stop's activation or release, or a change of enforcement mode or of the approval deadline. A surface records refusals of its own as `surface`: the agent HTTP, MCP and Arcade surfaces record most refusals of a request made to them, such as one that does not parse or one made with a credential that is not an agent's, and the console and the human pages record refusals such as a failed CSRF check, an invalid continuation, or a personal access token asking for a route it may not use or a change it may not make. `operation` names what was refused and `reason` is the refusal code ([error and refusal codes](ERROR_CODES.md)). `route` and `method` appear when the refusal knows them. The record is best effort: when it cannot be appended, the request is refused all the same and no event is written. Many other refusals append nothing, among them the console's role and body checks made before an operation runs (a person whose role does not allow the change, a body that does not validate), a rate limit's refusal, a refusal by the Arcade tool map, and any refusal of a caller that never authenticated, which is not attributable. | `operation`, `reason`, `actor_credential_id`, `route`, `method` |
| `execution.dispatch_attempt` | The gateway took an execution's one send attempt to its provider. A lost reply never grants another. The actor is the agent that requested it. | `execution_id`, `plan_hash`, `operation_id`, `precondition_class` |
| `execution.reconciliation_requested` | An administrator or the recovery run asked the provider what became of an operation whose outcome is uncertain. | `execution_id`, `operation_id`, `plan_hash`, `reason`, `cancel_if_missing` |
| `execution.cancellation_requested` | During a reconciliation that asked for it (`cancel_if_missing`), the provider had no record of the operation, so ExecBound asked it to cancel rather than run it later. | `execution_id`, `operation_id`, `plan_hash`, `reason` |
| `execution.checkpoint_granted` | Admission issued, or issued again, a grant for an operation an external executor performs: the deadlines to act and to report, and the precondition class. | `execution_id`, `operation_id`, `plan_hash`, `precondition_class`, `act_expires_at`, `report_expires_at`, `regranted` |
| `execution.outcome_reported` | An external executor's report was accepted, at the tier its evidence supports. The settlement it leads to is the `execution.transition` beside it. `reported_at` is the executor's own clock, and null when the report carries evidence. | `execution_id`, `operation_id`, `plan_hash`, `outcome`, `reason`, `tier`, `reported_at` |
| `execution.claim_released` | The recovery run released the target claim an asserted settlement still held once its act window closed. The execution stays settled at the tier and impact it had. | `execution_id`, `operation_id`, `plan_hash`, `settlement_tier`, `reason` |
| `execution.control_point_contradiction` | An Arcade control point reported on a call ExecBound denied, or one whose own inputs describe a different request from the one the decision froze. This is evidence of a misconfiguration or a bypass, not proof of one. The platform's own `toolkit`, `tool_name` and `tool_version` are kept, or `tool_identity` is `WITHHELD` in their place when they look like a credential; the execution's identifiers appear when the call was matched to one. | `contradiction`, `tool_identity`, `toolkit`, `tool_name`, `tool_version`, `execution_id`, `operation_id`, `plan_hash` |

## Approvals

| Kind | Written when | Payload |
| --- | --- | --- |
| `approval.transition` | An approval was approved, denied, expired, invalidated, or consumed by the execution it authorized. `binding` records the decisions it stands on, and `comment` is present only when a reviewer left one. | `execution_id`, `approval_id`, `from_state`, `to_state`, `plan_hash`, `binding`, `replay`, `comment` |
| `approval.decision_recorded` | A reviewer approved, but the approval needs more approvers than have approved so far, so it keeps waiting. The approval's own state changes in `approval.transition`. | `execution_id`, `approval_id`, `plan_hash`, `binding`, `replay`, `comment` |
| `approval_scope.assigned` | An administrator made a person an approver for one action on one canonical target, or reactivated that assignment. | `approver_id`, `canonical_target_id`, `action`, `actor_credential_id` |
| `approval_scope.revoked` | An administrator removed that assignment. Pending decisions under it then fail their scope check. | `approver_id`, `canonical_target_id`, `action`, `actor_credential_id` |
| `approval_rule.changed` | An administrator saved or disabled an approval rule, which routes requests to a reviewer group by space, action and target. | `rule_id`, `change`, `reason` |
| `tenant.approval_deadline_changed` | An administrator changed how long a new approval may wait, or turned the deadline off. Approvals already pending keep the expiry they were created with. | `previous`, `seconds`, `reason`, `principal_id`, `credential_id`, `actor_credential_id`, `replay` |

## Emergency stop and enforcement mode

| Kind | Written when | Payload |
| --- | --- | --- |
| `tenant.stop_activated` | An administrator activated the emergency stop: new admissions, approval decisions and dispatch attempts halt. `dispatch_committed` counts what was already committed to dispatch. | `stop_id`, `reason`, `principal_id`, `credential_id`, `actor_credential_id`, `replay`, `dispatch_committed` |
| `tenant.stop_released` | An administrator released it. Nothing it halted is retried or resumed automatically. | `stop_id`, `reason`, `principal_id`, `credential_id`, `actor_credential_id`, `replay` |
| `tenant.mode_changed` | An administrator switched the workspace between enforcing and observing. | `previous`, `mode`, `reason`, `principal_id`, `credential_id`, `actor_credential_id`, `replay` |

## Policy

Replay reads the five `policy.bundle_*` kinds to check that each one's `content_hash` is the hash of the bundle the export carries under its `bundle_id`; a mismatch refuses the export. They decide nothing beyond that. Replay compares no hash for `policy.ruleset_compiled` or `policy.rules_changed` and decides nothing from them: it reads a bundle's content from the export's own bundles, never from their payloads.

| Kind | Written when | Payload |
| --- | --- | --- |
| `policy.bundle_created` | A policy bundle was written as a draft. | `bundle_id`, `content_hash`, `actor_credential_id` |
| `policy.ruleset_compiled` | A draft was compiled from a ruleset; written beside its `policy.bundle_created`. | `bundle_id`, `content_hash`, `rules`, `budgets`, `actor_credential_id` |
| `policy.rules_changed` | A person edited a draft's rules, which writes a successor draft. `supersedes` names the draft it replaced; the two drafts' own lifecycle events stand beside it. | `bundle_id`, `supersedes`, `content_hash`, `rules`, `budgets`, `actor_credential_id` |
| `policy.bundle_validated` | A draft passed validation against the catalog and its mappings. | `bundle_id`, `content_hash`, `actor_credential_id` |
| `policy.bundle_activated` | A space selected a validated bundle, so it decides that space's requests. | `bundle_id`, `content_hash`, `space_id`, `actor_credential_id`, and `reason` when one was given (every console activation, and `bundle-activate --reason`) |
| `policy.bundle_deselected` | A space stopped selecting a bundle that no other space still selects. | `bundle_id`, `content_hash`, `space_id`, `actor_credential_id` |
| `policy.bundle_retired` | A bundle was retired and can no longer be selected. | `bundle_id`, `content_hash`, `space_id`, `actor_credential_id` |

## Agents, credentials and keys

| Kind | Written when | Payload |
| --- | --- | --- |
| `principal.created` | A principal was created: an agent, a person, or the workspace's scheduler principal (kind `SYSTEM`) just before the first event it acts in. | `principal_id`, `kind`, `actor_credential_id` |
| `principal.labelled` | A principal was given a display name, when it was added in the console, named later, or invited with `person-invite`. | `principal_id`, `label`, `actor_credential_id` |
| `principal.deactivated` | A person switched a principal off. Its credentials and sessions are revoked in the same transaction, each with its own event. | `principal_id`, `reason`, `credentials_revoked`, `sessions_revoked`, `actor_credential_id` |
| `principal.reactivated` | A person switched it back on. | `principal_id`, `actor_credential_id` |
| `agent.bound` | A discovered agent was bound to the principal that governs it. | `binding_id`, `agent_id`, `principal_id`, `actor_credential_id` |
| `agent.unbound` | That binding was withdrawn. | `binding_id`, `agent_id`, `principal_id`, `reason`, `actor_credential_id` |
| `credential.issued` | An API key or another credential was issued to a principal. Its secret is never in the chain. With Rotate, `replaces` names the live key of the same agent the new key replaces; an issue without it writes no such key. | `credential_id`, `principal_id`, `kind`, `expires_at`, `replaces`, `actor_credential_id` |
| `credential.revoked` | A credential was revoked: by an administrator, because its principal was switched off or promoted, because a set-password code was redeemed, or because the directory account behind it was refused, unlinked or disabled. `reason` says which, and is absent for a plain revocation. | `credential_id`, `principal_id`, `reason`, `actor_credential_id` |
| `credential.deleted` | A revoked or expired API key was taken out of every list. Its issue and revocation stay in the chain. | `credential_id`, `actor_credential_id` |
| `personal_token.issued` | An administrator minted a personal access token for themselves. | `token_id`, `credential_id`, `name`, `expires_at`, `actor_credential_id` |
| `personal_token.revoked` | A personal access token was revoked. | `token_id`, `actor_credential_id` |
| `personal_token.deleted` | A revoked or expired personal access token was deleted from the list. | `token_id`, `actor_credential_id` |
| `group.created` | A principal group, which limit rules and signal sources can name, was created. | `group_id`, `name` |
| `group.assigned` | An agent was added to a group. | `group_id`, `principal_id` |
| `group.revoked` | An agent was removed from a group. | `group_id`, `principal_id` |
| `executor_key.registered` | An external executor's public key was registered. | `key_id`, `algorithm` |
| `executor_key.rotated` | A new key replaced the previous one in one step. | `key_id`, `previous_key_id`, `algorithm` |
| `executor_key.revoked` | A key was retired. Grants issued while it was current still verify. | `key_id` |
| `executor_key.compromised` | A key was cut off as compromised: it attests nothing, whenever the grant was issued. | `key_id` |

## Connector accounts, targets and context

| Kind | Written when | Payload |
| --- | --- | --- |
| `account.created` | A connector account was created for a provider. | `account_id`, `provider` |
| `mapping.created` | A catalog action was bound to an account's provider operation. | `operation_ref`, `account_id`, `provider`, `action`, `mapping_version`, `context_contract_version` |
| `target.created` | A canonical target was created. | `canonical_target_id` |
| `resource.created` | A provider resource was registered as a target, with its aliases. | `resource_id`, `account_id`, `provider`, `resource_type`, `provider_id`, `version`, `canonical_target_id`, `aliases` |
| `context_source.created` | A trusted context source was created, with the writers allowed to attest through it. | `source_id`, `account_id`, `kind`, `allowed_writers` |
| `context_source.deactivated` | A context source was deactivated; every fact it attested then fails resolution. | `source_id` |
| `context.imported` | A context manifest was applied. The payload carries the manifest's digest and counts, never an entry's value. | `source_id`, `account_id`, `kind`, `writer`, `manifest_digest`, `manifest_bytes`, `entries`, `applied`, `unchanged`, `unknown_resources`, `facts_written`, `facts_retracted`, `resources_deactivated`, `incidents_created`, `incidents_updated` |
| `signal_source.created` | A security signal producer was registered, with what it may attest and for whom. | `source_id`, `space_id`, `offered_tenant_wide`, `label`, `producer_name`, `producer_version_min`, `producer_version_max`, `capabilities`, `subject_kinds`, `principal_ids`, `principal_group_id`, `placement`, `input_path`, `attests_liveness`, `expires_at` |
| `signal_source.rotated` | A producer's token was replaced; the previous one works for the grace window. | `source_id`, `expires_at`, `grace_seconds` |
| `signal_source.revoked` | A producer was revoked: every token stops and every fact it attested fails. | `source_id` |
| `samples.installed` | An administrator installed the sample targets and their starter bundle. | `account_id`, `provider`, `bundle_id`, `content_hash`, `targets`, `actor_credential_id` |
| `samples.removed` | An administrator removed them. `retired` says whether the starter bundle was retired too. | `account_id`, `bundle_id`, `retired`, `actor_credential_id` |
| `demo.provisioned` | `execbound seed-demo` created one of its two synthetic workspaces. | `principal_count` |

## Spaces

| Kind | Written when | Payload |
| --- | --- | --- |
| `space.created` | A space was created in the workspace. | `space_id`, `name`, `detail`, `actor_credential_id` |
| `space.renamed` | A space was renamed. | `space_id`, `name`, `actor_credential_id` |
| `space.archived` | A space was archived: new work stops and every row stays readable. | `space_id`, `reason`, `actor_credential_id` |
| `space.unarchived` | An archived space was restored. | `space_id`, `reason`, `actor_credential_id` |
| `space.member_assigned` | A person was given a role in a space. | `space_id`, `principal_id`, `role`, `actor_credential_id` |
| `space.member_unassigned` | A person's membership of a space was removed. | `space_id`, `principal_id`, `actor_credential_id` |

## Access and roles

Each of these follows one successful access change. A change that promotes a person also ends their credentials, sessions and pending directory invitations, each with its own `credential.revoked`, `human_session.revoked` or `identity.invitation_revoked` event whose `reason` is `ROLE_PROMOTION`.

| Kind | Written when | Payload |
| --- | --- | --- |
| `access.create_group` | An administrator created a user group. | `subject_id`, `reason`, `change`, `revoked_password_resets` |
| `access.update_group` | An administrator changed a user group's name or description. | `subject_id`, `reason`, `change`, `revoked_password_resets` |
| `access.delete_group` | An administrator deleted a user group. | `subject_id`, `reason`, `change`, `revoked_password_resets` |
| `access.set_members` | An administrator set a user group's members. | `subject_id`, `reason`, `change`, `revoked_password_resets` |
| `access.set_user_roles` | An administrator set a person's roles, or an accepted invitation granted them. | `subject_id`, `reason`, `change`, `revoked_password_resets` |
| `access.group_member_added` | An invitation that named a reviewer group was accepted, and the new person joined that group. The actor is the inviter, whose authority the acceptance re-checked. | `subject_id`, `principal_id`, `invitation_id`, `reason` |
| `access.set_group_roles` | An administrator set a user group's roles. | `subject_id`, `reason`, `change`, `revoked_password_resets` |

## People, sign-in and sessions

| Kind | Written when | Payload |
| --- | --- | --- |
| `person.email_set` | A person was given the address they sign in with. Only the address's domain is recorded. | `principal_id`, `domain`, `actor_credential_id` |
| `password.reset_issued` | A one-time set-password code was minted for a person. Whatever code was pending is revoked first. | `principal_id`, `reset_id`, `expires_at`, `actor_credential_id` |
| `password.set` | A person redeemed a set-password code. Every session and credential they had ends, each with its own event. | `reset_id` |
| `password.changed` | A signed-in person replaced their password, presenting the current one, where the password belongs to this workspace's sign-in rather than to an account. An account's password change is `account_security.password_changed`. | `credential_id` |
| `human_sign_in.password` | A person signed in with a password. `kind` is the role they signed in with. | `credential_id`, `kind`, `expires_at` |
| `human_sign_in.google` | A person signed in with Google. | `credential_id`, `kind`, `expires_at`, `subject`, `subject_digest` |
| `human_sign_in.github` | A person signed in with GitHub. | `credential_id`, `kind`, `expires_at`, `subject`, `subject_digest` |
| `human_sign_in.microsoft` | A person signed in with a Microsoft work account. `subject` is the account's tenant and object identifiers, joined by a colon. | `credential_id`, `kind`, `expires_at`, `subject`, `subject_digest` |
| `human_sign_in.directory` | A person signed in through the workspace's own identity provider. | `credential_id`, `kind`, `provider_id`, `subject`, `subject_digest`, `expires_at` |
| `human_session.issued` | A console session was issued after a sign-in. | `session_id`, `credential_id`, `kind`, `expires_at` |
| `human_session.revoked` | A console session ended before it expired: signed out, ended from another device, ended by an administrator, or ended because the credential under it was. | `session_id`, `credential_id`, `principal_id`, `reason`, `actor_credential_id` |
| `workspace.entered` | A person switched their session into another workspace they belong to. | `session_id` |

## Account and account security

Most of these are written by a person acting on their own account; `account.resolve` and `account_security.requirement_changed` are an administrator's. The `account_security.*` kinds carry the session that acted.

| Kind | Written when | Payload |
| --- | --- | --- |
| `account.profile` | A person changed their own display name. The name is not copied into the chain. | `operation` |
| `account.request` | A person asked for their data, or asked to close their account or the workspace. | `operation` |
| `account.resolve` | An administrator completed or declined such a request. The response is not copied into the chain. | `operation` |
| `account_security.enrollment_started` | A person began enrolling an authenticator app. | `session_id` |
| `account_security.factor_enabled` | That enrollment was confirmed with a valid code. | `session_id` |
| `account_security.verified` | A person verified their second factor, with an authenticator code or a passkey. | `session_id`, `method` |
| `account_security.verification_failed` | A second-factor code or passkey did not verify. | `session_id`, `method` |
| `account_security.code_reused` | An authenticator code for a step this factor already used, still inside the current window, was presented again. It is not accepted and is not counted as a failure. | `session_id` |
| `account_security.assurance_carried` | A person switched into this workspace within thirty minutes of verifying their second factor in the workspace they left, so the new session carries that verification and asks for no code. Written in the workspace switched into. It names no other workspace: the workspace and session the verification came from are recorded for the account alone (see [DATA_MODEL.md](DATA_MODEL.md)). | `session_id` (the new session), `account_session_id` (the account sign-in it belongs to), `method`, `verified_at` (when the factor was verified, which the new session's thirty minutes still count from) |
| `account_security.recovery_used` | A person verified with one of their recovery codes. | `session_id`, `method` |
| `account_security.recovery_replaced` | A person replaced their recovery codes. | `session_id` |
| `account_security.factor_disabled` | A person removed their authenticator app. | `session_id` |
| `account_security.requirement_changed` | An administrator changed who in the workspace must use a second factor: no one beyond those who choose to, administrators, or everyone. | `session_id`, `requirement` |
| `account_security.passkey_added` | A person registered a passkey. | `session_id` |
| `account_security.passkey_removed` | A person removed a passkey. | `session_id` |
| `account_security.password_changed` | A person changed their account's password, presenting the current one. | `session_id` |
| `account_security.password_set` | A person who signed in another way gave their account its first password. | `session_id` |
| `account_security.provider_link_started` | A person began linking a Google, GitHub or Microsoft account to sign in with. | `session_id`, `provider` |
| `account_security.provider_linked` | That link was completed. | `session_id`, `provider` |
| `account_security.signed_out` | A person signed out. | `session_id`, `sessions` |
| `account_security.other_devices_signed_out` | A person ended their sessions on every other device. | `session_id`, `sessions` |

## Directory sign-in

| Kind | Written when | Payload |
| --- | --- | --- |
| `identity_provider.registered` | An administrator registered the workspace's own identity provider, as a draft. | `provider_id`, `issuer`, `issuer_digest`, `subject_claim` |
| `identity_provider.verified` | An administrator's own first sign-in through a draft provider verified it. | `provider_id` |
| `identity_provider.enabled` | An administrator enabled the provider for sign-in. | `provider_id`, `previous` |
| `identity_provider.disabled` | An administrator disabled it, which ends every session standing on it. | `provider_id`, `previous` |
| `identity.invited` | An administrator minted a code that lets one person link their directory account. Whatever was pending for them is revoked first. | `principal_id`, `provider_id`, `invitation_id`, `expires_at` |
| `identity.invitation_revoked` | That code was revoked before it was used. | `invitation_id`, `principal_id`, `reason` |
| `identity.linked` | A directory, Google or GitHub account was bound to a person: by the person, by an administrator, or at an invited sign-in. `via` says how, and `provider` names Google or GitHub. | `principal_id`, `provider_id`, `provider`, `subject`, `subject_digest`, `via` |
| `identity.unlinked` | An administrator removed a person's directory account, which ends every session standing on it. | `principal_id`, `link_id` |
| `identity.recheck_refused` | The identity provider refused a person when their session was rechecked, so the session's credential was ended. | `credential_id`, `provider_id`, `reason` |

## Teammate invitations

| Kind | Written when | Payload |
| --- | --- | --- |
| `invitation.created` | An administrator invited someone to the workspace by email. Only the address's domain is recorded. | `invitation_id`, `email_domain`, `grants`, `expires_at`, `reviewer_group_id` (only when the invitation names a reviewer group) |
| `invitation.resent` | The invitation's email was sent again. | `invitation_id` |
| `invitation.revoked` | The invitation was revoked, by an administrator or because it had expired when a new one was made for the same address. | `invitation_id`, `reason` |
| `invitation.accepted` | The invited person accepted. The roles it granted are recorded by the `access.set_user_roles` beside it, and a reviewer group it joined by the `access.group_member_added` beside that. When the invitation named a group, whether it was applied and, if not, why: `GROUP_GONE` (deleted), `GROUP_ROLES` (it now grants Administrator or Policy manager), `GROUP_SCOPE` (it now grants something the invitation did not) or `GROUP_FULL` (100 members). | `invitation_id`, `principal_id`, `reviewer_group_id`, `reviewer_group_applied`, `reviewer_group_refusal` (the last three only when the invitation named a reviewer group) |

## Weekly summary

A person's own opt-in to the plain-text weekly summary. Neither decides an execution, an approval or a policy, so replay records both as informational. Sending a summary is logged, not audited.

| Kind | Written when | Payload |
| --- | --- | --- |
| `weekly_summary.subscribed` | A person turned their own weekly summary on under My account. | none |
| `weekly_summary.unsubscribed` | A person turned it off, under My account (`via` is settings) or with the one-click link in a summary (`via` is link). The actor is the subscriber either way. | `via` |

## The assistant

The assistant reads through the asking person's session and writes nothing, so its events record use and never authority.

| Kind | Written when | Payload |
| --- | --- | --- |
| `tenant.assistant_changed` | An administrator switched the assistant on or off for the workspace. | `previous`, `enabled`, `reason`, `principal_id`, `credential_id`, `actor_credential_id`, `replay` |
| `assistant.asked` | The assistant answered a question, or drafted a policy rule from a person's words (`proposed`). `rows` counts what it read and the token counts are the model's usage. | `turn_id`, `context_kind`, `context_id`, `tools`, `rows`, `model`, `input_tokens`, `cached_tokens`, `output_tokens`, `cannot_answer`, `proposed`, `actor_credential_id` |
| `assistant.explained` | A person opened the assistant's explanation of a record. | `turn_id`, `context_kind`, `context_id`, `state`, `actor_credential_id` |
| `assistant.refused` | A turn ended without an answer. | `turn_id`, `reason`, `tools`, `actor_credential_id` |

## Monitoring

Monitoring records what sources report and what collectors read, in tables of its own, and appends nothing to the chain for it: reporting sources, observations, findings and collection runs stay off it. Two exceptions are an administrator's acts. One is a decision about a finding. The other is a change to a monitoring connection, because a connection holds or reaches a credential (a sealed key, an operator's key file, a directory's consent), so who created, re-keyed, consented to, scheduled or revoked one is evidence beside the rest of the chain. The connection's space is on each row, and no payload carries a key, a ciphertext, a fingerprint, a consent's `state` or token, or the name a directory shows for the deployment's app.

| Kind | Written when | Payload |
| --- | --- | --- |
| `monitor.finding_acknowledged` | An administrator acknowledged a monitoring finding in a space they see. The finding's space is on the row; no story, target reference, outcome or reported actor is in the payload. An acknowledgement is final; acknowledging a finding that is already acknowledged appends nothing. The administrator's optional note, screened for secret-shaped text, travels in `note` only when there is one. | `finding_id`, `rule_version`, `note` (only with a note), `actor_credential_id` |
| `monitor.connection_created` | An administrator connected Tines from the console with a pasted key, sealed for the collector (`credential_mode` `sealed`); a directory administrator's consent completed a Microsoft Entra connection an administrator started from the console (`platform_app`), when `attempt_id` names the attempt and the actor is the administrator who started it; or an operator registered a connection with `create-connection` (`key_file`). The label was screened for secret-shaped text. | `connection_id`, `space_id`, `kind`, `credential_mode`, `label`, `attempt_id` (consent only), `actor_credential_id` (not for a consent) |
| `monitor.key_replaced` | An administrator pasted a new key for a sealed connection, which is then asked for a collection. | `connection_id`, `actor_credential_id` |
| `monitor.collection_requested` | An administrator asked for a collection ("Collect now"); the next scheduled pass picks it up. A request already waiting is the one answered, and asking again appends nothing. | `connection_id`, `actor_credential_id` |
| `monitor.schedule_changed` | An administrator set a connection's intervals; null is the kind's default. | `connection_id`, `collect_interval_seconds`, `activity_interval_seconds`, `actor_credential_id` |
| `monitor.egress_recorded` | An administrator recorded, changed or cleared the addresses a Tines tenant's HTTP requests leave from, which a directory's sign-ins in the same Space are matched against for driver evidence. The addresses themselves are on the connection, not the event. | `connection_id`, `addresses` (how many), `actor_credential_id` |
| `monitor.connection_revoked` | An administrator revoked a connection from the console or with `revoke-connection`. Its row and evidence are kept and any run's lease ends. | `connection_id`, `actor_credential_id` |
| `monitor.consent_recorded` | A directory administrator consented to the deployment's platform app for a Microsoft Entra connection, new or one whose consent was updated. The actor is the administrator who started the attempt from the console; the consent's callback carries no session, so no credential is named, and `attempt_id` names the attempt the starting browser was bound to. `directory_ref` is the directory a verified sign-in named. | `connection_id`, `directory_ref`, `attempt_id` |
