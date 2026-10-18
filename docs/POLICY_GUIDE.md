# Write a policy

A policy says what an agent may do on its own, what needs a person, and what never happens. You write it as a ruleset, a short list of rules and budgets, and ExecBound compiles it into the Cedar policy it decides with. [Policy and rulesets](POLICY.md) explains how a decision is made; this page is how to write one.

## How rules combine

- **Nothing is allowed by default.** An action runs only when an `ALLOW` rule matches it.
- **A matching `DENY` rule always wins,** over every `ALLOW` and `REVIEW` rule.
- **A matching `REVIEW` rule asks a person first,** for a request an `ALLOW` rule already permits. A `REVIEW` rule on its own allows nothing.
- **Order never matters.** Rules for the same action and effect combine with OR; the conditions inside one rule combine with AND.
- **Budgets** cap how many targets an action may touch in a window, then deny or ask a person.

So a typical policy has one `ALLOW` rule per action saying when it is acceptable at all, `DENY` rules for what must never happen, and `REVIEW` rules for what a person should see first.

## A complete example

```json
{
  "version": 1,
  "rules": [
    {"id": "allow-isolate-open-incident", "action": "endpoint.isolate", "effect": "ALLOW",
     "when": [
       {"kind": "fact", "name": "role", "operator": "in", "values": ["workstation", "server"]},
       {"kind": "fact", "name": "incident_status", "operator": "is", "values": ["OPEN"]},
       {"kind": "fact", "name": "incident_severity", "operator": "in", "values": ["HIGH", "CRITICAL"]}]},
    {"id": "deny-domain-controller", "action": "endpoint.isolate", "effect": "DENY",
     "when": [{"kind": "fact", "name": "role", "operator": "is", "values": ["domain_controller"]}]},
    {"id": "review-high-criticality", "action": "endpoint.isolate", "effect": "REVIEW", "quorum": 2,
     "when": [{"kind": "fact", "name": "criticality", "operator": "at_least", "values": [3]}],
     "note": "Two people decide for criticality 3 and above."}
  ],
  "budgets": [
    {"rule_id": "principal-autonomous-isolation", "action": "endpoint.isolate", "scope": "principal",
     "window_seconds": 3600, "max_targets": 10, "budget": "autonomous", "on_exceed": "REQUIRE_APPROVAL"}
  ]
}
```

An agent may isolate a workstation or server that has an open high or critical incident; never a domain controller; a target of criticality 3 or more only after two people approve; and at most ten targets an hour on its own before a person has to approve the next.

## The ruleset

| Field | Contract |
| --- | --- |
| `version` | `1`. |
| `rules` | 1 to 64 rules, each with a unique `id`. |
| `budgets` | Up to 64 budgets, each with a unique `rule_id`. Optional. |
| `context` | How fresh trusted facts must be, and who may write them. Optional; see [Context](#context). |

Every object is strict: an unknown field is refused, not ignored.

## Rules

| Field | Contract |
| --- | --- |
| `id` | Lowercase letters, digits, `.`, `_` and `-`, starting with a letter; up to 80 characters. |
| `action` | One action, such as `endpoint.isolate`. Your workspace must map it to a provider. |
| `effect` | `ALLOW`, `DENY` or `REVIEW`. |
| `when` | Up to 8 conditions, all of which must hold. No conditions means the rule always applies to its action. |
| `quorum` | For a `REVIEW` rule only: how many different people must approve, 2 to 5. Without it, one approval is enough. |
| `note` | Up to 200 characters shown beside the rule in the console. It changes nothing. |

## Conditions

```json
{"kind": "fact", "name": "incident_severity", "operator": "in", "values": ["HIGH", "CRITICAL"]}
```

| Field | Contract |
| --- | --- |
| `kind` | `fact`, something ExecBound knows about the target from a trusted source, or `argument`, a value the agent sent. |
| `name` | A fact or argument the action declares; the tables below list them. |
| `operator` | `is`, `is_not`, `in`, `at_least` or `at_most`. `at_least` and `at_most` compare numbers. |
| `values` | 1 to 16 values. Only `in` takes more than one. |

One rule cannot test the same fact twice. To say "this or that", use `in`, or write two rules with the same effect.

### Facts

Facts come from inventory and incident sources ExecBound trusts, never from the agent's request.

| Fact | Values | Actions |
| --- | --- | --- |
| `role` | `workstation`, `server`, `domain_controller` | Endpoint actions |
| `privilege_class` | `standard`, `privileged`, `tier0` | Identity actions |
| `environment` | `development`, `staging`, `production` | All |
| `is_production` | `true`, `false` | All |
| `criticality` | `0` to `4` | All |
| `incident_status` | `OPEN`, `CLOSED` | All |
| `incident_severity` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | All |

### Actions and their arguments

| Action | Arguments |
| --- | --- |
| `endpoint.isolate` | None |
| `endpoint.lift_isolation` | `reason`: `false_positive` or `remediated` |
| `identity.disable` | None |
| `identity.enable` | None |
| `identity.revoke_sessions` | None |
| `identity.reset_password` | `require_change_at_next_sign_in`: `true` or `false` |

A condition on an argument looks the same as one on a fact:

```json
{"kind": "argument", "name": "reason", "operator": "is", "values": ["false_positive"]}
```

The [action catalog](ACTION_CATALOG.md) describes each action.

## Budgets

A budget counts the distinct targets an action has touched in a rolling window and acts when the next one would go over.

| Field | Contract |
| --- | --- |
| `rule_id` | A unique id, in the same form as a rule's. |
| `action` | The action counted. `actions` can list up to 8, including `action`, to count several together. |
| `scope` | Whose use is counted: `principal` (each agent separately), `tenant` (the whole workspace), `space`, `group`, `account` or `selector`. The last four each need their qualifier: `space_id`, `group_id`, `account_id` or `selector` (`{"fact": ..., "equals": ...}`). |
| `window_seconds` | The rolling window. |
| `max_targets` | How many distinct targets fit in it. |
| `budget` | `autonomous` counts only what ran without a person's approval; `total` counts everything. |
| `on_exceed` | `REQUIRE_APPROVAL` asks a person for the next one; `DENY` refuses it. |

A budget that denies names itself in the refusal as `HARD_LIMIT:<rule_id>`. The console's rules editor writes `principal` and `tenant` budgets; the other scopes are written in the JSON.

## Context

`context` sets, per source, how old a trusted fact may be and which writers are trusted for it:

```json
"context": [
  {"context_contract_version": "endpoint-isolation.v1", "source_kind": "inventory",
   "max_age_seconds": 3600, "permitted_writers": ["inventory_sync"]},
  {"context_contract_version": "endpoint-isolation.v1", "source_kind": "incident",
   "max_age_seconds": 3600, "permitted_writers": ["soc_analyst"]}
]
```

A fact older than its limit, or written by a writer not listed, is not used, and a request that depends on it is refused. Without `context`, inventory facts from `inventory_sync` and incident facts from `soc_analyst` may be up to 300 seconds old; the most any contract allows is 3,600. [Trusted context](CONTEXT_CONTRACTS.md) describes the contracts.

## Write, check and activate it in the console

1. Open **Policies**. Create a draft from a template, from the active policy, from pasted JSON, or from a rules file.
2. Open the draft's **Rules** and edit them. Saving writes a new draft; a policy's content never changes once written.
3. **Validate** it. ExecBound compiles the rules and refuses anything it cannot compile, naming the rule and condition.
4. **Preview** it against the last hour, day, week or 30 days of real requests. The preview names each decision that would change and the rule that would change it. A Policy manager previews over the decisions recorded in the Spaces they manage. **Changes from the active policy** beside it reads how the draft's rules, budgets and mappings differ from the policy in use, as the rules read; the preview is what shows what would actually have decided differently.
5. **Activate** it, saying what changed and why. The reason is kept in the audit record and shown on the policy list. If you have a second factor enrolled and verified it more than thirty minutes ago, ExecBound asks for a code first. The previous policy goes back to validated, so rolling back is activating it again.

To move rules between workspaces, open a policy written as rules and choose **Download rules**. The file is the one `ruleset-compile` reads. It leaves out budgets counted for a named group, account or Space, and the context settings, because those name the workspace's own records; rule notes and condition values travel as written. In the other workspace, choose the Space and **Start from a rules file**: it becomes a draft over that Space's own action mappings, and still has to be validated, previewed and activated there. A file naming an action that Space does not map, or maps only through a signal contract, is refused at that rule.

Each space has its own active policy. With none active, every request in the space is refused.

## Self-hosted: compile it with the CLI

On your own deployment, write the rules in a file and let the image compile them. [Install on one host](INSTALL.md#3-write-the-policy) has the commands: `execbound ruleset-compile` turns the rules into a bundle, and `bundle-create`, `bundle-validate` and `bundle-activate` put it into effect. The starter file `starter-rules.json` is a first draft to edit.

## Common refusals

| Message | What to fix |
| --- | --- |
| `Unknown fact: <name>` or `Unknown argument: <name>` | The action does not declare it; check the tables above. |
| `Value outside the declared domain` | A value the fact does not take, such as `"critical"` for `incident_severity`, which is upper case. |
| `No mapping serves: <action>` | Your workspace does not map that action to a provider. |
| `No rule authorizes anything` | The ruleset has `REVIEW` rules but no `ALLOW` rule. |
| ``Only `in` takes several values`` | Use `in`, or one value. |
| `Only a REVIEW rule carries a quorum` | Remove `quorum`, or make the rule `REVIEW`. |
| `Scope qualifier mismatch` | A budget's scope and its qualifier disagree. |
| `Policy store refused: INVALID_TEXT at <location>.`, or in the console `Check <location>: ...` | A note, rule id or value there looks like a password, key or token, which would stop the workspace's history being exported. Reword it; nothing was saved. |

A refusal names its place as `rules.<n>.when.<m>`. The rules are counted in the order ExecBound compiles them, sorted by effect and then id, not in the order you wrote them.

An `INVALID_TEXT` location starts `ruleset.` and counts differently: `ruleset.rules.<n>` counts the rules in the order you wrote them, and `ruleset.budgets.<n>` counts the budgets in the order of their ids.
