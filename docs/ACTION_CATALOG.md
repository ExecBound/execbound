# Action catalog

A canonical action is the unit of authority the kernel enforces: one name, one resource type, one set of typed arguments, one default context contract and one provider operation per provider. The catalog in [`protocol/src/execbound_protocol/catalog.py`](../protocol/src/execbound_protocol/catalog.py), part of the Apache-2.0 `execbound-protocol` package and re-exported by `src/execbound/operations.py`, is the single place that says which actions exist, which options each one accepts and where each one binds. Those facts used to be closed literal types repeated across resolution, the provider protocol, the mock services, the migrations and the packs.

Acceptance cases SA1 to SA15 are in the [acceptance inventory](ACCEPTANCE_TESTS.md#soc-action-catalog). Trusted facts are a separate catalog; see [Context contracts](CONTEXT_CONTRACTS.md).

## Production catalog

`PRODUCTION_ACTIONS` contains six actions and seven bindings: one for each action on the mock providers, and `identity.disable` on Microsoft Graph as well. Released specs and bindings are immutable: a changed argument set or provider operation is released as a new action or a new binding, because frozen plans, pending approvals and replay look actions up by name.

| Action | Resource type | Label | Arguments | Default contract | Reversed by |
| --- | --- | --- | --- | --- | --- |
| `endpoint.isolate` | `endpoint` | Isolate endpoint | none | `endpoint-isolation.v1`; `endpoint-isolation.v2` per mapping | `endpoint.lift_isolation` |
| `endpoint.lift_isolation` | `endpoint` | Lift endpoint isolation | `reason`: `String` in `false_positive`, `remediated` | `endpoint-recovery.v1` | `endpoint.isolate` |
| `identity.disable` | `identity` | Disable identity | none | `identity-control.v1` | `identity.enable` |
| `identity.enable` | `identity` | Enable identity | none | `identity-control.v1` | `identity.disable` |
| `identity.revoke_sessions` | `identity` | Revoke identity sessions | none | `identity-control.v1` | none |
| `identity.reset_password` | `identity` | Reset identity password | `require_change_at_next_sign_in`: `Boolean` | `identity-credential.v1` | none |

`reversed_by` names the catalog action that undoes one, when the catalog has one: a revoked session or a reset password cannot be given back, so those two name none. It is display data for the approval page, which says whether what an approver is about to allow can be taken back and by which action; nothing plans, dispatches or authorizes from it, and a spec gaining one keeps its name, its arguments and every frozen plan that names it. The catalog refuses a reversal that names an unknown action, the action itself or an action on another resource type.

| Provider | Action | Provider operation |
| --- | --- | --- |
| `mock_crowdstrike` | `endpoint.isolate` | `contain` |
| `mock_crowdstrike` | `endpoint.lift_isolation` | `lift_containment` |
| `mock_entra` | `identity.disable` | `disable` |
| `mock_entra` | `identity.enable` | `enable` |
| `mock_entra` | `identity.revoke_sessions` | `revoke_sessions` |
| `mock_entra` | `identity.reset_password` | `reset_password` |
| `graph` | `identity.disable` | `disable` |

The default contract is the production contract the validation seed provisions for that action's mappings, and the one `mapping-create` writes unless `--contract-version` names another. A tenant mapping names its own `context_contract_version`, which the contract catalog still has to serve for that action and resource type. `endpoint-isolation.v2` also serves `endpoint.isolate` and is no action's default: it adds the EDR's `compromise` fact, and a mapping opts into it with `mapping-create --contract-version endpoint-isolation.v2` ([Security signals](SIGNALS.md)).

An agent sends a tenant's `operation_ref`, never a catalog action name. It learns the references its own space offers, each with the catalog action and label it performs, its arguments and the values or range each accepts, from the read-only MCP tool `list_actions` or `GET /v1/actions`. That is not a per-action tool and grants nothing: a listed action is not permission, and every request is still decided.

A binding is also what the [external execution checkpoint](CHECKPOINT.md) is keyed by, in two places. A bundle mapping that declares an external executor is refused unless its provider, action and provider operation are a released binding here, because the executor acts against that vendor operation and the settled record names it, so a narrowed or extended injected catalog must not widen what a grant may describe. And the precondition class an operator declares in the private configuration file is keyed by `(provider, provider_operation)` — the tuple the catalog refuses to duplicate — so it names one binding exactly. Neither is catalog content: the class stays outside the serialized operation composite, so released specs and bindings stay immutable and no frozen plan or bundle hash moves.

The [Arcade logic extension](ARCADE.md)'s tool map is a third declaration of the same kind, and it is keyed further out still: an entry names an `operation_ref`, which is the **tenant's** key into `operation_mappings`, and the provider, resource type, action, provider operation, schema version, context contract and connector account all come from the mapping that reference resolves to. So a deployment-wide configuration file cannot check a reference against a tenant's rows, and it does not try: what it refuses at load is a reference outside the character class `ActionRequest.operation_ref` itself admits, because that is one no request this deployment parses could carry. A reference that parses but resolves to nothing, or that the control point's space does not offer, is the kernel's ordinary refusal at admission, with no foreign disclosure ([threat model](THREAT_MODEL.md#b1-protected-agent-to-gateway), T1.17). The `arguments` map is bounded the same way as every other caller's: the wire admits a bounded scalar and **this catalog** refuses everything but the action's own enumerated values, so a tool mapped to an argument the action does not declare is refused at resolution rather than at the edge.

## Catalog model

| Type | Fields |
| --- | --- |
| `ArgumentSpec` | `name` matching `^[a-z][a-z0-9_]{0,62}$`, `cedar_type` (`String`, `Long` or `Boolean`), `domain` (`StringDomain`, `IntegerDomain` or `BooleanDomain`) |
| `ActionSpec` | `action` matching `^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$`, `resource_type`, `label` of 1 to 80 characters, `arguments` (0 to 16, unique, sorted by name), `context_contract_version` |
| `ProviderBinding` | `provider` and `provider_operation` matching `^[a-z][a-z0-9_]{0,62}$`, `action`, `schema_version` `action.v1` |
| `OperationSpec` | The composite of one action spec and one binding: `provider`, `resource_type`, `action`, `provider_operation`, `schema_version`, `context_contract_version`, `label`, `arguments` |

The scalar domain types live in [`domains.py`](../protocol/src/execbound_protocol/domains.py) in the protocol package, re-exported by `src/execbound/domains.py`, so the action catalog and the contract catalog share one definition of what a checkable domain is; `contracts.py` re-exports the same names. The rules per Cedar type are the same as for facts: a `String` needs a non-empty `StringDomain` whose values are 1 to 254 characters, a `Long` needs an `IntegerDomain` with integer bounds inside the signed 64-bit range and `minimum <= maximum`, and a `Boolean` needs `BooleanDomain`.

`ActionCatalog(actions, bindings)` validates at construction and raises `CatalogError` when:

- an action repeats, or a binding names an action the catalog does not contain;
- two bindings share a provider and action, or a provider and provider operation;
- an action, provider, provider operation or argument name is invalid, an argument name repeats, there are more than 16 arguments, or the arguments are not listed in name order;
- an argument's domain does not satisfy the rules above;
- the label is empty or longer than 80 characters, or the context contract version is outside `^[a-z][a-z0-9_.-]{0,79}$`;
- the schema version is not `action.v1`.

| Method | Result |
| --- | --- |
| `action(name)` | The `ActionSpec`, or `CatalogError` |
| `binding(provider, action)` | The `ProviderBinding`, or `CatalogError` |
| `bindings_for(provider)` | Every binding of one provider, in sorted order |
| `bound(provider, action)` | The `OperationSpec` composed from both |
| `validate_operation(provider=, resource_type=, action=, provider_operation=, schema_version=)` | The `OperationSpec` when the whole tuple matches, else `CatalogError` |
| `normalize_arguments(action, arguments)` | The normalized `dict`, else `CatalogError` |

`ActionName`, `ProviderName` and `ProviderOperation` are pattern-constrained strings rather than closed literals, so tests can inject synthetic actions and bindings the way they inject synthetic contracts. Their serialized form is unchanged. Unknown values are rejected by catalog checks at mapping resolution, evaluation, bundle validation and provider command construction instead of by the model types, so `CanonicalIntent` and `ResolvedRequest` keep only structural checks and the operation tuple is rechecked wherever authority is established. `ResourceType` stays a two-value literal because no column admits another value.

The catalog is injectable through the contract catalog: `Catalog(contracts, actions=PRODUCTION_ACTIONS)`. Every function that already takes `catalog: Catalog` reaches the actions through `catalog.actions`, so no new parameter is threaded through the runtime. `operation(action)` returns the `ActionSpec` and carries no provider fields; callers that need a provider read a binding. The mock provider processes and the provider protocol models use `PRODUCTION_ACTIONS` only, so a synthetic action is never dispatchable.

## Arguments

### Wire shape

`ActionRequest.arguments` is `Arguments`: a required, strict mapping of 0 to 16 keys matching `^[a-z][a-z0-9_]{0,62}$` to exactly one of a `str` of 1 to 254 characters, a signed 64-bit `int` or a `bool`. There is no coercion between those types, and nested objects, lists and null values are rejected. `parse_request` continues to reject floats, non-finite numbers, duplicate keys and oversized bodies before validation. An empty mapping serializes as `{}`, byte-identical to the removed `EmptyArguments`, so every existing intent, plan, binding, wire and command hash is unchanged.

The MCP `execute` tool schema is generated from the model, so it describes this wire shape. It does not disclose per-action names or domains; those are in the production table above.

### Normalization

Normalization is: exact key set, exact Python type for the Cedar type, domain membership and canonical JSON key order. There is no case folding, trimming, defaulting or numeric conversion, and every declared argument is required.

`ActionCatalog.normalize_arguments` applies it, and `mapping_context` in [`resolution/registry.py`](../src/execbound/resolution/registry.py) calls it for both resolution paths: `resolve_request` and the coordinator's `resolve_snapshot`, which `attest_snapshot` also uses. It runs only for an operation the agent's space offers: admission checks the requested `operation_ref` against that set first (`execution/offered.py`) and refuses any other as an unknown one, 503 `EXECUTION_UNAVAILABLE` whatever its arguments. It runs after `validate_operation` and before any fact is loaded; `resolve_snapshot` reads the mapping on its own first so an invalid argument fails before the coherent statement reads any resource, alias, incident or fact row, whatever the caller named as its target. A failure raises `ResolutionError("INVALID_ARGUMENTS")`; admission in [`execution/admission.py`](../src/execbound/execution/admission.py) audits that reason and answers the caller with `INVALID_REQUEST`.

### Frozen forms, Cedar and display

`CanonicalIntent.arguments` and `ProviderCommand.arguments` are the same `Arguments` model. The intent hash covers the arguments, so a same-key retry with different arguments re-resolves to a different intent hash and returns `IDEMPOTENCY_CONFLICT`, while a new key with the same arguments for the same unresolved intent attaches to the existing execution as before.

`policy/evaluate.py` re-validates the frozen arguments against the action spec exactly as it re-validates facts against the contract, then builds the Cedar context as `{}` when the action declares no arguments and `{"arguments": {<name>: <value>, ...}}` otherwise. Policies read `context.arguments.reason`. Arguments never become resource attributes: they are caller intent, not trusted facts.

The Approvals and Activity pages add a **Requested arguments** section listing `name: value` pairs from the frozen intent as escaped text, omitted when the action declares none, so the server-generated summary shows the reason or option a reviewer is approving. Replay reports carry the frozen arguments on each decision row and render an `Arguments:` line when they are non-empty.

No argument admits free text. Every argument is an enumerated string, a bounded integer or a boolean, so no argument can carry a secret, markup or a second target selector, and no redaction step is needed before audit or display. A scalar named like a target still parses, because the wire accepts any bounded scalar map; normalization is what refuses it, before any fact or incident is read.

## Adding an action

1. **Never change or remove a released action or binding.** Frozen plans, pending approvals, the human pages and replay look actions up by name, and the migration check constraints record the names history may contain. Release a behavior change as a new action.
2. **Add the `ActionSpec` and `ProviderBinding`** to `PRODUCTION_ACTIONS`, keeping arguments sorted by name and within the domain rules above. Choose an existing provider whose mock can actually execute the operation.
3. **Add or reuse a context contract.** The action's `context_contract_version` must name a contract in `PRODUCTION_CATALOG` that serves this action with this resource type; follow [Adding a contract](CONTEXT_CONTRACTS.md#adding-a-contract). Reuse a released contract only when the new action is already in its `actions` set; otherwise add a new version rather than changing a released one.
4. **Widen the check constraints.** Four places in the schema enumerate the catalog's action names: the `approval_scopes_action_check` and `execution_impact_action_check` constraints, the CHECK on `approval_rule_actions.action`, and the list inside the body of `approval_rule_change`, the last two from `0048_approval_rules`. Add a migration numbered from the current head that replaces all four, with a downgrade that refuses while any tenant retains a row naming the new action, following [0018_soc_actions](../migrations/versions/0018_soc_actions.py). Update `SCHEMA_REVISION` in [`db.py`](../src/execbound/db.py) in the same change.
5. **Add the mock operation and its evidence rule.** Give the store a branch for the new action, list the action in that store's `dispatch_actions`, and, when the effect is not already provable from the existing transition, add a transition model to `JournalRecord` with a `consistent` rule that requires it for this action and forbids it for every other. `mock_app.py` registers one route per binding of the configured provider and refuses at startup when the catalog binds an action the store cannot execute.
6. **Declare the action in the pack schema.** Every mapped action must appear under `ExecBound.actions` with an `appliesTo.context` record that matches the catalog exactly; see the SOC pack below.
7. **Provision mappings and scopes.** A tenant needs an `operation_mappings` row for the action and reviewer `approval_scopes` rows for the targets a human may approve.
8. **Extend `seed-validation`.** It derives mappings from `PRODUCTION_ACTIONS.bindings` and approval scopes from the action's resource type, so a new action reaches the fixture without a hard-coded list; check that the SOC pack and the fixture manifest still agree.
9. **Add tests** alongside the existing families:

| Test file | Add or keep |
| --- | --- |
| `tests/test_action_catalog.py` | Construction rules, the production contents, binding lookup and argument normalization |
| `tests/test_soc_pack.py` | The pack maps and polices the action and declares its argument context |
| `tests/test_soc_provider.py` | The provider operation, its journal transition and the rejection of altered arguments |
| `tests/test_soc_execution.py` | The action end to end: allow, approval, denial, impact and the reviewer page |
| `tests/test_soc_schema.py` | The widened checks, the guarded downgrade and the runtime revision |

## Adding a binding

A second provider for an existing action needs three things and no new action:

1. a `ProviderBinding` for the new provider, which must not repeat that provider's action or provider operation;
2. a provider kind the mock service, the connector and `ProviderAccount` accept, with its own store whose `dispatch_actions` cover every action bound to it;
3. a tenant `operation_mappings` row naming that provider, action and provider operation, so the mapping resolves to the new binding.

The catalog side alone is covered by the synthetic `mock_defender_test` binding for `endpoint.isolate` in [`tests/soc_fixtures.py`](../tests/soc_fixtures.py), which resolves through a tenant mapping without any new provider process. Nothing dispatches to a synthetic provider: the mock services and the provider protocol read `PRODUCTION_ACTIONS`.

`identity.disable` already carries two bindings, `mock_entra` and `graph`. Bindings are keyed by provider and action, so a frozen plan keeps the provider it was frozen with, and which binding serves a request follows from the tenant's account, whose connector names its provider. The validation seed keys its mapping rows by action name, so it maps one binding per action, the mock's.

## SOC policy pack

[`execbound_harness/soc_demo.py`](../src/execbound_harness/soc_demo.py) builds `soc_bundle(tenant_id, endpoint_account_id, identity_account_id, *, mapping_version, bundle_id=None)`: a schema declaring `Agent`, the `Endpoint` and `Identity` entities with the v1 attributes and all six actions with their context records, six mappings, twelve limit rules and two policy sets. These are synthetic demonstration rules, not organization policy.

Authorization:

- `endpoint.isolate`: permit a workstation with an `OPEN`, `CRITICAL` linked incident; forbid `domain_controller` and criticality 4.
- `endpoint.lift_isolation`: permit when the tenant matches and either `resource.incident_status == "CLOSED"` or `context.arguments.reason == "false_positive"`.
- `identity.disable`, `identity.enable`, `identity.revoke_sessions`: permit a `standard` identity with an `OPEN`, `CRITICAL` linked incident; forbid `privileged`, `tier0` and criticality 4.
- `identity.reset_password`: permit a `standard` identity with an `OPEN` linked incident of severity `HIGH` or `CRITICAL`; forbid `privileged`, `tier0` and criticality 4.

Approval:

- `identity.enable`: always.
- `endpoint.isolate`, `identity.disable`, `identity.revoke_sessions`: `resource.is_production`.
- `endpoint.lift_isolation`: `resource.is_production || context.arguments.reason == "remediated"`.
- `identity.reset_password`: `resource.is_production || context.arguments.require_change_at_next_sign_in == false`.

Every action gets a principal autonomous threshold of 10 targets per rolling hour with `REQUIRE_APPROVAL` and a tenant total ceiling of 20 per rolling 15 minutes with `DENY`.

`seed-validation` provisions the mappings and reviewer scopes for all six actions, installs this pack through the same lifecycle path as the demo bundle but stops at `VALIDATED`, and writes `soc-bundle-<index>.json` to the output directory. The merged demo bundle stays `ACTIVE`, its bytes are unchanged, and the browser demonstration is unchanged.

### Activating it

Nothing new has to be created. Take the `bundle_id` from `soc-bundle-<index>.json` and run the ordinary ADMIN activation command against the fixture's tenant:

```sh
uv run execbound bundle-activate --tenant <tenant-UUID> --credential-file local-data/demo-1/admin-0.token --bundle <bundle-UUID>
```

Activation is serialized on the tenant control row: it validates the pack's components against the catalog again, selects the SOC bundle for the tenant's first space and returns the demo bundle it replaces to `VALIDATED` once no space selects it, atomically with their audit events. Because the demo bundle is then no longer the space's selection, any approval still pending under it becomes stale at re-attestation and returns `STALE_AUTHORIZATION`; the agent's original request is re-evaluated under the new bundle. Use `execbound bundle-preview` first for a read-only comparison over recent history, and `bundle-list` to confirm the selection afterwards.

## Cedar action contexts

Bundle validation checks each mapping's action against the catalog as well as its contract. For each mapping, the action must be declared under `ExecBound.actions`, and its `appliesTo.context` must be a `Record` whose attributes are:

- exactly empty when the action declares no arguments;
- otherwise exactly one required attribute `arguments`, itself a `Record` declaring each argument name with its Cedar type, all required, and nothing else.

```json
{
  "endpoint.lift_isolation": {
    "appliesTo": {
      "principalTypes": ["Agent"],
      "resourceTypes": ["Endpoint"],
      "context": {
        "type": "Record",
        "attributes": {
          "arguments": {
            "type": "Record",
            "attributes": {"reason": {"type": "String"}}
          }
        }
      }
    }
  }
}
```

The existing endpoint and identity packs declare empty context records and validate unchanged. Replay candidate bundles go through the same model validation, but offline replay cannot rebuild `OperationSpec`s because exports carry no mapping rows, so `simulate` validates candidates without `operations=`; action-context validation is guaranteed there only because a candidate must keep the original, store-validated Cedar schema and mappings to be compatible at all.

## Vendor reference

The table below documents where each canonical action would bind on real vendors. One cell is implemented: Entra `identity.disable`, as the `graph` binding, which sets `accountEnabled` false through Microsoft Graph. Graph offers no conditional write, so the binding is declared `CHECKED_BY_CONNECTOR`: ExecBound reads the user and compares it with the frozen version immediately before the write, and records the measured window between them. That is not an atomic check ([Provider](PROVIDER.md)). Every other cell is documentation: no vendor call is implemented for it, no credential is used and no semantic equivalence is claimed until a narrower contract is validated.

| Canonical action | Mock binding | CrowdStrike Falcon | Microsoft Defender for Endpoint | Microsoft Entra ID | Okta |
| --- | --- | --- | --- | --- | --- |
| `endpoint.isolate` | `contain` | Device action `contain` | Machine action `isolate` (`IsolationType` full or selective) | | |
| `endpoint.lift_isolation` | `lift_containment` | Device action `lift_containment` | Machine action `unisolate` | | |
| `identity.disable` | `disable` | | | Set `accountEnabled` false | Lifecycle `suspend` or `deactivate` |
| `identity.enable` | `enable` | | | Set `accountEnabled` true | Lifecycle `unsuspend` or `reactivate` |
| `identity.revoke_sessions` | `revoke_sessions` | | | `revokeSignInSessions` | Delete user sessions |
| `identity.reset_password` | `reset_password` | | | `passwordProfile` with `forceChangePasswordNextSignIn` | Lifecycle `reset_password` (sends a reset email; different semantics) |

## Failure codes

None of these dispatch.

| Condition | Result |
| --- | --- |
| `arguments` is not a flat object, has more than 16 keys or an invalid key, or holds a nested value, list, null, float, empty or oversized string, or an integer outside 64 bits | `InvalidRequest` at parse, before any lookup |
| An operation the agent's space does not offer, whatever its arguments | Refused before arguments are validated: audited `INVALID_OPERATION`, `INVALID_CONFIGURATION` or `INVALID_BUNDLE` and answered `EXECUTION_UNAVAILABLE` (HTTP 503), as an unknown operation is |
| Missing, extra, mistyped or out-of-domain argument for the resolved action of an operation the space offers | `ResolutionError("INVALID_ARGUMENTS")`; admission audits `INVALID_ARGUMENTS` and returns `INVALID_REQUEST` (HTTP 400), the same caller-visible result as an unsupported option before the catalog existed |
| Mapping row names a provider, action and provider operation that are not a catalog binding, or an action outside the catalog | `INVALID_OPERATION` (unchanged) |
| Frozen plan arguments fail the action spec at evaluation | `DENY` with `INVALID_ARGUMENTS` |
| Bundle schema omits a mapped action, its context record does not declare exactly the action's arguments, or a limit rule names an action outside the catalog | `PolicyStoreError` with `INVALID_COMPONENT` |
| Same idempotency key, different arguments | `IDEMPOTENCY_CONFLICT` |
| Provider command arguments fail the production catalog | Provider returns 400 with no journal; unreachable with a consistent deployment, and otherwise the operation stays unresolved like any invalid response |
| Journal transition inconsistent with the action, such as a lift whose `after.contained` is true or a reset without a credential transition | Invalid evidence; impact and target claim stay unresolved |
| Migration downgrade with retained rows naming a new action | Downgrade refuses |

## Tests

| File | Covers |
| --- | --- |
| `tests/test_action_catalog.py` | SA1: construction rules, production contents, bindings, normalization, synthetic multi-binding |
| `tests/test_domains.py` | The shared scalar domains and exact-type value checks |
| `tests/test_identity_compatibility.py` | SA2: the identity golden fixture's plans, commands and signed journals |
| `tests/test_requests.py` | SA3: the wire shape, boundaries, duplicate keys and unchanged empty serialization |
| `tests/test_resolution.py` | SA3, SA9: normalization before facts, the synthetic `Long` action and the second binding |
| `tests/test_policy_evaluation.py` | SA10: arguments in the Cedar context, frozen arguments outside the spec, mismatched operation tuples |
| `tests/test_context_bundle_validation.py` | SA10: action contexts that omit, add, mistype or make optional an argument |
| `tests/test_soc_pack.py` | SA14: the pack's mappings, limits, argument contexts and Cedar validation |
| `tests/test_soc_provider.py` | SA11: both new mock operations, their transitions and altered-argument rejection |
| `tests/test_soc_execution.py` | SA4 to SA8, SA12: both actions end to end, approval pages, idempotency and impact |
| `tests/test_soc_schema.py` | SA13: the widened checks, the guarded downgrade and the round trip |
| `tests/test_replay_scenarios.py`, `tests/test_replay_verify.py` | SA15: a candidate that forbids an argument value, and verification of argument-bearing commands |
| `tests/test_validation_demo.py` | SA14: the seed installs the SOC bundle as `VALIDATED` beside the active demo bundle |

`tests/soc_fixtures.py` provides `PROBE` (a synthetic `Long`-argument action), `SECOND_BINDING`, `TEST_ACTIONS`, `TEST_CATALOG` and the lift and reset scenarios.

`ACCEPTANCE_PREFIXES` in [`validation_evidence.py`](../src/execbound_harness/validation_evidence.py) records these files as acceptance group `SA`, and group `F`'s argument-shape prefixes now name the catalog's rejection tests. `tests/test_validation_evidence.py` runs pytest collection and fails if any prefix stops matching a test, so a rename is caught before CI.
