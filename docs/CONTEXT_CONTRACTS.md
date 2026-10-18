# Context contracts

A context contract is the versioned vocabulary of trusted facts that resolution may freeze and Cedar may read for an action. It names each fact, its Cedar type and value domain, where the fact is stored, which source kind attests it, how long evidence stays fresh and which writers a source may list. That vocabulary used to be hard-coded across resolution, the evaluator, the demo Cedar schemas and the approval page. The catalog in [`src/execbound/contracts.py`](../src/execbound/contracts.py) now holds it in one place. Tenants tune freshness and writers through bundle settings; contracts change only through reviewed code.

Acceptance cases CC1 to CC12 are in the [acceptance inventory](ACCEPTANCE_TESTS.md#context-contracts).

## Production contracts

`PRODUCTION_CATALOG` contains five contracts. `endpoint-isolation.v1` and `identity-control.v1` reproduce earlier behavior exactly: `tests/test_context_parity.py` compares resolution and evaluation output byte for byte with `tests/fixtures/context-contracts-v1-parity.json`, which was generated from the code before the catalog existed.

| Version | Actions | Resource type / Cedar entity | Facts | Incident | Claim binding | Display fact |
| --- | --- | --- | --- | --- | --- | --- |
| `endpoint-isolation.v1` | `endpoint.isolate` | `endpoint` / `Endpoint` | `role`, `environment`, `criticality`, `is_production`, `incident_status`, `incident_severity` | `required` | false | `role` |
| `endpoint-isolation.v2` | `endpoint.isolate` | `endpoint` / `Endpoint` | Those of `endpoint-isolation.v1`, then `compromise` | `required` | true | `role` |
| `endpoint-recovery.v1` | `endpoint.lift_isolation` | `endpoint` / `Endpoint` | Identical to `endpoint-isolation.v1` | `required` | true | `role` |
| `identity-control.v1` | `identity.disable`, `identity.enable`, `identity.revoke_sessions` | `identity` / `Identity` | `privilege_class`, `environment`, `criticality`, `is_production`, `incident_status`, `incident_severity` | `required` | true | `privilege_class` |
| `identity-credential.v1` | `identity.reset_password` | `identity` / `Identity` | Identical to `identity-control.v1` | `required` | true | `privilege_class` |

`endpoint-recovery.v1` and `identity-credential.v1` exist because a released contract stays immutable in every field: `endpoint-isolation.v1` keeps its legacy unbound incident claim, so `endpoint.lift_isolation` gets its own version rather than joining that contract's action set. Because their entity attributes equal those of `endpoint-isolation.v1` and `identity-control.v1`, the four `.v1` contracts share one bundle with one `Endpoint` and one `Identity` entity.

`endpoint-isolation.v2` adds `compromise`, the verdict of an out-of-process EDR about the target host, read through the bundle's `signal_mappings` ([Security signals](SIGNALS.md)). It binds the incident claim, as every new incident-required contract must. Its extra attribute means its `Endpoint` differs from the v1 contracts', so one bundle cannot map it beside `endpoint-isolation.v1` or `endpoint-recovery.v1`. It is no action's default: a mapping opts into it with `mapping-create --contract-version endpoint-isolation.v2`.

The other four contracts are column-backed. `role`, `privilege_class`, `environment` and `criticality` come from `resources`; `incident_status` and `incident_severity` come from the `status` and `severity` columns of `incidents`. `is_production` is derived as `environment == "production"`.

An operation mapping selects the contract. The owner-provisioned `operation_mappings.context_contract_version` column names a version, and resolution calls `Catalog.for_operation(version, action, resource_type)`, which requires the contract to exist, serve the mapping's action and match its resource type. `OperationSpec.context_contract_version` in [`operations.py`](../src/execbound/operations.py) is the production default per action; the validation seed uses it when it provisions mappings, and `mapping-create` uses it unless `--contract-version` names another version the catalog says serves the action. The frozen plan records the version as `ResolvedRequest.context_contract_version`, which is stored in `executions.frozen` and covered by both the plan hash and the re-attestation binding hash.

Functions that need contracts take a `catalog` argument that defaults to `PRODUCTION_CATALOG`, including `Runtime`, `admit`, `decide_approval`, `resolve_request`, `resolve_snapshot`, `attest_snapshot`, `evaluate`, `validate_bundle`, `activate_bundle`, `load_active_bundle` and `simulate`. A catalog also carries the action catalog as `catalog.actions`, defaulting to `PRODUCTION_ACTIONS`, so the runtime threads one object for both vocabularies. Tests inject a catalog with extra contracts, extra actions or both instead of patching globals. The gateway configuration and the `replay` command use the default, so a contract is usable outside tests only after it is added to `PRODUCTION_CATALOG`.

## Catalog model

### Contracts

| `ContextContract` field | Meaning |
| --- | --- |
| `version` | Identifier matching `^[a-z][a-z0-9_.-]{0,79}$`, unique in the catalog |
| `resource_type` | `endpoint` or `identity` |
| `cedar_entity_type` | Entity name matching `^[A-Z][A-Za-z0-9]{0,62}$`, used as `ExecBound::<name>` |
| `actions` | Non-empty set of actions from the injected action catalog whose resource type equals `resource_type` |
| `incident` | `required` or `none` |
| `bind_incident_claim` | When true, evaluation requires the frozen incident to be the claimed incident |
| `display_fact` | Fact shown as the resource class on the Approvals and Activity pages |
| `sources` | One `SourceDefaults` for each source kind the facts use, and no others |
| `facts` | Ordered tuple of `FactSpec` |

### Facts, domains and Cedar types

| `FactSpec` field | Meaning |
| --- | --- |
| `name` | Matches `^[a-z][a-z0-9_]{0,62}$`; `tenant` and `account` are reserved |
| `cedar_type` | `String`, `Long` or `Boolean` |
| `domain` | `StringDomain(values)`, `IntegerDomain(minimum, maximum)` or `BooleanDomain()` |
| `source_kind` | `inventory`, `incident` or `signal` |
| `storage` | `Column(column)`, `FactRow()`, `Signal(capability)`, or `None` for a derived fact |
| `derivation` | `Equals(dependency, value)` or `None` |

| Cedar type | Required domain | Accepted value |
| --- | --- | --- |
| `String` | `StringDomain` with at least one value, each 1 to 254 characters | A `str` in the set |
| `Long` | `IntegerDomain` with integer bounds, `minimum <= maximum`, inside the signed 64-bit range | An `int` in the inclusive range |
| `Boolean` | `BooleanDomain` | A `bool` |

`value_matches` requires the exact Python type, so `"4"` and `True` never satisfy a `Long` fact.

### Source kinds and storage

`source_kind` is the `context_sources.kind` that must attest an inventory or incident fact. Storage decides where resolution reads it.

| Storage | Allowed for | Value and provenance |
| --- | --- | --- |
| `Column("role")`, `Column("privilege_class")`, `Column("environment")`, `Column("criticality")` | `inventory` facts | The `resources` row: the column, `provider_id` as source object, `version`, `source_id`, `observed_at` |
| `Column("status")`, `Column("severity")` | `incident` facts | The linked `incidents` row: the column, `incident_id` as source object, `version`, `source_id`, `observed_at` |
| `FactRow()` | `inventory` facts only | The `resource_facts` row named after the fact: `value`, `version`, `source_id`, `observed_at`, with the resource's `provider_id` as source object |
| `Signal(capability)` | `signal` facts only | The newest `security_signals` record of every source the bundle's mapping admits, mapped to one value: the determining source as `source_id`, its registration version as `version`, the resource's `provider_id` as source object, the earliest record's observation, and the records themselves frozen beside the fact |

The permitted columns are the `COLUMNS` mapping in `contracts.py`. Incident facts are always column-backed, so a new inventory fact uses `FactRow()`.

`signal` is the third kind: a fact stored as `Signal(capability)`, resolved from `security_signals` through the bundle's `signal_mappings`, never from a column or a manifest. Its writers are the fixed label `signal_mappings`, because admission is by source id in the mapping. It must be a `String` whose domain is exactly the capability's, only a resource-subject capability is supported, no fact may be derived from it, and a contract holds at most one fact per capability. See [Security signals](SIGNALS.md).

### Incident mode and claim binding

With `incident="required"`, the contract declares at least one incident fact. Resolution loads the incident named by `claimed_context.incident_id` only when it is linked to the resolved resource in the same tenant, account, provider and resource type. With `incident="none"`, the contract declares no incident facts and resolution loads no incident; a claimed `incident_id` stays an untrusted claim and produces no facts.

`bind_incident_claim=True` adds an evaluation check that every frozen incident fact's source object equals the claimed `incident_id`. The catalog rejects it when `incident` is `none`, and requires it to be true whenever `incident` is `required`. `endpoint-isolation.v1` is the one named exception: it keeps `bind_incident_claim=False` to preserve earlier behavior, because the current evaluator does not check it for that version and resolution already enforces the incident link through its query. `contracts.LEGACY_UNBOUND_INCIDENT_CLAIMS` lists that exempted version; a new contract that requires an incident must set `bind_incident_claim=True`.

### Derivations

`Equals(dependency, value)` is the only derivation. It yields a `Boolean` that is true when the dependency's value equals `value`. A derived fact has no storage, has the same source kind as its dependency, and copies the dependency's source, version, writers, observation time and expiry with origin `DERIVED`. The dependency must be a resolved fact of the same contract, not another derived fact, and `value` must be inside its domain.

Resolution computes facts in tuple order. The catalog requires a derived fact to be listed after its dependency and raises `ContractError` at construction when it is listed first.

### Source defaults

`SourceDefaults(max_age_seconds, ceiling_seconds, permitted_writers)` sets, for one source kind, the default freshness window, the largest window a bundle may set and the default writer allowlist. All five production contracts use these values, and only `endpoint-isolation.v2` has the `signal` kind:

| Source kind | Default max age | Ceiling | Default permitted writers |
| --- | --- | --- | --- |
| `inventory` | 300 seconds | 3,600 seconds | `inventory_sync` |
| `incident` | 300 seconds | 3,600 seconds | `soc_analyst` |
| `signal` | 300 seconds | 3,600 seconds | `signal_mappings`, the only label the kind admits |

### Cedar entity

Evaluation sends Cedar a principal `ExecBound::Agent` with attribute `tenant`, the action `ExecBound::Action::"<action>"`, a context that is empty unless the action declares arguments (see [Action catalog](ACTION_CATALOG.md#arguments)), and a resource of type `ExecBound::<cedar_entity_type>` with ID `<tenant>/<account>/<provider>/<resource_type>/<target_id>`. The resource's attributes are `tenant` and `account` as strings plus every contract fact. Caller claims never become attributes. A bundle's Cedar schema must declare that entity with exactly those attributes; see step 6 of [Adding a contract](#adding-a-contract).

### Construction rules

`Catalog(...)` validates every contract and raises `ContractError` when:

- two contracts share a version;
- the version, entity type, resource type or incident mode is invalid;
- `actions` is empty, names an action missing from `catalog.actions`, or names an action for another resource type;
- `facts` is empty, or a fact name repeats, is invalid, or is `tenant` or `account`;
- a Cedar type is unsupported or its domain breaks the rules above;
- a resolved fact names a column outside `COLUMNS` for its source kind, has no storage, or uses `FactRow()` as an incident fact;
- a `Signal` fact is not of the `signal` kind, names an unknown capability or one whose subject is not a resource, or is not a `String` with exactly the capability's domain, or two facts name one capability;
- a derivation's dependency is missing or derived, is a `signal` fact, is listed after the derived fact instead of before it, the derived fact has storage or is not `Boolean`, the source kinds differ, or the value is outside the dependency's domain;
- `display_fact` is not a fact of the contract;
- incident facts exist with `incident="none"`, or none exist with `incident="required"`;
- `bind_incident_claim` is true without a required incident;
- `incident="required"` and `bind_incident_claim` is false, unless the version is listed in `LEGACY_UNBOUND_INCIDENT_CLAIMS`;
- `sources` does not cover exactly the source kinds the facts use;
- a default does not satisfy `1 <= max_age_seconds <= ceiling_seconds <= 86400` (`MAX_CEILING_SECONDS`);
- default writers are empty, more than 16, unsorted, duplicated, or not all matching `^[a-z][a-z0-9_.-]{0,63}$`;
- the `signal` kind's default writers are anything but exactly `signal_mappings`.

## Adding a contract

The synthetic contract in [`tests/context_fixtures.py`](../tests/context_fixtures.py) is the worked example. `SYNTHETIC_VERSION` is `endpoint-facts.test`. It serves `endpoint.isolate` through the operation mapping `endpoint.isolate.facts` (`SYNTHETIC_OPERATION`), with three row-backed facts, one derivation and no incident. `tests/test_context_execution.py` runs it through the runtime to a single provider mutation.

1. **Never change or remove a released version.** Frozen plans, pending approvals, the Approvals and Activity pages and replay look contracts up by the version stored in each plan. A removed or altered contract makes that history deny, fail re-attestation or fail to render. Release a behavior change as a new version.
2. **Check the action.** Every action must already exist in the [action catalog](ACTION_CATALOG.md) with the contract's resource type. `Catalog` validates each contract's `actions` against its injected `catalog.actions`, so an unknown action raises `ContractError` at construction. Adding actions is separate work; follow [Adding an action](ACTION_CATALOG.md#adding-an-action).
3. **Choose storage.** Use `FactRow()` for new inventory facts. Use `Column(...)` only for the existing columns above. A fact a detector attests uses `Signal(capability)` with a `signal` source default, as `endpoint-isolation.v2` does. Incident facts can only use `Column("status")` and `Column("severity")`; set `incident="none"` when the action needs no incident. When the action needs an incident, set `incident="required"` and `bind_incident_claim=True`; the catalog rejects `incident="required"` with `bind_incident_claim=False` for any version other than the exempted `endpoint-isolation.v1`.
4. **Define facts, sources, derivations and the display fact.** List a derived fact after the dependency it reads: the catalog rejects a contract that lists a derived fact before its dependency. The synthetic contract declares String, Long and Boolean row facts, an `Equals` derivation listed after its dependency, inventory defaults and `exposure` as its display fact:

   ```python
   SYNTHETIC = ContextContract(
       version=SYNTHETIC_VERSION,
       resource_type="endpoint",
       cedar_entity_type="Endpoint",
       actions=frozenset({"endpoint.isolate"}),
       incident="none",
       bind_incident_claim=False,
       display_fact="exposure",
       sources=MappingProxyType({"inventory": SourceDefaults(300, 3600, ("inventory_sync",))}),
       facts=(
           FactSpec(
               "exposure",
               "String",
               StringDomain(frozenset({"internal", "external"})),
               "inventory",
               FactRow(),
           ),
           FactSpec("risk_score", "Long", IntegerDomain(0, 100), "inventory", FactRow()),
           FactSpec("edr_managed", "Boolean", BooleanDomain(), "inventory", FactRow()),
           FactSpec(
               "is_external",
               "Boolean",
               BooleanDomain(),
               "inventory",
               None,
               Equals("exposure", "external"),
           ),
       ),
   )
   ```

5. **Register it.** Add the contract to `PRODUCTION_CATALOG`; the tests build `CATALOG = Catalog((ENDPOINT_ISOLATION_V1, IDENTITY_CONTROL_V1, SYNTHETIC))` instead. `test_production_catalog_matches_operation_defaults` in `tests/test_contracts.py` asserts that every action's `OperationSpec.context_contract_version` is a production contract serving it, and pins the one production version that is no action's default, `endpoint-isolation.v2`. A second version of an existing action is chosen per mapping with `mapping-create --contract-version`, and the operation default does not move: changing it would move every new mapping, and the packs and fixtures built on the default, onto the new version. Adding another such version therefore changes that test deliberately.
6. **Write the Cedar JSON schema entity.** Under `ExecBound.entityTypes`, declare the contract's entity type with a `Record` shape whose attributes are exactly `tenant` and `account` as `String` plus each fact with its Cedar type. `required` may be omitted or `true`; no other attribute keys are allowed. The entity from `SYNTHETIC_SCHEMA`:

   ```json
   {
     "ExecBound": {
       "entityTypes": {
         "Endpoint": {
           "shape": {
             "type": "Record",
             "attributes": {
               "tenant": {"type": "String"},
               "account": {"type": "String"},
               "exposure": {"type": "String"},
               "risk_score": {"type": "Long"},
               "edr_managed": {"type": "Boolean"},
               "is_external": {"type": "Boolean"}
             }
           }
         }
       }
     }
   }
   ```

   The full schema also declares the `Agent` entity with a `tenant` attribute and the `endpoint.isolate` action's `appliesTo`, which Cedar validation and evaluation need. The contract check reads only contract entities. Contracts used by one bundle that share an entity type must declare identical attributes, so `endpoint-facts.test` and `endpoint-isolation.v1` cannot share a bundle.
7. **Point mappings at the version.** Provision an `operation_mappings` row whose `context_contract_version` is the new version; `mapping-create --contract-version <version>` writes one for a production contract. `seed_synthetic` inserts `endpoint.isolate.facts` for provider `mock_crowdstrike`, resource type `endpoint`, provider operation `contain`, mapping version `map-v1` and schema `action.v1`. The bundle's `MappingRef` must repeat the account, mapping version, schema version and `context_contract_version`.
8. **Provision trusted facts.** Attest the facts with an active `context_sources` row of the fact's kind whose `allowed_writers` are trusted labels inside the effective allowlist, and write one `resource_facts` row per row-backed fact per resource, normally through a manifest and `context-import`. See [Writing `resource_facts` rows](#writing-resource_facts-rows) and [Provisioning trusted context](#provisioning-trusted-context).
9. **Use it in a bundle.** Policies read facts as `resource.<fact>`. `SYNTHETIC_AUTHORIZATION` permits isolation when the tenant matches, `resource.edr_managed` is true and `resource.risk_score >= 50`, and forbids it when `resource.is_external`. `synthetic_bundle(...)` assembles the bundle, which is then created, validated and activated through `policy/store.py` with the catalog passed in. Add `context_settings` only when the defaults do not fit.
10. **Add tests** alongside the existing families:

| Test file | Add or keep |
| --- | --- |
| `tests/test_contracts.py` | The production catalog still constructs and agrees with operation defaults; add rule tests if construction changes |
| `tests/test_context_parity.py` | Must pass unchanged; never regenerate its golden fixture to accept a change |
| `tests/test_context_bundle_validation.py` | The contract's pack schema validates, and missing, extra, mistyped or optional attributes fail |
| `tests/test_context_resolution.py` | Facts resolve from storage with provenance and expiry; sources, writers, settings and invalid rows fail closed |
| `tests/test_context_evaluation.py` | Facts reach Cedar, forbidden values deny, derivations and source consistency are enforced |
| `tests/test_context_execution.py` | One provider mutation when allowed, none when denied, a changed fact row makes a pending approval stale, the display fact renders as text |
| `tests/test_replay_scenarios.py` | Candidate settings for the contract behave as described under [Freshness](#freshness) |
| `tests/test_signal_contract.py` and the other `tests/test_signal_*.py` files | For a contract with a `Signal` fact: its construction rules, and the acceptance group the [security signals guide](SIGNALS.md#evidence-and-limits) names |

## Resolution and trust

`resolve_facts` in [`resolution/facts.py`](../src/execbound/resolution/facts.py) builds the `TrustedFact` tuple for one contract and never authorizes. `resolve_request` and the coordinator's `resolve_snapshot` both call it with the rows they load.

- Facts come only from contract storage: the resource row, its `resource_facts` rows, for a required incident the linked incident row, and for a signal fact the newest `security_signals` record of each source the bundle's `signal_mappings` admits, read in the same statement. Rows for fact names the contract does not declare are ignored.
- Each resolved fact is trusted through the source that attests its storage: the resource's source for inventory columns, the incident's source for incident columns, and the fact row's own `source_id` for row-backed facts. That source must be active, have the fact's source kind, and list a non-empty `allowed_writers` set inside the effective permitted writers. A row fact moved to another source is checked against that source even when the resource's source is valid. A signal fact is trusted through the bundle's mapping instead: every admitted source must be active, unrevoked, independent, usable by the agent's space and scoped to the agent, and must have a fresh record whose verdict the mapping reads ([Security signals](SIGNALS.md#how-a-decision-reads-it)).
- The value must be non-null and match the fact's Cedar type and domain.
- Caller claims never substitute for trusted facts. Resolution reads no claim except `claimed_context.incident_id`, and that is only an untrusted selector for an incident already linked to the target. The incident's columns and source supply the facts.
- A mapping whose contract is missing or does not serve it raises `ResolutionError` with `INVALID_OPERATION`. Any fact, source, setting or freshness failure raises `INVALID_CONTEXT`.

Evaluation rechecks frozen evidence against the contract in `_trusted_entities` ([`policy/evaluate.py`](../src/execbound/policy/evaluate.py)): exact fact names, types and domains; origin, source kind, dependencies and derivation results; sorted, unique writer tuples inside the evaluating bundle's allowlist; and source consistency. Column-backed inventory facts share one source tuple whose object and version are the resource's provider ID and version. Row-backed facts must name the resource's provider ID. Incident facts share one source tuple whose object is a canonical UUID. A signal fact must name the resource's provider ID and carry its frozen records, which evaluation reads through the evaluating bundle's own `signal_mappings` entry; a fact whose records do not reproduce its value, source, source version and observation, do not support its validity, or were observed or received after the decision, denies.

## Freshness

No expiry is stored. Resolution computes each resolved fact's `valid_until` as `observed_at` plus the effective max age: the bundle's setting for that contract and source kind, or the contract default. It rejects a fact when `observed_at > now` or `valid_until <= now`. A signal fact's `observed_at` is its earliest record's, and its `valid_until` the earliest of each record's observation plus the effective max age and the producer's own `expires_at`. A derived fact copies its dependency's times. The plan's `valid_until` is the earliest of the credential expiry, every fact's `valid_until`, the alias expiry and the run expiry, and resolution fails when `now` has reached it.

Evaluation applies the rule again with the evaluating bundle's settings. A frozen fact is valid only when all of these hold:

- `observed_at <= resolved_at <= now < valid_until`;
- `valid_until <= observed_at + effective max age`;
- the plan's `valid_until <= valid_until`.

The plan itself must satisfy `resolved_at <= now < plan valid_until <= credential expiry`, and evaluation also denies with `INVALID_CONTEXT` when it finishes at or after the plan's `valid_until`. Approvals expire no later than the plan's `valid_until`.

A longer max age lets a newly resolved request accept an older observation (`test_widened_setting_admits_fact_older_than_default_age`). It cannot extend a plan that is already frozen: evaluation still requires `now < valid_until` for the frozen value, and re-attestation rejects a current resolution whose `valid_until` is earlier than the frozen one or whose facts were observed earlier. A shorter max age denies frozen facts whose `valid_until` exceeds the shorter window. `test_longer_max_age_cannot_extend_frozen_validity` and the replay candidate tests cover both directions.

## Bundle context settings

`BundleContent.context_settings` is an optional list of `ContextSetting` entries, at most one per contract and source kind. An excerpt of stored bundle JSON, with the other bundle fields omitted:

```json
{
  "context_settings": [
    {
      "context_contract_version": "endpoint-isolation.v1",
      "source_kind": "incident",
      "max_age_seconds": 600,
      "permitted_writers": ["soc_analyst"]
    },
    {
      "context_contract_version": "endpoint-isolation.v1",
      "source_kind": "inventory",
      "max_age_seconds": 900,
      "permitted_writers": ["cmdb_sync", "inventory_sync"]
    }
  ]
}
```

- A setting replaces the contract default for its contract and source kind. It does not add to it: the inventory entry above keeps `inventory_sync` so sources that list it stay accepted. A source kind without a setting uses the contract default.
- Model rules in [`policy/models.py`](../src/execbound/policy/models.py): `max_age_seconds` is 1 to 86,400; `permitted_writers` holds 1 to 16 unique labels matching `^[a-z][a-z0-9_.-]{0,63}$`, stored sorted; the list holds 1 to 32 entries with unique `(context_contract_version, source_kind)` pairs, stored sorted by that pair. An empty list is rejected, so omit the field to use defaults.
- Unset settings are omitted from the stored bytes, so bundles without settings keep their earlier canonical JSON and content hashes.
- `validate_bundle`, `activate_bundle` and `load_active_bundle` check the bundle against the catalog. Each mapping's contract must exist and serve that mapping. The Cedar schema must be in Cedar's JSON schema format, and each used contract's entity must declare exactly `tenant`, `account` and the contract's facts with their types. Each setting must name a contract used by the bundle's mappings and a source kind that contract uses, with `max_age_seconds` no higher than that source's ceiling; a setting for the `signal` kind may tune only the max age, and its `permitted_writers` must be exactly `["signal_mappings"]`. The schema must also declare each mapped action with a context record matching the action catalog; see [Cedar action contexts](ACTION_CATALOG.md#cedar-action-contexts). Failures raise `PolicyStoreError` with `INVALID_COMPONENT`.
- Settings are part of the bundle content hash, and plan hashes bind that hash. Content is immutable, so changing settings means a new bundle, and activating it makes plans and approvals frozen under the previous bundle stale.
- Writer allowlists must name only trusted writer labels. A source's `allowed_writers` records who can change its data. A bundle that admits a label the protected agent can write (the tests use `agent`) makes resolution accept agent-written context, which removes the protection acceptance scenario T requires.

## Writing `resource_facts` rows

Migration [0009_context_contracts](../migrations/versions/0009_context_contracts.py) creates the table.

| Column | Constraint and meaning |
| --- | --- |
| `tenant_id`, `account_id`, `provider`, `resource_type`, `resource_id` | Foreign key to the `resources` row the fact describes |
| `fact_name` | Matches `^[a-z][a-z0-9_]{0,62}$`; the contract's fact name |
| `value` | `jsonb` scalar: a string of 1 to 254 characters, a boolean, or an integer within Cedar's signed 64-bit `Long` range (-9223372036854775808 to 9223372036854775807; no fraction or exponent) |
| `source_id` | With tenant and account, a foreign key to the attesting `context_sources` row |
| `version` | 1 to 80 characters; frozen as the fact's `source_version` |
| `observed_at` | `timestamptz`; when the trusted source observed the value |

The primary key is the resource key plus `fact_name`, so each resource has at most one row per fact. An index covers `(tenant_id, account_id, source_id)`.

- Encode the value for its Cedar type: `'"internal"'::jsonb` for `String`, `'70'::jsonb` for `Long`, `'true'::jsonb` for `Boolean`. The table accepts any scalar of these shapes, but resolution fails closed on a type or domain mismatch, such as `'"70"'` for a `Long` fact.
- Storage covers the whole signed 64-bit `Long` range since migration `0020_resource_facts_long`, so any `IntegerDomain` a contract can express is storable; earlier revisions stopped at 18 digits.
- Tenant RLS is forced. The runtime role `execbound_app` has SELECT only and cannot insert, update, delete or truncate.
- Write rows with a trusted owner or sync connection, never the runtime connection or anything the protected agent controls. Forced RLS also filters a non-bypass owner, so set `execbound.tenant_id` in the transaction first, as the validation seed does for the registry.
- A changed value, version or source makes a pending approval stale at re-attestation. Advancing only `observed_at` keeps the binding but does not extend a frozen plan.
- `execbound context-import` is the supported way to write rows outside fixtures: it validates each fact against the catalog and the source, keeps a row's version unchanged while its content is unchanged and audits the import; see [Provisioning trusted context](#provisioning-trusted-context). `seed-validation` still writes its rows directly, and tests seed rows through `seed_synthetic` or manifests.
- Migration 0009 refuses to downgrade while any row exists; see [Data model](DATA_MODEL.md#migration-history).

```sql
BEGIN;
SELECT set_config('execbound.tenant_id', '<tenant UUID>', true);
INSERT INTO execbound.resource_facts
  (tenant_id, account_id, provider, resource_type, resource_id,
   fact_name, value, source_id, version, observed_at)
VALUES
  ('<tenant UUID>', '<account UUID>', 'mock_crowdstrike', 'endpoint', '<resource UUID>',
   'risk_score', '70'::jsonb, '<inventory source UUID>', 'fact-v1', '<observation time>');
COMMIT;
```

## Provisioning trusted context

Trusted context is provisioned by [`provisioning.py`](../src/execbound/provisioning.py) and the owner commands `context-source-create`, `context-source-deactivate` and `context-import`; the [operations guide](OPERATIONS.md#provision-trusted-context) shows the commands. Acceptance cases CP1 to CP12 are in the [acceptance inventory](ACCEPTANCE_TESTS.md#trusted-context-provisioning).

Two processes hold different authority. An adapter talks to the source system and writes a manifest file: network access, no database authority. The importer reads the manifest and writes rows with the owner connection inside one tenant transaction under an ADMIN actor: database authority, no network. The runtime role keeps SELECT only on `context_sources`, `resources`, `incidents` and `resource_facts`, `check_runtime` is unchanged, and no HTTP or MCP route reaches the importer.

A manifest (`execbound.context-manifest.v1`, parsed with strict models that forbid unknown fields) names the tenant, account, source, kind (`inventory` or `incident`) and writer label, then lists entries. An inventory entry names a resource by `provider`, `resource_type` and `provider_id`, gives a content `version` and a timezone-aware `observed_at`, `facts` keyed by contract fact name, optional `retract` names, an optional `active` flag and an optional `provider_version`. An incident entry adds `incident_id` and carries `incident_status` and `incident_severity` in `facts`. Bounds: 16 MiB, 10,000 entries, 64 facts and 32 retractions per entry, no duplicate resource or incident, no name in both `facts` and `retract`, and an entry must state something.

The importer:

- routes each fact name through the catalog to its storage for the entry's resource type and source kind, and refuses derived names (`DERIVED_FACT`), names no contract declares (`UNKNOWN_FACT`), names that contracts store differently (`AMBIGUOUS_FACT`) and values with the wrong exact type or outside any declaring contract's domain (`INVALID_VALUE`);
- refuses an entry holding text shaped like a password, key or token anywhere in it (`INVALID_MANIFEST`, naming the entry), because an entry's values are copied into every plan that resolves them;
- requires `--tenant` to equal the manifest's tenant (`TENANT_MISMATCH`), an active ADMIN actor (`INVALID_ACTOR`), an active account (`INVALID_ACCOUNT`), an active source of the manifest's kind (`INVALID_SOURCE`) and a writer that source allows (`INVALID_WRITER`);
- skips and counts resources the registry does not hold under the account, or refuses the manifest with `--strict` (`UNKNOWN_RESOURCE`); it never creates resources, aliases or canonical identities;
- refuses an observation more than 60 seconds ahead of the clock (`FUTURE_OBSERVATION`) or earlier than the retained observation of a row the entry touches (`OBSERVATION_REGRESSION`);
- changes a `resource_facts` or `incidents` row's `version` exactly when its content changes (the value, or the status and severity, and the attesting source), keeps the retained version and advances only `observed_at` otherwise, and refuses a reused version with different content (`VERSION_REUSED`); a routine sync with a new snapshot label therefore leaves pending approvals valid, while a real change makes re-attestation return `STALE_AUTHORIZATION`;
- treats `resources.version` as the provider's expected version, which every plan freezes as `resource_version` and which is checked at dispatch, atomically by the provider where the binding declares `ENFORCED_BY_PROVIDER`, and by the connector's own read and comparison where it declares `CHECKED_BY_CONNECTOR`: a manifest changes it only through `provider_version`, while the inventory columns, the `active` flag and the source are the row's content and change under the retained version (re-attestation still sees changed values through the frozen plan);
- deletes a retracted row-backed fact, nulls a retracted column-backed fact and deactivates a resource on `active: false`; each makes resolution fail closed, with `INVALID_CONTEXT` for a missing fact and `INVALID_TARGET` for an inactive resource;
- keeps an incident bound to its first resource (`INCIDENT_RELINKED`); a ticket that moves to another asset is a new incident identifier;
- writes in one transaction with multi-row statements, then appends `context.imported` with the source, account, kind, writer, manifest digest, manifest size and counts, never values. A refused manifest writes and audits nothing. Re-importing the same manifest is a no-op that reports every entry as `unchanged`.

Sources are created with their kind and 1 to 16 writer labels, none shaped like a password, key or token (`INVALID_WRITER`), which stay fixed for the source's life, and are deactivated when retired or compromised; both changes are audited (`context_source.created`, `context_source.deactivated`), and a deactivated source makes every fact it attests fail resolution. A source's `allowed_writers` must still lie inside the effective permitted writers of the bundle that evaluates a fact, so a source with an extra label needs a `context_settings` entry that admits it before its facts resolve. Replay treats the three provisioning events as informational.

[`execbound_harness/context_manifests.py`](../src/execbound_harness/context_manifests.py) turns a synthetic asset export and a synthetic ticket export ([`tests/fixtures/context-asset-export.json`](../tests/fixtures/context-asset-export.json), [`context-ticket-export.json`](../tests/fixtures/context-ticket-export.json)) into manifests: ticket states `new`, `in_progress` and `on_hold` map to `OPEN`, `resolved` and `closed` to `CLOSED`, priorities 1 to 5 to `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` and `LOW`, the incident identifier is `uuid5(source, "<number>:<asset>")` so re-exports update the same rows, and an unmapped state, priority or asset class refuses the export. The export shapes name no real product; adapters for real inventory or ticketing systems are planned and unverified. The monitoring intake never writes facts or incidents.

## Execution, approvals and replay

- **Admission.** A request with a new idempotency key loads the active bundle, checks the requested operation against what the agent's space offers under it (`execution/offered.py`), resolves with its settings and signal mappings and freezes the plan with its contract version. A changed request under a known idempotency key is resolved the same way, with the active bundle's settings and signal mappings, and conflicts when its canonical intent differs; [Execution](EXECUTION.md) describes the same-key retry.
- **Re-attestation.** Pending retries, approval decisions and the precommit check re-resolve with the settings and signal mappings of the bundle the execution was frozen under and require an unchanged binding hash. Otherwise they return `STALE_AUTHORIZATION`. A signal fact's frozen records and times are outside that hash, so a producer re-reporting the same verdict keeps a pending approval, while a changed value does not.
- **Approvals.** An approval expires at the earlier of the tenant's approval deadline after creation (120 seconds by default; configurable from 120 to 3,600, or off) and the plan's `valid_until`; with the deadline off, `valid_until` is the only clock, so an approval never outlives its facts. The Approvals and Activity pages show the contract's display fact as the resource class, add the environment label only when the plan has an `environment` fact, and render both as escaped text. If a frozen plan names a contract version that the running catalog does not contain, the pages render the escaped label `unknown contract <version>` for that row instead of failing the whole listing.
- **Replay.** Replay evaluates recorded frozen plans with the same evaluator and the candidate's settings. A candidate must keep the original mappings and Cedar schema; otherwise its decisions are `UNRESOLVED` with `UNSUPPORTED_CANDIDATE_CONTEXT`. A candidate's `signal_mappings` are re-applied to the records each plan froze, and one that needs a record or a liveness attestation the plan never froze is `UNRESOLVED` with `SIGNAL_EVIDENCE_UNAVAILABLE`. See [Replay](REPLAY.md) and [Security signals](SIGNALS.md#replay).

## Failure codes

| Condition | Raised in | Result |
| --- | --- | --- |
| A mapping names a contract that is missing or does not serve its action and resource type | `resolution/registry.py` | `ResolutionError` code `INVALID_OPERATION` |
| Missing, null, mistyped or out-of-domain fact; inactive, wrong-kind or untrusted source; future or expired observation; missing required incident; setting above the ceiling; a signal fact with no mapping entry, a silent, revoked or `agent_forwarded` admitted source, an unmapped verdict or a `clean` resting on a source that does not attest liveness | `resolution/facts.py`, `execution/snapshot.py`, `signals/resolve.py` | `ResolutionError` code `INVALID_CONTEXT` |
| Frozen evidence fails a contract, setting or freshness check, including an unknown contract version, or a signal fact its frozen records do not reproduce under the evaluating bundle's mapping | `policy/evaluate.py` | `DENY` with reason `INVALID_CONTEXT` |
| The agent's space's bundle names the requested operation at a reference the tenant's mapping no longer matches: another account, mapping, schema or contract version, or the mapping or its account inactive | `execution/offered.py`, at admission before arguments or a target are read | `ResolutionError` code `INVALID_BUNDLE`, audited; the agent is answered `EXECUTION_UNAVAILABLE` and no execution is recorded |
| The bundle's mapping reference names a different contract version than the plan | `policy/evaluate.py` | `DENY` with reason `INVALID_BUNDLE`; for a new or changed request the row above refuses first, so this stays as a defence |
| Re-attestation finds a changed binding, earlier observation or shorter validity | `execution/snapshot.py` | `STALE_AUTHORIZATION` |
| Mapping contract, contract entities or settings fail at validation, activation or active-bundle load | `policy/store.py` | `PolicyStoreError` code `INVALID_COMPONENT` |
| A replay candidate with the original mappings and schema fails Cedar or contract validation | `replay/simulate.py` | Candidate `DENY` with reason `POLICY_ERROR` |
| A replay candidate fails model validation or names another tenant | `replay/simulate.py` | `ReplayValidationError` code `INVALID_CANDIDATE` |
| A replay candidate's signal mapping needs a record or a liveness attestation the plan never froze | `signals/replay.py`, `replay/simulate.py` | Candidate `UNRESOLVED` with reason `SIGNAL_EVIDENCE_UNAVAILABLE` |

`admit` does not pass resolution codes to its caller. It raises a generic `ExecutionError` and audits the rejection with the resolution's own code as the reason (`INVALID_OPERATION`, `INVALID_TARGET`, `INVALID_CONTEXT`, `INVALID_RUN` and the rest, from the closed list `RESOLUTION_CODES`), so a person can tell an unknown action from an unknown target or stale facts while the caller cannot. Before resolution, one statement checks the requested operation against what the agent's space offers: an operation the tenant does not map, maps but the space's bundle does not name, or maps to a tuple the catalog no longer binds is audited `INVALID_OPERATION`, one the bundle names through another space's account `INVALID_CONFIGURATION`, and one it names at a stale reference `INVALID_BUNDLE`, which wins when the reference is both; every one is answered the same `EXECUTION_UNAVAILABLE`, costs the same statements and records no execution ([threat model](THREAT_MODEL.md#b1-protected-agent-to-gateway), T1.17). When the coherent snapshot statement has no single row, the cause is read from two columns the same statement computes, whether the target resolves as `registry.resource` would resolve it and whether the run is live, so every refusal after the mapping read costs the same round trips whatever its cause: an unknown or ambiguous target is `INVALID_TARGET`, a run that is not live is `INVALID_RUN`, and anything else stays `INVALID_CONTEXT`. Bad arguments are audited as `INVALID_ARGUMENTS` and answered `INVALID_REQUEST`, as before, but only for an operation the space offers. A refusal raised as an `ExecutionError` keeps its own code in the audit (though `INVALID_CONFIGURATION`, wherever admission raises it, is answered `EXECUTION_UNAVAILABLE`), and an unexpected database or value error is still audited as `DEPENDENCY_OR_CONTEXT_UNAVAILABLE`, the reason every resolution refusal carried before September 28, 2026.

## Tests

| File | Covers |
| --- | --- |
| `tests/test_contracts.py` | CC1: construction rules, production catalog, value matching, effective settings |
| `tests/test_context_parity.py` | CC2: v1 resolution and evaluation against the golden fixture |
| `tests/test_context_resolution.py` | CC3 to CC6: row-backed resolution, claims, unserved contracts, settings, writers, row sources |
| `tests/test_context_provisioning.py` | CP1 to CP12: manifests, the importer's routing, order and version rules, sources, the harness adapter, runtime privileges |
| `tests/test_context_evaluation.py` | CC3, CC5, CC6, CC10: settings during evaluation, frozen validity, synthetic facts in Cedar |
| `tests/test_context_bundle_validation.py` | CC5, CC7: contract entities and settings at validation and activation |
| `tests/test_context_execution.py` | CC3, CC11, CC12: runtime execution, stale approvals, widened and narrowed settings, display fact |
| `tests/test_resource_facts_schema.py` | CC8, CC9: tenant isolation, runtime grants, value bounds, guarded downgrade |
| `tests/test_replay_scenarios.py` | CC10: candidate max age and invalid candidate settings |

`tests/context_fixtures.py` provides `SYNTHETIC`, `CATALOG`, `SYNTHETIC_SCHEMA`, `SYNTHETIC_AUTHORIZATION`, `synthetic_bundle` and `seed_synthetic`.
