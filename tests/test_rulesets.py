# SPDX-License-Identifier: AGPL-3.0-only
"""The ruleset model and the compiler that turns it into the bundle the kernel executes (#273)."""

import json
from itertools import permutations
from uuid import uuid4

import pytest
from pydantic import ValidationError
from soc_fixtures import TEST_CATALOG
from test_context_bundle_validation import seeded_soc_bundle
from test_emergency_stop import audit
from test_execution import world as world
from test_resolution import registry as registry

from execbound.audit import canonical_json
from execbound.contracts import PRODUCTION_CATALOG
from execbound.getting_started import FIRST_ACTION, host_facts
from execbound.policy.cedar import approval_policy_ids, validate_policy_sets
from execbound.policy.models import LimitRule, MappingRef
from execbound.policy.rulesets import (
    Condition,
    Projection,
    Rule,
    Ruleset,
    RulesetError,
    compile_ruleset,
    condition_line,
    project,
    review_rule_ids,
    ruleset_bundle,
    sentence,
    writable_fields,
)
from execbound.policy.schema import SchemaError, cedar_schema
from execbound.policy.store import (
    PolicyStoreError,
    activate_bundle,
    create_bundle,
    validate_bundle,
)
from execbound_harness.demo import ENDPOINT_RULESET, argument, fact
from execbound_harness.fixtures import ENDPOINT_PROVIDER, IDENTITY_PROVIDER
from execbound_harness.fixtures import targets as fixture_targets
from execbound_harness.soc_demo import APPROVAL, CEDAR_SCHEMA, SOC_RULESET

ISOLATE = "endpoint.isolate"
LIFT = "endpoint.lift_isolation"
RESET = "identity.reset_password"


def mappings(*actions):
    contract = {
        ISOLATE: "endpoint-isolation.v1",
        LIFT: "endpoint-recovery.v1",
        RESET: "identity-credential.v1",
    }
    return tuple(
        MappingRef(
            operation_ref=action,
            account_id=uuid4(),
            mapping_version="map-v1",
            schema_version="action.v1",
            context_contract_version=contract[action],
        )
        for action in actions
    )


def rule(**changes):
    values = {
        "id": "allow-workstation",
        "action": ISOLATE,
        "effect": "ALLOW",
        "when": (Condition(kind="fact", name="role", operator="is", values=("workstation",)),),
    }
    return Rule(**values | changes)


def compiled(*rules, actions=(ISOLATE,)):
    return compile_ruleset(Ruleset(rules=tuple(rules)), mappings(*actions))


# --- the compiler ---------------------------------------------------------------------


def test_a_ruleset_compiles_to_cedar_the_engine_accepts():
    """The whole point: rules become policy sets that validate against the generated schema.

    Validated through the real `validate_policy_sets`, never a stub, because a compiler whose
    output only satisfies its own test is a compiler that fails at activation.
    """
    policy = compiled(
        rule(),
        rule(
            id="deny-dc",
            effect="DENY",
            when=(
                Condition(
                    kind="fact",
                    name="role",
                    operator="in",
                    values=("domain_controller", "server"),
                ),
            ),
        ),
        rule(
            id="review-production",
            effect="REVIEW",
            quorum=2,
            when=(Condition(kind="fact", name="is_production", operator="is", values=(True,)),),
        ),
    )
    validate_policy_sets(
        schema=policy.cedar_schema,
        authorization=policy.authorization_policies,
        approval=policy.approval_policies,
    )
    assert "permit(" in policy.authorization_policies
    assert "forbid(" in policy.authorization_policies


def test_a_review_rules_quorum_names_the_obligation_the_engine_will_report():
    """The binding that would silently fail: a quorum naming an obligation nothing raises.

    Cedar identifies a static policy by its position, and that identifier is what evaluation
    reports and what replay compares. The compiler derives the obligation from the position it
    is about to write, so this asserts the two agree by asking the engine, not by restating the
    compiler's arithmetic.
    """
    policy = compiled(
        rule(),
        rule(id="review-a", effect="REVIEW", quorum=2),
        rule(
            id="review-b",
            effect="REVIEW",
            quorum=3,
            when=(Condition(kind="fact", name="criticality", operator="at_least", values=(3,)),),
        ),
    )
    assert policy.quorum is not None
    named = {quorum.obligation for quorum in policy.quorum}
    raised = {
        f"policy:{policy_id}"
        for policy_id in approval_policy_ids(
            schema=policy.cedar_schema, approval=policy.approval_policies
        )
    }
    assert named == raised
    assert {quorum.rule_id for quorum in policy.quorum} == {"review-a", "review-b"}


def test_compilation_is_deterministic_and_independent_of_the_order_rules_were_written():
    """Validation compares a recompile against stored bytes, so byte equality is the contract."""
    first, second = rule(), rule(id="deny-dc", effect="DENY")
    forward = compiled(first, second)
    backward = compiled(second, first)
    assert forward == backward
    assert compiled(first, second) == forward


@pytest.mark.parametrize(
    "condition",
    [
        Condition(kind="fact", name="role", operator="is", values=("workstation",)),
        Condition(kind="fact", name="role", operator="is_not", values=("server",)),
        Condition(kind="fact", name="role", operator="in", values=("workstation", "server")),
        Condition(kind="fact", name="criticality", operator="at_least", values=(2,)),
        Condition(kind="fact", name="criticality", operator="at_most", values=(3,)),
        Condition(kind="fact", name="is_production", operator="is", values=(False,)),
    ],
)
def test_every_operator_and_type_compiles_to_policy_the_engine_validates(condition):
    policy = compiled(rule(when=(condition,)))
    validate_policy_sets(
        schema=policy.cedar_schema,
        authorization=policy.authorization_policies,
        approval=policy.approval_policies,
    )


def test_a_condition_on_an_argument_reads_the_context_not_the_resource():
    policy = compiled(
        rule(
            action=LIFT,
            when=(
                Condition(
                    kind="argument", name="reason", operator="is", values=("false_positive",)
                ),
            ),
        ),
        actions=(LIFT,),
    )
    assert "context.arguments.reason" in policy.authorization_policies
    validate_policy_sets(
        schema=policy.cedar_schema,
        authorization=policy.authorization_policies,
        approval=policy.approval_policies,
    )


def test_a_rule_with_no_conditions_still_compiles_on_both_sides():
    """A forbid with no `when` applies outright; a permit keeps the tenant fence and no more."""
    policy = compiled(rule(when=()), rule(id="deny-all", effect="DENY", when=()))
    assert "principal.tenant == resource.tenant" in policy.authorization_policies
    assert 'forbid(principal, action == ExecBound::Action::"endpoint.isolate", resource);' in (
        policy.authorization_policies
    )
    validate_policy_sets(
        schema=policy.cedar_schema,
        authorization=policy.authorization_policies,
        approval=policy.approval_policies,
    )


def test_a_note_is_inert_and_reaches_no_compiled_component():
    """It is shown on pages and compiled nowhere, so Cedar-shaped text in one stays text."""
    note = 'forbid(principal, action, resource); // "workstation"'
    policy = compiled(rule(note=note))
    assert "forbid(" not in policy.authorization_policies
    for component in (
        policy.cedar_schema,
        policy.authorization_policies,
        policy.approval_policies,
    ):
        assert note not in component
        assert "//" not in component


# --- refusals -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("changes", "location"),
    [
        (
            {"when": (Condition(kind="fact", name="hostname", operator="is", values=("a",)),)},
            "rules.0.when.0",
        ),
        (
            {
                "action": LIFT,
                "when": (Condition(kind="argument", name="nope", operator="is", values=("a",)),),
            },
            "rules.0.when.0",
        ),
        (
            {"when": (Condition(kind="fact", name="role", operator="is", values=("router",)),)},
            "rules.0.when.0",
        ),
        (
            {"when": (Condition(kind="fact", name="criticality", operator="is", values=(9,)),)},
            "rules.0.when.0",
        ),
        (
            {
                "when": (
                    Condition(kind="fact", name="role", operator="at_least", values=("server",)),
                )
            },
            "rules.0.when.0",
        ),
    ],
    ids=["unknown fact", "unknown argument", "outside domain", "outside range", "ordered on text"],
)
def test_a_condition_the_catalog_does_not_declare_is_refused_with_its_location(changes, location):
    """A refusal names the field, so an editor can point at it rather than reject the whole set."""
    actions = (LIFT,) if changes.get("action") == LIFT else (ISOLATE,)
    with pytest.raises(RulesetError) as raised:
        compiled(rule(**changes), actions=actions)
    assert raised.value.location == location


def test_a_rule_for_an_action_no_mapping_serves_is_refused():
    with pytest.raises(RulesetError) as raised:
        compiled(rule(action=LIFT), actions=(ISOLATE,))
    assert raised.value.location == "rules.0.action"


def test_a_mapping_whose_ref_is_no_catalog_action_is_refused_where_it_is():
    custom = mappings(ISOLATE)[0].model_copy(update={"operation_ref": "isolate.corroborated"})
    with pytest.raises(RulesetError) as raised:
        compile_ruleset(Ruleset(rules=(rule(action=LIFT),)), (*mappings(LIFT), custom))
    assert raised.value.location == "mappings.1"
    assert str(raised.value) == "Operation ref is not a catalog action: isolate.corroborated"


def test_a_mapping_on_a_contract_that_does_not_serve_its_action_is_refused_where_it_is():
    wrong = mappings(ISOLATE)[0].model_copy(
        update={"context_contract_version": "endpoint-recovery.v1"}
    )
    with pytest.raises(RulesetError) as raised:
        compile_ruleset(Ruleset(rules=(rule(),)), (wrong,))
    assert raised.value.location == "mappings.0"


def test_two_mappings_that_describe_one_entity_differently_are_refused_before_the_schema(
    monkeypatch,
):
    """endpoint-isolation.v2 adds `compromise` to Endpoint; endpoint-recovery.v1 does not."""
    from execbound.policy import rulesets

    def unreachable(*_args, **_kwargs):
        raise AssertionError("the schema is built only from contracts that agree")

    isolate = mappings(ISOLATE)[0].model_copy(
        update={"context_contract_version": "endpoint-isolation.v2"}
    )
    with monkeypatch.context() as patch:
        patch.setattr(rulesets, "cedar_schema", unreachable)
        with pytest.raises(RulesetError) as raised:
            compile_ruleset(Ruleset(rules=(rule(),)), (isolate, *mappings(LIFT)))
    assert raised.value.location == "mappings.1"
    assert str(raised.value) == (
        "Mappings endpoint.isolate (endpoint-isolation.v2) and endpoint.lift_isolation "
        "(endpoint-recovery.v1) describe the Endpoint entity differently and cannot share "
        "a bundle"
    )
    # Two contracts that describe it alike still share one.
    compiled(rule(), actions=(ISOLATE, LIFT))


def named(ref, action=ISOLATE, version="endpoint-isolation.v1"):
    """A mapping whose operation ref is not its catalog action's name (`mapping-create --ref`)."""
    return MappingRef(
        operation_ref=ref,
        action=action,
        account_id=uuid4(),
        mapping_version="map-v1",
        schema_version="action.v1",
        context_contract_version=version,
    )


def test_a_mapping_whose_ref_names_its_action_compiles_as_that_action():
    """The ref is the operator's name; the rules, the schema and the fields are the action's."""
    plain = compiled(rule())
    custom = named("isolate.corroborated")
    assert compile_ruleset(Ruleset(rules=(rule(),)), (custom,)) == plain
    assert writable_fields((custom,)) == writable_fields(mappings(ISOLATE))
    assert set(writable_fields((custom,))) == {ISOLATE}
    # Two refs for one action on one contract describe it once, and alike.
    assert compile_ruleset(Ruleset(rules=(rule(),)), (*mappings(ISOLATE), custom)) == plain
    assert writable_fields((*mappings(ISOLATE), custom)) == writable_fields(mappings(ISOLATE))
    with pytest.raises(RulesetError) as raised:
        compile_ruleset(Ruleset(rules=(rule(action=LIFT),)), (custom,))
    assert raised.value.location == "rules.0.action"
    # An action the catalog lacks is named as the mapping's, not as its ref.
    unknown = named("isolate.corroborated", action="endpoint.explode")
    with pytest.raises(RulesetError) as raised:
        compile_ruleset(Ruleset(rules=(rule(),)), (unknown,))
    assert (raised.value.location, str(raised.value)) == (
        "mappings.0",
        "Mapping action is not a catalog action: endpoint.explode",
    )


def test_one_action_under_two_contracts_is_refused_where_the_second_is():
    """One Cedar action, one entity: it cannot mean v1's facts and v2's in one bundle."""
    corroborated = named("isolate.corroborated", version="endpoint-isolation.v2")
    with pytest.raises(RulesetError) as raised:
        compile_ruleset(Ruleset(rules=(rule(),)), (*mappings(ISOLATE), corroborated))
    assert raised.value.location == "mappings.1"
    assert str(raised.value) == (
        "Mappings endpoint.isolate (endpoint-isolation.v1) and isolate.corroborated "
        "(endpoint-isolation.v2) serve endpoint.isolate under different contracts and "
        "cannot share a bundle"
    )
    # Chosen on its own, the v2 ref compiles as endpoint.isolate on v2.
    alone = compile_ruleset(Ruleset(rules=(rule(),)), (corroborated,))
    assert '"compromise"' in alone.cedar_schema


def test_the_early_entity_check_refuses_exactly_what_the_schema_would():
    """The compiler's early check and `cedar_schema` read one description of an entity."""
    catalog = PRODUCTION_CATALOG
    served = [
        (action, version)
        for version in sorted(catalog.versions)
        for action in sorted(catalog.contract(version).actions)
    ]
    checked = 0
    for (first, first_version), (second, second_version) in permutations(served, 2):
        if first == second:
            continue
        pair = (
            MappingRef(
                operation_ref=first,
                account_id=uuid4(),
                mapping_version="map-v1",
                schema_version="action.v1",
                context_contract_version=first_version,
            ),
            MappingRef(
                operation_ref=second,
                account_id=uuid4(),
                mapping_version="map-v1",
                schema_version="action.v1",
                context_contract_version=second_version,
            ),
        )
        rules = Ruleset(rules=(Rule(id="allow", action=first, effect="ALLOW"),))
        try:
            cedar_schema(
                {
                    first: catalog.contract(first_version),
                    second: catalog.contract(second_version),
                },
                actions=catalog.actions,
            )
        except SchemaError:
            with pytest.raises(RulesetError) as raised:
                compile_ruleset(rules, pair, catalog=catalog)
            assert raised.value.location == "mappings.1"
            checked += 1
        else:
            compile_ruleset(rules, pair, catalog=catalog)
    assert checked


def test_a_ruleset_of_only_reviews_produces_no_authorization_set_and_is_refused():
    """Not a policy judgement: `BundleContent.authorization_policies` cannot be empty.

    A set of only denials is legal and compiles, because refusing it would invent a rule the
    bundle format does not have. A set of only reviews emits no authorization policy at all,
    which no bundle can hold, so it is refused here with a location rather than at activation
    as an opaque model error.
    """
    compiled(rule(id="deny-dc", effect="DENY"))
    with pytest.raises(RulesetError) as raised:
        compiled(rule(id="review", effect="REVIEW", quorum=2))
    assert raised.value.location == "rules"


@pytest.mark.parametrize(
    "changes",
    [
        {"quorum": 2, "effect": "ALLOW"},
        {"quorum": 1, "effect": "REVIEW"},
        {"quorum": 6, "effect": "REVIEW"},
        {"note": "x" * 201},
        {
            "when": tuple(
                Condition(kind="fact", name="role", operator="is", values=("workstation",))
                for _ in range(9)
            )
        },
    ],
    ids=[
        "quorum without review",
        "quorum below two",
        "quorum above five",
        "note too long",
        "ninth condition",
    ],
)
def test_the_model_refuses_a_rule_it_cannot_mean(changes):
    with pytest.raises(ValidationError):
        rule(**changes)


def test_a_ruleset_beyond_the_rule_bound_is_refused():
    with pytest.raises(ValidationError):
        Ruleset(rules=tuple(rule(id=f"rule-{index:03d}") for index in range(65)))


def test_two_rules_cannot_share_an_id():
    with pytest.raises(ValidationError):
        Ruleset(rules=(rule(), rule()))


@pytest.mark.parametrize(
    "condition",
    [
        {"operator": "is", "values": ("workstation", "server")},
        {"operator": "in", "values": ("workstation", "workstation")},
    ],
    ids=["several values without in", "duplicate value"],
)
def test_the_model_refuses_a_condition_whose_values_do_not_match_its_operator(condition):
    with pytest.raises(ValidationError):
        Condition(**{"kind": "fact", "name": "role"} | condition)


# --- the schema generator -------------------------------------------------------------


def test_the_generated_schema_is_sorted_and_stable():
    policy = compiled(rule(), actions=(ISOLATE, LIFT))
    assert policy.cedar_schema == compiled(rule(), actions=(LIFT, ISOLATE)).cedar_schema


def test_the_generator_refuses_a_catalog_it_cannot_describe():
    with pytest.raises(SchemaError):
        cedar_schema(
            {},
            actions=__import__(
                "execbound.operations", fromlist=["PRODUCTION_ACTIONS"]
            ).PRODUCTION_ACTIONS,
        )


# --- obligation ids -------------------------------------------------------------------


def test_a_hand_written_bundles_obligation_ids_are_unchanged_by_this_unit():
    """The guard on the whole change: obligation ids are replayed, so they cannot move.

    `replay/verify.py` compares a decision's obligation_ids against the captured ones and
    `execution.approvals` reads them back from storage, so every bundle written before rulesets
    existed must keep resolving to the identifier it already resolved to. This asserts the exact
    set rather than a count, because a count passes on renamed ids.
    """
    assert approval_policy_ids(schema=CEDAR_SCHEMA, approval=APPROVAL) == frozenset(
        {"policy0", "policy1", "policy2", "policy3", "policy4", "policy5"}
    )


# --- the bundle -----------------------------------------------------------------------


def seeded_ruleset_bundle(admin_engine, world):
    """A bundle whose five components are exactly what its ruleset compiles to."""
    seeded = seeded_soc_bundle(admin_engine, world)
    rules = Ruleset(
        rules=(
            rule(),
            rule(
                id="deny-dc",
                effect="DENY",
                when=(
                    Condition(
                        kind="fact", name="role", operator="is", values=("domain_controller",)
                    ),
                ),
            ),
            rule(
                id="review-production",
                effect="REVIEW",
                quorum=2,
                when=(Condition(kind="fact", name="is_production", operator="is", values=(True,)),),
            ),
        ),
        budgets=(
            LimitRule(
                rule_id="isolations-per-hour",
                action=ISOLATE,
                scope="tenant",
                window_seconds=3600,
                max_targets=3,
                budget="total",
                on_exceed="DENY",
            ),
        ),
    )
    policy = compile_ruleset(rules, seeded.mappings, catalog=TEST_CATALOG)
    return seeded.model_copy(
        update={
            "bundle_id": uuid4(),
            "cedar_schema": policy.cedar_schema,
            "authorization_policies": policy.authorization_policies,
            "approval_policies": policy.approval_policies,
            "limits": policy.limits,
            "quorum": policy.quorum,
            "ruleset": rules,
        }
    )


def test_a_bundle_whose_components_are_its_rulesets_output_activates(db, world, admin_engine):
    """End to end through the real store, which is also the generated schema's first real test.

    `_components` runs `validate_bundle_contracts` over the Cedar schema, so a generated schema
    that drifted from the contracts it describes fails here rather than at a customer.
    """
    bundle = seeded_ruleset_bundle(admin_engine, world)
    create_bundle(db, world["admin"], bundle, world["clock"])
    validate_bundle(db, world["admin"], bundle.bundle_id, world["clock"], catalog=TEST_CATALOG)
    activate_bundle(db, world["admin"], bundle.bundle_id, world["clock"], catalog=TEST_CATALOG)


@pytest.mark.parametrize(
    "component",
    ["cedar_schema", "authorization_policies", "approval_policies", "limits", "quorum"],
)
def test_a_component_edited_away_from_its_ruleset_is_refused_and_named(
    db, world, admin_engine, component
):
    """The safety property: policy text can never say something the rules do not.

    Each component is moved on its own, so every one of the five is load-bearing rather than
    only the first the check happens to reach.
    """
    bundle = seeded_ruleset_bundle(admin_engine, world)
    # Each edit must stay structurally valid, because `_components` runs first and a broken
    # component is refused as a component defect before the ruleset is ever consulted. What is
    # under test here is a bundle that is perfectly well-formed and simply disagrees with its
    # own rules.
    schema = json.loads(bundle.cedar_schema)
    schema["ExecBound"]["entityTypes"]["Unused"] = {"shape": {"type": "Record", "attributes": {}}}
    edited = {
        "cedar_schema": canonical_json(schema),
        "authorization_policies": bundle.authorization_policies.replace(
            "workstation", "domain_controller"
        ),
        "approval_policies": bundle.approval_policies.replace(
            "is_production == true", "is_production == false"
        ),
        "limits": bundle.limits[:0] + (bundle.limits[0].model_copy(update={"max_targets": 9}),),
        "quorum": None,
    }[component]
    moved = bundle.model_copy(update={"bundle_id": uuid4(), component: edited})
    create_bundle(db, world["admin"], moved, world["clock"])
    with pytest.raises(PolicyStoreError) as caught:
        validate_bundle(db, world["admin"], moved.bundle_id, world["clock"], catalog=TEST_CATALOG)
    assert caught.value.code == "RULESET_MISMATCH"
    assert caught.value.location == component


def test_a_bundle_without_a_ruleset_carries_no_trace_of_one(db, world, admin_engine):
    """The frozen-bytes guard: the field is absent from the serialized form, not merely null.

    Every bundle written before this unit is a bundle without a ruleset, and its content hash
    is computed over these bytes. An `exclude_if` that stopped working would put `"ruleset":
    null` into the JSON and move every one of those hashes.
    """
    bundle = seeded_soc_bundle(admin_engine, world)
    assert bundle.ruleset is None
    assert "ruleset" not in bundle.model_dump_json()
    assert "ruleset" not in bundle.model_dump(mode="json")
    create_bundle(db, world["admin"], bundle, world["clock"])
    validate_bundle(db, world["admin"], bundle.bundle_id, world["clock"], catalog=TEST_CATALOG)


def test_a_review_rule_without_a_quorum_still_shifts_the_positions_after_it():
    """The off-by-one this compiler could plausibly have: a policy emitted but not counted.

    A REVIEW rule with no quorum needs no obligation, yet it still writes an approval policy,
    so everything after it moves. If the position were taken from the quorum list rather than
    the approval list, `review-b` would claim `policy0` here and a two-approver requirement
    would silently attach to the wrong rule.
    """
    policy = compiled(
        rule(),
        rule(id="review-a", effect="REVIEW"),
        rule(id="review-b", effect="REVIEW", quorum=2),
    )
    assert policy.quorum is not None and len(policy.quorum) == 1
    assert policy.quorum[0].rule_id == "review-b"
    assert policy.quorum[0].obligation == "policy:policy1"
    assert approval_policy_ids(
        schema=policy.cedar_schema, approval=policy.approval_policies
    ) == frozenset({"policy0", "policy1"})


# --- what the pages show -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({}, "Allow endpoint.isolate when role is workstation."),
        (
            {
                "when": (
                    Condition(kind="fact", name="role", operator="is", values=("workstation",)),
                    Condition(kind="fact", name="incident_status", operator="is", values=("OPEN",)),
                    Condition(kind="fact", name="criticality", operator="at_most", values=(3,)),
                )
            },
            "Allow endpoint.isolate when role is workstation, incident_status is OPEN "
            "and criticality is at most 3.",
        ),
        (
            {
                "id": "deny-servers",
                "effect": "DENY",
                "when": (
                    Condition(
                        kind="fact",
                        name="role",
                        operator="in",
                        values=("server", "domain_controller"),
                    ),
                ),
            },
            "Deny endpoint.isolate when role is one of server, domain_controller.",
        ),
        (
            {
                "id": "review-prod",
                "effect": "REVIEW",
                "quorum": 2,
                "when": (
                    Condition(kind="fact", name="is_production", operator="is", values=(True,)),
                ),
            },
            "Review endpoint.isolate (2 approvers) when is_production is true.",
        ),
        ({"id": "review-all", "effect": "REVIEW", "when": ()}, "Review endpoint.isolate always."),
        (
            {
                "id": "not-servers",
                "when": (
                    Condition(kind="fact", name="role", operator="is_not", values=("server",)),
                ),
            },
            "Allow endpoint.isolate when role is not server.",
        ),
    ],
    ids=[
        "one condition",
        "three conditions",
        "in",
        "review with quorum",
        "no conditions",
        "is not",
    ],
)
def test_a_rule_reads_as_one_sentence(changes, expected):
    """The wording the pages show beside the Cedar; never the decision, which is the kernel's."""
    assert sentence(rule(**changes)) == expected


def test_a_note_is_not_part_of_the_sentence():
    assert "<b>" not in sentence(rule(note="<b>why</b>"))


def test_review_rule_ids_name_the_obligations_the_engine_actually_raises():
    """A preview says which rule changed an answer; the map is checked against the engine.

    The engine numbers approval policies by position in the order the compiler writes them.
    This asks the engine for the ids it raises and the compiler for the quorum it emitted, and
    requires the map to agree with both, rather than restating the compiler's arithmetic.
    """
    rules = (
        rule(),
        rule(id="review-b", effect="REVIEW", quorum=3),
        rule(id="review-a", effect="REVIEW"),
        rule(id="deny-dc", effect="DENY"),
    )
    ruleset = Ruleset(rules=rules)
    policy = compile_ruleset(ruleset, mappings(ISOLATE))
    named = review_rule_ids(ruleset)
    raised = {
        f"policy:{policy_id}"
        for policy_id in approval_policy_ids(
            schema=policy.cedar_schema, approval=policy.approval_policies
        )
    }
    assert set(named) == raised
    assert set(named.values()) == {"review-a", "review-b"}
    # The quorum the compiler emitted names the same obligation the map does for that rule.
    assert policy.quorum is not None and len(policy.quorum) == 1
    [quorum] = policy.quorum
    assert named[quorum.obligation] == "review-b"


def test_creating_a_ruleset_bundle_is_audited_as_compiled_from_rules(db, world, admin_engine):
    """Beside `policy.bundle_created`, never instead of it, and with counts rather than text."""
    seeded = seeded_soc_bundle(admin_engine, world)
    ruleset = Ruleset(rules=(rule(), rule(id="deny-dc", effect="DENY")))
    bundle = ruleset_bundle(
        ruleset,
        tenant_id=seeded.tenant_id,
        bundle_id=uuid4(),
        mappings=seeded.mappings,
        catalog=TEST_CATALOG,
    )
    create_bundle(db, world["admin"], bundle, world["clock"])
    tenant = world["identity"].tenant_id
    created = [
        e
        for e in audit(admin_engine, tenant, "policy.bundle_created")
        if e["bundle_id"] == str(bundle.bundle_id)
    ]
    compiled = [
        e
        for e in audit(admin_engine, tenant, "policy.ruleset_compiled")
        if e["bundle_id"] == str(bundle.bundle_id)
    ]
    assert len(created) == 1 and len(compiled) == 1
    # Like every policy lifecycle event, it names the credential that acted.
    assert compiled[0] == {
        "bundle_id": str(bundle.bundle_id),
        "content_hash": bundle.content_hash,
        "rules": 2,
        "budgets": 0,
        "actor_credential_id": str(world["admin"].credential_id),
    }
    # A bundle pasted as a document carries no ruleset and gets no such event.
    assert not [
        e
        for e in audit(admin_engine, tenant, "policy.ruleset_compiled")
        if e["bundle_id"] == str(seeded.bundle_id)
    ]


# --- Reading the rules for a person ---------------------------------------------------------

WORKSTATION = {
    "role": "workstation",
    "environment": "development",
    "criticality": 1,
    "is_production": False,
    "incident_status": "OPEN",
    "incident_severity": "CRITICAL",
}


def test_a_reading_names_its_rules_follows_precedence_and_says_what_it_lacked():
    """`project` is the pages' reading, never the decision; it must at least read honestly."""
    read = lambda facts, arguments=None: project(ENDPOINT_RULESET, ISOLATE, facts, arguments)  # noqa: E731
    assert read(WORKSTATION) == Projection("allow", ("isolate-workstation-open-critical",))
    production = {**WORKSTATION, "environment": "production", "is_production": True}
    assert read(production) == Projection(
        "require approval", ("isolate-workstation-open-critical", "isolate-production-needs-review")
    )
    # A denial wins over an allow and a review that also apply, and is the only rule named.
    assert read({**production, "role": "domain_controller"}) == Projection(
        "deny", ("isolate-never-domain-controller",)
    )
    # Nothing allows a server: the reading is the default denial, resting on no rule.
    assert read({**WORKSTATION, "role": "server"}) == Projection("deny", ())
    # Values are compared with their type, as Cedar would: a text "4" is not the number 4
    # and an integer 1 is not the boolean true, so neither rule reads as applying.
    assert read({**WORKSTATION, "criticality": "4"}).effect == "allow"
    assert read({**production, "is_production": 1}).effect == "allow"
    assert read({**WORKSTATION, "criticality": 4}) == Projection(
        "deny", ("isolate-never-criticality-4",)
    )
    # A fact no value was given for leaves its rule unread and is named, not guessed at.
    partial = {key: value for key, value in WORKSTATION.items() if not key.startswith("incident")}
    assert read(partial) == Projection("deny", (), ("incident_status", "incident_severity"))
    # An argument condition reads the arguments and never the facts.
    lift = "endpoint.lift_isolation"
    assert project(SOC_RULESET, lift, WORKSTATION, {"reason": "false_positive"}) == Projection(
        "allow", ("lift-when-false-positive",)
    )
    assert project(SOC_RULESET, lift, {**WORKSTATION, "reason": "false_positive"}) == Projection(
        "deny", (), ("reason",)
    )


def fixture_hosts():
    """The hosts the fixture writes, each with an open critical incident."""
    accounts = {ENDPOINT_PROVIDER: str(uuid4()), IDENTITY_PROVIDER: str(uuid4())}
    return [
        {**target, "criticality": 1, "incident_severity": "CRITICAL"}
        for target in fixture_targets("seed", uuid4(), accounts)
    ]


def test_the_rules_read_every_fact_a_fixture_host_presents():
    """`host_facts` names every fact the pack's rules read on each fixture host, so a reading
    over one is never partial. Whether the reading equals what the sandbox seeder states is
    the seeder's plugin's own test."""
    hosts = fixture_hosts()
    assert len(hosts) == 32
    for host in hosts:
        reading = project(SOC_RULESET, FIRST_ACTION[host["resource_type"]], host_facts(host))
        assert reading.unknown == (), host["label"]
        assert reading.rules or reading.effect == "deny", host["label"]
    # A host with no open incident presents no incident facts, and the reading says so.
    bare = {**hosts[0], "incident_id": None}
    assert project(SOC_RULESET, "endpoint.isolate", host_facts(bare)).unknown == (
        "incident_status",
        "incident_severity",
    )


@pytest.mark.parametrize(
    ("condition", "line"),
    [
        (fact("role", "is", "workstation"), "role is workstation"),
        (fact("role", "is_not", "server"), "role is not server"),
        (
            fact("role", "in", "server", "domain_controller"),
            "role is one of server, domain_controller",
        ),
        (fact("criticality", "at_least", 3), "criticality is at least 3"),
        (fact("criticality", "at_most", 2), "criticality is at most 2"),
        (fact("is_production", "is", True), "is_production is true"),
        (argument("reason", "is", "false_positive"), "argument reason is false_positive"),
    ],
)
def test_a_condition_reads_back_in_the_words_the_editor_parses(condition, line):
    """`condition_line` is the inverse of the rules editor's grammar, which is how the
    assistant's proposal can pre-fill the form it never submits (#330)."""
    assert condition_line(condition) == line
