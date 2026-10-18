# SPDX-License-Identifier: AGPL-3.0-only
"""A signal fact read back and changed on the console's rules page (#478, #273).

The Defender for Endpoint scenario's own rules (`integrations/mde-producer/scenario`), compiled
over an `endpoint-isolation.v2` mapping under its own ref, `isolate.corroborated`, with the
scenario's verdict table as the draft's signal mapping. What #478's close-out left unshown is
whether the rules page reads that draft the way it reads any other: the REVIEW rule with its
`compromise is_not compromised` condition and its sentence, the `compromise` fact offered by
the add-a-rule form with the capability's declared domain, and a change of the compromise
condition written as a successor draft that keeps the signal mapping and still validates.
"""

from pathlib import Path
from uuid import UUID, uuid4

from console_api_fixtures import API, assert_no_secrets, console_client
from pydantic import TypeAdapter
from signal_fixtures import CAPABILITY, V2, register
from test_console_api_rules import events
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound import administration as admin
from execbound.cli import load_ruleset_file
from execbound.policy.models import MappingRef
from execbound.policy.rulesets import ruleset_bundle, writable_fields
from execbound.policy.store import create_bundle, read_bundle
from execbound.signals.capabilities import RESOURCE_COMPROMISE_V1
from execbound.signals.models import SignalMapping, SignalThreshold

POLICY = API + "/policy"
SCENARIO = Path(__file__).resolve().parents[1] / "integrations" / "mde-producer" / "scenario"
REVIEW = "isolate-review-unless-compromised"
COMPROMISE_NOT_COMPROMISED = {
    "kind": "fact",
    "name": "compromise",
    "operator": "is_not",
    "values": ["compromised"],
}


def scenario_draft(db, admin_engine, world, tmp_path) -> tuple[UUID, SignalMapping]:
    """The MDE scenario as a DRAFT written as rules, over `isolate.corroborated` on v2.

    Built the way `ruleset-compile --ref isolate.corroborated --signal-mappings` builds it: the
    rules file's own context settings carried as the bundle's, and one signal mapping that
    admits one registered source through the committed verdict table.
    """
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    mapping = admin.create_mapping(
        admin_engine,
        tenant,
        world["account"],
        "endpoint.isolate",
        actor,
        operation_ref="isolate.corroborated",
        context_contract_version=V2,
    )
    source, _token = register(admin_engine, world, tmp_path / "signal-token")
    thresholds = TypeAdapter(tuple[SignalThreshold, ...]).validate_json(
        (SCENARIO / "thresholds.json").read_text(encoding="utf-8")
    )
    signal = SignalMapping(
        context_contract_version=V2,
        capability=CAPABILITY,
        admitted_sources=(source,),
        thresholds=thresholds,
    )
    ruleset = load_ruleset_file(SCENARIO / "rules.json")
    content = ruleset_bundle(
        ruleset,
        tenant_id=tenant,
        bundle_id=uuid4(),
        mappings=(
            MappingRef(
                operation_ref=mapping.operation_ref,
                account_id=mapping.account_id,
                mapping_version=mapping.mapping_version,
                schema_version="action.v1",
                context_contract_version=mapping.context_contract_version,
                action="endpoint.isolate",
            ),
        ),
        context_settings=ruleset.context,
        signal_mappings=(signal,),
    )
    create_bundle(db, world["admin"], content, world["clock"])
    return content.bundle_id, signal


def stated(view: dict) -> dict:
    """The ruleset as the console's editor states it back: every rule, every budget."""
    return {
        "rules": [
            {key: rule[key] for key in ("id", "action", "effect", "when", "quorum", "note")}
            for group in view["groups"]
            for rule in group["rules"]
        ],
        "budgets": [
            {
                key: budget[key]
                for key in (
                    "rule_id",
                    "action",
                    "scope",
                    "window_seconds",
                    "max_targets",
                    "budget",
                    "on_exceed",
                )
            }
            for budget in view["budgets"]
        ],
    }


def test_the_rules_page_reads_back_the_compromise_condition_and_its_sentence(
    db, runtime, admin_engine, world, tmp_path
):
    bundle_id, _signal = scenario_draft(db, admin_engine, world, tmp_path)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        page = client.get(f"{POLICY}/{bundle_id}/rules")
        assert page.status_code == 200, page.text
        assert_no_secrets(page)
        body = page.json()
    assert body["editable"] is True and body["written_as_rules"] is True
    # Rules speak of the action the ref serves, never of the ref.
    assert [group["action"] for group in body["groups"]] == ["endpoint.isolate"]
    rules = {rule["id"]: rule for rule in body["groups"][0]["rules"]}
    assert list(rules) == [
        "isolate-open-incident",
        "isolate-never-domain-controller",
        REVIEW,
    ]
    review = rules[REVIEW]
    assert review["effect"] == "REVIEW" and review["quorum"] is None
    assert review["when"] == [COMPROMISE_NOT_COMPROMISED]
    assert review["sentence"] == "Review endpoint.isolate when compromise is not compromised."
    assert review["note"] == load_ruleset_file(SCENARIO / "rules.json").rules[2].note
    # The compiled policy the page shows beside the rules is about the same fact.
    assert "compromise" in body["compiled"]["cedar_schema"]
    assert "compromise" in body["compiled"]["approval_policies"]


def test_the_form_offers_the_compromise_fact_with_the_capability_s_declared_domain(
    db, runtime, admin_engine, world, tmp_path
):
    bundle_id, _signal = scenario_draft(db, admin_engine, world, tmp_path)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        body = client.get(f"{POLICY}/{bundle_id}/rules").json()
        # The world's own bundle maps endpoint.isolate on v1, whose contract has no signal.
        v1 = client.get(f"{POLICY}/{world['bundle'].bundle_id}/rules").json()
    assert [field["action"] for field in body["fields"]] == ["endpoint.isolate"]
    choices = {choice["name"]: choice for choice in body["fields"][0]["choices"]}
    # The fact's domain is the capability's, all four values: the form writes rules about the
    # fact, and `clean` is a value a source that attests liveness may produce, even though the
    # scenario's own verdict table never maps to it.
    assert choices["compromise"] == {
        "kind": "fact",
        "name": "compromise",
        "cedar_type": "String",
        "operators": ["is", "is_not", "in"],
        "values": sorted(RESOURCE_COMPROMISE_V1.values),
        "minimum": None,
        "maximum": None,
    }
    assert set(choices["compromise"]["values"]) == {
        "clean",
        "no_detection",
        "suspect",
        "compromised",
    }
    # Every name the form offers is one the compiler knows for this draft's mappings.
    record = read_bundle(db, world["admin"], bundle_id, world["clock"])
    known = writable_fields(record.content.mappings)["endpoint.isolate"]
    assert set(choices) == {choice.name for choice in known}
    # The v1 contract's form offers everything but the signal fact.
    v1_names = {choice["name"] for choice in v1["fields"][0]["choices"]}
    assert "compromise" not in v1_names
    assert v1_names == set(choices) - {"compromise"}


def test_a_compromise_condition_removed_and_added_again_is_a_successor_that_validates(
    db, runtime, admin_engine, world, tmp_path
):
    bundle_id, signal = scenario_draft(db, admin_engine, world, tmp_path)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        read = client.get(f"{POLICY}/{bundle_id}/rules").json()
        body = stated(read)
        assert body["rules"][2]["when"] == [COMPROMISE_NOT_COMPROMISED]

        # Removed: the review rule no longer reads the signal and reviews every isolation.
        without = {
            **body,
            "rules": [*body["rules"][:2], {**body["rules"][2], "when": []}],
        }
        removed = client.post(f"{POLICY}/{bundle_id}/rules", without)
        assert removed.status_code == 200, removed.text
        assert_no_secrets(removed)
        second = removed.json()
        assert second["bundle_id"] != str(bundle_id)
        assert second["state"] == "DRAFT" and second["editable"] is True
        review = {rule["id"]: rule for rule in second["groups"][0]["rules"]}[REVIEW]
        assert review["when"] == [] and review["sentence"] == "Review endpoint.isolate always."
        assert "compromise" not in second["compiled"]["approval_policies"]

        # Added back in another shape: two approvers unless the EDR reports compromise.
        again = {
            "kind": "fact",
            "name": "compromise",
            "operator": "in",
            "values": ["no_detection", "suspect"],
        }
        stated_again = stated(second)
        stated_again["rules"][2] = {**stated_again["rules"][2], "when": [again], "quorum": 2}
        added = client.post(f"{POLICY}/{second['bundle_id']}/rules", stated_again)
        assert added.status_code == 200, added.text
        third = added.json()
        assert third["bundle_id"] not in (str(bundle_id), second["bundle_id"])
        review = {rule["id"]: rule for rule in third["groups"][0]["rules"]}[REVIEW]
        assert review["when"] == [again] and review["quorum"] == 2
        assert review["sentence"] == (
            "Review endpoint.isolate (2 approvers) when compromise is one of no_detection, suspect."
        )
        assert "compromise" in third["compiled"]["approval_policies"]
        # The form's choices are the same after each step: the mappings decide them.
        assert third["fields"] == read["fields"]

        # Both drafts it replaced are retired and still read as they did.
        listed = {row["bundle_id"]: row["state"] for row in client.get(POLICY).json()["bundles"]}
        assert listed[str(bundle_id)] == "RETIRED"
        assert listed[second["bundle_id"]] == "RETIRED"
        first = client.get(f"{POLICY}/{bundle_id}/rules").json()
        assert first["editable"] is False
        assert first["groups"][0]["rules"][2]["when"] == [COMPROMISE_NOT_COMPROMISED]

        # The successor is a bundle the kernel will take: it validates like any other.
        validated = client.post(f"{POLICY}/{third['bundle_id']}/validate", {"confirm": True})
        assert validated.status_code == 200, validated.text
        assert validated.json()["state"] == "VALIDATED"

    # The body cannot state a signal mapping, so each step carried the draft's forward.
    record = read_bundle(db, world["admin"], UUID(third["bundle_id"]), world["clock"])
    assert record.content.signal_mappings == (signal,)
    assert record.content.ruleset is not None
    assert record.content.ruleset.context == load_ruleset_file(SCENARIO / "rules.json").context


def test_a_compromise_value_outside_the_domain_or_an_ordered_operator_is_refused_where_written(
    db, runtime, admin_engine, world, tmp_path
):
    tenant = world["identity"].tenant_id
    bundle_id, _signal = scenario_draft(db, admin_engine, world, tmp_path)
    changes = len(events(admin_engine, tenant, "policy.rules_changed"))
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        body = stated(client.get(f"{POLICY}/{bundle_id}/rules").json())
        before = {row["bundle_id"]: row["state"] for row in client.get(POLICY).json()["bundles"]}
        assert before[str(bundle_id)] == "DRAFT"
        for condition in (
            {**COMPROMISE_NOT_COMPROMISED, "values": ["breached"]},
            {**COMPROMISE_NOT_COMPROMISED, "operator": "at_least"},
        ):
            sent = {
                **body,
                "rules": [*body["rules"][:2], {**body["rules"][2], "when": [condition]}],
            }
            refused = client.post(f"{POLICY}/{bundle_id}/rules", sent)
            assert refused.status_code == 400, refused.text
            assert refused.json()["code"] == "INVALID_BODY"
            assert refused.json()["fields"] == ["ruleset.rules.2.when.0"]
            assert "breached" not in refused.text
            assert_no_secrets(refused)
        # Nothing was written: the tenant has the same bundles in the same states, and the
        # draft is still the draft, still editable.
        after = {row["bundle_id"]: row["state"] for row in client.get(POLICY).json()["bundles"]}
        assert after == before
        assert client.get(f"{POLICY}/{bundle_id}/rules").json()["editable"] is True
    # And no change was audited.
    assert len(events(admin_engine, tenant, "policy.rules_changed")) == changes
