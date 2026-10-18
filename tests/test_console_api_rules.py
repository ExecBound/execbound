# SPDX-License-Identifier: AGPL-3.0-only
"""A draft's rules, read and changed (#333; #273's read and write functions).

The two routes through the harness first, then what they promise: the rules of a draft grouped
by the actions its mappings serve, the typed domains the add-a-rule form's selects are built
from, and one write that takes the whole ruleset. The write is `change_draft_rules`, which
writes a successor draft and retires the one it replaces, because the application role holds
`SELECT, INSERT` on `policy_bundle_contents` and cannot rewrite a row; the audit chain records
both ends of every step. The refusals #273 specifies are here: an undeclared fact, a value
outside its declared domain and a wrong type each answer with the field's location.
"""

from uuid import UUID, uuid4

import pytest
from console_api_fixtures import API, assert_no_secrets, console_client, refusals
from scope_fixtures import group
from scope_fixtures import owner as owner
from space_fixtures import default_space, make_space, seat
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.policy.models import LimitRule, LimitSelector, Ruleset
from execbound.policy.rulesets import rule_schema, ruleset_bundle, writable_fields
from execbound.policy.store import (
    PolicyStoreError,
    activate_bundle,
    change_draft_rules,
    create_bundle,
    read_bundle,
    validate_bundle,
)
from execbound_harness.demo import ENDPOINT_RULESET, endpoint_bundle

POLICY = API + "/policy"
ZERO = "00000000-0000-0000-0000-000000000000"
ALLOW = {
    "id": "allow-workstations",
    "action": "endpoint.isolate",
    "effect": "ALLOW",
    "when": [{"kind": "fact", "name": "role", "operator": "is", "values": ["workstation"]}],
    "quorum": None,
    "note": None,
}
DENY = {
    "id": "deny-domain-controllers",
    "action": "endpoint.isolate",
    "effect": "DENY",
    "when": [{"kind": "fact", "name": "role", "operator": "is", "values": ["domain_controller"]}],
    "quorum": None,
    "note": None,
}
BUDGET = {
    "rule_id": "principal-hourly",
    "action": "endpoint.isolate",
    "scope": "principal",
    "window_seconds": 3600,
    "max_targets": 3,
    "budget": "autonomous",
    "on_exceed": "REQUIRE_APPROVAL",
}
ROUTES = [
    (f"{POLICY}/{ZERO}/rules", "GET", None),
    (f"{POLICY}/{ZERO}/rules", "POST", {"rules": [ALLOW], "budgets": []}),
]


def ruleset_draft(db, world, ruleset: Ruleset | None = None) -> UUID:
    """A DRAFT written as rules for this tenant, which is what the editor edits."""
    content = ruleset_bundle(
        ruleset or ENDPOINT_RULESET,
        tenant_id=world["identity"].tenant_id,
        bundle_id=uuid4(),
        mappings=world["bundle"].mappings,
    )
    create_bundle(db, world["admin"], content, world["clock"])
    return content.bundle_id


def events(admin_engine, tenant, kind: str) -> list[dict]:
    with admin_engine.connect() as conn:
        return [
            row["payload"]
            for row in conn.execute(
                text(
                    "SELECT payload FROM execbound.audit_events "
                    "WHERE tenant_id=:t AND kind=:k ORDER BY sequence"
                ),
                {"t": tenant, "k": kind},
            ).mappings()
        ]


@pytest.mark.parametrize("path,method,_body", ROUTES)
def test_every_route_refuses_a_bearer_and_no_session(
    db, runtime, seeded, admin_engine, world, path, method, _body
):
    results = refusals(db, runtime, seeded, admin_engine, world, path, method)
    assert results["bearer"].status_code == 403 and results["bearer"].json()["code"] == "FORBIDDEN"
    assert results["audited"] == 1
    assert results["no_session"].status_code == 401


def test_an_approver_is_refused_both_routes(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        for path, method, body in ROUTES:
            response = approver.get(path) if method == "GET" else approver.post(path, body)
            assert response.status_code == 403, (path, response.text)
            assert response.json()["code"] == "FORBIDDEN"
            assert_no_secrets(response)


def test_the_rules_read_grouped_by_action_with_the_form_s_typed_domains(
    db, runtime, admin_engine, world
):
    bundle_id = ruleset_draft(db, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        page = client.get(f"{POLICY}/{bundle_id}/rules")
        assert page.status_code == 200, page.text
        assert_no_secrets(page)
        body = page.json()
        assert body["editable"] is True and body["written_as_rules"] is True
        assert [group["action"] for group in body["groups"]] == ["endpoint.isolate"]
        group = body["groups"][0]
        assert group["label"] and group["rules"]
        assert {rule["effect"] for rule in group["rules"]} <= {"ALLOW", "DENY", "REVIEW"}
        assert all(rule["sentence"].endswith(".") for rule in group["rules"])
        # The form's selects come from the contract's declared domains and nothing else.
        choices = {choice["name"]: choice for choice in body["fields"][0]["choices"]}
        assert choices["role"]["values"] == ["domain_controller", "server", "workstation"]
        assert choices["role"]["operators"] == ["is", "is_not", "in"]
        assert choices["criticality"]["cedar_type"] == "Long"
        # Only a Long admits the ordered operators, as the compiler requires.
        assert choices["criticality"]["operators"] == ["is", "is_not", "in", "at_least", "at_most"]
        assert choices["criticality"]["minimum"] == 0 and choices["criticality"]["maximum"] == 4
        assert choices["is_production"]["values"] == [False, True]
        # Every name the form offers is one the compiler knows for this bundle.
        known = {
            choice.name for choice in writable_fields(world["bundle"].mappings)["endpoint.isolate"]
        }
        assert set(choices) == known
        assert body["compiled"]["authorization_policies"]


def test_a_change_writes_a_successor_draft_retires_the_old_one_and_audits_both_ends(
    db, runtime, admin_engine, world
):
    tenant = world["identity"].tenant_id
    bundle_id = ruleset_draft(db, world)
    before = len(events(admin_engine, tenant, "policy.rules_changed"))
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        answer = client.post(f"{POLICY}/{bundle_id}/rules", {"rules": [ALLOW, DENY], "budgets": []})
        assert answer.status_code == 200, answer.text
        assert_no_secrets(answer)
        body = answer.json()
        # The address follows the successor: content is insert-only in the database.
        assert body["bundle_id"] != str(bundle_id)
        assert body["state"] == "DRAFT" and body["editable"] is True
        rules = {rule["id"] for rule in body["groups"][0]["rules"]}
        assert rules == {"allow-workstations", "deny-domain-controllers"}
        assert "forbid(principal" in body["compiled"]["authorization_policies"]
        # The draft it replaced is retired, not rewritten, and still reads as it did.
        listed = {row["bundle_id"]: row for row in client.get(POLICY).json()["bundles"]}
        assert listed[str(bundle_id)]["state"] == "RETIRED"
        old = client.get(f"{POLICY}/{bundle_id}/rules").json()
        assert old["editable"] is False
        assert {rule["id"] for rule in old["groups"][0]["rules"]} != rules

    changed = events(admin_engine, tenant, "policy.rules_changed")
    assert len(changed) == before + 1
    assert changed[-1]["bundle_id"] == body["bundle_id"]
    assert changed[-1]["supersedes"] == str(bundle_id)
    assert changed[-1]["rules"] == 2 and changed[-1]["budgets"] == 0
    # The chain records counts and digests, never the rules' text.
    assert "workstation" not in str(changed[-1])


def test_a_budget_and_a_quorum_and_a_note_are_the_same_write(db, runtime, admin_engine, world):
    bundle_id = ruleset_draft(db, world)
    review = {
        "id": "review-servers",
        "action": "endpoint.isolate",
        "effect": "REVIEW",
        "when": [{"kind": "fact", "name": "role", "operator": "is", "values": ["server"]}],
        "quorum": 2,
        "note": "<img src=x onerror=alert(1)>",
    }
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        answer = client.post(
            f"{POLICY}/{bundle_id}/rules", {"rules": [ALLOW, review], "budgets": [BUDGET]}
        )
        assert answer.status_code == 200, answer.text
        body = answer.json()
        shown = {rule["id"]: rule for rule in body["groups"][0]["rules"]}
        assert shown["review-servers"]["quorum"] == 2
        # A note is carried as text and is not part of the sentence or the compiled policy.
        assert shown["review-servers"]["note"] == review["note"]
        assert review["note"] not in shown["review-servers"]["sentence"]
        assert review["note"] not in str(body["compiled"])
        budget = body["budgets"][0]
        assert budget["rule_id"] == "principal-hourly" and budget["editable"] is True
        assert budget["max_targets"] == 3 and budget["window"] == "1 hour"
        # The quorum reached the compiled bundle, named by its rule on the bundle page.
        detail = client.get(f"{POLICY}/{body['bundle_id']}").json()
        assert [row["rule"] for row in detail["quorum"]] == ["review-servers"]
        assert detail["limits"][0]["rule_id"] == "principal-hourly"


@pytest.mark.parametrize(
    "condition,where",
    [
        ({"kind": "fact", "name": "colour", "operator": "is", "values": ["red"]}, "when.0"),
        ({"kind": "fact", "name": "role", "operator": "is", "values": ["router"]}, "when.0"),
        ({"kind": "fact", "name": "criticality", "operator": "is", "values": [9]}, "when.0"),
        ({"kind": "fact", "name": "role", "operator": "at_least", "values": ["server"]}, "when.0"),
        ({"kind": "argument", "name": "reason", "operator": "is", "values": ["x"]}, "when.0"),
    ],
    ids=[
        "unknown fact",
        "out of domain",
        "out of range",
        "ordered on a string",
        "unknown argument",
    ],
)
def test_the_form_refuses_a_condition_the_compiler_would_not_accept(
    db, runtime, admin_engine, world, condition, where
):
    """#273's own list, each answered with the field's location and never the value at fault."""
    bundle_id = ruleset_draft(db, world)
    rule = {**ALLOW, "when": [condition]}
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        refused = client.post(f"{POLICY}/{bundle_id}/rules", {"rules": [rule], "budgets": []})
        assert refused.status_code == 400, refused.text
        body = refused.json()
        assert body["code"] == "INVALID_BODY"
        assert body["fields"] == [f"ruleset.rules.0.{where}"], body
        assert str(condition["values"][0]) not in refused.text
        assert_no_secrets(refused)
        # Nothing was written: the draft is still the draft, still editable.
        assert client.get(f"{POLICY}/{bundle_id}/rules").json()["editable"] is True


def test_a_body_the_rule_model_refuses_names_its_own_field(db, runtime, admin_engine, world):
    bundle_id = ruleset_draft(db, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        # A quorum on a rule that is not a review is the model's own rule, not this API's.
        refused = client.post(
            f"{POLICY}/{bundle_id}/rules", {"rules": [{**ALLOW, "quorum": 2}], "budgets": []}
        )
        assert refused.status_code == 400 and refused.json()["code"] == "INVALID_BODY"
        assert any(item.startswith("ruleset.rules.0") for item in refused.json()["fields"])
        # An empty ruleset is refused before the store sees it: nothing would be authorized.
        assert client.post(f"{POLICY}/{bundle_id}/rules", {"rules": []}).status_code == 400
        # A scope the form does not offer is refused at the field rather than half-accepted.
        elsewhere = {**BUDGET, "scope": "selector"}
        refused = client.post(
            f"{POLICY}/{bundle_id}/rules", {"rules": [ALLOW], "budgets": [elsewhere]}
        )
        assert refused.status_code == 400 and refused.json()["fields"] == ["budgets.0.scope"]


def test_only_a_draft_written_as_rules_can_be_changed(db, runtime, admin_engine, world):
    """A validated draft, a hand-written one and the active bundle are read but not edited."""
    bundle_id = ruleset_draft(db, world)
    validate_bundle(db, world["admin"], bundle_id, world["clock"])
    written = endpoint_bundle(
        world["identity"].tenant_id, world["account"], mapping_version="map-v1"
    ).model_copy(update={"bundle_id": uuid4()})
    create_bundle(db, world["admin"], written, world["clock"])
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        for target in (bundle_id, written.bundle_id, world["bundle"].bundle_id):
            view = client.get(f"{POLICY}/{target}/rules")
            assert view.status_code == 200, (target, view.text)
            assert view.json()["editable"] is False
            refused = client.post(f"{POLICY}/{target}/rules", {"rules": [ALLOW], "budgets": []})
            assert refused.status_code == 409, (target, refused.text)
            assert refused.json()["code"] == "CONFLICT"
        # A bundle that is not this tenant's, or none at all, is 404 on both routes.
        assert client.get(f"{POLICY}/{ZERO}/rules").status_code == 404
        assert client.post(f"{POLICY}/{ZERO}/rules", {"rules": [ALLOW]}).status_code == 404


def test_the_changed_draft_validates_and_activates_like_any_other(db, runtime, admin_engine, world):
    """The point of the whole step: rules become a bundle the kernel will execute."""
    bundle_id = ruleset_draft(db, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        made = client.post(
            f"{POLICY}/{bundle_id}/rules", {"rules": [ALLOW, DENY], "budgets": [BUDGET]}
        ).json()["bundle_id"]
        assert client.post(f"{POLICY}/{made}/validate", {"confirm": True}).status_code == 200
        activated = client.post(
            f"{POLICY}/{made}/activate", {"confirm": True, "reason": "Test rollout"}
        )
        assert activated.status_code == 200, activated.text
        assert activated.json()["state"] == "ACTIVE"
    # The store's own mismatch check passed, so the components are the compiler's output.
    record = read_bundle(db, world["admin"], UUID(made), world["clock"])
    assert record.content.ruleset is not None
    assert {rule.id for rule in record.content.ruleset.rules} == {ALLOW["id"], DENY["id"]}


def test_the_store_refuses_a_change_to_something_that_is_not_an_editable_draft(db, world):
    """The function's own boundary, not the route's: the store decides, and it is asked here."""
    active = world["bundle"]
    ruleset = ENDPOINT_RULESET
    with pytest.raises(PolicyStoreError) as refused:
        change_draft_rules(db, world["admin"], active.bundle_id, ruleset, world["clock"])
    assert refused.value.code == "INVALID_STATE"
    # An approver cannot change rules even with a bundle id that is otherwise editable.
    draft = ruleset_draft(db, world)
    with pytest.raises(PolicyStoreError) as refused:
        change_draft_rules(db, world["human"], draft, ruleset, world["clock"])
    assert refused.value.code == "INVALID_IDENTITY"


def test_activating_a_ruleset_draft_that_was_edited_leaves_one_active_bundle(db, world):
    """Two edits in a row, then activation: the chain of retired drafts is the history."""
    first = ruleset_draft(db, world)
    ruleset = ENDPOINT_RULESET
    second = change_draft_rules(db, world["admin"], first, ruleset, world["clock"]).content
    third = change_draft_rules(
        db, world["admin"], second.bundle_id, ruleset, world["clock"]
    ).content
    assert len({first, second.bundle_id, third.bundle_id}) == 3
    validate_bundle(db, world["admin"], third.bundle_id, world["clock"])
    activate_bundle(db, world["admin"], third.bundle_id, world["clock"])
    assert read_bundle(db, world["admin"], third.bundle_id, world["clock"]).state == "ACTIVE"
    for superseded in (first, second.bundle_id):
        assert read_bundle(db, world["admin"], superseded, world["clock"]).state == "RETIRED"


def test_the_rule_models_json_schema_is_exported_for_the_assistant():
    """#330's "Describe a rule" validates the model's answer with this schema."""
    schema = rule_schema()
    assert schema["type"] == "object"
    assert set(schema["properties"]) == {"id", "action", "effect", "when", "quorum", "note"}
    assert schema["additionalProperties"] is False
    assert "Condition" in str(schema["$defs"])


def test_a_change_carries_forward_what_the_body_cannot_say(db, world):
    """A surface that cannot express a field must never be able to drop one.

    The write states rules and budgets. The draft's mappings, its context settings and the
    ruleset's own context settings are the draft's and are carried forward, so an editor with
    no field for them cannot quietly remove them.
    """
    settings = world["bundle"].context_settings
    ruleset = ENDPOINT_RULESET.model_copy(update={"context": settings})
    content = ruleset_bundle(
        ruleset,
        tenant_id=world["identity"].tenant_id,
        bundle_id=uuid4(),
        mappings=world["bundle"].mappings,
        context_settings=settings,
    )
    create_bundle(db, world["admin"], content, world["clock"])
    # The same rules again, stated without a context, as the console's body states them.
    stated = Ruleset.model_validate_json(
        ENDPOINT_RULESET.model_dump_json(include={"rules", "budgets"})
    )
    assert stated.context is None
    after = change_draft_rules(
        db, world["admin"], content.bundle_id, stated, world["clock"]
    ).content
    assert after.ruleset is not None
    assert after.ruleset.context == settings
    assert after.context_settings == settings
    assert after.mappings == world["bundle"].mappings


# ---------------------------------------------------------------------------
# Budgets with a qualifier: a group, an account or a space (#273). The read offers
# the tenant's own groups, the accounts the draft's mappings name and the spaces the draft may
# serve; the write accepts a single-action budget naming one of them and refuses anything else
# at the field. A selector or several-action budget, or one counted for a qualifier the read no
# longer offers, is still read and not edited.
# ---------------------------------------------------------------------------


def tenant_space(admin_engine, world, name: str | None = None) -> UUID:
    """The world's default space, or a new one of its tenant when ``name`` is given."""
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        return make_space(conn, tenant, name) if name else default_space(conn, tenant)


def planted(admin_engine, tenant: UUID, space: UUID) -> dict[str, UUID]:
    """A group, an active connector account and a space of ``tenant``, as real rows.

    Nothing the console offers can create one for a tenant the session is not in, so they are
    written straight to their tables to find out what the rules route does when they exist.
    """
    rows = {"group_id": uuid4(), "account_id": uuid4(), "space_id": space}
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.principal_groups (tenant_id, group_id, name, created_at) "
                "VALUES (:t, :g, 'Elsewhere', now())"
            ),
            {"t": tenant, "g": rows["group_id"]},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts "
                "(tenant_id, account_id, provider, active, space_id) "
                "VALUES (:t, :a, 'mock_crowdstrike', true, :s)"
            ),
            {"t": tenant, "a": rows["account_id"], "s": space},
        )
    return rows


def qualified(scope: str, value: UUID, rule_id: str = "qualified") -> dict:
    """A budget body counted for one group, account or space, as the form sends it."""
    return {**BUDGET, "rule_id": rule_id, "scope": scope, f"{scope}_id": str(value)}


def limit(rule_id: str, **changes) -> LimitRule:
    """The same budget as the model the store keeps, for a draft written past the route."""
    return LimitRule(**{**BUDGET, "rule_id": rule_id, **changes})


def stated(view: dict) -> dict:
    """The body the console's `stated()` sends: every rule and budget the read returned."""
    rules = [
        {key: rule[key] for key in ("id", "action", "effect", "when", "quorum", "note")}
        for group in view["groups"]
        for rule in group["rules"]
    ]
    budgets = []
    for row in view["budgets"]:
        budget = {
            key: row[key]
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
        for key in ("group_id", "account_id", "space_id"):
            if row[key] is not None:
                budget[key] = row[key]
        budgets.append(budget)
    return {"rules": rules, "budgets": budgets}


def test_the_rules_read_offers_only_this_tenant_s_groups_accounts_and_spaces(
    db, runtime, admin_engine, world, seeded, owner
):
    triage = group(owner, world, name="Tier-1 SOC")
    theirs = planted(admin_engine, seeded["tenants"][1], seeded["spaces"][1])
    space = tenant_space(admin_engine, world)
    bundle_id = ruleset_draft(db, world)
    account = world["account"]
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        page = client.get(f"{POLICY}/{bundle_id}/rules")
        assert page.status_code == 200, page.text
        assert_no_secrets(page)
        offered = page.json()["qualifiers"]
    assert offered == {
        "groups": [{"id": str(triage), "label": "Tier-1 SOC"}],
        # The accounts this draft's own mappings name, and no other account of the tenant.
        "accounts": [{"id": str(account), "label": f"mock_crowdstrike ({str(account)[:8]})"}],
        "spaces": [{"id": str(space), "label": "Default"}],
    }
    for value in theirs.values():
        assert str(value) not in page.text
    assert "Elsewhere" not in page.text


def test_a_group_an_account_and_a_space_budget_are_written_read_back_and_activate(
    db, runtime, admin_engine, world, owner
):
    triage = group(owner, world, name="Tier-1 SOC")
    space = tenant_space(admin_engine, world)
    bundle_id = ruleset_draft(db, world)
    budgets = [
        qualified("group", triage, "squad-hourly"),
        qualified("account", world["account"], "account-hourly"),
        qualified("space", space, "space-hourly"),
    ]
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        answer = client.post(f"{POLICY}/{bundle_id}/rules", {"rules": [ALLOW], "budgets": budgets})
        assert answer.status_code == 200, answer.text
        assert_no_secrets(answer)
        body = answer.json()
        shown = {row["rule_id"]: row for row in body["budgets"]}
        assert shown["squad-hourly"]["scope"] == "group"
        assert shown["squad-hourly"]["group_id"] == str(triage)
        assert shown["squad-hourly"]["qualifier"] == "Tier-1 SOC"
        assert shown["account-hourly"]["account_id"] == str(world["account"])
        assert shown["account-hourly"]["qualifier"].startswith("mock_crowdstrike (")
        assert shown["space-hourly"]["space_id"] == str(space)
        assert shown["space-hourly"]["qualifier"] == "Default"
        # Each is a shape the form shows, so the draft stays editable as a whole.
        assert all(row["editable"] for row in body["budgets"]) and body["editable"] is True
        for row in body["budgets"]:
            others = {"group_id", "account_id", "space_id"} - {f"{row['scope']}_id"}
            assert all(row[key] is None for key in others), row
        # What the console restates on its next edit is accepted as it was read back.
        again = client.post(f"{POLICY}/{body['bundle_id']}/rules", stated(body))
        assert again.status_code == 200, again.text
        made = again.json()["bundle_id"]
        assert client.post(f"{POLICY}/{made}/validate", {"confirm": True}).status_code == 200
        activated = client.post(
            f"{POLICY}/{made}/activate", {"confirm": True, "reason": "Test rollout"}
        )
        assert activated.status_code == 200, activated.text
    limits = {
        rule.rule_id: rule
        for rule in read_bundle(db, world["admin"], UUID(made), world["clock"]).content.limits
    }
    assert limits["squad-hourly"].group_id == triage
    assert limits["account-hourly"].account_id == world["account"]
    assert limits["space-hourly"].space_id == space


@pytest.mark.parametrize("scope", ["group", "account", "space"])
def test_a_qualifier_of_another_tenant_is_refused_at_its_field(
    db, runtime, admin_engine, world, seeded, scope
):
    """Another tenant's group, account or space is refused where it was written, and its
    identifier is not echoed. The store's own refusal (T5.11) still stands behind the route:
    a draft that carries one anyway, written through the store, does not validate."""
    theirs = planted(admin_engine, seeded["tenants"][1], seeded["spaces"][1])
    field = f"{scope}_id"
    bundle_id = ruleset_draft(db, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        refused = client.post(
            f"{POLICY}/{bundle_id}/rules",
            {"rules": [ALLOW], "budgets": [BUDGET, qualified(scope, theirs[field])]},
        )
        assert refused.status_code == 400, refused.text
        assert refused.json()["code"] == "INVALID_BODY"
        assert refused.json()["fields"] == [f"ruleset.budgets.1.{field}"]
        assert str(theirs[field]) not in refused.text
        assert_no_secrets(refused)
        # Nothing was written: the draft is still the draft, still editable.
        assert client.get(f"{POLICY}/{bundle_id}/rules").json()["editable"] is True
    budget = limit("elsewhere", scope=scope, **{field: theirs[field]})
    carried = change_draft_rules(
        db,
        world["admin"],
        bundle_id,
        ENDPOINT_RULESET.model_copy(update={"budgets": (budget,)}),
        world["clock"],
    ).content
    with pytest.raises(PolicyStoreError) as invalid:
        validate_bundle(db, world["admin"], carried.bundle_id, world["clock"])
    assert (invalid.value.code, invalid.value.location) == (
        "INVALID_COMPONENT",
        f"limits.0.{field}",
    )


def test_a_qualifier_of_this_tenant_the_draft_cannot_use_is_refused_at_its_field(
    db, runtime, admin_engine, world, seeded
):
    """An account no mapping of the draft names and a space the draft does not serve would
    never charge anything; the form does not offer them and the write does not take them."""
    tenant = world["identity"].tenant_id
    first = tenant_space(admin_engine, world)
    unmapped = planted(admin_engine, tenant, first)["account_id"]
    unserved = tenant_space(admin_engine, world, "Customer B")
    bundle_id = ruleset_draft(db, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        # Two spaces: a write needs the space it lands in.
        chosen = client.post(API + "/session/space", {"space_id": str(first)})
        assert chosen.status_code == 200, chosen.text
        offered = client.get(f"{POLICY}/{bundle_id}/rules").json()["qualifiers"]
        assert [row["id"] for row in offered["accounts"]] == [str(world["account"])]
        assert [row["id"] for row in offered["spaces"]] == [str(first)]
        for scope, value in (("account", unmapped), ("space", unserved)):
            refused = client.post(
                f"{POLICY}/{bundle_id}/rules",
                {"rules": [ALLOW], "budgets": [qualified(scope, value)]},
            )
            assert refused.status_code == 400, (scope, refused.text)
            assert refused.json()["fields"] == [f"ruleset.budgets.0.{scope}_id"], scope
        accepted = client.post(
            f"{POLICY}/{bundle_id}/rules",
            {"rules": [ALLOW], "budgets": [qualified("space", first)]},
        )
        assert accepted.status_code == 200, accepted.text


def test_a_budget_s_scope_and_qualifier_must_agree(db, runtime, admin_engine, world, owner):
    """The model's own rule, at the budget: a scope without its qualifier, a qualifier
    without its scope, or a second qualifier, never widens to the tenant."""
    triage = group(owner, world, name="triage")
    bundle_id = ruleset_draft(db, world)
    cases = [
        ({**BUDGET, "scope": "group"}, "ruleset.budgets.0"),
        ({**BUDGET, "group_id": str(triage)}, "ruleset.budgets.0"),
        (
            {**qualified("group", triage), "account_id": str(world["account"])},
            "ruleset.budgets.0",
        ),
        ({**BUDGET, "scope": "group", "group_id": "not-a-uuid"}, "budgets.0.group_id"),
        ({**BUDGET, "actions": ["endpoint.isolate"]}, "budgets.0.actions"),
    ]
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        for budget, where in cases:
            refused = client.post(
                f"{POLICY}/{bundle_id}/rules", {"rules": [ALLOW], "budgets": [budget]}
            )
            assert refused.status_code == 400, (budget, refused.text)
            assert refused.json()["fields"] == [where], (budget, refused.json())


def test_a_selector_or_several_action_budget_keeps_the_draft_read_only(
    db, runtime, admin_engine, world, owner
):
    """A group budget is a shape the form shows and restates; a selector budget is not, and
    the draft carrying one is still read but not changed, so no edit can drop it."""
    triage = group(owner, world, name="triage")
    grouped = limit("squad", scope="group", group_id=triage)
    selected = limit(
        "workstations", scope="selector", selector=LimitSelector(fact="role", equals="workstation")
    )
    plain = ruleset_draft(db, world, ENDPOINT_RULESET.model_copy(update={"budgets": (grouped,)}))
    mixed = ruleset_draft(
        db, world, ENDPOINT_RULESET.model_copy(update={"budgets": (grouped, selected)})
    )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        view = client.get(f"{POLICY}/{plain}/rules").json()
        assert [(row["rule_id"], row["editable"]) for row in view["budgets"]] == [("squad", True)]
        assert view["budgets"][0]["qualifier"] == "triage"
        restated = client.post(f"{POLICY}/{plain}/rules", stated(view))
        assert restated.status_code == 200, restated.text
        view = client.get(f"{POLICY}/{mixed}/rules").json()
        assert [(row["rule_id"], row["editable"]) for row in view["budgets"]] == [
            ("squad", True),
            ("workstations", False),
        ]
        refused = client.post(
            f"{POLICY}/{mixed}/rules", {"rules": stated(view)["rules"], "budgets": []}
        )
        assert refused.status_code == 400, refused.text
        assert refused.json()["fields"] == ["ruleset.budgets"]
    kept = read_bundle(db, world["admin"], mixed, world["clock"])
    assert kept.state == "DRAFT" and {rule.rule_id for rule in kept.content.limits} == {
        "squad",
        "workstations",
    }


@pytest.mark.parametrize("scope", ["group", "space"])
def test_a_budget_whose_qualifier_is_no_longer_offered_locks_the_draft_and_is_named(
    db, runtime, admin_engine, world, owner, scope
):
    """A budget counted for a group the owner has since removed, or for a space the draft does
    not serve (as a copy of a tenant-wide bundle carries one), names a qualifier the read does
    not offer. The form cannot restate it and the write refuses it, so the read says so: that
    budget is not editable, which keeps the whole draft read-only and names it, rather than
    offering an unrelated edit that every save would refuse at the budget's field (#678)."""
    tenant = world["identity"].tenant_id
    home = tenant_space(admin_engine, world)
    value = (
        group(owner, world, name="triage")
        if scope == "group"
        else tenant_space(admin_engine, world, "Customer B")
    )
    budgets = (limit("principal-hourly"), limit("squad", scope=scope, **{f"{scope}_id": value}))
    bundle_id = ruleset_draft(db, world, ENDPOINT_RULESET.model_copy(update={"budgets": budgets}))
    if scope == "group":
        with admin_engine.begin() as conn:
            # No command removes a group; the owner connection does (T5.11).
            conn.execute(
                text("DELETE FROM execbound.principal_groups WHERE tenant_id=:t AND group_id=:g"),
                {"t": tenant, "g": value},
            )
    before = read_bundle(db, world["admin"], bundle_id, world["clock"]).content
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        chosen = client.post(API + "/session/space", {"space_id": str(home)})
        assert chosen.status_code == 200, chosen.text
        page = client.get(f"{POLICY}/{bundle_id}/rules")
        assert page.status_code == 200, page.text
        view = page.json()
        assert str(value) not in [row["id"] for row in view["qualifiers"][f"{scope}s"]]
        # The budget that locks the draft is named, and what it is counted for by the
        # identifier the read has no words for; the budget beside it is a shape the form shows.
        assert [(row["rule_id"], row["editable"]) for row in view["budgets"]] == [
            ("principal-hourly", True),
            ("squad", False),
        ]
        assert view["budgets"][1][f"{scope}_id"] == str(value)
        assert view["budgets"][1]["qualifier"] == str(value)
        # An unrelated rule edit is not offered through it: sent anyway, restating the budgets
        # as read, it is refused at the stale budget's field and nothing is written.
        body = stated(view)
        body["rules"][0]["note"] = "Reviewed with the night shift."
        refused = client.post(f"{POLICY}/{bundle_id}/rules", body)
        assert refused.status_code == 400, refused.text
        assert refused.json()["code"] == "INVALID_BODY"
        assert refused.json()["fields"] == [f"ruleset.budgets.1.{scope}_id"]
        assert_no_secrets(refused)
    after = read_bundle(db, world["admin"], bundle_id, world["clock"])
    assert after.state == "DRAFT" and after.content.content_hash == before.content_hash


def test_the_spaces_offered_are_those_the_draft_may_serve_and_the_person_may_see(
    db, runtime, admin_engine, world
):
    tenant = world["identity"].tenant_id
    first = tenant_space(admin_engine, world)
    second = tenant_space(admin_engine, world, "Customer B")
    third = tenant_space(admin_engine, world, "Customer C")
    bundle_id = ruleset_draft(db, world)

    def spaces(client) -> list[str]:
        page = client.get(f"{POLICY}/{bundle_id}/rules")
        assert page.status_code == 200, page.text
        return [row["label"] for row in page.json()["qualifiers"]["spaces"]]

    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        # Owned by one space and offered to no other: that space, and no other is named.
        assert spaces(client) == ["Default"]
    with admin_engine.begin() as conn:
        # Offering a bundle tenant-wide has no application path; the owner's SQL does it.
        conn.execute(
            text(
                "UPDATE execbound.policy_bundle_contents SET offered_tenant_wide=true "
                "WHERE tenant_id=:t AND bundle_id=:b"
            ),
            {"t": tenant, "b": bundle_id},
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        assert spaces(client) == ["Customer B", "Customer C", "Default"]
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        for space in (first, second):
            seat(conn, tenant, space, world["admin"].principal_id, "ADMIN")
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        # A person seated in two spaces is offered those two, and the third is not named.
        assert spaces(client) == ["Customer B", "Default"]
        assert str(third) not in client.get(f"{POLICY}/{bundle_id}/rules").text
