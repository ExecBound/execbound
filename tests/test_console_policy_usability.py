# SPDX-License-Identifier: AGPL-3.0-only
"""The policy start options through the authenticated surface and real store."""

from uuid import UUID, uuid4

from console_api_fixtures import console_client
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.contracts import PRODUCTION_CATALOG
from execbound.policy.store import read_bundle
from execbound.surfaces.console_api.policy_starters import editable_copy

POLICY = "/api/console/v1/policy"


def test_first_policy_compiles_existing_mappings_without_an_active_bundle(
    db, runtime, admin_engine, world
):
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"),
            {"t": str(world["identity"].tenant_id)},
        )
        conn.execute(
            text("DELETE FROM execbound.space_policy_selection WHERE tenant_id = :t"),
            {"t": world["identity"].tenant_id},
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        page = client.get(POLICY).json()
        assert page["active"] is None and page["starter_available"]
        created = client.post(POLICY, {"source": "template", "template": "security-response"})
        assert created.status_code == 200, created.text
        body = created.json()
        assert body["state"] == "DRAFT" and body["written_as_rules"]
        assert {rule["action"] for rule in body["rules"]} == {"endpoint.isolate"}
        # A ref that is its action's own name names no other.
        assert [(row["operation_ref"], row["action"]) for row in body["mappings"]] == [
            ("endpoint.isolate", None)
        ]
        assert (
            client.post(f"{POLICY}/{body['bundle_id']}/validate", {"confirm": True}).status_code
            == 200
        )
        assert client.get(POLICY).json()["active"] is None


def test_seeded_policy_becomes_an_editable_draft_before_validation(
    db, runtime, admin_engine, world
):
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        active = client.get(f"{POLICY}/{world['bundle'].bundle_id}").json()
        assert active["form_available"] is True
        assert active["rules_origin"] == "recognized-seed"
        assert active["rules"] and not active["written_as_rules"]
        made = client.post(POLICY, {"source": "template", "template": "current-protections"})
        assert made.status_code == 200, made.text
        body = made.json()
        assert body["state"] == "DRAFT" and body["written_as_rules"] and not body["active"]
        stored = read_bundle(db, world["admin"], UUID(body["bundle_id"]), world["clock"])
        assert stored.content.mappings == world["bundle"].mappings
        assert stored.content.limits == world["bundle"].limits
        assert (
            client.post(f"{POLICY}/{body['bundle_id']}/validate", {"confirm": True}).status_code
            == 200
        )
        assert client.get(POLICY).json()["active"] == active["bundle_id"]


def test_custom_cedar_is_copyable_but_not_replaced_by_a_form(db, runtime, admin_engine, world):
    content = world["bundle"].model_copy(
        update={
            "bundle_id": uuid4(),
            "authorization_policies": "forbid(principal, action, resource);",
        }
    )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        created = client.post(POLICY, {"source": "document", "document": content.model_dump_json()})
        assert created.status_code == 200, created.text
        original = created.json()
        assert not original["form_available"] and original["rules_origin"] == "cedar"
        refused = client.post(
            POLICY,
            {
                "source": "template",
                "template": "current-protections",
                "bundle_id": original["bundle_id"],
            },
        )
        assert refused.status_code == 400, refused.text
        copied = client.post(POLICY, {"source": "bundle", "bundle_id": original["bundle_id"]})
        assert copied.status_code == 200, copied.text
        assert copied.json()["compiled"] == original["compiled"]
        assert copied.json()["mappings"] == original["mappings"]


def test_form_write_cannot_drop_an_advanced_budget(db, runtime, admin_engine, world):
    content = editable_copy(world["bundle"], PRODUCTION_CATALOG)
    assert content is not None and content.ruleset is not None
    limits = tuple(
        limit.model_copy(update={"actions": (limit.action,)}) for limit in content.limits
    )
    content = content.model_copy(
        update={"limits": limits, "ruleset": content.ruleset.model_copy(update={"budgets": limits})}
    )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        created = client.post(POLICY, {"source": "document", "document": content.model_dump_json()})
        assert created.status_code == 200, created.text
        body = created.json()
        assert not body["form_available"]
        rules = client.get(f"{POLICY}/{body['bundle_id']}/rules").json()
        assert all(not row["editable"] for row in rules["budgets"])
        sent = {
            "rules": [rule.model_dump(mode="json") for rule in content.ruleset.rules],
            "budgets": [],
        }
        refused = client.post(f"{POLICY}/{body['bundle_id']}/rules", sent)
        assert refused.status_code == 400, refused.text
        original = read_bundle(db, world["admin"], UUID(body["bundle_id"]), world["clock"])
        assert original.state == "DRAFT" and original.content.limits == limits


def test_first_policy_over_a_ref_that_is_not_its_action_writes_rules_about_the_action(
    db, runtime, admin_engine, world
):
    """The workspace's isolation mappings are `alternate.isolate` and `second.isolate`, both
    serving endpoint.isolate on one contract: the rules, and the page, speak of it once."""
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text("DELETE FROM execbound.space_policy_selection WHERE tenant_id = :t"), {"t": tenant}
        )
        for ref in ("alternate.isolate", "second.isolate"):
            conn.execute(
                text(
                    "INSERT INTO execbound.operation_mappings "
                    "SELECT tenant_id,:r,account_id,provider,resource_type,action,"
                    "provider_operation,mapping_version,schema_version,context_contract_version,"
                    "active FROM execbound.operation_mappings "
                    "WHERE tenant_id=:t AND operation_ref='endpoint.isolate'"
                ),
                {"t": tenant, "r": ref},
            )
        conn.execute(
            text(
                "UPDATE execbound.operation_mappings SET active = false "
                "WHERE tenant_id = :t AND operation_ref = 'endpoint.isolate'"
            ),
            {"t": tenant},
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        created = client.post(POLICY, {"source": "template", "template": "security-response"})
        assert created.status_code == 200, created.text
        body = created.json()
        assert {rule["action"] for rule in body["rules"]} == {"endpoint.isolate"}
        assert [(row["operation_ref"], row["action"]) for row in body["mappings"]] == [
            ("alternate.isolate", "endpoint.isolate"),
            ("second.isolate", "endpoint.isolate"),
        ]
        stored = read_bundle(db, world["admin"], UUID(body["bundle_id"]), world["clock"])
        assert [(item.operation_ref, item.action) for item in stored.content.mappings] == [
            ("alternate.isolate", "endpoint.isolate"),
            ("second.isolate", "endpoint.isolate"),
        ]
        rules = client.get(f"{POLICY}/{body['bundle_id']}/rules").json()
        assert [group["action"] for group in rules["groups"]] == ["endpoint.isolate"]
        assert rules["groups"][0]["rules"]
        assert [item["action"] for item in rules["fields"]] == ["endpoint.isolate"]
        assert rules["fields"][0]["choices"]
        assert (
            client.post(f"{POLICY}/{body['bundle_id']}/validate", {"confirm": True}).status_code
            == 200
        )


def test_first_policy_leaves_out_a_mapping_that_needs_a_signal_mapping(
    db, runtime, admin_engine, world
):
    """v1 `endpoint.isolate` beside v2 `isolate.corroborated`: the starter covers the first.

    A contract with a signal fact needs the bundle's `signal_mappings`, which the starter
    cannot write (the operator's verdict table and admitted producers), and one bundle cannot
    carry both contracts for one entity. So the starter leaves the v2 mapping out rather than
    fail as a whole, and the operator adds it with its signal mapping later.
    """
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text("DELETE FROM execbound.space_policy_selection WHERE tenant_id = :t"), {"t": tenant}
        )
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings "
                "SELECT tenant_id,'isolate.corroborated',account_id,provider,resource_type,action,"
                "provider_operation,mapping_version,schema_version,'endpoint-isolation.v2',"
                "active FROM execbound.operation_mappings "
                "WHERE tenant_id=:t AND operation_ref='endpoint.isolate'"
            ),
            {"t": tenant},
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        page = client.get(POLICY).json()
        assert page["active"] is None and page["starter_available"], page
        created = client.post(POLICY, {"source": "template", "template": "security-response"})
        assert created.status_code == 200, created.text
        body = created.json()
        assert [
            (row["operation_ref"], row["context_contract_version"]) for row in body["mappings"]
        ] == [("endpoint.isolate", "endpoint-isolation.v1")]
        assert {rule["action"] for rule in body["rules"]} == {"endpoint.isolate"}
        assert (
            client.post(f"{POLICY}/{body['bundle_id']}/validate", {"confirm": True}).status_code
            == 200
        )


def test_a_draft_whose_own_mappings_cannot_compile_is_refused_as_a_bundle(
    db, runtime, admin_engine, world
):
    """A mapping conflict is the draft's defect, not the rules the caller sent.

    Such a draft exists because a pasted document is stored as it is: creating a draft does
    not compile it. Changing its rules is refused at the bundle's own field, whichever of the
    page's recognition or the store's recompile reaches the conflict first.
    """
    from execbound.policy.models import MappingRef

    content = editable_copy(world["bundle"], PRODUCTION_CATALOG)
    assert content is not None and content.ruleset is not None
    conflicting = MappingRef(
        **content.mappings[0].model_dump(exclude={"operation_ref", "context_contract_version"}),
        operation_ref="isolate.corroborated",
        action="endpoint.isolate",
        context_contract_version="endpoint-isolation.v2",
    )
    content = content.model_copy(update={"mappings": (*content.mappings, conflicting)})
    sent = {
        "rules": [rule.model_dump(mode="json") for rule in content.ruleset.rules],
        "budgets": [budget.model_dump(mode="json") for budget in content.ruleset.budgets],
    }
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        created = client.post(POLICY, {"source": "document", "document": content.model_dump_json()})
        assert created.status_code == 200, created.text
        assert created.json()["state"] == "DRAFT" and not created.json()["form_available"]
        refused = client.post(f"{POLICY}/{created.json()['bundle_id']}/rules", sent)
    assert refused.status_code == 409, refused.text
    assert (refused.json()["code"], refused.json()["fields"]) == ("INVALID_BUNDLE", ["mappings.1"])
