# SPDX-License-Identifier: AGPL-3.0-only
"""The Policy area of the console API (#333).

Every route through the harness first: an administrator, an approver refused, a bearer
credential refused and audited, no session, a cross-tenant or malformed id answering 404, and
the secret check over every response. Then the lifecycle as JSON, against the same store
functions the Jinja pages call — including that a draft's preview equals what the page
computes for the same fixtures, and that an unvalidated draft cannot be activated.
"""

import json
from datetime import datetime, timedelta
from uuid import UUID, uuid4

import pytest
import secret_shapes
from console_api_fixtures import API, assert_no_secrets, console_client, refusals
from space_fixtures import make_space
from sqlalchemy import text
from test_access_control import current, roles
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import pending
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.policy.models import Rule
from execbound.policy.preview import preview_bundle
from execbound.policy.rulesets import ruleset_bundle
from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
from execbound_harness.demo import ENDPOINT_RULESET, endpoint_bundle

POLICY = API + "/policy"
ZERO = "00000000-0000-0000-0000-000000000000"
CONFIRM = {"confirm": True}
# Activation asks what changed and why (#678); the other steps keep the bare confirmation.
ACTIVATE = {"confirm": True, "reason": "Test rollout"}
# Every route with a well-formed body, so a refusal is the role's and not the body's.
ROUTES = [
    (POLICY, "GET", None),
    (POLICY, "POST", {"source": "active"}),
    (f"{POLICY}/{ZERO}", "GET", None),
    (f"{POLICY}/{ZERO}/validate", "POST", CONFIRM),
    (f"{POLICY}/{ZERO}/preview", "POST", {"window": "24h"}),
    (f"{POLICY}/{ZERO}/activate", "POST", ACTIVATE),
    (f"{POLICY}/{ZERO}/retire", "POST", CONFIRM),
    (f"{POLICY}/{ZERO}/compare", "GET", None),
    (f"{POLICY}/{ZERO}/ruleset", "GET", None),
]


def document(world, **changes) -> str:
    """A pasteable bundle for this tenant, as the page's textarea would carry it."""
    bundle = endpoint_bundle(
        world["identity"].tenant_id, world["account"], mapping_version="map-v1"
    )
    return bundle.model_copy(update={"bundle_id": uuid4(), **changes}).model_dump_json()


def draft(client, world, **changes) -> dict:
    created = client.post(POLICY, {"source": "document", "document": document(world, **changes)})
    assert created.status_code == 200, created.text
    return created.json()


@pytest.fixture
def ruleset_world(db, world):
    """The endpoint pack as rules, active in the world's tenant, so the rules read back."""
    content = ruleset_bundle(
        ENDPOINT_RULESET,
        tenant_id=world["identity"].tenant_id,
        bundle_id=uuid4(),
        mappings=world["bundle"].mappings,
    )
    create_bundle(db, world["admin"], content, world["clock"])
    validate_bundle(db, world["admin"], content.bundle_id, world["clock"])
    activate_bundle(db, world["admin"], content.bundle_id, world["clock"])
    return content


@pytest.mark.parametrize("path,method,_body", ROUTES)
def test_every_route_refuses_a_bearer_and_no_session(
    db, runtime, seeded, admin_engine, world, path, method, _body
):
    results = refusals(db, runtime, seeded, admin_engine, world, path, method)
    assert results["bearer"].status_code == 403 and results["bearer"].json()["code"] == "FORBIDDEN"
    assert results["audited"] == 1
    assert results["no_session"].status_code == 401
    assert results["no_session"].json()["code"] == "SESSION_REQUIRED"


def test_an_approver_is_refused_on_every_route(db, runtime, admin_engine, world):
    """Policy is the administrator's, exactly as `/policy` refuses an approver today."""
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        for path, method, body in ROUTES:
            response = approver.get(path) if method == "GET" else approver.post(path, body)
            assert response.status_code == 403, (path, response.text)
            assert response.json()["code"] == "FORBIDDEN"
            assert_no_secrets(response)


def test_the_list_marks_the_active_bundle_and_the_detail_carries_its_components(
    db, runtime, admin_engine, world
):
    active = world["bundle"]
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        page = client.get(POLICY)
        assert page.status_code == 200, page.text
        assert_no_secrets(page)
        body = page.json()
        assert body["active"] == str(active.bundle_id)
        rows = {row["bundle_id"]: row for row in body["bundles"]}
        assert rows[str(active.bundle_id)]["state"] == "ACTIVE"
        assert rows[str(active.bundle_id)]["active"] is True
        assert rows[str(active.bundle_id)]["content_hash"] == active.content_hash

        detail = client.get(f"{POLICY}/{active.bundle_id}")
        assert detail.status_code == 200, detail.text
        assert_no_secrets(detail)
        seen = detail.json()
        assert seen["state"] == "ACTIVE" and seen["active"] is True
        assert [row["operation_ref"] for row in seen["mappings"]] == ["endpoint.isolate"]
        assert seen["mappings"][0]["observe_only"] is False
        # The compiled policy is read-only text; it is what the kernel executes.
        assert seen["compiled"]["authorization_policies"] == active.authorization_policies
        assert seen["compiled"]["cedar_schema"] == active.cedar_schema
        # A bundle written by hand carries no rules, and says so rather than inventing them.
        assert seen["written_as_rules"] is False
        assert seen["rules_origin"] == "recognized-seed" and seen["form_available"] is True
        assert {rule["id"] for rule in seen["rules"]} == {
            rule.id for rule in ENDPOINT_RULESET.rules
        }


def test_a_limit_carries_a_meter_only_where_one_number_is_its_own(db, runtime, admin_engine, world):
    """The meters are admission's own count, and a scope without one tenant-wide answer
    carries no figure rather than a figure that belongs to one agent."""
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        seen = client.get(f"{POLICY}/{world['bundle'].bundle_id}").json()
        assert seen["limits"], "the world's bundle carries a limit rule"
        for row in seen["limits"]:
            assert row["max_targets"] > 0 and row["window"] and row["counted"]
            assert row["actions"] and row["labels"]
            if row["scope"] in ("tenant", "group"):
                assert isinstance(row["used"], int) and row["used"] >= 0
            else:
                # Counted per agent, per account or per value; one number would not be its own.
                assert row["used"] is None
                assert row["counted"].endswith("on its own")


def test_a_draft_is_created_validated_previewed_activated_and_retired(
    db, runtime, admin_engine, world
):
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        created = draft(
            client, world, authorization_policies="forbid(principal, action, resource);"
        )
        assert created["state"] == "DRAFT" and created["active"] is False
        bundle_id = created["bundle_id"]
        assert_no_secrets(client.get(f"{POLICY}/{bundle_id}"))

        validated = client.post(f"{POLICY}/{bundle_id}/validate", CONFIRM)
        assert validated.status_code == 200, validated.text
        assert validated.json()["state"] == "VALIDATED"

        previewed = client.post(f"{POLICY}/{bundle_id}/preview", {"window": "24h"})
        assert previewed.status_code == 200, previewed.text
        assert previewed.json()["available"] is True
        assert previewed.json()["window"] == "24h"

        activated = client.post(f"{POLICY}/{bundle_id}/activate", ACTIVATE)
        assert activated.status_code == 200, activated.text
        assert activated.json()["state"] == "ACTIVE" and activated.json()["active"] is True
        # `ACTIVE` means "selected by at least one space" since migration 0041, so the
        # bundle this space stopped selecting goes back to VALIDATED in the same
        # transaction and another space may select it later.
        listed = {row["bundle_id"]: row for row in client.get(POLICY).json()["bundles"]}
        assert listed[str(world["bundle"].bundle_id)]["state"] == "VALIDATED"

        # A bundle a space selects cannot be retired; the one it stopped selecting can.
        assert client.post(f"{POLICY}/{bundle_id}/retire", CONFIRM).status_code == 409
        retired = client.post(f"{POLICY}/{world['bundle'].bundle_id}/retire", CONFIRM)
        assert retired.status_code == 200 and retired.json()["state"] == "RETIRED"
        assert client.get(POLICY).json()["active"] == bundle_id


def test_a_draft_whose_cedar_does_not_validate_is_refused_at_its_component(
    db, runtime, admin_engine, world
):
    """Cedar text that does not validate is the bundle's own defect: `INVALID_BUNDLE` naming
    the component, as any other component defect is, and not the store being unavailable."""
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        bundle_id = draft(client, world, approval_policies="forbid(principal, action, resource);")[
            "bundle_id"
        ]
        refused = client.post(f"{POLICY}/{bundle_id}/validate", CONFIRM)
        assert refused.status_code == 409, refused.text
        assert refused.json()["code"] == "INVALID_BUNDLE"
        assert refused.json()["fields"] == ["approval_policies"]
        assert_no_secrets(refused)
        assert client.get(f"{POLICY}/{bundle_id}").json()["state"] == "DRAFT"


def test_activating_an_unvalidated_draft_is_refused(db, runtime, admin_engine, world):
    """The store's own state machine, answered as a typed conflict and nothing else."""
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        bundle_id = draft(client, world)["bundle_id"]
        refused = client.post(f"{POLICY}/{bundle_id}/activate", ACTIVATE)
        assert refused.status_code == 409, refused.text
        assert refused.json()["code"] == "CONFLICT"
        assert_no_secrets(refused)
        # Nothing moved: the draft is still a draft and the selection is unchanged.
        assert client.get(f"{POLICY}/{bundle_id}").json()["state"] == "DRAFT"
        assert client.get(POLICY).json()["active"] == str(world["bundle"].bundle_id)


def test_a_drafts_preview_matches_todays_preview_for_the_same_fixtures(
    db, runtime, admin_engine, world
):
    """The route is the page's `preview_bundle`, not a second reading of the same history.

    The candidate forbids what the active bundle allows, so the fixtures produce a changed
    decision rather than an empty answer that would agree vacuously.
    """
    pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        bundle_id = draft(
            client, world, authorization_policies="forbid(principal, action, resource);"
        )["bundle_id"]
        assert client.post(f"{POLICY}/{bundle_id}/validate", CONFIRM).status_code == 200
        answer = client.post(f"{POLICY}/{bundle_id}/preview", {"window": "24h"}).json()

    today = preview_bundle(
        db,
        world["admin"],
        UUID(bundle_id),
        window=timedelta(hours=24),
        clock=world["clock"],
        catalog=runtime.catalog,
    )
    assert answer["available"] is True
    assert answer["considered"] == today.considered
    assert answer["window_seconds"] == today.window_seconds
    assert answer["baseline_effects"] == today.baseline_effects
    assert answer["candidate_effects"] == today.candidate_effects
    assert answer["complete"] == today.complete
    assert [row["execution_id"] for row in answer["changed"]] == [
        str(change.execution_id) for change in today.changed
    ]
    assert [row["candidate_effect"] for row in answer["changed"]] == [
        change.candidate_effect for change in today.changed
    ]
    assert answer["changed"], "the candidate forbids what the fixtures did, so one must change"


def test_a_copy_of_the_active_bundle_is_a_new_draft_carrying_its_rules(
    db, runtime, admin_engine, world, ruleset_world
):
    """Copying is pasting: the active content is read back through the page's own parser, so
    a bundle written as rules keeps them and the copy is a different bundle."""
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        active = client.get(f"{POLICY}/{ruleset_world.bundle_id}").json()
        assert active["written_as_rules"] is True
        assert active["rules"] and all(row["sentence"].endswith(".") for row in active["rules"])
        assert {row["effect"] for row in active["rules"]} <= {"ALLOW", "DENY", "REVIEW"}

        copied = client.post(POLICY, {"source": "active"})
        assert copied.status_code == 200, copied.text
        body = copied.json()
        assert body["state"] == "DRAFT" and body["active"] is False
        assert body["bundle_id"] != str(ruleset_world.bundle_id)
        assert body["written_as_rules"] is True
        assert [row["id"] for row in body["rules"]] == [row["id"] for row in active["rules"]]
        assert [row["sentence"] for row in body["rules"]] == [
            row["sentence"] for row in active["rules"]
        ]
        # Everything but the identity is the same, so the compiled policy is byte for byte
        # what the active bundle carries; the digest differs because the identity is in it.
        assert body["compiled"] == active["compiled"]
        assert body["limits"] == active["limits"] and body["quorum"] == active["quorum"]
        assert body["content_hash"] != active["content_hash"]
        # And it is a bundle the store accepts: the copy's components still match its rules.
        assert client.post(f"{POLICY}/{body['bundle_id']}/validate", CONFIRM).status_code == 200


def test_a_preview_names_the_rule_behind_a_changed_decision(
    db, runtime, admin_engine, world, ruleset_world
):
    """A ruleset candidate's changed decisions carry rule ids, never the engine's positions."""
    pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        copied = client.post(POLICY, {"source": "active"}).json()
        assert client.post(f"{POLICY}/{copied['bundle_id']}/validate", CONFIRM).status_code == 200
        answer = client.post(f"{POLICY}/{copied['bundle_id']}/preview", {"window": "7d"}).json()
        assert answer["available"] is True and answer["window"] == "7d"
        known = {row["id"] for row in copied["rules"]}
        for change in answer["changed"]:
            assert set(change["rule_ids"]) <= known
            assert not any(name.startswith("policy") for name in change["rule_ids"])


def elsewhere(admin_engine, world, tenant, principal) -> str:
    """A real bundle of another tenant, written straight to the tables it lives in.

    Nothing this API offers can create one for a tenant the session is not in, which is the
    point: the row has to be planted to find out what a fenced read does when it exists.
    """
    content = endpoint_bundle(tenant, world["account"], mapping_version="map-v1")
    with admin_engine.begin() as conn:
        for statement in (
            "INSERT INTO execbound.policy_bundle_contents"
            "(tenant_id, bundle_id, content_hash, content, created_at, created_by, space_id)"
            " VALUES (:t, :b, :h, CAST(:c AS jsonb), now(), :p, "
            "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))",
            "INSERT INTO execbound.policy_bundle_lifecycle"
            "(tenant_id, bundle_id, content_hash, state, changed_at)"
            " VALUES (:t, :b, :h, 'DRAFT', now())",
        ):
            conn.execute(
                text(statement),
                {
                    "t": tenant,
                    "b": content.bundle_id,
                    "h": content.content_hash,
                    "c": content.model_dump_json(),
                    "p": principal,
                },
            )
    return str(content.bundle_id)


def test_an_unknown_malformed_or_cross_tenant_bundle_answers_not_found(
    db, runtime, admin_engine, world, seeded
):
    """A bundle that is not this tenant's is the same answer as one that does not exist.

    The store's read is fenced by tenant, so the row is not there to be found; this module
    maps that refusal to `NOT_FOUND` on every route without distinguishing the two, and the
    planted row proves the fence rather than an id that happens to be unused.
    """
    other = seeded["tenants"][1]
    assert other != world["identity"].tenant_id, "the planted bundle is another tenant's"
    theirs = elsewhere(admin_engine, world, other, seeded["principals"][1])
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        assert theirs not in {row["bundle_id"] for row in client.get(POLICY).json()["bundles"]}
        for value in (theirs, ZERO, "not-a-uuid", str(uuid4()).upper()):
            assert client.get(f"{POLICY}/{value}").status_code == 404, value
            assert client.get(f"{POLICY}/{value}").json()["code"] == "NOT_FOUND"
            for step in ("validate", "activate", "retire"):
                refused = client.post(
                    f"{POLICY}/{value}/{step}", ACTIVATE if step == "activate" else CONFIRM
                )
                assert refused.status_code == 404, (value, step, refused.text)
            assert client.post(f"{POLICY}/{value}/preview", {"window": "24h"}).status_code == 404


def test_an_invalid_document_names_its_fields_and_echoes_no_value(db, runtime, admin_engine, world):
    """The page's own locations, under the field the document arrived in, and no value back."""
    secretish = "eyJhbGciOiJIUzI1NiJ9.should-not-come-back"
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        for text_body in ("{", json.dumps([1, 2]), json.dumps({"cedar_schema": secretish})):
            refused = client.post(POLICY, {"source": "document", "document": text_body})
            assert refused.status_code == 400, refused.text
            body = refused.json()
            assert body["code"] == "INVALID_BODY"
            assert body["fields"] and all(item.startswith("document.") for item in body["fields"])
            assert secretish not in refused.text
            assert_no_secrets(refused)
        # A document for another tenant is refused at the field, never created.
        value = json.loads(document(world))
        value["tenant_id"] = str(uuid4())
        refused = client.post(POLICY, {"source": "document", "document": json.dumps(value)})
        assert refused.status_code == 400
        assert refused.json()["fields"] == ["document.tenant_id: must be this tenant"]
        assert value["tenant_id"] not in refused.text


def test_a_step_without_its_confirmation_and_a_body_the_model_refuses(
    db, runtime, admin_engine, world
):
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        bundle_id = draft(client, world)["bundle_id"]
        for body in ({}, {"confirm": False}, {"confirm": "yes"}, {"confirm": True, "extra": 1}):
            refused = client.post(f"{POLICY}/{bundle_id}/validate", body)
            assert refused.status_code == 400, (body, refused.text)
            assert refused.json()["code"] == "INVALID_BODY"
        # The source and the document belong together, in both directions.
        for body in (
            {"source": "active", "document": document(world)},
            {"source": "document"},
            {"source": "elsewhere"},
        ):
            refused = client.post(POLICY, body)
            assert refused.status_code == 400 and refused.json()["code"] == "INVALID_BODY"
        # A window outside the closed set never reaches the store.
        refused = client.post(f"{POLICY}/{bundle_id}/preview", {"window": "90d"})
        assert refused.status_code == 400 and refused.json()["fields"] == ["window"]


def test_a_copy_with_no_active_bundle_is_a_conflict(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        # A bundle a space selects cannot be retired, so the selection is removed
        # directly: what this test is about is the copy with nothing selected.
        with admin_engine.begin() as conn:
            conn.execute(
                text("SELECT set_config('execbound.tenant_id', :t, true)"),
                {"t": str(world["identity"].tenant_id)},
            )
            conn.execute(text("DELETE FROM execbound.space_policy_selection"))
        refused = client.post(POLICY, {"source": "active"})
        assert refused.status_code == 409 and refused.json()["code"] == "CONFLICT"
        assert_no_secrets(refused)


def activation_events(admin_engine, tenant) -> list[dict]:
    with admin_engine.connect() as conn:
        return [
            dict(row._mapping)
            for row in conn.execute(
                text(
                    "SELECT payload, occurred_at, actor_id FROM execbound.audit_events "
                    "WHERE tenant_id=:t AND kind='policy.bundle_activated' ORDER BY sequence"
                ),
                {"t": tenant},
            )
        ]


def test_activation_requires_a_reason_and_records_it(db, runtime, admin_engine, world):
    """The change that decides what agents may do records why (#678). A missing,
    blank or secret-shaped reason is refused naming `reason`, with nothing activated; the
    blank one is the store's own refusal, past the model's length bound."""
    tenant = world["identity"].tenant_id
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        bundle_id = draft(client, world)["bundle_id"]
        assert client.post(f"{POLICY}/{bundle_id}/validate", CONFIRM).status_code == 200
        before = len(activation_events(admin_engine, tenant))
        for body in (
            CONFIRM,
            {"confirm": True, "reason": ""},
            {"confirm": True, "reason": "   "},
            {"confirm": True, "reason": "x" * 501},
            {"confirm": True, "reason": secret_shapes.STRIPE},
        ):
            refused = client.post(f"{POLICY}/{bundle_id}/activate", body)
            assert refused.status_code == 400, (body, refused.text)
            assert refused.json()["code"] == "INVALID_BODY"
            assert refused.json()["fields"] == ["reason"], refused.text
            assert_no_secrets(refused)
            assert secret_shapes.STRIPE not in refused.text
        assert client.get(POLICY).json()["active"] == str(world["bundle"].bundle_id)
        assert len(activation_events(admin_engine, tenant)) == before
        activated = client.post(f"{POLICY}/{bundle_id}/activate", ACTIVATE)
        assert activated.status_code == 200, activated.text
        latest = activation_events(admin_engine, tenant)[-1]["payload"]
        assert (latest["bundle_id"], latest["reason"]) == (bundle_id, "Test rollout")


def principal_number(admin_engine, identity) -> int:
    with admin_engine.connect() as conn:
        return conn.execute(
            text("SELECT number FROM execbound.principals WHERE tenant_id=:t AND principal_id=:p"),
            {"t": identity.tenant_id, "p": identity.principal_id},
        ).scalar_one()


def test_the_list_and_the_detail_carry_the_latest_activation_note(db, runtime, admin_engine, world):
    tenant = world["identity"].tenant_id
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        first = draft(client, world)["bundle_id"]
        other = draft(client, world)["bundle_id"]
        never = draft(client, world)["bundle_id"]
        for bundle_id in (first, other):
            assert client.post(f"{POLICY}/{bundle_id}/validate", CONFIRM).status_code == 200
        for bundle_id, reason in ((first, "First"), (other, "Between"), (first, "Second")):
            body = {"confirm": True, "reason": reason}
            answered = client.post(f"{POLICY}/{bundle_id}/activate", body)
            assert answered.status_code == 200, answered.text
        rows = {row["bundle_id"]: row for row in client.get(POLICY).json()["bundles"]}
        assert rows[first]["note"] == "Second"
        assert rows[other]["note"] == "Between"
        assert rows[never]["note"] is None
        detail = client.get(f"{POLICY}/{first}").json()
        event = activation_events(admin_engine, tenant)[-1]
        assert detail["activation"]["reason"] == "Second"
        assert detail["activation"]["by_id"] == str(world["admin"].principal_id)
        assert detail["activation"]["by_number"] == principal_number(admin_engine, world["admin"])
        assert datetime.fromisoformat(detail["activation"]["at"]) == event["occurred_at"]
        assert client.get(f"{POLICY}/{never}").json()["activation"] is None


def test_a_note_from_a_space_the_reader_cannot_see_is_not_shown(db, runtime, admin_engine, world):
    """A bundle offered tenant-wide is readable from every Space, but the reason it was
    activated in Space B is B's: a Policy manager of Space A never reads it (PL5)."""
    tenant = world["identity"].tenant_id
    admin = world["admin"]
    offered = world["bundle"].model_copy(update={"bundle_id": uuid4()})
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        first = conn.execute(
            text("SELECT space_id FROM execbound.spaces WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one()
        second = make_space(conn, tenant, "Customer B")
        conn.execute(
            text(
                "UPDATE execbound.connector_accounts SET offered_tenant_wide=true "
                "WHERE tenant_id=:t"
            ),
            {"t": tenant},
        )
    create_bundle(db, admin, offered, world["clock"], space=first)
    validate_bundle(db, admin, offered.bundle_id, world["clock"])
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.policy_bundle_contents SET offered_tenant_wide=true "
                "WHERE tenant_id=:t AND bundle_id=:b"
            ),
            {"t": tenant, "b": offered.bundle_id},
        )
    activate_bundle(db, admin, offered.bundle_id, world["clock"], space=second, reason="B only")
    roles(db, admin, world["human"], [{"role": "policy_manager", "space_id": first}])
    manager = current(db, world["human"])
    with console_client(db, runtime, admin_engine, manager) as client:
        rows = {row["bundle_id"]: row for row in client.get(POLICY).json()["bundles"]}
        assert rows[str(offered.bundle_id)]["note"] is None
        detail = client.get(f"{POLICY}/{offered.bundle_id}")
        assert detail.status_code == 200, detail.text
        assert detail.json()["activation"] is None
        assert "B only" not in detail.text
    with console_client(db, runtime, admin_engine, admin) as client:
        rows = {row["bundle_id"]: row for row in client.get(POLICY).json()["bundles"]}
        assert rows[str(offered.bundle_id)]["note"] == "B only"


def test_the_activation_notes_index_exists(admin_engine):
    with admin_engine.connect() as conn:
        definition = conn.execute(
            text(
                "SELECT indexdef FROM pg_indexes WHERE schemaname='execbound' "
                "AND tablename='audit_events' AND indexname='audit_events_policy_activation'"
            )
        ).scalar_one()
    assert "WHERE (kind = 'policy.bundle_activated'::text)" in definition


def created(db, world, ruleset, **changes):
    """A draft written as rules over the world's mappings, created and left a draft."""
    content = ruleset_bundle(
        ruleset,
        tenant_id=world["identity"].tenant_id,
        bundle_id=uuid4(),
        mappings=world["bundle"].mappings,
        **changes,
    )
    create_bundle(db, world["admin"], content, world["clock"])
    return content


def test_the_comparison_names_each_change_against_this_spaces_active_policy(
    db, runtime, admin_engine, world, ruleset_world
):
    """As the rules read: a draft that adds an allow reads "Allows more" against the policy
    active in this Space, with both sides' sentences and nothing replayed (PL6)."""
    added = Rule(id="allow-everything-else", action="endpoint.isolate", effect="ALLOW")
    candidate = created(
        db, world, ENDPOINT_RULESET.model_copy(update={"rules": (*ENDPOINT_RULESET.rules, added)})
    )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        answer = client.get(f"{POLICY}/{candidate.bundle_id}/compare")
    assert answer.status_code == 200, answer.text
    assert_no_secrets(answer)
    body = answer.json()
    assert body["comparable"] is True and body["why_not"] is None
    assert body["against"] == str(ruleset_world.bundle_id)
    [rule] = body["rules"]
    assert rule["change"] == "added" and rule["rule_id"] == "allow-everything-else"
    assert rule["direction"] == "wider" and rule["after_effect"] == "ALLOW"
    assert rule["after"] and rule["before"] is None
    assert (body["wider"], body["narrower"], body["unclear"]) == (1, 0, 0)
    assert body["budgets"] == [] and body["mappings"] == []


def test_a_draft_that_only_adds_an_account_mapping_reads_as_allowing_more(
    db, runtime, admin_engine, world, ruleset_world
):
    tenant = world["identity"].tenant_id
    second = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts "
                "(tenant_id, account_id, provider, space_id) "
                "SELECT tenant_id, :a, provider, space_id FROM execbound.connector_accounts "
                "WHERE tenant_id = :t AND account_id = :old"
            ),
            {"t": tenant, "a": second, "old": world["account"]},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings (tenant_id, operation_ref, account_id, "
                "provider, resource_type, action, provider_operation, mapping_version, "
                "schema_version, context_contract_version) "
                "SELECT tenant_id, 'isolate.second', :a, provider, resource_type, action, "
                "provider_operation, mapping_version, schema_version, context_contract_version "
                "FROM execbound.operation_mappings WHERE tenant_id = :t AND account_id = :old"
            ),
            {"t": tenant, "a": second, "old": world["account"]},
        )
    [mapping] = world["bundle"].mappings
    content = ruleset_bundle(
        ENDPOINT_RULESET,
        tenant_id=tenant,
        bundle_id=uuid4(),
        # Another name for the same action, served through the second account.
        mappings=(
            mapping,
            mapping.model_copy(
                update={
                    "operation_ref": "isolate.second",
                    "account_id": second,
                    "action": "endpoint.isolate",
                }
            ),
        ),
    )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        made = client.post(POLICY, {"source": "document", "document": content.model_dump_json()})
        assert made.status_code == 200, made.text
        answered = client.get(f"{POLICY}/{made.json()['bundle_id']}/compare")
        assert answered.status_code == 200, answered.text
        body = answered.json()
    assert body["rules"] == [] and body["budgets"] == []
    [change] = body["mappings"]
    assert change["change"] == "added" and change["account_id"] == str(second)
    assert change["operation_ref"] == "isolate.second"
    assert change["action"] == "endpoint.isolate" and change["direction"] == "wider"
    assert body["wider"] == 1


def test_the_comparison_says_why_it_cannot_compare(db, runtime, admin_engine, world, ruleset_world):
    tenant = world["identity"].tenant_id
    rules = created(db, world, ENDPOINT_RULESET)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        active = client.get(f"{POLICY}/{ruleset_world.bundle_id}/compare").json()
        assert (active["comparable"], active["why_not"]) == (False, "is-active")
        cedar = draft(client, world, authorization_policies="forbid(principal, action, resource);")
        written = client.get(f"{POLICY}/{cedar['bundle_id']}/compare").json()
        assert (written["comparable"], written["why_not"]) == (False, "cedar")
        assert written["against"] == str(ruleset_world.bundle_id)
        with admin_engine.begin() as conn:
            conn.execute(
                text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)}
            )
            conn.execute(text("DELETE FROM execbound.space_policy_selection"))
        none = client.get(f"{POLICY}/{rules.bundle_id}/compare").json()
        assert (none["comparable"], none["why_not"], none["against"]) == (False, "no-active", None)
        with admin_engine.begin() as conn:
            conn.execute(
                text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)}
            )
            make_space(conn, tenant, "Customer B")
        everywhere = client.get(f"{POLICY}/{rules.bundle_id}/compare").json()
        assert (everywhere["comparable"], everywhere["why_not"]) == (False, "no-space")


def test_a_recognized_seed_compares_through_its_reviewed_rules(
    db, runtime, admin_engine, world, ruleset_world
):
    """The world's own bundle is the endpoint pack written by hand, which the detail page
    recognizes; it compares through that recognition rather than reading as Cedar."""
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        body = client.get(f"{POLICY}/{world['bundle'].bundle_id}/compare").json()
    assert body["comparable"] is True, body
    assert body["why_not"] is None


def test_another_spaces_bundle_is_not_compared(db, runtime, admin_engine, world):
    tenant = world["identity"].tenant_id
    admin = world["admin"]
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        first = conn.execute(
            text("SELECT space_id FROM execbound.spaces WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one()
        second = make_space(conn, tenant, "Customer B")
        conn.execute(
            text(
                "UPDATE execbound.connector_accounts SET offered_tenant_wide=true "
                "WHERE tenant_id=:t"
            ),
            {"t": tenant},
        )
    others = world["bundle"].model_copy(update={"bundle_id": uuid4()})
    create_bundle(db, admin, others, world["clock"], space=second)
    roles(db, admin, world["human"], [{"role": "policy_manager", "space_id": first}])
    with console_client(db, runtime, admin_engine, current(db, world["human"])) as client:
        refused = client.get(f"{POLICY}/{others.bundle_id}/compare")
    assert (refused.status_code, refused.json()["code"]) == (404, "NOT_FOUND")
