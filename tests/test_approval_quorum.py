# SPDX-License-Identifier: AGPL-3.0-only
"""Approval quorum for high-risk actions: QA1 to QA12 on real PostgreSQL and Chromium."""

import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from uuid import uuid4

import cedarpy
import pytest
from alembic import command
from alembic.config import Config
from replay_fixtures import chain_export
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_execution import provision_identity, request
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import credential, form_values
from test_human_surface import human_config as human_config
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_protected_path import resource
from test_runtime import runtime as runtime

from execbound.app import create_app
from execbound.db import TABLES, check_runtime
from execbound.execution import admit, decide_approval
from execbound.execution.models import ExecutionError
from execbound.policy.models import BundleContent, QuorumRule
from execbound.policy.preview import preview_bundle
from execbound.policy.store import PolicyStoreError, activate_bundle, create_bundle, validate_bundle
from execbound.replay.export import export_history
from execbound.replay.verify import verify_export
from execbound_harness.demo import endpoint_bundle

ORIGIN = {"Origin": "http://127.0.0.1"}


def production_obligation(bundle):
    """The obligation id of the bundle's single approval policy, as evaluation names it."""
    parsed = json.loads(cedarpy.policies_to_json_str(bundle.approval_policies))
    return "policy:" + next(iter(parsed["staticPolicies"]))


def quorum_bundle(world, required=2, obligation=None):
    """The endpoint bundle with a quorum rule on its production approval obligation."""
    base = endpoint_bundle(world["identity"].tenant_id, world["account"], mapping_version="map-v1")
    rule = QuorumRule(
        rule_id="two-person-production",
        obligation=obligation or production_obligation(base),
        required=required,
    )
    return base.model_copy(update={"bundle_id": uuid4(), "quorum": (rule,)})


def activate(db, world, bundle):
    create_bundle(db, world["admin"], bundle, world["clock"])
    validate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    activate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    return bundle


def second_approver(admin_engine, db, world):
    human = provision_identity(
        admin_engine, db, world["identity"].tenant_id, "HUMAN_APPROVER", world["clock"].now()
    )
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.approval_scopes "
                "(tenant_id, approver_id, canonical_target_id, action, space_id) "
                "VALUES (:t, :p, :c, 'endpoint.isolate', "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
            ),
            {"t": human.tenant_id, "p": human.principal_id, "c": world["canonical"]},
        )
    return human


def approval_state(engine, approval_id):
    with engine.connect() as conn:
        return conn.execute(
            text("SELECT state, required_approvers FROM execbound.approvals WHERE approval_id=:a"),
            {"a": approval_id},
        ).one()


def decisions(engine, approval_id):
    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT principal_id, decision FROM execbound.approval_decisions "
                "WHERE approval_id=:a ORDER BY decided_at"
            ),
            {"a": approval_id},
        ).all()


def test_qa1_qa2_two_distinct_approvers_satisfy_and_consume_the_quorum_once(
    db, world, admin_engine, live_provider, connector
):
    activate(db, world, quorum_bundle(world))
    other = second_approver(admin_engine, db, world)
    pending = admit(db, world["identity"], request(world), world["clock"])
    approval_id = pending.view.approval_id
    assert approval_state(admin_engine, approval_id) == ("PENDING", 2)
    first = decide_approval(db, world["human"], approval_id, "APPROVE", world["clock"])
    assert first.state == "PENDING_APPROVAL" and first.approval_state == "PENDING"
    retry = admit(db, world["identity"], request(world), world["clock"])
    assert retry.ticket is None and retry.view.state == "PENDING_APPROVAL"
    assert resource(live_provider, world).mutation_count == 0
    second = decide_approval(db, other, approval_id, "APPROVE", world["clock"])
    assert second.approval_state == "APPROVED"
    assert [d[1] for d in decisions(admin_engine, approval_id)] == ["APPROVE", "APPROVE"]
    done = admit(db, world["identity"], request(world), world["clock"])
    assert done.ticket is not None and done.view.state == "DISPATCH_COMMITTED"
    assert approval_state(admin_engine, approval_id)[0] == "CONSUMED"


def test_qa3_the_same_approver_cannot_count_twice(db, world, admin_engine):
    activate(db, world, quorum_bundle(world))
    pending = admit(db, world["identity"], request(world), world["clock"])
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    with pytest.raises(ExecutionError) as repeated:
        decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    assert repeated.value.code == "INVALID_STATE"
    # A fresh credential for the same principal is still the same person.
    reissued = provision_identity(
        admin_engine, db, world["identity"].tenant_id, "HUMAN_APPROVER", world["clock"].now()
    )
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.credentials SET principal_id=:p WHERE credential_id=:c"),
            {"p": world["human"].principal_id, "c": reissued.credential_id},
        )
    same_person = reissued.__class__(
        reissued.tenant_id,
        world["human"].principal_id,
        reissued.credential_id,
        reissued.kind,
        reissued.expires_at,
    )
    with pytest.raises(ExecutionError) as again:
        decide_approval(db, same_person, pending.view.approval_id, "APPROVE", world["clock"])
    assert again.value.code == "INVALID_STATE"
    assert len(decisions(admin_engine, pending.view.approval_id)) == 1
    assert approval_state(admin_engine, pending.view.approval_id)[0] == "PENDING"


def test_qa4_a_single_denial_ends_the_approval(db, world, admin_engine, live_provider, connector):
    activate(db, world, quorum_bundle(world))
    other = second_approver(admin_engine, db, world)
    pending = admit(db, world["identity"], request(world), world["clock"])
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    denied = decide_approval(db, other, pending.view.approval_id, "DENY", world["clock"])
    assert denied.state == "DENIED" and denied.approval_state == "DENIED"
    retry = admit(db, world["identity"], request(world), world["clock"])
    assert retry.ticket is None and retry.view.state == "DENIED"
    assert resource(live_provider, world).mutation_count == 0


def test_qa5_partial_approvals_expire_with_the_window(db, world, admin_engine):
    activate(db, world, quorum_bundle(world))
    other = second_approver(admin_engine, db, world)
    pending = admit(db, world["identity"], request(world), world["clock"])
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    world["clock"].value += timedelta(seconds=121)
    stale = decide_approval(db, other, pending.view.approval_id, "APPROVE", world["clock"])
    assert stale.state == "STALE_AUTHORIZATION"
    assert approval_state(admin_engine, pending.view.approval_id)[0] == "EXPIRED"
    later = admit(db, world["identity"], request(world), world["clock"])
    assert later.ticket is None and later.view.state != "DISPATCH_COMMITTED"


def test_qa6_a_lapsed_approver_invalidates_the_whole_approval(
    db, world, admin_engine, live_provider, connector
):
    activate(db, world, quorum_bundle(world))
    other = second_approver(admin_engine, db, world)
    pending = admit(db, world["identity"], request(world), world["clock"])
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    decide_approval(db, other, pending.view.approval_id, "APPROVE", world["clock"])
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.credentials SET revoked_at=now() WHERE credential_id=:c"),
            {"c": other.credential_id},
        )
    retry = admit(db, world["identity"], request(world), world["clock"])
    assert retry.ticket is None and retry.view.state == "STALE_AUTHORIZATION"
    assert resource(live_provider, world).mutation_count == 0


def test_qa7_a_bundle_change_between_decisions_invalidates_the_approval(db, world, admin_engine):
    activate(db, world, quorum_bundle(world))
    other = second_approver(admin_engine, db, world)
    pending = admit(db, world["identity"], request(world), world["clock"])
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    activate(db, world, quorum_bundle(world))
    stale = decide_approval(db, other, pending.view.approval_id, "APPROVE", world["clock"])
    assert stale.state == "STALE_AUTHORIZATION"
    assert approval_state(admin_engine, pending.view.approval_id)[0] == "INVALIDATED"


def test_qa8_concurrent_decisions_complete_the_quorum_once(
    db, world, admin_engine, live_provider, connector
):
    activate(db, world, quorum_bundle(world))
    other = second_approver(admin_engine, db, world)
    pending = admit(db, world["identity"], request(world), world["clock"])
    approval_id = pending.view.approval_id
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda human: decide_approval(db, human, approval_id, "APPROVE", world["clock"]),
                [world["human"], other],
            )
        )
    assert sorted(r.approval_state for r in results) == ["APPROVED", "PENDING"]
    assert len(decisions(admin_engine, approval_id)) == 2
    done = admit(db, world["identity"], request(world), world["clock"])
    assert done.ticket is not None and approval_state(admin_engine, approval_id)[0] == "CONSUMED"


@pytest.mark.parametrize(
    "changes",
    [
        {"obligation": "policy:does-not-exist"},
        {"required": 1},
        {"required": 6},
    ],
)
def test_qa9_invalid_quorum_rules_fail_validation(db, world, changes):
    base = endpoint_bundle(world["identity"].tenant_id, world["account"], mapping_version="map-v1")
    values = {
        "rule_id": "bad",
        "obligation": production_obligation(base),
        "required": 2,
    }
    values.update(changes)
    if changes.get("required") in {1, 6}:
        with pytest.raises(ValueError):
            QuorumRule(**values)
        return
    bundle = base.model_copy(update={"bundle_id": uuid4(), "quorum": (QuorumRule(**values),)})
    create_bundle(db, world["admin"], bundle, world["clock"])
    with pytest.raises(PolicyStoreError) as refused:
        validate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    assert refused.value.code == "INVALID_COMPONENT"
    assert refused.value.location == "quorum.0.obligation"
    duplicate = base.model_copy(
        update={"bundle_id": uuid4(), "quorum": (QuorumRule(**values), QuorumRule(**values))}
    )
    with pytest.raises(ValueError):
        BundleContent.model_validate(duplicate.model_dump())


def test_qa10_pages_show_progress_and_offer_no_form_to_an_approver_who_decided(
    db, world, admin_engine, runtime, human_config
):
    activate(db, world, quorum_bundle(world))
    other = second_approver(admin_engine, db, world)
    view = runtime.execute(world["identity"], request(world).model_dump_json().encode())
    app = create_app(db, runtime=runtime, human=human_config)
    with __import__("fastapi.testclient", fromlist=["TestClient"]).TestClient(
        app, base_url="http://127.0.0.1", follow_redirects=False
    ) as client:
        _, values = form_values(client.get("/login").text, "/session")
        values["credential"] = credential(admin_engine, world["human"])
        assert client.post("/session", data=values, headers=ORIGIN).status_code == 303
        classic = f"/approvals/{view.approval_id}/classic"
        page = client.get(classic)
        assert "0 of 2 approvals recorded" in page.text
        path, form = form_values(page.text, "/decide")
        form["decision"] = "APPROVE"
        assert client.post(path, data=form, headers=ORIGIN).status_code == 303
        page = client.get(classic)
        assert "1 of 2 approvals recorded" in page.text and "/decide" not in page.text
        assert client.post(path, data=form, headers=ORIGIN).status_code == 409
    assert approval_state(admin_engine, view.approval_id) == ("PENDING", 2)
    assert other.principal_id != world["human"].principal_id


def test_qa11_replay_captures_every_approver_and_refuses_a_short_quorum(
    db, world, admin_engine, live_provider, connector
):
    activate(db, world, quorum_bundle(world))
    other = second_approver(admin_engine, db, world)
    pending = admit(db, world["identity"], request(world), world["clock"])
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    decide_approval(db, other, pending.view.approval_id, "APPROVE", world["clock"])
    admit(db, world["identity"], request(world), world["clock"])
    export = export_history(db, world["admin"], world["clock"])
    history = verify_export(export, export.head)
    assert history.complete
    consumed = [
        e.capture
        for e in history.events
        if e.capture is not None
        and e.capture.approval is not None
        and e.capture.approval.status == "VERIFIED"
    ]
    assert consumed and consumed[-1].approval.required_approvers == 2
    assert len({a.principal_id for a in consumed[-1].approval.approvers}) == 2
    forged = consumed[-1].model_copy(
        update={
            "approval": consumed[-1].approval.model_copy(
                update={"approvers": consumed[-1].approval.approvers[:1]}
            )
        }
    )
    export = chain_export([forged], [b for b in export.bundles if b.bundle_id == forged.bundle_id])
    verified = verify_export(export, export.head)
    assert not verified.complete and "INSUFFICIENT_QUORUM" in verified.issues
    candidate = quorum_bundle(world, required=3)
    create_bundle(db, world["admin"], candidate, world["clock"])
    preview = preview_bundle(
        db, world["admin"], candidate.bundle_id, window=timedelta(hours=1), clock=world["clock"]
    )
    assert preview.changed and {c.required_approvers for c in preview.changed} == {3}
    assert all(c.candidate_effect == "UNRESOLVED" for c in preview.changed)


def test_qa12_migration_round_trip_and_runtime_catalog(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    assert "approval_decisions" in TABLES
    with db.transaction(tenant) as conn:
        check_runtime(conn)
    activate(db, world, quorum_bundle(world))
    pending = admit(db, world["identity"], request(world), world["clock"])
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    for statement in (
        "DELETE FROM execbound.approval_decisions",
        "UPDATE execbound.approval_decisions SET decision='DENY'",
    ):
        with pytest.raises(DBAPIError, match="permission denied"), db.transaction(tenant) as conn:
            conn.execute(text(statement))
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    with pytest.raises(RuntimeError):
        command.downgrade(config, "0016_export_cursors")
    with db.transaction(tenant) as conn:
        check_runtime(conn)
