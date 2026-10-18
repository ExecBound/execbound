# SPDX-License-Identifier: AGPL-3.0-only
"""A Policy manager previews a candidate over the Spaces they manage (#678).

The preview replays the tenant's own frozen history. It was a workspace administrator's alone,
because it reads a workspace-wide replay export, which left a Policy manager able to activate
a policy and never to see what it would change. Now a Policy manager, and an administrator
narrowed to some Spaces, previews too, but only the decisions recorded in Spaces where they
hold `policy.manage` leave the preview, before anything is counted. A workspace-wide
administrator's answer is what it was, apart from `scope`. The replay export itself still
refuses anyone without `workspace.manage`. Real PostgreSQL throughout (THREAT_MODEL.md, the
preview's row; PL2 and PL3).
"""

from datetime import timedelta
from uuid import uuid4

import pytest
from console_api_fixtures import API, console_client
from space_fixtures import default_space, make_space, seat
from sqlalchemy import text
from test_access_control import current, roles
from test_execution import provision_identity
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_resolution import request
from test_runtime import runtime as runtime

from execbound.execution import admit, decide_approval
from execbound.policy import preview as preview_module
from execbound.policy.preview import preview_bundle
from execbound.policy.store import create_bundle, validate_bundle
from execbound.replay import export as export_module
from execbound.replay.export import ExportError, export_history

pytestmark = pytest.mark.integration

POLICY = API + "/policy"
DAY = timedelta(hours=24)
FORBID = "forbid(principal, action, resource);"


def fenced(conn, tenant) -> None:
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


@pytest.fixture
def spaces(db, runtime, admin_engine, world):
    """Two Spaces, one recorded decision in each, a candidate that changes both, and the
    people who preview it: a Policy manager of A (a viewer of B), an administrator seated as
    `ADMIN` in A alone, and the world's workspace-wide administrator."""
    tenant = world["identity"].tenant_id
    admin = world["admin"]
    first_run = admit(db, world["identity"], request(world, idempotency_key="in-a"), world["clock"])
    # Declined, so the target is free for a second request rather than joined to the first.
    decide_approval(db, world["human"], first_run.view.approval_id, "DENY", world["clock"])
    second_run = admit(
        db, world["identity"], request(world, idempotency_key="in-b"), world["clock"]
    )
    assert first_run.view.execution_id != second_run.view.execution_id
    narrowed = provision_identity(admin_engine, db, tenant, "ADMIN", world["clock"].now())
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, "Customer B")
        conn.execute(
            text(
                "UPDATE execbound.executions SET space_id=:s WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"t": tenant, "s": second, "e": second_run.view.execution_id},
        )
        conn.execute(
            text(
                "UPDATE execbound.connector_accounts SET offered_tenant_wide=true "
                "WHERE tenant_id=:t"
            ),
            {"t": tenant},
        )
        seat(conn, tenant, first, narrowed.principal_id, "ADMIN")
    candidate = world["bundle"].model_copy(
        update={"bundle_id": uuid4(), "authorization_policies": FORBID}
    )
    create_bundle(db, admin, candidate, world["clock"], space=first)
    validate_bundle(db, admin, candidate.bundle_id, world["clock"])
    others = world["bundle"].model_copy(
        update={"bundle_id": uuid4(), "authorization_policies": FORBID}
    )
    create_bundle(db, admin, others, world["clock"], space=second)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.policy_bundle_contents SET offered_tenant_wide = "
                "(bundle_id = :offered) WHERE tenant_id=:t AND bundle_id IN (:offered, :other)"
            ),
            {"t": tenant, "offered": candidate.bundle_id, "other": others.bundle_id},
        )
    roles(
        db,
        admin,
        world["human"],
        [{"role": "policy_manager", "space_id": first}, {"role": "viewer", "space_id": second}],
    )
    return {
        "tenant": tenant,
        "first": first,
        "second": second,
        "in_a": first_run.view.execution_id,
        "in_b": second_run.view.execution_id,
        "candidate": candidate.bundle_id,
        "others": others.bundle_id,
        "manager": current(db, world["human"]),
        "narrowed": narrowed,
    }


def preview(db, runtime, world, identity, bundle_id):
    return preview_bundle(
        db, identity, bundle_id, window=DAY, clock=world["clock"], catalog=runtime.catalog
    )


def in_space(world_answer, execution_id) -> int:
    """How many of the workspace-wide answer's decisions belong to one execution: a declined
    approval's execution is replayed at admission and again at its decision."""
    return sum(1 for change in world_answer.changed if change.execution_id == execution_id)


def test_a_policy_managers_preview_holds_only_their_spaces_decisions(db, runtime, world, spaces):
    whole = preview(db, runtime, world, world["admin"], spaces["candidate"])
    answer = preview(db, runtime, world, spaces["manager"], spaces["candidate"])
    assert answer.scope == "spaces"
    assert {change.execution_id for change in answer.changed} == {spaces["in_a"]}
    assert answer.considered == len(answer.changed) == in_space(whole, spaces["in_a"])
    assert sum(answer.baseline_effects.values()) == answer.considered
    assert sum(answer.candidate_effects.values()) == answer.considered
    assert str(spaces["in_b"]) not in answer.model_dump_json()


def test_a_narrowed_administrators_preview_holds_only_their_spaces_decisions(
    db, runtime, admin_engine, world, spaces
):
    """An `ADMIN`-kind principal seated as `ADMIN` in A holds `workspace.manage` only through
    `access_has_permission`'s `p_any` branch, the case #662 fixed for keys; the preview
    filters them like a Policy manager rather than calling them workspace-wide."""
    answer = preview(db, runtime, world, spaces["narrowed"], spaces["candidate"])
    assert answer.scope == "spaces"
    assert {change.execution_id for change in answer.changed} == {spaces["in_a"]}
    assert str(spaces["in_b"]) not in answer.model_dump_json()
    with console_client(db, runtime, admin_engine, spaces["narrowed"]) as client:
        seen = client.post(f"{POLICY}/{spaces['candidate']}/preview", {"window": "24h"})
        assert seen.status_code == 200, seen.text
        assert seen.json()["scope"] == "spaces"
        assert {row["execution_id"] for row in seen.json()["changed"]} == {str(spaces["in_a"])}
        assert str(spaces["in_b"]) not in seen.text


def test_an_administrators_preview_is_unchanged(db, runtime, admin_engine, world, spaces):
    answer = preview(db, runtime, world, world["admin"], spaces["candidate"])
    assert answer.scope == "workspace"
    assert {change.execution_id for change in answer.changed} == {spaces["in_a"], spaces["in_b"]}
    considered = in_space(answer, spaces["in_a"]) + in_space(answer, spaces["in_b"])
    assert answer.considered == considered
    assert answer.baseline_effects == {"REQUIRE_APPROVAL": considered}
    assert answer.candidate_effects == {"DENY": considered}
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        seen = client.post(f"{POLICY}/{spaces['candidate']}/preview", {"window": "24h"}).json()
    assert seen["scope"] == "workspace"
    assert seen["considered"] == considered and len(seen["changed"]) == considered


def test_a_policy_managers_unavailable_preview_says_spaces(
    db, runtime, admin_engine, world, spaces, monkeypatch
):
    def unavailable(*_args, **_kwargs):
        raise export_module.ExportError()

    monkeypatch.setattr(preview_module, "export_history", unavailable)
    for identity, scope in ((spaces["manager"], "spaces"), (world["admin"], "workspace")):
        with console_client(db, runtime, admin_engine, identity) as client:
            seen = client.post(f"{POLICY}/{spaces['candidate']}/preview", {"window": "24h"})
            assert seen.status_code == 200, seen.text
            assert seen.json()["available"] is False
            assert seen.json()["scope"] == scope


def spy(monkeypatch):
    calls = []
    real = preview_bundle

    def recorded(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)

    from execbound.surfaces.console_api import policy as console_policy

    monkeypatch.setattr(console_policy, "preview_bundle", recorded)
    return calls


def test_another_spaces_bundle_is_not_found_for_a_manager(
    db, runtime, admin_engine, world, spaces, monkeypatch
):
    calls = spy(monkeypatch)
    with console_client(db, runtime, admin_engine, spaces["manager"]) as client:
        seen = client.post(f"{POLICY}/{spaces['others']}/preview", {"window": "24h"})
    assert (seen.status_code, seen.json()["code"]) == (404, "NOT_FOUND")
    assert calls == []


def test_the_replay_export_still_refuses_a_policy_manager(db, world, spaces):
    """The export answers a refused identity as it answers every failure, with the generic
    `ExportError`, exactly as before; only the preview passes `policy.manage`."""
    with pytest.raises(ExportError):
        export_history(db, spaces["manager"], world["clock"])
    # The one path the preview takes: the whole chain, read for its integrity check.
    history = export_history(db, spaces["manager"], world["clock"], permission="policy.manage")
    assert history.head.sequence > 0


def test_a_policy_manager_previews_through_the_console_and_others_are_refused(
    db, runtime, admin_engine, world, spaces, monkeypatch
):
    with console_client(db, runtime, admin_engine, spaces["manager"]) as client:
        seen = client.post(f"{POLICY}/{spaces['candidate']}/preview", {"window": "24h"})
        assert seen.status_code == 200, seen.text
        assert seen.json()["scope"] == "spaces"
        assert {row["execution_id"] for row in seen.json()["changed"]} == {str(spaces["in_a"])}
    viewer = provision_identity(
        admin_engine, db, spaces["tenant"], "HUMAN_APPROVER", world["clock"].now()
    )
    roles(db, world["admin"], viewer, [{"role": "viewer", "space_id": spaces["first"]}])
    calls = spy(monkeypatch)
    approver = provision_identity(
        admin_engine, db, spaces["tenant"], "HUMAN_APPROVER", world["clock"].now()
    )
    for identity in (approver, current(db, viewer)):
        with console_client(db, runtime, admin_engine, identity) as client:
            refused = client.post(f"{POLICY}/{spaces['candidate']}/preview", {"window": "24h"})
            assert (refused.status_code, refused.json()["code"]) == (403, "FORBIDDEN")
    assert calls == []


def test_a_policy_manager_of_no_space_with_executions_sees_nothing_of_theirs(
    db, runtime, admin_engine, world, spaces
):
    tenant = spaces["tenant"]
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        empty = make_space(conn, tenant, "Customer C")
    someone = provision_identity(
        admin_engine, db, spaces["tenant"], "HUMAN_APPROVER", world["clock"].now()
    )
    roles(db, world["admin"], someone, [{"role": "policy_manager", "space_id": empty}])
    answer = preview(db, runtime, world, current(db, someone), spaces["candidate"])
    assert answer.scope == "spaces"
    assert answer.considered == 0 and answer.changed == ()
