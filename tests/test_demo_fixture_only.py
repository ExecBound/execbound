# SPDX-License-Identifier: AGPL-3.0-only
"""Isolation of optional synthetic fixtures on the execution path (#475).

These two exercise `demo_check` (which reads `fixture_only`) from `admit` and `dispatch_owned`
directly, with no hosted fixture (no signups, no mail relay, no Community claim).
"""

import hashlib

import pytest
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import world as world
from test_migration_without_bypass import fenced
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider


def _fingerprint(engine, tenant, tables):
    """The same per-table row hash `signup_fixtures.fingerprint` computes, scoped to the
    four execution tables these tests care about, none of which carry a migration-era column
    exclusion, so the plain `to_jsonb(r)` reduction is exactly equivalent here."""
    result = {}
    with engine.begin() as conn:
        fenced(conn, tenant)
        for table in tables:
            rows = sorted(
                str(r[0])
                for r in conn.execute(
                    text(f"SELECT to_jsonb(r) FROM execbound.{table} r WHERE tenant_id=:t"),
                    {"t": tenant},
                )
            )
            result[table] = (len(rows), hashlib.sha256("\n".join(rows).encode()).hexdigest())
    return result


def test_admitted_demo_cannot_dispatch_after_import_retires_fixture_authority(
    db, admin_engine, world, connector, live_provider
):
    from test_context_provisioning import apply, entry, manifest
    from test_execution import request
    from test_protected_path import resource

    from execbound.execution import admit, decide_approval
    from execbound.execution.models import ExecutionError
    from execbound.provider.gateway import dispatch_owned

    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        for table in ("resources", "resource_facts", "incidents"):
            conn.execute(
                text(f"UPDATE execbound.{table} SET demo_fixture=true WHERE tenant_id=:t"),
                {"t": tenant},
            )
    demo = request(world).model_copy(update={"synthetic_demo": True})
    pending = admit(db, world["identity"], demo, world["clock"])
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    admitted = admit(db, world["identity"], demo, world["clock"])
    assert admitted.ticket is not None
    apply(
        admin_engine,
        world,
        manifest(world, entry(world["clock"].now(), facts={"role": "workstation"})),
    )
    with pytest.raises(ExecutionError) as refused:
        dispatch_owned(db, admitted.ticket, connector, world["clock"])
    assert refused.value.code == "DEMO_UNAVAILABLE"
    assert resource(live_provider, world).mutation_count == 0
    # Dropping the marker from a retry cannot widen its frozen restriction.
    with pytest.raises(ExecutionError) as retry:
        admit(db, world["identity"], request(world), world["clock"])
    assert retry.value.code == "DEMO_UNAVAILABLE"


def test_demo_intent_is_refused_in_mixed_workspace_before_reservation(db, admin_engine, world):
    from test_execution import request as execution_request

    from execbound.execution import admit
    from execbound.execution.models import ExecutionError
    from execbound.requests import parse_request

    request = parse_request(
        execution_request(world)
        .model_dump_json()
        .replace('"operation_ref":', '"synthetic_demo":true,"operation_ref":', 1)
        .encode()
    )
    tenant = world["admin"].tenant_id
    tables = ("executions", "approvals", "execution_impact", "execution_keys")
    before = _fingerprint(admin_engine, tenant, tables)
    with pytest.raises(ExecutionError) as refused:
        admit(db, world["identity"], request, world["clock"])
    assert refused.value.code == "DEMO_UNAVAILABLE"
    after = _fingerprint(admin_engine, tenant, tables)
    for table in tables:
        assert before[table] == after[table]
