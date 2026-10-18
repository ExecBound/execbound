# SPDX-License-Identifier: AGPL-3.0-only
"""TG12 to TG14: a Gate story's whole exchange, with the protected mock as its vendor.

The story here holds what a Tines Gate story holds: an agent credential, the vendor's
dispatch token and an ES256 key. It asks the runtime, sends the grant's provider command to
the real mock app, and reports what the vendor answered. ExecBound dispatches nothing.
"""

import hashlib
import json
import secrets

import pytest
from checkpoint_fixtures import (
    CONTAIN,
    JOURNAL_KEY,
    JOURNAL_KEY_ID,
    attestation_claims,
    gate_runtime,
    journal_provider,
    jws,
    register_es256,
    retained,
)
from checkpoint_fixtures import gate_world as gate_world
from checkpoint_fixtures import owner as owner
from fastapi.testclient import TestClient
from test_execution import registry as registry
from test_execution import targets
from test_execution import world as world
from test_resolution import request

from execbound.execution.models import ExecutionError, PreconditionConfig
from execbound.provider.mock_app import create_mock_app
from execbound.provider.mock_store import MockStore
from execbound.provider.models import ProviderAccount

ENFORCED = PreconditionConfig({CONTAIN: "ENFORCED_BY_PROVIDER"})


@pytest.fixture
def vendor(tmp_path, gate_world):
    world = gate_world
    token = secrets.token_urlsafe(32)
    account = ProviderAccount(
        world["identity"].tenant_id,
        world["account"],
        hashlib.sha256(token.encode()).hexdigest(),
        hashlib.sha256(secrets.token_urlsafe(32).encode()).hexdigest(),
        JOURNAL_KEY,
        key_id=JOURNAL_KEY_ID,
    )
    store = MockStore(tmp_path / "vendor.sqlite3")
    with TestClient(create_mock_app(store, (account,))) as client:
        yield store, client, {"Authorization": f"Bearer {token}"}


def _seed(store, grant):
    command = grant["provider_command"]
    store.provision_resource(
        command["tenant_id"], command["canonical_target_id"], command["expected_version"]
    )
    store.provision_representation(
        command["tenant_id"],
        command["account_id"],
        command["resource_provider_id"],
        command["canonical_target_id"],
    )


def _ask(runtime, world, action):
    view = runtime.execute(world["identity"], action.model_dump_json().encode())
    return view, runtime.present(world["identity"], view)


def _report(runtime, world, execution_id, body):
    return runtime.report(world["identity"], execution_id, json.dumps(body).encode())


def test_tg12_grant_command_journal_report_settles_provider_verified(
    db, gate_world, admin_engine, vendor
):
    world = gate_world
    store, client, auth = vendor
    runtime = gate_runtime(
        db, world, preconditions=ENFORCED, checkpoint_providers=[journal_provider(world)]
    )
    view, described = _ask(runtime, world, request(world))
    grant = described["checkpoint"]["grant"]
    _seed(store, grant)
    answered = client.post(
        f"/v1/{grant['provider_operation']}", json=grant["provider_command"], headers=auth
    )
    assert answered.status_code == 200
    journal = answered.json()
    settled = _report(
        runtime,
        world,
        view.execution_id,
        {
            "report_secret": grant["report_secret"],
            "outcome": "EXECUTED",
            "reason": "EXECUTED",
            "journal": journal,
        },
    )
    assert settled.state == "EXECUTED"
    row = retained(admin_engine, world["identity"].tenant_id, view.execution_id)
    assert (row.tier, row.impact, row.released_at is not None) == (
        "PROVIDER_VERIFIED",
        "CONFIRMED",
        True,
    )
    resource = store.resource(
        world["identity"].tenant_id, grant["provider_command"]["canonical_target_id"]
    )
    assert resource.mutation_count == 1


def test_tg13_a_lost_vendor_response_is_reconciled_by_lookup_without_a_second_effect(
    db, gate_world, admin_engine, vendor
):
    world = gate_world
    store, client, auth = vendor
    runtime = gate_runtime(
        db, world, preconditions=ENFORCED, checkpoint_providers=[journal_provider(world)]
    )
    view, described = _ask(runtime, world, request(world))
    grant = described["checkpoint"]["grant"]
    _seed(store, grant)
    # The effect lands and the story never sees the answer.
    client.post(f"/v1/{grant['provider_operation']}", json=grant["provider_command"], headers=auth)
    unknown = _report(
        runtime,
        world,
        view.execution_id,
        {
            "report_secret": grant["report_secret"],
            "outcome": "UNKNOWN",
            "reported_at": world["clock"].now().isoformat(),
        },
    )
    assert unknown.state == "INDETERMINATE"
    looked_up = client.post("/v1/journal", json=grant["provider_command"], headers=auth)
    assert looked_up.status_code == 200
    settled = _report(
        runtime,
        world,
        view.execution_id,
        {
            "report_secret": grant["report_secret"],
            "outcome": "EXECUTED",
            "reason": "EXECUTED",
            "journal": looked_up.json(),
        },
    )
    assert settled.state == "EXECUTED"
    resource = store.resource(
        world["identity"].tenant_id, grant["provider_command"]["canonical_target_id"]
    )
    assert resource.mutation_count == 1


def test_tg14_evidence_for_one_execution_settles_no_other_and_a_regrant_carries_no_secret(
    db, gate_world, owner, admin_engine, vendor
):
    world = gate_world
    store, client, auth = vendor
    tines = register_es256(owner, world)
    runtime = gate_runtime(
        db, world, preconditions=ENFORCED, checkpoint_providers=[journal_provider(world)]
    )
    first, second = targets(admin_engine, world, count=2)
    a_view, a = _ask(runtime, world, first)
    b_view, b = _ask(runtime, world, second)
    a_grant, b_grant = a["checkpoint"]["grant"], b["checkpoint"]["grant"]
    _seed(store, a_grant)
    a_journal = client.post(
        f"/v1/{a_grant['provider_operation']}", json=a_grant["provider_command"], headers=auth
    ).json()
    cases = (
        (
            {
                "report_secret": a_grant["report_secret"],
                "outcome": "EXECUTED",
                "reason": "EXECUTED",
                "reported_at": world["clock"].now().isoformat(),
            },
            "INVALID_REPORT",
        ),
        (
            {
                "report_secret": b_grant["report_secret"],
                "outcome": "EXECUTED",
                "reason": "EXECUTED",
                "journal": a_journal,
            },
            "INVALID_RECORD",
        ),
        (
            {
                "report_secret": b_grant["report_secret"],
                "outcome": "EXECUTED",
                "reason": "EXECUTED",
                "attestation": jws(
                    tines,
                    {"alg": "ES256", "kid": "tines-v1"},
                    attestation_claims(db, world, a_view.execution_id),
                ),
            },
            "INVALID_RECORD",
        ),
    )
    for body, code in cases:
        with pytest.raises(ExecutionError) as refused:
            _report(runtime, world, b_view.execution_id, body)
        assert refused.value.code == code
    assert (
        retained(admin_engine, world["identity"].tenant_id, b_view.execution_id).state
        == "DISPATCH_COMMITTED"
    )
    _, again = _ask(runtime, world, second)
    regrant = again["checkpoint"]["grant"]
    assert regrant["regranted"] is True and regrant["report_secret"] is None
    assert regrant["provider_command"] == b_grant["provider_command"]
