# SPDX-License-Identifier: AGPL-3.0-only
"""The Gate trial seed: one synthetic tenant with an Execute path and a Gate path."""

import json
import os
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import text
from test_validation_ports import held_listeners as held_listeners

from execbound.audit import canonical_json
from execbound.db import Database
from execbound.identity import authenticate
from execbound.policy.models import BundleContent
from execbound.policy.store import create_bundle, validate_bundle
from execbound.surfaces.configuration import read_configuration
from execbound_harness.fixtures import fixture_id
from execbound_harness.gate_demo import reviewer_email, seed_gate
from execbound_harness.validation_run import DemoServices


@pytest.mark.integration
def test_the_seed_writes_a_gate_tenant_the_gateway_configuration_accepts(seeded, tmp_path):
    output = tmp_path / "gate"
    seed_gate(os.environ["TEST_MIGRATION_DATABASE_URL"], output, seed="gate-test-1")
    config = read_configuration(output / "gateway.json")
    assert len(config.connectors) == 1
    assert len(config.checkpoint_providers) == 1
    gate = config.checkpoint_providers[0]
    assert (gate.tenant_id, gate.account_id) != (
        config.connectors[0].tenant_id,
        config.connectors[0].account_id,
    )
    tines = json.loads((output / "tines.json").read_text())
    assert set(tines) == {
        "execbound_gate",
        "execbound_gate_vendor",
        "execbound_gate_key_id",
        "execbound_execute",
        "gate_operation_ref",
        "targets",
    }
    assert (output / "tines-gate-signing.pem").read_text().startswith("-----BEGIN PRIVATE KEY-----")
    accounts = json.loads((output / "endpoint-accounts.json").read_text())
    assert {item["account_id"] for item in accounts} == {
        str(config.connectors[0].account_id),
        str(gate.account_id),
    }


@pytest.mark.integration
def test_the_seeded_reviewer_is_a_password_person_with_exactly_two_approvals(seeded, tmp_path):
    """Post-trial fix #1: reviewer tokens went after the live trial. The reviewer is a
    HUMAN_APPROVER person with an email and no bearer credential, seeded through
    ``invite_person``/``assign_approver`` exactly as the live trial's operator commands ran
    them, holding approver scopes for the two production targets and nothing wider."""
    output = tmp_path / "gate"
    seed = "gate-test-reviewer"
    seed_gate(os.environ["TEST_MIGRATION_DATABASE_URL"], output, seed=seed)
    fixture = json.loads((output / "fixture.json").read_text())
    credentials = json.loads((output / "credentials.json").read_text())
    tenant = UUID(fixture["tenant_id"])
    reviewer = UUID(fixture["reviewer"]["principal_id"])

    assert fixture["reviewer"]["email"] == reviewer_email(seed)
    # No approval path in the seed relies on a reviewer token: the credential map holds
    # only the two agents and the administrator.
    assert set(credentials) == {"execute-agent", "gate-agent", "admin"}
    assert (output / "reviewer-code.txt").is_file()

    execute_production = fixture_id(seed, f"{tenant}/execute/production/canonical")
    gate_production = fixture_id(seed, f"{tenant}/gate/production/canonical")

    db = Database(os.environ["TEST_DATABASE_URL"])
    try:
        with db.transaction(tenant) as conn:
            person = (
                conn.execute(
                    text(
                        "SELECT kind, email, active FROM execbound.principals "
                        "WHERE tenant_id=:t AND principal_id=:p"
                    ),
                    {"t": tenant, "p": reviewer},
                )
                .mappings()
                .one()
            )
            assert person["kind"] == "HUMAN_APPROVER"
            assert person["email"] == reviewer_email(seed)
            assert person["active"]
            credential_count = conn.execute(
                text(
                    "SELECT count(*) FROM execbound.credentials "
                    "WHERE tenant_id=:t AND principal_id=:p"
                ),
                {"t": tenant, "p": reviewer},
            ).scalar_one()
            assert credential_count == 0
            scopes = conn.execute(
                text(
                    "SELECT canonical_target_id, action FROM execbound.approval_scopes "
                    "WHERE tenant_id=:t AND approver_id=:p"
                ),
                {"t": tenant, "p": reviewer},
            ).all()
            assert {(target, action) for target, action in scopes} == {
                (execute_production, "endpoint.isolate"),
                (gate_production, "endpoint.isolate"),
            }
    finally:
        db.close()


@pytest.mark.integration
def test_the_seeded_bundle_separates_gate_and_execute_principals(
    seeded, monkeypatch, tmp_path, held_listeners
):
    """Post-trial fix #2: nothing else in the kernel keeps a Gate principal from reaching an
    Execute mapping or an Execute principal from reaching a Gate account (checkpoint guide,
    limitation 9); the live trial found exactly this ("the Gate credential sent
    `operation_ref endpoint.isolate` on an Execute target and ExecBound dispatched it") and
    fixed it live by activating a bundle carrying the two Cedar forbids. The seed must
    provision them itself: a cross-path request is denied on both sides, and each path's own
    request still reaches its own account (still granted for Gate, still dispatches for
    Execute)."""
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    listeners = held_listeners("gateway", "endpoint")
    ports = [listeners[name].getsockname()[1] for name in ("gateway", "endpoint")]
    output = tmp_path / "gate"
    seed = "gate-test-separation"
    seed_gate(
        os.environ["TEST_MIGRATION_DATABASE_URL"],
        output,
        seed=seed,
        gateway_port=ports[0],
        endpoint_port=ports[1],
    )
    fixture = json.loads((output / "fixture.json").read_text())
    credentials = json.loads((output / "credentials.json").read_text())
    tenant = fixture["tenant_id"]

    def spot(path: str, label: str) -> dict[str, str]:
        # `target.kind == "canonical"` matches `resources.resource_id`, not
        # `canonical_targets.canonical_target_id` (see `execution/snapshot.py`'s coherent
        # read and `validation_run.action_request`, which uses the same field for the
        # same reason).
        return {
            "resource": str(fixture_id(seed, f"{tenant}/{path}/{label}/resource")),
            "incident": str(fixture_id(seed, f"{tenant}/{path}/{label}/incident")),
        }

    execute_workstation = spot("execute", "workstation-01")
    gate_workstation = spot("gate", "workstation-01")

    def body(operation_ref: str, target: dict[str, str], key: str) -> dict[str, object]:
        return {
            "operation_ref": operation_ref,
            "target": {"kind": "canonical", "value": target["resource"]},
            "arguments": {},
            "idempotency_key": key,
            "claimed_context": {"incident_id": target["incident"]},
        }

    running = DemoServices(output, {"ports": fixture["ports"]}, listeners=listeners)
    try:
        running.start("endpoint")
        running.start("gateway")
        with httpx.Client(trust_env=False, timeout=5) as client:

            def ask(token: str, payload: dict[str, object]) -> dict[str, object]:
                return client.post(
                    running.origin + "/v1/execute",
                    json=payload,
                    headers={"Authorization": "Bearer " + token},
                ).json()

            cross_gate = ask(
                credentials["gate-agent"], body("endpoint.isolate", execute_workstation, "sep-1")
            )
            assert cross_gate["state"] == "DENIED"

            cross_execute = ask(
                credentials["execute-agent"],
                body("gate.endpoint.isolate", gate_workstation, "sep-2"),
            )
            assert cross_execute["state"] == "DENIED"

            own_gate = ask(
                credentials["gate-agent"], body("gate.endpoint.isolate", gate_workstation, "sep-3")
            )
            assert own_gate["state"] == "DISPATCH_COMMITTED"

            own_execute = ask(
                credentials["execute-agent"], body("endpoint.isolate", execute_workstation, "sep-4")
            )
            assert own_execute["state"] == "EXECUTED"
    finally:
        running.stop("gateway")
        running.stop("endpoint")


@pytest.mark.integration
def test_the_seeded_bundle_validates_through_the_policy_store(seeded, tmp_path):
    """Post-trial fix #3: the trial copied the seeded bundle and `bundle-create` then
    `bundle-validate` answered `INVALID_COMPONENT` ("Setting names an unused contract or
    source kind"), because `_with_max_age` writes a setting for every catalog contract and
    this bundle maps only the endpoint one; `install_bundle` never validates, so the seed
    never caught it. Prove the seeded content itself validates through the real store."""
    output = tmp_path / "gate"
    seed_gate(os.environ["TEST_MIGRATION_DATABASE_URL"], output, seed="gate-test-validate")
    fixture = json.loads((output / "fixture.json").read_text())
    credentials = json.loads((output / "credentials.json").read_text())
    tenant = UUID(fixture["tenant_id"])

    db = Database(os.environ["TEST_DATABASE_URL"])
    try:
        identity = authenticate(db, credentials["admin"])
        with db.transaction(tenant) as conn:
            content = conn.execute(
                text("SELECT content FROM execbound.policy_bundle_contents WHERE tenant_id=:t"),
                {"t": tenant},
            ).scalar_one()
        installed = BundleContent.model_validate_json(canonical_json(content))
        draft = installed.model_copy(update={"bundle_id": uuid4()})
        record = create_bundle(db, identity, draft)
        validated = validate_bundle(db, identity, record.content.bundle_id)
        assert validated.state == "VALIDATED"
    finally:
        db.close()
