# SPDX-License-Identifier: AGPL-3.0-only
"""Guarded repeatable synthetic fixture provisioning never touches unrelated tenants."""

import json
import os
from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, UUID, uuid5

import pytest
from sqlalchemy import text

from execbound.db import Database
from execbound.identity import authenticate
from execbound.policy.evaluate import evaluate
from execbound.policy.models import BundleContent, ProjectedUsage, UsageSnapshot
from execbound.policy.store import load_active_bundle
from execbound.provider.identity_store import IdentityStore
from execbound.provider.mock_app import create_mock_app
from execbound.provider.mock_store import MockStore
from execbound.requests import parse_request
from execbound.resolution import resolve_request
from execbound.surfaces.configuration import load_runtime


def test_validation_seed_has_two_tenants_both_providers_and_independent_credentials(
    admin_engine, seeded, tmp_path
):
    from execbound_harness.validation_demo import seed_validation

    output = tmp_path / "private-demo"
    seed_validation(os.environ["TEST_MIGRATION_DATABASE_URL"], output, seed="fixture-test")
    fixture = json.loads((output / "fixture.json").read_text())
    credentials = json.loads((output / "credentials.json").read_text())
    config = json.loads((output / "gateway.json").read_text())
    assert len(fixture["tenants"]) == 2
    assert len(config["connectors"]) == 4
    assert len({c["dispatch_token"] for c in config["connectors"]}) == 4
    assert len({c["control_token"] for c in config["connectors"]}) == 4
    assert len({next(iter(c["evidence_keys"].values())) for c in config["connectors"]}) == 4
    db = Database(os.environ["TEST_DATABASE_URL"])
    try:
        for tenant in fixture["tenants"]:
            targets = tenant["targets"]
            assert sum(t["role"] == "workstation" for t in targets) >= 25
            assert {t["privilege_class"] for t in targets if t["resource_type"] == "identity"} == {
                "standard",
                "privileged",
                "tier0",
            }
            actors = credentials[tenant["tenant_id"]]
            assert {authenticate(db, item["token"]).kind for item in actors} == {
                "AGENT",
                "HUMAN_APPROVER",
                "ADMIN",
            }
            assert sum(item["kind"] == "AGENT" for item in actors) >= 2
            with db.transaction(tenant["tenant_id"]) as conn:
                assert (
                    conn.execute(
                        text("SELECT count(*) FROM execbound.operation_mappings")
                    ).scalar_one()
                    == 6
                )
                assert (
                    conn.execute(text("SELECT count(*) FROM execbound.tenants")).scalar_one() == 1
                )
        # Reusing a public namespace must fail transactionally, preserving the first fixture.
        original = (output / "credentials.json").read_bytes()
        with pytest.raises(ValueError):
            seed_validation(os.environ["TEST_MIGRATION_DATABASE_URL"], output, seed="fixture-test")
        assert (output / "credentials.json").read_bytes() == original
        with pytest.raises(ValueError):
            seed_validation(
                os.environ["TEST_MIGRATION_DATABASE_URL"],
                tmp_path / "collision",
                seed="fixture-test",
            )
        with admin_engine.connect() as conn:
            assert conn.execute(text("SELECT count(*) FROM execbound.tenants")).scalar_one() == 4
    finally:
        db.close()


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+psycopg://execbound_owner:secret@remote.example:55439/execbound",
        "postgresql+psycopg://execbound_owner:secret@127.0.0.1:55439/production",
        "postgresql+psycopg://execbound_app:secret@127.0.0.1:55439/execbound",
        "postgresql+psycopg://execbound_owner:secret@127.0.0.1:55439/execbound?host=remote.example",
    ],
)
def test_validation_seed_refuses_unsafe_database_before_output_or_connection(
    url, tmp_path, monkeypatch
):
    from execbound_harness import validation_demo

    def forbidden(*args, **kwargs):
        raise AssertionError("Unsafe destination connected")

    monkeypatch.setattr(validation_demo, "create_engine", forbidden)
    output = tmp_path / "demo"
    with pytest.raises(ValueError):
        validation_demo.seed_validation(url, output)
    assert not output.exists()


@pytest.fixture
def demo(seeded, tmp_path):
    from execbound_harness.validation_demo import seed_validation

    output = tmp_path / "private-demo"
    seed_validation(os.environ["TEST_MIGRATION_DATABASE_URL"], output, seed="verified-demo")
    return (
        output,
        json.loads((output / "fixture.json").read_text()),
        json.loads((output / "credentials.json").read_text()),
    )


def test_validation_seed_startup_and_provider_inventory_match(demo, monkeypatch):
    output, fixture, credentials = demo
    db = Database(os.environ["TEST_DATABASE_URL"])
    runtime = None
    try:
        runtime, human = load_runtime(output / "gateway.json", db)
        assert len(runtime.connectors) == 4
        assert human.origin == "http://127.0.0.1:8100"
        stores = {
            "endpoint": MockStore(output / "endpoint.sqlite3"),
            "identity": IdentityStore(output / "identity.sqlite3"),
        }
        for label, provider in (("endpoint", "mock_crowdstrike"), ("identity", "mock_entra")):
            monkeypatch.setenv("EXECBOUND_MOCK_PROVIDER", provider)
            monkeypatch.setenv(
                "EXECBOUND_MOCK_ACCOUNTS_PATH", str(output / f"{label}-accounts.json")
            )
            monkeypatch.setenv("EXECBOUND_MOCK_DATABASE_PATH", str(output / f"{label}.sqlite3"))
            app = create_mock_app()
            assert any(route.path == "/v1/journal" for route in app.routes)
        for index, tenant in enumerate(fixture["tenants"]):
            for target in tenant["targets"]:
                state = stores[target["resource_type"]].resource(
                    UUID(tenant["tenant_id"]), UUID(target["canonical_target_id"])
                )
                assert state.version == "resource-v1" and state.mutation_count == 0
                if target["resource_type"] == "identity":
                    assert state.account_enabled == (target["label"] != "identity-enable")
            admin = next(a for a in credentials[tenant["tenant_id"]] if a["kind"] == "ADMIN")
            active = load_active_bundle(db, authenticate(db, admin["token"]))
            assert len(active.mappings) == 4 and len(active.limits) == 8
            with db.transaction(tenant["tenant_id"]) as conn:
                rows = conn.execute(
                    text("""SELECT approver_id, action, count(*) FROM
                    execbound.approval_scopes GROUP BY approver_id,action""")
                ).all()
                scopes = {(str(p), action): count for p, action, count in rows}
                actors = {a["label"]: a["principal_id"] for a in tenant["actors"]}
                assert scopes == {
                    (actors["human_endpoint"], "endpoint.isolate"): 26,
                    (actors["human_endpoint"], "endpoint.lift_isolation"): 26,
                    **{
                        (actors["human_identity"], action): 6
                        for action in (
                            "identity.disable",
                            "identity.enable",
                            "identity.revoke_sessions",
                            "identity.reset_password",
                        )
                    },
                }
                soc = BundleContent.model_validate_json(
                    (output / f"soc-bundle-{index}.json").read_bytes()
                )
                assert conn.execute(
                    text("""SELECT kind, payload->>'bundle_id' FROM execbound.audit_events
                        ORDER BY sequence""")
                ).all() == [
                    ("policy.bundle_created", str(active.bundle_id)),
                    ("policy.bundle_validated", str(active.bundle_id)),
                    ("policy.bundle_activated", str(active.bundle_id)),
                    ("policy.bundle_created", str(soc.bundle_id)),
                    ("policy.bundle_validated", str(soc.bundle_id)),
                ]
    finally:
        if runtime is not None:
            for connector in runtime.connectors.values():
                connector.close()
        db.close()


def test_validation_seed_installs_the_soc_bundle_as_validated(demo, db):
    output, fixture, _ = demo
    for index, tenant in enumerate(fixture["tenants"]):
        soc = BundleContent.model_validate_json((output / f"soc-bundle-{index}.json").read_bytes())
        baseline = BundleContent.model_validate_json((output / f"bundle-{index}.json").read_bytes())
        assert len(soc.mappings) == 6 and len(soc.limits) == 12
        assert {m.operation_ref for m in baseline.mappings} < {
            m.operation_ref for m in soc.mappings
        }
        with db.transaction(tenant["tenant_id"]) as conn:
            states = dict(
                conn.execute(
                    text("SELECT bundle_id, state FROM execbound.policy_bundle_lifecycle")
                ).all()
            )
            active = conn.execute(
                text("SELECT bundle_id FROM execbound.space_policy_selection")
            ).scalar_one()
        assert states[soc.bundle_id] == "VALIDATED"
        assert states[baseline.bundle_id] == "ACTIVE" and active == baseline.bundle_id


@pytest.mark.parametrize(
    "label,action,effect",
    [
        ("workstation-01", "endpoint.isolate", "ELIGIBLE"),
        ("workstation-25", "endpoint.isolate", "REQUIRE_APPROVAL"),
        ("domain-controller", "endpoint.isolate", "DENY"),
        ("identity-disable", "identity.disable", "ELIGIBLE"),
        ("identity-enable", "identity.enable", "REQUIRE_APPROVAL"),
        ("identity-revoke-sessions", "identity.revoke_sessions", "ELIGIBLE"),
        ("identity-production", "identity.disable", "REQUIRE_APPROVAL"),
        ("identity-privileged", "identity.disable", "DENY"),
        ("identity-tier0", "identity.revoke_sessions", "DENY"),
    ],
)
def test_validation_mixed_policy_enforces_each_provider_contract(demo, label, action, effect):
    _, fixture, credentials = demo
    tenant = fixture["tenants"][0]
    target = next(t for t in tenant["targets"] if t["label"] == label)
    actor = next(a for a in credentials[tenant["tenant_id"]] if a["label"] == "agent-0")
    db = Database(os.environ["TEST_DATABASE_URL"])
    try:
        identity = authenticate(db, actor["token"])
        bundle = load_active_bundle(db, identity)
        request = parse_request(
            json.dumps(
                {
                    "operation_ref": action,
                    "target": {"kind": "canonical", "value": target["resource_id"]},
                    "arguments": {},
                    "idempotency_key": "validation-test",
                    "claimed_context": {"incident_id": target["incident_id"]},
                }
            ).encode()
        )
        resolved = resolve_request(db, identity, request)
        usage = UsageSnapshot(
            tenant_id=identity.tenant_id,
            principal_id=identity.principal_id,
            bundle_id=bundle.bundle_id,
            account_id=resolved.intent.account_id,
            counts=tuple(
                ProjectedUsage(rule_id=rule.rule_id, confirmed_targets=0, unresolved_targets=0)
                for rule in bundle.limits
            ),
        )
        assert (
            evaluate(bundle=bundle, identity=identity, resolved=resolved, usage=usage).effect
            == effect
        )
    finally:
        db.close()


def test_validation_namespace_public_artifacts_and_expiry(demo):
    output, fixture, credentials = demo
    tenant = fixture["tenants"][0]
    assert UUID(tenant["tenant_id"]) == uuid5(
        NAMESPACE_URL, "https://execbound.invalid/validation/v1/verified-demo/tenant/0"
    )
    created, expiry, context_expiry = (
        datetime.fromisoformat(fixture[k])
        for k in ("created_at", "expires_at", "context_expires_at")
    )
    assert datetime.now(UTC) - created < timedelta(seconds=30)
    assert expiry - created == timedelta(hours=8)
    assert context_expiry - created == timedelta(seconds=300)
    public = (output / "fixture.json").read_text()
    config = json.loads((output / "gateway.json").read_text())
    all_secrets = [c["token"] for actors in credentials.values() for c in actors]
    all_secrets += [c[k] for c in config["connectors"] for k in ("dispatch_token", "control_token")]
    all_secrets += [v for c in config["connectors"] for v in c["evidence_keys"].values()]
    all_secrets += list(config["continuation_keys"].values())
    assert len(set(all_secrets)) == len(all_secrets)
    assert all(secret not in public for secret in all_secrets)
    baseline = BundleContent.model_validate_json((output / "bundle-0.json").read_bytes())
    candidate = BundleContent.model_validate_json((output / "candidate-0.json").read_bytes())
    assert baseline.mappings == candidate.mappings
    assert all(rule.max_targets == 1 for rule in candidate.limits)
    assert baseline.content_hash != candidate.content_hash
    if os.name != "nt":
        assert output.stat().st_mode & 0o777 == 0o700
        assert all(path.stat().st_mode & 0o077 == 0 for path in output.iterdir())


def test_validation_publication_failure_rolls_back_new_namespace_only(
    admin_engine, seeded, tmp_path, monkeypatch
):
    from execbound_harness import validation_demo

    output = tmp_path / "failed-demo"
    sentinel = tmp_path / "unrelated.txt"
    sentinel.write_text("retain")
    write = validation_demo._write

    def fail_publication(path, *args, **kwargs):
        if path.name == "fixture.pending.json":
            raise OSError("secret-diagnostic-not-for-user")
        return write(path, *args, **kwargs)

    monkeypatch.setattr(validation_demo, "_write", fail_publication)
    with pytest.raises(ValueError, match="^Validation fixture unavailable$"):
        validation_demo.seed_validation(
            os.environ["TEST_MIGRATION_DATABASE_URL"], output, seed="rollback"
        )
    assert output.is_dir()
    assert not (output / "fixture.json").exists()
    assert sentinel.read_text() == "retain"
    with admin_engine.connect() as conn:
        assert set(conn.execute(text("SELECT tenant_id FROM execbound.tenants")).scalars()) == set(
            seeded["tenants"]
        )
        assert conn.execute(text("SELECT count(*) FROM execbound.resources")).scalar_one() == 0
    # A known rollback permits the same namespace, but always use a fresh directory.
    monkeypatch.setattr(validation_demo, "_write", write)
    validation_demo.seed_validation(
        os.environ["TEST_MIGRATION_DATABASE_URL"], tmp_path / "retry-demo", seed="rollback"
    )
    assert (tmp_path / "retry-demo" / "fixture.json").is_file()


@pytest.mark.parametrize("replace_directory", [False, True])
def test_validation_failure_retains_foreign_files_and_replaced_directories(
    tmp_path, monkeypatch, replace_directory
):
    from execbound_harness import validation_demo

    output = tmp_path / "private"

    def unavailable(*args, **kwargs):
        if replace_directory:
            output.rename(tmp_path / "original-private")
            output.mkdir()
        (output / "foreign.txt").write_text("belongs to another process")
        raise OSError("connection unavailable")

    monkeypatch.setattr(validation_demo, "create_engine", unavailable)
    with pytest.raises(ValueError, match="^Validation fixture unavailable$"):
        validation_demo.seed_validation(
            "postgresql+psycopg://execbound_owner:secret@127.0.0.1:55439/execbound_test",
            output,
        )
    assert (output / "foreign.txt").read_text() == "belongs to another process"
    assert not (output / "fixture.json").exists()
    if replace_directory:
        assert (tmp_path / "original-private" / "endpoint.sqlite3").exists()


def test_validation_failed_database_commit_cannot_publish_success_manifest(
    admin_engine, seeded, tmp_path, monkeypatch
):
    from sqlalchemy import event

    from execbound_harness import validation_demo

    create = validation_demo.create_engine

    def reject_commit(*args, **kwargs):
        engine = create(*args, **kwargs)

        @event.listens_for(engine, "commit")
        def reject(connection):
            raise OSError("commit failed")

        return engine

    monkeypatch.setattr(validation_demo, "create_engine", reject_commit)
    output = tmp_path / "commit-failure"
    with pytest.raises(ValueError, match="^Validation fixture unavailable$"):
        validation_demo.seed_validation(
            os.environ["TEST_MIGRATION_DATABASE_URL"], output, seed="commit-failure"
        )
    assert output.is_dir()
    assert (output / "fixture.pending.json").is_file()
    assert not (output / "fixture.json").exists()
    with admin_engine.connect() as conn:
        assert set(conn.execute(text("SELECT tenant_id FROM execbound.tenants")).scalars()) == set(
            seeded["tenants"]
        )


def test_validation_publication_collision_retains_foreign_manifest(
    admin_engine, seeded, tmp_path, monkeypatch
):
    from execbound_harness import validation_demo

    link = validation_demo.os.link

    def foreign_destination(source, destination):
        destination.write_text("foreign manifest; retain verbatim")
        return link(source, destination)

    monkeypatch.setattr(validation_demo.os, "link", foreign_destination)
    output = tmp_path / "publication-collision"
    with pytest.raises(ValueError, match="^Validation fixture unavailable$"):
        validation_demo.seed_validation(
            os.environ["TEST_MIGRATION_DATABASE_URL"], output, seed="publication-collision"
        )
    assert (output / "fixture.json").read_text() == "foreign manifest; retain verbatim"
    assert (output / "fixture.pending.json").is_file()
    # The database committed before manifest publication; never delete that namespace
    # or pretend the caller can safely reuse it after a publication failure.
    with admin_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.tenants")).scalar_one() == 4


@pytest.mark.parametrize(
    "options",
    [
        {"seed": "../escape"},
        {"seed": ""},
        {"gateway_port": 8101},
        {"endpoint_port": True},
        {"identity_port": 80},
    ],
)
def test_validation_options_fail_before_output_and_database(tmp_path, monkeypatch, options):
    from execbound_harness import validation_demo

    def forbidden(*args, **kwargs):
        raise AssertionError("Invalid fixture connected")

    monkeypatch.setattr(validation_demo, "create_engine", forbidden)
    output = tmp_path / "private"
    with pytest.raises(ValueError):
        validation_demo.seed_validation(
            "postgresql+psycopg://execbound_owner:secret@127.0.0.1:55439/execbound_test",
            output,
            **options,
        )
    assert not output.exists()
