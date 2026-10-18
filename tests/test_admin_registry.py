# SPDX-License-Identifier: AGPL-3.0-only
"""Owner registry provisioning: connector accounts, operation mappings, canonical targets
and resources for a tenant that no fixture seeded, so a hosted tenant can admit an action."""

import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from conftest import assert_secret_free
from sqlalchemy import create_engine, text

from execbound import administration as admin
from execbound import provisioning
from execbound.cli import main
from execbound.connection import connect_args, database_url
from execbound.identity import authenticate
from execbound.policy.models import Ruleset
from execbound.policy.rulesets import sentence
from execbound.requests import ActionRequest, Arguments, ClaimedContext, ResourceSelector
from execbound.resolution import ResolutionError, resolve_request


@pytest.fixture
def owner(seeded):
    engine = admin.owner_engine(os.environ["TEST_MIGRATION_DATABASE_URL"])
    yield engine
    engine.dispose()


@pytest.fixture
def cli_env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setenv("MIGRATION_DATABASE_URL", os.environ["TEST_MIGRATION_DATABASE_URL"])


def bootstrap(owner, db, tmp_path):
    """A fresh tenant with its first ADMIN and one AGENT whose identity can resolve requests."""
    tenant = admin.create_tenant(owner, "Registry")
    actor = admin.create_principal(owner, tenant, "ADMIN")
    agent = admin.create_principal(owner, tenant, "AGENT", actor=actor)
    output = tmp_path / "agent.token"
    admin.issue_credential(owner, tenant, agent, actor, lifetime=timedelta(hours=1), output=output)
    identity = authenticate(db, output.read_text(encoding="utf-8").strip())
    return tenant, actor, agent, identity


def audit_kinds(engine, tenant):
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        rows = conn.execute(
            text("SELECT kind FROM execbound.audit_events WHERE tenant_id=:t ORDER BY sequence"),
            {"t": tenant},
        )
        return [row[0] for row in rows]


def incident_manifest(tenant, account, source, incident, observed):
    return {
        "manifest": "execbound.context-manifest.v1",
        "tenant_id": str(tenant),
        "account_id": str(account),
        "source_id": str(source),
        "kind": "incident",
        "writer": "soc_analyst",
        "entries": [
            {
                "provider": "mock_crowdstrike",
                "resource_type": "endpoint",
                "provider_id": "device-01",
                "version": "ticket-1",
                "observed_at": observed.isoformat(),
                "facts": {"incident_status": "OPEN", "incident_severity": "CRITICAL"},
                "incident_id": str(incident),
            }
        ],
    }


def request(ref, kind, value, incident):
    return ActionRequest(
        operation_ref=ref,
        target=ResourceSelector(kind=kind, value=value),
        arguments=Arguments({}),
        idempotency_key=f"registry-{kind}",
        claimed_context=ClaimedContext(incident_id=incident),
    )


def run(monkeypatch, capsys, *argv):
    monkeypatch.setattr(sys, "argv", ["execbound", *argv])
    main()
    return json.loads(capsys.readouterr().out)


def refused(monkeypatch, capsys, *argv):
    monkeypatch.setattr(sys, "argv", ["execbound", *argv])
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2
    return capsys.readouterr().err


def test_accounts_mappings_targets_and_resources_resolve_a_request(
    owner, db, admin_engine, tmp_path
):
    tenant, actor, agent, identity = bootstrap(owner, db, tmp_path)

    endpoint = admin.create_account(owner, tenant, "mock_crowdstrike", actor)
    identity_account = admin.create_account(owner, tenant, "mock_entra", actor)
    for provider, principal, code in (
        ("vendor_x", actor, "INVALID_PROVIDER"),
        ("mock_crowdstrike", agent, "INVALID_ACTOR"),
        ("mock_crowdstrike", uuid4(), "INVALID_ACTOR"),
    ):
        with pytest.raises(admin.AdministrationError) as bad_account:
            admin.create_account(owner, tenant, provider, principal)
        assert bad_account.value.code == code
    assert [(a.provider, a.account_id, a.active) for a in admin.list_accounts(owner, tenant)] == [
        ("mock_crowdstrike", endpoint, True),
        ("mock_entra", identity_account, True),
    ]

    assert admin.create_mapping(
        owner, tenant, endpoint, "endpoint.isolate", actor
    ).operation_ref == ("endpoint.isolate")
    custom = admin.create_mapping(
        owner,
        tenant,
        identity_account,
        "identity.disable",
        actor,
        operation_ref="disable-user",
        mapping_version="map-v2",
    )
    assert (custom.operation_ref, custom.provider_operation, custom.mapping_version) == (
        "disable-user",
        "disable",
        "map-v2",
    )
    for account, action, code, extra in (
        (endpoint, "endpoint.isolate", "INVALID_REFERENCE", {}),
        (endpoint, "identity.disable", "INVALID_ACTION", {}),
        (endpoint, "endpoint.explode", "INVALID_ACTION", {}),
        (uuid4(), "endpoint.isolate", "INVALID_ACCOUNT", {}),
        (endpoint, "endpoint.lift_isolation", "INVALID_REFERENCE", {"operation_ref": "Bad Ref"}),
        (endpoint, "endpoint.lift_isolation", "INVALID_VERSION", {"mapping_version": ""}),
    ):
        with pytest.raises(admin.AdministrationError) as bad_mapping:
            admin.create_mapping(owner, tenant, account, action, actor, **extra)
        assert bad_mapping.value.code == code
    mappings = admin.list_mappings(owner, tenant)
    assert [
        (m.operation_ref, m.account_id, m.provider, m.resource_type, m.action, m.provider_operation)
        for m in mappings
    ] == [
        ("disable-user", identity_account, "mock_entra", "identity", "identity.disable", "disable"),
        (
            "endpoint.isolate",
            endpoint,
            "mock_crowdstrike",
            "endpoint",
            "endpoint.isolate",
            "contain",
        ),
    ]
    assert {
        (m.mapping_version, m.schema_version, m.context_contract_version) for m in mappings
    } == {
        ("map-v2", "action.v1", "identity-control.v1"),
        ("map-v1", "action.v1", "endpoint-isolation.v1"),
    }

    inventory = provisioning.create_context_source(
        owner, tenant, endpoint, "inventory", ["inventory_sync"], actor
    )
    incident_source = provisioning.create_context_source(
        owner, tenant, endpoint, "incident", ["soc_analyst"], actor
    )
    target = admin.create_target(owner, tenant, actor)
    created = admin.create_resource(
        owner,
        tenant,
        endpoint,
        "endpoint",
        "device-01",
        inventory,
        actor,
        target=target,
        hostname="WS01.Example.",
        facts={"role": "workstation", "environment": "production", "criticality": 2},
    )
    assert created.canonical_target_id == target
    assert created.aliases == ("hostname:ws01.example", "provider_id:device-01")
    implicit = admin.create_resource(
        owner, tenant, endpoint, "endpoint", "device-02", inventory, actor
    )
    assert implicit.canonical_target_id not in {target, created.resource_id}
    assert implicit.aliases == ("provider_id:device-02",)
    for kwargs, code in (
        ({"provider_id": "device-01"}, "INVALID_PROVIDER_ID"),
        ({"provider_id": "device 03"}, "INVALID_PROVIDER_ID"),
        ({"provider_id": "device-03", "source": incident_source}, "INVALID_SOURCE"),
        ({"provider_id": "device-03", "source": uuid4()}, "INVALID_SOURCE"),
        ({"provider_id": "device-03", "target": uuid4()}, "INVALID_TARGET"),
        ({"provider_id": "device-03", "hostname": "ws01.example"}, "INVALID_ALIAS"),
        ({"provider_id": "device-03", "hostname": "not a host"}, "INVALID_ALIAS"),
        ({"provider_id": "device-03", "alias_days": 0}, "INVALID_ALIAS"),
        ({"provider_id": "device-03", "facts": {"role": "printer"}}, "INVALID_FACT"),
        ({"provider_id": "device-03", "facts": {"criticality": True}}, "INVALID_FACT"),
        ({"provider_id": "device-03", "facts": {"privilege_class": "tier0"}}, "INVALID_FACT"),
        ({"provider_id": "device-03", "version": ""}, "INVALID_VERSION"),
        ({"provider_id": "device-03", "resource_type": "printer"}, "INVALID_RESOURCE_TYPE"),
        ({"provider_id": "device-03", "account": identity_account}, "INVALID_SOURCE"),
    ):
        arguments = {
            "account": endpoint,
            "resource_type": "endpoint",
            "source": inventory,
            **kwargs,
        }
        provider_id = arguments.pop("provider_id")
        with pytest.raises(admin.AdministrationError) as bad_resource:
            admin.create_resource(
                owner,
                tenant,
                arguments.pop("account"),
                arguments.pop("resource_type"),
                provider_id,
                arguments.pop("source"),
                actor,
                **arguments,
            )
        assert bad_resource.value.code == code, kwargs
    with pytest.raises(admin.AdministrationError) as identity_hostname:
        user_source = provisioning.create_context_source(
            owner, tenant, identity_account, "inventory", ["inventory_sync"], actor
        )
        admin.create_resource(
            owner,
            tenant,
            identity_account,
            "identity",
            "user-01",
            user_source,
            actor,
            hostname="user01.example",
        )
    assert identity_hostname.value.code == "INVALID_ALIAS"
    listed = admin.list_resources(owner, tenant)
    assert [(r.provider_id, r.canonical_target_id, r.aliases, r.active) for r in listed] == [
        ("device-01", target, ("hostname:ws01.example", "provider_id:device-01"), True),
        ("device-02", implicit.canonical_target_id, ("provider_id:device-02",), True),
    ]

    incident = uuid4()
    observed = datetime.now(UTC) - timedelta(seconds=30)
    parsed = provisioning.parse_manifest(
        json.dumps(
            incident_manifest(tenant, endpoint, incident_source, incident, observed)
        ).encode()
    )
    assert (
        provisioning.import_manifest(owner, tenant, parsed, actor).counts["incidents_created"] == 1
    )
    for kind, value in (
        ("hostname", "ws01.example"),
        ("provider_id", "device-01"),
        ("canonical", str(created.resource_id)),
    ):
        resolved = resolve_request(db, identity, request("endpoint.isolate", kind, value, incident))
        assert resolved.intent.account_id == endpoint
        assert resolved.resource_provider_id == "device-01"
        assert resolved.mapping_version == "map-v1"
        assert {fact.name: fact.value for fact in resolved.facts}.items() >= {
            "role": "workstation",
            "environment": "production",
            "criticality": 2,
            "is_production": True,
            "incident_status": "OPEN",
        }.items()
    with pytest.raises(ResolutionError) as no_facts:
        resolve_request(
            db, identity, request("endpoint.isolate", "provider_id", "device-02", incident)
        )
    assert no_facts.value.code == "INVALID_CONTEXT"
    kinds = audit_kinds(admin_engine, tenant)
    assert kinds.count("account.created") == 2
    assert kinds.count("mapping.created") == 2
    assert kinds.count("target.created") == 1
    assert kinds.count("resource.created") == 2


def test_registry_commands_through_the_cli(owner, db, cli_env, tmp_path, monkeypatch, capsys):
    tenant, actor, agent, identity = bootstrap(owner, db, tmp_path)
    account = run(
        monkeypatch,
        capsys,
        "account-create",
        "--tenant",
        str(tenant),
        "--provider",
        "mock_crowdstrike",
        "--actor",
        str(actor),
    )
    assert account["provider"] == "mock_crowdstrike"
    account_id = UUID(account["account_id"])
    mapping = run(
        monkeypatch,
        capsys,
        "mapping-create",
        "--tenant",
        str(tenant),
        "--account",
        str(account_id),
        "--action",
        "endpoint.isolate",
        "--actor",
        str(actor),
    )
    assert (mapping["operation_ref"], mapping["provider_operation"]) == (
        "endpoint.isolate",
        "contain",
    )
    source = provisioning.create_context_source(
        owner, tenant, account_id, "inventory", ["inventory_sync"], actor
    )
    target = run(
        monkeypatch, capsys, "target-create", "--tenant", str(tenant), "--actor", str(actor)
    )
    resource = run(
        monkeypatch,
        capsys,
        "resource-create",
        "--tenant",
        str(tenant),
        "--account",
        str(account_id),
        "--resource-type",
        "endpoint",
        "--provider-id",
        "device-01",
        "--source",
        str(source),
        "--target",
        target["canonical_target_id"],
        "--hostname",
        "ws01.example",
        "--role",
        "workstation",
        "--environment",
        "production",
        "--criticality",
        "2",
        "--actor",
        str(actor),
    )
    assert resource["canonical_target_id"] == target["canonical_target_id"]
    assert resource["aliases"] == ["hostname:ws01.example", "provider_id:device-01"]
    assert [
        item["provider"]
        for item in run(monkeypatch, capsys, "account-list", "--tenant", str(tenant))
    ] == ["mock_crowdstrike"]
    assert [
        item["operation_ref"]
        for item in run(monkeypatch, capsys, "mapping-list", "--tenant", str(tenant))
    ] == ["endpoint.isolate"]
    listed = run(monkeypatch, capsys, "resource-list", "--tenant", str(tenant))
    assert [(item["provider_id"], item["aliases"]) for item in listed] == [
        ("device-01", ["hostname:ws01.example", "provider_id:device-01"])
    ]
    error = refused(
        monkeypatch,
        capsys,
        "resource-create",
        "--tenant",
        str(tenant),
        "--account",
        str(account_id),
        "--resource-type",
        "endpoint",
        "--provider-id",
        "device-01",
        "--source",
        str(source),
        "--actor",
        str(actor),
    )
    assert "INVALID_PROVIDER_ID" in error
    assert_secret_free(json.dumps([account, mapping, target, resource, listed]))


def test_registry_provisioning_is_tenant_scoped_and_owner_only(owner, seeded, db, tmp_path):
    tenant, actor, agent, identity = bootstrap(owner, db, tmp_path)
    other = admin.create_tenant(owner, "Other")
    other_actor = admin.create_principal(owner, other, "ADMIN")
    account = admin.create_account(owner, tenant, "mock_crowdstrike", actor)
    with pytest.raises(admin.AdministrationError) as foreign_actor:
        admin.create_account(owner, tenant, "mock_entra", other_actor)
    assert foreign_actor.value.code == "INVALID_ACTOR"
    with pytest.raises(admin.AdministrationError) as foreign_account:
        admin.create_mapping(owner, other, account, "endpoint.isolate", other_actor)
    assert foreign_account.value.code == "INVALID_ACCOUNT"
    assert admin.list_accounts(owner, other) == ()
    assert admin.list_mappings(owner, other) == ()
    assert admin.list_resources(owner, other) == ()

    parsed = database_url(os.environ["TEST_DATABASE_URL"])
    runtime = create_engine(parsed, hide_parameters=True, connect_args=connect_args(parsed))
    try:
        for operation in (
            lambda: admin.create_account(runtime, tenant, "mock_entra", actor),
            lambda: admin.create_mapping(runtime, tenant, account, "endpoint.isolate", actor),
            lambda: admin.create_target(runtime, tenant, actor),
            lambda: admin.list_resources(runtime, tenant),
        ):
            with pytest.raises(admin.AdministrationError) as not_owner:
                operation()
            assert not_owner.value.code == "INVALID_CONNECTION"
    finally:
        runtime.dispose()


# The starter ruleset ships in the wheel, because `execbound init` copies it out of the
# image into an installation that has no repository to copy it from.
STARTER_RULES = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "execbound"
    / "data"
    / "community"
    / "starter-rules.json"
)


def test_the_shipped_starter_ruleset_compiles_and_activates(
    owner, db, cli_env, tmp_path, monkeypatch, capsys
):
    """The community bundle's own starter rules reach ACTIVE through the image's commands.

    This is the installation's first policy, and until `ruleset-compile` existed there was no
    way to author one from the image: the bundle document the lifecycle accepts carries a
    Cedar schema and two policy sets, and the console's rules editor needs an active bundle
    before it will let anyone write a rule. The test follows exactly what the runbook does, so
    a starter file that drifts from the compiler, or a compiler that stops agreeing with what
    validation recompiles, fails here rather than on a stranger's machine.
    """
    tenant, actor, _agent, _identity = bootstrap(owner, db, tmp_path)
    credential = tmp_path / "admin.token"
    admin.issue_credential(
        owner, tenant, actor, actor, lifetime=timedelta(hours=1), output=credential
    )
    account = run(
        monkeypatch,
        capsys,
        *("account-create", "--tenant", str(tenant)),
        *("--provider", "mock_crowdstrike", "--actor", str(actor)),
    )
    run(
        monkeypatch,
        capsys,
        *("mapping-create", "--tenant", str(tenant)),
        *("--account", account["account_id"], "--action", "endpoint.isolate"),
        *("--actor", str(actor)),
    )
    bundle_file = tmp_path / "bundle.json"
    compiled = run(
        monkeypatch,
        capsys,
        *("ruleset-compile", "--tenant", str(tenant)),
        *("--input", str(STARTER_RULES), "--output", str(bundle_file)),
    )
    assert compiled["mappings"] == ["endpoint.isolate"]
    assert (compiled["rules"], compiled["budgets"]) == (4, 2)
    document = json.loads(bundle_file.read_text(encoding="utf-8"))
    assert document["tenant_id"] == str(tenant)
    # The rules are carried, which is what makes validation recompile and compare them.
    assert [rule["id"] for rule in document["ruleset"]["rules"]] == [
        "isolate-workstation-open-critical",
        "isolate-never-domain-controller",
        "isolate-never-criticality-4",
        "isolate-production-needs-review",
    ]
    # What the starter rules *say*, in the console's own words and the runbook's. Pinning
    # only that the file activates would let an edited fact value ship: the bundle would
    # still compile and still activate, and the runbook's allowed action would be refused
    # on a stranger's machine with nothing here to have caught it.
    assert [
        sentence(rule)
        for rule in Ruleset.model_validate_json(json.dumps(document["ruleset"])).rules
    ] == [
        "Allow endpoint.isolate when role is workstation, incident_status is OPEN and "
        "incident_severity is CRITICAL.",
        "Deny endpoint.isolate when role is domain_controller.",
        "Deny endpoint.isolate when criticality is 4.",
        "Review endpoint.isolate when is_production is true.",
    ]
    for command in ("bundle-create", "bundle-validate", "bundle-activate"):
        state = run(
            monkeypatch,
            capsys,
            *(command, "--tenant", str(tenant), "--credential-file", str(credential)),
            *(("--input", str(bundle_file)) if command == "bundle-create" else ()),
            *(() if command == "bundle-create" else ("--bundle", compiled["bundle_id"])),
        )
    assert state["state"] == "ACTIVE"
    assert bundle_file.stat().st_mode & 0o077 == 0
    assert_secret_free(json.dumps([compiled, document]))


def test_ruleset_compile_refuses_to_overwrite_and_says_which_field_was_wrong(
    owner, db, cli_env, tmp_path, monkeypatch, capsys
):
    """The three refusals an operator actually meets, each naming what to fix.

    Overwriting matters because the bundle a deployment activated is the record of what it
    activated; a second run that silently replaced it would leave the file and the database
    disagreeing about the same bundle id.
    """
    tenant, actor, _agent, _identity = bootstrap(owner, db, tmp_path)
    output = tmp_path / "bundle.json"
    # No mapping yet: the actions a rule may speak about are the tenant's own mappings.
    assert "no active operation mapping" in refused(
        monkeypatch,
        capsys,
        *("ruleset-compile", "--tenant", str(tenant)),
        *("--input", str(STARTER_RULES), "--output", str(output)),
    )
    account = run(
        monkeypatch,
        capsys,
        *("account-create", "--tenant", str(tenant)),
        *("--provider", "mock_entra", "--actor", str(actor)),
    )
    run(
        monkeypatch,
        capsys,
        *("mapping-create", "--tenant", str(tenant)),
        *("--account", account["account_id"], "--action", "identity.disable"),
        *("--actor", str(actor)),
    )
    # A mapping exists, but none serves the action the starter rules name.
    assert "endpoint.isolate" in refused(
        monkeypatch,
        capsys,
        *("ruleset-compile", "--tenant", str(tenant)),
        *("--input", str(STARTER_RULES), "--output", str(output)),
    )
    assert not output.exists()
    unknown = tmp_path / "unknown-fact.json"
    unknown.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "disable-anything",
                        "action": "identity.disable",
                        "effect": "ALLOW",
                        "when": [
                            {
                                "kind": "fact",
                                "name": "hostname",
                                "operator": "is",
                                "values": ["ws01.example"],
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    # The location names the rule and the condition, and the refused value is not echoed.
    problem = refused(
        monkeypatch,
        capsys,
        *("ruleset-compile", "--tenant", str(tenant)),
        *("--input", str(unknown), "--output", str(output)),
    )
    assert "rules.0.when.0" in problem and "ws01.example" not in problem
    good = tmp_path / "identity-rules.json"
    good.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "disable-standard-identity",
                        "action": "identity.disable",
                        "effect": "ALLOW",
                        "when": [
                            {
                                "kind": "fact",
                                "name": "privilege_class",
                                "operator": "is",
                                "values": ["standard"],
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    run(
        monkeypatch,
        capsys,
        *("ruleset-compile", "--tenant", str(tenant)),
        *("--input", str(good), "--output", str(output)),
    )
    assert "not written" in refused(
        monkeypatch,
        capsys,
        *("ruleset-compile", "--tenant", str(tenant)),
        *("--input", str(good), "--output", str(output)),
    )
