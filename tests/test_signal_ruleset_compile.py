# SPDX-License-Identifier: AGPL-3.0-only
"""`ruleset-compile` for a signal bundle: chosen mappings, carried signal mappings (#478)."""

import json
from datetime import timedelta

from test_admin_registry import bootstrap, refused, run
from test_admin_registry import cli_env as cli_env
from test_admin_registry import owner as owner

from execbound import administration as admin
from execbound.provisioning import create_signal_source


def condition(name, operator, value):
    return {"kind": "fact", "name": name, "operator": operator, "values": [value]}


RULES = {
    "version": 1,
    "rules": [
        {
            "id": "isolate-open-incident",
            "action": "endpoint.isolate",
            "effect": "ALLOW",
            "when": [condition("incident_status", "is", "OPEN")],
        },
        {
            "id": "isolate-never-domain-controller",
            "action": "endpoint.isolate",
            "effect": "DENY",
            "when": [condition("role", "is", "domain_controller")],
        },
        {
            "id": "isolate-review-unless-compromised",
            "action": "endpoint.isolate",
            "effect": "REVIEW",
            "when": [condition("compromise", "is_not", "compromised")],
        },
    ],
}
THRESHOLDS = [
    {"verdict": "None", "value": "no_detection"},
    {"verdict": "Informational", "value": "no_detection"},
    {"verdict": "Low", "value": "suspect"},
    {"verdict": "Medium", "value": "compromised"},
    {"verdict": "High", "value": "compromised"},
]


def tenant_with_both_contracts(owner, db, tmp_path, monkeypatch, capsys):
    """Lift on endpoint-recovery.v1, isolation on v1, and isolation on v2 under its own ref.

    Refs are unique per tenant, so the v2 baseline's companion is `isolate.corroborated`, and
    one bundle cannot hold v2 beside either of the others: `--ref` must choose.
    """
    tenant, actor, agent, _identity = bootstrap(owner, db, tmp_path)
    account = run(
        monkeypatch,
        capsys,
        *("account-create", "--tenant", str(tenant)),
        *("--provider", "mock_crowdstrike", "--actor", str(actor)),
    )["account_id"]
    for action, ref, version in (
        ("endpoint.lift_isolation", "endpoint.lift_isolation", ()),
        ("endpoint.isolate", "endpoint.isolate", ()),
        (
            "endpoint.isolate",
            "isolate.corroborated",
            ("--contract-version", "endpoint-isolation.v2"),
        ),
    ):
        run(
            monkeypatch,
            capsys,
            *("mapping-create", "--tenant", str(tenant), "--account", account),
            *("--action", action, "--ref", ref, "--actor", str(actor), *version),
        )
    grant = create_signal_source(
        owner,
        tenant,
        actor,
        label="MDE lab",
        producer="execbound-mde-producer",
        version_min="0.1.0",
        version_max="0.9.9",
        capabilities=("resource_compromise.v1",),
        principals=(agent,),
        lifetime=timedelta(hours=8),
        output=tmp_path / "producer.token",
    )
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps(RULES), encoding="utf-8")
    return tenant, actor, grant.source_id, rules


def signal_entry(source, thresholds=THRESHOLDS):
    return {
        "context_contract_version": "endpoint-isolation.v2",
        "capability": "resource_compromise.v1",
        "admitted_sources": [str(source)],
        "thresholds": thresholds,
    }


def signal_file(tmp_path, source, thresholds=THRESHOLDS):
    path = tmp_path / "signal-mappings.json"
    path.write_text(json.dumps([signal_entry(source, thresholds)]), encoding="utf-8")
    return path


def test_a_signal_bundle_compiles_over_its_chosen_mapping_and_activates(
    owner, db, cli_env, tmp_path, monkeypatch, capsys
):
    tenant, actor, source, rules = tenant_with_both_contracts(
        owner, db, tmp_path, monkeypatch, capsys
    )
    credential = tmp_path / "admin.token"
    admin.issue_credential(
        owner, tenant, actor, actor, lifetime=timedelta(hours=1), output=credential
    )
    bundle_file = tmp_path / "bundle.json"
    compiled = run(
        monkeypatch,
        capsys,
        *("ruleset-compile", "--tenant", str(tenant), "--input", str(rules)),
        *("--ref", "isolate.corroborated"),
        *("--signal-mappings", str(signal_file(tmp_path, source))),
        *("--output", str(bundle_file)),
    )
    assert (compiled["mappings"], compiled["signal_mappings"]) == (["isolate.corroborated"], 1)
    document = json.loads(bundle_file.read_text(encoding="utf-8"))
    assert [entry["admitted_sources"] for entry in document["signal_mappings"]] == [[str(source)]]
    # The mapping names the action its ref serves, and the rules compile about that action.
    assert [(item["operation_ref"], item["action"]) for item in document["mappings"]] == [
        ("isolate.corroborated", "endpoint.isolate")
    ]
    assert '"endpoint.isolate"' in document["cedar_schema"]
    assert "isolate.corroborated" not in document["authorization_policies"]
    for command in ("bundle-create", "bundle-validate", "bundle-activate"):
        state = run(
            monkeypatch,
            capsys,
            *(command, "--tenant", str(tenant), "--credential-file", str(credential)),
            *(("--input", str(bundle_file)) if command == "bundle-create" else ()),
            *(() if command == "bundle-create" else ("--bundle", compiled["bundle_id"])),
        )
    assert state["state"] == "ACTIVE"


def test_an_unknown_ref_or_a_malformed_signal_mapping_is_refused_and_writes_nothing(
    owner, db, cli_env, tmp_path, monkeypatch, capsys
):
    tenant, _actor, source, rules = tenant_with_both_contracts(
        owner, db, tmp_path, monkeypatch, capsys
    )
    output = tmp_path / "bundle.json"
    assert "--ref names no active operation mapping" in refused(
        monkeypatch,
        capsys,
        *("ruleset-compile", "--tenant", str(tenant), "--input", str(rules)),
        *("--ref", "isolate.nowhere", "--output", str(output)),
    )
    malformed = signal_file(tmp_path, source, [{"verdict": "High", "value": "bogus"}])
    message = refused(
        monkeypatch,
        capsys,
        *("ruleset-compile", "--tenant", str(tenant), "--input", str(rules)),
        *("--ref", "isolate.corroborated", "--signal-mappings", str(malformed)),
        *("--output", str(output)),
    )
    assert "Signal mappings file is invalid" in message and "bogus" not in message
    assert not output.exists()
    for body, expected in (
        ("not json", "Signal mappings file is not a readable JSON document"),
        ('[{"capability": 1, "capability": 2}]', "Signal mappings file is not a readable JSON"),
        ("{}", "Signal mappings file must contain a JSON array"),
        # Each entry is well formed; the bundle refuses the set, and says which field.
        ("[]", "The compiled bundle is invalid: signal_mappings: "),
        (
            json.dumps([signal_entry(source), signal_entry(source)]),
            "The compiled bundle is invalid: signal_mappings: ",
        ),
    ):
        shaped = tmp_path / "shaped.json"
        shaped.write_text(body, encoding="utf-8")
        assert expected in refused(
            monkeypatch,
            capsys,
            *("ruleset-compile", "--tenant", str(tenant), "--input", str(rules)),
            *("--ref", "isolate.corroborated", "--signal-mappings", str(shaped)),
            *("--output", str(output)),
        )
        assert not output.exists()


def test_mappings_that_cannot_compile_together_are_refused_where_they_are(
    owner, db, cli_env, tmp_path, monkeypatch, capsys
):
    tenant, _actor, _source, rules = tenant_with_both_contracts(
        owner, db, tmp_path, monkeypatch, capsys
    )
    output = tmp_path / "bundle.json"
    command = ("ruleset-compile", "--tenant", str(tenant), "--input", str(rules))
    # Every active mapping by default, and endpoint.isolate cannot mean v1 and v2 at once.
    assert refused(monkeypatch, capsys, *command, "--output", str(output)).splitlines()[0] == (
        "Ruleset is invalid: Mappings endpoint.isolate (endpoint-isolation.v1) and "
        "isolate.corroborated (endpoint-isolation.v2) serve endpoint.isolate under different "
        "contracts and cannot share a bundle (mappings.2); choose the mappings to compile "
        "over with --ref"
    )
    # Chosen mappings the compiler cannot read together: no hint, because --ref already chose.
    # v2 isolation cannot share Endpoint with recovery.v1.
    assert refused(
        monkeypatch,
        capsys,
        *command,
        *("--ref", "endpoint.lift_isolation", "--ref", "isolate.corroborated"),
        *("--output", str(output)),
    ).splitlines()[0] == (
        "Ruleset is invalid: Mappings endpoint.lift_isolation (endpoint-recovery.v1) and "
        "isolate.corroborated (endpoint-isolation.v2) describe the Endpoint entity "
        "differently and cannot share a bundle (mappings.1)"
    )
    assert not output.exists()


def test_a_repeated_ref_compiles_its_mapping_once(
    owner, db, cli_env, tmp_path, monkeypatch, capsys
):
    tenant, _actor, source, rules = tenant_with_both_contracts(
        owner, db, tmp_path, monkeypatch, capsys
    )
    bundle_file = tmp_path / "bundle.json"
    compiled = run(
        monkeypatch,
        capsys,
        *("ruleset-compile", "--tenant", str(tenant), "--input", str(rules)),
        *("--ref", "isolate.corroborated", "--ref", "isolate.corroborated"),
        *("--signal-mappings", str(signal_file(tmp_path, source))),
        *("--output", str(bundle_file)),
    )
    assert compiled["mappings"] == ["isolate.corroborated"]
    document = json.loads(bundle_file.read_text(encoding="utf-8"))
    assert [item["operation_ref"] for item in document["mappings"]] == ["isolate.corroborated"]
