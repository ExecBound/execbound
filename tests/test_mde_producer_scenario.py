# SPDX-License-Identifier: AGPL-3.0-only
"""The committed MDE scenario isolates without review only when the EDR reports compromise,
maps verdicts as docs/SIGNALS.md documents, and compiles (#478)."""

import json
from datetime import timedelta
from pathlib import Path

from pydantic import TypeAdapter
from signal_fixtures import MDE_THRESHOLDS
from test_admin_registry import cli_env as cli_env
from test_admin_registry import owner as owner
from test_admin_registry import run
from test_signal_ruleset_compile import tenant_with_both_contracts

from execbound import administration as admin
from execbound.cli import load_ruleset_file
from execbound.policy.rulesets import sentence
from execbound.signals.models import SignalThreshold

SCENARIO = Path(__file__).resolve().parents[1] / "integrations" / "mde-producer" / "scenario"


def sentences(name):
    return [sentence(rule) for rule in load_ruleset_file(SCENARIO / name).rules]


def test_the_scenario_isolates_without_review_only_when_the_edr_reports_compromise():
    assert sentences("rules.json") == [
        "Allow endpoint.isolate when incident_status is OPEN.",
        "Deny endpoint.isolate when role is domain_controller.",
        "Review endpoint.isolate when compromise is not compromised.",
    ]


def test_the_baseline_is_the_same_policy_without_the_signal():
    assert sentences("baseline-rules.json") == sentences("rules.json")[:2]


def test_both_raise_context_freshness_for_the_trial_and_leave_the_signal_at_its_default():
    for name, version in (
        ("rules.json", "endpoint-isolation.v2"),
        ("baseline-rules.json", "endpoint-isolation.v1"),
    ):
        context = load_ruleset_file(SCENARIO / name).context
        assert {
            (item.context_contract_version, item.source_kind, item.max_age_seconds)
            for item in context
        } == {(version, "inventory", 3600), (version, "incident", 3600)}


def test_the_verdict_table_is_the_documented_one():
    """The committed table is the documented one: Medium and High read as `compromised`, Low
    as `suspect`, and nothing as `clean`."""
    table = TypeAdapter(tuple[SignalThreshold, ...]).validate_json(
        (SCENARIO / "thresholds.json").read_text(encoding="utf-8")
    )
    assert sorted(table, key=lambda row: row.verdict) == sorted(
        MDE_THRESHOLDS, key=lambda row: row.verdict
    )


def test_both_rule_files_compile_and_activate(owner, db, cli_env, tmp_path, monkeypatch, capsys):
    tenant, actor, source, _rules = tenant_with_both_contracts(
        owner, db, tmp_path, monkeypatch, capsys
    )
    credential = tmp_path / "admin.token"
    admin.issue_credential(
        owner, tenant, actor, actor, lifetime=timedelta(hours=1), output=credential
    )
    thresholds = json.loads((SCENARIO / "thresholds.json").read_text(encoding="utf-8"))
    signal_mappings = tmp_path / "signal-mappings.json"
    signal_mappings.write_text(
        json.dumps(
            [
                {
                    "context_contract_version": "endpoint-isolation.v2",
                    "capability": "resource_compromise.v1",
                    "admitted_sources": [str(source)],
                    "thresholds": thresholds,
                }
            ]
        ),
        encoding="utf-8",
    )
    for name, ref, extra in (
        ("baseline-rules.json", "endpoint.isolate", ()),
        ("rules.json", "isolate.corroborated", ("--signal-mappings", str(signal_mappings))),
    ):
        bundle_file = tmp_path / f"{ref}.bundle.json"
        compiled = run(
            monkeypatch,
            capsys,
            *("ruleset-compile", "--tenant", str(tenant), "--input", str(SCENARIO / name)),
            *("--ref", ref, *extra, "--output", str(bundle_file)),
        )
        for command in ("bundle-create", "bundle-validate", "bundle-activate"):
            state = run(
                monkeypatch,
                capsys,
                *(command, "--tenant", str(tenant), "--credential-file", str(credential)),
                *(("--input", str(bundle_file)) if command == "bundle-create" else ()),
                *(() if command == "bundle-create" else ("--bundle", compiled["bundle_id"])),
            )
        assert state["state"] == "ACTIVE", name
