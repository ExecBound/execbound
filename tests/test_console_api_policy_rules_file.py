# SPDX-License-Identifier: AGPL-3.0-only
"""Rules files: download a policy's rules, and start a draft from one (#678; PL8, PL9).

The file is the `Ruleset` document `ruleset-compile` already reads. A download leaves out what
names this workspace's own records (a budget counted for a group, an account or a Space, and
the context settings), and an import refuses them, resolves every action against the target
Space's own mappings and lands only as a draft. Real PostgreSQL throughout
(THREAT_MODEL.md, the rules file row).
"""

import json
import re
from uuid import uuid4

import pytest
import secret_shapes
from console_api_fixtures import API, assert_no_secrets, console_client
from scope_fixtures import group
from scope_fixtures import owner as owner
from space_fixtures import make_space
from sqlalchemy import text
from test_access_control import current, roles
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.cli import load_ruleset_file
from execbound.policy.models import ContextSetting, LimitRule, LimitSelector
from execbound.policy.rulesets import MAX_RULESET_FILE_BYTES, ruleset_bundle
from execbound.policy.store import create_bundle
from execbound.surfaces.console_api import policy as console_policy
from execbound_harness.demo import ENDPOINT_RULESET

pytestmark = pytest.mark.integration

POLICY = API + "/policy"
UUID_TEXT = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
CONTEXT = ContextSetting(
    context_contract_version="endpoint-isolation.v1",
    source_kind="inventory",
    max_age_seconds=600,
    permitted_writers=("cmdb",),
)


def fenced(conn, tenant) -> None:
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def rules_bundle(db, world, ruleset, **changes):
    content = ruleset_bundle(
        ruleset,
        tenant_id=world["identity"].tenant_id,
        bundle_id=uuid4(),
        mappings=world["bundle"].mappings,
        **changes,
    )
    create_bundle(db, world["admin"], content, world["clock"])
    return content


@pytest.fixture
def shared(db, owner, world):
    """The endpoint pack's rules with a tenant budget, a group budget, a selector budget, a
    note and a context block: everything a download keeps or leaves out."""
    triage = group(owner, world, name="Tier-1 SOC")
    budgets = (
        *ENDPOINT_RULESET.budgets,
        LimitRule(
            rule_id="squad-hourly",
            action="endpoint.isolate",
            scope="group",
            group_id=triage,
            window_seconds=3600,
            max_targets=3,
            budget="total",
            on_exceed="REQUIRE_APPROVAL",
        ),
        LimitRule(
            rule_id="workstations-hourly",
            action="endpoint.isolate",
            scope="selector",
            selector=LimitSelector(fact="role", equals="workstation"),
            window_seconds=3600,
            max_targets=5,
            budget="total",
            on_exceed="DENY",
        ),
    )
    rules = tuple(
        rule.model_copy(update={"note": "Domain controllers stay up"})
        if rule.id == "isolate-never-domain-controller"
        else rule
        for rule in ENDPOINT_RULESET.rules
    )
    ruleset = ENDPOINT_RULESET.model_copy(
        update={"rules": rules, "budgets": budgets, "context": (CONTEXT,)}
    )
    return rules_bundle(db, world, ruleset, context_settings=(CONTEXT,))


def download(client, bundle_id):
    answer = client.get(f"{POLICY}/{bundle_id}/ruleset")
    assert answer.status_code == 200, answer.text
    assert_no_secrets(answer)
    return answer.json()


def test_a_download_is_the_ruleset_file_the_cli_reads(
    db, runtime, admin_engine, world, shared, tmp_path
):
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        body = download(client, shared.bundle_id)
        detail = client.get(f"{POLICY}/{shared.bundle_id}").json()
    assert body["filename"] == f"execbound-rules-{str(shared.bundle_id)[:8]}.json"
    assert body["omitted_budgets"] == ["squad-hourly"]
    assert body["omitted_context"] is True
    path = tmp_path / body["filename"]
    path.write_text(json.dumps(body["ruleset"]), encoding="utf-8")
    assert shared.ruleset is not None
    expected = shared.ruleset.model_copy(
        update={
            "budgets": tuple(item for item in shared.ruleset.budgets if item.scope != "group"),
            "context": None,
        }
    )
    assert load_ruleset_file(path) == expected
    assert detail["rules_file"] == {
        "available": True,
        "omitted_budgets": ["squad-hourly"],
        "omitted_context": True,
    }


def test_a_download_carries_no_identifier(db, runtime, admin_engine, world, shared):
    """The claim is record identifiers, and no more: no tenant, account, mapping, group,
    Space or principal id leaves in a rules file."""
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        body = download(client, shared.bundle_id)
    assert UUID_TEXT.search(json.dumps(body["ruleset"])) is None


def test_a_download_keeps_selector_budgets_and_notes_as_written(
    db, runtime, admin_engine, world, shared
):
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        ruleset = download(client, shared.bundle_id)["ruleset"]
    kept = {budget["rule_id"]: budget for budget in ruleset["budgets"]}
    assert kept["workstations-hourly"]["selector"] == {"fact": "role", "equals": "workstation"}
    notes = {rule["id"]: rule.get("note") for rule in ruleset["rules"]}
    assert notes["isolate-never-domain-controller"] == "Domain controllers stay up"


def test_a_bundle_not_written_as_rules_cannot_be_downloaded(db, runtime, admin_engine, world):
    """A pasted Cedar document has no rules to download, and a recognized seed has its
    reviewed rules only once an editable draft of it exists."""
    cedar = world["bundle"].model_copy(
        update={
            "bundle_id": uuid4(),
            "authorization_policies": "forbid(principal, action, resource);",
        }
    )
    create_bundle(db, world["admin"], cedar, world["clock"])
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        for bundle_id in (cedar.bundle_id, world["bundle"].bundle_id):
            refused = client.get(f"{POLICY}/{bundle_id}/ruleset")
            assert (refused.status_code, refused.json()["code"]) == (409, "CONFLICT")
            assert client.get(f"{POLICY}/{bundle_id}").json()["rules_file"] == {
                "available": False,
                "omitted_budgets": [],
                "omitted_context": False,
            }


def two_spaces(admin_engine, world, *, offered: bool = True):
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        first = conn.execute(
            text("SELECT space_id FROM execbound.spaces WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one()
        second = make_space(conn, tenant, "Customer B")
        if offered:
            conn.execute(
                text(
                    "UPDATE execbound.connector_accounts SET offered_tenant_wide=true "
                    "WHERE tenant_id=:t"
                ),
                {"t": tenant},
            )
    return first, second


def test_another_spaces_bundle_is_not_downloaded(db, runtime, admin_engine, world):
    first, second = two_spaces(admin_engine, world)
    others = ruleset_bundle(
        ENDPOINT_RULESET,
        tenant_id=world["identity"].tenant_id,
        bundle_id=uuid4(),
        mappings=world["bundle"].mappings,
    )
    create_bundle(db, world["admin"], others, world["clock"], space=second)
    roles(db, world["admin"], world["human"], [{"role": "policy_manager", "space_id": first}])
    with console_client(db, runtime, admin_engine, current(db, world["human"])) as client:
        refused = client.get(f"{POLICY}/{others.bundle_id}/ruleset")
    assert (refused.status_code, refused.json()["code"]) == (404, "NOT_FOUND")


def counts(admin_engine, tenant):
    with admin_engine.connect() as conn:
        bundles = conn.execute(
            text("SELECT count(*) FROM execbound.policy_bundle_contents WHERE tenant_id=:t"),
            {"t": tenant},
        ).scalar_one()
        head = conn.execute(
            text("SELECT sequence FROM execbound.audit_heads WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one_or_none()
    return bundles, head


def kinds_since(admin_engine, tenant, after):
    with admin_engine.connect() as conn:
        return list(
            conn.execute(
                text(
                    "SELECT kind FROM execbound.audit_events WHERE tenant_id=:t AND sequence > :s "
                    "ORDER BY sequence"
                ),
                {"t": tenant, "s": after or 0},
            ).scalars()
        )


def test_a_rules_file_becomes_a_draft_over_this_spaces_mappings(
    db, runtime, admin_engine, world, shared
):
    tenant = world["identity"].tenant_id
    _, second = two_spaces(admin_engine, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        file = json.dumps(download(client, shared.bundle_id)["ruleset"])
        before = client.get(POLICY).json()["active"]
        moved = client.post(API + "/session/space", {"space_id": str(second)})
        assert moved.status_code == 200, moved.text
        _, head = counts(admin_engine, tenant)
        made = client.post(POLICY, {"source": "ruleset", "ruleset": file})
        assert made.status_code == 200, made.text
        assert_no_secrets(made)
        body = made.json()
        assert body["state"] == "DRAFT" and body["written_as_rules"] is True
        assert body["active"] is False
        listed = client.get(POLICY).json()
        assert listed["active"] != body["bundle_id"]
        client.post(API + "/session/space", {"space_id": None})
        assert client.get(POLICY).json()["active"] in (before, None)
    with admin_engine.connect() as conn:
        owned = conn.execute(
            text(
                "SELECT space_id FROM execbound.policy_bundle_contents "
                "WHERE tenant_id=:t AND bundle_id=:b"
            ),
            {"t": tenant, "b": body["bundle_id"]},
        ).scalar_one()
    assert owned == second
    assert [row["operation_ref"] for row in body["mappings"]] == ["endpoint.isolate"]
    kinds = kinds_since(admin_engine, tenant, head)
    assert "policy.bundle_created" in kinds
    assert "policy.bundle_activated" not in kinds


RULE = {"id": "allow-isolation", "action": "endpoint.isolate", "effect": "ALLOW"}
BUDGET = {
    "rule_id": "squad",
    "action": "endpoint.isolate",
    "scope": "group",
    "group_id": "00000000-0000-4000-8000-000000000009",
    "window_seconds": 3600,
    "max_targets": 3,
    "budget": "total",
    "on_exceed": "DENY",
}


@pytest.mark.parametrize(
    ("file", "fields"),
    [
        (
            json.dumps({"rules": [{**RULE, "action": "identity.disable"}]}),
            ["ruleset.rules.0.action"],
        ),
        (json.dumps({"rules": [RULE], "budgets": [BUDGET]}), ["ruleset.budgets.0.group_id"]),
        (
            json.dumps({"rules": [RULE], "context": [json.loads(CONTEXT.model_dump_json())]}),
            ["ruleset.context"],
        ),
        ('{"rules": [], "rules": []}', ["ruleset"]),
        ("not json", ["ruleset"]),
        ("[1, 2]", ["ruleset"]),
        (json.dumps({"version": 2, "rules": [RULE]}), ["ruleset.version"]),
        (
            json.dumps({"rules": [{**RULE, "note": secret_shapes.STRIPE}]}),
            ["ruleset.rules.0.note"],
        ),
    ],
    ids=[
        "unmapped",
        "group",
        "context",
        "duplicate-keys",
        "not-json",
        "array",
        "version",
        "secret-note",
    ],
)
def test_a_rules_file_is_refused_at_its_location_and_writes_nothing(
    db, runtime, admin_engine, world, file, fields
):
    tenant = world["identity"].tenant_id
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        before = counts(admin_engine, tenant)
        refused = client.post(POLICY, {"source": "ruleset", "ruleset": file})
    assert (refused.status_code, refused.json()["code"]) == (400, "INVALID_BODY"), refused.text
    assert refused.json()["fields"] == fields
    assert_no_secrets(refused)
    assert secret_shapes.STRIPE not in refused.text
    assert counts(admin_engine, tenant) == before


def test_an_action_served_only_by_a_signal_mapping_is_named_as_such(
    db, runtime, admin_engine, world
):
    """A rules file cannot carry the signal mappings, verdict table and admitted producers a
    signal contract needs, so "no action mapping" would be false: the mapping exists and is
    excluded on purpose."""
    tenant = world["identity"].tenant_id
    _, second = two_spaces(admin_engine, world, offered=False)
    account = uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts "
                "(tenant_id, account_id, provider, active, space_id) "
                "VALUES (:t, :a, 'mock_crowdstrike', true, :s)"
            ),
            {"t": tenant, "a": account, "s": second},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings (tenant_id, operation_ref, account_id, "
                "provider, resource_type, action, provider_operation, mapping_version, "
                "schema_version, context_contract_version) VALUES (:t, 'isolate.corroborated', "
                ":a, 'mock_crowdstrike', 'endpoint', 'endpoint.isolate', 'contain', 'map-v1', "
                "'action.v1', 'endpoint-isolation.v2')"
            ),
            {"t": tenant, "a": account},
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        assert client.post(API + "/session/space", {"space_id": str(second)}).status_code == 200
        before = counts(admin_engine, tenant)
        refused = client.post(
            POLICY, {"source": "ruleset", "ruleset": json.dumps({"rules": [RULE]})}
        )
    assert (refused.status_code, refused.json()["code"]) == (400, "SIGNAL_MAPPING_ONLY")
    assert refused.json()["fields"] == ["ruleset.rules.0.action"]
    assert counts(admin_engine, tenant) == before


def test_two_mappings_that_cannot_share_a_bundle_are_named_at_the_action(
    db, runtime, admin_engine, world, monkeypatch
):
    """With the shipped catalog every pair of mappings that cannot share a bundle involves a
    signal contract, which is left out first, so the compiler's refusal at a mapping is held
    here by making the compiler refuse it, as `ruleset-compile` reports it (`mappings.<n>`)."""
    from execbound.policy.rulesets import RulesetError

    def conflicting(*_args, **_kwargs):
        raise RulesetError("cannot share a bundle", "mappings.0")

    monkeypatch.setattr(console_policy, "ruleset_bundle", conflicting)
    tenant = world["identity"].tenant_id
    file = json.dumps({"rules": [{**RULE, "id": "deny-dc", "effect": "DENY"}, RULE]})
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        before = counts(admin_engine, tenant)
        refused = client.post(POLICY, {"source": "ruleset", "ruleset": file})
    assert (refused.status_code, refused.json()["code"]) == (400, "MAPPINGS_CONFLICT")
    assert refused.json()["fields"] == ["ruleset.rules.0.action"]
    assert counts(admin_engine, tenant) == before


def padded(size: int) -> str:
    """A valid rules document of `size` UTF-8 bytes, padded with whitespace."""
    core = json.dumps({"rules": [RULE]})
    return core[:-1] + " " * (size - len(core.encode("utf-8"))) + "}"


def test_an_oversized_rules_file_is_refused(db, runtime, admin_engine, world):
    tenant = world["identity"].tenant_id
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        before = counts(admin_engine, tenant)
        over = client.post(POLICY, {"source": "ruleset", "ruleset": padded(513 * 1024)})
        assert (over.status_code, over.json()["code"]) == (400, "INVALID_BODY"), over.text
        assert over.json()["fields"] == ["ruleset"]
        # Under the character bound, over 512 KB in bytes: the parser's byte check refuses it.
        wide = json.dumps({"rules": [RULE]})[:-1] + ', "x": "' + "é" * 270_000 + '"}'
        assert len(wide) <= MAX_RULESET_FILE_BYTES < len(wide.encode("utf-8"))
        # Sent as a browser's JSON.stringify sends it: the characters themselves, not escapes.
        raw = json.dumps({"source": "ruleset", "ruleset": wide}, ensure_ascii=False)
        refused = client.post(POLICY, raw=raw.encode("utf-8"))
        assert (refused.status_code, refused.json()["code"]) == (400, "INVALID_BODY")
        assert refused.json()["fields"] == ["ruleset"]
        # A file within the limit whose escaped body is larger than a pasted bundle's cap
        # passes the size checks: newlines escape to two characters each.
        core = json.dumps({"rules": [RULE]})
        newlines = core[:-1] + "\n" * (511 * 1024 - len(core)) + "}"
        assert len(json.dumps({"source": "ruleset", "ruleset": newlines})) > (
            console_policy.DOCUMENT_BYTES
        )
        accepted = client.post(POLICY, {"source": "ruleset", "ruleset": newlines})
        assert accepted.status_code == 200, accepted.text[:300]
        # A body over the create route's own cap is refused before it is parsed.
        huge = client.post(
            POLICY, {"source": "ruleset", "ruleset": "\n" * (console_policy.CREATE_BYTES)}
        )
        assert (huge.status_code, huge.json()["code"]) == (413, "TOO_LARGE")
    bundles, _ = counts(admin_engine, tenant)
    assert bundles == before[0] + 1


@pytest.mark.parametrize(
    "body",
    [
        {"source": "ruleset"},
        {"source": "ruleset", "ruleset": json.dumps({"rules": [RULE]}), "bundle_id": str(uuid4())},
        {
            "source": "ruleset",
            "ruleset": json.dumps({"rules": [RULE]}),
            "template": "current-protections",
        },
        {"source": "document", "document": "{}", "ruleset": json.dumps({"rules": [RULE]})},
    ],
    ids=["missing", "beside-a-bundle", "beside-a-template", "on-another-source"],
)
def test_a_rules_file_is_refused_beside_a_bundle_or_template(
    db, runtime, admin_engine, world, body
):
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        refused = client.post(POLICY, body)
    assert (refused.status_code, refused.json()["code"]) == (400, "INVALID_BODY")


def test_a_policy_manager_imports_only_into_a_space_they_manage(db, runtime, admin_engine, world):
    tenant = world["identity"].tenant_id
    first, second = two_spaces(admin_engine, world)
    roles(
        db,
        world["admin"],
        world["human"],
        [{"role": "policy_manager", "space_id": first}, {"role": "viewer", "space_id": second}],
    )
    with console_client(db, runtime, admin_engine, current(db, world["human"])) as client:
        assert client.post(API + "/session/space", {"space_id": str(second)}).status_code == 200
        before = counts(admin_engine, tenant)
        refused = client.post(
            POLICY, {"source": "ruleset", "ruleset": json.dumps({"rules": [RULE]})}
        )
    assert (refused.status_code, refused.json()["code"]) == (403, "FORBIDDEN")
    assert counts(admin_engine, tenant) == before


def test_the_rules_file_bound_is_the_domains_512_kb():
    """The domain's one size limit is 512 KB, and the console's create bound is derived from it:
    one rules file escaped as a JSON string (at most twice its length) plus its envelope, never
    the rules editor's 128 KB."""
    assert MAX_RULESET_FILE_BYTES == 512 * 1024
    assert console_policy.CREATE_BYTES == 2 * MAX_RULESET_FILE_BYTES + 4096
