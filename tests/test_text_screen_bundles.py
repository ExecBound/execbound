# SPDX-License-Identifier: AGPL-3.0-only
"""Policy bundle content (T7.7): the whole content `_insert_draft` writes is screened
once, for `create_bundle` and `change_draft_rules` alike, because the replay export carries
every bundle an audit event references, drafts never validated included.

A rule's note, a rule id, a raw document's condition value, a limit selector's `equals`, a
Cedar comment and a budget's rule id each carry a person's text into stored bundle content;
each is refused with `INVALID_TEXT` naming the exact field path, dotted exactly as the rules
route's own body errors and the compiler's `RulesetError` already name one
(`ruleset.rules.0.note`, never `ruleset.rules[0].note`), and quoting nothing, exactly as
`tests/test_text_screen_names.py` and the other T7.7 tests proved for their own boundaries. The
location always names where the person actually wrote the value: a bundle written as rules is
screened against `ruleset` first, because the compiled components before it in the dump — the
Cedar texts, `limits` and `quorum` — are the compiler's own copies of what `ruleset` already
says, at a different path a person never typed into. A condition value only reaches
`_insert_draft` unchecked through `create_bundle`: a raw document is never compiled before it
is stored, where `change_draft_rules` compiles first and the compiler's own fact domains admit
no secret-shaped string, so that path is proved with a rule note instead, which the compiler
carries but never checks. A plain bundle, every starter pack, every rule and pack
`data/starters/` holds, and the reviewed response starter over every SOC action still create,
so the screen catches what a person wrote and nothing the product writes for itself.
"""

from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from console_api_fixtures import API, assert_no_secrets, console_client
from secret_shapes import LOWER_STRIPE, STRIPE
from test_admin_cli import cli_env as cli_env
from test_admin_cli import owner as owner
from test_admin_cli import refused as cli_refused
from test_admin_cli import run as cli_run
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime
from text_screen_helpers import (
    assert_nothing_found,
    assert_refused_unquoted,
    kind_count,
    over_free_text,
    row_count,
)

from execbound import administration as admin
from execbound.contracts import PRODUCTION_CATALOG
from execbound.operations import PRODUCTION_ACTIONS
from execbound.policy.models import Condition, LimitRule, LimitSelector, MappingRef, Rule, Ruleset
from execbound.policy.rulesets import ruleset_bundle
from execbound.policy.store import PolicyStoreError, change_draft_rules, create_bundle
from execbound.secrets import find_secrets
from execbound.surfaces.console_api.policy_starters import PACKS, RULES, first_policy
from execbound_harness.demo import ENDPOINT_RULESET, endpoint_bundle
from execbound_harness.fixtures import ENDPOINT_PROVIDER, IDENTITY_PROVIDER, combined_bundle
from execbound_harness.identity_demo import identity_bundle
from execbound_harness.soc_demo import soc_bundle

POLICY = API + "/policy"

BUNDLE_CREATED_KIND = "policy.bundle_created"
RULESET_COMPILED_KIND = "policy.ruleset_compiled"
RULES_CHANGED_KIND = "policy.rules_changed"
BUNDLE_RETIRED_KIND = "policy.bundle_retired"
CONTENTS_TABLE = "policy_bundle_contents"
LIFECYCLE_TABLE = "policy_bundle_lifecycle"

ALLOW_WORKSTATION = {
    "id": "allow-workstation",
    "action": "endpoint.isolate",
    "effect": "ALLOW",
    "when": [{"kind": "fact", "name": "role", "operator": "is", "values": ["workstation"]}],
    "quorum": None,
    "note": None,
}


def _ruleset(**rule_changes) -> Ruleset:
    """One ALLOW rule over `endpoint.isolate`, with whatever the caller overrides."""
    fields = {
        "id": "allow-workstation",
        "action": "endpoint.isolate",
        "effect": "ALLOW",
        "when": (Condition(kind="fact", name="role", operator="is", values=("workstation",)),),
    }
    return Ruleset(rules=(Rule(**{**fields, **rule_changes}),))


def _rules_body(*, note=None, budgets=()) -> dict:
    """The rules route's own request shape: `tests/test_console_api_rules.py`'s `ALLOW` rule,
    with its `note` and `budgets` overridden."""
    return {"rules": [{**ALLOW_WORKSTATION, "note": note}], "budgets": list(budgets)}


def _counts(admin_engine, tenant) -> dict:
    """Every count a test below relies on, read together so a before/after comparison names
    exactly what changed."""
    return {
        "contents": row_count(admin_engine, tenant, CONTENTS_TABLE),
        "lifecycle": row_count(admin_engine, tenant, LIFECYCLE_TABLE),
        "created": kind_count(admin_engine, tenant, BUNDLE_CREATED_KIND),
        "compiled": kind_count(admin_engine, tenant, RULESET_COMPILED_KIND),
        "changed": kind_count(admin_engine, tenant, RULES_CHANGED_KIND),
        "retired": kind_count(admin_engine, tenant, BUNDLE_RETIRED_KIND),
    }


def _draft_with_ruleset(db, world) -> UUID:
    """A DRAFT written as rules for this tenant, which `change_draft_rules` edits."""
    content = ruleset_bundle(
        ENDPOINT_RULESET,
        tenant_id=world["identity"].tenant_id,
        bundle_id=uuid4(),
        mappings=world["bundle"].mappings,
    )
    create_bundle(db, world["admin"], content, world["clock"])
    return content.bundle_id


def _cli_credential(owner, world, tmp_path, name: str):
    """An ADMIN credential file for `world["admin"]`, the way `test_admin_cli.py` issues one
    for a CLI command to use with `--credential-file`."""
    credential_file = tmp_path / name
    admin.issue_credential(
        owner,
        world["identity"].tenant_id,
        world["admin"].principal_id,
        world["admin"].principal_id,
        lifetime=timedelta(hours=1),
        output=credential_file,
    )
    return credential_file


# -- `create_bundle`: a raw document is never compiled before it is stored -------------------


@over_free_text("value")
def test_a_rule_note_shaped_like_a_secret_is_refused_through_create_bundle(
    db, world, admin_engine, value
):
    tenant = world["identity"].tenant_id
    content = world["bundle"].model_copy(
        update={"bundle_id": uuid4(), "ruleset": _ruleset(note=value)}
    )
    before = _counts(admin_engine, tenant)
    with pytest.raises(PolicyStoreError) as refused:
        create_bundle(db, world["admin"], content, world["clock"])
    assert_refused_unquoted(refused, "INVALID_TEXT", value)
    assert refused.value.location == "ruleset.rules.0.note"
    assert_nothing_found(admin_engine, tenant)
    assert _counts(admin_engine, tenant) == before


def test_a_rule_id_shaped_like_a_secret_is_refused_through_create_bundle(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    content = world["bundle"].model_copy(
        update={"bundle_id": uuid4(), "ruleset": _ruleset(id=LOWER_STRIPE)}
    )
    before = _counts(admin_engine, tenant)
    with pytest.raises(PolicyStoreError) as refused:
        create_bundle(db, world["admin"], content, world["clock"])
    assert_refused_unquoted(refused, "INVALID_TEXT", LOWER_STRIPE)
    assert refused.value.location == "ruleset.rules.0.id"
    assert_nothing_found(admin_engine, tenant)
    assert _counts(admin_engine, tenant) == before


@over_free_text("value")
def test_a_condition_value_shaped_like_a_secret_is_refused_through_create_bundle(
    db, world, admin_engine, value
):
    """`create_bundle` never compiles a draft's rules, so a raw document can carry any string
    in a condition's declared domain; `change_draft_rules` compiles first and refuses the same
    sample before it ever reaches this screen (proved with a rule note instead, below)."""
    tenant = world["identity"].tenant_id
    condition = Condition(kind="fact", name="role", operator="is", values=(value,))
    content = world["bundle"].model_copy(
        update={"bundle_id": uuid4(), "ruleset": _ruleset(when=(condition,))}
    )
    before = _counts(admin_engine, tenant)
    with pytest.raises(PolicyStoreError) as refused:
        create_bundle(db, world["admin"], content, world["clock"])
    assert_refused_unquoted(refused, "INVALID_TEXT", value)
    assert refused.value.location == "ruleset.rules.0.when.0.values.0"
    assert_nothing_found(admin_engine, tenant)
    assert _counts(admin_engine, tenant) == before


@over_free_text("value")
def test_a_limit_selectors_equals_shaped_like_a_secret_is_refused_through_create_bundle(
    db, world, admin_engine, value
):
    tenant = world["identity"].tenant_id
    selector_limit = LimitRule(
        rule_id="selector-limit",
        action="endpoint.isolate",
        scope="selector",
        window_seconds=3600,
        max_targets=5,
        budget="autonomous",
        on_exceed="DENY",
        selector=LimitSelector(fact="role", equals=value),
    )
    content = world["bundle"].model_copy(update={"bundle_id": uuid4(), "limits": (selector_limit,)})
    before = _counts(admin_engine, tenant)
    with pytest.raises(PolicyStoreError) as refused:
        create_bundle(db, world["admin"], content, world["clock"])
    assert_refused_unquoted(refused, "INVALID_TEXT", value)
    assert refused.value.location == "limits.0.selector.equals"
    assert_nothing_found(admin_engine, tenant)
    assert _counts(admin_engine, tenant) == before


@over_free_text("value")
def test_a_cedar_comment_shaped_like_a_secret_is_refused_through_create_bundle(
    db, world, admin_engine, value
):
    tenant = world["identity"].tenant_id
    content = world["bundle"].model_copy(
        update={
            "bundle_id": uuid4(),
            "authorization_policies": f"// {value}\npermit(principal, action, resource);",
        }
    )
    before = _counts(admin_engine, tenant)
    with pytest.raises(PolicyStoreError) as refused:
        create_bundle(db, world["admin"], content, world["clock"])
    assert_refused_unquoted(refused, "INVALID_TEXT", value)
    assert refused.value.location == "authorization_policies"
    assert_nothing_found(admin_engine, tenant)
    assert _counts(admin_engine, tenant) == before


def test_a_plain_bundle_written_as_rules_is_still_created_through_create_bundle(
    db, world, admin_engine
):
    tenant = world["identity"].tenant_id
    content = world["bundle"].model_copy(update={"bundle_id": uuid4(), "ruleset": _ruleset()})
    before = _counts(admin_engine, tenant)
    record = create_bundle(db, world["admin"], content, world["clock"])
    assert record.state == "DRAFT"
    after = _counts(admin_engine, tenant)
    assert after["contents"] == before["contents"] + 1
    assert after["lifecycle"] == before["lifecycle"] + 1
    assert after["created"] == before["created"] + 1
    assert after["compiled"] == before["compiled"] + 1


def test_a_plain_document_bundle_is_still_created_through_create_bundle(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    content = world["bundle"].model_copy(update={"bundle_id": uuid4()})
    before = _counts(admin_engine, tenant)
    record = create_bundle(db, world["admin"], content, world["clock"])
    assert record.state == "DRAFT"
    after = _counts(admin_engine, tenant)
    assert after["contents"] == before["contents"] + 1
    assert after["lifecycle"] == before["lifecycle"] + 1
    assert after["created"] == before["created"] + 1
    assert after["compiled"] == before["compiled"]  # a document bundle carries no ruleset


# -- `change_draft_rules`: the compiler runs first, so only a note reaches this screen -------


@over_free_text("value")
def test_a_rule_note_shaped_like_a_secret_is_refused_through_change_draft_rules(
    db, world, admin_engine, value
):
    tenant = world["identity"].tenant_id
    bundle_id = _draft_with_ruleset(db, world)
    before = _counts(admin_engine, tenant)
    with pytest.raises(PolicyStoreError) as refused:
        change_draft_rules(db, world["admin"], bundle_id, _ruleset(note=value), world["clock"])
    assert_refused_unquoted(refused, "INVALID_TEXT", value)
    assert refused.value.location == "ruleset.rules.0.note"
    assert_nothing_found(admin_engine, tenant)
    assert _counts(admin_engine, tenant) == before


def test_a_budget_rule_id_shaped_like_a_secret_names_where_it_was_written(db, world, admin_engine):
    """A budget's compiled copy lives in `content.limits`, at the same index a person's own
    `ruleset.budgets` holds it under default sorting; without the ruleset-first screen this
    would be reported at `limits.0.rule_id`, a path the person never typed into. The location
    must instead name `ruleset.budgets.0.rule_id`, where the rules route's body put it."""
    tenant = world["identity"].tenant_id
    bundle_id = _draft_with_ruleset(db, world)
    budget = LimitRule(
        rule_id=LOWER_STRIPE,
        action="endpoint.isolate",
        scope="principal",
        window_seconds=3600,
        max_targets=3,
        budget="autonomous",
        on_exceed="REQUIRE_APPROVAL",
    )
    ruleset = _ruleset().model_copy(update={"budgets": (budget,)})
    before = _counts(admin_engine, tenant)
    with pytest.raises(PolicyStoreError) as refused:
        change_draft_rules(db, world["admin"], bundle_id, ruleset, world["clock"])
    assert_refused_unquoted(refused, "INVALID_TEXT", LOWER_STRIPE)
    assert refused.value.location == "ruleset.budgets.0.rule_id"
    assert_nothing_found(admin_engine, tenant)
    assert _counts(admin_engine, tenant) == before


def test_a_plain_change_draft_rules_is_still_accepted(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    bundle_id = _draft_with_ruleset(db, world)
    before = _counts(admin_engine, tenant)
    record = change_draft_rules(db, world["admin"], bundle_id, _ruleset(), world["clock"])
    assert record.state == "DRAFT"
    after = _counts(admin_engine, tenant)
    assert after["contents"] == before["contents"] + 1
    assert after["lifecycle"] == before["lifecycle"] + 1
    assert after["created"] == before["created"] + 1
    assert after["compiled"] == before["compiled"] + 1
    assert after["changed"] == before["changed"] + 1
    assert after["retired"] == before["retired"] + 1


# -- Product content: every starter pack, every starter rule and pack, and the reviewed ------
# -- response starter over every SOC action still create -------------------------------------


@pytest.mark.parametrize("kind", ["endpoint", "identity", "soc", "combined"])
def test_every_starter_pack_still_creates_as_a_draft(db, world, admin_engine, kind):
    tenant = world["identity"].tenant_id
    endpoint_account, identity_account = uuid4(), uuid4()
    builders = {
        "endpoint": lambda: endpoint_bundle(tenant, endpoint_account, mapping_version="map-v1"),
        "identity": lambda: identity_bundle(tenant, identity_account, mapping_version="map-v1"),
        "soc": lambda: soc_bundle(
            tenant, endpoint_account, identity_account, mapping_version="map-v1"
        ),
        "combined": lambda: combined_bundle(
            "starter",
            tenant,
            {
                ENDPOINT_PROVIDER: str(endpoint_account),
                IDENTITY_PROVIDER: str(identity_account),
            },
        ),
    }
    content = builders[kind]().model_copy(update={"bundle_id": uuid4()})
    before = kind_count(admin_engine, tenant, BUNDLE_CREATED_KIND)
    record = create_bundle(db, world["admin"], content, world["clock"])
    assert record.state == "DRAFT"
    assert kind_count(admin_engine, tenant, BUNDLE_CREATED_KIND) == before + 1


def test_every_starter_rule_and_pack_is_free_of_secret_shaped_text():
    """`data/starters/rules.json` and `packs.json` are the product's own reviewed content,
    independent of which actions any one tenant has mapped; `find_secrets` must find nothing
    anywhere in either file, not only in the rules one pack happens to use."""
    assert find_secrets(RULES) == []
    assert find_secrets(PACKS) == []


def test_the_reviewed_response_starter_still_creates_as_a_draft_over_every_soc_action(
    db, world, admin_engine
):
    """`first_policy` is what the console's "security-response" template builds from
    `data/starters/rules.json`, narrowed to whichever actions a tenant has mapped; mapping
    every SOC action exercises every rule the pack can produce, not only `endpoint.isolate`."""
    tenant = world["identity"].tenant_id
    mappings = tuple(
        MappingRef(
            operation_ref=action,
            account_id=uuid4(),
            mapping_version="map-v1",
            schema_version="action.v1",
            context_contract_version=PRODUCTION_ACTIONS.action(action).context_contract_version,
        )
        for action in PACKS["soc"]["actions"]
    )
    content = first_policy(tenant, mappings, PRODUCTION_CATALOG).model_copy(
        update={"bundle_id": uuid4()}
    )
    before = kind_count(admin_engine, tenant, BUNDLE_CREATED_KIND)
    record = create_bundle(db, world["admin"], content, world["clock"])
    assert record.state == "DRAFT"
    assert kind_count(admin_engine, tenant, BUNDLE_CREATED_KIND) == before + 1


# -- One HTTP-level test per entry point, and one through the CLI ---------------------------


def test_the_console_create_draft_route_refuses_a_secret_shaped_bundle_as_a_bad_value(
    db, runtime, admin_engine, world
):
    tenant = world["identity"].tenant_id
    document = (
        world["bundle"]
        .model_copy(update={"bundle_id": uuid4(), "ruleset": _ruleset(note=STRIPE)})
        .model_dump_json()
    )
    before = kind_count(admin_engine, tenant, BUNDLE_CREATED_KIND)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        response = client.post(POLICY, {"source": "document", "document": document})
    assert response.status_code == 400, response.text
    body = response.json()
    assert body["code"] == "INVALID_BODY"
    assert body["fields"] == ["ruleset.rules.0.note"]
    assert STRIPE not in response.text
    assert_no_secrets(response)
    assert kind_count(admin_engine, tenant, BUNDLE_CREATED_KIND) == before


def test_the_console_rules_route_refuses_a_secret_shaped_note_as_a_bad_value(
    db, runtime, admin_engine, world
):
    tenant = world["identity"].tenant_id
    bundle_id = _draft_with_ruleset(db, world)
    before = kind_count(admin_engine, tenant, RULES_CHANGED_KIND)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        response = client.post(f"{POLICY}/{bundle_id}/rules", _rules_body(note=STRIPE))
        assert response.status_code == 400, response.text
        answer = response.json()
        assert answer["code"] == "INVALID_BODY"
        assert answer["fields"] == ["ruleset.rules.0.note"]
        assert STRIPE not in response.text
        assert_no_secrets(response)
        # Nothing moved: the draft that was being edited is still a draft.
        assert client.get(f"{POLICY}/{bundle_id}/rules").json()["editable"] is True
    assert kind_count(admin_engine, tenant, RULES_CHANGED_KIND) == before


def test_the_console_rules_route_refuses_a_secret_shaped_budget_rule_id_at_its_own_location(
    db, runtime, admin_engine, world
):
    """The same confusion the store-level test proves, reached through the HTTP body: a
    budget's compiled copy sits in the bundle's `limits`, but the location reported must name
    where the body actually carried it, under `ruleset.budgets`."""
    tenant = world["identity"].tenant_id
    bundle_id = _draft_with_ruleset(db, world)
    budgets = [
        {
            "rule_id": LOWER_STRIPE,
            "action": "endpoint.isolate",
            "scope": "principal",
            "window_seconds": 3600,
            "max_targets": 3,
            "budget": "autonomous",
            "on_exceed": "REQUIRE_APPROVAL",
        }
    ]
    before = kind_count(admin_engine, tenant, RULES_CHANGED_KIND)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        response = client.post(f"{POLICY}/{bundle_id}/rules", _rules_body(budgets=budgets))
        assert response.status_code == 400, response.text
        answer = response.json()
        assert answer["code"] == "INVALID_BODY"
        assert answer["fields"] == ["ruleset.budgets.0.rule_id"]
        assert LOWER_STRIPE not in response.text
        assert_no_secrets(response)
    assert kind_count(admin_engine, tenant, RULES_CHANGED_KIND) == before


def test_the_cli_bundle_create_refuses_a_secret_shaped_note_and_names_the_location(
    owner, cli_env, world, admin_engine, monkeypatch, capsys, tmp_path
):
    tenant = world["identity"].tenant_id
    credential_file = _cli_credential(owner, world, tmp_path, "admin.token")
    content = world["bundle"].model_copy(
        update={"bundle_id": uuid4(), "ruleset": _ruleset(note=STRIPE)}
    )
    bundle_file = tmp_path / "bundle.json"
    bundle_file.write_text(content.model_dump_json(), encoding="utf-8")
    before = kind_count(admin_engine, tenant, BUNDLE_CREATED_KIND)
    result = cli_refused(
        monkeypatch,
        capsys,
        "bundle-create",
        "--tenant",
        str(tenant),
        "--credential-file",
        str(credential_file),
        "--input",
        str(bundle_file),
    )
    assert "INVALID_TEXT" in result.err
    assert "ruleset.rules.0.note" in result.err
    assert STRIPE not in result.err
    assert kind_count(admin_engine, tenant, BUNDLE_CREATED_KIND) == before


def test_the_cli_bundle_create_still_accepts_a_plain_bundle(
    owner, cli_env, world, admin_engine, monkeypatch, capsys, tmp_path
):
    tenant = world["identity"].tenant_id
    credential_file = _cli_credential(owner, world, tmp_path, "admin-2.token")
    content = world["bundle"].model_copy(update={"bundle_id": uuid4(), "ruleset": _ruleset()})
    bundle_file = tmp_path / "bundle-2.json"
    bundle_file.write_text(content.model_dump_json(), encoding="utf-8")
    before = kind_count(admin_engine, tenant, BUNDLE_CREATED_KIND)
    created = cli_run(
        monkeypatch,
        capsys,
        "bundle-create",
        "--tenant",
        str(tenant),
        "--credential-file",
        str(credential_file),
        "--input",
        str(bundle_file),
    )
    assert created["state"] == "DRAFT"
    assert kind_count(admin_engine, tenant, BUNDLE_CREATED_KIND) == before + 1
