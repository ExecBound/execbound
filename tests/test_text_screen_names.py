# SPDX-License-Identifier: AGPL-3.0-only
"""Names and labels a person writes (T7.7): principal labels, group names and
descriptions, space names and personal access token names, each refused with the boundary's
own existing code, quoting the value nowhere and leaving no trace of the write it would have
made, exactly as `tests/test_text_screen_reasons.py` proved for reasons.

`agents_pages.govern`'s label is the identity provider's own display name, not text a person
typed, so it is deliberately left unscreened: `create_agent`'s `screened_label` never runs
for it. It is withheld instead, at `govern` itself, where a credential-shaped display name
becomes the fallback label `Unnamed agent` rather than being refused; the two tests below
prove that (one shaped, one plain), leaving the stored `monitor_agents` row and the audit
chain exactly as T7.7 in `docs/THREAT_MODEL.md` describes.
"""

from datetime import timedelta

import pytest
from console_api_fixtures import API, assert_no_secrets, console_client
from monitoring_fixtures import collect
from secret_shapes import STRIPE
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime
from test_scout_run import agent, detailed_scenario
from test_text_screen_reasons import admin_session as admin_session
from test_text_screen_reasons import approval_rule as approval_rule
from text_screen_helpers import (
    APPROVAL_RULE_KIND,
    assert_nothing_found,
    assert_refused_unquoted,
    kind_count,
    over_free_text,
    row_count,
)

from execbound import access_control as access
from execbound import administration, approval_rules
from execbound.administration import AdministrationError
from execbound.personal_tokens import TokenError, issue_token
from execbound.spaces import SpaceError, create_space, rename_space
from execbound.surfaces import admin_pages, agents_pages, people_pages

PEOPLE = API + "/people"
AGENTS = API + "/agents"


def _label_of(engine, tenant, principal):
    with engine.begin() as conn:
        return conn.execute(
            text(
                "SELECT label FROM execbound.principals WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"t": tenant, "p": principal},
        ).scalar_one()


def _group_row(engine, tenant, group_id):
    with engine.begin() as conn:
        return dict(
            conn.execute(
                text(
                    "SELECT name, description FROM execbound.access_groups "
                    "WHERE tenant_id = :t AND group_id = :g"
                ),
                {"t": tenant, "g": group_id},
            )
            .mappings()
            .one()
        )


def _space_name(engine, tenant, space_id):
    with engine.begin() as conn:
        return conn.execute(
            text("SELECT name FROM execbound.spaces WHERE tenant_id = :t AND space_id = :s"),
            {"t": tenant, "s": space_id},
        ).scalar_one()


def _rule_name(engine, tenant, rule_id):
    with engine.begin() as conn:
        return conn.execute(
            text("SELECT name FROM execbound.approval_rules WHERE tenant_id=:t AND rule_id=:r"),
            {"t": tenant, "r": rule_id},
        ).scalar_one()


def _rule_save_body(engine, tenant, rule_id):
    """The `space_id`, `group_id`, `actions` and `targets` a real `save` sends alongside a
    rename: read back from the fixture rule's own stored row, exactly as the console route
    and `tests/test_approval_group_rules.py`'s `rule()` build one, so a rename exercised here
    is the body shape `change_rule` is actually called with, not a `disable` body with a
    `name` key bolted on (which a real caller never sends)."""
    with engine.begin() as conn:
        row = dict(
            conn.execute(
                text(
                    "SELECT space_id, group_id FROM execbound.approval_rules "
                    "WHERE tenant_id = :t AND rule_id = :r"
                ),
                {"t": tenant, "r": rule_id},
            )
            .mappings()
            .one()
        )
        actions = (
            conn.execute(
                text(
                    "SELECT action FROM execbound.approval_rule_actions "
                    "WHERE tenant_id = :t AND rule_id = :r ORDER BY action"
                ),
                {"t": tenant, "r": rule_id},
            )
            .scalars()
            .all()
        )
        targets = (
            conn.execute(
                text(
                    "SELECT canonical_target_id FROM execbound.approval_rule_targets "
                    "WHERE tenant_id = :t AND rule_id = :r ORDER BY canonical_target_id"
                ),
                {"t": tenant, "r": rule_id},
            )
            .scalars()
            .all()
        )
    return {
        "space_id": str(row["space_id"]),
        "group_id": str(row["group_id"]),
        "actions": list(actions),
        "targets": [str(target) for target in targets],
        "operation": "save",
    }


# -- Principal labels: `administration.screened_label`, shared by every typed-label writer --

LABEL_KIND = "principal.labelled"


@over_free_text("label")
def test_a_new_approvers_label_shaped_like_a_secret_is_refused_unquoted(
    runtime, world, admin_engine, admin_session, label
):
    tenant = world["identity"].tenant_id
    before_count = row_count(admin_engine, tenant, "principals")
    before_kind = kind_count(admin_engine, tenant, LABEL_KIND)
    with pytest.raises(AdministrationError) as refused:
        people_pages.create_approver(runtime, admin_session, label)
    assert_refused_unquoted(refused, "INVALID_LABEL", label)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, LABEL_KIND) == before_kind
    assert row_count(admin_engine, tenant, "principals") == before_count


def test_a_plain_new_approvers_label_is_still_accepted(runtime, world, admin_engine, admin_session):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, LABEL_KIND)
    before_count = row_count(admin_engine, tenant, "principals")
    people_pages.create_approver(runtime, admin_session, "Dana Reyes")
    assert kind_count(admin_engine, tenant, LABEL_KIND) == before + 1
    assert row_count(admin_engine, tenant, "principals") == before_count + 1


@over_free_text("label")
def test_a_relabel_shaped_like_a_secret_is_refused_unquoted(
    runtime, world, admin_engine, admin_session, label
):
    tenant = world["identity"].tenant_id
    principal = world["human"].principal_id
    before_label = _label_of(admin_engine, tenant, principal)
    before_kind = kind_count(admin_engine, tenant, LABEL_KIND)
    with pytest.raises(AdministrationError) as refused:
        people_pages.label_person(runtime, admin_session, principal, label)
    assert_refused_unquoted(refused, "INVALID_LABEL", label)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, LABEL_KIND) == before_kind
    assert _label_of(admin_engine, tenant, principal) == before_label


def test_a_plain_relabel_is_still_accepted(runtime, world, admin_engine, admin_session):
    tenant = world["identity"].tenant_id
    principal = world["human"].principal_id
    before = kind_count(admin_engine, tenant, LABEL_KIND)
    before_count = row_count(admin_engine, tenant, "principals")
    people_pages.label_person(runtime, admin_session, principal, "Dana")
    assert kind_count(admin_engine, tenant, LABEL_KIND) == before + 1
    assert row_count(admin_engine, tenant, "principals") == before_count
    assert _label_of(admin_engine, tenant, principal) == "Dana"


@over_free_text("label")
def test_a_new_agent_credentials_label_shaped_like_a_secret_is_refused_unquoted(
    runtime, world, admin_engine, admin_session, label
):
    tenant = world["identity"].tenant_id
    before_count = row_count(admin_engine, tenant, "principals")
    before_kind = kind_count(admin_engine, tenant, LABEL_KIND)
    with pytest.raises(AdministrationError) as refused:
        admin_pages.issue(
            runtime,
            admin_session,
            principal=None,
            kind="AGENT",
            lifetime=timedelta(hours=1),
            label=label,
        )
    assert_refused_unquoted(refused, "INVALID_LABEL", label)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, LABEL_KIND) == before_kind
    assert row_count(admin_engine, tenant, "principals") == before_count


def test_a_plain_new_agent_credentials_label_is_still_accepted(
    runtime, world, admin_engine, admin_session
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, LABEL_KIND)
    before_count = row_count(admin_engine, tenant, "principals")
    admin_pages.issue(
        runtime,
        admin_session,
        principal=None,
        kind="AGENT",
        lifetime=timedelta(hours=1),
        label="Coding agent on my laptop",
    )
    assert kind_count(admin_engine, tenant, LABEL_KIND) == before + 1
    assert row_count(admin_engine, tenant, "principals") == before_count + 1


@over_free_text("label")
def test_a_new_governed_agents_label_shaped_like_a_secret_is_refused_unquoted(
    runtime, world, admin_engine, admin_session, label
):
    tenant = world["identity"].tenant_id
    before_count = row_count(admin_engine, tenant, "principals")
    before_kind = kind_count(admin_engine, tenant, LABEL_KIND)
    with pytest.raises(AdministrationError) as refused:
        agents_pages.create_agent(runtime, admin_session, label)
    assert_refused_unquoted(refused, "INVALID_LABEL", label)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, LABEL_KIND) == before_kind
    assert row_count(admin_engine, tenant, "principals") == before_count


def test_a_plain_new_governed_agents_label_is_still_accepted(
    runtime, world, admin_engine, admin_session
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, LABEL_KIND)
    before_count = row_count(admin_engine, tenant, "principals")
    agents_pages.create_agent(runtime, admin_session, "Triage bot")
    assert kind_count(admin_engine, tenant, LABEL_KIND) == before + 1
    assert row_count(admin_engine, tenant, "principals") == before_count + 1


@over_free_text("label")
def test_an_invited_persons_label_shaped_like_a_secret_is_refused_unquoted(
    world, admin_engine, runtime, tmp_path, label
):
    tenant = world["identity"].tenant_id
    before_kind = kind_count(admin_engine, tenant, LABEL_KIND)
    before_count = row_count(admin_engine, tenant, "principals")
    output = tmp_path / "code.txt"
    with pytest.raises(AdministrationError) as refused:
        administration.invite_person(
            admin_engine,
            tenant,
            "new-admin@example.com",
            "ADMIN",
            label=label,
            actor=world["admin"].principal_id,
            origin="https://example.test",
            output=output,
            now=runtime.clock.now(),
        )
    assert_refused_unquoted(refused, "INVALID_LABEL", label)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, LABEL_KIND) == before_kind
    assert row_count(admin_engine, tenant, "principals") == before_count
    assert not output.exists()


def test_a_plain_invited_persons_label_is_still_accepted(world, admin_engine, runtime, tmp_path):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, LABEL_KIND)
    before_count = row_count(admin_engine, tenant, "principals")
    administration.invite_person(
        admin_engine,
        tenant,
        "new-admin-2@example.com",
        "ADMIN",
        label="Nameless no more",
        actor=world["admin"].principal_id,
        origin="https://example.test",
        output=tmp_path / "code.txt",
        now=runtime.clock.now(),
    )
    assert kind_count(admin_engine, tenant, LABEL_KIND) == before + 1
    assert row_count(admin_engine, tenant, "principals") == before_count + 1


@pytest.fixture
def discovered_agent(db, world):
    """Factory for one discovered agent with a given Entra display name, exactly as
    `tests/test_agents_bindings.py`'s `found` builds one with a long name. One fixture
    serves both the shaped and the plain display-name tests below."""

    def make(display_name):
        scenario = detailed_scenario(agents=[agent(1, displayName=display_name)])
        collect(db, world["admin"], world["clock"], scenario=scenario)
        with db.transaction(world["identity"].tenant_id) as conn:
            return conn.execute(
                text("SELECT agent_id FROM execbound.monitor_agents ORDER BY platform_ref")
            ).scalar_one()

    return make


def _display_name_of(engine, tenant, agent):
    with engine.begin() as conn:
        return conn.execute(
            text(
                "SELECT display_name FROM execbound.monitor_agents "
                "WHERE tenant_id = :t AND agent_id = :a"
            ),
            {"t": tenant, "a": agent},
        ).scalar_one()


def _labelled_payload(engine, tenant, principal):
    with engine.begin() as conn:
        return conn.execute(
            text(
                "SELECT payload FROM execbound.audit_events WHERE tenant_id = :t "
                "AND kind = :k AND payload ->> 'principal_id' = :p "
                "ORDER BY sequence DESC LIMIT 1"
            ),
            {"t": tenant, "k": LABEL_KIND, "p": str(principal)},
        ).scalar_one()


def test_govern_is_not_refused_for_a_secret_shaped_display_name(
    db, runtime, admin_engine, world, discovered_agent
):
    """`govern`'s label is the identity provider's display name, which is withheld rather
    than refused: a credential-shaped name cannot be refused without stopping the
    agent being governed at all, so it becomes the fallback label `Unnamed agent` instead,
    both on the stored principal and in the `principal.labelled` event. The discovered
    agent's own `display_name` is untouched, and the value itself never reaches the chain.
    """
    tenant = world["identity"].tenant_id
    shaped = discovered_agent(STRIPE)
    before = kind_count(admin_engine, tenant, LABEL_KIND)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        governed = client.post(f"{AGENTS}/{shaped}/govern", {"lifetime": "8"})
        assert governed.status_code == 200, governed.text
    assert kind_count(admin_engine, tenant, LABEL_KIND) == before + 1
    principal = governed.json()["principal_id"]
    assert _label_of(admin_engine, tenant, principal) == "Unnamed agent"
    assert _labelled_payload(admin_engine, tenant, principal)["label"] == "Unnamed agent"
    assert _display_name_of(admin_engine, tenant, shaped) == STRIPE
    assert_nothing_found(admin_engine, tenant)


def test_govern_still_labels_with_a_plain_display_name(
    db, runtime, admin_engine, world, discovered_agent
):
    """The ordinary case `test_govern_is_not_refused_for_a_secret_shaped_display_name` is the
    exception to: a plain display name becomes the label exactly as it does today."""
    tenant = world["identity"].tenant_id
    plain = discovered_agent("Build Pipeline Bot")
    before = kind_count(admin_engine, tenant, LABEL_KIND)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        governed = client.post(f"{AGENTS}/{plain}/govern", {"lifetime": "8"})
        assert governed.status_code == 200, governed.text
    assert kind_count(admin_engine, tenant, LABEL_KIND) == before + 1
    principal = governed.json()["principal_id"]
    assert _label_of(admin_engine, tenant, principal) == "Build Pipeline Bot"
    assert _labelled_payload(admin_engine, tenant, principal)["label"] == "Build Pipeline Bot"
    assert _display_name_of(admin_engine, tenant, plain) == "Build Pipeline Bot"


# -- Group names and descriptions: the owner's `create_group` and the console's `_change` ---

GROUP_KIND = "group.created"
ACCESS_GROUP_CREATE_KIND = "access.create_group"
ACCESS_GROUP_UPDATE_KIND = "access.update_group"


@over_free_text("name")
def test_an_owner_provisioned_group_name_shaped_like_a_secret_is_refused_unquoted(
    world, admin_engine, name
):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    before = kind_count(admin_engine, tenant, GROUP_KIND)
    before_rows = row_count(admin_engine, tenant, "principal_groups")
    with pytest.raises(AdministrationError) as refused:
        administration.create_group(admin_engine, tenant, name, actor)
    assert_refused_unquoted(refused, "INVALID_NAME", name)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, GROUP_KIND) == before
    assert row_count(admin_engine, tenant, "principal_groups") == before_rows


def test_a_plain_owner_provisioned_group_name_is_still_accepted(world, admin_engine):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    before = kind_count(admin_engine, tenant, GROUP_KIND)
    before_rows = row_count(admin_engine, tenant, "principal_groups")
    administration.create_group(admin_engine, tenant, "Responders", actor)
    assert kind_count(admin_engine, tenant, GROUP_KIND) == before + 1
    assert row_count(admin_engine, tenant, "principal_groups") == before_rows + 1


@over_free_text("name")
def test_an_access_group_name_shaped_like_a_secret_is_refused_unquoted(
    runtime, world, admin_engine, admin_session, name
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, ACCESS_GROUP_CREATE_KIND)
    before_rows = row_count(admin_engine, tenant, "access_groups")
    with pytest.raises(access.AccessError) as refused:
        access.create_group(runtime, admin_session, name, "On call", "Set up a group")
    assert_refused_unquoted(refused, "INVALID_NAME", name)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, ACCESS_GROUP_CREATE_KIND) == before
    assert row_count(admin_engine, tenant, "access_groups") == before_rows


@over_free_text("description")
def test_an_access_group_description_shaped_like_a_secret_is_refused_unquoted(
    runtime, world, admin_engine, admin_session, description
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, ACCESS_GROUP_CREATE_KIND)
    before_rows = row_count(admin_engine, tenant, "access_groups")
    with pytest.raises(access.AccessError) as refused:
        access.create_group(runtime, admin_session, "Responders", description, "Set up a group")
    assert_refused_unquoted(refused, "INVALID_NAME", description)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, ACCESS_GROUP_CREATE_KIND) == before
    assert row_count(admin_engine, tenant, "access_groups") == before_rows


def test_a_plain_access_group_name_and_description_are_still_accepted(
    runtime, world, admin_engine, admin_session
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, ACCESS_GROUP_CREATE_KIND)
    before_rows = row_count(admin_engine, tenant, "access_groups")
    group_id = access.create_group(runtime, admin_session, "Responders", "On call", "Set up")
    assert kind_count(admin_engine, tenant, ACCESS_GROUP_CREATE_KIND) == before + 1
    assert row_count(admin_engine, tenant, "access_groups") == before_rows + 1
    assert _group_row(admin_engine, tenant, group_id) == {
        "name": "Responders",
        "description": "On call",
    }


def test_a_secret_shaped_access_group_name_is_refused_as_invalid_body_naming_both_fields_over_http(
    db, runtime, admin_engine, world
):
    """`_change` screens name and description together (`secret_shaped(name, description)`)
    and `AccessError` raises the same `INVALID_NAME` whichever one was shaped like a secret,
    so `console_api/access.py`'s `REFUSALS` names both; a person checks the one they meant
    to change."""
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, ACCESS_GROUP_CREATE_KIND)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        refused = client.post(
            API + "/access/groups",
            {"name": STRIPE, "description": "On call", "reason": "Set up a group"},
        )
    assert refused.status_code == 400, refused.text
    body = refused.json()
    assert body["code"] == "INVALID_BODY" and body["fields"] == ["name", "description"]
    assert_no_secrets(refused)
    assert kind_count(admin_engine, tenant, ACCESS_GROUP_CREATE_KIND) == before


@pytest.fixture
def access_group(runtime, admin_session):
    """One access-control group, ready to be renamed."""
    return access.create_group(runtime, admin_session, "Responders", "On call", "Set up")


@over_free_text("name")
def test_an_access_group_rename_shaped_like_a_secret_is_refused_unquoted(
    runtime, world, admin_engine, admin_session, access_group, name
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, ACCESS_GROUP_UPDATE_KIND)
    with pytest.raises(access.AccessError) as refused:
        access.update_group(runtime, admin_session, access_group, name, "On call", "Rename")
    assert_refused_unquoted(refused, "INVALID_NAME", name)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, ACCESS_GROUP_UPDATE_KIND) == before
    assert _group_row(admin_engine, tenant, access_group)["name"] == "Responders"


def test_a_plain_access_group_rename_is_still_accepted(
    runtime, world, admin_engine, admin_session, access_group
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, ACCESS_GROUP_UPDATE_KIND)
    access.update_group(
        runtime, admin_session, access_group, "Responders team", "On call", "Rename"
    )
    assert kind_count(admin_engine, tenant, ACCESS_GROUP_UPDATE_KIND) == before + 1
    assert _group_row(admin_engine, tenant, access_group)["name"] == "Responders team"


# -- Approval rule names: `approval_rules.change_rule`, beside its own reason screen --------


@over_free_text("name")
def test_an_approval_rules_name_shaped_like_a_secret_is_refused_unquoted(
    runtime, world, admin_engine, admin_session, approval_rule, name
):
    tenant = world["identity"].tenant_id
    before_name = _rule_name(admin_engine, tenant, approval_rule)
    before = kind_count(admin_engine, tenant, APPROVAL_RULE_KIND)
    body = {**_rule_save_body(admin_engine, tenant, approval_rule), "name": name}
    with pytest.raises(approval_rules.ApprovalRuleError) as refused:
        approval_rules.change_rule(runtime, admin_session, approval_rule, body, "Rename the rule")
    assert_refused_unquoted(refused, "INVALID_BODY", name)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, APPROVAL_RULE_KIND) == before
    assert _rule_name(admin_engine, tenant, approval_rule) == before_name


def test_a_plain_approval_rules_name_is_still_accepted(
    runtime, world, admin_engine, admin_session, approval_rule
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, APPROVAL_RULE_KIND)
    body = {**_rule_save_body(admin_engine, tenant, approval_rule), "name": "Operational review"}
    changed = approval_rules.change_rule(runtime, admin_session, approval_rule, body, "Rename")
    assert changed == approval_rule
    assert kind_count(admin_engine, tenant, APPROVAL_RULE_KIND) == before + 1
    assert _rule_name(admin_engine, tenant, approval_rule) == "Operational review"


def test_a_secret_shaped_approval_rules_name_is_refused_as_invalid_body_over_http(
    db, runtime, admin_engine, world, approval_rule
):
    """`change_rule` answers the reason, the name and the choice counts alike with
    `ApprovalRuleError("INVALID_BODY")`; `exc.field`, set at the name screen, reaches the
    console as `fields=["name"]`, so the refusal names its field."""
    tenant = world["identity"].tenant_id
    before_name = _rule_name(admin_engine, tenant, approval_rule)
    before = kind_count(admin_engine, tenant, APPROVAL_RULE_KIND)
    # `_rule_save_body` carries `operation` for the domain call `change_rule` takes
    # directly; the console's own `ApprovalRuleBody` forbids that extra key, so the HTTP
    # body is the same fields without it.
    saved = _rule_save_body(admin_engine, tenant, approval_rule)
    body = {k: v for k, v in saved.items() if k != "operation"} | {
        "name": STRIPE,
        "reason": "Rename the rule",
    }
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        refused = client.post(API + f"/approval-rules/{approval_rule}", body)
    assert refused.status_code == 400, refused.text
    answer = refused.json()
    assert answer["code"] == "INVALID_BODY" and answer["fields"] == ["name"]
    assert_no_secrets(refused)
    assert kind_count(admin_engine, tenant, APPROVAL_RULE_KIND) == before
    assert _rule_name(admin_engine, tenant, approval_rule) == before_name


# -- Space names: `spaces.create_space` and `spaces.rename_space` --------------------------

SPACE_CREATED_KIND = "space.created"
SPACE_RENAMED_KIND = "space.renamed"


@over_free_text("name")
def test_a_new_spaces_name_shaped_like_a_secret_is_refused_unquoted(db, world, admin_engine, name):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    before = kind_count(admin_engine, tenant, SPACE_CREATED_KIND)
    before_rows = row_count(admin_engine, tenant, "spaces")
    with pytest.raises(SpaceError) as refused, db.transaction(tenant) as conn:
        create_space(conn, tenant, actor, name, None, credential=None)
    assert_refused_unquoted(refused, "INVALID_NAME", name)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, SPACE_CREATED_KIND) == before
    assert row_count(admin_engine, tenant, "spaces") == before_rows


def test_a_plain_new_spaces_name_is_still_accepted(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    before = kind_count(admin_engine, tenant, SPACE_CREATED_KIND)
    before_rows = row_count(admin_engine, tenant, "spaces")
    with db.transaction(tenant) as conn:
        create_space(conn, tenant, actor, "Customer D", None, credential=None)
    assert kind_count(admin_engine, tenant, SPACE_CREATED_KIND) == before + 1
    assert row_count(admin_engine, tenant, "spaces") == before_rows + 1


@pytest.fixture
def renamable_space(db, world):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    with db.transaction(tenant) as conn:
        return create_space(conn, tenant, actor, "Original name", None, credential=None)


@over_free_text("name")
def test_a_space_rename_shaped_like_a_secret_is_refused_unquoted(
    db, world, admin_engine, renamable_space, name
):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    before = kind_count(admin_engine, tenant, SPACE_RENAMED_KIND)
    with pytest.raises(SpaceError) as refused, db.transaction(tenant) as conn:
        rename_space(conn, tenant, actor, renamable_space, name, None, credential=None)
    assert_refused_unquoted(refused, "INVALID_NAME", name)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, SPACE_RENAMED_KIND) == before
    assert _space_name(admin_engine, tenant, renamable_space) == "Original name"


def test_a_plain_space_rename_is_still_accepted(db, world, admin_engine, renamable_space):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    before = kind_count(admin_engine, tenant, SPACE_RENAMED_KIND)
    with db.transaction(tenant) as conn:
        rename_space(conn, tenant, actor, renamable_space, "Renamed", None, credential=None)
    assert kind_count(admin_engine, tenant, SPACE_RENAMED_KIND) == before + 1
    assert _space_name(admin_engine, tenant, renamable_space) == "Renamed"


# -- Personal access token names: `personal_tokens.issue_token`, for an ADMIN -----------------

TOKEN_KIND = "personal_token.issued"


@over_free_text("name")
def test_a_token_name_shaped_like_a_secret_is_refused_unquoted_for_an_administrator(
    runtime, world, admin_engine, admin_session, name
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, TOKEN_KIND)
    before_rows = row_count(admin_engine, tenant, "personal_access_tokens")
    with pytest.raises(TokenError) as refused:
        issue_token(runtime.db, admin_session, name, timedelta(days=1), clock=runtime.clock)
    assert_refused_unquoted(refused, "INVALID_NAME", name)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, TOKEN_KIND) == before
    assert row_count(admin_engine, tenant, "personal_access_tokens") == before_rows


def test_a_plain_token_name_is_still_accepted_for_an_administrator(
    runtime, world, admin_engine, admin_session
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, TOKEN_KIND)
    before_rows = row_count(admin_engine, tenant, "personal_access_tokens")
    issue_token(runtime.db, admin_session, "ci", timedelta(days=1), clock=runtime.clock)
    assert kind_count(admin_engine, tenant, TOKEN_KIND) == before + 1
    assert row_count(admin_engine, tenant, "personal_access_tokens") == before_rows + 1


# -- One HTTP-level test per surface family: a label, and a token name ----------------------


def test_the_console_people_route_refuses_a_secret_shaped_label_as_a_bad_value(
    db, runtime, admin_engine, world
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, LABEL_KIND)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        response = client.post(PEOPLE, {"label": STRIPE})
    assert response.status_code == 400, response.text
    assert response.json()["code"] == "INVALID_BODY"
    assert response.json()["fields"] == ["label"]
    assert_no_secrets(response)
    assert kind_count(admin_engine, tenant, LABEL_KIND) == before


def test_the_console_token_issue_route_refuses_a_secret_shaped_name_as_a_bad_value(
    db, runtime, admin_engine, world
):
    """`tokens.py`'s `_REFUSALS` answers `INVALID_NAME`, which only `issue` can raise, as
    400 `INVALID_BODY` naming `name`, so the person sees which field to rephrase."""
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, TOKEN_KIND)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        response = client.post(API + "/settings/tokens/issue", {"name": STRIPE, "lifetime": "8"})
    assert response.status_code == 400, response.text
    body = response.json()
    assert body["code"] == "INVALID_BODY" and body["fields"] == ["name"]
    assert_no_secrets(response)
    assert kind_count(admin_engine, tenant, TOKEN_KIND) == before
