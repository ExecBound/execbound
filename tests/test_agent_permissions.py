# SPDX-License-Identifier: AGPL-3.0-only
"""Permissions describe the agent's selected Space, before it has made a request."""

from uuid import uuid4

from console_api_fixtures import API, assert_no_secrets, console_client
from directory_fixtures import settle
from sqlalchemy import text
from test_console_policy_spaces import second_space, select_bundle
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.contracts import PRODUCTION_CATALOG
from execbound.policy.models import BundleContent, LimitRule, MappingRef
from execbound.policy.rulesets import ruleset_bundle, sentence
from execbound.surfaces.console_api.policy_starters import first_policy
from execbound_harness.demo import ENDPOINT_RULESET


def test_permissions_use_the_agents_space_and_do_not_import_another_spaces_actions(
    db, runtime, admin_engine, world
):
    first, second, mapping = second_space(admin_engine, world)
    tenant = world["identity"].tenant_id
    other = first_policy(tenant, (mapping,), PRODUCTION_CATALOG)
    select_bundle(db, world, second, other)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        # Reading a specific agent is membership-authorized even while viewing another Space.
        assert client.post(API + "/session/space", {"space_id": str(second)}).status_code == 200
        response = client.get(f"{API}/agents/{world['identity'].principal_id}")
        assert response.status_code == 200, response.text
        body = response.json()
        assert {row["action"] for row in body["reach"]} == {"endpoint.isolate"}
        assert body["space"] == {"space_id": str(first), "name": "Default"}
        assert body["permissions_bundle_id"] == str(world["bundle"].bundle_id)
        assert body["permissions_inherited"] is False
        assert body["policy_document"]["complete"] is True
        assert (
            body["policy_document"]["authorization_policies"]
            == world["bundle"].authorization_policies
        )
        assert {rule["effect"] for rule in body["policy_document"]["rules"]} == {
            "Allow",
            "Deny",
            "Require approval",
        }
        assert body["reach"][0]["resource_scope"]
        assert_no_secrets(response)


def test_new_agent_permissions_show_conditions_and_shared_limits_before_any_activity(
    db, runtime, admin_engine, world
):
    tenant = world["identity"].tenant_id
    shared = LimitRule(
        rule_id="shared-isolations",
        action="endpoint.isolate",
        scope="tenant",
        window_seconds=3600,
        max_targets=10,
        budget="autonomous",
        on_exceed="REQUIRE_APPROVAL",
    )
    content = ruleset_bundle(
        ENDPOINT_RULESET.model_copy(update={"budgets": (shared,)}),
        tenant_id=tenant,
        bundle_id=uuid4(),
        mappings=world["bundle"].mappings,
    )
    with admin_engine.connect() as conn:
        first = conn.execute(
            text("SELECT space_id FROM execbound.spaces WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one()
    select_bundle(db, world, first, content)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        made = client.post(API + "/agents", {"label": "New responder"})
        assert made.status_code == 200, made.text
        body = client.get(f"{API}/agents/{made.json()['principal_id']}").json()
        assert body["recent"] == []
        assert any(row["max_targets"] == 10 and row["count"] == 0 for row in body["limits"])
        rules = body["reach"][0]["rules"]
        expected = {rule.id: sentence(rule) for rule in ENDPOINT_RULESET.rules}
        assert {rule["id"]: rule["description"] for rule in rules} == expected
        assert body["permissions_bundle_id"] == str(content.bundle_id)
        assert str(world["account"]) in " ".join(body["reach"][0]["resource_scope"])


def test_no_selected_policy_does_not_borrow_another_spaces_governed_paths(
    db, runtime, admin_engine, world
):
    first, second, mapping = second_space(admin_engine, world)
    tenant = world["identity"].tenant_id
    select_bundle(db, world, second, first_policy(tenant, (mapping,), PRODUCTION_CATALOG))
    with admin_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM execbound.space_policy_selection WHERE tenant_id=:t AND space_id=:s"),
            {"t": tenant, "s": first},
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        body = client.get(f"{API}/agents/{world['identity'].principal_id}").json()
        assert body["bundle"] is False
        assert body["reach"] == []
        assert body["permissions_bundle_id"] is None


def test_permissions_exclude_limits_qualified_to_another_space_or_unmapped_account(
    db, runtime, admin_engine, world
):
    first, second, mapping = second_space(admin_engine, world)
    tenant = world["identity"].tenant_id
    budgets = tuple(
        LimitRule(
            rule_id=f"limit-{scope}",
            action="endpoint.isolate",
            scope=scope,
            window_seconds=3600,
            max_targets=10,
            budget="total",
            on_exceed="DENY",
            **qualifier,
        )
        for scope, qualifier in (
            ("space", {"space_id": second}),
            ("account", {"account_id": mapping.account_id}),
        )
    )
    content = ruleset_bundle(
        ENDPOINT_RULESET.model_copy(update={"budgets": budgets}),
        tenant_id=tenant,
        bundle_id=uuid4(),
        mappings=world["bundle"].mappings,
    )
    select_bundle(db, world, first, content)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        body = client.get(f"{API}/agents/{world['identity'].principal_id}").json()
        assert body["limits"] == []


def test_limits_bear_on_an_agent_through_a_ref_that_is_not_the_actions_name(
    db, runtime, admin_engine, world
):
    """A limit names the catalog action; the bundle maps it under `alternate.isolate`."""
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings "
                "SELECT tenant_id,'alternate.isolate',account_id,provider,resource_type,action,"
                "provider_operation,mapping_version,schema_version,context_contract_version,active "
                "FROM execbound.operation_mappings "
                "WHERE tenant_id=:t AND operation_ref='endpoint.isolate'"
            ),
            {"t": tenant},
        )
        first = conn.execute(
            text("SELECT space_id FROM execbound.spaces WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one()
    reference = MappingRef(
        **world["bundle"].mappings[0].model_dump(exclude={"operation_ref"}),
        operation_ref="alternate.isolate",
        action="endpoint.isolate",
    )
    budgets = tuple(
        LimitRule(
            rule_id=f"limit-{scope}",
            action="endpoint.isolate",
            scope=scope,
            window_seconds=3600,
            max_targets=10,
            budget="total",
            on_exceed="DENY",
            **qualifier,
        )
        for scope, qualifier in (("tenant", {}), ("account", {"account_id": world["account"]}))
    )
    content = ruleset_bundle(
        ENDPOINT_RULESET.model_copy(update={"budgets": budgets}),
        tenant_id=tenant,
        bundle_id=uuid4(),
        mappings=(reference,),
    )
    select_bundle(db, world, first, content)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        made = client.post(API + "/agents", {"label": "New responder"})
        assert made.status_code == 200, made.text
        body = client.get(f"{API}/agents/{made.json()['principal_id']}").json()
        assert body["permissions_bundle_id"] == str(content.bundle_id)
        # Both bear on it: the tenant's, and the account's, whose account the ref serves.
        assert [row["actions"] for row in body["limits"]] == ["endpoint.isolate"] * 2


def test_limits_bear_through_a_hand_written_ref_that_does_not_name_its_action(
    db, runtime, admin_engine, world
):
    """A bundle written by hand may map an action under another ref without naming it.

    The store reads such a bundle by its mapping rows (`policy/store._components`) and
    admission charges the row's action, so the page reads the row too: the limits on
    `endpoint.isolate` bear on an agent the bundle reaches only through `alternate.isolate`,
    and the tenant's is counted the way admission counts it.
    """
    tenant = world["identity"].tenant_id
    # Two isolations by another agent, inside the tenant rule's window.
    settle(db, admin_engine, world, world["identity"], 2)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings "
                "SELECT tenant_id,'alternate.isolate',account_id,provider,resource_type,action,"
                "provider_operation,mapping_version,schema_version,context_contract_version,active "
                "FROM execbound.operation_mappings "
                "WHERE tenant_id=:t AND operation_ref='endpoint.isolate'"
            ),
            {"t": tenant},
        )
        first = conn.execute(
            text("SELECT space_id FROM execbound.spaces WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one()
    reference = MappingRef(
        **world["bundle"].mappings[0].model_dump(exclude={"operation_ref"}),
        operation_ref="alternate.isolate",
    )
    # The ref names no action, so the bundle alone would say it serves `alternate.isolate`.
    assert reference.action is None and reference.action_name == "alternate.isolate"
    budgets = tuple(
        LimitRule(
            rule_id=f"limit-{scope}",
            action="endpoint.isolate",
            scope=scope,
            window_seconds=3600,
            max_targets=10,
            budget="total",
            on_exceed="DENY",
            **qualifier,
        )
        for scope, qualifier in (("tenant", {}), ("account", {"account_id": world["account"]}))
    )
    content = BundleContent(
        tenant_id=tenant,
        bundle_id=uuid4(),
        cedar_schema=world["bundle"].cedar_schema,
        authorization_policies=world["bundle"].authorization_policies,
        approval_policies=world["bundle"].approval_policies,
        mappings=(reference,),
        limits=budgets,
    )
    assert content.ruleset is None
    select_bundle(db, world, first, content)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        made = client.post(API + "/agents", {"label": "New responder"})
        assert made.status_code == 200, made.text
        response = client.get(f"{API}/agents/{made.json()['principal_id']}")
        assert response.status_code == 200, response.text
        assert_no_secrets(response)
        body = response.json()
        assert body["permissions_bundle_id"] == str(content.bundle_id)
        assert body["recent"] == []
        # Both bear on it: the tenant's, counted tenant-wide, and the account's, whose account
        # the ref serves, which the page leaves uncounted.
        assert [(row["scope"], row["actions"], row["count"]) for row in body["limits"]] == [
            (f"Account {world['account']}", "endpoint.isolate", None),
            ("Tenant", "endpoint.isolate", 2),
        ]


def test_limits_do_not_bear_through_an_operation_the_agents_space_is_not_offered(
    db, runtime, admin_engine, world
):
    """The page reads what the agent's space is offered, the set admission checks first.

    Admission refuses an operation whose account another space holds before it reads a limit
    (`execution.offered`), so a rule on that operation's action or account cannot charge or
    cap this agent, whatever the selected bundle names; the space's own action keeps its
    rules.
    """
    first, second, mapping = second_space(admin_engine, world, offered=True)
    tenant = world["identity"].tenant_id
    starter = first_policy(tenant, (world["bundle"].mappings[0], mapping), PRODUCTION_CATALOG)
    assert starter.ruleset is not None
    account = LimitRule(
        rule_id="limit-account",
        action="endpoint.lift_isolation",
        scope="account",
        account_id=mapping.account_id,
        window_seconds=3600,
        max_targets=10,
        budget="total",
        on_exceed="DENY",
    )
    content = ruleset_bundle(
        starter.ruleset.model_copy(update={"budgets": (*starter.ruleset.budgets, account)}),
        tenant_id=tenant,
        bundle_id=uuid4(),
        mappings=starter.mappings,
    )
    select_bundle(db, world, first, content)
    # The other space stops offering its account; the selected policy still names it.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.connector_accounts SET offered_tenant_wide=false "
                "WHERE tenant_id=:t AND account_id=:a"
            ),
            {"t": tenant, "a": mapping.account_id},
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        # The world's agent, in the first space and with no history yet.
        body = client.get(f"{API}/agents/{world['identity'].principal_id}").json()
        assert body["permissions_bundle_id"] == str(content.bundle_id)
        assert body["recent"] == []
        assert {row["action"] for row in body["reach"]} == {"endpoint.isolate"}
        assert [(row["scope"], row["actions"]) for row in body["limits"]] == [
            ("Principal", "endpoint.isolate"),
            ("Tenant", "endpoint.isolate"),
        ]


def test_limits_do_not_bear_through_a_reference_the_tenants_mapping_no_longer_matches(
    db, runtime, admin_engine, world
):
    """A policy older than its mappings offers nothing through the stale reference.

    Admission refuses the operation as `INVALID_BUNDLE` before it reads a limit, so the
    page, which reads the same offered set, shows no rule on its action either, as it shows
    no governed path for it.
    """
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.operation_mappings SET mapping_version='map-v2' "
                "WHERE tenant_id=:t AND operation_ref='endpoint.isolate'"
            ),
            {"t": tenant},
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        body = client.get(f"{API}/agents/{world['identity'].principal_id}").json()
        assert body["permissions_bundle_id"] == str(world["bundle"].bundle_id)
        assert body["recent"] == [] and body["reach"] == []
        assert body["limits"] == []
