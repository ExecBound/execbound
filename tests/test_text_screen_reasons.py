# SPDX-License-Identifier: AGPL-3.0-only
"""Reasons an administrator writes into the audit chain, screened like any other text a
person types (T7.7): ten boundaries, each refused with its own existing class and
code, quoting the value nowhere, and leaving no trace of the write it would have made.

Some of these boundaries audit their own refusal: ``reconcile_operation`` and
``reconciliation.reconcile`` catch the raised error and call ``_rejection``, which appends
``execution.rejected`` naming only the refusal's code, never the value. Others refuse before
anything is written and audit nothing. Rather than assert the tenant's audit head either
moved or did not, depending on which boundary this is, every test here asserts the two things
true of both: no payload of the tenant's audit chain holds anything ``find_secrets`` flags,
and the event the call would have appended on success was not, with the state it would have
changed left exactly as it was. Each boundary's plain-reason control proves the opposite: the
event is appended once, under the same kind constant its refusal test checks stays put.
"""

from uuid import UUID

import pytest
from checkpoint_fixtures import checkpoint
from checkpoint_fixtures import gate_world as gate_world
from checkpoint_fixtures import owner as owner
from console_api_fixtures import API, assert_no_secrets, console_client, console_config
from secret_shapes import STRIPE
from sqlalchemy import text
from test_agents_bindings import found as found
from test_approval_group_rules import rule, setup_group
from test_console_api_people import PEOPLE
from test_emergency_stop import scoped
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import approved
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_recovery_run import lost_response
from test_runtime import runtime as runtime
from text_screen_helpers import (
    APPROVAL_RULE_KIND,
    assert_nothing_found,
    assert_refused_unquoted,
    kind_count,
    over_free_text,
)

from execbound import access_control as access
from execbound import approval_rules, bindings
from execbound.administration import AdministrationError
from execbound.approval_rules import ApprovalRuleError
from execbound.assistant.turns import AssistantError, set_tenant_switch, tenant_switch
from execbound.execution import activate_stop, reconcile, store
from execbound.execution.models import ExecutionError
from execbound.execution.modes import set_approval_deadline, set_enforcement_mode
from execbound.provider.gateway import reconcile_operation
from execbound.provider.models import provider_command
from execbound.provider.verifiers import verifier_for
from execbound.spaces import SpaceError, archive_space, create_space, is_archived
from execbound.surfaces import people_pages
from execbound.surfaces.sessions import issue_session, load_session


def execution_state(engine, tenant, execution_id):
    with engine.begin() as conn:
        scoped(conn, tenant)
        return conn.execute(
            text(
                "SELECT state FROM execbound.executions WHERE tenant_id = :t AND execution_id = :e"
            ),
            {"t": tenant, "e": execution_id},
        ).scalar_one()


@pytest.fixture
def admin_session(db, world):
    """A console session for the world's ADMIN, for the boundaries that take one."""
    issued = issue_session(db, world["admin"], clock=world["clock"])
    return load_session(db, issued.token, clock=world["clock"])


# -- execution/stops.py `_reason` -------------------------------------------------------

STOP_KIND = "tenant.stop_activated"


@over_free_text("reason")
def test_a_stop_reason_shaped_like_a_secret_is_refused_unquoted(db, world, admin_engine, reason):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, STOP_KIND)
    with pytest.raises(ExecutionError) as refused:
        activate_stop(db, world["admin"], reason, world["clock"])
    assert_refused_unquoted(refused, "INVALID_REASON", reason)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, STOP_KIND) == before
    with db.transaction(tenant) as conn:
        assert store.stop(conn, tenant) is None


def test_a_plain_stop_reason_is_still_accepted(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, STOP_KIND)
    activate_stop(db, world["admin"], "Incident 42", world["clock"])
    assert kind_count(admin_engine, tenant, STOP_KIND) == before + 1


# -- execution/modes.py `_reason` (shared by `set_enforcement_mode` and
# -- `set_approval_deadline`) -------------------------------------------------------------

MODE_KIND = "tenant.mode_changed"
DEADLINE_KIND = "tenant.approval_deadline_changed"


@over_free_text("reason")
def test_an_enforcement_mode_reason_shaped_like_a_secret_is_refused_unquoted(
    db, world, admin_engine, reason
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, MODE_KIND)
    with pytest.raises(ExecutionError) as refused:
        set_enforcement_mode(db, world["admin"], "OBSERVE", reason, world["clock"])
    assert_refused_unquoted(refused, "INVALID_REASON", reason)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, MODE_KIND) == before
    with db.transaction(tenant) as conn:
        assert store.enforcement_mode(conn, tenant) == "ENFORCE"


def test_a_plain_enforcement_mode_reason_is_still_accepted(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, MODE_KIND)
    change = set_enforcement_mode(db, world["admin"], "OBSERVE", "Pilot programme", world["clock"])
    assert change.mode == "OBSERVE"
    assert kind_count(admin_engine, tenant, MODE_KIND) == before + 1


@over_free_text("reason")
def test_an_approval_deadline_reason_shaped_like_a_secret_is_refused_unquoted(
    db, world, admin_engine, reason
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, DEADLINE_KIND)
    with db.transaction(tenant) as conn:
        before_deadline = store.approval_deadline(conn, tenant)
    with pytest.raises(ExecutionError) as refused:
        set_approval_deadline(db, world["admin"], 600, reason, world["clock"])
    assert_refused_unquoted(refused, "INVALID_REASON", reason)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, DEADLINE_KIND) == before
    with db.transaction(tenant) as conn:
        assert store.approval_deadline(conn, tenant) == before_deadline


# -- provider/gateway.py `reconcile_operation` -------------------------------------------

RECONCILE_OPERATION_KIND = "execution.reconciliation_requested"


@over_free_text("reason")
def test_a_reconcile_operation_reason_shaped_like_a_secret_is_refused_unquoted(
    db, world, live_provider, connector, admin_engine, reason
):
    tenant = world["identity"].tenant_id
    winner = approved(db, world)
    before_state = execution_state(admin_engine, tenant, winner.view.execution_id)
    before_requested = kind_count(admin_engine, tenant, RECONCILE_OPERATION_KIND)
    before_cancelled = kind_count(admin_engine, tenant, "execution.cancellation_requested")
    before_transitioned = kind_count(admin_engine, tenant, "execution.transition")
    with pytest.raises(ExecutionError) as refused:
        reconcile_operation(
            db,
            world["admin"],
            winner.view.execution_id,
            connector,
            reason=reason,
            clock=world["clock"],
        )
    assert_refused_unquoted(refused, "INVALID_REASON", reason)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, RECONCILE_OPERATION_KIND) == before_requested
    assert kind_count(admin_engine, tenant, "execution.cancellation_requested") == before_cancelled
    assert kind_count(admin_engine, tenant, "execution.transition") == before_transitioned
    assert execution_state(admin_engine, tenant, winner.view.execution_id) == before_state


def test_a_plain_reconcile_operation_reason_is_still_accepted(
    db, world, live_provider, connector, admin_engine
):
    tenant = world["identity"].tenant_id
    winner = approved(db, world)
    before = kind_count(admin_engine, tenant, RECONCILE_OPERATION_KIND)
    result = reconcile_operation(
        db,
        world["admin"],
        winner.view.execution_id,
        connector,
        reason="Check interrupted send",
        clock=world["clock"],
    )
    assert result.state == "INDETERMINATE"
    assert kind_count(admin_engine, tenant, RECONCILE_OPERATION_KIND) == before + 1


def test_a_secret_shaped_reconcile_reason_is_refused_as_invalid_body_over_http(
    db, runtime, admin_engine, world
):
    """The console route's dispatch branch (`_reconcile_dispatched` calling
    `reconcile_operation`) catches `ExecutionError("INVALID_REASON")` and answers 400
    `INVALID_BODY` naming `reason`, the way `deactivate`'s own route does. `error_status`
    has no entry for the code, so without that catch the app's generic `ExecutionError`
    handler would answer 503 `UNAVAILABLE`."""
    tenant = world["identity"].tenant_id
    winner = approved(db, world)
    before = kind_count(admin_engine, tenant, RECONCILE_OPERATION_KIND)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        detail = client.get(API + f"/executions/{winner.view.execution_id}").json()
        continuation = detail["reconcile"]["continuation"]
        refused = client.post(
            API + f"/executions/{winner.view.execution_id}/reconcile",
            {"continuation": continuation, "reason": STRIPE},
        )
    assert refused.status_code == 400, refused.text
    body = refused.json()
    assert body["code"] == "INVALID_BODY" and body["fields"] == ["reason"]
    assert_no_secrets(refused)
    assert kind_count(admin_engine, tenant, RECONCILE_OPERATION_KIND) == before


# -- execution/reconciliation.py `reconcile` ---------------------------------------------

RECONCILIATION_KIND = "execution.transition"


@over_free_text("reason")
def test_a_reconciliation_reason_shaped_like_a_secret_is_refused_unquoted(
    db, world, live_provider, connector, admin_engine, reason
):
    """Real evidence from the provider's retained journal, the same shape the settle-grant
    route hands this function, so a removed screen does not merely trade one refusal
    (``INVALID_EVIDENCE``) for another: it settles the grant and writes the reason."""
    tenant = world["identity"].tenant_id
    winner = lost_response(db, world, live_provider, "delay_after_commit")
    with db.transaction(tenant) as conn:
        command = store.command(store.read(conn, tenant, winner.view.execution_id))
    evidence = connector.lookup(provider_command(command))
    assert evidence is not None
    before_state = execution_state(admin_engine, tenant, winner.view.execution_id)
    before = kind_count(admin_engine, tenant, RECONCILIATION_KIND)
    with pytest.raises(ExecutionError) as refused:
        reconcile(
            db,
            world["admin"],
            winner.view.execution_id,
            reason=reason,
            evidence=evidence,
            verifier=verifier_for(connector.config),
            clock=world["clock"],
        )
    assert_refused_unquoted(refused, "INVALID_REASON", reason)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, RECONCILIATION_KIND) == before
    assert execution_state(admin_engine, tenant, winner.view.execution_id) == before_state


def test_a_plain_reconciliation_reason_is_still_accepted(
    db, world, live_provider, connector, admin_engine
):
    """Exercised through ``reconcile_operation``, which hands this same reason to
    ``reconciliation.reconcile`` once the provider's retained journal answers the lookup a
    timed-out dispatch could not. A full settlement from a real lost response is the proof
    that neither screen refuses a plain reason."""
    tenant = world["identity"].tenant_id
    winner = lost_response(db, world, live_provider, "delay_after_commit")
    before = kind_count(admin_engine, tenant, RECONCILIATION_KIND)
    settled = reconcile_operation(
        db,
        world["admin"],
        winner.view.execution_id,
        connector,
        reason="Verify operation after response loss",
        clock=world["clock"],
    )
    assert settled.state == "EXECUTED"
    assert kind_count(admin_engine, tenant, RECONCILIATION_KIND) == before + 1


def test_a_secret_shaped_settle_grant_reason_is_refused_as_invalid_body_over_http(
    db, runtime, admin_engine, gate_world
):
    """The console route's grant branch (`settle_grant` calling `reconciliation.reconcile`)
    answers `INVALID_REASON` as 400 `INVALID_BODY` naming `reason`, as the dispatch branch
    does. `reconcile` screens the reason before it reads the row or checks any evidence, so
    a bogus `record` reaches the same refusal as a genuine one would."""
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    execution_id = granted.view.execution_id
    before = kind_count(admin_engine, tenant, RECONCILIATION_KIND)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        detail = client.get(API + f"/executions/{execution_id}").json()
        assert detail["reconcile"]["kind"] == "record"
        continuation = detail["reconcile"]["continuation"]
        refused = client.post(
            API + f"/executions/{execution_id}/reconcile",
            {"continuation": continuation, "reason": STRIPE, "record": "{}"},
        )
    assert refused.status_code == 400, refused.text
    body = refused.json()
    assert body["code"] == "INVALID_BODY" and body["fields"] == ["reason"]
    assert_no_secrets(refused)
    assert kind_count(admin_engine, tenant, RECONCILIATION_KIND) == before


# -- access_control.py `_reason` (exercised through `set_roles_in`) ----------------------

ACCESS_KIND = "access.set_user_roles"


@over_free_text("reason")
def test_an_access_change_reason_shaped_like_a_secret_is_refused_unquoted(
    db, world, admin_engine, reason
):
    tenant = world["identity"].tenant_id
    actor, subject = world["admin"].principal_id, world["human"].principal_id
    before = kind_count(admin_engine, tenant, ACCESS_KIND)
    with pytest.raises(access.AccessError) as refused, db.transaction(tenant) as conn:
        access.set_roles_in(
            conn, tenant, actor, "user", subject, [{"role": "viewer", "space_id": None}], reason
        )
    assert_refused_unquoted(refused, "INVALID_REASON", reason)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, ACCESS_KIND) == before
    with db.transaction(tenant) as conn:
        assert access.is_managed(conn, tenant, subject) is False


def test_a_plain_access_change_reason_is_still_accepted(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    actor, subject = world["admin"].principal_id, world["human"].principal_id
    before = kind_count(admin_engine, tenant, ACCESS_KIND)
    with db.transaction(tenant) as conn:
        access.set_roles_in(
            conn,
            tenant,
            actor,
            "user",
            subject,
            [{"role": "viewer", "space_id": None}],
            "Promote reviewer",
        )
    with db.transaction(tenant) as conn:
        assert access.is_managed(conn, tenant, subject) is True
    assert kind_count(admin_engine, tenant, ACCESS_KIND) == before + 1


def test_a_secret_shaped_access_change_reason_is_refused_as_invalid_body_over_http(
    db, runtime, admin_engine, world
):
    """`console_api/access.py`'s `REFUSALS` answers `INVALID_REASON` as `INVALID_BODY`
    naming `reason`, the way `deactivate`'s own route does for its, so this refusal reads
    apart from `INVALID_NAME`'s combined name and description screen."""
    tenant = world["identity"].tenant_id
    subject = world["human"].principal_id
    before = kind_count(admin_engine, tenant, ACCESS_KIND)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        refused = client.post(
            API + f"/access/users/{subject}/roles",
            {"grants": [{"role": "viewer"}], "reason": STRIPE},
        )
    assert refused.status_code == 400, refused.text
    body = refused.json()
    assert body["code"] == "INVALID_BODY" and body["fields"] == ["reason"]
    assert_no_secrets(refused)
    assert kind_count(admin_engine, tenant, ACCESS_KIND) == before


# -- approval_rules.py `change_rule` ------------------------------------------------------


@pytest.fixture
def approval_rule(db, runtime, admin_engine, world):
    """One active approval rule, ready to be changed."""
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        group = setup_group(client, world)
        response = rule(client, world, group)
        assert response.status_code == 200, response.text
        return UUID(response.json()["rule_id"])


def _rule_active(engine, tenant, rule_id):
    with engine.begin() as conn:
        scoped(conn, tenant)
        return conn.execute(
            text("SELECT active FROM execbound.approval_rules WHERE tenant_id=:t AND rule_id=:r"),
            {"t": tenant, "r": rule_id},
        ).scalar_one()


@over_free_text("reason")
def test_an_approval_rule_reason_shaped_like_a_secret_is_refused_unquoted(
    db, runtime, admin_engine, world, admin_session, approval_rule, reason
):
    tenant = world["identity"].tenant_id
    before_active = _rule_active(admin_engine, tenant, approval_rule)
    before = kind_count(admin_engine, tenant, APPROVAL_RULE_KIND)
    with pytest.raises(ApprovalRuleError) as refused:
        approval_rules.change_rule(
            runtime, admin_session, approval_rule, {"operation": "disable"}, reason
        )
    assert_refused_unquoted(refused, "INVALID_BODY", reason)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, APPROVAL_RULE_KIND) == before
    assert _rule_active(admin_engine, tenant, approval_rule) == before_active


def test_a_plain_approval_rule_reason_is_still_accepted(
    db, runtime, world, admin_engine, admin_session, approval_rule
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, APPROVAL_RULE_KIND)
    changed = approval_rules.change_rule(
        runtime, admin_session, approval_rule, {"operation": "disable"}, "Retire the rule"
    )
    assert changed == approval_rule
    assert kind_count(admin_engine, tenant, APPROVAL_RULE_KIND) == before + 1


def test_a_secret_shaped_approval_rule_reason_is_refused_as_invalid_body_over_http(
    db, runtime, admin_engine, world, approval_rule
):
    """`change_rule` answers the reason, the name and the choice counts alike with
    `ApprovalRuleError("INVALID_BODY")`; `exc.field`, set at the reason check, reaches the
    console as `fields=["reason"]`, so the refusal names its field."""
    tenant = world["identity"].tenant_id
    before_active = _rule_active(admin_engine, tenant, approval_rule)
    before = kind_count(admin_engine, tenant, APPROVAL_RULE_KIND)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        refused = client.post(API + f"/approval-rules/{approval_rule}/disable", {"reason": STRIPE})
    assert refused.status_code == 400, refused.text
    body = refused.json()
    assert body["code"] == "INVALID_BODY" and body["fields"] == ["reason"]
    assert_no_secrets(refused)
    assert kind_count(admin_engine, tenant, APPROVAL_RULE_KIND) == before
    assert _rule_active(admin_engine, tenant, approval_rule) == before_active


# -- bindings.py `unbind` -----------------------------------------------------------------

UNBIND_KIND = "agent.unbound"


@pytest.fixture
def bound_agent(db, world, found):
    """One governed agent already bound to a discovered agent, ready to unbind."""
    agent_id = found["agents"][0]["agent_id"]
    with db.transaction(world["identity"].tenant_id) as conn:
        return bindings.bind(conn, world["admin"], agent_id, world["identity"].principal_id)


def _unbound_at(engine, tenant, binding):
    with engine.begin() as conn:
        scoped(conn, tenant)
        return conn.execute(
            text(
                "SELECT unbound_at FROM execbound.agent_bindings "
                "WHERE tenant_id=:t AND binding_id=:b"
            ),
            {"t": tenant, "b": binding},
        ).scalar_one()


@over_free_text("reason")
def test_an_unbind_reason_shaped_like_a_secret_is_refused_unquoted(
    db, world, admin_engine, bound_agent, reason
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, UNBIND_KIND)
    assert _unbound_at(admin_engine, tenant, bound_agent) is None
    with pytest.raises(AdministrationError) as refused:
        with db.transaction(tenant) as conn:
            bindings.unbind(conn, world["admin"], bound_agent, reason)
    assert_refused_unquoted(refused, "INVALID_REASON", reason)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, UNBIND_KIND) == before
    assert _unbound_at(admin_engine, tenant, bound_agent) is None


def test_a_plain_unbind_reason_is_still_accepted(db, world, admin_engine, bound_agent):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, UNBIND_KIND)
    with db.transaction(tenant) as conn:
        released = bindings.unbind(conn, world["admin"], bound_agent, "Retiring the pilot")
    assert released["agent_id"]
    assert kind_count(admin_engine, tenant, UNBIND_KIND) == before + 1


# -- surfaces/people_pages.py `deactivate` ------------------------------------------------

DEACTIVATE_KIND = "principal.deactivated"


def _principal_active(engine, tenant, principal):
    with engine.begin() as conn:
        scoped(conn, tenant)
        return conn.execute(
            text("SELECT active FROM execbound.principals WHERE tenant_id=:t AND principal_id=:p"),
            {"t": tenant, "p": principal},
        ).scalar_one()


@over_free_text("reason")
def test_a_deactivation_reason_shaped_like_a_secret_is_refused_unquoted(
    db, runtime, admin_engine, world, admin_session, reason
):
    tenant = world["identity"].tenant_id
    target = world["human"].principal_id
    before = kind_count(admin_engine, tenant, DEACTIVATE_KIND)
    assert _principal_active(admin_engine, tenant, target) is True
    with pytest.raises(AdministrationError) as refused:
        people_pages.deactivate(runtime, admin_session, target, reason)
    assert_refused_unquoted(refused, "INVALID_REASON", reason)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, DEACTIVATE_KIND) == before
    assert _principal_active(admin_engine, tenant, target) is True


def test_a_plain_deactivation_reason_is_still_accepted(
    db, runtime, world, admin_engine, admin_session
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, DEACTIVATE_KIND)
    people_pages.deactivate(runtime, admin_session, world["human"].principal_id, "left the team")
    assert kind_count(admin_engine, tenant, DEACTIVATE_KIND) == before + 1


def test_a_secret_shaped_deactivation_reason_is_refused_as_invalid_body_over_http(
    db, runtime, admin_engine, world
):
    """The console route maps `INVALID_REASON` to `INVALID_BODY` naming `reason`
    (`surfaces/console_api/directory.py` `REFUSALS`), so the person sees a 400 bad value
    and not a 500, the way `unbind`'s own route does."""
    tenant = world["identity"].tenant_id
    human = str(world["human"].principal_id)
    before = kind_count(admin_engine, tenant, DEACTIVATE_KIND)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        refused = client.post(f"{PEOPLE}/{human}/deactivate", {"reason": STRIPE})
    assert refused.status_code == 400
    body = refused.json()
    assert body["code"] == "INVALID_BODY" and body["fields"] == ["reason"]
    assert_no_secrets(refused)
    assert kind_count(admin_engine, tenant, DEACTIVATE_KIND) == before


# -- assistant/turns.py `set_tenant_switch` -----------------------------------------------

TENANT_SWITCH_KIND = "tenant.assistant_changed"


@over_free_text("reason")
def test_a_tenant_switch_reason_shaped_like_a_secret_is_refused_unquoted(
    db, world, admin_engine, reason
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, TENANT_SWITCH_KIND)
    with pytest.raises(AssistantError) as refused:
        set_tenant_switch(db, world["admin"], True, reason, world["clock"])
    assert_refused_unquoted(refused, "INVALID_REASON", reason)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, TENANT_SWITCH_KIND) == before
    with db.transaction(tenant) as conn:
        assert tenant_switch(conn, tenant) is False


def test_a_plain_tenant_switch_reason_is_still_accepted(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, TENANT_SWITCH_KIND)
    change = set_tenant_switch(db, world["admin"], True, "The sandbox is synthetic", world["clock"])
    assert change.enabled is True
    assert kind_count(admin_engine, tenant, TENANT_SWITCH_KIND) == before + 1


def test_a_secret_shaped_tenant_switch_reason_is_refused_as_invalid_body_over_http(
    db, runtime, admin_engine, world
):
    """Only `set_tenant_switch` raises `AssistantError("INVALID_REASON")`; `assistant.py`'s
    `REFUSALS` names `reason` for it, so the console answers 400 naming the field."""
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, TENANT_SWITCH_KIND)
    config = console_config(assistant_enabled=True)
    with console_client(db, runtime, admin_engine, world["admin"], config=config) as client:
        refused = client.post(API + "/assistant/settings", {"enabled": True, "reason": STRIPE})
    assert refused.status_code == 400, refused.text
    body = refused.json()
    assert body["code"] == "INVALID_BODY" and body["fields"] == ["reason"]
    assert_no_secrets(refused)
    assert kind_count(admin_engine, tenant, TENANT_SWITCH_KIND) == before


# -- spaces.py `_reason` (exercised through `archive_space`) ------------------------------

SPACE_ARCHIVE_KIND = "space.archived"


@over_free_text("reason")
def test_a_space_archive_reason_shaped_like_a_secret_is_refused_unquoted(
    db, world, admin_engine, reason
):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    with db.transaction(tenant) as conn:
        space = create_space(conn, tenant, actor, "Customer B", None, credential=None)
    before = kind_count(admin_engine, tenant, SPACE_ARCHIVE_KIND)
    with pytest.raises(SpaceError) as refused, db.transaction(tenant) as conn:
        archive_space(conn, tenant, actor, space, reason, credential=None)
    assert_refused_unquoted(refused, "INVALID_NAME", reason)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, SPACE_ARCHIVE_KIND) == before
    with db.transaction(tenant) as conn:
        assert is_archived(conn, tenant, space) is False


def test_a_plain_space_archive_reason_is_still_accepted(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    with db.transaction(tenant) as conn:
        space = create_space(conn, tenant, actor, "Customer C", None, credential=None)
    before = kind_count(admin_engine, tenant, SPACE_ARCHIVE_KIND)
    with db.transaction(tenant) as conn:
        archive_space(conn, tenant, actor, space, "Customer left", credential=None)
        assert is_archived(conn, tenant, space) is True
    assert kind_count(admin_engine, tenant, SPACE_ARCHIVE_KIND) == before + 1


def test_a_secret_shaped_space_archive_reason_is_refused_as_invalid_body_over_http(
    db, runtime, admin_engine, world
):
    """`_reason` kept the existing `SpaceError("INVALID_NAME")` code rather than invent one,
    and the console's shared `refused()` mapping names "name" for it, which is wrong on a
    form that carries only a reason; `console_api/spaces.py`'s `_state` answers `reason` for
    this route, the way `deactivate`'s own route does for its."""
    tenant = world["identity"].tenant_id
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        space = client.post(API + "/spaces", {"name": "Customer D"}).json()["space_id"]
        before = kind_count(admin_engine, tenant, SPACE_ARCHIVE_KIND)
        refused = client.post(API + f"/spaces/{space}/archive", {"reason": STRIPE})
    assert refused.status_code == 400, refused.text
    body = refused.json()
    assert body["code"] == "INVALID_BODY" and body["fields"] == ["reason"]
    assert_no_secrets(refused)
    assert kind_count(admin_engine, tenant, SPACE_ARCHIVE_KIND) == before
