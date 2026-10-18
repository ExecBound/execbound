# SPDX-License-Identifier: AGPL-3.0-only
"""An account's view of its own workspaces carries a count of its own waiting approvals and
nothing else of another workspace.

Each membership answers the kind and the workspace-wide roles a session there would carry and
what entering it asks. With nothing more to ask, a workspace other than the current one also
answers how many approvals wait for this account there and the earliest of their deadlines,
floored to the minute, read under that tenant's own row security with the pending queue's own
predicate. Where entering would ask for a factor, a factor's set-up or a directory sign-in, the
count is withheld and no count statement runs (#678).
"""

import json
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import event, text
from sqlalchemy.exc import DataError
from test_execution import activate, targets
from test_human_surface import pending
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world
from test_workspace_accounts import adopt, enroll, membership_in

from execbound import workspaces
from execbound.execution import decide_approval
from execbound.passwords import sign_in_with_password
from execbound.surfaces import human
from execbound.surfaces.human import PAGE_SIZE
from execbound.surfaces.sessions import issue_session, load_session

pytestmark = pytest.mark.integration

PASSWORD = "a retained example passphrase"
FIELDS = {
    "tenant_id",
    "name",
    "current",
    "kind",
    "roles",
    "entry",
    "waiting_state",
    "waiting",
    "next_lapse",
    "last_entered_at",
}


def new_tenant(engine, name):
    """A tenant with its one default space, as `seeded` makes them."""
    tenant, space = uuid4(), uuid4()
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id, name) VALUES (:t, :n)"),
            {"t": tenant, "n": name},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.spaces(tenant_id, space_id, name, created_at, created_by) "
                "VALUES (:t, :s, 'Default', now(), :p)"
            ),
            {"t": tenant, "s": space, "p": uuid4()},
        )
    return tenant, space


def grant(engine, tenant, principal, role, space=None):
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.access_principals(tenant_id,principal_id) "
                "VALUES(:t,:p) ON CONFLICT DO NOTHING"
            ),
            {"t": tenant, "p": principal},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.access_role_grants"
                "(tenant_id,grant_id,principal_id,role,space_id) VALUES(:t,:g,:p,:r,:s)"
            ),
            {"t": tenant, "g": uuid4(), "p": principal, "r": role, "s": space},
        )


# A verification older than the step-up window, which a switch does not carry (#678).
LONG_AGO = timedelta(minutes=31)


def signed_in(db, clock=None, engine=None, verified_ago=timedelta(seconds=1)):
    """A session for the account, in the workspace its password principal belongs to; with
    `engine`, one whose second factor is already confirmed, `verified_ago`, should the account
    hold one. A switch carries a verification under thirty minutes old into the workspace it
    opens; `LONG_AGO` is one it does not."""
    identity = sign_in_with_password(db, "member@example.test", PASSWORD, clock=clock)
    granted = issue_session(db, identity, clock=clock)
    if granted.mfa_required and engine is not None:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO execbound.session_assurance"
                    "(tenant_id,session_id,version,verified_at,method) "
                    "SELECT :t,:s,f.version,now() - :ago,'totp' "
                    "FROM execbound.user_factors f "
                    "JOIN execbound.workspace_memberships m USING (account_id) "
                    "WHERE m.tenant_id=:t AND m.principal_id=:p"
                ),
                {
                    "t": identity.tenant_id,
                    "s": granted.session_id,
                    "p": identity.principal_id,
                    "ago": verified_ago,
                },
            )
    return granted, load_session(db, granted.token, clock=clock)


def listed(db, clock=None, engine=None, verified_ago=timedelta(seconds=1), **options):
    granted, session = signed_in(db, clock, engine, verified_ago)
    return workspaces.list_workspaces(
        db, session, granted.account_token, clock=clock, waiting=True, **options
    )


def by_tenant(items):
    return {item["tenant_id"]: item for item in items}


@pytest.fixture
def three(db, admin_engine, seeded):
    """An account that is ADMIN in A, a viewer in B (and an approver in one of B's spaces), and
    an approver in C, signed in to A."""
    a, b = seeded["tenants"]
    principal, _ = enroll(admin_engine, a, kind="ADMIN")
    account = adopt(db, a, principal)
    in_b = membership_in(admin_engine, account, b)
    grant(admin_engine, b, in_b, "viewer")
    grant(admin_engine, b, in_b, "approver", seeded["spaces"][1])
    c, _ = new_tenant(admin_engine, "Third workspace")
    in_c = membership_in(admin_engine, account, c)
    grant(admin_engine, c, in_c, "approver")
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.tenants SET name='Team <script>' WHERE tenant_id=:t"), {"t": b}
        )
    return {
        "account": account,
        "principal": principal,
        "a": a,
        "b": b,
        "c": c,
        "in_b": in_b,
        "in_c": in_c,
    }


def test_xw1_each_workspace_answers_its_own_kind_and_workspace_roles(db, three):
    items = listed(db)
    assert [item["tenant_id"] for item in items] == [three["a"], three["b"], three["c"]]
    for item in items:
        assert set(item) == FIELDS
    found = by_tenant(items)
    assert found[three["a"]]["current"] is True
    assert found[three["a"]]["kind"] == "ADMIN"
    assert found[three["a"]]["roles"] == ["administrator", "approver"]
    assert (found[three["a"]]["waiting_state"], found[three["a"]]["waiting"]) == ("current", None)
    # The approver grant in one of B's spaces is not a role across B.
    assert found[three["b"]]["kind"] == "HUMAN_APPROVER"
    assert found[three["b"]]["roles"] == ["viewer"]
    assert found[three["b"]]["name"] == "Team <script>"
    assert found[three["c"]]["roles"] == ["approver"]
    for tenant in (three["b"], three["c"]):
        assert found[tenant]["current"] is False
        assert found[tenant]["entry"] == "open"
        assert found[tenant]["waiting_state"] == "counted"
        assert (found[tenant]["waiting"], found[tenant]["next_lapse"]) == (0, None)


def test_sn10_the_workspace_list_carries_the_last_entry(db, admin_engine, three):
    granted, session = signed_in(db)
    token = granted.account_token
    assert token is not None
    into_b = workspaces.switch_workspace(db, session, token, three["b"])
    back = workspaces.switch_workspace(db, load_session(db, into_b.token), token, three["a"])
    items = workspaces.list_workspaces(db, load_session(db, back.token), token, waiting=True)
    with admin_engine.connect() as conn:
        stamped = dict(
            conn.execute(
                text(
                    "SELECT tenant_id, last_entered_at FROM execbound.workspace_memberships "
                    "WHERE account_id=:a"
                ),
                {"a": three["account"]},
            ).all()
        )
    found = by_tenant(items)
    for tenant in (three["a"], three["b"], three["c"]):
        assert found[tenant]["last_entered_at"] == stamped[tenant]
    # A was entered last (the switch back), B before it, and C never.
    assert found[three["a"]]["last_entered_at"] > found[three["b"]]["last_entered_at"]
    assert found[three["c"]]["last_entered_at"] is None


def _policy(engine, tenant, requirement, by):
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.account_security_policy"
                "(tenant_id,requirement,changed_at,changed_by) VALUES(:t,:r,now(),:p) "
                "ON CONFLICT (tenant_id) DO UPDATE SET requirement=excluded.requirement"
            ),
            {"t": tenant, "r": requirement, "p": by},
        )


def _factor(engine, account, tenant, principal):
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.user_factors"
                "(account_id, tenant_id, principal_id, sealed, key_id, enabled_at) "
                "VALUES (:a, :t, :p, 'sealed', 'key', now())"
            ),
            {"a": account, "t": tenant, "p": principal},
        )


def _directory(db, engine, tenant):
    from test_directory_store import RING, FixedClock, enabled, person

    from execbound.directory import DirectoryConfig

    directory_admin = person(engine, tenant, "ADMIN")
    provider = enabled(
        db,
        DirectoryConfig(RING, "https://app.example"),
        {"tenant": tenant, "admin": directory_admin},
        FixedClock(),
    )
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.identity_providers SET require_sign_in=true "
                "WHERE tenant_id=:t AND provider_id=:p"
            ),
            {"t": tenant, "p": provider},
        )


@pytest.fixture
def statements(db):
    """Every statement the call runs, with the tenant setting it ran under, read on the same
    connection inside the call's own transaction, where a transaction-local setting lives."""
    seen = []

    def record(conn, cursor, statement, parameters, context, executemany):
        raw = cursor.connection.cursor()
        raw.execute("SELECT current_setting('execbound.tenant_id', true)")
        setting = raw.fetchone()[0]
        raw.close()
        seen.append((statement, dict(parameters or {}), setting))

    event.listen(db.engine, "before_cursor_execute", record)
    yield seen
    event.remove(db.engine, "before_cursor_execute", record)


def _counts_in(seen, tenant):
    return [
        statement
        for statement, _, setting in seen
        if "effective_approval_scopes" in statement and setting == str(tenant)
    ]


def test_xw3_entry_says_what_entering_asks_and_withholds_the_count(
    db, admin_engine, three, statements
):
    b, c = three["b"], three["c"]
    _directory(db, admin_engine, b)
    found = by_tenant(listed(db))
    assert found[b]["entry"] == "directory"
    assert found[c]["entry"] == "open"
    # Every workspace asks for a factor, and the account has none: it would have to set one up.
    _policy(admin_engine, c, "all", three["in_c"])
    statements.clear()
    found = by_tenant(listed(db))
    assert found[c]["entry"] == "enrol"
    assert _counts_in(statements, c) == [] and _counts_in(statements, b) == []
    # Administrators only: the account is a member there, not an administrator.
    _policy(admin_engine, c, "admins", three["in_c"])
    assert by_tenant(listed(db))[c]["entry"] == "open"
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.principals SET kind='ADMIN' "
                "WHERE tenant_id=:t AND principal_id=:p"
            ),
            {"t": c, "p": three["in_c"]},
        )
        conn.execute(
            text(
                "UPDATE execbound.access_role_grants SET role='administrator' "
                "WHERE tenant_id=:t AND principal_id=:p"
            ),
            {"t": c, "p": three["in_c"]},
        )
    found = by_tenant(listed(db))
    assert (found[c]["kind"], found[c]["entry"]) == ("ADMIN", "enrol")
    # Once the account holds a factor, every session it opens elsewhere asks for it, unless it
    # was entered on this session within the step-up window.
    _factor(admin_engine, three["account"], three["a"], three["principal"])
    statements.clear()
    found = by_tenant(listed(db, engine=admin_engine, verified_ago=LONG_AGO))
    assert found[b]["entry"] == "directory"
    assert found[c]["entry"] == "factor"
    for tenant in (b, c):
        assert found[tenant]["waiting_state"] == "withheld"
        assert (found[tenant]["waiting"], found[tenant]["next_lapse"]) == (None, None)
        assert _counts_in(statements, tenant) == []


def test_xw3_a_factor_turns_every_other_open_workspace_into_factor(db, admin_engine, three):
    _factor(admin_engine, three["account"], three["a"], three["principal"])
    found = by_tenant(listed(db, engine=admin_engine, verified_ago=LONG_AGO))
    assert found[three["b"]]["entry"] == "factor"
    assert found[three["c"]]["entry"] == "factor"


def test_xw3_a_recent_verification_opens_what_a_switch_would_carry_into(
    db, admin_engine, three, statements
):
    """A switch carries a verification under thirty minutes old, of the factor the account
    holds now, into the workspace it opens: those workspaces ask for nothing more, and are
    counted. A directory requirement is never carried."""
    b, c = three["b"], three["c"]
    _factor(admin_engine, three["account"], three["a"], three["principal"])
    _directory(db, admin_engine, b)
    statements.clear()
    found = by_tenant(listed(db, engine=admin_engine, verified_ago=timedelta(minutes=29)))
    assert (found[c]["entry"], found[c]["waiting_state"]) == ("open", "counted")
    assert (found[b]["entry"], found[b]["waiting_state"]) == ("directory", "withheld")
    assert _counts_in(statements, b) == []


def test_xw3_inside_sets_the_tenant_and_then_the_callers_back(db, seeded):
    a, b = seeded["tenants"]
    with db.transaction(a) as conn:
        read = text("SELECT current_setting('execbound.tenant_id',true)")
        with workspaces._inside(conn, b):
            assert conn.execute(read).scalar_one() == str(b)
        assert conn.execute(read).scalar_one() == str(a)


def test_xw3_an_error_inside_a_workspace_is_the_error_raised(db, three, monkeypatch):
    original = workspaces.entry_proof

    def failing(conn, *args):
        if failing.once:
            failing.once = False
            conn.execute(text("SELECT 1/0"))
        return original(conn, *args)

    failing.once = True
    monkeypatch.setattr(workspaces, "entry_proof", failing)
    with pytest.raises(DataError, match="division by zero"):
        listed(db)


@pytest.fixture
def world_member(db, admin_engine, seeded, world):
    """An account signed in to the second seeded tenant that is also the world's approver."""
    first, second = seeded["tenants"]
    assert world["identity"].tenant_id == first
    principal, _ = enroll(admin_engine, second)
    account = adopt(db, second, principal)
    membership_in(admin_engine, account, first, principal=world["human"].principal_id)
    return account


def _fresh_queue_length(db, runtime, world):
    granted, session = signed_in(db, world["clock"])
    switched = workspaces.switch_workspace(
        db, session, granted.account_token, world["identity"].tenant_id, clock=world["clock"]
    )
    fresh = load_session(db, switched.token, clock=world["clock"])
    rows = human.records(runtime, fresh, pending=True, reviewing=True, limit=PAGE_SIZE + 1)
    return [row for row in rows if row["approval"]]


def _hold(runtime, world, request):
    return runtime.execute(world["identity"], request.model_dump_json().encode())


def _group_rule(engine, world, canonical):
    tenant = world["identity"].tenant_id
    group, rule = uuid4(), uuid4()
    values = {
        "t": tenant,
        "g": group,
        "r": rule,
        "p": world["human"].principal_id,
        "c": canonical,
    }
    with engine.begin() as conn:
        space = conn.execute(
            text("SELECT space_id FROM execbound.spaces WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one()
        values["s"] = space
        for statement in (
            "INSERT INTO execbound.access_groups(tenant_id, group_id, name) "
            "VALUES (:t, :g, 'Responders')",
            "INSERT INTO execbound.access_group_members(tenant_id, group_id, principal_id) "
            "VALUES (:t, :g, :p)",
            "INSERT INTO execbound.approval_rules(tenant_id, rule_id, name, space_id, group_id) "
            "VALUES (:t, :r, 'Endpoint response', :s, :g)",
            "INSERT INTO execbound.approval_rule_actions(tenant_id, rule_id, action) "
            "VALUES (:t, :r, 'endpoint.isolate')",
            "INSERT INTO execbound.approval_rule_targets(tenant_id, rule_id, canonical_target_id) "
            "VALUES (:t, :r, :c)",
        ):
            conn.execute(text(statement), values)


def _target_of(engine, world, view):
    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT canonical_target_id FROM execbound.executions "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"t": world["identity"].tenant_id, "e": view.execution_id},
        ).scalar_one()


def _unassign(engine, world, canonical):
    with engine.begin() as conn:
        conn.execute(
            text(
                "DELETE FROM execbound.approval_scopes WHERE tenant_id=:t "
                "AND approver_id=:p AND canonical_target_id=:c"
            ),
            {"t": world["identity"].tenant_id, "p": world["human"].principal_id, "c": canonical},
        )


def _deadline(engine, world, view):
    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT expires_at FROM execbound.approvals WHERE tenant_id=:t AND approval_id=:a"
            ),
            {"t": world["identity"].tenant_id, "a": view.approval_id},
        ).scalar_one()


def _seat_elsewhere(engine, world, view):
    """Move a held execution, and its assignment, into a space the approver is not in."""
    from space_fixtures import make_space, place

    tenant = world["identity"].tenant_id
    canonical = _target_of(engine, world, view)
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        second = make_space(conn, tenant, "Customer B")
        place(conn, tenant, "executions", "execution_id", view.execution_id, second)
        conn.execute(
            text(
                "UPDATE execbound.approval_scopes SET space_id=:s WHERE tenant_id=:t "
                "AND approver_id=:p AND canonical_target_id=:c"
            ),
            {"t": tenant, "s": second, "p": world["human"].principal_id, "c": canonical},
        )


def test_xw2_the_count_is_the_pending_queue_a_fresh_session_there_reads(
    db, runtime, admin_engine, seeded, world, world_member
):
    clock = world["clock"]
    tenant = world["identity"].tenant_id
    activate(db, world, limits=())
    found = by_tenant(listed(db, clock))
    assert (found[tenant]["waiting_state"], found[tenant]["waiting"]) == ("counted", 0)
    assert found[tenant]["next_lapse"] is None
    direct = pending(runtime, world)
    held = [
        _hold(runtime, world, request)
        for request in targets(admin_engine, world, 6, production=True)
    ]
    by_rule, unassigned, expired, decided, elsewhere, kept = held
    # Through an approval rule's group rather than a direct assignment.
    rule_target = _target_of(admin_engine, world, by_rule)
    _unassign(admin_engine, world, rule_target)
    _group_rule(admin_engine, world, rule_target)
    # Waiting for somebody else: the administrator holds the assignment, the account does not.
    elsewhere_target = _target_of(admin_engine, world, unassigned)
    _unassign(admin_engine, world, elsewhere_target)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.approval_scopes"
                "(tenant_id,approver_id,canonical_target_id,action,space_id) "
                "SELECT :t,:p,:c,'endpoint.isolate',space_id FROM execbound.spaces "
                "WHERE tenant_id=:t"
            ),
            {"t": tenant, "p": world["admin"].principal_id, "c": elsewhere_target},
        )
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.approvals SET expires_at=:x WHERE tenant_id=:t AND approval_id=:a"
            ),
            {"t": tenant, "a": expired.approval_id, "x": clock.now() - timedelta(seconds=1)},
        )
    decide_approval(db, world["human"], decided.approval_id, "DENY", clock)
    _seat_elsewhere(admin_engine, world, elsewhere)
    item = by_tenant(listed(db, clock))[tenant]
    queue = _fresh_queue_length(db, runtime, world)
    assert {row["approval"]["approval_id"] for row in queue} == {
        direct.approval_id,
        by_rule.approval_id,
        kept.approval_id,
    }
    assert item["waiting"] == len(queue) == 3
    earliest = min(_deadline(admin_engine, world, view) for view in (direct, by_rule, kept))
    assert item["next_lapse"] == earliest.replace(second=0, microsecond=0)


def test_xw2_a_principal_without_the_decide_permission_has_nothing_waiting(
    db, runtime, admin_engine, seeded, world, world_member
):
    clock = world["clock"]
    tenant = world["identity"].tenant_id
    pending(runtime, world)
    assert by_tenant(listed(db, clock))[tenant]["waiting"] == 1
    # Managed, as a viewer: it reads the workspace and may decide nothing in it.
    grant(admin_engine, tenant, world["human"].principal_id, "viewer")
    item = by_tenant(listed(db, clock))[tenant]
    assert (item["waiting_state"], item["waiting"], item["next_lapse"]) == ("counted", 0, None)
    assert _fresh_queue_length(db, runtime, world) == []


def test_xw4_nothing_of_the_other_workspace_crosses(
    db, runtime, admin_engine, seeded, world, world_member, statements
):
    from console_api_fixtures import API, ORIGIN, console_config
    from fastapi.testclient import TestClient

    from execbound.app import create_app

    clock = world["clock"]
    tenant, second = seeded["tenants"]
    activate(db, world, limits=())
    held = [pending(runtime, world)] + [
        _hold(runtime, world, request)
        for request in targets(admin_engine, world, 2, production=True)
    ]
    # A third workspace after the world's, so a setting left behind by one would be seen.
    third, _ = new_tenant(admin_engine, "Third workspace")
    membership_in(admin_engine, world_member, third)
    granted, _ = signed_in(db, clock)
    statements.clear()
    with TestClient(
        create_app(db, runtime=runtime, human=console_config()), base_url=ORIGIN
    ) as client:
        client.cookies.set("eb_session", granted.token, domain="127.0.0.1")
        client.cookies.set("eb_csrf", granted.csrf_token, domain="127.0.0.1")
        client.cookies.set("eb_account", granted.account_token, domain="127.0.0.1")
        response = client.get(API + "/session/workspaces")
        assert response.status_code == 200, response.text
        seen = list(statements)
        body = response.text
        client.cookies.delete("eb_account", domain="127.0.0.1")
        assert client.get(API + "/session/workspaces").status_code == 401
    found = {item["tenant_id"]: item for item in json.loads(body)["workspaces"]}
    assert found[str(tenant)]["waiting"] == 3
    assert (found[str(second)]["waiting_state"], found[str(second)]["waiting"]) == (
        "current",
        None,
    )
    with admin_engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT e.execution_id, e.request_number, e.canonical_target_id, "
                "a.approval_id, s.name AS space FROM execbound.executions e "
                "JOIN execbound.approvals a ON a.tenant_id=e.tenant_id "
                "AND a.execution_id=e.execution_id JOIN execbound.spaces s "
                "ON s.tenant_id=e.tenant_id AND s.space_id=e.space_id WHERE e.tenant_id=:t"
            ),
            {"t": tenant},
        ).all()
        labels = conn.execute(
            text("SELECT label FROM execbound.principals WHERE tenant_id=:t AND label IS NOT NULL"),
            {"t": tenant},
        ).scalars()
        secrets = {str(world["target"]), str(world["identity"].principal_id), *labels}
    assert len(rows) == len(held)
    for row in rows:
        secrets |= {
            str(row.execution_id),
            str(row.approval_id),
            str(row.canonical_target_id),
            f"EB-{row.request_number}",
            row.space,
        }
    secrets.add("device-01")
    for value in secrets:
        assert value not in body, value
    # Every statement naming a membership's tenant ran under that tenant's own setting, and
    # every read of the setting, before a workspace is entered, saw the caller's.
    members = {str(tenant), str(second), str(third)}
    checked = 0
    for statement, parameters, setting in seen:
        if "set_config('execbound.tenant_id'" in statement:
            continue
        named = parameters.get("t")
        if named is not None and str(named) in members:
            assert setting == str(named), statement
            checked += 1
        if statement.strip() == "SELECT current_setting('execbound.tenant_id',true)":
            assert setting == str(second), statement
    assert checked > 0


def test_xw4_a_removed_membership_and_an_inactive_tenant_are_absent(db, admin_engine, three):
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.workspace_memberships SET active=false,version=version+1 "
                "WHERE account_id=:a AND tenant_id=:t"
            ),
            {"a": three["account"], "t": three["b"]},
        )
        conn.execute(
            text("UPDATE execbound.tenants SET active=false WHERE tenant_id=:t"),
            {"t": three["c"]},
        )
    assert [item["tenant_id"] for item in listed(db)] == [three["a"]]


def test_xw4_a_personal_access_token_is_refused_the_list():
    from execbound.surfaces.console_api.token_rules import TOKEN_REFUSED

    assert (
        "/api/console/v1/session/workspaces",
        "GET",
    ) in TOKEN_REFUSED


def test_xw5_counting_stops_at_the_caps(db, runtime, admin_engine, seeded, world, world_member):
    clock = world["clock"]
    tenant = world["identity"].tenant_id
    activate(db, world, limits=())
    for request in targets(admin_engine, world, 120, production=True):
        _hold(runtime, world, request)
    others = [new_tenant(admin_engine, f"Workspace {index:02d}")[0] for index in range(28)]
    for other in others:
        membership_in(admin_engine, world_member, other)
    items = listed(db, clock)
    assert len(items) == 30
    assert by_tenant(items)[tenant]["waiting"] == workspaces.WAITING_CAP == 100
    states = [item["waiting_state"] for item in items]
    assert states[: workspaces.COUNTED_WORKSPACES].count("not_counted") == 0
    assert set(states[workspaces.COUNTED_WORKSPACES :]) == {"not_counted"}
    for item in items[workspaces.COUNTED_WORKSPACES :]:
        assert (item["waiting"], item["next_lapse"]) == (None, None)


def test_xw2_next_lapse_is_floored_and_never_overstates(
    db, runtime, admin_engine, world, world_member
):
    view = pending(runtime, world)
    deadline = _deadline(admin_engine, world, view)
    item = by_tenant(listed(db, world["clock"]))[world["identity"].tenant_id]
    assert item["next_lapse"].second == 0 and item["next_lapse"].microsecond == 0
    assert item["next_lapse"] <= deadline < item["next_lapse"] + timedelta(minutes=1)
