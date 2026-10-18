# SPDX-License-Identifier: AGPL-3.0-only
"""Home, value reporting and the board (#678): what the server reads and counts.

HV1 to HV7 and HV10. A lapse is classified on the server's clock and nothing is written:
the overview, the board and the execution views read an approval past its deadline as
lapsed (nobody decided it) or approved but not used, before and after the recovery run's
sweep. "Effect unknown" is its own open figure. Every row is on real PostgreSQL.
"""

import json
from datetime import timedelta
from uuid import UUID, uuid4

from console_api_fixtures import API, console_client
from sqlalchemy import text
from test_approval_deadline import deadline, long_facts
from test_execution import activate as activate  # noqa: F401
from test_execution import provision_identity, targets
from test_execution import registry as registry  # noqa: F401
from test_execution import world as world  # noqa: F401
from test_protected_path import connector as connector  # noqa: F401
from test_protected_path import live_provider as live_provider  # noqa: F401
from test_runtime import runtime as runtime  # noqa: F401

from execbound.execution import admit, decide_approval
from execbound.recovery_run import expire_approval, recover
from execbound.surfaces import outcomes, sessions
from execbound.surfaces.console_api.overview import figures
from execbound.surfaces.dashboard import overview

DEADLINE = 600
GRACE = timedelta(seconds=301)


def session_of(db, world, identity):
    return sessions.load_session(
        db,
        sessions.issue_session(db, identity, clock=world["clock"]).token,
        clock=world["clock"],
    )


def ring(world, connector):
    return {(world["identity"].tenant_id, world["account"]): connector}


def held_requests(db, admin_engine, world, count):
    """`count` requests on targets of their own, each held for a person."""
    views = []
    for body in targets(admin_engine, world, count=count, production=True):
        view = admit(db, world["identity"], body, world["clock"]).view
        assert view.state == "PENDING_APPROVAL", view.state
        views.append(view)
    return views


def audit_count(admin_engine, tenant):
    with admin_engine.connect() as conn:
        return conn.execute(
            text("SELECT count(*) FROM execbound.audit_events WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one()


def approval_states(admin_engine, tenant):
    with admin_engine.connect() as conn:
        return dict(
            conn.execute(
                text(
                    "SELECT approval_id, state FROM execbound.approvals WHERE tenant_id=:t "
                    "ORDER BY approval_id"
                ),
                {"t": tenant},
            ).all()
        )


def lapsed_listed(admin_engine, world):
    """The lapses still awaiting the sweep, read with the one predicate Home's link opens."""
    with admin_engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT count(*) FROM execbound.executions e WHERE e.tenant_id=:t "
                "AND e.state='PENDING_APPROVAL' AND " + outcomes.PREDICATES["lapsed"]
            ),
            {"t": world["identity"].tenant_id, "now": world["clock"].now()},
        ).scalar_one()


def backdate(admin_engine, tenant, execution_id, by):
    """An approval that lapsed long ago and was never swept: its times moved back."""
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.approvals SET expires_at = expires_at - :by, "
                "created_at = created_at - :by WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"t": tenant, "e": execution_id, "by": by},
        )
        conn.execute(
            text(
                "UPDATE execbound.executions SET changed_at = changed_at - :by, "
                "created_at = created_at - :by WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"t": tenant, "e": execution_id, "by": by},
        )


def move(admin_engine, tenant, execution_id, state, *, back=timedelta(0)):
    """A row moved to `state` directly, as a test of the read alone may."""
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.executions SET state=:s, changed_at = changed_at - :by "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"t": tenant, "e": execution_id, "s": state, "by": back},
        )


def expiry(admin_engine, tenant, execution_id):
    with admin_engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT expires_at FROM execbound.approvals WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"t": tenant, "e": execution_id},
        ).scalar_one()


def bucket_of(series, moment):
    """The start of the series bucket that holds `moment`."""
    starts = [item["start"] for item in series]
    return max(start for start in starts if start <= moment)


def test_hv1_a_lapsed_approval_reads_as_lapsed_before_and_after_the_sweep(
    db, world, runtime, admin_engine, connector
):
    tenant = world["identity"].tenant_id
    long_facts(db, world)
    deadline(db, world, DEADLINE)
    undecided, approved, old = held_requests(db, admin_engine, world, 3)
    decide_approval(db, world["human"], approved.approval_id, "APPROVE", world["clock"])
    backdate(admin_engine, tenant, old.execution_id, timedelta(days=8))
    world["clock"].value += timedelta(seconds=DEADLINE) + GRACE
    admin = session_of(db, world, world["admin"])

    before_events = audit_count(admin_engine, tenant)
    before_approvals = approval_states(admin_engine, tenant)
    data = overview(runtime, admin, step=timedelta(hours=6), offset=timedelta(0))
    again = overview(runtime, admin, step=timedelta(hours=6), offset=timedelta(0))
    assert audit_count(admin_engine, tenant) == before_events
    assert approval_states(admin_engine, tenant) == before_approvals
    assert again["counts"] == data["counts"]

    assert data["pending"] == 0
    # Both undecided lapses, the old one included; never the approved one.
    assert data["lapsed"] == 2
    assert data["lapsed"] == lapsed_listed(admin_engine, world)
    window = figures(data["counts"])
    # The two in-window rows; the old lapse is in no window figure.
    assert window.stale == 2 and window.held == 0
    assert data["counts"].get("LAPSED") == 1 and data["counts"].get("UNUSED") == 1
    lapsed_at = expiry(admin_engine, tenant, undecided.execution_id)
    bucket = bucket_of(data["series"], lapsed_at)
    in_bucket = next(item for item in data["series"] if item["start"] == bucket)
    assert in_bucket["counts"].get("LAPSED") == 1 and in_bucket["counts"].get("UNUSED") == 1
    assert sum(sum(item["counts"].values()) for item in data["series"]) == 2

    with console_client(db, runtime, admin_engine, world["admin"]) as page:
        body = page.get(API + "/overview").json()
        assert body["pending_approvals"] == 0 and body["lapsed_approvals"] == 2
        # The count and the list Home's link opens are one predicate.
        listed = page.get(API + "/executions?outcome=lapsed&state=PENDING_APPROVAL").json()
        assert len(listed["items"]) == body["lapsed_approvals"]
        assert body["figures"]["stale"] == 2 and body["figures"]["held"] == 0
        assert body["awaiting"] == []

    # The sweep of the two in-window lapses leaves the window's figures as they were.
    assert expire_approval(db, world["admin"], undecided.execution_id, world["clock"])
    assert expire_approval(db, world["admin"], approved.execution_id, world["clock"])
    swept = overview(runtime, admin, step=timedelta(hours=6), offset=timedelta(0))
    assert figures(swept["counts"]) == window
    assert swept["lapsed"] == 1 and swept["pending"] == 0
    # The old one, swept now, is a change made now: it counts from the sweep.
    assert recover(db, world["admin"], ring(world, connector), clock=world["clock"]).expired == 1
    final = overview(runtime, admin, step=timedelta(hours=6), offset=timedelta(0))
    assert final["lapsed"] == 0 and final["pending"] == 0
    assert final["counts"].get("STALE_AUTHORIZATION") == 3


def test_hv1b_an_approval_inside_its_deadline_is_pending_and_an_approved_one_is_not(
    db, world, runtime, admin_engine
):
    long_facts(db, world)
    deadline(db, world, DEADLINE)
    waiting, approved = held_requests(db, admin_engine, world, 2)
    decide_approval(db, world["human"], approved.approval_id, "APPROVE", world["clock"])
    admin = session_of(db, world, world["admin"])
    data = overview(runtime, admin)
    assert figures(data["counts"]).held == 2
    assert data["pending"] == 1 and data["lapsed"] == 0
    assert waiting.approval_id is not None


def test_hv2_an_unknown_effect_is_its_own_open_figure(db, world, runtime, admin_engine):
    tenant = world["identity"].tenant_id
    rows = held_requests(db, admin_engine, world, 4)
    move(admin_engine, tenant, rows[0].execution_id, "FAILED_EFFECT_UNKNOWN")
    move(admin_engine, tenant, rows[1].execution_id, "STALE_AUTHORIZATION")
    move(admin_engine, tenant, rows[2].execution_id, "FAILED_NOT_EXECUTED")
    # Open until a person corrects it, however old it is.
    move(
        admin_engine, tenant, rows[3].execution_id, "FAILED_EFFECT_UNKNOWN", back=timedelta(days=10)
    )
    admin = session_of(db, world, world["admin"])
    data = overview(runtime, admin, step=timedelta(hours=6), offset=timedelta(0))
    window = figures(data["counts"])
    assert window.unknown == 2 and window.stale == 2
    assert window.decisions == window.unknown + window.stale
    totals = {"unknown": 0, "stale": 0}
    for item in data["series"]:
        found = figures(item["counts"])
        totals["unknown"] += found.unknown
        totals["stale"] += found.stale
    # The series is windowed by last change: the old effect-unknown row is in no bucket.
    assert totals == {"unknown": 1, "stale": 2}
    with console_client(db, runtime, admin_engine, world["admin"]) as page:
        listed = page.get(API + "/executions?state=FAILED_EFFECT_UNKNOWN").json()
        assert len(listed["items"]) == 2
        body = page.get(API + "/overview").json()
        assert body["figures"]["unknown"] == 2


def test_hv2b_last_request_at_is_null_until_a_request_and_scoped(db, world, runtime, admin_engine):
    tenant = world["identity"].tenant_id
    admin = session_of(db, world, world["admin"])
    assert overview(runtime, admin)["last_request_at"] is None
    [view] = held_requests(db, admin_engine, world, 1)
    with admin_engine.connect() as conn:
        created = conn.execute(
            text(
                "SELECT created_at FROM execbound.executions WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"t": tenant, "e": view.execution_id},
        ).scalar_one()
    assert overview(runtime, admin)["last_request_at"] == created
    outsider = provision_identity(admin_engine, db, tenant, "HUMAN_APPROVER", world["clock"].now())
    assert overview(runtime, session_of(db, world, outsider))["last_request_at"] is None
    with console_client(db, runtime, admin_engine, world["admin"]) as page:
        body = page.get(API + "/overview").json()
        assert body["last_request_at"] is not None


def test_hv3_the_board_counts_a_lapsed_request_apart_from_a_held_one(
    db, world, runtime, admin_engine
):
    long_facts(db, world)
    deadline(db, world, DEADLINE)
    lapsing, approved = held_requests(db, admin_engine, world, 2)
    decide_approval(db, world["human"], approved.approval_id, "APPROVE", world["clock"])
    world["clock"].value += timedelta(seconds=DEADLINE + 1)
    [waiting] = held_requests(db, admin_engine, world, 1)
    # The viewer's day placed so its midnight is hours away, whatever the hour of the run.
    now = world["clock"].now()
    minutes = 12 * 60 - (now.hour * 60 + now.minute)
    with console_client(db, runtime, admin_engine, world["admin"]) as page:
        response = page.get(API + f"/board?window=1h&utc_offset={minutes}")
        assert response.status_code == 200, response.text
        body = response.json()
    for period in ("window", "today"):
        assert body[period]["held"] == 1, (period, body[period])
        assert body[period]["lapsed"] == 1, (period, body[period])
    shots = {shot["execution_id"]: shot for shot in body["shots"]}
    assert shots[str(waiting.execution_id)]["word"] == "held for a person"
    assert shots[str(lapsing.execution_id)]["lapsed"] is True
    assert shots[str(lapsing.execution_id)]["word"] == "lapsed"
    assert shots[str(approved.execution_id)]["unused"] is True
    assert shots[str(approved.execution_id)]["lapsed"] is False


def test_hv4_the_record_says_its_approval_lapsed_by_the_servers_clock(
    db, world, runtime, admin_engine, connector
):
    tenant = world["identity"].tenant_id
    long_facts(db, world)
    deadline(db, world, DEADLINE)
    undecided, approved, inside = held_requests(db, admin_engine, world, 3)
    decide_approval(db, world["human"], approved.approval_id, "APPROVE", world["clock"])

    def read(page, view):
        record = page.get(API + f"/executions/{view.execution_id}").json()["approval"]
        listed = page.get(API + "/executions").json()["items"]
        [row] = [item for item in listed if item["execution_id"] == str(view.execution_id)]
        assert row["approval"]["lapsed"] == record["lapsed"]
        assert row["approval"]["unused"] == record["unused"]
        return record["lapsed"], record["unused"]

    with console_client(db, runtime, admin_engine, world["admin"]) as page:
        for view in (undecided, approved, inside):
            assert read(page, view) == (False, False)
        events = audit_count(admin_engine, tenant)
        # The clock alone crosses the deadline: the answer flips and nothing is written.
        world["clock"].value += timedelta(seconds=DEADLINE + 1)
        assert read(page, undecided) == (True, False)
        assert read(page, approved) == (False, True)
        assert audit_count(admin_engine, tenant) == events
    [later] = held_requests(db, admin_engine, world, 1)
    world["clock"].value += GRACE
    # The three admitted first are past their deadline by now; the later one is not.
    assert recover(db, world["admin"], ring(world, connector), clock=world["clock"]).expired == 3
    with console_client(db, runtime, admin_engine, world["admin"]) as page:
        # After the sweep, on both sides of which the record says the same.
        assert read(page, undecided) == (True, False)
        assert read(page, approved) == (False, True)
        assert read(page, later) == (False, False)


def ruleset_denial(db, runtime, admin_engine, world):
    """A denial under a bundle written as rules: the domain controller rule matches."""
    from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
    from execbound_harness.demo import endpoint_ruleset_bundle

    bundle = endpoint_ruleset_bundle(
        world["identity"].tenant_id, world["account"], mapping_version="map-v1"
    )
    create_bundle(db, world["admin"], bundle, world["clock"])
    validate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    activate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    [tier_zero] = targets(admin_engine, world, count=1, production=True)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.resources SET role='domain_controller' "
                "WHERE tenant_id=:t AND resource_id=:r"
            ),
            {"t": world["identity"].tenant_id, "r": UUID(tier_zero.target.value)},
        )
    view = runtime.execute(world["identity"], tier_zero.model_dump_json().encode())
    assert view.state == "DENIED"
    return bundle, view


def test_hv10_a_reason_names_the_rules_it_read_and_the_record_its_bundle(
    db, world, runtime, admin_engine, live_provider, connector
):
    bundle, refused = ruleset_denial(db, runtime, admin_engine, world)
    [production] = targets(admin_engine, world, count=1, production=True)
    held = runtime.execute(world["identity"], production.model_dump_json().encode())
    assert held.state == "PENDING_APPROVAL"
    with console_client(db, runtime, admin_engine, world["admin"]) as page:
        record = page.get(API + f"/executions/{refused.execution_id}").json()
        assert record["bundle_id"] == str(bundle.bundle_id)
        assert record["policy_readable"] is True
        [reason] = [item for item in record["reasons"] if item["code"] == "NOT_AUTHORIZED"]
        assert reason["rules"] == ["isolate-never-domain-controller"]
        assert reason["rule_id"] is None
        holding = page.get(API + f"/executions/{held.execution_id}").json()
        named = [item for item in holding["obligations"] if item["rule_id"]]
        assert named and all(item["rules"] == [item["rule_id"]] for item in named)
        assert all(item["rules"] == [item["rule_id"]] for item in holding["limits"])
        assert page.get(API + f"/policy/{bundle.bundle_id}/rules").status_code == 200


def test_hv10_a_limit_names_its_rule_and_a_cedar_bundle_names_none():
    from execbound.surfaces.console_api.executions import reason_views
    from execbound_harness.soc_demo import soc_bundle

    bundle = soc_bundle(uuid4(), uuid4(), uuid4(), mapping_version="map-v1")
    [limit] = bundle.limits[:1]
    [view] = reason_views([f"HARD_LIMIT:{limit.rule_id}"], bundle)
    assert view.rule_id == limit.rule_id and view.rules == [limit.rule_id]
    [cedar] = reason_views(["NOT_AUTHORIZED"], bundle)
    assert cedar.rules == [] and cedar.rule_id is None
    assert cedar.sentence.startswith("No rule in the active bundle permits")


def test_hv10b_the_rule_link_is_offered_only_where_the_rules_read_would_answer(
    db, world, runtime, admin_engine, live_provider, connector
):
    bundle, refused = ruleset_denial(db, runtime, admin_engine, world)
    # The approver reads the record in scope and may not open the policy that decided it.
    with admin_engine.begin() as conn:
        canonical = conn.execute(
            text(
                "SELECT canonical_target_id FROM execbound.executions "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"t": world["identity"].tenant_id, "e": refused.execution_id},
        ).scalar_one()
        conn.execute(
            text(
                "INSERT INTO execbound.approval_scopes "
                "(tenant_id,approver_id,canonical_target_id,action,space_id) "
                "VALUES (:t,:p,:c,'endpoint.isolate', "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t)) "
                "ON CONFLICT DO NOTHING"
            ),
            {"t": world["identity"].tenant_id, "p": world["human"].principal_id, "c": canonical},
        )
    for identity, expected in ((world["admin"], True), (world["human"], False)):
        with console_client(db, runtime, admin_engine, identity) as page:
            response = page.get(API + f"/executions/{refused.execution_id}")
            assert response.status_code == 200, response.text
            readable = response.json()["policy_readable"]
            rules = page.get(API + f"/policy/{bundle.bundle_id}/rules")
            assert readable is expected
            assert (rules.status_code == 200) is readable


DENIAL_PAYLOADS = (
    {"reasons": ["NOT_AUTHORIZED"]},
    {"reasons": ["NOT_AUTHORIZED", "HARD_LIMIT:r1"]},
    {"reason": "RESOURCE_BUSY"},
    {"reason": "HUMAN_DENIED"},
    {"reasons": ["INVALID_CONTEXT"]},
    {},
    {"reasons": ["POLICY_ERROR", "NOT_AUTHORIZED"]},
    {"reasons": ["HARD_LIMIT:r2"]},
    {"reasons": ["RESOURCE_BUSY"]},
)


def test_hv5b_denial_kind_refines_the_agents_category():
    from execbound.execution.store import denial_category

    for payload in DENIAL_PAYLOADS:
        kind = outcomes.denial_kind(payload)
        category = denial_category(payload)
        if category in {"busy", "limit"}:
            assert kind == category, payload
        else:
            assert kind in {"person", "policy"}, payload
        assert (kind == "person") == (payload == {"reason": "HUMAN_DENIED"}), payload


def deny_directly(admin_engine, world, execution_id, payload):
    """A row moved to DENIED with the payload its transition recorded, as a read test may."""
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.executions SET state='DENIED' "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"t": tenant, "e": execution_id},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.execution_events "
                "(tenant_id, event_id, execution_id, actor_id, from_state, to_state, "
                "created_at, payload) VALUES (:t, :id, :e, :a, 'PENDING_APPROVAL', 'DENIED', "
                ":n, CAST(:p AS jsonb))"
            ),
            {
                "t": tenant,
                "id": uuid4(),
                "e": execution_id,
                "a": world["identity"].principal_id,
                "n": world["clock"].now(),
                "p": json.dumps(payload),
            },
        )


def test_hv5c_the_sql_kind_equals_the_python_kind(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    rows = held_requests(db, admin_engine, world, len(DENIAL_PAYLOADS))
    for view, payload in zip(rows, DENIAL_PAYLOADS, strict=True):
        deny_directly(admin_engine, world, view.execution_id, payload)
    with admin_engine.connect() as conn:
        for view, payload in zip(rows, DENIAL_PAYLOADS, strict=True):
            kind = conn.execute(
                text(
                    "SELECT " + outcomes.DENIAL_KIND_SQL + " FROM execbound.executions e "
                    "WHERE e.tenant_id=:t AND e.execution_id=:e"
                ),
                {"t": tenant, "e": view.execution_id},
            ).scalar_one()
            assert kind == outcomes.denial_kind(payload), payload
            listed = {
                key
                for key in ("refused_policy", "refused_limit", "refused_busy")
                if conn.execute(
                    text(
                        "SELECT count(*) FROM execbound.executions e "
                        "WHERE e.tenant_id=:t AND e.execution_id=:e AND " + outcomes.PREDICATES[key]
                    ),
                    {"t": tenant, "e": view.execution_id, "now": world["clock"].now()},
                ).scalar_one()
            }
            expected = {"policy": {"refused_policy"}, "limit": {"refused_limit"}}.get(
                kind, {"refused_busy"} if kind == "busy" else set()
            )
            assert listed == expected, payload


def through(admin_engine, world, execution_id, *states):
    """A row taken along a chain of states, with an event for every step."""
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        previous = "PENDING_APPROVAL"
        for index, state in enumerate(states):
            conn.execute(
                text(
                    "INSERT INTO execbound.execution_events "
                    "(tenant_id, event_id, execution_id, actor_id, from_state, to_state, "
                    "created_at, payload) VALUES (:t, :id, :e, :a, :f, :s, :n, '{}'::jsonb)"
                ),
                {
                    "t": tenant,
                    "id": uuid4(),
                    "e": execution_id,
                    "a": world["identity"].principal_id,
                    "f": previous,
                    "s": state,
                    "n": world["clock"].now() + timedelta(milliseconds=index + 1),
                },
            )
            previous = state
        conn.execute(
            text("UPDATE execbound.executions SET state=:s WHERE tenant_id=:t AND execution_id=:e"),
            {"t": tenant, "e": execution_id, "s": previous},
        )


def test_hv5d_settled_needs_a_settled_state(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    executed, unknown, corrected = held_requests(db, admin_engine, world, 3)
    through(
        admin_engine,
        world,
        executed.execution_id,
        "DISPATCH_COMMITTED",
        "INDETERMINATE",
        "EXECUTED",
    )
    through(
        admin_engine,
        world,
        unknown.execution_id,
        "DISPATCH_COMMITTED",
        "INDETERMINATE",
        "FAILED_EFFECT_UNKNOWN",
    )
    through(
        admin_engine,
        world,
        corrected.execution_id,
        "DISPATCH_COMMITTED",
        "INDETERMINATE",
        "FAILED_EFFECT_UNKNOWN",
        "FAILED_NOT_EXECUTED",
    )
    with admin_engine.connect() as conn:
        settled = set(
            conn.execute(
                text(
                    "SELECT e.execution_id FROM execbound.executions e WHERE e.tenant_id=:t AND "
                    + outcomes.PREDICATES["settled"]
                ),
                {"t": tenant},
            ).scalars()
        )
    assert settled == {executed.execution_id, corrected.execution_id}


def test_hv5e_no_request_value_reaches_the_assembled_text(db, world, runtime, admin_engine):
    import execbound.surfaces.outcomes as module

    before = (module.OUTCOME_FILTER, module.COUNT_COLUMNS)
    assert all(isinstance(value, str) for value in before)
    with console_client(db, runtime, admin_engine, world["admin"]) as page:
        response = page.get(API + "/executions?outcome=lapsed'--")
        assert response.status_code == 400 and response.json()["code"] == "INVALID_REQUEST"
    assert (module.OUTCOME_FILTER, module.COUNT_COLUMNS) == before
    public = {name for name in vars(module) if not name.startswith("_")}
    callables = {name for name in public if callable(getattr(module, name))}
    # The literals, the predicates, the two assembled constants and the one Python reading;
    # nothing public returns SQL text built from an argument.
    assert callables <= {"denial_kind", "Mapping", "Any", "Literal", "DenialKind"}
    assert {"PREDICATES", "OUTCOME_FILTER", "COUNT_COLUMNS", "DENIAL_KIND_SQL"} <= public


def allowed_requests(db, admin_engine, world, count):
    """`count` requests with no approval row, committed for dispatch.

    The world's bundle lets a few development targets through and then holds the rest under
    its budget; a held one's approval is removed and its row moved on, as a test of the read
    alone may, so every one of them reads as a request no person was asked about.
    """
    tenant = world["identity"].tenant_id
    views = []
    for body in targets(admin_engine, world, count=count):
        view = admit(db, world["identity"], body, world["clock"]).view
        if view.state == "PENDING_APPROVAL":
            with admin_engine.begin() as conn:
                conn.execute(
                    text("DELETE FROM execbound.approvals WHERE tenant_id=:t AND execution_id=:e"),
                    {"t": tenant, "e": view.execution_id},
                )
                conn.execute(
                    text(
                        "UPDATE execbound.executions SET state='DISPATCH_COMMITTED' "
                        "WHERE tenant_id=:t AND execution_id=:e"
                    ),
                    {"t": tenant, "e": view.execution_id},
                )
        else:
            assert view.state == "DISPATCH_COMMITTED", view.state
        views.append(view)
    return views


def observe(admin_engine, world, execution_id, effect, reasons=()):
    """A row moved to observe mode's record of what it would have decided."""
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.executions SET state='OBSERVED', "
                "result = jsonb_build_object('observed', CAST(:o AS jsonb)) "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {
                "t": world["identity"].tenant_id,
                "e": execution_id,
                "o": json.dumps({"effect": effect, "reasons": list(reasons)}),
            },
        )


def every_outcome(db, runtime, admin_engine, world):
    """One request of every outcome in the classification, on one injected clock."""
    long_facts(db, world)
    deadline(db, world, DEADLINE)
    tenant = world["identity"].tenant_id
    unused, lapsed = held_requests(db, admin_engine, world, 2)
    world["clock"].value += timedelta(seconds=10)
    decide_approval(db, world["human"], unused.approval_id, "APPROVE", world["clock"])
    world["clock"].value += timedelta(seconds=DEADLINE + 1)
    waiting, approved, refused, closed = held_requests(db, admin_engine, world, 4)
    world["clock"].value += timedelta(seconds=30)
    decide_approval(db, world["human"], approved.approval_id, "APPROVE", world["clock"])
    world["clock"].value += timedelta(seconds=30)
    decide_approval(db, world["human"], refused.approval_id, "DENY", world["clock"])
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.approvals SET state='INVALIDATED' "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"t": tenant, "e": closed.execution_id},
        )
        conn.execute(
            text(
                "UPDATE execbound.executions SET state='STALE_AUTHORIZATION' "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"t": tenant, "e": closed.execution_id},
        )
    (
        policy,
        limit,
        busy,
        settled,
        unknown,
        corrected,
        unsettled,
        would_refuse,
        by_limit,
        would_hold,
        would_run,
    ) = allowed_requests(db, admin_engine, world, 11)
    deny_directly(admin_engine, world, policy.execution_id, {"reasons": ["NOT_AUTHORIZED"]})
    deny_directly(
        admin_engine, world, limit.execution_id, {"reasons": ["NOT_AUTHORIZED", "HARD_LIMIT:r1"]}
    )
    deny_directly(admin_engine, world, busy.execution_id, {"reason": "RESOURCE_BUSY"})
    through(admin_engine, world, settled.execution_id, "INDETERMINATE", "EXECUTED")
    through(admin_engine, world, unknown.execution_id, "INDETERMINATE", "FAILED_EFFECT_UNKNOWN")
    through(
        admin_engine,
        world,
        corrected.execution_id,
        "INDETERMINATE",
        "FAILED_EFFECT_UNKNOWN",
        "FAILED_NOT_EXECUTED",
    )
    observe(admin_engine, world, would_refuse.execution_id, "DENY", ["NOT_AUTHORIZED"])
    observe(admin_engine, world, by_limit.execution_id, "DENY", ["HARD_LIMIT:r1"])
    observe(admin_engine, world, would_hold.execution_id, "REQUIRE_APPROVAL")
    observe(admin_engine, world, would_run.execution_id, "ELIGIBLE")
    assert unsettled.execution_id is not None
    return {
        "approved": {approved.execution_id, unused.execution_id},
        "lapsed": {lapsed.execution_id},
        "waiting": {waiting.execution_id},
        "refused_by_person": {refused.execution_id},
    }


def report_of(db, runtime, world, identity):
    from execbound.surfaces.value import for_session

    return for_session(
        runtime, session_of(db, world, identity), timedelta(days=7), timedelta(hours=6), None
    )


def test_hv5_every_outcome_is_counted_once(db, world, runtime, admin_engine, live_provider):
    expected = every_outcome(db, runtime, admin_engine, world)
    counts = report_of(db, runtime, world, world["admin"]).counts
    assert counts.requests == 17
    assert (counts.refused_policy, counts.refused_limit, counts.refused_busy) == (1, 1, 1)
    assert [(top.action, top.action_label, top.count) for top in counts.top_actions] == [
        ("endpoint.isolate", "Isolate endpoint", 1)
    ]
    # `approved` includes the one approved and not used.
    assert (counts.approved, counts.approved_unused) == (2, 1)
    assert (counts.refused_by_person, counts.lapsed, counts.closed, counts.waiting) == (1, 1, 1, 1)
    assert counts.held_total == 6
    # The reconciled row and the corrected one; the uncorrected unknown effect is not settled.
    assert (counts.settled, counts.effect_unknown, counts.unsettled_now) == (2, 1, 1)
    # `would_refuse` includes the by-limit one.
    assert (counts.would_refuse, counts.would_refuse_by_limit) == (2, 1)
    assert (counts.would_hold, counts.would_run, counts.observed_total) == (1, 1, 4)
    # 10, 30 and 60 seconds on the injected clock.
    assert counts.median_seconds_to_decide == 30
    assert counts.refused_before_decision == 0
    assert counts.quiet_sources == 0 and counts.open_findings == 0
    assert expected["approved"]


def test_hv6_every_count_opens_its_own_list(db, world, runtime, admin_engine, live_provider):
    every_outcome(db, runtime, admin_engine, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as page:
        report = page.get(API + "/report").json()
        since = report["since"].replace("+", "%2B")
        flat = {
            "refused_policy": report["refused"]["policy"],
            "refused_limit": report["refused"]["limit"],
            "refused_busy": report["refused"]["busy"],
            "approved": report["held"]["approved"],
            "approved_unused": report["held"]["approved_unused"],
            "refused_by_person": report["held"]["refused"],
            "lapsed": report["held"]["lapsed"],
            "closed": report["held"]["closed"],
            "waiting": report["held"]["waiting"],
            "settled": report["uncertain"]["settled"],
            "unsettled_now": report["uncertain"]["unsettled_now"],
            "effect_unknown": report["uncertain"]["effect_unknown"],
            "would_refuse": report["observed"]["would_refuse"],
            "would_refuse_by_limit": report["observed"]["would_refuse_by_limit"],
            "would_hold": report["observed"]["would_hold"],
            "would_run": report["observed"]["would_run"],
        }
        assert set(flat) == set(outcomes.PREDICATES)
        for key, count in flat.items():
            listed = page.get(API + f"/executions?outcome={key}&from={since}")
            assert listed.status_code == 200, (key, listed.text)
            assert len(listed.json()["items"]) == count, key
            assert count >= 1, key


def test_hv7_the_report_counts_only_what_its_reader_may_read(
    db, world, runtime, admin_engine, live_provider, seeded
):
    from space_fixtures import make_space, place, seat

    every_outcome(db, runtime, admin_engine, world)
    tenant = world["identity"].tenant_id
    admin = report_of(db, runtime, world, world["admin"])
    assert admin.counts.requests == 17 and admin.space == "All spaces"
    assert admin.counts.refused_before_decision == 0
    # The legacy approver reads the requests on their assigned targets, and observe mode's four
    # are on targets no longer assigned to them.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.approval_scopes SET active=false WHERE tenant_id=:t "
                "AND canonical_target_id IN (SELECT canonical_target_id FROM execbound.executions "
                "WHERE tenant_id=:t AND state='OBSERVED')"
            ),
            {"t": tenant},
        )
    approver = report_of(db, runtime, world, world["human"])
    assert approver.counts.requests == 13 and approver.counts.observed_total == 0
    assert approver.counts.refused_before_decision is None
    assert approver.counts.quiet_sources is None
    outsider = provision_identity(admin_engine, db, tenant, "HUMAN_APPROVER", world["clock"].now())
    nobody = report_of(db, runtime, world, outsider).counts
    assert nobody.requests == 0 and nobody.refused_before_decision is None
    # An administrator seated in a second space counts only that space's requests.
    seated = provision_identity(admin_engine, db, tenant, "ADMIN", world["clock"].now())
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        second = make_space(conn, tenant, "Customer B")
        seat(conn, tenant, second, seated.principal_id, role="ADMIN")
        moved = (
            conn.execute(
                text(
                    "SELECT execution_id FROM execbound.executions WHERE tenant_id=:t "
                    "AND state='OBSERVED' ORDER BY execution_id LIMIT 2"
                ),
                {"t": tenant},
            )
            .scalars()
            .all()
        )
        for execution in moved:
            place(conn, tenant, "executions", "execution_id", execution, second)
    narrowed = report_of(db, runtime, world, seated).counts
    assert narrowed.requests == 2 and narrowed.observed_total == 2
    assert narrowed.refused_before_decision is None
    # Another tenant's administrator counts nothing of this one.
    stranger = provision_identity(
        admin_engine, db, seeded["tenants"][1], "ADMIN", world["clock"].now()
    )
    assert report_of(db, runtime, world, stranger).counts.requests == 0
