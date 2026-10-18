# SPDX-License-Identifier: AGPL-3.0-only
"""Who can decide a held request, recorded when it is held and read as coverage (AR15 to AR21).

Real PostgreSQL throughout. A held approval records how many people `scope_check` would let
decide it at that instant; nothing that decides reads the record, so a reviewer added after the
hold decides and one removed after the hold is refused, exactly as before.
"""

import ast
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from uuid import UUID, uuid4

import pytest
from space_fixtures import default_space, make_space, seat
from sqlalchemy import text
from test_approval_quorum import quorum_bundle
from test_execution import provision_identity, request
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound import approval_routing, approval_rules
from execbound.execution import admit, decide_approval
from execbound.execution.models import ExecutionError
from execbound.policy.rulesets import ruleset_bundle
from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
from execbound.surfaces.sessions import issue_session, load_session
from execbound_harness.demo import ENDPOINT_RULESET

pytestmark = pytest.mark.integration


def tenant_of(world) -> UUID:
    return world["identity"].tenant_id


def no_individual_scope(admin_engine, world) -> None:
    with admin_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM execbound.approval_scopes WHERE tenant_id=:t"),
            {"t": tenant_of(world)},
        )


def group(admin_engine, world, members, *, grants=()) -> UUID:
    """A reviewer group with `members` and `grants` [(role, space or None)], written directly."""
    tenant, found = tenant_of(world), uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO execbound.access_groups(tenant_id,group_id,name) VALUES (:t,:g,:n)"),
            {"t": tenant, "g": found, "n": f"Reviewers {found.hex[:8]}"},
        )
        for member in members:
            conn.execute(
                text(
                    "INSERT INTO execbound.access_group_members(tenant_id,group_id,principal_id) "
                    "VALUES (:t,:g,:p)"
                ),
                {"t": tenant, "g": found, "p": member},
            )
        for role, space in grants:
            conn.execute(
                text(
                    "INSERT INTO execbound.access_role_grants"
                    "(tenant_id,grant_id,group_id,role,space_id) VALUES (:t,:i,:g,:r,:s)"
                ),
                {"t": tenant, "i": uuid4(), "g": found, "r": role, "s": space},
            )
    return found


def rule(
    admin_engine,
    world,
    group_id,
    *,
    space=None,
    targets=None,
    action="endpoint.isolate",
    active=True,
) -> UUID:
    """An approval rule naming `group_id`, written directly (the console's path is tested
    elsewhere; here only the view's answer matters)."""
    tenant, found = tenant_of(world), uuid4()
    with admin_engine.begin() as conn:
        where = space or default_space(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.approval_rules(tenant_id,rule_id,name,space_id,group_id,"
                "active) VALUES (:t,:r,:n,:s,:g,:a)"
            ),
            {
                "t": tenant,
                "r": found,
                "n": f"Rule {found.hex[:8]}",
                "s": where,
                "g": group_id,
                "a": active,
            },
        )
        conn.execute(
            text(
                "INSERT INTO execbound.approval_rule_actions(tenant_id,rule_id,action) "
                "VALUES (:t,:r,:a)"
            ),
            {"t": tenant, "r": found, "a": action},
        )
        for target in targets or [world["canonical"]]:
            conn.execute(
                text(
                    "INSERT INTO execbound.approval_rule_targets"
                    "(tenant_id,rule_id,canonical_target_id) VALUES (:t,:r,:c)"
                ),
                {"t": tenant, "r": found, "c": target},
            )
    return found


def approver(admin_engine, db, world):
    return provision_identity(
        admin_engine, db, tenant_of(world), "HUMAN_APPROVER", world["clock"].now()
    )


def managed(admin_engine, world, principal, grants) -> None:
    """Make `principal` a managed person holding exactly `grants` [(role, space or None)]."""
    tenant = tenant_of(world)
    with admin_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO execbound.access_principals(tenant_id,principal_id) VALUES (:t,:p)"),
            {"t": tenant, "p": principal},
        )
        for role, space in grants:
            conn.execute(
                text(
                    "INSERT INTO execbound.access_role_grants"
                    "(tenant_id,grant_id,principal_id,role,space_id) VALUES (:t,:i,:p,:r,:s)"
                ),
                {"t": tenant, "i": uuid4(), "p": principal, "r": role, "s": space},
            )


def no_rule(admin_engine, db, world):
    no_individual_scope(admin_engine, world)


def a_group_of_two(admin_engine, db, world):
    no_individual_scope(admin_engine, world)
    second = approver(admin_engine, db, world)
    rule(
        admin_engine,
        world,
        group(admin_engine, world, [world["human"].principal_id, second.principal_id]),
    )


def a_scope_in_another_space(admin_engine, db, world):
    with admin_engine.begin() as conn:
        elsewhere = make_space(conn, tenant_of(world), "Elsewhere")
        conn.execute(
            text("UPDATE execbound.approval_scopes SET space_id=:s WHERE tenant_id=:t"),
            {"s": elsewhere, "t": tenant_of(world)},
        )


def a_member_whose_role_covers_another_space(admin_engine, db, world):
    no_individual_scope(admin_engine, world)
    with admin_engine.begin() as conn:
        elsewhere = make_space(conn, tenant_of(world), "Elsewhere")
    member = approver(admin_engine, db, world)
    managed(admin_engine, world, member.principal_id, [("approver", elsewhere)])
    rule(admin_engine, world, group(admin_engine, world, [member.principal_id]))


def a_disabled_rule(admin_engine, db, world):
    no_individual_scope(admin_engine, world)
    rule(
        admin_engine,
        world,
        group(admin_engine, world, [world["human"].principal_id]),
        active=False,
    )


def a_quorum_of_two_with_one(admin_engine, db, world):
    bundle = quorum_bundle(world, required=2)
    create_bundle(db, world["admin"], bundle, world["clock"])
    validate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    activate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    world["bundle"] = bundle


# (setup, recorded count, quorum) for each AR15 case.
AR15 = {
    "no rule": (no_rule, 0, 1),
    "a group of two": (a_group_of_two, 2, 1),
    "a scope in another space": (a_scope_in_another_space, 0, 1),
    "a member whose role covers another space": (a_member_whose_role_covers_another_space, 0, 1),
    "a disabled rule": (a_disabled_rule, 0, 1),
    "a quorum of two with one": (a_quorum_of_two_with_one, 1, 2),
}


def held(admin_engine, world, execution_id) -> dict:
    with admin_engine.connect() as conn:
        return dict(
            conn.execute(
                text(
                    "SELECT approval_id, reviewers_at_hold, required_approvers, space_id "
                    "FROM execbound.approvals WHERE tenant_id=:t AND execution_id=:e"
                ),
                {"t": tenant_of(world), "e": execution_id},
            )
            .mappings()
            .one()
        )


@pytest.mark.parametrize("case", list(AR15))
def test_ar15_a_held_request_records_who_could_decide_it(db, admin_engine, world, case):
    setup, count, quorum = AR15[case]
    setup(admin_engine, db, world)
    pending = admit(db, world["identity"], request(world), world["clock"])
    assert pending.view.state == "PENDING_APPROVAL"
    row = held(admin_engine, world, pending.view.execution_id)
    assert (row["reviewers_at_hold"], row["required_approvers"]) == (count, quorum)
    with db.transaction(tenant_of(world)) as conn:
        assert (
            approval_routing.eligible_reviewers(
                conn, tenant_of(world), row["space_id"], world["canonical"], "endpoint.isolate"
            )
            == count
        )


def test_ar16_a_reviewer_added_after_the_hold_decides_and_it_executes_once(
    db, admin_engine, world, live_provider, connector
):
    no_individual_scope(admin_engine, world)
    pending = admit(db, world["identity"], request(world), world["clock"])
    assert held(admin_engine, world, pending.view.execution_id)["reviewers_at_hold"] == 0
    rule(admin_engine, world, group(admin_engine, world, [world["human"].principal_id]))
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    committed = admit(db, world["identity"], request(world), world["clock"])
    assert committed.view.state == "DISPATCH_COMMITTED"
    assert committed.ticket is not None
    assert admit(db, world["identity"], request(world), world["clock"]).ticket is None
    assert held(admin_engine, world, pending.view.execution_id)["reviewers_at_hold"] == 0


def test_ar16_a_reviewer_removed_after_the_hold_is_refused(db, admin_engine, world):
    no_individual_scope(admin_engine, world)
    found = rule(admin_engine, world, group(admin_engine, world, [world["human"].principal_id]))
    pending = admit(db, world["identity"], request(world), world["clock"])
    assert held(admin_engine, world, pending.view.execution_id)["reviewers_at_hold"] == 1
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.approval_rules SET active=false WHERE tenant_id=:t AND rule_id=:r"
            ),
            {"t": tenant_of(world), "r": found},
        )
    with pytest.raises(ExecutionError) as refused:
        decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    assert refused.value.code == "NOT_FOUND"
    assert held(admin_engine, world, pending.view.execution_id)["reviewers_at_hold"] == 1


def production_target(admin_engine, world) -> tuple[UUID, object]:
    """A fresh production endpoint with its incident, and a request for it."""
    tenant = tenant_of(world)
    resource, incident, canonical = uuid4(), uuid4(), uuid4()
    p = {
        "t": tenant,
        "a": world["account"],
        "r": resource,
        "i": incident,
        "c": canonical,
        "s": world["inventory"],
        "z": world["incident_source"],
        "n": world["clock"].now(),
    }
    with admin_engine.begin() as conn:
        conn.execute(text("INSERT INTO execbound.canonical_targets VALUES (:t,:c,:n)"), p)
        conn.execute(
            text(
                "INSERT INTO execbound.resources "
                "(tenant_id,account_id,provider,resource_type,resource_id,provider_id,"
                "version,source_id,role,environment,criticality,observed_at) "
                "VALUES (:t,:a,'mock_crowdstrike','endpoint',:r,CAST(:r AS text),"
                "'v1',:s,'workstation','production',2,:n)"
            ),
            p,
        )
        conn.execute(
            text(
                "INSERT INTO execbound.resource_identities "
                "VALUES (:t,:a,'mock_crowdstrike','endpoint',:r,:c)"
            ),
            p,
        )
        conn.execute(
            text(
                "INSERT INTO execbound.incidents "
                "(tenant_id,account_id,provider,resource_type,incident_id,resource_id,"
                "source_id,version,status,severity,observed_at) "
                "VALUES (:t,:a,'mock_crowdstrike','endpoint',:i,:r,:z,'v1',"
                "'OPEN','CRITICAL',:n)"
            ),
            p,
        )
    wire = request(
        world,
        target={"kind": "canonical", "value": str(resource)},
        claimed_context={"incident_id": str(incident)},
        idempotency_key=str(uuid4()),
    )
    return canonical, wire


def test_ar17_a_rule_save_racing_a_hold_records_one_side(db, runtime, admin_engine, world):
    no_individual_scope(admin_engine, world)
    tenant = tenant_of(world)
    reviewers = group(admin_engine, world, [world["human"].principal_id])
    session = load_session(
        db, issue_session(db, world["admin"], clock=world["clock"]).token, clock=world["clock"]
    )
    with admin_engine.begin() as conn:
        space = default_space(conn, tenant)
    outcomes = set()
    for turn in range(21):
        canonical, wire = production_target(admin_engine, world)
        barrier = Barrier(2)
        # A third of the runs start together; the others give one side a short head start,
        # so both orders are exercised however the scheduler leans.
        lag = {0: (0.0, 0.0), 1: (0.0, 0.2), 2: (0.2, 0.0)}[turn % 3]

        def save(canonical=canonical, barrier=barrier, lag=lag[0]):
            barrier.wait()
            time.sleep(lag)
            return approval_rules.change_rule(
                runtime,
                session,
                None,
                {
                    "operation": "save",
                    "name": f"Race {canonical.hex[:8]}",
                    "group_id": str(reviewers),
                    "space_id": str(space),
                    "actions": ["endpoint.isolate"],
                    "targets": [str(canonical)],
                },
                "Route this endpoint to the response team",
            )

        def hold(wire=wire, barrier=barrier, lag=lag[1]):
            barrier.wait()
            time.sleep(lag)
            return admit(db, world["identity"], wire, world["clock"])

        with ThreadPoolExecutor(2) as pool:
            saving, holding = pool.submit(save), pool.submit(hold)
            changed, admitted = saving.result(timeout=60), holding.result(timeout=60)
        assert admitted.view.state == "PENDING_APPROVAL"
        with admin_engine.connect() as conn:
            # Both writers take the tenant fence and append to the tenant's one audit chain,
            # so the chain's order is the order in which they committed.
            rule_first = conn.execute(
                text(
                    "SELECT (SELECT sequence FROM execbound.audit_events WHERE tenant_id=:t "
                    "AND kind='approval_rule.changed' AND payload->>'rule_id'=:r) < "
                    "(SELECT min(sequence) FROM execbound.audit_events WHERE tenant_id=:t "
                    "AND payload->>'execution_id'=:e)"
                ),
                {"t": tenant, "r": str(changed), "e": str(admitted.view.execution_id)},
            ).scalar_one()
        recorded = held(admin_engine, world, admitted.view.execution_id)["reviewers_at_hold"]
        assert recorded == (1 if rule_first else 0)
        outcomes.add(recorded)
    assert outcomes <= {0, 1}


def test_the_count_is_never_read_by_a_decision():
    package = Path(__file__).parents[1] / "src" / "execbound" / "execution"
    readers = set()
    for path in package.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if "reviewers_at_hold" in node.value:
                    readers.add(path.name)
            elif isinstance(node, ast.Name | ast.Attribute):
                name = node.id if isinstance(node, ast.Name) else node.attr
                if name == "reviewers_at_hold":
                    readers.add(path.name)
    assert readers == {"admission.py"}


# Coverage (AR19 to AR21). Requests are cloned from one real held request so each case can
# place exactly the targets, times and holds it needs; the clones are terminal, so nothing
# else treats them as live work.


def admin_session(db, world, identity=None):
    return load_session(
        db,
        issue_session(db, identity or world["admin"], clock=world["clock"]).token,
        clock=world["clock"],
    )


def select_in(db, world, content, space):
    create_bundle(db, world["admin"], content, world["clock"])
    validate_bundle(db, world["admin"], content.bundle_id, world["clock"])
    activate_bundle(db, world["admin"], content.bundle_id, world["clock"], space=space)
    return content


def rules_bundle(world, *, quorum=None, observe_only=False):
    mapping = world["bundle"].mappings[0]
    if observe_only:
        mapping = mapping.model_copy(update={"observe_only": True})
    ruleset = ENDPOINT_RULESET
    if quorum is not None:
        ruleset = ruleset.model_copy(
            update={
                "rules": tuple(
                    r.model_copy(update={"quorum": quorum}) if r.effect == "REVIEW" else r
                    for r in ruleset.rules
                )
            }
        )
    return ruleset_bundle(
        ruleset, tenant_id=tenant_of(world), bundle_id=uuid4(), mappings=(mapping,)
    )


def template(db, admin_engine, world) -> UUID:
    """One real held request whose rows the clones copy."""
    pending = admit(
        db, world["identity"], request(world, idempotency_key="template"), world["clock"]
    )
    assert pending.view.state == "PENDING_APPROVAL"
    return pending.view.execution_id


def canonical_target(admin_engine, world, label=None) -> UUID:
    tenant, found = tenant_of(world), uuid4()
    resource = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO execbound.canonical_targets VALUES (:t,:c,:n)"),
            {"t": tenant, "c": found, "n": world["clock"].now()},
        )
        if label is not None:
            conn.execute(
                text(
                    "INSERT INTO execbound.resources "
                    "(tenant_id,account_id,provider,resource_type,resource_id,provider_id,"
                    "version,source_id,role,environment,criticality,observed_at) "
                    "VALUES (:t,:a,'mock_crowdstrike','endpoint',:r,:label,"
                    "'v1',:s,'workstation','production',2,:n)"
                ),
                {
                    "t": tenant,
                    "a": world["account"],
                    "r": resource,
                    "label": label,
                    "s": world["inventory"],
                    "n": world["clock"].now(),
                },
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.resource_identities "
                    "VALUES (:t,:a,'mock_crowdstrike','endpoint',:r,:c)"
                ),
                {"t": tenant, "a": world["account"], "r": resource, "c": found},
            )
    return found


NUMBER = iter(range(1_000_000, 10_000_000))


def requested(admin_engine, world, source, target, space, *, ago, held=False, required=1):
    """A terminal copy of `source` on `target` in `space`, `ago` before now, held or not."""
    tenant, execution = tenant_of(world), uuid4()
    at = world["clock"].now() - ago
    with admin_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO execbound.executions
              (tenant_id,execution_id,principal_id,credential_id,intent_hash,wire_hash,plan_hash,
               canonical_target_id,bundle_id,frozen,state,created_at,changed_at,operation_id,
               owner_hash,settlement_tier,space_id,request_number)
            SELECT tenant_id,:e,principal_id,credential_id,intent_hash,wire_hash,plan_hash,
                   :c,bundle_id,frozen,:state,:at,:at,:e,owner_hash,settlement_tier,:s,:n
              FROM execbound.executions WHERE tenant_id=:t AND execution_id=:source
            """),
            {
                "t": tenant,
                "e": execution,
                "c": target,
                "state": "STALE_AUTHORIZATION" if held else "DENIED",
                "at": at,
                "s": space,
                "n": next(NUMBER),
                "source": source,
            },
        )
        if held:
            conn.execute(
                text("""
                INSERT INTO execbound.approvals
                  (tenant_id,approval_id,execution_id,principal_id,plan_hash,bundle_id,
                   obligation_ids,expires_at,created_at,state,required_approvers,space_id,
                   reviewers_at_hold)
                SELECT tenant_id,:a,:e,principal_id,plan_hash,bundle_id,obligation_ids,
                       :at,:at,'EXPIRED',:required,:s,0
                  FROM execbound.approvals WHERE tenant_id=:t AND execution_id=:source
                """),
                {
                    "t": tenant,
                    "a": uuid4(),
                    "e": execution,
                    "at": at,
                    "required": required,
                    "s": space,
                    "source": source,
                },
            )
    return execution


def assign(admin_engine, world, people, target, space, action="endpoint.isolate"):
    with admin_engine.begin() as conn:
        for person in people:
            conn.execute(
                text(
                    "INSERT INTO execbound.approval_scopes "
                    "(tenant_id,approver_id,canonical_target_id,action,space_id) "
                    "VALUES (:t,:p,:c,:a,:s)"
                ),
                {"t": tenant_of(world), "p": person, "c": target, "a": action, "s": space},
            )


def by_name(answer):
    return {space["name"]: space for space in answer["spaces"]}


def test_ar19_coverage_lists_what_each_space_can_hold(db, runtime, admin_engine, world):
    tenant = tenant_of(world)
    with admin_engine.begin() as conn:
        second = make_space(conn, tenant, "Bravo rules")
        make_space(conn, tenant, "Charlie none")
        observing = make_space(conn, tenant, "Echo observe")
        archived = make_space(conn, tenant, "Delta archived")
        conn.execute(
            text(
                "UPDATE execbound.spaces SET archived_at=now() WHERE tenant_id=:t AND space_id=:s"
            ),
            {"t": tenant, "s": archived},
        )
    select_in(db, world, rules_bundle(world), second)
    select_in(db, world, rules_bundle(world, observe_only=True), observing)
    answer = approval_routing.read_coverage(runtime, admin_session(db, world))
    spaces = by_name(answer)
    assert list(spaces) == ["Bravo rules", "Charlie none", "Default", "Echo observe"]
    assert answer["truncated"] is False and answer["mode"] == "ENFORCE"
    rules = spaces["Bravo rules"]
    assert rules["policy"] == "rules" and rules["bundle_id"] is not None
    [isolate] = rules["actions"]
    assert isolate["action"] == "endpoint.isolate"
    assert isolate["action_label"] != "endpoint.isolate"
    assert isolate["known"] is True and isolate["required"] == 1 and isolate["upto"] is None
    assert isolate["held_by"] == [
        "rule:isolate-production-needs-review",
        "limit:principal-autonomous-isolation",
    ]
    custom = spaces["Default"]
    assert custom["policy"] == "custom"
    [unknown] = custom["actions"]
    assert unknown["known"] is False and "policy" in unknown["held_by"]
    assert spaces["Charlie none"] == {
        "space_id": spaces["Charlie none"]["space_id"],
        "name": "Charlie none",
        "bundle_id": None,
        "policy": "none",
        "actions": [],
    }
    assert spaces["Echo observe"]["policy"] == "rules"
    assert spaces["Echo observe"]["actions"] == []


def test_ar20_coverage_finds_held_requested_and_thin_targets(db, runtime, admin_engine, world):
    from datetime import timedelta

    tenant = tenant_of(world)
    no_individual_scope(admin_engine, world)
    with admin_engine.begin() as conn:
        space = default_space(conn, tenant)
        quorum = make_space(conn, tenant, "Quorum")
    select_in(db, world, rules_bundle(world), space)
    select_in(db, world, rules_bundle(world, quorum=2), quorum)
    source = template(db, admin_engine, world)
    second = approver(admin_engine, db, world)
    with admin_engine.begin() as conn:
        seat(conn, tenant, quorum, world["human"].principal_id)
    nobody = canonical_target(admin_engine, world, "nobody.example")
    for hours in (5, 3):
        requested(admin_engine, world, source, nobody, space, ago=timedelta(hours=hours), held=True)
    asked = canonical_target(admin_engine, world, "asked.example")
    requested(admin_engine, world, source, asked, space, ago=timedelta(hours=2))
    one = canonical_target(admin_engine, world, "one.example")
    requested(admin_engine, world, source, one, space, ago=timedelta(hours=4), held=True)
    assign(admin_engine, world, [world["human"].principal_id], one, space)
    two = canonical_target(admin_engine, world, "two.example")
    requested(admin_engine, world, source, two, space, ago=timedelta(hours=1), held=True)
    assign(admin_engine, world, [world["human"].principal_id, second.principal_id], two, space)
    short = canonical_target(admin_engine, world, "short.example")
    requested(
        admin_engine, world, source, short, quorum, ago=timedelta(hours=1), held=True, required=2
    )
    assign(admin_engine, world, [world["human"].principal_id], short, quorum)
    # Older than the window: never counted.
    stale = canonical_target(admin_engine, world, "stale.example")
    requested(admin_engine, world, source, stale, space, ago=timedelta(days=31), held=True)

    answer = approval_routing.read_coverage(runtime, admin_session(db, world))
    default = by_name(answer)["Default"]["actions"][0]

    def ids(listing):
        return [row["canonical_target_id"] for row in listing["rows"]]

    # The template itself was held with nobody, an hour or so ago at the clock's now.
    assert ids(default["held_uncovered"]) == [world["canonical"], nobody]
    assert default["held_uncovered"]["rows"][1]["requests"] == 2
    assert default["held_uncovered"]["rows"][1]["labels"] == "nobody.example"
    assert ids(default["requested_uncovered"]) == [asked]
    assert ids(default["thin"]) == [one]
    assert default["reviewers"] == 2
    short_action = by_name(answer)["Quorum"]["actions"][0]
    assert short_action["required"] == 2
    assert ids(short_action["held_uncovered"]) == [short]
    assert short_action["held_uncovered"]["rows"][0]["reviewers"] == 1
    assert ids(short_action["thin"]) == []

    many = [canonical_target(admin_engine, world) for _ in range(25)]
    # Later than everything above, newest first.
    for minutes, target in enumerate(many):
        requested(
            admin_engine,
            world,
            source,
            target,
            space,
            ago=-timedelta(minutes=len(many) - minutes),
            held=True,
        )
    answer = approval_routing.read_coverage(runtime, admin_session(db, world))
    listing = by_name(answer)["Default"]["actions"][0]["held_uncovered"]
    assert listing["total"] == 27
    assert ids(listing) == many[:20]


def test_ar20_coverage_truncates_past_its_bounds(db, runtime, admin_engine, world, monkeypatch):
    from datetime import timedelta

    tenant = tenant_of(world)
    with admin_engine.begin() as conn:
        space = default_space(conn, tenant)
    source = template(db, admin_engine, world)
    # Three groups in the window: the template's and two more.
    for hours in (1, 2):
        requested(
            admin_engine,
            world,
            source,
            canonical_target(admin_engine, world),
            space,
            ago=timedelta(hours=hours),
        )
    monkeypatch.setattr(approval_routing, "MAX_GROUPS", 3)
    assert approval_routing.read_coverage(runtime, admin_session(db, world))["truncated"] is False
    requested(
        admin_engine,
        world,
        source,
        canonical_target(admin_engine, world),
        space,
        ago=timedelta(hours=3),
    )
    assert approval_routing.read_coverage(runtime, admin_session(db, world))["truncated"] is True
    monkeypatch.setattr(approval_routing, "MAX_GROUPS", 5000)
    with admin_engine.begin() as conn:
        for index in range(50):
            make_space(conn, tenant, f"Space {index:02}")
    answer = approval_routing.read_coverage(runtime, admin_session(db, world))
    assert answer["truncated"] is True and len(answer["spaces"]) == 50


def test_ar21_coverage_does_not_wait_for_the_fence(db, runtime, admin_engine, world):
    from execbound.execution import store

    session = admin_session(db, world)
    with db.transaction(tenant_of(world)) as holder:
        store.fence(holder, tenant_of(world), world["clock"])
        with ThreadPoolExecutor(1) as pool:
            started = time.monotonic()
            answer = pool.submit(approval_routing.read_coverage, runtime, session).result(
                timeout=10
            )
            assert time.monotonic() - started < 2
    assert answer["spaces"]


def test_ar21_coverage_names_no_reviewer(db, runtime, admin_engine, world):
    import json

    session = admin_session(db, world)
    source = template(db, admin_engine, world)
    assert source
    answer = approval_routing.read_coverage(runtime, session)
    body = json.dumps(answer, default=str)
    with admin_engine.connect() as conn:
        people = conn.execute(
            text(
                "SELECT principal_id FROM execbound.principals WHERE tenant_id=:t "
                "AND kind <> 'AGENT'"
            ),
            {"t": tenant_of(world)},
        ).scalars()
        for person in people:
            assert str(person) not in body
    assert "@" not in body


def test_coverage_refuses_anyone_without_workspace_access_manage(db, runtime, admin_engine, world):
    tenant = tenant_of(world)
    with pytest.raises(approval_routing.ApprovalRoutingError) as refused:
        approval_routing.read_coverage(runtime, admin_session(db, world, world["human"]))
    # An approver is not an administrator at all, so the identity check answers first.
    assert refused.value.code == "INVALID_ACTOR"
    seated = provision_identity(admin_engine, db, tenant, "ADMIN", world["clock"].now())
    with admin_engine.begin() as conn:
        seat(conn, tenant, default_space(conn, tenant), seated.principal_id, "ADMIN")
    with pytest.raises(approval_routing.ApprovalRoutingError) as refused:
        approval_routing.read_coverage(runtime, admin_session(db, world, seated))
    assert refused.value.code == "INVALID_ACTOR"
    with pytest.raises(approval_routing.ApprovalRoutingError) as refused:
        approval_routing.read_unrouted(runtime, admin_session(db, world, seated))
    assert refused.value.code == "INVALID_ACTOR"


def test_coverage_on_a_populated_tenant(db, runtime, admin_engine, world):
    import statistics
    from datetime import timedelta

    tenant = tenant_of(world)
    with admin_engine.begin() as conn:
        spaces = [default_space(conn, tenant)]
        spaces += [make_space(conn, tenant, name) for name in ("Bravo", "Charlie")]
    for space in spaces[1:]:
        select_in(db, world, rules_bundle(world), space)
    source = template(db, admin_engine, world)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.canonical_targets "
                "SELECT :t, gen_random_uuid(), now() FROM generate_series(1, 2000)"
            ),
            {"t": tenant},
        )
        conn.execute(
            text("""
            WITH targets AS (
              SELECT canonical_target_id, row_number() OVER () - 1 AS i
                FROM execbound.canonical_targets WHERE tenant_id = :t
            ), copies AS (
              SELECT n, gen_random_uuid() AS e,
                     (CAST(:spaces AS uuid[]))[1 + n % 3] AS space_id,
                     :now - make_interval(secs => (n * 631 % 31536000)) AS at
                FROM generate_series(1, 50000) AS n
            )
            INSERT INTO execbound.executions
              (tenant_id,execution_id,principal_id,credential_id,intent_hash,wire_hash,
               plan_hash,canonical_target_id,bundle_id,frozen,state,created_at,changed_at,
               operation_id,owner_hash,settlement_tier,space_id,request_number)
            SELECT x.tenant_id,c.e,x.principal_id,x.credential_id,x.intent_hash,x.wire_hash,
                   x.plan_hash,t.canonical_target_id,x.bundle_id,x.frozen,'DENIED',c.at,c.at,
                   c.e,x.owner_hash,x.settlement_tier,c.space_id,100000000 + c.n
              FROM copies c
              JOIN targets t ON t.i = c.n % 2000
              CROSS JOIN execbound.executions x
             WHERE x.tenant_id = :t AND x.execution_id = :source
            """),
            {"t": tenant, "spaces": spaces, "now": world["clock"].now(), "source": source},
        )
        conn.execute(text("ANALYZE execbound.executions"))
    session = admin_session(db, world)
    timings = []
    for _ in range(5):
        started = time.perf_counter()
        answer = approval_routing.read_coverage(runtime, session)
        timings.append(time.perf_counter() - started)
    # A year of history, about a twelfth of it inside the window.
    assert answer["since"] == world["clock"].now() - timedelta(days=30)
    print(f"coverage read on 50,000 executions: median {statistics.median(timings):.3f} s")

    def window_plan(conn):
        return conn.execute(
            text(
                "EXPLAIN (FORMAT JSON) SELECT 1 FROM execbound.executions e WHERE e.tenant_id = :t "
                "AND e.created_at >= :since AND e.space_id = ANY(CAST(:spaces AS uuid[]))"
            ),
            {"t": tenant, "since": answer["since"], "spaces": spaces},
        ).scalar_one()[0]["Plan"]

    def ranges_created_at(node) -> bool:
        if node["Node Type"] in ("Index Scan", "Index Only Scan", "Bitmap Index Scan"):
            if "created_at >=" in node.get("Index Cond", ""):
                return True
        return any(ranges_created_at(child) for child in node.get("Plans", []))

    # The window is an index range bounded by created_at, not the tenant's whole year. Which
    # index carries it depends on the sample ANALYZE draws: usually `executions_created`, but on
    # some samples `executions_space` (tenant_id, space_id, created_at, ...) as an index-only
    # scan, since every Space is asked for. Both bound created_at in their index condition.
    with db.transaction(tenant) as conn:
        plan = window_plan(conn)
        assert ranges_created_at(plan), json.dumps(plan, indent=1)
        # The check can fail: without index access the window is a sequential scan.
        for scan in ("indexscan", "indexonlyscan", "bitmapscan"):
            conn.execute(text(f"SET LOCAL enable_{scan} = off"))
        assert not ranges_created_at(window_plan(conn))
    # Without the index, for the record, then its build time on this tenant.
    with admin_engine.begin() as conn:
        conn.execute(text("DROP INDEX execbound.executions_created"))
    try:
        without = []
        for _ in range(5):
            started = time.perf_counter()
            approval_routing.read_coverage(runtime, session)
            without.append(time.perf_counter() - started)
        print(f"without executions_created: median {statistics.median(without):.3f} s")
    finally:
        with admin_engine.begin() as conn:
            started = time.perf_counter()
            conn.execute(
                text(
                    "CREATE INDEX executions_created "
                    "ON execbound.executions (tenant_id, created_at)"
                )
            )
            print(f"executions_created built in {time.perf_counter() - started:.3f} s")
