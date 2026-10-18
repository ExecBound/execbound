# SPDX-License-Identifier: AGPL-3.0-only
"""An invitation may name the reviewer group its Approver joins on acceptance: AR2 to AR7.

Real PostgreSQL throughout. The group is checked when the invitation is created, through
`workspace_invitation_set_group` in the creating transaction, and again when it is accepted,
under the fence `access_change` holds; a group that grants more than the invitation shows is
refused at creation and skipped, with its reason recorded, at acceptance. A promotion of the
group racing an acceptance is ordered by that fence, on two real connections.
"""

import json
import threading
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from console_api_fixtures import API, ORIGIN, console_client
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_approval_group_rules import remove_individual_scope
from test_execution import provision_credential, request
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import form_values
from test_human_surface import human_config as human_config
from test_migration_without_bypass import fenced
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime
from test_teammate_invitations import (
    CHOSEN,
    account_holder,
    admin_session,
    bare_runtime,
    chain,
    console_client_for,
    invitation_row,
    open_join,
    owner_rows,
    scalar,
    send,
    workspace,
)

from execbound import access_control
from execbound.app import create_app
from execbound.execution import admit, decide_approval, store
from execbound.identity import authenticate
from execbound.invitations import (
    InvitationError,
    accept_invitation,
    create_invitation,
    list_invitations,
)
from execbound.replay.export import export_history
from execbound.replay.verify import verify_export
from execbound.surfaces.sessions import issue_session, load_session

pytestmark = pytest.mark.integration

ADDRESS = "riley@example.org"
SET_GROUP = "SELECT execbound.workspace_invitation_set_group(:a, :i, :g, :n)"


def now():
    return datetime.now(UTC)


def default_space(admin_engine, tenant) -> UUID:
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return conn.execute(
            text(
                "SELECT space_id FROM execbound.spaces WHERE tenant_id = :t "
                "ORDER BY created_at, space_id LIMIT 1"
            ),
            {"t": tenant},
        ).scalar_one()


def another_space(admin_engine, tenant, creator) -> UUID:
    space = uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.spaces(tenant_id, space_id, name, created_at, created_by) "
                "VALUES (:t, :s, :n, now(), :p)"
            ),
            {"t": tenant, "s": space, "n": f"Lab {space.hex[:6]}", "p": creator},
        )
    return space


def group_with(admin_engine, tenant, grants=(), *, name=None) -> UUID:
    """A reviewer group holding exactly `grants`, written by the owner under the fence."""
    group = uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.access_groups(tenant_id, group_id, name) VALUES (:t, :g, :n)"
            ),
            {"t": tenant, "g": group, "n": name or f"Reviewers {group.hex[:6]}"},
        )
        for role, space in grants:
            add_grant(conn, tenant, group, role, space)
    return group


def add_grant(conn, tenant, group, role, space) -> None:
    conn.execute(
        text(
            "INSERT INTO execbound.access_role_grants"
            "(tenant_id, grant_id, group_id, role, space_id) VALUES (:t, :id, :g, :r, :s)"
        ),
        {"t": tenant, "id": uuid4(), "g": group, "r": role, "s": space},
    )


def change_group(admin_engine, tenant, group, role, space) -> None:
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        add_grant(conn, tenant, group, role, space)


def delete_group(admin_engine, tenant, group) -> None:
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        for table in ("access_role_grants", "access_group_members", "access_groups"):
            conn.execute(
                text(f"DELETE FROM execbound.{table} WHERE tenant_id = :t AND group_id = :g"),
                {"t": tenant, "g": group},
            )


def fill_group(admin_engine, tenant, group, count) -> None:
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        for _ in range(count):
            principal = uuid4()
            conn.execute(
                text(
                    "INSERT INTO execbound.principals(tenant_id, principal_id, kind) "
                    "VALUES (:t, :p, 'HUMAN_APPROVER')"
                ),
                {"t": tenant, "p": principal},
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.access_group_members(tenant_id, group_id, principal_id) "
                    "VALUES (:t, :g, :p)"
                ),
                {"t": tenant, "g": group, "p": principal},
            )


def members_of(admin_engine, tenant, group) -> set[UUID]:
    rows = owner_rows(
        admin_engine,
        tenant,
        "SELECT principal_id FROM execbound.access_group_members "
        "WHERE tenant_id = :t AND group_id = :g",
        {"t": tenant, "g": group},
    )
    return {row["principal_id"] for row in rows}


def grants_of(admin_engine, tenant, principal) -> list[tuple[str, UUID | None]]:
    rows = owner_rows(
        admin_engine,
        tenant,
        "SELECT role, space_id FROM execbound.access_role_grants "
        "WHERE tenant_id = :t AND principal_id = :p ORDER BY role, space_id",
        {"t": tenant, "p": principal},
    )
    return [(row["role"], row["space_id"]) for row in rows]


def approver_in(space) -> list[dict]:
    return [{"role": "approver", "space_id": str(space)}]


def events_after_joining(admin_engine, tenant, principal):
    """The tenant's events from the acceptance that made `principal` on, oldest first."""
    events = chain(admin_engine, tenant)
    start = next(
        index
        for index, event in enumerate(events)
        if event["kind"] == "principal.created"
        and event["payload"].get("principal_id") == str(principal)
    )
    return events[start:]


def invited(db, admin_engine, where, group, *, email=ADDRESS, grants=None):
    """An invitation through the service, naming `group`, and a link for it."""
    session = admin_session(db, admin_engine, where)
    created = create_invitation(
        bare_runtime(db),
        session,
        email,
        grants if grants is not None else approver_in(where["space"]),
        reviewer_group=group,
    )
    return created["invitation_id"], send(db, where["tenant_id"], created["invitation_id"])


# --- AR2: what an invitation may name ---------------------------------------------------------


@pytest.mark.parametrize("grant", ["none", "approver_here"])
def test_ar2_an_invitation_names_a_review_only_group(db, admin_engine, seeded, grant):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    grants = [] if grant == "none" else [("approver", where["space"])]
    group = group_with(admin_engine, tenant, grants, name="Night shift")
    invitation, _ = invited(db, admin_engine, where, group)

    assert invitation_row(admin_engine, tenant, invitation)["reviewer_group_id"] == group
    rows = list_invitations(bare_runtime(db), admin_session(db, admin_engine, where))
    row = next(item for item in rows if item["invitation_id"] == invitation)
    assert (row["reviewer_group_id"], row["reviewer_group_name"]) == (group, "Night shift")
    created = next(e for e in chain(admin_engine, tenant) if e["kind"] == "invitation.created")
    assert created["payload"]["reviewer_group_id"] == str(group)


def test_ar2_an_administrator_and_approver_invitation_may_name_a_group(db, admin_engine, seeded):
    where = workspace(admin_engine)
    group = group_with(admin_engine, where["tenant_id"])
    grants = [{"role": "administrator", "space_id": None}, *approver_in(where["space"])]
    invitation, _ = invited(db, admin_engine, where, group, grants=grants)
    row = invitation_row(admin_engine, where["tenant_id"], invitation)
    assert row["reviewer_group_id"] == group


def test_ar2_an_invitation_without_a_group_records_none(db, admin_engine, seeded):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    created = create_invitation(
        bare_runtime(db), admin_session(db, admin_engine, where), ADDRESS, None
    )
    assert (
        invitation_row(admin_engine, tenant, created["invitation_id"])["reviewer_group_id"] is None
    )
    rows = list_invitations(bare_runtime(db), admin_session(db, admin_engine, where))
    assert (rows[0]["reviewer_group_id"], rows[0]["reviewer_group_name"]) == (None, None)
    event = next(e for e in chain(admin_engine, tenant) if e["kind"] == "invitation.created")
    assert "reviewer_group_id" not in event["payload"]


REFUSED = [
    "administrator",
    "policy_manager",
    "administrator_both",
    "policy_manager_both",
    "approver_everywhere",
    "viewer_elsewhere",
    "another_tenant",
    "viewer_invitation",
    "administrator_invitation",
]


@pytest.mark.parametrize("case", REFUSED)
def test_ar2_a_group_granting_more_than_the_invitation_is_refused(db, admin_engine, seeded, case):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    grants = approver_in(where["space"])
    if case == "administrator":
        group = group_with(admin_engine, tenant, [("administrator", None)])
    elif case == "policy_manager":
        group = group_with(admin_engine, tenant, [("policy_manager", where["space"])])
    elif case == "administrator_both":
        # The invitation covers the grant, so only the refusal of more than review stops it.
        group = group_with(admin_engine, tenant, [("administrator", None)])
        grants = [*grants, {"role": "administrator", "space_id": None}]
    elif case == "policy_manager_both":
        group = group_with(admin_engine, tenant, [("policy_manager", where["space"])])
        grants = [*grants, {"role": "policy_manager", "space_id": str(where["space"])}]
    elif case == "approver_everywhere":
        group = group_with(admin_engine, tenant, [("approver", None)])
    elif case == "viewer_elsewhere":
        lab = another_space(admin_engine, tenant, where["admin"])
        group = group_with(admin_engine, tenant, [("viewer", lab)])
    elif case == "another_tenant":
        other = workspace(admin_engine, name="Elsewhere")
        group = group_with(admin_engine, other["tenant_id"])
    elif case == "viewer_invitation":
        group = group_with(admin_engine, tenant)
        grants = [{"role": "viewer", "space_id": str(where["space"])}]
    else:
        group = group_with(admin_engine, tenant)
        grants = [{"role": "administrator", "space_id": None}]
    runtime = bare_runtime(db)
    with console_client_for(db, runtime, admin_engine, tenant, where["admin"]) as client:
        answer = client.post(
            API + "/teammate-invitations",
            {"email": ADDRESS, "grants": grants, "reviewer_group_id": str(group)},
        )
    assert answer.status_code == 400, answer.text
    assert answer.json()["code"] == "INVALID_BODY"
    assert answer.json()["fields"] == ["reviewer_group_id"]
    assert (
        owner_rows(
            admin_engine,
            tenant,
            "SELECT 1 FROM execbound.workspace_invitations WHERE tenant_id = :t",
            {"t": tenant},
        )
        == []
    )
    assert "invitation.created" not in [e["kind"] for e in chain(admin_engine, tenant)]


def test_ar2_a_malformed_group_id_is_refused_before_the_service(db, admin_engine, seeded):
    where = workspace(admin_engine)
    with console_client_for(
        db, bare_runtime(db), admin_engine, where["tenant_id"], where["admin"]
    ) as client:
        answer = client.post(
            API + "/teammate-invitations",
            {
                "email": ADDRESS,
                "grants": approver_in(where["space"]),
                "reviewer_group_id": "not-a-group",
            },
        )
    assert answer.status_code == 400, answer.text
    assert (
        owner_rows(
            admin_engine,
            where["tenant_id"],
            "SELECT 1 FROM execbound.workspace_invitations WHERE tenant_id = :t",
            {"t": where["tenant_id"]},
        )
        == []
    )


def test_ar2_a_second_group_is_refused(db, admin_engine, seeded):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    first = group_with(admin_engine, tenant)
    second = group_with(admin_engine, tenant)
    invitation, _ = invited(db, admin_engine, where, first)
    with pytest.raises(DBAPIError) as refused:
        scalar(
            db,
            tenant,
            SET_GROUP,
            {"a": where["admin"], "i": invitation, "g": second, "n": now()},
        )
    assert refused.value.orig.diag.message_primary == "INVALID_STATE"
    assert invitation_row(admin_engine, tenant, invitation)["reviewer_group_id"] == first


def test_ar2_a_narrowed_or_ordinary_actor_cannot_name_a_group(db, admin_engine, seeded):
    """The definer runs the administrator check every invitation path runs."""
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    group = group_with(admin_engine, tenant)
    invitation, _ = invited(db, admin_engine, where, None)
    member = uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind) "
                "VALUES (:t, :p, 'HUMAN_APPROVER')"
            ),
            {"t": tenant, "p": member},
        )
    with pytest.raises(DBAPIError) as refused:
        scalar(db, tenant, SET_GROUP, {"a": member, "i": invitation, "g": group, "n": now()})
    assert refused.value.orig.diag.message_primary == "FORBIDDEN"
    assert invitation_row(admin_engine, tenant, invitation)["reviewer_group_id"] is None


# --- AR3: the step-up and the token refusal ----------------------------------------------------


def test_ar3_inviting_with_a_group_steps_up_and_refuses_a_token(db, admin_engine, seeded):
    from execbound import mfa
    from execbound.envelope import KeyRing
    from execbound.personal_tokens import issue_token

    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = bare_runtime(db)
    group = group_with(admin_engine, tenant)
    body = {
        "email": ADDRESS,
        "grants": approver_in(where["space"]),
        "reviewer_group_id": str(group),
    }

    def rows():
        return owner_rows(
            admin_engine,
            tenant,
            "SELECT 1 FROM execbound.workspace_invitations WHERE tenant_id = :t",
            {"t": tenant},
        )

    token, _ = issue_token(
        db, admin_session(db, admin_engine, where), "ci", timedelta(days=1), clock=runtime.clock
    )
    with console_client_for(db, runtime, admin_engine, tenant, where["admin"]) as client:
        # Not entered: the signed-in client already runs the application's lifespan.
        bearer = TestClient(client.client.app, base_url=ORIGIN, follow_redirects=False)
        refused = bearer.post(
            API + "/teammate-invitations",
            json=body,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert refused.status_code == 403, refused.text
        assert refused.json()["code"] == "TOKEN_NOT_ALLOWED"
        assert rows() == []

        session = load_session(db, client.client.cookies.get("eb_session"), clock=runtime.clock)
        ring = KeyRing("test", {"test": b"m" * 32})
        seed = mfa.begin_enrollment(db, session, ring, clock=runtime.clock)
        codes = mfa.confirm_enrollment(
            db,
            session,
            ring,
            mfa.totp(seed, int(runtime.clock.now().timestamp() // 30)),
            clock=runtime.clock,
        )
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text(
                    "UPDATE execbound.session_assurance SET verified_at = :v "
                    "WHERE tenant_id = :t AND session_id = :s"
                ),
                {"v": now() - timedelta(minutes=31), "t": tenant, "s": session.session_id},
            )
        stale = client.post(API + "/teammate-invitations", body)
        assert stale.status_code == 401, stale.text
        assert stale.json()["code"] == "MFA_REQUIRED"
        assert rows() == []

        assert mfa.verify_factor(db, session, ring, codes[0], clock=runtime.clock)
        created = client.post(API + "/teammate-invitations", body)
        assert created.status_code == 200, created.text
    row = invitation_row(admin_engine, tenant, UUID(created.json()["invitation_id"]))
    assert row["reviewer_group_id"] == group


# --- AR4: acceptance applies the group -------------------------------------------------------


def person_identity(admin_engine, db, tenant, principal, issued_at):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        token = provision_credential(conn, tenant, principal, issued_at, timedelta(hours=2))
    return authenticate(db, token)


@pytest.mark.parametrize("path", ["password", "signed_in"])
def test_ar4_acceptance_adds_the_member_after_the_grants(
    db, runtime, admin_engine, world, live_provider, connector, path
):
    tenant = world["admin"].tenant_id
    space = default_space(admin_engine, tenant)
    remove_individual_scope(admin_engine, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        made = client.post(
            API + "/access/groups",
            {"name": "Responders", "description": None, "reason": "Route endpoint reviews"},
        )
        assert made.status_code == 200, made.text
        group = UUID(made.json()["group_id"])
        rule = client.post(
            API + "/approval-rules",
            {
                "name": "Endpoint response",
                "group_id": str(group),
                "space_id": str(space),
                "actions": ["endpoint.isolate"],
                "targets": [str(world["canonical"])],
                "reason": "Route endpoint requests to the responders",
            },
        )
        assert rule.status_code == 200, rule.text

    email = f"{path}-{uuid4().hex[:8]}@example.org"
    proof = {"password": CHOSEN}
    if path == "signed_in":
        _, _, grant, session = account_holder(db, admin_engine, email)
        proof = {"session": session, "account_token": grant.account_token}
    grant = issue_session(db, world["admin"], clock=runtime.clock)
    administrator = load_session(db, grant.token, clock=runtime.clock)
    created = create_invitation(
        runtime, administrator, email, approver_in(space), reviewer_group=group
    )
    token = send(db, tenant, created["invitation_id"])
    accepted = accept_invitation(db, token, **proof)
    assert accepted.outcome == "ACCEPTED"
    principal = accepted.principal_id

    assert members_of(admin_engine, tenant, group) == {principal}
    assert grants_of(admin_engine, tenant, principal) == [("approver", space)]
    events = events_after_joining(admin_engine, tenant, principal)
    assert [e["kind"] for e in events] == [
        "principal.created",
        "access.set_user_roles",
        "access.group_member_added",
        "invitation.accepted",
    ]
    added = events[2]
    assert added["actor_id"] == world["admin"].principal_id
    assert added["payload"] == {
        "subject_id": str(group),
        "principal_id": str(principal),
        "invitation_id": str(created["invitation_id"]),
        "reason": f"invitation {created['invitation_id']} accepted",
    }
    assert events[3]["payload"] == {
        "invitation_id": str(created["invitation_id"]),
        "principal_id": str(principal),
        "reviewer_group_id": str(group),
        "reviewer_group_applied": True,
        "reviewer_group_refusal": None,
    }

    reviewer = person_identity(admin_engine, db, tenant, principal, world["clock"].now())
    pending = admit(db, world["identity"], request(world), world["clock"])
    assert pending.view.state == "PENDING_APPROVAL"
    decide_approval(db, reviewer, pending.view.approval_id, "APPROVE", world["clock"])
    committed = admit(db, world["identity"], request(world), world["clock"])
    assert committed.view.state == "DISPATCH_COMMITTED"
    assert committed.ticket is not None
    assert admit(db, world["identity"], request(world), world["clock"]).ticket is None

    export = export_history(db, world["admin"], world["clock"])
    history = verify_export(export, export.head)
    assert history.complete and history.issues == ()


def test_ar4_an_invitation_without_a_group_accepts_as_before(db, admin_engine, seeded):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    created = create_invitation(
        bare_runtime(db), admin_session(db, admin_engine, where), ADDRESS, None
    )
    accepted = accept_invitation(db, send(db, tenant, created["invitation_id"]), password=CHOSEN)
    events = events_after_joining(admin_engine, tenant, accepted.principal_id)
    assert [e["kind"] for e in events] == [
        "principal.created",
        "access.set_user_roles",
        "invitation.accepted",
    ]
    assert events[2]["payload"] == {
        "invitation_id": str(created["invitation_id"]),
        "principal_id": str(accepted.principal_id),
    }


# --- AR5: a group that changed after the invitation ---------------------------------------------


@pytest.mark.parametrize(
    "change,reason",
    [
        ("deleted", "GROUP_GONE"),
        ("administrator", "GROUP_ROLES"),
        ("approver_everywhere", "GROUP_SCOPE"),
        ("viewer_elsewhere", "GROUP_SCOPE"),
        ("full", "GROUP_FULL"),
    ],
)
def test_ar5_a_changed_group_is_skipped_and_recorded(db, admin_engine, seeded, change, reason):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    group = group_with(admin_engine, tenant, [("approver", where["space"])])
    invitation, token = invited(db, admin_engine, where, group)
    if change == "deleted":
        delete_group(admin_engine, tenant, group)
    elif change == "administrator":
        change_group(admin_engine, tenant, group, "administrator", None)
    elif change == "approver_everywhere":
        change_group(admin_engine, tenant, group, "approver", None)
    elif change == "viewer_elsewhere":
        lab = another_space(admin_engine, tenant, where["admin"])
        change_group(admin_engine, tenant, group, "viewer", lab)
    else:
        fill_group(admin_engine, tenant, group, 100)
    before = members_of(admin_engine, tenant, group)

    accepted = accept_invitation(db, token, password=CHOSEN)
    assert accepted.outcome == "ACCEPTED"
    principal = accepted.principal_id
    assert members_of(admin_engine, tenant, group) == before
    assert principal not in before
    assert grants_of(admin_engine, tenant, principal) == [("approver", where["space"])]
    events = events_after_joining(admin_engine, tenant, principal)
    assert [e["kind"] for e in events] == [
        "principal.created",
        "access.set_user_roles",
        "invitation.accepted",
    ]
    assert events[2]["payload"] == {
        "invitation_id": str(invitation),
        "principal_id": str(principal),
        "reviewer_group_id": str(group),
        "reviewer_group_applied": False,
        "reviewer_group_refusal": reason,
    }


# --- AR6: a promotion of the group racing an acceptance ------------------------------------------


def test_ar6_a_group_promotion_racing_an_acceptance_is_ordered(
    db, admin_engine, seeded, monkeypatch
):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = bare_runtime(db)
    racing = threading.Event()
    barrier = threading.Barrier(2, timeout=20)
    real_fence = store.fence

    def meet(conn, fenced_tenant, clock):
        # Both parties open their transactions, meet here, and only then race to the fence.
        if racing.is_set():
            barrier.wait()
        return real_fence(conn, fenced_tenant, clock)

    monkeypatch.setattr(store, "fence", meet)
    outcomes = {"skipped": 0, "applied": 0}
    for round_number in range(20):
        group = group_with(admin_engine, tenant)
        invitation, token = invited(
            db, admin_engine, where, group, email=f"race{round_number}@example.org"
        )
        session = admin_session(db, admin_engine, where)
        results: dict[str, object] = {}

        def promote(group=group, session=session, results=results):
            try:
                access_control.set_group_roles(
                    runtime,
                    session,
                    group,
                    [{"role": "administrator", "space_id": None}],
                    "Promote the responders",
                )
                results["promote"] = "OK"
            except Exception as exc:  # noqa: BLE001 - recorded and asserted below
                results["promote"] = exc

        def join(token=token, results=results):
            try:
                results["join"] = accept_invitation(db, token, password=CHOSEN)
            except Exception as exc:  # noqa: BLE001 - recorded and asserted below
                results["join"] = exc

        racing.set()
        threads = [threading.Thread(target=promote), threading.Thread(target=join)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        racing.clear()
        assert results["promote"] == "OK", results
        joined = results["join"]
        assert not isinstance(joined, Exception), joined
        assert joined.outcome == "ACCEPTED"
        principal = joined.principal_id

        events = events_after_joining(admin_engine, tenant, principal)
        accepted = next(e for e in events if e["kind"] == "invitation.accepted")
        assert accepted["payload"]["invitation_id"] == str(invitation)
        member = principal in members_of(admin_engine, tenant, group)
        added = [
            e
            for e in events
            if e["kind"] == "access.group_member_added"
            and e["payload"]["principal_id"] == str(principal)
        ]
        promoted = [
            e
            for e in chain(admin_engine, tenant)
            if e["kind"] == "access.set_group_roles" and e["payload"]["subject_id"] == str(group)
        ]
        assert len(promoted) == 1
        if accepted["payload"]["reviewer_group_applied"]:
            outcomes["applied"] += 1
            assert member
            assert len(added) == 1
            assert promoted[0]["sequence"] > accepted["sequence"]
        else:
            outcomes["skipped"] += 1
            assert accepted["payload"]["reviewer_group_refusal"] == "GROUP_ROLES"
            assert not member
            assert added == []
            assert promoted[0]["sequence"] < accepted["sequence"]
    assert sum(outcomes.values()) == 20


# --- AR7: invite again, and where an invited Approver lands --------------------------------------


def test_ar7_inviting_again_replaces_an_expired_invitation_with_its_group(db, admin_engine, seeded):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    group = group_with(admin_engine, tenant)
    first, _ = invited(db, admin_engine, where, group)
    moment = now()
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.workspace_invitations SET created_at = :c, expires_at = :e "
                "WHERE invitation_id = :i"
            ),
            {"c": moment - timedelta(days=8), "e": moment - timedelta(days=1), "i": first},
        )
    second, _ = invited(db, admin_engine, where, group)
    assert second != first
    old, new = (
        invitation_row(admin_engine, tenant, first),
        invitation_row(admin_engine, tenant, second),
    )
    assert old["state"] == "REVOKED"
    assert (new["state"], new["reviewer_group_id"], new["grants"]) == (
        "PENDING",
        group,
        approver_in(where["space"]),
    )
    revoked = [e for e in chain(admin_engine, tenant) if e["kind"] == "invitation.revoked"]
    assert [e["payload"] for e in revoked] == [{"invitation_id": str(first), "reason": "EXPIRED"}]


def test_ar7_an_invited_approver_lands_on_approvals(db, admin_engine, human_config, seeded):
    where = workspace(admin_engine)
    group = group_with(admin_engine, where["tenant_id"])
    _, token = invited(db, admin_engine, where, group)
    app = create_app(db, runtime=bare_runtime(db), human=human_config)
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        shown = open_join(client, token)
        assert shown.status_code == 200
        _, values = form_values(shown.text, "/join/accept")
        values.update(password=CHOSEN, confirm=CHOSEN)
        made = client.post("/join/accept", data=values, headers={"Origin": ORIGIN})
        assert made.status_code == 303
        assert made.headers["location"] == "/approvals"

        # One who accepts while already signed in sees the joined page, as before.
        email = "existing-approver@example.org"
        _, _, grant, _ = account_holder(db, admin_engine, email, name="Their home")
        _, second = invited(db, admin_engine, where, group, email=email)
        client.cookies.clear()
        client.cookies.set(human_config.cookie("session"), grant.token)
        client.cookies.set(human_config.cookie("csrf"), grant.csrf_token)
        client.cookies.set(human_config.cookie("account"), grant.account_token)
        shown = open_join(client, second)
        _, values = form_values(shown.text, "/join/confirm")
        answer = client.post("/join/confirm", data=values, headers={"Origin": ORIGIN})
    assert answer.status_code == 200
    assert "You have joined" in answer.text


def test_ar2_the_service_refuses_a_group_with_a_typed_code(db, admin_engine, seeded):
    where = workspace(admin_engine)
    group = group_with(admin_engine, where["tenant_id"], [("administrator", None)])
    with pytest.raises(InvitationError) as refused:
        invited(db, admin_engine, where, group)
    assert refused.value.code == "INVALID_GROUP"
    assert json.dumps(refused.value.args) == json.dumps(("Invitation unavailable",))
