# SPDX-License-Identifier: AGPL-3.0-only
"""Human roles are live authority, independent of action-specific review assignment."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_execution import provision_identity
from test_execution import registry as registry
from test_execution import world as world

from execbound import access_control as access
from execbound.identity import authenticate
from execbound.policy.store import (
    PolicyStoreError,
    _identity,
    activate_bundle,
    create_bundle,
    read_bundle,
    validate_bundle,
)
from execbound.resolution.models import SystemClock
from execbound.surfaces.sessions import SessionError, issue_session, load_session


def test_role_catalog_never_grants_review_to_administrator():
    roles = {role["id"]: role for role in access.ROLES}
    assert set(roles) == {"administrator", "policy_manager", "approver", "viewer"}
    assert "approvals.decide" not in roles["administrator"]["permissions"]
    assert roles["administrator"]["scopes"] == ["WORKSPACE"]
    assert roles["viewer"]["permissions"] == ["console.read"]


@pytest.fixture
def humans(db, seeded, admin_engine):
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.principals SET kind='ADMIN', space_id=NULL"))
    return [authenticate(db, token) for token in seeded["tokens"]]


def test_unknown_permissions_fail_closed(db, humans):
    with db.transaction(humans[0].tenant_id) as conn:
        assert not access.has_permission(
            conn, humans[0].tenant_id, humans[0].principal_id, "invented"
        )
        assert access.has_permission(
            conn, humans[0].tenant_id, humans[0].principal_id, "access.manage"
        )


def test_last_administrator_is_preserved(db, humans):
    actor = humans[0]
    with pytest.raises(access.AccessError, match="LAST_ADMINISTRATOR"):
        with db.transaction(actor.tenant_id) as conn:
            access.set_roles_in(
                conn,
                actor.tenant_id,
                actor.principal_id,
                "user",
                actor.principal_id,
                [{"role": "viewer", "space_id": None}],
                "Reduce access",
            )
    with db.transaction(actor.tenant_id) as conn:
        assert access.has_permission(conn, actor.tenant_id, actor.principal_id, "access.manage")


def test_cross_tenant_role_assignment_is_refused(db, humans):
    actor, other = humans
    with pytest.raises(access.AccessError):
        with db.transaction(actor.tenant_id) as conn:
            access.set_roles_in(
                conn,
                actor.tenant_id,
                actor.principal_id,
                "user",
                other.principal_id,
                [{"role": "administrator", "space_id": None}],
                "Wrong tenant",
            )


def person(admin_engine, db, actor, kind="HUMAN_APPROVER"):
    return provision_identity(admin_engine, db, actor.tenant_id, kind, datetime.now(UTC))


def roles(db, actor, subject, grants):
    with db.transaction(actor.tenant_id) as conn:
        access.set_roles_in(
            conn,
            actor.tenant_id,
            actor.principal_id,
            "user",
            subject.principal_id,
            grants,
            "Test access change",
        )


def current(db, identity):
    with db.transaction(identity.tenant_id) as conn:
        return replace(
            identity, kind=access.effective_kind(conn, identity.tenant_id, identity.principal_id)
        )


def test_promoted_human_can_administer_and_stale_session_is_rejected(db, humans, admin_engine):
    from test_execution import provision_credential

    actor = humans[0]
    human = person(admin_engine, db, actor)
    session = issue_session(db, human)
    roles(db, actor, human, [{"role": "administrator", "space_id": None}])
    with pytest.raises(SessionError):
        load_session(db, session.token)
    # A promoted person authenticates again; the old bearer must never acquire admin.
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(actor.tenant_id)}
        )
        fresh = provision_credential(
            conn, actor.tenant_id, human.principal_id, datetime.now(UTC), timedelta(hours=1)
        )
    promoted = authenticate(db, fresh)
    assert promoted.kind == "ADMIN"
    with db.transaction(actor.tenant_id) as conn:
        _identity(conn, promoted, SystemClock(), admin=True)
        # The raw principal identity class was not rewritten to manufacture permission.
        assert (
            conn.execute(
                text("SELECT kind FROM execbound.principals WHERE principal_id=:p"),
                {"p": human.principal_id},
            ).scalar_one()
            == "HUMAN_APPROVER"
        )
        made = conn.execute(
            text("SELECT execbound.space_create('Granted admin',NULL,:p)"),
            {"p": human.principal_id},
        ).scalar_one()
        assert made
        assert not access.has_permission(
            conn, actor.tenant_id, human.principal_id, "approvals.decide", any_scope=True
        )


def test_demoted_original_admin_loses_sql_and_old_identity_authority(db, humans, admin_engine):
    actor = humans[0]
    human = person(admin_engine, db, actor, "ADMIN")
    session = issue_session(db, human)
    roles(db, actor, human, [{"role": "viewer", "space_id": None}])
    with pytest.raises(SessionError):
        load_session(db, session.token)
    with pytest.raises(PolicyStoreError):
        with db.transaction(actor.tenant_id) as conn:
            _identity(conn, human, SystemClock(), admin=True)
    with pytest.raises(DBAPIError, match="INVALID_ACTOR"):
        with db.transaction(actor.tenant_id) as conn:
            conn.execute(
                text("SELECT execbound.space_create('Forbidden',NULL,:p)"),
                {"p": human.principal_id},
            )
    viewer = current(db, human)
    assert viewer.kind == "HUMAN_APPROVER"
    assert issue_session(db, viewer)


def test_same_kind_last_role_revocation_ends_existing_session(db, humans, admin_engine):
    actor = humans[0]
    human = person(admin_engine, db, actor)
    roles(db, actor, human, [{"role": "viewer", "space_id": None}])
    session = issue_session(db, current(db, human))
    roles(db, actor, human, [])
    with pytest.raises(SessionError):
        load_session(db, session.token)
    with pytest.raises(SessionError):
        issue_session(db, current(db, human))


@pytest.mark.parametrize("via", ["user", "group_roles", "group_members"])
def test_promotion_revokes_previous_credentials_sessions_and_pending_resets(
    db, humans, admin_engine, via
):
    from test_execution import provision_credential

    from execbound.identity import AuthenticationFailed
    from execbound.passwords import PasswordError, issue_reset, redeem_reset

    actor = humans[0]
    human = person(admin_engine, db, actor)
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(actor.tenant_id)}
        )
        token = provision_credential(
            conn, actor.tenant_id, human.principal_id, datetime.now(UTC), timedelta(hours=1)
        )
        conn.execute(
            text("UPDATE execbound.principals SET email=:email WHERE principal_id=:p"),
            {"email": f"promotion-{human.principal_id}@example.test", "p": human.principal_id},
        )
    session = issue_session(db, authenticate(db, token))
    reset = issue_reset(db, actor.tenant_id, actor.principal_id, human.principal_id)
    with db.transaction(actor.tenant_id) as conn:
        if via == "user":
            access.set_roles_in(
                conn,
                actor.tenant_id,
                actor.principal_id,
                "user",
                human.principal_id,
                [{"role": "administrator", "space_id": None}],
                "Promote human",
            )
        else:
            group = access._change(
                conn,
                actor.tenant_id,
                actor.principal_id,
                "create_group",
                None,
                {"name": "Promoted group", "description": None},
                "New group",
            )
            if via == "group_roles":
                access._change(
                    conn,
                    actor.tenant_id,
                    actor.principal_id,
                    "set_members",
                    group,
                    {"members": [human.principal_id]},
                    "Add member",
                )
            access.set_roles_in(
                conn,
                actor.tenant_id,
                actor.principal_id,
                "group",
                group,
                [{"role": "administrator", "space_id": None}],
                "Promote group",
            )
            if via == "group_members":
                access._change(
                    conn,
                    actor.tenant_id,
                    actor.principal_id,
                    "set_members",
                    group,
                    {"members": [human.principal_id]},
                    "Add member",
                )
    with pytest.raises(AuthenticationFailed):
        authenticate(db, token)
    with pytest.raises(SessionError):
        load_session(db, session.token)
    with pytest.raises(PasswordError):
        redeem_reset(db, reset.code, "Previous reset cannot take admin control 726!")
    with db.transaction(actor.tenant_id) as conn:
        assert access.effective_kind(conn, actor.tenant_id, human.principal_id) == "ADMIN"
        assert (
            conn.execute(
                text("SELECT revoked_at FROM execbound.credentials WHERE credential_id=:c"),
                {"c": actor.credential_id},
            ).scalar_one()
            is None
        )


def test_promoted_person_can_sign_in_again_with_established_password(db, humans, admin_engine):
    from execbound.passwords import issue_reset, redeem_reset, sign_in_with_password

    actor = humans[0]
    human = person(admin_engine, db, actor)
    email = f"fresh-admin-{human.principal_id}@example.test"
    password = "Established password before role change 728!"
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(actor.tenant_id)}
        )
        conn.execute(
            text("UPDATE execbound.principals SET email=:email WHERE principal_id=:p"),
            {"email": email, "p": human.principal_id},
        )
    setup = issue_reset(db, actor.tenant_id, actor.principal_id, human.principal_id)
    redeem_reset(db, setup.code, password)
    roles(db, actor, human, [{"role": "administrator", "space_id": None}])
    fresh = sign_in_with_password(db, email, password)
    assert fresh.kind == "ADMIN"
    assert issue_session(db, fresh)


def test_promotion_revocation_handles_a_later_session_creation_time(db, humans, admin_engine):
    actor = humans[0]
    human = person(admin_engine, db, actor)
    issue_session(db, human)
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(actor.tenant_id)}
        )
        conn.execute(
            text(
                "UPDATE execbound.human_sessions "
                "SET created_at=clock_timestamp()+interval '5 seconds' "
                "WHERE tenant_id=:t AND principal_id=:p"
            ),
            {"t": actor.tenant_id, "p": human.principal_id},
        )
    roles(db, actor, human, [{"role": "administrator", "space_id": None}])
    with db.transaction(actor.tenant_id) as conn:
        assert conn.execute(
            text(
                "SELECT bool_and(revoked_at >= created_at) "
                "FROM execbound.human_sessions WHERE tenant_id=:t AND principal_id=:p"
            ),
            {"t": actor.tenant_id, "p": human.principal_id},
        ).scalar_one()


def test_workspace_promotion_ends_legacy_space_administrator_session(
    db, humans, admin_engine, seeded
):
    from space_fixtures import seat

    actor = humans[0]
    human = person(admin_engine, db, actor, "ADMIN")
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(actor.tenant_id)}
        )
        seat(conn, actor.tenant_id, seeded["spaces"][0], human.principal_id, "ADMIN")
    session = issue_session(db, human)
    roles(db, actor, human, [{"role": "administrator", "space_id": None}])
    with pytest.raises(SessionError):
        load_session(db, session.token)


def test_group_membership_preserves_legacy_access_and_revokes_inherited_access(
    db, humans, admin_engine, seeded
):
    actor = humans[0]
    human = person(admin_engine, db, actor)
    own_space = seeded["spaces"][0]
    with db.transaction(actor.tenant_id) as conn:
        group = access._change(
            conn,
            actor.tenant_id,
            actor.principal_id,
            "create_group",
            None,
            {"name": "Operations", "description": None},
            "New group",
        )
        access._change(
            conn,
            actor.tenant_id,
            actor.principal_id,
            "set_members",
            group,
            {"members": [human.principal_id]},
            "Add member",
        )
        access.set_roles_in(
            conn,
            actor.tenant_id,
            actor.principal_id,
            "group",
            group,
            [{"role": "policy_manager", "space_id": own_space}],
            "Grant policy",
        )
        assert not access.is_managed(conn, actor.tenant_id, human.principal_id)
        assert access.has_permission(
            conn, actor.tenant_id, human.principal_id, "approvals.decide", own_space
        )
        assert access.has_permission(
            conn, actor.tenant_id, human.principal_id, "policy.manage", own_space
        )
    with db.transaction(actor.tenant_id) as conn:
        access._change(
            conn,
            actor.tenant_id,
            actor.principal_id,
            "set_members",
            group,
            {"members": []},
            "Remove member",
        )
        assert not access.has_permission(
            conn, actor.tenant_id, human.principal_id, "policy.manage", own_space
        )
        assert access.has_permission(
            conn, actor.tenant_id, human.principal_id, "approvals.decide", own_space
        )


def test_group_cannot_add_agent_or_cross_tenant_person(db, humans, admin_engine):
    actor = humans[0]
    with db.transaction(actor.tenant_id) as conn:
        group = access._change(
            conn,
            actor.tenant_id,
            actor.principal_id,
            "create_group",
            None,
            {"name": "Operations", "description": None},
            "New group",
        )
    agent = person(admin_engine, db, actor, "AGENT")
    for forbidden in (humans[1].principal_id, agent.principal_id):
        with pytest.raises(access.AccessError, match="INVALID_PRINCIPAL"):
            with db.transaction(actor.tenant_id) as conn:
                access._change(
                    conn,
                    actor.tenant_id,
                    actor.principal_id,
                    "set_members",
                    group,
                    {"members": [forbidden]},
                    "Invalid member",
                )


def test_last_group_administrator_cannot_be_removed_or_deactivated(db, humans, admin_engine):
    actor = humans[0]
    human = person(admin_engine, db, actor)
    with db.transaction(actor.tenant_id) as conn:
        group = access._change(
            conn,
            actor.tenant_id,
            actor.principal_id,
            "create_group",
            None,
            {"name": "Administrators", "description": None},
            "New group",
        )
        access._change(
            conn,
            actor.tenant_id,
            actor.principal_id,
            "set_members",
            group,
            {"members": [human.principal_id]},
            "Add member",
        )
        access.set_roles_in(
            conn,
            actor.tenant_id,
            actor.principal_id,
            "group",
            group,
            [{"role": "administrator", "space_id": None}],
            "Grant admin",
        )
    roles(db, actor, actor, [{"role": "viewer", "space_id": None}])
    promoted = current(db, human)
    with pytest.raises(access.AccessError, match="LAST_ADMINISTRATOR"):
        with db.transaction(actor.tenant_id) as conn:
            access._change(
                conn,
                actor.tenant_id,
                promoted.principal_id,
                "set_members",
                group,
                {"members": []},
                "Remove final admin",
            )
    with pytest.raises(DBAPIError, match="INVALID_PRINCIPAL"):
        with db.transaction(actor.tenant_id) as conn:
            conn.execute(
                text("SELECT execbound.admin_deactivate_principal(:a,:a,'Disable')"),
                {"a": promoted.principal_id},
            )


def test_workspace_administrator_cannot_be_assigned_at_space_scope(db, humans, seeded):
    with pytest.raises(access.AccessError, match="INVALID_ROLE_SCOPE"):
        roles(
            db, humans[0], humans[0], [{"role": "administrator", "space_id": seeded["spaces"][0]}]
        )


def test_demoted_original_admin_cannot_count_as_last_admin_backup(db, humans, admin_engine, seeded):
    from execbound.spaces import SpaceError, assign_member

    actor = humans[0]
    backup = person(admin_engine, db, actor, "ADMIN")
    roles(db, actor, backup, [{"role": "viewer", "space_id": None}])
    with pytest.raises(SpaceError) as error:
        with db.transaction(actor.tenant_id) as conn:
            assign_member(
                conn,
                actor.tenant_id,
                actor.principal_id,
                seeded["spaces"][0],
                actor.principal_id,
                "ADMIN",
                credential=None,
            )
    assert error.value.code == "LAST_TENANT_ADMIN"


def test_two_concurrent_administrator_demotions_leave_one(db, humans, admin_engine):
    first = humans[0]
    second = person(admin_engine, db, first, "ADMIN")
    gate = Barrier(2)

    def demote(identity):
        gate.wait()
        try:
            roles(db, identity, identity, [{"role": "viewer", "space_id": None}])
            return "changed"
        except access.AccessError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(demote, [first, second]))
    assert sorted(results) == ["LAST_ADMINISTRATOR", "changed"]


def test_policy_manager_lifecycle_is_bound_to_authorized_space(db, world, admin_engine):
    actor, human = world["admin"], world["human"]
    second = uuid4()
    with admin_engine.begin() as conn:
        first = conn.execute(
            text("SELECT space_id FROM execbound.spaces WHERE tenant_id=:t"), {"t": actor.tenant_id}
        ).scalar_one()
        conn.execute(
            text(
                "INSERT INTO execbound.spaces(tenant_id,space_id,name,created_by,created_at) "
                "VALUES(:t,:s,'Other division',:p,now())"
            ),
            {"t": actor.tenant_id, "s": second, "p": actor.principal_id},
        )
        conn.execute(
            text(
                "UPDATE execbound.connector_accounts SET offered_tenant_wide=true "
                "WHERE tenant_id=:t"
            ),
            {"t": actor.tenant_id},
        )
    roles(
        db,
        actor,
        human,
        [{"role": "policy_manager", "space_id": first}, {"role": "viewer", "space_id": second}],
    )
    manager = current(db, human)
    own = world["bundle"].model_copy(update={"bundle_id": uuid4()})
    other = world["bundle"].model_copy(update={"bundle_id": uuid4()})
    assert create_bundle(db, manager, own, world["clock"], space=first).state == "DRAFT"
    assert validate_bundle(db, manager, own.bundle_id, world["clock"]).state == "VALIDATED"
    assert (
        activate_bundle(db, manager, own.bundle_id, world["clock"], space=first).state == "ACTIVE"
    )
    create_bundle(db, actor, other, world["clock"], space=second)
    with pytest.raises(PolicyStoreError):
        read_bundle(db, manager, other.bundle_id, world["clock"])
    with pytest.raises(PolicyStoreError):
        validate_bundle(db, manager, other.bundle_id, world["clock"])
    with pytest.raises(PolicyStoreError):
        activate_bundle(db, manager, own.bundle_id, world["clock"], space=second)
    roles(db, actor, human, [{"role": "viewer", "space_id": first}])
    with pytest.raises(PolicyStoreError):
        read_bundle(db, manager, own.bundle_id, world["clock"])


def test_runtime_role_cannot_write_authority_tables(db, humans):
    actor = humans[0]
    for table in (
        "access_principals",
        "access_groups",
        "access_group_members",
        "access_role_grants",
    ):
        with pytest.raises(DBAPIError, match="permission denied"):
            with db.transaction(actor.tenant_id) as conn:
                conn.execute(text(f"DELETE FROM execbound.{table}"))


@pytest.mark.parametrize("operation", ["link", "unlink", "invite"])
def test_promoted_administrator_directory_identity_cannot_be_changed(
    db, humans, admin_engine, operation
):
    actor = humans[0]
    promoted = person(admin_engine, db, actor)
    roles(db, actor, promoted, [{"role": "administrator", "space_id": None}])
    statements = {
        "link": "SELECT execbound.directory_link(:a,:p,:provider,'external-subject',now())",
        "unlink": "SELECT execbound.directory_unlink(:a,:p,now())",
        "invite": "SELECT execbound.directory_invite(:a,:p,:provider,:invite,:digest,"
        "now()+interval '2 days')",
    }
    with pytest.raises(DBAPIError, match="INVALID_PRINCIPAL"):
        with db.transaction(actor.tenant_id) as conn:
            conn.execute(
                text(statements[operation]),
                {
                    "a": actor.principal_id,
                    "p": promoted.principal_id,
                    "provider": uuid4(),
                    "invite": uuid4(),
                    "digest": "a" * 64,
                },
            )


def test_invitation_issued_before_promotion_cannot_bind_an_administrator(db, humans, admin_engine):
    from test_directory_store import ANOTHER_SUBJECT, RING, FixedClock, account, enabled

    from execbound import directory_store
    from execbound.directory import DirectoryConfig

    actor = humans[0]
    promoted = person(admin_engine, db, actor)
    config = DirectoryConfig(RING, "https://app.example")
    clock = FixedClock()
    cast = {"tenant": actor.tenant_id, "admin": actor.principal_id}
    provider = enabled(db, config, cast, clock)
    invitation = directory_store.invite(
        db, actor.tenant_id, actor.principal_id, promoted.principal_id, provider
    )
    roles(db, actor, promoted, [{"role": "administrator", "space_id": None}])
    with pytest.raises(directory_store.DirectoryError) as rejected:
        directory_store.sign_in(
            db,
            config,
            directory_store.locate_provider(db, provider),
            account(ANOTHER_SUBJECT),
            invitation_id=invitation.invitation_id,
            clock=clock,
        )
    assert rejected.value.code == "INVALID_INVITATION"


def test_promotion_preserves_established_directory_sign_in(db, humans, admin_engine):
    from test_directory_store import ANOTHER_SUBJECT, RING, FixedClock, account, enabled

    from execbound import directory_store
    from execbound.directory import DirectoryConfig

    actor = humans[0]
    human = person(admin_engine, db, actor)
    config = DirectoryConfig(RING, "https://app.example")
    clock = FixedClock()
    provider = enabled(db, config, {"tenant": actor.tenant_id, "admin": actor.principal_id}, clock)
    directory_store.link_person(
        db,
        actor.tenant_id,
        actor.principal_id,
        human.principal_id,
        provider,
        ANOTHER_SUBJECT,
        clock=clock,
    )
    located = directory_store.locate_provider(db, provider)
    previous = directory_store.sign_in(db, config, located, account(ANOTHER_SUBJECT), clock=clock)
    session = issue_session(db, previous, clock=clock)
    roles(db, actor, human, [{"role": "administrator", "space_id": None}])
    with pytest.raises(SessionError):
        load_session(db, session.token, clock=clock)
    fresh = directory_store.sign_in(db, config, located, account(ANOTHER_SUBJECT), clock=clock)
    assert fresh.kind == "ADMIN"
    assert issue_session(db, fresh, clock=clock)


def test_capabilities_do_not_disclose_unassigned_space_identifiers(
    db, humans, admin_engine, seeded
):
    from space_fixtures import make_space

    actor = humans[0]
    human = person(admin_engine, db, actor)
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(actor.tenant_id)}
        )
        hidden = make_space(conn, actor.tenant_id, "Invisible division")
    roles(db, actor, human, [{"role": "viewer", "space_id": seeded["spaces"][0]}])
    with db.transaction(actor.tenant_id) as conn:
        snapshot = access.capabilities(conn, actor.tenant_id, human.principal_id)
    assert set(snapshot["space_permissions"]) == {str(seeded["spaces"][0])}
    assert str(hidden) not in repr(snapshot)
    assert snapshot["workspace_permissions"] == []
    assert snapshot["permissions"] == ["console.read"]


def test_legacy_space_administrator_does_not_advertise_workspace_access_management(
    db, humans, admin_engine, seeded
):
    from space_fixtures import seat

    from execbound.runtime import Runtime
    from execbound.surfaces.console_api.errors import ApiError
    from execbound.surfaces.console_api.policy import PreviewBody, _preview

    actor = humans[0]
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(actor.tenant_id)}
        )
        seat(conn, actor.tenant_id, seeded["spaces"][0], actor.principal_id, "ADMIN")
    with db.transaction(actor.tenant_id) as conn:
        snapshot = access.capabilities(conn, actor.tenant_id, actor.principal_id)
        assert "access.manage" not in snapshot["permissions"]
        assert "workspace.manage" not in snapshot["permissions"]
        assert not access.owner_administrator(conn, actor.tenant_id, actor.principal_id)
    session = load_session(db, issue_session(db, actor).token)
    # Since #678 such an administrator previews too, but only over the decisions of the
    # spaces they administer (`tests/test_policy_preview_spaces.py`), so the preview is no
    # longer refused outright: a policy they cannot read answers as one that does not exist.
    with pytest.raises(ApiError) as rejected:
        _preview(Runtime(db, []), session, uuid4(), PreviewBody())
    assert rejected.value.code == "NOT_FOUND"
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(actor.tenant_id)}
        )
        assert not access.owner_administrator(conn, actor.tenant_id, actor.principal_id)


def test_search_does_not_disclose_targets_from_private_accounts_in_other_spaces(
    db, admin_engine, world
):
    from space_fixtures import default_space, make_space

    from execbound.runtime import Runtime
    from execbound.surfaces.console_api.search import search

    actor, human = world["admin"], world["human"]
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(actor.tenant_id)}
        )
        first = default_space(conn, actor.tenant_id)
        second = make_space(conn, actor.tenant_id, "Private target records")
        conn.execute(
            text(
                "UPDATE execbound.connector_accounts SET space_id=:s "
                "WHERE tenant_id=:t AND account_id=:a"
            ),
            {"t": actor.tenant_id, "s": second, "a": world["account"]},
        )
    roles(db, actor, human, [{"role": "viewer", "space_id": first}])
    session = load_session(
        db, issue_session(db, human, clock=world["clock"]).token, clock=world["clock"]
    )
    runtime = Runtime(db, [], clock=world["clock"])
    assert search(runtime, session, "ws01") == []
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(actor.tenant_id)}
        )
        conn.execute(
            text(
                "UPDATE execbound.connector_accounts SET offered_tenant_wide=true "
                "WHERE tenant_id=:t AND account_id=:a"
            ),
            {"t": actor.tenant_id, "a": world["account"]},
        )
    assert [row.kind for row in search(runtime, session, "ws01")] == ["target"]
