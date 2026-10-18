# SPDX-License-Identifier: AGPL-3.0-only
"""The visible set, the narrowing rule and the space lifecycle, on real PostgreSQL.

SP2 (the whole visible set, not only an administrator's), SP3 (membership restricts, the
ADMIN role narrows and only narrows, and the last tenant administrator cannot be narrowed
away) and SP4 (the current space is a preference and every read rechecks membership).
"""

import inspect
from uuid import uuid4

import pytest
from space_fixtures import default_space, make_space, seat, unseat
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import world as world
from test_runtime import runtime as runtime

from execbound.spaces import (
    SpaceError,
    Visibility,
    archive_space,
    assign_member,
    create_space,
    is_archived,
    principal_allows,
    rename_space,
    set_current_space,
    space_clause,
    unarchive_space,
    unassign_member,
    visible_spaces,
)
from execbound.surfaces.sessions import issue_session, load_session

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    "change",
    [create_space, rename_space, archive_space, unarchive_space, assign_member, unassign_member],
)
def test_every_space_change_makes_its_caller_say_which_credential_acted(change):
    """No default: a caller that leaves the credential out is a TypeError, not an event that
    silently names nobody. The console passes its session's credential; an owner command,
    which acts with none, says so with `credential=None`."""
    parameter = inspect.signature(change).parameters["credential"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty


def session_for(db, identity, clock=None):
    """A session on the test's own clock, so `check_session` reads the same instant the
    surfaces read; a session issued on the wall clock is a second in the future to them."""
    return load_session(db, issue_session(db, identity, clock=clock).token, clock=clock)


def visibility_of(db, session):
    with db.transaction(session.identity.tenant_id) as conn:
        return visible_spaces(conn, session)


def test_sp2_a_tenant_administrator_sees_every_space_and_a_member_sees_theirs(
    db, admin_engine, world
):
    tenant = world["identity"].tenant_id
    admin_session = session_for(db, world["admin"])
    approver_session = session_for(db, world["human"])
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, "Second")

    administrator = visibility_of(db, admin_session)
    assert administrator.everything and administrator.spaces == ()
    assert administrator.allows_many(2)
    assert administrator.allows(first) and administrator.allows(second)
    # A tenant administrator looking at every space contributes no predicate at all, so a
    # tenant that never made a second space runs the plans it always ran.
    assert space_clause(administrator, "e").sql == ""

    member = visibility_of(db, approver_session)
    assert not member.everything and member.spaces == (first,)
    assert not member.allows_many(2)
    assert member.allows(first) and not member.allows(second)
    assert "space_set" in space_clause(member, "e").params

    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        seat(conn, tenant, second, world["human"].principal_id)
    both = visibility_of(db, approver_session)
    assert sorted(both.spaces) == sorted((first, second))
    assert both.allows_many(2) and not both.everything


def test_sp3_a_tenant_administrator_given_a_membership_is_narrowed_at_once(db, admin_engine, world):
    tenant = world["identity"].tenant_id
    admin_session = session_for(db, world["admin"])
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, "Second")
    assert visibility_of(db, admin_session).everything
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        seat(conn, tenant, second, world["admin"].principal_id, "ADMIN")
    narrowed = visibility_of(db, admin_session)
    assert not narrowed.everything and narrowed.spaces == (second,)
    assert not narrowed.allows(first)


def test_sp3_the_admin_role_is_refused_for_an_approver_principal(db, world):
    """The space role narrows and only narrows, so `principals.kind` stays a necessary
    condition wherever it is checked and no area module weakens."""
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    with db.transaction(tenant) as conn:
        space = create_space(conn, tenant, actor, "Customer A", None, credential=None)
        with pytest.raises(SpaceError) as refused:
            assign_member(
                conn, tenant, actor, space, world["human"].principal_id, "ADMIN", credential=None
            )
    assert refused.value.code == "INVALID_ROLE"


def test_sp3_the_last_tenant_administrator_cannot_be_narrowed_away(db, world):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    with db.transaction(tenant) as conn:
        space = create_space(conn, tenant, actor, "Customer A", None, credential=None)
        with pytest.raises(SpaceError) as refused:
            assign_member(conn, tenant, actor, space, actor, "ADMIN", credential=None)
    assert refused.value.code == "LAST_TENANT_ADMIN"


def test_a_refusal_rolls_the_callers_transaction_back(db, world):
    """Every typed refusal is a database exception, so nothing the caller wrote survives."""
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    with pytest.raises(SpaceError) as refused, db.transaction(tenant) as conn:
        create_space(conn, tenant, actor, "Customer A", None, credential=None)
        create_space(conn, tenant, actor, "customer a", None, credential=None)
    assert refused.value.code == "NAME_TAKEN"
    with db.transaction(tenant) as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.spaces WHERE tenant_id=:t"), {"t": tenant}
            ).scalar_one()
            == 1
        )


def test_a_name_is_bounded_and_free_case_insensitively(db, world):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    for name, code in ((" ", "INVALID_NAME"), ("x" * 81, "INVALID_NAME")):
        with pytest.raises(SpaceError) as refused, db.transaction(tenant) as conn:
            create_space(conn, tenant, actor, name, None, credential=None)
        assert refused.value.code == code


def test_archive_and_unarchive_refuse_the_last_unarchived_space(db, world):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    with db.transaction(tenant) as conn:
        first = default_space(conn, tenant)
        with pytest.raises(SpaceError) as refused:
            archive_space(conn, tenant, actor, first, "closing", credential=None)
    assert refused.value.code == "CONFLICT"
    with db.transaction(tenant) as conn:
        second = create_space(conn, tenant, actor, "Customer B", "second line", credential=None)
    with db.transaction(tenant) as conn:
        archive_space(conn, tenant, actor, second, "customer left", credential=None)
    with db.transaction(tenant) as conn:
        assert is_archived(conn, tenant, second)
    # An archived space takes no new work, and the refusal rolls its caller back.
    with pytest.raises(SpaceError) as refused, db.transaction(tenant) as conn:
        assign_member(
            conn,
            tenant,
            actor,
            second,
            world["human"].principal_id,
            "HUMAN_APPROVER",
            credential=None,
        )
    assert refused.value.code == "SPACE_ARCHIVED"
    with db.transaction(tenant) as conn:
        unarchive_space(conn, tenant, actor, second, "customer returned", credential=None)
        assert not is_archived(conn, tenant, second)
        rename_space(conn, tenant, actor, second, "Customer B2", None, credential=None)


def test_only_a_tenant_administrator_administers_spaces(db, admin_engine, world):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    with db.transaction(tenant) as conn:
        space = create_space(conn, tenant, actor, "Customer A", None, credential=None)
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        seat(conn, tenant, space, actor, "ADMIN")
    with pytest.raises(SpaceError) as refused, db.transaction(tenant) as conn:
        create_space(conn, tenant, actor, "Customer C", None, credential=None)
    assert refused.value.code == "INVALID_ACTOR"
    with pytest.raises(SpaceError) as refused, db.transaction(tenant) as conn:
        # An approver is not an administrator of anything.
        create_space(conn, tenant, world["human"].principal_id, "Customer D", None, credential=None)
    assert refused.value.code == "INVALID_ACTOR"


def test_sp4_the_current_space_is_a_preference_and_a_removed_member_loses_it(
    db, admin_engine, world
):
    tenant = world["identity"].tenant_id
    approver_session = session_for(db, world["human"])
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        first = default_space(conn, tenant)
    with db.transaction(tenant) as conn:
        set_current_space(conn, approver_session, first)
    assert visibility_of(db, approver_session).current == first
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        unseat(conn, tenant, first, world["human"].principal_id)
    # The narrowing drops it: the session's column grants nothing.
    narrowed = visibility_of(db, approver_session)
    assert narrowed.current is None and narrowed.spaces == ()
    assert not narrowed.allows(first)


def test_sp4_setting_a_space_the_person_does_not_belong_to_is_refused(db, admin_engine, world):
    tenant = world["identity"].tenant_id
    approver_session = session_for(db, world["human"])
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        second = make_space(conn, tenant, "Second")
    with pytest.raises(SpaceError) as refused, db.transaction(tenant) as conn:
        set_current_space(conn, approver_session, second)
    assert refused.value.code == "INVALID_SPACE"
    # An unknown space and another tenant's answer the same way.
    with pytest.raises(SpaceError) as refused, db.transaction(tenant) as conn:
        set_current_space(conn, approver_session, uuid4())
    assert refused.value.code == "INVALID_SPACE"


def test_a_tenant_administrator_may_set_any_space_and_clear_it(db, admin_engine, world):
    tenant = world["identity"].tenant_id
    admin_session = session_for(db, world["admin"])
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        second = make_space(conn, tenant, "Second")
    with db.transaction(tenant) as conn:
        set_current_space(conn, admin_session, second)
    assert visibility_of(db, admin_session).current == second
    with db.transaction(tenant) as conn:
        set_current_space(conn, admin_session, None)
    assert visibility_of(db, admin_session).current is None


def test_membership_is_the_authority_for_one_row(db, admin_engine, world):
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, "Second")
    with db.transaction(tenant) as conn:
        assert principal_allows(conn, tenant, world["human"].principal_id, first)
        assert not principal_allows(conn, tenant, world["human"].principal_id, second)
        # A tenant administrator holds no membership at all and may act in every space.
        assert principal_allows(conn, tenant, world["admin"].principal_id, second)


def test_unassigning_a_membership_is_always_allowed_and_unknown_is_refused(db, world):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    with db.transaction(tenant) as conn:
        space = create_space(conn, tenant, actor, "Customer A", None, credential=None)
        assign_member(
            conn,
            tenant,
            actor,
            space,
            world["human"].principal_id,
            "HUMAN_APPROVER",
            credential=None,
        )
        unassign_member(conn, tenant, actor, space, world["human"].principal_id, credential=None)
        with pytest.raises(SpaceError) as refused:
            unassign_member(
                conn, tenant, actor, space, world["human"].principal_id, credential=None
            )
    assert refused.value.code == "INVALID_PRINCIPAL"


def test_the_visibility_of_nobody_allows_nothing():
    """A person of a kind that is not a tenant administrator and holds no membership sees
    nothing at all, which is "membership restricts" working rather than a surprise."""
    nobody = Visibility(everything=False, spaces=(), current=None, roles={})
    assert not nobody.allows_many(2)
    assert not nobody.unfiltered
    filtered = space_clause(nobody, "e")
    assert filtered.params["space_set"] == []
