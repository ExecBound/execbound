# SPDX-License-Identifier: AGPL-3.0-only
"""What the spaces tests share: a second space, a membership, a switch.

Migration 0041 gives every tenant exactly one `Default` space, seats every existing
approver in it and deliberately seats no administrator, so a tenant that never makes a
second space behaves exactly as it did. These helpers are for the tests that do make a
second one, and for the fixtures that create a person directly rather than through
`admin_create_principal`, which seats them itself.
"""

from uuid import UUID, uuid4

from sqlalchemy import text


def default_space(conn, tenant: UUID) -> UUID:
    """The tenant's one space, as every backfilled column names it."""
    return UUID(
        str(
            conn.execute(
                text(
                    "SELECT space_id FROM execbound.spaces WHERE tenant_id=:t "
                    "ORDER BY created_at, space_id LIMIT 1"
                ),
                {"t": tenant},
            ).scalar_one()
        )
    )


def make_space(conn, tenant: UUID, name: str, *, created_by: UUID | None = None) -> UUID:
    """A second space of the tenant, written on the owner connection."""
    space = uuid4()
    conn.execute(
        text(
            "INSERT INTO execbound.spaces"
            "(tenant_id, space_id, name, created_at, created_by) "
            "VALUES (:t, :s, :n, now(), :by)"
        ),
        {"t": tenant, "s": space, "n": name, "by": created_by or UUID(int=0)},
    )
    return space


def seat(conn, tenant: UUID, space: UUID, principal: UUID, role: str = "HUMAN_APPROVER") -> None:
    """Make one person a member of one space, with the role their kind allows."""
    conn.execute(
        text(
            "INSERT INTO execbound.space_members"
            "(tenant_id, space_id, principal_id, role, assigned_at) "
            "VALUES (:t, :s, :p, :r, now()) "
            "ON CONFLICT (tenant_id, space_id, principal_id) DO UPDATE SET role = excluded.role"
        ),
        {"t": tenant, "s": space, "p": principal, "r": role},
    )


def seat_in_default(conn, tenant: UUID, principal: UUID, role: str = "HUMAN_APPROVER") -> UUID:
    """Seat one person in the tenant's default space, as the migration seats approvers."""
    space = default_space(conn, tenant)
    seat(conn, tenant, space, principal, role)
    return space


def unseat(conn, tenant: UUID, space: UUID, principal: UUID) -> None:
    conn.execute(
        text(
            "DELETE FROM execbound.space_members "
            "WHERE tenant_id=:t AND space_id=:s AND principal_id=:p"
        ),
        {"t": tenant, "s": space, "p": principal},
    )


def place(conn, tenant: UUID, table: str, key: str, identifier: UUID, space: UUID) -> None:
    """Move one owned row into another space, for a two-space isolation case.

    The table, its key column and the space are the test's own literals; the identifiers
    are bound. Production has no move path at all, so this exists to build a fixture and
    nowhere else.
    """
    conn.execute(
        text(
            f"UPDATE execbound.{table} SET space_id=:s "  # noqa: S608
            f"WHERE tenant_id=:t AND {key}=:i"  # nosec B608 - the test's own literals
        ),
        {"t": tenant, "s": space, "i": identifier},
    )


def current_space(conn, tenant: UUID, session: UUID) -> UUID | None:
    value = conn.execute(
        text(
            "SELECT current_space_id FROM execbound.human_sessions "
            "WHERE tenant_id=:t AND session_id=:s"
        ),
        {"t": tenant, "s": session},
    ).scalar_one()
    return None if value is None else UUID(str(value))


def move_agent_to_a_second_space(admin_engine, world) -> UUID:
    """The world's agent moves to a new space that selects the same bundle.

    Its connector account stays behind in the default space, not offered tenant-wide, so the
    agent's operations are now named through another space's account. `world` is the
    execution world (`tests/test_execution.py`); returns the new space.
    """
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        second = make_space(conn, tenant, "Customer B")
        conn.execute(
            text(
                "UPDATE execbound.principals SET space_id=:s WHERE tenant_id=:t AND principal_id=:p"
            ),
            {"t": tenant, "s": second, "p": world["identity"].principal_id},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.space_policy_selection"
                "(tenant_id, space_id, bundle_id, changed_at, changed_by) "
                "VALUES (:t, :s, :b, now(), :a)"
            ),
            {
                "t": tenant,
                "s": second,
                "b": world["bundle"].bundle_id,
                "a": world["admin"].principal_id,
            },
        )
    return second
