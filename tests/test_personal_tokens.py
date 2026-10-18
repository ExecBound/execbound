# SPDX-License-Identifier: AGPL-3.0-only
"""Personal access tokens (design 2026-09-25): the schema, the store and the owner rules."""

import hashlib
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Event
from uuid import UUID, uuid4

import pytest
from alembic import command as alembic
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_execution import provision_credential, provision_identity
from test_execution import registry as registry
from test_execution import world as world
from test_migration_without_bypass import fenced
from test_migration_without_bypass import restricted as restricted
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound import access_control as access
from execbound.db import SCHEMA_REVISION
from execbound.identity import NEVER, authenticate
from execbound.personal_tokens import (
    TokenError,
    TokenSession,
    delete_token,
    issue_token,
    list_tokens,
    load_token_session,
    revoke_token,
)
from execbound.surfaces import people_pages
from execbound.surfaces.sessions import (
    SessionError,
    check_session,
    issue_session,
    load_session,
    revoke_other_sessions,
)


def admin_session(runtime, identity):
    grant = issue_session(runtime.db, identity, clock=runtime.clock)
    return load_session(runtime.db, grant.token, clock=runtime.clock)


def digest() -> str:
    return hashlib.sha256(secrets.token_bytes(32)).hexdigest()


def issue_row(runtime, actor, *, expires_at=None, name="ci"):
    """Call the definer function directly, as the runtime role, under the tenant fence."""
    token, credential = uuid4(), uuid4()
    now = datetime.now(UTC)
    with runtime.db.transaction(actor.tenant_id) as conn:
        conn.execute(
            text("SELECT execbound.admin_issue_personal_token(:a,:k,:c,:n,:h,:ch,:i,:e)"),
            {
                "a": actor.principal_id,
                "k": token,
                "c": credential,
                "n": name,
                "h": digest(),
                "ch": digest(),
                "i": now,
                "e": expires_at or now + timedelta(days=30),
            },
        )
    return token, credential


def revoke_credential(admin_engine, credential):
    """The blunt kind of revoke a deactivation, a password reset or a promotion does: the
    credential dies without personal_access_tokens ever being touched (0036, 0040, 0047). The
    runtime role has no direct write on credentials by design, so this goes through the
    owner connection, the same as `provision_credential` in test_execution.py does."""
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.credentials SET revoked_at = now() WHERE credential_id=:c"),
            {"c": credential},
        )


def test_an_administrator_mints_a_token_and_its_backing_credential(runtime, admin_engine, world):
    token, credential = issue_row(runtime, world["admin"])
    with admin_engine.connect() as conn:
        row = (
            conn.execute(
                text("SELECT * FROM execbound.personal_access_tokens WHERE token_id=:k"),
                {"k": token},
            )
            .mappings()
            .one()
        )
        backing = (
            conn.execute(
                text(
                    "SELECT principal_id, expires_at FROM execbound.credentials "
                    "WHERE credential_id=:c"
                ),
                {"c": credential},
            )
            .mappings()
            .one()
        )
    assert row["principal_id"] == world["admin"].principal_id
    assert backing["principal_id"] == world["admin"].principal_id
    assert backing["expires_at"] == row["expires_at"]


@pytest.mark.parametrize("who", ["human", "identity"])
def test_only_an_administrator_mints_one(runtime, world, who):
    with pytest.raises(DBAPIError, match="INVALID_ACTOR"):
        issue_row(runtime, world[who])


def test_a_token_that_never_expires_is_accepted_and_ninety_one_days_is_not(runtime, world):
    issue_row(runtime, world["admin"], expires_at=NEVER)
    with pytest.raises(DBAPIError, match="INVALID_LIFETIME"):
        issue_row(runtime, world["admin"], expires_at=datetime.now(UTC) + timedelta(days=91))


def test_an_owner_holds_at_most_ten_live_tokens(runtime, world):
    for _ in range(10):
        issue_row(runtime, world["admin"])
    with pytest.raises(DBAPIError, match="TOO_MANY_TOKENS"):
        issue_row(runtime, world["admin"])


def test_the_live_token_count_ignores_a_token_whose_backing_credential_was_revoked(
    runtime, admin_engine, world
):
    """Deactivation, a password reset and a promotion revoke every credential a principal
    holds without touching personal_access_tokens (0036, 0040, 0047): the live-token count
    must see that, or an owner could hold ten `live` rows with dead credentials and never
    mint again."""
    actor = world["admin"]
    tokens = [issue_row(runtime, actor) for _ in range(10)]
    _, revoked_credential = tokens[0]
    revoke_credential(admin_engine, revoked_credential)
    # An eleventh token row overall, but only the tenth whose backing credential is live.
    issue_row(runtime, actor)


def test_a_ninth_and_tenth_issue_race_and_exactly_one_wins(runtime, admin_engine, world):
    """The advisory lock, not just the count, prevents a concurrent double-issue: the second
    issuer is made to actually block behind the first (`pg_blocking_pids`), matching the
    deterministic pattern test_hosted_free.py's HF58 uses for the same class of race, rather
    than trusting scheduling to produce it."""
    actor = world["admin"]
    for _ in range(9):
        issue_row(runtime, actor)
    ran_first = Event()
    second_ready = Event()
    second_done = Event()
    seen: dict[str, object] = {}

    def attempt(conn):
        token, credential = uuid4(), uuid4()
        now = datetime.now(UTC)
        conn.execute(
            text("SELECT execbound.admin_issue_personal_token(:a,:k,:c,:n,:h,:ch,:i,:e)"),
            {
                "a": actor.principal_id,
                "k": token,
                "c": credential,
                "n": "ci",
                "h": digest(),
                "ch": digest(),
                "i": now,
                "e": now + timedelta(days=30),
            },
        )

    def run_first():
        with runtime.db.transaction(actor.tenant_id) as conn:
            attempt(conn)
            ran_first.set()
            assert second_ready.wait(5)
            deadline = time.monotonic() + 4
            blocked = False
            while not blocked and not second_done.is_set() and time.monotonic() < deadline:
                with admin_engine.connect() as probe:
                    blocked = bool(
                        probe.execute(
                            text("SELECT cardinality(pg_blocking_pids(:pid)) > 0"),
                            {"pid": seen["pid"]},
                        ).scalar_one()
                    )
                if not blocked:
                    time.sleep(0.02)
            seen["blocked"] = blocked
        return "ok"

    def run_second():
        try:
            with runtime.db.transaction(actor.tenant_id) as conn:
                seen["pid"] = conn.execute(text("SELECT pg_backend_pid()")).scalar_one()
                second_ready.set()
                assert ran_first.wait(5)
                attempt(conn)
            return "ok"
        finally:
            second_done.set()

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {"first": executor.submit(run_first), "second": executor.submit(run_second)}
        outcomes: dict[str, object] = {}
        for name, future in futures.items():
            try:
                outcomes[name] = future.result()
            except DBAPIError as error:
                outcomes[name] = error

    assert outcomes["first"] == "ok", outcomes
    refusal = outcomes["second"]
    assert isinstance(refusal, DBAPIError), outcomes
    assert "TOO_MANY_TOKENS" in str(refusal.orig)
    assert seen["blocked"] is True


def test_revoking_a_token_frees_a_slot_for_the_next_issue(runtime, world):
    actor = world["admin"]
    tokens = [issue_row(runtime, actor)[0] for _ in range(10)]
    with runtime.db.transaction(actor.tenant_id) as conn:
        conn.execute(
            text("SELECT execbound.admin_revoke_personal_token(:a,:k,:n)"),
            {"a": actor.principal_id, "k": tokens[0], "n": datetime.now(UTC)},
        )
    issue_row(runtime, actor)


def test_revoking_revokes_the_backing_credential_and_delete_needs_a_spent_token(
    runtime, admin_engine, world
):
    token, credential = issue_row(runtime, world["admin"])
    actor = world["admin"]
    with runtime.db.transaction(actor.tenant_id) as conn:
        with pytest.raises(DBAPIError, match="INVALID_TOKEN"):
            with conn.begin_nested():
                conn.execute(
                    text("SELECT execbound.admin_delete_personal_token(:a,:k,:n)"),
                    {"a": actor.principal_id, "k": token, "n": datetime.now(UTC)},
                )
        conn.execute(
            text("SELECT execbound.admin_revoke_personal_token(:a,:k,:n)"),
            {"a": actor.principal_id, "k": token, "n": datetime.now(UTC)},
        )
        conn.execute(
            text("SELECT execbound.admin_delete_personal_token(:a,:k,:n)"),
            {"a": actor.principal_id, "k": token, "n": datetime.now(UTC)},
        )
    with admin_engine.connect() as conn:
        revoked, deleted = conn.execute(
            text("SELECT revoked_at, deleted_at FROM execbound.credentials WHERE credential_id=:c"),
            {"c": credential},
        ).one()
    assert revoked is not None and deleted is not None


def test_revoke_by_a_different_administrator_records_who_and_an_approver_is_refused(
    runtime, admin_engine, world
):
    actor = world["admin"]
    other_admin = provision_identity(
        admin_engine, runtime.db, actor.tenant_id, "ADMIN", datetime.now(UTC)
    )
    token, _ = issue_row(runtime, actor)
    with pytest.raises(DBAPIError, match="INVALID_ACTOR"):
        with runtime.db.transaction(actor.tenant_id) as conn:
            conn.execute(
                text("SELECT execbound.admin_revoke_personal_token(:a,:k,:n)"),
                {"a": world["human"].principal_id, "k": token, "n": datetime.now(UTC)},
            )
    with runtime.db.transaction(actor.tenant_id) as conn:
        conn.execute(
            text("SELECT execbound.admin_revoke_personal_token(:a,:k,:n)"),
            {"a": other_admin.principal_id, "k": token, "n": datetime.now(UTC)},
        )
    with admin_engine.connect() as conn:
        revoked_at, revoked_by = conn.execute(
            text(
                "SELECT revoked_at, revoked_by FROM execbound.personal_access_tokens "
                "WHERE token_id=:k"
            ),
            {"k": token},
        ).one()
    assert revoked_at is not None
    assert revoked_by == other_admin.principal_id


def expired_row(admin_engine, actor):
    """A token already past its expiry, built directly rather than through the issuing
    function, which refuses any expiry under an hour out: a token cannot practically be aged
    to `expired` within a test's real wall-clock budget, so its already-expired state is
    seeded by hand. The runtime role has no direct write on either table, so the row is
    seeded through the owner connection, the same as `revoke_credential` above."""
    token, credential = uuid4(), uuid4()
    now = datetime.now(UTC)
    created_at = now - timedelta(hours=2)
    expires_at = now - timedelta(hours=1)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.credentials"
                "(tenant_id, credential_id, principal_id, token_hash, issued_at, expires_at) "
                "VALUES (:t, :c, :p, :h, :i, :e)"
            ),
            {
                "t": actor.tenant_id,
                "c": credential,
                "p": actor.principal_id,
                "h": digest(),
                "i": created_at,
                "e": expires_at,
            },
        )
        conn.execute(
            text(
                "INSERT INTO execbound.personal_access_tokens"
                "(tenant_id, token_id, principal_id, credential_id, name, token_hash, "
                "created_at, expires_at) "
                "VALUES (:t, :k, :p, :c, 'expired', :h, :i, :e)"
            ),
            {
                "t": actor.tenant_id,
                "k": token,
                "p": actor.principal_id,
                "c": credential,
                "h": digest(),
                "i": created_at,
                "e": expires_at,
            },
        )
    return token, credential


def test_delete_succeeds_for_an_expired_but_unrevoked_token(runtime, admin_engine, world):
    actor = world["admin"]
    token, _ = expired_row(admin_engine, actor)
    with runtime.db.transaction(actor.tenant_id) as conn:
        conn.execute(
            text("SELECT execbound.admin_delete_personal_token(:a,:k,:n)"),
            {"a": actor.principal_id, "k": token, "n": datetime.now(UTC)},
        )
    with admin_engine.connect() as conn:
        deleted = conn.execute(
            text("SELECT deleted_at FROM execbound.personal_access_tokens WHERE token_id=:k"),
            {"k": token},
        ).scalar_one()
    assert deleted is not None


def set_role(runtime, actor, subject, role):
    with runtime.db.transaction(actor.tenant_id) as conn:
        access.set_roles_in(
            conn,
            actor.tenant_id,
            actor.principal_id,
            "user",
            subject.principal_id,
            [{"role": role, "space_id": None}],
            "Test access change",
        )


def signed_in_afresh(runtime, admin_engine, person):
    """A new credential for a person whose earlier ones a promotion revoked."""
    with admin_engine.begin() as conn:
        fresh = provision_credential(
            conn, person.tenant_id, person.principal_id, runtime.clock.now(), timedelta(hours=2)
        )
    return authenticate(runtime.db, fresh)


@pytest.mark.parametrize("how", ["promotion", "deactivation"])
def test_a_token_revoked_through_its_backing_credential_can_be_deleted(
    runtime, admin_engine, world, how
):
    """A promotion (0047) and a deactivation (0036) revoke every credential a principal holds
    without touching personal_access_tokens, so the token lists as `revoked` while its own
    `revoked_at` stays empty. The console offers Delete for it, and the delete must succeed
    rather than answer a conflict forever; the audit history keeps the token.

    The owner is a person made an administrator by an access grant: a legacy ADMIN principal
    can be neither deactivated nor promoted. Taken back to a viewer first, they can be either,
    which is how an administrator reaches both functions."""
    admin = world["admin"]
    owner = provision_identity(
        admin_engine, runtime.db, admin.tenant_id, "HUMAN_APPROVER", runtime.clock.now()
    )
    set_role(runtime, admin, owner, "administrator")
    owner = signed_in_afresh(runtime, admin_engine, owner)
    token, view = issue_token(
        runtime.db, admin_session(runtime, owner), "ci", timedelta(days=1), clock=runtime.clock
    )
    token_id = UUID(view["token_id"])
    set_role(runtime, admin, owner, "viewer")
    if how == "promotion":
        # Made an administrator again: every credential the owner held is revoked, the
        # token's backing credential with it, and the owner signs in afresh to clean up.
        set_role(runtime, admin, owner, "administrator")
        acting = admin_session(runtime, signed_in_afresh(runtime, admin_engine, owner))
    else:
        acting = admin_session(runtime, admin)
        people_pages.deactivate(runtime, acting, owner.principal_id, "left the team")
    # PT5: whichever path revoked it, the token itself is refused on its very next request,
    # not only reported `revoked` by the store's own listing below.
    with pytest.raises(SessionError):
        load_token_session(runtime.db, token, clock=runtime.clock)
    with admin_engine.connect() as conn:
        own_revoked, credential_revoked = conn.execute(
            text(
                "SELECT k.revoked_at, c.revoked_at FROM execbound.personal_access_tokens k "
                "JOIN execbound.credentials c USING (tenant_id, credential_id) "
                "WHERE k.token_id=:k"
            ),
            {"k": token_id},
        ).one()
    assert own_revoked is None and credential_revoked is not None
    listed = list_tokens(runtime.db, acting, everyone=True, clock=runtime.clock)
    assert [row["state"] for row in listed if row["token_id"] == view["token_id"]] == ["revoked"]
    delete_token(runtime.db, acting, token_id, clock=runtime.clock)
    listed = list_tokens(runtime.db, acting, everyone=True, clock=runtime.clock)
    assert view["token_id"] not in {row["token_id"] for row in listed}
    with admin_engine.connect() as conn:
        name, deleted_at = conn.execute(
            text("SELECT name, deleted_at FROM execbound.personal_access_tokens WHERE token_id=:k"),
            {"k": token_id},
        ).one()
        kinds = (
            conn.execute(
                text(
                    "SELECT kind FROM execbound.audit_events "
                    "WHERE tenant_id=:t AND payload->>'token_id' = :k ORDER BY sequence"
                ),
                {"t": admin.tenant_id, "k": str(token_id)},
            )
            .scalars()
            .all()
        )
    assert name == "ci" and deleted_at is not None
    assert kinds == ["personal_token.issued", "personal_token.deleted"]


def test_listing_and_delete_agree_on_every_state(runtime, admin_engine, world):
    """Delete is offered for every row the list does not call `live`, so the definer
    function must accept exactly those: a token revoked itself, one revoked through its
    backing credential, and one past its expiry; and refuse the live one."""
    actor = world["admin"]
    session = admin_session(runtime, actor)

    def issued(name):
        _, view = issue_token(runtime.db, session, name, timedelta(days=1), clock=runtime.clock)
        return UUID(view["token_id"])

    live, revoked, underneath = issued("live"), issued("revoked"), issued("underneath")
    revoke_token(runtime.db, session, revoked, clock=runtime.clock)
    with admin_engine.connect() as conn:
        credential = conn.execute(
            text("SELECT credential_id FROM execbound.personal_access_tokens WHERE token_id=:k"),
            {"k": underneath},
        ).scalar_one()
    revoke_credential(admin_engine, credential)
    expired, _ = expired_row(admin_engine, actor)
    states = {
        row["name"]: row["state"]
        for row in list_tokens(runtime.db, session, everyone=False, clock=runtime.clock)
    }
    assert states == {
        "live": "live",
        "revoked": "revoked",
        "underneath": "revoked",
        "expired": "expired",
    }
    with pytest.raises(TokenError, match="INVALID_TOKEN"):
        delete_token(runtime.db, session, live, clock=runtime.clock)
    for token in (revoked, underneath, expired):
        delete_token(runtime.db, session, token, clock=runtime.clock)
    remaining = list_tokens(runtime.db, session, everyone=False, clock=runtime.clock)
    assert [row["name"] for row in remaining] == ["live"]


def test_personal_token_used_stamps_and_throttles_to_once_a_minute(runtime, admin_engine, world):
    actor = world["admin"]
    token, _ = issue_row(runtime, actor)
    first_used = datetime.now(UTC)
    with runtime.db.transaction(actor.tenant_id) as conn:
        conn.execute(
            text("SELECT execbound.personal_token_used(:k,:n)"), {"k": token, "n": first_used}
        )
    with admin_engine.connect() as conn:
        stamped = conn.execute(
            text("SELECT last_used_at FROM execbound.personal_access_tokens WHERE token_id=:k"),
            {"k": token},
        ).scalar_one()
    assert stamped is not None
    with runtime.db.transaction(actor.tenant_id) as conn:
        conn.execute(
            text("SELECT execbound.personal_token_used(:k,:n)"),
            {"k": token, "n": first_used + timedelta(seconds=30)},
        )
    with admin_engine.connect() as conn:
        unchanged = conn.execute(
            text("SELECT last_used_at FROM execbound.personal_access_tokens WHERE token_id=:k"),
            {"k": token},
        ).scalar_one()
    assert unchanged == stamped


def test_personal_token_used_does_nothing_once_the_backing_credential_is_revoked(
    runtime, admin_engine, world
):
    actor = world["admin"]
    token, credential = issue_row(runtime, actor)
    revoke_credential(admin_engine, credential)
    with runtime.db.transaction(actor.tenant_id) as conn:
        conn.execute(
            text("SELECT execbound.personal_token_used(:k,:n)"),
            {"k": token, "n": datetime.now(UTC)},
        )
    with admin_engine.connect() as conn:
        last_used = conn.execute(
            text("SELECT last_used_at FROM execbound.personal_access_tokens WHERE token_id=:k"),
            {"k": token},
        ).scalar_one()
    assert last_used is None


def test_personal_token_used_without_a_tenant_fence_is_invalid_tenant(admin_engine):
    with pytest.raises(DBAPIError, match="INVALID_TENANT"):
        with admin_engine.begin() as conn:
            conn.execute(
                text("SELECT execbound.personal_token_used(:k,:n)"),
                {"k": uuid4(), "n": datetime.now(UTC)},
            )


def test_another_tenant_reads_no_personal_access_token(runtime, world, seeded):
    """The tenant fence on the table itself, read as the runtime role (#155): the token's row
    is there for its own workspace and absent under another workspace's fence."""
    token, _ = issue_row(runtime, world["admin"])
    tenant = world["admin"].tenant_id
    other = next(candidate for candidate in seeded["tenants"] if candidate != tenant)
    with runtime.db.transaction(other) as conn:
        assert (
            conn.execute(text("SELECT count(*) FROM execbound.personal_access_tokens")).scalar_one()
            == 0
        )
    with runtime.db.transaction(tenant) as conn:
        assert conn.execute(
            text("SELECT token_id FROM execbound.personal_access_tokens")
        ).scalars().all() == [token]


def test_the_migration_runs_without_row_level_security_bypass_and_downgrades(restricted):
    # The `restricted` database is freshly created (base state) each test, so it must be
    # migrated up before it can be downgraded — see test_samples_schema.py's test_sm8b for
    # the same pattern against the immediately preceding migration.
    engine, config, _ = restricted
    alembic.upgrade(config, "head")
    tenant, principal = uuid4(), uuid4()
    token, credential = uuid4(), uuid4()
    now = datetime.now(UTC)
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id, name) VALUES (:t, :n)"),
            {"t": tenant, "n": f"tenant-{tenant.hex[:8]}"},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind) "
                "VALUES (:t, :p, 'ADMIN')"
            ),
            {"t": tenant, "p": principal},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.credentials"
                "(tenant_id, credential_id, principal_id, token_hash, issued_at, expires_at) "
                "VALUES (:t, :c, :p, :h, :i, :e)"
            ),
            {
                "t": tenant,
                "c": credential,
                "p": principal,
                "h": digest(),
                "i": now,
                "e": now + timedelta(days=30),
            },
        )
        conn.execute(
            text(
                "INSERT INTO execbound.personal_access_tokens"
                "(tenant_id, token_id, principal_id, credential_id, name, token_hash, "
                "created_at, expires_at) "
                "VALUES (:t, :k, :p, :c, 'ci', :h, :i, :e)"
            ),
            {
                "t": tenant,
                "k": token,
                "p": principal,
                "c": credential,
                "h": digest(),
                "i": now,
                "e": now + timedelta(days=30),
            },
        )
        conn.execute(
            text(
                "INSERT INTO execbound.authentication_failures"
                "(failure_id, surface, reason, window_start, tenant_id, subject_kind, "
                "subject_id, count, first_at, last_at) "
                "VALUES (:f, 'token', 'REVOKED', now(), :t, 'credential', :s, 1, now(), now())"
            ),
            {"f": uuid4(), "t": tenant, "s": uuid4()},
        )

    def still_at_head() -> None:
        with engine.connect() as conn:
            assert (
                conn.execute(text("SELECT version_num FROM execbound.alembic_version")).scalar_one()
                == SCHEMA_REVISION
            )

    # Both retained: the row already inserted above and the failure counter already inserted
    # above.
    with pytest.raises(RuntimeError, match="lossy downgrade refused"):
        alembic.downgrade(config, "0062_people_numbers")
    still_at_head()

    # A token row alone, no `token`-surface failure: the `OR` in the migration's own guard
    # refuses on either half, not only their conjunction.
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("DELETE FROM execbound.authentication_failures WHERE tenant_id=:t"), {"t": tenant}
        )
    with pytest.raises(RuntimeError, match="lossy downgrade refused"):
        alembic.downgrade(config, "0062_people_numbers")
    still_at_head()

    # A `token`-surface failure alone, no token row: the other half of the same `OR`.
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("DELETE FROM execbound.personal_access_tokens WHERE tenant_id=:t"), {"t": tenant}
        )
        conn.execute(
            text(
                "INSERT INTO execbound.authentication_failures"
                "(failure_id, surface, reason, window_start, tenant_id, subject_kind, "
                "subject_id, count, first_at, last_at) "
                "VALUES (:f, 'token', 'REVOKED', now(), :t, 'credential', :s, 1, now(), now())"
            ),
            {"f": uuid4(), "t": tenant, "s": uuid4()},
        )
    with pytest.raises(RuntimeError, match="lossy downgrade refused"):
        alembic.downgrade(config, "0062_people_numbers")
    still_at_head()

    # Neither retained: the downgrade succeeds.
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "DELETE FROM execbound.authentication_failures "
                "WHERE tenant_id=:t AND surface='token'"
            ),
            {"t": tenant},
        )
    alembic.downgrade(config, "0062_people_numbers")
    with engine.connect() as conn:
        assert (
            conn.execute(text("SELECT to_regclass('execbound.personal_access_tokens')")).scalar()
            is None
        )
        narrowed = conn.execute(
            text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conname = 'authentication_failures_surface_check'"
            )
        ).scalar_one()
        assert "token" not in narrowed
    alembic.upgrade(config, "head")


def test_a_token_loads_as_its_owner_and_passes_check_session(runtime, world):
    session = admin_session(runtime, world["admin"])
    token, view = issue_token(runtime.db, session, "ci", timedelta(days=1), clock=runtime.clock)
    assert token.startswith("ebp1.")
    loaded = load_token_session(runtime.db, token, clock=runtime.clock)
    assert isinstance(loaded, TokenSession)
    assert loaded.identity.principal_id == world["admin"].principal_id
    assert loaded.identity.kind == "ADMIN"
    assert str(loaded.token_id) == view["token_id"]
    with runtime.db.transaction(world["admin"].tenant_id) as conn:
        check_session(conn, loaded, runtime.clock)


@pytest.mark.parametrize("change", ["revoke", "wrong_secret", "garbled"])
def test_a_revoked_wrong_or_garbled_token_is_refused(runtime, world, change):
    session = admin_session(runtime, world["admin"])
    token, view = issue_token(runtime.db, session, "ci", timedelta(days=1), clock=runtime.clock)
    if change == "revoke":
        revoke_token(runtime.db, session, UUID(view["token_id"]), clock=runtime.clock)
    elif change == "wrong_secret":
        token = token[:-4] + "AAAA"
    else:
        token = "ebp1.not-a-token"
    with pytest.raises(SessionError):
        load_token_session(runtime.db, token, clock=runtime.clock)


def test_an_owner_who_stops_being_an_administrator_loses_the_token(runtime, admin_engine, world):
    session = admin_session(runtime, world["admin"])
    token, _ = issue_token(runtime.db, session, "ci", timedelta(days=1), clock=runtime.clock)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET active=false WHERE principal_id=:p"),
            {"p": world["admin"].principal_id},
        )
    with pytest.raises(SessionError):
        load_token_session(runtime.db, token, clock=runtime.clock)


def test_removal_from_the_workspace_ends_the_token_distinct_from_deactivation_or_demotion(
    runtime, admin_engine, world
):
    """PT5's third clause. `world["admin"]` (`test_execution.provision_identity`) has no
    `workspace_memberships` row, so neither PT5 test that ends a token through its owner
    touches that table: `test_an_owner_who_stops_being_an_administrator_loses_the_token` sets
    `principals.active=false` directly, and
    `test_an_owner_demoted_from_administrator_loses_the_token` changes the role through
    `access_role_grants`. Removing a person from a workspace is instead a membership marked
    inactive (`_owner_active` in personal_tokens.py checks `workspace_memberships.active`
    itself, and `tests/test_workspace_switching.py` simulates the same removal the same way for
    a browser session); the principal stays active with an unchanged ADMIN role throughout."""
    session = admin_session(runtime, world["admin"])
    token, _ = issue_token(runtime.db, session, "ci", timedelta(days=1), clock=runtime.clock)
    account = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO execbound.user_accounts(account_id, email) VALUES (:a, :e)"),
            {"a": account, "e": f"removed-{account.hex}@example.test"},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.workspace_memberships(account_id, tenant_id, principal_id) "
                "VALUES (:a, :t, :p)"
            ),
            {"a": account, "t": world["admin"].tenant_id, "p": world["admin"].principal_id},
        )
    # The membership exists and is active: the token still works.
    load_token_session(runtime.db, token, clock=runtime.clock)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.workspace_memberships SET active=false "
                "WHERE account_id=:a AND tenant_id=:t"
            ),
            {"a": account, "t": world["admin"].tenant_id},
        )
    with pytest.raises(SessionError):
        load_token_session(runtime.db, token, clock=runtime.clock)


def test_a_token_whose_backing_credential_is_revoked_is_refused_and_shown_as_revoked(
    runtime, admin_engine, world
):
    """Deactivation, a password reset and a promotion revoke every credential a principal
    holds without touching personal_access_tokens (0036, 0040, 0047); a token must stop
    working and must not read as `live` once its backing credential dies underneath it."""
    session = admin_session(runtime, world["admin"])
    token, view = issue_token(runtime.db, session, "ci", timedelta(days=1), clock=runtime.clock)
    with admin_engine.begin() as conn:
        fenced(conn, world["admin"].tenant_id)
        credential_id = conn.execute(
            text("SELECT credential_id FROM execbound.personal_access_tokens WHERE token_id=:k"),
            {"k": UUID(view["token_id"])},
        ).scalar_one()
        conn.execute(
            text("UPDATE execbound.credentials SET revoked_at=:n WHERE credential_id=:c"),
            {"n": datetime.now(UTC), "c": credential_id},
        )
    with pytest.raises(SessionError):
        load_token_session(runtime.db, token, clock=runtime.clock)
    rows = list_tokens(runtime.db, session, everyone=False, clock=runtime.clock)
    assert rows[0]["token_id"] == view["token_id"]
    assert rows[0]["state"] == "revoked"


def test_a_token_cannot_manage_tokens(runtime, world):
    session = admin_session(runtime, world["admin"])
    token, view = issue_token(runtime.db, session, "ci", timedelta(days=1), clock=runtime.clock)
    loaded = load_token_session(runtime.db, token, clock=runtime.clock)
    for call in (
        lambda: issue_token(runtime.db, loaded, "x", timedelta(days=1)),
        lambda: revoke_token(runtime.db, loaded, UUID(view["token_id"])),
        lambda: delete_token(runtime.db, loaded, UUID(view["token_id"])),
        lambda: list_tokens(runtime.db, loaded, everyone=False),
    ):
        with pytest.raises(TokenError, match="TOKEN_NOT_ALLOWED"):
            call()


def test_listing_shows_the_owners_tokens_and_everyone_shows_the_workspace(runtime, world):
    session = admin_session(runtime, world["admin"])
    issue_token(runtime.db, session, "ci", timedelta(days=1), clock=runtime.clock)
    own = list_tokens(runtime.db, session, everyone=False, clock=runtime.clock)
    everyone = list_tokens(runtime.db, session, everyone=True, clock=runtime.clock)
    assert [row["name"] for row in own] == ["ci"]
    assert {row["owner_id"] for row in everyone} == {str(world["admin"].principal_id)}
    assert "token_hash" not in own[0]


def backing_of(admin_engine, token: str) -> str:
    with admin_engine.connect() as conn:
        return str(
            conn.execute(
                text(
                    "SELECT credential_id FROM execbound.personal_access_tokens WHERE token_id = :k"
                ),
                {"k": token.split(".")[2]},
            ).scalar_one()
        )


def test_each_listed_token_names_its_backing_credential(runtime, admin_engine, world):
    """The one link from an audit event to a token: an event names the backing credential
    as `actor_credential_id`, and the token list names the same credential beside the token's
    name, in the owner's own list, the workspace's and the row issuing returns."""
    session = admin_session(runtime, world["admin"])
    token, view = issue_token(runtime.db, session, "ci", timedelta(days=1), clock=runtime.clock)
    backing = backing_of(admin_engine, token)
    assert view["credential_id"] == backing
    for everyone in (False, True):
        rows = list_tokens(runtime.db, session, everyone=everyone, clock=runtime.clock)
        assert [row["credential_id"] for row in rows if row["token_id"] == view["token_id"]] == [
            backing
        ]


def test_the_issued_event_carries_the_tokens_name(runtime, admin_engine, world):
    """So an event a token caused still maps to a name once the spent token is deleted and
    gone from every list: the name as stored, trimmed as the definer function trims it."""
    session = admin_session(runtime, world["admin"])
    token, view = issue_token(
        runtime.db, session, "  deploy bot  ", timedelta(days=1), clock=runtime.clock
    )
    with admin_engine.connect() as conn:
        payload = conn.execute(
            text(
                "SELECT payload FROM execbound.audit_events "
                "WHERE kind = 'personal_token.issued' AND payload->>'token_id' = :k"
            ),
            {"k": view["token_id"]},
        ).scalar_one()
    assert payload["name"] == "deploy bot" == view["name"]
    assert payload["credential_id"] == backing_of(admin_engine, token)


def test_a_token_is_refused_while_any_identity_provider_requires_sign_in(
    runtime, admin_engine, world
):
    """A token's credential never carries a `federated_sign_ins` row (that only ever belongs
    to a browser session's credential, minted by an actual OIDC callback), so unlike
    `validate_workspace_session` it cannot come back with a fresh directory sign-in. While
    any identity provider for the tenant requires sign-in, in any state, both loading an
    existing token and minting a new one are refused; a provider that stops requiring it
    restores the existing token."""
    from test_directory_store import RING, FixedClock, registered

    from execbound.directory import DirectoryConfig

    session = admin_session(runtime, world["admin"])
    token, _ = issue_token(runtime.db, session, "ci", timedelta(days=1), clock=runtime.clock)
    provider = registered(
        runtime.db,
        DirectoryConfig(RING, "https://app.example"),
        {"tenant": world["admin"].tenant_id, "admin": world["admin"].principal_id},
        FixedClock(),
    )
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.identity_providers SET require_sign_in=true "
                "WHERE tenant_id=:t AND provider_id=:p"
            ),
            {"t": world["admin"].tenant_id, "p": provider},
        )
    with pytest.raises(SessionError) as refused:
        load_token_session(runtime.db, token, clock=runtime.clock)
    assert refused.value.code == "DIRECTORY_REQUIRED"
    with pytest.raises(TokenError, match="DIRECTORY_REQUIRED"):
        issue_token(runtime.db, session, "ci2", timedelta(days=1), clock=runtime.clock)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.identity_providers SET require_sign_in=false "
                "WHERE tenant_id=:t AND provider_id=:p"
            ),
            {"t": world["admin"].tenant_id, "p": provider},
        )
    loaded = load_token_session(runtime.db, token, clock=runtime.clock)
    assert isinstance(loaded, TokenSession)


def test_an_owner_demoted_from_administrator_loses_the_token(runtime, admin_engine, world):
    """The same identity-authority loss `test_demoted_original_admin_loses_sql_and_old_identity_
    authority` (test_access_control.py) proves for a browser session, here for a token: a
    second administrator is provisioned so demoting the token's owner does not trip the
    LAST_ADMINISTRATOR guard."""
    other_admin = provision_identity(
        admin_engine, runtime.db, world["admin"].tenant_id, "ADMIN", runtime.clock.now()
    )
    session = admin_session(runtime, other_admin)
    token, _ = issue_token(runtime.db, session, "ci", timedelta(days=1), clock=runtime.clock)
    with runtime.db.transaction(world["admin"].tenant_id) as conn:
        access.set_roles_in(
            conn,
            world["admin"].tenant_id,
            world["admin"].principal_id,
            "user",
            other_admin.principal_id,
            [{"role": "viewer", "space_id": None}],
            "Test access change",
        )
    with pytest.raises(SessionError):
        load_token_session(runtime.db, token, clock=runtime.clock)


def test_listing_everyone_is_refused_to_a_non_administrator(runtime, world):
    session = admin_session(runtime, world["human"])
    with pytest.raises(TokenError, match="INVALID_ACTOR"):
        list_tokens(runtime.db, session, everyone=True, clock=runtime.clock)


def test_delete_token_removes_it_from_listing_and_is_audited(runtime, admin_engine, world):
    """PT6: issue, revoke and delete each append their own event to the chain, in order, and
    the chain keeps all three after the row is gone."""
    session = admin_session(runtime, world["admin"])
    token, view = issue_token(runtime.db, session, "ci", timedelta(days=1), clock=runtime.clock)
    token_id = UUID(view["token_id"])
    revoke_token(runtime.db, session, token_id, clock=runtime.clock)
    delete_token(runtime.db, session, token_id, clock=runtime.clock)
    rows = list_tokens(runtime.db, session, everyone=False, clock=runtime.clock)
    assert token_id not in {UUID(row["token_id"]) for row in rows}
    with admin_engine.connect() as conn:
        kinds = (
            conn.execute(
                text(
                    "SELECT kind FROM execbound.audit_events WHERE tenant_id=:t "
                    "AND payload->>'token_id' = :k ORDER BY sequence"
                ),
                {"t": world["admin"].tenant_id, "k": str(token_id)},
            )
            .scalars()
            .all()
        )
    assert kinds == ["personal_token.issued", "personal_token.revoked", "personal_token.deleted"]


def test_revoke_other_sessions_refuses_a_token_and_leaves_the_browser_session_alive(runtime, world):
    session = admin_session(runtime, world["admin"])
    token, _ = issue_token(runtime.db, session, "ci", timedelta(days=1), clock=runtime.clock)
    loaded = load_token_session(runtime.db, token, clock=runtime.clock)
    with pytest.raises(SessionError):
        revoke_other_sessions(runtime.db, loaded, clock=runtime.clock)
    with runtime.db.transaction(world["admin"].tenant_id) as conn:
        check_session(conn, session, runtime.clock)
