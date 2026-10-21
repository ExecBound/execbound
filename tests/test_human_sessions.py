# SPDX-License-Identifier: AGPL-3.0-only
"""Short-lived human credentials require current authority and atomic PostgreSQL state."""

import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Barrier, Event
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event, text
from sqlalchemy.exc import DBAPIError

from execbound.audit import read_events
from execbound.db import check_runtime
from execbound.identity import authenticate
from execbound.surfaces import sessions

pytestmark = pytest.mark.integration


class FixedClock:
    def __init__(self, value):
        self.value = value

    def now(self):
        return self.value


@pytest.fixture
def humans(db, seeded, admin_engine):
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET kind = 'HUMAN_APPROVER', space_id = NULL")
        )
        # The fixture's credentials last an hour; a session lasts twelve, so it outlives them.
        # Only the credentials the fixture hands out, to two days from the clocks the tests use.
        conn.execute(
            text(
                "UPDATE execbound.credentials SET expires_at = :e WHERE credential_id = ANY(:ids)"
            ),
            {
                "e": datetime.now(UTC) + timedelta(days=2),
                "ids": [UUID(token.split(".")[2]) for token in seeded["tokens"]],
            },
        )
    return [authenticate(db, token) for token in seeded["tokens"]]


def live_count(db, identity):
    with db.transaction(identity.tenant_id) as conn:
        return conn.execute(
            text("SELECT count(*) FROM execbound.human_sessions WHERE revoked_at IS NULL")
        ).scalar_one()


def session_count(db, identity):
    with db.transaction(identity.tenant_id) as conn:
        return conn.execute(text("SELECT count(*) FROM execbound.human_sessions")).scalar_one()


@pytest.mark.parametrize("kind", ["HUMAN_APPROVER", "ADMIN"])
def test_session_contains_only_hashed_secrets_and_authoritative_identity(
    db, humans, admin_engine, kind
):
    identity = replace(humans[0], kind=kind)
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.principals SET kind = :kind"), {"kind": kind})
    clock = FixedClock(datetime.now(UTC))
    grant = sessions.issue_session(db, identity, clock=clock)
    loaded = sessions.load_session(db, grant.token, clock=clock)
    assert loaded.identity == grant.identity == identity
    assert loaded.session_id == grant.session_id
    assert loaded.expires_at == grant.expires_at == clock.now() + sessions.SESSION_LIFETIME
    assert sessions.verify_csrf(loaded, grant.csrf_token)
    assert len(grant.token.split(".")[3]) == len(grant.csrf_token) == 43
    assert grant.token.startswith(f"hs1.{identity.tenant_id}.{grant.session_id}.")
    assert grant.token not in repr(grant) and grant.csrf_token not in repr(grant)
    assert loaded.csrf_hash not in repr(loaded)
    with db.transaction(identity.tenant_id) as conn:
        check_runtime(conn)
        row = conn.execute(text("SELECT * FROM execbound.human_sessions")).mappings().one()
        events = read_events(conn, identity.tenant_id)
    assert row["token_hash"] == hashlib.sha256(grant.token.encode()).hexdigest()
    assert row["csrf_hash"] == hashlib.sha256(grant.csrf_token.encode()).hexdigest()
    assert row["credential_expires_at"] == identity.expires_at
    assert row["kind"] == kind
    retained = repr(dict(row)) + repr(events)
    assert grant.token not in retained and grant.csrf_token not in retained
    assert events[-1]["kind"] == "human_session.issued"
    assert row["token_hash"] not in repr(events) and row["csrf_hash"] not in repr(events)
    assert db.engine.pool.checkedout() == 0


def test_agent_cannot_obtain_human_session(db, seeded):
    identity = authenticate(db, seeded["tokens"][0])
    with pytest.raises(sessions.SessionError, match="Session unavailable"):
        sessions.issue_session(db, identity)
    assert session_count(db, identity) == 0


@pytest.mark.parametrize("token", [None, 10, "", "secret", "hs1.bad.bad.secret", "a" * 1000])
def test_invalid_tokens_fail_safely(db, token):
    with pytest.raises(sessions.SessionError, match="Session unavailable"):
        sessions.load_session(db, token)


@pytest.mark.parametrize("component", [0, 1, 2, 3])
def test_session_selectors_do_not_authorize_without_matching_token(db, humans, component):
    first, second = [sessions.issue_session(db, identity) for identity in humans]
    parts = first.token.split(".")
    parts[component] = "eb1" if component == 0 else second.token.split(".")[component]
    with pytest.raises(sessions.SessionError):
        sessions.load_session(db, ".".join(parts))
    with db.engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.human_sessions")).scalar_one() == 0
    with db.transaction(humans[0].tenant_id) as conn:
        assert conn.execute(
            text("SELECT tenant_id FROM execbound.human_sessions")
        ).scalars().all() == [humans[0].tenant_id]


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE execbound.credentials SET revoked_at = now()",
        "UPDATE execbound.credentials SET expires_at = now() - interval '1 second'",
        "UPDATE execbound.credentials SET expires_at = expires_at + interval '1 minute'",
        "UPDATE execbound.credentials SET expires_at = expires_at - interval '1 minute'",
        "UPDATE execbound.principals SET active = false",
        "UPDATE execbound.principals SET kind = 'ADMIN', space_id = NULL",
        "UPDATE execbound.principals SET kind = 'AGENT', space_id = "
        "(SELECT space_id FROM execbound.spaces s WHERE s.tenant_id = principals.tenant_id)",
        "UPDATE execbound.tenants SET active = false",
    ],
)
def test_current_credential_tenant_and_role_changes_invalidate_sessions(
    db, humans, admin_engine, statement
):
    identity = humans[0]
    grant = sessions.issue_session(db, identity)
    loaded = sessions.load_session(db, grant.token)
    with admin_engine.begin() as conn:
        conn.execute(text(statement))
    for operation in (
        lambda: sessions.load_session(db, grant.token),
        lambda: sessions.issue_session(db, identity),
        lambda: sessions.revoke_session(db, loaded),
    ):
        with pytest.raises(sessions.SessionError):
            operation()


def test_session_never_outlives_credential_or_exact_expiry_boundary(db, humans, admin_engine):
    clock = FixedClock(datetime.now(UTC))
    identity = replace(humans[0], expires_at=clock.now() + timedelta(minutes=2))
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.credentials SET expires_at = :expires"),
            {"expires": identity.expires_at},
        )
    grant = sessions.issue_session(db, identity, clock=clock)
    assert grant.expires_at == identity.expires_at
    clock.value = grant.expires_at
    with pytest.raises(sessions.SessionError):
        sessions.load_session(db, grant.token, clock=clock)


def test_revoke_is_immediate_and_audited_without_secrets(db, humans):
    grant = sessions.issue_session(db, humans[0])
    loaded = sessions.load_session(db, grant.token)
    sessions.revoke_session(db, loaded)
    with pytest.raises(sessions.SessionError):
        sessions.load_session(db, grant.token)
    with pytest.raises(sessions.SessionError):
        sessions.revoke_session(db, loaded)
    with db.transaction(humans[0].tenant_id) as conn:
        events = read_events(conn, humans[0].tenant_id)
    assert [event["kind"] for event in events] == ["human_session.issued", "human_session.revoked"]
    assert grant.token not in repr(events) and grant.csrf_token not in repr(events)


@pytest.mark.parametrize("field", ["session_id", "identity", "csrf_hash", "expires_at"])
def test_revoke_rejects_mismatched_internal_session_binding(db, humans, field):
    grant = sessions.issue_session(db, humans[0])
    loaded = sessions.load_session(db, grant.token)
    values = {
        "session_id": uuid4(),
        "identity": humans[1],
        "csrf_hash": "0" * 64,
        "expires_at": loaded.expires_at + timedelta(seconds=1),
    }
    with pytest.raises(sessions.SessionError):
        sessions.revoke_session(db, replace(loaded, **{field: values[field]}))
    assert sessions.load_session(db, grant.token) == loaded


def test_csrf_is_session_bound_and_strictly_parsed(db, humans):
    grants = [sessions.issue_session(db, humans[0]) for _ in range(2)]
    loaded = sessions.load_session(db, grants[0].token)
    for invalid in (None, 1, "", "a" * 1000, grants[1].csrf_token, grants[0].csrf_token + "="):
        assert not sessions.verify_csrf(loaded, invalid)
    assert sessions.verify_csrf(loaded, grants[0].csrf_token)


def test_capacity_ends_the_oldest_session_to_admit_a_new_one(db, humans, admin_engine):
    """A sixth session of one credential ends the first and is admitted; five stay live."""
    clock = FixedClock(datetime.now(UTC))
    grants = []
    for _ in range(5):
        grants.append(sessions.issue_session(db, humans[0], clock=clock))
        clock.value += timedelta(seconds=1)
    sixth = sessions.issue_session(db, humans[0], clock=clock)
    assert sixth.identity == humans[0]
    with pytest.raises(sessions.SessionError) as gone:
        sessions.load_session(db, grants[0].token, clock=clock)
    assert gone.value.code == "INVALID_SESSION"
    for grant in grants[1:] + [sixth]:
        assert sessions.load_session(db, grant.token, clock=clock).identity == humans[0]
    assert live_count(db, humans[0]) == 5
    with db.transaction(humans[0].tenant_id) as conn:
        ended = [
            event["payload"]
            for event in read_events(conn, humans[0].tenant_id)
            if event["kind"] == "human_session.revoked"
        ]
    assert len(ended) == 1
    assert ended[0]["reason"] == "SESSION_CAPACITY"
    assert ended[0]["session_id"] == str(grants[0].session_id)
    assert ended[0]["credential_id"] == str(humans[0].credential_id)
    with admin_engine.begin() as conn:
        revoked = (
            conn.execute(
                text("SELECT session_id FROM execbound.human_sessions WHERE revoked_at IS NOT NULL")
            )
            .scalars()
            .all()
        )
    assert revoked == [grants[0].session_id]


def test_expired_sessions_do_not_consume_active_capacity(db, humans):
    clock = FixedClock(datetime.now(UTC))
    for _ in range(5):
        sessions.issue_session(db, humans[0], clock=clock)
    clock.value += sessions.SESSION_LIFETIME
    assert sessions.issue_session(db, humans[0], clock=clock).identity == humans[0]


def test_concurrent_issuance_has_one_shared_capacity_fence(db, humans):
    for _ in range(4):
        sessions.issue_session(db, humans[0])
    barrier = Barrier(5)

    def issue():
        barrier.wait(timeout=5)
        try:
            return sessions.issue_session(db, humans[0])
        except sessions.SessionError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda _: issue(), range(5)))
    # Every issuer is admitted, each ending an older session, and five stay live.
    assert all(isinstance(result, sessions.SessionGrant) for result in results), results
    assert session_count(db, humans[0]) == 9
    assert live_count(db, humans[0]) == 5


@pytest.mark.parametrize("operation", ["issue", "revoke"])
def test_audit_failure_rolls_back_session_write(db, humans, monkeypatch, operation):
    grant = sessions.issue_session(db, humans[0])
    loaded = sessions.load_session(db, grant.token)

    def unavailable(*args, **kwargs):
        raise ValueError("sensitive internal diagnostics")

    monkeypatch.setattr(sessions, "append_event", unavailable)
    with pytest.raises(sessions.SessionError) as exc:
        if operation == "issue":
            sessions.issue_session(db, humans[0])
        else:
            sessions.revoke_session(db, loaded)
    assert "sensitive" not in str(exc.value)
    assert session_count(db, humans[0]) == 1
    assert sessions.load_session(db, grant.token) == loaded


@pytest.mark.parametrize("operation", ["issue", "revoke"])
def test_revocation_during_audit_prevents_commit(db, humans, admin_engine, monkeypatch, operation):
    grant = sessions.issue_session(db, humans[0])
    loaded = sessions.load_session(db, grant.token)
    original = sessions.append_event

    def revoke_during_audit(*args, **kwargs):
        result = original(*args, **kwargs)
        with admin_engine.begin() as conn:
            conn.execute(text("UPDATE execbound.credentials SET revoked_at = now()"))
        return result

    monkeypatch.setattr(sessions, "append_event", revoke_during_audit)
    with pytest.raises(sessions.SessionError):
        if operation == "issue":
            sessions.issue_session(db, humans[0])
        else:
            sessions.revoke_session(db, loaded)
    with db.transaction(humans[0].tenant_id) as conn:
        rows = conn.execute(text("SELECT revoked_at FROM execbound.human_sessions")).scalars().all()
        events = read_events(conn, humans[0].tenant_id)
    assert rows == [None]
    assert len(events) == 1


@pytest.mark.parametrize("operation", ["issue", "load", "revoke"])
def test_role_rechecked_after_real_tenant_lock_wait(db, humans, admin_engine, operation):
    grant = sessions.issue_session(db, humans[0])
    loaded = sessions.load_session(db, grant.token)
    waiting = Event()

    def observe(conn, cursor, statement, parameters, context, many):
        if "tenant_policy_control WHERE tenant_id=" in statement and "FOR UPDATE" in statement:
            waiting.set()

    event.listen(db.engine, "before_cursor_execute", observe)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with admin_engine.begin() as conn:
                conn.execute(
                    text(
                        "SELECT tenant_id FROM execbound.tenant_policy_control "
                        "WHERE tenant_id = :tenant FOR UPDATE"
                    ),
                    {"tenant": humans[0].tenant_id},
                ).one()
                actions = {
                    "issue": lambda: sessions.issue_session(db, humans[0]),
                    "load": lambda: sessions.load_session(db, grant.token),
                    "revoke": lambda: sessions.revoke_session(db, loaded),
                }
                future = pool.submit(actions[operation])
                assert waiting.wait(timeout=3)
                conn.execute(
                    text(
                        "UPDATE execbound.principals SET kind = 'AGENT', space_id = "
                        "(SELECT space_id FROM execbound.spaces s "
                        "WHERE s.tenant_id = principals.tenant_id)"
                    )
                )
            with pytest.raises(sessions.SessionError):
                future.result(timeout=5)
    finally:
        event.remove(db.engine, "before_cursor_execute", observe)
    assert session_count(db, humans[0]) == 1


@pytest.mark.parametrize(
    "statement",
    [
        "DELETE FROM execbound.human_sessions",
        "UPDATE execbound.human_sessions SET token_hash = repeat('0', 64)",
        "UPDATE execbound.human_sessions SET csrf_hash = repeat('0', 64)",
        "UPDATE execbound.human_sessions SET expires_at = expires_at + interval '1 hour'",
        "UPDATE execbound.human_sessions SET kind = 'ADMIN'",
    ],
)
def test_session_runtime_cannot_delete_or_rebind_session(db, humans, statement):
    sessions.issue_session(db, humans[0])
    with pytest.raises(DBAPIError), db.transaction(humans[0].tenant_id) as conn:
        conn.execute(text(statement))


def test_token_digest_is_verified_before_deriving_human_identity(db, humans, monkeypatch):
    grant = sessions.issue_session(db, humans[0])
    other = sessions.issue_session(db, humans[0])
    parts = grant.token.split(".")
    parts[3] = other.token.split(".")[3]

    def forbidden_identity_lookup(*args, **kwargs):
        pytest.fail("Invalid token reached human identity validation")

    monkeypatch.setattr(sessions, "_human", forbidden_identity_lookup)
    with pytest.raises(sessions.SessionError):
        sessions.load_session(db, ".".join(parts))


def test_noncanonical_session_token_forms_are_rejected(db, humans):
    grant = sessions.issue_session(db, humans[0])
    parts = grant.token.split(".")
    alternate_uuid = parts.copy()
    alternate_uuid[1] = parts[1].replace("-", "")
    for invalid in (grant.token + "=", ".".join(alternate_uuid), " " + grant.token):
        with pytest.raises(sessions.SessionError):
            sessions.load_session(db, invalid)


def test_session_lifetime_expires_while_original_credential_remains_current(db, humans):
    clock = FixedClock(datetime.now(UTC))
    grant = sessions.issue_session(db, humans[0], clock=clock)
    loaded = sessions.load_session(db, grant.token, clock=clock)
    clock.value = grant.expires_at
    assert humans[0].expires_at > clock.now()
    with pytest.raises(sessions.SessionError):
        sessions.load_session(db, grant.token, clock=clock)
    with pytest.raises(sessions.SessionError):
        sessions.revoke_session(db, loaded, clock=clock)


@pytest.mark.parametrize(
    "assignment",
    [
        "kind = 'AGENT'",
        "token_hash = 'invalid'",
        "csrf_hash = 'invalid'",
        "expires_at = created_at + interval '2 days 1 minute'",
        "expires_at = created_at",
        "credential_expires_at = expires_at - interval '1 second'",
    ],
)
def test_schema_rejects_invalid_session_authority_or_lifetime(db, humans, admin_engine, assignment):
    sessions.issue_session(db, humans[0])
    with pytest.raises(DBAPIError), admin_engine.begin() as conn:
        conn.execute(text(f"UPDATE execbound.human_sessions SET {assignment}"))


def test_session_rls_rejects_cross_tenant_insert_and_revoke(db, humans):
    first, second = [sessions.issue_session(db, identity) for identity in humans]
    with db.transaction(humans[0].tenant_id) as conn:
        assert (
            conn.execute(
                text("UPDATE execbound.human_sessions SET revoked_at = now() WHERE tenant_id = :t"),
                {"t": humans[1].tenant_id},
            ).rowcount
            == 0
        )
    with pytest.raises(DBAPIError), db.transaction(humans[0].tenant_id) as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.human_sessions "
                "(tenant_id, session_id, principal_id, credential_id, kind, "
                "credential_expires_at, token_hash, csrf_hash, created_at, expires_at) "
                "SELECT :t, :s, :p, :c, kind, credential_expires_at, token_hash, csrf_hash, "
                "created_at, expires_at FROM execbound.human_sessions WHERE session_id = :old"
            ),
            {
                "t": humans[1].tenant_id,
                "s": uuid4(),
                "p": humans[1].principal_id,
                "c": humans[1].credential_id,
                "old": first.session_id,
            },
        )
    assert sessions.load_session(db, second.token).identity == humans[1]


def test_session_rls_flags_and_fk_indexes(admin_engine):
    with admin_engine.connect() as conn:
        assert conn.execute(
            text(
                "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class "
                "WHERE oid = 'execbound.human_sessions'::regclass"
            )
        ).scalar_one()
        definitions = (
            conn.execute(
                text(
                    "SELECT indexdef FROM pg_indexes WHERE schemaname = "
                    "'execbound' AND tablename = 'human_sessions'"
                )
            )
            .scalars()
            .all()
        )
    assert any("(tenant_id, credential_id" in definition for definition in definitions)
    assert any("(tenant_id, principal_id" in definition for definition in definitions)
