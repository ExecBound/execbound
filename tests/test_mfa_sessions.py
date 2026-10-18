# SPDX-License-Identifier: AGPL-3.0-only
"""MFA changes and proof consumption use the real PostgreSQL tenant fence."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from test_human_sessions import FixedClock
from test_human_sessions import humans as humans

from execbound import mfa
from execbound.envelope import KeyRing, unseal
from execbound.surfaces.sessions import SessionError, issue_session, load_session

pytestmark = pytest.mark.integration
RING = KeyRing("test", {"test": b"m" * 32})


def enrolled(db, humans):
    clock = FixedClock(datetime.now(UTC))
    granted = issue_session(db, humans[0], clock=clock)
    session = load_session(db, granted.token, clock=clock)
    seed = mfa.begin_enrollment(db, session, RING, clock=clock)
    codes = mfa.confirm_enrollment(
        db, session, RING, mfa.totp(seed, int(clock.now().timestamp() // 30)), clock=clock
    )
    return clock, granted, codes


def test_enrollment_requires_confirmation_and_gates_existing_sessions(db, humans):
    old = issue_session(db, humans[0])
    clock, current, codes = enrolled(db, humans)
    assert len(codes) == 10
    assert load_session(db, current.token, clock=clock).identity == humans[0]
    with pytest.raises(SessionError) as refused:
        load_session(db, old.token, clock=clock)
    assert refused.value.code == "MFA_REQUIRED"
    pending = load_session(db, old.token, clock=clock, allow_pending_mfa=True)
    assert pending.mfa_required
    assert mfa.verify_factor(db, pending, RING, codes[0], clock=clock)
    assert not load_session(db, old.token, clock=clock).mfa_required
    with db.transaction(humans[0].tenant_id) as conn:
        row = conn.execute(text("SELECT * FROM execbound.account_factors")).mappings().one()
        assert all(code not in repr(row) for code in codes)


def test_concurrent_recovery_consumption_only_one_session_wins(db, humans):
    clock, _, codes = enrolled(db, humans)
    grants = [issue_session(db, humans[0], clock=clock) for _ in range(2)]
    pending = [load_session(db, g.token, clock=clock, allow_pending_mfa=True) for g in grants]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(lambda s: mfa.verify_factor(db, s, RING, codes[0], clock=clock), pending)
        )
    assert sorted(results) == [False, True]


def test_enrollment_seed_is_encrypted_and_expires(db, humans):
    clock = FixedClock(datetime.now(UTC))
    grant = issue_session(db, humans[0], clock=clock)
    session = load_session(db, grant.token, clock=clock)
    secret = mfa.begin_enrollment(db, session, RING, clock=clock)
    with db.transaction(humans[0].tenant_id) as conn:
        assert secret not in repr(
            conn.execute(text("SELECT * FROM execbound.account_factors")).mappings().one()
        )
    clock.value += timedelta(minutes=6)
    with pytest.raises(mfa.MfaError):
        mfa.confirm_enrollment(
            db, session, RING, mfa.totp(secret, int(clock.now().timestamp() // 30)), clock=clock
        )


def test_failed_attempts_persist_and_lock_out_other_sessions(db, humans):
    clock, _, codes = enrolled(db, humans)
    grant = issue_session(db, humans[0], clock=clock)
    pending = load_session(db, grant.token, clock=clock, allow_pending_mfa=True)
    for _ in range(5):
        assert not mfa.verify_factor(db, pending, RING, "bad", clock=clock)
    assert not mfa.verify_factor(db, pending, RING, codes[0], clock=clock)
    with pytest.raises(SessionError):
        load_session(db, grant.token, clock=clock)


def test_runtime_cannot_change_factor_or_assurance_rows_directly(db, humans):
    clock, grant, _ = enrolled(db, humans)
    with db.transaction(humans[0].tenant_id) as conn:
        with pytest.raises(Exception, match="permission denied"):
            conn.execute(text("UPDATE execbound.account_factors SET enabled_at=NULL"))
    with db.transaction(humans[0].tenant_id) as conn:
        with pytest.raises(Exception, match="permission denied"):
            conn.execute(text("UPDATE execbound.session_assurance SET verified_at=now()"))


def test_totp_is_single_use_across_concurrent_sessions(db, humans):
    clock, _, _ = enrolled(db, humans)
    clock.value += timedelta(seconds=30)
    with db.transaction(humans[0].tenant_id) as conn:
        row = conn.execute(text("SELECT * FROM execbound.account_factors")).mappings().one()
        secret = unseal(
            RING,
            row["sealed"],
            row["key_id"],
            humans[0].tenant_id,
            humans[0].principal_id,
            "authenticator_seed",
        )
    code = mfa.totp(secret, int(clock.now().timestamp() // 30))
    grants = [issue_session(db, humans[0], clock=clock) for _ in range(2)]
    pending = [load_session(db, g.token, clock=clock, allow_pending_mfa=True) for g in grants]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(lambda s: mfa.check_factor(db, s, RING, code, clock=clock), pending)
        )
    # The loser presented the code the winner had just used: answered as such, never counted.
    assert sorted(results) == [mfa.FactorCheck.REUSED, mfa.FactorCheck.VERIFIED]
    assert factor_state(db, humans[0])["failures"] == 0
    assert kinds(db, humans[0]).count("account_security.verification_failed") == 0


def factor_state(db, human):
    with db.transaction(human.tenant_id) as conn:
        return dict(
            conn.execute(text("SELECT failures, locked_until FROM execbound.account_factors"))
            .mappings()
            .one()
        )


def kinds(db, human):
    with db.transaction(human.tenant_id) as conn:
        return list(
            conn.execute(
                text(
                    "SELECT kind FROM execbound.audit_events WHERE tenant_id=:t ORDER BY sequence"
                ),
                {"t": human.tenant_id},
            ).scalars()
        )


def test_sn12_a_code_just_used_is_not_a_failure(db, humans):
    clock, _, _ = enrolled(db, humans)
    clock.value += timedelta(seconds=30)
    with db.transaction(humans[0].tenant_id) as conn:
        row = conn.execute(text("SELECT * FROM execbound.account_factors")).mappings().one()
        secret = unseal(
            RING,
            row["sealed"],
            row["key_id"],
            humans[0].tenant_id,
            humans[0].principal_id,
            "authenticator_seed",
        )
    step = int(clock.now().timestamp() // 30)
    code = mfa.totp(secret, step)
    first, second = (
        load_session(
            db, issue_session(db, humans[0], clock=clock).token, clock=clock, allow_pending_mfa=True
        )
        for _ in range(2)
    )
    assert mfa.check_factor(db, first, RING, code, clock=clock) is mfa.FactorCheck.VERIFIED
    before = kinds(db, humans[0])
    for _ in range(5):
        assert mfa.check_factor(db, second, RING, code, clock=clock) is mfa.FactorCheck.REUSED
    added = kinds(db, humans[0])[len(before) :]
    assert added == ["account_security.code_reused"] * 5
    assert factor_state(db, humans[0]) == {"failures": 0, "locked_until": None}
    assert not mfa.verify_factor(db, second, RING, code, clock=clock)
    # The next step's code still opens the session: nothing was locked.
    clock.value += timedelta(seconds=30)
    following = mfa.totp(secret, step + 1)
    assert mfa.check_factor(db, second, RING, following, clock=clock) is mfa.FactorCheck.VERIFIED

    # Wrong codes are still failures: five lock the factor, and the lock refuses a right code.
    third = load_session(
        db, issue_session(db, humans[0], clock=clock).token, clock=clock, allow_pending_mfa=True
    )
    for _ in range(5):
        assert mfa.check_factor(db, third, RING, "bad", clock=clock) is mfa.FactorCheck.REFUSED
    assert factor_state(db, humans[0])["locked_until"] is not None
    clock.value += timedelta(seconds=30)
    right = mfa.totp(secret, step + 2)
    assert mfa.check_factor(db, third, RING, right, clock=clock) is mfa.FactorCheck.REFUSED
    # Locked, a code just used is refused like any other: the lock says nothing more.
    assert mfa.check_factor(db, third, RING, following, clock=clock) is mfa.FactorCheck.REFUSED


def test_policy_requires_enrollment_and_cannot_be_disabled_by_a_member(db, humans, admin_engine):
    from dataclasses import replace

    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET kind='ADMIN' WHERE principal_id=:p"),
            {"p": humans[0].principal_id},
        )
    admin = replace(humans[0], kind="ADMIN")
    clock, grant, _ = enrolled(db, [admin])
    session = load_session(db, grant.token, clock=clock)
    mfa.manage_security(db, session, "policy", "all", clock=clock)
    with pytest.raises(mfa.MfaError):
        mfa.manage_security(db, session, "disable", clock=clock)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET kind='HUMAN_APPROVER' WHERE principal_id=:p"),
            {"p": admin.principal_id},
        )
    with pytest.raises(SessionError):
        mfa.manage_security(db, session, "policy", "optional", clock=clock)


def aged(db, token, clock, minutes):
    """Move the injected clock `minutes` on, reading the session every seven minutes as an
    open console does, so the fifteen-minute idle limit keeps renewing it and only the age of
    the factor verified on it changes."""
    remaining = minutes
    while remaining > 0:
        step = min(7, remaining)
        clock.value += timedelta(minutes=step)
        remaining -= step
        load_session(db, token, clock=clock)
    return load_session(db, token, clock=clock)


def test_security_changes_require_recent_factor_and_rotation_invalidates_old_token(db, humans):
    clock, grant, _ = enrolled(db, humans)
    session = load_session(db, grant.token, clock=clock)
    rotated = mfa.rotate_verified_session(db, session, clock=clock)
    with pytest.raises(SessionError):
        load_session(db, grant.token, clock=clock)
    session = aged(db, rotated.token, clock, 31)
    with pytest.raises(mfa.MfaError) as refused:
        mfa.require_recent_factor(db, session, clock=clock)
    assert refused.value.code == "RECENT_AUTH_REQUIRED"


@pytest.mark.parametrize("minutes,fresh", [(29, True), (31, False)])
def test_a_verified_factor_steps_a_session_up_for_thirty_minutes(db, humans, minutes, fresh):
    """The decision of 28 September 2026: the step-up's window is thirty minutes,
    one constant every step-up caller reads, and the factor entered at sign-in counts for it."""
    assert mfa.STEP_UP_WINDOW == timedelta(minutes=30)
    clock, grant, _ = enrolled(db, humans)
    session = aged(db, grant.token, clock, minutes)
    if fresh:
        mfa.require_recent_factor(db, session, clock=clock)
        # The account security page's own changes read the same window.
        assert len(mfa.manage_security(db, session, "recovery", clock=clock)) == 10
    else:
        for change in (
            lambda: mfa.require_recent_factor(db, session, clock=clock),
            lambda: mfa.manage_security(db, session, "recovery", clock=clock),
        ):
            with pytest.raises(mfa.MfaError) as refused:
                change()
            assert refused.value.code == "RECENT_AUTH_REQUIRED"


@pytest.mark.parametrize("minutes,fresh", [(29, True), (31, False)])
def test_the_database_holds_the_same_thirty_minute_window(db, humans, minutes, fresh):
    """The definer function checks the factor's age again, beneath the Python check (0067);
    reaching it directly shows the two agree, so a change the guard lets through at minute
    twenty is not then refused by the database."""
    clock, grant, _ = enrolled(db, humans)
    session = aged(db, grant.token, clock, minutes)
    _, retained = mfa.new_recovery_codes(humans[0].principal_id)

    def replace_codes():
        with mfa._transaction(db, session, clock) as conn:
            mfa._change(conn, session, clock.now(), "recovery", {"recovery": retained})

    if fresh:
        replace_codes()
    else:
        with pytest.raises(mfa.MfaError):
            replace_codes()


def test_first_time_setup_still_needs_a_sign_in_within_five_minutes(db, humans):
    """Enrolling a first factor reads the session's own age, not a factor's: a different
    window, left at five minutes on purpose."""
    assert mfa.ENROLLMENT_WINDOW == timedelta(minutes=5)
    clock = FixedClock(datetime.now(UTC))
    grant = issue_session(db, humans[0], clock=clock)
    clock.value += timedelta(minutes=4)
    mfa.begin_enrollment(db, load_session(db, grant.token, clock=clock), RING, clock=clock)
    late = issue_session(db, humans[1], clock=clock)
    clock.value += timedelta(minutes=6)
    with pytest.raises(mfa.MfaError) as refused:
        mfa.begin_enrollment(db, load_session(db, late.token, clock=clock), RING, clock=clock)
    assert refused.value.code == "RECENT_AUTH_REQUIRED"


def test_other_tenant_cannot_read_factors_or_use_a_recovery_code(db, humans):
    clock, _, codes = enrolled(db, humans)
    other = issue_session(db, humans[1], clock=clock)
    session = load_session(db, other.token, clock=clock)
    with db.transaction(humans[1].tenant_id) as conn:
        assert (
            conn.execute(text("SELECT count(*) FROM execbound.account_factors")).scalar_one() == 0
        )
    with pytest.raises(mfa.MfaError):
        mfa.verify_factor(db, session, RING, codes[0], clock=clock)


def test_required_policy_gates_an_unenrolled_user_and_enrollment_unlocks(db, humans, admin_engine):
    with admin_engine.begin() as conn:
        conn.execute(
            text("""INSERT INTO execbound.account_security_policy
          (tenant_id,requirement,changed_at,changed_by) VALUES(:t,'all',now(),:p)"""),
            {"t": humans[0].tenant_id, "p": humans[0].principal_id},
        )
    clock = FixedClock(datetime.now(UTC))
    grant = issue_session(db, humans[0], clock=clock)
    assert grant.mfa_required
    with pytest.raises(SessionError):
        load_session(db, grant.token, clock=clock)
    pending = load_session(db, grant.token, clock=clock, allow_pending_mfa=True)
    seed = mfa.begin_enrollment(db, pending, RING, clock=clock)
    mfa.confirm_enrollment(
        db, pending, RING, mfa.totp(seed, int(clock.now().timestamp() // 30)), clock=clock
    )
    assert not load_session(db, grant.token, clock=clock).mfa_required


def test_required_factor_survives_a_new_password_credential(db, humans):
    from execbound.passwords import mint_session_credential

    clock, _, _ = enrolled(db, humans)
    identity = mint_session_credential(
        db, humans[0].tenant_id, humans[0].principal_id, "password", clock=clock
    )
    grant = issue_session(db, identity, clock=clock)
    assert grant.mfa_required
    with pytest.raises(SessionError):
        load_session(db, grant.token, clock=clock)


def test_passed_lockout_allows_unused_recovery_without_resetting_enrollment(db, humans):
    clock, _, codes = enrolled(db, humans)
    grant = issue_session(db, humans[0], clock=clock)
    pending = load_session(db, grant.token, clock=clock, allow_pending_mfa=True)
    for _ in range(5):
        mfa.verify_factor(db, pending, RING, "invalid", clock=clock)
    clock.value += timedelta(minutes=15, seconds=1)
    grant = issue_session(db, humans[0], clock=clock)
    pending = load_session(db, grant.token, clock=clock, allow_pending_mfa=True)
    assert mfa.verify_factor(db, pending, RING, codes[0], clock=clock)
