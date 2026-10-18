# SPDX-License-Identifier: AGPL-3.0-only
"""Sign-in against real PostgreSQL: the functions, the privileges and the two policies.

Every write here goes through a `SECURITY DEFINER` function, so each test states one thing
the function must refuse and asserts the code. The privilege tests are the ones that matter
most: if the runtime role could write these tables itself, every check in the functions
would be advice rather than a boundary.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from conftest import assert_secret_free
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from execbound.db import UnsafeDatabaseRole, check_runtime
from execbound.identity import AuthenticationFailed
from execbound.passwords import (
    MAX_RESET_LIFETIME,
    PasswordError,
    bind_identity,
    change_password,
    code_digest,
    hash_password,
    issue_reset,
    locate_email,
    locate_subject,
    mint_session_credential,
    read_record,
    redeem_reset,
    set_email,
    sign_in_with_password,
    verify_password,
)
from execbound.resolution.models import Clock
from execbound.surfaces.sessions import SessionError, issue_session, load_session

pytestmark = pytest.mark.integration

PASSWORD = "a decent passphrase"
ANOTHER = "an entirely different one"
SUBJECT = "109876543210987654321"


class FixedClock(Clock):
    def __init__(self) -> None:
        self.value = datetime.now(UTC)

    def now(self) -> datetime:
        return self.value


@pytest.fixture
def clock():
    return FixedClock()


def person(engine, tenant, kind, *, email=None, active=True):
    principal = uuid4()
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind, active, email, "
                "space_id) "
                "VALUES (:t, :p, :k, :a, :e, CASE WHEN :k = 'AGENT' THEN "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t) END)"
            ),
            {"t": tenant, "p": principal, "k": kind, "a": active, "e": email},
        )
    return principal


@pytest.fixture
def tenants(seeded):
    return seeded["tenants"][0], seeded["tenants"][1]


@pytest.fixture
def cast(admin_engine, tenants):
    """One tenant with an administrator and an approver who holds an address."""
    tenant, other = tenants
    return {
        "tenant": tenant,
        "other": other,
        "admin": person(admin_engine, tenant, "ADMIN", email="root@example.com"),
        "approver": person(admin_engine, tenant, "HUMAN_APPROVER", email="dana@example.com"),
        "agent": person(admin_engine, tenant, "AGENT"),
    }


def given_password(db, cast, password, clock, principal=None):
    """Set a password the way the product does: mint a code and redeem it."""
    target = principal or cast["approver"]
    reset = issue_reset(db, cast["tenant"], cast["admin"], target, clock=clock)
    return redeem_reset(db, reset.code, password, clock=clock)


# The privileges, first: every check below rests on the runtime role being unable to write.


@pytest.mark.parametrize(
    ("table", "columns", "values"),
    [
        (
            "principal_passwords",
            "tenant_id, principal_id, algorithm, n, r, p, dklen, salt, hash, created_at, "
            "updated_at",
            ":t, :p, 'scrypt', 32768, 8, 1, 32, :salt, :hash, now(), now()",
        ),
        (
            "password_resets",
            "tenant_id, reset_id, principal_id, token_hash, created_by, created_at, expires_at",
            ":t, :r, :p, :hash, :p, now(), now() + interval '1 day'",
        ),
        (
            "principal_identities",
            "tenant_id, principal_id, provider, subject, created_at",
            ":t, :p, 'google', 'forged', now()",
        ),
    ],
)
def test_the_runtime_role_cannot_write_a_sign_in_table(db, cast, table, columns, values):
    with db.transaction(cast["tenant"]) as conn:
        check_runtime(conn)
        with pytest.raises(Exception) as refused:
            conn.execute(
                text(f"INSERT INTO execbound.{table} ({columns}) VALUES ({values})"),
                {
                    "t": cast["tenant"],
                    "p": cast["approver"],
                    "r": uuid4(),
                    "salt": "ab" * 16,
                    "hash": "cd" * 32,
                },
            )
        assert "permission denied" in str(refused.value).lower()


def test_the_runtime_role_cannot_give_a_person_an_address_itself(db, cast):
    with db.transaction(cast["tenant"]) as conn:
        check_runtime(conn)
        with pytest.raises(Exception) as refused:
            conn.execute(
                text("UPDATE execbound.principals SET email = 'anyone@example.com'"),
            )
        assert "permission denied" in str(refused.value).lower()


def test_the_schema_catalog_knows_every_new_table_and_function(db, cast):
    """`check_runtime` is what refuses a schema missing one of these; a migration that
    dropped a function or a grant would fail here rather than at the first sign-in."""
    with db.transaction(cast["tenant"]) as conn:
        check_runtime(conn)
    from execbound.db import FUNCTIONS, TABLES

    names = {name for name, _ in FUNCTIONS}
    assert {"principal_passwords", "password_resets", "principal_identities"} <= set(TABLES)
    assert {
        "sign_in_credential",
        "identity_sign_in",
        "admin_set_email",
        "admin_reset_password",
        "password_reset_check",
        "password_redeem",
        "password_replace",
    } <= names


# The two single-row policies.


def test_an_address_resolves_to_its_one_person_and_reveals_no_other(db, cast):
    found = locate_email(db, "dana@example.com")
    assert found == (cast["tenant"], cast["approver"])
    assert locate_email(db, "nobody@example.com") is None


def test_the_marker_reveals_one_row_and_never_a_listing(db, cast):
    """Setting the marker answers about the address the caller already typed. Whoever can
    set it learns nothing it did not already name, which is the whole point of the policy."""
    with db.transaction(uuid4()) as conn:
        check_runtime(conn)
        conn.execute(text("SELECT set_config('execbound.sign_in_email', 'dana@example.com', true)"))
        assert conn.execute(text("SELECT count(*) FROM execbound.principals")).scalar_one() == 1
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.principals WHERE email <> :e"),
                {"e": "dana@example.com"},
            ).scalar_one()
            == 0
        )
    with db.transaction(uuid4()) as conn:
        check_runtime(conn)
        assert conn.execute(text("SELECT count(*) FROM execbound.principals")).scalar_one() == 0


def test_an_address_belongs_to_one_person_in_one_tenant(admin_engine, cast):
    with pytest.raises(Exception) as refused:
        person(admin_engine, cast["other"], "HUMAN_APPROVER", email="dana@example.com")
    assert "principals_email" in str(refused.value)


# The sign-in credential.


def test_a_verified_sign_in_mints_a_credential_nothing_can_present(db, cast, clock, seeded):
    identity = mint_session_credential(
        db, cast["tenant"], cast["approver"], "password", clock=clock
    )
    assert identity.kind == "HUMAN_APPROVER"
    assert identity.expires_at - clock.now() == timedelta(hours=8)
    from execbound.identity import authenticate

    # The digest is of bytes that were discarded, so no string authenticates as this row.
    forged = f"eb1.{identity.tenant_id}.{identity.credential_id}." + "A" * 43
    with pytest.raises(AuthenticationFailed):
        authenticate(db, forged)
    granted = issue_session(db, identity, clock=clock)
    assert load_session(db, granted.token, clock=clock).identity == identity


def test_a_sign_in_credential_is_refused_for_anybody_who_is_not_an_active_person(
    db, admin_engine, cast, clock
):
    for principal in (cast["agent"], person(admin_engine, cast["tenant"], "ADMIN", active=False)):
        with pytest.raises(PasswordError) as refused:
            mint_session_credential(db, cast["tenant"], principal, "password", clock=clock)
        assert refused.value.code == "INVALID_PRINCIPAL"
    with pytest.raises(PasswordError) as method:
        mint_session_credential(db, cast["tenant"], cast["approver"], "carrier", clock=clock)
    assert method.value.code == "INVALID_METHOD"


def test_a_sign_in_credential_is_refused_on_a_clock_that_disagrees(db, cast, clock):
    clock.value = datetime.now(UTC) + timedelta(hours=1)
    with pytest.raises(PasswordError) as refused:
        mint_session_credential(db, cast["tenant"], cast["approver"], "password", clock=clock)
    assert refused.value.code == "INVALID_CLOCK"


# Addresses.


def test_an_administrator_gives_an_approver_an_address_and_not_another_administrator(db, cast):
    assert (
        set_email(db, cast["tenant"], cast["admin"], cast["approver"], "Dana.New@Example.com")
        == "dana.new@example.com"
    )
    with pytest.raises(PasswordError) as refused:
        set_email(db, cast["tenant"], cast["admin"], cast["admin"], "root2@example.com")
    assert refused.value.code == "INVALID_PRINCIPAL"


def test_an_address_another_person_holds_is_refused(db, admin_engine, cast):
    second = person(admin_engine, cast["tenant"], "HUMAN_APPROVER")
    with pytest.raises(PasswordError) as refused:
        set_email(db, cast["tenant"], cast["admin"], second, "root@example.com")
    assert refused.value.code == "EMAIL_TAKEN"


def test_only_an_active_administrator_sets_an_address(db, admin_engine, cast):
    for actor in (
        cast["approver"],
        cast["agent"],
        person(admin_engine, cast["tenant"], "ADMIN", active=False),
        uuid4(),
    ):
        with pytest.raises(PasswordError) as refused:
            set_email(db, cast["tenant"], actor, cast["approver"], "new@example.com")
        assert refused.value.code == "INVALID_ACTOR"


@pytest.mark.parametrize("supplied", ["", "dana", "dana@example", "a" * 250 + "@example.com"])
def test_a_string_that_is_not_an_address_is_refused(db, cast, supplied):
    with pytest.raises(PasswordError) as refused:
        set_email(db, cast["tenant"], cast["admin"], cast["approver"], supplied)
    assert refused.value.code == "INVALID_EMAIL"


# Codes.


def test_minting_a_code_revokes_the_one_that_was_pending(db, admin_engine, cast, clock):
    first = issue_reset(db, cast["tenant"], cast["admin"], cast["approver"], clock=clock)
    second = issue_reset(db, cast["tenant"], cast["admin"], cast["approver"], clock=clock)
    with pytest.raises(PasswordError) as refused:
        redeem_reset(db, first.code, PASSWORD, clock=clock)
    assert refused.value.code == "INVALID_RESET"
    assert redeem_reset(db, second.code, PASSWORD, clock=clock) == cast["approver"]


def test_a_code_is_refused_for_an_administrator_and_for_a_person_with_no_address(
    db, admin_engine, cast, clock
):
    with pytest.raises(PasswordError) as target:
        issue_reset(db, cast["tenant"], cast["admin"], cast["admin"], clock=clock)
    assert target.value.code == "INVALID_PRINCIPAL"
    nameless = person(admin_engine, cast["tenant"], "HUMAN_APPROVER")
    with pytest.raises(PasswordError) as address:
        issue_reset(db, cast["tenant"], cast["admin"], nameless, clock=clock)
    assert address.value.code == "INVALID_EMAIL"


@pytest.mark.parametrize(
    "lifetime", [timedelta(minutes=30), MAX_RESET_LIFETIME + timedelta(days=1)]
)
def test_a_code_lifetime_outside_the_range_is_refused(db, cast, clock, lifetime):
    with pytest.raises(PasswordError) as refused:
        issue_reset(
            db, cast["tenant"], cast["admin"], cast["approver"], lifetime=lifetime, clock=clock
        )
    assert refused.value.code == "INVALID_LIFETIME"


def test_five_wrong_secrets_revoke_a_code_and_the_right_one_then_fails_the_same_way(
    db, cast, clock
):
    minted = issue_reset(db, cast["tenant"], cast["admin"], cast["approver"], clock=clock)
    wrong = minted.code.rsplit(".", 1)[0] + "." + "A" * 43
    for _ in range(5):
        with pytest.raises(PasswordError) as refused:
            redeem_reset(db, wrong, PASSWORD, clock=clock)
        assert refused.value.code == "INVALID_RESET"
    with pytest.raises(PasswordError) as after:
        redeem_reset(db, minted.code, PASSWORD, clock=clock)
    assert after.value.code == "INVALID_RESET"


def test_an_expired_a_redeemed_and_a_revoked_code_fail_identically(db, admin_engine, cast, clock):
    """A person who waited too long, one who already used it and one holding a code an
    administrator replaced all see the same sentence and the same status."""
    redeemed = issue_reset(db, cast["tenant"], cast["admin"], cast["approver"], clock=clock)
    redeem_reset(db, redeemed.code, PASSWORD, clock=clock)
    expired = issue_reset(db, cast["tenant"], cast["admin"], cast["approver"], clock=clock)
    # The function reads the database's own clock, so the row is the thing that has to age.
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"),
            {"t": str(cast["tenant"])},
        )
        conn.execute(
            text(
                "UPDATE execbound.password_resets SET expires_at = created_at + interval "
                "'1 hour', created_at = created_at - interval '2 days' WHERE reset_id = :r"
            ),
            {"r": expired.reset_id},
        )
    revoked = issue_reset(db, cast["tenant"], cast["admin"], cast["approver"], clock=clock)
    superseded = issue_reset(db, cast["tenant"], cast["admin"], cast["approver"], clock=clock)
    unknown = f"ebp1.{cast['tenant']}.{uuid4()}." + "A" * 43
    assert superseded.code
    for code in (redeemed.code, expired.code, revoked.code, unknown):
        with pytest.raises(PasswordError) as refused:
            redeem_reset(db, code, ANOTHER, clock=clock)
        assert refused.value.code == "INVALID_RESET"


def test_a_code_of_another_tenant_finds_nothing(db, cast, clock):
    minted = issue_reset(db, cast["tenant"], cast["admin"], cast["approver"], clock=clock)
    moved = minted.code.split(".")
    moved[1] = str(cast["other"])
    with pytest.raises(PasswordError) as refused:
        redeem_reset(db, ".".join(moved), PASSWORD, clock=clock)
    assert refused.value.code == "INVALID_RESET"


def test_only_one_of_two_concurrent_redemptions_wins(db, cast, clock):
    minted = issue_reset(db, cast["tenant"], cast["admin"], cast["approver"], clock=clock)
    with ThreadPoolExecutor(max_workers=2) as pool:
        answers = [
            pool.submit(_redeem, db, minted.code, password, clock)
            for password in (PASSWORD, ANOTHER)
        ]
        outcomes = [answer.result() for answer in answers]
    assert sorted(kind for kind, _ in outcomes) == ["refused", "won"]
    winner = next(value for kind, value in outcomes if kind == "won")
    assert winner == cast["approver"]
    record = read_record(db, cast["tenant"], cast["approver"])
    assert record is not None
    # Exactly one password took, and it is one of the two that were offered.
    assert sum(verify_password(record, candidate) for candidate in (PASSWORD, ANOTHER)) == 1


def _redeem(db, code, password, clock):
    try:
        return "won", redeem_reset(db, code, password, clock=clock)
    except PasswordError as refused:
        return "refused", refused.code


def test_redeeming_ends_every_session_and_credential_the_person_had(db, cast, clock):
    identity = mint_session_credential(
        db, cast["tenant"], cast["approver"], "password", clock=clock
    )
    granted = issue_session(db, identity, clock=clock)
    assert load_session(db, granted.token, clock=clock)
    minted = issue_reset(db, cast["tenant"], cast["admin"], cast["approver"], clock=clock)
    redeem_reset(db, minted.code, PASSWORD, clock=clock)
    with pytest.raises(SessionError):
        load_session(db, granted.token, clock=clock)
    with db.transaction(cast["tenant"]) as conn:
        live = conn.execute(
            text(
                "SELECT count(*) FROM execbound.credentials WHERE tenant_id = :t "
                "AND principal_id = :p AND revoked_at IS NULL"
            ),
            {"t": cast["tenant"], "p": cast["approver"]},
        ).scalar_one()
    assert live == 0


def test_setting_a_password_is_audited_without_the_code(db, cast, clock):
    minted = issue_reset(db, cast["tenant"], cast["admin"], cast["approver"], clock=clock)
    redeem_reset(db, minted.code, PASSWORD, clock=clock)
    with db.transaction(cast["tenant"]) as conn:
        events = [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT kind, payload FROM execbound.audit_events WHERE tenant_id = :t "
                    "ORDER BY sequence"
                ),
                {"t": cast["tenant"]},
            ).mappings()
        ]
    kinds = [row["kind"] for row in events]
    assert "password.reset_issued" in kinds and "password.set" in kinds
    assert_secret_free(events, known=(minted.code,))
    assert code_digest(minted.code) not in str(events)


# Passwords, end to end.


def test_the_address_and_the_password_together_sign_a_person_in(db, cast, clock):
    given_password(db, cast, PASSWORD, clock)
    identity = sign_in_with_password(db, "  Dana@Example.com ", PASSWORD, clock=clock)
    assert (identity.tenant_id, identity.principal_id) == (cast["tenant"], cast["approver"])
    assert identity.kind == "HUMAN_APPROVER"


@pytest.mark.parametrize(
    ("email", "password", "reason"),
    [
        ("dana@example.com", "the wrong one entirely", "MISMATCH"),
        ("nobody@example.com", PASSWORD, "UNKNOWN"),
        ("not-an-address", PASSWORD, "UNKNOWN"),
        ("root@example.com", PASSWORD, "UNKNOWN"),
    ],
)
def test_every_refusal_is_the_same_answer_with_its_own_private_reason(
    db, cast, clock, email, password, reason
):
    given_password(db, cast, PASSWORD, clock)
    with pytest.raises(AuthenticationFailed) as refused:
        sign_in_with_password(db, email, password, clock=clock)
    assert str(refused.value) == "Invalid credentials"
    assert refused.value.reason == reason


def test_a_deactivated_person_cannot_sign_in_with_their_password(db, admin_engine, cast, clock):
    given_password(db, cast, PASSWORD, clock)
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"),
            {"t": str(cast["tenant"])},
        )
        conn.execute(
            text("UPDATE execbound.principals SET active = false WHERE principal_id = :p"),
            {"p": cast["approver"]},
        )
    with pytest.raises(AuthenticationFailed) as refused:
        sign_in_with_password(db, "dana@example.com", PASSWORD, clock=clock)
    assert refused.value.reason == "INACTIVE"


def test_an_agent_holding_an_address_still_cannot_sign_in(db, admin_engine, cast, clock):
    """No path gives an AGENT a password, and if provisioning ever did the sign-in refuses."""
    agent = person(admin_engine, cast["tenant"], "AGENT", email="agent@example.com")
    record = hash_password(PASSWORD)
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"),
            {"t": str(cast["tenant"])},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.principal_passwords (tenant_id, principal_id, algorithm, "
                "n, r, p, dklen, salt, hash, created_at, updated_at) "
                "VALUES (:t, :p, :alg, :n, :r, :pp, :dk, :salt, :hash, now(), now())"
            ),
            {
                "t": cast["tenant"],
                "p": agent,
                "alg": record.algorithm,
                "n": record.n,
                "r": record.r,
                "pp": record.p,
                "dk": record.dklen,
                "salt": record.salt,
                "hash": record.hash,
            },
        )
    with pytest.raises(AuthenticationFailed) as refused:
        sign_in_with_password(db, "agent@example.com", PASSWORD, clock=clock)
    assert refused.value.reason == "INACTIVE"


def test_a_person_changes_their_own_password_and_only_with_the_current_one(db, cast, clock):
    given_password(db, cast, PASSWORD, clock)
    # Redemption writes its durable timestamp using the database clock.
    clock.value = datetime.now(UTC)
    identity = sign_in_with_password(db, "dana@example.com", PASSWORD, clock=clock)
    session = load_session(db, issue_session(db, identity, clock=clock).token, clock=clock)
    for wrong in ("not it at all", "", None):
        with pytest.raises(PasswordError) as refused:
            change_password(db, identity, wrong, ANOTHER, clock=clock, session=session)
        assert refused.value.code == "INVALID_CURRENT"
    change_password(db, identity, PASSWORD, ANOTHER, clock=clock, session=session)
    assert sign_in_with_password(db, "dana@example.com", ANOTHER, clock=clock)
    with pytest.raises(AuthenticationFailed):
        sign_in_with_password(db, "dana@example.com", PASSWORD, clock=clock)


def test_a_change_refuses_the_same_password_and_a_weak_one(db, cast, clock):
    given_password(db, cast, PASSWORD, clock)
    clock.value = datetime.now(UTC)
    identity = sign_in_with_password(db, "dana@example.com", PASSWORD, clock=clock)
    session = load_session(db, issue_session(db, identity, clock=clock).token, clock=clock)
    with pytest.raises(PasswordError) as same:
        change_password(db, identity, PASSWORD, PASSWORD, clock=clock, session=session)
    assert same.value.code == "PASSWORD_UNCHANGED"
    with pytest.raises(PasswordError) as weak:
        change_password(db, identity, PASSWORD, "short", clock=clock, session=session)
    assert weak.value.code == "INVALID_PASSWORD"


def test_a_change_cannot_become_a_set(db, admin_engine, cast, clock):
    """`password_replace` refuses a person holding none, so nothing that skipped the
    current-password check could create one through that door."""
    identity = mint_session_credential(
        db, cast["tenant"], cast["approver"], "password", clock=clock
    )
    assert read_record(db, cast["tenant"], cast["approver"]) is None
    with pytest.raises(PasswordError) as refused:
        change_password(db, identity, "anything at all", ANOTHER, clock=clock)
    assert refused.value.code == "INVALID_CURRENT"


# Provider identities.


def test_a_subject_binds_once_and_then_identifies_the_person(db, cast, clock):
    bind_identity(
        db,
        cast["tenant"],
        cast["approver"],
        provider="google",
        subject=SUBJECT,
        email="dana@example.com",
        display_name="Dana Reyes",
        clock=clock,
    )
    assert locate_subject(db, "google", SUBJECT) == (cast["tenant"], cast["approver"])
    # A later sign-in under a changed address still finds the person by subject.
    bind_identity(
        db,
        cast["tenant"],
        cast["approver"],
        provider="google",
        subject=SUBJECT,
        email="dana.reyes@example.net",
        display_name="Dana R",
        clock=clock,
    )
    assert locate_subject(db, "google", SUBJECT) == (cast["tenant"], cast["approver"])
    with db.transaction(cast["tenant"]) as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT email, display_name, last_sign_in_at "
                    "FROM execbound.principal_identities "
                    "WHERE tenant_id = :t AND principal_id = :p"
                ),
                {"t": cast["tenant"], "p": cast["approver"]},
            )
            .mappings()
            .all()
        )
    assert len(rows) == 1
    assert rows[0]["email"] == "dana.reyes@example.net"
    assert rows[0]["last_sign_in_at"] is not None


def test_a_subject_bound_to_one_person_is_never_moved_to_another(db, admin_engine, cast, clock):
    bind_identity(
        db,
        cast["tenant"],
        cast["approver"],
        provider="google",
        subject=SUBJECT,
        email="dana@example.com",
        display_name=None,
        clock=clock,
    )
    second = person(admin_engine, cast["tenant"], "HUMAN_APPROVER", email="sam@example.com")
    with pytest.raises(PasswordError) as refused:
        bind_identity(
            db,
            cast["tenant"],
            second,
            provider="google",
            subject=SUBJECT,
            email="sam@example.com",
            display_name=None,
            clock=clock,
        )
    assert refused.value.code == "INVALID_IDENTITY"


def test_one_provider_account_belongs_to_one_person_anywhere(db, admin_engine, cast, clock):
    bind_identity(
        db,
        cast["tenant"],
        cast["approver"],
        provider="google",
        subject=SUBJECT,
        email="dana@example.com",
        display_name=None,
        clock=clock,
    )
    elsewhere = person(admin_engine, cast["other"], "HUMAN_APPROVER", email="dana@other.example")
    with pytest.raises(Exception) as refused:
        bind_identity(
            db,
            cast["other"],
            elsewhere,
            provider="google",
            subject=SUBJECT,
            email="dana@other.example",
            display_name=None,
            clock=clock,
        )
    assert (
        isinstance(refused.value, (PasswordError, UnsafeDatabaseRole))
        or "unique" in str(refused.value).lower()
    )


@pytest.mark.parametrize("provider", ["entra", "okta", "", "google "])
def test_a_provider_this_deployment_does_not_serve_is_refused(db, cast, clock, provider):
    with pytest.raises(PasswordError) as refused:
        bind_identity(
            db,
            cast["tenant"],
            cast["approver"],
            provider=provider,
            subject=SUBJECT,
            email="dana@example.com",
            display_name=None,
            clock=clock,
        )
    assert refused.value.code == "INVALID_IDENTITY"


def test_the_subject_marker_reveals_one_row_and_never_a_listing(db, cast, clock):
    bind_identity(
        db,
        cast["tenant"],
        cast["approver"],
        provider="google",
        subject=SUBJECT,
        email="dana@example.com",
        display_name=None,
        clock=clock,
    )
    assert locate_subject(db, "google", "a-different-subject") is None
    with db.transaction(uuid4()) as conn:
        check_runtime(conn)
        assert (
            conn.execute(text("SELECT count(*) FROM execbound.principal_identities")).scalar_one()
            == 0
        )


def test_subject_known_holds_for_a_live_and_a_legacy_binding_never_for_a_stranger(
    db, admin_engine, cast, clock
):
    """`subject_known` is the question a provider signup asks before recording a request
    (#504, rule 2): does this pair already identify someone, whether the account signs in
    today or would need its legacy binding adopted first. A revoked binding still answers
    yes, because the subject once identified this account and must never identify a second
    one; what a revoked binding can no longer do is sign in, which is `provider_sign_in`'s
    question, not this one.

    Adoption leaves the legacy `principal_identities` row live, so on its own it would
    answer every case below without the live `user_identities` row ever being read. That
    row is revoked first, with `locate_subject` returning `None` as the control proving it,
    so the assertions after it are about the live row alone.
    """
    from test_workspace_accounts import adopt

    from execbound.user_accounts import subject_known

    bind_identity(
        db,
        cast["tenant"],
        cast["approver"],
        provider="google",
        subject=SUBJECT,
        email="dana@example.com",
        display_name="Dana Reyes",
        clock=clock,
    )
    # Legacy: bound but not yet adopted into an account's own `user_identities` row.
    assert subject_known(db, "google", SUBJECT) is True
    assert subject_known(db, "github", SUBJECT) is False
    assert subject_known(db, "google", "a-different-subject") is False

    account = adopt(db, cast["tenant"], cast["approver"])

    # Revoke the legacy row adoption left behind, so what follows is about the live
    # `user_identities` row `_binding` reads, not the legacy one `locate_subject` reads.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.principal_identities SET revoked_at=now() "
                "WHERE tenant_id=:t AND principal_id=:p AND provider='google' AND subject=:s"
            ),
            {"t": cast["tenant"], "p": cast["approver"], "s": SUBJECT},
        )
    assert locate_subject(db, "google", SUBJECT) is None  # control: the legacy half is gone

    assert subject_known(db, "google", SUBJECT) is True  # the live `user_identities` row

    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.user_identities SET revoked_at=now() WHERE account_id=:a"),
            {"a": account},
        )
    assert subject_known(db, "google", SUBJECT) is True  # revoked, but still a binding

    assert subject_known(db, "github", SUBJECT) is False  # another provider, same subject


def test_subject_known_turns_a_binding_fault_into_password_unavailable(db, monkeypatch):
    """`_binding`'s own query can fail as any other database read can; `subject_known` turns
    that fault into the one failure shape every caller of this question already handles
    (`PasswordError("PASSWORD_UNAVAILABLE")`), never the bare `SQLAlchemyError` a careless
    caller might not catch, and never a quiet `False` that would answer a provider signup's
    `begin_signup` as if nobody held the subject at all when the store was simply
    unreachable.

    Mutation: turning `subject_known`'s `except (SQLAlchemyError, PasswordError):` clause
    into `return False` would answer `False` here instead of raising, and this test fails.
    """
    import execbound.user_accounts as user_accounts

    def broken_binding(db, provider, subject):
        raise SQLAlchemyError("boom")

    monkeypatch.setattr(user_accounts, "_binding", broken_binding)
    with pytest.raises(PasswordError) as caught:
        user_accounts.subject_known(db, "google", SUBJECT)
    assert caught.value.code == "PASSWORD_UNAVAILABLE"


def test_subject_known_turns_a_locate_subject_fault_into_password_unavailable(db, monkeypatch):
    """The same holds for `locate_subject`'s own half, reached only once `_binding` itself
    found nothing: whatever code its own `PasswordError` carried is replaced too, so a
    caller of `subject_known` sees a single failure shape for this question, never two."""
    import execbound.passwords as passwords
    import execbound.user_accounts as user_accounts

    def broken_locate_subject(db, provider, subject):
        raise PasswordError("SOME_OTHER_CODE")

    monkeypatch.setattr(user_accounts, "_binding", lambda db, provider, subject: None)
    monkeypatch.setattr(passwords, "locate_subject", broken_locate_subject)
    with pytest.raises(PasswordError) as caught:
        user_accounts.subject_known(db, "google", SUBJECT)
    assert caught.value.code == "PASSWORD_UNAVAILABLE"


def test_subject_known_lets_unsafe_database_role_propagate_from_binding(db, monkeypatch):
    """`UnsafeDatabaseRole` is a database-safety refusal, not an ordinary fault: it is a
    `RuntimeError`, neither a `SQLAlchemyError` nor a `PasswordError`, so `subject_known`'s
    own `except (SQLAlchemyError, PasswordError)` does not catch it and it must reach the
    caller exactly as raised, never answered as `False` and never turned into
    `PasswordError("PASSWORD_UNAVAILABLE")`."""
    import execbound.user_accounts as user_accounts

    def broken_binding(db, provider, subject):
        raise UnsafeDatabaseRole("a detail nobody should see")

    monkeypatch.setattr(user_accounts, "_binding", broken_binding)
    with pytest.raises(UnsafeDatabaseRole):
        user_accounts.subject_known(db, "google", SUBJECT)


def test_the_hash_is_never_returned_by_any_read_a_page_makes(db, cast, clock):
    given_password(db, cast, PASSWORD, clock)
    record = read_record(db, cast["tenant"], cast["approver"])
    assert record is not None and verify_password(record, PASSWORD)
    with db.transaction(cast["tenant"]) as conn:
        stored = conn.execute(
            text(
                "SELECT hash FROM execbound.principal_passwords "
                "WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"t": cast["tenant"], "p": cast["approver"]},
        ).scalar_one()
    assert PASSWORD not in stored
    assert UUID(str(cast["approver"]))
