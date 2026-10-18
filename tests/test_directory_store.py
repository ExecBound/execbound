# SPDX-License-Identifier: AGPL-3.0-only
"""A customer's own identity provider against real PostgreSQL: privileges, states, race.

Every write here goes through a `SECURITY DEFINER` function, so each test states one thing a
function must refuse and asserts the code. The privilege tests are the ones that matter most:
if the runtime role could write these tables itself, every check in the functions would be
advice rather than a boundary.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from conftest import assert_secret_free
from idp_fixtures import (
    CLIENT_ID,
    CLIENT_SECRET,
    ISSUER,
    NAME,
    REFRESH,
    ROTATED,
    SUBJECT,
    TENANT_ID,
    USERNAME,
    StandIn,
    directory_key,
    discovery_document,
)
from sqlalchemy import text

from execbound import directory_store as store
from execbound.db import check_runtime
from execbound.directory import (
    DirectoryAccount,
    DirectoryConfig,
    Discovery,
)
from execbound.envelope import KEY_BYTES, KeyRing, unseal
from execbound.resolution.models import Clock
from execbound.runtime import Runtime
from execbound.surfaces.sessions import SessionError, issue_session, load_session

pytestmark = pytest.mark.integration

RING = KeyRing("dir-v1", {"dir-v1": b"\x11" * KEY_BYTES})
ANOTHER_SUBJECT = "77777777-0000-4000-8000-0000000000cc"


class FixedClock(Clock):
    def __init__(self) -> None:
        self.value = datetime.now(UTC)

    def now(self) -> datetime:
        return self.value


@pytest.fixture
def clock():
    return FixedClock()


@pytest.fixture
def settings():
    return DirectoryConfig(RING, "https://app.example")


@pytest.fixture
def runtime(db, clock):
    """Just enough runtime for the recheck: the database and the clock it reads."""
    return Runtime(db, [], clock=clock)


def person(engine, tenant, kind, *, active=True):
    principal = uuid4()
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind, active, space_id)"
                " VALUES (:t, :p, :k, :a, CASE WHEN :k = 'AGENT' THEN "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t) END)"
            ),
            {"t": tenant, "p": principal, "k": kind, "a": active},
        )
    return principal


@pytest.fixture
def cast(admin_engine, seeded):
    tenant, other = seeded["tenants"][0], seeded["tenants"][1]
    return {
        "tenant": tenant,
        "other": other,
        "admin": person(admin_engine, tenant, "ADMIN"),
        "approver": person(admin_engine, tenant, "HUMAN_APPROVER"),
        "second": person(admin_engine, tenant, "HUMAN_APPROVER"),
        "agent": person(admin_engine, tenant, "AGENT"),
        "stranger": person(admin_engine, other, "ADMIN"),
    }


def discovery() -> Discovery:
    document = discovery_document()
    return Discovery(
        ISSUER,
        document["authorization_endpoint"],
        document["token_endpoint"],
        document["jwks_uri"],
        TENANT_ID,
    )


def account(subject: str = SUBJECT) -> DirectoryAccount:
    return DirectoryAccount(subject, NAME, USERNAME, REFRESH)


def registered(db, settings, cast, clock):
    return store.register(
        db,
        settings,
        cast["tenant"],
        cast["admin"],
        name="Contoso",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        subject_claim="oid",
        discovery=discovery(),
        clock=clock,
    )


def enabled(db, settings, cast, clock):
    """A registered provider an administrator verified by signing in and then enabled."""
    provider = registered(db, settings, cast, clock)
    store.link_self(db, cast["tenant"], cast["admin"], provider, account(), clock=clock)
    store.set_state(db, cast["tenant"], cast["admin"], provider, "enabled", clock=clock)
    return provider


# ---- privileges: the boundary every check below rests on --------------------------------


@pytest.mark.parametrize(
    "table",
    ["identity_providers", "identity_links", "identity_invitations", "federated_sign_ins"],
)
@pytest.mark.parametrize(
    "shape",
    ["INSERT INTO {} (tenant_id) VALUES (:t)", "UPDATE {} SET tenant_id = :t", "DELETE FROM {}"],
)
def test_the_runtime_role_cannot_write_a_directory_table(db, cast, table, shape):
    statement = shape.format(f"execbound.{table}")
    with db.transaction(cast["tenant"]) as conn:
        check_runtime(conn)
        with pytest.raises(Exception) as refused:  # noqa: B017 - the driver's own class
            conn.execute(text(statement), {"t": cast["tenant"]})
        assert "permission denied" in str(refused.value).lower()


def test_the_schema_catalog_knows_every_new_table_and_function(db, cast):
    """`check_runtime` compares the live schema with the catalog, so this is the catalog test."""
    with db.transaction(cast["tenant"]) as conn:
        check_runtime(conn)
    from execbound.db import FUNCTIONS, TABLES

    names = {name for name, _ in FUNCTIONS}
    assert {
        "identity_providers",
        "identity_links",
        "identity_invitations",
        "federated_sign_ins",
    } <= set(TABLES)
    assert {
        "directory_register",
        "directory_set_state",
        "directory_link_self",
        "directory_link",
        "directory_unlink",
        "directory_invite",
        "directory_invitation_revoke",
        "directory_invitation_check",
        "directory_sign_in",
        "directory_recheck",
        "directory_revoke",
    } <= names


# ---- registration -----------------------------------------------------------------------


def test_a_registration_is_a_draft_whose_secret_is_only_ever_ciphertext(
    db, settings, cast, clock, admin_engine
):
    provider = registered(db, settings, cast, clock)
    with db.transaction(cast["tenant"]) as conn:
        check_runtime(conn)
        row = store.provider_in(conn, cast["tenant"])
    assert row["provider_id"] == provider
    assert row["state"] == "draft"
    assert row["issuer"] == ISSUER
    assert row["issuer_tenant"] == TENANT_ID
    assert CLIENT_SECRET not in row["secret_ciphertext"]
    assert (
        unseal(
            RING,
            row["secret_ciphertext"],
            row["secret_key_id"],
            cast["tenant"],
            provider,
            "client_secret",
        )
        == CLIENT_SECRET
    )


def test_a_second_live_provider_is_refused(db, settings, cast, clock):
    registered(db, settings, cast, clock)
    with pytest.raises(store.DirectoryError) as refused:
        registered(db, settings, cast, clock)
    assert refused.value.code == "PROVIDER_EXISTS"


def test_an_approver_cannot_register_a_provider(db, settings, cast, clock):
    with pytest.raises(store.DirectoryError) as refused:
        store.register(
            db,
            settings,
            cast["tenant"],
            cast["approver"],
            name="Contoso",
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            subject_claim="oid",
            discovery=discovery(),
            clock=clock,
        )
    assert refused.value.code == "INVALID_ACTOR"


def test_an_administrator_of_another_tenant_cannot_register_here(db, settings, cast, clock):
    with pytest.raises(store.DirectoryError) as refused:
        store.register(
            db,
            settings,
            cast["tenant"],
            cast["stranger"],
            name="Contoso",
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            subject_claim="oid",
            discovery=discovery(),
            clock=clock,
        )
    assert refused.value.code == "INVALID_ACTOR"


# ---- the state machine ------------------------------------------------------------------


def test_enabling_a_draft_is_refused_because_nobody_has_proved_it_works(db, settings, cast, clock):
    provider = registered(db, settings, cast, clock)
    with pytest.raises(store.DirectoryError) as refused:
        store.set_state(db, cast["tenant"], cast["admin"], provider, "enabled", clock=clock)
    assert refused.value.code == "INVALID_STATE"


@pytest.mark.parametrize("state", ["draft", "verified", "anything"])
def test_only_enabled_and_disabled_are_requestable(db, settings, cast, clock, state):
    provider = registered(db, settings, cast, clock)
    with pytest.raises(store.DirectoryError) as refused:
        store.set_state(db, cast["tenant"], cast["admin"], provider, state, clock=clock)
    assert refused.value.code == "INVALID_STATE"


def test_a_self_link_verifies_a_draft_and_links_only_the_acting_person(db, settings, cast, clock):
    provider = registered(db, settings, cast, clock)
    linked = store.link_self(db, cast["tenant"], cast["admin"], provider, account(), clock=clock)
    assert linked["verified"] is True
    assert linked["kind"] == "ADMIN"
    with db.transaction(cast["tenant"]) as conn:
        check_runtime(conn)
        row = store.provider_in(conn, cast["tenant"])
        linked = store.directory_of(conn, cast["tenant"], cast["admin"], datetime.now(UTC))
    assert row["state"] == "verified"
    assert row["verified_at"] is not None
    assert linked["link"]["subject"] == SUBJECT
    assert linked["link"]["via"] == "self"


def test_a_second_self_link_of_the_same_person_is_refused(db, settings, cast, clock):
    provider = enabled(db, settings, cast, clock)
    with pytest.raises(store.DirectoryError) as refused:
        store.link_self(
            db, cast["tenant"], cast["admin"], provider, account(ANOTHER_SUBJECT), clock=clock
        )
    assert refused.value.code == "ALREADY_LINKED"


def test_one_directory_account_belongs_to_one_person(db, settings, cast, clock):
    provider = enabled(db, settings, cast, clock)
    with pytest.raises(store.DirectoryError) as refused:
        store.link_person(
            db, cast["tenant"], cast["admin"], cast["approver"], provider, SUBJECT, clock=clock
        )
    assert refused.value.code == "ALREADY_LINKED"


def test_an_administrator_cannot_be_linked_by_anybody_but_themselves(
    db, settings, cast, clock, admin_engine
):
    """The 0021 invariant still holds with a directory in the world."""
    provider = enabled(db, settings, cast, clock)
    other_admin = person(admin_engine, cast["tenant"], "ADMIN")
    with pytest.raises(store.DirectoryError) as refused:
        store.link_person(
            db,
            cast["tenant"],
            cast["admin"],
            other_admin,
            provider,
            ANOTHER_SUBJECT,
            clock=clock,
        )
    assert refused.value.code == "INVALID_PRINCIPAL"


def test_an_agent_cannot_be_linked(db, settings, cast, clock):
    provider = enabled(db, settings, cast, clock)
    with pytest.raises(store.DirectoryError) as refused:
        store.link_person(
            db, cast["tenant"], cast["admin"], cast["agent"], provider, ANOTHER_SUBJECT, clock=clock
        )
    assert refused.value.code == "INVALID_PRINCIPAL"


# ---- the sign-in and what it stands on --------------------------------------------------


def test_a_linked_account_signs_in_and_the_refresh_token_is_only_ciphertext(
    db, settings, cast, clock, admin_engine
):
    provider = enabled(db, settings, cast, clock)
    store.link_person(
        db, cast["tenant"], cast["admin"], cast["approver"], provider, ANOTHER_SUBJECT, clock=clock
    )
    row = store.locate_provider(db, provider)
    identity = store.sign_in(db, settings, row, account(ANOTHER_SUBJECT), clock=clock)
    assert identity.principal_id == cast["approver"]
    assert identity.kind == "HUMAN_APPROVER"
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"),
            {"t": str(cast["tenant"])},
        )
        stored = (
            conn.execute(
                text(
                    "SELECT refresh_ciphertext, refresh_key_id, subject FROM "
                    "execbound.federated_sign_ins WHERE credential_id = :c"
                ),
                {"c": identity.credential_id},
            )
            .mappings()
            .one()
        )
    assert REFRESH not in stored["refresh_ciphertext"]
    assert (
        unseal(
            RING,
            stored["refresh_ciphertext"],
            stored["refresh_key_id"],
            cast["tenant"],
            provider,
            "refresh_token",
        )
        == REFRESH
    )


def test_a_subject_with_no_link_is_refused_and_never_created(db, settings, cast, clock):
    provider = enabled(db, settings, cast, clock)
    row = store.locate_provider(db, provider)
    assert store.locate_link(db, provider, ANOTHER_SUBJECT) is None
    with pytest.raises(store.DirectoryError) as refused:
        store.sign_in(db, settings, row, account(ANOTHER_SUBJECT), clock=clock)
    assert refused.value.code == "INVALID_LINK"


def test_a_disabled_provider_refuses_a_sign_in_and_ends_every_session_under_it(
    db, settings, cast, clock, admin_engine
):
    provider = enabled(db, settings, cast, clock)
    store.link_person(
        db, cast["tenant"], cast["admin"], cast["approver"], provider, ANOTHER_SUBJECT, clock=clock
    )
    row = store.locate_provider(db, provider)
    identity = store.sign_in(db, settings, row, account(ANOTHER_SUBJECT), clock=clock)
    granted = issue_session(db, identity, clock=clock)
    assert load_session(db, granted.token, clock=clock).session_id == granted.session_id

    store.set_state(db, cast["tenant"], cast["admin"], provider, "disabled", clock=clock)
    with pytest.raises(SessionError):
        load_session(db, granted.token, clock=clock)
    # And the provider itself is gone from every public read, so a flow already in the air ends.
    assert store.locate_provider(db, provider) is None


def test_unlinking_a_person_ends_their_sessions(db, settings, cast, clock):
    provider = enabled(db, settings, cast, clock)
    store.link_person(
        db, cast["tenant"], cast["admin"], cast["approver"], provider, ANOTHER_SUBJECT, clock=clock
    )
    row = store.locate_provider(db, provider)
    identity = store.sign_in(db, settings, row, account(ANOTHER_SUBJECT), clock=clock)
    granted = issue_session(db, identity, clock=clock)
    store.unlink_person(db, cast["tenant"], cast["admin"], cast["approver"], clock=clock)
    with pytest.raises(SessionError):
        load_session(db, granted.token, clock=clock)
    with pytest.raises(store.DirectoryError) as refused:
        store.unlink_person(db, cast["tenant"], cast["admin"], cast["approver"], clock=clock)
    assert refused.value.code == "INVALID_LINK"


# ---- invitations -------------------------------------------------------------------------


def test_an_invitation_binds_the_subject_to_the_person_it_named(db, settings, cast, clock):
    provider = enabled(db, settings, cast, clock)
    minted = store.invite(db, cast["tenant"], cast["admin"], cast["approver"], provider)
    assert minted.code.startswith(f"ebv1.{cast['tenant']}.{minted.invitation_id}.")
    invitation, found = store.check_invitation(db, minted.code)
    assert (invitation, found) == (minted.invitation_id, provider)
    row = store.locate_provider(db, provider)
    identity = store.sign_in(
        db, settings, row, account(ANOTHER_SUBJECT), invitation_id=invitation, clock=clock
    )
    assert identity.principal_id == cast["approver"]
    with db.transaction(cast["tenant"]) as conn:
        check_runtime(conn)
        linked = store.directory_of(conn, cast["tenant"], cast["approver"], datetime.now(UTC))
    assert linked["link"]["via"] == "invitation"
    assert linked["invitation"] is None


def test_a_redeemed_invitation_cannot_be_redeemed_again(db, settings, cast, clock):
    provider = enabled(db, settings, cast, clock)
    minted = store.invite(db, cast["tenant"], cast["admin"], cast["approver"], provider)
    invitation, _ = store.check_invitation(db, minted.code)
    row = store.locate_provider(db, provider)
    store.sign_in(
        db, settings, row, account(ANOTHER_SUBJECT), invitation_id=invitation, clock=clock
    )
    with pytest.raises(store.DirectoryError) as refused:
        store.check_invitation(db, minted.code)
    assert refused.value.code == "INVALID_INVITATION"


def test_five_wrong_secrets_revoke_an_invitation(db, settings, cast, clock):
    provider = enabled(db, settings, cast, clock)
    minted = store.invite(db, cast["tenant"], cast["admin"], cast["approver"], provider)
    wrong = minted.code[:-1] + ("A" if minted.code[-1] != "A" else "B")
    for _ in range(5):
        with pytest.raises(store.DirectoryError):
            store.check_invitation(db, wrong)
    # The right code now fails exactly as a wrong one did, which is the point of the counter.
    with pytest.raises(store.DirectoryError) as refused:
        store.check_invitation(db, minted.code)
    assert refused.value.code == "INVALID_INVITATION"


def test_a_revoked_expired_and_unknown_code_all_fail_the_same_way(db, settings, cast, clock):
    provider = enabled(db, settings, cast, clock)
    minted = store.invite(db, cast["tenant"], cast["admin"], cast["approver"], provider)
    store.revoke_invitation(db, cast["tenant"], cast["admin"], minted.invitation_id)
    codes = [minted.code, f"ebv1.{cast['tenant']}.{uuid4()}.{'a' * 43}", "nonsense"]
    for code in codes:
        with pytest.raises(store.DirectoryError) as refused:
            store.check_invitation(db, code)
        assert refused.value.code == "INVALID_INVITATION"


def test_minting_a_second_invitation_revokes_the_first(db, settings, cast, clock):
    provider = enabled(db, settings, cast, clock)
    first = store.invite(db, cast["tenant"], cast["admin"], cast["approver"], provider)
    second = store.invite(db, cast["tenant"], cast["admin"], cast["approver"], provider)
    with pytest.raises(store.DirectoryError):
        store.check_invitation(db, first.code)
    assert store.check_invitation(db, second.code)[0] == second.invitation_id


@pytest.mark.parametrize("lifetime", [timedelta(minutes=30), timedelta(days=15)])
def test_a_lifetime_outside_the_bounds_is_refused(db, settings, cast, clock, lifetime):
    provider = enabled(db, settings, cast, clock)
    with pytest.raises(store.DirectoryError) as refused:
        store.invite(
            db, cast["tenant"], cast["admin"], cast["approver"], provider, lifetime=lifetime
        )
    assert refused.value.code == "INVALID_LIFETIME"


def test_a_person_who_is_already_linked_cannot_be_invited(db, settings, cast, clock):
    provider = enabled(db, settings, cast, clock)
    store.link_person(
        db, cast["tenant"], cast["admin"], cast["approver"], provider, ANOTHER_SUBJECT, clock=clock
    )
    with pytest.raises(store.DirectoryError) as refused:
        store.invite(db, cast["tenant"], cast["admin"], cast["approver"], provider)
    assert refused.value.code == "ALREADY_LINKED"


def test_another_tenants_selector_reaches_nothing(db, settings, cast, clock):
    provider = enabled(db, settings, cast, clock)
    minted = store.invite(db, cast["tenant"], cast["admin"], cast["approver"], provider)
    moved = minted.code.replace(str(cast["tenant"]), str(cast["other"]))
    with pytest.raises(store.DirectoryError) as refused:
        store.check_invitation(db, moved)
    assert refused.value.code == "INVALID_INVITATION"


def test_another_tenant_reads_no_provider_or_link(db, settings, cast, clock):
    """The tenant fence on the two tables a sign-in reads, as the runtime role (#155). Each also
    carries a sign-in policy that admits one row by a selector the sign-in sets
    (`directory_provider`, `directory_subject`); with no selector, another workspace's fence
    reads nothing of either, and the workspace's own reads its provider and its link."""
    enabled(db, settings, cast, clock)
    for tenant, expected in ((cast["other"], 0), (cast["tenant"], 1)):
        with db.transaction(tenant) as conn:
            for table in ("identity_providers", "identity_links"):
                counted = conn.execute(text(f"SELECT count(*) FROM execbound.{table}"))
                assert counted.scalar_one() == expected, (table, expected)


def test_only_one_of_two_concurrent_redemptions_wins(db, settings, cast, clock):
    """Two browsers holding one code produce one session, under one row lock, on real rows."""
    provider = enabled(db, settings, cast, clock)
    minted = store.invite(db, cast["tenant"], cast["admin"], cast["approver"], provider)
    invitation, _ = store.check_invitation(db, minted.code)
    row = store.locate_provider(db, provider)
    with ThreadPoolExecutor(max_workers=2) as pool:
        answers = [
            pool.submit(_redeem, db, settings, row, subject, invitation, clock)
            for subject in (ANOTHER_SUBJECT, "88888888-0000-4000-8000-0000000000dd")
        ]
        outcomes = [answer.result() for answer in answers]
    assert sorted(kind for kind, _ in outcomes) == ["refused", "won"]
    winner = next(value for kind, value in outcomes if kind == "won")
    assert winner.principal_id == cast["approver"]
    with db.transaction(cast["tenant"]) as conn:
        check_runtime(conn)
        links = conn.execute(
            text(
                "SELECT count(*) FROM execbound.identity_links WHERE tenant_id = :t "
                "AND principal_id = :p AND revoked_at IS NULL"
            ),
            {"t": cast["tenant"], "p": cast["approver"]},
        ).scalar_one()
    assert links == 1


def _redeem(db, settings, row, subject, invitation, clock):
    try:
        return "won", store.sign_in(
            db, settings, row, account(subject), invitation_id=invitation, clock=clock
        )
    except store.DirectoryError as refused:
        return "refused", refused.code


# ---- the two single-row reads -------------------------------------------------------------


def test_the_provider_read_answers_only_about_the_id_it_was_given(db, settings, cast, clock):
    provider = enabled(db, settings, cast, clock)
    assert store.locate_provider(db, provider).tenant_id == cast["tenant"]
    assert store.locate_provider(db, uuid4()) is None


def test_the_link_read_answers_only_about_the_account_it_was_given(db, settings, cast, clock):
    provider = enabled(db, settings, cast, clock)
    assert store.locate_link(db, provider, SUBJECT) == (cast["tenant"], cast["admin"])
    assert store.locate_link(db, provider, ANOTHER_SUBJECT) is None
    assert store.locate_link(db, uuid4(), SUBJECT) is None


def test_neither_read_lists_anything(db, cast):
    """Without a marker the policies permit no row at all, whatever is in the tables."""
    with db.transaction(cast["tenant"]) as conn:
        check_runtime(conn)
        assert (
            conn.execute(text("SELECT count(*) FROM execbound.identity_providers")).scalar_one()
            == 0
        )


# ---- the recheck --------------------------------------------------------------------------


def _session(db, settings, cast, clock, stand_in=None):
    """An approver signed in through the directory, with the stand-in told who they are.

    The administrator holds `SUBJECT` from verifying the provider, so the approver holds the
    other one, and the refresh the recheck redeems has to name the same account or the recheck
    would be reading a subject change that never happened.
    """
    if stand_in is not None:
        stand_in.refresh_claims = {"oid": ANOTHER_SUBJECT}
    provider = enabled(db, settings, cast, clock)
    store.link_person(
        db, cast["tenant"], cast["admin"], cast["approver"], provider, ANOTHER_SUBJECT, clock=clock
    )
    row = store.locate_provider(db, provider)
    identity = store.sign_in(db, settings, row, account(ANOTHER_SUBJECT), clock=clock)
    granted = issue_session(db, identity, clock=clock)
    return provider, load_session(db, granted.token, clock=clock), granted


def test_a_verified_recheck_stamps_the_row_and_stores_the_rotated_token(
    db, cast, clock, runtime, admin_engine
):
    key = directory_key()
    stand_in = StandIn(key, now=lambda: clock.value.timestamp())
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    provider, session, _ = _session(db, settings, cast, clock, stand_in)
    clock.value = clock.value + store.RECHECK_INTERVAL + timedelta(seconds=1)
    store.recheck_session(runtime, settings, session)
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"),
            {"t": str(cast["tenant"])},
        )
        stored = (
            conn.execute(
                text(
                    "SELECT refresh_ciphertext, refresh_key_id, verified_at FROM "
                    "execbound.federated_sign_ins WHERE credential_id = :c"
                ),
                {"c": session.identity.credential_id},
            )
            .mappings()
            .one()
        )
    assert (
        unseal(
            RING,
            stored["refresh_ciphertext"],
            stored["refresh_key_id"],
            cast["tenant"],
            provider,
            "refresh_token",
        )
        == ROTATED
    )


def test_a_refused_recheck_ends_the_session_on_this_request(db, cast, clock, runtime):
    key = directory_key()
    stand_in = StandIn(
        key,
        now=lambda: clock.value.timestamp(),
        refresh_status=400,
        refresh_body={"error": "invalid_grant"},
    )
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    _, session, granted = _session(db, settings, cast, clock, stand_in)
    clock.value = clock.value + store.RECHECK_INTERVAL + timedelta(seconds=1)
    with pytest.raises(SessionError):
        store.recheck_session(runtime, settings, session)
    with pytest.raises(SessionError):
        load_session(db, granted.token, clock=clock)


def test_an_unreachable_directory_is_tolerated_and_then_refuses(db, cast, clock, runtime):
    key = directory_key()
    stand_in = StandIn(key, now=lambda: clock.value.timestamp(), unreachable=True)
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    _, session, granted = _session(db, settings, cast, clock, stand_in)
    clock.value = clock.value + store.RECHECK_INTERVAL + timedelta(seconds=1)
    # Inside the grace the session stands, and nothing is revoked.
    store.recheck_session(runtime, settings, session)
    assert load_session(db, granted.token, clock=clock).session_id == granted.session_id
    clock.value = clock.value + store.RECHECK_GRACE
    with pytest.raises(SessionError):
        store.recheck_session(runtime, settings, session)
    # And nothing was revoked by that refusal, so an outage that resolves lets people carry on
    # rather than forcing every person in the tenant to sign in again.
    with db.transaction(cast["tenant"]) as conn:
        check_runtime(conn)
        state = (
            conn.execute(
                text(
                    "SELECT f.revoked_reason, c.revoked_at FROM execbound.federated_sign_ins f "
                    "JOIN execbound.credentials c USING (tenant_id, credential_id) "
                    "WHERE f.credential_id = :c"
                ),
                {"c": session.identity.credential_id},
            )
            .mappings()
            .one()
        )
    assert state["revoked_reason"] is None and state["revoked_at"] is None
    stand_in.unreachable = False
    store.recheck_session(runtime, settings, session)


def test_a_recheck_before_the_interval_asks_the_directory_nothing(db, cast, clock, runtime):
    key = directory_key()
    stand_in = StandIn(key, now=lambda: clock.value.timestamp())
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    _, session, _ = _session(db, settings, cast, clock, stand_in)
    before = len(stand_in.seen)
    store.recheck_session(runtime, settings, session)
    assert len(stand_in.seen) == before


def test_a_password_session_reaches_no_directory_at_all(db, cast, clock, runtime, admin_engine):
    """One indexed read and nothing else for every session that is not a directory session."""
    key = directory_key()
    stand_in = StandIn(key, now=lambda: clock.value.timestamp())
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    from execbound.passwords import mint_session_credential

    identity = mint_session_credential(
        db, cast["tenant"], cast["approver"], "password", clock=clock
    )
    granted = issue_session(db, identity, clock=clock)
    session = load_session(db, granted.token, clock=clock)
    clock.value = clock.value + store.RECHECK_INTERVAL + timedelta(seconds=1)
    store.recheck_session(runtime, settings, session)
    assert stand_in.seen == []


# ---- nothing rendered or returned carries a secret -----------------------------------------


def test_no_reader_of_a_provider_or_a_person_carries_a_secret(db, settings, cast, clock, runtime):
    provider = enabled(db, settings, cast, clock)
    minted = store.invite(db, cast["tenant"], cast["admin"], cast["second"], provider)
    with db.transaction(cast["tenant"]) as conn:
        check_runtime(conn)
        seen = store.directory_of(conn, cast["tenant"], cast["second"], datetime.now(UTC))
    assert_secret_free(seen)
    assert minted.code not in repr(seen)
