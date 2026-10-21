# SPDX-License-Identifier: AGPL-3.0-only
"""When a console session ends, and what the session view says about it (#678).

A session lasts twelve hours without activity and renews on any authenticated read once seven
and a half minutes have passed since it was last extended, never past the credential's own expiry
or two days after sign-in. The first test
holds the renewal for the session a setup credential opens, read as a visible console reads
it: once a minute. The second holds the hard end the session view names, which no renewal
moves, and why it ends then.
"""

from datetime import datetime, timedelta

import pytest
from console_api_fixtures import API, ORIGIN
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_console_serving import write_build
from test_directory_store import cast as cast
from test_directory_store import clock as clock
from test_directory_store import settings as settings
from test_human_surface import credential, form_values
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world
from test_sign_in_surface import ADDRESS, PASSWORD
from test_sign_in_surface import signed_up as signed_up
from test_workspace_switching import member_pair

from execbound import workspaces
from execbound.app import create_app
from execbound.passwords import sign_in_with_password
from execbound.surfaces import console as console_module
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import (
    SESSION_ABSOLUTE,
    SESSION_LIFETIME,
    issue_session,
    load_session,
)
from execbound.surfaces.tokens import TokenKeys

pytestmark = pytest.mark.integration


@pytest.fixture
def built(tmp_path, monkeypatch):
    root = write_build(tmp_path / "console_dist")
    monkeypatch.setattr(console_module, "build_root", lambda: root)
    return root


def _config() -> HumanConfig:
    return HumanConfig(ORIGIN, TokenKeys("state-v1", {"state-v1": b"k" * 32}))


def _renewed(response) -> dict[str, int]:
    """The session cookies a response rewrote, by name, with their `Max-Age`."""
    ages: dict[str, int] = {}
    for value in response.headers.get_list("set-cookie"):
        name = value.split("=", 1)[0]
        if name in {"eb_session", "eb_csrf"}:
            age = [part for part in value.split(";") if part.strip().lower().startswith("max-age")]
            ages[name] = int(age[0].split("=", 1)[1])
    return ages


def test_sn7_a_setup_credential_session_renews_while_it_is_read(
    db, runtime, world, admin_engine, built
):
    """Read once a minute for twenty minutes, a setup-credential session stays signed in and
    its cookies are rewritten every `RENEW_AFTER`; left alone for twelve hours, it ends.

    The session is not account-bound and passes through no skew-fenced function once it is
    exchanged, so the injected clock advances freely.
    """
    clock = world["clock"]
    admin = world["admin"]
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.credentials SET expires_at=:e "
                "WHERE tenant_id=:t AND credential_id=:c"
            ),
            {"e": clock.now() + timedelta(days=8), "t": admin.tenant_id, "c": admin.credential_id},
        )
    app = create_app(db, runtime=runtime, human=_config())
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        _, values = form_values(client.get("/login").text, "/session")
        values["credential"] = credential(admin_engine, admin)
        assert client.post("/session", data=values, headers={"Origin": ORIGIN}).status_code == 303
        renewals: list[int] = []
        for minute in range(1, 21):
            clock.value += timedelta(seconds=60)
            read = client.get(API + "/session")
            assert read.status_code == 200, (minute, read.text)
            ages = _renewed(read)
            if ages:
                assert set(ages) == {"eb_session", "eb_csrf"}, ages
                assert all(
                    abs(age - SESSION_LIFETIME.total_seconds()) <= 1 for age in ages.values()
                )
                renewals.append(minute)
        # The first read past seven and a half minutes renews, and the first read that long
        # after the renewed row's own extension renews again.
        assert renewals == [8, 16], renewals
        # A page load past the cadence renews the same way.
        clock.value += timedelta(minutes=8)
        page = client.get("/activity")
        assert page.status_code == 200, page.text
        assert set(_renewed(page)) == {"eb_session", "eb_csrf"}
        clock.value += SESSION_LIFETIME + timedelta(minutes=1)
        ended = client.get(API + "/session")
        assert ended.status_code == 401, ended.text
        assert ended.json()["code"] == "SESSION_REQUIRED"


def _row(admin_engine, tenant, session_id) -> dict:
    with admin_engine.begin() as conn:
        return dict(
            conn.execute(
                text(
                    "SELECT created_at, credential_expires_at, expires_at "
                    "FROM execbound.human_sessions WHERE tenant_id=:t AND session_id=:s"
                ),
                {"t": tenant, "s": session_id},
            )
            .mappings()
            .one()
        )


def _just_short_of_two_days(session, row) -> None:
    """A sign-in credential is minted for two days just before its session row: the end is
    the credential's, a moment short of the row's own two days, and it is a sign-in's."""
    assert session.ends_at == row["credential_expires_at"]
    gap = row["created_at"] + SESSION_ABSOLUTE - session.ends_at
    assert timedelta(0) <= gap < timedelta(seconds=5), gap
    assert session.end_reason == "sign_in"


def test_sn8_the_view_names_the_hard_end_and_why(
    db, runtime, world, admin_engine, seeded, signed_up
):
    # A password sign-in through an account, then the session a switch opens from it.
    grant, current, _, _ = member_pair(db, admin_engine, seeded)
    row = _row(admin_engine, seeded["tenants"][0], grant.session_id)
    _just_short_of_two_days(current, row)
    switched = workspaces.switch_workspace(db, current, grant.account_token, seeded["tenants"][1])
    moved = load_session(db, switched.token)
    # The switched-to row was created later, but its end is still the account sign-in's two
    # days, which the account session fixed when it opened with the first row.
    assert abs(moved.ends_at - (row["created_at"] + SESSION_ABSOLUTE)) < timedelta(seconds=5)
    assert moved.end_reason == "sign_in"

    # A password set on the principal through a code, as an administrator's reset sets one.
    legacy = issue_session(
        db, sign_in_with_password(db, ADDRESS, PASSWORD, clock=runtime.clock), clock=runtime.clock
    )
    session = load_session(db, legacy.token, clock=runtime.clock)
    _just_short_of_two_days(session, _row(admin_engine, signed_up["tenant"], legacy.session_id))

    # A setup credential that expires an hour after the idle limit, exchanged at `POST /session`
    # and read through the session view; then a renewal moves `expires_at` and never `ends_at`.
    clock, admin = world["clock"], world["admin"]
    ends = clock.now() + SESSION_LIFETIME + timedelta(hours=1)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.credentials SET expires_at=:e "
                "WHERE tenant_id=:t AND credential_id=:c"
            ),
            {"e": ends, "t": admin.tenant_id, "c": admin.credential_id},
        )
    app = create_app(db, runtime=runtime, human=_config())
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        _, values = form_values(client.get("/login").text, "/session")
        values["credential"] = credential(admin_engine, admin)
        assert client.post("/session", data=values, headers={"Origin": ORIGIN}).status_code == 303
        first = client.get(API + "/session").json()
        assert first["end_reason"] == "setup_credential"
        assert datetime.fromisoformat(first["ends_at"]) == ends
        clock.value += timedelta(minutes=8)
        later = client.get(API + "/session")
        assert set(_renewed(later)) == {"eb_session", "eb_csrf"}
        assert later.json()["expires_at"] > first["expires_at"]
        assert later.json()["ends_at"] == first["ends_at"]
        assert later.json()["end_reason"] == "setup_credential"


def test_sn8_a_directory_session_ends_two_days_after_sign_in(
    db, settings, cast, clock, admin_engine
):
    """Directory sign-in mints its credential for two days as a password sign-in does."""
    from test_directory_store import ANOTHER_SUBJECT, account, enabled

    from execbound import directory_store as store

    provider = enabled(db, settings, cast, clock)
    store.link_person(
        db, cast["tenant"], cast["admin"], cast["approver"], provider, ANOTHER_SUBJECT, clock=clock
    )
    identity = store.sign_in(
        db, settings, store.locate_provider(db, provider), account(ANOTHER_SUBJECT), clock=clock
    )
    clock.value += timedelta(milliseconds=3)
    granted = issue_session(db, identity, clock=clock)
    session = load_session(db, granted.token, clock=clock)
    # Bound to no account, it is the session the tolerance keeps from reading as a setup
    # credential's.
    assert session.account_id is None
    _just_short_of_two_days(session, _row(admin_engine, cast["tenant"], granted.session_id))
