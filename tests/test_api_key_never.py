# SPDX-License-Identifier: AGPL-3.0-only
"""An agent's API key issued with no expiry (0057): `NEVER`, for an agent and nothing else.

A key that never expires still carries a real expiry, the one far-future instant `NEVER`, so
authentication, admission and the replay capture read it as they read any other. The database
function lets that exact instant past the 90-day cap for an agent's key and for nothing else,
and the console API offers it only where an agent's key is issued.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from alembic import command as alembic
from console_api_fixtures import API, console_client
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_console_api_agents import without_token
from test_emergency_stop import audit
from test_execution import registry as registry
from test_execution import world as world
from test_migration_without_bypass import restricted as restricted
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_resolution import request
from test_runtime import runtime as runtime

from execbound.identity import NEVER, authenticate, new_token

CREDENTIALS = API + "/credentials"


def test_never_is_the_last_day_of_year_9999_in_utc():
    assert NEVER == datetime(9999, 12, 31, tzinfo=UTC)


def test_an_agents_key_issued_to_never_expire_authenticates_and_acts(
    db, runtime, admin_engine, world
):
    tenant = world["identity"].tenant_id
    agent = str(world["identity"].principal_id)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        issued = client.post(f"{API}/agents/{agent}/credentials/issue", {"lifetime": "never"})
        assert issued.status_code == 200, issued.text
        shown = without_token(issued)
        assert shown["kind"] == "AGENT" and datetime.fromisoformat(shown["expires_at"]) == NEVER
        token = issued.json()["token"]
        listed = client.get(CREDENTIALS).json()["credentials"]
        row = next(row for row in listed if row["credential_id"] == shown["credential_id"])
        assert row["state"] == "live" and datetime.fromisoformat(row["expires_at"]) == NEVER
    identity = authenticate(runtime.db, token)
    assert identity.expires_at == NEVER
    event = audit(admin_engine, tenant, "credential.issued")[-1]
    assert event["credential_id"] == shown["credential_id"]
    assert event["expires_at"] == NEVER.isoformat()
    # The key proposes an action as any agent key does: admission, the frozen plan and the
    # replay capture all take its expiry as an ordinary instant.
    view = runtime.execute(identity, request(world).model_dump_json().encode())
    assert view.state == "PENDING_APPROVAL", view


def test_an_agent_created_for_its_key_can_take_one_that_never_expires(
    db, runtime, admin_engine, world
):
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        made = client.post(f"{CREDENTIALS}/issue", {"principal": "new:AGENT", "lifetime": "never"})
        assert made.status_code == 200, made.text
        assert datetime.fromisoformat(without_token(made)["expires_at"]) == NEVER
        assert authenticate(runtime.db, made.json()["token"]).expires_at == NEVER


def test_no_expiry_is_refused_for_a_person_and_on_the_person_routes(
    db, runtime, admin_engine, world
):
    tenant = world["identity"].tenant_id
    human = str(world["human"].principal_id)

    def principals() -> int:
        with admin_engine.begin() as conn:
            return conn.execute(
                text("SELECT count(*) FROM execbound.principals WHERE tenant_id = :t"),
                {"t": tenant},
            ).scalar_one()

    before = principals()
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        existing = client.post(f"{CREDENTIALS}/issue", {"principal": human, "lifetime": "never"})
        assert existing.status_code == 400, existing.text
        assert existing.json()["fields"] == ["lifetime"] and "token" not in existing.json()
        created = client.post(
            f"{CREDENTIALS}/issue", {"principal": "new:HUMAN_APPROVER", "lifetime": "never"}
        )
        assert created.status_code == 400 and created.json()["fields"] == ["lifetime"]
        # A person's credential and a set-password code keep their own lifetimes.
        for path in (
            f"{API}/people/{human}/credentials/issue",
            f"{API}/people/{human}/password-link",
        ):
            refused = client.post(path, {"lifetime": "never"})
            assert refused.status_code == 400, (path, refused.text)
            assert refused.json()["fields"] == ["lifetime"]
    assert principals() == before


def test_the_migration_lifts_the_cap_for_never_alone_and_the_downgrade_restores_it(restricted):
    engine, config, _ = restricted
    signature = "execbound.admin_issue_credential(uuid,uuid,uuid,text,timestamptz,timestamptz)"

    def function() -> tuple[str, bool, bool]:
        with engine.connect() as conn:
            return tuple(
                conn.execute(
                    text(
                        "SELECT pg_get_functiondef(CAST(:f AS regprocedure)), p.prosecdef, "
                        "has_function_privilege('execbound_app', :f, 'EXECUTE') "
                        "FROM pg_proc p WHERE p.oid = CAST(:f AS regprocedure)"
                    ),
                    {"f": signature},
                ).one()
            )

    alembic.upgrade(config, "0056_gate_evidence")
    capped, _, _ = function()
    assert "9999-12-31" not in capped
    alembic.upgrade(config, "0057_api_key_never")
    lifted, definer, granted = function()
    assert "9999-12-31 00:00:00+00" in lifted and "v_kind = 'AGENT'" in lifted
    assert lifted.count("interval '90 days'") == 1 and definer and granted
    alembic.downgrade(config, "0056_gate_evidence")
    restored, definer, granted = function()
    assert restored == capped and definer and granted
    alembic.upgrade(config, "head")


@pytest.mark.parametrize(
    "expires",
    [
        lambda now: now + timedelta(days=91),
        lambda now: datetime(2100, 1, 1, tzinfo=UTC),
        lambda now: NEVER - timedelta(seconds=1),
    ],
    ids=["91 days", "a far date", "a second before never"],
)
def test_the_function_lets_only_never_past_the_cap_and_only_for_an_agent(
    runtime, admin_engine, world, expires
):
    tenant = world["identity"].tenant_id
    now = datetime.now(UTC)
    for principal, until in (
        (world["identity"].principal_id, expires(now)),
        (world["human"].principal_id, NEVER),
    ):
        credential = uuid4()
        _, digest = new_token(tenant, credential)
        with pytest.raises(DBAPIError, match="INVALID_LIFETIME"):
            with runtime.db.transaction(tenant) as conn:
                conn.execute(
                    text(
                        "SELECT execbound.admin_issue_credential("
                        ":actor, :principal, :credential, :digest, :issued, :expires)"
                    ),
                    {
                        "actor": world["admin"].principal_id,
                        "principal": principal,
                        "credential": credential,
                        "digest": digest,
                        "issued": now,
                        "expires": until,
                    },
                )
