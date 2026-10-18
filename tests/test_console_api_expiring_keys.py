# SPDX-License-Identifier: AGPL-3.0-only
"""Agent keys that expire soon, and a rotation that is recorded rather than inferred (AK5).

A key needs a notice when its agent is active and awake, the key is live, it expires within
seven days of the server's clock, it has been used, and no live key names it as the key it
replaces. One notice per agent, the soonest. The same rule answers `GET /credentials/expiring`
and the agent detail's `expiring_key`, and a key is shown as replaced only after an issue with
`replaces` names it.
"""

from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from console_api_fixtures import API, console_client
from sqlalchemy import text
from test_console_api_tokens import auth, bearer, minted
from test_execution import provision_credential
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime
from test_spaces_credentials import spaces as spaces

pytestmark = pytest.mark.integration

EXPIRING = API + "/credentials/expiring"


def agent(admin_engine, tenant, label=None, *, space=None) -> UUID:
    principal = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind, space_id, label) "
                "VALUES (:t, :p, 'AGENT', COALESCE(CAST(:s AS uuid), "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t "
                "ORDER BY created_at LIMIT 1)), :l)"
            ),
            {"t": tenant, "p": principal, "s": space, "l": label},
        )
    return principal


def key(admin_engine, tenant, principal, now, expires_in, *, used=True) -> UUID:
    issued = now - timedelta(hours=1)
    with admin_engine.begin() as conn:
        token = provision_credential(
            conn, tenant, principal, issued, expires_in + timedelta(hours=1)
        )
        credential = UUID(token.split(".")[2])
        if used:
            conn.execute(
                text(
                    "UPDATE execbound.credentials SET last_used_at = :u "
                    "WHERE tenant_id = :t AND credential_id = :c"
                ),
                {"u": now - timedelta(minutes=5), "t": tenant, "c": credential},
            )
    return credential


def quiet_seeded_key(admin_engine, tenant):
    """The world's agent holds a used key that expires within the hour; set it aside."""
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.credentials SET last_used_at = NULL "
                "WHERE tenant_id = :t AND last_used_at IS NOT NULL AND principal_id IN "
                "(SELECT principal_id FROM execbound.principals WHERE tenant_id = :t "
                "AND kind = 'AGENT')"
            ),
            {"t": tenant},
        )


def listed(client):
    answer = client.get(EXPIRING)
    assert answer.status_code == 200, answer.text
    return answer.json()


def test_ak5_one_notice_per_agent_until_a_rotation_names_the_key(db, runtime, admin_engine, world):
    tenant = world["identity"].tenant_id
    now = world["clock"].now()
    quiet_seeded_key(admin_engine, tenant)
    stories = agent(admin_engine, tenant, "Tines stories")
    first = key(admin_engine, tenant, stories, now, timedelta(days=3))
    # Keys that never notify: never used, beyond seven days, never expiring, on an asleep
    # agent, on a deactivated agent, revoked.
    quiet = agent(admin_engine, tenant)
    key(admin_engine, tenant, quiet, now, timedelta(days=3), used=False)
    key(admin_engine, tenant, quiet, now, timedelta(days=8))
    with admin_engine.begin() as conn:
        never = provision_credential(conn, tenant, quiet, now - timedelta(hours=1), timedelta(0))
        conn.execute(
            text(
                "UPDATE execbound.credentials SET expires_at = '9999-12-31T00:00:00Z', "
                "last_used_at = :u WHERE tenant_id = :t AND credential_id = :c"
            ),
            {"u": now - timedelta(minutes=5), "t": tenant, "c": UUID(never.split(".")[2])},
        )
    asleep, gone = agent(admin_engine, tenant), agent(admin_engine, tenant)
    key(admin_engine, tenant, asleep, now, timedelta(days=2))
    key(admin_engine, tenant, gone, now, timedelta(days=2))
    revoked = key(admin_engine, tenant, quiet, now, timedelta(days=1))
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.principals SET active = false, dormant_at = :n "
                "WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"n": now - timedelta(days=1), "t": tenant, "p": asleep},
        )
        conn.execute(
            text(
                "UPDATE execbound.principals SET active = false, deactivated_at = :n "
                "WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"n": now - timedelta(minutes=1), "t": tenant, "p": gone},
        )
        conn.execute(
            text(
                "UPDATE execbound.credentials SET revoked_at = :n "
                "WHERE tenant_id = :t AND credential_id = :c"
            ),
            {"n": now - timedelta(minutes=1), "t": tenant, "c": revoked},
        )

    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        body = listed(client)
        assert [row["credential_id"] for row in body["keys"]] == [str(first)]
        assert body["more"] == 0
        row = body["keys"][0]
        assert row["principal_id"] == str(stories)
        assert row["principal_label"] == "Tines stories"
        assert row["last_used_at"] is not None and row["number"] is not None

        # A second used key for another integration, and a third issued without Rotate:
        # neither retires the first.
        key(admin_engine, tenant, stories, now, timedelta(days=60))
        third = client.post(f"{API}/agents/{stories}/credentials/issue", {"lifetime": "720"})
        assert third.status_code == 200, third.text
        assert [row["credential_id"] for row in listed(client)["keys"]] == [str(first)]
        page = client.get(API + "/credentials").json()
        assert not any(row["replaced"] for row in page["credentials"])

        rotated = client.post(
            f"{API}/agents/{stories}/credentials/issue",
            {"lifetime": "2160", "replaces": str(first)},
        )
        assert rotated.status_code == 200, rotated.text
        assert listed(client)["keys"] == []
        page = {
            row["credential_id"]: row
            for row in client.get(API + "/credentials").json()["credentials"]
        }
        assert page[str(first)]["replaced"] and page[str(first)]["state"] == "live"
        assert page[str(first)]["last_used_at"] is not None
        detail = client.get(f"{API}/agents/{stories}").json()
        rows = {row["credential_id"]: row for row in detail["credentials"]}
        assert rows[str(first)]["replaced"]
        assert not rows[rotated.json()["credential_id"]]["replaced"]
        assert detail["expiring_key"] is None


def test_ak5_more_counts_the_agents_beyond_five(db, runtime, admin_engine, world):
    tenant = world["identity"].tenant_id
    now = world["clock"].now()
    quiet_seeded_key(admin_engine, tenant)
    made = [agent(admin_engine, tenant, f"Agent {index}") for index in range(7)]
    soonest = {}
    for index, principal in enumerate(made):
        # Two keys each; only the soonest is the agent's notice.
        soonest[principal] = key(admin_engine, tenant, principal, now, timedelta(hours=10 + index))
        key(admin_engine, tenant, principal, now, timedelta(days=5))
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        body = listed(client)
        assert [row["credential_id"] for row in body["keys"]] == [
            str(soonest[principal]) for principal in made[:5]
        ]
        assert body["more"] == 2
        detail = client.get(f"{API}/agents/{made[6]}").json()
        assert detail["expiring_key"]["credential_id"] == str(soonest[made[6]])


def test_ak5_a_narrowed_administrator_sees_their_own_spaces_agents_alone(
    db, runtime, admin_engine, world, spaces
):
    tenant = spaces["tenant"]
    now = world["clock"].now()
    quiet_seeded_key(admin_engine, tenant)
    hidden = key(admin_engine, tenant, spaces["other_agent"].principal_id, now, timedelta(days=2))
    own = key(admin_engine, tenant, spaces["own_agent"].principal_id, now, timedelta(days=2))
    with console_client(db, runtime, admin_engine, spaces["narrowed_identity"]) as client:
        assert [row["credential_id"] for row in listed(client)["keys"]] == [str(own)]
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        assert {row["credential_id"] for row in listed(client)["keys"]} == {str(own), str(hidden)}


def test_ak5_an_approver_is_refused_and_a_token_may_read(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["human"]) as client:
        refused = client.get(EXPIRING)
        assert refused.status_code == 403 and refused.json()["code"] == "FORBIDDEN"
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        token = minted(runtime, world)
        with bearer(console, token) as client:
            answer = client.get(EXPIRING, headers=auth(token))
            assert answer.status_code == 200, answer.text
            assert set(answer.json()) == {"keys", "more"}
