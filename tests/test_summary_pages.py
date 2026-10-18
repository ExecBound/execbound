# SPDX-License-Identifier: AGPL-3.0-only
"""The weekly summary's one-click unsubscribe (#678): HV14.

`GET` changes nothing and sets no cookie; `POST` ends the subscription only for that message's
own secret, and every `POST` answers the same status and body, a forged, unknown, used,
malformed or other workspace's link and one naming a workspace that does not exist included.
An old link cannot end a renewed subscription. Both pages send `no-referrer` and `no-store`,
the request log carries no path, and both limits answer 429.
"""

import hashlib
import secrets
from datetime import date, timedelta
from uuid import uuid4

import pytest
from console_api_fixtures import ORIGIN, console_config
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_execution import registry as registry  # noqa: F401
from test_execution import world as world  # noqa: F401
from test_migration_without_bypass import fenced
from test_protected_path import connector as connector  # noqa: F401
from test_protected_path import live_provider as live_provider  # noqa: F401
from test_runtime import runtime as runtime  # noqa: F401
from test_structured_logging import captured as captured  # noqa: F401
from test_structured_logging import records
from test_teammate_invitations import workspace

from execbound.app import create_app
from execbound.resolution.models import SystemClock
from execbound.surfaces.limits import RequestLimiter, RequestLimits

PAGE = "/weekly-summary/unsubscribe/"
ONE_CLICK = {"Content-Type": "application/x-www-form-urlencoded"}
BODY = "List-Unsubscribe=One-Click"


def monday() -> date:
    today = date.today()
    return today - timedelta(days=today.weekday())


def subscribed(db, admin_engine, *, name="Summaries"):
    """A workspace whose administrator subscribed, and one queued message's link."""
    where = workspace(admin_engine, name=name)
    tenant, admin = where["tenant_id"], where["admin"]
    with db.transaction(tenant) as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.weekly_summary_subscriptions "
                "(tenant_id, principal_id, subscribed_at) "
                "VALUES (:t, :p, now() - interval '1 minute')"
            ),
            {"t": tenant, "p": admin},
        )
        conn.execute(text("SELECT execbound.weekly_summary_enqueue(:w, now())"), {"w": monday()})
        message = conn.execute(
            text("SELECT message_id FROM execbound.weekly_summary_messages WHERE tenant_id=:t"),
            {"t": tenant},
        ).scalar_one()
        secret = secrets.token_urlsafe(32)
        conn.execute(
            text(
                "UPDATE execbound.weekly_summary_messages SET unsubscribe_hash=:h "
                "WHERE tenant_id=:t AND message_id=:m"
            ),
            {"t": tenant, "m": message, "h": hashlib.sha256(secret.encode()).hexdigest()},
        )
    return {
        "tenant": tenant,
        "admin": admin,
        "message": message,
        "secret": secret,
        "link": f"ebw1.{tenant}.{message}.{secret}",
    }


def state(admin_engine, tenant, admin):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        row = (
            conn.execute(
                text(
                    "SELECT ended_at, ended_via FROM execbound.weekly_summary_subscriptions "
                    "WHERE tenant_id=:t AND principal_id=:p"
                ),
                {"t": tenant, "p": admin},
            )
            .mappings()
            .one()
        )
        events = conn.execute(
            text(
                "SELECT count(*) FROM execbound.audit_events WHERE tenant_id=:t "
                "AND kind='weekly_summary.unsubscribed'"
            ),
            {"t": tenant},
        ).scalar_one()
    return row["ended_at"] is None, row["ended_via"], events


@pytest.fixture
def client(db, runtime):
    runtime.clock = SystemClock()
    with TestClient(
        create_app(db, runtime=runtime, human=console_config()),
        base_url=ORIGIN,
        follow_redirects=False,
    ) as test:
        yield test


def post(client, link):
    return client.post(PAGE + link, content=BODY, headers=ONE_CLICK)


def test_hv14_the_page_reads_and_changes_nothing(db, admin_engine, client):
    one = subscribed(db, admin_engine)
    before = state(admin_engine, one["tenant"], one["admin"])
    page = client.get(PAGE + one["link"])
    assert page.status_code == 200
    assert '<form method="post">' in page.text and "<script" not in page.text
    assert "set-cookie" not in page.headers
    assert page.headers["referrer-policy"] == "no-referrer"
    assert page.headers["cache-control"] == "no-store"
    assert "form-action" in page.headers["content-security-policy"]
    assert state(admin_engine, one["tenant"], one["admin"]) == before == (True, None, 0)
    assert client.get(PAGE + one["link"] + "?x=1").status_code == 400


def test_hv14_one_click_ends_only_its_own_subscription_and_answers_every_request_alike(
    db,
    admin_engine,
    client,
    captured,  # noqa: F811
):
    one = subscribed(db, admin_engine)
    other = subscribed(db, admin_engine, name="Elsewhere")
    done = post(client, one["link"])
    assert done.status_code == 200
    assert "If this link was yours, the weekly summary is off." in done.text
    assert done.headers["referrer-policy"] == "no-referrer"
    assert done.headers["cache-control"] == "no-store"
    assert state(admin_engine, one["tenant"], one["admin"]) == (False, "LINK", 1)
    forged = secrets.token_urlsafe(32)
    for link in (
        one["link"],  # used already
        f"ebw1.{one['tenant']}.{one['message']}.{forged}",
        f"ebw1.{one['tenant']}.{uuid4()}.{one['secret']}",
        f"ebw1.{one['tenant']}.{other['message']}.{other['secret']}",
        f"ebw1.{uuid4()}.{one['message']}.{one['secret']}",
        "ebw1.not-a-link",
        "anything",
    ):
        answer = post(client, link)
        assert answer.status_code == done.status_code, link
        assert answer.text == done.text, link
    # The other workspace's subscriber is untouched, and nothing else changed here.
    assert state(admin_engine, other["tenant"], other["admin"]) == (True, None, 0)
    assert state(admin_engine, one["tenant"], one["admin"]) == (False, "LINK", 1)
    # RFC 8058's own form body, and the page's form, both reach the endpoint; the request
    # log names no path, so the link's secret never reaches it.
    logged = [line for line in records(captured) if line.get("event") == "request.completed"]
    assert logged and all(one["secret"] not in str(line) for line in logged)
    assert all("path" not in line for line in logged)


def test_hv14_an_old_link_cannot_end_a_renewed_subscription(db, admin_engine, client):
    one = subscribed(db, admin_engine)
    assert post(client, one["link"]).status_code == 200
    with db.transaction(one["tenant"]) as conn:
        conn.execute(
            text(
                "UPDATE execbound.weekly_summary_subscriptions SET subscribed_at=now(), "
                "ended_at=NULL, ended_via=NULL WHERE tenant_id=:t AND principal_id=:p"
            ),
            {"t": one["tenant"], "p": one["admin"]},
        )
    assert post(client, one["link"]).status_code == 200
    assert state(admin_engine, one["tenant"], one["admin"])[:2] == (True, None)


def test_hv14_the_request_shape_is_held(db, admin_engine, client):
    one = subscribed(db, admin_engine)
    link = PAGE + one["link"]
    assert (
        client.post(link, content=BODY, headers={"Content-Type": "text/plain"}).status_code == 400
    )
    assert client.post(link, content="x" * 4096, headers=ONE_CLICK).status_code == 400
    assert (
        client.post(link, content=BODY, headers={**ONE_CLICK, "X-Tenant-Id": "x"}).status_code
        == 400
    )
    assert state(admin_engine, one["tenant"], one["admin"]) == (True, None, 0)


def test_hv14_both_limits_answer_too_many(db, admin_engine, runtime, client):
    one = subscribed(db, admin_engine)
    other = subscribed(db, admin_engine, name="Other")
    runtime.limiter = RequestLimiter(RequestLimits(login_attempts=2), runtime.clock)
    for _ in range(2):
        assert client.get(PAGE + one["link"]).status_code == 200
    limited = client.get(PAGE + one["link"])
    assert limited.status_code == 429 and "retry-after" in limited.headers
    # Another message's link still answers: the per-message bound is its own.
    assert client.get(PAGE + other["link"]).status_code == 200
    runtime.limiter = RequestLimiter(RequestLimits(client_requests=2), runtime.clock)
    assert client.get(PAGE + other["link"]).status_code == 200
    assert client.get(PAGE + other["link"]).status_code == 200
    assert post(client, other["link"]).status_code == 429
    assert state(admin_engine, other["tenant"], other["admin"]) == (True, None, 0)
