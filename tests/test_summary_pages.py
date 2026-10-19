# SPDX-License-Identifier: AGPL-3.0-only
"""The weekly summary's one-click unsubscribe (#678): HV14.

`GET` changes nothing and sets no cookie; `POST` ends the subscription only for that message's
own secret, and every `POST` answers the same status and body, a forged, unknown, used,
malformed or other workspace's link and one naming a workspace that does not exist included.
An old link cannot end a renewed subscription. Both pages send `no-referrer` and `no-store`,
and every 400 and 429 `no-referrer` too; the request log carries no path, a forged, unknown or
malformed link logs nothing and the stop only its ids; both limits answer 429; and a database
fault while stopping answers the same page and logs one error line with no ids.
"""

import hashlib
import json
import secrets
from datetime import UTC, date, datetime, timedelta
from uuid import uuid4

import pytest
from console_api_fixtures import ORIGIN, console_config
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from test_execution import registry as registry  # noqa: F401
from test_execution import world as world  # noqa: F401
from test_migration_without_bypass import fenced
from test_protected_path import connector as connector  # noqa: F401
from test_protected_path import live_provider as live_provider  # noqa: F401
from test_runtime import runtime as runtime  # noqa: F401
from test_structured_logging import captured as captured  # noqa: F401
from test_structured_logging import records
from test_teammate_invitations import workspace

from execbound import weekly_summary
from execbound.app import create_app
from execbound.resolution.models import SystemClock
from execbound.surfaces.limits import RequestLimiter, RequestLimits

PAGE = "/weekly-summary/unsubscribe/"
ONE_CLICK = {"Content-Type": "application/x-www-form-urlencoded"}
BODY = "List-Unsubscribe=One-Click"
BROWSER = {"Accept": "text/html"}


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


def test_hv14_the_request_log_names_no_path_and_the_stop_only_its_ids(
    db,
    admin_engine,
    client,
    captured,  # noqa: F811
):
    """A forged link, a link naming a workspace that does not exist and a malformed one are no
    fault: none writes a `weekly_summary.*` line or anything at ERROR, so nobody holding a link
    can fill the operator's error log. The real stop writes one line, with the tenant and
    message ids alone, and no line carries a path, the secret, its digest or the link."""
    one = subscribed(db, admin_engine)
    forged = f"ebw1.{one['tenant']}.{one['message']}.{secrets.token_urlsafe(32)}"
    before = len(records(captured))
    assert client.get(PAGE + one["link"]).status_code == 200
    assert post(client, forged).status_code == 200
    assert post(client, f"ebw1.{uuid4()}.{one['message']}.{one['secret']}").status_code == 200
    assert post(client, "ebw1.not-a-link").status_code == 200
    assert post(client, one["link"]).status_code == 200
    assert state(admin_engine, one["tenant"], one["admin"]) == (False, "LINK", 1)
    lines = records(captured)[before:]
    completed = [line for line in lines if line["event"] == "request.completed"]
    assert len(completed) == 5 and all("path" not in line for line in completed)
    assert [line for line in lines if line["level"] == "ERROR"] == []
    assert [line for line in lines if line["event"] == "log.suppressed"] == []
    written = json.dumps(lines)
    digest = hashlib.sha256(one["secret"].encode()).hexdigest()
    for value in (one["secret"], "ebw1.", "/weekly-summary/", digest):
        assert value not in written, value
    assert [
        {k: v for k, v in line.items() if k not in ("ts", "level", "request_id")}
        for line in lines
        if line["event"].startswith("weekly_summary.")
    ] == [
        {
            "event": "weekly_summary.unsubscribed",
            "tenant_id": str(one["tenant"]),
            "message_id": str(one["message"]),
        }
    ]


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


def test_hv14_an_error_page_sends_no_referrer(db, admin_engine, runtime, client):
    """A refusal's page is answered at the link's own address, which holds its secret, and it
    loads the stylesheet and links to sign in: it keeps `no-referrer` too, for every 400 the
    request's shape can earn and for the 429 of each limit, as a page and as a plain answer."""
    one = subscribed(db, admin_engine)
    link = PAGE + one["link"]

    def chunked():
        yield BODY.encode()

    refusals = {
        "a query string": lambda h: client.get(link + "?x=1", headers=h),
        "an identity header": lambda h: client.get(link, headers={**h, "X-Tenant-Id": "x"}),
        "an Authorization header": lambda h: client.get(
            link, headers={**h, "Authorization": "Bearer x"}
        ),
        "a Content-Encoding header": lambda h: client.post(
            link, content=BODY, headers={**h, **ONE_CLICK, "Content-Encoding": "gzip"}
        ),
        "a GET with a body": lambda h: client.request("GET", link, content="x", headers=h),
        "a GET with a chunked body": lambda h: client.request(
            "GET", link, content=chunked(), headers=h
        ),
        "a POST that is not a form": lambda h: client.post(
            link, content=BODY, headers={**h, "Content-Type": "application/json"}
        ),
        "a chunked POST": lambda h: client.post(
            link, content=chunked(), headers={**h, **ONE_CLICK}
        ),
        "a POST whose length is not a number": lambda h: client.post(
            link, content=BODY, headers={**h, **ONE_CLICK, "Content-Length": "x"}
        ),
        "a POST too long": lambda h: client.post(
            link, content="x" * 4096, headers={**h, **ONE_CLICK}
        ),
    }
    for what, request in refusals.items():
        for headers in (BROWSER, {}):
            refused = request(headers)
            assert refused.status_code == 400, what
            assert ("text/html" in refused.headers["content-type"]) == bool(headers), what
            assert refused.headers["referrer-policy"] == "no-referrer", what
    # Each limit: the per-message bound, then the per-peer one.
    for limits in (RequestLimits(login_attempts=1), RequestLimits(client_requests=1)):
        runtime.limiter = RequestLimiter(limits, runtime.clock)
        assert client.get(link, headers=BROWSER).status_code == 200
        for headers in (BROWSER, {}):
            limited = client.post(link, content=BODY, headers={**ONE_CLICK, **headers})
            assert limited.status_code == 429 and "retry-after" in limited.headers, limits
            assert ("text/html" in limited.headers["content-type"]) == bool(headers), limits
            assert limited.headers["referrer-policy"] == "no-referrer", limits
    assert state(admin_engine, one["tenant"], one["admin"]) == (True, None, 0)


class Behind:
    """A clock ten minutes behind the database's, which the stop's definer refuses."""

    def now(self) -> datetime:
        return datetime.now(UTC) - timedelta(minutes=10)


@pytest.mark.parametrize("fault", ["the audit append", "the definer"])
def test_hv14_a_stop_the_database_refuses_is_logged_and_answered_alike(
    db,
    admin_engine,
    runtime,
    client,
    captured,  # noqa: F811
    monkeypatch,
    fault,
):
    """A fault while ending the subscription, whether the audit chain refuses the append or the
    definer refuses the call, changes nothing and answers the same page as every other `POST`;
    it is one error line with a fixed code and no ids, so a probe learns nothing from the page,
    nothing of the link reaches the log, and an operator still sees the fault."""
    one = subscribed(db, admin_engine)
    alike = post(client, "ebw1.not-a-link")

    def refused(*args, **kwargs):
        raise SQLAlchemyError("the audit chain cannot be written")

    if fault == "the audit append":
        monkeypatch.setattr(weekly_summary, "append_event", refused)
    else:
        runtime.clock = Behind()
    before = len(records(captured))
    answer = post(client, one["link"])
    assert alike.status_code == 200
    assert (answer.status_code, answer.text) == (alike.status_code, alike.text)
    assert state(admin_engine, one["tenant"], one["admin"]) == (True, None, 0)
    lines = records(captured)[before:]
    assert [line["event"] for line in lines if line["level"] == "ERROR"] == [
        "weekly_summary.refused"
    ]
    rest = [line for line in lines if line["event"] != "request.completed"]
    assert [{k: v for k, v in line.items() if k not in ("ts", "request_id")} for line in rest] == [
        {"event": "weekly_summary.refused", "level": "ERROR", "code": "UNAVAILABLE"}
    ]
    logged = json.dumps(lines)
    for leaked in (one["secret"], one["link"], "cannot be written", "INVALID_CLOCK"):
        assert leaked not in logged, leaked
    error = json.dumps(rest)
    assert str(one["tenant"]) not in error and str(one["message"]) not in error
