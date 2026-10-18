# SPDX-License-Identifier: AGPL-3.0-only
"""The weekly summary's drain and template (#678): HV13.

One summary per subscriber per week, carrying the recipient's own counts and fixed copy only;
an empty week skipped with no SMTP traffic; a deactivated or addressless recipient skipped; an
account in two workspaces summarized in each at its account address; the per-workspace and
deployment caps holding messages for later; failures backing off and ending; and a message
past its week failing without being sent. The relay is the local test double; nothing here
reaches a real host.

The drain's database functions check their instant against the database's own clock, so these
tests run on the real clock, and `STALE_AFTER` is widened where a test needs this week's
Monday to still be deliverable on whatever day the suite runs.
"""

import re
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from smtp_double import PASSWORD as RELAY_PASSWORD
from smtp_double import USERNAME as RELAY_USER
from smtp_double import relay
from sqlalchemy import text
from test_execution import provision_identity, targets
from test_execution import registry as registry  # noqa: F401
from test_execution import world as world  # noqa: F401
from test_migration_without_bypass import fenced
from test_migration_without_bypass import restricted as restricted  # noqa: F401
from test_workspace_accounts import adopt, enroll, second_membership

from execbound import weekly_summary
from execbound.execution import admit
from execbound.resolution.models import SystemClock
from execbound.transports import MailConfig

ORIGIN = "http://127.0.0.1"
SENDER = "summaries@example.com"
WORDS = ("prevent", "attack", "threat", "blocked")
DISCLAIMER = (
    "These are counts of what ExecBound recorded. A refusal is not proof that harm was prevented."
)


@pytest.fixture
def mail(tmp_path):
    directory = tmp_path / "relay"
    directory.mkdir(parents=True, exist_ok=True)
    with relay(directory) as running:
        yield running


@pytest.fixture
def deliverable(monkeypatch):
    """This week's Monday stays deliverable whatever day the suite runs on."""
    monkeypatch.setattr(weekly_summary, "STALE_AFTER", timedelta(days=8))


def config(running, **changes) -> MailConfig:
    base = {"weekly_summary": True, **changes}
    return MailConfig("localhost", running.port, "tls", RELAY_USER, RELAY_PASSWORD, SENDER, **base)


def drain(db, running, *, enqueue=True, **changes):
    return weekly_summary.run(
        db,
        mail=config(running, **changes),
        origin=ORIGIN,
        clock=SystemClock(),
        tls_context=running.context,
        enqueue=enqueue,
    )


def last_week(moment: datetime | None = None) -> datetime:
    """An instant inside the week the next run reports on."""
    since, until = weekly_summary.window(weekly_summary.week_ending(moment or datetime.now(UTC)))
    return until - timedelta(days=2)


def set_email(admin_engine, tenant, principal, email, *, label=None):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.principals SET email=:e, label=coalesce(:l, label) "
                "WHERE tenant_id=:t AND principal_id=:p"
            ),
            {"t": tenant, "p": principal, "e": email, "l": label},
        )


def subscribe(db, tenant, principal):
    with db.transaction(tenant) as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.weekly_summary_subscriptions "
                "(tenant_id, principal_id, subscribed_at) VALUES (:t, :p, now())"
            ),
            {"t": tenant, "p": principal},
        )


def backdate(admin_engine, tenant, moment):
    """Every request of the tenant moved into the week the run reports on."""
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        for table, columns in (
            ("executions", ("created_at", "changed_at")),
            ("approvals", ("created_at",)),
        ):
            conn.execute(
                text(
                    f"UPDATE execbound.{table} SET "  # nosec B608 - this file's literals
                    + ", ".join(f"{column}=:m" for column in columns)
                    + " WHERE tenant_id=:t"
                ),
                {"t": tenant, "m": moment},
            )


def rows(admin_engine, tenant):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT principal_id, state, attempts, last_error, unsubscribe_hash "
                    "FROM execbound.weekly_summary_messages WHERE tenant_id=:t"
                ),
                {"t": tenant},
            ).mappings()
        ]


def held(db, admin_engine, world, count):
    views = []
    for body in targets(admin_engine, world, count=count, production=True):
        views.append(admit(db, world["identity"], body, world["clock"]).view)
    return views


def unscope(admin_engine, world, execution_id):
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.approval_scopes SET active=false WHERE canonical_target_id = "
                "(SELECT canonical_target_id FROM execbound.executions WHERE tenant_id=:t "
                "AND execution_id=:e)"
            ),
            {"t": world["identity"].tenant_id, "e": execution_id},
        )


def body_of(message) -> str:
    return message.get_content()


def requests_line(body: str) -> int:
    found = re.search(r"^Requests made: (\d+) ", body, re.MULTILINE)
    assert found is not None, body
    return int(found.group(1))


def test_hv13_a_subscriber_gets_one_summary_with_their_own_counts(
    db, world, admin_engine, mail, deliverable
):
    tenant = world["identity"].tenant_id
    world["clock"].value = datetime.now(UTC)
    first, second = held(db, admin_engine, world, 2)
    unscope(admin_engine, world, second.execution_id)
    backdate(admin_engine, tenant, last_week())
    set_email(admin_engine, tenant, world["admin"].principal_id, "admin@example.org")
    set_email(admin_engine, tenant, world["human"].principal_id, "approver@example.org")
    subscribe(db, tenant, world["admin"].principal_id)
    subscribe(db, tenant, world["human"].principal_id)
    counts = drain(db, mail)
    assert counts["queued"] == 2 and counts["delivered"] == 2, counts
    received = {message["To"]: body_of(message) for message in mail.messages()}
    assert requests_line(received["admin@example.org"]) == 2
    # The approver's counts are their own scope's.
    assert requests_line(received["approver@example.org"]) == 1
    assert "Monitoring, as reported by sources" in received["admin@example.org"]
    assert "Monitoring" not in received["approver@example.org"]
    again = drain(db, mail)
    assert again["queued"] == 0 and again["delivered"] == 0
    assert len(mail.messages()) == 2
    assert first.execution_id is not None


def test_hv13b_the_summary_carries_counts_and_nothing_else(
    db, world, admin_engine, mail, deliverable
):
    tenant = world["identity"].tenant_id
    world["clock"].value = datetime.now(UTC)
    [view] = held(db, admin_engine, world, 1)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("UPDATE execbound.principals SET label=:l WHERE tenant_id=:t AND principal_id=:p"),
            {"t": tenant, "p": world["identity"].principal_id, "l": "<script>x</script>-agent"},
        )
        conn.execute(
            text(
                "UPDATE execbound.resources SET provider_id='evil.example.' || resource_id "
                "WHERE tenant_id=:t"
            ),
            {"t": tenant},
        )
        conn.execute(
            text("UPDATE execbound.tenants SET name=:n WHERE tenant_id=:t"),
            {"t": tenant, "n": "Acme <b>SOC</b>"},
        )
    backdate(admin_engine, tenant, last_week())
    set_email(
        admin_engine, tenant, world["human"].principal_id, "dana@example.org", label="Dana Person"
    )
    subscribe(db, tenant, world["human"].principal_id)
    assert drain(db, mail)["delivered"] == 1
    [message] = mail.messages()
    subject, body = str(message["Subject"]), body_of(message)
    week = weekly_summary.week_ending(datetime.now(UTC)).isoformat()
    assert subject == f"[ExecBound] Weekly summary for Acme bSOC/b: 7 days to {week}"
    whole = subject + body
    for forbidden in (
        "<script>",
        "script",
        "-agent",
        "evil.example",
        "Dana Person",
        str(view.execution_id),
        str(view.approval_id),
        str(world["human"].principal_id),
        str(world["identity"].principal_id),
    ):
        assert forbidden not in whole, forbidden
    assert message["List-Unsubscribe-Post"] == "List-Unsubscribe=One-Click"
    unsubscribe = message["List-Unsubscribe"]
    assert re.fullmatch(
        r"<http://127\.0\.0\.1/weekly-summary/unsubscribe/ebw1\.[0-9a-f-]{36}\.[0-9a-f-]{36}"
        r"\.[A-Za-z0-9_-]{43}>",
        unsubscribe,
    )
    links = set(re.findall(r"https?://\S+", body))
    assert links == {f"{ORIGIN}/", unsubscribe[1:-1]}
    lowered = whole.replace(DISCLAIMER, "").lower()
    for word in WORDS:
        assert word not in lowered, word
    assert DISCLAIMER in body.replace("\n", " ").replace("harm was ", "harm was ")
    [row] = rows(admin_engine, tenant)
    assert row["state"] == "DELIVERED" and re.fullmatch("[0-9a-f]{64}", row["unsubscribe_hash"])


def test_hv13c_a_week_with_nothing_in_it_is_skipped(db, world, admin_engine, mail, deliverable):
    tenant = world["identity"].tenant_id
    set_email(admin_engine, tenant, world["admin"].principal_id, "admin@example.org")
    subscribe(db, tenant, world["admin"].principal_id)
    counts = drain(db, mail)
    assert counts["skipped"] == 1 and counts["delivered"] == 0
    assert mail.raw == [] and mail.envelopes == []
    [row] = rows(admin_engine, tenant)
    assert (row["state"], row["last_error"]) == ("SKIPPED", "EMPTY_WEEK")


def test_hv13d_a_deactivated_or_addressless_subscriber_gets_nothing(
    db, world, admin_engine, mail, deliverable
):
    tenant = world["identity"].tenant_id
    world["clock"].value = datetime.now(UTC)
    held(db, admin_engine, world, 1)
    backdate(admin_engine, tenant, last_week())
    before = provision_identity(admin_engine, db, tenant, "ADMIN", datetime.now(UTC))
    after = provision_identity(admin_engine, db, tenant, "ADMIN", datetime.now(UTC))
    nobody = world["admin"].principal_id
    for who, email in (
        (before.principal_id, "a@example.org"),
        (after.principal_id, "b@example.org"),
    ):
        set_email(admin_engine, tenant, who, email)
        subscribe(db, tenant, who)
    subscribe(db, tenant, nobody)

    def deactivate(principal):
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text(
                    "UPDATE execbound.principals SET active=false "
                    "WHERE tenant_id=:t AND principal_id=:p"
                ),
                {"t": tenant, "p": principal},
            )

    deactivate(before.principal_id)
    assert weekly_summary._enqueue_all(db, SystemClock()) == 2
    deactivate(after.principal_id)
    counts = drain(db, mail, enqueue=False)
    assert counts["skipped"] == 2 and counts["delivered"] == 0
    found = {
        row["principal_id"]: (row["state"], row["last_error"]) for row in rows(admin_engine, tenant)
    }
    # Deactivated before the enqueue: no message at all.
    assert before.principal_id not in found
    assert found[after.principal_id] == ("SKIPPED", "PRINCIPAL_INACTIVE")
    assert found[nobody] == ("SKIPPED", "NO_ADDRESS")
    assert mail.raw == []


def rejected(admin_engine, tenant, actor, moment):
    """One refusal before a decision, which only a workspace administrator's summary counts."""
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        sequence = conn.execute(
            text(
                "SELECT coalesce(max(sequence), 0) + 1 FROM execbound.audit_events "
                "WHERE tenant_id=:t"
            ),
            {"t": tenant},
        ).scalar_one()
        conn.execute(
            text(
                "INSERT INTO execbound.audit_events (tenant_id, sequence, event_id, actor_id, "
                "kind, occurred_at, payload, previous_hash, event_hash) VALUES (:t, :s, :e, :a, "
                "'execution.rejected', :m, CAST(:payload AS jsonb), "
                "repeat('0', 64), repeat('0', 64))"
            ),
            {
                "t": tenant,
                "s": sequence,
                "e": uuid4(),
                "a": actor,
                "m": moment,
                "payload": '{"operation": "admit", "reason": "INVALID_TARGET"}',
            },
        )


def test_hv13g_one_account_in_two_workspaces_gets_each_workspace_summary_at_its_account_address(
    db, admin_engine, seeded, mail, deliverable
):
    first_tenant, second_tenant = seeded["tenants"]
    principal, _ = enroll(admin_engine, first_tenant, kind="ADMIN")
    account = adopt(db, first_tenant, principal)
    other = second_membership(admin_engine, seeded, account)
    with admin_engine.begin() as conn:
        fenced(conn, second_tenant)
        conn.execute(
            text(
                "UPDATE execbound.principals SET kind='ADMIN' "
                "WHERE tenant_id=:t AND principal_id=:p"
            ),
            {"t": second_tenant, "p": other},
        )
        address = conn.execute(
            text("SELECT email FROM execbound.user_accounts WHERE account_id=:a"), {"a": account}
        ).scalar_one()
        assert (
            conn.execute(
                text(
                    "SELECT email FROM execbound.principals WHERE tenant_id=:t AND principal_id=:p"
                ),
                {"t": second_tenant, "p": other},
            ).scalar_one()
            is None
        )
    for tenant, who in ((first_tenant, principal), (second_tenant, other)):
        rejected(admin_engine, tenant, who, last_week())
        subscribe(db, tenant, who)
    counts = drain(db, mail)
    assert counts["delivered"] == 2, counts
    messages = mail.messages()
    assert {message["To"] for message in messages} == {address}
    names = {str(message["Subject"]).split(" for ", 1)[1].split(":", 1)[0] for message in messages}
    assert len(names) == 2


def test_hv13e_the_caps_hold_messages_for_later(db, world, admin_engine, mail, deliverable):
    tenant = world["identity"].tenant_id
    world["clock"].value = datetime.now(UTC)
    held(db, admin_engine, world, 1)
    backdate(admin_engine, tenant, last_week())
    for who, email in (
        (world["admin"].principal_id, "admin@example.org"),
        (world["human"].principal_id, "approver@example.org"),
    ):
        set_email(admin_engine, tenant, who, email)
        subscribe(db, tenant, who)
    first = drain(db, mail, daily_limit=1)
    assert first["delivered"] == 1 and first["deferred"] == 1, first
    states = sorted(row["state"] for row in rows(admin_engine, tenant))
    assert states == ["DELIVERED", "PENDING"]
    # The deployment's ceiling holds the same message the same way.
    second = drain(db, mail, weekly_summary_daily_cap=1)
    assert second["delivered"] == 0 and second["deferred"] == 1, second
    third = drain(db, mail)
    assert third["delivered"] == 1
    assert len(mail.messages()) == 2


def test_hv13f_failures_back_off_and_end(db, world, admin_engine, tmp_path, deliverable):
    tenant = world["identity"].tenant_id
    world["clock"].value = datetime.now(UTC)
    held(db, admin_engine, world, 1)
    backdate(admin_engine, tenant, last_week())
    set_email(admin_engine, tenant, world["admin"].principal_id, "refused@example.org")
    subscribe(db, tenant, world["admin"].principal_id)
    directory = tmp_path / "refusing"
    directory.mkdir()
    with relay(directory, refuse=("refused@example.org",)) as refusing:
        first = drain(db, refusing)
        assert first["deferred"] == 1, first
        [row] = rows(admin_engine, tenant)
        assert (row["state"], row["attempts"], row["last_error"]) == ("PENDING", 1, "MAIL_REFUSED")
        for attempt in range(2, 6):
            with admin_engine.begin() as conn:
                fenced(conn, tenant)
                conn.execute(
                    text(
                        "UPDATE execbound.weekly_summary_messages SET next_attempt_at=now() "
                        "WHERE tenant_id=:t"
                    ),
                    {"t": tenant},
                )
            drain(db, refusing, enqueue=False)
            [row] = rows(admin_engine, tenant)
            assert row["attempts"] == attempt
        assert row["state"] == "FAILED"
        assert refusing.raw == []


def test_hv13f_a_message_past_its_week_ends_without_being_sent(db, world, admin_engine, mail):
    tenant = world["identity"].tenant_id
    world["clock"].value = datetime.now(UTC)
    set_email(admin_engine, tenant, world["admin"].principal_id, "admin@example.org")
    subscribe(db, tenant, world["admin"].principal_id)
    old = weekly_summary.week_ending(datetime.now(UTC)) - timedelta(days=7)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.weekly_summary_messages (tenant_id, message_id, "
                "principal_id, week_ending, created_at, next_attempt_at) "
                "VALUES (:t, :m, :p, :w, now(), now())"
            ),
            {"t": tenant, "m": uuid4(), "p": world["admin"].principal_id, "w": old},
        )
    counts = drain(db, mail, enqueue=False)
    assert counts["failed"] == 1 and mail.raw == []
    [row] = rows(admin_engine, tenant)
    assert (row["state"], row["last_error"]) == ("FAILED", "WEEK_PASSED")


def test_hv13h_the_drain_delivers_under_an_owner_without_bypass(restricted, mail, deliverable):  # noqa: F811
    """A managed host's posture end to end: two workspaces, one subscriber each, one run delivers
    both, with the owner not bypassing row security."""
    import os

    from alembic import command
    from test_teammate_invitations import workspace

    from execbound.connection import with_database_name
    from execbound.db import Database

    engine, alembic, _ = restricted
    command.upgrade(alembic, "head")
    db = Database(
        with_database_name(os.environ["TEST_DATABASE_URL"], engine.url.database), pool_size=1
    )
    try:
        moment = last_week()
        for name in ("First", "Second"):
            where = workspace(engine, name=name)
            set_email(engine, where["tenant_id"], where["admin"], f"{name.lower()}@example.org")
            rejected(engine, where["tenant_id"], where["admin"], moment)
            subscribe(db, where["tenant_id"], where["admin"])
        counts = drain(db, mail)
        assert counts["queued"] == 2 and counts["delivered"] == 2, counts
        assert {message["To"] for message in mail.messages()} == {
            "first@example.org",
            "second@example.org",
        }
    finally:
        db.engine.dispose()


def test_hv13_the_drain_refuses_a_deployment_without_the_summary(db, mail):
    with pytest.raises(weekly_summary.SummaryError) as refused:
        drain(db, mail, weekly_summary=False)
    assert refused.value.code == "INVALID_CONFIGURATION"


def test_hv13_the_link_is_parsed_strictly():
    tenant, message = uuid4(), uuid4()
    secret = "A" * 43
    link = f"ebw1.{tenant}.{message}.{secret}"
    assert weekly_summary.parse_link(link) == (tenant, message, secret)
    for bad in (
        link + "x",
        link.upper(),
        f"ebw1.{tenant}.{message}",
        f"ebt1.{tenant}.{message}.{secret}",
        "",
        f"ebw1.{str(tenant).upper()}.{message}.{secret}",
    ):
        assert weekly_summary.parse_link(bad) is None, bad
    assert isinstance(tenant, UUID)
