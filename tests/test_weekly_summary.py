# SPDX-License-Identifier: AGPL-3.0-only
"""The weekly summary's drain and template (#678): HV13.

One summary per subscriber per week, carrying the recipient's own counts and fixed copy only;
an empty week skipped with no SMTP traffic; a deactivated or addressless recipient skipped; an
account in two workspaces summarized in each at its account address; the per-workspace and
deployment caps holding messages for later; failures backing off and ending; a message past
its week failing without being sent; and the one-click header on one unfolded line, as the relay
receives it, while every other header still folds. The relay is the local test double; nothing
here reaches a real host.

The drain's database functions check their instant against the database's own clock, so these
tests run on the real clock, and `STALE_AFTER` is widened where a test needs this week's
Monday to still be deliverable on whatever day the suite runs.
"""

import io
import re
from datetime import UTC, date, datetime, timedelta
from email import message_from_bytes, policy
from email.errors import HeaderWriteError
from email.generator import BytesGenerator
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
from test_notification_transports import NON_LATIN_WORKSPACE, chosen_by_tenant, chosen_like
from test_workspace_accounts import adopt, enroll, second_membership

from execbound import weekly_summary
from execbound.execution import admit
from execbound.resolution.models import SystemClock
from execbound.transports import (
    MailConfig,
    WeeklyCounts,
    choose_workspace,
    render_weekly_summary,
)

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
    # What the relay took holds the bracketed link itself on one line, not encoded words.
    [raw] = mail.raw
    assert f"\r\nList-Unsubscribe: {unsubscribe}\r\n".encode() in raw
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


def test_hv13i_the_drain_names_the_summarys_own_workspace_by_its_tenant_id(
    db, world, admin_engine, mail, deliverable
):
    """`Acme & Co` reads `Acme Co`, which is not the name as written, so the summary says which
    workspace to choose by its tenant id: the drain must hand the template the id of the
    workspace the summary is about."""
    tenant = world["identity"].tenant_id
    world["clock"].value = datetime.now(UTC)
    held(db, admin_engine, world, 1)
    backdate(admin_engine, tenant, last_week())
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("UPDATE execbound.tenants SET name = 'Acme & Co' WHERE tenant_id = :t"),
            {"t": tenant},
        )
    set_email(admin_engine, tenant, world["admin"].principal_id, "admin@example.org")
    subscribe(db, tenant, world["admin"].principal_id)
    counts = drain(db, mail)
    assert counts["delivered"] == 1, counts
    [message] = mail.messages()
    lines = body_of(message).splitlines()
    assert choose_workspace("Acme & Co", tenant) == chosen_like("Acme Co", tenant)
    assert chosen_like("Acme Co", tenant) in lines


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


# --- HV13i: the template's workspace name, rendered with no database -------------------------

TENANT = UUID("3f2504e0-4f89-11d3-9a0c-0305e82c3303")
COUNTS = WeeklyCounts(
    requests=4,
    executed=2,
    refused_policy=1,
    refused_limit=0,
    refused_busy=0,
    held=1,
    approved=1,
    refused_by_person=0,
    lapsed=0,
    waiting=0,
    median_seconds_to_decide=90,
    unsettled_now=0,
    effect_unknown=0,
    observed=0,
    would_refuse=0,
    would_refuse_by_limit=0,
    would_hold=0,
    would_run=0,
    quiet_sources=None,
    open_findings=None,
)
STOP = (
    f"{ORIGIN}/weekly-summary/unsubscribe/ebw1.{TENANT}.00000000-0000-4000-8000-0000000000aa."
    "zYx-Wvu_TsrqPon987654321zYx-Wvu_TsrqPon9876"
)


def summary(workspace: str, tenant_id: object = TENANT):
    return render_weekly_summary(
        MailConfig("localhost", 2525, "tls", RELAY_USER, RELAY_PASSWORD, SENDER),
        "jane@example.com",
        workspace,
        COUNTS,
        COUNTS,
        date(2026, 10, 12),
        ORIGIN,
        STOP,
        tenant_id=tenant_id,  # type: ignore[arg-type]
    )


def test_hv13i_a_name_shown_as_written_is_chosen_by_name_and_no_tenant_id():
    email = summary("Synthetic SOC")
    body = email.get_content()
    assert email["Subject"] == "[ExecBound] Weekly summary for Synthetic SOC: 7 days to 2026-10-12"
    assert body.splitlines()[0] == (
        "ExecBound in Synthetic SOC, the 7 days to Monday 2026-10-12 00:00 UTC."
    )
    assert "If you belong to more than one workspace, choose Synthetic SOC." in body.splitlines()
    # The tenant id appears once, in the unsubscribe link it always carried.
    assert body.count(str(TENANT)) == 1


def test_hv13i_a_name_nothing_of_which_survives_is_left_out_and_chosen_by_tenant_id():
    """A name in a script `safe_label` drops would read "unknown", and "choose unknown" helps
    nobody: the summary says "your workspace" and names the tenant id Workspace settings
    shows."""
    email = summary(NON_LATIN_WORKSPACE)
    body = email.get_content()
    # "Effect unknown" is one of the summary's own counts.
    assert "unknown" not in str(email["Subject"]) + body.replace("Effect unknown: 0", "")
    assert email["Subject"] == "[ExecBound] Weekly summary for your workspace: 7 days to 2026-10-12"
    lines = body.splitlines()
    assert lines[0] == "ExecBound in your workspace, the 7 days to Monday 2026-10-12 00:00 UTC."
    assert chosen_by_tenant(TENANT) in lines
    assert body.isascii()


def test_hv13i_the_template_refuses_a_tenant_id_that_is_not_one():
    with pytest.raises(ValueError, match="INVALID_WEEKLY_SUMMARY"):
        summary("Synthetic SOC", tenant_id=str(TENANT))


# --- HV13j: the one-click header as the relay receives it -------------------------------------

# Any RFC 2047 encoded word: `=?charset?encoding?text?=`.
ENCODED_WORD = re.compile(rb"=\?[^?\s]+\?[BbQq]\?[^?\s]*\?=")
# The longest host the template takes, so the longest one-click link it can carry.
LONGEST_HOST = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))
LONGEST_STOP = STOP.replace(ORIGIN, f"https://{LONGEST_HOST}")


def on_the_wire(email) -> bytes:
    """The bytes `smtplib.SMTP.send_message` hands the relay: the message's own policy, CRLF."""
    buffer = io.BytesIO()
    BytesGenerator(buffer).flatten(email, linesep="\r\n")
    return buffer.getvalue()


def longest(workspace: str):
    return render_weekly_summary(
        MailConfig("localhost", 2525, "tls", RELAY_USER, RELAY_PASSWORD, SENDER),
        "jane@example.com",
        workspace,
        COUNTS,
        COUNTS,
        date(2026, 10, 12),
        f"https://{LONGEST_HOST}",
        LONGEST_STOP,
        tenant_id=TENANT,
    )


@pytest.mark.parametrize(
    "workspace",
    [
        # Folds at its spaces; and a name with none, which folds only as encoded words.
        "Northern Region: Security Operations Centre. Tier 2 Incident Response Team",
        "N" * 80,
    ],
)
def test_hv13j_the_one_click_header_goes_out_on_one_line_and_the_subject_still_folds(workspace):
    """Folded at 78 columns, the one-click link, which has no space to fold at, would go out as
    RFC 2047 encoded words, which a mail client reading `List-Unsubscribe` does not take for an
    address. It goes out on one line as the bracketed link itself, for the longest link the
    template takes; every other header still folds, so the subject's lines stay within 78
    columns and any encoded word in it within RFC 2047's 75 characters."""
    email = longest(workspace)
    expected = f"List-Unsubscribe: <{LONGEST_STOP}>".encode()
    # The bytes path (`fold_binary`, which `smtplib` takes) and the string path (`fold`).
    for wire, end in (
        (on_the_wire(email), b"\r\n"),
        (email.as_bytes(), b"\n"),
        (email.as_string().encode(), b"\n"),
    ):
        lines = wire.split(end + end, 1)[0].split(end)
        [at] = [i for i, line in enumerate(lines) if line.startswith(b"List-Unsubscribe:")]
        assert lines[at] == expected and b"=?" not in lines[at]
        # The next line starts a header of its own: nothing of the link was folded onto it.
        assert not lines[at + 1].startswith((b" ", b"\t")), lines[at + 1]
        # RFC 5322's limit on any line, which the longest link stays well within.
        assert len(lines[at]) <= 998
        for i, line in enumerate(lines):
            assert i == at or len(line) <= 78, line
        words = ENCODED_WORD.findall(end.join(lines))
        assert all(len(word) <= 75 for word in words), max(words, key=len)
        [subject] = [i for i, line in enumerate(lines) if line.startswith(b"Subject: ")]
        assert lines[subject + 1].startswith((b" ", b"\t")), "the subject did not fold"
    received = message_from_bytes(on_the_wire(email), policy=policy.default)
    assert str(received["Subject"]) == (
        f"[ExecBound] Weekly summary for {workspace}: 7 days to 2026-10-12"
    )
    assert str(received["List-Unsubscribe"]) == f"<{LONGEST_STOP}>"


def test_hv13j_the_one_click_header_still_refuses_a_line_break_on_the_way_out():
    """The one-click header is written as it is, unfolded, so nothing refolds a line break out
    of it: the generator's own check, `verify_generated_headers`, refuses one instead of
    letting it start a header of its own."""
    email = summary("Synthetic SOC")
    assert email.policy.verify_generated_headers
    del email["List-Unsubscribe"]
    email.set_raw("List-Unsubscribe", f"<{STOP}>\r\nBcc: someone@example.org")
    with pytest.raises(HeaderWriteError):
        on_the_wire(email)
    with pytest.raises(HeaderWriteError):
        email.as_bytes()
    with pytest.raises(HeaderWriteError):
        email.as_string()
