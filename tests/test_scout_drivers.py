# SPDX-License-Identifier: AGPL-3.0-only
"""Driver evidence (#355): SR25 to SR27.

Real PostgreSQL, the fake Graph and the fake Tines. Who drives a directory's non-human actor is
evidence of its own, never mixed with what the actor can reach: `declared` when the directory
names the driver (the AI publisher catalog's entry for its application, or an agent identity's
blueprint), `network` when its successful sign-ins come from a range the reviewed egress catalog
attributes to a platform or from the Space's recorded Tines egress, and `joined` when that Tines
evidence meets the Tines tenant's credentials allowed to call Microsoft Graph or Microsoft
sign-in, naming every story that uses them and never one alone. An actor with none is
unattributed. No address, name or full user agent is kept, and losing the beta sign-in read never
changes a run.
"""

import ipaddress
import json
import os
import re
import sys
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from console_api_fixtures import every_log_line
from secret_shapes import STRIPE
from space_fixtures import default_space, make_space, seat
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from test_context_provisioning import statements
from test_monitor_collect_due import key_file
from test_monitoring_store import FixedClock
from test_scout_audit import parsed, scheduled
from test_scout_delta import admins as admins
from test_scout_delta import agent_row, connection_row, delta, full, principal
from test_scout_run import AGENT_ONE, BLUEPRINT_APP, connect, detailed_scenario
from test_tines_collection import KEY as TINES_KEY

from execbound.monitoring import collection, commands, drivers, egress, graph, store
from execbound.monitoring.models import MonitorError
from execbound.spaces import set_current_space
from execbound_harness import fake_tines
from execbound_harness.fake_graph import serving

pytestmark = pytest.mark.integration

ANTHROPIC_SERVER = "07c030f6-5743-41b7-ba00-0a6e85f37c17"
ANTHROPIC_ADDRESS = "160.79.104.20"
MAKE_ADDRESS = "54.75.157.176"
WORKATO_ADDRESS = "52.5.142.59"
# One of the addresses n8n publishes and says it changes without notice: never evidence.
N8N_ADDRESS = "4.182.88.118"
# A synthetic tenant's egress: a public address no catalog entry holds.
TINES_ADDRESS = "18.200.10.20"
OTHER_TINES_ADDRESS = "18.200.10.21"
NOBODY_ADDRESS = "20.30.40.50"
PRIVATE_ADDRESS = "10.1.2.3"
APP_ID = "abababab-0000-4000-8000-000000000077"
USER_AGENT = "python-requests/2.31.0 (CPython 3.12; build-host-17 198.51.100.9)"
# Nothing in this list may survive into a table, a run result, an answer or a log line.
FORBIDDEN = (
    ANTHROPIC_ADDRESS,
    MAKE_ADDRESS,
    WORKATO_ADDRESS,
    TINES_ADDRESS,
    NOBODY_ADDRESS,
    PRIVATE_ADDRESS,
    "198.51.100.9",
    "build-host-17",
    "CPython 3.12",
    "person@synthetic.invalid",
    "A Person",
    "automation@synthetic.invalid",
    "A Synthetic Automation",
    "Synthetic City",
    "A reason nobody should keep",
    APP_ID,
    "SYNTHETIC-METADATA-MUST-NOT-BE-RETAINED",
)
# What a Tines credential's allowed hosts name, which is classified and never kept. Graph's own
# origin is a directory connection's address, so it is the sign-in host that is looked for.
HOSTS = ("login.microsoftonline.com", "api.example.invalid", "x.invalid")


@pytest.fixture
def clock():
    return FixedClock(datetime.now(UTC))


def moment(value):
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def sign_in(when, *, actor, address=ANTHROPIC_ADDRESS, user_agent=USER_AGENT, error=0):
    """A service principal sign-in as beta Graph writes one, carrying every field Scout must
    drop beside the four it reads."""
    return {
        "id": str(uuid4()),
        # Graph writes a sign-in's moment to the second.
        "createdDateTime": moment(when.replace(microsecond=0)),
        "servicePrincipalId": actor,
        "servicePrincipalName": "automation@synthetic.invalid",
        "appId": APP_ID,
        "appDisplayName": "A Synthetic Automation",
        "userPrincipalName": "person@synthetic.invalid",
        "userDisplayName": "A Person",
        "ipAddress": address,
        "userAgent": user_agent,
        "location": {"city": "Synthetic City", "countryOrRegion": "ZZ"},
        "status": {"errorCode": error, "failureReason": "A reason nobody should keep"},
        "signInEventTypes": ["servicePrincipal"],
        "resourceDisplayName": "Microsoft Graph",
    }


def ref(index):
    return principal(index)["id"]


def directory(*sign_ins, principals=None, **changes):
    """Classic service principals 9 to 14 and the sign-in log `sign_ins`."""
    values = {
        "principals": principals
        if principals is not None
        else [principal(index) for index in range(9, 15)],
        "sign_ins": list(sign_ins),
    }
    values.update(changes)
    return detailed_scenario(**values)


def drivers_of(db, tenant):
    with db.transaction(tenant) as conn:
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT a.platform_ref AS actor, d.evidence, d.platform_ref, d.detail_refs, "
                    "d.detail_capped, d.catalog_version, d.first_seen_at, d.last_seen_at, "
                    "d.gone_at, d.source_connection_id "
                    "FROM execbound.monitor_actor_drivers d "
                    "JOIN execbound.monitor_agents a "
                    "  ON a.tenant_id = d.tenant_id AND a.agent_id = d.agent_id "
                    "ORDER BY a.platform_ref, d.evidence, d.platform_ref"
                )
            ).mappings()
        ]


def live(rows):
    return {
        (row["actor"], row["evidence"], row["platform_ref"]) for row in rows if not row["gone_at"]
    }


def everything(db, tenant):
    """Every row Scout and Monitor keep for this tenant, as text."""
    tables = (
        "monitor_actor_drivers",
        "monitor_agents",
        "monitor_connections",
        "monitor_inventory",
        "monitor_observations",
        "monitor_findings",
    )
    with db.transaction(tenant) as conn:
        return json.dumps(
            {
                table: [
                    {key: str(value) for key, value in row.items()}
                    for row in conn.execute(text(f"SELECT * FROM execbound.{table}")).mappings()
                ]
                for table in tables
            }
        )


def sign_in_reads(server):
    return [query for path, query, _ in server.requests if path == graph.SIGN_INS_PATH]


def tines_connection(db, admin, clock, **overrides):
    values = {
        "label": "Synthetic Tines tenant",
        "base_url": fake_tines.BASE_URL,
        "key_fingerprint": collection.fingerprint(TINES_KEY),
    }
    values.update(overrides)
    return store.create_connection(db, admin, clock=clock, **values)


def credential(identifier, hosts, stories, *, actions=2, team=7):
    """A Tines credential as `user_credentials` lists one with `include_references=true`,
    carrying the fields Scout must never read; its team's stories reference it."""
    return {
        "id": identifier,
        "name": f"credential_{identifier}",
        "mode": "OAUTH",
        "team_id": team,
        "allowed_hosts": list(hosts),
        "restriction_type": "RESTRICTED" if hosts else "UNRESTRICTED",
        "metadata": {"note": "SYNTHETIC-METADATA-MUST-NOT-BE-RETAINED"},
        "owner": {"email": "person@synthetic.invalid", "first_name": "A", "last_name": "Person"},
        "expires_at": None,
        "references": [
            {
                "story_id": story,
                "team_id": team,
                "action_ids": [story * 1000 + n for n in range(actions)],
            }
            for story in stories
        ],
    }


# The Tines tenant's credentials: two allowed to call Microsoft Graph or Microsoft sign-in, one
# with no host restriction and one for other hosts only.
CREDENTIALS = [
    credential(301, ["graph.microsoft.com"], [4001, 4002]),
    credential(302, ["https://login.microsoftonline.com/", "api.example.invalid"], [4003]),
    credential(303, [], [4004]),
    credential(304, ["api.example.invalid"], [4005]),
]


def tines_inventory(db, admin, clock, connection_id, credentials=CREDENTIALS, **changes):
    scenario = fake_tines.Scenario(credentials=list(credentials), **changes)
    with (
        fake_tines.serving(scenario) as server,
        httpx.Client(
            transport=fake_tines.transport(server), trust_env=False, follow_redirects=False
        ) as http,
    ):
        result = collection.run(
            db,
            admin,
            connection_id=connection_id,
            api_key=TINES_KEY,
            client=http,
            inventory=True,
            audit_pages=0,
            clock=clock,
        )
        return result, server


def detail(db, admin, clock, platform_ref):
    from execbound.surfaces import sessions

    grant = sessions.issue_session(db, admin, clock=clock)
    session = sessions.load_session(db, grant.token, clock=clock)
    agent_id = agent_row(db, admin.tenant_id, platform_ref)["agent_id"]
    return store.agent_detail(db, session, agent_id, clock=clock)


# SR25: declared


def test_sr25_a_catalogued_publisher_and_a_blueprint_are_declared_and_the_rest_unattributed(
    db, admins, clock
):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    consented = principal(10, appId=ANTHROPIC_SERVER)
    with serving(directory(principals=[principal(9), consented])) as server:
        result = full(db, admin, clock, connection_id, server)
    assert result["outcome"] == "COMPLETE"
    assert result["drivers"] == {"declared": 2, "gone": 0}
    rows = drivers_of(db, admin.tenant_id)
    assert live(rows) == {
        (AGENT_ONE, "declared", f"blueprint:{BLUEPRINT_APP}"),
        (ref(10), "declared", "publisher:anthropic"),
    }
    publisher = next(row for row in rows if row["platform_ref"] == "publisher:anthropic")
    assert publisher["catalog_version"] == "ai-publishers.2026-10-13"
    assert publisher["detail_refs"] == [] and publisher["source_connection_id"] == connection_id
    # Principal 9 has no row: it is unattributed, which is the absence of evidence.
    assert not [row for row in rows if row["actor"] == ref(9)]


def test_sr25_a_declared_driver_goes_when_its_condition_ends_and_returns_when_it_holds(
    db, admins, clock
):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    consented = principal(10, appId=ANTHROPIC_SERVER)
    with serving(directory(principals=[consented])) as server:
        full(db, admin, clock, connection_id, server)
        server.scenario.principals = []
        server.scenario.agents = []
        clock.value += timedelta(hours=7)
        assert full(db, admin, clock, connection_id, server)["drivers"]["gone"] == 2
        assert live(drivers_of(db, admin.tenant_id)) == set()
        server.scenario.principals = [consented]
        clock.value += timedelta(hours=7)
        full(db, admin, clock, connection_id, server)
    rows = drivers_of(db, admin.tenant_id)
    assert (ref(10), "declared", "publisher:anthropic") in live(rows)
    # The blueprint's agent stayed gone, and its row with it; nothing was deleted.
    assert [row["gone_at"] is not None for row in rows if row["actor"] == AGENT_ONE] == [True]


def test_sr25_a_delta_pass_declares_a_new_consent_without_waiting_for_a_full_collection(
    db, admins, clock
):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(directory(principals=[principal(9)])) as server:
        full(db, admin, clock, connection_id, server)
        server.scenario.delta = [principal(10, appId=ANTHROPIC_SERVER)]
        clock.value += timedelta(minutes=5)
        result = delta(db, admin, clock, connection_id, server)
    assert result["outcome"] == "COMPLETE" and result["drivers"]["declared"] == 2
    assert (ref(10), "declared", "publisher:anthropic") in live(drivers_of(db, admin.tenant_id))


# SR26: network evidence from sign-ins


def test_sr26_a_sign_in_from_each_published_range_names_its_platform_and_nothing_else_does(
    db, admins, clock, tmp_path, monkeypatch, capsys
):
    """As the jobs service reads the sign-ins and as an operator's run reads them again: one
    network row for each published range, none for the rest, and no address, name or user agent
    remainder in any row, result, printed line or log line any logger writes (`every_log_line`,
    since ExecBound's own logger does not propagate to `caplog` and keeps its fields off the
    message)."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    files = tmp_path / "key-files"
    key_file(files, connection_id, entra=True)
    now = clock.now()
    # Inside the read's overlap, so the operator's run after the scheduled one reads them again.
    sign_ins = [
        sign_in(now - timedelta(minutes=25), actor=ref(9), address=ANTHROPIC_ADDRESS),
        sign_in(now - timedelta(minutes=10), actor=ref(9), address=ANTHROPIC_ADDRESS),
        sign_in(now - timedelta(minutes=20), actor=ref(10), address=MAKE_ADDRESS),
        sign_in(now - timedelta(minutes=20), actor=ref(11), address=WORKATO_ADDRESS),
        sign_in(now - timedelta(minutes=20), actor=ref(12), address=NOBODY_ADDRESS),
        sign_in(now - timedelta(minutes=20), actor=ref(13), address=PRIVATE_ADDRESS),
        # A refused sign-in from a catalogued range establishes nothing.
        sign_in(
            now - timedelta(minutes=20), actor=ref(14), address=ANTHROPIC_ADDRESS, error=7000215
        ),
        # n8n publishes addresses it says change without notice: not evidence.
        sign_in(now - timedelta(minutes=20), actor=ref(14), address=N8N_ADDRESS),
    ]
    with every_log_line() as logged, serving(directory(*sign_ins)) as server:
        printed = scheduled(
            monkeypatch, capsys, server, "collect-due", "--all-tenants", "--key-files", str(files)
        )
        (report,) = [value for value in map(parsed, printed.splitlines()) if "tenants" in value]
        assert report["tenants"][str(admin.tenant_id)]["collected"] == 1
        # The scheduled run read the host's clock; the operator's run after it.
        clock.value = datetime.now(UTC)
        result = full(db, admin, clock, connection_id, server)
    assert result["outcome"] == "COMPLETE"
    assert result["capabilities"]["sign_ins"] == "available"
    counts = result["sign_ins"]
    assert counts["state"] == "complete"
    assert (counts["read"], counts["matched"], counts["unmatched"], counts["failed"]) == (
        8,
        4,
        3,
        1,
    )
    assert counts["network"] == 3
    network = {row for row in live(drivers_of(db, admin.tenant_id)) if row[1] == "network"}
    assert network == {
        (ref(9), "network", "egress:anthropic"),
        (ref(10), "network", "egress:make"),
        (ref(11), "network", "egress:workato"),
    }
    anthropic = next(
        row for row in drivers_of(db, admin.tenant_id) if row["platform_ref"] == "egress:anthropic"
    )
    # Its first and last sign-ins, to the second as Graph wrote them.
    assert anthropic["first_seen_at"] == (now - timedelta(minutes=25)).replace(microsecond=0)
    assert anthropic["last_seen_at"] == (now - timedelta(minutes=10)).replace(microsecond=0)
    assert anthropic["catalog_version"] == egress.VERSION
    # Both halves were captured, so an empty sweep is not a vacuous one; the pass's line counts
    # its sign-in reads.
    assert logged.holds("monitor.collect_due", "sign_ins_failed", "sign_ins_sampled")
    kept = everything(db, admin.tenant_id) + json.dumps(result, default=str) + printed + logged()
    for value in FORBIDDEN:
        assert value not in kept, value


def test_sr26_a_user_agent_alone_never_yields_evidence_and_is_kept_only_as_its_token(
    db, admins, clock
):
    """A client names whatever platform it likes in its user agent, so only the address a
    sign-in came from decides a network row: a user agent naming Tines or a catalogued platform
    from an address nothing matches gives none, and one naming the other platform from a
    recorded or catalogued address gives the address's platform alone."""
    admin = admins[0]
    tines = tines_connection(db, admin, clock)
    record(db, admin, clock, tines, [TINES_ADDRESS])
    connection_id = connect(db, admin, clock)
    now = clock.now()
    hour = now - timedelta(hours=1)
    sign_ins = [
        sign_in(now - timedelta(hours=2), actor=ref(9), address=NOBODY_ADDRESS, user_agent="Tines"),
        sign_in(
            hour,
            actor=ref(9),
            address=NOBODY_ADDRESS,
            user_agent="Tines/1.0 (+https://www.tines.com)",
        ),
        sign_in(hour, actor=ref(10), address=NOBODY_ADDRESS, user_agent="Anthropic/1.0"),
        # The address decides, whatever the user agent names.
        sign_in(hour, actor=ref(11), address=TINES_ADDRESS, user_agent="Anthropic/1.0"),
        sign_in(hour, actor=ref(12), address=ANTHROPIC_ADDRESS, user_agent="Tines/1.0"),
        sign_in(hour, actor=ref(13), address=NOBODY_ADDRESS),
        # A token shaped like an address, a mailbox or a secret is no hint at all.
        sign_in(hour, actor=ref(14), address=NOBODY_ADDRESS, user_agent="10.0.0.1/a"),
        sign_in(
            hour, actor=ref(15), address=NOBODY_ADDRESS, user_agent="person@synthetic.invalid/1"
        ),
        sign_in(hour, actor=ref(16), address=NOBODY_ADDRESS, user_agent=STRIPE + "/1"),
    ]
    principals = [principal(index) for index in range(9, 17)]
    with serving(directory(*sign_ins, principals=principals)) as server:
        result = full(db, admin, clock, connection_id, server)
    assert result["sign_ins"]["matched"] == 2
    assert {row for row in live(drivers_of(db, admin.tenant_id)) if row[1] == "network"} == {
        (ref(11), "network", f"tines:{tines}"),
        (ref(12), "network", "egress:anthropic"),
    }
    hints = {
        index: agent_row(db, admin.tenant_id, ref(index))["user_agent_hint"]
        for index in range(9, 17)
    }
    assert hints == {
        9: "Tines/1.0",
        10: "Anthropic/1.0",
        11: "Anthropic/1.0",
        12: "Tines/1.0",
        13: "python-requests/2.31.0",
        14: None,
        15: None,
        16: None,
    }
    assert agent_row(db, admin.tenant_id, ref(9))["user_agent_seen_at"] == hour.replace(
        microsecond=0
    )


@pytest.mark.parametrize(
    ("value", "kept"),
    [
        ("python-requests/2.31.0 (CPython; host)", "python-requests/2.31.0"),
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0"),
        ("axios/1.6.8", "axios/1.6.8"),
        ("Tines", "Tines"),
        ("Tines;foo", "Tines"),
        ("python-requests/2.31.0/extra", None),
        ("python-requests@2.31", None),
        ("2001:db8::1", None),
        ("", None),
        ("   ", None),
        (None, None),
        (17, None),
        ("x" * 600, None),
    ],
)
def test_sr26_a_user_agent_hint_is_only_a_leading_product_token(value, kept):
    assert graph.user_agent_hint(value) == kept


def test_sr26_a_platform_with_no_published_stable_egress_stays_unattributed():
    catalog = egress.PRODUCTION
    assert {platform.key for platform in catalog.unattributable} == {"zapier", "n8n-cloud"}
    assert all(not platform.networks for platform in catalog.unattributable)
    # Pending entries match nothing until their feed is read.
    assert {platform.key for platform in catalog.platforms if platform.pending} == {
        "openai",
        "azure-connectors",
    }
    assert catalog.match(N8N_ADDRESS) is None
    assert catalog.match(NOBODY_ADDRESS) is None
    assert catalog.match(PRIVATE_ADDRESS) is None
    assert catalog.match("not an address") is None
    assert catalog.match(ANTHROPIC_ADDRESS).key == "anthropic"
    assert catalog.match(f"::ffff:{ANTHROPIC_ADDRESS}") is None


def test_sr26_the_read_asks_for_service_principal_sign_ins_from_its_cursor(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    first_moment = clock.now()
    with serving(directory()) as server:
        full(db, admin, clock, connection_id, server)
        probe, read = sign_in_reads(server)
        assert probe["$top"] == "1"
        assert probe["$filter"] == graph.SIGN_IN_FILTER.format(
            start=moment((first_moment - timedelta(days=1)).replace(microsecond=0))
        )
        assert read == {
            "$filter": graph.SIGN_IN_FILTER.format(
                start=moment((first_moment - timedelta(days=30)).replace(microsecond=0))
            ),
            "$select": "id,createdDateTime,servicePrincipalId,ipAddress,userAgent,status",
            "$top": "500",
        }
        cursor = connection_row(db, admin.tenant_id, connection_id)["sign_in_cursor"]
        assert cursor == (first_moment - timedelta(minutes=30)).replace(microsecond=0)
        # A delta pass reads on from the cursor, and moves it on.
        clock.value += timedelta(minutes=5)
        delta(db, admin, clock, connection_id, server)
        assert sign_in_reads(server)[-1]["$filter"].startswith(
            f"createdDateTime ge {moment(cursor)}"
        )
        moved = connection_row(db, admin.tenant_id, connection_id)["sign_in_cursor"]
        assert moved == (clock.now() - timedelta(minutes=30)).replace(microsecond=0)
        # A host clock set back never moves it back.
        clock.value -= timedelta(minutes=3)
        delta(db, admin, clock, connection_id, server)
        assert connection_row(db, admin.tenant_id, connection_id)["sign_in_cursor"] == moved


def test_sr26_a_read_refused_part_way_keeps_what_it_matched_and_leaves_the_cursor(
    db, admins, clock
):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    now = clock.now()
    sign_ins = [
        sign_in(now - timedelta(minutes=10), actor=ref(9), address=ANTHROPIC_ADDRESS),
        sign_in(now - timedelta(hours=5), actor=ref(10), address=MAKE_ADDRESS),
    ]
    with serving(directory(*sign_ins, sign_in_max_top=1, sign_in_page_status=429)) as server:
        result = full(db, admin, clock, connection_id, server)
    assert result["outcome"] == "COMPLETE"
    assert result["sign_ins"]["state"] == "failed"
    assert result["sign_ins"]["error_code"] == "RATE_LIMITED"
    assert {row[2] for row in live(drivers_of(db, admin.tenant_id)) if row[1] == "network"} == {
        "egress:anthropic"
    }
    assert connection_row(db, admin.tenant_id, connection_id)["sign_in_cursor"] is None
    assert connection_row(db, admin.tenant_id, connection_id)["last_error_code"] is None


@pytest.mark.parametrize(
    "link",
    [
        "https://graph.example.invalid/beta/auditLogs/signIns?$skiptoken=1",
        "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=1",
        "https://graph.microsoft.com/beta/users?$skiptoken=1",
        "http://graph.microsoft.com/beta/auditLogs/signIns?$skiptoken=1",
        "https://graph.microsoft.com:8443/beta/auditLogs/signIns?$skiptoken=1",
        "https://graph.microsoft.com:99999/beta/auditLogs/signIns?$skiptoken=1",
    ],
)
def test_sr26_a_next_link_off_the_pinned_read_is_refused(db, admins, clock, link):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    now = clock.now()
    sign_ins = [
        sign_in(now - timedelta(minutes=10), actor=ref(9)),
        sign_in(now - timedelta(minutes=20), actor=ref(10), address=MAKE_ADDRESS),
    ]
    with serving(directory(*sign_ins, sign_in_max_top=1, sign_in_next_link=link)) as server:
        result = full(db, admin, clock, connection_id, server)
        # The probe and one page, and nothing sent where the link pointed.
        assert len(sign_in_reads(server)) == 2
    assert result["sign_ins"]["state"] == "failed"
    assert result["sign_ins"]["error_code"] == "MALFORMED"
    assert result["outcome"] == "COMPLETE"


def test_sr26_a_next_link_in_graph_s_own_casing_is_followed(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    now = clock.now()
    sign_ins = [
        sign_in(now - timedelta(minutes=10), actor=ref(9)),
        sign_in(now - timedelta(minutes=20), actor=ref(10), address=MAKE_ADDRESS),
    ]
    with serving(directory(*sign_ins, sign_in_max_top=1)) as server:
        result = full(db, admin, clock, connection_id, server)
        paths = [path for path, _, _ in server.requests if path.lower().endswith("signins")]
    assert result["sign_ins"]["state"] == "complete" and result["sign_ins"]["pages"] == 2
    assert set(paths) == {graph.SIGN_INS_PATH}


def test_sr26_the_read_is_bounded_and_takes_the_newest(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    now = clock.now()
    sign_ins = [
        sign_in(now - timedelta(minutes=minutes), actor=ref(9 + minutes % 2), address=address)
        for minutes, address in zip(
            range(1, 7),
            (
                ANTHROPIC_ADDRESS,
                MAKE_ADDRESS,
                ANTHROPIC_ADDRESS,
                MAKE_ADDRESS,
                WORKATO_ADDRESS,
                WORKATO_ADDRESS,
            ),
            strict=True,
        )
    ]
    with serving(directory(*sign_ins, sign_in_max_top=1)) as server:
        result = full(db, admin, clock, connection_id, server)
    counts = result["sign_ins"]
    assert (counts["state"], counts["pages"], counts["read"]) == ("sampled", 4, 4)
    # The newest four were read, and Workato's two, the oldest, never were; the cursor moves on.
    assert "egress:workato" not in {row[2] for row in live(drivers_of(db, admin.tenant_id))}
    assert connection_row(db, admin.tenant_id, connection_id)["sign_in_cursor"] is not None


def test_sr26_the_reports_pacer_waits_for_the_window_and_refuses_past_its_bound():
    moment_now = [0.0]
    waits = []

    def sleep(seconds):
        waits.append(seconds)
        moment_now[0] += seconds

    pace = graph.Pace(monotonic=lambda: moment_now[0], sleep=sleep)
    for _ in range(5):
        pace.before()
    assert waits == []
    moment_now[0] = 4.0
    pace.before()
    # The sixth inside ten seconds waits until the oldest leaves the window.
    assert waits == [6.0]
    for _ in range(4):
        pace.before()
    # The eleventh would need another ten seconds, past the twelve a run may wait in all.
    with pytest.raises(graph.GraphError) as refused:
        pace.before()
    assert refused.value.code == "PACED" and pace.waited == 6.0


def test_sr26_the_audit_read_and_sign_ins_share_one_reports_budget(db, admins, clock, monkeypatch):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    paced = []

    def pacer():
        moment_now = [0.0]

        def sleep(seconds):
            paced.append(seconds)
            moment_now[0] += seconds

        pace = graph.Pace(monotonic=lambda: moment_now[0], sleep=sleep)
        return pace

    monkeypatch.setattr(graph, "PACER", pacer)
    now = clock.now()
    sign_ins = [sign_in(now - timedelta(minutes=n), actor=ref(9)) for n in range(1, 6)]
    with serving(directory(*sign_ins, sign_in_max_top=1)) as server:
        result = full(db, admin, clock, connection_id, server)
        reports = [p for p, _, _ in server.requests if p.startswith(graph.REPORTS_PREFIXES)]
    # Two probes, one audit page and four sign-in pages: seven reports requests, one wait.
    assert len(reports) == 7 and paced == [10.0]
    assert result["sign_ins"]["state"] == "sampled"


def test_sr26_a_read_the_reports_budget_stops_after_its_first_page_is_a_sample(
    db, admins, clock, monkeypatch
):
    """The run's own budget is the read's bound, not Graph refusing it: what it read is the
    newest, so the cursor moves on."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    monkeypatch.setattr(graph, "REPORTS_WAIT", 0.0)
    now = clock.now()
    sign_ins = [sign_in(now - timedelta(minutes=n), actor=ref(9)) for n in range(1, 6)]
    with serving(directory(*sign_ins, sign_in_max_top=1)) as server:
        result = full(db, admin, clock, connection_id, server)
    # Two probes and an audit page, then two sign-in pages: the sixth would need a wait.
    assert (result["sign_ins"]["state"], result["sign_ins"]["error_code"]) == ("sampled", "PACED")
    assert result["sign_ins"]["pages"] == 2 and result["outcome"] == "COMPLETE"
    assert connection_row(db, admin.tenant_id, connection_id)["sign_in_cursor"] is not None


def test_sr26_a_read_the_reports_budget_stops_before_its_first_page_leaves_the_cursor(
    db, admins, clock, monkeypatch
):
    """Before its first page the run's budget is a refusal: nothing was read, so the read failed
    and the cursor stays where the last read left it, whatever the run's clock says now."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    now = clock.now()
    sign_ins = [sign_in(now - timedelta(minutes=n), actor=ref(9)) for n in range(1, 6)]
    with serving(directory(*sign_ins)) as server:
        assert full(db, admin, clock, connection_id, server)["sign_ins"]["state"] == "complete"
        cursor = connection_row(db, admin.tenant_id, connection_id)["sign_in_cursor"]
        assert cursor is not None
        # Two probes and an audit page take the whole budget, and the first sign-in page would
        # need a wait the run cannot make.
        monkeypatch.setattr(graph, "REPORTS_LIMIT", 3)
        monkeypatch.setattr(graph, "REPORTS_WAIT", 0.0)
        clock.value += timedelta(hours=1)
        sent = len(sign_in_reads(server))
        result = full(db, admin, clock, connection_id, server)
        # The probe's sign-in request was sent, and the read's first page never was.
        assert len(sign_in_reads(server)) == sent + 1
    assert (result["sign_ins"]["state"], result["sign_ins"]["error_code"]) == ("failed", "PACED")
    assert result["sign_ins"]["pages"] == 0 and result["outcome"] == "COMPLETE"
    assert connection_row(db, admin.tenant_id, connection_id)["sign_in_cursor"] == cursor


@pytest.mark.parametrize(
    ("changes", "count"),
    [
        # Graph refuses the second page: the read failed, and the cursor stays.
        ({"sign_in_max_top": 1, "sign_in_page_status": 429}, "sign_ins_failed"),
        # More sign-ins than four pages: the newest were read, the rest were not.
        ({"sign_in_max_top": 1}, "sign_ins_sampled"),
    ],
)
def test_sr26_collect_due_counts_a_refused_or_bounded_sign_in_read(
    db, admins, clock, tmp_path, monkeypatch, capsys, changes, count
):
    """A sign-in read changes no run's outcome or health, so the scheduled pass is where one
    that fails or stops at its bound is seen: in its report and in its log line, each with the
    count itself."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    files = tmp_path / "key-files"
    key_file(files, connection_id, entra=True)
    sign_ins = [sign_in(clock.now() - timedelta(minutes=n), actor=ref(9)) for n in range(1, 6)]
    with every_log_line() as logged, serving(directory(*sign_ins, **changes)) as server:
        printed = scheduled(
            monkeypatch, capsys, server, "collect-due", "--all-tenants", "--key-files", str(files)
        )
    expected = {"sign_ins_failed": 0, "sign_ins_sampled": 0, count: 1}
    (report,) = [line for line in map(parsed, printed.splitlines()) if "tenants" in line]
    counts = report["tenants"][str(admin.tenant_id)]
    assert (counts["collected"], counts["failed"]) == (1, 0)
    assert {key: counts[key] for key in expected} == expected
    (line,) = [
        line
        for line in map(parsed, logged.written().splitlines())
        if line.get("event") == "monitor.collect_due"
    ]
    assert {key: line[key] for key in expected} == expected
    assert connection_row(db, admin.tenant_id, connection_id)["last_outcome"] == "COMPLETE"


@pytest.mark.parametrize(
    ("statuses", "audit_log", "sign_ins"),
    [
        ({"sign_in_status": 403}, "available", "unlicensed"),
        ({"sign_in_status": 403, "status": {"audits": 403}}, "forbidden", "forbidden"),
        ({"sign_in_status": 403, "status": {"audits": 503}}, "unknown", "unknown"),
        ({"sign_in_status": 404}, "available", "unsupported"),
        ({"sign_in_status": 503}, "available", "unknown"),
    ],
)
def test_sr26_losing_the_beta_capability_is_classified_and_the_run_continues(
    db, admins, clock, statuses, audit_log, sign_ins
):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    now = clock.now()
    scenario = directory(sign_in(now - timedelta(minutes=5), actor=ref(9)), **statuses)
    with serving(scenario) as server:
        result = full(db, admin, clock, connection_id, server)
        assert result["outcome"] == "COMPLETE"
        assert (result["capabilities"]["audit_log"], result["capabilities"]["sign_ins"]) == (
            audit_log,
            sign_ins,
        )
        reads_after_probe = len(sign_in_reads(server)) - 1
        row = connection_row(db, admin.tenant_id, connection_id)
        assert row["last_outcome"] == "COMPLETE" and row["last_error_code"] is None
        assert row["capabilities"]["sign_ins"]["state"] == sign_ins
        # A delta pass reads under what the probe established.
        clock.value += timedelta(minutes=5)
        passed = delta(db, admin, clock, connection_id, server)
        assert passed["outcome"] == "COMPLETE"
    if sign_ins in graph.NO_SIGN_INS:
        assert result["sign_ins"]["state"] == sign_ins and reads_after_probe == 0
        assert passed["sign_ins"]["state"] == sign_ins
    assert [row for row in drivers_of(db, admin.tenant_id) if row["evidence"] == "network"] == []
    # Only the audit log's own refusal makes the connection read as incomplete.
    reporting = store.collection_reporting(
        connection_row(db, admin.tenant_id, connection_id), clock.now()
    )
    assert reporting == (audit_log != "forbidden")


def test_sr26_a_sign_in_by_a_principal_not_yet_inventoried_is_matched_once_it_is(
    db, admins, clock, monkeypatch
):
    """A match for a principal the inventory does not hold yet is counted and not kept, and the
    cursor waits at it, so the read after the inventory holds the principal matches it; a
    principal that never appears holds the cursor no further back than the thirty days."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    # One principal the next collection inventories, and one it never does.
    stranger, never = principal(15), principal(16)
    when = (clock.now() - timedelta(hours=2)).replace(microsecond=0)
    earlier = (clock.now() - timedelta(hours=3)).replace(microsecond=0)
    sign_ins = (
        sign_in(when, actor=stranger["id"]),
        sign_in(earlier, actor=never["id"], address=MAKE_ADDRESS),
    )

    def cursor():
        return connection_row(db, admin.tenant_id, connection_id)["sign_in_cursor"]

    with serving(directory(*sign_ins)) as server:
        result = full(db, admin, clock, connection_id, server)
        assert result["sign_ins"]["matched"] == 2 and result["sign_ins"]["unknown_actor"] == 2
        assert [
            row for row in drivers_of(db, admin.tenant_id) if row["evidence"] == "network"
        ] == []
        assert cursor() == earlier
        server.scenario.principals.append(stranger)
        clock.value += timedelta(hours=7)
        again = full(db, admin, clock, connection_id, server)
        assert again["sign_ins"]["unknown_actor"] == 1
        assert {row for row in live(drivers_of(db, admin.tenant_id)) if row[1] == "network"} == {
            (stranger["id"], "network", "egress:anthropic")
        }
        assert cursor() == earlier
        # Once that sign-in is older than a first read looks back, the cursor waits no longer.
        # The look-back is shortened here rather than the clock moved a month, past the
        # administrator's credential.
        monkeypatch.setattr(graph, "SIGN_IN_LOOKBACK", timedelta(hours=10))
        clock.value += timedelta(hours=7)
        full(db, admin, clock, connection_id, server)
    assert cursor() == (clock.now() - timedelta(hours=10)).replace(microsecond=0)
    assert cursor() > earlier


def test_sr26_a_sign_in_stamped_ahead_of_the_read_is_dropped_or_kept_at_the_read(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    now = clock.now()
    sign_ins = [
        sign_in(now + timedelta(minutes=2), actor=ref(9)),
        sign_in(now + timedelta(hours=2), actor=ref(10), address=MAKE_ADDRESS),
    ]
    with serving(directory(*sign_ins)) as server:
        result = full(db, admin, clock, connection_id, server)
    assert result["sign_ins"]["dropped"] == 1
    (row,) = [row for row in drivers_of(db, admin.tenant_id) if row["evidence"] == "network"]
    assert row["platform_ref"] == "egress:anthropic" and row["last_seen_at"] <= now


# SR27: the Tines tenant's egress and the credential join


def record(db, admin, clock, connection_id, addresses):
    return drivers.set_egress_addresses(db, admin, connection_id, addresses, clock=clock)


def audit_events(admin_engine, tenant, kind):
    with admin_engine.connect() as conn:
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT payload, space_id FROM execbound.audit_events "
                    "WHERE tenant_id = :t AND kind = :k ORDER BY sequence"
                ),
                {"t": tenant, "k": kind},
            ).mappings()
        ]


def test_sr27_an_administrator_records_a_tines_tenant_s_egress_and_it_is_audited(
    db, admins, clock, admin_engine
):
    admin = admins[0]
    tines = tines_connection(db, admin, clock)
    assert record(
        db, admin, clock, tines, [OTHER_TINES_ADDRESS, TINES_ADDRESS, "2a05:d018::1"]
    ) == [
        TINES_ADDRESS,
        OTHER_TINES_ADDRESS,
        "2a05:d018::1",
    ]
    row = connection_row(db, admin.tenant_id, tines)
    assert [str(address) for address in row["egress_addresses"]] == [
        TINES_ADDRESS,
        OTHER_TINES_ADDRESS,
        "2a05:d018::1",
    ]
    assert row["egress_recorded_by"] == admin.principal_id and row["egress_recorded_at"] is not None
    (event,) = audit_events(admin_engine, admin.tenant_id, "monitor.egress_recorded")
    assert event["payload"]["addresses"] == 3 and event["payload"]["connection_id"] == str(tines)
    assert TINES_ADDRESS not in json.dumps(event["payload"])
    # An empty list clears the record.
    assert record(db, admin, clock, tines, []) == []
    assert connection_row(db, admin.tenant_id, tines)["egress_addresses"] is None


@pytest.mark.parametrize(
    ("addresses", "code"),
    [
        ([TINES_ADDRESS] * 2, "INVALID_EGRESS"),
        ([f"18.200.10.{n}" for n in range(30, 39)], "INVALID_EGRESS"),
        ([PRIVATE_ADDRESS], "INVALID_EGRESS"),
        (["127.0.0.1"], "INVALID_EGRESS"),
        (["169.254.10.1"], "INVALID_EGRESS"),
        (["198.51.100.4"], "INVALID_EGRESS"),
        (["224.0.0.5"], "INVALID_EGRESS"),
        (["fd00::1"], "INVALID_EGRESS"),
        # A zone names an interface on the host that wrote it, never a tenant's egress.
        (["2606:4700::1%1"], "INVALID_EGRESS"),
        (["18.200.10.0/24"], "INVALID_EGRESS"),
        (["not an address"], "INVALID_EGRESS"),
        ([17], "INVALID_EGRESS"),
        ("18.200.10.20", "INVALID_EGRESS"),
        # An address the catalog gives to another platform cannot be this tenant's.
        ([ANTHROPIC_ADDRESS], "EGRESS_CATALOGUED"),
    ],
)
def test_sr27_what_cannot_be_recorded_as_egress(db, admins, clock, addresses, code):
    """The store's own rule refuses each, before the database is asked: the database refuses
    most of them too, so a refusal it raised would otherwise stand in for the store's."""
    admin = admins[0]
    tines = tines_connection(db, admin, clock)
    with pytest.raises(MonitorError) as refused:
        drivers.egress_addresses(addresses)
    assert refused.value.code == code
    with statements(db.engine) as sent, pytest.raises(MonitorError) as refused:
        record(db, admin, clock, tines, addresses)
    assert refused.value.code == code
    assert not any(EGRESS_FUNCTION in statement for statement in sent)
    assert connection_row(db, admin.tenant_id, tines)["egress_addresses"] is None


def test_sr27_the_database_holds_the_addresses_to_its_own_copy_of_the_rule(db, admins, clock):
    """The definer function refuses what the collector would, whatever the caller sends, and
    the runtime cannot write the column any other way."""
    admin = admins[0]
    tines = tines_connection(db, admin, clock)
    entra = connect(db, admin, clock)
    nine = [f"18.200.10.{n}" for n in range(30, 39)]
    for addresses in ([PRIVATE_ADDRESS], ["18.200.10.0/24"], [TINES_ADDRESS] * 2, ["::1"], nine):
        with (
            pytest.raises(Exception, match="INVALID_EGRESS"),
            db.transaction(admin.tenant_id) as conn,
        ):
            conn.execute(
                text("SELECT execbound.admin_set_egress_addresses(:a, :c, CAST(:v AS inet[]))"),
                {"a": admin.principal_id, "c": tines, "v": addresses},
            )
    with pytest.raises(Exception, match="INVALID_STATE"), db.transaction(admin.tenant_id) as conn:
        conn.execute(
            text("SELECT execbound.admin_set_egress_addresses(:a, :c, CAST(:v AS inet[]))"),
            {"a": admin.principal_id, "c": entra, "v": [TINES_ADDRESS]},
        )
    with (
        pytest.raises(Exception, match="permission denied"),
        db.transaction(admin.tenant_id) as conn,
    ):
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections "
                "SET egress_addresses = ARRAY['18.200.10.20']::inet[] WHERE connection_id = :c"
            ),
            {"c": tines},
        )


EGRESS_FUNCTION = "admin_set_egress_addresses"


def call_egress_function(db, admin, connection, addresses, *, actor=None):
    with db.transaction(admin.tenant_id) as conn:
        conn.execute(
            text("SELECT execbound.admin_set_egress_addresses(:a, :c, CAST(:v AS inet[]))"),
            {"a": actor or admin.principal_id, "c": connection, "v": addresses},
        )


@pytest.mark.parametrize("block", drivers.NOT_EGRESS)
def test_sr27_the_store_and_the_database_refuse_every_block_alike(db, admins, clock, block):
    """One list of blocks no tenant's egress can be in, the store's and the database's alike:
    the first, the second and the last address of each is refused by both, the store's own
    rule refusing it before the database is asked."""
    admin = admins[0]
    tines = tines_connection(db, admin, clock)
    network = ipaddress.ip_network(block)
    first = network.network_address
    for address in sorted({str(first), str(first + 1), str(network.broadcast_address)}):
        with pytest.raises(MonitorError) as refused:
            drivers.egress_addresses([address])
        assert refused.value.code == "INVALID_EGRESS", address
        with statements(db.engine) as sent, pytest.raises(MonitorError) as refused:
            record(db, admin, clock, tines, [address])
        assert refused.value.code == "INVALID_EGRESS", address
        assert not any(EGRESS_FUNCTION in statement for statement in sent), address
        with pytest.raises(Exception, match="INVALID_EGRESS"):
            call_egress_function(db, admin, tines, [address])
    assert connection_row(db, admin.tenant_id, tines)["egress_addresses"] is None


def test_sr27_the_database_s_copy_of_the_egress_rule_is_the_store_s(db, admins, clock):
    """The function refuses the store's blocks and no others, and both take a public address
    just past one."""
    admin = admins[0]
    with db.transaction(admin.tenant_id) as conn:
        definition = conn.execute(
            text(
                "SELECT pg_get_functiondef("
                "'execbound.admin_set_egress_addresses(uuid, uuid, inet[])'::regprocedure)"
            )
        ).scalar_one()
    assert set(re.findall(r"'([0-9a-f.:]+/[0-9]+)'", definition)) == set(drivers.NOT_EGRESS)
    tines = tines_connection(db, admin, clock)
    for address in ("192.0.1.1", "2000::1", "2a05:d018::1", TINES_ADDRESS):
        assert record(db, admin, clock, tines, [address]) == [address]
        call_egress_function(db, admin, tines, [address])


def test_sr27_an_entra_connection_has_no_egress_and_a_narrowed_administrator_records_none(
    db, admins, clock, admin_engine
):
    admin = admins[0]
    entra = connect(db, admin, clock)
    with pytest.raises(MonitorError) as refused:
        record(db, admin, clock, entra, [TINES_ADDRESS])
    assert refused.value.code == "INVALID_STATE"
    with admin_engine.begin() as conn:
        elsewhere = make_space(conn, admin.tenant_id, "Elsewhere")
    tines = tines_connection(db, admin, clock, space=elsewhere)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.space_members (tenant_id, space_id, principal_id, role, "
                "assigned_at) SELECT :t, space_id, :p, 'ADMIN', now() FROM execbound.spaces "
                "WHERE tenant_id = :t AND space_id <> :s"
            ),
            {"t": admin.tenant_id, "p": admin.principal_id, "s": elsewhere},
        )
    # The store refuses the narrowed administrator itself, before the function is asked.
    with statements(db.engine) as sent, pytest.raises(MonitorError) as refused:
        record(db, admin, clock, tines, [TINES_ADDRESS])
    assert refused.value.code == "INVALID_ADMIN"
    assert not any(EGRESS_FUNCTION in statement for statement in sent)


def test_sr27_the_egress_function_checks_the_actor_whatever_its_caller_checked(
    db, admins, clock, admin_engine
):
    """The definer function refuses, called directly, an approver, an agent, the scheduler, an
    administrator no longer active, one a membership narrows to another Space and one seated in
    the connection's Space as an approver; an administrator seated in it as one records. Its kind
    condition repeats what `access_effective_kind` answers for an agent and the scheduler, so
    either refuses those two."""
    admin = admins[0]
    tenant = admin.tenant_id
    tines = tines_connection(db, admin, clock)
    with admin_engine.begin() as conn:
        here = conn.execute(
            text(
                "SELECT space_id FROM execbound.monitor_connections "
                "WHERE tenant_id = :t AND connection_id = :c"
            ),
            {"t": tenant, "c": tines},
        ).scalar_one()
        elsewhere = make_space(conn, tenant, "Elsewhere")
        actors = {}
        for name, kind, active, space in (
            ("approver", "HUMAN_APPROVER", True, None),
            ("agent", "AGENT", True, here),
            ("inactive", "ADMIN", False, None),
            ("narrowed", "ADMIN", True, None),
            ("approving here", "ADMIN", True, None),
            ("seated", "ADMIN", True, None),
        ):
            actors[name] = uuid4()
            conn.execute(
                text(
                    "INSERT INTO execbound.principals "
                    "(tenant_id, principal_id, kind, active, space_id) "
                    "VALUES (:t, :p, :k, :a, :s)"
                ),
                {"t": tenant, "p": actors[name], "k": kind, "a": active, "s": space},
            )
        seat(conn, tenant, elsewhere, actors["narrowed"], "ADMIN")
        seat(conn, tenant, here, actors["approving here"], "HUMAN_APPROVER")
        seat(conn, tenant, here, actors["seated"], "ADMIN")
    with db.transaction(tenant) as conn:
        actors["scheduler"] = conn.execute(
            text("SELECT execbound.scheduler_actor() ->> 'principal_id'")
        ).scalar_one()
    for name in ("approver", "agent", "scheduler", "inactive", "narrowed", "approving here"):
        with pytest.raises(Exception, match="INVALID_ACTOR"):
            call_egress_function(db, admin, tines, [TINES_ADDRESS], actor=actors[name])
        assert connection_row(db, tenant, tines)["egress_addresses"] is None, name
    call_egress_function(db, admin, tines, [TINES_ADDRESS], actor=actors["seated"])
    assert connection_row(db, tenant, tines)["egress_recorded_by"] == actors["seated"]


def joined_world(db, admin, clock, *, credentials=CREDENTIALS, address=TINES_ADDRESS, **connection):
    """A Tines tenant with its credentials collected and its egress recorded, and a directory
    in the same Space whose principal 9 signs in from `address`."""
    tines = tines_connection(db, admin, clock, **connection)
    result, _ = tines_inventory(db, admin, clock, tines, credentials=credentials)
    assert result["outcome"] == "COMPLETE", result
    record(db, admin, clock, tines, [TINES_ADDRESS])
    entra = connect(db, admin, clock)
    scenario = directory(sign_in(clock.now() - timedelta(minutes=5), actor=ref(9), address=address))
    return tines, entra, scenario


def test_sr27_a_sign_in_from_the_recorded_egress_joins_every_story_using_a_microsoft_credential(
    db, admins, clock, tmp_path, monkeypatch, capsys
):
    admin = admins[0]
    tines, entra, scenario = joined_world(db, admin, clock)
    files = tmp_path / "key-files"
    key_file(files, entra, entra=True)
    # The jobs service's pass and then an operator's run, inside the read's overlap.
    with every_log_line() as logged, serving(scenario) as server:
        printed = scheduled(
            monkeypatch, capsys, server, "collect-due", "--all-tenants", "--key-files", str(files)
        )
        clock.value = datetime.now(UTC)
        result = full(db, admin, clock, entra, server)
    assert logged.holds("monitor.collect_due")
    assert (result["sign_ins"]["network"], result["sign_ins"]["joined"]) == (1, 1)
    rows = [row for row in drivers_of(db, admin.tenant_id) if row["actor"] == ref(9)]
    by_level = {row["evidence"]: row for row in rows}
    assert by_level["network"]["platform_ref"] == f"tines:{tines}"
    joined = by_level["joined"]
    assert joined["platform_ref"] == f"tines:{tines}"
    # Every story that references a credential allowed to call Microsoft Graph or Microsoft
    # sign-in, and none that uses an unrestricted credential or another host's: never one story.
    assert joined["detail_refs"] == ["4001", "4002", "4003"]
    assert joined["detail_capped"] is False
    assert (joined["first_seen_at"], joined["last_seen_at"]) == (
        by_level["network"]["first_seen_at"],
        by_level["network"]["last_seen_at"],
    )
    found = detail(db, admin, clock, ref(9))
    (tines_join,) = [row for row in found["drivers"] if row["evidence"] == "joined"]
    assert tines_join["label"] == "Synthetic Tines tenant"
    assert tines_join["unrestricted_credentials"] == 1
    kept = everything(db, admin.tenant_id) + json.dumps([result, found], default=str) + printed
    # The Tines connection holds the egress its administrator recorded, and nothing else does.
    recorded = connection_row(db, admin.tenant_id, tines)["egress_addresses"]
    assert [str(address) for address in recorded] == [TINES_ADDRESS]
    kept = kept.replace(f"IPv4Address('{TINES_ADDRESS}')", "")
    for value in (*FORBIDDEN, *HOSTS):
        assert value not in kept, value
    # Every log line too. The recorded egress is the one value read back as it was written: the
    # database engine's own debug lines name the connection row's addresses whenever it is read,
    # and the sign-in from it is the read's alone (SR26 sweeps sign-in addresses nobody recorded).
    logs = logged()
    for value in (*FORBIDDEN, *HOSTS):
        assert value == TINES_ADDRESS or value not in logs, value


def test_sr27_the_tines_inventory_keeps_a_credential_s_scope_and_stories_and_nothing_else(
    db, admins, clock
):
    admin = admins[0]
    tines = tines_connection(db, admin, clock)
    result, server = tines_inventory(db, admin, clock, tines)
    assert result["inventory"]["credentials"] == 4
    reads = [query for path, query, _ in server.requests if path == fake_tines.CREDENTIALS_PATH]
    assert reads[-1]["include_references"] == "true"
    with db.transaction(admin.tenant_id) as conn:
        kept = {
            row["external_id"]: (row["host_scope"], row["story_refs"], row["references_capped"])
            for row in conn.execute(
                text(
                    "SELECT external_id, host_scope, story_refs, references_capped "
                    "FROM execbound.monitor_inventory WHERE item_kind = 'credential'"
                )
            ).mappings()
        }
    assert kept == {
        "301": ("microsoft", ["4001", "4002"], False),
        "302": ("microsoft", ["4003"], False),
        "303": ("unrestricted", ["4004"], False),
        "304": ("other", ["4005"], False),
    }


@pytest.mark.parametrize(
    ("hosts", "scope"),
    [
        (["graph.microsoft.com"], "microsoft"),
        (["GRAPH.MICROSOFT.COM."], "microsoft"),
        (["https://graph.microsoft.com/v1.0/users"], "microsoft"),
        (["login.microsoftonline.com:443"], "microsoft"),
        (["api.example.invalid", "login.microsoftonline.com"], "microsoft"),
        # A wildcard that would cover Graph is not Graph: a scope never says more than its hosts.
        (["*.microsoft.com"], "other"),
        (["graph.microsoft.com.example.invalid"], "other"),
        ([], "unrestricted"),
        ("graph.microsoft.com", None),
        (None, None),
    ],
)
def test_sr27_a_credential_s_allowed_hosts_are_classified_and_dropped(hosts, scope):
    record = {"id": 301, "name": "c", "allowed_hosts": hosts}
    assert collection.parse_credential(record).host_scope == scope
    assert collection.parse_credential({"id": 301, "name": "c"}).host_scope is None


def test_sr27_tines_cap_on_references_is_stated_as_at_least(db, admins, clock):
    admin = admins[0]
    # 60 stories of two actions each: Tines lists the first 100 actions, so fifty stories.
    wide = credential(305, ["graph.microsoft.com"], range(5001, 5061))
    tines, entra, scenario = joined_world(db, admin, clock, credentials=[wide])
    with db.transaction(admin.tenant_id) as conn:
        stories, capped = conn.execute(
            text(
                "SELECT story_refs, references_capped FROM execbound.monitor_inventory "
                "WHERE item_kind = 'credential'"
            )
        ).one()
    assert len(stories) == 50 and capped is True
    with serving(scenario) as server:
        full(db, admin, clock, entra, server)
    (joined,) = [row for row in drivers_of(db, admin.tenant_id) if row["evidence"] == "joined"]
    assert len(joined["detail_refs"]) == 50 and joined["detail_capped"] is True


@pytest.mark.parametrize(
    ("team", "joined"),
    [
        # A connection scoped to a team joins only that team's stories, whoever owns the
        # credential they use.
        ("7", ["4001", "4002", "4003"]),
        ("9", ["4901", "4902"]),
        # One scoped to no team reads every team's stories, and joins them all.
        (None, ["4001", "4002", "4003", "4901", "4902", "4903"]),
    ],
)
def test_sr27_a_join_names_only_the_stories_of_the_connection_s_own_team(
    db, admins, clock, team, joined
):
    """A credential one team shares with another is referenced by both teams' stories, and the
    references of a team the connection is not scoped to, or of none, are not its stories."""
    admin = admins[0]
    shared = credential(301, ["graph.microsoft.com"], [4001, 4002])
    shared["references"] += [
        {"story_id": 4901, "team_id": 9, "action_ids": [1, 2]},
        # A reference that names no team is no team's, so a scoped connection never joins it.
        {"story_id": 4903, "action_ids": [3]},
    ]
    credentials = [
        shared,
        credential(302, ["login.microsoftonline.com"], [4003]),
        credential(306, ["graph.microsoft.com"], [4902], team=9),
    ]
    tines, entra, scenario = joined_world(db, admin, clock, credentials=credentials, team_id=team)
    with serving(scenario) as server:
        full(db, admin, clock, entra, server)
    (row,) = [row for row in drivers_of(db, admin.tenant_id) if row["evidence"] == "joined"]
    assert row["detail_refs"] == joined


def test_sr27_no_credential_allowed_to_call_microsoft_means_no_join(db, admins, clock):
    admin = admins[0]
    tines, entra, scenario = joined_world(
        db,
        admin,
        clock,
        credentials=[credential(303, [], [4004]), credential(304, ["x.invalid"], [4005])],
    )
    with serving(scenario) as server:
        full(db, admin, clock, entra, server)
    assert {
        row["evidence"] for row in drivers_of(db, admin.tenant_id) if row["actor"] == ref(9)
    } == {"network"}


def test_sr27_changing_the_egress_ends_its_rows_and_rereads_thirty_days_once(db, admins, clock):
    admin = admins[0]
    tines, entra, scenario = joined_world(db, admin, clock)
    with serving(scenario) as server:
        full(db, admin, clock, entra, server)
        assert connection_row(db, admin.tenant_id, entra)["sign_in_cursor"] is not None
        record(db, admin, clock, tines, [OTHER_TINES_ADDRESS])
        assert live(drivers_of(db, admin.tenant_id)) == set() or all(
            row[1] == "declared" for row in live(drivers_of(db, admin.tenant_id))
        )
        assert connection_row(db, admin.tenant_id, entra)["sign_in_cursor"] is None
        clock.value += timedelta(minutes=5)
        delta(db, admin, clock, entra, server)
        # The re-read looked back thirty days, and the old address matches no recorded one.
        assert sign_in_reads(server)[-1]["$filter"].startswith(
            "createdDateTime ge "
            + moment((clock.now() - timedelta(days=30)).replace(microsecond=0))
        )
        assert not {
            row for row in live(drivers_of(db, admin.tenant_id)) if row[2].startswith("tines:")
        }
        record(db, admin, clock, tines, [TINES_ADDRESS])
        clock.value += timedelta(minutes=5)
        delta(db, admin, clock, entra, server)
    assert {row[1] for row in live(drivers_of(db, admin.tenant_id)) if row[0] == ref(9)} == {
        "network",
        "joined",
    }


def test_sr27_egress_recorded_while_a_read_runs_drops_that_read_s_tines_matches(
    db, admins, clock, monkeypatch
):
    admin = admins[0]
    tines, entra, scenario = joined_world(db, admin, clock)
    original = graph.read_sign_ins

    def racing(*args, **kwargs):
        found = original(*args, **kwargs)
        record(db, admin, clock, tines, [OTHER_TINES_ADDRESS])
        return found

    monkeypatch.setattr(graph, "read_sign_ins", racing)
    with serving(scenario) as server:
        result = full(db, admin, clock, entra, server)
    assert result["sign_ins"]["stale"] == 1 and result["sign_ins"]["network"] == 0
    assert connection_row(db, admin.tenant_id, entra)["sign_in_cursor"] is None


def test_sr27_egress_recorded_after_a_run_began_still_rereads_thirty_days(
    db, admins, clock, monkeypatch
):
    """A run loads its connection when it begins and reads sign-ins minutes later. Egress
    recorded in between clears the cursor the run found, so the read starts where the recording
    left it, thirty days back, and not where the run began."""
    admin = admins[0]
    tines, entra, scenario = joined_world(db, admin, clock)
    # Principal 10 signed in ten days ago from the address the administrator records next.
    scenario.sign_ins.append(
        sign_in(clock.now() - timedelta(days=10), actor=ref(10), address=OTHER_TINES_ADDRESS)
    )
    with serving(scenario) as server:
        full(db, admin, clock, entra, server)
        assert connection_row(db, admin.tenant_id, entra)["sign_in_cursor"] is not None
        original = drivers.space_egress

        def recorded_first(*args, **kwargs):
            record(db, admin, clock, tines, [TINES_ADDRESS, OTHER_TINES_ADDRESS])
            return original(*args, **kwargs)

        monkeypatch.setattr(drivers, "space_egress", recorded_first)
        clock.value += timedelta(minutes=5)
        result = delta(db, admin, clock, entra, server)
        assert sign_in_reads(server)[-1]["$filter"].startswith(
            "createdDateTime ge "
            + moment((clock.now() - timedelta(days=30)).replace(microsecond=0))
        )
    assert result["sign_ins"]["stale"] == 0
    assert {(ref(9), "network", f"tines:{tines}"), (ref(10), "network", f"tines:{tines}")} <= live(
        drivers_of(db, admin.tenant_id)
    )
    # The thirty days were read once: the cursor moves on as after any complete read.
    assert connection_row(db, admin.tenant_id, entra)["sign_in_cursor"] == (
        clock.now() - timedelta(minutes=30)
    ).replace(microsecond=0)


def test_sr27_evidence_from_a_corrected_egress_is_dated_from_its_own_sign_ins(db, admins, clock):
    """A row an egress change ended and a later match brings back is new evidence: its first
    sighting is the new address's, never one from the address the administrator replaced."""
    admin = admins[0]
    tines, entra, scenario = joined_world(db, admin, clock)
    with serving(scenario) as server:
        full(db, admin, clock, entra, server)
        record(db, admin, clock, tines, [OTHER_TINES_ADDRESS])
        later = clock.now() + timedelta(hours=1)
        server.scenario.sign_ins.append(sign_in(later, actor=ref(9), address=OTHER_TINES_ADDRESS))
        clock.value += timedelta(hours=2)
        delta(db, admin, clock, entra, server)
    rows = {
        row["evidence"]: row
        for row in drivers_of(db, admin.tenant_id)
        if row["actor"] == ref(9) and row["platform_ref"] == f"tines:{tines}"
    }
    for level in ("network", "joined"):
        assert rows[level]["gone_at"] is None, level
        assert rows[level]["first_seen_at"] == later.replace(microsecond=0), level
        assert rows[level]["last_seen_at"] == later.replace(microsecond=0), level


def tines_rows(db, tenant, tines):
    """Each driver row naming the Tines connection `tines`: (actor, level) to whether it is live."""
    return {
        (row["actor"], row["evidence"]): row["gone_at"] is None
        for row in drivers_of(db, tenant)
        if row["platform_ref"] == f"tines:{tines}"
    }


def test_sr27_a_revoked_tines_connection_ends_the_join_and_the_match(db, admins, clock):
    admin = admins[0]
    tines, entra, scenario = joined_world(db, admin, clock)
    with serving(scenario) as server:
        full(db, admin, clock, entra, server)
        assert tines_rows(db, admin.tenant_id, tines) == {
            (ref(9), "network"): True,
            (ref(9), "joined"): True,
        }
        store.revoke_connection(db, admin, tines, clock=clock)
        # Revoking ends both at once, before any directory is read again.
        assert tines_rows(db, admin.tenant_id, tines) == {
            (ref(9), "network"): False,
            (ref(9), "joined"): False,
        }
        clock.value += timedelta(minutes=5)
        passed = delta(db, admin, clock, entra, server)
    # And no later read matches the revoked tenant's egress.
    assert passed["sign_ins"]["matched"] == 0
    assert tines_rows(db, admin.tenant_id, tines) == {
        (ref(9), "network"): False,
        (ref(9), "joined"): False,
    }


def test_sr27_a_join_follows_the_tines_tenant_while_the_directory_s_sign_ins_go_unread(
    db, admins, clock
):
    """A directory that has lost the sign-in read still has its joins kept true: they follow the
    Tines inventory's credentials when it is collected, and the Tines connection's revocation,
    without waiting for a sign-in read that never comes."""
    admin = admins[0]
    tines, entra, scenario = joined_world(db, admin, clock)
    with serving(scenario) as server:
        full(db, admin, clock, entra, server)
        # The directory loses Microsoft Entra ID P1 or P2: its sign-ins are not read again.
        server.scenario.sign_in_status = 403
        clock.value += timedelta(hours=7)
        assert full(db, admin, clock, entra, server)["sign_ins"]["state"] == "unlicensed"
    assert tines_rows(db, admin.tenant_id, tines)[(ref(9), "joined")] is True
    # No credential of the Tines tenant is allowed to call Microsoft any more.
    clock.value += timedelta(minutes=5)
    tines_inventory(db, admin, clock, tines, credentials=[credential(303, [], [4004])])
    assert tines_rows(db, admin.tenant_id, tines) == {
        (ref(9), "network"): True,
        (ref(9), "joined"): False,
    }
    # One is again, and the network evidence still stands: the join holds again.
    clock.value += timedelta(minutes=5)
    tines_inventory(db, admin, clock, tines)
    (joined,) = [
        row
        for row in drivers_of(db, admin.tenant_id)
        if row["evidence"] == "joined" and row["gone_at"] is None
    ]
    assert joined["detail_refs"] == ["4001", "4002", "4003"]
    store.revoke_connection(db, admin, tines, clock=clock)
    assert set(tines_rows(db, admin.tenant_id, tines).values()) == {False}


def test_sr27_a_join_never_crosses_a_space(db, admins, clock, admin_engine):
    admin = admins[0]
    with admin_engine.begin() as conn:
        elsewhere = make_space(conn, admin.tenant_id, "Elsewhere")
    tines = tines_connection(db, admin, clock, space=elsewhere)
    tines_inventory(db, admin, clock, tines)
    record(db, admin, clock, tines, [TINES_ADDRESS])
    entra = connect(db, admin, clock)
    with serving(directory(sign_in(clock.now(), actor=ref(9), address=TINES_ADDRESS))) as server:
        result = full(db, admin, clock, entra, server)
    assert result["sign_ins"]["unmatched"] == 1
    assert not [row for row in drivers_of(db, admin.tenant_id) if row["evidence"] != "declared"]


def test_sr27_the_agent_detail_names_a_tines_tenant_only_to_a_session_that_sees_its_space(
    db, admins, clock, admin_engine
):
    """An actor's detail is the tenant's, but a Tines connection's label, its inventory's story
    ids and its count of unrestricted credentials are its Space's. A session looking at another
    Space, or an administrator narrowed to another Space, reads the actor's own directory
    evidence and nothing that names the Tines tenant: what the connection's own page refuses as
    CONNECTION_UNAVAILABLE the actor's page does not answer either."""
    admin = admins[0]
    tines, entra, _ = joined_world(db, admin, clock)
    sign_ins = [
        sign_in(clock.now() - timedelta(minutes=5), actor=ref(9), address=TINES_ADDRESS),
        sign_in(clock.now() - timedelta(minutes=4), actor=ref(9), address=MAKE_ADDRESS),
    ]
    with serving(directory(*sign_ins)) as server:
        full(db, admin, clock, entra, server)
    with admin_engine.begin() as conn:
        own = default_space(conn, admin.tenant_id)
        other = make_space(conn, admin.tenant_id, "Customer B")
    from execbound.surfaces import sessions

    session = sessions.load_session(
        db, sessions.issue_session(db, admin, clock=clock).token, clock=clock
    )
    agent_id = agent_row(db, admin.tenant_id, ref(9))["agent_id"]

    def looking_at(space):
        with db.transaction(admin.tenant_id) as conn:
            set_current_space(conn, session, space)

    def seen():
        found = store.agent_detail(db, session, agent_id, clock=clock)["drivers"]
        return {(row["evidence"], row["platform_ref"]) for row in found}, json.dumps(
            found, default=str
        )

    whole = {
        ("joined", f"tines:{tines}"),
        ("network", f"tines:{tines}"),
        ("network", "egress:make"),
    }
    assert seen()[0] == whole
    looking_at(own)
    assert seen()[0] == whole
    looking_at(other)
    rows, answered = seen()
    assert rows == {("network", "egress:make")}
    for value in (str(tines), "Synthetic Tines tenant", "4001", "4002", "4003"):
        assert value not in answered, value
    # Narrowed to the other Space, looking at every Space it sees: still none of the Tines tenant.
    looking_at(None)
    with admin_engine.begin() as conn:
        seat(conn, admin.tenant_id, other, admin.principal_id, "ADMIN")
    rows, answered = seen()
    assert rows == {("network", "egress:make")}
    for value in (str(tines), "Synthetic Tines tenant", "4001", "4002", "4003"):
        assert value not in answered, value


def test_sr27_record_egress_from_the_command_line(
    db, admins, clock, tmp_path, capsys, monkeypatch, seeded
):
    admin = admins[0]
    tines = tines_connection(db, admin, clock)
    token = tmp_path / "admin-token.txt"
    token.write_text(seeded["tokens"][0])
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    common = ["commands", "record-egress", "--credential-file", str(token)]
    monkeypatch.setattr(
        sys,
        "argv",
        [
            *common,
            "--connection",
            str(tines),
            "--address",
            OTHER_TINES_ADDRESS,
            "--address",
            TINES_ADDRESS,
        ],
    )
    commands.main()
    assert json.loads(capsys.readouterr().out) == {
        "connection_id": str(tines),
        "addresses": [TINES_ADDRESS, OTHER_TINES_ADDRESS],
    }
    monkeypatch.setattr(sys, "argv", [*common, "--connection", str(tines), "--clear"])
    commands.main()
    assert json.loads(capsys.readouterr().out)["addresses"] == []
    assert connection_row(db, admin.tenant_id, tines)["egress_addresses"] is None
    # Neither or both of an address and --clear is refused before the database is reached.
    for extra in ([], ["--clear", "--address", TINES_ADDRESS]):
        monkeypatch.setattr(sys, "argv", [*common, "--connection", str(tines), *extra])
        with pytest.raises(SystemExit):
            commands.main()
    # A refused address names nothing it was given.
    monkeypatch.setattr(
        sys, "argv", [*common, "--connection", str(tines), "--address", PRIVATE_ADDRESS]
    )
    with pytest.raises(SystemExit):
        commands.main()
    assert PRIVATE_ADDRESS not in capsys.readouterr().err


def test_sr27_driver_rows_hold_their_shape(db, admins, clock):
    """The database refuses a row whose platform does not fit its level, story ids anywhere but a
    join, or anything in them that is not an identifier."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(directory(principals=[principal(9)])) as server:
        full(db, admin, clock, connection_id, server)
    agent_id = agent_row(db, admin.tenant_id, ref(9))["agent_id"]
    bad = [
        ("declared", "egress:anthropic", []),
        ("network", "publisher:anthropic", []),
        ("joined", "egress:anthropic", ["4001"]),
        ("network", "egress:anthropic", ["4001"]),
        ("joined", f"tines:{uuid4()}", ["4001,4002"]),
        ("joined", f"tines:{uuid4()}", ["a name with spaces"]),
        ("joined", f"tines:{uuid4()}", [str(n) for n in range(101)]),
        ("network", "egress:Anthropic", []),
        ("network", "tines:not-a-uuid", []),
    ]
    accepted = []
    for evidence, platform_ref, stories in bad:
        try:
            with db.transaction(admin.tenant_id) as conn:
                conn.execute(
                    text(
                        "INSERT INTO execbound.monitor_actor_drivers (tenant_id, agent_id, "
                        "evidence, platform_ref, source_connection_id, detail_refs, "
                        "first_seen_at, last_seen_at) "
                        "VALUES (:t, :a, :e, :p, :c, CAST(:d AS text[]), now(), now())"
                    ),
                    {
                        "t": admin.tenant_id,
                        "a": agent_id,
                        "e": evidence,
                        "p": platform_ref,
                        "c": connection_id,
                        "d": stories,
                    },
                )
            accepted.append((evidence, platform_ref, stories))
        except IntegrityError as refused:
            assert "violates check constraint" in str(refused.orig)
    assert accepted == []
    with (
        pytest.raises(Exception, match="permission denied"),
        db.transaction(admin.tenant_id) as conn,
    ):
        conn.execute(text("DELETE FROM execbound.monitor_actor_drivers"))


def test_sr27_a_driver_row_is_its_own_tenant_s(db, admins, clock):
    """Read and written straight on the table, with no join that another table's row security
    could answer for: another tenant sees none of the rows and can write none into this one."""
    first, second = admins
    connection_id = connect(db, first, clock)
    with serving(directory(principals=[principal(10, appId=ANTHROPIC_SERVER)])) as server:
        full(db, first, clock, connection_id, server)
    agent_id = agent_row(db, first.tenant_id, ref(10))["agent_id"]

    def count(tenant):
        with db.transaction(tenant) as conn:
            return conn.execute(
                text("SELECT count(*) FROM execbound.monitor_actor_drivers")
            ).scalar_one()

    held = count(first.tenant_id)
    assert held > 0
    assert count(second.tenant_id) == 0
    with (
        pytest.raises(Exception, match="row-level security"),
        db.transaction(second.tenant_id) as conn,
    ):
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_actor_drivers (tenant_id, agent_id, evidence, "
                "platform_ref, source_connection_id, first_seen_at, last_seen_at) "
                "VALUES (:t, :a, 'network', 'egress:make', :c, now(), now())"
            ),
            {"t": first.tenant_id, "a": agent_id, "c": connection_id},
        )
    with db.transaction(second.tenant_id) as conn:
        assert (
            conn.execute(
                text("UPDATE execbound.monitor_actor_drivers SET gone_at = now()")
            ).rowcount
            == 0
        )
    assert count(first.tenant_id) == held


def test_sr27_the_agent_detail_names_each_driver_s_source_and_what_cannot_be_attributed(
    db, admins, clock
):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    consented = principal(10, appId=ANTHROPIC_SERVER)
    sign_ins = [sign_in(clock.now() - timedelta(minutes=5), actor=ref(10), address=MAKE_ADDRESS)]
    with serving(directory(*sign_ins, principals=[consented])) as server:
        full(db, admin, clock, connection_id, server)
    found = detail(db, admin, clock, ref(10))
    by_ref = {row["platform_ref"]: row for row in found["drivers"]}
    assert by_ref["publisher:anthropic"]["label"] == "Anthropic"
    assert by_ref["publisher:anthropic"]["source"].startswith("https://support.claude.com/")
    assert by_ref["egress:make"]["label"] == "Make"
    assert by_ref["egress:make"]["source"] == egress.MAKE
    assert by_ref["egress:make"]["retrieved"] == egress.READ_ON
    assert found["agent"]["user_agent_hint"] == "python-requests/2.31.0"
    # Declared evidence is listed before network evidence.
    assert [row["evidence"] for row in found["drivers"]] == ["declared", "network"]


def test_sr27_a_driver_row_never_outlives_its_actor_unmarked(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    sign_ins = [sign_in(clock.now() - timedelta(minutes=5), actor=ref(9))]
    with serving(directory(*sign_ins, principals=[principal(9)])) as server:
        full(db, admin, clock, connection_id, server)
        server.scenario.principals = []
        server.scenario.sign_ins = []
        clock.value += timedelta(hours=7)
        full(db, admin, clock, connection_id, server)
    (row,) = [row for row in drivers_of(db, admin.tenant_id) if row["actor"] == ref(9)]
    assert row["evidence"] == "network" and row["gone_at"] is not None
