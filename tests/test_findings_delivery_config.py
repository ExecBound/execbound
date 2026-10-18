# SPDX-License-Identifier: AGPL-3.0-only
"""Which destinations receive findings (#31): FD7, and FD8's configuration half.

No database: a destination and the private configuration are validated, and refused whole,
before any connection is made. A destination opts in through `classes`, `["approvals"]` when
it is left out, so a file written before findings delivery keeps its meaning; `rules` and
`spaces` narrow a findings destination; `messages` and `approvers` stay an approval
destination's. A refusal never quotes the file.
"""

import secrets
from uuid import UUID, uuid4

import pytest
from conftest import assert_secret_free
from test_approval_delivery_config import configuration, destination, destinations, write
from test_findings_messages import message
from test_notification_email import MAIL, PASSWORD

from execbound import schedule
from execbound.monitoring.delivery import FINDING_RULES

# Through the configuration module, which loads the execution package first: importing
# `execbound.notifications` on its own meets the package's import cycle.
from execbound.surfaces.configuration import Destination, read_configuration, read_outbound
from execbound.surfaces.human import HumanConfig, check_origin
from execbound.surfaces.tokens import TokenKeys
from execbound.transports import MailConfig, safe_label

TENANT = UUID("00000000-0000-4000-8000-0000000000a1")
HOOK = "https://alerts.example.net/execbound/hook"
KEY = "s3cr3t-hook-secret-value-" + "x" * 20
SPACE = UUID("00000000-0000-4000-8000-0000000000b1")
FINDINGS = frozenset({"findings"})
BOTH = frozenset({"approvals", "findings"})
# Origins outside the console's rule, which `HumanConfig` and `read_outbound` both refuse.
BAD_ORIGINS = (
    "http://console.example.net",
    "https://console.example.net/app",
    "https://user@console.example.net",
    "https://console.example.net?x=1",
    "ftp://console.example.net",
)
# Origins the console's rule takes and a finding message's refuses, so that every message built
# from one would be `INVALID_NOTIFICATION`: an upper-case scheme, an underscore in the host and
# a host that is not ASCII.
UNRENDERABLE_ORIGINS = (
    "HTTPS://console.example.net",
    "https://my_host.example",
    "https://ex\u00e4mple.com",
)


def test_fd7_a_destination_without_classes_is_an_approval_destination():
    plain = Destination("soc", TENANT, HOOK, KEY)
    assert plain.classes == frozenset({"approvals"})
    assert (plain.rules, plain.spaces) == (None, None)


@pytest.mark.parametrize(
    "changes",
    [
        {"classes": FINDINGS},
        {"classes": BOTH},
        {"classes": FINDINGS, "rules": frozenset({"sensitive-action.v2"})},
        {"classes": FINDINGS, "spaces": frozenset({SPACE})},
        {"classes": BOTH, "messages": frozenset({"pending", "closed"})},
        {"classes": BOTH, "approvers": frozenset({uuid4()})},
    ],
)
def test_fd7_each_allowed_destination_holds(changes):
    Destination("soc", TENANT, HOOK, KEY, **changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"classes": frozenset()},
        {"classes": frozenset({"sms"})},
        {"classes": ("findings",)},
        {"rules": frozenset({"sensitive-action.v2"})},
        {"spaces": frozenset({SPACE})},
        {"classes": FINDINGS, "rules": frozenset()},
        {"classes": FINDINGS, "rules": frozenset({"no-such-rule.v1"})},
        {"classes": FINDINGS, "rules": ("sensitive-action.v2",)},
        {"classes": FINDINGS, "spaces": frozenset({str(SPACE)})},
        {"classes": FINDINGS, "messages": frozenset({"pending", "closed"})},
        {"classes": FINDINGS, "approvers": frozenset({uuid4()})},
        {"kind": "security-events", "classes": BOTH},
        {"kind": "security-events", "classes": FINDINGS},
    ],
)
def test_fd7_the_destination_holds_the_rules_without_the_file(changes):
    with pytest.raises(ValueError):
        Destination("soc", TENANT, HOOK, KEY, **changes)


def test_fd7_an_empty_catalog_admits_nothing():
    """A narrowing given a catalog holds every item to it, an empty one included; only None
    means no catalog, as for Spaces. A catalog emptied by mistake refuses every rule rather
    than admitting any."""
    # Imported here, once the configuration module above has loaded the package: importing
    # `execbound.notifications` first meets the package's import cycle.
    from execbound.notifications import _narrowing

    assert not _narrowing(frozenset({"x"}), str, True, ())
    assert _narrowing(frozenset({"x"}), str, True, ("x",))
    assert _narrowing(frozenset({"x"}), str, True, None)


def test_fd7_every_label_is_short_fixed_copy():
    """A label reaches an email subject and a chat header as it is, so it is already what
    `safe_label` would leave, and short enough for both."""
    assert FINDING_RULES
    for rule, label in FINDING_RULES.items():
        assert safe_label(label) == label, rule
        assert 1 <= len(label) <= 60, rule


def test_fd7_an_old_file_still_means_approvals_only(tmp_path):
    [loaded] = destinations(tmp_path, destination())
    assert loaded.classes == frozenset({"approvals"})
    assert (loaded.rules, loaded.spaces) == (None, None)


@pytest.mark.parametrize(
    "changes",
    [
        {"classes": ["findings"]},
        {"classes": ["approvals", "findings"], "messages": ["pending", "closed"]},
        {"classes": ["findings"], "rules": ["sensitive-action.v2", "source-health.v1"]},
        {"classes": ["findings"], "spaces": [str(SPACE)]},
    ],
)
def test_fd7_each_allowed_file_loads(tmp_path, changes):
    [loaded] = destinations(tmp_path, destination(**changes))
    assert loaded.classes == frozenset(changes["classes"])
    assert loaded.rules == (frozenset(changes["rules"]) if "rules" in changes else None)
    assert loaded.spaces == (frozenset({SPACE}) if "spaces" in changes else None)


@pytest.mark.parametrize(
    "bad",
    [
        destination(classes=[]),
        destination(classes=["findings", "findings"]),
        destination(classes=["sms"]),
        destination(classes="findings"),
        destination(kind="security-events", classes=["approvals"]),
        destination(rules=["sensitive-action.v2"]),
        destination(spaces=[str(SPACE)]),
        destination(classes=["findings"], rules=["no-such-rule.v1"]),
        destination(classes=["findings"], rules=["sensitive-action.v2", "sensitive-action.v2"]),
        destination(classes=["findings"], rules=[]),
        destination(classes=["findings"], spaces=[str(SPACE), str(SPACE)]),
        destination(classes=["findings"], messages=["pending"]),
        destination(classes=["findings"], approvers=[str(uuid4())]),
    ],
)
def test_fd7_a_file_outside_the_rules_is_refused_without_quoting_it(tmp_path, bad):
    private = (
        "s3cr3t-hook-secret-value",
        "alerts.example.net",
        "no-such-rule",
        str(SPACE),
        *(str(item) for item in bad.get("approvers", ())),
    )
    with pytest.raises(ValueError) as refused:
        destinations(tmp_path, bad)
    # The validator's own refusal, before the runtime's opaque sentence replaces it.
    with pytest.raises(ValueError) as read:
        read_configuration(write(tmp_path, configuration(bad)))
    for shown in (str(refused.value), str(read.value)):
        assert_secret_free(shown)
        for item in private:
            assert item not in shown


def test_fd7_a_reload_that_changes_classes_rules_or_spaces_is_refused_by_the_shape(tmp_path):
    both = destination(classes=["approvals", "findings"])
    before = read_configuration(write(tmp_path, configuration(both)))
    for changed in (
        destination(),
        destination(classes=["approvals"]),
        destination(classes=["findings"]),
        destination(classes=["approvals", "findings"], rules=["sensitive-action.v2"]),
        destination(classes=["approvals", "findings"], spaces=[str(SPACE)]),
    ):
        after = read_configuration(write(tmp_path, configuration(changed)))
        assert before.shape() != after.shape(), changed


def test_read_outbound_reads_the_destinations_relay_and_origin_alone(tmp_path):
    path = write(tmp_path, configuration(destination(classes=["findings"])))
    outbound = read_outbound(path)
    assert outbound.origin == "http://127.0.0.1:8000"
    assert [(d.destination_id, d.classes) for d in outbound.destinations] == [
        ("soc", frozenset({"findings"}))
    ]
    assert outbound.mail is None and outbound.tls_context is None
    path.write_text('{"not json": "' + KEY, encoding="utf-8")
    with pytest.raises(ValueError) as refused:
        read_outbound(path)
    assert str(refused.value) == "Invalid runtime configuration"
    # Not chained either: the JSON error held as its context would carry the file's text.
    assert refused.value.__context__ is None


def test_read_outbound_reads_the_mail_relay(tmp_path):
    jane = {
        "destination_id": "soc-email-jane",
        "tenant_id": str(TENANT),
        "kind": "email",
        "to": "jane@example.com",
        "classes": ["findings"],
    }
    outbound = read_outbound(write(tmp_path, configuration(jane) | {"mail": MAIL}))
    assert [(d.destination_id, d.kind, d.to) for d in outbound.destinations] == [
        ("soc-email-jane", "email", "jane@example.com")
    ]
    assert outbound.mail == MailConfig(
        host="smtp.resend.com",
        port=465,
        tls="tls",
        username="resend",
        password=PASSWORD,
        sender="no-reply@notify.example.com",
    )
    assert PASSWORD not in repr(outbound)


def test_read_outbound_refuses_one_destination_id_twice_in_a_workspace(tmp_path):
    other = destination(url="https://alerts.example.net/other", classes=["findings"])
    path = write(tmp_path, configuration(destination(), other))
    # The file reads; only the destinations built from it are refused.
    read_configuration(path)
    with pytest.raises(ValueError) as refused:
        read_outbound(path)
    assert str(refused.value) == "Invalid runtime configuration"
    assert refused.value.__context__ is None


@pytest.mark.parametrize("origin", BAD_ORIGINS)
def test_read_outbound_holds_the_origin_to_the_consoles_own_rule(tmp_path, origin):
    """A finding's link is built from the origin, so it is checked as `HumanConfig` checks
    the console's: https, or http on a loopback address, and nothing after the host."""
    value = configuration(destination(classes=["findings"])) | {"origin": origin}
    with pytest.raises(ValueError) as refused:
        read_outbound(write(tmp_path, value))
    assert str(refused.value) == "Invalid runtime configuration"
    assert refused.value.__context__ is None


@pytest.mark.parametrize("origin", UNRENDERABLE_ORIGINS)
def test_read_outbound_holds_the_origin_to_the_finding_messages_rule_too(tmp_path, origin):
    """Every finding's link is built from the origin, and a message holds it to a narrower rule
    than the console's. An origin the console takes and no message renders is refused when the
    file is read, opaquely, so the jobs service runs `monitor-process` without `--deliver` and
    `process --deliver` fails at once, rather than every delivery failing pass after pass."""
    check_origin(origin)
    with pytest.raises(ValueError, match="INVALID_NOTIFICATION"):
        message(origin=origin)
    path = write(tmp_path, configuration(destination(classes=["findings"])) | {"origin": origin})
    with pytest.raises(ValueError) as refused:
        read_outbound(path)
    assert str(refused.value) == "Invalid runtime configuration"
    assert refused.value.__context__ is None and refused.value.__cause__ is None
    assert_secret_free(repr(refused.value), known=(KEY, HOOK))
    assert origin not in repr(refused.value)
    assert schedule.runtime_configured(path) is False


@pytest.mark.parametrize(
    "origin",
    [
        "https://console.example.net",
        "https://Console.Example.NET:8443",
        "https://gateway.example",
        "http://127.0.0.1:8000",
        "http://127.0.0.1",
        "http://[::1]:8000",
    ],
)
def test_read_outbound_still_reads_every_origin_the_fixtures_use(tmp_path, origin):
    """The message's rule refuses none of the origins the console and the fixtures use: a
    finding message renders from each, and `read_outbound` reads the file."""
    assert message(origin=origin).origin == origin
    path = write(tmp_path, configuration(destination(classes=["findings"])) | {"origin": origin})
    assert read_outbound(path).origin == origin
    assert schedule.runtime_configured(path) is True


@pytest.mark.parametrize("origin", BAD_ORIGINS)
def test_the_console_configuration_refuses_an_origin_outside_its_rule(origin):
    """`HumanConfig` reads the same `check_origin` as `read_outbound`, so the rule moved out of
    it still holds the console's own origin. The refusal is the origin's, and the same keys
    with an origin inside the rule are taken."""
    keys = TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)})
    for good in ("https://console.example.net", "http://127.0.0.1:8000"):
        assert HumanConfig(good, keys).origin == good
    with pytest.raises(ValueError, match="origin"):
        HumanConfig(origin, keys)


@pytest.mark.parametrize(
    "classes,expected", [(None, True), (["approvals"], True), (["findings"], False)]
)
def test_fd8_notify_is_scheduled_only_for_an_approval_destination(tmp_path, classes, expected):
    item = destination() if classes is None else destination(classes=classes)
    path = write(tmp_path, configuration(item))
    assert schedule.destinations_configured(path) is expected


def test_the_jobs_service_names_the_approval_kinds_the_notifier_does():
    """`schedule` keeps its own copy of the set, because it does not import `notifications`;
    the import is deferred here for the same cycle, and the configuration module above has
    loaded the execution package first."""
    from execbound import notifications

    assert schedule.APPROVAL_DESTINATION_KINDS == notifications.APPROVAL_KINDS
