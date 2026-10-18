# SPDX-License-Identifier: AGPL-3.0-only
"""Each notification destination chooses its approval messages (#678, AY11).

No database: the private configuration is read and validated, and refused whole, before any
connection is made. A destination without `messages` behaves exactly as before.
"""

import json
from pathlib import Path
from uuid import UUID

import pytest
from conftest import assert_secret_free
from test_notification_chat import SLACK
from test_notification_email import load

# Through the configuration module, which loads the execution package first: importing
# `execbound.notifications` on its own meets the package's import cycle.
from execbound.surfaces.configuration import Destination, read_configuration

TENANT = "00000000-0000-4000-8000-0000000000a1"
URL = "https://alerts.example.net/execbound/hook"
SECRET = "s3cr3t-hook-secret-value-" + "x" * 20


def destination(**changes: object) -> dict[str, object]:
    return {
        "destination_id": "soc",
        "tenant_id": TENANT,
        "kind": "webhook",
        "url": URL,
        "secret": SECRET,
    } | changes


def configuration(*notifications: dict[str, object]) -> dict[str, object]:
    return {
        "origin": "http://127.0.0.1:8000",
        "active_key_id": "k1",
        "continuation_keys": {"k1": "11" * 32},
        "connectors": [
            {
                "tenant_id": TENANT,
                "account_id": "00000000-0000-4000-8000-0000000000a2",
                "origin": "http://127.0.0.1:9",
                "dispatch_token": "dispatch-" + "d" * 32,
                "control_token": "control-" + "c" * 32,
                "evidence_keys": {"k1": "22" * 32},
            }
        ],
        "notifications": list(notifications),
    }


def write(tmp_path: Path, value: dict[str, object]) -> Path:
    path = tmp_path / "private.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def destinations(tmp_path: Path, *notifications: dict[str, object]) -> tuple[Destination, ...]:
    # The email tests' loader: a database handle nothing answers, since loading connects to none.
    return load(tmp_path, configuration(*notifications)).notifications


def test_ay11_a_destination_without_messages_receives_the_announcement_alone(tmp_path):
    [loaded] = destinations(tmp_path, destination())
    assert loaded.messages == frozenset({"pending"})
    assert Destination("soc", UUID(TENANT), URL, SECRET).messages == frozenset({"pending"})


@pytest.mark.parametrize(
    "messages",
    [["pending", "closed"], ["pending", "reminder", "closed"], ["reminder"], ["closed", "pending"]],
)
def test_ay11_each_allowed_list_loads(tmp_path, messages):
    [loaded] = destinations(tmp_path, destination(messages=messages))
    assert loaded.messages == frozenset(messages)


@pytest.mark.parametrize(
    "bad",
    [
        destination(messages=[]),
        destination(messages=["pending", "pending"]),
        destination(messages=["closed"]),
        destination(messages=["sms"]),
        destination(messages="pending"),
        destination(kind="security-events", messages=["pending"]),
        destination(kind="slack", url=SLACK, secret=None, messages=["closed"]),
    ],
)
def test_ay11_a_list_outside_the_rules_refuses_the_file_without_quoting_it(tmp_path, bad):
    bad = {key: value for key, value in bad.items() if value is not None}
    with pytest.raises(ValueError) as refused:
        destinations(tmp_path, bad)
    shown = str(refused.value)
    assert_secret_free(shown)
    for private in (SECRET, URL, "secretpart", "/services/"):
        assert private not in shown


@pytest.mark.parametrize(
    "changes",
    [
        {"messages": frozenset()},
        {"messages": frozenset({"closed"})},
        {"messages": frozenset({"pending", "sms"})},
        {"messages": ("pending",)},
        {"kind": "security-events", "messages": frozenset({"pending", "closed"})},
    ],
)
def test_ay11_the_destination_holds_the_rules_without_the_file(changes):
    with pytest.raises(ValueError):
        Destination("soc", UUID(TENANT), URL, SECRET, **changes)  # type: ignore[arg-type]


def test_ay11_a_reload_that_changes_messages_is_refused_by_the_shape(tmp_path):
    before = read_configuration(write(tmp_path, configuration(destination())))
    explicit = read_configuration(write(tmp_path, configuration(destination(messages=["pending"]))))
    after = read_configuration(
        write(tmp_path, configuration(destination(messages=["pending", "closed"])))
    )
    assert before.shape() != after.shape()
    assert explicit.shape() != after.shape()
