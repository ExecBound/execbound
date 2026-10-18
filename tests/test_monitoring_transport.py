# SPDX-License-Identifier: AGPL-3.0-only
"""Parsing and transport boundaries do not need a database or vendor account."""

import hashlib
import hmac
import json
from uuid import uuid4

import httpx
import pytest

from execbound.monitoring.delivery import LocalReceiver, send_notification
from execbound.monitoring.http import parse_event
from execbound.monitoring.models import MonitorError
from execbound.monitoring.tines import TinesConfig, TinesConfigError, check_connection


def valid_event():
    return {
        "version": 1,
        "event_id": "event-1",
        "story_id": "story-1",
        "occurred_at": "2026-09-14T12:00:00Z",
        "kind": "tool_result",
        "action": "identity.disable",
        "target_ref": "lab-user-17",
        "outcome": "success",
    }


def test_event_parsing_preserves_reported_outcome():
    event = parse_event(json.dumps(valid_event()).encode())
    assert event.action == "identity.disable"
    assert event.outcome == "success"


@pytest.mark.parametrize(
    "payload",
    [
        b'{"event_id":"a","event_id":"b"}',
        b"[]",
        b"null",
        b'{"value":NaN}',
        b'"' + b"x" * 17000 + b'"',
        b"\xff",
    ],
)
def test_parser_rejects_malformed_ambiguous_and_oversize_input(payload):
    with pytest.raises(MonitorError):
        parse_event(payload)


@pytest.mark.parametrize("field", ["tenant_id", "principal_id", "headers", "arguments", "url"])
def test_parser_rejects_undeclared_authority_and_payload_fields(field):
    value = valid_event() | {field: "secret-canary"}
    with pytest.raises(MonitorError) as error:
        parse_event(json.dumps(value).encode())
    assert "secret-canary" not in str(error.value)


@pytest.mark.parametrize("value", ["2026-09-14T12:00:00", 123, None])
def test_occurrence_requires_explicit_timezone(value):
    with pytest.raises(MonitorError):
        parse_event(json.dumps(valid_event() | {"occurred_at": value}).encode())


@pytest.mark.parametrize(
    "url",
    [
        "https://example.org",
        "http://127.0.0.1.evil.test:8200/alerts",
        "http://localhost:8200/alerts",
        "http://127.0.0.1:8200/alerts?to=secret",
        "http://user:pass@127.0.0.1:8200/alerts",
        "http://127.0.0.2:8200/alerts",
    ],
)
def test_local_receiver_rejects_other_destinations(url):
    with pytest.raises(MonitorError):
        LocalReceiver(url, "k" * 32)


def test_sender_signs_exact_bytes_and_does_not_follow_redirects():
    received = []

    def handle(request):
        received.append(request)
        return httpx.Response(302, headers={"location": "http://169.254.169.254/"})

    receiver = LocalReceiver("http://127.0.0.1:8200/alerts", "k" * 32)
    delivery_id = uuid4()
    with httpx.Client(transport=httpx.MockTransport(handle), follow_redirects=False) as client:
        assert not send_notification(receiver, delivery_id, b'{"finding":"synthetic"}', client)
    assert len(received) == 1
    request = received[0]
    assert request.headers["x-execbound-delivery"] == str(delivery_id)
    assert hmac.compare_digest(
        request.headers["x-execbound-signature"],
        hmac.new(
            b"k" * 32,
            request.headers["X-ExecBound-Delivery"].encode() + b"\n" + request.content,
            hashlib.sha256,
        ).hexdigest(),
    )
    assert receiver.secret not in repr(receiver)


def test_sender_accepts_local_receiver_acknowledgement():
    receiver = LocalReceiver("http://127.0.0.1:8200/alerts", "k" * 32)
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(204))) as client:
        assert send_notification(receiver, uuid4(), b"{}", client)


@pytest.mark.parametrize(
    "url",
    [
        "http://lab.tines.com",
        "https://lab.tines.com.evil.test",
        "https://user:password@lab.tines.com",
        "https://lab.tines.com/api/v1",
        "https://127.0.0.1",
        "https://lab.tines.com?token=secret",
    ],
)
def test_tines_config_limits_management_key_destination(url):
    with pytest.raises(TinesConfigError):
        TinesConfig(url, "test-key")


def test_tines_key_file_is_explicit_and_secrets_are_not_returned(tmp_path, monkeypatch):
    path = tmp_path / ".env.tines"
    path.write_text("TINES_BASE_URL=https://lab.tines.com\nTINES_API_KEY=secret-canary\n")
    monkeypatch.setenv("TINES_API_KEY", "wrong-global-key")
    config = TinesConfig.from_file(path)
    received = []

    def handle(request):
        received.append(request)
        return httpx.Response(200, json={"stories": [{"name": "private-story-canary"}]})

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        result = check_connection(config, client)
    assert received[0].method == "GET"
    assert received[0].url.path == "/api/v1/stories"
    assert received[0].headers["x-user-token"] == "secret-canary"
    assert "secret-canary" not in repr(config)
    assert "private-story-canary" not in json.dumps(result)


def test_tines_check_never_follows_redirect_or_returns_error_body():
    calls = []

    def handle(request):
        calls.append(request)
        return httpx.Response(302, headers={"location": "https://evil.test"}, text="secret-canary")

    with httpx.Client(transport=httpx.MockTransport(handle), follow_redirects=True) as client:
        with pytest.raises(TinesConfigError) as error:
            check_connection(TinesConfig("https://lab.tines.com", "key"), client)
    assert len(calls) == 1
    assert "secret-canary" not in str(error.value)
