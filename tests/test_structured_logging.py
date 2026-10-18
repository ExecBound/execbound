# SPDX-License-Identifier: AGPL-3.0-only
"""Schema-only structured logs with request identifiers: SE1 to SE4."""

import io
import json
import logging
import secrets
from uuid import UUID, uuid4

import pytest
from test_execution import registry as registry
from test_execution import request
from test_execution import world as world
from test_monitoring_http import monitor_web as monitor_web
from test_monitoring_http import post_event
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import api as api
from test_runtime import runtime as runtime

from execbound import logging_schema
from execbound.execution import activate_stop, release_stop


@pytest.fixture
def captured():
    stream = io.StringIO()
    handler = logging_schema.capture_handler(stream)
    logger = logging.getLogger("execbound")
    logger.addHandler(handler)
    try:
        yield stream
    finally:
        logger.removeHandler(handler)


def records(stream):
    return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]


def events(stream, name):
    return [r for r in records(stream) if r["event"] == name]


def test_se1_requests_carry_identifiers_and_the_response_echoes_them(api, world, captured):
    supplied = str(uuid4())
    response = api.post(
        "/v1/execute",
        json=request(world).model_dump(mode="json"),
        headers={"X-Request-Id": supplied},
    )
    assert response.status_code == 202 and response.headers["X-Request-Id"] == supplied
    [completed] = events(captured, "request.completed")
    assert completed["request_id"] == supplied and completed["surface"] == "http"
    assert completed["status"] == 202 and isinstance(completed["duration_ms"], int)
    [executed] = events(captured, "execute.completed")
    assert executed["request_id"] == supplied and executed["state"] == "PENDING_APPROVAL"
    assert executed["tenant_id"] == str(world["identity"].tenant_id)
    UUID(executed["execution_id"])
    status = api.get(
        "/v1/executions/" + response.json()["execution_id"], headers={"X-Request-Id": "not a uuid"}
    )
    assert status.status_code == 202
    replaced = status.headers["X-Request-Id"]
    assert replaced != "not a uuid" and UUID(replaced)
    assert events(captured, "status.completed")[-1]["request_id"] == replaced
    for record in records(captured):
        assert set(record) <= logging_schema.FIELDS
        assert "message" not in record and record["event"] in logging_schema.EVENTS


@pytest.mark.parametrize(
    "fields",
    [
        {"token": "Bearer " + secrets.token_urlsafe(16)},
        {"code": f"eb1.{uuid4()}.{uuid4()}.{secrets.token_urlsafe(32)}"},
        {"reason": "postgresql+psycopg://user:pw@db/execbound"},
        {"hostname": "WS01.EXAMPLE."},
    ],
)
def test_se2_records_with_secrets_or_unknown_fields_are_suppressed(captured, fields):
    logging_schema.log_event("execute.completed", state="PENDING_APPROVAL", **fields)
    logging_schema.log_event("not.in.catalog", status=200)
    suppressed = events(captured, "log.suppressed")
    assert len(suppressed) == 2 and all(r["level"] == "WARNING" for r in suppressed)
    text = captured.getvalue()
    for value in fields.values():
        assert value not in text
    assert "not.in.catalog" not in text
    assert {r["reason"] for r in suppressed} == {"UNKNOWN_FIELD", "UNKNOWN_EVENT"} or {
        r["reason"] for r in suppressed
    } == {"PRIVATE_TEXT", "UNKNOWN_EVENT"}


def test_se3_a_logging_failure_never_changes_the_outcome(api, world, captured, monkeypatch):
    def explode(*args, **kwargs):
        raise RuntimeError("formatter broken")

    monkeypatch.setattr(logging_schema, "_serialize", explode)
    response = api.post("/v1/execute", json=request(world).model_dump(mode="json"))
    assert response.status_code == 202 and response.json()["state"] == "PENDING_APPROVAL"
    assert "Traceback" not in captured.getvalue()


def test_se4_security_events_log_only_identifiers_codes_and_counts(
    api, world, db, monitor_web, captured
):
    tenant = world["identity"].tenant_id
    wrong = f"eb1.{tenant}.{world['identity'].credential_id}.{secrets.token_urlsafe(32)}"
    api.headers.pop("Authorization", None)
    probe = "/v1/executions/" + str(uuid4())
    assert api.get(probe, headers={"Authorization": "Bearer " + wrong}).status_code == 401
    [refused] = events(captured, "authentication.refused")
    assert refused["surface"] == "http" and refused["reason"] == "MISMATCH"
    assert wrong not in captured.getvalue()
    activate_stop(db, world["admin"], "Incident <b>7</b>", world["clock"])
    release_stop(db, world["admin"], "Closed", world["clock"])
    [activated] = events(captured, "stop.activated")
    [released] = events(captured, "stop.released")
    assert activated["tenant_id"] == str(tenant) and "Incident" not in captured.getvalue()
    assert released["principal_id"] == str(world["admin"].principal_id)
    client, admin, source, _ = monitor_web
    assert post_event(client, source).status_code == 202
    [intake] = events(captured, "monitor.intake")
    assert intake["status"] == 202 and intake["source_id"] == str(source.source_id)
    assert source.token not in captured.getvalue()


def test_the_standard_error_handler_follows_stderr_rather_than_the_one_it_was_installed_with(
    monkeypatch, capsys
):
    """`install` is called once, and the stream it was given can be replaced or closed.

    Under pytest that is routine: capture is per test, so the handler installed during one
    test holds a stream that is closed before the next one runs. Every later `log_event`
    then wrote to a dead file, and `logging` printed a traceback for each rather than
    raising, which `log_event`'s own `except` could never see. A full suite emitted 125 of
    them, and they are the noise a real failure has to be found in.
    """
    logger = logging.getLogger("execbound")
    saved = logger.handlers[:]
    for handler in saved:
        logger.removeHandler(handler)
    try:
        installed_with = io.StringIO()
        monkeypatch.setattr("sys.stderr", installed_with)
        logging_schema.install()
        installed_with.close()

        now = io.StringIO()
        monkeypatch.setattr("sys.stderr", now)
        logging_schema.log_event("mock.reprovisioned", canonical_target_id="t")

        output = now.getvalue()
        assert "Logging error" not in output, "logging printed a traceback instead of a record"
        written = [json.loads(line) for line in output.splitlines() if line.strip()]
        assert [r["event"] for r in written] == ["mock.reprovisioned"]
    finally:
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        for handler in saved:
            logger.addHandler(handler)
