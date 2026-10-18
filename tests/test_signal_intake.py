# SPDX-License-Identifier: AGPL-3.0-only
"""The signal intake, `POST /v1/signals`."""

import json
import re
import traceback
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import anyio
import httpx
import pytest
from fastapi.testclient import TestClient
from signal_conformance import reference_envelope
from signal_fixtures import insert_source
from sqlalchemy import text
from test_migration_without_bypass import fenced
from test_resolution import registry as registry
from test_signal_envelope import OPTIONAL, body, raw
from test_structured_logging import captured as captured
from test_structured_logging import events

from execbound.app import create_app
from execbound.runtime import Runtime
from execbound.secrets import find_secrets
from execbound.signals import http as signal_http
from execbound.signals import intake as signal_intake
from execbound.signals.envelope import SecuritySignal, parse_signal, record_digest
from execbound.signals.intake import REFUSALS, SignalError, admit_signal
from execbound.signals.tokens import new_token

pytestmark = pytest.mark.integration

MIGRATION = Path(__file__).parents[1] / "migrations" / "versions" / "0068_security_signals.py"
REFUSED = {"detail": "Signal refused"}
NOT_AN_ENVELOPE = {**REFUSED, "code": "INVALID_ENVELOPE"}


@pytest.fixture
def intake(db, registry, admin_engine, seeded):
    now = datetime.now(UTC)
    tenant = registry["identity"].tenant_id
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        source, token = insert_source(conn, tenant, registry["identity"].principal_id, now)
    with TestClient(create_app(db, runtime=Runtime(db, []))) as client:
        yield {
            **registry,
            "db": db,
            "client": client,
            "tenant": tenant,
            "source": source,
            "token": token,
            "agent_token": seeded["tokens"][0],
        }


def envelope(intake, **changes):
    """The one minimal producer every signal test builds from (`signal_conformance`'s own)."""
    return reference_envelope(intake["account"], **changes)


def post(intake, payload=None, *, token=None, headers=None, raw=None):
    sent = {
        "Authorization": f"Bearer {token or intake['token']}",
        "Content-Type": "application/json",
        **(headers or {}),
    }
    content = raw if raw is not None else json.dumps(payload or envelope(intake)).encode()
    return intake["client"].post("/v1/signals", content=content, headers=sent)


def stored(admin_engine, intake):
    with admin_engine.begin() as conn:
        fenced(conn, intake["tenant"])
        return conn.execute(text("SELECT count(*) FROM execbound.security_signals")).scalar_one()


def health(admin_engine, intake, source=None):
    """What the writer recorded against a source (read as the owner)."""
    with admin_engine.begin() as conn:
        fenced(conn, intake["tenant"])
        return (
            conn.execute(
                text(
                    "SELECT rate_count, record_count, conflict_count, last_accepted_at, "
                    "last_refused_at, last_refusal_code FROM execbound.signal_sources "
                    "WHERE source_id = :s"
                ),
                {"s": source or intake["source"]},
            )
            .mappings()
            .one()
        )


def another_source(admin_engine, intake, **changes):
    with admin_engine.begin() as conn:
        fenced(conn, intake["tenant"])
        return insert_source(
            conn, intake["tenant"], intake["identity"].principal_id, datetime.now(UTC), **changes
        )


def failures(admin_engine, intake):
    with admin_engine.begin() as conn:
        fenced(conn, intake["tenant"])
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT reason, tenant_id, subject_kind, subject_id, count "
                    "FROM execbound.authentication_failures WHERE surface = 'signal'"
                )
            ).mappings()
        ]


def test_accepted_then_a_retry_then_a_conflict(intake, admin_engine):
    body = envelope(intake)
    first = post(intake, body)
    assert first.status_code == 202
    assert first.json()["duplicate"] is False
    assert first.json()["source_event_id"] == body["source_event_id"]
    retry = post(intake, body)
    assert retry.status_code == 200 and retry.json()["duplicate"] is True
    assert retry.json()["received_at"] == first.json()["received_at"]
    conflict = post(intake, {**body, "verdict": "High"})
    assert (conflict.status_code, conflict.json()["code"]) == (409, "CONFLICTING_DUPLICATE")
    assert stored(admin_engine, intake) == 1


@pytest.mark.parametrize(
    "content_type", ["application/json; charset=utf-8", "Application/JSON", "application/JSON"]
)
def test_an_accepted_envelope_answers_its_receipt_and_nothing_else(
    intake, admin_engine, content_type
):
    response = post(intake, headers={"Content-Type": content_type})
    assert response.status_code == 202
    answer = response.json()
    assert set(answer) == {"source_event_id", "received_at", "duplicate", "source_id"}
    assert answer["source_id"] == str(intake["source"])
    assert intake["token"] not in response.text
    row = health(admin_engine, intake)
    assert (row["rate_count"], row["record_count"]) == (1, 1)


@pytest.mark.parametrize(
    "headers,path_suffix",
    [
        ({"x-tenant-id": "00000000-0000-0000-0000-000000000001"}, ""),
        ({"x-principal-id": "00000000-0000-0000-0000-000000000001"}, ""),
        ({"x-role": "ADMIN"}, ""),
        ({"Content-Encoding": "gzip"}, ""),
        ({"Content-Type": "text/plain"}, ""),
        ({}, "?tenant=someone"),
    ],
)
def test_a_request_shaped_outside_the_bounds_is_refused_and_stores_nothing(
    intake, admin_engine, headers, path_suffix
):
    sent = {
        "Authorization": f"Bearer {intake['token']}",
        "Content-Type": "application/json",
        **headers,
    }
    response = intake["client"].post(
        "/v1/signals" + path_suffix, content=json.dumps(envelope(intake)).encode(), headers=sent
    )
    assert response.status_code == 400
    assert stored(admin_engine, intake) == 0


@pytest.mark.parametrize("content_types", [[], ["application/json", "application/json"]])
def test_exactly_one_json_content_type_is_required(intake, admin_engine, content_types):
    sent = [("Authorization", f"Bearer {intake['token']}")] + [
        ("Content-Type", value) for value in content_types
    ]
    response = intake["client"].post(
        "/v1/signals", content=json.dumps(envelope(intake)).encode(), headers=sent
    )
    assert response.status_code == 400
    assert stored(admin_engine, intake) == 0


@pytest.mark.parametrize(
    "raw,answer",
    [
        # Cut off while it is read, before any parsing: the request's own refusal.
        (b"x" * 8193, {"detail": "Invalid signal request"}),
        (b'{"schema_version": "a", "schema_version": "b"}', NOT_AN_ENVELOPE),
        (json.dumps({"confidence": 1.0}).encode(), NOT_AN_ENVELOPE),
    ],
    ids=["oversized", "repeated-key", "float"],
)
def test_a_body_outside_the_envelope_is_refused(intake, admin_engine, raw, answer):
    response = post(intake, raw=raw)
    assert (response.status_code, response.json()) == (400, answer)
    assert stored(admin_engine, intake) == 0


def test_an_envelope_of_exactly_the_bound_is_read_and_one_byte_more_is_not(intake, admin_engine):
    body = json.dumps(envelope(intake)).encode()
    at_bound = body + b" " * (8192 - len(body))
    assert post(intake, raw=at_bound).status_code == 202
    over = post(intake, raw=at_bound + b" ")
    assert (over.status_code, over.json()) == (400, {"detail": "Invalid signal request"})
    assert stored(admin_engine, intake) == 1


@pytest.mark.parametrize("which", ["missing", "agent", "malformed", "revoked"])
def test_only_a_live_producer_token_opens_the_route(intake, admin_engine, which):
    if which == "revoked":
        with admin_engine.begin() as conn:
            fenced(conn, intake["tenant"])
            conn.execute(
                text(
                    "UPDATE execbound.signal_sources SET active = false, revoked_at = now(), "
                    "revoked_by = created_by WHERE source_id = :s"
                ),
                {"s": intake["source"]},
            )
    if which == "missing":
        response = intake["client"].post(
            "/v1/signals",
            content=json.dumps(envelope(intake)).encode(),
            headers={"Content-Type": "application/json"},
        )
    else:
        token = {"agent": intake["agent_token"], "malformed": "sg1.nope"}.get(which)
        response = post(intake, token=token)
    assert response.status_code == 401
    assert stored(admin_engine, intake) == 0


def test_a_request_with_no_credential_is_not_counted(intake, admin_engine):
    response = intake["client"].post(
        "/v1/signals",
        content=json.dumps(envelope(intake)).encode(),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 401
    assert failures(admin_engine, intake) == []


@pytest.mark.parametrize(
    "authorization",
    ["Basic c2cxOm5vcGU=", "bearer {token}", "Bearer {token}" + "x" * 50],
    ids=["another-scheme", "lowercase-scheme", "over-long"],
)
def test_a_credential_of_another_shape_is_refused_before_the_body_is_read(
    intake, admin_engine, authorization
):
    # The body is not an envelope: were the credential's shape checked after reading it, the
    # answer would be the envelope's 400 rather than the credential's 401.
    response = intake["client"].post(
        "/v1/signals",
        content=b"{}",
        headers={
            "Authorization": authorization.format(token=intake["token"]),
            "Content-Type": "application/json",
        },
    )
    assert (response.status_code, response.json()) == (
        401,
        {"detail": "Producer credential required"},
    )
    [failure] = failures(admin_engine, intake)
    assert (failure["reason"], failure["tenant_id"], failure["subject_id"]) == (
        "MALFORMED",
        None,
        None,
    )


def test_a_revoked_token_is_counted_on_the_signal_surface(intake, admin_engine):
    with admin_engine.begin() as conn:
        fenced(conn, intake["tenant"])
        conn.execute(
            text(
                "UPDATE execbound.signal_sources SET active = false, revoked_at = now(), "
                "revoked_by = created_by WHERE source_id = :s"
            ),
            {"s": intake["source"]},
        )
    assert post(intake).status_code == 401
    with admin_engine.begin() as conn:
        fenced(conn, intake["tenant"])
        surfaces = conn.execute(
            text("SELECT surface, reason FROM execbound.authentication_failures")
        ).all()
    assert ("signal", "REVOKED") in [tuple(row) for row in surfaces]


@pytest.mark.parametrize(
    "which,reason,attributed",
    [
        ("unknown source", "UNKNOWN", False),
        ("unknown tenant", "UNKNOWN", False),
        ("wrong secret", "MISMATCH", True),
        ("revoked", "REVOKED", True),
        ("expired", "EXPIRED", True),
        ("inactive tenant", "INACTIVE", True),
        ("malformed", "MALFORMED", False),
        ("agent credential", "MALFORMED", False),
        ("monitoring prefix", "MALFORMED", False),
        ("personal access token prefix", "MALFORMED", False),
        ("human session prefix", "MALFORMED", False),
    ],
)
def test_every_credential_refusal_answers_the_same_and_records_its_reason(
    intake, admin_engine, captured, which, reason, attributed
):
    tenant, source, token = intake["tenant"], intake["source"], intake["token"]
    if which == "unknown source":
        token = new_token(tenant, uuid4())[0]
    elif which == "unknown tenant":
        token = new_token(uuid4(), source)[0]
    elif which == "wrong secret":
        token = new_token(tenant, source)[0]
    elif which == "revoked":
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text(
                    "UPDATE execbound.signal_sources SET active = false, revoked_at = now(), "
                    "revoked_by = created_by WHERE source_id = :s"
                ),
                {"s": source},
            )
    elif which == "expired":
        now = datetime.now(UTC)
        source, token = another_source(
            admin_engine,
            intake,
            created_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
        )
    elif which == "inactive tenant":
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.tenants SET active = false WHERE tenant_id = :t"),
                {"t": tenant},
            )
    elif which == "malformed":
        token = "sg1.nope"
    elif which == "agent credential":
        token = intake["agent_token"]
    else:
        # The live token with only its prefix changed: the shape of another credential kind.
        prefix = {
            "monitoring prefix": "mo1",
            "personal access token prefix": "ebp1",
            "human session prefix": "hs1",
        }[which]
        token = prefix + token[3:]
    response = post(intake, token=token)
    # An unknown source, a wrong secret and every other refusal read alike to the caller.
    assert (response.status_code, response.json()) == (
        401,
        {**REFUSED, "code": "INVALID_SOURCE"},
    )
    assert stored(admin_engine, intake) == 0
    [failure] = failures(admin_engine, intake)
    assert failure["reason"] == reason
    expected = (tenant, "source", source) if attributed else (None, None, None)
    assert (failure["tenant_id"], failure["subject_kind"], failure["subject_id"]) == expected
    # The refusal's own line names the source only once the writer found it: a token naming
    # a source it cannot prove it holds writes no line attributed to that source.
    [line] = events(captured, "signal.refused")
    assert (line["code"], line["source_id"]) == (
        "INVALID_SOURCE",
        str(source) if attributed else None,
    )
    assert token not in captured.getvalue() and intake["token"] not in captured.getvalue()


def test_a_reason_the_intake_does_not_know_is_recorded_without_attribution(
    intake, admin_engine, monkeypatch, captured
):
    monkeypatch.setattr(
        signal_intake,
        "ADMIT",
        text(
            "SELECT jsonb_build_object('refused', 'INVALID_SOURCE', 'reason', 'ELSEWHERE', "
            "'source', CAST(:source AS text))"
        ),
    )
    response = post(intake)
    assert (response.status_code, response.json()) == (401, {**REFUSED, "code": "INVALID_SOURCE"})
    [failure] = failures(admin_engine, intake)
    assert (failure["reason"], failure["tenant_id"], failure["subject_id"]) == (
        "UNKNOWN",
        None,
        None,
    )
    [line] = events(captured, "signal.refused")
    assert (line["code"], line["source_id"]) == ("INVALID_SOURCE", None)


@pytest.mark.parametrize(
    "path,method",
    [
        ("/v1/execute", "post"),
        ("/v1/me", "get"),
        ("/v1/actions", "get"),
        ("/v1/executions/00000000-0000-0000-0000-000000000000", "get"),
        ("/v1/executions/00000000-0000-0000-0000-000000000000/outcome", "post"),
        ("/v1/monitor/events", "post"),
        ("/mcp", "post"),
    ],
)
def test_a_producer_token_opens_no_other_route(intake, path, method):
    response = getattr(intake["client"], method)(
        path,
        headers={"Authorization": f"Bearer {intake['token']}", "Content-Type": "application/json"},
        **({"content": b"{}"} if method == "post" else {}),
    )
    assert response.status_code in {400, 401}
    assert response.status_code != 200


def test_a_field_outside_the_registration_answers_its_code(intake, admin_engine):
    response = post(intake, envelope(intake, producer={"name": "other", "version": "0.1.0"}))
    assert (response.status_code, response.json()["code"]) == (403, "INCOMPATIBLE_PRODUCER")
    future = (datetime.now(UTC) + timedelta(minutes=2)).isoformat()
    response = post(intake, envelope(intake, source_event_id="future", observed_at=future))
    assert (response.status_code, response.json()["code"]) == (400, "FUTURE_OBSERVATION")
    assert stored(admin_engine, intake) == 0


@pytest.mark.parametrize(
    "case,status,code",
    [
        ("subject", 403, "INVALID_SUBJECT"),
        ("version", 403, "INCOMPATIBLE_PRODUCER"),
        ("stale", 400, "STALE_ON_ARRIVAL"),
        ("rate", 429, "SOURCE_RATE_LIMIT"),
        ("capacity", 429, "SOURCE_CAPACITY"),
    ],
)
def test_the_writer_s_refusals_answer_their_codes_and_are_recorded(
    intake, admin_engine, case, status, code
):
    source, token = intake["source"], intake["token"]
    body = envelope(intake)
    if case == "subject":
        body["subject"] = {**body["subject"], "account_id": str(uuid4())}
    elif case == "version":
        body["producer"] = {**body["producer"], "version": "1.0.0"}
    elif case == "stale":
        body["observed_at"] = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    elif case == "rate":
        source, token = another_source(
            admin_engine, intake, rate_window_at=datetime.now(UTC), rate_count=600
        )
    else:
        source, token = another_source(admin_engine, intake, record_count=500000)
    response = post(intake, body, token=token)
    assert (response.status_code, response.json()) == (status, {**REFUSED, "code": code})
    assert stored(admin_engine, intake) == 0
    assert health(admin_engine, intake, source)["last_refusal_code"] == code


def test_the_intake_knows_every_code_the_writer_returns():
    """A code `signal_admit` returns that the intake did not list would answer 503."""
    migration = MIGRATION.read_text()
    returned = set(re.findall(r"'refused', '([A-Z_]+)'", migration)) | set(
        re.findall(r"v_refusal := '([A-Z_]+)'", migration)
    )
    assert returned == REFUSALS | {"INVALID_SOURCE"}
    [recorded] = re.findall(r"last_refusal_code IN \(([^)]*)\)", migration)
    assert set(re.findall(r"'([A-Z_]+)'", recorded)) == REFUSALS


# Every code a producer can be answered with, and its status. The writer's own codes are
# `REFUSALS`; the intake adds three of its own.
STATUS = {
    "INVALID_SOURCE": 401,
    "CAPABILITY_REFUSED": 403,
    "SUBJECT_REFUSED": 403,
    "INCOMPATIBLE_PRODUCER": 403,
    "INVALID_SUBJECT": 403,
    "CONFLICTING_DUPLICATE": 409,
    "SOURCE_RATE_LIMIT": 429,
    "SOURCE_CAPACITY": 429,
    "SIGNAL_UNAVAILABLE": 503,
    "FUTURE_OBSERVATION": 400,
    "STALE_ON_ARRIVAL": 400,
    "INVALID_SIGNAL": 400,
    "INVALID_ENVELOPE": 400,
}


def test_the_status_table_names_every_code():
    assert set(STATUS) == REFUSALS | {"INVALID_SOURCE", "INVALID_ENVELOPE", "SIGNAL_UNAVAILABLE"}


@pytest.mark.parametrize("code,status", sorted(STATUS.items()))
def test_each_refusal_answers_its_status_and_its_code_alone(intake, monkeypatch, code, status):
    # Two of these (`CAPABILITY_REFUSED`, `SUBJECT_REFUSED`) no envelope can reach today: the
    # envelope and the registration each admit one capability and one subject kind.
    def refuse(db, token, signal, clock=None):
        raise SignalError(code)

    monkeypatch.setattr(signal_http, "admit_signal", refuse)
    response = post(intake)
    assert (response.status_code, response.json()) == (status, {**REFUSED, "code": code})


def test_a_writer_that_fails_answers_unavailable_and_stores_nothing(
    intake, admin_engine, monkeypatch, captured
):
    class Skewed:
        # `signal_admit` raises on a receipt time five minutes from its own clock.
        def now(self):
            return datetime.now(UTC) - timedelta(hours=1)

    monkeypatch.setattr(signal_intake, "SystemClock", Skewed)
    response = post(intake)
    assert (response.status_code, response.json()) == (
        503,
        {**REFUSED, "code": "SIGNAL_UNAVAILABLE"},
    )
    assert stored(admin_engine, intake) == 0
    assert intake["token"] not in captured.getvalue()


def test_a_code_the_intake_does_not_know_is_never_passed_through(intake, monkeypatch):
    monkeypatch.setattr(signal_intake, "REFUSALS", frozenset())
    response = post(intake, envelope(intake, producer={"name": "other", "version": "0.1.0"}))
    assert (response.status_code, response.json()) == (
        503,
        {**REFUSED, "code": "SIGNAL_UNAVAILABLE"},
    )


def test_the_log_line_names_the_source_and_never_the_token(intake, captured):
    # `log_event` writes nothing without a handler on the `execbound` logger and carries
    # its record in `extra`, so the structured-logging capture is what reads it back.
    assert post(intake).status_code == 202
    [line] = events(captured, "signal.intake")
    assert line["status"] == 202 and line["source_id"] == str(intake["source"])
    assert intake["token"] not in captured.getvalue()
    [completed] = events(captured, "request.completed")
    assert completed["surface"] == "signal"


def test_a_refusal_is_logged_with_its_code_and_never_the_token(intake, captured):
    response = post(intake, envelope(intake, producer={"name": "other", "version": "0.1.0"}))
    assert response.status_code == 403
    [line] = events(captured, "signal.refused")
    assert line["code"] == "INCOMPATIBLE_PRODUCER"
    assert line["source_id"] == str(intake["source"])
    assert events(captured, "signal.intake") == []
    assert intake["token"] not in captured.getvalue()


@pytest.mark.parametrize("why", ["not an envelope", "secret-shaped"])
def test_both_envelope_refusals_are_logged_alike_naming_no_source(intake, captured, why):
    # Each body carries text of its own that no log line may repeat: a marker in a repeated
    # key, which makes the body unparseable, or a secret-shaped verdict.
    secret = "sk_live_abcdefgh12"
    marker = "zz_marker_7f3"
    raw = (
        b'{"zz_marker_7f3": "a", "zz_marker_7f3": "b"}'
        if why == "not an envelope"
        else json.dumps(envelope(intake, verdict=secret)).encode()
    )
    response = post(intake, raw=raw)
    assert (response.status_code, response.json()) == (400, {**REFUSED, "code": "INVALID_ENVELOPE"})
    [line] = events(captured, "signal.refused")
    assert (line["code"], line["source_id"]) == ("INVALID_ENVELOPE", None)
    assert events(captured, "signal.intake") == []
    logged = captured.getvalue()
    assert logged, "the capture read no log lines"
    assert secret not in logged and marker not in logged and intake["token"] not in logged


# Text the audit export's guard would flag. A producer's own text is frozen into plans and
# carried in audit events, so one that looked like a secret would make the tenant's export
# refuse its window for good; the intake refuses it instead (moved here from the envelope's
# own tests when the envelope module became self-contained).
SECRET_SHAPED = {
    "stripe": "sk_live_abcdefgh12",
    "producer-token": new_token(UUID(int=1), UUID(int=2))[0],
    "bearer": "Bearer abcdefgh1",
}


def test_the_reference_envelope_with_every_field_carries_nothing_secret_shaped():
    signal = parse_signal(raw(body(**OPTIONAL)))
    assert find_secrets(signal.model_dump(mode="json")) == []


def test_an_envelope_with_every_field_is_stored_exactly_as_sent(intake, admin_engine):
    """Every column is the producer's own value. Every value the producer chooses differs from
    the defaults and from every other field, so a value taken from the wrong field or replaced
    by a constant shows."""
    source, token = another_source(admin_engine, intake, registration_version=3)
    observed = datetime.now(UTC).replace(microsecond=123456) - timedelta(seconds=30)
    payload = json.dumps(
        envelope(
            intake,
            source_event_id="device-7f:alert-0042",
            producer={"name": "execbound-mde-producer", "version": "0.4.2"},
            verdict="High",
            confidence=731,
            severity="Sev 2",
            subject={
                "kind": "resource",
                "account_id": str(intake["account"]),
                "provider": "mock_crowdstrike",
                "resource_type": "server",
                "provider_id": "device-7f",
            },
            action="endpoint.isolate",
            observed_at=observed.isoformat(),
            expires_at=(observed + timedelta(minutes=7)).isoformat(),
            attributes={"risk_score": "Medium", "exposure_level": -72, "onboarded": True},
            evidence_ref="mde:machines/device-7f/alerts",
            evidence_digest="0123456789abcdef" * 4,
        )
    ).encode()
    signal = parse_signal(payload)
    response = post(intake, raw=payload, token=token)
    assert response.status_code == 202
    with admin_engine.begin() as conn:
        fenced(conn, intake["tenant"])
        [row] = conn.execute(text("SELECT * FROM execbound.security_signals")).mappings().all()
    subject = signal.subject
    assert dict(row) == {
        "tenant_id": intake["tenant"],
        "source_id": source,
        "source_event_id": "device-7f:alert-0042",
        "record_digest": record_digest(signal),
        "registration_version": 3,
        "producer_name": signal.producer.name,
        "producer_version": "0.4.2",
        "capability": signal.capability,
        "verdict": "High",
        "confidence": 731,
        "severity": "Sev 2",
        "subject_kind": subject.kind,
        "subject_account_id": subject.account_id,
        "subject_provider": subject.provider,
        "subject_resource_type": "server",
        "subject_provider_id": "device-7f",
        "action": "endpoint.isolate",
        # The one field the intake refuses to store (`test_a_request_reference_is_refused_...`).
        "request_reference": None,
        "observed_at": observed,
        "received_at": datetime.fromisoformat(response.json()["received_at"]),
        "expires_at": observed + timedelta(minutes=7),
        "attributes": {"risk_score": "Medium", "exposure_level": -72, "onboarded": True},
        "evidence_ref": "mde:machines/device-7f/alerts",
        "evidence_digest": "0123456789abcdef" * 4,
    }
    # The digest is of the parsed envelope, the one a retry spelled differently matches.
    assert row["record_digest"] == record_digest(parse_signal(payload))


def test_a_request_reference_is_refused_before_the_token_or_the_writer(
    intake, admin_engine, captured
):
    """`resource_compromise.v1` takes no request-scoped record (#478).

    A request's `reference` is the agent's own string, so a record scoped by it would apply to
    whichever agent named it; resolution reads only unscoped records, and the intake refuses
    one rather than store a record that could never apply. The envelope as published still
    carries the field, so this is the intake's capability rule, checked like the secret screen:
    before the token is read and before the writer is called, so it counts against neither the
    source's rate nor its health.
    """
    payload = json.dumps(envelope(intake, request_reference="ticket-9")).encode()
    signal = parse_signal(payload)
    assert signal.request_reference == "ticket-9"
    response = post(intake, raw=payload)
    assert (response.status_code, response.json()) == (400, NOT_AN_ENVELOPE)
    assert stored(admin_engine, intake) == 0
    row = health(admin_engine, intake)
    assert (row["rate_count"], row["last_refused_at"]) == (0, None)
    [line] = events(captured, "signal.refused")
    assert (line["code"], line["source_id"]) == ("INVALID_ENVELOPE", None)
    for token in (intake["token"], "not-a-producer-token"):
        with pytest.raises(SignalError) as caught:
            admit_signal(intake["db"], token, signal)
        assert caught.value.code == "INVALID_ENVELOPE" and caught.value.failure is None
    # The same envelope without the reference is admitted.
    unscoped = json.dumps(envelope(intake, source_event_id="device-01:unscoped")).encode()
    assert post(intake, raw=unscoped).status_code == 202


@pytest.mark.parametrize(
    ("field", "shape"),
    [
        ("source_event_id", "stripe"),
        ("source_event_id", "producer-token"),
        ("verdict", "stripe"),
        ("verdict", "bearer"),
        ("attribute", "stripe"),
        ("attribute", "producer-token"),
    ],
)
def test_secret_shaped_text_is_refused_and_never_quoted(
    intake, admin_engine, captured, field, shape
):
    value = SECRET_SHAPED[shape]
    changes = {"attributes": {"note": value}} if field == "attribute" else {field: value}
    payload = json.dumps(envelope(intake, **changes)).encode()
    # The model and the parser alone accept it, so the refusal below is the intake's screen
    # and not a pattern's.
    SecuritySignal.model_validate_json(payload)
    signal = parse_signal(payload)
    response = post(intake, raw=payload)
    assert (response.status_code, response.json()) == (
        400,
        {**REFUSED, "code": "INVALID_ENVELOPE"},
    )
    assert stored(admin_engine, intake) == 0
    # The screen runs before the writer is called, like any other malformed envelope, so it
    # counts against neither the source's rate nor its health.
    row = health(admin_engine, intake)
    assert (row["rate_count"], row["last_refused_at"]) == (0, None)
    assert value not in response.text and value not in captured.getvalue()
    with pytest.raises(SignalError) as caught:
        admit_signal(intake["db"], intake["token"], signal)
    assert caught.value.code == "INVALID_ENVELOPE" and caught.value.failure is None
    for rendering in (
        str(caught.value),
        repr(caught.value),
        "".join(traceback.format_exception(caught.value)),
    ):
        assert value not in rendering


def test_an_attribute_named_as_a_secret_is_refused(intake, admin_engine):
    payload = json.dumps(envelope(intake, attributes={"password": 1})).encode()
    SecuritySignal.model_validate_json(payload)
    parse_signal(payload)
    response = post(intake, raw=payload)
    assert (response.status_code, response.json()) == (
        400,
        {**REFUSED, "code": "INVALID_ENVELOPE"},
    )
    assert stored(admin_engine, intake) == 0


# The two bounds below need a body that arrives slowly, which the synchronous test client
# cannot send: it reads the whole body before calling the application.
HEADERS = {"Content-Type": "application/json"}


def asgi(db):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(db)), base_url="http://testserver"
    )


def producer_headers():
    return {**HEADERS, "Authorization": "Bearer " + new_token(uuid4(), uuid4())[0]}


@pytest.mark.anyio
async def test_a_slow_body_is_refused_at_its_deadline(db, monkeypatch):
    # The intake's five-second body deadline, shortened here so the test does not wait for it.
    assert signal_http.BODY_DEADLINE_SECONDS == 5
    monkeypatch.setattr(signal_http, "BODY_DEADLINE_SECONDS", 0.2)
    release = anyio.Event()

    async def slow():
        yield b"{"
        with anyio.move_on_after(5):
            await release.wait()
        yield b"}"

    async with asgi(db) as client:
        with anyio.fail_after(3):
            response = await client.post("/v1/signals", content=slow(), headers=producer_headers())
        release.set()
    assert (response.status_code, response.json()) == (400, {"detail": "Invalid signal request"})


@pytest.mark.anyio
async def test_an_endless_body_is_cut_off_at_the_bound(db):
    sent = 0

    async def endless():
        nonlocal sent
        while True:
            sent += 1
            yield b" " * 1024

    async with asgi(db) as client:
        with anyio.fail_after(3):
            response = await client.post(
                "/v1/signals", content=endless(), headers=producer_headers()
            )
    assert (response.status_code, response.json()) == (400, {"detail": "Invalid signal request"})
    # Eight kilobytes and the chunk that would have crossed them, never more.
    assert sent <= 9


@pytest.mark.anyio
async def test_the_ninth_concurrent_intake_is_refused_at_once(db):
    held, release = [], anyio.Event()
    all_held = anyio.Event()

    async def stalled():
        # The route has taken its slot by the time it reads the first chunk.
        held.append(1)
        if len(held) == signal_http.INTAKE_SLOTS:
            all_held.set()
        yield b"{"
        with anyio.move_on_after(5):
            await release.wait()
        yield b"}"

    answers = []

    async def hold(client):
        answers.append(
            await client.post("/v1/signals", content=stalled(), headers=producer_headers())
        )

    async with asgi(db) as client:
        with anyio.fail_after(5):
            async with anyio.create_task_group() as group:
                for _ in range(signal_http.INTAKE_SLOTS):
                    group.start_soon(hold, client)
                await all_held.wait()
                busy = await client.post("/v1/signals", content=b"{}", headers=producer_headers())
                release.set()
            # Every slot is given back: the next request is read, and refused as a body.
            after = await client.post("/v1/signals", content=b"{}", headers=producer_headers())
    assert signal_http.INTAKE_SLOTS == 8
    assert (busy.status_code, busy.json()) == (429, {"detail": "Signal intake busy"})
    assert [answer.status_code for answer in answers] == [400] * 8
    assert (after.status_code, after.json()) == (400, {**REFUSED, "code": "INVALID_ENVELOPE"})
