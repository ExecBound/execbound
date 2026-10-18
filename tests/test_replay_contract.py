# SPDX-License-Identifier: AGPL-3.0-only
"""Offline replay accepts only bounded, versioned, secret-free immutable records."""

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from execbound.audit import GENESIS
from execbound.replay.models import AuditEvent, ReplayExport, TrustedHead
from execbound.replay.verify import ReplayValidationError, parse_export, verify_export


def empty_export():
    tenant = uuid4()
    return ReplayExport(
        tenant_id=tenant,
        events=(),
        head=TrustedHead(tenant_id=tenant, sequence=0, event_hash=GENESIS),
        bundles=(),
    )


def test_empty_export_is_explicit_and_round_trips():
    export = empty_export()
    assert parse_export(export.model_dump_json().encode()) == export
    assert verify_export(export, export.head).complete


@pytest.mark.parametrize("version", [True, 1.0, "1", 0, 2])
def test_export_version_rejects_coercion_or_unknown_values(version):
    value = empty_export().model_dump(mode="json")
    value["version"] = version
    with pytest.raises(ReplayValidationError):
        parse_export(json.dumps(value).encode())


@pytest.mark.parametrize(
    "raw",
    [b"{}", b"[]", b'{"version":1,"version":1}', b'{"number":1.5}', b'{"number":NaN}', b"\xff"],
)
def test_original_json_rejects_incomplete_or_ambiguous_input(raw):
    with pytest.raises(ReplayValidationError):
        parse_export(raw)


def test_audit_payload_is_deeply_immutable():
    event = AuditEvent(
        tenant_id=uuid4(),
        sequence=1,
        event_id=uuid4(),
        actor_id=uuid4(),
        kind="demo.provisioned",
        occurred_at=datetime.now(UTC),
        payload={"nested": {"items": [1, {"safe": True}]}},
        previous_hash=GENESIS,
        event_hash="a" * 64,
    )
    with pytest.raises((TypeError, AttributeError)):
        event.payload["nested"]["items"][1]["safe"] = False
    assert event.model_dump(mode="json")["payload"] == {"nested": {"items": [1, {"safe": True}]}}
    with pytest.raises(ValidationError):
        event.sequence = 2
