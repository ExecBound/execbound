# SPDX-License-Identifier: AGPL-3.0-only
"""The shared conformance rows and a decision each way, with the real producer (#478)."""

import dataclasses
import io
import urllib.error
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import uuid4

import pytest
from execbound_mde_producer import gateway
from execbound_mde_producer.config import CoveredHost
from execbound_mde_producer.defender import project
from execbound_mde_producer.envelope import envelope
from mde_fakes import machine
from signal_conformance import ROW_IDS, accepted, check, conflicting_duplicate, rows
from signal_fixtures import signal_world as signal_world
from test_execution import request
from test_execution import world as world
from test_mde_producer import WIN, configured
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_resolution import registry as registry
from test_runtime import api as api
from test_runtime import runtime as runtime
from test_signal_conformance import make_send
from test_signal_intake import intake as intake
from test_signal_intake import stored


@dataclasses.dataclass
class _Response:
    status: int

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class ClientOpener:
    """`urllib`'s opener shape over a FastAPI test client."""

    def __init__(self, client):
        self.client = client

    def __call__(self, sent, timeout=None):
        answer = self.client.post(
            urlsplit(sent.full_url).path, content=sent.data, headers=dict(sent.header_items())
        )
        if answer.status_code >= 400:
            raise urllib.error.HTTPError(
                sent.full_url,
                answer.status_code,
                "refused",
                answer.headers,
                io.BytesIO(answer.content),
            )
        return _Response(answer.status_code)


def producer_builder(tmp_path, account, risk="Medium"):
    config = dataclasses.replace(
        configured(tmp_path, (CoveredHost(WIN, "device-01"),)), account_id=account
    )

    def build(**changes):
        read = project(machine("m-win", resource=WIN, risk=risk))
        value = envelope(config, config.hosts[0], read, datetime.now(UTC), "0.1.0")
        value.update(changes)
        return value

    return build


def test_the_producers_envelope_is_accepted(intake, admin_engine, tmp_path):
    build = producer_builder(tmp_path, intake["account"])
    check(accepted(build), make_send(intake))
    assert stored(admin_engine, intake) == 1


@pytest.mark.parametrize("row_id", ROW_IDS)
def test_the_producers_envelope_meets_every_conformance_row(intake, admin_engine, tmp_path, row_id):
    build = producer_builder(tmp_path, intake["account"])
    [row] = [item for item in rows(build, foreign_account=uuid4()) if item.id == row_id]
    check(row, make_send(intake))
    assert stored(admin_engine, intake) == 0


def test_the_producers_conflicting_duplicate_keeps_the_first(intake, admin_engine, tmp_path):
    build = producer_builder(tmp_path, intake["account"])
    check(conflicting_duplicate(build), make_send(intake))
    assert stored(admin_engine, intake) == 1


@pytest.mark.parametrize(
    "risk,status,state", [("Medium", 200, "EXECUTED"), ("None", 202, "PENDING_APPROVAL")]
)
def test_the_producers_verdict_decides_through_the_mapping(
    api, db, signal_world, live_provider, tmp_path, risk, status, state
):
    build = producer_builder(tmp_path, signal_world["account"], risk=risk)
    # Observed at the world's clock, the clock the runtime decides on.
    sent = build(observed_at=signal_world["clock"].now().isoformat())
    answer = gateway.post(
        "http://testserver", signal_world["token"], sent, opener=ClientOpener(api)
    )
    assert answer == gateway.Answer(202, None)
    # HTTP admission timestamps receipt with the system clock. Decisions cannot precede it.
    signal_world["clock"].value = datetime.now(UTC)
    executed = api.post("/v1/execute", json=request(signal_world).model_dump(mode="json"))
    assert (executed.status_code, executed.json()["state"]) == (status, state)
