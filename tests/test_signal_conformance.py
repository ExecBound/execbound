# SPDX-License-Identifier: AGPL-3.0-only
"""The conformance rows against the kernel's reference producer.

SG2 (an unknown, forged or wrong-kind token) and SG3 (a credential refused on the signal
surface and the reverse) both need a live producer token and a live agent token, which
`tests/signal_conformance.py` does not mint to stay usable by a producer's own tests without a
registered source of its own. They are kept here, run against sources and credentials the
fixtures below register for real.
"""

import json
from typing import Any
from uuid import uuid4

import pytest
from signal_conformance import (
    ROW_IDS,
    accepted,
    check,
    conflicting_duplicate,
    reference_envelope,
    rows,
)
from sqlalchemy import text
from test_migration_without_bypass import fenced
from test_resolution import registry as registry
from test_signal_intake import intake as intake
from test_signal_intake import post, stored

from execbound.signals.tokens import new_token


def builder(intake):
    return lambda **changes: reference_envelope(intake["account"], **changes)


def other_tenant(intake, seeded):
    return next(tenant for tenant in seeded["tenants"] if tenant != intake["tenant"])


def count(admin_engine, tenant):
    """Records under one tenant. `admin_engine` connects as the container's superuser, which
    bypasses row-level security altogether, so `fenced()` alone limits nothing for it; the
    `WHERE` clause is what actually counts only `tenant`'s rows."""
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return conn.execute(
            text("SELECT count(*) FROM execbound.security_signals WHERE tenant_id = :t"),
            {"t": tenant},
        ).scalar_one()


def foreign_account(admin_engine, tenant):
    """An account that exists only for `tenant`, for the SG1 rows that imply another one."""
    account = uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts(tenant_id, account_id, provider, "
                "space_id) VALUES (:t, :a, 'mock_crowdstrike', "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
            ),
            {"t": tenant, "a": account},
        )
    return account


def make_send(intake):
    """`signal_conformance.check`'s own `send`: a path, a body and headers in, the response's
    status and parsed JSON out."""

    def send(path: str, body: bytes, headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
        response = intake["client"].post(
            path,
            content=body,
            headers={
                "Authorization": f"Bearer {intake['token']}",
                "Content-Type": "application/json",
                **headers,
            },
        )
        return response.status_code, response.json()

    return send


def test_sg0_the_reference_producer_is_accepted_and_lands_in_its_own_tenant_only(
    intake, admin_engine, seeded
):
    other = other_tenant(intake, seeded)
    send = make_send(intake)
    row = accepted(builder(intake))
    check(row, send)
    retry_status, retry_payload = send("/v1/signals", row.body, {})
    assert retry_status == 200 and retry_payload["duplicate"] is True
    assert count(admin_engine, intake["tenant"]) == 1
    # The account id (UUID(int=10)) exists in both tenants; only the token's own tenant is
    # written to.
    assert count(admin_engine, other) == 0


@pytest.mark.parametrize("row_id", ROW_IDS)
def test_sg1_to_sg9_a_hostile_or_broken_envelope_is_refused_and_stores_nothing(
    intake, admin_engine, seeded, row_id
):
    other = other_tenant(intake, seeded)
    account = foreign_account(admin_engine, other)
    [row] = [
        item
        for item in rows(builder(intake), foreign_account=account, foreign_tenant=other)
        if item.id == row_id
    ]
    check(row, make_send(intake))
    assert stored(admin_engine, intake) == 0
    # The other tenant is untouched whatever the envelope implied or named (SG1 and its
    # header/query variants).
    assert count(admin_engine, other) == 0


def test_sg8_a_conflicting_duplicate_keeps_the_first(intake, admin_engine):
    row = conflicting_duplicate(builder(intake))
    check(row, make_send(intake))
    assert stored(admin_engine, intake) == 1


@pytest.mark.parametrize("token", ["sg1.nope", "mo1.nope", "Basic abc"])
def test_sg2_an_unknown_or_wrong_kind_token_records_nothing(intake, admin_engine, token):
    response = intake["client"].post(
        "/v1/signals",
        content=json.dumps(builder(intake)()).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    assert response.status_code == 401
    assert stored(admin_engine, intake) == 0


@pytest.mark.parametrize(
    "which", ["well-formed-unknown-source", "forged-secret", "another-credential-kind"]
)
def test_sg2_a_token_shaped_right_but_wrong_underneath_records_nothing(intake, admin_engine, which):
    if which == "well-formed-unknown-source":
        # A real tenant, a source no registration names: the digest lookup itself must fail.
        token = new_token(intake["tenant"], uuid4())[0]
    elif which == "forged-secret":
        # The real source, a freshly minted (and therefore wrong) secret: the digest
        # comparison itself must fail, not merely a shape check.
        token = new_token(intake["tenant"], intake["source"])[0]
    else:
        # A monitoring credential's prefix on an otherwise well-formed producer token.
        token = "mo1" + intake["token"][3:]
    response = intake["client"].post(
        "/v1/signals",
        content=json.dumps(builder(intake)()).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    assert response.status_code == 401
    assert stored(admin_engine, intake) == 0


def test_sg3_credentials_are_refused_both_ways(intake, admin_engine):
    assert post(intake, token=intake["agent_token"]).status_code == 401
    execute = intake["client"].post(
        "/v1/execute",
        json={},
        headers={"Authorization": f"Bearer {intake['token']}"},
    )
    assert execute.status_code == 401
    assert stored(admin_engine, intake) == 0
