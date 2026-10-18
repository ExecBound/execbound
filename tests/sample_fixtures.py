# SPDX-License-Identifier: AGPL-3.0-only
"""Shared fixtures for sample targets (#420).

`empty_workspace` is a new workspace (active, no agent limit, one Default space, one ADMIN and
nothing else), written over the owner connection. `password_workspace` makes one the way a
self-hosted operator does, through the owner commands' own functions, for the cases that need
the administrator signed in with a password, as a person is.
"""

import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from conftest import remember_secret
from sqlalchemy import text
from test_execution import provision_credential, provision_identity
from test_protected_path import LiveProvider

from execbound.administration import create_tenant, invite_person
from execbound.execution.models import PreconditionConfig
from execbound.identity import Identity, authenticate
from execbound.passwords import redeem_reset, sign_in_with_password
from execbound.provider.connector import ConnectionConfig
from execbound.provider.mock_store import MockStore
from execbound.provider.sample_accounts import SampleProvider
from execbound.resolution.models import SystemClock
from execbound.runtime import Runtime
from execbound.spaces import default_space
from execbound.surfaces.tokens import TokenKeys

PASSWORD = "correct horse battery staple"


@dataclass(frozen=True)
class Workspace:
    tenant_id: UUID
    space_id: UUID
    admin: Identity


def _fenced(conn, tenant):
    # Limits nothing on an `admin_engine` connection, whose owner bypasses row security
    # (see tenant_fence).
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def empty_workspace(admin_engine, db) -> Workspace:
    tenant, space = uuid4(), uuid4()
    with admin_engine.begin() as conn:
        _fenced(conn, tenant)
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id, name, active) VALUES (:t, :n, true)"),
            {"t": tenant, "n": f"samples-{tenant.hex[:8]}"},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.spaces(tenant_id, space_id, name, created_at, created_by) "
                "VALUES (:t, :s, 'Default', now(), :t)"
            ),
            {"t": tenant, "s": space},
        )
    admin = provision_identity(admin_engine, db, tenant, "ADMIN", datetime.now(UTC))
    return Workspace(tenant, space, admin)


def person(admin_engine, db, workspace, kind="HUMAN_APPROVER") -> Identity:
    """A second person of the workspace, seated in its Default space."""
    return provision_identity(admin_engine, db, workspace.tenant_id, kind, datetime.now(UTC))


def agent_token(admin_engine, workspace, lifetime=timedelta(hours=2)) -> str:
    """A new agent owned by the workspace's Default space, and its bearer token, issued a
    minute ago for ``lifetime``."""
    principal, now = uuid4(), datetime.now(UTC)
    with admin_engine.begin() as conn:
        _fenced(conn, workspace.tenant_id)
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind, space_id) "
                "VALUES (:t, :p, 'AGENT', :s)"
            ),
            {"t": workspace.tenant_id, "p": principal, "s": workspace.space_id},
        )
        return provision_credential(
            conn, workspace.tenant_id, principal, now - timedelta(minutes=1), lifetime
        )


def agent_identity(admin_engine, db, workspace, lifetime=timedelta(hours=2)) -> Identity:
    return authenticate(db, agent_token(admin_engine, workspace, lifetime))


def password_workspace(engine, db, tmp_path, email="sam@example.org") -> Workspace:
    """A workspace made through the owner commands' functions (`tenant-create`, then
    `person-invite` for its first administrator), the administrator's password set from the
    one-time code and signed in with it."""
    tenant = create_tenant(engine, "Sample Lab")
    output = tmp_path / f"admin-{tenant.hex[:8]}.code"
    invite_person(engine, tenant, email, "ADMIN", origin="http://127.0.0.1", output=output)
    redeem_reset(db, output.read_text(encoding="utf-8").strip(), PASSWORD)
    admin = sign_in_with_password(db, email, PASSWORD)
    with db.transaction(admin.tenant_id) as conn:
        space = default_space(conn, admin.tenant_id)
    return Workspace(admin.tenant_id, space, admin)


@pytest.fixture
def sample_key() -> bytes:
    """A fresh sample key, registered so no rendered output may repeat it."""
    key = secrets.token_bytes(32)
    remember_secret(key.hex())
    return key


def offline_runtime(db, key):
    """A runtime whose sample provider is never contacted: install, status and resolution."""
    providers = (
        [] if key is None else [SampleProvider("mock_crowdstrike", "http://127.0.0.1:9", key)]
    )
    return Runtime(
        db,
        [],
        keys=TokenKeys("samples-v1", {"samples-v1": secrets.token_bytes(32)}),
        sample_providers=providers,
    )


ENFORCED = PreconditionConfig({("mock_crowdstrike", "contain"): "ENFORCED_BY_PROVIDER"})


@pytest.fixture
def sample_mock(tmp_path, sample_key):
    """The endpoint mock as a process of its own, holding the sample key and one ordinary
    account of another tenant, which must keep behaving exactly as it did."""
    tenant, account = uuid4(), uuid4()
    dispatch, control = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    journal = secrets.token_bytes(32)
    for value in (dispatch, control, journal.hex()):
        remember_secret(value)
    accounts = tmp_path / "sample-mock-accounts.json"
    accounts.write_text(
        json.dumps(
            [
                {
                    "tenant_id": str(tenant),
                    "account_id": str(account),
                    "dispatch_token_hash": hashlib.sha256(dispatch.encode()).hexdigest(),
                    "control_token_hash": hashlib.sha256(control.encode()).hexdigest(),
                    "signing_key_hex": journal.hex(),
                    "key_id": "journal-v1",
                }
            ]
        ),
        encoding="utf-8",
    )
    database = tmp_path / "sample-mock.sqlite3"
    provider = LiveProvider(
        MockStore(database),
        {
            **os.environ,
            "EXECBOUND_MOCK_DATABASE_PATH": str(database),
            "EXECBOUND_MOCK_ACCOUNTS_PATH": str(accounts),
            "EXECBOUND_MOCK_SAMPLE_KEY": sample_key.hex(),
            "TEST_PROVIDER_INVOCATIONS": str(tmp_path / "sample-invocations.txt"),
            "TEST_PROVIDER_REQUESTS": str(tmp_path / "sample-requests.txt"),
        },
        tmp_path / "sample-provider.ready",
    )
    provider.start()
    provider.config = ConnectionConfig(
        tenant,
        account,
        f"http://127.0.0.1:{provider.port}",
        dispatch,
        control,
        {"journal-v1": journal},
        timeout_seconds=2,
    )
    yield provider
    provider.stop()


@pytest.fixture
def sample_runtime(db, sample_mock, sample_key):
    """A gateway runtime that knows no workspace: only the sample key and the mock's origin."""
    return Runtime(
        db,
        [],
        clock=SystemClock(),
        keys=TokenKeys("samples-v1", {"samples-v1": secrets.token_bytes(32)}),
        preconditions=ENFORCED,
        sample_providers=[
            SampleProvider("mock_crowdstrike", sample_mock.config.origin, sample_key, 2)
        ],
    )


def invocations(provider) -> list[str]:
    """The operation ids the mock's store was asked to dispatch, in order."""
    path = Path(provider.environment["TEST_PROVIDER_INVOCATIONS"])
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []
