# SPDX-License-Identifier: Apache-2.0
"""Private identity state with one atomic version, transition and journal fence."""

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from execbound_protocol.catalog import ProviderName
from execbound_protocol.provider import (
    CredentialState,
    CredentialTransition,
    IdentityState,
    IdentityTransition,
    JournalRecord,
    ProviderCommand,
    ProviderError,
)

from execbound_connectors.mock_store import JournalStore


@dataclass(frozen=True)
class MockIdentity:
    tenant_id: UUID
    canonical_target_id: UUID
    version: str
    account_enabled: bool
    session_generation: int
    password_generation: int
    must_change_password: bool
    mutation_count: int


_SEED_IDENTITY = """INSERT INTO resources
    (tenant_id, canonical_target_id, version, account_enabled, session_generation,
        mutation_count)
    VALUES (?, ?, ?, ?, ?, 0)
    ON CONFLICT (tenant_id, canonical_target_id) DO NOTHING"""
_RESET_IDENTITY = """INSERT INTO resources
    (tenant_id, canonical_target_id, version, account_enabled, session_generation,
        mutation_count)
    VALUES (?, ?, ?, ?, ?, 0)
    ON CONFLICT (tenant_id, canonical_target_id) DO UPDATE SET
        version = excluded.version, account_enabled = excluded.account_enabled,
        session_generation = excluded.session_generation"""


class IdentityStore(JournalStore):
    provider: ProviderName = "mock_entra"
    resource_columns = frozenset(
        {
            "tenant_id",
            "canonical_target_id",
            "version",
            "account_enabled",
            "session_generation",
            "password_generation",
            "must_change_password",
            "mutation_count",
        }
    )
    dispatch_actions = frozenset(
        {
            "identity.disable",
            "identity.enable",
            "identity.revoke_sessions",
            "identity.reset_password",
        }
    )

    def _initialize_resources(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS resources (
                tenant_id TEXT NOT NULL,
                canonical_target_id TEXT NOT NULL,
                version TEXT NOT NULL,
                account_enabled INTEGER NOT NULL CHECK (account_enabled IN (0, 1)),
                session_generation INTEGER NOT NULL CHECK (session_generation >= 0),
                mutation_count INTEGER NOT NULL CHECK (mutation_count >= 0),
                password_generation INTEGER NOT NULL DEFAULT 0
                    CHECK (password_generation >= 0),
                must_change_password INTEGER NOT NULL DEFAULT 0
                    CHECK (must_change_password IN (0, 1)),
                PRIMARY KEY (tenant_id, canonical_target_id)
            )"""
        )
        existing = {row["name"] for row in conn.execute("PRAGMA table_info(resources)")}
        for column, definition in (
            ("password_generation", "INTEGER NOT NULL DEFAULT 0 CHECK (password_generation >= 0)"),
            (
                "must_change_password",
                "INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0, 1))",
            ),
        ):
            if column not in existing:
                # Stores created before credential evidence existed keep their rows.
                conn.execute(f"ALTER TABLE resources ADD COLUMN {column} {definition}")

    def provision_resource(
        self,
        tenant_id: UUID,
        canonical_target_id: UUID,
        version: str,
        account_enabled: bool = True,
        session_generation: int = 0,
    ) -> None:
        """Seed a target the first time it is named; never overwrite what the mock holds.

        `boot._provision` runs this on every start, so a target an agent has already acted
        on arrives here again with the file's seeded values. Taking them would put the
        provider back at the seeded version while the gateway's inventory expects the
        receipt's, which strands the target: the next action is refused `VERSION_MISMATCH`,
        settles `STALE_AUTHORIZATION`, and no refresh repairs it because no new receipt
        exists (#350). A disabled identity also read as enabled again, so the provider
        contradicted the audit chain's record of what had been done. A deliberate reset is
        `reprovision_resource`.
        """
        self._write_resource(
            tenant_id,
            canonical_target_id,
            version,
            account_enabled,
            session_generation,
            reset=False,
        )

    def reprovision_resource(
        self,
        tenant_id: UUID,
        canonical_target_id: UUID,
        version: str,
        account_enabled: bool = True,
        session_generation: int = 0,
    ) -> None:
        """Reset one target to stated values: the operator's repair, asked for by name."""
        self._write_resource(
            tenant_id,
            canonical_target_id,
            version,
            account_enabled,
            session_generation,
            reset=True,
        )

    def _write_resource(
        self,
        tenant_id: UUID,
        canonical_target_id: UUID,
        version: str,
        account_enabled: bool,
        session_generation: int,
        *,
        reset: bool,
    ) -> None:
        if (
            not isinstance(version, str)
            or not 0 < len(version) <= 80
            or type(account_enabled) is not bool
            or type(session_generation) is not int
            or not 0 <= session_generation < 2**63 - 1
        ):
            raise ProviderError("INVALID_CONFIGURATION")
        # Two whole statements rather than one with an interpolated clause: the difference
        # between them is the whole point of the split, and a reader should see both.
        # `mutation_count` is untouched by either: it counts what the mock did, and a reset
        # of the stated fields is not a reason to forget that it acted.
        with self._transaction() as conn:
            conn.execute(
                _RESET_IDENTITY if reset else _SEED_IDENTITY,
                (
                    str(tenant_id),
                    str(canonical_target_id),
                    version,
                    int(account_enabled),
                    session_generation,
                ),
            )

    def resource(self, tenant_id: UUID, canonical_target_id: UUID) -> MockIdentity | None:
        with self._transaction() as conn:
            row = conn.execute(
                """SELECT version, account_enabled, session_generation, mutation_count,
                    password_generation, must_change_password
                FROM resources WHERE tenant_id = ? AND canonical_target_id = ?""",
                (str(tenant_id), str(canonical_target_id)),
            ).fetchone()
            if row is None:
                return None
            return MockIdentity(
                tenant_id,
                canonical_target_id,
                row["version"],
                bool(row["account_enabled"]),
                row["session_generation"],
                row["password_generation"],
                bool(row["must_change_password"]),
                row["mutation_count"],
            )

    def dispatch(self, command: ProviderCommand) -> JournalRecord:
        command = self._command(command)
        with self._transaction() as conn:
            existing = self._lookup(conn, command)
            if existing is not None:
                return existing
            row = conn.execute(
                """SELECT r.version, r.account_enabled, r.session_generation,
                    r.password_generation, r.must_change_password FROM resources r
                JOIN representations p ON p.tenant_id = r.tenant_id
                    AND p.canonical_target_id = r.canonical_target_id
                WHERE p.tenant_id = ? AND p.account_id = ? AND p.resource_provider_id = ?
                    AND r.canonical_target_id = ?""",
                (
                    str(command.tenant_id),
                    str(command.account_id),
                    command.resource_provider_id,
                    str(command.canonical_target_id),
                ),
            ).fetchone()
            resulting_version = None if row is None else str(row["version"])
            outcome: Literal["TARGET_NOT_FOUND", "VERSION_MISMATCH", "EXECUTED"]
            transition = None
            credential = None
            if row is None:
                outcome = "TARGET_NOT_FOUND"
            elif resulting_version != command.expected_version:
                outcome = "VERSION_MISMATCH"
            else:
                reset = command.action == "identity.reset_password"
                before = IdentityState(
                    account_enabled=bool(row["account_enabled"]),
                    session_generation=row["session_generation"],
                )
                # Every identity action states its own effect; an action this store cannot
                # execute is refused before any mutation.
                if command.action == "identity.enable":
                    enabled, generation = True, before.session_generation
                elif command.action == "identity.disable":
                    enabled, generation = False, before.session_generation
                elif command.action == "identity.revoke_sessions":
                    enabled, generation = before.account_enabled, before.session_generation + 1
                elif reset:
                    enabled, generation = before.account_enabled, before.session_generation
                else:
                    raise ProviderError("INVALID_MESSAGE")
                after = IdentityState(account_enabled=enabled, session_generation=generation)
                transition = IdentityTransition(before=before, after=after)
                credential_before = CredentialState(
                    password_generation=row["password_generation"],
                    must_change_password=bool(row["must_change_password"]),
                )
                credential_after = credential_before
                if reset:
                    # The mock never generates, stores, returns or logs a password; the
                    # generation counter is the only evidence that the secret changed.
                    credential_after = CredentialState(
                        password_generation=credential_before.password_generation + 1,
                        must_change_password=bool(
                            command.arguments.root["require_change_at_next_sign_in"]
                        ),
                    )
                    credential = CredentialTransition(
                        before=credential_before, after=credential_after
                    )
                outcome = "EXECUTED"
                resulting_version = str(uuid4())
                cursor = conn.execute(
                    """UPDATE resources SET version = ?, account_enabled = ?,
                        session_generation = ?, password_generation = ?,
                        must_change_password = ?, mutation_count = mutation_count + 1
                    WHERE tenant_id = ? AND canonical_target_id = ? AND version = ?""",
                    (
                        resulting_version,
                        int(after.account_enabled),
                        after.session_generation,
                        credential_after.password_generation,
                        int(credential_after.must_change_password),
                        str(command.tenant_id),
                        str(command.canonical_target_id),
                        command.expected_version,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ProviderError("INVALID_STATE")
            record = JournalRecord(
                command=command,
                command_hash=command.command_hash,
                outcome=outcome,
                occurred_at=datetime.now(UTC),
                resulting_version=resulting_version,
                mutation_count=1 if outcome == "EXECUTED" else 0,
                identity_transition=transition,
                credential_transition=credential,
            )
            self._write_record(conn, record)
        return record
