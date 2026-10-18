# SPDX-License-Identifier: Apache-2.0
"""Private mock state: mutation, precondition and operation proof share one fence."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from execbound_protocol.catalog import ProviderName
from execbound_protocol.provider import (
    EndpointState,
    EndpointTransition,
    JournalRecord,
    ProviderCommand,
    ProviderError,
    parse_provider,
)


@dataclass(frozen=True)
class MockResource:
    tenant_id: UUID
    canonical_target_id: UUID
    version: str
    contained: bool
    mutation_count: int


class JournalStore:
    """Provider-owned journal and SQLite fence shared by separate physical state stores."""

    provider: ProviderName = "mock_crowdstrike"
    resource_columns: frozenset[str] = frozenset()
    # Every action this store can actually execute; the service refuses to expose a route
    # for a catalog binding outside it.
    dispatch_actions: frozenset[str] = frozenset()

    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        with self._transaction() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS provider_metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1), provider TEXT NOT NULL
                )"""
            )
            conn.execute(
                "INSERT OR IGNORE INTO provider_metadata (singleton, provider) VALUES (1, ?)",
                (self.provider,),
            )
            kind = conn.execute(
                "SELECT provider FROM provider_metadata WHERE singleton = 1"
            ).fetchone()
            if kind["provider"] != self.provider:
                raise ProviderError("INVALID_CONFIGURATION")
            self._initialize_resources(conn)
            actual_columns = frozenset(
                row["name"] for row in conn.execute("PRAGMA table_info(resources)")
            )
            if actual_columns != self.resource_columns:
                raise ProviderError("INVALID_CONFIGURATION")
            conn.execute(
                """CREATE TABLE IF NOT EXISTS representations (
                    tenant_id TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    resource_provider_id TEXT NOT NULL,
                    canonical_target_id TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, account_id, resource_provider_id),
                    FOREIGN KEY (tenant_id, canonical_target_id)
                        REFERENCES resources (tenant_id, canonical_target_id)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS journal (
                    tenant_id TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    command_hash TEXT NOT NULL,
                    command_json TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, account_id, operation_id)
                )"""
            )
            # Accidental runtime SQL cannot overwrite or remove retained operation proof.
            conn.execute(
                """CREATE TRIGGER IF NOT EXISTS journal_immutable_update
                BEFORE UPDATE ON journal BEGIN
                    SELECT RAISE(ABORT, 'Immutable journal');
                END"""
            )
            conn.execute(
                """CREATE TRIGGER IF NOT EXISTS journal_immutable_delete
                BEFORE DELETE ON journal BEGIN
                    SELECT RAISE(ABORT, 'Immutable journal');
                END"""
            )

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA synchronous = FULL")
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
        finally:
            conn.close()

    def provision_representation(
        self,
        tenant_id: UUID,
        account_id: UUID,
        resource_provider_id: str,
        canonical_target_id: UUID,
    ) -> None:
        if not isinstance(resource_provider_id, str) or not 0 < len(resource_provider_id) <= 128:
            raise ProviderError("INVALID_CONFIGURATION")
        with self._transaction() as conn:
            conn.execute(
                """INSERT INTO representations
                    (tenant_id, account_id, resource_provider_id, canonical_target_id)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT (tenant_id, account_id, resource_provider_id) DO UPDATE SET
                        canonical_target_id = excluded.canonical_target_id""",
                (str(tenant_id), str(account_id), resource_provider_id, str(canonical_target_id)),
            )

    @classmethod
    def _command(cls, command: ProviderCommand) -> ProviderCommand:
        # Frozen models still permit model_copy/model_construct; validate every trust crossing.
        command = parse_provider(command.model_dump_json().encode(), ProviderCommand)
        if command.provider != cls.provider:
            raise ProviderError("INVALID_SCOPE")
        return command

    @staticmethod
    def _lookup(conn: sqlite3.Connection, command: ProviderCommand) -> JournalRecord | None:
        row = conn.execute(
            """SELECT command_hash, command_json, record_json FROM journal
            WHERE tenant_id = ? AND account_id = ? AND operation_id = ?""",
            (str(command.tenant_id), str(command.account_id), str(command.operation_id)),
        ).fetchone()
        if row is None:
            return None
        stored = parse_provider(row["command_json"].encode(), ProviderCommand)
        record = parse_provider(row["record_json"].encode(), JournalRecord)
        if row["command_hash"] != stored.command_hash or record.command != stored:
            raise ProviderError("INVALID_JOURNAL")
        if command != stored or command.command_hash != row["command_hash"]:
            raise ProviderError("OPERATION_CONFLICT")
        return record

    @staticmethod
    def _write_record(conn: sqlite3.Connection, record: JournalRecord) -> None:
        command = record.command
        conn.execute(
            """INSERT INTO journal
            (tenant_id, account_id, operation_id, command_hash, command_json, record_json)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (
                str(command.tenant_id),
                str(command.account_id),
                str(command.operation_id),
                command.command_hash,
                command.model_dump_json(),
                record.model_dump_json(),
            ),
        )

    def lookup(self, command: ProviderCommand) -> JournalRecord | None:
        command = self._command(command)
        with self._transaction() as conn:
            return self._lookup(conn, command)

    def cancel(self, command: ProviderCommand) -> JournalRecord:
        command = self._command(command)
        with self._transaction() as conn:
            existing = self._lookup(conn, command)
            if existing is not None:
                return existing
            record = JournalRecord(
                command=command,
                command_hash=command.command_hash,
                outcome="CANCELLED_NOT_EXECUTED",
                occurred_at=datetime.now(UTC),
                resulting_version=None,
                mutation_count=0,
            )
            self._write_record(conn, record)
        return record

    def _initialize_resources(self, conn: sqlite3.Connection) -> None:
        raise NotImplementedError

    def dispatch(self, command: ProviderCommand) -> JournalRecord:
        raise NotImplementedError


_SEED_RESOURCE = """INSERT INTO resources
    (tenant_id, canonical_target_id, version, contained, mutation_count)
    VALUES (?, ?, ?, ?, 0)
    ON CONFLICT (tenant_id, canonical_target_id) DO NOTHING"""
_RESET_RESOURCE = """INSERT INTO resources
    (tenant_id, canonical_target_id, version, contained, mutation_count)
    VALUES (?, ?, ?, ?, 0)
    ON CONFLICT (tenant_id, canonical_target_id) DO UPDATE SET
        version = excluded.version, contained = excluded.contained"""


class MockStore(JournalStore):
    """Private endpoint state; provisioning has no HTTP routes."""

    resource_columns = frozenset(
        {
            "tenant_id",
            "canonical_target_id",
            "version",
            "contained",
            "mutation_count",
        }
    )
    dispatch_actions = frozenset({"endpoint.isolate", "endpoint.lift_isolation"})

    def _initialize_resources(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS resources (
                tenant_id TEXT NOT NULL,
                canonical_target_id TEXT NOT NULL,
                version TEXT NOT NULL,
                contained INTEGER NOT NULL CHECK (contained IN (0, 1)),
                mutation_count INTEGER NOT NULL CHECK (mutation_count >= 0),
                PRIMARY KEY (tenant_id, canonical_target_id)
            )"""
        )

    def provision_resource(
        self,
        tenant_id: UUID,
        canonical_target_id: UUID,
        version: str,
        contained: bool = False,
    ) -> None:
        """Seed a target the first time it is named; never overwrite what the mock holds.

        `boot._provision` runs this on every start, so a target an agent has already acted
        on arrives here again with the file's seeded values. Taking them would put the
        provider back at the seeded version while the gateway's inventory expects the
        receipt's, which strands the target: the next action is refused `VERSION_MISMATCH`,
        settles `STALE_AUTHORIZATION`, and no refresh repairs it because no new receipt
        exists (#350). After the first start the mock's own state is the provider's truth,
        as a real vendor's would be. A deliberate reset is `reprovision_resource`.
        """
        self._write_resource(tenant_id, canonical_target_id, version, contained, reset=False)

    def reprovision_resource(
        self,
        tenant_id: UUID,
        canonical_target_id: UUID,
        version: str,
        contained: bool = False,
    ) -> None:
        """Reset one target to stated values: the operator's repair, asked for by name."""
        self._write_resource(tenant_id, canonical_target_id, version, contained, reset=True)

    def provision_sample(self, command: ProviderCommand, version: str) -> None:
        """A sample account's target, the first time a dispatch names it (#420).

        The mock learns a sample target from the command ExecBound sends for it rather than
        from a file, at the version ExecBound's sample facts record, so the first allowed
        request really executes. Neither row is ever overwritten: after the first dispatch the
        mock's own state is the provider's truth, exactly as `provision_resource` keeps it, and
        versions then change normally.
        """
        command = self._command(command)
        if not isinstance(version, str) or not 0 < len(version) <= 80:
            raise ProviderError("INVALID_CONFIGURATION")
        with self._transaction() as conn:
            conn.execute(
                _SEED_RESOURCE,
                (str(command.tenant_id), str(command.canonical_target_id), version, 0),
            )
            conn.execute(
                """INSERT INTO representations
                    (tenant_id, account_id, resource_provider_id, canonical_target_id)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT (tenant_id, account_id, resource_provider_id) DO NOTHING""",
                (
                    str(command.tenant_id),
                    str(command.account_id),
                    command.resource_provider_id,
                    str(command.canonical_target_id),
                ),
            )

    def _write_resource(
        self,
        tenant_id: UUID,
        canonical_target_id: UUID,
        version: str,
        contained: bool,
        *,
        reset: bool,
    ) -> None:
        if not isinstance(version, str) or not 0 < len(version) <= 80:
            raise ProviderError("INVALID_CONFIGURATION")
        # Two whole statements rather than one with an interpolated clause: the difference
        # between them is the whole point of the split, and a reader should see both.
        # `mutation_count` is untouched by either: it counts what the mock did, and a reset
        # of the stated fields is not a reason to forget that it acted.
        with self._transaction() as conn:
            conn.execute(
                _RESET_RESOURCE if reset else _SEED_RESOURCE,
                (
                    str(tenant_id),
                    str(canonical_target_id),
                    version,
                    int(contained),
                ),
            )

    def resource(self, tenant_id: UUID, canonical_target_id: UUID) -> MockResource | None:
        with self._transaction() as conn:
            row = conn.execute(
                """SELECT version, contained, mutation_count FROM resources
                WHERE tenant_id = ? AND canonical_target_id = ?""",
                (str(tenant_id), str(canonical_target_id)),
            ).fetchone()
            if row is None:
                return None
            return MockResource(
                tenant_id=tenant_id,
                canonical_target_id=canonical_target_id,
                version=row["version"],
                contained=bool(row["contained"]),
                mutation_count=row["mutation_count"],
            )

    def dispatch(self, command: ProviderCommand) -> JournalRecord:
        command = self._command(command)
        with self._transaction() as conn:
            existing = self._lookup(conn, command)
            if existing is not None:
                return existing
            row = conn.execute(
                """SELECT r.version, r.contained FROM resources r
                JOIN representations p
                    ON p.tenant_id = r.tenant_id
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
            if row is None:
                outcome = "TARGET_NOT_FOUND"
            elif resulting_version != command.expected_version:
                outcome = "VERSION_MISMATCH"
            else:
                # Every endpoint action decides its own new state; an action this store
                # cannot execute is refused before any mutation.
                if command.action == "endpoint.isolate":
                    contained = True
                elif command.action == "endpoint.lift_isolation":
                    contained = False
                    transition = EndpointTransition(
                        before=EndpointState(contained=bool(row["contained"])),
                        after=EndpointState(contained=contained),
                    )
                else:
                    raise ProviderError("INVALID_MESSAGE")
                outcome = "EXECUTED"
                resulting_version = str(uuid4())
                cursor = conn.execute(
                    """UPDATE resources SET version = ?, contained = ?,
                    mutation_count = mutation_count + 1
                    WHERE tenant_id = ? AND canonical_target_id = ? AND version = ?""",
                    (
                        resulting_version,
                        int(contained),
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
                endpoint_transition=transition,
            )
            self._write_record(conn, record)
        return record
