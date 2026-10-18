# SPDX-License-Identifier: AGPL-3.0-only
"""Atomic tenant event chains. Keep a trusted head separately to detect truncation."""

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

# Canonical JSON is the protocol's (#496): one definition for every hash.
from execbound_protocol.canonical import canonical_json as canonical_json
from sqlalchemy import text
from sqlalchemy.engine import Connection

GENESIS = "0" * 64


def acted_with(credential: UUID | None) -> dict[str, str]:
    """The credential that acted, as an administration event's payload names it.

    Spread into a payload (`{..., **acted_with(identity.credential_id)}`), it adds the one key
    every administration event uses for this, `actor_credential_id`. The credential is the
    caller's own: a browser session's, or a personal access token's backing credential, which
    belongs to exactly one token, so the token list maps the event to the token's name. An
    owner command acts over the owner connection with no credential and passes `None`, which
    adds nothing.

    Adding the key to an event kind that did not carry it changes future bytes only: a
    retained event is re-hashed from its own retained bytes, so nothing already in a chain
    moves, and replay reads no event's `actor_credential_id`.
    """
    return {} if credential is None else {"actor_credential_id": str(credential)}


def _envelope(row: dict[str, Any]) -> dict[str, Any]:
    occurred_at: datetime = row["occurred_at"]
    return {
        "version": 1,
        "tenant_id": str(row["tenant_id"]),
        "sequence": row["sequence"],
        "event_id": str(row["event_id"]),
        "actor_id": str(row["actor_id"]),
        "kind": row["kind"],
        "occurred_at": occurred_at.astimezone(UTC).isoformat(timespec="microseconds"),
        "payload": row["payload"],
        "previous_hash": row["previous_hash"],
    }


def _event_hash(row: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(_envelope(row)).encode("utf-8")).hexdigest()


def append_event(
    conn: Connection,
    tenant_id: UUID,
    actor_id: UUID,
    kind: str,
    payload: dict[str, Any],
    *,
    space: UUID | None = None,
) -> dict[str, Any]:
    """Caller owns the transaction; an append failure must roll back that transaction.

    ``space`` is written to the row's own column and is **never** part of the hashed
    payload: `_envelope` reads named keys only, so every retained event, every head and
    every export stays byte-identical to what it was before spaces, and there is still one
    chain and one head per tenant.
    """
    if not conn.in_transaction():
        raise ValueError("Audit append requires an explicit tenant transaction")
    if not re.fullmatch(r"[a-z][a-z0-9_.]{0,79}", kind) or type(payload) is not dict:
        raise ValueError("Invalid audit event")
    encoded = canonical_json(payload)
    if len(encoded.encode("utf-8")) > 16384:
        raise ValueError("Audit payload exceeds 16 KiB")
    conn.execute(
        text(
            "INSERT INTO execbound.audit_heads(tenant_id) VALUES (:tenant) "
            "ON CONFLICT (tenant_id) DO NOTHING"
        ),
        {"tenant": tenant_id},
    )
    head = (
        conn.execute(
            text(
                "SELECT sequence, event_hash FROM execbound.audit_heads "
                "WHERE tenant_id = :tenant FOR UPDATE"
            ),
            {"tenant": tenant_id},
        )
        .mappings()
        .one()
    )
    event = {
        "tenant_id": tenant_id,
        "sequence": head["sequence"] + 1,
        "event_id": uuid4(),
        "actor_id": actor_id,
        "kind": kind,
        "occurred_at": conn.execute(text("SELECT clock_timestamp()")).scalar_one(),
        "payload": json.loads(encoded),
        "previous_hash": head["event_hash"],
    }
    event["event_hash"] = _event_hash(event)
    conn.execute(
        text("""
        INSERT INTO execbound.audit_events
          (tenant_id, sequence, event_id, actor_id, kind, occurred_at,
           payload, previous_hash, event_hash, space_id)
        VALUES (:tenant_id, :sequence, :event_id, :actor_id, :kind, :occurred_at,
                CAST(:payload AS jsonb), :previous_hash, :event_hash, :space_id)
    """),
        {**event, "payload": encoded, "space_id": space},
    )
    conn.execute(
        text(
            "UPDATE execbound.audit_heads SET sequence = :sequence, event_hash = :event_hash "
            "WHERE tenant_id = :tenant_id"
        ),
        event,
    )
    return event


def read_events(conn: Connection, tenant_id: UUID) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in conn.execute(
            text(
                "SELECT * FROM execbound.audit_events WHERE tenant_id = :tenant ORDER BY sequence"
            ),
            {"tenant": tenant_id},
        ).mappings()
    ]


class ChainWalk:
    """What `verify_chain` checks of a whole list, checked of one event at a time, so a long
    history is read a page at a time and never has to fit in memory (`audit_verify`).

    `count` is how many events have verified, `previous` the last one's hash and `broken_at`
    the sequence where the walk first failed, after which it accepts nothing. `hashes` keeps
    the hash at each sequence in `wanted`, genesis's at 0 included, so a retained checkpoint
    can be placed on the chain once the walk is done.
    """

    def __init__(self, tenant_id: UUID, wanted: frozenset[int] = frozenset()) -> None:
        self.tenant_id = tenant_id
        self.wanted = wanted
        self.count = 0
        self.previous = GENESIS
        self.broken_at: int | None = None
        self.hashes: dict[int, str] = {0: GENESIS}

    def add(self, event: dict[str, Any]) -> bool:
        if self.broken_at is not None:
            return False
        sequence = self.count + 1
        try:
            intact = (
                event["tenant_id"] == self.tenant_id
                and event["sequence"] == sequence
                and event["previous_hash"] == self.previous
                and _event_hash(event) == event["event_hash"]
            )
        except (ValueError, TypeError, KeyError, AttributeError):
            intact = False
        if not intact:
            self.broken_at = sequence
            return False
        self.count, self.previous = sequence, str(event["event_hash"])
        if sequence in self.wanted:
            self.hashes[sequence] = self.previous
        return True

    def ends_at(self, sequence: int, event_hash: str) -> bool:
        """Whether every event verified and the last is the head the caller trusts."""
        return self.broken_at is None and self.count == sequence and self.previous == event_hash


def verify_chain(
    events: list[dict[str, Any]], tenant_id: UUID, trusted_sequence: int, trusted_hash: str
) -> bool:
    walk = ChainWalk(tenant_id)
    try:
        return all(walk.add(event) for event in events) and walk.ends_at(
            trusted_sequence, trusted_hash
        )
    except (ValueError, TypeError, KeyError, AttributeError):
        return False
