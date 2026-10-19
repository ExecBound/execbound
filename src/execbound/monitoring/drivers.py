# SPDX-License-Identifier: AGPL-3.0-only
"""Who drives a directory's non-human actors, and how that is known (#355).

A driver row says what evidence there is that a platform drives an actor, and keeps that apart
from what the actor can reach. Three levels are stored in `monitor_actor_drivers`:

- `declared`: the directory names the driver. The principal's application is in the reviewed AI
  publisher catalog (`publisher:<key>`), or the actor is an agent identity whose blueprint the
  directory names (`blueprint:<application id>`).
- `network`: the actor's successful sign-ins come from a range the reviewed egress catalog
  attributes to a platform (`egress:<key>`), or from an address an administrator of the Space
  recorded as its Tines tenant's egress (`tines:<connection id>`). A match names a platform, never
  a workflow, and no address is stored.
- `joined`: that Tines network evidence, plus the Tines tenant's credentials allowed to call
  Microsoft Graph or Microsoft sign-in, plus every story that references them. Stories share
  credentials, so a join names every such story and never one as the one that acted.

An actor with none of them is unattributed, which is the absence of a row. A row whose condition
ends is marked gone, never deleted, and a condition that holds again clears the mark. Nothing here
raises a finding, admits, approves or settles anything.
"""

import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError

from execbound.audit import acted_with, append_event
from execbound.db import Database
from execbound.execution.scheduled import ScheduledActor
from execbound.identity import Identity
from execbound.monitoring import ai_publishers, egress
from execbound.monitoring.models import MonitorError
from execbound.monitoring.store import (
    DEPENDENCY_ERRORS,
    DIRECTORY_KINDS,
    SYSTEM_CLOCK,
    _administers,
    _check_actor,
    _connection_key,
    _leased,
    _locked_connection,
    _now,
    _session,
    _unleased,
    check_admin,
)
from execbound.resolution.models import Clock
from execbound.spaces import Visibility, space_clause, visible_spaces
from execbound.surfaces.sessions import Session

PUBLISHER_VERSION = f"ai-publishers.{ai_publishers.READ_ON.isoformat()}"
# A join keeps at most this many stories, as Tines lists at most 100 actions for a credential.
MAX_STORIES = 100
# A Tines tenant's egress is at most this many single addresses.
MAX_EGRESS = 8
# The blocks no Tines tenant's egress can be in, from IANA's special-purpose address registries:
# the store refuses an address in any of them, and `admin_set_egress_addresses` holds the same
# list (migration 0098), so the two refuse alike whichever Python reads the address.
NOT_EGRESS = (
    "0.0.0.0/8",  # this network
    "10.0.0.0/8",  # private
    "100.64.0.0/10",  # shared address space
    "127.0.0.0/8",  # loopback
    "169.254.0.0/16",  # link-local
    "172.16.0.0/12",  # private
    "192.0.0.0/24",  # IETF protocol assignments
    "192.0.2.0/24",  # documentation
    "192.88.99.0/24",  # the deprecated 6to4 relay anycast
    "192.168.0.0/16",  # private
    "198.18.0.0/15",  # benchmarking
    "198.51.100.0/24",  # documentation
    "203.0.113.0/24",  # documentation
    "224.0.0.0/4",  # multicast
    "240.0.0.0/4",  # reserved, and the limited broadcast address
    # Everything outside IPv6 global unicast (2000::/3): the unspecified and loopback
    # addresses, IPv4-mapped and translated addresses, discard-only, segment routing,
    # unique-local, link-local and multicast space, and what is not allocated.
    "::/3",
    "4000::/2",
    "8000::/1",
    "2001::/23",  # IETF protocol assignments: Teredo, benchmarking, ORCHID
    "2001:db8::/32",  # documentation
    "2002::/16",  # 6to4
    "3fff::/20",  # documentation
)
_NOT_EGRESS = tuple(ipaddress.ip_network(block) for block in NOT_EGRESS)
BLUEPRINT_LABEL = "Agent identity blueprint"


@dataclass(frozen=True)
class Recorded:
    """The Tines egress a Space recorded, as one sign-in read matches against it: each address
    to the active Tines connections that recorded it, a version that changes whenever any of
    them is recorded again, cleared or revoked, and the connection's sign-in cursor as it stood
    beside them, where the read starts."""

    version: tuple[tuple[str, str], ...]
    addresses: dict[str, tuple[str, ...]]
    cursor: datetime | None = None


_SPACE_EGRESS = text("""
    SELECT t.connection_id, t.egress_recorded_at,
           ARRAY(SELECT host(a) FROM unnest(t.egress_addresses) AS a) AS addresses
    FROM execbound.monitor_connections t
    JOIN execbound.monitor_connections e
      ON e.tenant_id = t.tenant_id AND e.space_id = t.space_id
    WHERE e.tenant_id = :t AND e.connection_id = :c AND e.kind = 'entra_agent_id'
      AND t.kind = 'tines' AND t.active AND t.egress_addresses IS NOT NULL
    ORDER BY t.connection_id
""")


def _recorded(conn: Connection, tenant: UUID, connection_id: UUID) -> Recorded:
    addresses: dict[str, list[str]] = {}
    version = []
    for row in conn.execute(_SPACE_EGRESS, {"t": tenant, "c": connection_id}).mappings():
        version.append((str(row["connection_id"]), row["egress_recorded_at"].isoformat()))
        for address in row["addresses"]:
            canonical = str(ipaddress.ip_address(address))
            addresses.setdefault(canonical, []).append(str(row["connection_id"]))
    return Recorded(
        version=tuple(version),
        addresses={address: tuple(found) for address, found in addresses.items()},
    )


def space_egress(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    *,
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> Recorded:
    """The Tines egress recorded in this Entra connection's own Space, for a sign-in read, with
    the cursor read in the same transaction. Recording egress clears the cursor and changes the
    version together, so a read that starts from this cursor matches against this record: the
    cursor a run found when it began may already have been cleared."""
    try:
        with db.transaction(actor.tenant_id) as conn:
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
            row = _locked_connection(conn, actor.tenant_id, connection_id, lease=lease)
            found = _recorded(conn, actor.tenant_id, connection_id)
            return Recorded(found.version, found.addresses, row["sign_in_cursor"])
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None


def _upsert(
    conn: Connection,
    tenant: UUID,
    *,
    agent_id: UUID,
    evidence: str,
    platform_ref: str,
    source: UUID,
    first: datetime,
    last: datetime,
    catalog_version: str | None = None,
    stories: Sequence[str] = (),
    capped: bool = False,
) -> None:
    """One driver row. A live row's moments are widened to cover what it already held. A gone
    row whose condition holds again is new evidence: its gone mark is cleared and its moments are
    this evidence's alone, so a row an egress change ended never carries the replaced address's
    first sighting into what the new one established."""
    conn.execute(
        text("""
        INSERT INTO execbound.monitor_actor_drivers
            (tenant_id, agent_id, evidence, platform_ref, source_connection_id, detail_refs,
             detail_capped, catalog_version, first_seen_at, last_seen_at)
        VALUES (:t, :a, :evidence, :ref, :source, CAST(:stories AS text[]), :capped, :version,
                :first, :last)
        ON CONFLICT (tenant_id, agent_id, evidence, platform_ref, source_connection_id)
        DO UPDATE SET
            first_seen_at = CASE WHEN monitor_actor_drivers.gone_at IS NULL
                THEN LEAST(monitor_actor_drivers.first_seen_at, EXCLUDED.first_seen_at)
                ELSE EXCLUDED.first_seen_at END,
            last_seen_at = CASE WHEN monitor_actor_drivers.gone_at IS NULL
                THEN GREATEST(monitor_actor_drivers.last_seen_at, EXCLUDED.last_seen_at)
                ELSE EXCLUDED.last_seen_at END,
            detail_refs = EXCLUDED.detail_refs,
            detail_capped = EXCLUDED.detail_capped,
            catalog_version = EXCLUDED.catalog_version,
            gone_at = NULL
    """),
        {
            "t": tenant,
            "a": agent_id,
            "evidence": evidence,
            "ref": platform_ref,
            "source": source,
            "stories": list(stories),
            "capped": capped,
            "version": catalog_version,
            "first": first,
            "last": last,
        },
    )


def _gone(conn: Connection, tenant: UUID, where: str, params: Mapping[str, Any]) -> int:
    """Mark the live rows `where` selects gone; never earlier than a row's first sighting."""
    return conn.execute(
        text(
            "UPDATE execbound.monitor_actor_drivers d "
            "SET gone_at = GREATEST(:now, d.first_seen_at) "
            "WHERE d.tenant_id = :t AND d.gone_at IS NULL AND " + where  # nosec B608 - literals
        ),
        {"t": tenant, **params},
    ).rowcount


def derive_declared(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    *,
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> dict[str, int]:
    """What the directory itself says drives each actor of this connection, from what the store
    holds: the AI publisher catalog's key and an agent identity's blueprint. Run at the end of
    every full collection and delta pass. A row whose principal is gone, or whose key or
    blueprint has changed, is marked gone; so are the connection's network and joined rows for a
    principal that is gone, and its network rows for a catalog entry that no longer matches."""
    now = _now(clock)
    tenant = actor.tenant_id
    counts = {"declared": 0, "gone": 0}
    try:
        with db.transaction(tenant) as conn:
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
            _locked_connection(conn, tenant, connection_id, lease=lease)
            agents = (
                conn.execute(
                    text(
                        "SELECT agent_id, identity_class, blueprint_ref, ai_publisher "
                        "FROM execbound.monitor_agents "
                        "WHERE tenant_id = :t AND connection_id = :c AND gone_at IS NULL"
                    ),
                    {"t": tenant, "c": connection_id},
                )
                .mappings()
                .all()
            )
            wanted: list[tuple[UUID, str]] = []
            for agent in agents:
                if agent["ai_publisher"] is not None:
                    wanted.append((agent["agent_id"], f"publisher:{agent['ai_publisher']}"))
                if agent["identity_class"] == "agent_identity" and agent["blueprint_ref"]:
                    wanted.append((agent["agent_id"], f"blueprint:{agent['blueprint_ref']}"))
            for agent_id, ref in wanted:
                _upsert(
                    conn,
                    tenant,
                    agent_id=agent_id,
                    evidence="declared",
                    platform_ref=ref,
                    source=connection_id,
                    first=now,
                    last=now,
                    catalog_version=PUBLISHER_VERSION if ref.startswith("publisher:") else None,
                )
            counts["declared"] = len(wanted)
            keep = [f"{agent_id}|{ref}" for agent_id, ref in wanted]
            counts["gone"] += _gone(
                conn,
                tenant,
                "d.source_connection_id = :c AND d.evidence = 'declared' "
                "AND NOT (d.agent_id::text || '|' || d.platform_ref = ANY(:keep))",
                {"c": connection_id, "keep": keep, "now": now},
            )
            counts["gone"] += _gone(
                conn,
                tenant,
                "d.source_connection_id = :c AND EXISTS (SELECT 1 FROM execbound.monitor_agents a "
                "WHERE a.tenant_id = d.tenant_id AND a.agent_id = d.agent_id "
                "AND a.gone_at IS NOT NULL)",
                {"c": connection_id, "now": now},
            )
            matching = [f"egress:{p.key}" for p in egress.PRODUCTION.platforms if p.networks]
            counts["gone"] += _gone(
                conn,
                tenant,
                "d.source_connection_id = :c AND d.evidence = 'network' "
                "AND d.platform_ref LIKE 'egress:%' AND NOT (d.platform_ref = ANY(:matching))",
                {"c": connection_id, "matching": matching, "now": now},
            )
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return counts


def _join(conn: Connection, tenant: UUID, connection_id: UUID, now: datetime) -> tuple[int, int]:
    """Bring the connection's joined rows in line with its Tines network rows and the Tines
    tenants' credentials, within the connection's own Space: how many hold, how many went.

    For each live `network` row naming an active Tines connection of the Space, the join names
    every story that references one of that connection's live credentials whose allowed hosts
    include Microsoft Graph or Microsoft sign-in, at most `MAX_STORIES`, and says when that list is
    "at least": when Tines' own cap was reached for a credential, or more stories than the row
    keeps. Its moments are the network row's. No such credential, or a revoked connection, ends
    the join.
    """
    networks = (
        conn.execute(
            text("""
        SELECT d.agent_id, d.platform_ref, d.first_seen_at, d.last_seen_at
        FROM execbound.monitor_actor_drivers d
        JOIN execbound.monitor_connections e
          ON e.tenant_id = d.tenant_id AND e.connection_id = d.source_connection_id
        JOIN execbound.monitor_connections t
          ON t.tenant_id = d.tenant_id AND t.space_id = e.space_id
         AND d.platform_ref = 'tines:' || t.connection_id::text
        WHERE d.tenant_id = :t AND d.source_connection_id = :c AND d.evidence = 'network'
          AND d.gone_at IS NULL AND t.kind = 'tines' AND t.active
    """),
            {"t": tenant, "c": connection_id},
        )
        .mappings()
        .all()
    )
    stories: dict[str, tuple[list[str], bool]] = {}
    held: list[str] = []
    for row in networks:
        ref = row["platform_ref"]
        if ref not in stories:
            found: set[str] = set()
            capped = False
            for credential in conn.execute(
                text(
                    "SELECT story_refs, references_capped FROM execbound.monitor_inventory "
                    "WHERE tenant_id = :t AND connection_id = :tines AND item_kind = 'credential' "
                    "AND gone_at IS NULL AND host_scope = 'microsoft'"
                ),
                {"t": tenant, "tines": UUID(ref.removeprefix("tines:"))},
            ).mappings():
                found.update(credential["story_refs"] or ())
                capped = capped or bool(credential["references_capped"])
            ordered = sorted(found, key=lambda story: (len(story), story))
            stories[ref] = (ordered[:MAX_STORIES], capped or len(ordered) > MAX_STORIES)
        kept, capped = stories[ref]
        if not kept:
            continue
        _upsert(
            conn,
            tenant,
            agent_id=row["agent_id"],
            evidence="joined",
            platform_ref=ref,
            source=connection_id,
            first=row["first_seen_at"],
            last=row["last_seen_at"],
            stories=kept,
            capped=capped,
        )
        held.append(f"{row['agent_id']}|{ref}")
    gone = _gone(
        conn,
        tenant,
        "d.source_connection_id = :c AND d.evidence = 'joined' "
        "AND NOT (d.agent_id::text || '|' || d.platform_ref = ANY(:held))",
        {"c": connection_id, "held": held, "now": now},
    )
    return len(held), gone


def rejoin(conn: Connection, tenant: UUID, tines_connection: UUID, now: datetime) -> None:
    """Bring every join naming this Tines connection in line with its credentials as its
    inventory now holds them, in the inventory's own transaction: a credential no longer allowed
    to call Microsoft, or no longer listed, ends the joins it made, whether or not the directory's
    sign-ins are still read."""
    sources = conn.execute(
        text(
            "SELECT DISTINCT source_connection_id FROM execbound.monitor_actor_drivers "
            "WHERE tenant_id = :t AND platform_ref = :ref AND evidence IN ('network', 'joined') "
            "AND gone_at IS NULL ORDER BY source_connection_id"
        ),
        {"t": tenant, "ref": f"tines:{tines_connection}"},
    ).scalars()
    for source in list(sources):
        _join(conn, tenant, source, now)


def end_tines(conn: Connection, tenant: UUID, tines_connection: UUID, now: datetime) -> int:
    """Mark gone every network and joined row naming this Tines connection, in the transaction
    that revokes it: its recorded egress is no longer what any sign-in is matched against, and
    its credentials join nothing."""
    return _gone(
        conn,
        tenant,
        "d.platform_ref = :ref AND d.evidence IN ('network', 'joined')",
        {"ref": f"tines:{tines_connection}", "now": now},
    )


def end_connection(conn: Connection, tenant: UUID, connection_id: UUID, now: datetime) -> int:
    """Mark gone every row a directory connection's own reads gave its actors, in the transaction
    that removes the synthetic directory (#355, step 4)."""
    return _gone(conn, tenant, "d.source_connection_id = :c", {"c": connection_id, "now": now})


def apply_sign_ins(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    matches: Mapping[tuple[str, str], tuple[datetime, datetime]],
    hints: Mapping[str, tuple[datetime, str]],
    *,
    recorded: Recorded,
    cursor: datetime | None,
    oldest: datetime,
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> dict[str, int]:
    """Keep what one sign-in read established, and nothing it read: the network rows its matches
    give the connection's own principals, each principal's newest user agent hint, the cursor and
    the joins those rows make.

    A match for a principal the connection does not hold live, one the next collection may yet
    inventory, is counted (`unknown_actor`) and not kept, and the cursor waits at the earliest
    such match, no further back than `oldest`, so the read after the inventory holds the
    principal matches it. When the Space's recorded Tines egress is no longer what the read
    matched against (`recorded`), or the cursor it started from has been cleared since, its Tines
    matches are dropped (`stale`) and the cursor is left, so the next read matches what is
    recorded now. The cursor never moves back.
    """
    now = _now(clock)
    tenant = actor.tenant_id
    counts = {"network": 0, "joined": 0, "unknown_actor": 0, "stale": 0}
    try:
        with db.transaction(tenant) as conn:
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
            row = _locked_connection(conn, tenant, connection_id, lease=lease, guarded=True)
            if row["kind"] not in DIRECTORY_KINDS:
                raise MonitorError("INVALID_STATE")
            stale = _recorded(conn, tenant, connection_id).version != recorded.version or (
                row["sign_in_cursor"] is None and recorded.cursor is not None
            )
            agents = {
                str(agent["platform_ref"]).lower(): agent["agent_id"]
                for agent in conn.execute(
                    text(
                        "SELECT agent_id, platform_ref FROM execbound.monitor_agents "
                        "WHERE tenant_id = :t AND connection_id = :c AND gone_at IS NULL"
                    ),
                    {"t": tenant, "c": connection_id},
                ).mappings()
            }
            waiting: datetime | None = None
            for (principal, ref), (first, last) in sorted(matches.items()):
                if stale and ref.startswith("tines:"):
                    counts["stale"] += 1
                    continue
                agent_id = agents.get(principal)
                if agent_id is None:
                    counts["unknown_actor"] += 1
                    waiting = first if waiting is None else min(waiting, first)
                    continue
                _upsert(
                    conn,
                    tenant,
                    agent_id=agent_id,
                    evidence="network",
                    platform_ref=ref,
                    source=connection_id,
                    first=first,
                    last=last,
                    catalog_version=egress.VERSION if ref.startswith("egress:") else None,
                )
                counts["network"] += 1
            for principal, (moment, hint) in sorted(hints.items()):
                agent_id = agents.get(principal)
                if agent_id is None:
                    continue
                conn.execute(
                    text("""
                    UPDATE execbound.monitor_agents
                    SET user_agent_hint = :hint, user_agent_seen_at = :moment
                    WHERE tenant_id = :t AND agent_id = :a
                      AND (user_agent_seen_at IS NULL OR user_agent_seen_at < :moment)
                """),
                    {"t": tenant, "a": agent_id, "hint": hint, "moment": moment},
                )
            if cursor is not None and waiting is not None:
                cursor = min(cursor, max(waiting.replace(microsecond=0), oldest))
            if cursor is not None and not stale:
                if not conn.execute(
                    text("""
                    UPDATE execbound.monitor_connections
                    SET sign_in_cursor = GREATEST(sign_in_cursor, :cursor)
                    WHERE tenant_id = :t AND connection_id = :c
                      AND (CAST(:lease AS uuid) IS NULL OR (collecting_lease = :lease AND active))
                """),
                    {"cursor": cursor, "t": tenant, "c": connection_id, "lease": lease},
                ).rowcount:
                    raise _unleased(conn, tenant, connection_id)
            else:
                _leased(row, lease)
            # The synthetic directory is matched against the egress catalog alone and joins no
            # Tines tenant (#355, step 4): `_recorded` holds no address for it.
            if row["kind"] == "entra_agent_id":
                counts["joined"], _ = _join(conn, tenant, connection_id, now)
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return counts


def egress_addresses(values: object) -> list[str]:
    """What an administrator may record as a Tines tenant's egress: at most `MAX_EGRESS`
    distinct single addresses, none in a block `NOT_EGRESS` names and none in a range the egress
    catalog attributes to a platform, in canonical form and sorted. An empty list clears the
    record."""
    if not isinstance(values, list | tuple) or len(values) > MAX_EGRESS:
        raise MonitorError("INVALID_EGRESS")
    found: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for value in values:
        if type(value) is not str or len(value) > 64:
            raise MonitorError("INVALID_EGRESS")
        try:
            parsed = ipaddress.ip_address(value.strip())
        except ValueError:
            raise MonitorError("INVALID_EGRESS") from None
        if (
            # A zone names an interface on the host that wrote the address, and the database's
            # address type has none.
            getattr(parsed, "scope_id", None) is not None
            or any(parsed in block for block in _NOT_EGRESS)
            or parsed in found
        ):
            raise MonitorError("INVALID_EGRESS")
        if egress.PRODUCTION.match(str(parsed)) is not None:
            # An address a reviewed catalog attributes to another platform cannot be this one's.
            raise MonitorError("EGRESS_CATALOGUED")
        found.add(parsed)
    return [str(address) for address in sorted(found, key=lambda a: (a.version, int(a)))]


_REFUSALS = {
    "INVALID_TENANT": "INVALID_ADMIN",
    "INVALID_ACTOR": "INVALID_ADMIN",
    "INVALID_STATE": "INVALID_STATE",
    "INVALID_EGRESS": "INVALID_EGRESS",
}


def _refusal(exc: DBAPIError) -> MonitorError:
    diagnostic = getattr(exc.orig, "diag", None)
    message = str(getattr(diagnostic, "message_primary", None) or "")
    return MonitorError(_REFUSALS.get(message, "MONITOR_UNAVAILABLE"))


def set_egress_addresses(
    db: Database,
    identity: Identity,
    connection_id: UUID,
    addresses: object,
    *,
    clock: Clock = SYSTEM_CLOCK,
    session: Session | None = None,
) -> list[str]:
    """Record a Tines connection's egress addresses as an administrator of its Space, from the
    command line (`identity`) or the console (`session`, whose Spaces must hold the connection).

    `admin_set_egress_addresses` is the one writer, and checks the actor, the Space and the
    addresses again inside the database. Recording changes what every sign-in of the Space's
    directories is matched against, so the connection's `network` and `joined` rows are marked
    gone and the sign-in cursors of the Space's Microsoft Entra connections are cleared: the next
    read of each looks back thirty days once and matches against what is recorded now. The change
    appends `monitor.egress_recorded`, with how many addresses and never which, as its last write.
    """
    wanted = egress_addresses(addresses)
    now = _now(clock)
    if type(connection_id) is not UUID:
        raise MonitorError("CONNECTION_UNAVAILABLE")
    tenant = identity.tenant_id
    try:
        with db.transaction(tenant) as conn:
            if session is None:
                check_admin(conn, identity, clock=clock)
            else:
                _session(conn, session, clock)
            conn.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                {"key": _connection_key(tenant)},
            )
            row = (
                conn.execute(
                    text(
                        "SELECT space_id, kind, active FROM execbound.monitor_connections "
                        "WHERE tenant_id = :t AND connection_id = :c FOR UPDATE"
                    ),
                    {"t": tenant, "c": connection_id},
                )
                .mappings()
                .one_or_none()
            )
            if row is None or (
                session is not None and not visible_spaces(conn, session).allows(row["space_id"])
            ):
                raise MonitorError("CONNECTION_UNAVAILABLE")
            if not row["active"]:
                raise MonitorError("CONNECTION_REVOKED")
            if row["kind"] != "tines":
                raise MonitorError("INVALID_STATE")
            if not _administers(conn, identity, row["space_id"]):
                raise MonitorError("INVALID_ADMIN")
            conn.execute(
                text("SELECT execbound.admin_set_egress_addresses(:a, :c, CAST(:v AS inet[]))"),
                {"a": identity.principal_id, "c": connection_id, "v": wanted},
            )
            _gone(
                conn,
                tenant,
                "d.platform_ref = :ref AND d.evidence IN ('network', 'joined')",
                {"ref": f"tines:{connection_id}", "now": now},
            )
            conn.execute(
                text("""
                UPDATE execbound.monitor_connections SET sign_in_cursor = NULL
                WHERE tenant_id = :t AND space_id = :s AND kind = 'entra_agent_id'
                  AND sign_in_cursor IS NOT NULL
            """),
                {"t": tenant, "s": row["space_id"]},
            )
            if session is None:
                check_admin(conn, identity, clock=clock)
            else:
                _session(conn, session, clock)
            append_event(
                conn,
                tenant,
                identity.principal_id,
                # A literal, so the replay registration scan (HF31) reads the kind.
                "monitor.egress_recorded",
                {
                    "connection_id": str(connection_id),
                    "addresses": len(wanted),
                    **acted_with(identity.credential_id),
                },
                space=row["space_id"],
            )
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return wanted


def _label(ref: str, tines: Mapping[str, str]) -> dict[str, Any]:
    """What a driver row's platform is called and where its catalog entry was read."""
    kind, _, key = ref.partition(":")
    if kind == "publisher":
        publisher = next((p for p in ai_publishers.PRODUCTION.publishers if p.key == key), None)
        if publisher is not None:
            return {
                "kind": kind,
                "label": publisher.label,
                "source": publisher.source,
                "retrieved": publisher.retrieved,
            }
    if kind == "egress":
        platform = egress.PRODUCTION.platform(key)
        if platform is not None:
            return {
                "kind": kind,
                "label": platform.label,
                "source": platform.source,
                "retrieved": platform.retrieved,
            }
    if kind == "blueprint":
        return {"kind": kind, "label": BLUEPRINT_LABEL, "source": None, "retrieved": None}
    if kind == "tines":
        return {"kind": kind, "label": tines.get(key, "Tines"), "source": None, "retrieved": None}
    return {"kind": kind, "label": key, "source": None, "retrieved": None}


def agent_drivers(
    conn: Connection, tenant: UUID, agent_id: UUID, visibility: Visibility
) -> list[dict[str, Any]]:
    """One actor's driver rows as its detail reads them, strongest evidence first, each with its
    platform's name and, for a Tines tenant, how many of its live credentials carry no host
    restriction: counted and stated, and never joined.

    The actor is the tenant's, and so is what its own directory says of it, but a Tines
    connection, its label and its inventory are its Space's: a `tines:` row is read only when its
    connection is in the Spaces `visibility` holds, under the one helper's predicate the
    Connections view reads by, so the agent page names no Tines tenant its connection page would
    refuse."""
    space = space_clause(visibility, "c")
    rows = [
        dict(row)
        for row in conn.execute(
            text(
                "SELECT d.evidence, d.platform_ref, d.source_connection_id, d.detail_refs, "
                "d.detail_capped, d.catalog_version, d.first_seen_at, d.last_seen_at, d.gone_at "
                "FROM execbound.monitor_actor_drivers d "
                "WHERE d.tenant_id = :t AND d.agent_id = :a "
                "AND (d.platform_ref NOT LIKE 'tines:%' OR EXISTS ("
                "SELECT 1 FROM execbound.monitor_connections c "
                "WHERE c.tenant_id = d.tenant_id AND c.kind = 'tines' "
                "AND d.platform_ref = 'tines:' || c.connection_id::text"
                + space.sql  # nosec B608 - the one helper's predicate; values bound
                + ")) "
                "ORDER BY d.gone_at IS NOT NULL, "
                "CASE d.evidence WHEN 'joined' THEN 0 WHEN 'declared' THEN 1 ELSE 2 END, "
                "d.platform_ref LIMIT 50"
            ),
            {"t": tenant, "a": agent_id, **space.params},
        ).mappings()
    ]
    tines_refs = sorted(
        {
            UUID(row["platform_ref"].removeprefix("tines:"))
            for row in rows
            if row["platform_ref"].startswith("tines:")
        }
    )
    labels: dict[str, str] = {}
    unrestricted: dict[str, int] = {}
    if tines_refs:
        for found in conn.execute(
            text(
                "SELECT c.connection_id, c.label, "
                "(SELECT count(*) FROM execbound.monitor_inventory i "
                "WHERE i.tenant_id = c.tenant_id AND i.connection_id = c.connection_id "
                "AND i.item_kind = 'credential' AND i.gone_at IS NULL "
                "AND i.host_scope = 'unrestricted') AS unrestricted "
                "FROM execbound.monitor_connections c "
                "WHERE c.tenant_id = :t AND c.connection_id = ANY(:ids)" + space.sql  # nosec B608 - the one helper's predicate; values bound
            ),
            {"t": tenant, "ids": tines_refs, **space.params},
        ).mappings():
            labels[str(found["connection_id"])] = found["label"]
            unrestricted[str(found["connection_id"])] = int(found["unrestricted"])
    for row in rows:
        named = _label(row["platform_ref"], labels)
        row.update(named)
        row["detail_refs"] = list(row["detail_refs"] or [])
        row["unrestricted_credentials"] = (
            unrestricted.get(row["platform_ref"].removeprefix("tines:"))
            if named["kind"] == "tines"
            else None
        )
    return rows


# The order the agent detail lists driver rows in, which the Agents page's one row follows: the
# join names stories, the directory's own declaration a template or a publisher, and a network
# match a platform alone.
_PRECEDENCE = "CASE d.evidence WHEN 'joined' THEN 0 WHEN 'declared' THEN 1 ELSE 2 END"


def agents_summary(
    conn: Connection, tenant: UUID, agent_ids: Sequence[UUID], visibility: Visibility
) -> dict[UUID, dict[str, Any]]:
    """Each actor's strongest current driver row the session may see, as the Agents page shows it
    (#355, step 4), with how many more current rows it may see: `driver` holds its level, kind
    and label, and `tines` whether any of those rows is a Tines tenant's, strongest or not, for
    the Tines Gate recipe's pointer the agent detail gives on the same rows. A `tines:` row is
    seen only when its connection is in the Spaces `visibility` holds, as on the agent detail.
    An actor with none is absent: unattributed."""
    if not agent_ids:
        return {}
    space = space_clause(visibility, "c")
    rows = conn.execute(
        text(
            "SELECT d.agent_id, d.evidence, d.platform_ref, c.label AS tines_label "
            "FROM execbound.monitor_actor_drivers d "
            "LEFT JOIN execbound.monitor_connections c "
            "  ON c.tenant_id = d.tenant_id AND c.kind = 'tines' "
            " AND d.platform_ref = 'tines:' || c.connection_id::text "
            "WHERE d.tenant_id = :t AND d.agent_id = ANY(:ids) AND d.gone_at IS NULL "
            "AND (d.platform_ref NOT LIKE 'tines:%' OR (c.connection_id IS NOT NULL"
            + space.sql  # nosec B608 - the one helper's predicate; values bound
            + ")) ORDER BY d.agent_id, "
            + _PRECEDENCE
            + ", d.platform_ref"
        ),
        {"t": tenant, "ids": list(agent_ids), **space.params},
    ).mappings()
    found: dict[UUID, dict[str, Any]] = {}
    for row in rows:
        from_tines = row["platform_ref"].startswith("tines:")
        held = found.get(row["agent_id"])
        if held is not None:
            held["more"] += 1
            held["tines"] = held["tines"] or from_tines
            continue
        tines = {row["platform_ref"].removeprefix("tines:"): row["tines_label"] or "Tines"}
        named = _label(row["platform_ref"], tines)
        found[row["agent_id"]] = {
            "driver": {"evidence": row["evidence"], "kind": named["kind"], "label": named["label"]},
            "more": 0,
            "tines": from_tines,
        }
    return found
