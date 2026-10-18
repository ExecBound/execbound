# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic asset and ticket exports to context manifests.

The export shapes are generic fixtures for tests and demonstrations; they name no real
inventory or ticketing product, and nothing here talks to a network or a database.
"""

from collections.abc import Mapping
from datetime import datetime
from typing import Any
from uuid import UUID, uuid5

MANIFEST_FORMAT = "execbound.context-manifest.v1"
STATES = {
    "new": "OPEN",
    "in_progress": "OPEN",
    "on_hold": "OPEN",
    "resolved": "CLOSED",
    "closed": "CLOSED",
}
PRIORITIES = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW", 5: "LOW"}
CLASSES = {"endpoint": "endpoint", "identity": "identity"}


class AdapterError(ValueError):
    """The export holds something the adapter will not guess a mapping for."""


def _timestamp(value: object) -> str:
    if type(value) is not str:
        raise AdapterError("Timestamp must be a string")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AdapterError("Timestamp needs a timezone")
    return parsed.isoformat()


def _resource_type(value: object) -> str:
    kind = CLASSES.get(value) if type(value) is str else None
    if kind is None:
        raise AdapterError("Unmapped asset class")
    return kind


def _manifest(
    tenant: UUID, account: UUID, source: UUID, kind: str, writer: str, entries: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "manifest": MANIFEST_FORMAT,
        "tenant_id": str(tenant),
        "account_id": str(account),
        "source_id": str(source),
        "kind": kind,
        "writer": writer,
        "entries": entries,
    }


def inventory_manifest(
    export: Mapping[str, Any],
    *,
    tenant: UUID,
    account: UUID,
    source: UUID,
    writer: str = "inventory_sync",
) -> dict[str, Any]:
    """Assets (identifier, class, attributes, facts, update stamp) to an inventory manifest."""
    observed = _timestamp(export.get("exported_at"))
    entries: list[dict[str, Any]] = []
    for asset in export.get("assets", ()):
        facts = {**asset.get("attributes", {}), **asset.get("facts", {})}
        entry: dict[str, Any] = {
            "provider": asset["provider"],
            "resource_type": _resource_type(asset.get("class")),
            "provider_id": asset["asset_id"],
            "version": _timestamp(asset.get("updated_at")),
            "observed_at": observed,
            "facts": facts,
        }
        if asset.get("decommissioned") is True:
            entry["active"] = False
        if "provider_version" in asset:
            entry["provider_version"] = asset["provider_version"]
        entries.append(entry)
    return _manifest(tenant, account, source, "inventory", writer, entries)


def incident_manifest(
    export: Mapping[str, Any],
    *,
    tenant: UUID,
    account: UUID,
    source: UUID,
    writer: str = "soc_analyst",
) -> dict[str, Any]:
    """Tickets (number, state, priority, affected asset, update stamp) to an incident manifest.

    The incident identifier is `uuid5(source, "<number>:<asset>")`, so a ticket that concerns
    several assets becomes one incident row per asset and re-exports update the same rows.
    """
    observed = _timestamp(export.get("exported_at"))
    entries: list[dict[str, Any]] = []
    for ticket in export.get("tickets", ()):
        status = STATES.get(ticket.get("state")) if type(ticket.get("state")) is str else None
        if status is None:
            raise AdapterError("Unmapped ticket state")
        priority = ticket.get("priority")
        severity = PRIORITIES.get(priority) if type(priority) is int else None
        if severity is None:
            raise AdapterError("Unmapped ticket priority")
        asset = ticket["asset"]
        entries.append(
            {
                "incident_id": str(uuid5(source, f"{ticket['number']}:{asset['asset_id']}")),
                "provider": asset["provider"],
                "resource_type": _resource_type(asset.get("class")),
                "provider_id": asset["asset_id"],
                "version": _timestamp(ticket.get("updated_at")),
                "observed_at": observed,
                "facts": {"incident_status": status, "incident_severity": severity},
            }
        )
    return _manifest(tenant, account, source, "incident", writer, entries)
