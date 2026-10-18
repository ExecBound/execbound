# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit, bounded, read-only collection from the Tines management API.

Every request is a ``GET`` to the connection's pinned origin with redirects, ambient proxies
and in-run retries disabled and the body and time bounded. Every response passes a field
allowlist before anything is retained, so configuration options, audit inputs and outputs,
response text, addresses, user agents and email addresses never reach memory beyond the
response buffer. Collection produces evidence: nothing here admits, approves, settles,
reserves or refunds, and no execution privilege is used.
"""

import hashlib
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import httpx

from execbound.db import Database
from execbound.execution.scheduled import ScheduledActor
from execbound.identity import Identity
from execbound.monitoring import store
from execbound.monitoring.models import (
    AI_MODEL_OPERATION,
    AI_TOOL_OPERATION,
    CHANGE_CLASSES,
    LOCAL_ACTION_TYPES,
    OUTBOUND_ACTION_TYPES,
    TINES_OPERATIONS,
    MonitorError,
)
from execbound.resolution.models import Clock, SystemClock

MAX_BODY = 4 * 1024 * 1024
TIMEOUT = 10.0
PAGE_SIZE = 100
MAX_STORIES = 500
MAX_ACTIONS = 5000
MAX_CREDENTIALS = 500
MAX_AUDIT_PAGES = 200
# The vendor's shortest configurable audit retention; the first run starts no earlier.
RETENTION_FLOOR = timedelta(days=30)
# Re-reading this much before the cursor makes a page boundary or a crash safe to repeat.
OVERLAP = timedelta(minutes=5)
SYNC_INTERVAL = timedelta(days=1)

CAPABILITIES = ("stories", "actions", "credentials", "audit", "ai_audit")
STORIES_PATH = "/api/v1/stories"
# Actions are a flat collection filtered by story, not a sub-resource of a story: the
# nested path answers 404. Verified against a live tenant on September 16, 2026, including
# that `story_id` really filters (per-story counts sum to the unfiltered total and every
# returned record carries the requested story).
ACTIONS_PATH = "/api/v1/actions"
CREDENTIALS_PATH = "/api/v1/user_credentials"
AUDIT_PATH = "/api/v1/audit_logs"
# The vendor still calls an action an "agent" in list responses; the other three keys match
# their endpoint. Verified live on the same date.
ENVELOPES = {
    "stories": "stories",
    "actions": "agents",
    "credentials": "user_credentials",
    "audit": "audit_logs",
}


IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,96}$")
SYSTEM_CLOCK = SystemClock()


class CollectionError(MonitorError):
    """A stable collection code; never a vendor message or response content."""

    def __init__(self, code: str, *, retry_after: int | None = None) -> None:
        self.retry_after = retry_after
        super().__init__(code)


def fingerprint(api_key: str) -> str:
    if type(api_key) is not str or not 1 <= len(api_key) <= 4096:
        raise CollectionError("INVALID_INPUT")
    return hashlib.sha256(api_key.encode()).hexdigest()


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError
    return dict(pairs)


def _constant(value: str) -> Any:
    raise ValueError


def _identifier(value: object, *, limit: int = 96) -> str | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        value = str(value)
    if type(value) is not str or not IDENTIFIER.fullmatch(value) or len(value) > limit:
        return None
    return value


def _label(value: object) -> tuple[str, bool]:
    """A display name with control characters removed, bounded and marked when truncated."""
    if type(value) is not str:
        return "Unnamed", False
    cleaned = "".join(char for char in value if char.isprintable()).strip()
    if not cleaned:
        return "Unnamed", False
    return (cleaned[:96], True) if len(cleaned) > 96 else (cleaned, False)


def _moment(value: object) -> datetime | None:
    if type(value) is not str or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _count(value: object) -> int | None:
    if isinstance(value, bool) or type(value) is not int or not 0 <= value <= 1_000_000_000:
        return None
    return value


@dataclass(frozen=True)
class Item:
    """One allowlisted inventory row; nothing else from the record is retained."""

    item_kind: str
    external_id: str
    name: str
    name_truncated: bool
    story_external_id: str | None = None
    item_type: str | None = None
    disabled: bool | None = None
    outbound: bool | None = None
    source_updated_at: datetime | None = None


@dataclass(frozen=True)
class Record:
    """One allowlisted audit record, normalized into the observation contract."""

    external_ref: str
    event_id: str
    occurred_at: datetime
    operation_name: str
    kind: str
    change_class: str | None
    story_ref: str | None
    actor_ref: str | None
    action: str | None
    outcome: str | None
    input_tokens: int | None
    output_tokens: int | None
    tenant_ref: str | None
    content_hash: str


def parse_story(record: object) -> Item | None:
    if not isinstance(record, dict):
        return None
    external = _identifier(record.get("id"))
    if external is None:
        return None
    name, truncated = _label(record.get("name"))
    disabled = record.get("disabled")
    return Item(
        "story",
        external,
        name,
        truncated,
        item_type=_identifier(record.get("mode"), limit=32),
        disabled=disabled if type(disabled) is bool else None,
        source_updated_at=_moment(record.get("updated_at")),
    )


def parse_action(record: object, story: str) -> Item | None:
    if not isinstance(record, dict):
        return None
    external = _identifier(record.get("id"))
    if external is None:
        return None
    name, truncated = _label(record.get("name"))
    kind = record.get("type")
    outbound: bool | None = None
    if type(kind) is str:
        if kind in OUTBOUND_ACTION_TYPES:
            outbound = True
        elif kind in LOCAL_ACTION_TYPES:
            outbound = False
    disabled = record.get("disabled")
    # "options" carries URLs, headers and credential references; it is never read.
    return Item(
        "action",
        external,
        name,
        truncated,
        story_external_id=story,
        item_type=_identifier(kind),
        disabled=disabled if type(disabled) is bool else None,
        outbound=outbound,
    )


def parse_credential(record: object) -> Item | None:
    if not isinstance(record, dict):
        return None
    external = _identifier(record.get("id"))
    if external is None:
        return None
    name, truncated = _label(record.get("name"))
    # A credential value is never returned by the vendor and is never read here either.
    return Item(
        "credential",
        external,
        name,
        truncated,
        item_type=_identifier(record.get("mode"), limit=32),
        source_updated_at=_moment(record.get("expires_at")),
    )


def parse_audit(record: object) -> Record | None:
    """Normalize one audit record, or return None so the run counts it unsupported."""
    if not isinstance(record, dict):
        return None
    external = _identifier(record.get("id"))
    occurred = _moment(record.get("created_at"))
    operation = _identifier(record.get("operation_name"))
    if external is None or occurred is None or operation is None:
        return None
    change_class = TINES_OPERATIONS.get(operation)
    action = outcome = None
    input_tokens = output_tokens = None
    if operation == AI_MODEL_OPERATION:
        kind = "ai_model_run"
        inputs = record.get("inputs")
        outputs = record.get("outputs")
        # Only the model identifier and the token counts; never a prompt or a completion.
        action = _identifier(inputs.get("model"), limit=64) if isinstance(inputs, dict) else None
        if isinstance(outputs, dict):
            input_tokens = _count(outputs.get("input_tokens"))
            output_tokens = _count(outputs.get("output_tokens"))
    elif operation == AI_TOOL_OPERATION:
        kind = "ai_tool_run"
        inputs = record.get("inputs")
        outputs = record.get("outputs")
        # The tool name as reported; the detection profile maps it to a catalog action.
        action = (
            _identifier(inputs.get("tool_name"), limit=64) if isinstance(inputs, dict) else None
        )
        status = outputs.get("status") if isinstance(outputs, dict) else None
        outcome = status if status in {"success", "error"} else "unknown"
        if action is None:
            return None
    else:
        kind = "config_change"
    content = {
        "external_ref": external,
        "operation_name": operation,
        "occurred_at": occurred.isoformat(),
        "story": _identifier(record.get("story_id")),
        "actor": _identifier(record.get("user_id")),
        "action": action,
        "outcome": outcome,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
    }
    return Record(
        external_ref=external,
        event_id=f"audit:{external}",
        occurred_at=occurred,
        operation_name=operation,
        kind=kind,
        change_class=change_class if change_class in CHANGE_CLASSES else None,
        story_ref=_identifier(record.get("story_id")),
        actor_ref=_identifier(record.get("user_id")),
        action=action,
        outcome=outcome,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        tenant_ref=_identifier(record.get("tenant_id")),
        content_hash=hashlib.sha256(
            json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    )


class Reader:
    """Bounded ``GET`` access to one pinned Tines origin."""

    def __init__(
        self, base_url: str, api_key: str, client: httpx.Client, *, team_id: str | None = None
    ) -> None:
        self.base_url = base_url
        self._key = api_key
        self._client = client
        self.team_id = team_id

    def get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        try:
            with self._client.stream(
                "GET",
                self.base_url + path,
                params=params,
                headers={"X-User-Token": self._key, "Accept": "application/json"},
                follow_redirects=False,
                timeout=TIMEOUT,
            ) as response:
                if response.status_code in {401, 403}:
                    raise CollectionError("AUTH_LOST")
                if response.status_code == 404:
                    raise CollectionError("UNSUPPORTED")
                if response.status_code == 422:
                    # The tenant's plan does not include the feature. The vendor says so in
                    # the body, which is never read: "not available here" is the whole fact.
                    raise CollectionError("UNSUPPORTED")
                if response.status_code == 429:
                    raise CollectionError(
                        "RATE_LIMITED", retry_after=_retry_after(response.headers)
                    )
                if response.status_code != 200:
                    raise CollectionError("UNAVAILABLE")
                raw = bytearray()
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > MAX_BODY:
                        raise CollectionError("OVERSIZE")
                    raw.extend(chunk)
        except httpx.HTTPError:
            raise CollectionError("UNAVAILABLE") from None
        try:
            body = json.loads(bytes(raw), object_pairs_hook=_object, parse_constant=_constant)
        except (ValueError, RecursionError):
            raise CollectionError("MALFORMED") from None
        if not isinstance(body, dict):
            raise CollectionError("MALFORMED")
        return body

    def page(self, path: str, key: str, page: int, **params: Any) -> tuple[list[Any], bool]:
        query: dict[str, Any] = {"per_page": PAGE_SIZE, "page": page, **params}
        if self.team_id is not None and path == STORIES_PATH:
            query["team_id"] = self.team_id
        body = self.get(path, query)
        records = body.get(ENVELOPES[key])
        meta = body.get("meta")
        if not isinstance(records, list) or not isinstance(meta, dict):
            raise CollectionError("MALFORMED")
        return records, meta.get("next_page") is not None

    def walk(self, path: str, key: str, *, limit: int, pages: int, **params: Any) -> Iterator[Any]:
        seen = 0
        for number in range(1, pages + 1):
            records, more = self.page(path, key, number, **params)
            for record in records:
                if seen >= limit:
                    return
                seen += 1
                yield record
            if not more:
                return


def _retry_after(headers: httpx.Headers) -> int | None:
    value = headers.get("Retry-After")
    if value is None or not value.strip().isdigit():
        return None
    return min(int(value.strip()), 86400)


def _reader(row: dict[str, Any], api_key: str, client: httpx.Client) -> Reader:
    if fingerprint(api_key) != row["key_fingerprint"]:
        # A key that is not the registered one never reaches the vendor.
        raise CollectionError("KEY_MISMATCH")
    return Reader(row["base_url"], api_key, client, team_id=row["team_id"])


def probe_capabilities(reader: Reader, now: datetime) -> dict[str, dict[str, Any]]:
    """One bounded request per capability; a probe classifies and retains nothing else."""
    result: dict[str, dict[str, Any]] = {}

    def classify(call: Any) -> tuple[str, Any]:
        try:
            return "available", call()
        except CollectionError as error:
            if error.code == "AUTH_LOST":
                return "forbidden", None
            if error.code == "UNSUPPORTED":
                return "unsupported", None
            if error.code == "RATE_LIMITED":
                # Being refused for rate is the platform's answer to the run, never a
                # statement about whether the capability exists.
                raise
            return "unknown", None

    state, _ = classify(lambda: reader.get(STORIES_PATH, {"per_page": 1, "page": 1}))
    result["stories"] = {"state": state, "at": now.isoformat()}
    # Actions are their own collection, so probing them needs no story to exist first.
    state, _ = classify(lambda: reader.get(ACTIONS_PATH, {"per_page": 1, "page": 1}))
    result["actions"] = {"state": state, "at": now.isoformat()}
    state, _ = classify(lambda: reader.get(CREDENTIALS_PATH, {"per_page": 1, "page": 1}))
    result["credentials"] = {"state": state, "at": now.isoformat()}
    state, _ = classify(lambda: reader.get(AUDIT_PATH, {"per_page": 1, "page": 1}))
    result["audit"] = {"state": state, "at": now.isoformat()}
    if state != "available":
        # The AI records come from the same endpoint; asking again cannot tell us more.
        result["ai_audit"] = {"state": state, "at": now.isoformat()}
        return result
    state, body = classify(
        lambda: reader.get(
            AUDIT_PATH,
            {
                "per_page": 1,
                "page": 1,
                "operation_name[]": [AI_MODEL_OPERATION, AI_TOOL_OPERATION],
            },
        )
    )
    if state == "available":
        records = body.get(ENVELOPES["audit"]) if isinstance(body, dict) else None
        # Enhanced AI records are off by default: proof is a listed record, not a 200.
        state = "available" if isinstance(records, list) and records else "unknown"
    result["ai_audit"] = {"state": state, "at": now.isoformat()}
    return result


def probe(
    db: Database,
    identity: Identity,
    *,
    connection_id: UUID,
    api_key: str,
    client: httpx.Client,
    clock: Clock = SYSTEM_CLOCK,
) -> dict[str, dict[str, Any]]:
    row = store.load_connection(db, identity, connection_id)
    reader = _reader(row, api_key, client)
    capabilities = probe_capabilities(reader, clock.now())
    store.record_capabilities(db, identity, connection_id, capabilities, clock=clock)
    return capabilities


def _inventory(reader: Reader, capabilities: dict[str, dict[str, Any]]) -> tuple[list[Item], int]:
    items: list[Item] = []
    unsupported = 0
    stories: list[Item] = []
    if capabilities["stories"]["state"] == "available":
        for record in reader.walk(
            STORIES_PATH, "stories", limit=MAX_STORIES, pages=MAX_STORIES // PAGE_SIZE + 1
        ):
            parsed = parse_story(record)
            if parsed is None:
                unsupported += 1
            else:
                stories.append(parsed)
    items.extend(stories)
    if capabilities["actions"]["state"] == "available":
        budget = MAX_ACTIONS
        for story in stories:
            if budget <= 0:
                break
            for record in reader.walk(
                ACTIONS_PATH,
                "actions",
                limit=budget,
                pages=MAX_ACTIONS // PAGE_SIZE + 1,
                story_id=story.external_id,
            ):
                parsed = parse_action(record, story.external_id)
                if parsed is None:
                    unsupported += 1
                else:
                    budget -= 1
                    items.append(parsed)
    if capabilities["credentials"]["state"] == "available":
        for record in reader.walk(
            CREDENTIALS_PATH,
            "credentials",
            limit=MAX_CREDENTIALS,
            pages=MAX_CREDENTIALS // PAGE_SIZE + 1,
        ):
            parsed = parse_credential(record)
            if parsed is None:
                unsupported += 1
            else:
                items.append(parsed)
    return items, unsupported


def run(
    db: Database,
    actor: Identity | ScheduledActor,
    *,
    connection_id: UUID,
    api_key: str,
    client: httpx.Client,
    inventory: bool = False,
    audit_pages: int = 20,
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> dict[str, Any]:
    """One collection run; counts and codes only, never response content.

    `lease` is the connection's lease, which every write of the run proves (`due.claim`); a
    run whose lease is gone, or whose connection was revoked, stops at its next write.
    """
    if type(audit_pages) is not int or not 0 <= audit_pages <= MAX_AUDIT_PAGES:
        raise CollectionError("INVALID_INPUT")
    run_id = uuid4()
    row = store.load_connection(db, actor, connection_id, lease=lease)
    reader = _reader(row, api_key, client)
    now = clock.now()
    result: dict[str, Any] = {
        "run_id": str(run_id),
        "capabilities": {},
        "inventory": {"stories": 0, "actions": 0, "credentials": 0, "gone": 0, "unsupported": 0},
        "audit": {
            "pages": 0,
            "accepted": 0,
            "duplicates": 0,
            "unsupported": 0,
            "quarantined": 0,
        },
        "coverage": {},
        "outcome": "COMPLETE",
    }
    outcome = "COMPLETE"
    error_code: str | None = None
    retry_after: int | None = None
    due = row["last_sync_at"] is None or now - row["last_sync_at"] >= SYNC_INTERVAL
    capabilities: dict[str, dict[str, Any]] = {}
    try:
        capabilities = probe_capabilities(reader, now)
        store.record_capabilities(db, actor, connection_id, capabilities, clock=clock, lease=lease)
        result["capabilities"] = {name: value["state"] for name, value in capabilities.items()}
        if capabilities["audit"]["state"] == "forbidden":
            # Permission for the audit API is the run's own authority, not just coverage.
            raise CollectionError("AUTH_LOST")
        if inventory or due:
            items, unsupported = _inventory(reader, capabilities)
            counts = store.apply_inventory(
                db, actor, connection_id, items, clock=clock, lease=lease
            )
            result["inventory"] = {**counts, "unsupported": unsupported}
            result["coverage"] = store.reconcile_coverage(
                db, actor, connection_id, clock=clock, lease=lease
            )
        if audit_pages and capabilities["audit"]["state"] == "available":
            outcome = _collect_audit(
                db, actor, connection_id, reader, row, audit_pages, result, clock=clock, lease=lease
            )
    except CollectionError as error:
        error_code = error.code
        retry_after = error.retry_after
        outcome = {
            "AUTH_LOST": "AUTH_LOST",
            "RATE_LIMITED": "RATE_LIMITED",
        }.get(error.code, "ERROR")
    result["outcome"] = outcome
    store.record_run_outcome(
        db,
        actor,
        connection_id,
        outcome=outcome,
        run_id=run_id,
        error_code=error_code,
        retry_after=retry_after,
        synced=bool(inventory or due),
        clock=clock,
        lease=lease,
    )
    return result


def _collect_audit(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    reader: Reader,
    row: dict[str, Any],
    audit_pages: int,
    result: dict[str, Any],
    *,
    clock: Clock,
    lease: UUID | None,
) -> str:
    now = clock.now()
    cursor = row["audit_cursor"]
    floor = now - RETENTION_FLOOR
    # A cursor the vendor can no longer serve means the window between them is lost.
    gap = cursor is not None and cursor < floor
    after = (cursor - OVERLAP) if cursor is not None else floor
    outcome = "COMPLETE"
    for number in range(1, audit_pages + 1):
        records, more = reader.page(
            AUDIT_PATH, "audit", number, after=after.astimezone(UTC).isoformat()
        )
        parsed: list[Record] = []
        for record in records:
            item = parse_audit(record)
            if item is None:
                result["audit"]["unsupported"] += 1
            else:
                parsed.append(item)
        result["audit"]["pages"] += 1
        # The page, its pending evaluations and the cursor advance commit together, so a
        # failure re-reads the page instead of skipping it.
        counts = store.ingest_collected_page(
            db,
            actor,
            connection_id,
            sorted(parsed, key=lambda item: (item.occurred_at, item.external_ref)),
            clock=clock,
            lease=lease,
        )
        for key in ("accepted", "duplicates", "quarantined"):
            result["audit"][key] += counts[key]
        if not more:
            break
        if number == audit_pages:
            outcome = "BACKLOG"
    if gap:
        outcome = "RETENTION_GAP"
    return outcome
