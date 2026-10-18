# SPDX-License-Identifier: AGPL-3.0-only
"""One name per principal, on every page the server writes a principal into (#678).

An agent is its label, else `Agent 3`; a person is their label, else `User 3`; the scheduler
is "ExecBound scheduler". The number is the workspace's counting number that migrations 0058
and 0062 gave every principal: a display handle only, unique per workspace and class, never a
key. Every reference, authorization and audit record keeps the UUID. The console renders the
same rule from the same table of cases (`console/src/test/principal-names.json`, read by a test
on each side), so the two cannot drift.

`principal_facts` reads one workspace's principals on a connection the caller has already
fenced, for ids the caller took from rows it already read under its own scope, never from a
request. It names its tenant in the statement as well as relying on forced row-level security,
so a missing predicate is caught by a test of the text rather than hidden by the policy.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

PERSON_KINDS = frozenset({"ADMIN", "HUMAN_APPROVER"})
SCHEDULER = "ExecBound scheduler"

FACTS = (
    "SELECT principal_id, kind, label, number FROM execbound.principals "
    "WHERE tenant_id=:t AND principal_id = ANY(CAST(:ids AS uuid[]))"
)


@dataclass(frozen=True)
class PrincipalFacts:
    """What a page needs to name a principal: its kind, its label and its counting number."""

    kind: str
    label: str | None
    number: int | None


def _noun(kind: str | None) -> str:
    return "Agent" if kind == "AGENT" else "User"


def principal_handle(kind: str | None, number: int | None, principal_id: UUID | None = None) -> str:
    """The handle, Agent N or User N; else the noun and the id's first eight characters."""
    noun = _noun(kind)
    if number is not None:
        return f"{noun} {number}"
    if principal_id is not None:
        return f"{noun} {str(principal_id)[:8]}"
    return noun


def principal_name(
    kind: str | None, label: str | None, number: int | None, principal_id: UUID | None = None
) -> str:
    """The label; else the scheduler's own name for SYSTEM; else the handle."""
    if label:
        return label
    if kind == "SYSTEM":
        return SCHEDULER
    return principal_handle(kind, number, principal_id)


def principal_facts(
    conn: Connection, tenant: UUID, ids: Iterable[UUID]
) -> dict[UUID, PrincipalFacts]:
    """One workspace's principals' kind, label and number, on a connection the caller fenced.

    Ids from another workspace find nothing. It opens no transaction and sets no fence of its
    own: the caller's transaction is the one its rows were read in.
    """
    wanted = sorted({str(identifier) for identifier in ids if identifier is not None})
    if not wanted:
        return {}
    found = conn.execute(text(FACTS), {"t": tenant, "ids": wanted}).mappings()
    return {
        row["principal_id"]: PrincipalFacts(
            kind=str(row["kind"]),
            label=None if row["label"] is None else str(row["label"]),
            number=None if row["number"] is None else int(row["number"]),
        )
        for row in found
    }
