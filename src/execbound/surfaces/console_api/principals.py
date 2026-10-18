# SPDX-License-Identifier: AGPL-3.0-only
"""A principal as the console API hands it to the console (#678).

The id, the kind, the label and the workspace's counting number, so the console names every
agent and person one way: its label, else `Agent 3` or `User 3`. Every field is required in the
schema, nullable where it can be missing, so the generated client types are exact. Nothing here
reaches an agent: the agent API carries no number, kind or name of any principal.
"""

from collections.abc import Mapping
from typing import Literal, cast
from uuid import UUID

from pydantic import BaseModel

from execbound.surfaces.names import PrincipalFacts

PrincipalKind = Literal["AGENT", "HUMAN_APPROVER", "ADMIN", "SYSTEM"]
KINDS: frozenset[str] = frozenset({"AGENT", "HUMAN_APPROVER", "ADMIN", "SYSTEM"})


class PrincipalRef(BaseModel):
    principal_id: UUID
    kind: PrincipalKind
    label: str | None
    number: int | None


def principal_kind(kind: str | None) -> PrincipalKind | None:
    return cast(PrincipalKind, kind) if kind in KINDS else None


def principal_ref(
    principal_id: UUID | None, facts: Mapping[UUID, PrincipalFacts]
) -> PrincipalRef | None:
    """The reference for one id, or None for an id the facts do not hold."""
    if principal_id is None:
        return None
    found = facts.get(principal_id)
    if found is None:
        return None
    kind = principal_kind(found.kind)
    if kind is None:
        return None
    return PrincipalRef(
        principal_id=principal_id, kind=kind, label=found.label, number=found.number
    )
