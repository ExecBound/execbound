# SPDX-License-Identifier: AGPL-3.0-only
"""The console sections a workspace switch may land on, and who may open each.

A switch keeps the person's section, never their record: the section is one of a closed set
of page roots, each with the rule its navigation entry carries, so no request can name a
record, a query string or an address outside the console, and no answer can send a session
to a page it cannot open (#678).

The roots and rules mirror the console's navigation list (`console/src/shell/navigation.ts`),
without `/ask`, whose page exists only where a model is configured; a parity test holds the two
together.
"""

from collections.abc import Collection
from dataclasses import dataclass
from typing import Literal, get_args

Section = Literal[
    "/",
    "/approvals",
    "/activity",
    "/board",
    "/policy",
    "/agents",
    "/people",
    "/access",
    "/credentials",
    "/approvers",
    "/spaces",
    "/monitor",
    "/welcome",
    "/tenant",
    "/help",
    "/settings",
]
SECTIONS: frozenset[str] = frozenset(get_args(Section))


@dataclass(frozen=True)
class Rule:
    """Who may open a root: an `ADMIN` session, a permission, both, or (the default) anyone."""

    admin: bool = False
    permission: str | None = None


RULES: dict[str, Rule] = {
    "/approvals": Rule(permission="approvals.decide"),
    "/policy": Rule(permission="policy.manage"),
    "/agents": Rule(admin=True),
    "/credentials": Rule(admin=True),
    "/spaces": Rule(admin=True),
    "/monitor": Rule(admin=True),
    "/welcome": Rule(admin=True),
    "/tenant": Rule(admin=True),
    "/people": Rule(admin=True, permission="access.manage"),
    "/access": Rule(admin=True, permission="access.manage"),
    "/approvers": Rule(admin=True, permission="access.manage"),
}


def opens(kind: str, permissions: Collection[str], section: str) -> bool:
    """Whether a session of this kind and these permissions may open this root."""
    if section not in SECTIONS:
        return False
    rule = RULES.get(section, Rule())
    if rule.admin and kind != "ADMIN":
        return False
    return rule.permission is None or rule.permission in permissions


def start(kind: str, permissions: Collection[str]) -> str:
    """Where a session starts: its kind's landing when that root opens for it, else Home.

    The landing depends on the kind alone, so a viewer, whose kind is an approver's but who
    may decide nothing, would otherwise be sent to a page it cannot open.
    """
    from execbound.surfaces.human import landing

    first = landing(kind)
    return first if opens(kind, permissions, first) else "/"


def place(kind: str, permissions: Collection[str], section: str | None) -> str:
    """The section a new session opens: the one asked for if it may open it, else its start."""
    answer = (
        section
        if section is not None and opens(kind, permissions, section)
        else start(kind, permissions)
    )
    if not opens(kind, permissions, answer):
        raise AssertionError("a session must never be sent to a section it cannot open")
    return answer
