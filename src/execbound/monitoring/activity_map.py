# SPDX-License-Identifier: AGPL-3.0-only
"""Which directory audit entries are which catalog actions (#355).

A Microsoft Entra directory's audit log records what was done to it and who did it. Scout reads
the entries an application initiated and asks one question of each: is this one of the actions
the action catalog names? The answer is a lookup in this reviewed table, keyed on what the
directory itself writes, the service that logged the entry, its activity name and, where one
activity covers several changes, the one modified property that says which. It is never a guess
from a display name or a free-text reason.

Every entry names the primary source it was read from and the day it was read, as the grant
catalog and the AI publisher catalog do, and maps to an action the production action catalog
holds, which is checked when this module loads: an action the kernel does not name cannot become
a reach claim. The activity names are Microsoft's audit activity reference for the Core
Directory service. What that reference does not give is how an application's change appears:
which activities one Graph request logs, and how a modified property's values are written. Those
are fixture-verified until a read-only probe of a real directory settles them, and an entry the
map cannot read is counted as unmapped rather than guessed at.

Read on 16 October 2026, and named here so the gaps are visible rather than silent:

- **Role assignment is not mapped.** `Add member to role` is a Core Directory activity, but the
  action catalog has no role action and Scout claims no reach on an action outside it, the rule
  already applied to Azure actions. It is counted as an unmapped application activity.
- **Self-service password management's `Reset password (by admin)`** is logged by another
  service; the read asks for Core Directory entries alone, where an application's reset is
  expected, until a probe shows otherwise.
"""

import re
from dataclasses import dataclass
from datetime import date

from execbound_protocol.catalog import PRODUCTION_ACTIONS, CatalogError

VERSION = "entra-audit.v1"
READ_ON = date(2026, 10, 16)
SERVICE = "Core Directory"
REFERENCE = (
    "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities"
)
KEY = re.compile(r"^[a-z][a-z0-9_]{0,47}$")
# The only target type the four identity actions act on.
USER = "User"
# The modified properties an entry is read for, and nothing else of its values is kept.
ACCOUNT_ENABLED = "AccountEnabled"
INSPECTED = frozenset({ACCOUNT_ENABLED})


class MapError(ValueError):
    """A map that cannot explain itself; raised when it is built."""


@dataclass(frozen=True, slots=True)
class Activity:
    """One reviewed statement that an audit entry is a catalog action, with its source.

    `change`, where set, is the one modified property that decides it, with the value it held
    before and after: `Update user` is the disable action only when `AccountEnabled` went from
    true to false.
    """

    key: str
    service: str
    name: str
    action: str
    change: tuple[str, bool, bool] | None
    source: str
    retrieved: date

    @property
    def operation(self) -> str:
        """What an observation records as its operation: the map's version and this key."""
        return f"{VERSION}:{self.key}"


class ActivityMap:
    """Activities by what the directory writes, each claimed once and each a catalog action."""

    def __init__(self, activities: tuple[Activity, ...]) -> None:
        self.activities = activities
        self._index: dict[tuple[str, str], list[Activity]] = {}
        keys: set[str] = set()
        for activity in activities:
            try:
                PRODUCTION_ACTIONS.action(activity.action)
            except CatalogError:
                raise MapError(activity.key) from None
            if (
                KEY.fullmatch(activity.key) is None
                or activity.key in keys
                or not activity.source.startswith("https://")
                or not activity.name
                or (activity.change is not None and activity.change[0] not in INSPECTED)
                or (activity.change is not None and activity.change[1] == activity.change[2])
            ):
                raise MapError(activity.key)
            keys.add(activity.key)
            found = self._index.setdefault((activity.service, activity.name), [])
            # One activity name is either one action, or several told apart by a change.
            if any(
                other.change is None or activity.change is None or other.change == activity.change
                for other in found
            ):
                raise MapError(activity.key)
            found.append(activity)

    def match(
        self, service: str, name: str, changes: dict[str, tuple[bool | None, bool | None]]
    ) -> Activity | None:
        """The activity an entry is, from its service, its name and the inspected properties
        it changed (old and new, each None where the value could not be read); None if the map
        does not cover it."""
        for activity in self._index.get((service, name), ()):
            if activity.change is None:
                return activity
            prop, before, after = activity.change
            if changes.get(prop) == (before, after):
                return activity
        return None


PRODUCTION = ActivityMap(
    (
        Activity(
            "disable_account",
            SERVICE,
            "Disable account",
            "identity.disable",
            None,
            REFERENCE,
            READ_ON,
        ),
        Activity(
            "enable_account",
            SERVICE,
            "Enable account",
            "identity.enable",
            None,
            REFERENCE,
            READ_ON,
        ),
        # The issue's own example: `Update user` with `AccountEnabled` going from true to false.
        Activity(
            "update_user_disabled",
            SERVICE,
            "Update user",
            "identity.disable",
            (ACCOUNT_ENABLED, True, False),
            REFERENCE,
            READ_ON,
        ),
        Activity(
            "update_user_enabled",
            SERVICE,
            "Update user",
            "identity.enable",
            (ACCOUNT_ENABLED, False, True),
            REFERENCE,
            READ_ON,
        ),
        Activity(
            "reset_password",
            SERVICE,
            "Reset password",
            "identity.reset_password",
            None,
            REFERENCE,
            READ_ON,
        ),
        # Revoking a user's sessions moves its refresh tokens' valid-from moment, which the
        # directory logs under this activity.
        Activity(
            "revoke_sessions",
            SERVICE,
            "Update StsRefreshTokenValidFrom Timestamp",
            "identity.revoke_sessions",
            None,
            REFERENCE,
            READ_ON,
        ),
    )
)
