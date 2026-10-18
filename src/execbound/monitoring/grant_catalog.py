# SPDX-License-Identifier: AGPL-3.0-only
"""Which directory grants reach which catalog actions.

Inference about what an external agent can do is a lookup in this reviewed table, never a
pattern match on a name, so every inferred reach row can be explained to the person who
holds the grant and disputed by them. A grant this catalog does not name produces an
``unknown`` reach row carrying the grant itself: "we do not know" is a finding, and a guess
would be a false one.

Two keying decisions matter, and both exist so that no identifier is invented here.

Microsoft Graph application permissions and delegated scopes are keyed by their **published
name**, not by the app role identifier a grant actually carries. A delegated grant already
names scopes as text, and an app role assignment's identifier is resolved to a name at
collection time from the resource application's own ``appRoles`` collection, which the
tenant serves. The tenant is therefore the authority for that mapping rather than a GUID
copied into this file, and an identifier that cannot be resolved stays unresolved.

Directory roles have no such indirection, so they are keyed by ``roleTemplateId`` and only
the three below are shipped: each is quoted from a primary Microsoft reference read on
17 September 2026. The rest wait for the live probe rather than being recalled.

Not yet established, and named here so the gap is visible rather than silent:

- the role template identifiers for User Administrator, Privileged Authentication
  Administrator and Password Administrator, each of which the same reference shows can
  disable an account or reset a password;
- Azure RBAC role assignments, which Microsoft Graph does not serve at all;
- the CrowdStrike Falcon namespace, which arrives with its own source.
"""

from dataclasses import dataclass
from datetime import date
from re import fullmatch

from execbound.operations import PRODUCTION_ACTIONS

VERSION = "entra.v1"
ENTRA = "entra"
# Quoted verbatim from the inheritable-permissions reference; it is the resource application
# every Graph permission below is granted on.
MICROSOFT_GRAPH = "00000003-0000-0000-c000-000000000000"

GRANT_KINDS = frozenset(
    {
        "graph_role",
        "graph_scope",
        "directory_role",
        "inherited_roles",
        "inherited_scopes",
        "tines_credential",
    }
)
# How a grant reaches the action, which is what a reader needs to judge it.
BREADTHS = frozenset(
    {
        # The grant names this operation and little else.
        "direct",
        # The grant contains this operation inside a much wider authority.
        "broad",
        # The grant acts on behalf of a signed-in user and is bounded by that user's own
        # authority, so reaching the action also depends on who signs in.
        "delegated",
    }
)
GUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
SCOPE = r"[A-Za-z][A-Za-z0-9]*(-[A-Za-z0-9]+)?(\.[A-Za-z0-9]+)+"

GRAPH_REFERENCE = (
    "https://learn.microsoft.com/en-us/graph/api/resources/agentid-platform-overview"
    "?view=graph-rest-1.0"
)
REVOKE_REFERENCE = (
    "https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0"
)
ROLE_REFERENCE = (
    "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/"
    "privileged-roles-permissions"
)
READ_ON = date(2026, 9, 17)


class GrantCatalogError(ValueError):
    """A catalog that cannot be trusted to explain itself; raised at import."""


@dataclass(frozen=True, slots=True)
class GrantEntry:
    """One reviewed statement that a grant reaches an action, with where it came from."""

    namespace: str
    grant_kind: str
    resource_ref: str
    value: str
    action: str
    breadth: str
    source: str
    read_on: date


def _graph(value: str, actions: dict[str, str], source: str) -> list[GrantEntry]:
    """An application permission and its delegated twin, which are named identically."""
    entries = []
    for kind, breadth in (("graph_role", None), ("graph_scope", "delegated")):
        entries += [
            GrantEntry(
                namespace=ENTRA,
                grant_kind=kind,
                resource_ref=MICROSOFT_GRAPH,
                value=value,
                action=action,
                breadth=breadth or direct_or_broad,
                source=source,
                read_on=READ_ON,
            )
            for action, direct_or_broad in actions.items()
        ]
    return entries


def _role(template: str, actions: dict[str, str]) -> list[GrantEntry]:
    return [
        GrantEntry(
            namespace=ENTRA,
            grant_kind="directory_role",
            resource_ref="",
            value=template,
            action=action,
            breadth=breadth,
            source=ROLE_REFERENCE,
            read_on=READ_ON,
        )
        for action, breadth in actions.items()
    ]


ALL_IDENTITY_ACTIONS = (
    "identity.disable",
    "identity.enable",
    "identity.revoke_sessions",
    "identity.reset_password",
)

ENTRIES: tuple[GrantEntry, ...] = tuple(
    # "Allows the app to enable and disable users' accounts", and nothing else.
    _graph(
        "User.EnableDisableAccount.All",
        {"identity.disable": "direct", "identity.enable": "direct"},
        GRAPH_REFERENCE,
    )
    # Named by the revoke API as one of its three permissions.
    + _graph("User.RevokeSessions.All", {"identity.revoke_sessions": "direct"}, REVOKE_REFERENCE)
    + _graph(
        "User-PasswordProfile.ReadWrite.All",
        {"identity.reset_password": "direct"},  # nosec B105 - a breadth, not a secret
        GRAPH_REFERENCE,
    )
    # Write access to the whole user object contains every one of these operations.
    + _graph("User.ReadWrite.All", dict.fromkeys(ALL_IDENTITY_ACTIONS, "broad"), REVOKE_REFERENCE)
    + _graph(
        "Directory.ReadWrite.All", dict.fromkeys(ALL_IDENTITY_ACTIONS, "broad"), REVOKE_REFERENCE
    )
    # Authentication Administrator. Its published role permissions list users/disable,
    # users/enable, users/invalidateAllRefreshTokens and users/password/update by name.
    + _role("c4e39bd9-1100-46d3-8c65-fb160da0071f", dict.fromkeys(ALL_IDENTITY_ACTIONS, "direct"))
    # Helpdesk Administrator: "can change passwords, invalidate refresh tokens".
    + _role(
        "729827e3-9c14-49f7-bb1b-9608f156bbb8",
        {
            "identity.reset_password": "direct",  # nosec B105 - a breadth, not a secret
            "identity.revoke_sessions": "direct",
        },
    )
    # Global Administrator, which reaches these the way it reaches everything else.
    + _role("62e90394-69f5-4237-9190-012177145e10", dict.fromkeys(ALL_IDENTITY_ACTIONS, "broad"))
)


class GrantCatalog:
    """A frozen, versioned lookup from a directory grant to a catalog action."""

    def __init__(self, entries: tuple[GrantEntry, ...], *, version: str = VERSION) -> None:
        if fullmatch(r"[a-z][a-z0-9_.-]{0,31}", version) is None:
            raise GrantCatalogError("Invalid catalog version")
        table: dict[tuple[str, str, str, str], tuple[GrantEntry, ...]] = {}
        seen: set[tuple[str, str, str, str, str]] = set()
        for entry in entries:
            self._check(entry)
            identity = (
                entry.namespace,
                entry.grant_kind,
                entry.resource_ref,
                entry.value,
                entry.action,
            )
            if identity in seen:
                raise GrantCatalogError("Duplicate grant entry")
            seen.add(identity)
            table.setdefault(identity[:4], ())
            table[identity[:4]] += (entry,)
        self.version = version
        self._table = table
        self._entries = entries

    @staticmethod
    def _check(entry: GrantEntry) -> None:
        if entry.grant_kind not in GRANT_KINDS:
            raise GrantCatalogError("Unknown grant kind")
        if entry.breadth not in BREADTHS:
            raise GrantCatalogError("Unknown grant breadth")
        if fullmatch(r"[a-z][a-z0-9_]{0,31}", entry.namespace) is None:
            raise GrantCatalogError("Invalid namespace")
        try:
            PRODUCTION_ACTIONS.action(entry.action)
        except Exception as error:
            # A typo here would silently stop mapping a consequential grant, so it fails
            # at import rather than at the first collection that needed it.
            raise GrantCatalogError("Grant names an action outside the catalog") from error
        if entry.grant_kind == "directory_role":
            if entry.resource_ref or fullmatch(GUID, entry.value) is None:
                raise GrantCatalogError("A directory role is a role template identifier")
        elif fullmatch(GUID, entry.resource_ref) is None or fullmatch(SCOPE, entry.value) is None:
            raise GrantCatalogError("A Graph grant is a permission name on a resource application")

    def lookup(
        self, namespace: str, grant_kind: str, resource_ref: str, value: str
    ) -> tuple[GrantEntry, ...]:
        """Every action this grant reaches, or an empty tuple. Never a prefix or a guess."""
        return self._table.get((namespace, grant_kind, resource_ref, value), ())

    @property
    def entries(self) -> tuple[GrantEntry, ...]:
        return self._entries

    @property
    def actions(self) -> frozenset[str]:
        return frozenset(entry.action for entry in self._entries)


PRODUCTION_GRANTS = GrantCatalog(ENTRIES)
