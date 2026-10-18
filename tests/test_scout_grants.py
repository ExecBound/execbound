# SPDX-License-Identifier: AGPL-3.0-only
"""The grant catalog: what it refuses at construction, and what it will not guess."""

from dataclasses import replace
from datetime import date

import pytest

from execbound.monitoring.grant_catalog import (
    ENTRA,
    MICROSOFT_GRAPH,
    PRODUCTION_GRANTS,
    VERSION,
    GrantCatalog,
    GrantCatalogError,
    GrantEntry,
)
from execbound.operations import PRODUCTION_ACTIONS

GRAPH_ROLE = GrantEntry(
    namespace=ENTRA,
    grant_kind="graph_role",
    resource_ref=MICROSOFT_GRAPH,
    value="User.EnableDisableAccount.All",
    action="identity.disable",
    breadth="direct",
    source="https://example.invalid/reference",
    read_on=date(2026, 9, 17),
)
DIRECTORY_ROLE = replace(
    GRAPH_ROLE,
    grant_kind="directory_role",
    resource_ref="",
    value="c4e39bd9-1100-46d3-8c65-fb160da0071f",
)


def test_the_shipped_catalog_names_only_catalog_actions():
    assert PRODUCTION_GRANTS.version == VERSION == "entra.v1"
    for action in PRODUCTION_GRANTS.actions:
        # Raises rather than returning a sentinel if the action left the catalog.
        PRODUCTION_ACTIONS.action(action)
    # Graph reaches identities. It has no path to an endpoint, and claiming one would be
    # the kind of invention this table exists to prevent.
    assert all(action.startswith("identity.") for action in PRODUCTION_GRANTS.actions)


def test_every_shipped_entry_carries_where_it_came_from():
    for entry in PRODUCTION_GRANTS.entries:
        assert entry.source.startswith("https://learn.microsoft.com/")
        assert entry.read_on == date(2026, 9, 17)


def test_a_delegated_scope_is_always_marked_delegated():
    """It acts for a signed-in user, so it can never be read as standalone authority."""
    for entry in PRODUCTION_GRANTS.entries:
        assert (entry.grant_kind == "graph_scope") == (entry.breadth == "delegated")


def test_an_unmapped_grant_returns_nothing_rather_than_a_near_match():
    assert PRODUCTION_GRANTS.lookup(ENTRA, "graph_role", MICROSOFT_GRAPH, "Mail.Read") == ()
    # A prefix of a mapped name is not the mapped name.
    assert PRODUCTION_GRANTS.lookup(ENTRA, "graph_role", MICROSOFT_GRAPH, "User.Enable") == ()
    assert PRODUCTION_GRANTS.lookup(ENTRA, "graph_role", MICROSOFT_GRAPH, "User.ReadWrite") == ()
    # The same name on a different resource application is a different grant.
    assert (
        PRODUCTION_GRANTS.lookup(
            ENTRA, "graph_role", "00000003-0000-0ff1-ce00-000000000000", "User.ReadWrite.All"
        )
        == ()
    )
    # A role template the catalog does not carry stays unknown, not "no reach".
    assert (
        PRODUCTION_GRANTS.lookup(ENTRA, "directory_role", "", "fe930be7-5e62-47db-91af-98c") == ()
    )


def test_a_mapped_grant_returns_every_action_it_reaches():
    disable = PRODUCTION_GRANTS.lookup(
        ENTRA, "graph_role", MICROSOFT_GRAPH, "User.EnableDisableAccount.All"
    )
    assert {entry.action for entry in disable} == {"identity.disable", "identity.enable"}
    assert {entry.breadth for entry in disable} == {"direct"}
    broad = PRODUCTION_GRANTS.lookup(
        ENTRA, "graph_role", MICROSOFT_GRAPH, "Directory.ReadWrite.All"
    )
    assert len(broad) == 4 and {entry.breadth for entry in broad} == {"broad"}


@pytest.mark.parametrize(
    ("entry", "match"),
    [
        (replace(GRAPH_ROLE, action="identity.quarantine"), "outside the catalog"),
        (replace(GRAPH_ROLE, action="endpoint.detonate"), "outside the catalog"),
        (replace(GRAPH_ROLE, grant_kind="azure_rbac"), "grant kind"),
        (replace(GRAPH_ROLE, breadth="total"), "breadth"),
        (replace(GRAPH_ROLE, namespace="Entra"), "namespace"),
        # A Graph grant names a permission on a resource application, both well formed.
        (replace(GRAPH_ROLE, resource_ref=""), "resource application"),
        (replace(GRAPH_ROLE, resource_ref="microsoft-graph"), "resource application"),
        (replace(GRAPH_ROLE, value="User Enable Disable"), "resource application"),
        (replace(GRAPH_ROLE, value=""), "resource application"),
        # A directory role is a role template identifier and is not scoped to a resource.
        (replace(DIRECTORY_ROLE, resource_ref=MICROSOFT_GRAPH), "role template"),
        (replace(DIRECTORY_ROLE, value="Authentication Administrator"), "role template"),
    ],
)
def test_construction_refuses_an_entry_that_cannot_explain_itself(entry, match):
    with pytest.raises(GrantCatalogError, match=match):
        GrantCatalog((entry,))


def test_construction_refuses_a_repeated_statement():
    with pytest.raises(GrantCatalogError, match="Duplicate"):
        GrantCatalog((GRAPH_ROLE, GRAPH_ROLE))
    # The same grant reaching a second action is not a duplicate.
    GrantCatalog((GRAPH_ROLE, replace(GRAPH_ROLE, action="identity.enable")))


def test_construction_refuses_an_unusable_version():
    for version in ("", "Entra.v1", "1", "x" * 40):
        with pytest.raises(GrantCatalogError, match="version"):
            GrantCatalog((GRAPH_ROLE,), version=version)
