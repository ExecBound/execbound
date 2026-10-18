# SPDX-License-Identifier: AGPL-3.0-only
"""The action catalog, now defined in `execbound_protocol.catalog` (#496).

A provider command is validated against the catalog, production data included, so the
catalog is the protocol's and has one definition there. This module keeps every name
importable where it always was.
"""

from execbound_protocol.catalog import (
    ACTION_PATTERN,
    NAME_PATTERN,
    PRODUCTION_ACTIONS,
    ActionCatalog,
    ActionName,
    ActionSpec,
    ArgumentSpec,
    CatalogError,
    OperationSpec,
    ProviderBinding,
    ProviderName,
    ProviderOperation,
    ResourceType,
    SchemaVersion,
    operation,
    validate_operation,
)

__all__ = [
    "ACTION_PATTERN",
    "ActionCatalog",
    "ActionName",
    "ActionSpec",
    "ArgumentSpec",
    "CatalogError",
    "NAME_PATTERN",
    "operation",
    "OperationSpec",
    "PRODUCTION_ACTIONS",
    "ProviderBinding",
    "ProviderName",
    "ProviderOperation",
    "ResourceType",
    "SchemaVersion",
    "validate_operation",
]
