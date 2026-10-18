# SPDX-License-Identifier: AGPL-3.0-only
"""The Microsoft Graph client, now defined in `execbound_connectors.graph` (#496).

Kept importable where it always was: the server's own modules, retained configuration
and installed deployments name this path.
"""

from execbound_connectors.graph import (
    GRAPH_ORIGIN,
    GRAPH_SCOPE,
    LOGIN_ORIGIN,
    MAX_BODY,
    TIMEOUT,
    USER_SELECT,
    GraphCredential,
    GraphDisable,
    GraphDispatchError,
    GraphUserWriter,
)

__all__ = [
    "GRAPH_ORIGIN",
    "GRAPH_SCOPE",
    "GraphCredential",
    "GraphDisable",
    "GraphDispatchError",
    "GraphUserWriter",
    "LOGIN_ORIGIN",
    "MAX_BODY",
    "TIMEOUT",
    "USER_SELECT",
]
