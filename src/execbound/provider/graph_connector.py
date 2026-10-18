# SPDX-License-Identifier: AGPL-3.0-only
"""The Microsoft Graph connector, now `execbound_connectors.graph_connector` (#496).

Kept importable where it always was: the server's own modules, retained configuration
and installed deployments name this path.
"""

from execbound_connectors.graph_connector import (
    DISABLE,
    GRAPH_PROVIDER,
    GraphConnectionConfig,
    GraphConnector,
)

__all__ = [
    "DISABLE",
    "GRAPH_PROVIDER",
    "GraphConnectionConfig",
    "GraphConnector",
]
