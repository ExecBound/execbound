# SPDX-License-Identifier: AGPL-3.0-only
"""The mock vendor servers, now defined in `execbound_connectors.mock_app` (#496).

Kept importable where it always was: the server's own modules, retained configuration
and installed deployments name this path.
"""

from execbound_connectors.mock_app import (
    SAMPLE_KEY_VARIABLE,
    Role,
    create_mock_app,
)

__all__ = [
    "create_mock_app",
    "Role",
    "SAMPLE_KEY_VARIABLE",
]
