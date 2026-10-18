# SPDX-License-Identifier: AGPL-3.0-only
"""The endpoint mock's store, now defined in `execbound_connectors.mock_store` (#496).

Kept importable where it always was: the server's own modules, retained configuration
and installed deployments name this path.
"""

from execbound_connectors.mock_store import (
    JournalStore,
    MockResource,
    MockStore,
)

__all__ = [
    "JournalStore",
    "MockResource",
    "MockStore",
]
