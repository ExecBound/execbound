# SPDX-License-Identifier: AGPL-3.0-only
"""The identity mock's store, now defined in `execbound_connectors.identity_store` (#496).

Kept importable where it always was: the server's own modules, retained configuration
and installed deployments name this path.
"""

from execbound_connectors.identity_store import (
    IdentityStore,
    MockIdentity,
)

__all__ = [
    "IdentityStore",
    "MockIdentity",
]
