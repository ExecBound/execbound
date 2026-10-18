# SPDX-License-Identifier: Apache-2.0
"""The frozen precondition for a vendor that offers no version, and its one recipe.

Microsoft Graph returns no ETag for a user object and rejects nothing on ``If-Match``, so a
dispatch against it has no vendor version to freeze. What it does have is the state the
decision was made against, and freezing a hash of exactly the fields the action depends on
is what lets the connector refuse a write whose subject moved underneath it.

The hash is carried in the frozen plan's existing ``resource_version``, prefixed so a reader
can tell a composite from a vendor's own version and so a connector knows which recipe to
recompute. Nothing is added to ``ResolvedRequest``: ``plan_hash`` hashes that whole model, so
a new field would move every frozen plan hash in history.

This module is the single definition of the recipe. The freezing path and the connector both
call it, because a precondition computed two ways is a precondition that silently passes.
"""

import hashlib
from collections.abc import Mapping
from typing import Any

from execbound_protocol.canonical import canonical_json

# The version line is part of the hashed content as well as the prefix: changing which fields
# the composite covers must change every hash it produces, or an old frozen plan would
# compare equal to a new reading that checked something different.
GRAPH_USER_V1 = "graph-user.v1"

# Exactly the fields `identity.disable` depends on, and the reason each is here:
#
#   id                       the object actually addressed, so a recreated or re-pointed
#                            principal is refused rather than disabled.
#   accountEnabled           the transition this action exists to make; an account already
#                            disabled is not disabled again.
#   userPrincipalName        a rename between plan and dispatch means the operator's intent
#                            no longer names this subject.
#   onPremisesSyncEnabled    a directory-synced user cannot be durably disabled in the cloud,
#                            because the on-premises directory reverts it. Graph returns null
#                            for a cloud-only user and true for a synced one, so null and
#                            false are different answers and must hash differently.
GRAPH_USER_FIELDS: Mapping[str, tuple[type, ...]] = {
    "id": (str,),
    "accountEnabled": (bool,),
    "userPrincipalName": (str,),
    "onPremisesSyncEnabled": (bool, type(None)),
}


class CompositeDrift(ValueError):
    """The vendor did not answer the shape this recipe was written against."""


def graph_user_composite(user: Mapping[str, Any]) -> str:
    """Return the frozen version for a Graph user, or refuse the reading.

    An allowlist rather than a projection: Graph resources are open types, so a response
    carrying a field this recipe does not know is a response this recipe was not written
    against, and guessing is how a precondition ends up checking less than it claims.
    """
    if not isinstance(user, Mapping):
        raise CompositeDrift("A Graph user reading must be an object")
    unknown = set(user) - set(GRAPH_USER_FIELDS)
    if unknown:
        raise CompositeDrift(f"Unknown Graph user fields: {', '.join(sorted(unknown))}")
    missing = set(GRAPH_USER_FIELDS) - set(user)
    if missing:
        raise CompositeDrift(f"Missing Graph user fields: {', '.join(sorted(missing))}")

    content: dict[str, Any] = {"recipe": GRAPH_USER_V1}
    for field, allowed in GRAPH_USER_FIELDS.items():
        value = user[field]
        # `type(...) is` rather than isinstance: in Python True is an int, and a vendor that
        # answered 1 where it once answered true has drifted even though isinstance agrees.
        if not any(type(value) is candidate for candidate in allowed):
            raise CompositeDrift(f"Unexpected type for {field}")
        if type(value) is str and not value:
            raise CompositeDrift(f"Empty value for {field}")
        content[field] = value
    digest = hashlib.sha256(canonical_json(content).encode()).hexdigest()
    return f"{GRAPH_USER_V1}:{digest}"
