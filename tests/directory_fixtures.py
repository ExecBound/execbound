# SPDX-License-Identifier: AGPL-3.0-only
"""Shared setup for the directory's tests: autonomous executions an agent already made.

The Agents pages moved into the console when it replaced the old Jinja pages (#333) and
their Jinja tests went with them, but this helper describes activity rather than a page, so
it lives here for the console API's tests, the binding tests and the tenant line's.
"""

from test_execution import finish, targets

from execbound.execution import admit


def settle(db, engine, world, identity, count, *, executed=True):
    """``count`` autonomous isolations by ``identity``, settled as executed when asked."""
    admitted = []
    for req in targets(engine, world, count):
        admission = admit(db, identity, req, world["clock"])
        assert admission.ticket is not None
        if executed:
            finish(db, world, admission)
        admitted.append(admission)
    return admitted
