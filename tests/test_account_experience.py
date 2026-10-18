# SPDX-License-Identifier: AGPL-3.0-only
"""Account preferences and requests cannot alter another user's state."""

import pytest
from test_human_sessions import humans as humans

from execbound import accounts
from execbound.surfaces.sessions import issue_session, load_session

pytestmark = pytest.mark.integration


def test_data_requests_are_idempotent_and_visible_only_to_the_requester(db, humans):
    session = load_session(db, issue_session(db, humans[0]).token)
    for _ in range(2):
        accounts.change(db, session, "request", {"kind": "data_access"})
    requests = accounts.overview(db, session)["requests"]
    assert len(requests) == 1 and requests[0]["kind"] == "data_access"
    other = load_session(db, issue_session(db, humans[1]).token)
    assert accounts.overview(db, other)["requests"] == []


def test_display_name_is_bounded_and_updates_only_own_profile(db, humans):
    session = load_session(db, issue_session(db, humans[0]).token)
    accounts.change(db, session, "profile", {"name": "Dana Reyes"})
    assert accounts.overview(db, session)["name"] == "Dana Reyes"
    with pytest.raises(accounts.AccountError):
        accounts.change(db, session, "profile", {"name": ""})
    with pytest.raises(accounts.AccountError):
        accounts.change(
            db, session, "profile", {"name": "Dana", "principal_id": str(humans[1].principal_id)}
        )
