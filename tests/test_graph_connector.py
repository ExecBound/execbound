# SPDX-License-Identifier: AGPL-3.0-only
"""The Graph write path: one read, one comparison, at most one write, and every refusal.

The client holds no authority. These tests cover what it does against a socket — its real
URL building, its pinned origins, its bounds and its refusals — not what a dispatch makes of
the result, which is a separate contract.
"""

import httpx
import pytest

from execbound.provider.composite import graph_user_composite
from execbound.provider.graph import (
    GraphCredential,
    GraphDispatchError,
    GraphUserWriter,
)
from execbound_harness.fake_graph import CLIENT, DIRECTORY, SECRET, TOKEN, Scenario, serving
from execbound_harness.fake_graph import transport as fake_transport

USER_ID = "6f1b0c2e-6f40-4a2c-9a3f-2f6c0b1d7e55"
USER = {
    "id": USER_ID,
    "accountEnabled": True,
    "userPrincipalName": "agent@contoso.onmicrosoft.com",
    "onPremisesSyncEnabled": None,
}


def writer(server, secret=SECRET):
    client = httpx.Client(transport=fake_transport(server), follow_redirects=False)
    return GraphUserWriter(GraphCredential(DIRECTORY, CLIENT, secret), client)


def scenario(**changes):
    return Scenario(users={USER_ID: {**USER, **changes}})


def test_a_disable_reads_compares_and_writes_exactly_once():
    plan = graph_user_composite(USER)
    with serving(scenario()) as server:
        result = writer(server).disable(USER_ID, plan)
    assert result.patched and result.observed == plan
    assert result.window_ms >= 0
    # Exactly one write, asserted by what actually reached the socket rather than by a flag.
    touched = [entry for entry in server.requests if entry[0] == f"/v1.0/users/{USER_ID}"]
    assert len(touched) == 2  # one read, one write, and nothing else
    assert server.scenario.users[USER_ID]["accountEnabled"] is False


def test_a_change_after_the_read_is_undetectable_and_that_is_the_whole_window():
    """This is the limitation CHECKED_BY_CONNECTOR exists to state, pinned as a test.

    A vendor offering a conditional write would refuse this on the caller's behalf. Graph
    cannot, so a change landing between the read and the write goes through, and the
    measured window is the only honest account of the exposure. A test asserting a refusal
    here would be asserting a guarantee the design explicitly does not make, which is worse
    than no test: it would let someone later "fix" the connector to claim atomicity.
    """
    plan = graph_user_composite(USER)
    raced = scenario()
    raced.race = {"userPrincipalName": "someone-else@contoso.onmicrosoft.com"}
    with serving(raced) as server:
        result = writer(server).disable(USER_ID, plan)
    # The write landed on a subject that had already moved, and nothing detected it.
    assert result.patched
    assert server.scenario.users[USER_ID]["userPrincipalName"].startswith("someone-else")
    assert server.scenario.users[USER_ID]["accountEnabled"] is False
    # What the dispatch can honestly report is how long the gap was, not that it was empty.
    assert result.window_ms >= 0


def test_a_mismatch_refuses_before_any_write_is_attempted():
    """A stale plan must not reach the vendor at all, not merely fail afterwards."""
    with serving(scenario(accountEnabled=False)) as server:
        with pytest.raises(GraphDispatchError):
            writer(server).disable(USER_ID, graph_user_composite(USER))
        assert server.scenario.users[USER_ID]["accountEnabled"] is False
        # The read happened; nothing else did.
        assert len([e for e in server.requests if e[0] == f"/v1.0/users/{USER_ID}"]) == 1


def test_a_reading_the_recipe_was_not_written_against_is_schema_drift():
    with serving(scenario(jobTitle="Agent")) as server:
        with pytest.raises(GraphDispatchError) as refused:
            writer(server).disable(USER_ID, graph_user_composite(USER))
    assert refused.value.reason == "SCHEMA_DRIFT"


def test_the_select_context_graph_echoes_is_not_mistaken_for_a_field():
    """Graph returns @odata.context on a $select. Treating it as drift would refuse every
    real response, so it is dropped before the allowlist sees the reading."""
    plan = graph_user_composite(USER)
    with serving(scenario()) as server:
        assert writer(server).disable(USER_ID, plan).patched


@pytest.mark.parametrize(
    "status,reason",
    [(403, "FORBIDDEN"), (500, "REFUSED"), (409, "REFUSED")],
    ids=["forbidden-write", "server-error", "conflict"],
)
def test_a_refused_write_is_reported_rather_than_retried(status, reason):
    plan = graph_user_composite(USER)
    refusing = scenario()
    refusing.write_status = status
    with serving(refusing) as server:
        with pytest.raises(GraphDispatchError) as refused:
            writer(server).disable(USER_ID, plan)
        assert refused.value.reason == reason
        writes = [e for e in server.requests if e[0] == f"/v1.0/users/{USER_ID}"]
        # One read and one write attempt. A second write would be the resend that cannot
        # tell its own earlier success from someone else re-enabling the account.
        assert len(writes) == 2


def test_an_absent_target_is_not_a_drift_and_not_a_mismatch():
    with serving(Scenario(users={})) as server:
        with pytest.raises(GraphDispatchError) as refused:
            writer(server).disable(USER_ID, graph_user_composite(USER))
    assert refused.value.reason == "TARGET_ABSENT"


def test_a_rejected_credential_reports_auth_lost_and_reads_nothing():
    with serving(scenario()) as server:
        with pytest.raises(GraphDispatchError) as refused:
            writer(server, secret="wrong-secret").disable(USER_ID, graph_user_composite(USER))
        assert refused.value.reason == "AUTH_LOST"
        assert not [e for e in server.requests if e[0].startswith("/v1.0/users/")]


def test_no_failure_puts_the_secret_or_the_token_in_its_reason():
    """A reason is read by people and written to logs; neither credential belongs in one."""
    with serving(scenario(jobTitle="Agent")) as server:
        with pytest.raises(GraphDispatchError) as refused:
            writer(server).disable(USER_ID, graph_user_composite(USER))
    rendered = f"{refused.value.reason} {refused.value}"
    assert SECRET not in rendered and TOKEN not in rendered


def test_the_client_never_follows_a_redirect_or_trusts_the_environment():
    """A redirect off the pinned origin is how a write reaches somewhere it was not sent."""
    default = GraphUserWriter(GraphCredential(DIRECTORY, CLIENT, SECRET))
    try:
        assert default._client.follow_redirects is False
        assert default._client.trust_env is False
    finally:
        default.close()


def test_the_credential_keeps_its_secret_out_of_its_repr():
    assert SECRET not in repr(GraphCredential(DIRECTORY, CLIENT, SECRET))
