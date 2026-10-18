# SPDX-License-Identifier: AGPL-3.0-only
"""Shared monitoring setup: one collection run against the fake directory.

The `/monitor/{view}` pages moved into the console when it replaced the old Jinja pages
(#333) and their Chromium tests went with them; this collects rows rather than rendering
them, so the console API's monitoring tests and the console's own Chromium pass read it
here.
"""

import httpx
from test_scout_run import detailed_scenario

from execbound.monitoring import graph
from execbound.monitoring import store as monitor_store
from execbound_harness.fake_graph import CLIENT, DIRECTORY, SECRET, serving, transport

GRAPH_URL = "https://graph.microsoft.com"
# A display name a directory could genuinely hold, which must never become markup.
HOSTILE_NAME = '<script>alert("x")</script> payroll'


def collect(db, admin, clock, *, scenario=None):
    connection_id = monitor_store.create_connection(
        db,
        admin,
        label="Synthetic directory",
        base_url=GRAPH_URL,
        key_fingerprint=graph.fingerprint(SECRET),
        kind="entra_agent_id",
        directory_ref=DIRECTORY,
        client_ref=CLIENT,
        clock=clock,
    )
    with serving(scenario or detailed_scenario()) as server:
        with httpx.Client(
            transport=transport(server), trust_env=False, follow_redirects=False
        ) as http:
            graph.run(
                db,
                admin,
                connection_id=connection_id,
                client_secret=SECRET,
                client=http,
                clock=clock,
            )
    return connection_id
