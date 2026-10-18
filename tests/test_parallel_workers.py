# SPDX-License-Identifier: AGPL-3.0-only
"""Each pytest worker connects to a database of its own, and to no other.

The suite truncates every table the product owns between tests, so two workers sharing one
database would empty each other's rows mid-test. The risk worth testing is not that
`TRUNCATE` crosses a database boundary, which is PostgreSQL's guarantee and not this
project's, but that two workers are routed to the same name, or that the routing widens the
set of databases local tooling will accept.
"""

import os

import pytest
from conftest import current_test_database, local_test_url

from execbound.connection import (
    TEST_DATABASE,
    database_url,
    local_database_url,
    worker_database,
)

OWNER = "execbound_owner"
RUNTIME = "execbound_app"


@pytest.mark.parametrize(
    ("worker", "expected"),
    [(None, TEST_DATABASE), ("master", TEST_DATABASE), ("gw0", f"{TEST_DATABASE}_gw0")],
    ids=["undistributed", "master", "worker-zero"],
)
def test_a_worker_is_named_its_own_database(worker, expected):
    assert worker_database(worker) == expected


def test_every_worker_gets_a_distinct_database():
    names = [worker_database(f"gw{n}") for n in range(64)]
    assert len(set(names)) == len(names)
    assert TEST_DATABASE not in names, "no worker may take the undistributed database"


@pytest.mark.parametrize(
    "worker",
    ["gw", "GW0", "gw0; DROP DATABASE execbound", "gw-1", "gw1000", "", "../execbound", "gw0 "],
    ids=["no-number", "upper", "injection", "negative", "too-many", "empty", "path", "space"],
)
def test_a_worker_id_xdist_would_never_produce_is_refused(worker):
    with pytest.raises(ValueError, match="INVALID_WORKER"):
        worker_database(worker)


def test_this_process_reads_and_writes_only_its_own_database():
    """The two URLs the suite runs on both name this process's database, and nothing else."""
    name = current_test_database()
    for variable, username in (
        ("TEST_DATABASE_URL", RUNTIME),
        ("TEST_MIGRATION_DATABASE_URL", OWNER),
    ):
        parsed = local_test_url(os.environ[variable], username)
        assert parsed.database == name
        assert parsed.username == username
        assert parsed.host in {"127.0.0.1", "localhost", "::1"}


def test_another_workers_database_is_refused_by_the_local_guard():
    """The allowlist stays a set of exactly one name; a sibling's name is not in it.

    This goes through `local_test_url`, the function the fixtures actually call, rather
    than through `local_database_url` with a hand-written allowlist. The first version did
    the latter and proved nothing: widening the real allowlist left it passing.
    """
    mine = current_test_database()
    sibling = next(name for name in (worker_database(f"gw{n}") for n in range(64)) if name != mine)
    sibling_url = (
        database_url(os.environ["TEST_MIGRATION_DATABASE_URL"])
        .set(database=sibling)
        .render_as_string(hide_password=False)
    )
    with pytest.raises(ValueError, match="exact loopback database"):
        local_test_url(sibling_url, OWNER)


def test_the_guard_still_refuses_what_it_always_refused():
    name = current_test_database()
    url = os.environ["TEST_MIGRATION_DATABASE_URL"]
    for broken in (
        url.replace("127.0.0.1", "10.0.0.1").replace("localhost", "10.0.0.1"),
        url.replace(OWNER, RUNTIME),
        url + "?sslmode=require",
        url.replace(name, "postgres"),
    ):
        with pytest.raises(ValueError):
            local_database_url(broken, databases={name}, username=OWNER)
