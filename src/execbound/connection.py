# SPDX-License-Identifier: AGPL-3.0-only
"""Validate the connection that psycopg will actually use, before any I/O."""

import os
import re
from typing import Any

from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
# PostgreSQL allows 63 bytes. Lowercase only, so no quoting question arises and the name
# a command is given is the name the server sees.
DATABASE_NAME = re.compile(r"[a-z][a-z0-9_]{0,62}")
TLS_OPTIONS = {"sslmode", "sslrootcert", "sslcert", "sslkey"}
# The single test database, and the workers that may each hold one of their own. pytest-xdist
# names a worker `gw0`, `gw1` and so on, and sets nothing at all for an undistributed run.
TEST_DATABASE = "execbound_test"
TEST_WORKER = re.compile(r"gw(0|[1-9][0-9]{0,2})")


def worker_database(worker: str | None) -> str:
    """The test database one pytest worker owns.

    The suite truncates every table the product owns between tests, so two workers sharing
    one database would empty each other's rows mid-test, non-deterministically. Each gets
    its own instead, named for the worker. An undistributed run has no worker and keeps the
    single `execbound_test` it has always used, so `pytest` with no flags is unchanged.

    The name is built here rather than read from configuration so that the set of databases
    local tooling will accept stays closed: a worker id that is not one xdist produces is
    refused rather than reaching a connection.
    """
    if worker is None or worker == "master":
        return TEST_DATABASE
    if type(worker) is not str or TEST_WORKER.fullmatch(worker) is None:
        raise ValueError("INVALID_WORKER")
    return f"{TEST_DATABASE}_{worker}"


def local_databases() -> set[str]:
    """The databases local tooling may open on the loopback server.

    The two named ones, plus the test database belonging to *this* process when it is a
    pytest worker. The worker's is its own and never a sibling's, so the set is at most
    three names and a worker cannot reach another worker's data. The base `execbound_test`
    stays in the set under a worker as well: it is still a real local database, code and
    fixtures name it literally, and dropping it would be a narrowing this change has no
    reason to make. Outside pytest `PYTEST_XDIST_WORKER` is unset and the set is exactly
    the two names it has always been, so nothing about a deployed run changes.
    """
    return {"execbound", TEST_DATABASE, worker_database(os.environ.get("PYTEST_XDIST_WORKER"))}


def database_url(value: str | URL) -> URL:
    try:
        parsed = make_url(value)
    except (ArgumentError, ValueError):
        raise ValueError("Invalid PostgreSQL connection URL") from None
    if parsed.drivername != "postgresql+psycopg":
        raise ValueError("Database URLs must use postgresql+psycopg")
    if not all((parsed.host, parsed.username, parsed.password, parsed.database)):
        raise ValueError("Database URL must specify host, database, username and password")
    if set(parsed.query) - TLS_OPTIONS or any(
        type(item) is not str for item in parsed.query.values()
    ):
        raise ValueError("Database URL query accepts only unique TLS options")
    if parsed.host not in LOOPBACK_HOSTS and (
        parsed.query.get("sslmode") != "verify-full" or not parsed.query.get("sslrootcert")
    ):
        raise ValueError("Remote PostgreSQL requires sslmode=verify-full and sslrootcert")
    return parsed


def with_database_name(value: str | URL, name: str) -> URL:
    """The same connection with another database name, as an object.

    A restored copy sits on the server the caller is already configured for, so only the
    name changes. Returning a `URL` rather than a string is the point: SQLAlchemy hides a
    password when it renders one, so asking it not to has to be a deliberate act, and
    changing a database name is not a reason to perform one. The refusal names
    `INVALID_DATABASE` and never echoes the value it was given.
    """
    if type(name) is not str or DATABASE_NAME.fullmatch(name) is None:
        raise ValueError("INVALID_DATABASE")
    return database_url(value).set(database=name)


def local_database_url(value: str, *, databases: set[str], username: str) -> URL:
    parsed = database_url(value)
    if (
        parsed.host not in LOOPBACK_HOSTS
        or parsed.database not in databases
        or parsed.username != username
        or parsed.query
    ):
        raise ValueError(
            "Local tooling requires its exact loopback database and role without query options"
        )
    return parsed


def connect_args(parsed: URL) -> dict[str, Any]:
    # Explicit libpq parameters take precedence over PGPORT/PGHOSTADDR and service
    # defaults. A loopback URL must never be redirected to a remote address.
    args: dict[str, Any] = {
        "port": parsed.port or 5432,
        "connect_timeout": 5,
        "prepare_threshold": None,
    }
    if parsed.host in LOOPBACK_HOSTS:
        args["hostaddr"] = "::1" if parsed.host == "::1" else "127.0.0.1"
    return args
