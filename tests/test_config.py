# SPDX-License-Identifier: AGPL-3.0-only
import pytest

from execbound.connection import connect_args, database_url, local_database_url
from execbound.db import Database


@pytest.mark.parametrize(
    "url",
    [
        "sqlite:///ignored.db",
        "postgresql+psycopg://runtime:secret@db.example.com/postgres",
        "postgresql+psycopg://runtime:secret@db.example.com/postgres?sslmode=require",
        "postgresql+psycopg://runtime:secret@db.example.com/postgres?sslmode=verify-full",
    ],
)
def test_remote_tls_and_postgresql_are_required(url):
    with pytest.raises(ValueError) as error:
        Database(url)
    assert "secret" not in str(error.value)


def test_verified_tls_connection_can_be_configured():
    db = Database(
        "postgresql+psycopg://runtime:secret@db.example.com/postgres"
        "?sslmode=verify-full&sslrootcert=system"
    )
    db.close()


@pytest.mark.parametrize(
    "query",
    [
        "host=remote.example",
        "hostaddr=192.0.2.1",
        "dbname=production",
        "user=postgres",
        "service=production",
        "port=5432",
        "password=changed",
    ],
)
def test_query_cannot_override_database_authority(query):
    with pytest.raises(ValueError):
        Database("postgresql+psycopg://runtime:secret@127.0.0.1:55439/execbound_test?" + query)


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+psycopg://execbound_owner:secret@127.0.0.1/execbound",
        "postgresql+psycopg://execbound_app:secret@127.0.0.1/execbound_test",
        "postgresql+psycopg://execbound_owner:secret@127.0.0.1/another_test",
        "postgresql+psycopg://execbound_owner:secret@127.0.0.1/execbound_test?sslmode=disable",
        "postgresql+psycopg://execbound_owner:secret@remote.example/execbound_test?sslmode=verify-full&sslrootcert=system",
    ],
)
def test_local_tooling_requires_exact_database_and_role(url):
    with pytest.raises(ValueError):
        local_database_url(url, databases={"execbound_test"}, username="execbound_owner")


def test_loopback_connection_pins_address_and_port(monkeypatch):
    monkeypatch.setenv("PGHOSTADDR", "192.0.2.1")
    monkeypatch.setenv("PGPORT", "1")
    parsed = database_url("postgresql+psycopg://owner:secret@localhost/execbound_test")
    options = connect_args(parsed)
    assert options["hostaddr"] == "127.0.0.1"
    assert options["port"] == 5432
