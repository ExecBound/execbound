# SPDX-License-Identifier: AGPL-3.0-only
"""Migrations run only through a separately supplied owner connection."""

import os

from alembic import context
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection
from sqlalchemy.pool import NullPool

from execbound.connection import connect_args, database_url

if context.is_offline_mode():
    raise RuntimeError("Use an online owner connection for privilege-aware migrations")


def prepare(connection: Connection) -> None:
    # The version table lives with the private application tables, outside public.
    connection.execute(text("CREATE SCHEMA IF NOT EXISTS execbound"))
    connection.execute(text("REVOKE ALL ON SCHEMA execbound FROM PUBLIC"))


shared = context.config.attributes.get("connection")
if shared is not None:
    # A caller's own owner connection, inside a transaction it began and will end (Alembic's
    # shared-connection recipe): every pending migration runs in it and nothing here commits,
    # so the caller can do more in the same transaction and commit all of it or none. Alembic
    # sees the open transaction and makes `begin_transaction` a no-op. Nothing in core passes
    # one; a plugin's owner command does.
    prepare(shared)
    context.configure(connection=shared, version_table_schema="execbound")
    with context.begin_transaction():
        context.run_migrations()
else:
    load_dotenv()
    url = context.config.attributes.get("database_url") or os.environ["MIGRATION_DATABASE_URL"]
    parsed = database_url(url)
    engine = create_engine(
        parsed, poolclass=NullPool, hide_parameters=True, connect_args=connect_args(parsed)
    )
    with engine.connect() as connection:
        prepare(connection)
        connection.commit()
        context.configure(connection=connection, version_table_schema="execbound")
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()
