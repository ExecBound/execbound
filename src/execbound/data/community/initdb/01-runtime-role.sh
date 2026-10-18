#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Create the restricted runtime role the gateway connects as.
#
# It owns no tables and cannot bypass row-level security; `GET /health/ready` refuses a
# role that can, so this is not a hardening nicety, it is what makes the gateway start.
# The owner role is the one the image created from POSTGRES_USER.
#
# This runs once, on an empty data directory. A database that already exists keeps the
# role it was created with.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE execbound_app
  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS
  PASSWORD '$EXECBOUND_APP_PASSWORD';
SQL
