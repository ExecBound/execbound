# SPDX-License-Identifier: AGPL-3.0-only
"""Intake-only loopback origin for an explicitly started temporary HTTPS tunnel."""

import argparse
import os

import uvicorn
from dotenv import load_dotenv
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from execbound.app import create_app
from execbound.connection import local_database_url
from execbound.db import Database


def create_ingress(db: Database) -> ASGIApp:
    application = create_app(db)

    async def boundary(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        if scope["type"] == "http" and (
            scope["method"] != "POST" or scope.get("raw_path") != b"/v1/monitor/events"
        ):
            response = JSONResponse(
                {"detail": "Not found"},
                status_code=404,
                headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
            )
            await response(scope, receive, send)
            return
        await application(scope, receive, send)

    return boundary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8122)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Port must be between 1024 and 65535")
    db = None
    try:
        load_dotenv()
        url = os.environ["DATABASE_URL"]
        local_database_url(url, databases={"execbound"}, username="execbound_app")
        db = Database(url)
        uvicorn.run(
            create_ingress(db),
            host="127.0.0.1",
            port=args.port,
            access_log=False,
            log_level="warning",
        )
    except Exception:
        parser.exit(1, "Local monitoring ingress unavailable.\n")
    finally:
        if db is not None:
            db.close()


if __name__ == "__main__":
    main()
