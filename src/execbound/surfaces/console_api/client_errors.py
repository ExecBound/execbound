# SPDX-License-Identifier: AGPL-3.0-only
"""`POST /api/console/v1/client-errors`: what the console reports when a page throws.

The report is the route, the release, the error's name and a hash of the component stack
(#333): never a message text
and never a page's data, which is why the route is a path with no query and the model refuses
any other field. The report becomes one structured log event and is stored nowhere else.
"""

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from execbound.logging_schema import log_event
from execbound.runtime import Runtime
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.human import HumanConfig


class ClientErrorReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    route: str = Field(min_length=1, max_length=200, pattern=r"^/[A-Za-z0-9/_.$-]*$")
    release: str = Field(max_length=40, pattern=r"^[0-9a-f]*$")
    name: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_.:\- ]+$")
    stack_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


def client_error_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.post(
        "/client-errors", status_code=204, response_class=Response, operation_id="reportClientError"
    )
    async def report_client_error(request: Request) -> Response:
        current, report = await guards.mutation(request, ClientErrorReport, max_bytes=4096)
        log_event(
            "console.client_error",
            level="WARNING",
            tenant_id=str(current.identity.tenant_id),
            principal_id=str(current.identity.principal_id),
            route=report.route,
            release=report.release,
            error_name=report.name,
            stack_hash=report.stack_hash,
        )
        return Response(status_code=204)
