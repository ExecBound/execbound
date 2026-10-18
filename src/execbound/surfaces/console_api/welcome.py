# SPDX-License-Identifier: AGPL-3.0-only
"""`/api/console/v1/welcome/example`: the fixed synthetic Cedar examples (#333)."""

from fastapi import APIRouter, Request
from starlette.concurrency import run_in_threadpool

from execbound.runtime import Runtime
from execbound.surfaces.console_api.bodies import body as body_of
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.console_api.learning import LearningRequest, LearningResult, example
from execbound.surfaces.human import HumanConfig


def welcome_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.post(
        "/welcome/example",
        response_model=LearningResult,
        operation_id="runLearningExample",
        openapi_extra=body_of(LearningRequest),
    )
    async def run_example(request: Request) -> LearningResult:
        _, body = await guards.mutation(request, LearningRequest, kind="ADMIN")
        # Session authority is checked by the shared guard; the example has no live inputs.
        try:
            return await run_in_threadpool(example, body.scenario)
        except ValueError:
            raise ApiError("UNAVAILABLE") from None
