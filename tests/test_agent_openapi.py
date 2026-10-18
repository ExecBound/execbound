# SPDX-License-Identifier: AGPL-3.0-only
"""The published agent API document describes the routes the gateway serves, and is current.

The gateway's agent routes read their own bodies, so the document is written from the models
they validate with (`surfaces/agent_openapi.py`), and it opens with the sections a caller
reads first (`surfaces/agent_api_guide.py`). These tests hold it to the router, to the error
table the gateway answers with, and to the limits the gateway enforces.
"""

import json
import re
from pathlib import Path
from typing import cast

from test_route_authority import SERVED

from execbound.requests import ActionRequest
from execbound.runtime import Runtime
from execbound.surfaces.agent_api_guide import ERROR_MEANINGS
from execbound.surfaces.agent_openapi import agent_api_document, codes_by_status
from execbound.surfaces.http import ERROR_STATUS, router

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = ROOT / "docs" / "api" / "agent-v1.json"


def operations(document: dict) -> set[tuple[str, str]]:
    return {(path, method.upper()) for path, item in document["paths"].items() for method in item}


def test_the_committed_document_is_current():
    rendered = json.dumps(agent_api_document(), indent=2, sort_keys=True) + "\n"
    assert DOCUMENT.read_text(encoding="utf-8") == rendered, "run scripts/agent_openapi.py"


def test_the_document_describes_exactly_the_agent_routes_the_gateway_serves():
    served = {
        (route.path, method)
        for route in router(cast(Runtime, None)).routes
        for method in route.methods  # type: ignore[attr-defined]
    }
    assert ("/v1/me", "GET") in SERVED
    for operation in served:
        assert operation in SERVED, operation
    assert operations(agent_api_document()) == served | {("/v1/me", "GET")}


def test_the_request_body_is_the_model_the_gateway_parses():
    schemas = agent_api_document()["components"]["schemas"]
    assert set(schemas["ActionRequest"]["properties"]) == set(ActionRequest.model_fields)
    execute = agent_api_document()["paths"]["/v1/execute"]["post"]
    body = execute["requestBody"]["content"]["application/json"]["schema"]
    assert body == {"$ref": "#/components/schemas/ActionRequest"}


def test_every_status_the_gateway_can_answer_is_documented_on_every_execution_route():
    statuses = {str(status) for status in ERROR_STATUS.values()} | {"200", "202", "401", "503"}
    for path in ("/v1/execute", "/v1/executions/{execution_id}"):
        for operation in agent_api_document()["paths"][path].values():
            assert set(operation["responses"]) == statuses, path
    grouped = codes_by_status()
    for code, status in ERROR_STATUS.items():
        assert code in grouped[status]


def introduction() -> str:
    return agent_api_document()["info"]["description"]


def test_the_reference_opens_with_authentication_before_any_route():
    """A reader finds how to authenticate on the same page as the routes, ahead of them."""
    headings = [line for line in introduction().splitlines() if line.startswith("## ")]
    assert headings == [
        "## Authentication",
        "## Requests",
        "## Responses",
        "## Errors",
        "## Rate limits",
        "## MCP",
    ]
    text = introduction()
    for needed in ("Authorization: Bearer <API key>", "### Get an API key", "GET /v1/me"):
        assert needed in text, needed


def test_the_guide_is_true_on_a_deployment_of_any_address():
    """A self-hosted install serves this guide too. It names the hosted gateway, its server,
    once, as the hosted service's, and the steps and examples a reader follows name none."""
    document = agent_api_document()
    [server] = document["servers"]
    hosted = server["url"].removeprefix("https://")
    text = introduction()
    assert text.count(hosted) == 1
    assert f"The hosted service answers at `https://{hosted}`" in text


def test_every_code_the_gateway_answers_is_explained_and_nothing_else():
    answered = {code for codes in codes_by_status().values() for code in codes}
    assert set(ERROR_MEANINGS) == answered


def test_the_errors_section_lists_every_code_at_its_status():
    rows = re.findall(r"^\| (\d{3}) \| `([A-Z_]+)` \|", introduction(), re.M)
    documented = {code: int(status) for status, code in rows}
    for status, codes in codes_by_status().items():
        for code in codes:
            assert documented.get(code) == status, code
    assert len(rows) == len(documented), "a code is listed twice"


def test_the_documented_limits_are_the_gateways():
    from execbound.surfaces.limits import RequestLimits

    limits = RequestLimits()
    text = introduction()
    assert (
        f"| Requests per API key | {limits.agent_requests} per {limits.agent_window_seconds} "
        in text
    )
    assert f"| {limits.client_requests:,} per {limits.client_window_seconds} seconds |" in text
