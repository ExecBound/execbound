# SPDX-License-Identifier: AGPL-3.0-only
"""The executor protocol specification says what the code does (#37).

`docs/protocol/EXECUTOR_PROTOCOL.md` is the normative text for anyone building an executor, and
it is written from the code rather than beside it. Prose cannot be checked by a machine; its
tables can, and these tests hold each one equal to the thing it describes: the routes each
reference mock registers and the credential each route accepts, the catalog bindings the
protocol reaches, every field of every object it names, the outcome pairs, the precondition
classes, each refusal and its reference answer, both conformance modules' checks, and the
settlement table, which the checkpoint report vectors and the server's outcome route are held
to as well. A table that drifts from the code fails here, by name. The links it carries are
checked too, anchors included, because the documentation site refuses a broken one.
"""

import hashlib
import re
from pathlib import Path
from typing import get_args
from uuid import uuid4

import pytest
from checkpoint_vectors import published
from execbound_connectors.accounts import ProviderAccount
from execbound_connectors.identity_store import IdentityStore
from execbound_connectors.mock import ConnectionConfig
from execbound_connectors.mock_app import create_mock_app
from execbound_connectors.mock_store import MockStore
from execbound_protocol.catalog import PRODUCTION_ACTIONS
from execbound_protocol.checkpoint_conformance import CHECKS as REPORT_CHECKS
from execbound_protocol.checkpoint_conformance import REFUSED_AS
from execbound_protocol.conformance import CHECKS
from execbound_protocol.executor import ExecutorRecord, JwsClaims, JwsHeader, SignedOutcome
from execbound_protocol.outcomes import TERMINAL_PAIRS
from execbound_protocol.provider import (
    MAX_PROVIDER_BYTES,
    JournalRecord,
    ProviderCommand,
    SignedJournal,
)
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from pydantic import BaseModel

from execbound.execution.models import CheckpointGrant, PreconditionClass
from execbound.execution.outcomes import OutcomeReport

# Reads a document, so it carries `docs` and `pytest -m docs` selects it (#748).
pytestmark = pytest.mark.docs

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs" / "protocol" / "EXECUTOR_PROTOCOL.md"
TEXT = SPEC.read_text(encoding="utf-8") if SPEC.exists() else ""
KEYWORDS = re.compile(r"\b(?:MUST|MUST NOT|REQUIRED|SHALL|SHALL NOT|SHOULD|SHOULD NOT|MAY)\b")


def cell(value: str) -> str:
    """A table cell's text, unquoted when the whole cell is one code span."""
    value = value.strip()
    if len(value) > 1 and value[0] == value[-1] == "`" and "`" not in value[1:-1]:
        return value[1:-1]
    return value


def table(*header: str) -> list[list[str]]:
    """The rows of the one table whose header is exactly `header`, each cell unquoted."""
    found = []
    lines = TEXT.splitlines()
    for index, line in enumerate(lines):
        cells = [cell(part) for part in line.strip().strip("|").split("|")]
        if not line.startswith("|") or tuple(cells) != header:
            continue
        rows = []
        for row in lines[index + 2 :]:
            if not row.startswith("|"):
                break
            rows.append([cell(part) for part in row.strip().strip("|").split("|")])
        found.append(rows)
    assert len(found) == 1, f"the specification holds {len(found)} tables headed {header}"
    return found[0]


def column(*header: str) -> list[str]:
    return [row[0] for row in table(*header)]


def test_the_specification_exists_and_uses_rfc_2119_words():
    assert TEXT, "docs/protocol/EXECUTOR_PROTOCOL.md is missing"
    assert "RFC 2119" in TEXT and "RFC 8174" in TEXT
    assert KEYWORDS.search(TEXT)


def chapters() -> dict[str, str]:
    parts = re.split(r"^## ", TEXT, flags=re.M)
    return {part.splitlines()[0]: part for part in parts[1:]}


def test_chapter_three_specifies_nothing_and_says_so():
    """Registration and the pull transport are not built, so chapter 3 is a pointer: a
    requirement written there would be a promise no code keeps."""
    (title,) = [name for name in chapters() if name.startswith("3. ")]
    body = chapters()[title]
    assert KEYWORDS.search(body) is None, body
    assert "not yet specified" in body.lower()


def test_versions_are_stated_as_unreleased_and_served_by_main():
    rows = table("Part", "Version", "Served by")
    assert [row[0] for row in rows] == [
        "The executor protocol",
        "The checkpoint report",
        "Registration and the pull transport",
    ]
    assert [row[1] for row in rows] == ["1", "1", "none"]
    assert rows[0][2] == rows[1][2] == "Unreleased; served by the main branch"
    assert rows[2][2] == "Not yet specified"


# Chapter 1: routes, bindings and credentials.

PROTOCOL_PROVIDERS = ("mock_crowdstrike", "mock_entra")
DISPATCH, CONTROL = "spec-dispatch-token-0001", "spec-control-token-0001"


def test_the_protocol_reaches_exactly_the_providers_a_connection_admits():
    """ExecBound dispatches over this protocol through `ConnectionConfig`, which names the
    providers it admits; every other catalog provider has a connector of its own."""
    admitted = set()
    for provider in sorted({binding.provider for binding in PRODUCTION_ACTIONS.bindings}):
        try:
            ConnectionConfig(
                tenant_id=uuid4(),
                account_id=uuid4(),
                origin="http://127.0.0.1:8010",
                dispatch_token=DISPATCH,
                control_token=CONTROL,
                evidence_keys={"k": b"\x00" * 32},
                provider=provider,
            )
        except ValueError:
            continue
        admitted.add(provider)
    assert admitted == set(PROTOCOL_PROVIDERS)
    assert {row[0] for row in table("Provider", "Action", "Dispatch route")} == admitted


def test_the_binding_table_is_the_catalog_for_those_providers():
    rows = {tuple(row) for row in table("Provider", "Action", "Dispatch route")}
    assert rows == {
        (binding.provider, binding.action, "/v1/" + binding.provider_operation)
        for provider in PROTOCOL_PROVIDERS
        for binding in PRODUCTION_ACTIONS.bindings_for(provider)
    }


def account(provider: str) -> tuple[ProviderAccount, ProviderCommand]:
    binding = PRODUCTION_ACTIONS.bindings_for(provider)[0]
    command = ProviderCommand(
        tenant_id=uuid4(),
        account_id=uuid4(),
        canonical_target_id=uuid4(),
        provider=provider,
        action=binding.action,
        provider_operation=binding.provider_operation,
        resource_provider_id="spec-target",
        expected_version="resource-v1",
        operation_id=uuid4(),
        execution_id=uuid4(),
        intent_hash="a" * 64,
        plan_hash="b" * 64,
    )
    return (
        ProviderAccount(
            tenant_id=command.tenant_id,
            account_id=command.account_id,
            dispatch_token_hash=hashlib.sha256(DISPATCH.encode()).hexdigest(),
            control_token_hash=hashlib.sha256(CONTROL.encode()).hexdigest(),
            signing_key=b"\x02" * 32,
            provider=provider,
        ),
        command,
    )


def mock(tmp_path: Path, provider: str) -> tuple[TestClient, ProviderCommand, object]:
    store_class = IdentityStore if provider == "mock_entra" else MockStore
    store = store_class(tmp_path / f"{provider}.sqlite3")
    provider_account, command = account(provider)
    store.provision_resource(command.tenant_id, command.canonical_target_id, "resource-v1")
    store.provision_representation(
        command.tenant_id, command.account_id, "spec-target", command.canonical_target_id
    )
    app = create_mock_app(store, (provider_account,), provider=provider)
    return TestClient(app), command, app


def expanded_routes(provider: str) -> set[tuple[str, frozenset[str]]]:
    """The route table, with its one templated dispatch row expanded by the binding table."""
    dispatch = {
        row[2] for row in table("Provider", "Action", "Dispatch route") if row[0] == provider
    }
    routes = set()
    for route, method, _, _ in table("Route", "Method", "Credential", "What it answers"):
        paths = dispatch if route == "/v1/{provider_operation}" else {route}
        routes |= {(path, frozenset({method})) for path in paths}
    return routes


@pytest.mark.parametrize("provider", PROTOCOL_PROVIDERS)
def test_the_route_table_is_the_routes_each_reference_mock_registers(tmp_path, provider):
    _, _, app = mock(tmp_path, provider)
    registered = {
        (route.path, frozenset(route.methods))
        for route in app.routes  # type: ignore[attr-defined]
        if isinstance(route, APIRoute)
    }
    assert registered == expanded_routes(provider)
    # Nothing else answers: FastAPI's documentation routes are off on the mocks.
    assert all(isinstance(route, APIRoute) for route in app.routes)  # type: ignore[attr-defined]


@pytest.mark.parametrize("provider", PROTOCOL_PROVIDERS)
def test_each_route_accepts_exactly_the_credentials_the_table_names(tmp_path, provider):
    client, command, _ = mock(tmp_path, provider)
    dispatch_route = "/v1/" + command.provider_operation
    for route, _, credential, _ in table("Route", "Method", "Credential", "What it answers"):
        named = {role for role in ("dispatch", "control") if role in credential}
        assert named, (route, credential)
        path = dispatch_route if route == "/v1/{provider_operation}" else route
        for role, token in (("dispatch", DISPATCH), ("control", CONTROL)):
            fresh = command.model_copy(update={"operation_id": uuid4()})
            response = client.post(
                path,
                content=fresh.model_dump_json(),
                headers={"Authorization": f"Bearer {token}"},
            )
            accepted = response.status_code != 401
            assert accepted == (role in named), (route, role, response.status_code)


# Every object the specification describes field by field.


def fields(model: type[BaseModel]) -> set[str]:
    return {name for name, info in model.model_fields.items() if not info.exclude}


@pytest.mark.parametrize(
    ("header", "model"),
    [
        (("Command field", "Type", "Meaning"), ProviderCommand),
        (("Record field", "Type", "Meaning"), JournalRecord),
        (("Signed journal field", "Type", "Meaning"), SignedJournal),
        (("Executor record field", "Type", "Meaning"), ExecutorRecord),
        (("Signed outcome field", "Type", "Meaning"), SignedOutcome),
        (("JWS header member", "Meaning"), JwsHeader),
        (("JWS claim", "Meaning"), JwsClaims),
        (("Report field", "Contract"), OutcomeReport),
    ],
    ids=lambda value: value.__name__ if isinstance(value, type) else value[0],
)
def test_each_field_table_names_every_field_of_its_model(header, model):
    assert set(column(*header)) == fields(model)


def test_the_grant_table_is_what_the_presenter_sends():
    """The grant is the model's own fields plus `provider_command`, which the runtime's
    presenter adds, and minus the frozen command it never serializes."""
    assert set(column("Grant field", "Meaning")) == fields(CheckpointGrant) | {"provider_command"}
    assert "command" not in column("Grant field", "Meaning")


def test_the_outcome_pairs_are_the_protocols():
    rows = table("Reason", "Outcome", "Signed evidence may carry it")
    assert {row[0]: row[1] for row in rows} == dict(TERMINAL_PAIRS)
    signable = set(get_args(ExecutorRecord.model_fields["reason"].annotation))
    assert {row[0] for row in rows if row[2] == "yes"} == signable
    assert {row[2] for row in rows} == {"yes", "no"}


def test_the_journal_outcomes_are_the_records():
    outcomes = column("Outcome", "Mutations", "resulting_version", "Settles as")
    assert set(outcomes) == set(get_args(JournalRecord.model_fields["outcome"].annotation))


def test_the_precondition_classes_are_the_models_literal():
    classes = column(
        "Class", "What the grant carries", "What the executor does", "What a report means"
    )
    assert len(classes) == len(set(classes))
    assert set(classes) == set(get_args(PreconditionClass))


def test_the_bound_the_text_states_is_the_parsers():
    assert f"{MAX_PROVIDER_BYTES:,} bytes" in TEXT


# Refusals. The rows are the reference mock's answers; each is sent here and its status read.


def refusal_requests(command: ProviderCommand):
    body = command.model_dump_json().encode()
    dispatch = {"Authorization": f"Bearer {DISPATCH}"}
    control = {"Authorization": f"Bearer {CONTROL}"}
    unknown = command.model_copy(update={"operation_id": uuid4()}).model_dump_json().encode()
    other_account = command.model_copy(update={"account_id": uuid4()})
    changed = command.model_copy(update={"expected_version": "another-version"})
    return {
        "A missing, malformed or unknown credential": ("/v1/contain", body, {}),
        "A credential of the wrong role for the route": ("/v1/contain", body, control),
        "A repeated `Authorization` header, a query string, or an `x-tenant-id`, "
        "`x-account-id`, `x-principal-id` or `x-role` header": (
            "/v1/contain",
            body,
            {**dispatch, "x-tenant-id": str(uuid4())},
        ),
        "A body over the bound, malformed JSON, a repeated key, a number that is not an "
        "integer, an unknown field, an unserved version, an action the catalog does not bind "
        "to the operation, or arguments the action does not admit": (
            "/v1/contain",
            b'{"version":1.0}',
            dispatch,
        ),
        "A command whose `provider_operation` is not the route's": (
            "/v1/lift_containment",
            body,
            dispatch,
        ),
        "A command naming another tenant, account or provider than the credential's": (
            "/v1/contain",
            other_account.model_dump_json().encode(),
            dispatch,
        ),
        "`/v1/journal` for an operation the journal does not hold": (
            "/v1/journal",
            unknown,
            dispatch,
        ),
        "A command that differs from the retained command under the same `operation_id`": (
            "/v1/contain",
            changed.model_dump_json().encode(),
            dispatch,
        ),
    }


def test_each_refusal_is_the_reference_mocks_answer(tmp_path):
    client, command, _ = mock(tmp_path, "mock_crowdstrike")
    assert client.post(
        "/v1/contain",
        content=command.model_dump_json(),
        headers={"Authorization": f"Bearer {DISPATCH}"},
    ).is_success
    rows = table("Refused", "Reference answer")
    requests = refusal_requests(command)
    stated = {row[0]: row[1] for row in rows}
    unavailable = "Anything the executor cannot complete, its own store failing included"
    assert set(stated) == set(requests) | {unavailable}
    assert stated[unavailable] == "503"
    for refused, (path, body, headers) in requests.items():
        response = client.post(path, content=body, headers=headers)
        assert str(response.status_code) == stated[refused], refused
        assert response.json() == {"detail": "Provider request unavailable"}, refused
        assert response.headers["cache-control"] == "no-store", refused


# The conformance module and the links.


def test_the_conformance_table_is_the_modules_checks():
    assert tuple(column("Check", "What it asserts")) == CHECKS


def test_the_report_conformance_table_is_the_modules_checks():
    rows = table("Report check", "What it asserts", "Refused as")
    assert tuple(row[0] for row in rows) == REPORT_CHECKS
    for name, _, refused in rows:
        if name in REFUSED_AS:
            assert refused == REFUSED_AS[name], name
        else:
            assert refused.startswith("Accepted; "), name


# The words section 2.8 settles in, as the vectors write them.
SETTLED = {"Confirmed": "CONFIRMED", "Released": "RELEASED", "Charged": "CHARGED", "Held": "HELD"}


def test_the_settlement_table_is_the_checkpoint_report_vectors():
    """Every row of section 2.8 has a vector and every vector is a row, settling exactly as the
    row says; `tests/test_checkpoint_report_server.py` holds the server to the same vectors."""
    rows = {
        row[0].replace("`", ""): row[1:]
        for row in table("Report", "State", "Tier", "Impact", "Target claim")
    }
    vectors = published().vectors
    assert {vector.row for vector in vectors} == set(rows)
    by_name = {vector.name: vector for vector in vectors}
    for vector in vectors:
        state, tier, impact, claim = rows[vector.row]
        settles = vector.settles
        if vector.row == "A provider's journal":
            # The journal's rows are the attested rows of the same reason, at its own tier.
            assert state == "As the journal's outcome, the same three rows"
            assert impact == "As the attested rows"
            attested = by_name["record-" + vector.name.removeprefix("journal-")].settles
            assert (settles.state, settles.impact) == (attested.state, attested.impact)
        else:
            assert settles.state == state, vector.name
            assert settles.impact == SETTLED[impact], vector.name
        assert settles.tier == (None if tier == "none" else tier), vector.name
        assert settles.claim == SETTLED[claim.split(";")[0]], vector.name


def test_each_refusal_vector_is_a_refusal_of_section_2_9():
    statuses = {row[1]: row[2] for row in table("Refusal", "Code", "Status")}
    for refusal in published().refusals:
        assert statuses[refusal.code] == "400", refusal.name


def slug(heading: str) -> str:
    """GitHub's and Docusaurus's anchor for a heading."""
    text = re.sub(r"[`*]", "", heading.strip().lower())
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    return {slug(match[1]) for match in re.finditer(r"^#{1,6} (.+)$", text, re.M)}


def test_every_link_resolves_and_every_anchor_exists():
    links = re.findall(r"\]\(([^)\s]+)\)", re.sub(r"```.*?```", "", TEXT, flags=re.S))
    assert links
    for link in links:
        if link.startswith(("http://", "https://")):
            continue
        path, _, anchor = link.partition("#")
        target = SPEC if not path else (SPEC.parent / path).resolve()
        assert target.is_file(), link
        if anchor and target.suffix == ".md":
            assert anchor in anchors(target), link


@pytest.mark.parametrize("guide", ["PROVIDER.md", "CHECKPOINT.md"])
def test_the_guides_point_at_the_specification_as_the_normative_text(guide):
    text = (ROOT / "docs" / guide).read_text(encoding="utf-8")
    links = re.findall(r"\]\((protocol/EXECUTOR_PROTOCOL\.md(?:#[^)]+)?)\)", text)
    assert links, guide
    for link in links:
        _, _, anchor = link.partition("#")
        assert not anchor or anchor in anchors(SPEC), link
    assert "normative" in text
