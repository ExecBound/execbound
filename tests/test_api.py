# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from fastapi.testclient import TestClient

from execbound.app import create_app
from execbound.db import Database

pytestmark = pytest.mark.integration


def test_health_and_authenticated_identity(db, seeded):
    with TestClient(create_app(db)) as client:
        assert client.get("/health/live").json() == {"status": "ok"}
        assert client.get("/health/ready").status_code == 200
        response = client.get(
            "/v1/me",
            headers={
                "Authorization": "Bearer " + seeded["tokens"][0],
            },
        )
        assert response.status_code == 200
        assert response.json()["tenant_id"] == str(seeded["tenants"][0])
        assert response.json()["kind"] == "AGENT"
        assert "token_hash" not in response.text
        assert response.headers["cache-control"] == "no-store"
        assert client.post("/v1/execute", json={}).status_code == 404


def test_readiness_reports_the_version_and_the_commit_and_nothing_else(db, monkeypatch):
    """A trial record cites what it talked to: the package version and the source commit
    (#251). The commit comes from EXECBOUND_COMMIT, else the platform's own variable, and
    anything that is not a commit id is reported as nothing rather than echoed."""
    import importlib.metadata

    version = importlib.metadata.version("execbound")
    monkeypatch.delenv("EXECBOUND_COMMIT", raising=False)
    monkeypatch.delenv("RENDER_GIT_COMMIT", raising=False)
    with TestClient(create_app(db)) as client:
        assert client.get("/health/ready").json() == {
            "status": "ready",
            "version": version,
            "commit": None,
        }
        monkeypatch.setenv("EXECBOUND_COMMIT", "ABC1234")
        assert client.get("/health/ready").json()["commit"] == "abc1234"
        monkeypatch.setenv("EXECBOUND_COMMIT", "not a sha; DATABASE_URL=postgresql://x")
        monkeypatch.setenv("RENDER_GIT_COMMIT", "0" * 40)
        body = client.get("/health/ready").json()
        assert body["commit"] == "0" * 40 and set(body) == {"status", "version", "commit"}
        monkeypatch.setenv("RENDER_GIT_COMMIT", "short")
        assert client.get("/health/ready").json()["commit"] is None


@pytest.mark.parametrize(
    "header,value",
    [
        ("X-Tenant-ID", "other-tenant"),
        ("X-Principal-ID", "other-principal"),
        ("X-Role", "ADMIN"),
    ],
)
def test_caller_identity_headers_are_rejected(db, seeded, header, value):
    with TestClient(create_app(db)) as client:
        response = client.get(
            "/v1/me",
            headers={
                "Authorization": "Bearer " + seeded["tokens"][0],
                header: value,
            },
        )
        assert response.status_code == 400


def test_duplicate_authorization_is_rejected(db, seeded):
    with TestClient(create_app(db)) as client:
        response = client.get(
            "/v1/me",
            headers=[
                ("Authorization", "Bearer " + seeded["tokens"][0]),
                ("authorization", "Bearer " + seeded["tokens"][1]),
            ],
        )
        assert response.status_code == 400


def test_identity_body_is_rejected(db, seeded):
    with TestClient(create_app(db)) as client:
        response = client.request(
            "GET",
            "/v1/me",
            json={"tenant_id": "other-tenant"},
            headers={"Authorization": "Bearer " + seeded["tokens"][0]},
        )
        assert response.status_code == 400


def test_identity_query_is_rejected(db, seeded):
    with TestClient(create_app(db)) as client:
        response = client.get(
            "/v1/me?tenant_id=other-tenant",
            headers={"Authorization": "Bearer " + seeded["tokens"][0]},
        )
        assert response.status_code == 400


@pytest.mark.parametrize("authorization", [None, "Basic abc", "Bearer invalid", "Bearer"])
def test_api_rejects_missing_or_bad_credentials(db, authorization):
    with TestClient(create_app(db)) as client:
        headers = {"Authorization": authorization} if authorization else {}
        response = client.get("/v1/me", headers=headers)
        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid credentials"}
        assert response.headers["www-authenticate"] == "Bearer"


def test_privileged_runtime_fails_closed(admin_engine, seeded):
    database = Database(admin_engine.url.render_as_string(hide_password=False))
    try:
        with TestClient(create_app(database)) as client:
            assert client.get("/health/ready").status_code == 503
            assert (
                client.get(
                    "/v1/me", headers={"Authorization": "Bearer " + seeded["tokens"][0]}
                ).status_code
                == 503
            )
    finally:
        database.close()


def test_database_outage_is_generic_and_liveness_still_works():
    database = Database("postgresql+psycopg://invalid:unreported-secret@127.0.0.1:1/execbound")
    try:
        with TestClient(create_app(database)) as client:
            assert client.get("/health/live").status_code == 200
            response = client.get("/health/ready")
            assert response.status_code == 503
            assert response.json() == {"detail": "Service unavailable"}
    finally:
        database.close()
