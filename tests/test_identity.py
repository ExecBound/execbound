# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from sqlalchemy import text

from execbound.identity import AuthenticationFailed, authenticate

pytestmark = pytest.mark.integration


def test_identity_comes_from_verified_credential(db, seeded):
    identity = authenticate(db, seeded["tokens"][0])
    assert identity.tenant_id == seeded["tenants"][0]
    assert identity.principal_id == seeded["principals"][0]
    assert identity.credential_id == seeded["credentials"][0]
    assert identity.kind == "AGENT"


@pytest.mark.parametrize("token", ["", "secret", "eb1.bad.bad.secret", "eb1." + "a" * 1000])
def test_malformed_credentials_fail(db, token):
    with pytest.raises(AuthenticationFailed):
        authenticate(db, token)


@pytest.mark.parametrize("field", [1, 2, 3])
def test_swapped_selectors_and_secret_fail(db, seeded, field):
    parts = seeded["tokens"][0].split(".")
    parts[field] = seeded["tokens"][1].split(".")[field]
    with pytest.raises(AuthenticationFailed):
        authenticate(db, ".".join(parts))
    with db.engine.begin() as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.credentials")).scalar_one() == 0


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE execbound.credentials SET revoked_at = now()",
        "UPDATE execbound.credentials SET expires_at = now() - interval '1 second'",
        "UPDATE execbound.principals SET active = false",
        "UPDATE execbound.tenants SET active = false",
    ],
)
def test_disabled_or_expired_identity_fails(db, seeded, admin_engine, statement):
    with admin_engine.begin() as conn:
        conn.execute(text(statement))
    with pytest.raises(AuthenticationFailed):
        authenticate(db, seeded["tokens"][0])
