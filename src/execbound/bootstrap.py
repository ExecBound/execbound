# SPDX-License-Identifier: AGPL-3.0-only
"""The material a deployment needs before anything can start, generated rather than typed.

A private configuration carries continuation keys, per-provider dispatch and control tokens
and evidence keys. Asking an operator to invent them produces weak keys; giving them an
example to copy produces the same secret in every installation. So it is generated here,
written to files the operator owns, and never printed.

This lives in the runtime package rather than the test harness because it ships in the
image: an installation has no repository, so whatever writes its configuration has to be
something it can already run. `execbound_harness.fixtures` imports from here rather than
keeping a second copy, so there is one definition of what a connector's material is.
"""

import hashlib
import json
import secrets
from pathlib import Path
from typing import Any
from uuid import UUID

# Both mocks refuse a mutation whose expected version has moved, so the honest declaration
# for their bindings is ENFORCED_BY_PROVIDER. Leaving them undeclared would record
# UNAVAILABLE on every dispatch, which means "this deployment never said", and would
# understate on the pages exactly what these providers do.
MOCK_PRECONDITIONS: tuple[tuple[str, str], ...] = (
    ("mock_crowdstrike", "contain"),
    ("mock_crowdstrike", "lift_containment"),
    ("mock_entra", "disable"),
    ("mock_entra", "enable"),
    ("mock_entra", "revoke_sessions"),
    ("mock_entra", "reset_password"),
)


def provider_material(
    provider: str, tenant: UUID, account: str, origin: str, *, key_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Fresh tokens and a signing key for one account.

    Returns the gateway's connector entry, which holds the raw tokens, and the provider's
    own account record, which holds only their digests. The provider never learns a token
    it was not given and the gateway never stores a digest it cannot use.
    """
    dispatch, control, key = (
        secrets.token_urlsafe(32),
        secrets.token_urlsafe(32),
        secrets.token_hex(32),
    )
    connector = {
        "tenant_id": str(tenant),
        "account_id": account,
        "provider": provider,
        "origin": origin,
        "dispatch_token": dispatch,
        "control_token": control,
        "evidence_keys": {key_id: key},
    }
    record = {
        "tenant_id": str(tenant),
        "account_id": account,
        "provider": provider,
        "dispatch_token_hash": hashlib.sha256(dispatch.encode()).hexdigest(),
        "control_token_hash": hashlib.sha256(control.encode()).hexdigest(),
        "signing_key_hex": key,
        "key_id": key_id,
    }
    return connector, record


def write_private(directory: Path, name: str, value: Any) -> Path:
    """Write one private file, owner-readable only, refusing to overwrite.

    Refusing rather than overwriting is deliberate: a second run against a live deployment
    would replace tokens the providers and the database already agree on, and the failure
    would appear later as a provider refusing a dispatch rather than here as a clobbered
    file.
    """
    path = directory / name
    if path.exists():
        raise FileExistsError(f"{name} already exists in that directory")
    directory.mkdir(parents=True, exist_ok=True)
    path.touch(mode=0o600)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
