# SPDX-License-Identifier: AGPL-3.0-only
"""The producer credential, `sg1.<tenant>.<source>.<secret>`, held only as its digest.

The same shape and checks as the monitoring source token (`monitoring/store.py`, `mo1.`),
with a prefix of its own: no other parser accepts `sg1.`, so a producer token opens
`/v1/signals` and nothing else, and an agent's `eb1.` token never opens `/v1/signals`.
"""

import base64
import hashlib
import re
import secrets
from uuid import UUID

PREFIX = "sg1"
MAX_TOKEN_LENGTH = 160


class SignalTokenError(ValueError):
    """A malformed producer token. The message never quotes any part of it."""


def digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token(tenant: UUID, source: UUID) -> tuple[str, str]:
    """A fresh token and the digest that is the only thing stored."""
    token = f"{PREFIX}.{tenant}.{source}.{secrets.token_urlsafe(32)}"
    return token, digest(token)


def selectors(token: object) -> tuple[UUID, UUID]:
    """The tenant and source a well-formed token names; nothing is looked up here."""
    try:
        if type(token) is not str or len(token) > MAX_TOKEN_LENGTH:
            raise ValueError
        prefix, tenant_text, source_text, secret = token.split(".")
        tenant, source = UUID(tenant_text), UUID(source_text)
        if (
            prefix != PREFIX
            or str(tenant) != tenant_text
            or str(source) != source_text
            or re.fullmatch(r"[A-Za-z0-9_-]{43}", secret) is None
        ):
            raise ValueError
        decoded = base64.b64decode(secret + "=", altchars=b"-_", validate=True)
        if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != secret:
            raise ValueError
        return tenant, source
    except ValueError:
        raise SignalTokenError("Invalid producer token") from None
