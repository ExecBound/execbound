# SPDX-License-Identifier: AGPL-3.0-only
"""One definition of what a secret looks like, for the export guard, the log guard, the
test helper (#265), the write screens that refuse secret-shaped text before it reaches a
tenant's audit chain (`secret_shaped`), and the identity provider's withholding of a
credential-shaped value it must accept rather than refuse (`withheld`).

Depends on the standard library only. The log guard kept its own copy of the pattern so
that it imported nothing from the identity or execution packages; this module keeps that
property, and folds in the `mo1` prefix the two copies had already drifted over.

A finding carries a path and a kind and never the text that matched, so no failure message,
`repr` or log line built from one can carry the secret it found.
"""

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

SECRET_KEYS = frozenset(
    {
        "token",
        "token_hash",
        "owner_hash",
        "secret",
        "password",
        "authorization",
        "cookie",
        "cookies",
        "set_cookie",
        "csrf",
        "csrf_token",
        "session_token",
        "access_token",
        "refresh_token",
        "private_key",
        "signing_key",
        "signing_key_hex",
        "signing_material",
        "dispatch_token",
        "control_token",
        "dispatch_token_hash",
        "control_token_hash",
        "evidence_keys",
        "continuation_keys",
        "database_url",
        "connection_string",
        "runtime_config",
        "configuration",
        "provider_url",
    }
)

# Every alternative is anchored so that ordinary content cannot reach it: a bare UUID, a
# hostname, the word "Bearer" on its own, a `sig` outside a query string, a certificate
# rather than a key, and `sk_`/`rk_` inside a longer identifier all fail. `tests/
# test_secrets.py` holds a matching string and the near misses for each one.
SECRET_TEXT = re.compile(
    # An Authorization header value. `\S+` also matched the prose "a static bearer
    # credential" and the `Bearer <API key>` placeholder a setup recipe tells a
    # reader to replace, so it reported the documentation of the header as the header.
    # Length is the wrong discriminator: the export guard must keep refusing a value as
    # short as `synthetic-private`. Structure is the right one. The value must be eight or
    # more characters of the unreserved set and must carry at least one character an English
    # word does not: a digit, a dot, a dash, an underscore, a tilde, a slash, a plus or an
    # equals. A placeholder starting `<`, `$` or `"` never enters the set at all.
    r"\bBearer\s+(?=[A-Za-z0-9._~+/=-]*[0-9._~+/=-])[A-Za-z0-9._~+/=-]{8,}"
    # Agent credential, human session, monitoring source, onboarding code, invitation code,
    # set-password code, security signal producer, weekly summary unsubscribe link and a
    # Microsoft Entra consent attempt's OAuth state (#678).
    r"|\b(?:eb1|hs1|mo1|ebi1|ebv1|ebp1|sg1|ebw1|mc1)\.[0-9a-fA-F-]{36}\.[0-9a-fA-F-]{36}\.[A-Za-z0-9_-]+"
    # Two-segment email links, a signup verification link and a password reset link: a
    # UUID and a 256-bit base64url secret. The three-segment alternative above never
    # matched them.
    r"|\b(?:ebs1|ebr1)\.[0-9a-fA-F-]{36}\.[A-Za-z0-9_-]{43}\b"
    # A database or cache URL, which carries its password.
    r"|(?:postgres(?:ql)?|mysql|redis)(?:\+[a-z]+)?://"
    # A Slack incoming webhook. The path segment is the secret, so the host alone is not
    # enough and /archives/ links do not match.
    r"|hooks\.slack\.com/services/"
    # A Power Automate trigger URL, whose `sig` query parameter is the secret. The `[?&]`
    # keeps `signature=` and any prose mentioning sig out.
    r"|logic\.azure\.com[^\s]*[?&]sig="
    # Private key material of any type. A certificate carries no secret and does not match.
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    # Stripe secret and restricted keys. The live/test segment is required: `rk_` alone
    # appears inside ordinary identifiers and could not be anchored safely.
    r"|\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,}"
    # A three-part JWT. One or two parts is a base64 fragment, not a token. Every JWT
    # begins with exactly `eyJ`, `{"` in base64url, so this alternative alone keeps its
    # case: under the pattern's IGNORECASE a lowercase hostname or email domain such as
    # `eyjump.corp.example` would otherwise read as one.
    r"|(?-i:\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)",
    re.IGNORECASE,
)

# A path segment that would otherwise repeat a secret used as a mapping key.
REDACTED = "<redacted>"


@dataclass(frozen=True)
class Finding:
    """Where a secret was found and why it counts as one. Never what it was."""

    path: str
    kind: str  # "key", "pattern" or "known"


def _join(parent: str, segment: str) -> str:
    return f"{parent}.{segment}" if parent else segment


def find_secrets(
    value: Any, *, known: Sequence[str] = (), limit: int | None = None
) -> list[Finding]:
    """Walk mappings, sequences and strings and report every secret, without quoting one.

    `known` holds values a caller minted and can recognise by value alone, such as a
    continuation token or a show-once code that carries no prefix. `limit` stops the walk
    early, which is what the export guard wants: it only needs to know that one exists.
    """
    findings: list[Finding] = []
    _walk(value, "", tuple(known), findings, limit)
    return findings


WITHHELD = "WITHHELD"


def secret_shaped(*values: Any) -> bool:
    """Whether any of these would make the export's secret check refuse; names none of them."""
    return bool(find_secrets(values, limit=1))


def withheld(field: str, value: str) -> dict[str, str]:
    """`field` as an audit payload carries it: the value itself, or, where it is shaped like a
    secret, `WITHHELD` beside its SHA-256, which correlates events without carrying it."""
    if not secret_shaped(value):
        return {field: value}
    return {field: WITHHELD, f"{field}_digest": hashlib.sha256(value.encode()).hexdigest()}


def _walk(
    value: Any, path: str, known: tuple[str, ...], findings: list[Finding], limit: int | None
) -> None:
    if limit is not None and len(findings) >= limit:
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            segment = str(key)
            if segment.lower().replace("-", "_") in SECRET_KEYS:
                findings.append(Finding(path=_join(path, segment), kind="key"))
            else:
                # A key can itself be a secret; its own text must not reach the path.
                for kind in _text_kinds(segment, known):
                    findings.append(Finding(path=_join(path, REDACTED), kind=kind))
                    segment = REDACTED
            _walk(child, _join(path, segment), known, findings, limit)
            if limit is not None and len(findings) >= limit:
                return
        return
    if isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _walk(child, f"{path}[{index}]", known, findings, limit)
            if limit is not None and len(findings) >= limit:
                return
        return
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")
    if isinstance(value, str):
        for kind in _text_kinds(value, known):
            findings.append(Finding(path=path or "$", kind=kind))


def _text_kinds(value: str, known: tuple[str, ...]) -> tuple[str, ...]:
    """The kinds a single string earns: a registered value first, then a known shape."""
    kinds: list[str] = []
    if any(item and item in value for item in known):
        kinds.append("known")
    if SECRET_TEXT.search(value):
        kinds.append("pattern")
    return tuple(kinds)
