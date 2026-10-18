# SPDX-License-Identifier: AGPL-3.0-only
"""Every constant-time comparison compares bytes, or two strings that are ASCII by construction.

`hmac.compare_digest` and `secrets.compare_digest` raise `TypeError` for a `str` holding a
character outside ASCII. Where a request supplies the text, that exception escaped to the
catch-all handler and a person was answered 503 rather than refused: a new password with an
umlaut in it, or a directory callback's `state`. This scan parses every call under
`src/execbound`. A call comparing two `.encode()` results passes; any other call must be
listed here with the reason both of its sides are ASCII before it runs, and a listed call that
no longer exists fails too, so the list cannot go stale.
"""

import ast
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "src"

# (file, first argument, second argument) as `ast.unparse` writes them: why both are ASCII.
REVIEWED = {
    (
        "execbound/account_links.py",
        "row['token_hash']",
        "digest(token)",
    ): "a stored hex digest against the hex digest of a token already shape-checked",
    (
        "execbound/account_links.py",
        "row['state_hash']",
        "digest(flow.state)",
    ): "a stored hex digest against the hex digest of the server's own flow state",
    (
        "execbound/directory.py",
        "hmac.new(key, raw, hashlib.sha256).hexdigest()",
        "supplied",
    ): "a computed hex MAC against a supplied value `_HEX_DIGEST` has already matched",
    (
        "execbound/execution/dispatch.py",
        "row['owner_hash']",
        "store.ticket_digest(ticket.secret)",
    ): "a stored hex digest against the hex digest the server computes",
    (
        "execbound/execution/outcomes.py",
        "row['owner_hash']",
        "store.ticket_digest(report.report_secret)",
    ): "a stored hex digest against the hex digest the server computes",
    (
        "execbound/identity.py",
        "digest",
        "row['token_hash'] if row else '0' * 64",
    ): "hex digests of a credential `authenticate` shape-checked first",
    (
        "execbound/mfa.py",
        "totp(secret, step)",
        "code",
    ): "six ASCII digits each: `verify_totp` matches the code against `[0-9]{6}` first",
    (
        "execbound/mfa.py",
        "digest",
        "item",
    ): "hex digests of a recovery code `_RECOVERY` matched first",
    (
        "execbound/monitoring/store.py",
        "supplied",
        "active_hash",
    ): "the hex digest of the presented token against a stored hex digest",
    (
        "execbound/monitoring/store.py",
        "supplied",
        "(source['previous_token_hash'] if source else None) or '1' * 64",
    ): "the hex digest of the presented token against a stored hex digest",
    (
        "execbound/monitoring/store.py",
        "existing['content_hash']",
        "digest",
    ): "two hex content digests the server computed",
    (
        "execbound/monitoring/store.py",
        "existing['content_hash']",
        "record.content_hash",
    ): "two hex content digests the server computed",
    (
        "execbound/passwords.py",
        "computed",
        "record.hash",
    ): "two encoded password hashes, computed and stored by the server",
    (
        "execbound/personal_tokens.py",
        "digest",
        "stored",
    ): "hex digests of a token `TOKEN` matched first",
    (
        "execbound/surfaces/console_api/approvals.py",
        "claim.nonce",
        "_nonce(current, csrf)",
    ): "a MAC-verified continuation nonce its model holds to `[A-Za-z0-9_-]`, and its own",
    (
        "execbound/surfaces/human.py",
        "claim.nonce",
        "_nonce(session, csrf)",
    ): "a MAC-verified continuation nonce its model holds to `[A-Za-z0-9_-]`, and its own",
    (
        "execbound/surfaces/sessions.py",
        "_hash(token)",
        "session.csrf_hash",
    ): "hex digests; `_secret` has shape-checked the token before `_hash` encodes it",
    (
        "execbound/surfaces/sessions.py",
        "current.csrf_hash",
        "session.csrf_hash",
    ): "two stored hex digests",
    (
        "execbound/surfaces/sessions.py",
        "digest",
        "row['token_hash'] if row else '0' * 64",
    ): "hex digests of a session token shape-checked first",
    (
        "execbound/surfaces/tokens.py",
        "supplied_mac",
        "expected_mac",
    ): "a supplied MAC `_WIRE_TOKEN` matched as 64 hex digits, against the computed one",
    (
        "execbound/user_accounts.py",
        "stored or '0' * 64",
        "hashlib.sha256(token.encode('ascii')).hexdigest()",
    ): "hex digests of an account session token shape-checked first",
}


def _calls() -> set[tuple[str, str, str]]:
    found = set()
    for path in sorted((SOURCE / "execbound").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.attr if isinstance(node.func, ast.Attribute) else None
            if name is None and isinstance(node.func, ast.Name):
                name = node.func.id
            if name != "compare_digest":
                continue
            if all(
                isinstance(argument, ast.Call)
                and isinstance(argument.func, ast.Attribute)
                and argument.func.attr == "encode"
                for argument in node.args
            ):
                continue
            first, second = (ast.unparse(argument) for argument in node.args)
            found.add((path.relative_to(SOURCE).as_posix(), first, second))
    return found


def test_every_text_comparison_is_bytes_or_reviewed_ascii():
    calls = _calls()
    assert sorted(calls - set(REVIEWED)) == [], (
        "compare_digest over `str` that may hold non-ASCII: compare `.encode()` results, or "
        "list the call here with the reason both sides are ASCII before it runs"
    )
    assert sorted(set(REVIEWED) - calls) == [], "a reviewed call that no longer exists"
