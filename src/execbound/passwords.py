# SPDX-License-Identifier: AGPL-3.0-only
"""A password a person holds: the hash, the one-time codes that set it, and the sign-in.

The password is never stored. What is stored is a salted scrypt hash with the parameters
recorded in their own columns beside it, so raising them later is a write rather than a
migration and a row written under the old ones keeps verifying.

A verified sign-in mints an ordinary `credentials` row whose digest is of bytes this module
discards, so nothing can ever present it, and `issue_session` then runs exactly as it does
for a credential typed into the form. That is why sessions, CSRF, cookies, renewal,
revocation and the recheck are unchanged by this file.

An address is resolved before any tenant is known by setting `execbound.sign_in_email` and
reading the one row the `sign_in_email` policy of migration 0039 then permits: the policy
answers about the address the caller already typed and about nothing else. Everything after
that happens inside that person's fence.
"""

import hashlib
import hmac
import re
import secrets
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from execbound.audit import append_event
from execbound.db import Database, UnsafeDatabaseRole, check_runtime
from execbound.identity import (
    UNATTRIBUTED_CONTEXT,
    AuthenticationFailed,
    Identity,
    PrincipalKind,
)
from execbound.resolution.models import Clock, SystemClock
from execbound.secrets import secret_shaped, withheld

if TYPE_CHECKING:
    from execbound.surfaces.sessions import Session

# The stored hash's parameters. `maxmem` is explicit because the library's default is below
# what these need, so leaving it out would fail when somebody signs in rather than here.
ALGORITHM = "scrypt"
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
DKLEN = 32
MAXMEM = 64 * 1024 * 1024
SALT_BYTES = 16

# NIST SP 800-63B: length is the control that works, composition rules are the one that makes
# passwords worse. The upper bound is there so a body cannot make the server do unbounded work.
MIN_PASSWORD = 12
MAX_PASSWORD = 200

MAX_EMAIL = 254
_EMAIL = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")

# The credential a sign-in mints lives exactly as long as a session may be renewed for, so a
# password session renews for as long as a credential session does and no longer.
SIGN_IN_LIFETIME = timedelta(hours=8)
DEFAULT_RESET_LIFETIME = timedelta(hours=24)
MIN_RESET_LIFETIME = timedelta(hours=1)
MAX_RESET_LIFETIME = timedelta(days=14)

CODE_PREFIX = "ebp1"
SIGN_IN_METHODS = frozenset({"password", "google", "github", "microsoft"})


class PasswordError(ValueError):
    """Safe code only; no address, no code and no password reaches a message or a log."""

    def __init__(self, code: str = "PASSWORD_UNAVAILABLE") -> None:
        self.code = code
        super().__init__("Password unavailable")


@dataclass(frozen=True)
class PasswordRecord:
    """One stored hash with the parameters it was derived under."""

    algorithm: str
    n: int
    r: int
    p: int
    dklen: int
    salt: str
    hash: str

    def parameters(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "n": self.n,
            "r": self.r,
            "p": self.p,
            "dklen": self.dklen,
            "salt": self.salt,
            "hash": self.hash,
        }


@dataclass(frozen=True)
class Reset:
    """A minted set-password code. The code exists for one response and is stored hashed."""

    code: str
    reset_id: UUID
    principal_id: UUID
    expires_at: datetime


def _now(clock: Clock) -> datetime:
    value = clock.now()
    if value.tzinfo is None or value.utcoffset() is None:
        raise PasswordError("INVALID_CLOCK")
    return value.astimezone(UTC)


def normalize_email(value: object) -> str | None:
    """One spelling for an address, or None when it is not one at all.

    NFKC, stripped and lower-cased, which is what the column's CHECK also states, so what a
    person typed and what is stored cannot differ by a case or a compatibility form.
    """
    if type(value) is not str or len(value) > 4 * MAX_EMAIL:
        return None
    normalized = unicodedata.normalize("NFKC", value).strip().lower()
    if not 3 <= len(normalized) <= MAX_EMAIL or _EMAIL.fullmatch(normalized) is None:
        return None
    return normalized


def check_password(password: object, email: str | None = None) -> str:
    """The password as it will be hashed, or `INVALID_PASSWORD`."""
    if type(password) is not str:
        raise PasswordError("INVALID_PASSWORD")
    normalized = unicodedata.normalize("NFKC", password)
    if not MIN_PASSWORD <= len(normalized) <= MAX_PASSWORD:
        raise PasswordError("INVALID_PASSWORD")
    if email is not None and normalized.strip().lower() == email:
        raise PasswordError("INVALID_PASSWORD")
    return normalized


def derive(password: str, record: PasswordRecord) -> str:
    """The hash for a password under one record's own parameters, never the module's."""
    if record.algorithm != ALGORITHM:
        raise PasswordError("INVALID_PASSWORD")
    return hashlib.scrypt(
        unicodedata.normalize("NFKC", password).encode("utf-8"),
        salt=bytes.fromhex(record.salt),
        n=record.n,
        r=record.r,
        p=record.p,
        dklen=record.dklen,
        maxmem=MAXMEM,
    ).hex()


def hash_password(password: str) -> PasswordRecord:
    salt = secrets.token_bytes(SALT_BYTES).hex()
    record = PasswordRecord(ALGORITHM, SCRYPT_N, SCRYPT_R, SCRYPT_P, DKLEN, salt, "0" * 64)
    return PasswordRecord(
        ALGORITHM, SCRYPT_N, SCRYPT_R, SCRYPT_P, DKLEN, salt, derive(password, record)
    )


def verify_password(record: PasswordRecord, password: object) -> bool:
    """Constant-time comparison; anything that is not a string costs the same and fails."""
    candidate = password if type(password) is str else ""
    try:
        computed = derive(candidate, record)
    except (PasswordError, ValueError):
        return False
    return hmac.compare_digest(computed, record.hash)


# What an address nobody holds is verified against, so an unknown address costs what a known
# one costs. Built once at import under the current parameters; the secret is discarded.
DECOY = hash_password(secrets.token_urlsafe(32))


def reset_code(tenant_id: UUID, reset_id: UUID) -> tuple[str, str]:
    code = f"{CODE_PREFIX}.{tenant_id}.{reset_id}.{secrets.token_urlsafe(32)}"
    return code, hashlib.sha256(code.encode("ascii")).hexdigest()


def reset_selectors(code: object) -> tuple[UUID, UUID]:
    """The tenant and code a string names, read without any lookup or comparison."""
    try:
        if type(code) is not str or len(code) > 160:
            raise ValueError
        version, tenant_text, reset_text, secret = code.split(".")
        tenant_id, reset_id = UUID(tenant_text), UUID(reset_text)
        if (
            version != CODE_PREFIX
            or str(tenant_id) != tenant_text
            or str(reset_id) != reset_text
            or re.fullmatch(r"[A-Za-z0-9_-]{43}", secret) is None
        ):
            raise ValueError
        return tenant_id, reset_id
    except ValueError:
        raise PasswordError("INVALID_RESET") from None


def code_digest(code: str) -> str:
    return hashlib.sha256(code.encode("ascii")).hexdigest()


def _refusal(exc: DBAPIError) -> PasswordError:
    diagnostic = getattr(exc.orig, "diag", None)
    message = getattr(diagnostic, "message_primary", None)
    known = {
        "ACCOUNT_OWNER_REQUIRED",
        "INVALID_TENANT",
        "INVALID_ACTOR",
        "INVALID_PRINCIPAL",
        "INVALID_EMAIL",
        "EMAIL_TAKEN",
        "INVALID_DIGEST",
        "INVALID_LIFETIME",
        "INVALID_CLOCK",
        "INVALID_PASSWORD",
        "INVALID_RESET",
        "INVALID_STATE",
        "INVALID_METHOD",
        "INVALID_IDENTITY",
    }
    return PasswordError(message if message in known else "PASSWORD_UNAVAILABLE")


def locate_email(db: Database, email: str) -> tuple[UUID, UUID] | None:
    """The one person holding an address, across tenants, or None.

    The marker below is what the `sign_in_email` policy compares each row's own email
    against, so this read can see the row for the address the caller supplied and no other
    row in any tenant. It is not authority: the kind, the active flags and the password are
    read again inside that person's fence.
    """
    try:
        with db.transaction(UNATTRIBUTED_CONTEXT) as conn:
            check_runtime(conn)
            conn.execute(
                text("SELECT set_config('execbound.sign_in_email', :e, true)"), {"e": email}
            )
            row = (
                conn.execute(
                    text(
                        "SELECT tenant_id, principal_id FROM execbound.principals WHERE email = :e"
                    ),
                    {"e": email},
                )
                .mappings()
                .one_or_none()
            )
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise PasswordError("PASSWORD_UNAVAILABLE") from None
    return (row["tenant_id"], row["principal_id"]) if row is not None else None


def locate_subject(db: Database, provider: str, subject: str) -> tuple[UUID, UUID] | None:
    """The one person a provider account is bound to, across tenants, or None."""
    marker = f"{provider}:{subject}"
    try:
        with db.transaction(UNATTRIBUTED_CONTEXT) as conn:
            check_runtime(conn)
            conn.execute(
                text("SELECT set_config('execbound.sign_in_subject', :s, true)"), {"s": marker}
            )
            row = (
                conn.execute(
                    text(
                        "SELECT tenant_id, principal_id FROM execbound.principal_identities "
                        "WHERE provider = :p AND subject = :s AND revoked_at IS NULL"
                    ),
                    {"p": provider, "s": subject},
                )
                .mappings()
                .one_or_none()
            )
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise PasswordError("PASSWORD_UNAVAILABLE") from None
    return (row["tenant_id"], row["principal_id"]) if row is not None else None


_PERSON = """
SELECT p.kind, p.active AS principal_active, t.active AS tenant_active,
       w.algorithm, w.n, w.r, w.p, w.dklen, w.salt, w.hash
FROM execbound.principals p
JOIN execbound.tenants t USING (tenant_id)
LEFT JOIN execbound.principal_passwords w
       ON w.tenant_id = p.tenant_id AND w.principal_id = p.principal_id
WHERE p.tenant_id = :t AND p.principal_id = :p
"""


def _record(row: Any) -> PasswordRecord | None:
    if row is None or row["algorithm"] is None:
        return None
    return PasswordRecord(
        row["algorithm"], row["n"], row["r"], row["p"], row["dklen"], row["salt"], row["hash"]
    )


def sign_in_with_password(
    db: Database,
    email: object,
    password: object,
    *,
    clock: Clock | None = None,
    prefer: UUID | None = None,
) -> Identity:
    """Authenticate a person by address and password; every refusal is one answer.

    The hash is verified before any state is read and against a decoy when the address
    belongs to nobody, so a wrong address and a wrong password cost the same. The reason is
    private and reaches `record_failure`; the caller shows one sentence for all of them.
    An account's sign-in opens `prefer` when it is one of the account's usable workspaces
    (`first_membership`); a sign-in without an account has one workspace and ignores it.
    """
    clock = clock or SystemClock()
    normalized = normalize_email(email)
    from execbound.user_accounts import first_membership, locate_account, password_record

    account = locate_account(db, normalized) if normalized else None
    if account is not None:
        record = password_record(db, account["account_id"])
        matched = verify_password(record or DECOY, password)
        if record is None or not matched or not account["active"]:
            raise AuthenticationFailed(reason="MISMATCH")
        member = first_membership(db, account["account_id"], prefer=prefer)
        return mint_session_credential(
            db,
            member["tenant_id"],
            member["principal_id"],
            "password",
            clock=clock,
            account=(account["account_id"], account["version"]),
        )
    found = locate_email(db, normalized) if normalized is not None else None
    record = None
    row: Any = None
    if found is not None:
        tenant_id, principal_id = found
        try:
            with db.transaction(tenant_id) as conn:
                check_runtime(conn)
                row = (
                    conn.execute(text(_PERSON), {"t": tenant_id, "p": principal_id})
                    .mappings()
                    .one_or_none()
                )
        except (SQLAlchemyError, UnsafeDatabaseRole):
            raise PasswordError("PASSWORD_UNAVAILABLE") from None
        record = _record(row)
    matched = verify_password(record or DECOY, password)
    if found is None:
        # Nobody holds this address. Nothing is attributed, because there is nobody to
        # attribute it to, and the answer and the cost are the same as a wrong password's.
        raise AuthenticationFailed(reason="UNKNOWN")
    tenant_id, principal_id = found
    attributed: dict[str, Any] = {
        "tenant_id": tenant_id,
        "subject_kind": "principal",
        "subject_id": principal_id,
    }
    if record is None or not matched:
        raise AuthenticationFailed(
            reason="MISMATCH" if record is not None else "UNKNOWN", **attributed
        )
    if (
        not row["tenant_active"]
        or not row["principal_active"]
        or row["kind"] not in {"HUMAN_APPROVER", "ADMIN"}
    ):
        raise AuthenticationFailed(reason="INACTIVE", **attributed)
    # The one-time administrator setup door may still enroll an original workspace.
    # Once the password is proved, all later authentication belongs to its account.
    from execbound.user_accounts import adopt_personal_identity

    adopt_personal_identity(db, tenant_id, principal_id)
    return sign_in_with_password(db, normalized, password, clock=clock)


def mint_session_credential(
    db: Database,
    tenant_id: UUID,
    principal_id: UUID,
    method: str,
    *,
    clock: Clock | None = None,
    detail: dict[str, Any] | None = None,
    account: tuple[UUID, int] | None = None,
) -> Identity:
    """The credential a verified sign-in stands on; its secret never exists outside this call.

    Thirty-two random bytes are hashed and discarded, so the row authenticates nobody and
    exists only to give `issue_session` the credential every session is already bound to.
    """
    clock = clock or SystemClock()
    if method not in SIGN_IN_METHODS:
        raise PasswordError("INVALID_METHOD")
    credential_id = uuid4()
    digest = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
    issued_at = _now(clock)
    expires_at = issued_at + SIGN_IN_LIFETIME
    kind = ""
    try:
        with db.transaction(tenant_id) as conn:
            check_runtime(conn)
            statement = (
                "SELECT execbound.sign_in_credential(:p, :c, :h, :m, :i, :e)"
                if account is None
                else "SELECT execbound.account_login_credential(:a,:v,:p,:c,:h,:m,:i,:e)"
            )
            kind = conn.execute(
                text(statement),
                {
                    "a": account[0] if account else None,
                    "v": account[1] if account else None,
                    "p": principal_id,
                    "c": credential_id,
                    "h": digest,
                    "m": method,
                    "i": issued_at,
                    "e": expires_at,
                },
            ).scalar_one()
            from execbound.access_control import effective_kind

            kind = effective_kind(conn, tenant_id, principal_id)
            append_event(
                conn,
                tenant_id,
                principal_id,
                f"human_sign_in.{method}",
                {
                    "credential_id": str(credential_id),
                    "kind": kind,
                    "expires_at": expires_at.isoformat(),
                    **(detail or {}),
                },
            )
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise PasswordError("PASSWORD_UNAVAILABLE") from None
    if kind == "ADMIN":
        role: PrincipalKind = "ADMIN"
    elif kind == "HUMAN_APPROVER":
        role = "HUMAN_APPROVER"
    else:
        raise PasswordError("INVALID_PRINCIPAL")
    return Identity(tenant_id, principal_id, credential_id, role, expires_at)


def bind_identity(
    db: Database,
    tenant_id: UUID,
    principal_id: UUID,
    *,
    provider: str,
    subject: str,
    email: str | None,
    display_name: str | None,
    clock: Clock | None = None,
) -> None:
    """Bind a provider account to a person, or refresh the hints on an existing binding."""
    clock = clock or SystemClock()
    now = _now(clock)
    try:
        with db.transaction(tenant_id) as conn:
            check_runtime(conn)
            existed = conn.execute(
                text(
                    "SELECT 1 FROM execbound.principal_identities WHERE tenant_id = :t "
                    "AND provider = :v AND subject = :s AND revoked_at IS NULL"
                ),
                {"t": tenant_id, "v": provider, "s": subject},
            ).scalar_one_or_none()
            conn.execute(
                text("SELECT execbound.identity_sign_in(:p, :v, :s, :e, :d, :n)"),
                {
                    "p": principal_id,
                    "v": provider,
                    "s": subject,
                    "e": email,
                    "d": display_name,
                    "n": now,
                },
            )
            if existed is None:
                append_event(
                    conn,
                    tenant_id,
                    principal_id,
                    "identity.linked",
                    # `subject` is this provider's own claim, the same text `directory_store`
                    # withholds rather than refuses: refusing would stop a person signing in
                    # with an account their provider already proved.
                    {"provider": provider, **withheld("subject", subject)},
                )
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise PasswordError("PASSWORD_UNAVAILABLE") from None


def set_email(
    db: Database, tenant_id: UUID, actor_id: UUID, principal_id: UUID, email: object
) -> str:
    """An ADMIN gives a person the address they sign in with."""
    normalized = normalize_email(email)
    if normalized is None:
        raise PasswordError("INVALID_EMAIL")
    # Only the domain reaches `person.email_set`, so only the domain is screened.
    if secret_shaped(normalized.rsplit("@", 1)[1]):
        raise PasswordError("INVALID_EMAIL")
    try:
        with db.transaction(tenant_id) as conn:
            check_runtime(conn)
            written = conn.execute(
                text("SELECT execbound.admin_set_email(:a, :p, :e)"),
                {"a": actor_id, "p": principal_id, "e": normalized},
            ).scalar_one()
            append_event(
                conn,
                tenant_id,
                actor_id,
                "person.email_set",
                {"principal_id": str(principal_id), "domain": written.rsplit("@", 1)[1]},
            )
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise PasswordError("PASSWORD_UNAVAILABLE") from None
    return str(written)


def issue_reset(
    db: Database,
    tenant_id: UUID,
    actor_id: UUID,
    principal_id: UUID,
    *,
    lifetime: timedelta = DEFAULT_RESET_LIFETIME,
    clock: Clock | None = None,
) -> Reset:
    """Mint one set-password code for a person; whatever was pending is revoked first."""
    clock = clock or SystemClock()
    if not MIN_RESET_LIFETIME <= lifetime <= MAX_RESET_LIFETIME:
        raise PasswordError("INVALID_LIFETIME")
    reset_id = uuid4()
    code, digest = reset_code(tenant_id, reset_id)
    expires_at = _now(clock) + lifetime
    try:
        with db.transaction(tenant_id) as conn:
            check_runtime(conn)
            conn.execute(
                text("SELECT execbound.admin_reset_password(:a, :p, :r, :h, :e)"),
                {
                    "a": actor_id,
                    "p": principal_id,
                    "r": reset_id,
                    "h": digest,
                    "e": expires_at,
                },
            )
            append_event(
                conn,
                tenant_id,
                actor_id,
                "password.reset_issued",
                {
                    "principal_id": str(principal_id),
                    "reset_id": str(reset_id),
                    "expires_at": expires_at.isoformat(),
                },
            )
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise PasswordError("PASSWORD_UNAVAILABLE") from None
    return Reset(code, reset_id, principal_id, expires_at)


def _ended(conn: Connection, tenant_id: UUID, principal_id: UUID, result: dict[str, Any]) -> None:
    """One audit event per session and credential a redemption ended, in its transaction."""
    for credential in result["credentials"]:
        append_event(
            conn,
            tenant_id,
            principal_id,
            "credential.revoked",
            {"credential_id": credential, "reason": "PASSWORD_SET"},
        )
    for session_id in result["sessions"]:
        append_event(
            conn,
            tenant_id,
            principal_id,
            "human_session.revoked",
            {"session_id": session_id, "reason": "PASSWORD_SET"},
        )


def redeem_reset(
    db: Database, code: object, password: object, *, clock: Clock | None = None
) -> UUID:
    """Set a password from a one-time code, ending every session and credential it had.

    A code that can be handed over is also a recovery path, so a recovery must not leave the
    previous holder signed in. The function returns what it ended and the events are
    appended in the same transaction, so there is no moment where the rows and the chain
    disagree.
    """
    clock = clock or SystemClock()
    tenant_id, reset_id = reset_selectors(code)
    if type(code) is not str:
        raise PasswordError("INVALID_RESET")
    chosen = check_password(password)
    record = hash_password(chosen)
    now = _now(clock)
    principal_id = UUID(int=0)
    result: Any = None
    try:
        with db.transaction(tenant_id) as conn:
            check_runtime(conn)
            result = conn.execute(
                text(
                    "SELECT execbound.password_redeem(:r, :h, :alg, :n, :rr, :pp, :dk, "
                    ":salt, :hash, :now)"
                ),
                {
                    "r": reset_id,
                    "h": code_digest(code),
                    "alg": record.algorithm,
                    "n": record.n,
                    "rr": record.r,
                    "pp": record.p,
                    "dk": record.dklen,
                    "salt": record.salt,
                    "hash": record.hash,
                    "now": now,
                },
            ).scalar_one_or_none()
            if result is not None:
                principal_id = UUID(result["principal_id"])
                append_event(
                    conn,
                    tenant_id,
                    principal_id,
                    "password.set",
                    {"reset_id": str(reset_id)},
                )
                _ended(conn, tenant_id, principal_id, result)
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise PasswordError("PASSWORD_UNAVAILABLE") from None
    # The refusal is raised after the transaction commits, never inside it: the function
    # counts a wrong secret and revokes the code on the fifth, and rolling that back would
    # make the counter a suggestion rather than a limit.
    if result is None:
        raise PasswordError("INVALID_RESET")
    return principal_id


def read_record(db: Database, tenant_id: UUID, principal_id: UUID) -> PasswordRecord | None:
    try:
        with db.transaction(tenant_id) as conn:
            check_runtime(conn)
            row = (
                conn.execute(
                    text(
                        "SELECT algorithm, n, r, p, dklen, salt, hash "
                        "FROM execbound.principal_passwords "
                        "WHERE tenant_id = :t AND principal_id = :p"
                    ),
                    {"t": tenant_id, "p": principal_id},
                )
                .mappings()
                .one_or_none()
            )
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise PasswordError("PASSWORD_UNAVAILABLE") from None
    return _record(row)


def set_first_password(
    db: Database, session: "Session", new: object, *, clock: Clock | None = None
) -> None:
    """An account with no password sets its first one, from Account security (#593).

    The bar is provider linking's: an account session signed in within five minutes, a
    factor verified within the step-up window when one is enabled, and a verified address.
    The Python check refuses early with the reason; `user_security_change`'s `password_set`
    asks the same and inserts only when no password exists, so it never replaces one. The
    password is hashed exactly as every other one, and only the change is recorded.
    """
    clock = clock or SystemClock()
    from execbound.mfa import MfaError, _change, _event, _recent, _transaction
    from execbound.user_accounts import password_record

    if session.account_id is None:
        raise PasswordError("ACCOUNT_OWNER_REQUIRED")
    if password_record(db, session.account_id) is not None:
        raise PasswordError("PASSWORD_EXISTS")
    record = hash_password(check_password(new))
    try:
        with _transaction(db, session, clock) as conn:
            _recent(conn, session, clock.now(), enrollment=True)
            _change(conn, session, clock.now(), "password_set", record.parameters())
            _event(conn, session, "password_set")
    except MfaError as exc:
        code = "RECENT_AUTH_REQUIRED" if exc.code == "RECENT_AUTH_REQUIRED" else None
        raise PasswordError(code or "PASSWORD_UNAVAILABLE") from None


def change_password(
    db: Database,
    identity: Identity,
    current: object,
    new: object,
    *,
    clock: Clock | None = None,
    session: "Session | None" = None,
) -> None:
    """The signed-in person replaces their own password, presenting the current one.

    The write refuses a person who holds no password, so nothing that skips this check can
    create one through this door.
    """
    clock = clock or SystemClock()
    from execbound.user_accounts import password_record

    with db.transaction(identity.tenant_id) as conn:
        account = conn.execute(
            text(
                "SELECT account_id FROM execbound.workspace_memberships "
                "WHERE tenant_id=:t AND principal_id=:p"
            ),
            {"t": identity.tenant_id, "p": identity.principal_id},
        ).scalar_one_or_none()
    if account is not None:
        if session is None or session.account_id != account or session.identity != identity:
            raise PasswordError("ACCOUNT_OWNER_REQUIRED")
        record = password_record(db, account)
        if record is None or not verify_password(record, current):
            raise PasswordError("INVALID_CURRENT")
        chosen = check_password(new)
        if verify_password(record, chosen):
            raise PasswordError("PASSWORD_UNCHANGED")
        replacement = hash_password(chosen)
        from execbound.mfa import MfaError, _change, _event, _transaction

        try:
            with _transaction(db, session, clock) as conn:
                _change(
                    conn,
                    session,
                    clock.now(),
                    "password",
                    {**replacement.parameters(), "expected_hash": record.hash},
                )
                _event(conn, session, "password_changed")
        except MfaError:
            raise PasswordError("PASSWORD_UNAVAILABLE") from None
        return
    record = read_record(db, identity.tenant_id, identity.principal_id)
    if record is None or not verify_password(record, current):
        raise PasswordError("INVALID_CURRENT")
    chosen = check_password(new)
    if verify_password(record, chosen):
        raise PasswordError("PASSWORD_UNCHANGED")
    replacement = hash_password(chosen)
    now = _now(clock)
    try:
        with db.transaction(identity.tenant_id) as conn:
            check_runtime(conn)
            conn.execute(
                text(
                    "SELECT execbound.password_replace(:p, :alg, :n, :rr, :pp, :dk, "
                    ":salt, :hash, :now)"
                ),
                {
                    "p": identity.principal_id,
                    "alg": replacement.algorithm,
                    "n": replacement.n,
                    "rr": replacement.r,
                    "pp": replacement.p,
                    "dk": replacement.dklen,
                    "salt": replacement.salt,
                    "hash": replacement.hash,
                    "now": now,
                },
            )
            append_event(
                conn,
                identity.tenant_id,
                identity.principal_id,
                "password.changed",
                {"credential_id": str(identity.credential_id)},
            )
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise PasswordError("PASSWORD_UNAVAILABLE") from None
