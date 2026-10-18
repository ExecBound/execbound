# SPDX-License-Identifier: AGPL-3.0-only
"""A local SMTP relay for tests: aiosmtpd with a certificate from a CA the test mints.

Nothing here reaches a real host. The CA is trusted only by the context the relay hands the
test, so the transport's certificate and hostname verification run exactly as they would
against a real relay, and the default context (the system trust store) is refused.
"""

import ipaddress
import socket
import ssl
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email import message_from_bytes, policy
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

USERNAME = "relay-user"
PASSWORD = "relay-password-0123456789"


def free_port() -> int:
    """aiosmtpd's controller cannot take port 0 (aio-libs/aiosmtpd#276), so pick one."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def mint(directory: Path) -> tuple[Path, Path, Path]:
    """A throwaway CA and a certificate for `localhost` and 127.0.0.1 signed by it."""
    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ExecBound test relay CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    paths = directory / "ca.pem", directory / "relay.pem", directory / "relay.key"
    paths[0].write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    paths[1].write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    paths[2].write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return paths


@dataclass
class Relay:
    port: int
    context: ssl.SSLContext
    raw: list[bytes] = field(default_factory=list)
    envelopes: list[tuple[str, list[str]]] = field(default_factory=list)

    def messages(self) -> list[EmailMessage]:
        return [
            message_from_bytes(raw, _class=EmailMessage, policy=policy.default)  # type: ignore[call-arg]
            for raw in self.raw
        ]


class _Handler:
    def __init__(self, relay: Relay, refuse: frozenset[str]) -> None:
        self.relay, self.refuse = relay, refuse

    async def handle_RCPT(  # noqa: N802 - aiosmtpd's hook name
        self, server: Any, session: Any, envelope: Any, address: str, rcpt_options: Any
    ) -> str:
        if address in self.refuse:
            return "550 5.1.1 Mailbox unavailable"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server: Any, session: Any, envelope: Any) -> str:  # noqa: N802
        self.relay.raw.append(envelope.original_content)
        self.relay.envelopes.append((envelope.mail_from, list(envelope.rcpt_tos)))
        return "250 OK"


def _authenticator(
    server: Any, session: Any, envelope: Any, mechanism: str, auth_data: Any
) -> AuthResult:
    accepted = (
        isinstance(auth_data, LoginPassword)
        and auth_data.login == USERNAME.encode()
        and auth_data.password == PASSWORD.encode()
    )
    # `handled=False` makes aiosmtpd send its own 535 on failure; the default (True) means
    # "the reply was already sent" and would leave the client waiting.
    return AuthResult(success=accepted, handled=False)


@contextmanager
def relay(directory: Path, mode: str = "tls", *, refuse: tuple[str, ...] = ()) -> Iterator[Relay]:
    """Run the relay in `tls` (implicit), `starttls`, or `plain` (no STARTTLS offered)."""
    ca, cert, key = mint(directory)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    state = Relay(free_port(), ssl.create_default_context(cafile=str(ca)))
    options: dict[str, Any] = {"authenticator": _authenticator}
    if mode == "tls":
        options |= {"ssl_context": server_context, "auth_require_tls": False}
    elif mode == "starttls":
        options |= {"tls_context": server_context, "require_starttls": True}
    elif mode == "plain":
        options |= {"auth_require_tls": False}
    else:
        raise ValueError(mode)
    controller = Controller(
        _Handler(state, frozenset(refuse)), hostname="127.0.0.1", port=state.port, **options
    )
    controller.start()
    try:
        yield state
    finally:
        controller.stop()
