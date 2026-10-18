# SPDX-License-Identifier: AGPL-3.0-only
"""MC3: the platform app's certificate credential, which only the collector holds (#678).

A directory an administrator consented to is read with the deployment's own app registration,
which authenticates with a certificate: an RFC 7523 client assertion signed RS256 with the
certificate's key, naming the certificate by its SHA-256 thumbprint, for the token endpoint of
the directory being read, living five minutes with a fresh `jti`. The credential is a file the
collector alone holds (`scout-app.json`), read and checked whole and never printed. Every test
runs against the fake directory; nothing reaches Microsoft.
"""

import base64
import json
from datetime import UTC, datetime

import httpx
import pytest

from execbound.monitoring import graph
from execbound_harness import fake_graph
from execbound_harness.fake_graph import CLIENT, DIRECTORY

ENDPOINT = f"{graph.LOGIN_ORIGIN}/{DIRECTORY}/oauth2/v2.0/token"


def segment(value: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))


@pytest.fixture
def credential():
    return fake_graph.platform_app()


@pytest.fixture
def app(credential):
    return graph.PlatformApp.from_text(json.dumps(credential))


def post(server, assertion, *, client_id=CLIENT):
    with httpx.Client(transport=fake_graph.transport(server), trust_env=False) as http:
        return http.post(
            ENDPOINT,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_assertion_type": fake_graph.ASSERTION_TYPE,
                "client_assertion": assertion,
                "scope": graph.GRAPH_SCOPE,
            },
        )


def test_mc3_an_assertion_names_the_certificate_and_lives_five_minutes_with_a_fresh_id(app):
    now = datetime.now(UTC)
    first, second = app.assertion(ENDPOINT, now), app.assertion(ENDPOINT, now)
    header, payload = segment(first.split(".")[0]), segment(first.split(".")[1])
    assert header == {"alg": "RS256", "typ": "JWT", "x5t#S256": app.thumbprint}
    assert payload["aud"] == ENDPOINT
    assert payload["iss"] == payload["sub"] == CLIENT
    assert payload["exp"] - payload["nbf"] == graph.ASSERTION_SECONDS == 300
    assert payload["nbf"] == payload["iat"] == int(now.timestamp())
    assert segment(second.split(".")[1])["jti"] != payload["jti"]


def test_mc3_the_token_endpoint_takes_a_correct_assertion_and_refuses_a_wrong_key_or_audience(
    credential, app
):
    other = graph.PlatformApp.from_text(json.dumps(fake_graph.platform_app()))
    now = datetime.now(UTC)
    with fake_graph.serving(
        fake_graph.Scenario(certificate=credential["certificate_pem"])
    ) as server:
        assert post(server, app.assertion(ENDPOINT, now)).status_code == 200
        assert [claims["iss"] for claims in server.assertions] == [CLIENT]
        refused = {
            # Signed by another key, which names another certificate.
            "another key": post(server, other.assertion(ENDPOINT, now)),
            # For another directory's token endpoint.
            "another audience": post(
                server, app.assertion(ENDPOINT.replace(DIRECTORY, CLIENT), now)
            ),
            # Long expired.
            "expired": post(server, app.assertion(ENDPOINT, datetime(2026, 1, 1, tzinfo=UTC))),
            # Naming another app as its client.
            "another client": post(server, app.assertion(ENDPOINT, now), client_id=DIRECTORY),
        }
        assert {name: answer.status_code for name, answer in refused.items()} == dict.fromkeys(
            refused, 401
        )
        assert len(server.assertions) == 1


def test_mc3_a_reader_with_the_platform_apps_certificate_authenticates(credential, app):
    scenario = fake_graph.Scenario(certificate=credential["certificate_pem"])
    with (
        fake_graph.serving(scenario) as server,
        httpx.Client(
            transport=fake_graph.transport(server), trust_env=False, follow_redirects=False
        ) as http,
    ):
        reader = graph.Reader(DIRECTORY, CLIENT, None, http, app=app)
        reader.authenticate()
        assert graph.verify_directory(reader) == DIRECTORY
        # No secret was sent, and the one token request carried the assertion.
        [token] = [path for path in server.paths() if path.endswith("/oauth2/v2.0/token")]
        assert token == f"/{DIRECTORY}/oauth2/v2.0/token"
        assert len(server.assertions) == 1


def test_mc3_a_reader_needs_exactly_one_credential():
    with httpx.Client(trust_env=False) as http:
        with pytest.raises(graph.GraphError) as refused:
            graph.Reader(DIRECTORY, CLIENT, None, http)
        assert refused.value.code == "INVALID_INPUT"


@pytest.mark.parametrize(
    "case",
    [
        "not-json",
        "list",
        "missing",
        "extra",
        "client",
        "client-newline",
        "certificate",
        "key",
        "mismatch",
        "small-key",
        "oversize",
        "duplicate",
    ],
)
def test_mc3_the_platform_app_file_is_checked_whole_and_never_printed(tmp_path, credential, case):
    key = credential["private_key_pem"]
    other = fake_graph.platform_app()
    raw = {
        "not-json": "not json " + key,
        "list": json.dumps([credential]),
        "missing": json.dumps({"client_id": CLIENT, "private_key_pem": key}),
        "extra": json.dumps({**credential, "note": "x"}),
        "client": json.dumps({**credential, "client_id": "not-a-client"}),
        # Read whole: a final newline passes a pattern read with `re.match`.
        "client-newline": json.dumps({**credential, "client_id": CLIENT + "\n"}),
        "certificate": json.dumps({**credential, "certificate_pem": "not a certificate"}),
        "key": json.dumps({**credential, "private_key_pem": key[:200]}),
        # A certificate for another key: the token endpoint would refuse every assertion.
        "mismatch": json.dumps({**credential, "certificate_pem": other["certificate_pem"]}),
        "small-key": json.dumps({**credential, **_small(credential)}),
        "oversize": json.dumps({**credential, "client_id": CLIENT + " " * 20000}),
        "duplicate": (
            f'{{"client_id": "{CLIENT}", "client_id": "{CLIENT}", '
            f'"certificate_pem": {json.dumps(credential["certificate_pem"])}, '
            f'"private_key_pem": {json.dumps(key)}}}'
        ),
    }[case]
    path = tmp_path / "scout-app.json"
    path.write_text(raw, encoding="utf-8")
    for read in (
        lambda: graph.PlatformApp.from_file(path),
        lambda: graph.PlatformApp.from_text(raw),
    ):
        with pytest.raises(graph.GraphError) as refused:
            read()
        assert refused.value.code == "INVALID_INPUT"
        assert key[40:80] not in str(refused.value)
        assert refused.value.__cause__ is None and refused.value.__suppress_context__


def _small(credential):
    """A 1024-bit key and its certificate: too small to sign for a directory."""
    from datetime import timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Small")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return {
        "certificate_pem": certificate.public_bytes(Encoding.PEM).decode("ascii"),
        "private_key_pem": key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode("ascii"),
    }


def test_mc3_the_platform_apps_private_key_is_never_in_its_representation(credential, app):
    assert app.client_id == CLIENT
    for text in (repr(app), str(app)):
        assert credential["private_key_pem"][40:80] not in text
