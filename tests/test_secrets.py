# SPDX-License-Identifier: AGPL-3.0-only
"""One definition of what a secret looks like (#265). The export guard and the test helper
read the same module, and no finding, repr or assertion message may carry a matched value."""

import hashlib
import json

import pytest
from secret_shapes import FREE_TEXT, FREE_TEXT_IDS

from execbound.replay.verify import ReplayValidationError, reject_secrets
from execbound.secrets import SECRET_KEYS, Finding, find_secrets, secret_shaped, withheld

# Each alternative of SECRET_TEXT with a string it must match. The values are synthetic.
MATCHES = {
    "bearer": "Authorization: Bearer 8fQ2rT7xL0pN4vZ9kC1mB6sD3wY5hJ8gA2eR4tU7",
    # Short, but structured. tests/test_replay_verify.py requires the export guard to
    # keep refusing this one, which is why the rule is structure and not length.
    "bearer-short": "Bearer synthetic-private",
    "agent-token": (
        "eb1.3f2504e0-4f89-11d3-9a0c-0305e82c3301."
        "5a1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8.zYx-Wvu_TsrqPon987654321"
    ),
    "session-token": (
        "hs1.3f2504e0-4f89-11d3-9a0c-0305e82c3301."
        "5a1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8.zYx-Wvu_TsrqPon987654321"
    ),
    "onboarding-code": (
        "ebi1.3f2504e0-4f89-11d3-9a0c-0305e82c3301."
        "5a1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8.zYx-Wvu_TsrqPon987654321"
    ),
    "invitation-code": (
        "ebv1.3f2504e0-4f89-11d3-9a0c-0305e82c3301."
        "5a1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8.zYx-Wvu_TsrqPon987654321"
    ),
    # A weekly summary's unsubscribe link (#678): the secret is in the path, by RFC 8058.
    "summary-unsubscribe": (
        "ebw1.3f2504e0-4f89-11d3-9a0c-0305e82c3301."
        "5a1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8.zYx-Wvu_TsrqPon987654321zYx-Wvu_TsrqPon98765"
    ),
    # An approval email's unsubscribe link (#179): the secret is in the path, by RFC 8058.
    "approval-email-unsubscribe": (
        "eba1.3f2504e0-4f89-11d3-9a0c-0305e82c3301."
        "5a1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8.zYx-Wvu_TsrqPon987654321zYx-Wvu_TsrqPon9876"
    ),
    # A consent attempt's OAuth state (#678), which reaches Microsoft and comes back: the
    # tenant, the attempt and a 256-bit secret.
    "connect-state": (
        "mc1.3f2504e0-4f89-11d3-9a0c-0305e82c3301."
        "5a1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8.zYx-Wvu_TsrqPon987654321zYx-Wvu_TsrqPon9876"
    ),
    # Two-segment email links: a password reset link and a signup verification link. The
    # secret is 43 base64url characters, 256 bits.
    "reset-link": (
        "ebr1.3f2504e0-4f89-11d3-9a0c-0305e82c3301.zYx-Wvu_TsrqPon987654321zYx-Wvu_TsrqPon9876"
    ),
    "signup-link": (
        "ebs1.3f2504e0-4f89-11d3-9a0c-0305e82c3301.zYx-Wvu_TsrqPon987654321zYx-Wvu_TsrqPon9876"
    ),
    "database-url": "postgresql+psycopg://execbound_app:hunter2@127.0.0.1:55439/execbound",
    "slack-webhook": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXX",
    "power-automate": (
        "https://prod-11.westus.logic.azure.com:443/workflows/abc/triggers/manual/paths/"
        "invoke?api-version=2016-06-01&sig=Nf3rEXAMPLEsignatureVALUE"
    ),
    "private-key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----",
    "stripe-secret": "sk_live_51ABCdefGHIjklMNOpqrSTU",
    "stripe-test": "sk_test_51ABCdefGHIjklMNOpqrSTU",
    "stripe-restricted": "rk_live_51ABCdefGHIjklMNOpqrSTU",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
}

# Near misses. Each is ordinary content a page, a log line or an export may legitimately
# carry, and each sits next to an alternative above.
NEAR_MISSES = [
    "Bearer",
    # Prose about the header, and the placeholders a setup recipe tells a reader to replace.
    # An earlier `Bearer \S+` reported all four as credentials.
    "a static bearer credential, and wait for the authorization",
    'claude mcp add --header "Authorization: Bearer <API key>"',
    '"headers": {"Authorization": "Bearer ${env:EXECBOUND_CREDENTIAL}"}',
    '"headers": {"Authorization": "Bearer " + os.environ["EXECBOUND_CREDENTIAL"]},',
    "Authorization: Bearer short",
    # An English word carries no digit, dot or dash, so prose after the scheme is not a
    # credential however long it runs.
    "Authorization: Bearer credentialsarenotwordslikethis",
    "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
    "eb1.short",
    "eb1",
    "ebw1",
    "ebw1.short",
    "eba1",
    "eba1.short",
    "mc1",
    "mc1.short",
    # A version number in prose is not a state.
    "the mc1 prefix",
    # A reset link's near misses: a 42-character secret, a middle that is not a UUID's
    # characters, the prefix inside a longer word, and another version's prefix.
    "ebr1.3f2504e0-4f89-11d3-9a0c-0305e82c3301.zYx-Wvu_TsrqPon987654321zYx-Wvu_TsrqPon987",
    "ebr1.not-a-uuid-at-all-but-thirty-six-cha.zYx-Wvu_TsrqPon987654321zYx-Wvu_TsrqPon9876",
    "xebr1.3f2504e0-4f89-11d3-9a0c-0305e82c3301.zYx-Wvu_TsrqPon987654321zYx-Wvu_TsrqPon9876",
    "ebr2.3f2504e0-4f89-11d3-9a0c-0305e82c3301.zYx-Wvu_TsrqPon987654321zYx-Wvu_TsrqPon9876",
    "ebr1",
    "postgres",
    "The postgres role owns the database.",
    "https://hooks.slack.com/archives/C00000000/p1700000000",
    "https://prod-11.westus.logic.azure.com/workflows/abc?api-version=2016-06-01",
    "https://prod-11.westus.logic.azure.com/workflows/abc?api-version=2016&signature=y",
    "-----BEGIN CERTIFICATE-----",
    "sk_live",
    "rk_identifier_1234",
    "risk_live_assessment",
    "eyJhbGciOiJIUzI1NiJ9",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0",
    "sig=",
]


@pytest.mark.parametrize("name", sorted(MATCHES))
def test_every_pattern_alternative_matches_its_own_shape(name):
    assert [f.kind for f in find_secrets(MATCHES[name])] == ["pattern"]


@pytest.mark.parametrize("value", NEAR_MISSES)
def test_no_near_miss_matches(value):
    assert find_secrets(value) == []


def test_forbidden_keys_match_case_and_dash_insensitively():
    for key in ("Authorization", "AUTHORIZATION", "set-cookie", "Set-Cookie", "Private-Key"):
        assert [f.kind for f in find_secrets({key: "ordinary"})] == ["key"], key
    assert find_secrets({"tokenish": "ordinary"}) == []
    assert "authorization" in SECRET_KEYS


def test_nested_paths_are_reported_in_json_path_form():
    document = {"tenants": [{"name": "Synthetic 0"}, {"token": "ordinary"}]}
    assert find_secrets(document) == [Finding(path="tenants[1].token", kind="key")]
    assert find_secrets({"a": {"b": [["deep"]]}}, known=["deep"]) == [
        Finding(path="a.b[0][0]", kind="known")
    ]
    assert find_secrets("a bare string", known=["bare"]) == [Finding(path="$", kind="known")]


def test_known_values_are_found_wherever_they_sit():
    secret = "zYx-Wvu_TsrqPon987654321"
    assert find_secrets({"body": {"issued": [secret]}}, known=[secret]) == [
        Finding(path="body.issued[0]", kind="known")
    ]
    html = f"<p class='code'>Your code is {secret}. It is shown once.</p>"
    assert find_secrets(html, known=[secret]) == [Finding(path="$", kind="known")]
    assert find_secrets(f"prefix-{secret}-suffix", known=[secret]) == [
        Finding(path="$", kind="known")
    ]
    assert find_secrets({"body": {"issued": [secret]}}) == []


def test_a_secret_used_as_a_mapping_key_does_not_reach_the_path():
    secret = "zYx-Wvu_TsrqPon987654321"
    findings = find_secrets({secret: "ordinary"}, known=[secret])
    assert findings and all(secret not in finding.path for finding in findings)


def test_no_finding_its_repr_or_the_helper_message_carries_the_value():
    from conftest import SecretLeak, assert_secret_free

    secret = "zYx-Wvu_TsrqPon987654321"
    document = {"tenants": [{"token": secret}], "url": MATCHES["database-url"]}
    findings = find_secrets(document, known=[secret])
    assert findings
    for rendering in (str(findings), repr(findings), json.dumps([f.path for f in findings])):
        assert secret not in rendering
        assert "hunter2" not in rendering
    with pytest.raises(SecretLeak) as raised:
        assert_secret_free(document, known=[secret])
    message = str(raised.value)
    assert secret not in message and "hunter2" not in message
    assert "tenants[0].token" in message


def test_the_limit_stops_the_walk_at_the_first_finding():
    document = {"token": "a", "password": "b", "secret": "c"}
    assert len(find_secrets(document, limit=1)) == 1
    assert len(find_secrets(document)) == 3


def test_reject_secrets_keeps_its_contract():
    reject_secrets({"tenant": "Synthetic 0", "counts": [1, 2, 3], "hash": "a" * 64})
    for rejected in ({"token": "x"}, {"nested": [{"authorization": "x"}]}, MATCHES["agent-token"]):
        with pytest.raises(ReplayValidationError) as raised:
            reject_secrets(rejected)
        assert raised.value.code == "PRIVATE_DATA"


@pytest.mark.parametrize(
    "value",
    [
        "eyjump.corp.example",
        "eyja.example.com",
        "eyjmail.example.co.uk",
        "EYJMAIL.EXAMPLE.CO.UK",
        "Eyjmail.example.co.uk",
    ],
)
def test_a_lowercase_or_uppercase_three_label_name_is_not_a_jwt(value):
    assert find_secrets(value) == []


@pytest.mark.parametrize(
    "value",
    [
        "Authorization: " + MATCHES["jwt"],
        "?id_token=" + MATCHES["jwt"],
        "(" + MATCHES["jwt"] + ")",
    ],
    ids=["header", "query", "parenthesized"],
)
def test_every_real_jwt_still_matches(value):
    assert [f.kind for f in find_secrets(value)] == ["pattern"]


def test_secret_shaped_answers_for_any_of_its_values_and_quotes_none():
    assert secret_shaped("plain", MATCHES["stripe-secret"]) is True
    assert secret_shaped("plain", None, 3) is False


def test_withheld_keeps_a_plain_value_and_digests_a_shaped_one():
    assert withheld("subject", "user-42") == {"subject": "user-42"}
    shaped = withheld("subject", MATCHES["stripe-secret"])
    assert shaped == {
        "subject": "WITHHELD",
        "subject_digest": hashlib.sha256(MATCHES["stripe-secret"].encode()).hexdigest(),
    }
    assert MATCHES["stripe-secret"] not in repr(shaped)


def test_free_text_ids_name_one_readable_id_per_sample_in_order():
    """`FREE_TEXT_IDS` keeps a credential-shaped sample out of pytest node ids, JUnit reports
    and CI logs; this guards the two tuples in `secret_shapes.py` from drifting apart."""
    assert len(FREE_TEXT_IDS) == len(FREE_TEXT)
