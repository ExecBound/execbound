# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic values shaped like credentials, one for each shape the screens' tests need.

The one file the new screens' tests take them from, so one export allowance covers them all.
None of them is a credential anywhere.
"""

STRIPE = "sk_live_51ABCdefGHIjklMNOpqrSTU"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
AGENT_TOKEN = "eb1.3f2504e0-4f89-11d3-9a0c-0305e82c3301.5a1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8.x"
BEARER = "Bearer abc12345x"
DATABASE_URL = "postgres://owner:pw@db.example.com/x"
SLACK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXX"
# Shapes a lowercase-only pattern admits, for fields such as rule ids and writer labels.
LOWER_STRIPE = STRIPE.lower()
# Free text: the shapes a reason, a name or a label can carry. ExecBound's own credential is
# the likeliest thing a person pastes, so it belongs beside the third-party shapes.
FREE_TEXT = (
    STRIPE,
    JWT,
    AGENT_TOKEN,
    BEARER,
    DATABASE_URL,
    SLACK,
    "see " + STRIPE + " for details",
)
# One short, readable pytest id per `FREE_TEXT` item, in the same order, so a node id, a
# JUnit report or a CI log names the shape rather than carrying the credential-shaped value
# itself. `tests/test_secrets.py` asserts the two tuples stay the same length.
FREE_TEXT_IDS = (
    "stripe",
    "jwt",
    "agent-token",
    "bearer",
    "database-url",
    "slack",
    "embedded",
)
