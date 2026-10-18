# SPDX-License-Identifier: AGPL-3.0-only
"""Where a deployment sends people for help: its support address and public pages (#496).

Core names none of them but one. A deployment sets them in its runtime configuration's `service`
block, or a loaded plugin registers them, never both, and a link with no address is not shown:
the sign-in page's "Forgot your password or lost access?", the MFA pages' "Get account help",
every page footer's Help, Privacy, Terms and Source, and the console's links, which read them
from the session. The one core names is Source, the public repository, where a deployment with
neither a block nor a plugin's links still links; a block may point it elsewhere or turn it off.
The registry's own rules are in `tests/test_plugins.py`; the console's rendering is in the
console's own tests.
"""

import json
import re
import secrets
from dataclasses import asdict
from uuid import uuid4

import pytest
from console_api_fixtures import API, console_client, console_config
from fastapi.testclient import TestClient
from plugin_fixtures import captured as captured
from plugin_fixtures import events
from plugin_fixtures import sample as sample
from test_sign_in_surface import ORIGIN, sign_in
from test_sign_in_surface import connector as connector
from test_sign_in_surface import live_provider as live_provider
from test_sign_in_surface import registry as registry
from test_sign_in_surface import runtime as runtime
from test_sign_in_surface import signed_up as signed_up
from test_sign_in_surface import world as world

from execbound import mfa
from execbound.app import create_app
from execbound.envelope import KeyRing
from execbound.mfa import totp
from execbound.plugins import NO_PLUGINS
from execbound.service_links import SOURCE_URL, ServiceLinks
from execbound.surfaces.configuration import load_runtime, read_configuration, reload_keys
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import load_session
from execbound.surfaces.tokens import TokenKeys

LINKS = ServiceLinks(
    support_email="support@example.com",
    help_url="https://example.com/help",
    status_url="https://example.com/status",
    privacy_url="https://example.com/privacy",
    terms_url="https://example.com/terms",
    plans_url="https://example.com/plans",
    security_url="https://example.com/security",
    privacy_requests_url="https://example.com/help#requests",
    source_url="https://example.com/source",
    operator="Example Operations Ltd",
)
NO_LINKS = ServiceLinks()
# What a deployment with neither a `service` block nor a plugin's links shows: Source alone.
DEFAULT = ServiceLinks(source_url=SOURCE_URL)
# The page frame's footer with every link: the four the server-rendered pages carry.
FOOTER = [
    (LINKS.help_url, "Help"),
    (LINKS.privacy_url, "Privacy"),
    (LINKS.terms_url, "Terms"),
    (LINKS.source_url, "Source"),
]
RING = KeyRing("test", {"test": b"m" * 32})
HTML = {"Accept": "text/html,application/xhtml+xml"}


def configuration(**changes: object) -> dict:
    """The smallest private configuration a gateway loads, one Gate account, with changes."""
    return {
        "origin": ORIGIN,
        "active_key_id": "continuation-v1",
        "continuation_keys": {"continuation-v1": secrets.token_bytes(32).hex()},
        "checkpoint_providers": [
            {
                "tenant_id": str(uuid4()),
                "account_id": str(uuid4()),
                "evidence_keys": {"journal-v1": secrets.token_bytes(32).hex()},
            }
        ],
    } | changes


def written(tmp_path, value: dict):
    path = tmp_path / "private.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_no_service_links_is_every_link_absent():
    assert asdict(ServiceLinks()) == dict.fromkeys(asdict(LINKS))
    keys = TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)})
    assert HumanConfig(ORIGIN, keys).service == ServiceLinks()
    with pytest.raises(ValueError):
        HumanConfig(ORIGIN, keys, service=asdict(LINKS))


def test_core_names_its_public_source_where_nothing_else_names_links():
    """The one address core carries: the public repository, which a self-hoster who changes the
    code points at their own copy (the AGPL's network clause). `ServiceLinks()` itself stays
    empty, so a plugin's links, which replace core's whole, name no Source unless they set it."""
    assert SOURCE_URL == "https://github.com/ExecBound/execbound"
    assert ServiceLinks().source_url is None
    assert NO_PLUGINS.service(None) == DEFAULT


def test_the_human_configuration_refuses_service_links_changed_after_they_were_checked():
    """A frozen dataclass can still be changed by `object.__setattr__`, so the configuration
    that renders every page checks the values again rather than trusting the type."""
    changed = ServiceLinks(help_url=LINKS.help_url)
    object.__setattr__(changed, "help_url", "javascript:alert(1)")
    keys = TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)})
    with pytest.raises(ValueError, match="Invalid service links"):
        HumanConfig(ORIGIN, keys, service=changed)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/help",
        "HTTPS://example.com/help",
        "javascript:alert(1)",
        "//example.com/help",
        "/help",
        "https://",
        "https:///help",
        "https://example.com/a b",
        "https://example.com/\thelp",
        "https://example.com/help\n",
        "https://example.com/\x00",
        "https://example.com/it's",
        "https://example.com/a<b",
        "https://example.com/a>b",
        "https://example.com/`help`",
        "https://example.com/a\\b",
        "https://example.com/" + "a" * 181,
        "",
        3,
    ],
)
def test_a_link_is_an_https_address_of_at_most_two_hundred_characters(url):
    with pytest.raises(ValueError):
        ServiceLinks(help_url=url)


@pytest.mark.parametrize(
    "address",
    [
        "",
        "support",
        "@example.com",
        "support@",
        "a@b@example.com",
        "sup port@example.com",
        "support@exa mple.com",
        "support@example.com\n",
        "support?cc=x@example.com",
        # A `?` alone: the case above also holds `=`, so a pattern that let `?` in would pass it.
        "support?@example.com",
        "a&b@example.com",
        "a%0Ab@example.com",
        "a=b@example.com",
        "x" * 65 + "@example.com",
        "support@" + "d" * 191,
        "support@" + ("d" * 46 + ".") * 4 + "com",
        3,
    ],
)
def test_a_support_address_is_one_at_sign_between_a_short_local_part_and_a_domain(address):
    with pytest.raises(ValueError):
        ServiceLinks(support_email=address)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com@evil.example/help",
        "https://user:secret@example.com/help",
        "https://:secret@example.com/help",
        "https://@example.com/help",
        "https://a@b",
    ],
)
def test_a_link_carries_no_user_information(url):
    """`https://example.com@evil.example/help` reads as example.com and goes to evil.example,
    and a `user:secret@` prefix would put a credential into every page that renders the link.
    The value is the operator's, so this is a guard against a mistake rather than an attacker."""
    with pytest.raises(ValueError):
        ServiceLinks(help_url=url)


def test_an_at_sign_after_the_host_is_admitted():
    # The positive control for the refusal above: an `@` in the path, query or fragment does
    # not change the host the link goes to.
    for url in [
        "https://example.com/people/@support",
        "https://example.com/help?to=a@example.com",
        "https://example.com/help#a@b",
    ]:
        assert ServiceLinks(help_url=url).help_url == url


def test_the_longest_address_and_link_are_admitted():
    # A domain of dotted labels, 190 characters with its top-level label.
    domain = ("d" * 46 + ".") * 4 + "co"
    longest = ServiceLinks(
        support_email="x" * 64 + "@" + domain, help_url="https://example.com/" + "a" * 180
    )
    assert longest.valid() and len(domain) == 190 and len(longest.help_url or "") == 200


@pytest.mark.parametrize(
    ("name", "admitted"),
    [
        ("ExecBound LLC", True),
        ("Acme Security, Inc.", True),
        ("Smith & Jones (Ops)", True),
        ("O'Neill IT", True),
        ("A" * 80, True),
        ("A" * 81, False),
        ("", False),
        (" Acme", False),
        ("Acme ", False),
        ("-Acme", False),
        ("Acme <script>", False),
        ('Acme "Ops"', False),
        ("Acme\nOps", False),
    ],
)
def test_an_operator_is_a_short_name_that_renders_as_text(name, admitted):
    """The footers name the deployment's operator as its copyright holder, so the name is text
    of at most 80 characters with nothing a page would read as markup or an attribute."""
    if admitted:
        assert ServiceLinks(operator=name).operator == name
    else:
        with pytest.raises(ValueError):
            ServiceLinks(operator=name)


def test_the_runtime_configuration_names_the_service_links(tmp_path):
    full = read_configuration(written(tmp_path, configuration(service=asdict(LINKS))))
    assert full.service is not None and full.service.links() == LINKS
    one = read_configuration(written(tmp_path, configuration(service={"help_url": LINKS.help_url})))
    assert one.service is not None
    assert one.service.links() == ServiceLinks(help_url=LINKS.help_url, source_url=SOURCE_URL)
    assert read_configuration(written(tmp_path, configuration())).service is None


@pytest.mark.parametrize(
    ("block", "shown"),
    [
        ({}, SOURCE_URL),
        ({"source_url": "https://example.com/our-copy"}, "https://example.com/our-copy"),
        ({"source_url": None}, None),
    ],
)
def test_a_service_block_keeps_the_source_link_unless_it_names_another_or_none(
    tmp_path, block, shown
):
    """Leaving `source_url` out keeps the public repository; a deployment that changed the code
    names its own copy, and `null` turns the link off."""
    read = read_configuration(written(tmp_path, configuration(service=block)))
    assert read.service is not None and read.service.links() == ServiceLinks(source_url=shown)


@pytest.mark.parametrize(
    "block",
    [
        {"help_url": "http://example.com/help"},
        {"support_email": "not an address"},
        {"support_email": "help?cc=someone@example.com"},
        {"help_url": 'https://example.com/"onmouseover="x'},
        {"status_url": "https://example.com/" + "a" * 181},
        {"source_url": "http://example.com/source"},
        {"source_url": "javascript:alert(1)"},
        {"help_url": 3},
        {"support_url": "https://example.com/support"},
        {"operator": "<b>Acme</b>"},
        {"operator": " Acme"},
        {"operator": "A" * 81},
        {"operator": 3},
        [],
        "https://example.com/help",
    ],
)
def test_a_service_block_with_a_bad_link_or_an_unknown_field_refuses_the_file(tmp_path, block):
    with pytest.raises(ValueError):
        read_configuration(written(tmp_path, configuration(service=block)))


def test_a_changed_service_block_changes_what_a_reload_may_not(tmp_path):
    value = configuration(service={"help_url": LINKS.help_url})
    before = read_configuration(written(tmp_path, value)).shape()
    changed = value | {"service": {"help_url": "https://example.com/other"}}
    assert read_configuration(written(tmp_path, changed)).shape() != before


@pytest.mark.integration
def test_a_gateway_takes_its_service_links_from_its_configuration(db, tmp_path):
    _, human = load_runtime(written(tmp_path, configuration(service=asdict(LINKS))), db)
    assert human.service == LINKS
    _, bare = load_runtime(written(tmp_path, configuration()), db)
    assert bare.service == DEFAULT


@pytest.mark.integration
def test_a_gateway_takes_its_service_links_from_a_plugin(db, tmp_path, sample):
    value = configuration(plugins={"sample_plugin": {}})
    _, human = load_runtime(written(tmp_path, value), db)
    assert human.service == sample.SERVICE_LINKS


@pytest.mark.integration
def test_a_service_block_beside_a_plugins_links_refuses_start(db, tmp_path, sample, captured):
    """Both at once is a misconfigured deployment, and choosing one would hide which links its
    pages show, so the whole file is refused and the refusal is logged by its code."""
    value = configuration(service={"help_url": LINKS.help_url}, plugins={"sample_plugin": {}})
    with pytest.raises(ValueError, match="Invalid runtime configuration"):
        load_runtime(written(tmp_path, value), db)
    [event] = events(captured, "plugins.refused")
    assert event["code"] == "PLUGIN_CONFLICT" and "plugin" not in event


@pytest.mark.integration
def test_a_reload_that_changes_the_service_block_is_refused(db, tmp_path):
    value = configuration(service={"help_url": LINKS.help_url})
    path = written(tmp_path, value)
    runtime, human = load_runtime(path, db)
    baseline = read_configuration(path)
    written(tmp_path, value | {"service": {"help_url": "https://example.com/other"}})
    outcome = reload_keys(path, runtime, human, baseline)
    assert (outcome.state, outcome.code) == ("refused", "CONFIGURATION_CHANGED")
    assert human.service == ServiceLinks(help_url=LINKS.help_url, source_url=SOURCE_URL)


def gateway(db, runtime, service: ServiceLinks = NO_LINKS) -> TestClient:
    human = HumanConfig(
        ORIGIN,
        TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)}),
        mfa=RING,
        service=service,
    )
    return TestClient(
        create_app(db, runtime=runtime, human=human), base_url=ORIGIN, follow_redirects=False
    )


def footer(page: str) -> list[tuple[str, str]]:
    """The page frame's footer links, as (destination, words)."""
    [found] = re.findall(r"<footer>(.*?)</footer>", page, re.S)
    return re.findall(r'<a href="([^"]+)">([^<]*)</a>', found)


def refused_page(client: TestClient, seeded) -> str:
    """An error page: an agent's credential on a person's page is refused with one."""
    answer = client.get(
        f"/approvals/{uuid4()}/classic",
        headers={**HTML, "Authorization": "Bearer " + seeded["tokens"][0]},
    )
    assert answer.status_code == 403 and "This session cannot do that" in answer.text
    return answer.text


@pytest.mark.integration
def test_without_service_links_no_page_links_to_a_service_page(db, runtime, seeded):
    with gateway(db, runtime) as client:
        login = client.get("/login")
        assert login.status_code == 200
        error = refused_page(client, seeded)
    assert "Forgot your password or lost access?" not in login.text
    for page in (login.text, error):
        assert footer(page) == []
        # A self-hosted deployment is its operator's: with none named, the software is credited.
        assert "Powered by ExecBound</span></footer>" in page
        assert "ExecBound LLC" not in page
        assert 'href="https://' not in page


@pytest.mark.integration
def test_every_footer_links_the_public_source_where_nothing_names_other_links(db, runtime, seeded):
    with gateway(db, runtime, NO_PLUGINS.service(None)) as client:
        login = client.get("/login")
        assert login.status_code == 200
        error = refused_page(client, seeded)
    assert "Forgot your password or lost access?" not in login.text
    for page in (login.text, error):
        assert footer(page) == [(SOURCE_URL, "Source")]
        assert f'Powered by ExecBound · <a href="{SOURCE_URL}">Source</a></span></footer>' in page


@pytest.mark.integration
def test_the_sign_in_page_and_every_footer_link_the_deployments_pages(db, runtime, seeded):
    with gateway(db, runtime, LINKS) as client:
        login = client.get("/login")
        assert login.status_code == 200
        error = refused_page(client, seeded)
        # Two more pages that run before a session exists, each rendering its own footer.
        invitation = client.get("/join")
        password = client.get("/set-password")
    assert "<h1>Open your invitation.</h1>" in invitation.text
    assert "<h1>Choose a password.</h1>" in password.text
    [section] = re.findall(r'<section class="login">(.*?)</section>', login.text, re.S)
    assert f'<p><a href="{LINKS.help_url}">Forgot your password or lost access?</a></p>' in section
    for page in (login.text, error, invitation.text, password.text):
        assert footer(page) == FOOTER
        assert "<span>© 2026 Example Operations Ltd · " in page
        assert "Powered by ExecBound" not in page


@pytest.mark.integration
@pytest.mark.parametrize("service", [NO_LINKS, LINKS], ids=["none", "all"])
def test_the_mfa_pages_offer_account_help_only_at_the_deployments_address(
    db, runtime, signed_up, service
):
    """Account security (`mfa.html`) and the second step of signing in (`mfa_challenge.html`)."""
    shown = 0 if service == NO_LINKS else 1
    with gateway(db, runtime, service) as client:
        assert sign_in(client).status_code == 303
        security = client.get("/account/security")
        session = load_session(db, client.cookies.get("eb_session"), clock=runtime.clock)
        seed = mfa.begin_enrollment(db, session, RING, clock=runtime.clock)
        code = totp(seed, int(runtime.clock.now().timestamp() // 30))
        mfa.confirm_enrollment(db, session, RING, code, clock=runtime.clock)
        client.cookies.clear()
        assert sign_in(client).headers["location"] == "/mfa"
        challenge = client.get("/mfa")
    assert "<h1>Account security</h1>" in security.text
    assert "<h1>Two-step verification</h1>" in challenge.text
    for page in (security, challenge):
        assert page.status_code == 200
        assert '<a href="/login">Sign in again</a>' in page.text
        assert page.text.count("Get account help") == shown
        assert page.text.count(f'<a href="mailto:{LINKS.support_email}">Get account help</a>') == (
            shown
        )
        assert footer(page.text) == (FOOTER if shown else [])


@pytest.mark.integration
@pytest.mark.parametrize("service", [NO_LINKS, DEFAULT, LINKS], ids=["none", "default", "all"])
def test_the_console_session_carries_the_deployments_service_links(
    db, runtime, admin_engine, world, service
):
    config = console_config(service=service)
    with console_client(db, runtime, admin_engine, world["admin"], config=config) as admin:
        view = admin.get(API + "/session").json()
    assert view["service"] == asdict(service)
