# SPDX-License-Identifier: AGPL-3.0-only
"""The reviewed egress catalog and its feeds (#355): SR26.

The catalog says which platform a sign-in's address belongs to, by the platform's own published
egress. Every entry names its primary source and the day it was read, every network is checked
when the catalog is built, and no address belongs to two platforms. Feeds are parsed whole from
files a person downloaded; nothing in the collector or the refresh fetches a range list.
"""

import ast
import json
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

from execbound.monitoring import egress, egress_feeds
from execbound.monitoring.egress import Catalog, CatalogError, Platform

ROOT = Path(__file__).resolve().parents[1]
DAY = date(2026, 10, 18)


def platform(key="example", networks=("203.1.0.0/24",), **changes):
    values = {
        "key": key,
        "label": "Example",
        "networks": networks,
        "source": "https://example.invalid/egress",
        "retrieved": DAY,
    }
    values.update(changes)
    return Platform(**values)


def test_sr26_every_entry_names_its_source_and_the_day_it_was_read():
    for entry in egress.PRODUCTION.platforms:
        assert entry.source.startswith("https://"), entry.key
        # A feed's entry was read the day its feed was; every other, the day the catalog was.
        read = egress_feeds.FEEDS.get(entry.feed or "")
        assert entry.retrieved == (read.retrieved if read else egress.READ_ON), entry.key
        assert entry.stable or not entry.networks, entry.key
    assert egress.VERSION == egress.PRODUCTION.version == egress.catalog_version(egress_feeds.FEEDS)
    assert egress.catalog_version({}) == "egress.2026-10-18"
    by_key = {entry.key: entry for entry in egress.PRODUCTION.platforms}
    assert by_key["anthropic"].networks == ("160.79.104.0/21",)
    assert len(by_key["make"].networks) == 18 and len(by_key["workato"].networks) == 30
    assert all(value.endswith("/32") for value in by_key["make"].networks)


@pytest.mark.parametrize(
    ("address", "key"),
    [
        ("160.79.104.0", "anthropic"),
        ("160.79.111.255", "anthropic"),
        ("160.79.112.0", None),
        ("160.79.103.255", None),
        ("54.75.157.176", "make"),
        ("54.75.157.177", None),
        ("3.234.79.251", "workato"),
        ("10.0.0.1", None),
        ("127.0.0.1", None),
        ("::1", None),
        ("2001:db8::1", None),
        ("", None),
        ("160.79.104.0/21", None),
    ],
)
def test_sr26_an_address_names_one_platform_or_none(address, key):
    found = egress.PRODUCTION.match(address)
    assert (found.key if found else None) == key


@pytest.mark.parametrize(
    "entries",
    [
        # Private, shared, documentation, multicast and too wide.
        [platform(networks=("10.0.0.0/8",))],
        [platform(networks=("100.64.0.0/10",))],
        [platform(networks=("198.51.100.0/24",))],
        [platform(networks=("224.0.0.0/4",))],
        [platform(networks=("4.0.0.0/8",))],
        [platform(networks=("2600::/16",))],
        # Not canonical, not a network, host bits set.
        [platform(networks=("203.1.0.0/024",))],
        [platform(networks=("203.1.0.1/24",))],
        [platform(networks=("an address",))],
        # Two entries claiming one address, or an entry overlapping itself.
        [platform(), platform(key="other", networks=("203.1.0.128/25",))],
        [platform(networks=("203.1.0.0/24", "203.1.0.7/32"))],
        # A key, a label and a source the catalog cannot stand behind. The repeated key's two
        # entries claim disjoint networks, so only the key can refuse them.
        [platform(key="Example")],
        [platform(), platform(networks=("203.2.0.0/24",))],
        [platform(label="")],
        [platform(source="http://example.invalid/egress")],
        # An entry that publishes no stable egress holds no networks and no feed.
        [platform(stable=False)],
        [platform(networks=(), stable=False, feed="openai")],
    ],
)
def test_sr26_a_catalog_that_cannot_explain_itself_is_refused(entries):
    with pytest.raises(CatalogError):
        Catalog(entries)


def test_sr26_two_platforms_with_disjoint_networks_make_a_catalog():
    """What the refusals above are measured against: two keys, two disjoint networks."""
    built = Catalog([platform(), platform(key="other", networks=("203.2.0.0/24",))])
    assert [entry.key for entry in built.platforms] == ["example", "other"]
    assert built.platform("other") is not None and built.match("203.2.0.9").key == "other"


def test_sr26_an_ipv6_entry_matches_within_its_network():
    catalog = Catalog([platform(networks=("2a05:d018::/36",))])
    assert catalog.match("2a05:d018:0fff::1").key == "example"
    assert catalog.match("2a05:d019::1") is None


def openai_feed(*prefixes, **changes):
    document = {"creationTime": "2026-10-18T00:00:00Z", "prefixes": list(prefixes)}
    document.update(changes)
    return json.dumps(document).encode()


def test_sr26_an_openai_feed_is_read_whole_and_collapsed():
    raw = openai_feed(
        {"ipv4Prefix": "203.2.0.0/25"},
        {"ipv4Prefix": "203.2.0.128/25"},
        {"ipv6Prefix": "2a05:d018:0000::/48"},
    )
    assert egress.parse_openai_feed(raw) == ("203.2.0.0/24", "2a05:d018::/48")


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b'{"creationTime": "x", "prefixes": [], "prefixes": []}',
        openai_feed(),
        openai_feed({"ipv4Prefix": "203.2.0.0/24", "ipv6Prefix": "2a05:d018::/48"}),
        openai_feed({"service": "connectors"}),
        openai_feed({"ipv4Prefix": "10.0.0.0/24"}),
        openai_feed({"ipv4Prefix": 17}),
        openai_feed(prefixes="203.2.0.0/24"),
        json.dumps({"prefixes": [{"ipv4Prefix": "203.2.0.0/24"}]}).encode(),
        b" " * (egress.MAX_FEED + 1),
    ],
    # Named, because pytest would otherwise put each document in the node id, and the oversize
    # one alone would make the collected list and the junit file exceed what the validation
    # evidence reads.
    ids=[
        "not-json",
        "duplicate-key",
        "no-prefixes",
        "both-families-in-one-entry",
        "an-entry-without-a-prefix",
        "a-reserved-range",
        "a-prefix-not-a-string",
        "prefixes-not-a-list",
        "no-creation-time",
        "over-max-feed",
    ],
)
def test_sr26_an_openai_feed_that_cannot_be_read_whole_is_refused(raw):
    with pytest.raises(CatalogError):
        egress.parse_openai_feed(raw)


def service_tags(*values):
    return json.dumps({"changeNumber": 1, "cloud": "Public", "values": list(values)}).encode()


def tag(name, *prefixes):
    return {"name": name, "id": name, "properties": {"addressPrefixes": list(prefixes)}}


def test_sr26_the_service_tag_download_gives_azure_connectors_alone():
    raw = service_tags(
        tag("AzureConnectors", "203.3.0.0/26", "203.3.0.64/26"),
        tag("AzureConnectors.WestEurope", "203.4.0.0/26"),
        tag("AzureCloud", "203.5.0.0/16"),
    )
    assert egress.parse_service_tags(raw) == ("203.3.0.0/25",)


@pytest.mark.parametrize(
    "raw",
    [
        service_tags(tag("AzureCloud", "203.5.0.0/16")),
        service_tags(
            tag("AzureConnectors", "203.3.0.0/26"), tag("AzureConnectors", "203.4.0.0/26")
        ),
        service_tags(tag("AzureConnectors", "192.168.0.0/24")),
        service_tags({"name": "AzureConnectors", "properties": {}}),
        json.dumps({"values": "AzureConnectors"}).encode(),
    ],
)
def test_sr26_a_service_tag_file_that_cannot_be_read_whole_is_refused(raw):
    with pytest.raises(CatalogError):
        egress.parse_service_tags(raw)


def written_feeds(module):
    """The feeds a module a refresh wrote holds, read by running it, as the reviewed module's own
    `Feed` values."""
    namespace: dict = {}
    exec(compile(module, "egress_feeds", "exec"), namespace)  # the module the test just wrote
    return {
        key: egress_feeds.Feed(feed.retrieved, feed.networks)
        for key, feed in namespace["FEEDS"].items()
    }


def test_sr26_a_refresh_fills_the_pending_entries_and_keeps_what_it_was_not_given():
    current = Path(egress_feeds.__file__).read_text(encoding="utf-8")
    written = egress.refresh(
        current,
        retrieved=date(2026, 10, 20),
        existing={},
        openai=[openai_feed({"ipv4Prefix": "203.2.0.0/24"})],
    )
    feeds = written_feeds(written)
    assert set(feeds) == {"openai"}
    assert feeds["openai"].networks == ("203.2.0.0/24",)
    assert feeds["openai"].retrieved == date(2026, 10, 20)
    # Everything before `FEEDS` is the reviewed module as it was.
    assert written.split(egress.FEEDS_MARK)[0] == current.split(egress.FEEDS_MARK)[0]
    # A second refresh given only the service tags keeps the OpenAI feed it was not given, its
    # networks and the day it was read, and dates the Azure feed from its own reading.
    kept = egress.refresh(
        written,
        retrieved=date(2026, 10, 21),
        existing=feeds,
        service_tags=service_tags(tag("AzureConnectors", "203.3.0.0/25")),
    )
    feeds = written_feeds(kept)
    assert feeds == {
        "openai": egress_feeds.Feed(date(2026, 10, 20), ("203.2.0.0/24",)),
        "azure-connectors": egress_feeds.Feed(date(2026, 10, 21), ("203.3.0.0/25",)),
    }
    assert kept.split(egress.FEEDS_MARK)[0] == current.split(egress.FEEDS_MARK)[0]
    built = egress.build(feeds)
    assert built.match("203.2.0.9").key == "openai"
    assert built.platform("openai").retrieved == date(2026, 10, 20)
    assert built.match("203.3.0.9").key == "azure-connectors"
    assert built.platform("azure-connectors").retrieved == date(2026, 10, 21)


def test_sr26_a_refresh_that_changes_the_feeds_names_a_new_catalog_version():
    """A network row names the catalog revision it was matched against, so every set of feed
    networks is its own version, whatever day it was read on."""
    day = date(2026, 10, 20)
    versions = [
        egress.catalog_version(feeds)
        for feeds in (
            {},
            {"openai": egress_feeds.Feed(day, ("203.2.0.0/24",))},
            {"openai": egress_feeds.Feed(day, ("203.2.0.0/23",))},
            {"openai": egress_feeds.Feed(date(2026, 10, 21), ("203.2.0.0/24",))},
            {
                "openai": egress_feeds.Feed(day, ("203.2.0.0/24",)),
                "azure-connectors": egress_feeds.Feed(day, ("203.3.0.0/25",)),
            },
        )
    ]
    assert len(set(versions)) == len(versions)
    # Each fits the column a driver row keeps it in.
    for version in versions:
        assert re.fullmatch(r"[a-z][a-z0-9.-]{0,47}", version), version
    built = egress.build({"openai": egress_feeds.Feed(day, ("203.2.0.0/24",))})
    assert built.version == versions[1] and built.version.startswith("egress.2026-10-18.")


def test_sr26_a_feed_that_overlaps_another_platform_refuses_the_refresh():
    current = Path(egress_feeds.__file__).read_text(encoding="utf-8")
    with pytest.raises(CatalogError):
        egress.refresh(
            current,
            retrieved=DAY,
            existing={},
            openai=[openai_feed({"ipv4Prefix": "160.79.104.0/24"})],
        )


def test_sr26_the_refresh_script_writes_a_module_that_formats_and_checks(tmp_path):
    module = tmp_path / "egress_feeds.py"
    module.write_text(Path(egress_feeds.__file__).read_text(encoding="utf-8"), encoding="utf-8")
    feed = tmp_path / "chatgpt-connectors.json"
    feed.write_bytes(openai_feed({"ipv4Prefix": "203.2.0.0/24"}, {"ipv4Prefix": "203.9.0.0/24"}))
    tags = tmp_path / "ServiceTags_Public.json"
    tags.write_bytes(service_tags(tag("AzureConnectors", "203.3.0.0/25")))
    script = ROOT / "scripts" / "refresh_egress_catalog.py"
    common = [sys.executable, str(script), "--retrieved", "2026-10-20", "--module", str(module)]
    checked = subprocess.run([*common, "--openai-feed", str(feed), "--check"], check=False)
    assert checked.returncode == 1
    wrote = subprocess.run(
        [*common, "--openai-feed", str(feed), "--service-tags", str(tags)], check=False
    )
    assert wrote.returncode == 0
    checked = subprocess.run(
        [*common, "--openai-feed", str(feed), "--service-tags", str(tags), "--check"], check=False
    )
    assert checked.returncode == 0
    formatted = subprocess.run(
        [sys.executable, "-m", "ruff", "format", "--check", str(module)],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    assert formatted.returncode == 0, formatted.stdout
    private = tmp_path / "private.json"
    private.write_bytes(openai_feed({"ipv4Prefix": "10.0.0.0/24"}))
    refused = subprocess.run(
        [*common, "--openai-feed", str(private)], check=False, capture_output=True, text=True
    )
    assert refused.returncode == 2 and "Refused" in refused.stderr


def test_sr26_the_refresh_script_keeps_the_feeds_of_the_module_it_rewrites(tmp_path):
    """A feed the script is not given keeps what the module it was named holds, not what the
    installed package's module holds: refreshing only the service tags of a module that already
    holds the OpenAI feed keeps that feed, its networks and the day it was read."""
    module = tmp_path / "egress_feeds.py"
    module.write_text(Path(egress_feeds.__file__).read_text(encoding="utf-8"), encoding="utf-8")
    feed = tmp_path / "chatgpt-connectors.json"
    feed.write_bytes(openai_feed({"ipv4Prefix": "203.2.0.0/24"}))
    tags = tmp_path / "ServiceTags_Public.json"
    tags.write_bytes(service_tags(tag("AzureConnectors", "203.3.0.0/25")))
    script = ROOT / "scripts" / "refresh_egress_catalog.py"

    def run(retrieved, *feeds):
        command = [sys.executable, str(script), "--retrieved", retrieved, "--module", str(module)]
        return subprocess.run([*command, *feeds], check=False, capture_output=True, text=True)

    assert run("2026-10-20", "--openai-feed", str(feed)).returncode == 0
    assert written_feeds(module.read_text(encoding="utf-8")) == {
        "openai": egress_feeds.Feed(date(2026, 10, 20), ("203.2.0.0/24",)),
    }
    # The module now holds a feed the installed package's does not: checking only the service
    # tags against it compares what this module would become, and refreshing them keeps it.
    assert run("2026-10-21", "--service-tags", str(tags), "--check").returncode == 1
    assert run("2026-10-21", "--service-tags", str(tags)).returncode == 0
    assert written_feeds(module.read_text(encoding="utf-8")) == {
        "openai": egress_feeds.Feed(date(2026, 10, 20), ("203.2.0.0/24",)),
        "azure-connectors": egress_feeds.Feed(date(2026, 10, 21), ("203.3.0.0/25",)),
    }
    assert run("2026-10-21", "--service-tags", str(tags), "--check").returncode == 0


def test_sr26_nothing_in_the_catalog_or_the_collector_fetches_a_range_list():
    """The catalog, its feeds, the refresh script and the driver evidence import no network
    client; no other module writes out a page or range list the catalog cites; and a module that
    sends a request names none of the catalog's page or feed constants or its entries, and reads
    no `source` but its own arguments'. The collector's requests go only to the pinned Graph and
    Microsoft sign-in origins and the connection's own Tines tenant, and a range list reaches the
    code only through a reviewed file. A static guard: what it cannot see is held in review."""
    clients = {
        "aiohttp",
        "http.client",
        "httpx",
        "pycurl",
        "requests",
        "socket",
        "urllib.request",
        "urllib3",
    }
    monitoring = ROOT / "src" / "execbound" / "monitoring"
    for path in (
        monitoring / "egress.py",
        monitoring / "egress_feeds.py",
        monitoring / "drivers.py",
        ROOT / "scripts" / "refresh_egress_catalog.py",
    ):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
                imported.update(f"{node.module}.{alias.name}" for alias in node.names)
        assert not {
            name for name in imported if name in clients or name.split(".")[0] in clients
        }, path
    # Every page and range list the catalog cites, and the service tag download: no other module
    # writes one out, so none is a request any module makes.
    urls = _egress_urls()
    assert {"ANTHROPIC", "MAKE", "WORKATO", "OPENAI", "OPENAI_FEEDS", "AZURE_CONNECTORS"} <= set(
        urls
    )
    assert set(urls["OPENAI_FEEDS"]) == set(egress.OPENAI_FEEDS)
    written = (*(url for found in urls.values() for url in found), "ServiceTags_Public")
    for path in _python_sources():
        if path.name in {"egress.py", "egress_feeds.py", "refresh_egress_catalog.py"}:
            continue
        source = path.read_text(encoding="utf-8")
        for value in (*written, "download.microsoft.com"):
            assert value not in source, (str(path.relative_to(ROOT)), value)
    # Nor does a module that sends a request reach one through the catalog: it never names a page
    # or feed constant or the entries, and reads no `source` but its own arguments', so
    # `client.get(egress.OPENAI_FEEDS[0])`, `get(egress.MAKE)` and `get(platform.source)` fail.
    entries = {*urls, "PLATFORMS", "platforms", "platform", "unattributable"}
    sending = set()
    for path in _python_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if not _imports_a_client(tree, clients):
            continue
        sending.add(path.name)
        found = sorted(_catalog_reach(tree, entries))
        assert not found, (str(path.relative_to(ROOT)), found)
    assert {"graph.py", "collection.py"} <= sending


def _egress_urls() -> dict[str, tuple[str, ...]]:
    """Each module-level constant of egress.py that holds page or feed addresses, by name."""
    path = ROOT / "src" / "execbound" / "monitoring" / "egress.py"
    found: dict[str, tuple[str, ...]] = {}
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if not (isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)):
            continue
        values = node.value.elts if isinstance(node.value, ast.Tuple) else [node.value]
        held = tuple(
            value.value
            for value in values
            if isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and value.value.startswith("https://")
            and value.value != "https://"
        )
        if held:
            found[node.targets[0].id] = held
    return found


def _python_sources() -> list[Path]:
    return sorted([*(ROOT / "src").rglob("*.py"), *(ROOT / "scripts").rglob("*.py")])


def _imports_a_client(tree: ast.AST, clients: set[str]) -> bool:
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module, *(f"{node.module}.{alias.name}" for alias in node.names)]
        if any(name in clients or name.split(".")[0] in clients for name in names):
            return True
    return False


def _through_egress(node: ast.AST) -> bool:
    """Whether an expression is reached from the egress module: `egress` itself, or another
    module's attribute of that name (`drivers.egress`)."""
    while isinstance(node, (ast.Attribute, ast.Call, ast.Subscript)):
        if isinstance(node, ast.Attribute) and node.attr == "egress":
            return True
        node = node.func if isinstance(node, ast.Call) else node.value
    return isinstance(node, ast.Name) and node.id == "egress"


def _catalog_reach(tree: ast.AST, entries: set[str]) -> set[str]:
    """What a module names of the catalog's pages, feeds and entries, and any `source` it reads
    off something other than its own command-line arguments."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "execbound.monitoring.egress":
            found.update(alias.name for alias in node.names if alias.name in entries)
        if not isinstance(node, ast.Attribute):
            continue
        if node.attr in entries and _through_egress(node.value):
            found.add(node.attr)
        if node.attr == "source" and not (
            isinstance(node.value, ast.Name) and node.value.id == "args"
        ):
            found.add(ast.unparse(node))
    return found
