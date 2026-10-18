# SPDX-License-Identifier: AGPL-3.0-only
"""Which platform a network address belongs to, by the platform's own published egress (#355).

A service principal's sign-in carries the address it came from. When that address is in a range
a platform publishes as the one its servers connect from, the sign-in is `network` evidence that
the platform drives the actor. It names a platform, never a workflow: every customer of the
platform shares the range. The lookup is this reviewed table, never a guess from a name or a
reverse lookup, and the collector never fetches a range list while it runs: the networks are
code, and a change to them is a reviewed pull request.

Every entry names its primary source and the day it was read. Every network is checked when the
catalog is built: it is a network in canonical form, global unicast (not private, shared,
loopback, link-local, documentation, multicast or reserved), no wider than a /12 for IPv4 or a /32
for IPv6, and it overlaps no other network in the catalog, so an address names one platform or
none.

Read on 18 October 2026, and named here so the gaps are visible rather than silent:

- **Anthropic** publishes its outbound range in the page's text, and says it will not change
  without notice.
- **Make** and **Workato** publish their egress addresses in a table on a page: three for each of
  Make's six zones and of Workato's nine data centres and its self-service one. Each address was
  transcribed from the page on the day named, and is compared against the page in review.
- **OpenAI** publishes its egress only as two JSON feeds and says they change; **Power Automate
  and Logic Apps** use the `AzureConnectors` service tag, published in Microsoft's weekly service
  tag download. Both entries take their networks from `egress_feeds`, which
  `scripts/refresh_egress_catalog.py` writes from files a person downloaded; until it has, they
  are pending and match nothing.
- **Zapier** says it has no static range, and **n8n Cloud** publishes addresses that it says change
  without notice. Neither is used as evidence: their actors cannot be attributed by network, and
  an agent's detail answer names both among its gaps (`driver_gaps`) rather than guessing.

A platform is added by a reviewed pull request that cites a primary source.
"""

import bisect
import hashlib
import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import date
from typing import Any

from execbound.monitoring import egress_feeds

READ_ON = date(2026, 10, 18)
KEY = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
# The widest network an entry may hold: past this a range would claim a large part of a cloud.
WIDEST = {4: 12, 6: 32}
# What a feed file may be before it is parsed, and how many prefixes it may hold.
MAX_FEED = 16 * 1024 * 1024
MAX_PREFIXES = 20000

ANTHROPIC = "https://platform.claude.com/docs/en/api/ip-addresses"
MAKE = "https://help.make.com/allow-connections-to-and-from-make-ip-addresses"
WORKATO = "https://docs.workato.com/security/ip-allowlists.html"
OPENAI = "https://developers.openai.com/api/docs/guides/ip-addresses"
OPENAI_FEEDS = (
    "https://openai.com/chatgpt-connectors.json",
    "https://openai.com/chatgpt-agents.json",
)
AZURE_CONNECTORS = "https://learn.microsoft.com/en-us/connectors/common/outbound-ip-addresses"
SERVICE_TAG = "AzureConnectors"
ZAPIER = (
    "https://help.zapier.com/hc/en-us/articles/8496216020877-Zapier-IP-addresses-and-allowlisting"
)
N8N = "https://docs.n8n.io/manage-cloud/cloud-ip/"


class CatalogError(ValueError):
    """A catalog or a feed that cannot explain itself; raised when it is built or parsed."""


@dataclass(frozen=True, slots=True)
class Platform:
    """One reviewed statement that a platform's servers connect from these networks.

    `stable` is false for a platform that publishes no stable egress: it holds no networks and
    is named so an agent's detail answer can say its actors cannot be attributed by network.
    `feed` names the `egress_feeds` entry that fills a platform's networks; until the feed is read
    the platform is pending and matches nothing.
    """

    key: str
    label: str
    networks: tuple[str, ...]
    source: str
    retrieved: date
    stable: bool = True
    feed: str | None = None

    @property
    def pending(self) -> bool:
        return self.stable and not self.networks


def network(
    value: object, *, canonical: bool = True
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """One network an entry may hold, or `CatalogError`. A reviewed entry writes it as
    `ipaddress` does (`canonical`); a feed may write it otherwise, and is rewritten."""
    if type(value) is not str or len(value) > 64:
        raise CatalogError("network")
    try:
        parsed = ipaddress.ip_network(value, strict=True)
    except ValueError:
        raise CatalogError("network") from None
    if (
        (canonical and str(parsed) != value)
        or not parsed.is_global
        or parsed.is_multicast
        or parsed.prefixlen < WIDEST[parsed.version]
    ):
        raise CatalogError("network")
    return parsed


def _span(found: ipaddress.IPv4Network | ipaddress.IPv6Network) -> tuple[int, int, int]:
    return (found.version, int(found.network_address), int(found.broadcast_address))


def catalog_version(feeds: Mapping[str, egress_feeds.Feed]) -> str:
    """The revision a network row says it was matched against: the day the reviewed entries were
    read and, once any feed has been, the latest day one was read and a digest of every feed's
    networks, so a refresh that changes what the catalog matches always names a new version."""
    version = f"egress.{READ_ON.isoformat()}"
    if not feeds:
        return version
    latest = max(read.retrieved for read in feeds.values())
    networks = json.dumps(
        {name: list(feeds[name].networks) for name in sorted(feeds)}, separators=(",", ":")
    )
    digest = hashlib.sha256(networks.encode()).hexdigest()[:8]
    return f"{version}.feeds.{latest.isoformat()}.{digest}"


class Catalog:
    """Platforms by the networks they publish, each address claimed by one platform at most,
    and the revision they make (`catalog_version`)."""

    def __init__(self, platforms: Iterable[Platform], *, version: str | None = None) -> None:
        self.version = version or catalog_version({})
        self.platforms = tuple(platforms)
        keys: set[str] = set()
        spans: list[tuple[int, int, int, Platform]] = []
        for platform in self.platforms:
            if (
                KEY.fullmatch(platform.key) is None
                or platform.key in keys
                or not 1 <= len(platform.label) <= 64
                or not platform.source.startswith("https://")
                or (not platform.stable and (platform.networks or platform.feed))
            ):
                raise CatalogError(platform.key)
            keys.add(platform.key)
            for value in platform.networks:
                family, start, end = _span(network(value))
                spans.append((family, start, end, platform))
        spans.sort(key=lambda span: span[:3])
        for before, after in zip(spans, spans[1:], strict=False):
            if before[0] == after[0] and after[1] <= before[2]:
                raise CatalogError(after[3].key)
        self._spans = spans
        self._starts = [span[:2] for span in spans]

    def match(self, address: str) -> Platform | None:
        """The stable platform whose published network holds `address`, or None. An address
        that is not one, or not global unicast, belongs to no platform."""
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return None
        if not parsed.is_global or parsed.is_multicast:
            return None
        key = (parsed.version, int(parsed))
        index = bisect.bisect_right(self._starts, key) - 1
        if index < 0:
            return None
        version, start, end, platform = self._spans[index]
        return platform if version == key[0] and start <= key[1] <= end else None

    def platform(self, key: str) -> Platform | None:
        return next((p for p in self.platforms if p.key == key), None)

    @property
    def unattributable(self) -> tuple[Platform, ...]:
        """Platforms that publish no stable egress, which an agent's detail answer names among its
        gaps."""
        return tuple(p for p in self.platforms if not p.stable)


def _addresses(*values: str) -> tuple[str, ...]:
    return tuple(f"{value}/32" for value in values)


def _feed(platform: Platform, feeds: Mapping[str, egress_feeds.Feed]) -> Platform:
    """`platform` with the networks and the reading day of its feed, if the feed was read."""
    read = feeds.get(platform.feed or "")
    if read is None:
        return platform
    return Platform(
        key=platform.key,
        label=platform.label,
        networks=read.networks,
        source=platform.source,
        retrieved=read.retrieved,
        feed=platform.feed,
    )


# The reviewed entries. One that names a feed takes its networks from `egress_feeds` (`build`).
PLATFORMS = (
    Platform(
        key="anthropic",
        label="Anthropic",
        # "the stable IP addresses that Anthropic uses for outbound requests"
        networks=("160.79.104.0/21",),
        source=ANTHROPIC,
        retrieved=READ_ON,
    ),
    Platform(
        key="make",
        label="Make",
        networks=_addresses(
            # us2.make.com, us1.make.com, eu2.make.com, eu1.make.com
            "44.209.150.16",
            "44.210.162.163",
            "35.170.163.230",
            "54.209.79.175",
            "54.80.47.193",
            "54.161.178.114",
            "34.254.1.9",
            "52.31.156.93",
            "52.50.32.186",
            "54.75.157.176",
            "54.78.149.203",
            "52.18.144.195",
            # us1.make.celonis.com, eu1.make.celonis.com
            "44.196.246.20",
            "3.94.51.90",
            "52.4.48.212",
            "3.125.27.86",
            "3.68.125.41",
            "18.193.24.45",
        ),
        source=MAKE,
        retrieved=READ_ON,
    ),
    Platform(
        key="workato",
        label="Workato",
        networks=_addresses(
            # US, EU, JP, SG, AU, IL, CN, KR and UK, then the self-service data centre
            "52.5.142.59",
            "34.226.132.221",
            "52.54.43.157",
            "3.65.225.246",
            "3.66.45.94",
            "18.198.249.58",
            "52.193.168.95",
            "13.113.30.44",
            "18.176.45.101",
            "13.215.42.244",
            "18.141.131.114",
            "52.74.226.121",
            "54.253.214.156",
            "13.236.115.248",
            "13.238.90.15",
            "51.16.210.3",
            "51.84.133.176",
            "51.17.208.207",
            "161.189.63.116",
            "52.82.72.174",
            "52.83.128.24",
            "43.200.205.181",
            "43.201.190.232",
            "3.36.217.81",
            "35.179.4.243",
            "35.179.240.64",
            "16.60.82.97",
            "174.129.15.46",
            "13.216.205.222",
            "3.234.79.251",
        ),
        source=WORKATO,
        retrieved=READ_ON,
    ),
    Platform(
        key="openai",
        label="OpenAI",
        networks=(),
        source=OPENAI,
        retrieved=READ_ON,
        feed="openai",
    ),
    Platform(
        key="azure-connectors",
        label="Power Automate and Logic Apps",
        networks=(),
        source=AZURE_CONNECTORS,
        retrieved=READ_ON,
        feed="azure-connectors",
    ),
    Platform(
        key="zapier",
        label="Zapier",
        networks=(),
        source=ZAPIER,
        retrieved=READ_ON,
        stable=False,
    ),
    Platform(
        key="n8n-cloud",
        label="n8n Cloud",
        networks=(),
        source=N8N,
        retrieved=READ_ON,
        stable=False,
    ),
)


def build(feeds: Mapping[str, egress_feeds.Feed]) -> Catalog:
    """The catalog the reviewed entries make with these feeds' networks."""
    return Catalog(
        (_feed(platform, feeds) if platform.feed else platform for platform in PLATFORMS),
        version=catalog_version(feeds),
    )


PRODUCTION = build(egress_feeds.FEEDS)
# What a network row matched against the production catalog names as its `catalog_version`.
VERSION = PRODUCTION.version
FEED_NAMES = tuple(platform.feed for platform in PLATFORMS if platform.feed)


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError
    return dict(pairs)


def _constant(value: str) -> Any:
    raise ValueError


def _document(raw: bytes) -> Any:
    if type(raw) is not bytes or len(raw) > MAX_FEED:
        raise CatalogError("feed")
    try:
        return json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
    except (ValueError, RecursionError, UnicodeDecodeError):
        raise CatalogError("feed") from None


def collapse(values: Iterable[str]) -> tuple[str, ...]:
    """Checked networks, merged where they touch and sorted: what a feed's entry holds."""
    parsed = [network(value, canonical=False) for value in values]
    if not parsed or len(parsed) > MAX_PREFIXES:
        raise CatalogError("feed")
    four = [item for item in parsed if isinstance(item, ipaddress.IPv4Network)]
    six = [item for item in parsed if isinstance(item, ipaddress.IPv6Network)]
    merged = [*ipaddress.collapse_addresses(four), *ipaddress.collapse_addresses(six)]
    return tuple(str(item) for item in merged)


def parse_openai_feed(raw: bytes) -> tuple[str, ...]:
    """The prefixes of one OpenAI egress feed: an object with a `creationTime` and a `prefixes`
    array whose every entry names exactly one of `ipv4Prefix` and `ipv6Prefix`. Anything else,
    and any prefix that is not a network an entry may hold, refuses the whole feed."""
    document = _document(raw)
    if (
        not isinstance(document, dict)
        or type(document.get("creationTime")) is not str
        or not isinstance(document.get("prefixes"), list)
    ):
        raise CatalogError("feed")
    values = []
    for entry in document["prefixes"]:
        if not isinstance(entry, dict):
            raise CatalogError("feed")
        named = [entry[key] for key in ("ipv4Prefix", "ipv6Prefix") if key in entry]
        if len(named) != 1 or type(named[0]) is not str:
            raise CatalogError("feed")
        values.append(named[0])
    return collapse(values)


def parse_service_tags(raw: bytes, tag: str = SERVICE_TAG) -> tuple[str, ...]:
    """The address prefixes of one service tag in Microsoft's service tag download: an object
    whose `values` hold exactly one entry named `tag`, whose `properties.addressPrefixes` is a
    list of networks. Anything else refuses the whole file."""
    document = _document(raw)
    values = document.get("values") if isinstance(document, dict) else None
    if not isinstance(values, list):
        raise CatalogError("feed")
    named = [entry for entry in values if isinstance(entry, dict) and entry.get("name") == tag]
    if len(named) != 1:
        raise CatalogError("feed")
    properties = named[0].get("properties")
    prefixes = properties.get("addressPrefixes") if isinstance(properties, dict) else None
    if not isinstance(prefixes, list):
        raise CatalogError("feed")
    return collapse(prefixes)


FEEDS_MARK = "FEEDS: dict[str, Feed] = "


def render_feeds(current: str, feeds: Mapping[str, egress_feeds.Feed]) -> str:
    """`egress_feeds`'s source with its `FEEDS` replaced by `feeds`, sorted, one network a line,
    in the form the formatter keeps; everything before `FEEDS` is kept as it is."""
    head, mark, _ = current.partition(FEEDS_MARK)
    if not mark or set(feeds) - set(FEED_NAMES):
        raise CatalogError("feeds")
    if not feeds:
        return head + FEEDS_MARK + "{}\n"
    lines = [head + FEEDS_MARK + "{"]
    for name in sorted(feeds):
        read = feeds[name]
        day = read.retrieved
        # A one-element tuple's comma is its syntax, not a trailing comma, so the formatter
        # writes it on one line.
        networks = (
            [f'        networks=("{read.networks[0]}",),']
            if len(read.networks) == 1
            else [
                "        networks=(",
                *(f'            "{value}",' for value in read.networks),
                "        ),",
            ]
        )
        lines += [
            f'    "{name}": Feed(',
            f"        retrieved=date({day.year}, {day.month}, {day.day}),",
            *networks,
            "    ),",
        ]
    return "\n".join([*lines, "}"]) + "\n"


def refresh(
    current: str,
    *,
    retrieved: date,
    existing: Mapping[str, egress_feeds.Feed] = egress_feeds.FEEDS,
    openai: Iterable[bytes] = (),
    service_tags: bytes | None = None,
) -> str:
    """The module a refresh writes from `current`, the module's source, and `existing`, the feeds
    it holds: the OpenAI feeds' prefixes merged as one entry, and the `AzureConnectors` tag's,
    each read on `retrieved`; a feed not given keeps what `existing` held. The result is built into
    the catalog before it is returned, so a feed whose networks overlap another platform's, or any
    that no entry may hold, refuses the whole refresh."""
    feeds = dict(existing)
    given = [parse_openai_feed(raw) for raw in openai]
    if given:
        merged = collapse(value for networks in given for value in networks)
        feeds["openai"] = egress_feeds.Feed(retrieved=retrieved, networks=merged)
    if service_tags is not None:
        feeds["azure-connectors"] = egress_feeds.Feed(
            retrieved=retrieved, networks=parse_service_tags(service_tags)
        )
    build(feeds)
    return render_feeds(current, feeds)
