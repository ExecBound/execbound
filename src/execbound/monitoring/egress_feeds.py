# SPDX-License-Identifier: AGPL-3.0-only
"""Egress ranges read from machine-readable feeds (#355). Written by
`scripts/refresh_egress_catalog.py`; review it like the catalog it fills.

A platform that publishes its egress only as a feed, rather than in a page's text, has an entry
in `egress.PRODUCTION` that names its feed here. Until a refresh reads the feed, the entry holds
no networks and matches nothing: it is pending, and an agent's detail answer names it among its
gaps. The collector never fetches a feed; a person downloads it, the script parses and checks it,
and the rewritten module goes through a pull request.
"""

from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True, slots=True)
class Feed:
    """The networks one feed held on the day it was read, as the script collapsed them."""

    retrieved: date
    networks: tuple[str, ...]


FEEDS: dict[str, Feed] = {}
