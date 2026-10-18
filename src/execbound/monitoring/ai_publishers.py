# SPDX-License-Identifier: AGPL-3.0-only
"""Which directory applications an AI publisher provides (#355).

`new-ai-consent.v1` asks one question of a principal that appears in a directory: is its
application one an AI publisher provides? The answer is a lookup in this reviewed table, never a
guess from a display name, which anyone registering an application can choose. Every entry names
the primary source it was read from and the day it was read, as the grant catalog's do: the
publisher's own documentation, or a directory's `verifiedPublisher` fields.

An entry matches on any of three identifiers a directory serves for a service principal: the
application's `appId`, the organization that owns the application (`appOwnerOrganizationId`), or
its verified publisher's `verifiedPublisherId`. The collector matches each principal when it
parses it and keeps only the entry's key; none of the identifiers it matched on is stored.

Read on 13 October 2026, and named here so the gaps are visible rather than silent:

- **Anthropic.** Its Microsoft 365 connector adds two service principals to a directory, and
  Anthropic's setup article gives both application identifiers. Anthropic's owning organization
  and verified publisher identifier are not given there, so neither is an entry.
- **OpenAI.** Its help article for the SharePoint and Microsoft 365 apps names the application
  only by its display name, "ChatGPT / OpenAI, L.L.C.", and gives no identifier, so OpenAI has
  no entry until a primary source gives one.
- **Microsoft's own applications, Copilot included, are not entries.** Dozens of first-party
  principals sit in every directory, and Copilot Studio agents arrive as agent identities with
  their own class.

A publisher is added by a reviewed pull request that cites a primary source.
"""

import re
from dataclasses import dataclass
from datetime import date

READ_ON = date(2026, 10, 13)
GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
# A verified publisher identifier is a Microsoft partner number: digits only.
PUBLISHER_NUMBER = re.compile(r"^[0-9]{1,16}$")
KEY = re.compile(r"^[a-z][a-z0-9-]{0,31}$")

ANTHROPIC_M365 = (
    "https://support.claude.com/en/articles/12542951-enable-and-use-the-microsoft-365-connector"
)


class CatalogError(ValueError):
    """A catalog that cannot explain itself; raised when it is built."""


@dataclass(frozen=True, slots=True)
class Publisher:
    """One reviewed statement that these applications are an AI publisher's, with its source."""

    key: str
    label: str
    app_refs: tuple[str, ...]
    owner_refs: tuple[str, ...]
    publisher_refs: tuple[str, ...]
    source: str
    retrieved: date


class Catalog:
    """Publishers by every identifier they are known by, each identifier claimed once."""

    def __init__(self, publishers: tuple[Publisher, ...]) -> None:
        self.publishers = publishers
        self._index: dict[tuple[str, str], Publisher] = {}
        keys: set[str] = set()
        for publisher in publishers:
            if (
                KEY.fullmatch(publisher.key) is None
                or publisher.key in keys
                or not 1 <= len(publisher.label) <= 48
                or not publisher.source.startswith("https://")
                or not (publisher.app_refs or publisher.owner_refs or publisher.publisher_refs)
            ):
                raise CatalogError(publisher.key)
            keys.add(publisher.key)
            for kind, refs, shape in (
                ("app", publisher.app_refs, GUID),
                ("owner", publisher.owner_refs, GUID),
                ("publisher", publisher.publisher_refs, PUBLISHER_NUMBER),
            ):
                for ref in refs:
                    if shape.fullmatch(ref) is None or (kind, ref) in self._index:
                        raise CatalogError(publisher.key)
                    self._index[(kind, ref)] = publisher

    def publisher(
        self,
        *,
        app_ref: str | None = None,
        owner_ref: str | None = None,
        publisher_ref: str | None = None,
    ) -> Publisher | None:
        for kind, ref in (("app", app_ref), ("owner", owner_ref), ("publisher", publisher_ref)):
            if ref is not None and (found := self._index.get((kind, ref.lower()))) is not None:
                return found
        return None

    def match(
        self,
        *,
        app_ref: str | None = None,
        owner_ref: str | None = None,
        publisher_ref: str | None = None,
    ) -> str | None:
        """The key of the publisher any of these identifiers names, or None."""
        found = self.publisher(app_ref=app_ref, owner_ref=owner_ref, publisher_ref=publisher_ref)
        return None if found is None else found.key

    def label(self, key: str | None) -> str | None:
        return next((p.label for p in self.publishers if p.key == key), None)


PRODUCTION = Catalog(
    (
        Publisher(
            key="anthropic",
            label="Anthropic",
            # "M365 MCP Client for Claude" and "M365 MCP Server for Claude", as the article
            # lists the two service principals the connector adds.
            app_refs=(
                "08ad6f98-a4f8-4635-bb8d-f1a3044760f0",
                "07c030f6-5743-41b7-ba00-0a6e85f37c17",
            ),
            owner_refs=(),
            publisher_refs=(),
            source=ANTHROPIC_M365,
            retrieved=READ_ON,
        ),
    )
)
