# SPDX-License-Identifier: AGPL-3.0-only
"""Where a deployment sends people for help: its support address and its public pages.

The pages that run before a session exists, the console's Help page, My account and the
footers link to a support address, a help page, a status page and the privacy, terms, plans,
security and request-handling pages. None of them is the software's: each belongs to whoever
runs the deployment. So core names none of them. A deployment sets them in its runtime
configuration's `service` block, or a loaded plugin registers them (`Registry.service_links`),
never both; a link with no address is not shown at all.

The footers' Source link is the one core names: `SOURCE_URL`, the public repository, which
a deployment with neither a block nor a plugin's links shows, and which a block that leaves
`source_url` out keeps. Someone who runs changed code points it at their copy, which helps them
meet the AGPL's network clause, or turns it off with `null`. A plugin's links replace core's
whole, so a plugin that leaves `source_url` unset shows none.

`operator` is who runs the deployment, shown as the footers' copyright holder. Core names
none, and a footer with none credits the software instead, "Powered by ExecBound": a self-hosted
deployment is its operator's, not ExecBound's. The hosted service's plugin names ExecBound LLC.
It is a name of at most 80 letters, digits, spaces and `.,&'()-`, starting with a letter or
digit, so it renders as text wherever it appears.

Every other value is checked here, once, whichever source gave it, because each is rendered as a
link's destination: a URL is `https://` with a host and no user information, at most 200
characters and nothing a browser would read as a space or a control character; an address is
one `@` between a local part of at most 64 characters and a domain of dotted labels of at most
190.
"""

import re
from dataclasses import dataclass, fields
from urllib.parse import urlsplit

# The public repository: what the footers' Source link shows unless the deployment says otherwise.
SOURCE_URL = "https://github.com/ExecBound/execbound"
MAX_URL = 200
MAX_DOMAIN = 190
# Letters, digits and `._+-` only: nothing that would add a header to a `mailto:` link
# (`?`, `&`, `%`) or leave an attribute (`"`, `<`, `>`).
_ADDRESS = re.compile(r"[A-Za-z0-9._+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,63}")
_OPERATOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .,&'()-]{0,79}")


def _url(value: object) -> bool:
    if value is None:
        return True
    if type(value) is not str or len(value) > MAX_URL or not value.isprintable():
        return False
    if not value.startswith("https://") or any(character.isspace() for character in value):
        return False
    if any(character in value for character in "\"'<>`\\"):
        return False
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    # No user information, even an empty one: `https://example.com@evil.example` goes to
    # evil.example, and a `user:secret@` prefix would be rendered on every page.
    return bool(parts.hostname) and "@" not in parts.netloc


def _operator(value: object) -> bool:
    return value is None or (
        type(value) is str and _OPERATOR.fullmatch(value) is not None and value == value.strip()
    )


def _address(value: object) -> bool:
    return value is None or (
        type(value) is str
        and value.isprintable()
        and _ADDRESS.fullmatch(value) is not None
        and len(value.partition("@")[2]) <= MAX_DOMAIN
    )


@dataclass(frozen=True)
class ServiceLinks:
    """A deployment's support address and public pages; None is a link not shown."""

    support_email: str | None = None
    help_url: str | None = None
    status_url: str | None = None
    privacy_url: str | None = None
    terms_url: str | None = None
    plans_url: str | None = None
    security_url: str | None = None
    privacy_requests_url: str | None = None
    # None here, as every field is: `SOURCE_URL` is applied where the links are resolved
    # (`LoadedPlugins.service` and the configuration's `service` block), never by this class.
    source_url: str | None = None
    operator: str | None = None

    def __post_init__(self) -> None:
        if not self.valid():
            raise ValueError("Invalid service links")

    def valid(self) -> bool:
        """Whether every value is one this module admits. Checked again by the registry, so
        a value changed after construction is refused rather than rendered."""
        return (
            _address(self.support_email)
            and _operator(self.operator)
            and all(
                _url(getattr(self, field.name))
                for field in fields(self)
                if field.name not in ("support_email", "operator")
            )
        )
