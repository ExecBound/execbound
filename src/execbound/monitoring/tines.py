# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit, read-only management connectivity check; never a background collector."""

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from dotenv import dotenv_values


class TinesConfigError(ValueError):
    def __init__(self) -> None:
        super().__init__("Tines connection unavailable; check tenant, key and read permissions.")


@dataclass(frozen=True)
class TinesConfig:
    base_url: str
    api_key: str = field(repr=False)

    def __post_init__(self) -> None:
        try:
            url = urlsplit(self.base_url)
            if (
                url.scheme != "https"
                or not url.hostname
                or not url.hostname.endswith((".tines.com", ".tines.io"))
                or url.port not in {None, 443}
                or url.username
                or url.password
                or url.path
                or url.query
                or url.fragment
                or self.base_url != self.base_url.strip()
                or not 1 <= len(self.api_key) <= 4096
                or not self.api_key.isascii()
                or any(
                    char.isspace() or ord(char) < 33 or ord(char) == 127 for char in self.api_key
                )
            ):
                raise ValueError
        except ValueError:
            raise TinesConfigError() from None

    @classmethod
    def from_file(cls, path: Path) -> "TinesConfig":
        try:
            if path.stat().st_size > 16384:
                raise ValueError
            # No ambient override or interpolation can silently change the key/destination.
            values = dotenv_values(path, interpolate=False)
            return cls(values.get("TINES_BASE_URL") or "", values.get("TINES_API_KEY") or "")
        except (OSError, ValueError):
            raise TinesConfigError() from None


def check_connection(config: TinesConfig, client: httpx.Client) -> dict[str, str]:
    try:
        with client.stream(
            "GET",
            config.base_url + "/api/v1/stories",
            params={"per_page": 1, "page": 1},
            headers={"X-User-Token": config.api_key, "Accept": "application/json"},
            follow_redirects=False,
            timeout=5,
        ) as response:
            if response.status_code != 200:
                raise TinesConfigError()
            # Do not retain/read the story response: it can contain customer configuration.
        return {
            "platform": "tines",
            "status": "read-access-confirmed",
            "scope": "stories-list-only",
        }
    except httpx.HTTPError:
        raise TinesConfigError() from None
