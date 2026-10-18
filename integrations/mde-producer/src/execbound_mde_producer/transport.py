# SPDX-License-Identifier: Apache-2.0
"""Direct, bounded HTTP: credentials never follow redirects or ambient proxies."""

import urllib.request
from typing import Any

MAX_RETRY_AFTER = 3600


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def open_direct(request: urllib.request.Request, *, timeout: int) -> Any:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect()).open(
        request, timeout=timeout
    )


def retry_after(value: str | None) -> int | None:
    if value is None or not value.isascii() or not value.isdigit() or len(value) > 10:
        return None
    return min(MAX_RETRY_AFTER, max(1, int(value)))
