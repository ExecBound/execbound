# SPDX-License-Identifier: Apache-2.0
"""Defender for Endpoint, read-only: a client-credentials token and the machines list.

The application holds `WindowsDefenderATP` `Machine.Read.All` and nothing else. Each machine
is projected to four fields as soon as it is read, so an IP address, the Entra device id or a
tag never reaches the envelope, the log or anything else (#478).
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from http.client import HTTPException
from typing import Any

from execbound_mde_producer.config import ConfigError, _gateway
from execbound_mde_producer.transport import open_direct, retry_after

LOGIN = "https://login.microsoftonline.com"
API = "https://api.security.microsoft.com"
SCOPE = "https://api.securitycenter.microsoft.com/.default"
RISK_SCORES = frozenset({"None", "Informational", "Low", "Medium", "High"})
MAX_PAGES = 20
MAX_PAGE_BYTES = 8 * 1024 * 1024
Opener = Callable[..., Any]


class DefenderError(RuntimeError):
    """A refused or failed read: a status and, when throttled, the advised wait; no secret."""

    def __init__(
        self, message: str, *, status: int | None = None, retry_after: int | None = None
    ) -> None:
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


@dataclass(frozen=True)
class Machine:
    machine_id: str
    risk_score: str | None
    health_status: str | None
    azure_resource_id: str | None


def project(item: Mapping[str, Any]) -> Machine:
    machine_id = item.get("id")
    if not isinstance(machine_id, str) or not 1 <= len(machine_id) <= 256:
        raise DefenderError("Invalid machine identity")
    metadata = item.get("vmMetadata")
    resource = metadata.get("resourceId") if isinstance(metadata, dict) else None
    risk = item.get("riskScore")
    health = item.get("healthStatus")
    return Machine(
        machine_id=machine_id,
        risk_score=risk if isinstance(risk, str) and risk in RISK_SCORES else None,
        health_status=health if isinstance(health, str) else None,
        azure_resource_id=resource if isinstance(resource, str) else None,
    )


class Defender:
    def __init__(
        self,
        credentials: Mapping[str, str],
        *,
        opener: Opener = open_direct,
        login: str = LOGIN,
        api: str = API,
        clock: Callable[[], float] = time.time,
    ) -> None:
        try:
            self._tenant = credentials["AZURE_TENANT_ID"]
            self._client = credentials["AZURE_CLIENT_ID"]
            self._secret = credentials["AZURE_CLIENT_SECRET"]
        except KeyError:
            raise ConfigError("Missing Defender credential") from None
        if not all(isinstance(v, str) and v for v in (self._tenant, self._client, self._secret)):
            raise ConfigError("Invalid Defender credential")
        if not self._tenant.isascii() or not all(c.isalnum() or c in "-." for c in self._tenant):
            raise ConfigError("Invalid Defender tenant")
        self._opener = opener
        self._login = _gateway(login)
        self._api = _gateway(api)
        self._clock = clock
        self._token: str | None = None
        self._expiry = 0.0

    def _call(self, request: urllib.request.Request, what: str) -> Any:
        try:
            with self._opener(request, timeout=30) as response:
                raw = response.read(MAX_PAGE_BYTES + 1)
                if len(raw) > MAX_PAGE_BYTES:
                    raise DefenderError(f"{what} response too large")
                return json.loads(raw)
        except urllib.error.HTTPError as error:
            if error.code == 401:
                self._token = None
            advised = error.headers.get("Retry-After") if error.headers else None
            error.close()
            raise DefenderError(
                f"{what} refused",
                status=error.code,
                retry_after=retry_after(advised),
            ) from None
        except (OSError, ValueError, RecursionError, HTTPException):
            raise DefenderError(f"{what} unavailable") from None

    def _access(self) -> str:
        if self._token is not None and self._clock() < self._expiry - 120:
            return self._token
        body = urllib.parse.urlencode(
            {
                "client_id": self._client,
                "client_secret": self._secret,
                "scope": SCOPE,
                "grant_type": "client_credentials",
            }
        ).encode()
        request = urllib.request.Request(
            f"{self._login}/{self._tenant}/oauth2/v2.0/token", data=body, method="POST"
        )
        answer = self._call(request, "Token")
        if not isinstance(answer, dict) or type(answer.get("access_token")) is not str:
            raise DefenderError("Token unavailable")
        token: str = answer["access_token"]
        expiry = answer.get("expires_in")
        if (
            not token
            or not token.isascii()
            or len(token) > 32768
            or any(ord(c) <= 32 or ord(c) == 127 for c in token)
            or type(expiry) is not int
            or not 1 <= expiry <= 86400
        ):
            raise DefenderError("Token unavailable")
        self._token, self._expiry = token, self._clock() + expiry
        return token

    def machines(self) -> list[Machine]:
        found: list[Machine] = []
        url: str | None = f"{self._api}/api/machines"
        for _ in range(MAX_PAGES):
            if url is None:
                return found
            if not url.startswith(self._api + "/"):
                raise DefenderError("Next link leaves the API")
            request = urllib.request.Request(
                url, headers={"Authorization": f"Bearer {self._access()}"}
            )
            page = self._call(request, "Machines")
            if not isinstance(page, dict) or not isinstance(page.get("value"), list):
                raise DefenderError("Machines unavailable")
            for item in page["value"]:
                if not isinstance(item, dict):
                    raise DefenderError("Machines unavailable")
                found.append(project(item))
            link = page.get("@odata.nextLink")
            if link is not None and (not isinstance(link, str) or not link):
                raise DefenderError("Invalid next link")
            url = link if isinstance(link, str) else None
            if url is None:
                return found
        raise DefenderError("Too many pages")
