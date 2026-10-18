# SPDX-License-Identifier: AGPL-3.0-only
"""The sample plugin: the contract every registry point is tested against (#238, #496).

The tests load this file as ``execbound.sample_plugin``, the way an installed first-party
plugin is found; it is never installed. It uses every point the registry offers but one: a
human page, a console API area, a console page, a command, a session feature, approval links,
a sign-in link, a provider signup point, service links and the classification of its console
route for tokens. It claims no dormant object, so its database tests run against a core
database; a test that needs a claim registers one of its own (#496). Its own boot entry,
`boot_run`, hands core boot the files it writes and the variables they consume, as a plugin
with private material of its own does.
"""

import argparse
from collections.abc import Callable, Mapping, MutableMapping, Sequence
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Request
from starlette.responses import PlainTextResponse, Response

from execbound import boot
from execbound.plugins import (
    PLUGIN_API_VERSION,
    ApprovalLinks,
    Command,
    CommandError,
    Plugin,
    ProviderSignup,
    Registry,
    SignInLink,
)
from execbound.requests import StrictModel
from execbound.runtime import Runtime
from execbound.service_links import ServiceLinks
from execbound.signin import ExternalAccount
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import Session

# A support address and a help page of the sample's own, on a reserved domain, so a test can see
# the loader carry a plugin's service links and a `service` block beside them refuse start.
SERVICE_LINKS = ServiceLinks(
    support_email="support@sample.invalid", help_url="https://sample.invalid/help"
)


class SampleConfig(StrictModel):
    greeting: str = "hello"


def greeting(runtime: Runtime) -> str:
    config = runtime.plugins.config("sample_plugin")
    return config.greeting if isinstance(config, SampleConfig) else "unconfigured"


def pages(runtime: Runtime, config: HumanConfig) -> APIRouter:
    routes = APIRouter()

    @routes.get("/sample-plugin/hello")
    def hello() -> dict[str, str]:
        return {"greeting": greeting(runtime)}

    return routes


def area(routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards) -> None:
    @routes.get("/sample-plugin")
    async def read(request: Request) -> dict[str, str]:
        await guards.session(request)
        return {"greeting": greeting(runtime)}


def administers_pool(runtime: Runtime, session: Session) -> bool:
    """On when the section asks for it, so a test can see core read the feature back as the
    session's `invitations`."""
    return greeting(runtime) == "pool"


def approval_path(tenant_id: UUID, approval_id: UUID) -> str:
    return f"/workspaces/{tenant_id}/approvals/{approval_id}"


async def review(
    request: Request,
    runtime: Runtime,
    config: HumanConfig,
    session: Session,
    csrf: str,
    tenant_id: UUID,
    approval_id: UUID,
    classic: bool,
) -> Response | None:
    """Let the page render for the session's own tenant; answer 409 for any other."""
    if tenant_id == session.identity.tenant_id:
        return None
    return PlainTextResponse("sample review " + ("classic" if classic else "console"), 409)


def sign_in_label(runtime: Runtime) -> str:
    """The sign-in page's link to the sample's page, worded from the section, so a test can
    see core render a plugin's words as text."""
    return "Say " + greeting(runtime)


async def provider_signup_finish(
    runtime: Runtime, config: HumanConfig, request: Request, account: ExternalAccount
) -> Response | None:
    """Nothing of the sample's own to show: the subject signs in exactly as `/login` would."""
    return None


def provider_signup_refused(runtime: Runtime, config: HumanConfig, request: Request) -> Response:
    return PlainTextResponse("sample signup refused", 403)


def configure(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("words", nargs="+")


def run(args: argparse.Namespace) -> str:
    if args.words == ["refuse"]:
        raise CommandError("Sample refused: NO.")
    return "sample: " + " ".join(args.words)


def register(registry: Registry) -> None:
    registry.human_router(pages)
    registry.console_area(area)
    # Its console API route, which core's table does not classify, is the plugin's to classify.
    registry.token_routes(allowed=[("/api/console/v1/sample-plugin", "GET")])
    registry.console_path("/sample-plugin")
    registry.command(Command("sample-echo", "Echo the words back", configure, run))
    registry.session_feature("invitations", administers_pool)
    registry.approval_links(ApprovalLinks(approval_path, review))
    registry.sign_in_link(SignInLink("/sample-plugin/hello", sign_in_label))
    registry.provider_signup(ProviderSignup(provider_signup_finish, provider_signup_refused))
    registry.service_links(SERVICE_LINKS)


# Its own boot material: one token from its own variable, checked before core boot writes
# anything, written owner-only after core's files, and never left in the started process.
BOOT_TOKEN = "EXECBOUND_SAMPLE_TOKEN"
BOOT_FILE = "sample.token"
BOOT_CONSUMED = (BOOT_TOKEN,)


def boot_files(
    environment: Mapping[str, str], directory: Path, runtime_document: bytes | None
) -> list[tuple[Path, bytes]]:
    token = environment.get(BOOT_TOKEN)
    if not token:
        return []
    if not boot._is_token(token):
        raise boot.BootError(f"{BOOT_TOKEN} is not a token")
    return [(directory / BOOT_FILE, (token + "\n").encode("ascii"))]


def boot_run(
    arguments: Sequence[str],
    environment: MutableMapping[str, str] | None = None,
    *,
    execute: Callable[[str, Sequence[str]], object] = boot._execute,
) -> int:
    return boot.run(
        arguments, environment, execute=execute, files=boot_files, consumed=BOOT_CONSUMED
    )


PLUGIN = Plugin("sample_plugin", PLUGIN_API_VERSION, register, SampleConfig)
