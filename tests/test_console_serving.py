# SPDX-License-Identifier: AGPL-3.0-only
"""The console at its own paths: its routes, its policy, its files, its session (#333).

The switch removed the `/next/` prefix and the flag that gated it. So the first test here is
that the addresses the application answers are the addresses the application has — read from
its own generated route tree, not from a second list written by hand — and that a path it does
not have answers 404 rather than a shell that would render "not found" with a 200. Then: the
document needs a session and carries the running commit; the hashed files are immutable and the
rest revalidate; a bearer credential is refused and audited as on every page; the pages that
stay keep their own policy; the paths that moved redirect; and a build the package does not
carry is said so plainly rather than answering 404.
"""

import json
import re
import secrets
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_human_surface import credential, form_values
from test_human_surface import human_config as human_config
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world

from execbound.app import create_app
from execbound.surfaces import console as console_module
from execbound.surfaces.console import (
    CONSOLE_POLICY,
    CONSOLE_ROUTES,
    PAGE_POLICY,
    console_routes,
    is_console_path,
    load_build,
    packaged_edition,
    page_policy,
)
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.tokens import TokenKeys

ORIGIN = {"Origin": "http://127.0.0.1"}
ROUTE_TREE = Path(__file__).resolve().parents[1] / "console" / "src" / "routeTree.gen.ts"
DOCUMENT = (
    '<!doctype html><html lang="en"><head>'
    '<meta name="execbound-release" content="" />'
    '<link rel="icon" href="/console/favicon.svg" type="image/svg+xml" />'
    '<link rel="icon" href="/console/favicon.ico" sizes="16x16 32x32 48x48" />'
    '<link rel="stylesheet" href="/console/tokens.css" />'
    '</head><body><div id="root"></div>'
    '<script type="module" src="/console/assets/index-abc.js"></script></body></html>'
)
APPEARANCE = Path(__file__).resolve().parents[1] / "console" / "src" / "lib" / "appearance.ts"
CONSOLE_INDEX = Path(__file__).resolve().parents[1] / "console" / "index.html"
BASE_TEMPLATE = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "execbound"
    / "surfaces"
    / "templates"
    / "base.html"
)


def served() -> HumanConfig:
    return HumanConfig(
        "http://127.0.0.1",
        TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)}),
    )


def write_build(root: Path) -> Path:
    (root / "assets").mkdir(parents=True)
    (root / ".vite").mkdir()
    (root / ".vite" / "manifest.json").write_text("{}", encoding="utf-8")
    (root / "index.html").write_text(DOCUMENT, encoding="utf-8")
    (root / "assets" / "index-abc.js").write_text("console.log(1);\n", encoding="utf-8")
    (root / "tokens.css").write_text(":root { --eb-bg: #fff; }\n", encoding="utf-8")
    (root / "fonts").mkdir()
    (root / "fonts" / "plex.woff2").write_bytes(b"wOF2")
    (root / "favicon.svg").write_text("<svg xmlns='http://www.w3.org/2000/svg'/>", encoding="utf-8")
    (root / "favicon.ico").write_bytes(b"\x00\x00\x01\x00\x01\x00")
    (root / "notes.unknown").write_text("not served\n", encoding="utf-8")
    return root


@pytest.fixture
def fake_build(tmp_path, monkeypatch):
    root = write_build(tmp_path / "console_dist")
    monkeypatch.setattr(console_module, "build_root", lambda: root)
    monkeypatch.setenv("EXECBOUND_COMMIT", "abc1234def")
    return root


@pytest.fixture
def console(db, runtime, fake_build):
    app = create_app(db, runtime=runtime, human=served())
    with TestClient(app, base_url="http://127.0.0.1", follow_redirects=False) as client:
        yield client


def sign_in(client, admin_engine, world):
    _, values = form_values(client.get("/login").text, "/session")
    values["credential"] = credential(admin_engine, world["admin"])
    assert client.post("/session", data=values, headers=ORIGIN).status_code == 303


def application_routes(tree: Path = ROUTE_TREE) -> set[str]:
    """Every address an application has, from its own generated route tree.

    TanStack Router writes `FileRoutesByFullPath` from the route files, so this is the
    application's own answer to "what can I open", not a second list kept by hand. Core's tree
    is the default; a plugin's console edition has its own (#496).
    """
    text_ = tree.read_text(encoding="utf-8")
    block = text_.split("export interface FileRoutesByFullPath {", 1)[1].split("}", 1)[0]
    found = set()
    for path in re.findall(r"^\s*'([^']+)':", block, re.M):
        # `/approvals/` is the index route of a directory, which is `/approvals`.
        normalised = path[:-1] if path.endswith("/") and path != "/" else path
        found.add(re.sub(r"\$[A-Za-z]+", "{}", normalised))
    return found


def test_the_server_answers_exactly_the_addresses_the_application_has():
    """A page added to the application without a line in `CONSOLE_ROUTES` is unreachable.

    The server enumerates the console's routes rather than serving the document from a
    catch-all, so an address that does not exist answers 404 instead of a shell that renders
    "not found" with a 200, and this is what keeps the two lists equal. With no plugin loaded,
    the server's list is exactly core's.
    """
    assert console_routes() == CONSOLE_ROUTES
    assert {re.sub(r"\{[a-z_]+\}", "{}", path) for path in CONSOLE_ROUTES} == application_routes()


def test_without_a_plugin_its_console_addresses_are_not_served(console, admin_engine, world):
    """The addresses a plugin's console edition adds are not the console without that plugin
    (#496): no route answers them, so they answer 404 under the pages' policy."""
    sign_in(console, admin_engine, world)
    zero = "00000000-0000-0000-0000-000000000000"
    for path in (
        "/invitations",
        f"/workspaces/{zero}/approvals/{zero}",
        f"/workspaces/{zero}/approvals/{zero}/classic",
    ):
        response = console.get(path)
        assert response.status_code == 404, path
        assert response.headers["Content-Security-Policy"] == PAGE_POLICY, path
        assert not is_console_path(path), path


def test_an_address_the_application_does_not_have_is_a_404(console, admin_engine, world):
    sign_in(console, admin_engine, world)
    for path in ("/nothing", "/policy/00000000-0000-0000-0000-000000000000/rules/extra", "/a/b/c"):
        assert console.get(path).status_code == 404, path
    assert console.get("/nothing").headers["Content-Security-Policy"] == PAGE_POLICY


def test_the_document_needs_a_session_and_carries_the_release(console, admin_engine, world):
    assert console.get("/").status_code == 303
    assert console.get("/").headers["location"] == "/login"
    # The page rides the sign-in as a hint; an `open` that is not a record id is dropped (#678).
    assert console.get("/activity?open=1").headers["location"] == "/login?review=%2Factivity"
    sign_in(console, admin_engine, world)
    for path in ("/", "/activity", "/activity?open=1&state=held", "/approvals", "/welcome"):
        page = console.get(path)
        assert page.status_code == 200, path
        assert page.headers["content-type"].startswith("text/html")
        assert page.headers["Cache-Control"] == "no-store"
        assert page.headers["Content-Security-Policy"] == CONSOLE_POLICY
        assert '<meta name="execbound-release" content="abc1234def">' in page.text
        assert 'content=""' not in page.text
    # A duplicated key is still refused, as the pages refuse one; the keys themselves are the
    # application's own state and the server reads none of them.
    assert console.get("/activity?open=1&open=2").status_code == 400


def test_the_pages_that_stay_keep_the_pages_policy(console):
    """The console and the pages share the address space now, so the policy is chosen by the
    route and not by a prefix: `/approvals/{id}` is the application and `/approvals/{id}/classic`
    is the page behind it."""
    for path in ("/login", "/assets/app.css"):
        response = console.get(path)
        assert response.status_code == 200, path
        assert response.headers["Content-Security-Policy"] == PAGE_POLICY, path
    zero = "00000000-0000-0000-0000-000000000000"
    assert is_console_path(f"/approvals/{zero}")
    assert not is_console_path(f"/approvals/{zero}/classic")
    assert not is_console_path("/login")
    assert not is_console_path("/showcase")
    assert is_console_path("/console/tokens.css")
    assert is_console_path("/api/console/v1/session")


def test_the_paths_that_moved_redirect_so_a_bookmark_still_arrives(console):
    """A permanent redirect, with whatever the old address carried after the path kept."""
    moved = {
        "/admin/people": "/people",
        "/admin/people/00000000-0000-0000-0000-000000000000": (
            "/people/00000000-0000-0000-0000-000000000000"
        ),
        "/admin/credentials": "/credentials",
        "/admin/approvers": "/approvers",
        "/admin/settings": "/tenant",
        "/policy/rules": "/policy",
        "/monitor/connections": "/monitor?view=connections",
        "/next": "/",
        "/next/activity": "/activity",
    }
    for old, new in moved.items():
        response = console.get(old)
        assert response.status_code == 308, old
        assert response.headers["location"] == new, old
    # The search the old address carried is kept.
    assert console.get("/admin/people?state=all").headers["location"] == "/people?state=all"
    # A redirect reads no session and touches no row, so it is the same answer signed out.
    assert console.get("/admin/people").status_code == 308
    # `rules` is a redirect and not a bundle whose id happens to be that word.
    assert console.get("/policy/rules").headers["location"] == "/policy"
    # A monitoring view the page does not have is not invented.
    assert console.get("/monitor/nothing").status_code == 404
    # The welcome page's two downloads moved to a plugin's own routes, and so did their old
    # addresses: core has neither (#496).
    assert console.get("/welcome/sandbox.json").status_code == 404
    assert console.get("/welcome/candidate-bundle.json").status_code == 404


def test_hashed_files_are_immutable_and_the_rest_revalidate(console):
    asset = console.get("/console/assets/index-abc.js")
    assert asset.status_code == 200
    assert asset.headers["content-type"].startswith("text/javascript")
    assert asset.headers["Cache-Control"] == "public, max-age=31536000, immutable"
    assert asset.headers["Content-Security-Policy"] == CONSOLE_POLICY
    etag = asset.headers["ETag"]
    assert (
        console.get("/console/assets/index-abc.js", headers={"If-None-Match": etag}).status_code
        == 304
    )
    tokens = console.get("/console/tokens.css")
    assert tokens.status_code == 200
    assert tokens.headers["content-type"].startswith("text/css")
    assert tokens.headers["Cache-Control"] == "no-cache"
    assert (
        console.get(
            "/console/tokens.css", headers={"If-None-Match": tokens.headers["ETag"]}
        ).status_code
        == 304
    )
    font = console.get("/console/fonts/plex.woff2")
    assert font.status_code == 200 and font.headers["content-type"] == "font/woff2"
    assert console.get("/console/assets/missing.js").status_code == 404
    # The document is never a file: it is the page, with its session check and its release.
    assert console.get("/console/index.html").status_code == 404
    # Build metadata and a file of a type the module does not know are not served at all.
    assert console.get("/console/.vite/manifest.json").status_code == 404
    assert console.get("/console/notes.unknown").status_code == 404


def test_the_appearance_is_on_the_root_element_before_any_script_could_run(
    console, admin_engine, world
):
    """System, Light or Dark, applied by the server so the first paint is already right.

    The console carries no inline script and paints a plain frame from the tokens before the
    bundle runs, so a scheme the browser applied would arrive one paint late every visit. The
    cookie is the only way a choice can reach the document that early, and this is the test
    that it does: the attribute is in the bytes the server writes, not something a script put
    there afterwards.
    """
    sign_in(console, admin_engine, world)
    plain = console.get("/")
    assert '<html lang="en">' in plain.text, "the system scheme carries no attribute at all"
    assert "data-eb-scheme" not in plain.text
    assert plain.headers["Vary"] == "Cookie"
    for scheme in ("light", "dark"):
        console.cookies.set("eb_appearance", scheme)
        page = console.get("/settings")
        assert f'<html lang="en" data-eb-scheme="{scheme}">' in page.text, scheme
        # The release is still stamped, and stamped once.
        assert page.text.count('content="abc1234def"') == 1, scheme
    # Anything else is System: a word from another version, a value somebody typed into their
    # own browser, an empty cookie. Nothing here needs validating beyond that membership,
    # because nothing but the palette depends on it. The page still answers 200, so none of
    # these passes by having been refused rather than by having been read as System.
    for junk in ("sepia", "", "SYSTEM", "Dark", '"dark"', "light dark", "%22%3E%3Cscript%3E"):
        console.cookies.set("eb_appearance", junk)
        answer = console.get("/")
        assert answer.status_code == 200, (junk, answer.status_code)
        assert "data-eb-scheme" not in answer.text, junk
    console.cookies.delete("eb_appearance")


def test_the_browser_writes_the_cookie_the_server_reads():
    """One name, agreed across the two languages.

    The `__Host-` prefix is a browser guarantee about where a cookie came from, so the server
    takes it wherever it is reached over HTTPS. The browser has to build the same name or a
    hosted deployment would write one cookie and read another — which would look like an
    appearance that simply never sticks.
    """
    client = APPEARANCE.read_text(encoding="utf-8")
    hosted = HumanConfig("https://app.example.com", TokenKeys("k", {"k": secrets.token_bytes(32)}))
    assert hosted.cookie("appearance") == "__Host-eb_appearance"
    assert served().cookie("appearance") == "eb_appearance"
    assert '"__Host-" : "") + "eb_appearance"' in client, "the client builds some other name"
    # And the three words the two sides agree on, with System as the absence of the cookie.
    assert 'APPEARANCES = ["system", "light", "dark"]' in client
    assert console_module.SCHEMES == ("light", "dark")


def test_the_mark_is_served_where_a_browser_asks_for_it(console):
    """`/favicon.ico` is requested by a browser whatever a document says, and both documents
    name the SVG as well. One copy of the mark in the package serves the console, the pages
    that stay and the bare root request."""
    for path, kind in (("/favicon.ico", "image/x-icon"), ("/favicon.svg", "image/svg+xml")):
        icon = console.get(path)
        assert icon.status_code == 200, path
        assert icon.headers["content-type"].startswith(kind), path
        assert icon.headers["Cache-Control"] == "no-cache", path
        assert (
            console.get(path, headers={"If-None-Match": icon.headers["ETag"]}).status_code == 304
        ), path
        # The same bytes the build serves under its own address: one copy, never two.
        assert icon.content == console.get("/console" + path).content, path
    # Nothing but the two: the root is not a second way into the build.
    assert console.get("/favicon.png").status_code == 404
    # An icon is not a page and needs no session.
    assert console.get("/favicon.ico").status_code == 200

    # Every document links them, the console's and the pages that run before a session.
    links = re.findall(
        r'<link rel="(?:apple-touch-)?icon"[^>]*href="([^"]+)"', console.get("/login").text
    )
    assert links == ["/favicon.svg", "/favicon.ico"], links
    for href in links:
        assert console.get(href).status_code == 200, href
    document = CONSOLE_INDEX.read_text(encoding="utf-8")
    assert document.count('<link rel="icon"') == 2, "the console document links no icon"
    assert 'sizes="16x16 32x32 48x48"' in document
    assert '<link rel="icon" href="/favicon.svg"' in BASE_TEMPLATE.read_text(encoding="utf-8")


def test_a_bearer_credential_is_refused_and_audited(console, seeded, admin_engine, world):
    headers = {"Authorization": "Bearer " + seeded["tokens"][0], **ORIGIN}
    assert console.get("/", headers=headers).status_code == 403
    assert console.get("/activity", headers=headers).status_code == 403
    with admin_engine.connect() as conn:
        rejected = conn.execute(
            text(
                "SELECT count(*) FROM execbound.audit_events "
                "WHERE tenant_id=:t AND actor_id=:p AND kind='execution.rejected'"
            ),
            {"t": world["identity"].tenant_id, "p": world["identity"].principal_id},
        ).scalar_one()
    assert rejected == 2


def test_a_build_the_package_does_not_carry_is_said_plainly(db, runtime, tmp_path, monkeypatch):
    monkeypatch.setattr(console_module, "build_root", lambda: tmp_path / "absent")
    app = create_app(db, runtime=runtime, human=served())
    with TestClient(app, base_url="http://127.0.0.1") as client:
        for path in ("/", "/activity", "/console/assets/index.js"):
            response = client.get(path)
            assert response.status_code == 503, path
            assert response.text == "The console build is not packaged."
        # The pages that stay are not the console's and answer as they always did.
        assert client.get("/login").status_code == 200


def test_a_page_may_load_the_mark_it_links():
    """Every page links `/favicon.svg` and `/favicon.ico`, and a favicon is an image.

    With no `img-src` the page's own `default-src 'none'` refused both, so on 21 September
    2026 the sign-in tab showed the browser's blank globe while the console's tabs showed the
    mark. Same origin only: nothing a page renders may pull an image from anywhere else, and
    configuring a sign-in provider widens `form-action` and nothing more.
    """
    for policy in (PAGE_POLICY, page_policy(("https://accounts.google.com",))):
        directives = dict(part.strip().split(" ", 1) for part in policy.split(";"))
        assert directives["img-src"] == "'self'"
        assert directives["default-src"] == "'none'"


def test_load_build_reads_every_servable_file_once(tmp_path):
    root = write_build(tmp_path / "dist")
    build = load_build(root)
    assert build is not None
    assert sorted(build) == [
        "assets/index-abc.js",
        "favicon.ico",
        "favicon.svg",
        "fonts/plex.woff2",
        "index.html",
        "tokens.css",
    ]
    assert build["fonts/plex.woff2"].media_type == "font/woff2"
    assert build["index.html"].etag.startswith('"') and len(build["index.html"].etag) == 34
    assert load_build(tmp_path / "nowhere") is None
    (tmp_path / "empty").mkdir()
    assert load_build(tmp_path / "empty") is None


def assert_no_inline(build: dict[str, console_module.BuildFile]) -> None:
    """The policy is `script-src 'self'` and `style-src 'self'` with no nonce, so a build may
    not inline anything, whichever edition it is."""
    document = build["index.html"].body.decode("utf-8")
    scripts = re.findall(r"<script\b[^>]*>", document)
    assert scripts, "the document loads no script"
    for tag in scripts:
        assert 'type="module"' in tag and re.search(r'src="/console/assets/[^"]+\.js"', tag), tag
    assert "<style" not in document and " style=" not in document
    bodies = re.findall(r"<script\b[^>]*>(.*?)</script>", document, re.S)
    assert bodies and all(body.strip() == "" for body in bodies), "an inline script body"
    for key, file in build.items():
        if key.startswith("assets/") and file.media_type.startswith("text/javascript"):
            assert "\n" not in key and re.search(r"-[A-Za-z0-9_-]{8}\.js$", key), key
    assert any(key.startswith("assets/") and key.endswith(".css") for key in build)


def test_a_packaged_build_emits_no_inline_script_or_style():
    """Checked over the build the package carries when one is present (CI builds it before the
    suite); a checkout with no build carries nothing to check."""
    build = load_build()
    if build is None:
        assert not build_root_exists(), "a console_dist directory exists but is not a build"
        return
    assert_no_inline(build)


def build_root_exists() -> bool:
    return console_module.build_root().is_dir()


def test_the_packaged_edition_is_read_from_the_document(tmp_path):
    """The build names its edition in the document (`console/scripts/editions.ts`), which is all
    the server reads of it (#496); a document without a well-formed name names none."""
    assert packaged_edition(tmp_path / "missing") is None
    root = write_build(tmp_path / "build")
    assert packaged_edition(root) is None
    for content, expected in (
        ("core", "core"),
        ("other_edition", "other_edition"),
        ("", None),
        ("Core!", None),
        ("a" * 33, None),
    ):
        (root / "index.html").write_text(
            DOCUMENT.replace(
                "</head>", f'<meta name="execbound-edition" content="{content}" /></head>'
            ),
            encoding="utf-8",
        )
        assert packaged_edition(root) == expected, content


def test_readiness_reports_the_edition_the_packaged_build_names(db, runtime, tmp_path, monkeypatch):
    root = write_build(tmp_path / "console_dist")
    (root / "index.html").write_text(
        DOCUMENT.replace("</head>", '<meta name="execbound-edition" content="core" /></head>'),
        encoding="utf-8",
    )
    monkeypatch.setattr(console_module, "build_root", lambda: root)
    # A human surface refuses the test client's default `testserver` host, as every page
    # test here does, so both clients name the loopback address.
    app = create_app(db, runtime=runtime, human=served())
    with TestClient(app, base_url="http://127.0.0.1") as client:
        assert client.get("/health/ready").json()["console"] == "core"
    # A process with no human surface serves no console, so it reports none.
    with TestClient(create_app(db, runtime=runtime), base_url="http://127.0.0.1") as client:
        assert "console" not in client.get("/health/ready").json()


def test_the_packaged_build_is_the_core_edition():
    """The package, the wheel and the self-hosted image carry the core edition (#496):
    its document names it, and its manifest lists no module under src/hosted/. The core build
    itself refuses to reach one (`console/scripts/editions.ts`); this reads the build the
    package carries, for which the manifest can speak only as far as its chunks' entry modules."""
    if load_build() is None:
        assert not build_root_exists(), "a console_dist directory exists but is not a build"
        return
    assert packaged_edition() == "core", "rebuild the core console: `pnpm build` in console/"
    manifest = json.loads(
        console_module.build_root().joinpath(".vite/manifest.json").read_text(encoding="utf-8")
    )
    assert [key for key in manifest if key.startswith("src/hosted/")] == []


STORIES = ("execbound-governed-action.json", "execbound-gate.json")
INTEGRATIONS = Path(__file__).resolve().parents[1] / "integrations"


@pytest.fixture
def story_console(db, runtime, fake_build):
    """The fake build with the two Tines stories and their licence where the console build
    writes them (#678)."""
    stories = fake_build / "stories" / "tines"
    stories.mkdir(parents=True)
    for name in STORIES:
        (stories / name).write_bytes((INTEGRATIONS / "tines" / name).read_bytes())
    (stories / "LICENSE").write_bytes((INTEGRATIONS / "LICENSE").read_bytes())
    app = create_app(db, runtime=runtime, human=served())
    with TestClient(app, base_url="http://127.0.0.1", follow_redirects=False) as client:
        yield client


def test_a_story_file_is_served_with_its_type_and_revalidated(story_console):
    story = story_console.get("/console/stories/tines/execbound-gate.json")
    assert story.status_code == 200
    assert story.headers["content-type"] == "application/json"
    assert story.headers["Cache-Control"] == "no-cache"
    assert story.content == (INTEGRATIONS / "tines" / "execbound-gate.json").read_bytes()
    assert (
        story_console.get(
            "/console/stories/tines/execbound-gate.json",
            headers={"If-None-Match": story.headers["ETag"]},
        ).status_code
        == 304
    )


def test_the_story_licence_is_packaged_but_not_served(story_console):
    # No media type is known for a file without an extension, so it is no file of the console.
    assert story_console.get("/console/stories/tines/LICENSE").status_code == 404


def test_the_packaged_build_carries_the_committed_tines_stories_unchanged():
    """Over the build the package carries when one is present (CI builds it before the suite):
    each story is the committed file byte for byte, and the licence travels beside them."""
    build = load_build()
    if build is None:
        assert not build_root_exists(), "a console_dist directory exists but is not a build"
        return
    for name in STORIES:
        committed = (INTEGRATIONS / "tines" / name).read_bytes()
        assert build[f"stories/tines/{name}"].body == committed, name
    licence = console_module.build_root() / "stories" / "tines" / "LICENSE"
    assert licence.read_bytes() == (INTEGRATIONS / "LICENSE").read_bytes()
