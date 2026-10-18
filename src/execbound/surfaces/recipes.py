# SPDX-License-Identifier: AGPL-3.0-only
"""The welcome page's recipes: every command and JSON block a reader copies, rendered from
a template with the gateway origin as its only variable and pinned byte for byte by a test.

The credential is never rendered; each recipe says where it comes from. The optional client
requires a source checkout until public distribution is available; native MCP needs none.
"""

from jinja2 import Environment, PackageLoader, StrictUndefined

INSTALL_COMMAND = (
    "# Optional Python client: requires an ExecBound source checkout.\n"
    "# Public installation is not available yet. Native MCP needs no ExecBound client.\n"
    "# Run from the checkout root:\n"
    'pipx install "./clients/python[mcp]"'
)
RECIPES = (
    "install.sh",
    "demo.sh",
    "claude_code.sh",
    "cursor.json",
    "openai_agents.py.txt",
    "claude_agent_sdk.sh",
)
_templates = Environment(
    loader=PackageLoader("execbound.surfaces", "templates/recipes"),
    autoescape=False,  # nosec B701 - plain text the page escapes on insertion
    keep_trailing_newline=True,
    undefined=StrictUndefined,
)


def render_recipe(name: str, origin: str) -> str:
    """One recipe as plain text; the page escapes it like any other untrusted string."""
    if name not in RECIPES:
        raise KeyError(name)
    return _templates.get_template(name).render(origin=origin, install=INSTALL_COMMAND)


def render_recipes(origin: str) -> dict[str, str]:
    return {name: render_recipe(name, origin) for name in RECIPES}
