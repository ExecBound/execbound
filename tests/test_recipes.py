# SPDX-License-Identifier: AGPL-3.0-only
"""Every command and JSON block the welcome page shows is rendered from a template with the
origin as its only variable and pinned byte for byte, so a path or flag change fails here and
not at a customer (#247)."""

import json
import re
from pathlib import Path

import pytest
from conftest import assert_secret_free

from execbound.surfaces.recipes import INSTALL_COMMAND, RECIPES, render_recipe, render_recipes

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "recipes"
ORIGIN = "https://sandbox.example"


@pytest.mark.parametrize("name", RECIPES)
def test_each_recipe_matches_its_fixture(name):
    rendered = render_recipe(name, ORIGIN)
    assert rendered == (FIXTURES / name).read_text(encoding="utf-8")
    assert_secret_free(rendered)
    assert "\r" not in rendered
    assert rendered.endswith("\n") and not rendered.endswith("\n\n")


def test_the_recipes_carry_the_origin_and_never_a_credential():
    rendered = render_recipes(ORIGIN)
    assert set(rendered) == set(RECIPES)
    assert INSTALL_COMMAND in rendered["install.sh"]
    assert f"{ORIGIN}/mcp/" in rendered["claude_code.sh"]
    cursor = json.loads(rendered["cursor.json"])
    assert cursor["mcpServers"]["execbound"] == {
        "url": f"{ORIGIN}/mcp/",
        "headers": {"Authorization": "Bearer ${env:EXECBOUND_CREDENTIAL}"},
    }
    assert 'os.environ["EXECBOUND_CREDENTIAL"]' in rendered["openai_agents.py.txt"]
    assert f"EXECBOUND_URL={ORIGIN}" in rendered["claude_agent_sdk.sh"]
    assert f"EXECBOUND_URL={ORIGIN}" in rendered["demo.sh"]


def test_the_claude_agent_sdk_recipe_names_every_tool_its_example_registers():
    """The recipe tells a reader what the example gives the model; a tool it leaves out is one
    the reader does not know to expect."""
    example = (ROOT / "clients/python/examples/claude_agent_sdk_tool.py").read_text(
        encoding="utf-8"
    )
    tools = re.findall(r'@tool\(\s*"(\w+)"', example)
    assert tools == ["execbound_list_actions", "execbound_action"]
    recipe = render_recipe("claude_agent_sdk.sh", ORIGIN)
    assert [name for name in tools if not re.search(rf"\b{name}\b", recipe)] == []


def test_the_demo_recipe_runs_only_what_either_kind_of_workspace_carries():
    """The demo recipe is shown for a workspace's sample targets and for synthetic fixtures
    alike (#247). `budget` asked for by name fails on samples, so the recipe runs `all`, which
    runs the beats the workspace carries and says when the budget beat was not one of them."""
    recipe = render_recipe("demo.sh", ORIGIN)
    commands = [line for line in recipe.splitlines() if line.startswith("execbound-demo")]
    assert commands == ["execbound-demo --private . all"]


def test_the_demo_recipe_issues_a_second_agent_key_only_for_synthetic_fixtures():
    """Both beats a samples file runs send as agent A, so the recipe has an administrator issue
    one agent key for sample targets and a second only for the budget beat, which runs on
    synthetic fixtures alone: a live key that is never sent is not one to ask for."""
    recipe = render_recipe("demo.sh", ORIGIN)
    named = [json.loads(found) for found in re.findall(r'"credentials": (\{[^}]*\})', recipe)]
    assert named == [
        {"agent_a": "agent-a.token"},
        {"agent_a": "agent-a.token", "agent_b": "agent-b.token"},
    ]
    assert re.search(r"^# Synthetic fixtures need a second agent's key", recipe, re.MULTILINE)


def test_the_claude_agent_sdk_recipe_reads_the_key_the_demo_recipe_saves():
    """Agent A's key file is saved where the demo recipe makes its directory, and the Claude
    Agent SDK recipe reads it from there, not from a directory nothing creates."""
    made = re.search(r"^mkdir -p (\S+) ", render_recipe("demo.sh", ORIGIN), re.MULTILINE)
    assert made is not None
    recipe = render_recipe("claude_agent_sdk.sh", ORIGIN)
    assert f"EXECBOUND_CREDENTIAL_FILE={made.group(1)}/agent-a.token" in recipe


def test_the_demo_recipe_keeps_the_agent_keys_private():
    """The demo directory holds an agent's API key, which on sample targets outlives the demo
    and keeps its agent's authority once the workspace connects a real provider. So the recipe
    makes the directory its owner's alone before anything is saved in it, and the key files
    too before the demo reads them, rather than leaving either to the umask."""
    commands = [
        line for line in render_recipe("demo.sh", ORIGIN).splitlines() if not line.startswith("#")
    ]
    made = next(i for i, line in enumerate(commands) if line.startswith("mkdir -p "))
    assert commands[made].startswith(
        "mkdir -p ~/execbound-demo && chmod 700 ~/execbound-demo && cd ~/execbound-demo"
    )
    keys = commands.index("chmod 600 *.token")
    run = next(i for i, line in enumerate(commands) if line.startswith("execbound-demo "))
    assert made < keys < run


def test_an_unknown_recipe_is_refused():
    with pytest.raises(KeyError):
        render_recipe("base.html", ORIGIN)


def test_unpublished_client_is_optional_and_requires_a_checkout():
    """Do not send a hosted visitor to a repository that has not been published."""
    assert "source checkout" in INSTALL_COMMAND
    assert "Native MCP needs no ExecBound client" in INSTALL_COMMAND
    assert "github.com" not in INSTALL_COMMAND
    assert 'pipx install "./clients/python[mcp]"' in INSTALL_COMMAND
    assert 'pipx install "./clients/python[mcp]"' in (ROOT / "clients/python/README.md").read_text(
        encoding="utf-8"
    )
