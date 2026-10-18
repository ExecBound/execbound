# SPDX-License-Identifier: AGPL-3.0-only
"""The command-line reference, written from the commands' own argument parsers.

`docs/CLI_REFERENCE.md` is this module's output and nothing else: `scripts/cli_reference.py`
writes it, and `tests/test_cli_reference.py` fails when the committed page no longer matches
what the parsers describe, so the reference and the commands cannot drift apart. Only core's
commands are here; a plugin's are added to the parser at run time and documented with it.
"""

import argparse
import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

# A default read from the environment would make the page depend on the shell it was written
# in, so these are unset while the parsers are built and the built-in default is shown.
_ENVIRONMENT_DEFAULTS = ("EXECBOUND_IMAGE",)

INTRO = """\
# Command-line reference

Every command the `execbound` command line and the monitoring commands take, and the arguments
each accepts. This page is generated from the commands' own argument parsers by
`scripts/cli_reference.py`, and a test fails when it no longer matches them. What each command
is for, in context, is in [operations](OPERATIONS.md), [install on one host](INSTALL.md) and
[deployment](DEPLOYMENT.md), and the codes a command refuses with are in
[error and refusal codes](ERROR_CODES.md).

A plugin may add commands of its own, which the plugin documents. They appear in `execbound --help`
once `EXECBOUND_PLUGINS` enables the plugin; `execbound plugins` lists only the enabled plugins'
names and the plugin API version.
"""


@contextmanager
def _without_environment_defaults() -> Iterator[None]:
    saved = {name: os.environ.pop(name) for name in _ENVIRONMENT_DEFAULTS if name in os.environ}
    try:
        yield
    finally:
        os.environ.update(saved)


def _cell(text: str) -> str:
    return " ".join(text.split()).replace("|", "\\|")


def _sentence(text: str) -> str:
    """A help string as a sentence: a cell, ending in a full stop."""
    text = _cell(text)
    return text if not text or text.endswith((".", "?", "!", ")")) else text + "."


def _default(action: argparse.Action) -> str | None:
    """The default worth showing, or None. A blank one, such as `""`, would render as an empty
    code span, so it is left out like an absent one."""
    value = action.default
    if value is None or value is argparse.SUPPRESS or isinstance(value, bool):
        return None
    if isinstance(value, list | tuple) and not value:
        return None
    text = str(value)
    return text if text.strip() else None


def _required(action: argparse.Action) -> bool:
    if action.option_strings:
        return action.required
    return action.nargs not in ("?", "*")


def _arguments(parser: argparse.ArgumentParser) -> list[str]:
    formatter = parser._get_formatter()
    rows = []
    for action in parser._actions:
        if isinstance(action, argparse._HelpAction) or action.help is argparse.SUPPRESS:
            continue
        invocation = formatter._format_action_invocation(action)
        notes = [_sentence(action.help or "")]
        if action.choices is not None and not isinstance(action, argparse._SubParsersAction):
            notes.append("One of " + ", ".join(f"`{choice}`" for choice in action.choices) + ".")
        default = _default(action)
        if default is not None:
            notes.append(f"Default `{_cell(default)}`.")
        described = " ".join(note for note in notes if note).strip()
        required = "yes" if _required(action) else "no"
        rows.append(f"| `{_cell(invocation)}` | {required} | {described} |")
    lines: list[str] = []
    if rows:
        lines += ["| Argument | Required | Description |", "| --- | --- | --- |", *rows, ""]
    for group in parser._mutually_exclusive_groups:
        names = [f"`{action.option_strings[-1]}`" for action in group._group_actions]
        which = "Exactly one" if group.required else "At most one"
        lines += [f"{which} of {', '.join(names)}.", ""]
    return lines


def _commands(program: str, parser: argparse.ArgumentParser) -> list[str]:
    subparsers = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    helps = {choice.dest: choice.help for choice in subparsers._choices_actions}
    lines = [f"## `{program}`", "", _sentence(parser.description or ""), ""]
    lines += [
        "| Command | What it does |",
        "| --- | --- |",
        *(f"| `{name}` | {_cell(helps.get(name) or '')} |" for name in subparsers.choices),
        "",
    ]
    for name, command in subparsers.choices.items():
        lines += [f"### `{program} {name}`", ""]
        if helps.get(name):
            lines += [_sentence(helps[name] or ""), ""]
        lines += _arguments(command)
    return lines


def render() -> str:
    """The whole page, from both parsers."""
    from execbound.cli import build_parser
    from execbound.monitoring.commands import build_parser as monitoring_parser

    with _without_environment_defaults():
        execbound, _ = build_parser()
        monitoring = monitoring_parser()
    lines: list[Any] = [INTRO]
    lines += _commands("execbound", execbound)
    lines += _commands("python -m execbound.monitoring.commands", monitoring)
    return "\n".join(lines).rstrip("\n") + "\n"
