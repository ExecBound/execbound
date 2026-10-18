# SPDX-License-Identifier: AGPL-3.0-only
"""Help for the arguments that mean the same in every command that takes them.

`--tenant`, `--actor` and `--credential-file` recur across most commands, always with one
meaning, so their help is written once here and filled in wherever a command's own parser
gives none. A command whose argument means something else gives its own help, which wins.
"""

import argparse

COMMON_HELP = {
    "--tenant": "The tenant's id.",
    "--actor": (
        "The id of an active administrator of the tenant, whom the change is made and audited as."
    ),
    "--credential-file": (
        "A private file holding a current administrator's API key, which is never passed on the "
        "command line."
    ),
}
# The commands that change or read something of every space at once, which an administrator
# narrowed to spaces is refused (decided 8 October 2026), give this help instead.
WORKSPACE_CREDENTIAL_HELP = (
    "A private file holding a current workspace administrator's API key, which is never passed "
    "on the command line."
)


def describe_common(parser: argparse.ArgumentParser) -> None:
    """Fill in the shared help for every command of `parser` that gives none of its own."""
    for action in parser._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        for command in action.choices.values():
            for argument in command._actions:
                name = argument.option_strings[-1] if argument.option_strings else None
                if name in COMMON_HELP and not argument.help:
                    argument.help = COMMON_HELP[name]
