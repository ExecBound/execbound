# SPDX-License-Identifier: AGPL-3.0-only
"""The Arcade logic extension: the operator's tool map, and the refusals it makes.

The extension evaluates no policy and can only refuse. It turns a hook into the wire body
the kernel already defines and calls the same runtime methods an agent request reaches, so
nothing it does can permit what the kernel did not.
"""

from execbound.arcade.map import (
    ArcadeBlock,
    ArcadeTool,
    GovernedCall,
    ToolMap,
    ToolMapError,
    UngovernedToolkit,
)
from execbound.arcade.models import (
    HookResult,
    InvalidHook,
    PostHookRequest,
    PreHookRequest,
    parse_post_hook,
    parse_pre_hook,
)
from execbound.arcade.routes import arcade_router

__all__ = [
    "ArcadeBlock",
    "ArcadeTool",
    "GovernedCall",
    "HookResult",
    "InvalidHook",
    "PostHookRequest",
    "PreHookRequest",
    "ToolMap",
    "ToolMapError",
    "UngovernedToolkit",
    "arcade_router",
    "parse_post_hook",
    "parse_pre_hook",
]
