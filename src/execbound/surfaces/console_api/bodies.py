# SPDX-License-Identifier: AGPL-3.0-only
"""Documenting a mutation's JSON body, so the generated client is typed for it.

`guards.mutation` reads a body itself, after the session, the token, the Origin and the media
type, so the handler declares no body parameter and FastAPI documents none. `body(Model)` is
the `openapi_extra` a mutation route passes so the document carries the model under
`components.schemas` and the client's `body` is typed; `body_schemas()` is what the document
builder merges in. A model documented here is still validated by the guard alone.
"""

from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel
from pydantic.json_schema import models_json_schema

_BODIES: dict[str, type[BaseModel]] = {}


def body(model: type[BaseModel]) -> dict[str, Any]:
    """The `openapi_extra` of a route whose body `guards.mutation` reads as `model`."""
    _BODIES[model.__name__] = model
    return {
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {"schema": {"$ref": f"#/components/schemas/{model.__name__}"}}
            },
        }
    }


def body_schemas(names: Iterable[str] | None = None) -> dict[str, Any]:
    """The documented body models' schemas, keyed by name, with nested models beside them.

    `_BODIES` only grows: every area's `body()` call registers into it, in whichever process
    called it first, whether or not that area's router is the one a later caller built. With
    `names` given, only those models (and the nested models they need) are documented, so a
    document built from one router never carries a schema only a different router's route
    referenced; with no `names`, every model this process has ever documented is included, as
    before.
    """
    models = _BODIES if names is None else {n: _BODIES[n] for n in names if n in _BODIES}
    if not models:
        return {}
    _, definitions = models_json_schema(
        [(model, "validation") for model in models.values()],
        ref_template="#/components/schemas/{model}",
    )
    return dict(definitions.get("$defs", {}))
