# SPDX-License-Identifier: AGPL-3.0-only
"""Sample accounts, now defined in `execbound_connectors.samples` (#496).

Kept importable where it always was: the server's own modules, retained configuration
and installed deployments name this path.
"""

from execbound_connectors.samples import (
    MAX_KEY_BYTES,
    MIN_KEY_BYTES,
    SAMPLE_KEY_ID,
    SAMPLE_PROVIDER,
    SAMPLE_RESOURCE_VERSION,
    SampleLabel,
    SampleMaterial,
    SampleProvider,
    derive,
    parse_sample_key,
    sample_account,
    sample_connection,
    sample_material,
)

__all__ = [
    "derive",
    "MAX_KEY_BYTES",
    "MIN_KEY_BYTES",
    "parse_sample_key",
    "sample_account",
    "sample_connection",
    "SAMPLE_KEY_ID",
    "sample_material",
    "SAMPLE_PROVIDER",
    "SAMPLE_RESOURCE_VERSION",
    "SampleLabel",
    "SampleMaterial",
    "SampleProvider",
]
