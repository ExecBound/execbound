# SPDX-License-Identifier: AGPL-3.0-only
"""The viewer's distance from UTC, as the console sends it with a read that counts "today".

Home, the live board and the decided approvals each count from the viewer's midnight when the
console names the viewer's offset, and from UTC midnight when it does not, so an old client and
the server-rendered showcase keep the day they had. One parser, so the three reads refuse the
same values: an optional string of up to three digits with an optional minus, at most fourteen
hours either way, since every zone in use lies within fourteen hours of UTC. Anything else is
`INVALID_REQUEST`, refused before any read. A repeated key never reaches here: the guards'
query allowlist refuses it first.
"""

import re
from datetime import timedelta

from execbound.surfaces.console_api.errors import ApiError

OFFSET = re.compile(r"-?[0-9]{1,3}")
MAX_OFFSET_MINUTES = 14 * 60


def utc_offset(raw: str | None) -> timedelta | None:
    """The viewer's minutes east of UTC, or None; anything malformed is INVALID_REQUEST."""
    if raw is None:
        return None
    if not OFFSET.fullmatch(raw) or abs(int(raw)) > MAX_OFFSET_MINUTES:
        raise ApiError("INVALID_REQUEST")
    return timedelta(minutes=int(raw))
