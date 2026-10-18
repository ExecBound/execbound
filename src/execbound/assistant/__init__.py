# SPDX-License-Identifier: AGPL-3.0-only
"""The console assistant: reads with the asking person's authority, changes nothing.

Described in docs/SURFACES.md, The console's assistant (#330). The engine lives here; the
console-facing routes are one area module of the console API. Nothing in this package writes
anything but its own turn rows, and those only through the database's definer functions.
"""

# Audit kinds this package appends. Never a question or an answer: the chain is immutable.
ASKED = "assistant.asked"
EXPLAINED = "assistant.explained"
REFUSED = "assistant.refused"
