# SPDX-License-Identifier: AGPL-3.0-only
"""Verify a restored ExecBound database and provider stores. See docs/RECOVERY.md."""

import sys

from execbound.recovery import main

if __name__ == "__main__":
    sys.exit(main())
