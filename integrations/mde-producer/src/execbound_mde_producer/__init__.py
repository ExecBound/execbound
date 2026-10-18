# SPDX-License-Identifier: Apache-2.0
"""Microsoft Defender for Endpoint as an ExecBound security signal producer (#478).

It reads each covered host's risk score with a read-only application and posts it, unmapped,
as an `execbound.security-signal.v1` envelope. What a verdict means is the operator's mapping
in ExecBound's bundle; this package decides nothing and is never called by ExecBound.
"""

__version__ = "0.1.0"
