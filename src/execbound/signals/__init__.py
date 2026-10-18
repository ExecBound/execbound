# SPDX-License-Identifier: AGPL-3.0-only
"""Security signals: evidence an out-of-process producer attests, read as trusted context.

A signal is a source kind inside the context-contract machinery, never a path to authority
of its own (see docs/SIGNALS.md). A producer can submit envelopes inside its registered
scope and nothing else: it reads nothing, decides nothing and is never called. What a verdict
means is the operator's mapping in the bundle.
"""
